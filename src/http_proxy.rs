use std::time::Instant;

use anyhow::{Result, bail};
use base64::Engine as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use url::Url;

use crate::socks5::{self, Mode, Options};

pub async fn serve(mut client: TcpStream, options: Options, first_byte: u8) -> Result<()> {
    let session_started = Instant::now();
    let handshake_started = Instant::now();
    let parsed = match timeout(
        options.handshake_timeout,
        read_proxy_request(&mut client, first_byte),
    )
    .await
    {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => {
            crate::perftrace::stage("http.handshake", handshake_started, false, &[]);
            let _ = write_http_status(&mut client, 400, "Bad Request", &[]).await;
            return Err(error);
        }
        Err(_) => {
            crate::perftrace::stage("http.handshake", handshake_started, false, &[]);
            bail!("HTTP proxy handshake timed out");
        }
    };

    let route = if socks5::requires_auth(&options.mode) {
        let Some((username, password)) = parsed.credentials.as_ref() else {
            crate::perftrace::stage("http.handshake", handshake_started, false, &[]);
            write_http_status(
                &mut client,
                407,
                "Proxy Authentication Required",
                &[("Proxy-Authenticate", "Basic realm=\"oixc-proxy\"")],
            )
            .await?;
            bail!("HTTP proxy authentication required");
        };
        match socks5::authenticate(&options.mode, username, password).await {
            Ok(route) => route,
            Err(error) => {
                crate::perftrace::stage("http.handshake", handshake_started, false, &[]);
                write_http_status(
                    &mut client,
                    407,
                    "Proxy Authentication Required",
                    &[("Proxy-Authenticate", "Basic realm=\"oixc-proxy\"")],
                )
                .await?;
                return Err(error);
            }
        }
    } else {
        match &options.mode {
            Mode::Fixed { route, .. } => route.clone(),
            Mode::Dynamic(_) => unreachable!(),
        }
    };
    crate::perftrace::stage("http.handshake", handshake_started, true, &[]);

    let started = Instant::now();
    let mut session = match route.client.dial_tcp(&parsed.host, parsed.port).await {
        Ok(session) => session,
        Err(_) => {
            crate::perftrace::stage("http.upstream", started, false, &[]);
            crate::perftrace::stage("http.session", session_started, false, &[]);
            write_http_status(&mut client, 502, "Bad Gateway", &[]).await?;
            bail!("open upstream tunnel");
        }
    };
    crate::perftrace::stage("http.upstream", started, true, &[]);

    if parsed.connect {
        write_raw(&mut client, b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
    } else if let Some(head) = parsed.forwarded_head.as_ref() {
        session.write(head).await?;
        if !parsed.leftover.is_empty() {
            session.write(&parsed.leftover).await?;
        }
    }

    let result = socks5::relay(client, session).await;
    crate::perftrace::stage("http.session", session_started, result.is_ok(), &[]);
    result
}

struct ParsedRequest {
    connect: bool,
    host: String,
    port: u16,
    credentials: Option<(String, String)>,
    forwarded_head: Option<Vec<u8>>,
    leftover: Vec<u8>,
}

async fn read_proxy_request(client: &mut TcpStream, first_byte: u8) -> Result<ParsedRequest> {
    let mut request = vec![first_byte];
    let mut buffer = [0u8; 1024];
    loop {
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        let read = client.read(&mut buffer).await?;
        if read == 0 {
            bail!("unexpected EOF in HTTP proxy request");
        }
        request.extend_from_slice(&buffer[..read]);
        if request.len() > 8 << 10 {
            bail!("HTTP proxy request headers are too large");
        }
    }
    let split = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("HTTP proxy request is truncated"))?;
    let leftover = request[split + 4..].to_vec();
    let text = String::from_utf8_lossy(&request[..split]);
    let mut lines = text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("HTTP proxy request line is missing"))?;
    let headers: Vec<&str> = lines.collect();
    let credentials = parse_basic_proxy_auth(&headers);
    let mut parsed = parse_request_line(request_line, &headers, credentials)?;
    parsed.leftover = leftover;
    Ok(parsed)
}

fn parse_request_line(
    request_line: &str,
    headers: &[&str],
    credentials: Option<(String, String)>,
) -> Result<ParsedRequest> {
    let mut fields = request_line.split_whitespace();
    let method = fields
        .next()
        .ok_or_else(|| anyhow::anyhow!("HTTP proxy request line is invalid"))?;
    let target = fields
        .next()
        .ok_or_else(|| anyhow::anyhow!("HTTP proxy request line is invalid"))?;
    if fields.next().is_none() {
        bail!("HTTP proxy request line is invalid");
    }
    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = parse_connect_target(target)?;
        return Ok(ParsedRequest {
            connect: true,
            host,
            port,
            credentials,
            forwarded_head: None,
            leftover: Vec::new(),
        });
    }
    let (host, port, forwarded_head) = rewrite_absolute_request(request_line, headers)?;
    Ok(ParsedRequest {
        connect: false,
        host,
        port,
        credentials,
        forwarded_head: Some(forwarded_head),
        leftover: Vec::new(),
    })
}

fn parse_connect_target(target: &str) -> Result<(String, u16)> {
    if let Some(rest) = target.strip_prefix('[') {
        let (host, rest) = rest
            .split_once(']')
            .ok_or_else(|| anyhow::anyhow!("HTTP CONNECT target is invalid"))?;
        let port = rest
            .strip_prefix(':')
            .ok_or_else(|| anyhow::anyhow!("HTTP CONNECT target is invalid"))?
            .parse()
            .map_err(|_| anyhow::anyhow!("HTTP CONNECT port is invalid"))?;
        if host.is_empty() || port == 0 {
            bail!("HTTP CONNECT target is invalid");
        }
        return Ok((host.to_owned(), port));
    }
    let (host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("HTTP CONNECT target is invalid"))?;
    let port = port
        .parse()
        .map_err(|_| anyhow::anyhow!("HTTP CONNECT port is invalid"))?;
    if host.is_empty() || host.contains(':') || port == 0 {
        bail!("HTTP CONNECT target is invalid");
    }
    Ok((host.to_owned(), port))
}

fn parse_basic_proxy_auth(headers: &[&str]) -> Option<(String, String)> {
    for header in headers {
        let (name, value) = header.split_once(':')?;
        if !name.eq_ignore_ascii_case("proxy-authorization") {
            continue;
        }
        let mut parts = value.split_whitespace();
        let scheme = parts.next()?;
        let encoded = parts.next()?;
        if !scheme.eq_ignore_ascii_case("basic") || parts.next().is_some() {
            continue;
        }
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .ok()?;
        let pair = String::from_utf8(decoded).ok()?;
        return pair
            .split_once(':')
            .map(|(user, pass)| (user.to_owned(), pass.to_owned()));
    }
    None
}

fn rewrite_absolute_request(
    request_line: &str,
    headers: &[&str],
) -> Result<(String, u16, Vec<u8>)> {
    let mut fields = request_line.splitn(3, ' ');
    let method = fields
        .next()
        .ok_or_else(|| anyhow::anyhow!("HTTP proxy request line is invalid"))?;
    let target = fields
        .next()
        .ok_or_else(|| anyhow::anyhow!("HTTP proxy request line is invalid"))?;
    let version = fields.next().unwrap_or("HTTP/1.1");
    let url = Url::parse(target).map_err(|_| anyhow::anyhow!("HTTP proxy URL is invalid"))?;
    if url.scheme() != "http" {
        bail!("HTTP proxy only forwards http:// URLs");
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("HTTP proxy URL is missing a host"))?
        .to_owned();
    let port = url.port().unwrap_or(80);
    if port == 0 {
        bail!("HTTP proxy port is invalid");
    }
    let path = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };
    let origin = match url.query() {
        Some(query) => format!("{path}?{query}"),
        None => path.to_owned(),
    };
    let mut forwarded = format!("{method} {origin} {version}\r\n");
    for header in headers {
        let Some((name, _)) = header.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("proxy-authorization")
            || name.eq_ignore_ascii_case("proxy-connection")
        {
            continue;
        }
        forwarded.push_str(header);
        forwarded.push_str("\r\n");
    }
    forwarded.push_str("\r\n");
    Ok((host, port, forwarded.into_bytes()))
}

async fn write_http_status(
    client: &mut TcpStream,
    status: u16,
    reason: &str,
    headers: &[(&str, &str)],
) -> Result<()> {
    let mut response =
        format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n");
    for (name, value) in headers {
        response.push_str(name);
        response.push_str(": ");
        response.push_str(value);
        response.push_str("\r\n");
    }
    response.push_str("\r\n");
    write_raw(client, response.as_bytes()).await
}

async fn write_raw(client: &mut TcpStream, payload: &[u8]) -> Result<()> {
    client.write_all(payload).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_connect_targets() {
        assert_eq!(
            parse_connect_target("example.com:443").unwrap(),
            ("example.com".to_owned(), 443)
        );
        assert_eq!(
            parse_connect_target("1.2.3.4:80").unwrap(),
            ("1.2.3.4".to_owned(), 80)
        );
        assert_eq!(
            parse_connect_target("[2001:db8::1]:443").unwrap(),
            ("2001:db8::1".to_owned(), 443)
        );
        assert!(parse_connect_target("example.com").is_err());
        assert!(parse_connect_target("[::1]").is_err());
    }

    #[test]
    fn parses_basic_proxy_authorization() {
        let encoded = base64::engine::general_purpose::STANDARD.encode("name-abc:secret-1");
        let headers = [format!("Proxy-Authorization: Basic {encoded}")];
        let refs: Vec<&str> = headers.iter().map(String::as_str).collect();
        assert_eq!(
            parse_basic_proxy_auth(&refs).unwrap(),
            ("name-abc".to_owned(), "secret-1".to_owned())
        );
    }

    #[test]
    fn rewrites_absolute_form_http_request() {
        let (host, port, head) = rewrite_absolute_request(
            "GET http://example.com:8080/foo?x=1 HTTP/1.1",
            &[
                "Host: example.com:8080",
                "Proxy-Authorization: Basic abc",
                "Proxy-Connection: keep-alive",
                "Accept: */*",
            ],
        )
        .unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
        let head = String::from_utf8(head).unwrap();
        assert_eq!(
            head,
            "GET /foo?x=1 HTTP/1.1\r\nHost: example.com:8080\r\nAccept: */*\r\n\r\n"
        );
    }
}
