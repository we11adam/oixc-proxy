use std::io::Cursor;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use base64::Engine as _;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;
use url::{Host, Url};

use crate::snell::{SnellSession, SnellSessionReader, SnellSessionWriter};
use crate::socks5::{self, Activity, Mode, Options};

const BODY_BATCH_SIZE: usize = 32 << 10;
const CHUNK_LINE_LIMIT: usize = 4 << 10;
const TRAILER_LIMIT: usize = 8 << 10;
const RESPONSE_HEAD_LIMIT: usize = 64 << 10;
const LINGER_TIMEOUT: Duration = Duration::from_secs(2);

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
            Mode::Fixed { route, .. } => route.get(),
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

    let result = match parsed.forwarded {
        None => {
            write_raw(&mut client, b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
            // Clients may send tunnelled bytes, such as a TLS ClientHello,
            // together with the CONNECT request.
            if !parsed.leftover.is_empty() {
                session.write(&parsed.leftover).await?;
            }
            socks5::relay(client, session, options.tcp_idle_timeout).await
        }
        Some(forwarded) if forwarded.upgrade => {
            // After a protocol switch the connection no longer carries HTTP
            // requests, so relay it as an opaque tunnel.
            session.write(&forwarded.head).await?;
            if !parsed.leftover.is_empty() {
                session.write(&parsed.leftover).await?;
            }
            socks5::relay(client, session, options.tcp_idle_timeout).await
        }
        Some(forwarded) => {
            relay_one_request(
                client,
                session,
                forwarded,
                parsed.leftover,
                options.tcp_idle_timeout,
            )
            .await
        }
    };
    crate::perftrace::stage("http.session", session_started, result.is_ok(), &[]);
    result
}

/// Forwards exactly one request and its response.
///
/// The client chose the upstream for this connection through the first
/// request only. Later keep-alive requests may target other hosts and would
/// carry `Proxy-Authorization`, so they must never reach this upstream.
/// The rewritten request asks the origin to close after responding, the
/// response tells the client the same, and any client bytes after the request
/// body are discarded.
async fn relay_one_request(
    client: TcpStream,
    mut session: SnellSession,
    forwarded: ForwardedRequest,
    leftover: Vec<u8>,
    idle_timeout: Duration,
) -> Result<()> {
    let started = Instant::now();
    let (client_read, client_write) = client.into_split();
    let mut request =
        BufReader::with_capacity(BODY_BATCH_SIZE, Cursor::new(leftover).chain(client_read));
    let activity = Activity::new();
    let clean = {
        let (remote_read, remote_write) = session.split();
        let mut sink = ActiveSink {
            writer: remote_write,
            activity: &activity,
        };
        let upload = forward_body(&mut request, &mut sink, forwarded.framing, forwarded.head);
        let download = async {
            let (mut client_write, mut remote_read) = (client_write, remote_read);
            forward_response_head(&mut remote_read, &mut client_write, &activity).await?;
            socks5::download(client_write, remote_read, &activity).await
        };
        let relay = async {
            tokio::pin!(upload, download);
            tokio::select! {
                upload_result = &mut upload => upload_result.is_ok() && download.await.is_ok(),
                download_result = &mut download => {
                    let _ = download_result;
                    false
                }
            }
        };
        socks5::until_idle(relay, &activity, idle_timeout)
            .await
            .unwrap_or(false)
    };
    session.finish(clean, false).await;
    crate::perftrace::stage("http.relay", started, clean, &[]);
    if !clean {
        bail!("HTTP proxy relay ended with an error");
    }
    // Closing a socket with unread input makes the kernel send RST, which can
    // destroy response bytes the client has not read yet.
    let _ = timeout(LINGER_TIMEOUT, discard_until_eof(&mut request)).await;
    Ok(())
}

trait ChunkSource {
    async fn read_chunk(&mut self) -> Result<&[u8]>;
}

impl ChunkSource for SnellSessionReader<'_> {
    async fn read_chunk(&mut self) -> Result<&[u8]> {
        SnellSessionReader::read_chunk(self).await
    }
}

/// Forwards response heads up to and including the final one.
///
/// The request asked the origin to close, but an origin only should repeat
/// that in its response. A client that is not told may reuse the connection
/// and send another request, which would be discarded, so the final head
/// always carries `Connection: close`. Interim 1xx heads pass through as is.
async fn forward_response_head<S, W>(
    source: &mut S,
    client: &mut W,
    activity: &Activity,
) -> Result<()>
where
    S: ChunkSource,
    W: AsyncWrite + Unpin,
{
    let mut buffer = Vec::new();
    let mut searched = 0;
    loop {
        let Some(end) = find_head_end(&buffer, searched) else {
            if buffer.len() > RESPONSE_HEAD_LIMIT {
                bail!("HTTP response header is too large");
            }
            searched = buffer.len().saturating_sub(2);
            let chunk = source.read_chunk().await?;
            activity.touch();
            if chunk.is_empty() {
                bail!("HTTP response ended inside its header");
            }
            buffer.extend_from_slice(chunk);
            continue;
        };
        if is_interim_response(&buffer[..end])? {
            client.write_all(&buffer[..end]).await?;
            buffer.drain(..end);
            searched = 0;
            continue;
        }
        client
            .write_all(&close_response_head(&buffer[..end]))
            .await?;
        client.write_all(&buffer[end..]).await?;
        return Ok(());
    }
}

/// Returns the length of the head ending in an empty line, accepting bare LF
/// line endings as RFC 9112 allows.
fn find_head_end(buffer: &[u8], from: usize) -> Option<usize> {
    (from..buffer.len()).find_map(|index| {
        if buffer[index] != b'\n' {
            return None;
        }
        match buffer.get(index + 1..) {
            Some([b'\n', ..]) => Some(index + 2),
            Some([b'\r', b'\n', ..]) => Some(index + 3),
            _ => None,
        }
    })
}

fn is_interim_response(head: &[u8]) -> Result<bool> {
    let status = match head {
        [
            b'H',
            b'T',
            b'T',
            b'P',
            b'/',
            major,
            b'.',
            minor,
            b' ',
            status @ ..,
        ] if major.is_ascii_digit()
            && minor.is_ascii_digit()
            && status.len() >= 3
            && status[..3].iter().all(u8::is_ascii_digit) =>
        {
            &status[..3]
        }
        _ => bail!("HTTP response status line is invalid"),
    };
    // 101 switches protocols and is final; it is never requested here.
    Ok(status[0] == b'1' && status != b"101")
}

/// Rewrites a final response head to close the connection. Connection
/// options are hop-by-hop, so the headers they name are dropped as well,
/// except those that frame the body.
fn close_response_head(head: &[u8]) -> Vec<u8> {
    let lines: Vec<&[u8]> = head
        .split(|value| *value == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .filter(|line| !line.is_empty())
        .collect();
    let name_of = |line: &[u8]| -> Option<Vec<u8>> {
        let colon = line.iter().position(|value| *value == b':')?;
        Some(line[..colon].to_ascii_lowercase())
    };
    let options: Vec<Vec<u8>> = lines[1..]
        .iter()
        .filter(|line| name_of(line).as_deref() == Some(b"connection"))
        .flat_map(|line| line["connection:".len()..].split(|value| *value == b','))
        .map(|option| option.trim_ascii().to_ascii_lowercase())
        .collect();
    let dropped = |name: &[u8]| {
        matches!(name, b"connection" | b"keep-alive" | b"proxy-connection")
            || (!matches!(name, b"content-length" | b"transfer-encoding")
                && options.iter().any(|option| option == name))
    };

    let mut output = Vec::with_capacity(head.len() + 19);
    output.extend_from_slice(lines[0]);
    output.extend_from_slice(b"\r\n");
    let mut keep = true;
    for line in &lines[1..] {
        // A folded line continues the previous header.
        if !line.starts_with(b" ") && !line.starts_with(b"\t") {
            keep = name_of(line).is_none_or(|name| !dropped(&name));
        }
        if keep {
            output.extend_from_slice(line);
            output.extend_from_slice(b"\r\n");
        }
    }
    output.extend_from_slice(b"Connection: close\r\n\r\n");
    output
}

async fn discard_until_eof<R: AsyncRead + Unpin>(reader: &mut BufReader<R>) {
    let mut buffer = [0u8; 4096];
    while matches!(reader.read(&mut buffer).await, Ok(read) if read != 0) {}
}

trait BodySink {
    async fn send(&mut self, content: &[u8]) -> Result<()>;
}

/// Forwards request bytes upstream and records them as relay activity.
struct ActiveSink<'a, 'b> {
    writer: SnellSessionWriter<'b>,
    activity: &'a Activity,
}

impl BodySink for ActiveSink<'_, '_> {
    async fn send(&mut self, content: &[u8]) -> Result<()> {
        self.activity.touch();
        self.writer.write(content).await.map(|_| ())
    }
}

/// Sends `head` followed by exactly one request body read from `reader`.
async fn forward_body<R, S>(
    reader: &mut BufReader<R>,
    sink: &mut S,
    framing: BodyFraming,
    head: Vec<u8>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    S: BodySink,
{
    let mut output = head;
    match framing {
        BodyFraming::Empty => {}
        BodyFraming::Length(length) => copy_body_bytes(reader, sink, &mut output, length).await?,
        BodyFraming::Chunked => loop {
            let line = read_body_line(reader, sink, &mut output, CHUNK_LINE_LIMIT).await?;
            let size = parse_chunk_size(&line)?;
            output.extend_from_slice(&line);
            if size == 0 {
                let mut trailer_bytes = 0;
                loop {
                    let line = read_body_line(reader, sink, &mut output, TRAILER_LIMIT).await?;
                    trailer_bytes += line.len();
                    if trailer_bytes > TRAILER_LIMIT {
                        bail!("HTTP request trailers are too large");
                    }
                    output.extend_from_slice(&line);
                    if line == b"\r\n" {
                        break;
                    }
                }
                break;
            }
            copy_body_bytes(reader, sink, &mut output, size).await?;
            let line = read_body_line(reader, sink, &mut output, 2).await?;
            if line != b"\r\n" {
                bail!("HTTP request chunk is malformed");
            }
            output.extend_from_slice(&line);
        },
    }
    if !output.is_empty() {
        sink.send(&output).await?;
    }
    Ok(())
}

/// Returns buffered request bytes, first sending pending output when the next
/// read has to wait on the client so streamed bodies are not held back.
async fn fill_body<'a, R, S>(
    reader: &'a mut BufReader<R>,
    sink: &mut S,
    output: &mut Vec<u8>,
) -> Result<&'a [u8]>
where
    R: AsyncRead + Unpin,
    S: BodySink,
{
    if reader.buffer().is_empty() && !output.is_empty() {
        sink.send(output).await?;
        output.clear();
    }
    let buffered = reader.fill_buf().await?;
    if buffered.is_empty() {
        bail!("unexpected EOF in HTTP request body");
    }
    Ok(buffered)
}

async fn copy_body_bytes<R, S>(
    reader: &mut BufReader<R>,
    sink: &mut S,
    output: &mut Vec<u8>,
    mut remaining: u64,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    S: BodySink,
{
    while remaining != 0 {
        let buffered = fill_body(reader, sink, output).await?;
        let take = buffered
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        output.extend_from_slice(&buffered[..take]);
        reader.consume(take);
        remaining -= take as u64;
        if output.len() >= BODY_BATCH_SIZE {
            sink.send(output).await?;
            output.clear();
        }
    }
    Ok(())
}

async fn read_body_line<R, S>(
    reader: &mut BufReader<R>,
    sink: &mut S,
    output: &mut Vec<u8>,
    limit: usize,
) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
    S: BodySink,
{
    let mut line = Vec::new();
    loop {
        let buffered = fill_body(reader, sink, output).await?;
        let (take, done) = match buffered.iter().position(|value| *value == b'\n') {
            Some(index) => (index + 1, true),
            None => (buffered.len(), false),
        };
        if line.len() + take > limit {
            bail!("HTTP request chunk line is too long");
        }
        line.extend_from_slice(&buffered[..take]);
        reader.consume(take);
        if done {
            if !line.ends_with(b"\r\n") {
                bail!("HTTP request chunk line is malformed");
            }
            return Ok(line);
        }
    }
}

fn parse_chunk_size(line: &[u8]) -> Result<u64> {
    let line = &line[..line.len() - 2];
    let size = match line.iter().position(|value| *value == b';') {
        Some(index) => &line[..index],
        None => line,
    };
    let end = size
        .iter()
        .rposition(|value| !matches!(value, b' ' | b'\t'))
        .map_or(0, |index| index + 1);
    let size = &size[..end];
    if size.is_empty() || size.len() > 15 || !size.iter().all(u8::is_ascii_hexdigit) {
        bail!("HTTP request chunk size is invalid");
    }
    let size = std::str::from_utf8(size).expect("hex digits are ASCII");
    Ok(u64::from_str_radix(size, 16).expect("validated hex chunk size"))
}

struct ParsedRequest {
    host: String,
    port: u16,
    credentials: Option<(String, String)>,
    /// `None` for CONNECT.
    forwarded: Option<ForwardedRequest>,
    leftover: Vec<u8>,
}

struct ForwardedRequest {
    head: Vec<u8>,
    framing: BodyFraming,
    upgrade: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BodyFraming {
    Empty,
    Length(u64),
    Chunked,
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
            host,
            port,
            credentials,
            forwarded: None,
            leftover: Vec::new(),
        });
    }
    let (host, port, forwarded) = rewrite_absolute_request(request_line, headers)?;
    Ok(ParsedRequest {
        host,
        port,
        credentials,
        forwarded: Some(forwarded),
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
        let Some((name, value)) = header.split_once(':') else {
            continue;
        };
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
) -> Result<(String, u16, ForwardedRequest)> {
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
    // `host_str` keeps the brackets around IPv6 literals, which the dialer
    // would treat as part of a host name.
    let host = match url.host() {
        Some(Host::Domain(domain)) => domain.to_owned(),
        Some(Host::Ipv4(address)) => address.to_string(),
        Some(Host::Ipv6(address)) => address.to_string(),
        None => bail!("HTTP proxy URL is missing a host"),
    };
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

    let mut fields = Vec::with_capacity(headers.len());
    for header in headers {
        if header.starts_with([' ', '\t']) {
            bail!("HTTP request header line folding is not supported");
        }
        let Some((name, value)) = header.split_once(':') else {
            continue;
        };
        if name.is_empty() || name.ends_with([' ', '\t']) {
            bail!("HTTP request header name is invalid");
        }
        fields.push((*header, name, value.trim_matches([' ', '\t'])));
    }
    // Keeps empty list elements so that an empty framing header is rejected
    // instead of being read as absent.
    let named = |wanted: &'static str| -> Vec<&str> {
        fields
            .iter()
            .filter(|(_, name, _)| name.eq_ignore_ascii_case(wanted))
            .flat_map(|(_, _, value)| value.split(','))
            .map(|token| token.trim_matches([' ', '\t']))
            .collect()
    };
    let framing = request_framing(version, named("content-length"), named("transfer-encoding"))?;
    let connection_options = named("connection");
    let upgrade = connection_options
        .iter()
        .any(|option| option.eq_ignore_ascii_case("upgrade"))
        && fields
            .iter()
            .any(|(_, name, _)| name.eq_ignore_ascii_case("upgrade"));

    let mut forwarded = format!("{method} {origin} {version}\r\n");
    for (header, name, _) in &fields {
        let keep_upgrade = upgrade && name.eq_ignore_ascii_case("upgrade");
        if is_hop_by_hop(name, upgrade)
            || (!keep_upgrade
                && !is_framing_header(name)
                && connection_options
                    .iter()
                    .any(|option| option.eq_ignore_ascii_case(name)))
        {
            continue;
        }
        forwarded.push_str(header);
        forwarded.push_str("\r\n");
    }
    forwarded.push_str(if upgrade {
        "Connection: Upgrade, close\r\n\r\n"
    } else {
        "Connection: close\r\n\r\n"
    });
    Ok((
        host,
        port,
        ForwardedRequest {
            head: forwarded.into_bytes(),
            framing,
            upgrade,
        },
    ))
}

fn is_hop_by_hop(name: &str, upgrade: bool) -> bool {
    [
        "connection",
        "keep-alive",
        "proxy-connection",
        "proxy-authorization",
        "te",
    ]
    .iter()
    .any(|hop| name.eq_ignore_ascii_case(hop))
        || (!upgrade && name.eq_ignore_ascii_case("upgrade"))
}

/// The proxy and the origin must agree on where the request body ends, so
/// a `Connection` option may never remove these headers.
fn is_framing_header(name: &str) -> bool {
    ["host", "content-length", "transfer-encoding"]
        .iter()
        .any(|framing| name.eq_ignore_ascii_case(framing))
}

/// Rejects every ambiguous framing that could let the origin see a different
/// request boundary than the proxy (RFC 9112 section 6.3).
fn request_framing(
    version: &str,
    content_lengths: Vec<&str>,
    transfer_codings: Vec<&str>,
) -> Result<BodyFraming> {
    if !transfer_codings.is_empty() {
        if !content_lengths.is_empty() {
            bail!("HTTP request has both Transfer-Encoding and Content-Length");
        }
        if !version.eq_ignore_ascii_case("HTTP/1.1") {
            bail!("HTTP/1.0 request uses Transfer-Encoding");
        }
        if transfer_codings.iter().any(|coding| coding.is_empty()) {
            bail!("HTTP request Transfer-Encoding is invalid");
        }
        let chunked = transfer_codings
            .iter()
            .filter(|coding| coding.eq_ignore_ascii_case("chunked"))
            .count();
        if chunked != 1
            || !transfer_codings[transfer_codings.len() - 1].eq_ignore_ascii_case("chunked")
        {
            bail!("HTTP request transfer coding is unsupported");
        }
        return Ok(BodyFraming::Chunked);
    }
    let Some(first) = content_lengths.first() else {
        return Ok(BodyFraming::Empty);
    };
    if first.is_empty()
        || !first.bytes().all(|value| value.is_ascii_digit())
        || content_lengths.iter().any(|value| value != first)
    {
        bail!("HTTP request Content-Length is invalid");
    }
    let length: u64 = first
        .parse()
        .map_err(|_| anyhow::anyhow!("HTTP request Content-Length is invalid"))?;
    Ok(if length == 0 {
        BodyFraming::Empty
    } else {
        BodyFraming::Length(length)
    })
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

    struct Chunks(std::collections::VecDeque<Vec<u8>>, Vec<u8>);

    impl Chunks {
        fn new(chunks: &[&[u8]]) -> Self {
            Self(
                chunks.iter().map(|chunk| chunk.to_vec()).collect(),
                Vec::new(),
            )
        }
    }

    impl ChunkSource for Chunks {
        async fn read_chunk(&mut self) -> Result<&[u8]> {
            self.1 = self.0.pop_front().unwrap_or_default();
            Ok(&self.1)
        }
    }

    async fn forwarded_head(chunks: &[&[u8]]) -> Result<Vec<u8>> {
        let mut client = Vec::new();
        forward_response_head(&mut Chunks::new(chunks), &mut client, &Activity::new()).await?;
        Ok(client)
    }

    #[tokio::test]
    async fn final_response_head_always_closes() {
        let output = forwarded_head(&[
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nConnection: keep-",
            b"alive, X-Hop, Content-Length\r\nKeep-Alive: timeout=5\r\nX-Hop: 1\r\n",
            b"Content-Length: 5\r\nX-Folded: a\r\n b\r\n\r\nhello",
        ])
        .await
        .unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            concat!(
                "HTTP/1.1 100 Continue\r\n\r\n",
                "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Folded: a\r\n b\r\n",
                "Connection: close\r\n\r\nhello",
            )
        );

        let output = forwarded_head(&[b"HTTP/1.0 204 No Content\nServer: x\n\n"])
            .await
            .unwrap();
        assert_eq!(
            output,
            b"HTTP/1.0 204 No Content\r\nServer: x\r\nConnection: close\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn malformed_or_truncated_response_heads_fail() {
        assert!(forwarded_head(&[b"garbage\r\n\r\n"]).await.is_err());
        assert!(forwarded_head(&[b"HTTP/1.1 200 OK\r\n"]).await.is_err());
        let large = vec![b'x'; RESPONSE_HEAD_LIMIT + 1];
        assert!(
            forwarded_head(&[b"HTTP/1.1 200 OK\r\nX: ", &large])
                .await
                .is_err()
        );
    }

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

        let headers = [
            "Host: example.com:443".to_owned(),
            "malformed header without a colon".to_owned(),
            format!("Proxy-Authorization: Basic {encoded}"),
        ];
        let refs: Vec<&str> = headers.iter().map(String::as_str).collect();
        assert_eq!(
            parse_basic_proxy_auth(&refs).unwrap(),
            ("name-abc".to_owned(), "secret-1".to_owned())
        );
    }

    #[test]
    fn rewrites_ipv6_literal_without_brackets() {
        let (host, port, forwarded) = rewrite_absolute_request(
            "GET http://[2001:db8::1]:8080/ HTTP/1.1",
            &["Host: [2001:db8::1]:8080"],
        )
        .unwrap();
        assert_eq!((host.as_str(), port), ("2001:db8::1", 8080));
        assert!(
            forwarded
                .head
                .starts_with(b"GET / HTTP/1.1\r\nHost: [2001:db8::1]:8080\r\n")
        );
    }

    #[test]
    fn rewrites_absolute_form_http_request() {
        let (host, port, forwarded) = rewrite_absolute_request(
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
        assert_eq!(forwarded.framing, BodyFraming::Empty);
        assert!(!forwarded.upgrade);
        let head = String::from_utf8(forwarded.head).unwrap();
        assert_eq!(
            head,
            "GET /foo?x=1 HTTP/1.1\r\nHost: example.com:8080\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn rewrite_disables_keep_alive_and_strips_hop_by_hop_headers() {
        let (_, _, forwarded) = rewrite_absolute_request(
            "POST http://example.com/ HTTP/1.1",
            &[
                "Host: example.com",
                "Connection: keep-alive, X-Hop, Content-Length",
                "Keep-Alive: timeout=5",
                "X-Hop: 1",
                "TE: trailers",
                "Upgrade: h2c",
                "Content-Length: 3",
            ],
        )
        .unwrap();
        assert_eq!(forwarded.framing, BodyFraming::Length(3));
        assert!(!forwarded.upgrade);
        assert_eq!(
            String::from_utf8(forwarded.head).unwrap(),
            "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn rewrite_keeps_upgrade_handshake() {
        let (_, _, forwarded) = rewrite_absolute_request(
            "GET http://example.com/ws HTTP/1.1",
            &[
                "Host: example.com",
                "Connection: keep-alive, Upgrade",
                "Upgrade: websocket",
            ],
        )
        .unwrap();
        assert!(forwarded.upgrade);
        assert_eq!(
            String::from_utf8(forwarded.head).unwrap(),
            "GET /ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade, close\r\n\r\n"
        );
    }

    #[test]
    fn rejects_ambiguous_request_framing() {
        let rewrite = |headers: &[&str]| {
            rewrite_absolute_request("POST http://example.com/ HTTP/1.1", headers)
                .map(|(_, _, forwarded)| forwarded.framing)
        };
        assert!(rewrite(&["Transfer-Encoding: chunked", "Content-Length: 5"]).is_err());
        assert!(rewrite(&["Content-Length: 5", "Content-Length: 6"]).is_err());
        assert!(rewrite(&["Content-Length: +5"]).is_err());
        assert!(rewrite(&["Content-Length:"]).is_err());
        assert!(rewrite(&["Transfer-Encoding:"]).is_err());
        assert!(rewrite(&["Transfer-Encoding: gzip"]).is_err());
        assert!(rewrite(&["Transfer-Encoding: chunked, chunked"]).is_err());
        assert!(rewrite(&["Host: example.com", " folded"]).is_err());
        assert_eq!(
            rewrite(&["Content-Length: 5, 5"]).unwrap(),
            BodyFraming::Length(5)
        );
        assert_eq!(rewrite(&["Content-Length: 0"]).unwrap(), BodyFraming::Empty);
        assert_eq!(
            rewrite(&["Transfer-Encoding: gzip", "Transfer-Encoding: Chunked"]).unwrap(),
            BodyFraming::Chunked
        );
        assert!(
            rewrite_absolute_request(
                "POST http://example.com/ HTTP/1.0",
                &["Transfer-Encoding: chunked"]
            )
            .is_err()
        );
    }

    impl BodySink for Vec<u8> {
        async fn send(&mut self, content: &[u8]) -> Result<()> {
            self.extend_from_slice(content);
            Ok(())
        }
    }

    async fn forward(input: &[u8], framing: BodyFraming) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut reader = BufReader::with_capacity(7, input);
        let mut sink = Vec::new();
        forward_body(&mut reader, &mut sink, framing, b"HEAD|".to_vec()).await?;
        let mut rest = Vec::new();
        reader.read_to_end(&mut rest).await?;
        Ok((sink, rest))
    }

    #[tokio::test]
    async fn forwards_only_the_first_request_body() {
        let next =
            b"GET http://other.example/ HTTP/1.1\r\nProxy-Authorization: Basic c2VjcmV0\r\n\r\n";

        let mut input = b"hello world".to_vec();
        input.extend_from_slice(next);
        let (sent, rest) = forward(&input, BodyFraming::Length(11)).await.unwrap();
        assert_eq!(sent, b"HEAD|hello world");
        assert_eq!(rest, next);

        let body = b"5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nX-Trailer: 1\r\n\r\n";
        let mut input = body.to_vec();
        input.extend_from_slice(next);
        let (sent, rest) = forward(&input, BodyFraming::Chunked).await.unwrap();
        assert_eq!(&sent[..5], b"HEAD|");
        assert_eq!(&sent[5..], body);
        assert_eq!(rest, next);

        let (sent, rest) = forward(next, BodyFraming::Empty).await.unwrap();
        assert_eq!(sent, b"HEAD|");
        assert_eq!(rest, next);
    }

    struct ChannelSink(tokio::sync::mpsc::UnboundedSender<Vec<u8>>);

    impl BodySink for ChannelSink {
        async fn send(&mut self, content: &[u8]) -> Result<()> {
            self.0.send(content.to_vec())?;
            Ok(())
        }
    }

    #[tokio::test]
    async fn sends_head_before_waiting_for_the_body() {
        // `Expect: 100-continue` clients wait for the origin before sending
        // the body, so the head must not be held back until the body arrives.
        let (mut client, proxy) = tokio::io::duplex(1024);
        let (sender, mut sent) = tokio::sync::mpsc::unbounded_channel();
        let forwarding = tokio::spawn(async move {
            let mut reader = BufReader::new(proxy);
            forward_body(
                &mut reader,
                &mut ChannelSink(sender),
                BodyFraming::Length(5),
                b"HEAD|".to_vec(),
            )
            .await
        });
        assert_eq!(sent.recv().await.unwrap(), b"HEAD|");
        client.write_all(b"hello").await.unwrap();
        forwarding.await.unwrap().unwrap();
        assert_eq!(sent.recv().await.unwrap(), b"hello");
        assert!(sent.recv().await.is_none());
    }

    #[tokio::test]
    async fn rejects_malformed_chunked_bodies() {
        for body in [
            &b"z\r\nhello\r\n0\r\n\r\n"[..],
            b"5\r\nhelloXX0\r\n\r\n",
            b"5\nhello\r\n0\r\n\r\n",
            b"10000000000000000\r\n",
            b"5\r\nhel",
        ] {
            assert!(
                forward(body, BodyFraming::Chunked).await.is_err(),
                "{body:?}"
            );
        }
        assert!(forward(b"short", BodyFraming::Length(6)).await.is_err());
    }
}
