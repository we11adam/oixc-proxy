use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use crate::gateway::{
    CLASH_PROVIDER_PATH, GatewayManager, HEALTH_PATH, PROVIDER_PATH, STATUS_PATH,
};

pub async fn serve(listener: TcpListener, manager: Arc<GatewayManager>) -> Result<()> {
    loop {
        let connection = crate::accept::accept(&listener, "nodelist HTTP")
            .await
            .context("accept nodelist HTTP connection")?;
        let manager = manager.clone();
        tokio::spawn(async move {
            let _ = serve_connection(connection, manager).await;
        });
    }
}

async fn serve_connection(connection: TcpStream, manager: Arc<GatewayManager>) -> Result<()> {
    let peer = connection.peer_addr()?.ip();
    serve_http(connection, manager, peer).await
}

async fn serve_http(
    mut connection: impl AsyncRead + AsyncWrite + Unpin,
    manager: Arc<GatewayManager>,
    peer: IpAddr,
) -> Result<()> {
    let request = timeout(Duration::from_secs(5), read_headers(&mut connection))
        .await
        .map_err(|_| anyhow::anyhow!("nodelist HTTP header timed out"))??;
    let first_line = request
        .split(|byte| *byte == b'\n')
        .next()
        .ok_or_else(|| anyhow::anyhow!("invalid HTTP request"))?;
    let first_line = String::from_utf8_lossy(first_line);
    let mut fields = first_line.trim_end_matches('\r').split_whitespace();
    let method = fields.next().unwrap_or("");
    let target = fields.next().unwrap_or("");
    let (path, query) = split_target(target);
    if fields.next().is_none() {
        return write_response(
            &mut connection,
            400,
            "Bad Request",
            &[],
            b"bad request\n",
            method == "HEAD",
        )
        .await;
    }

    match path {
        STATUS_PATH => {
            if method != "GET" && method != "HEAD" {
                return write_response(
                    &mut connection,
                    405,
                    "Method Not Allowed",
                    &[("Allow", "GET, HEAD")],
                    b"method not allowed\n",
                    method == "HEAD",
                )
                .await;
            }
            let body = serde_json::to_vec(&manager.status().await)?;
            write_response(
                &mut connection,
                200,
                "OK",
                &[
                    ("Content-Type", "application/json"),
                    ("Cache-Control", "no-store"),
                    ("X-Content-Type-Options", "nosniff"),
                ],
                &body,
                method == "HEAD",
            )
            .await
        }
        HEALTH_PATH => {
            if method != "GET" && method != "HEAD" {
                write_response(
                    &mut connection,
                    405,
                    "Method Not Allowed",
                    &[("Allow", "GET, HEAD")],
                    b"method not allowed\n",
                    method == "HEAD",
                )
                .await
            } else {
                write_response(&mut connection, 204, "No Content", &[], &[], true).await
            }
        }
        PROVIDER_PATH | CLASH_PROVIDER_PATH => {
            if method != "GET" && method != "HEAD" {
                return write_response(
                    &mut connection,
                    405,
                    "Method Not Allowed",
                    &[("Allow", "GET, HEAD")],
                    b"method not allowed\n",
                    method == "HEAD",
                )
                .await;
            }
            let include_all = query_flag(query, "all");
            let socks = query_flag(query, "socks");
            let raw = path == PROVIDER_PATH && query_flag(query, "raw");
            let (provider, content_type) = if path == CLASH_PROVIDER_PATH {
                (
                    manager.clash_provider(include_all, socks).await,
                    "text/yaml; charset=utf-8",
                )
            } else if raw {
                let provider = match manager.raw_provider(include_all, peer).await {
                    Ok(Some(document)) => Ok(document),
                    Ok(None) => {
                        return write_response(
                            &mut connection,
                            403,
                            "Forbidden",
                            &[("Cache-Control", "no-store")],
                            b"raw provider requires a loopback peer\n",
                            method == "HEAD",
                        )
                        .await;
                    }
                    Err(error) => Err(error),
                };
                (provider, "text/plain; charset=utf-8")
            } else {
                (
                    manager.provider(include_all, socks).await,
                    "text/plain; charset=utf-8",
                )
            };
            match provider {
                Ok(provider) => {
                    let subscription = if path == CLASH_PROVIDER_PATH {
                        manager.subscription_header().await
                    } else {
                        None
                    };
                    let mut headers = vec![
                        ("Content-Type", content_type),
                        ("Cache-Control", "no-store"),
                        ("X-Content-Type-Options", "nosniff"),
                    ];
                    if let Some(value) = subscription.as_deref() {
                        headers.push(("Subscription-Userinfo", value));
                    }
                    write_response(
                        &mut connection,
                        200,
                        "OK",
                        &headers,
                        &provider,
                        method == "HEAD",
                    )
                    .await
                }
                Err(_) => {
                    write_response(
                        &mut connection,
                        503,
                        "Service Unavailable",
                        if raw {
                            &[("Cache-Control", "no-store")]
                        } else {
                            &[]
                        },
                        b"gateway unavailable\n",
                        method == "HEAD",
                    )
                    .await
                }
            }
        }
        _ => {
            write_response(
                &mut connection,
                404,
                "Not Found",
                &[("Content-Type", "text/plain; charset=utf-8")],
                b"404 page not found\n",
                method == "HEAD",
            )
            .await
        }
    }
}

fn split_target(target: &str) -> (&str, &str) {
    target.split_once('?').unwrap_or((target, ""))
}

fn query_flag(query: &str, name: &str) -> bool {
    query
        .split('&')
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            (key == name).then_some(value)
        })
        .next_back()
        == Some("1")
}

async fn read_headers(connection: &mut (impl AsyncRead + Unpin)) -> Result<Vec<u8>> {
    let mut request = Vec::with_capacity(1024);
    let mut buffer = [0u8; 1024];
    loop {
        let read = connection.read(&mut buffer).await?;
        if read == 0 {
            bail!("unexpected EOF in HTTP request");
        }
        request.extend_from_slice(&buffer[..read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(request);
        }
        if request.len() > 8 << 10 {
            bail!("HTTP request headers are too large");
        }
    }
}

async fn write_response(
    connection: &mut (impl AsyncWrite + Unpin),
    status: u16,
    reason: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    head: bool,
) -> Result<()> {
    let mut response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in headers {
        response.push_str(name);
        response.push_str(": ");
        response.push_str(value);
        response.push_str("\r\n");
    }
    response.push_str("\r\n");
    connection.write_all(response.as_bytes()).await?;
    if !head {
        connection.write_all(body).await?;
    }
    connection.shutdown().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn request_for_test(manager: Arc<GatewayManager>, method: &str, path: &str) -> String {
        request_from_peer(manager, method, path, "127.0.0.1").await
    }

    async fn request_from_peer(
        manager: Arc<GatewayManager>,
        method: &str,
        path: &str,
        peer: &str,
    ) -> String {
        let (mut client, server) = tokio::io::duplex(65536);
        let task = tokio::spawn(serve_http(server, manager, peer.parse().unwrap()));
        client
            .write_all(format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut bytes = Vec::new();
        client.read_to_end(&mut bytes).await.unwrap();
        task.await.unwrap().unwrap();
        String::from_utf8(bytes).unwrap()
    }

    #[tokio::test]
    async fn raw_export_guard_uses_peer_not_forwarded_headers_and_allows_explicit_opt_in() {
        let manager = Arc::new(GatewayManager::provider_for_test());
        for peer in ["127.0.0.1", "127.0.0.2", "::1", "::ffff:127.0.0.1"] {
            let response =
                request_from_peer(manager.clone(), "GET", "/surge-proxies.conf?raw=1", peer).await;
            assert!(response.starts_with("HTTP/1.1 200"));
            assert!(response.contains("Cache-Control: no-store"));
            assert!(response.contains(" = snell, node.example.test, 443, psk=mock-secret,"));
        }
        for peer in ["192.0.2.1", "2001:db8::1", "::ffff:192.0.2.1"] {
            for method in ["GET", "HEAD"] {
                let response =
                    request_from_peer(manager.clone(), method, "/surge-proxies.conf?raw=1", peer)
                        .await;
                assert!(response.starts_with("HTTP/1.1 403"));
                assert!(response.contains("Cache-Control: no-store"));
                assert!(!response.contains("mock-secret"));
                assert!(!response.contains("node.example.test"));
                if method == "HEAD" {
                    assert!(response.ends_with("\r\n\r\n"));
                }
            }
            let permitted = Arc::new(GatewayManager::raw_provider_for_test(true));
            assert!(
                request_from_peer(permitted, "GET", "/surge-proxies.conf?raw=1", peer)
                    .await
                    .starts_with("HTTP/1.1 200")
            );
        }
        let (mut client, server) = tokio::io::duplex(65536);
        let task = tokio::spawn(serve_http(server, manager, "192.0.2.1".parse().unwrap()));
        client.write_all(b"GET /surge-proxies.conf?raw=1 HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 127.0.0.1\r\nForwarded: for=127.0.0.1\r\n\r\n").await.unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).await.unwrap();
        task.await.unwrap().unwrap();
        assert!(response.starts_with("HTTP/1.1 403"));
    }

    #[tokio::test]
    async fn raw_combines_all_ignores_socks_and_head_omits_secrets() {
        let manager = Arc::new(GatewayManager::provider_for_test());
        let filtered = request_for_test(manager.clone(), "GET", "/surge-proxies.conf?raw=1").await;
        assert_eq!(
            filtered,
            request_for_test(manager.clone(), "GET", "/surge-proxies.conf?raw=1&socks=1").await
        );
        let all = request_for_test(manager.clone(), "GET", "/surge-proxies.conf?raw=1&all=1").await;
        assert!(filtered.contains("Mock Fusion 01 = snell,"));
        assert!(!filtered.contains("Mock Extra 02"));
        assert!(all.contains("Mock Extra 02 = snell,"));
        assert_eq!(
            all,
            request_for_test(
                manager.clone(),
                "GET",
                "/surge-proxies.conf?all=1&raw=1&socks=1"
            )
            .await
        );
        let head =
            request_for_test(manager.clone(), "HEAD", "/surge-proxies.conf?raw=1&all=1").await;
        assert_eq!(
            head,
            format!("{}\r\n\r\n", all.split_once("\r\n\r\n").unwrap().0)
        );
        assert!(
            request_for_test(manager.clone(), "POST", "/surge-proxies.conf?raw=1")
                .await
                .starts_with("HTTP/1.1 405")
        );
        manager.close().await;
        let unavailable = request_for_test(manager, "GET", "/surge-proxies.conf?raw=1").await;
        assert!(unavailable.starts_with("HTTP/1.1 503"));
        assert!(unavailable.contains("Cache-Control: no-store"));
    }

    #[tokio::test]
    async fn without_raw_provider_bytes_and_query_flag_semantics_are_unchanged() {
        let manager = Arc::new(GatewayManager::provider_for_test());
        let selector = crate::surge::node_selector("Mock Fusion 01").unwrap();
        assert_eq!(
            manager.provider(false, false).await.unwrap().as_ref(),
            format!("Mock Fusion 01 = http, 127.0.0.1, 6172, {selector}, mock-secret\n").as_bytes()
        );
        for (path, clash) in [
            ("/surge-proxies.conf", false),
            ("/clash-proxies.yaml", true),
        ] {
            for all in [false, true] {
                for socks in [false, true] {
                    let query = format!("all={}&socks={}", u8::from(all), u8::from(socks));
                    let target = format!("{path}?{query}");
                    let response =
                        request_from_peer(manager.clone(), "GET", &target, "192.0.2.1").await;
                    let expected = if clash {
                        manager.clash_provider(all, socks).await.unwrap()
                    } else {
                        manager.provider(all, socks).await.unwrap()
                    };
                    assert_eq!(
                        response.split_once("\r\n\r\n").unwrap().1.as_bytes(),
                        expected.as_ref()
                    );
                    for flag in ["raw=0", "raw=true", "raw=1&raw=0"] {
                        assert_eq!(
                            response,
                            request_from_peer(
                                manager.clone(),
                                "GET",
                                &format!("{target}&{flag}"),
                                "192.0.2.1"
                            )
                            .await
                        );
                    }
                    if clash {
                        assert_eq!(
                            response,
                            request_from_peer(
                                manager.clone(),
                                "GET",
                                &format!("{target}&raw=1"),
                                "192.0.2.1"
                            )
                            .await
                        );
                    }
                }
            }
        }
        assert!(
            request_from_peer(
                manager,
                "GET",
                "/surge-proxies.conf?raw=0&raw=1",
                "192.0.2.1"
            )
            .await
            .starts_with("HTTP/1.1 403")
        );
    }

    #[tokio::test]
    async fn clash_get_and_head_publish_only_fresh_valid_userinfo() {
        let manager = Arc::new(GatewayManager::provider_for_test());
        let info =
            crate::subscription::UserInfo::parse("upload=1;download=2;total=100;expire=1700000000")
                .unwrap();
        manager
            .update_subscription(Some(info.clone()), Some(crate::diagnostics::unix_now()))
            .await;
        for method in ["GET", "HEAD"] {
            let response =
                request_for_test(manager.clone(), method, "/clash-proxies.yaml?all=1&socks=1")
                    .await;
            let (headers, body) = response.split_once("\r\n\r\n").unwrap();
            assert!(headers.contains(
                "Subscription-Userinfo: upload=1; download=2; total=100; expire=1700000000"
            ));
            assert!(headers.contains("200 OK"));
            if method == "HEAD" {
                assert!(body.is_empty());
            } else {
                assert!(!body.is_empty());
            }
        }
        assert!(
            !request_for_test(manager.clone(), "GET", "/surge-proxies.conf")
                .await
                .contains("Subscription-Userinfo")
        );
        manager
            .update_subscription(
                Some(info),
                Some(crate::diagnostics::unix_now() - crate::subscription::MAX_USERINFO_AGE - 1),
            )
            .await;
        assert!(
            !request_for_test(manager.clone(), "GET", "/clash-proxies.yaml")
                .await
                .contains("Subscription-Userinfo")
        );
        manager.update_subscription(None, None).await;
        assert!(
            !request_for_test(manager.clone(), "HEAD", "/clash-proxies.yaml")
                .await
                .contains("Subscription-Userinfo")
        );
        manager.close().await;
        assert!(manager.subscription_header().await.is_none());
    }

    #[tokio::test]
    async fn status_reports_failures_and_head_omits_body() {
        let manager = Arc::new(GatewayManager::empty_for_test());
        manager.initialize_status(true, Some(crate::diagnostics::unix_now() - 90));
        manager.refresh_started();
        let error = anyhow::Error::new(crate::diagnostics::ApiFailure {
            kind: crate::diagnostics::ErrorKind::Authentication,
            status: Some(401),
            retry_after_seconds: None,
        });
        manager.refresh_finished(Some(&error));
        for method in ["GET", "HEAD", "POST"] {
            let response = request_for_test(manager.clone(), method, "/status").await;
            let (headers, body) = response.split_once("\r\n\r\n").unwrap();
            if method == "POST" {
                assert!(headers.contains("405"));
                continue;
            }
            assert!(headers.contains("200 OK"));
            assert!(headers.contains("no-store"));
            if method == "HEAD" {
                assert!(body.is_empty());
            } else {
                let value: serde_json::Value = serde_json::from_str(body).unwrap();
                assert_eq!(value["ready"], false);
                assert_eq!(value["catalog"]["last_error"], "authentication");
                assert_eq!(value["catalog"]["refresh_failures"], 1);
                assert!(value["catalog"]["cache_age_seconds"].as_u64().unwrap() >= 90);
            }
        }
        manager.refresh_finished(None);
        assert!(manager.status().await["catalog"]["last_error"].is_null());
    }

    #[test]
    fn splits_path_from_query() {
        assert_eq!(
            split_target("/surge-proxies.conf"),
            ("/surge-proxies.conf", "")
        );
        assert_eq!(
            split_target("/surge-proxies.conf?all=1"),
            ("/surge-proxies.conf", "all=1")
        );
        assert_eq!(
            split_target("/clash-proxies.yaml?all=1&x=2"),
            ("/clash-proxies.yaml", "all=1&x=2")
        );
    }

    #[test]
    fn query_flag_accepts_only_name_equals_one() {
        assert!(!query_flag("", "all"));
        assert!(query_flag("all=1", "all"));
        assert!(query_flag("foo=bar&all=1", "all"));
        assert!(query_flag("all=1&foo=bar", "all"));
        assert!(query_flag("all=0&all=1", "all"));
        assert!(!query_flag("all=1&all=0", "all"));
        assert!(!query_flag("all=0", "all"));
        assert!(!query_flag("all=true", "all"));
        assert!(!query_flag("all=", "all"));
        assert!(!query_flag("all", "all"));
        assert!(!query_flag("ALL=1", "all"));
        assert!(!query_flag("ball=1", "all"));
        assert!(!query_flag("all=11", "all"));
        assert!(query_flag("all=1&socks=1", "socks"));
        assert!(!query_flag("all=1", "socks"));
        assert!(!query_flag("socks=true", "socks"));
    }
}
