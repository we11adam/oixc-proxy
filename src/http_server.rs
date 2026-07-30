use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use crate::gateway::{GatewayManager, HEALTH_PATH, PROVIDER_PATH};

pub async fn serve(listener: TcpListener, manager: Arc<GatewayManager>) -> Result<()> {
    loop {
        let (connection, _) = listener
            .accept()
            .await
            .map_err(|_| anyhow::anyhow!("accept nodelist HTTP connection"))?;
        let manager = manager.clone();
        tokio::spawn(async move {
            let _ = serve_connection(connection, manager).await;
        });
    }
}

async fn serve_connection(mut connection: TcpStream, manager: Arc<GatewayManager>) -> Result<()> {
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
    let path = fields.next().unwrap_or("");
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
        PROVIDER_PATH => {
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
            match manager.provider().await {
                Ok(provider) => {
                    write_response(
                        &mut connection,
                        200,
                        "OK",
                        &[
                            ("Content-Type", "text/plain; charset=utf-8"),
                            ("Cache-Control", "no-store"),
                            ("X-Content-Type-Options", "nosniff"),
                        ],
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
                        &[],
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

async fn read_headers(connection: &mut TcpStream) -> Result<Vec<u8>> {
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
    connection: &mut TcpStream,
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
