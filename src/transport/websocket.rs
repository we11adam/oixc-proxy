//! Bounded WebSocket-to-byte-stream carrier. TLS runs above this stream.
use anyhow::{Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::{Sink, SinkExt, StreamExt};
use std::future::Future;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
#[cfg(test)]
use tokio::io::AsyncReadExt;
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, DuplexStream, ReadBuf,
};
use tokio::task::JoinHandle;
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{
        Message,
        protocol::{Role, WebSocketConfig},
    },
};

const HEADER_LIMIT: usize = 64 << 10;
const FRAME_LIMIT: usize = 1 << 20;
const CHUNK: usize = 64 << 10;

pub trait IoStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> IoStream for T {}
pub type BoxStream = Box<dyn IoStream>;

/// Drop cancels the worker, including when a nested TLS handshake is cancelled.
pub struct WebSocketIo {
    stream: DuplexStream,
    task: JoinHandle<()>,
    commands: futures_channel::mpsc::Sender<Command>,
    barrier: Option<tokio::sync::oneshot::Receiver<io::Result<()>>>,
    shutdown: bool,
    shutdown_done: bool,
}
enum Command {
    Data(Vec<u8>),
    Barrier(bool, tokio::sync::oneshot::Sender<io::Result<()>>),
}
fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "WebSocket carrier closed")
}
impl Drop for WebSocketIo {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl AsyncRead for WebSocketIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, b)
    }
}
impl AsyncWrite for WebSocketIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.shutdown {
            return Poll::Ready(Err(closed()));
        }
        if b.is_empty() {
            return Poll::Ready(Ok(0));
        }
        std::task::ready!(Pin::new(&mut self.commands).poll_ready(cx)).map_err(|_| closed())?;
        let n = b.len().min(CHUNK);
        Pin::new(&mut self.commands)
            .start_send(Command::Data(b[..n].to_vec()))
            .map_err(|_| closed())?;
        Poll::Ready(Ok(n))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.shutdown_done {
            return Poll::Ready(Ok(()));
        }
        if self.barrier.is_none() {
            std::task::ready!(Pin::new(&mut self.commands).poll_ready(cx)).map_err(|_| closed())?;
            let (tx, rx) = tokio::sync::oneshot::channel();
            let close = self.shutdown;
            Pin::new(&mut self.commands)
                .start_send(Command::Barrier(close, tx))
                .map_err(|_| closed())?;
            self.barrier = Some(rx);
        }
        let result = std::task::ready!(Pin::new(self.barrier.as_mut().unwrap()).poll(cx));
        self.barrier = None;
        Poll::Ready(result.unwrap_or_else(|_| Err(closed())))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.shutdown_done {
            return Poll::Ready(Ok(()));
        }
        // Drain an earlier flush before issuing the ordered close barrier.
        if !self.shutdown {
            std::task::ready!(self.as_mut().poll_flush(cx))?;
            self.shutdown = true;
        }
        std::task::ready!(self.as_mut().poll_flush(cx))?;
        self.shutdown_done = true;
        Poll::Ready(Ok(()))
    }
}

pub fn validate_path(path: &str) -> Result<()> {
    if !path.starts_with('/')
        || path.len() > 8192
        || !path.bytes().all(|b| b.is_ascii_graphic())
        || path.contains('#')
    {
        bail!("invalid WebSocket path");
    }
    Ok(())
}

pub async fn upgrade<S: IoStream + 'static>(
    stream: S,
    host: &str,
    path: &str,
) -> Result<WebSocketIo> {
    validate_path(path)?;
    if host.is_empty()
        || host.len() > 253
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-_:[]".contains(&b))
    {
        bail!("invalid WebSocket host");
    }
    let mut nonce = [0; 16];
    getrandom::fill(&mut nonce).map_err(|_| anyhow::anyhow!("generate WebSocket nonce"))?;
    let key = STANDARD.encode(nonce);
    let mut stream = BufReader::new(stream);
    let days = crate::diagnostics::unix_now().saturating_sub(1_768_262_400) / 86_400;
    let major = 144 + days / 35;
    stream.write_all(format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36\r\n\r\n").as_bytes()).await?;
    stream.flush().await?;
    // Read only through the terminator. BufReader retains an early first frame.
    let mut head = Vec::new();
    loop {
        let b = stream.fill_buf().await?;
        if b.is_empty() {
            bail!("WebSocket upgrade response truncated");
        }
        let mut consumed = 0;
        for &byte in b {
            head.push(byte);
            consumed += 1;
            if head.len() > HEADER_LIMIT {
                bail!("WebSocket response headers exceed 64 KiB");
            }
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        stream.consume(consumed);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    validate_response(&head, &key)?;
    let config = WebSocketConfig::default()
        .max_frame_size(Some(FRAME_LIMIT))
        .max_message_size(Some(FRAME_LIMIT))
        .write_buffer_size(0)
        .max_write_buffer_size(2 * FRAME_LIMIT);
    let ws = WebSocketStream::from_raw_socket(stream, Role::Client, Some(config)).await;
    Ok(bridge(ws))
}

fn validate_response(head: &[u8], key: &str) -> Result<()> {
    let head =
        std::str::from_utf8(head).map_err(|_| anyhow::anyhow!("invalid WebSocket response"))?;
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .unwrap_or_default()
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
    if status.len() < 2 || status[0] != "HTTP/1.1" || status[1] != "101" {
        bail!("WebSocket upgrade requires HTTP 101");
    }
    let mut accept = None;
    let mut upgrade = false;
    let mut connection = false;
    for line in lines.filter(|s| !s.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("invalid WebSocket response header"))?;
        if name.eq_ignore_ascii_case("sec-websocket-accept")
            && accept.replace(value.trim()).is_some()
        {
            bail!("duplicate WebSocket accept");
        }
        if name.eq_ignore_ascii_case("upgrade") {
            upgrade = value.trim().eq_ignore_ascii_case("websocket");
        }
        if name.eq_ignore_ascii_case("connection") {
            connection |= value
                .split(',')
                .any(|v| v.trim().eq_ignore_ascii_case("upgrade"));
        }
        if name.eq_ignore_ascii_case("sec-websocket-extensions")
            || name.eq_ignore_ascii_case("sec-websocket-protocol")
        {
            bail!("unsolicited WebSocket extension or subprotocol");
        }
    }
    let hash = ring::digest::digest(
        &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
        format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11").as_bytes(),
    );
    if !upgrade || !connection || accept != Some(STANDARD.encode(hash.as_ref()).as_str()) {
        bail!("WebSocket upgrade validation failed");
    }
    Ok(())
}

fn bridge<S: IoStream + 'static>(ws: WebSocketStream<S>) -> WebSocketIo {
    let (stream, worker) = tokio::io::duplex(CHUNK);
    let (commands, mut queued) = futures_channel::mpsc::channel::<Command>(2);
    let task = tokio::spawn(async move {
        let (sink, mut source) = ws.split();
        let sink = std::sync::Arc::new(tokio::sync::Mutex::new(sink));
        let mut write = worker;
        let upload = async {
            while let Some(command) = queued.next().await {
                match command {
                    Command::Data(data) => {
                        if sink
                            .lock()
                            .await
                            .send(Message::Binary(data.into()))
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                    Command::Barrier(close, ack) => {
                        let result = if close {
                            sink.lock().await.close().await
                        } else {
                            sink.lock().await.flush().await
                        };
                        let failed = result.is_err();
                        let _ = ack.send(result.map_err(|_| closed()));
                        if failed || close {
                            return;
                        }
                    }
                }
            }
        };
        let download = async {
            while let Some(message) = source.next().await {
                match message {
                    Ok(Message::Binary(data)) => {
                        if write.write_all(&data).await.is_err() {
                            return;
                        }
                    }
                    Ok(Message::Ping(_)) => {
                        if sink.lock().await.flush().await.is_err() {
                            return;
                        }
                    }
                    Ok(Message::Pong(_)) => {}
                    Ok(Message::Close(_)) => {
                        let _ = sink.lock().await.flush().await;
                        return;
                    }
                    _ => return,
                }
            }
        };
        tokio::select! {_ = upload=>{}, _ = download=>{}}
    });
    WebSocketIo {
        stream,
        task,
        commands,
        barrier: None,
        shutdown: false,
        shutdown_done: false,
    }
}

#[cfg(test)]
pub(crate) async fn test_server<S: IoStream + 'static>(mut stream: S) -> Result<WebSocketIo> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(stream.read_u8().await?);
        if head.len() > HEADER_LIMIT {
            bail!("test headers too large");
        }
    }
    let head = String::from_utf8(head)?;
    assert!(head.starts_with("GET /carrier HTTP/1.1\r\nHost: localhost\r\n"));
    let key = head
        .lines()
        .find_map(|l| l.strip_prefix("Sec-WebSocket-Key: "))
        .unwrap();
    assert_eq!(STANDARD.decode(key)?.len(), 16);
    let digest = ring::digest::digest(
        &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
        format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11").as_bytes(),
    );
    stream.write_all(format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",STANDARD.encode(digest.as_ref())).as_bytes()).await?;
    stream.flush().await?;
    Ok(bridge(
        WebSocketStream::from_raw_socket(stream, Role::Server, None).await,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn duplex_backpressure_flush_and_cancellation() {
        let (client, server) = tokio::io::duplex(4096);
        let server = tokio::spawn(async move {
            let server = test_server(server).await.unwrap();
            let (mut r, mut w) = tokio::io::split(server);
            let upload = async {
                w.write_all(&vec![7; 300_000]).await.unwrap();
                w.flush().await.unwrap();
            };
            let download = async {
                let mut b = vec![0; 300_000];
                r.read_exact(&mut b).await.unwrap();
                assert!(b.iter().all(|b| *b == 9));
            };
            tokio::join!(upload, download);
        });
        let client = upgrade(client, "localhost", "/carrier").await.unwrap();
        let abort = client.task.abort_handle();
        let (mut r, mut w) = tokio::io::split(client);
        let upload = async {
            w.write_all(&vec![9; 300_000]).await.unwrap();
            w.flush().await.unwrap();
        };
        let download = async {
            let mut b = vec![0; 300_000];
            r.read_exact(&mut b).await.unwrap();
            assert!(b.iter().all(|b| *b == 7));
        };
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            tokio::join!(upload, download);
        })
        .await
        .unwrap();
        drop((r, w));
        tokio::task::yield_now().await;
        assert!(abort.is_finished());
        server.await.unwrap();
    }
    #[tokio::test]
    async fn headers_and_early_frame_share_a_read_and_headers_are_bounded() {
        let (client, mut server) = tokio::io::duplex(100_000);
        let task = tokio::spawn(async move {
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(server.read_u8().await.unwrap());
            }
            let request = String::from_utf8(request).unwrap();
            let key = request
                .lines()
                .find_map(|l| l.strip_prefix("Sec-WebSocket-Key: "))
                .unwrap();
            let hash = ring::digest::digest(
                &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
                format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11").as_bytes(),
            );
            let mut response=format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",STANDARD.encode(hash.as_ref())).into_bytes();
            response.extend([0x82, 5]);
            response.extend(b"early");
            server.write_all(&response).await.unwrap();
            // Keep the transport alive while its first frame is consumed.
            let mut b = [0; 1];
            let _ = server.read(&mut b).await;
        });
        let mut client = upgrade(client, "localhost", "/carrier").await.unwrap();
        let mut b = [0; 5];
        client.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"early");
        drop(client);
        task.await.unwrap();
        let (client, mut server) = tokio::io::duplex(100_000);
        server
            .write_all(&vec![b'a'; HEADER_LIMIT + 1])
            .await
            .unwrap();
        assert!(upgrade(client, "localhost", "/").await.is_err());
    }
    #[test]
    fn rejects_bad_upgrade_and_injection() {
        assert!(validate_path("/\r\nInjected: x").is_err());
        assert!(validate_response(b"HTTP/1.1 200 OK\r\n\r\n", "x").is_err());
        let response=b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
        assert!(validate_response(response, "dGhlIHNhbXBsZSBub25jZQ==").is_ok());
        assert!(validate_response(response, "wrong").is_err());
    }
}
