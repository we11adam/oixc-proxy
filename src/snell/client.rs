use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncRead, AsyncWrite, BufReader, ReadBuf, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Semaphore};
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;

use crate::transport::EchDialer;

use super::{
    Exporter, RecordReader, RecordWriter, ZeroRecord, build_connect_request, build_identity_v2,
    build_udp_associate_request, decode_udp_response, encode_udp_request,
};

const INITIAL_FRAME_BUDGET: usize = 0x491;
const READ_BUFFER_SIZE: usize = 32 << 10;
type TransportReadHalf = BufReader<ReadHalf<ClientTransportStream>>;
type TransportWriteHalf = WriteHalf<ClientTransportStream>;

#[derive(Clone)]
pub struct SnellDialer {
    inner: SnellDialerKind,
}

#[derive(Clone)]
enum SnellDialerKind {
    Ech(EchDialer),
    #[cfg(feature = "benchmark")]
    Direct {
        address: SocketAddr,
        exporter: Exporter,
        timeout: Duration,
    },
}

struct DialedTransport {
    stream: ClientTransportStream,
    exporter: Exporter,
}

// Keep the production TLS stream inline. Boxing it only to make the
// benchmark-only TCP variant similarly sized would change the code being
// measured and add an allocation to every real node connection.
#[cfg_attr(feature = "benchmark", allow(clippy::large_enum_variant))]
enum ClientTransportStream {
    Ech(TlsStream<TcpStream>),
    #[cfg(feature = "benchmark")]
    Direct(TcpStream),
}

impl From<EchDialer> for SnellDialer {
    fn from(value: EchDialer) -> Self {
        Self {
            inner: SnellDialerKind::Ech(value),
        }
    }
}

impl SnellDialer {
    #[cfg(feature = "benchmark")]
    pub fn direct_for_benchmark(
        address: SocketAddr,
        exporter: Exporter,
        timeout: Duration,
    ) -> Result<Self> {
        if timeout.is_zero() || timeout > Duration::from_secs(120) {
            bail!("benchmark transport timeout is invalid");
        }
        Ok(Self {
            inner: SnellDialerKind::Direct {
                address,
                exporter,
                timeout,
            },
        })
    }

    async fn dial(&self) -> Result<DialedTransport> {
        match &self.inner {
            SnellDialerKind::Ech(dialer) => {
                let connection = dialer.dial().await?;
                Ok(DialedTransport {
                    stream: ClientTransportStream::Ech(connection.stream),
                    exporter: connection.exporter,
                })
            }
            #[cfg(feature = "benchmark")]
            SnellDialerKind::Direct {
                address,
                exporter,
                timeout: dial_timeout,
            } => {
                let stream = timeout(*dial_timeout, TcpStream::connect(*address))
                    .await
                    .map_err(|_| anyhow::anyhow!("benchmark transport timed out"))?
                    .context("connect benchmark transport")?;
                stream.set_nodelay(true).ok();
                Ok(DialedTransport {
                    stream: ClientTransportStream::Direct(stream),
                    exporter: *exporter,
                })
            }
        }
    }
}

impl ClientTransportStream {
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        match self {
            Self::Ech(stream) => stream.get_ref().0.local_addr(),
            #[cfg(feature = "benchmark")]
            Self::Direct(stream) => stream.local_addr(),
        }
    }
}

impl AsyncRead for ClientTransportStream {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Ech(stream) => Pin::new(stream).poll_read(context, buffer),
            #[cfg(feature = "benchmark")]
            Self::Direct(stream) => Pin::new(stream).poll_read(context, buffer),
        }
    }
}

impl AsyncWrite for ClientTransportStream {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Ech(stream) => Pin::new(stream).poll_write(context, buffer),
            #[cfg(feature = "benchmark")]
            Self::Direct(stream) => Pin::new(stream).poll_write(context, buffer),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Ech(stream) => Pin::new(stream).poll_flush(context),
            #[cfg(feature = "benchmark")]
            Self::Direct(stream) => Pin::new(stream).poll_flush(context),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Ech(stream) => Pin::new(stream).poll_shutdown(context),
            #[cfg(feature = "benchmark")]
            Self::Direct(stream) => Pin::new(stream).poll_shutdown(context),
        }
    }
}

#[derive(Clone)]
pub struct SnellClient {
    inner: Arc<ClientInner>,
}

#[derive(Clone)]
pub struct SnellClientOptions {
    pub node_name: String,
    pub psk: String,
    pub reuse: bool,
    pub max_idle: usize,
    pub max_uses: usize,
    pub idle_timeout: Duration,
    pub handshake_timeout: Duration,
    pub close_timeout: Duration,
    pub dialer: SnellDialer,
    pub dial_limit: Option<Arc<Semaphore>>,
    pub dial_limit_timeout: Duration,
}

struct ClientInner {
    options: SnellClientOptions,
    idle: Mutex<Vec<IdleConnection>>,
    closed: AtomicBool,
}

struct IdleConnection {
    physical: PhysicalConnection,
    uses: usize,
    idle_since: Instant,
}

struct PhysicalConnection {
    reader: SnellReader,
    writer: RecordWriter<TransportWriteHalf>,
    local_addr: SocketAddr,
}

struct SnellReader {
    records: RecordReader<TransportReadHalf>,
    buffered: Vec<u8>,
    buffered_offset: usize,
    server_eof: bool,
    reply_pending: bool,
    reply_error: Option<String>,
}

pub struct SnellSession {
    physical: PhysicalConnection,
    client: SnellClient,
    uses: usize,
    reusable: bool,
}

pub struct SnellSessionReader<'a> {
    reader: &'a mut SnellReader,
}

pub struct SnellSessionWriter<'a> {
    writer: &'a mut RecordWriter<TransportWriteHalf>,
    reusable: bool,
}

pub struct SnellPacketSession {
    reader: Mutex<SnellReader>,
    writer: Mutex<RecordWriter<TransportWriteHalf>>,
    local_addr: SocketAddr,
}

impl SnellClient {
    pub fn new(options: SnellClientOptions) -> Result<Self> {
        if options.psk.is_empty() {
            bail!("Snell PSK and transport dialer are required");
        }
        if options.handshake_timeout.is_zero()
            || options.handshake_timeout > Duration::from_secs(120)
        {
            bail!("Snell handshake timeout is invalid");
        }
        if options.close_timeout.is_zero() || options.close_timeout > Duration::from_secs(30) {
            bail!("Snell reuse close timeout is invalid");
        }
        if options.reuse {
            if options.max_idle == 0 || options.max_idle > 128 {
                bail!("Snell reuse max idle is invalid");
            }
            if options.max_uses == 0 || options.max_uses > 1024 {
                bail!("Snell reuse max uses is invalid");
            }
            if options.idle_timeout.is_zero() || options.idle_timeout > Duration::from_secs(600) {
                bail!("Snell reuse idle timeout is invalid");
            }
        }
        Ok(Self {
            inner: Arc::new(ClientInner {
                options,
                idle: Mutex::new(Vec::new()),
                closed: AtomicBool::new(false),
            }),
        })
    }

    pub async fn dial_tcp(&self, host: &str, port: u16) -> Result<SnellSession> {
        if self.inner.closed.load(Ordering::Acquire) {
            bail!("Snell client is closed");
        }
        if self.inner.options.reuse {
            while let Some(mut idle) = self.take_idle().await {
                if idle
                    .physical
                    .start_reuse(host, port, self.inner.options.handshake_timeout)
                    .await
                    .is_ok()
                {
                    idle.uses += 1;
                    return Ok(SnellSession {
                        physical: idle.physical,
                        client: self.clone(),
                        uses: idle.uses,
                        reusable: true,
                    });
                }
                idle.physical.retire().await;
            }
        }

        let physical = self.open_tcp(host, port, self.inner.options.reuse).await?;
        Ok(SnellSession {
            physical,
            client: self.clone(),
            uses: 1,
            reusable: self.inner.options.reuse,
        })
    }

    pub async fn dial_udp(&self) -> Result<SnellPacketSession> {
        let physical = self
            .open_command(&build_udp_associate_request(), false)
            .await?;
        Ok(SnellPacketSession {
            reader: Mutex::new(physical.reader),
            writer: Mutex::new(physical.writer),
            local_addr: physical.local_addr,
        })
    }

    pub async fn close(&self) {
        if self.inner.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let idle = std::mem::take(&mut *self.inner.idle.lock().await);
        for entry in idle {
            entry.physical.retire().await;
        }
    }

    async fn open_tcp(&self, host: &str, port: u16, reuse: bool) -> Result<PhysicalConnection> {
        let request = build_connect_request(host, port, reuse)?;
        self.open_command(&request, true).await
    }

    async fn open_command(&self, request: &[u8], defer_reply: bool) -> Result<PhysicalConnection> {
        let _permit = if let Some(limit) = &self.inner.options.dial_limit {
            Some(
                timeout(self.inner.options.dial_limit_timeout, limit.acquire())
                    .await
                    .map_err(|_| anyhow::anyhow!("ECH-TLS node connection timed out"))?
                    .map_err(|_| anyhow::anyhow!("ECH dial concurrency limiter is closed"))?,
            )
        } else {
            None
        };
        let connection = self.inner.options.dialer.dial().await?;
        let open_started = Instant::now();
        let local_addr = connection
            .stream
            .local_addr()
            .context("read Snell local address")?;
        let exporter = connection.exporter;
        let (read_half, write_half) = tokio::io::split(connection.stream);
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce)
            .map_err(|_| anyhow::anyhow!("generate Snell identity nonce"))?;
        let identity = build_identity_v2(&self.inner.options.psk, &exporter, &nonce)?;
        let mut writer = RecordWriter::new(write_half, &self.inner.options.psk, nonce)?;
        // Identity v2 carries the record salt. The first record must therefore
        // omit the ordinary salt prefix.
        writer.mark_salt_sent();
        let padding_length = initial_padding_length(request.len())?;
        let frame = writer
            .encode_frame(request, padding_length)
            .context("encode Snell CONNECT request")?;
        let mut initial_flight = Vec::with_capacity(identity.len() + frame.len());
        initial_flight.extend_from_slice(&identity);
        initial_flight.extend_from_slice(&frame);
        writer.write_raw_all(&initial_flight).await?;
        crate::perftrace::stage(
            "snell.initial_flight",
            open_started,
            true,
            &[
                ("identity_bytes", identity.len().to_string()),
                ("payload_bytes", request.len().to_string()),
                ("padding_bytes", padding_length.to_string()),
            ],
        );

        let mut physical = PhysicalConnection {
            reader: SnellReader {
                records: RecordReader::new(
                    BufReader::with_capacity(READ_BUFFER_SIZE, read_half),
                    self.inner.options.psk.clone(),
                ),
                buffered: Vec::new(),
                buffered_offset: 0,
                server_eof: false,
                reply_pending: true,
                reply_error: None,
            },
            writer,
            local_addr,
        };
        if !defer_reply {
            timeout(
                self.inner.options.handshake_timeout,
                physical.reader.ensure_reply(),
            )
            .await
            .map_err(|_| anyhow::anyhow!("Snell handshake timed out"))??;
        }
        Ok(physical)
    }

    async fn take_idle(&self) -> Option<IdleConnection> {
        loop {
            let entry = self.inner.idle.lock().await.pop()?;
            if entry.idle_since.elapsed() <= self.inner.options.idle_timeout {
                return Some(entry);
            }
            entry.physical.retire().await;
        }
    }

    async fn release(&self, physical: PhysicalConnection, uses: usize) {
        if self.inner.closed.load(Ordering::Acquire) || uses >= self.inner.options.max_uses {
            physical.retire().await;
            return;
        }
        let mut idle = self.inner.idle.lock().await;
        if idle.len() >= self.inner.options.max_idle {
            drop(idle);
            physical.retire().await;
            return;
        }
        idle.push(IdleConnection {
            physical,
            uses,
            idle_since: Instant::now(),
        });
    }
}

impl PhysicalConnection {
    async fn start_reuse(
        &mut self,
        host: &str,
        port: u16,
        operation_timeout: Duration,
    ) -> Result<()> {
        let request = build_connect_request(host, port, true)?;
        if self.reader.buffered_remaining() != 0 || !self.reader.server_eof {
            bail!("Snell connection is not ready for reuse");
        }
        self.reader.server_eof = false;
        self.reader.reply_pending = false;
        self.reader.reply_error = None;
        timeout(operation_timeout, self.writer.write_frame(&request, 0))
            .await
            .map_err(|_| anyhow::anyhow!("Snell reused CONNECT timed out"))??;
        self.reader.reply_pending = true;
        Ok(())
    }

    async fn retire(mut self) {
        let _ = self.writer.shutdown().await;
    }
}

impl SnellSession {
    pub fn local_addr(&self) -> SocketAddr {
        self.physical.local_addr
    }

    pub fn split(&mut self) -> (SnellSessionReader<'_>, SnellSessionWriter<'_>) {
        (
            SnellSessionReader {
                reader: &mut self.physical.reader,
            },
            SnellSessionWriter {
                writer: &mut self.physical.writer,
                reusable: self.reusable,
            },
        )
    }

    pub async fn read(&mut self, destination: &mut [u8]) -> Result<usize> {
        self.physical.reader.read_application(destination).await
    }

    pub async fn write(&mut self, content: &[u8]) -> Result<usize> {
        write_application(&mut self.physical.writer, content).await
    }

    pub fn close_timeout(&self) -> Duration {
        self.client.inner.options.close_timeout
    }

    pub async fn finish(mut self, clean_relay: bool, close_write_sent: bool) {
        if !self.reusable || !clean_relay {
            self.physical.retire().await;
            return;
        }
        let close_result = timeout(self.client.inner.options.close_timeout, async {
            if !close_write_sent {
                self.physical.writer.write_frame(&[], 0).await?;
            }
            self.physical.reader.complete_reuse_close().await
        })
        .await;
        if matches!(close_result, Ok(Ok(()))) {
            self.client.release(self.physical, self.uses).await;
        } else {
            self.physical.retire().await;
        }
    }
}

impl SnellSessionReader<'_> {
    pub async fn read(&mut self, destination: &mut [u8]) -> Result<usize> {
        self.reader.read_application(destination).await
    }
}

impl SnellSessionWriter<'_> {
    pub async fn write(&mut self, content: &[u8]) -> Result<usize> {
        write_application(self.writer, content).await
    }

    pub async fn close_write(&mut self) -> Result<()> {
        if self.reusable {
            self.writer.write_frame(&[], 0).await
        } else {
            self.writer.shutdown().await
        }
    }
}

impl SnellPacketSession {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub async fn write_to_host(&self, payload: &[u8], host: &str, port: u16) -> Result<usize> {
        let frame = encode_udp_request(host, port, payload)?;
        self.writer.lock().await.write_frame(&frame, 0).await?;
        Ok(payload.len())
    }

    pub async fn read_from(&self) -> Result<(SocketAddr, Vec<u8>)> {
        let mut reader = self.reader.lock().await;
        reader.ensure_reply().await?;
        let frame = reader.read_frame().await?;
        let (address, payload) = decode_udp_response(&frame)?;
        Ok((address, payload.to_vec()))
    }

    pub async fn close(self) {
        let _ = self.writer.into_inner().shutdown().await;
    }
}

impl SnellReader {
    fn buffered_remaining(&self) -> usize {
        self.buffered.len() - self.buffered_offset
    }

    pub async fn read_application(&mut self, destination: &mut [u8]) -> Result<usize> {
        self.ensure_reply().await?;
        if destination.is_empty() {
            return Ok(0);
        }
        while self.buffered_remaining() == 0 {
            match self.read_frame().await {
                Ok(payload) => {
                    self.buffered = payload;
                    self.buffered_offset = 0;
                }
                Err(error) if error.downcast_ref::<ZeroRecord>().is_some() => {
                    self.server_eof = true;
                    return Ok(0);
                }
                Err(error) => return Err(error),
            }
        }
        let length = destination.len().min(self.buffered_remaining());
        destination[..length]
            .copy_from_slice(&self.buffered[self.buffered_offset..self.buffered_offset + length]);
        self.buffered_offset += length;
        Ok(length)
    }

    async fn read_frame(&mut self) -> Result<Vec<u8>> {
        self.records.read_frame().await
    }

    async fn ensure_reply(&mut self) -> Result<()> {
        if let Some(error) = &self.reply_error {
            bail!("{error}");
        }
        if !self.reply_pending {
            return Ok(());
        }
        self.reply_pending = false;
        let result = self.read_reply().await;
        if let Err(error) = &result {
            self.reply_error = Some(error.to_string());
        }
        result
    }

    async fn read_reply(&mut self) -> Result<()> {
        let status = self.read_exact_payload(1).await?[0];
        match status {
            0 => Ok(()),
            2 => {
                let detail = self.read_exact_payload(2).await?;
                let _message = self.read_exact_payload(detail[1] as usize).await?;
                bail!("Snell server rejected the request with code {}", detail[0]);
            }
            _ => bail!("Snell server returned an unexpected status"),
        }
    }

    async fn read_exact_payload(&mut self, length: usize) -> Result<Vec<u8>> {
        while self.buffered_remaining() < length {
            let payload = self
                .read_frame()
                .await
                .map_err(|error| anyhow::anyhow!("read Snell CONNECT response: {error}"))?;
            if self.buffered_remaining() == 0 {
                self.buffered = payload;
                self.buffered_offset = 0;
            } else {
                self.buffered.extend_from_slice(&payload);
            }
        }
        let start = self.buffered_offset;
        self.buffered_offset += length;
        Ok(self.buffered[start..start + length].to_vec())
    }

    async fn complete_reuse_close(&mut self) -> Result<()> {
        self.buffered.clear();
        self.buffered_offset = 0;
        self.ensure_reply().await?;
        while !self.server_eof {
            match self.read_frame().await {
                Ok(_) => {}
                Err(error) if error.downcast_ref::<ZeroRecord>().is_some() => {
                    self.server_eof = true;
                }
                Err(error) => return Err(error.context("finish Snell reused session")),
            }
        }
        Ok(())
    }
}

fn initial_padding_length(payload_length: usize) -> Result<usize> {
    let Some(available) = INITIAL_FRAME_BUDGET.checked_sub(payload_length) else {
        return Ok(0);
    };
    if available == 0 {
        return Ok(0);
    }
    let mut random = [0u8; 2];
    getrandom::fill(&mut random)
        .map_err(|_| anyhow::anyhow!("generate Snell initial padding length"))?;
    Ok(u16::from_be_bytes(random) as usize % available + 1)
}

async fn write_application(
    writer: &mut RecordWriter<TransportWriteHalf>,
    content: &[u8],
) -> Result<usize> {
    writer.write_payload(content).await?;
    Ok(content.len())
}
