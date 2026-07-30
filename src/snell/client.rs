use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Semaphore};
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;

use crate::transport::EchDialer;

use super::{
    RecordReader, RecordWriter, ZeroRecord, build_connect_request, build_identity_v2,
    build_udp_associate_request, decode_udp_response, encode_udp_request,
};

const INITIAL_FRAME_BUDGET: usize = 0x491;
const MAX_RECORD_PAYLOAD_SIZE: usize = (1 << 14) - 1;
type TlsReadHalf = ReadHalf<TlsStream<TcpStream>>;
type TlsWriteHalf = WriteHalf<TlsStream<TcpStream>>;

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
    pub dialer: EchDialer,
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

#[derive(Clone)]
struct PhysicalConnection {
    reader: Arc<Mutex<SnellReader>>,
    writer: Arc<Mutex<RecordWriter<TlsWriteHalf>>>,
    local_addr: SocketAddr,
}

struct SnellReader {
    records: RecordReader<TlsReadHalf>,
    buffered: VecDeque<u8>,
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

pub struct SnellPacketSession {
    physical: PhysicalConnection,
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
        Ok(SnellPacketSession { physical })
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
            .get_ref()
            .0
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

        let physical = PhysicalConnection {
            reader: Arc::new(Mutex::new(SnellReader {
                records: RecordReader::new(read_half, self.inner.options.psk.clone()),
                buffered: VecDeque::new(),
                server_eof: false,
                reply_pending: true,
                reply_error: None,
            })),
            writer: Arc::new(Mutex::new(writer)),
            local_addr,
        };
        if !defer_reply {
            timeout(
                self.inner.options.handshake_timeout,
                physical.reader.lock().await.ensure_reply(),
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
        {
            let mut reader = self.reader.lock().await;
            if !reader.buffered.is_empty() || !reader.server_eof {
                bail!("Snell connection is not ready for reuse");
            }
            reader.server_eof = false;
            reader.reply_pending = false;
            reader.reply_error = None;
        }
        timeout(
            operation_timeout,
            self.writer.lock().await.write_frame(&request, 0),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Snell reused CONNECT timed out"))??;
        self.reader.lock().await.reply_pending = true;
        Ok(())
    }

    async fn retire(&self) {
        let _ = self.writer.lock().await.shutdown().await;
    }
}

impl SnellSession {
    pub fn local_addr(&self) -> SocketAddr {
        self.physical.local_addr
    }

    pub async fn read(&self, destination: &mut [u8]) -> Result<usize> {
        self.physical
            .reader
            .lock()
            .await
            .read_application(destination)
            .await
    }

    pub async fn write(&self, content: &[u8]) -> Result<usize> {
        write_application(&self.physical.writer, content).await
    }

    pub async fn close_write(&self) -> Result<()> {
        if self.reusable {
            self.physical.writer.lock().await.write_frame(&[], 0).await
        } else {
            self.physical.writer.lock().await.shutdown().await
        }
    }

    pub fn close_timeout(&self) -> Duration {
        self.client.inner.options.close_timeout
    }

    pub async fn finish(self, clean_relay: bool, close_write_sent: bool) {
        if !self.reusable || !clean_relay {
            self.physical.retire().await;
            return;
        }
        let close_result = timeout(self.client.inner.options.close_timeout, async {
            if !close_write_sent {
                self.physical
                    .writer
                    .lock()
                    .await
                    .write_frame(&[], 0)
                    .await?;
            }
            self.physical
                .reader
                .lock()
                .await
                .complete_reuse_close()
                .await
        })
        .await;
        if matches!(close_result, Ok(Ok(()))) {
            self.client.release(self.physical, self.uses).await;
        } else {
            self.physical.retire().await;
        }
    }
}

impl SnellPacketSession {
    pub fn local_addr(&self) -> SocketAddr {
        self.physical.local_addr
    }

    pub async fn write_to_host(&self, payload: &[u8], host: &str, port: u16) -> Result<usize> {
        let frame = encode_udp_request(host, port, payload)?;
        self.physical
            .writer
            .lock()
            .await
            .write_frame(&frame, 0)
            .await?;
        Ok(payload.len())
    }

    pub async fn read_from(&self) -> Result<(SocketAddr, Vec<u8>)> {
        let mut reader = self.physical.reader.lock().await;
        reader.ensure_reply().await?;
        let frame = reader.read_frame().await?;
        let (address, payload) = decode_udp_response(&frame)?;
        Ok((address, payload.to_vec()))
    }

    pub async fn close(self) {
        self.physical.retire().await;
    }
}

impl SnellReader {
    pub async fn read_application(&mut self, destination: &mut [u8]) -> Result<usize> {
        self.ensure_reply().await?;
        if destination.is_empty() {
            return Ok(0);
        }
        while self.buffered.is_empty() {
            match self.read_frame().await {
                Ok(payload) => self.buffered.extend(payload),
                Err(error) if error.downcast_ref::<ZeroRecord>().is_some() => {
                    self.server_eof = true;
                    return Ok(0);
                }
                Err(error) => return Err(error),
            }
        }
        let length = destination.len().min(self.buffered.len());
        for slot in &mut destination[..length] {
            *slot = self.buffered.pop_front().expect("length checked");
        }
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
        while self.buffered.len() < length {
            let payload = self
                .read_frame()
                .await
                .map_err(|error| anyhow::anyhow!("read Snell CONNECT response: {error}"))?;
            self.buffered.extend(payload);
        }
        Ok((0..length)
            .map(|_| self.buffered.pop_front().expect("length checked"))
            .collect())
    }

    async fn complete_reuse_close(&mut self) -> Result<()> {
        self.buffered.clear();
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

pub async fn write_application(
    writer: &Arc<Mutex<RecordWriter<TlsWriteHalf>>>,
    content: &[u8],
) -> Result<usize> {
    let mut written = 0;
    let mut writer = writer.lock().await;
    while written < content.len() {
        let end = (written + MAX_RECORD_PAYLOAD_SIZE).min(content.len());
        writer.write_frame(&content[written..end], 0).await?;
        written = end;
    }
    Ok(written)
}
