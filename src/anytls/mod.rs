//! AnyTLS v2, bounded frame parsing and per-node idle session reuse.
mod padding;
#[cfg(test)]
mod tests;
use crate::{
    nodes::Proxy,
    transport::{TransportContext, websocket::BoxStream},
};
use anyhow::{Context, Result, bail};
use padding::Scheme;
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    sync::{Mutex, Semaphore, oneshot},
    task::JoinHandle,
    time::timeout,
};

const READ_CHUNK: usize = 32 << 10;
const COMPACT_THRESHOLD: usize = 32 << 10;
const MAX_PENDING_HEARTBEATS: usize = 64;
const RETIRE_TIMEOUT: Duration = Duration::from_secs(2);

fn lock<T>(mutex: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
pub(super) fn frame(command: u8, id: u32, payload: &[u8]) -> Result<Vec<u8>> {
    let mut data = Vec::with_capacity(7 + payload.len());
    encode_frame_into(&mut data, command, id, payload)?;
    Ok(data)
}

fn encode_frame_into(out: &mut Vec<u8>, command: u8, id: u32, payload: &[u8]) -> Result<()> {
    let len = u16::try_from(payload.len()).context("AnyTLS frame too large")?;
    out.reserve(7 + payload.len());
    out.push(command);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(())
}

#[cfg(test)]
struct Frame {
    command: u8,
    id: u32,
    data: Vec<u8>,
}

struct FrameReader<R> {
    io: R,
    buffer: Vec<u8>,
    offset: usize,
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    fn new(io: R) -> Self {
        Self {
            io,
            buffer: Vec::with_capacity(READ_CHUNK),
            offset: 0,
        }
    }

    #[cfg(test)]
    async fn next(&mut self) -> Result<Frame> {
        let mut data = Vec::new();
        let (command, id) = self.next_into(&mut data).await?;
        Ok(Frame { command, id, data })
    }

    /// Reads the next frame payload into `out`, reusing its capacity.
    /// Cancel-safe: if cancelled while waiting for I/O, buffered bytes remain intact.
    async fn next_into(&mut self, out: &mut Vec<u8>) -> Result<(u8, u32)> {
        loop {
            let available = self.buffer.len() - self.offset;
            if available >= 7 {
                let len = usize::from(u16::from_be_bytes([
                    self.buffer[self.offset + 5],
                    self.buffer[self.offset + 6],
                ]));
                if available >= 7 + len {
                    let command = self.buffer[self.offset];
                    let id = u32::from_be_bytes(
                        self.buffer[self.offset + 1..self.offset + 5]
                            .try_into()
                            .unwrap(),
                    );
                    out.clear();
                    out.extend_from_slice(&self.buffer[self.offset + 7..self.offset + 7 + len]);
                    self.offset += 7 + len;
                    if self.offset == self.buffer.len() {
                        self.buffer.clear();
                        self.offset = 0;
                    }
                    return Ok((command, id));
                }
            }
            if self.offset == self.buffer.len() {
                self.buffer.clear();
                self.offset = 0;
            } else if self.offset >= COMPACT_THRESHOLD {
                self.buffer.copy_within(self.offset.., 0);
                self.buffer.truncate(available);
                self.offset = 0;
            }
            self.buffer.reserve(READ_CHUNK);
            let n = self.io.read_buf(&mut self.buffer).await?;
            if n == 0 {
                bail!("AnyTLS session ended or frame truncated");
            }
        }
    }
}

struct Writer {
    io: WriteHalf<BoxStream>,
    scheme: Arc<StdMutex<Arc<Scheme>>>,
    pending_heartbeats: Arc<StdMutex<VecDeque<u32>>>,
    packet: u32,
    scratch: Vec<u8>,
}

impl Writer {
    async fn send_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.packet = self.packet.saturating_add(1);
        let scheme = lock(&self.scheme).clone();
        if self.packet >= scheme.stop() {
            if !bytes.is_empty() {
                self.io.write_all(bytes).await?;
            }
            self.io.flush().await?;
        } else {
            padding::write(&mut self.io, &scheme, self.packet, bytes).await?;
        }
        Ok(())
    }

    async fn send(&mut self, bytes: &[u8]) -> Result<()> {
        self.send_bytes(bytes).await?;
        self.flush_pending_heartbeats().await
    }

    async fn send_frame(&mut self, command: u8, id: u32, payload: &[u8]) -> Result<()> {
        let mut scratch = std::mem::take(&mut self.scratch);
        scratch.clear();
        let encoded = encode_frame_into(&mut scratch, command, id, payload);
        let result = match encoded {
            Ok(()) => self.send_bytes(&scratch).await,
            Err(error) => Err(error),
        };
        self.scratch = scratch;
        result?;
        self.flush_pending_heartbeats().await
    }

    async fn control(&mut self, command: u8, id: u32) -> Result<()> {
        self.send_frame(command, id, &[]).await
    }

    async fn flush_pending_heartbeats(&mut self) -> Result<()> {
        loop {
            let next = lock(&self.pending_heartbeats).pop_front();
            let Some(id) = next else {
                return Ok(());
            };
            let mut scratch = std::mem::take(&mut self.scratch);
            scratch.clear();
            encode_frame_into(&mut scratch, 9, id, &[])?;
            let result = self.send_bytes(&scratch).await;
            self.scratch = scratch;
            result?;
        }
    }

    async fn shutdown(&mut self) -> Result<()> {
        self.io.shutdown().await?;
        Ok(())
    }
}

struct Physical {
    reader: FrameReader<ReadHalf<BoxStream>>,
    writer: Arc<Mutex<Writer>>,
    scheme: Arc<StdMutex<Arc<Scheme>>>,
    pending_heartbeats: Arc<StdMutex<VecDeque<u32>>>,
    local: SocketAddr,
    generation: u64,
    id: u32,
    version: u8,
    uses: usize,
    sequence: u64,
}

impl Physical {
    async fn control(&mut self, command: u8, id: u32, data: &[u8]) -> Result<bool> {
        match command {
            0 => {}
            5 => bail!("AnyTLS server rejected the session"),
            6 => {
                if id != 0 {
                    bail!("invalid AnyTLS padding stream");
                }
                let scheme = Scheme::parse(data)
                    .map_err(|_| anyhow::anyhow!("invalid AnyTLS server padding scheme"))?;
                *lock(&self.scheme) = Arc::new(scheme);
            }
            8 => {
                if !data.is_empty() {
                    bail!("invalid AnyTLS heartbeat");
                }
                // Never block the reader on an active writer that may be stalled
                // by peer backpressure: reply immediately when idle, or queue
                // for the writer to flush once its current write completes.
                if let Ok(mut writer) = self.writer.try_lock() {
                    writer.control(9, id).await?;
                } else {
                    let mut pending = lock(&self.pending_heartbeats);
                    if pending.len() >= MAX_PENDING_HEARTBEATS {
                        bail!("AnyTLS heartbeat backlog exceeded");
                    }
                    pending.push_back(id);
                }
            }
            9 => {
                if !data.is_empty() {
                    bail!("invalid AnyTLS heartbeat reply");
                }
            }
            10 => {
                if id != 0 {
                    bail!("invalid AnyTLS settings stream");
                }
                let s = std::str::from_utf8(data)
                    .map_err(|_| anyhow::anyhow!("invalid AnyTLS server settings"))?;
                self.version = if s.lines().any(|l| l == "v=2") { 2 } else { 1 };
            }
            2 | 3 | 7 => {
                if id == 0 || (command == 3 && !data.is_empty()) {
                    bail!("invalid AnyTLS stream control");
                }
                return Ok(false);
            }
            _ => bail!("unsupported AnyTLS server command"),
        }
        Ok(true)
    }

    fn retire_in_background(self) {
        let writer = self.writer;
        tokio::spawn(async move {
            let mut writer = writer.lock().await;
            let _ = timeout(RETIRE_TIMEOUT, writer.shutdown()).await;
        });
    }
}

struct Idle {
    request: Option<oneshot::Sender<oneshot::Sender<Physical>>>,
    task: JoinHandle<()>,
    sequence: u64,
    generation: u64,
}

impl Drop for Idle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Inner {
    proxy: Proxy,
    context: Arc<TransportContext>,
    scheme: Arc<StdMutex<Arc<Scheme>>>,
    last_success: Arc<StdMutex<Option<(u64, SocketAddr)>>>,
    idle: Mutex<Vec<Idle>>,
    closed: AtomicBool,
    timeout: Duration,
    idle_timeout: Duration,
    max_idle: usize,
    max_uses: usize,
    global: Arc<Semaphore>,
    node: Arc<Semaphore>,
    diagnostics: Arc<crate::diagnostics::NodeDiagnostics>,
    sequence: AtomicU64,
}

#[derive(Clone)]
pub struct Client {
    inner: Arc<Inner>,
}

impl Client {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proxy: Proxy,
        context: Arc<TransportContext>,
        timeout: Duration,
        idle_timeout: Duration,
        max_idle: usize,
        max_uses: usize,
        global: Arc<Semaphore>,
        node: Arc<Semaphore>,
        diagnostics: Arc<crate::diagnostics::NodeDiagnostics>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                proxy,
                context,
                scheme: Arc::new(StdMutex::new(Arc::new(Scheme::default()))),
                last_success: Arc::new(StdMutex::new(None)),
                idle: Mutex::new(Vec::new()),
                closed: AtomicBool::new(false),
                timeout,
                idle_timeout,
                max_idle,
                max_uses,
                global,
                node,
                diagnostics,
                sequence: AtomicU64::new(1),
            }),
        }
    }

    pub async fn close(&self) {
        self.inner.closed.store(true, Ordering::Release);
        let idle = std::mem::take(&mut *self.inner.idle.lock().await);
        for mut entry in idle {
            let (tx, rx) = oneshot::channel();
            if entry
                .request
                .take()
                .is_some_and(|request| request.send(tx).is_ok())
                && let Ok(physical) = rx.await
            {
                physical.retire_in_background();
            }
        }
    }

    pub async fn prune_idle(&self, network_generation: u64) {
        let mut stale = Vec::new();
        {
            let mut pool = self.inner.idle.lock().await;
            let mut kept = Vec::with_capacity(pool.len());
            for entry in pool.drain(..) {
                if !entry.task.is_finished() && entry.generation == network_generation {
                    kept.push(entry);
                } else {
                    stale.push(entry);
                }
            }
            *pool = kept;
        }
        for mut entry in stale {
            if !entry.task.is_finished() {
                let (tx, rx) = oneshot::channel();
                if entry
                    .request
                    .take()
                    .is_some_and(|request| request.send(tx).is_ok())
                    && let Ok(physical) = rx.await
                {
                    physical.retire_in_background();
                }
            }
        }
    }

    pub async fn dial_tcp(&self, host: &str, port: u16) -> Result<Session> {
        let destination = socks_address(host, port)?;
        let started = std::time::Instant::now();
        let result = timeout(self.inner.timeout, self.open(destination))
            .await
            .unwrap_or_else(|_| Err(std::io::Error::from(std::io::ErrorKind::TimedOut).into()));
        let mut timings = crate::diagnostics::DialTimings::default();
        timings.total_ms = started.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
        self.inner
            .diagnostics
            .record(result.as_ref().map(|_| ()), timings);
        result
    }

    async fn open(&self, destination: Vec<u8>) -> Result<Session> {
        if self.inner.closed.load(Ordering::Acquire) {
            bail!("AnyTLS client is closed");
        }
        let generation = self.inner.context.network_generation().await;
        let mut physical = None;
        loop {
            let idle = self.inner.idle.lock().await.pop();
            let Some(mut idle) = idle else {
                break;
            };
            let (tx, rx) = oneshot::channel();
            if idle.request.take().unwrap().send(tx).is_ok()
                && let Ok(p) = rx.await
            {
                if p.generation == generation && p.id < u32::MAX && p.uses < self.inner.max_uses {
                    physical = Some(p);
                    break;
                }
                p.retire_in_background();
            }
        }
        let mut p = if let Some(p) = physical {
            p
        } else {
            self.connect().await?
        };
        p.id += 1;
        p.uses += 1;
        let id = p.id;
        let mut request = Vec::with_capacity(128 + destination.len());
        if p.uses == 1 {
            let scheme = lock(&self.inner.scheme).clone();
            encode_frame_into(
                &mut request,
                4,
                0,
                format!(
                    "v=2\nclient=oixc-proxy/{}\npadding-md5={}",
                    crate::VERSION,
                    scheme.hash
                )
                .as_bytes(),
            )?;
        }
        encode_frame_into(&mut request, 1, id, &[])?;
        encode_frame_into(&mut request, 2, id, &destination)?;
        p.writer.lock().await.send(&request).await?;
        let mut first = Vec::new();
        let mut payload = Vec::new();
        loop {
            let incoming = if p.version >= 2 {
                Some(p.reader.next_into(&mut payload).await?)
            } else {
                match timeout(Duration::from_millis(250), p.reader.next_into(&mut payload)).await {
                    Ok(f) => Some(f?),
                    Err(_) => None,
                }
            };
            let Some((command, frame_id)) = incoming else {
                break;
            };
            if p.control(command, frame_id, &payload).await? {
                continue;
            }
            if frame_id < id {
                continue;
            }
            if frame_id != id {
                bail!("invalid AnyTLS stream id");
            }
            match command {
                7 => {
                    if !payload.is_empty() {
                        bail!("AnyTLS server refused the stream");
                    }
                    break;
                }
                2 if p.version == 1 => {
                    first = std::mem::take(&mut payload);
                    break;
                }
                3 => bail!("AnyTLS stream closed during handshake"),
                _ => bail!("unexpected AnyTLS stream handshake frame"),
            }
        }
        let writer = SessionWriter {
            writer: p.writer.clone(),
            id,
            closed: false,
            fin_sent: false,
            account_tcp: true,
        };
        Ok(Session {
            reader: SessionReader {
                physical: Some(p),
                buffer: Vec::new(),
                buffer_offset: 0,
                pending: (!first.is_empty()).then_some(first),
                eof: false,
                account_tcp: true,
            },
            writer,
            client: self.clone(),
        })
    }

    async fn connect(&self) -> Result<Physical> {
        // Acquire per-node permit before the global permit so one stalled node
        // cannot consume the entire process dial budget and starve other nodes.
        let _node = self.inner.node.acquire().await?;
        let _global = self.inner.global.acquire().await?;
        let (mut stream, local, generation) = self
            .inner
            .context
            .dial_anytls(&self.inner.proxy, &self.inner.last_success)
            .await?;
        let scheme = lock(&self.inner.scheme).clone();
        let n = scheme.authentication_padding()?;
        let mut auth = Vec::with_capacity(34 + n);
        auth.extend_from_slice(&Sha256::digest(self.inner.proxy.psk.as_bytes()));
        auth.extend_from_slice(&(n as u16).to_be_bytes());
        auth.resize(34 + n, 0);
        stream.write_all(&auth).await?;
        stream.flush().await?;
        let (read, write) = tokio::io::split(stream);
        let pending_heartbeats = Arc::new(StdMutex::new(VecDeque::new()));
        Ok(Physical {
            reader: FrameReader::new(read),
            writer: Arc::new(Mutex::new(Writer {
                io: write,
                scheme: self.inner.scheme.clone(),
                pending_heartbeats: pending_heartbeats.clone(),
                packet: 0,
                scratch: Vec::new(),
            })),
            scheme: self.inner.scheme.clone(),
            pending_heartbeats,
            local,
            generation,
            id: 0,
            version: 1,
            uses: 0,
            sequence: self.inner.sequence.fetch_add(1, Ordering::Relaxed),
        })
    }

    async fn release(&self, mut p: Physical) {
        if self.inner.closed.load(Ordering::Acquire) || p.uses >= self.inner.max_uses {
            p.retire_in_background();
            return;
        }
        let mut pool = self.inner.idle.lock().await;
        // close() can win the mutex after the first closed check above.
        if self.inner.closed.load(Ordering::Acquire) {
            drop(pool);
            p.retire_in_background();
            return;
        }
        pool.retain(|i| !i.task.is_finished());
        if pool.len() >= self.inner.max_idle {
            drop(pool);
            p.retire_in_background();
            return;
        }
        let (tx, mut rx) = oneshot::channel::<oneshot::Sender<Physical>>();
        let sequence = p.sequence;
        let generation = p.generation;
        let idle_timeout = self.inner.idle_timeout;
        let task = tokio::spawn(async move {
            let until = tokio::time::sleep(idle_timeout);
            tokio::pin!(until);
            let mut payload = Vec::new();
            loop {
                tokio::select! {
                    request = &mut rx => {
                        if let Ok(tx) = request {
                            let _ = tx.send(p);
                        }
                        return;
                    }
                    _ = &mut until => {
                        let mut writer = p.writer.lock().await;
                        let _ = timeout(RETIRE_TIMEOUT, writer.shutdown()).await;
                        return;
                    }
                    incoming = p.reader.next_into(&mut payload) => {
                        let Ok((command, frame_id)) = incoming else {
                            return;
                        };
                        match timeout(Duration::from_secs(2), p.control(command, frame_id, &payload)).await {
                            Ok(Ok(true)) => {}
                            Ok(Ok(false)) if frame_id <= p.id => {}
                            _ => return,
                        }
                    }
                }
            }
        });
        pool.push(Idle {
            request: Some(tx),
            task,
            sequence,
            generation,
        });
        pool.sort_by_key(|idle| idle.sequence);
    }

    pub async fn dial_udp(&self) -> Result<PacketSession> {
        if !self.inner.proxy.udp && !self.inner.proxy.anytls.as_ref().is_some_and(|o| o.udp) {
            bail!("AnyTLS UDP is disabled");
        }
        let mut session = self.dial_tcp("sp.v2.udp-over-tcp.arpa", 0).await?;
        session.reader.account_tcp = false;
        session.writer.account_tcp = false;
        // Non-connect UoT v2, with an unused SOCKS request destination.
        timeout(self.inner.timeout, session.write(&[0, 1, 0, 0, 0, 0, 0, 0]))
            .await
            .map_err(|_| anyhow::anyhow!("AnyTLS UDP request timed out"))??;
        let local = session.local_addr();
        Ok(PacketSession {
            reader: Mutex::new(session.reader),
            writer: Mutex::new(session.writer),
            local,
        })
    }
}

pub struct Session {
    reader: SessionReader,
    writer: SessionWriter,
    client: Client,
}

pub struct SessionReader {
    physical: Option<Physical>,
    buffer: Vec<u8>,
    buffer_offset: usize,
    pending: Option<Vec<u8>>,
    eof: bool,
    account_tcp: bool,
}

pub struct SessionWriter {
    writer: Arc<Mutex<Writer>>,
    id: u32,
    closed: bool,
    fin_sent: bool,
    account_tcp: bool,
}

impl Session {
    pub fn local_addr(&self) -> SocketAddr {
        self.reader.physical.as_ref().unwrap().local
    }

    pub fn split(&mut self) -> (&mut SessionReader, &mut SessionWriter) {
        (&mut self.reader, &mut self.writer)
    }

    pub async fn write(&mut self, b: &[u8]) -> Result<usize> {
        self.writer.write(b).await
    }

    pub fn close_timeout(&self) -> Duration {
        Duration::from_secs(2)
    }

    pub async fn finish(mut self, clean: bool, _close_sent: bool) {
        if !clean {
            if let Some(p) = self.reader.physical.take() {
                p.retire_in_background();
            }
            return;
        }
        // AnyTLS FIN closes the entire bidirectional stream, so we defer it
        // until the relay completes and skip it when the server already sent FIN.
        if !self.reader.eof
            && !matches!(
                timeout(self.close_timeout(), self.writer.send_fin()).await,
                Ok(Ok(()))
            )
        {
            if let Some(p) = self.reader.physical.take() {
                p.retire_in_background();
            }
            return;
        }
        if let Some(p) = self.reader.physical.take() {
            self.client.release(p).await;
        }
    }
}

impl SessionReader {
    pub async fn read_chunk(&mut self) -> Result<&[u8]> {
        self.buffer.clear();
        self.buffer_offset = 0;
        if let Some(data) = self.pending.take() {
            self.buffer = data;
            if self.account_tcp {
                crate::traffic::record(crate::traffic::Direction::TcpDownload, self.buffer.len());
            }
            return Ok(&self.buffer);
        }
        if self.eof {
            return Ok(&[]);
        }
        let p = self.physical.as_mut().unwrap();
        loop {
            let (command, frame_id) = p.reader.next_into(&mut self.buffer).await?;
            if p.control(command, frame_id, &self.buffer).await? {
                self.buffer.clear();
                continue;
            }
            if frame_id < p.id {
                self.buffer.clear();
                continue;
            }
            if frame_id != p.id {
                bail!("invalid AnyTLS stream id");
            }
            match command {
                2 if !self.buffer.is_empty() => {
                    if self.account_tcp {
                        crate::traffic::record(
                            crate::traffic::Direction::TcpDownload,
                            self.buffer.len(),
                        );
                    }
                    return Ok(&self.buffer);
                }
                2 => {}
                3 => {
                    if !self.buffer.is_empty() {
                        bail!("invalid AnyTLS FIN");
                    }
                    self.eof = true;
                    return Ok(&[]);
                }
                7 => {
                    if !self.buffer.is_empty() {
                        bail!("AnyTLS stream rejected");
                    }
                    self.buffer.clear();
                }
                _ => bail!("invalid AnyTLS stream frame"),
            }
        }
    }

    async fn read_exact_bytes(&mut self, mut dst: &mut [u8]) -> Result<()> {
        while !dst.is_empty() {
            if self.buffer_offset >= self.buffer.len() {
                let data = self.read_chunk().await?;
                if data.is_empty() {
                    bail!("AnyTLS UDP stream closed");
                }
            }
            let available = self.buffer.len() - self.buffer_offset;
            let count = dst.len().min(available);
            dst[..count]
                .copy_from_slice(&self.buffer[self.buffer_offset..self.buffer_offset + count]);
            self.buffer_offset += count;
            dst = &mut dst[count..];
        }
        Ok(())
    }

    async fn skip_bytes(&mut self, mut remaining: usize) -> Result<()> {
        while remaining > 0 {
            if self.buffer_offset >= self.buffer.len() {
                let data = self.read_chunk().await?;
                if data.is_empty() {
                    bail!("AnyTLS UDP stream closed");
                }
            }
            let available = self.buffer.len() - self.buffer_offset;
            let count = remaining.min(available);
            self.buffer_offset += count;
            remaining -= count;
        }
        Ok(())
    }
}

impl SessionWriter {
    pub async fn write(&mut self, b: &[u8]) -> Result<usize> {
        if self.closed {
            bail!("AnyTLS stream is closed");
        }
        let mut writer = self.writer.lock().await;
        for chunk in b.chunks(u16::MAX as usize) {
            writer.send_frame(2, self.id, chunk).await?;
            if self.account_tcp {
                crate::traffic::record(crate::traffic::Direction::TcpUpload, chunk.len());
            }
        }
        Ok(b.len())
    }

    /// Marks the local upload half closed without sending AnyTLS `cmdFIN`,
    /// because AnyTLS `cmdFIN` tears down both directions and would truncate
    /// server responses after a client TCP half-close.
    pub async fn close_write(&mut self) -> Result<()> {
        self.closed = true;
        Ok(())
    }

    async fn send_fin(&mut self) -> Result<()> {
        self.closed = true;
        if !self.fin_sent {
            self.fin_sent = true;
            self.writer.lock().await.control(3, self.id).await?;
        }
        Ok(())
    }
}

fn socks_address(host: &str, port: u16) -> Result<Vec<u8>> {
    let mut address = Vec::new();
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            address.push(1);
            address.extend(ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            address.push(4);
            address.extend(ip.octets());
        }
        Err(_) => {
            if host.is_empty() || host.len() > 255 || host.bytes().any(|b| b.is_ascii_control()) {
                bail!("invalid AnyTLS target");
            }
            address.extend([3, host.len() as u8]);
            address.extend(host.as_bytes());
        }
    }
    address.extend(port.to_be_bytes());
    Ok(address)
}

pub struct PacketSession {
    reader: Mutex<SessionReader>,
    writer: Mutex<SessionWriter>,
    local: SocketAddr,
}

impl PacketSession {
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    pub async fn write_to_host(&self, payload: &[u8], host: &str, port: u16) -> Result<usize> {
        if payload.len() > 65507 || port == 0 {
            return Err(crate::snell::DatagramError.into());
        }
        let mut address = socks_address(host, port).map_err(|_| crate::snell::DatagramError)?;
        address[0] = match address[0] {
            1 => 0,
            4 => 1,
            _ => 2,
        };
        address.extend((payload.len() as u16).to_be_bytes());
        address.extend(payload);
        self.writer.lock().await.write(&address).await?;
        crate::traffic::record(crate::traffic::Direction::UdpUpload, payload.len());
        Ok(payload.len())
    }

    pub async fn read_from(&self, frame: &mut Vec<u8>) -> Result<(SocketAddr, usize)> {
        let mut reader = self.reader.lock().await;
        let mut kind = [0u8; 1];
        reader.read_exact_bytes(&mut kind).await?;
        let ip = match kind[0] {
            0 => {
                let mut b = [0u8; 4];
                reader.read_exact_bytes(&mut b).await?;
                Some(IpAddr::from(b))
            }
            1 => {
                let mut b = [0u8; 16];
                reader.read_exact_bytes(&mut b).await?;
                Some(IpAddr::from(b))
            }
            2 => {
                // Consume FQDN address + port + payload so the UoT stream stays
                // synchronized, then drop only this datagram.
                let mut domain_len = [0u8; 1];
                reader.read_exact_bytes(&mut domain_len).await?;
                reader.skip_bytes(usize::from(domain_len[0])).await?;
                None
            }
            _ => bail!("AnyTLS UDP response has invalid address type"),
        };
        let mut tail = [0u8; 4];
        reader.read_exact_bytes(&mut tail).await?;
        let port = u16::from_be_bytes([tail[0], tail[1]]);
        let len = usize::from(u16::from_be_bytes([tail[2], tail[3]]));
        let Some(ip) = ip else {
            reader.skip_bytes(len).await?;
            return Err(crate::snell::DatagramError.into());
        };
        if port == 0 || len > 65507 {
            reader.skip_bytes(len).await?;
            return Err(crate::snell::DatagramError.into());
        }
        frame.clear();
        frame.resize(len, 0);
        reader.read_exact_bytes(frame).await?;
        crate::traffic::record(crate::traffic::Direction::UdpDownload, len);
        Ok((SocketAddr::new(ip, port), 0))
    }

    pub async fn close(self) {
        let _ = timeout(Duration::from_secs(2), self.writer.lock().await.send_fin()).await;
    }
}
