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

fn lock<T>(mutex: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
pub(super) fn frame(command: u8, id: u32, payload: &[u8]) -> Result<Vec<u8>> {
    let len = u16::try_from(payload.len()).context("AnyTLS frame too large")?;
    let mut data = Vec::with_capacity(7 + payload.len());
    data.push(command);
    data.extend(id.to_be_bytes());
    data.extend(len.to_be_bytes());
    data.extend(payload);
    Ok(data)
}
struct Frame {
    command: u8,
    id: u32,
    data: Vec<u8>,
}
struct FrameReader<R> {
    io: R,
    buffer: Vec<u8>,
}
impl<R: AsyncRead + Unpin> FrameReader<R> {
    async fn next(&mut self) -> Result<Frame> {
        loop {
            if self.buffer.len() >= 7 {
                let len = usize::from(u16::from_be_bytes([self.buffer[5], self.buffer[6]]));
                if self.buffer.len() >= 7 + len {
                    let command = self.buffer[0];
                    let id = u32::from_be_bytes(self.buffer[1..5].try_into().unwrap());
                    let data = self.buffer[7..7 + len].to_vec();
                    self.buffer.drain(..7 + len);
                    return Ok(Frame { command, id, data });
                }
            }
            let mut chunk = [0; 8192];
            let n = self.io.read(&mut chunk).await?;
            if n == 0 {
                bail!("AnyTLS session ended or frame truncated");
            }
            self.buffer.extend_from_slice(&chunk[..n]);
        }
    }
}
struct Writer {
    io: WriteHalf<BoxStream>,
    scheme: Arc<StdMutex<Scheme>>,
    packet: u32,
}
impl Writer {
    async fn send(&mut self, bytes: &[u8]) -> Result<()> {
        self.packet = self.packet.saturating_add(1);
        let scheme = lock(&self.scheme).clone();
        padding::write(&mut self.io, &scheme, self.packet, bytes).await
    }
    async fn control(&mut self, command: u8, id: u32) -> Result<()> {
        self.send(&frame(command, id, &[])?).await
    }
}
struct Physical {
    reader: FrameReader<ReadHalf<BoxStream>>,
    writer: Arc<Mutex<Writer>>,
    local: SocketAddr,
    generation: u64,
    id: u32,
    version: u8,
    uses: usize,
    sequence: u64,
}
impl Physical {
    async fn control(&mut self, f: &Frame) -> Result<bool> {
        match f.command {
            0 => {}
            5 => bail!("AnyTLS server rejected the session"),
            6 => {
                if f.id != 0 {
                    bail!("invalid AnyTLS padding stream");
                }
                let scheme = Scheme::parse(&f.data)
                    .map_err(|_| anyhow::anyhow!("invalid AnyTLS server padding scheme"))?;
                let writer = self.writer.lock().await;
                *lock(&writer.scheme) = scheme;
            }
            8 => {
                if !f.data.is_empty() {
                    bail!("invalid AnyTLS heartbeat");
                }
                self.writer.lock().await.control(9, f.id).await?;
            }
            9 => {
                if !f.data.is_empty() {
                    bail!("invalid AnyTLS heartbeat reply");
                }
            }
            10 => {
                if f.id != 0 {
                    bail!("invalid AnyTLS settings stream");
                }
                let s = std::str::from_utf8(&f.data)
                    .map_err(|_| anyhow::anyhow!("invalid AnyTLS server settings"))?;
                self.version = if s.lines().any(|l| l == "v=2") { 2 } else { 1 };
            }
            2 | 3 | 7 => {
                if f.id == 0 || (f.command == 3 && !f.data.is_empty()) {
                    bail!("invalid AnyTLS stream control");
                }
                return Ok(false);
            }
            _ => bail!("unsupported AnyTLS server command"),
        }
        Ok(true)
    }
}
struct Idle {
    request: Option<oneshot::Sender<oneshot::Sender<Physical>>>,
    task: JoinHandle<()>,
    sequence: u64,
}
impl Drop for Idle {
    fn drop(&mut self) {
        self.task.abort();
    }
}
struct Inner {
    proxy: Proxy,
    context: Arc<TransportContext>,
    scheme: Arc<StdMutex<Scheme>>,
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
                scheme: Arc::new(StdMutex::new(Scheme::default())),
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
        self.inner.idle.lock().await.clear();
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
                && p.generation == generation
                && p.id < u32::MAX
                && p.uses < self.inner.max_uses
            {
                physical = Some(p);
                break;
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
        let mut request = Vec::new();
        if p.uses == 1 {
            let scheme = lock(&self.inner.scheme).clone();
            request.extend(frame(
                4,
                0,
                format!(
                    "v=2\nclient=oixc-proxy/{}\npadding-md5={}",
                    crate::VERSION,
                    scheme.hash
                )
                .as_bytes(),
            )?);
        }
        request.extend(frame(1, id, &[])?);
        request.extend(frame(2, id, &destination)?);
        p.writer.lock().await.send(&request).await?;
        let mut first = Vec::new();
        loop {
            let incoming = if p.version >= 2 {
                Some(p.reader.next().await?)
            } else {
                match timeout(Duration::from_millis(250), p.reader.next()).await {
                    Ok(f) => Some(f?),
                    Err(_) => None,
                }
            };
            let Some(f) = incoming else {
                break;
            };
            if p.control(&f).await? {
                continue;
            }
            if f.id < id {
                continue;
            }
            if f.id != id {
                bail!("invalid AnyTLS stream id");
            }
            match f.command {
                7 => {
                    if !f.data.is_empty() {
                        bail!("AnyTLS server refused the stream");
                    }
                    break;
                }
                2 if p.version == 1 => {
                    first = f.data;
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
            account_tcp: true,
        };
        Ok(Session {
            reader: SessionReader {
                physical: Some(p),
                buffer: Vec::new(),
                pending: (!first.is_empty()).then_some(first),
                eof: false,
                account_tcp: true,
            },
            writer,
            client: self.clone(),
        })
    }
    async fn connect(&self) -> Result<Physical> {
        let _global = self.inner.global.acquire().await?;
        let _node = self.inner.node.acquire().await?;
        let (mut stream, local, generation) =
            self.inner.context.dial_anytls(&self.inner.proxy).await?;
        let scheme = lock(&self.inner.scheme).clone();
        let n = scheme.authentication_padding()?;
        let mut auth = Sha256::digest(self.inner.proxy.psk.as_bytes()).to_vec();
        auth.extend((n as u16).to_be_bytes());
        auth.resize(34 + n, 0);
        stream.write_all(&auth).await?;
        stream.flush().await?;
        let (read, write) = tokio::io::split(stream);
        Ok(Physical {
            reader: FrameReader {
                io: read,
                buffer: Vec::new(),
            },
            writer: Arc::new(Mutex::new(Writer {
                io: write,
                scheme: self.inner.scheme.clone(),
                packet: 0,
            })),
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
            return;
        }
        let mut pool = self.inner.idle.lock().await;
        // close() can win the mutex after the first closed check above.
        if self.inner.closed.load(Ordering::Acquire) {
            return;
        }
        pool.retain(|i| !i.task.is_finished());
        if pool.len() >= self.inner.max_idle {
            return;
        }
        let (tx, mut rx) = oneshot::channel::<oneshot::Sender<Physical>>();
        let sequence = p.sequence;
        let idle_timeout = self.inner.idle_timeout;
        let task = tokio::spawn(async move {
            let until = tokio::time::sleep(idle_timeout);
            tokio::pin!(until);
            loop {
                tokio::select! {
                    request=&mut rx=>{if let Ok(tx)=request {let _=tx.send(p);}return;},
                    _=&mut until=>return,
                    incoming=p.reader.next()=>{let Ok(f)=incoming else{return;};match timeout(Duration::from_secs(2),p.control(&f)).await {Ok(Ok(true))=>{},Ok(Ok(false)) if f.id<=p.id=>{},_=>return,}}
                }
            }
        });
        pool.push(Idle {
            request: Some(tx),
            task,
            sequence,
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
    pending: Option<Vec<u8>>,
    eof: bool,
    account_tcp: bool,
}
pub struct SessionWriter {
    writer: Arc<Mutex<Writer>>,
    id: u32,
    closed: bool,
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
    pub async fn finish(mut self, clean: bool, close_sent: bool) {
        if !clean {
            return;
        }
        if !self.reader.eof
            && !close_sent
            && !matches!(
                timeout(self.close_timeout(), self.writer.close_write()).await,
                Ok(Ok(()))
            )
        {
            return;
        }
        if let Some(p) = self.reader.physical.take() {
            self.client.release(p).await;
        }
    }
}
impl SessionReader {
    pub async fn read_chunk(&mut self) -> Result<&[u8]> {
        if !self.buffer.is_empty() {
            self.buffer.clear();
        }
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
            let f = p.reader.next().await?;
            if p.control(&f).await? {
                continue;
            }
            if f.id < p.id {
                continue;
            }
            if f.id != p.id {
                bail!("invalid AnyTLS stream id");
            }
            match f.command {
                2 if !f.data.is_empty() => {
                    self.buffer = f.data;
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
                    if !f.data.is_empty() {
                        bail!("invalid AnyTLS FIN");
                    }
                    self.eof = true;
                    return Ok(&[]);
                }
                7 => {
                    if !f.data.is_empty() {
                        bail!("AnyTLS stream rejected");
                    }
                }
                _ => bail!("invalid AnyTLS stream frame"),
            }
        }
    }
}
impl SessionWriter {
    pub async fn write(&mut self, b: &[u8]) -> Result<usize> {
        if self.closed {
            bail!("AnyTLS stream is closed");
        }
        let mut writer = self.writer.lock().await;
        for chunk in b.chunks(u16::MAX as usize) {
            writer.send(&frame(2, self.id, chunk)?).await?;
            if self.account_tcp {
                crate::traffic::record(crate::traffic::Direction::TcpUpload, chunk.len());
            }
        }
        Ok(b.len())
    }
    pub async fn close_write(&mut self) -> Result<()> {
        if !self.closed {
            self.closed = true;
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
        async fn take(reader: &mut SessionReader, n: usize) -> Result<Vec<u8>> {
            let mut bytes = Vec::with_capacity(n);
            while bytes.len() < n {
                if reader.buffer.is_empty() {
                    let data = reader.read_chunk().await?;
                    if data.is_empty() {
                        bail!("AnyTLS UDP stream closed");
                    }
                }
                let count = (n - bytes.len()).min(reader.buffer.len());
                bytes.extend(reader.buffer.drain(..count));
            }
            Ok(bytes)
        }
        let kind = take(&mut reader, 1).await?[0];
        let ip = match kind {
            0 => {
                let b = take(&mut reader, 4).await?;
                IpAddr::from(<[u8; 4]>::try_from(b.as_slice()).unwrap())
            }
            1 => {
                let b = take(&mut reader, 16).await?;
                IpAddr::from(<[u8; 16]>::try_from(b.as_slice()).unwrap())
            }
            _ => bail!("AnyTLS UDP response requires an IP address"),
        };
        let b = take(&mut reader, 4).await?;
        let port = u16::from_be_bytes([b[0], b[1]]);
        let len = usize::from(u16::from_be_bytes([b[2], b[3]]));
        *frame = take(&mut reader, len).await?;
        if port == 0 || len > 65507 {
            return Err(crate::snell::DatagramError.into());
        }
        crate::traffic::record(crate::traffic::Direction::UdpDownload, len);
        Ok((SocketAddr::new(ip, port), 0))
    }
    pub async fn close(self) {
        let _ = timeout(
            Duration::from_secs(2),
            self.writer.lock().await.close_write(),
        )
        .await;
    }
}
