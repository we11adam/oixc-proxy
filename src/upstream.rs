//! Shared gateway interface for the independent Snell and AnyTLS protocols.
use crate::{
    anytls,
    config::RuntimeConfig,
    diagnostics::NodeDiagnostics,
    nodes::Proxy,
    snell,
    transport::{EchDialer, TransportContext},
};
use anyhow::Result;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::sync::Semaphore;

#[derive(Clone)]
pub enum Client {
    Snell(snell::SnellClient),
    AnyTls(anytls::Client),
}
impl From<snell::SnellClient> for Client {
    fn from(c: snell::SnellClient) -> Self {
        Self::Snell(c)
    }
}
impl Client {
    pub(crate) fn build(
        proxy: &Proxy,
        runtime: &RuntimeConfig,
        transport: Arc<TransportContext>,
        global: Arc<Semaphore>,
    ) -> Result<(Self, Arc<NodeDiagnostics>)> {
        let node = Arc::new(Semaphore::new(runtime.per_node_dial_concurrency));
        if proxy.proxy_type == "anytls" {
            let diagnostics = Arc::new(NodeDiagnostics::default());
            return Ok((
                Self::AnyTls(anytls::Client::new(
                    proxy.clone(),
                    transport,
                    runtime.request_timeout,
                    runtime.reuse_idle_timeout,
                    runtime.reuse_max_idle,
                    runtime.reuse_max_uses,
                    global,
                    node,
                    diagnostics.clone(),
                )),
                diagnostics,
            ));
        }
        let dialer = EchDialer::new_with_context(proxy, runtime.request_timeout, transport)?;
        let diagnostics = dialer.diagnostics.clone();
        let client = snell::SnellClient::new_with_node_dial_limit(
            snell::SnellClientOptions {
                node_name: proxy.name.clone(),
                psk: proxy.psk.clone(),
                reuse: proxy.reuse,
                max_idle: runtime.reuse_max_idle,
                max_uses: runtime.reuse_max_uses,
                idle_timeout: runtime.reuse_idle_timeout,
                handshake_timeout: runtime.request_timeout,
                close_timeout: Duration::from_secs(2),
                dialer: dialer.into(),
                dial_limit: Some(global),
                dial_limit_timeout: runtime.request_timeout.max(Duration::from_secs(45)),
            },
            Some(node),
        )?;
        Ok((Self::Snell(client), diagnostics))
    }
    pub async fn dial_tcp(&self, host: &str, port: u16) -> Result<Session> {
        Ok(match self {
            Self::Snell(c) => Session::Snell(c.dial_tcp(host, port).await?),
            Self::AnyTls(c) => Session::AnyTls(c.dial_tcp(host, port).await?),
        })
    }
    pub async fn dial_udp(&self) -> Result<PacketSession> {
        Ok(match self {
            Self::Snell(c) => PacketSession::Snell(Box::new(c.dial_udp().await?)),
            Self::AnyTls(c) => PacketSession::AnyTls(Box::new(c.dial_udp().await?)),
        })
    }
    pub async fn close(&self) {
        match self {
            Self::Snell(c) => c.close().await,
            Self::AnyTls(c) => c.close().await,
        }
    }
    pub async fn prune_idle(&self, network_generation: u64) {
        match self {
            Self::Snell(c) => c.prune_idle(network_generation).await,
            Self::AnyTls(c) => c.prune_idle(network_generation).await,
        }
    }
}
pub enum Session {
    Snell(snell::SnellSession),
    AnyTls(anytls::Session),
}
pub enum SessionReader<'a> {
    Snell(snell::SnellSessionReader<'a>),
    AnyTls(&'a mut anytls::SessionReader),
}
pub enum SessionWriter<'a> {
    Snell(snell::SnellSessionWriter<'a>),
    AnyTls(&'a mut anytls::SessionWriter),
}
impl Session {
    pub fn local_addr(&self) -> SocketAddr {
        match self {
            Self::Snell(s) => s.local_addr(),
            Self::AnyTls(s) => s.local_addr(),
        }
    }
    pub fn split(&mut self) -> (SessionReader<'_>, SessionWriter<'_>) {
        match self {
            Self::Snell(s) => {
                let (r, w) = s.split();
                (SessionReader::Snell(r), SessionWriter::Snell(w))
            }
            Self::AnyTls(s) => {
                let (r, w) = s.split();
                (SessionReader::AnyTls(r), SessionWriter::AnyTls(w))
            }
        }
    }
    pub async fn write(&mut self, b: &[u8]) -> Result<usize> {
        match self {
            Self::Snell(s) => s.write(b).await,
            Self::AnyTls(s) => s.write(b).await,
        }
    }
    pub fn close_timeout(&self) -> Duration {
        match self {
            Self::Snell(s) => s.close_timeout(),
            Self::AnyTls(s) => s.close_timeout(),
        }
    }
    pub async fn finish(self, clean: bool, sent: bool) {
        match self {
            Self::Snell(s) => s.finish(clean, sent).await,
            Self::AnyTls(s) => s.finish(clean, sent).await,
        }
    }
}
impl SessionReader<'_> {
    pub async fn read_chunk(&mut self) -> Result<&[u8]> {
        match self {
            Self::Snell(s) => s.read_chunk().await,
            Self::AnyTls(s) => s.read_chunk().await,
        }
    }
}
impl SessionWriter<'_> {
    pub async fn write(&mut self, b: &[u8]) -> Result<usize> {
        match self {
            Self::Snell(s) => s.write(b).await,
            Self::AnyTls(s) => s.write(b).await,
        }
    }
    pub async fn close_write(&mut self) -> Result<()> {
        match self {
            Self::Snell(s) => s.close_write().await,
            Self::AnyTls(s) => s.close_write().await,
        }
    }
}
pub enum PacketSession {
    Snell(Box<snell::SnellPacketSession>),
    AnyTls(Box<anytls::PacketSession>),
}
impl PacketSession {
    pub fn local_addr(&self) -> SocketAddr {
        match self {
            Self::Snell(s) => s.local_addr(),
            Self::AnyTls(s) => s.local_addr(),
        }
    }
    pub async fn write_to_host(&self, b: &[u8], host: &str, port: u16) -> Result<usize> {
        match self {
            Self::Snell(s) => s.write_to_host(b, host, port).await,
            Self::AnyTls(s) => s.write_to_host(b, host, port).await,
        }
    }
    pub async fn read_from(&self, b: &mut Vec<u8>) -> Result<(SocketAddr, usize)> {
        match self {
            Self::Snell(s) => s.read_from(b).await,
            Self::AnyTls(s) => s.read_from(b).await,
        }
    }
    pub async fn close(self) {
        match self {
            Self::Snell(s) => (*s).close().await,
            Self::AnyTls(s) => (*s).close().await,
        }
    }
}
