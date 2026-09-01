use std::collections::{HashSet, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

use anyhow::{Result, bail};
use base64::Engine as _;
use rustls::client::{EchConfig, EchMode};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{EchConfigListBytes, ServerName};
use rustls::{ClientConfig, ProtocolVersion, RootCertStore};
use tokio::net::{TcpStream, lookup_host};
use tokio::task::JoinSet;
use tokio::time::{Instant as TokioInstant, sleep, timeout};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::nodes::Proxy;
use crate::snell::Exporter;

use super::PrivateDnsResolver;

const EXPORTER_LABEL: &[u8] = b"EXPORTER-Dler-Snell-Identity-v2";
const MAX_ECH_CONFIG_LENGTH: usize = 64 << 10;
const HAPPY_EYEBALLS_DELAY: Duration = Duration::from_millis(250);

pub struct EchConnection {
    pub stream: TlsStream<TcpStream>,
    pub exporter: Exporter,
}

pub struct TransportContext {
    roots: Arc<RootCertStore>,
    provider: Arc<CryptoProvider>,
    resolver: PrivateDnsResolver,
}

#[derive(Clone)]
pub struct EchDialer {
    server: String,
    sni: String,
    port: u16,
    alpn: Vec<u8>,
    timeout: Duration,
    tls_config: Arc<ClientConfig>,
    resolver: PrivateDnsResolver,
    last_success: Arc<Mutex<Option<SocketAddr>>>,
}

impl TransportContext {
    pub fn built_in() -> Result<Self> {
        let mut roots = RootCertStore::empty();
        let native = rustls_native_certs::load_native_certs();
        for certificate in native.certs {
            let _ = roots.add(certificate);
        }
        if roots.is_empty() {
            bail!("load system TLS root certificates");
        }
        Ok(Self {
            roots: Arc::new(roots),
            provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
            resolver: PrivateDnsResolver::built_in()?,
        })
    }
}

impl EchDialer {
    pub fn new(proxy: &Proxy, dial_timeout: Duration) -> Result<Self> {
        Self::new_with_context(proxy, dial_timeout, Arc::new(TransportContext::built_in()?))
    }

    pub fn new_with_context(
        proxy: &Proxy,
        dial_timeout: Duration,
        context: Arc<TransportContext>,
    ) -> Result<Self> {
        if dial_timeout.is_zero() || dial_timeout > Duration::from_secs(120) {
            bail!("ECH dial timeout must be between 1ns and 2m");
        }
        validate_profile(proxy)?;
        let encoded = &proxy.obfs.ech_config;
        if encoded.is_empty() || encoded.len() > MAX_ECH_CONFIG_LENGTH.div_ceil(3) * 4 {
            bail!("ECH config size is invalid");
        }
        let ech_bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| anyhow::anyhow!("ECH config is not valid Base64"))?;
        if ech_bytes.len() < 4 || ech_bytes.len() > MAX_ECH_CONFIG_LENGTH {
            bail!("ECH config list size is invalid");
        }
        if u16::from_be_bytes([ech_bytes[0], ech_bytes[1]]) as usize != ech_bytes.len() - 2 {
            bail!("ECH config list length does not match");
        }

        let ech = EchConfig::new(
            EchConfigListBytes::from(ech_bytes),
            rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES,
        )
        .map_err(|_| anyhow::anyhow!("ECH config list is unsupported"))?;
        let mut tls_config = ClientConfig::builder_with_provider(context.provider.clone())
            .with_ech(EchMode::Enable(ech))
            .map_err(|_| anyhow::anyhow!("configure ECH-TLS"))?
            .with_root_certificates(context.roots.clone())
            .with_no_client_auth();
        tls_config.alpn_protocols = vec![proxy.obfs.alpn.as_bytes().to_vec()];

        Ok(Self {
            server: proxy.server.clone(),
            sni: proxy.obfs.sni.clone(),
            port: proxy.port,
            alpn: proxy.obfs.alpn.as_bytes().to_vec(),
            timeout: dial_timeout,
            tls_config: Arc::new(tls_config),
            resolver: context.resolver.clone(),
            last_success: Arc::new(Mutex::new(None)),
        })
    }

    pub async fn dial(&self) -> Result<EchConnection> {
        let started = Instant::now();
        let result = timeout(self.timeout, self.dial_inner())
            .await
            .map_err(|_| anyhow::anyhow!("ECH-TLS node connection timed out"))?;
        crate::perftrace::stage("ech.dial", started, result.is_ok(), &[]);
        result
    }

    async fn dial_inner(&self) -> Result<EchConnection> {
        let tcp_started = Instant::now();
        let raw = self.dial_tcp().await;
        crate::perftrace::stage("ech.tcp_connect", tcp_started, raw.is_ok(), &[]);
        let raw = raw?;
        raw.set_nodelay(true).ok();
        let server_name = ServerName::try_from(self.sni.clone())
            .map_err(|_| anyhow::anyhow!("ECH-TLS server name is invalid"))?;
        let connector = TlsConnector::from(self.tls_config.clone());
        let handshake_started = Instant::now();
        let stream = connector.connect(server_name, raw).await.map_err(|_| {
            anyhow::anyhow!("perform ECH-TLS handshake: TLS verification or negotiation failed")
        });
        crate::perftrace::stage("ech.tls_handshake", handshake_started, stream.is_ok(), &[]);
        let stream = stream?;
        let connection = stream.get_ref().1;
        if connection.protocol_version() != Some(ProtocolVersion::TLSv1_3) {
            bail!("ECH transport did not negotiate TLS 1.3");
        }
        if connection.alpn_protocol() != Some(self.alpn.as_slice()) {
            bail!("ECH transport negotiated an unexpected ALPN");
        }
        let exporter = connection
            .export_keying_material([0u8; 32], EXPORTER_LABEL, None)
            .map_err(|_| anyhow::anyhow!("export ECH-TLS identity material"))?;
        Ok(EchConnection { stream, exporter })
    }

    async fn dial_tcp(&self) -> Result<TcpStream> {
        let dns_started = Instant::now();
        let addresses = match self.resolver.lookup(&self.server).await {
            Ok(Some(addresses)) => Ok(addresses
                .into_iter()
                .map(|ip| SocketAddr::new(ip, self.port))
                .collect::<Vec<_>>()),
            Ok(None) => lookup_host((self.server.as_str(), self.port))
                .await
                .map(|addresses| addresses.collect())
                .map_err(|_| anyhow::anyhow!("resolve ECH-TLS node")),
            Err(error) => Err(error),
        };
        crate::perftrace::stage("ech.dns", dns_started, addresses.is_ok(), &[]);
        let addresses = addresses?;
        let preferred = self.last_success.lock().ok().and_then(|value| *value);
        let addresses = interleave_addresses(addresses, preferred);
        let (stream, address) =
            connect_happy_eyeballs(addresses)
                .await
                .map_err(|error| match error.kind() {
                    io::ErrorKind::ConnectionRefused => {
                        anyhow::anyhow!("ECH-TLS node refused the connection")
                    }
                    io::ErrorKind::NetworkUnreachable | io::ErrorKind::HostUnreachable => {
                        anyhow::anyhow!("ECH-TLS node network is unreachable")
                    }
                    _ => anyhow::anyhow!("connect to ECH-TLS node"),
                })?;
        if let Ok(mut preferred) = self.last_success.lock() {
            *preferred = Some(address);
        }
        Ok(stream)
    }
}

fn interleave_addresses(
    addresses: Vec<SocketAddr>,
    preferred: Option<SocketAddr>,
) -> Vec<SocketAddr> {
    let mut seen = HashSet::with_capacity(addresses.len());
    let mut unique = addresses
        .into_iter()
        .filter(|address| seen.insert(*address))
        .collect::<Vec<_>>();
    if let Some(preferred) = preferred {
        if let Some(index) = unique.iter().position(|address| *address == preferred) {
            let preferred = unique.remove(index);
            unique.insert(0, preferred);
        }
    }

    let prefer_ipv4 = unique.first().is_none_or(SocketAddr::is_ipv4);
    let mut ipv4 = unique
        .iter()
        .copied()
        .filter(SocketAddr::is_ipv4)
        .collect::<VecDeque<_>>();
    let mut ipv6 = unique
        .iter()
        .copied()
        .filter(SocketAddr::is_ipv6)
        .collect::<VecDeque<_>>();
    let mut ordered = Vec::with_capacity(unique.len());
    let mut take_ipv4 = prefer_ipv4;
    while !ipv4.is_empty() || !ipv6.is_empty() {
        let next = if take_ipv4 {
            ipv4.pop_front().or_else(|| ipv6.pop_front())
        } else {
            ipv6.pop_front().or_else(|| ipv4.pop_front())
        };
        if let Some(next) = next {
            ordered.push(next);
        }
        take_ipv4 = !take_ipv4;
    }
    ordered
}

async fn connect_happy_eyeballs(addresses: Vec<SocketAddr>) -> io::Result<(TcpStream, SocketAddr)> {
    let mut pending = VecDeque::from(addresses);
    let Some(first) = pending.pop_front() else {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "no resolved addresses",
        ));
    };
    let mut attempts = JoinSet::new();
    spawn_connect(&mut attempts, first);
    let launch_delay = sleep(HAPPY_EYEBALLS_DELAY);
    tokio::pin!(launch_delay);
    let mut last_error = None;

    loop {
        tokio::select! {
            result = attempts.join_next(), if !attempts.is_empty() => {
                match result {
                    Some(Ok(Ok(success))) => return Ok(success),
                    Some(Ok(Err(error))) => last_error = Some(error),
                    Some(Err(error)) => last_error = Some(io::Error::other(error)),
                    None => {}
                }
                if attempts.is_empty() {
                    if let Some(address) = pending.pop_front() {
                        spawn_connect(&mut attempts, address);
                        launch_delay
                            .as_mut()
                            .reset(TokioInstant::now() + HAPPY_EYEBALLS_DELAY);
                    } else {
                        return Err(last_error.unwrap_or_else(|| {
                            io::Error::new(io::ErrorKind::AddrNotAvailable, "no resolved addresses")
                        }));
                    }
                }
            }
            _ = &mut launch_delay, if !pending.is_empty() => {
                let address = pending.pop_front().expect("guarded above");
                spawn_connect(&mut attempts, address);
                launch_delay
                    .as_mut()
                    .reset(TokioInstant::now() + HAPPY_EYEBALLS_DELAY);
            }
        }
    }
}

fn spawn_connect(attempts: &mut JoinSet<io::Result<(TcpStream, SocketAddr)>>, address: SocketAddr) {
    attempts.spawn(async move {
        TcpStream::connect(address)
            .await
            .map(|stream| (stream, address))
    });
}

fn validate_profile(proxy: &Proxy) -> Result<()> {
    if proxy.proxy_type != "snell"
        || proxy.version != 4
        || !proxy.identity
        || proxy.server.is_empty()
        || proxy.port == 0
        || proxy.obfs.mode != "ech-tls"
        || proxy.obfs.sni.is_empty()
        || proxy.obfs.path.is_empty()
        || proxy.obfs.alpn != "snell-ech/1"
        || proxy.obfs.identity_version != 2
        || proxy.obfs.legacy_fallback
        || proxy.obfs.skip_cert_verify
    {
        bail!("unsupported Snell ECH-TLS node configuration");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_eyeballs_order_interleaves_families_and_prefers_last_success() {
        let ipv4_a = "192.0.2.1:443".parse().unwrap();
        let ipv4_b = "192.0.2.2:443".parse().unwrap();
        let ipv6_a = "[2001:db8::1]:443".parse().unwrap();
        let ipv6_b = "[2001:db8::2]:443".parse().unwrap();
        assert_eq!(
            interleave_addresses(vec![ipv4_a, ipv4_b, ipv6_a, ipv6_b, ipv4_a], Some(ipv6_b),),
            vec![ipv6_b, ipv4_a, ipv6_a, ipv4_b]
        );
    }
}
