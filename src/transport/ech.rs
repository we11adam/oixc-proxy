use std::collections::{HashSet, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

use anyhow::{Result, bail};
use base64::Engine as _;
use rustls::client::{EchConfig, EchMode};
use rustls::crypto::CryptoProvider;
use rustls::internal::msgs::codec::Codec as _;
use rustls::pki_types::{EchConfigListBytes, ServerName};
use rustls::{CertificateError, ClientConfig, PeerIncompatible, ProtocolVersion};
use tokio::net::{TcpSocket, TcpStream, lookup_host};
use tokio::task::JoinSet;
use tokio::time::{Instant as TokioInstant, Sleep, sleep, timeout};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::network::{NetworkMonitor, NetworkSnapshot};
use crate::nodes::Proxy;
use crate::snell::Exporter;

use super::PrivateDnsResolver;
use super::trust::{TrustSnapshot, TrustStore};

const EXPORTER_LABEL: &[u8] = b"EXPORTER-Dler-Snell-Identity-v2";
const MAX_ECH_CONFIG_LENGTH: usize = 64 << 10;
const HAPPY_EYEBALLS_DELAY: Duration = Duration::from_millis(250);

pub struct EchConnection {
    pub stream: TlsStream<TcpStream>,
    pub exporter: Exporter,
    pub network_generation: u64,
}

pub struct TransportContext {
    roots: Arc<TrustStore>,
    provider: Arc<CryptoProvider>,
    resolver: PrivateDnsResolver,
    network: NetworkMonitor,
}

struct CachedTlsConfig {
    generation: u64,
    ech: Arc<EchConfig>,
    config: Arc<ClientConfig>,
}

#[derive(Clone)]
pub struct EchDialer {
    server: String,
    sni: String,
    port: u16,
    alpn: Vec<u8>,
    timeout: Duration,
    tls_config: Arc<Mutex<Option<CachedTlsConfig>>>,
    /// Starts from the catalog and follows retry configs from the server.
    ech: Arc<Mutex<Arc<EchConfig>>>,
    context: Arc<TransportContext>,
    resolver: PrivateDnsResolver,
    network: NetworkMonitor,
    last_success: Arc<Mutex<Option<(u64, SocketAddr)>>>,
}

impl TransportContext {
    pub fn built_in() -> Result<Self> {
        Self::built_in_with_network(NetworkMonitor::new(None))
    }

    pub fn built_in_with_network(network: NetworkMonitor) -> Result<Self> {
        Ok(Self {
            roots: Arc::new(TrustStore::new()?),
            provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
            resolver: PrivateDnsResolver::built_in()?,
            network,
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
        let ech = parse_ech_config(&proxy.obfs.ech_config)?;
        Ok(Self {
            server: proxy.server.clone(),
            sni: proxy.obfs.sni.clone(),
            port: proxy.port,
            alpn: proxy.obfs.alpn.as_bytes().to_vec(),
            timeout: dial_timeout,
            tls_config: Arc::new(Mutex::new(None)),
            ech: Arc::new(Mutex::new(Arc::new(ech))),
            resolver: context.resolver.clone(),
            network: context.network.clone(),
            last_success: Arc::new(Mutex::new(None)),
            context,
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
        let trust = self.context.roots.snapshot().await;
        match self.dial_with_trust(&trust).await {
            Err(error)
                if error.chain().any(|cause| {
                    cause
                        .downcast_ref::<io::Error>()
                        .is_some_and(unknown_issuer)
                }) =>
            {
                let refreshed = self.context.roots.refresh(trust.generation).await;
                if refreshed.generation != trust.generation {
                    // Retry only the handshake, before any application payload is sent.
                    self.dial_with_trust(&refreshed).await
                } else {
                    Err(error)
                }
            }
            result => result,
        }
    }

    fn current_ech(&self) -> Result<Arc<EchConfig>> {
        self.ech
            .lock()
            .map(|ech| ech.clone())
            .map_err(|_| anyhow::anyhow!("ECH configuration lock poisoned"))
    }

    fn config_for(&self, trust: &TrustSnapshot) -> Result<Arc<ClientConfig>> {
        let ech = self.current_ech()?;
        let mut cached = self
            .tls_config
            .lock()
            .map_err(|_| anyhow::anyhow!("TLS configuration lock poisoned"))?;
        if let Some(cached) = &*cached {
            if cached.generation == trust.generation && Arc::ptr_eq(&cached.ech, &ech) {
                return Ok(cached.config.clone());
            }
        }
        let mut config = ClientConfig::builder_with_provider(self.context.provider.clone())
            .with_ech(EchMode::Enable((*ech).clone()))
            .map_err(|_| anyhow::anyhow!("configure ECH-TLS"))?
            .with_root_certificates(trust.roots.clone())
            .with_no_client_auth();
        config.alpn_protocols = vec![self.alpn.clone()];
        let config = Arc::new(config);
        *cached = Some(CachedTlsConfig {
            generation: trust.generation,
            ech,
            config: config.clone(),
        });
        Ok(config)
    }

    async fn dial_with_trust(&self, trust: &TrustSnapshot) -> Result<EchConnection> {
        match self.dial_once(trust).await {
            Err(error) => match ech_retry_config(&error) {
                Some(retry) => {
                    // The server authenticated itself for its public name
                    // before offering these; RFC 9849 allows one retry.
                    if let Ok(mut ech) = self.ech.lock() {
                        *ech = Arc::new(retry);
                    }
                    crate::perftrace::event("ech.retry_config", &[]);
                    self.dial_once(trust).await
                }
                None => Err(error),
            },
            result => result,
        }
    }

    async fn dial_once(&self, trust: &TrustSnapshot) -> Result<EchConnection> {
        let tcp_started = Instant::now();
        let raw = self.dial_tcp().await;
        crate::perftrace::stage("ech.tcp_connect", tcp_started, raw.is_ok(), &[]);
        let (raw, network_generation) = raw?;
        raw.set_nodelay(true).ok();
        let server_name = ServerName::try_from(self.sni.clone())
            .map_err(|_| anyhow::anyhow!("ECH-TLS server name is invalid"))?;
        let connector = TlsConnector::from(self.config_for(trust)?);
        let handshake_started = Instant::now();
        let stream = connector.connect(server_name, raw).await;
        crate::perftrace::stage("ech.tls_handshake", handshake_started, stream.is_ok(), &[]);
        if let Err(error) = &stream {
            // Fixed categories avoid leaking hostnames or certificate contents.
            crate::perftrace::event(
                "ech.tls_error",
                &[
                    (
                        "reason",
                        if unknown_issuer(error) {
                            "unknown_issuer"
                        } else {
                            "tls_or_io"
                        }
                        .to_owned(),
                    ),
                    ("roots", trust.roots.len().to_string()),
                    ("trust_generation", trust.generation.to_string()),
                ],
            );
        }
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
        Ok(EchConnection {
            stream,
            exporter,
            network_generation,
        })
    }

    pub async fn network_generation(&self) -> u64 {
        self.network.snapshot().await.generation()
    }

    async fn dial_tcp(&self) -> Result<(TcpStream, u64)> {
        let network = self.network.snapshot().await;
        if crate::perftrace::enabled() {
            crate::perftrace::event("network.snapshot", &network.diagnostic_fields());
        }
        let dns_started = Instant::now();
        let addresses = match self.resolver.lookup(&self.server, &network).await {
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
        let addresses = addresses?
            .into_iter()
            .filter(|address| network.supports(*address))
            .collect();
        let preferred = self
            .last_success
            .lock()
            .ok()
            .and_then(|value| value.filter(|(generation, _)| *generation == network.generation()))
            .map(|(_, address)| address);
        let addresses = interleave_addresses(addresses, preferred);
        if crate::perftrace::enabled() {
            crate::perftrace::event(
                "network.candidates",
                &[
                    ("count", addresses.len().to_string()),
                    (
                        "families",
                        addresses
                            .iter()
                            .map(|address| if address.is_ipv4() { "ipv4" } else { "ipv6" })
                            .collect::<Vec<_>>()
                            .join(","),
                    ),
                ],
            );
        }
        let connected = connect_happy_eyeballs(addresses, network.clone()).await;
        if let Err(error) = &connected {
            crate::perftrace::event(
                "network.connect_error",
                &[("kind", format!("{:?}", error.kind()))],
            );
        }
        let (stream, address) = connected.map_err(|error| match error.kind() {
            io::ErrorKind::ConnectionRefused => {
                anyhow::anyhow!("ECH-TLS node refused the connection")
            }
            io::ErrorKind::NetworkUnreachable | io::ErrorKind::HostUnreachable => {
                anyhow::anyhow!("ECH-TLS node network is unreachable")
            }
            _ => anyhow::anyhow!("connect to ECH-TLS node"),
        })?;
        if crate::perftrace::enabled() {
            let local = stream.local_addr().ok();
            crate::perftrace::event(
                "network.connected",
                &[
                    (
                        "family",
                        if address.is_ipv4() { "ipv4" } else { "ipv6" }.to_owned(),
                    ),
                    (
                        "local",
                        local
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "unknown".to_owned()),
                    ),
                    ("generation", network.generation().to_string()),
                ],
            );
        }
        if let Ok(mut preferred) = self.last_success.lock() {
            *preferred = Some((network.generation(), address));
        }
        Ok((stream, network.generation()))
    }
}

fn unknown_issuer(error: &io::Error) -> bool {
    matches!(
        error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<rustls::Error>()),
        Some(rustls::Error::InvalidCertificate(
            CertificateError::UnknownIssuer
        ))
    )
}

/// Returns the replacement ECH configuration a server sent while rejecting
/// the one it was offered.
fn ech_retry_config(error: &anyhow::Error) -> Option<EchConfig> {
    error.chain().find_map(|cause| {
        let rustls::Error::PeerIncompatible(PeerIncompatible::ServerRejectedEncryptedClientHello(
            Some(configs),
        )) = cause
            .downcast_ref::<io::Error>()?
            .get_ref()?
            .downcast_ref::<rustls::Error>()?
        else {
            return None;
        };
        ech_config_from_list(configs.get_encoding()).ok()
    })
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

async fn connect_happy_eyeballs(
    addresses: Vec<SocketAddr>,
    network: NetworkSnapshot,
) -> io::Result<(TcpStream, SocketAddr)> {
    race_connects(addresses, move |address| {
        connect_from(address, network.clone())
    })
    .await
}

/// Starts an attempt per address, staggered by the Happy Eyeballs delay. A
/// failed attempt starts the next one at once (RFC 8305, section 5) while
/// slower attempts keep running.
async fn race_connects<T, F, C>(
    addresses: Vec<SocketAddr>,
    connect: C,
) -> io::Result<(T, SocketAddr)>
where
    T: Send + 'static,
    F: Future<Output = io::Result<T>> + Send + 'static,
    C: Fn(SocketAddr) -> F,
{
    let mut pending = VecDeque::from(addresses);
    let mut attempts = JoinSet::new();
    let launch_delay = sleep(HAPPY_EYEBALLS_DELAY);
    tokio::pin!(launch_delay);
    let mut launch_next = |attempts: &mut JoinSet<_>, launch_delay: Pin<&mut Sleep>| {
        let Some(address) = pending.pop_front() else {
            return false;
        };
        let attempt = connect(address);
        attempts.spawn(async move { attempt.await.map(|stream| (stream, address)) });
        launch_delay.reset(TokioInstant::now() + HAPPY_EYEBALLS_DELAY);
        true
    };
    if !launch_next(&mut attempts, launch_delay.as_mut()) {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "no resolved addresses",
        ));
    }
    let mut last_error = None;
    let mut exhausted = false;

    loop {
        tokio::select! {
            result = attempts.join_next(), if !attempts.is_empty() => {
                match result {
                    Some(Ok(Ok(success))) => return Ok(success),
                    Some(Ok(Err(error))) => last_error = Some(error),
                    Some(Err(error)) => last_error = Some(io::Error::other(error)),
                    None => {}
                }
                exhausted = !launch_next(&mut attempts, launch_delay.as_mut());
                if exhausted && attempts.is_empty() {
                    return Err(last_error.unwrap_or_else(|| {
                        io::Error::new(io::ErrorKind::AddrNotAvailable, "no resolved addresses")
                    }));
                }
            }
            _ = &mut launch_delay, if !exhausted => {
                exhausted = !launch_next(&mut attempts, launch_delay.as_mut());
            }
        }
    }
}

async fn connect_from(address: SocketAddr, network: NetworkSnapshot) -> io::Result<TcpStream> {
    let socket = if address.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    network.bind_tcp(&socket, address)?;
    socket.connect(address).await
}

pub(crate) fn parse_ech_config(encoded: &str) -> Result<EchConfig> {
    if encoded.is_empty() || encoded.len() > MAX_ECH_CONFIG_LENGTH.div_ceil(3) * 4 {
        bail!("ECH config size is invalid");
    }
    let ech_bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| anyhow::anyhow!("ECH config is not valid Base64"))?;
    ech_config_from_list(ech_bytes)
}

fn ech_config_from_list(ech_bytes: Vec<u8>) -> Result<EchConfig> {
    if ech_bytes.len() < 4 || ech_bytes.len() > MAX_ECH_CONFIG_LENGTH {
        bail!("ECH config list size is invalid");
    }
    if u16::from_be_bytes([ech_bytes[0], ech_bytes[1]]) as usize != ech_bytes.len() - 2 {
        bail!("ECH config list length does not match");
    }
    EchConfig::new(
        EchConfigListBytes::from(ech_bytes),
        rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES,
    )
    .map_err(|_| anyhow::anyhow!("ECH config list is unsupported"))
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
    fn parses_only_supported_ech_config_lists() {
        assert!(parse_ech_config(crate::nodes::TEST_ECH_CONFIG).is_ok());
        assert!(parse_ech_config("AAAA").is_err());
        assert!(parse_ech_config("not base64").is_err());
        assert!(parse_ech_config("").is_err());
    }

    #[test]
    fn recovers_retry_configs_from_ech_rejection() {
        use rustls::internal::msgs::codec::Reader;
        use rustls::internal::msgs::handshake::EchConfigPayload;

        let list = base64::engine::general_purpose::STANDARD
            .decode(crate::nodes::TEST_ECH_CONFIG)
            .unwrap();
        let configs = Vec::<EchConfigPayload>::read(&mut Reader::init(&list)).unwrap();
        let rejected = |configs| {
            anyhow::Error::from(io::Error::other(rustls::Error::PeerIncompatible(
                PeerIncompatible::ServerRejectedEncryptedClientHello(configs),
            )))
            .context("ECH-TLS handshake")
        };
        assert!(ech_retry_config(&rejected(Some(configs))).is_some());
        assert!(ech_retry_config(&rejected(None)).is_none());
        assert!(ech_retry_config(&rejected(Some(Vec::new()))).is_none());
        assert!(ech_retry_config(&anyhow::anyhow!("handshake failed")).is_none());
    }

    #[test]
    fn reload_is_only_triggered_by_unknown_issuer() {
        assert!(unknown_issuer(&io::Error::other(
            rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer,)
        )));
        for error in [CertificateError::Expired, CertificateError::BadSignature] {
            assert!(!unknown_issuer(&io::Error::other(
                rustls::Error::InvalidCertificate(error)
            )));
        }
        assert!(!unknown_issuer(&io::Error::other("unknown issuer")));
    }

    #[tokio::test]
    #[ignore = "requires OIXC_TLS_TEST_CACHE and live managed HK node"]
    async fn live_recovers_incomplete_trust_without_restart() {
        let path = std::env::var("OIXC_TLS_TEST_CACHE").unwrap();
        let value: serde_yaml::Value =
            serde_yaml::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let managed: crate::nodes::ManagedConfig =
            serde_yaml::from_value(value["managed"].clone()).unwrap();
        let proxy = managed
            .proxies
            .iter()
            .find(|p| p.name.contains("香港 Fusion 01"))
            .unwrap();
        let context = Arc::new(TransportContext::built_in().unwrap());
        let mut incomplete = rustls::RootCertStore::empty();
        // Keep a real but unrelated local CA, reproducing the captured process.
        let roots = context.roots.snapshot().await;
        incomplete.roots = roots
            .roots
            .roots
            .iter()
            .filter(|root| {
                root.subject
                    .as_ref()
                    .windows(5)
                    .any(|part| part == b"Surge")
            })
            .cloned()
            .collect();
        assert!(!incomplete.is_empty(), "test requires the local Surge CA");
        context.roots.replace_for_test(incomplete).await;
        let dialer =
            EchDialer::new_with_context(proxy, Duration::from_secs(15), context.clone()).unwrap();
        let before = context.roots.snapshot().await;
        let error = match dialer.dial_with_trust(&before).await {
            Err(error) => error,
            Ok(_) => panic!("incomplete trust unexpectedly accepted server"),
        };
        assert!(
            error
                .downcast_ref::<io::Error>()
                .is_some_and(unknown_issuer)
        );
        dialer
            .dial()
            .await
            .expect("must reload trust and retry successfully");
        let after = context.roots.snapshot().await;
        assert!(after.generation > before.generation);
        assert!(after.roots.len() > before.roots.len());
    }

    /// Port 1 never answers, port 2 fails after 10ms, other ports connect.
    async fn fake_connect(address: SocketAddr) -> io::Result<u16> {
        match address.port() {
            1 => std::future::pending().await,
            2 => {
                sleep(Duration::from_millis(10)).await;
                Err(io::ErrorKind::ConnectionRefused.into())
            }
            port => Ok(port),
        }
    }

    fn ports(ports: &[u16]) -> Vec<SocketAddr> {
        ports
            .iter()
            .map(|port| SocketAddr::from(([192, 0, 2, 1], *port)))
            .collect()
    }

    #[tokio::test(start_paused = true)]
    async fn failed_attempt_starts_the_next_one_immediately() {
        let started = TokioInstant::now();
        let (port, _) = race_connects(ports(&[1, 2, 3]), fake_connect)
            .await
            .unwrap();
        assert_eq!(port, 3);
        assert_eq!(
            started.elapsed(),
            HAPPY_EYEBALLS_DELAY + Duration::from_millis(10)
        );

        let started = TokioInstant::now();
        let (port, _) = race_connects(ports(&[2, 2, 3]), fake_connect)
            .await
            .unwrap();
        assert_eq!(port, 3);
        assert_eq!(started.elapsed(), Duration::from_millis(20));

        let error = race_connects(ports(&[2, 2]), fake_connect)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
        assert_eq!(
            race_connects(Vec::new(), fake_connect)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::AddrNotAvailable
        );
    }

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
