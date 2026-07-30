use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use rustls::client::{EchConfig, EchMode};
use rustls::pki_types::{EchConfigListBytes, ServerName};
use rustls::{ClientConfig, ProtocolVersion, RootCertStore};
use tokio::net::{TcpStream, lookup_host};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::nodes::Proxy;
use crate::snell::Exporter;

use super::PrivateDnsResolver;

const EXPORTER_LABEL: &[u8] = b"EXPORTER-Dler-Snell-Identity-v2";
const MAX_ECH_CONFIG_LENGTH: usize = 64 << 10;

pub struct EchConnection {
    pub stream: TlsStream<TcpStream>,
    pub exporter: Exporter,
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
}

impl EchDialer {
    pub fn new(proxy: &Proxy, dial_timeout: Duration) -> Result<Self> {
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
        let mut roots = RootCertStore::empty();
        let native = rustls_native_certs::load_native_certs();
        for certificate in native.certs {
            let _ = roots.add(certificate);
        }
        if roots.is_empty() {
            bail!("load system TLS root certificates");
        }
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut tls_config = ClientConfig::builder_with_provider(provider)
            .with_ech(EchMode::Enable(ech))
            .map_err(|_| anyhow::anyhow!("configure ECH-TLS"))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls_config.alpn_protocols = vec![proxy.obfs.alpn.as_bytes().to_vec()];

        Ok(Self {
            server: proxy.server.clone(),
            sni: proxy.obfs.sni.clone(),
            port: proxy.port,
            alpn: proxy.obfs.alpn.as_bytes().to_vec(),
            timeout: dial_timeout,
            tls_config: Arc::new(tls_config),
            resolver: PrivateDnsResolver::built_in()?,
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
        let raw = self.dial_tcp().await?;
        crate::perftrace::stage("ech.tcp_connect", tcp_started, true, &[]);
        raw.set_nodelay(true).ok();
        let server_name = ServerName::try_from(self.sni.clone())
            .map_err(|_| anyhow::anyhow!("ECH-TLS server name is invalid"))?;
        let connector = TlsConnector::from(self.tls_config.clone());
        let handshake_started = Instant::now();
        let stream = connector.connect(server_name, raw).await.map_err(|_| {
            anyhow::anyhow!("perform ECH-TLS handshake: TLS verification or negotiation failed")
        })?;
        crate::perftrace::stage("ech.tls_handshake", handshake_started, true, &[]);
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
        let addresses = match self.resolver.lookup(&self.server).await? {
            Some(addresses) => addresses
                .into_iter()
                .map(|ip| SocketAddr::new(ip, self.port))
                .collect::<Vec<_>>(),
            None => lookup_host((self.server.as_str(), self.port))
                .await
                .map_err(|_| anyhow::anyhow!("resolve ECH-TLS node"))?
                .collect(),
        };
        let mut last_error = None;
        for address in addresses {
            match TcpStream::connect(address).await {
                Ok(stream) => return Ok(stream),
                Err(error) => last_error = Some(error),
            }
        }
        let error = last_error.context("resolve ECH-TLS node")?;
        match error.kind() {
            std::io::ErrorKind::ConnectionRefused => bail!("ECH-TLS node refused the connection"),
            std::io::ErrorKind::NetworkUnreachable | std::io::ErrorKind::HostUnreachable => {
                bail!("ECH-TLS node network is unreachable")
            }
            _ => bail!("connect to ECH-TLS node"),
        }
    }
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
