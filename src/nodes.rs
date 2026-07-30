use std::collections::HashSet;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

const MAX_MANAGED_CONFIG_BYTES: usize = 8 << 20;
const PREMIUM_LOVE_NODE_MARKER: &str = "fusion";

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedConfig {
    pub proxies: Vec<Proxy>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Proxy {
    pub name: String,
    #[serde(rename = "type")]
    pub proxy_type: String,
    pub server: String,
    pub port: u16,
    pub psk: String,
    pub version: u8,
    #[serde(default)]
    pub udp: bool,
    #[serde(default)]
    pub tfo: bool,
    #[serde(default)]
    pub reuse: bool,
    #[serde(default)]
    pub identity: bool,
    #[serde(rename = "obfs-opts")]
    pub obfs: ObfsOptions,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObfsOptions {
    pub mode: String,
    pub sni: String,
    pub path: String,
    pub alpn: String,
    #[serde(rename = "ech-config")]
    pub ech_config: String,
    #[serde(rename = "identity-version")]
    pub identity_version: u8,
    #[serde(rename = "legacy-fallback", default)]
    pub legacy_fallback: bool,
    #[serde(rename = "skip-cert-verify", default)]
    pub skip_cert_verify: bool,
    #[serde(default)]
    pub preconnect: u8,
}

impl ManagedConfig {
    pub fn parse(content: &[u8]) -> Result<Self> {
        if content.is_empty() || content.len() > MAX_MANAGED_CONFIG_BYTES {
            bail!("managed config size is invalid");
        }

        let mut documents = serde_yaml::Deserializer::from_slice(content);
        let first = documents
            .next()
            .context("managed config does not match the expected YAML schema")?;
        let config = Self::deserialize(first).map_err(|_| {
            anyhow::anyhow!("managed config does not match the expected YAML schema")
        })?;
        if documents.next().is_some() {
            bail!("managed config contains multiple YAML documents");
        }
        config.validate()?;
        Ok(config)
    }

    pub fn filter_premium_love(self) -> Result<Self> {
        let proxies = self
            .proxies
            .into_iter()
            .filter(|proxy| proxy.name.to_lowercase().contains(PREMIUM_LOVE_NODE_MARKER))
            .collect::<Vec<_>>();
        if proxies.is_empty() {
            bail!("managed config contains no premium/love Fusion proxies");
        }
        Ok(Self { proxies })
    }

    fn validate(&self) -> Result<()> {
        if self.proxies.is_empty() {
            bail!("managed config contains no proxies");
        }
        let mut names = HashSet::with_capacity(self.proxies.len());
        for (index, proxy) in self.proxies.iter().enumerate() {
            proxy
                .validate()
                .with_context(|| format!("proxy at index {index}"))?;
            if !names.insert(&proxy.name) {
                bail!("proxy at index {index} has a duplicate name");
            }
        }
        Ok(())
    }
}

impl Proxy {
    fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            bail!("name is required");
        }
        if self.proxy_type != "snell" || self.version != 4 {
            bail!("only Snell v4 nodes are supported");
        }
        if self.server.trim().is_empty() || self.port == 0 || self.psk.is_empty() {
            bail!("server, port, and PSK are required");
        }
        if !self.identity {
            bail!("identity authentication is required");
        }
        if self.obfs.mode != "ech-tls"
            || self.obfs.alpn != "snell-ech/1"
            || self.obfs.identity_version != 2
            || self.obfs.legacy_fallback
            || self.obfs.skip_cert_verify
        {
            bail!("unsupported ECH-TLS settings");
        }
        if self.obfs.sni.is_empty() || self.obfs.path.is_empty() || self.obfs.ech_config.is_empty()
        {
            bail!("SNI, path, and ECH config are required");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const YAML: &str = r#"
proxies:
  - name: Hong Kong Fusion 01
    type: snell
    server: node.cloud-nodes.com
    port: 443
    psk: secret
    version: 4
    udp: true
    tfo: false
    reuse: true
    identity: true
    obfs-opts:
      mode: ech-tls
      sni: example.com
      path: /
      alpn: snell-ech/1
      ech-config: AAAA
      identity-version: 2
      legacy-fallback: false
      skip-cert-verify: false
      preconnect: 0
"#;

    #[test]
    fn parses_and_filters_fusion_nodes() {
        let managed = ManagedConfig::parse(YAML.as_bytes()).unwrap();
        assert_eq!(managed.filter_premium_love().unwrap().proxies.len(), 1);
    }

    #[test]
    fn rejects_unknown_yaml_fields() {
        let content = YAML.replace("    udp: true", "    unexpected: true");
        assert!(ManagedConfig::parse(content.as_bytes()).is_err());
    }
}
