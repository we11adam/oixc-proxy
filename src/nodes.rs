use std::collections::HashSet;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

const MAX_MANAGED_CONFIG_BYTES: usize = 8 << 20;

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

/// The API document is parsed per node so that one node the client cannot
/// use, for example after the server adds a field, does not take every other
/// node offline. Each node is still validated strictly.
#[derive(Deserialize)]
struct RemoteManagedConfig {
    proxies: Vec<serde_yaml::Value>,
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
        let remote = RemoteManagedConfig::deserialize(first).map_err(|_| {
            anyhow::anyhow!("managed config does not match the expected YAML schema")
        })?;
        if documents.next().is_some() {
            bail!("managed config contains multiple YAML documents");
        }
        let mut proxies = Vec::with_capacity(remote.proxies.len());
        let mut names = HashSet::with_capacity(remote.proxies.len());
        for (index, value) in remote.proxies.into_iter().enumerate() {
            let label = proxy_label(index, &value);
            match Proxy::from_value(value) {
                Ok(proxy) if names.insert(proxy.name.clone()) => proxies.push(proxy),
                Ok(_) => eprintln!("skipping {label}: duplicate name"),
                Err(error) => eprintln!("skipping {label}: {error:#}"),
            }
        }
        let config = Self { proxies };
        config.validate()?;
        Ok(config)
    }

    pub fn allowed_proxies(&self) -> Vec<Proxy> {
        self.proxies
            .iter()
            .filter(|proxy| is_allowed_node_name(&proxy.name))
            .cloned()
            .collect()
    }

    pub fn filter_allowed_nodes(self) -> Result<Self> {
        let proxies = self.allowed_proxies();
        if proxies.is_empty() {
            bail!("managed config contains no allowed Fusion/CIA/IXP proxies");
        }
        Ok(Self { proxies })
    }

    pub(crate) fn validate(&self) -> Result<()> {
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

fn is_allowed_node_name(name: &str) -> bool {
    if name.to_lowercase().contains("fusion") {
        return true;
    }
    name.split(|character: char| !character.is_alphanumeric())
        .any(|token| token.eq_ignore_ascii_case("cia"))
}

fn proxy_label(index: usize, value: &serde_yaml::Value) -> String {
    match value.get("name").and_then(serde_yaml::Value::as_str) {
        Some(name) => format!("proxy at index {index} ({name})"),
        None => format!("proxy at index {index}"),
    }
}

impl Proxy {
    fn from_value(value: serde_yaml::Value) -> Result<Self> {
        // serde errors can quote field values such as the PSK.
        let proxy: Self = serde_yaml::from_value(value)
            .map_err(|_| anyhow::anyhow!("does not match the expected schema"))?;
        proxy.validate()?;
        Ok(proxy)
    }

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
        crate::transport::parse_ech_config(&self.obfs.ech_config)?;
        crate::surge::node_selector(&self.name)?;
        Ok(())
    }
}

#[cfg(test)]
pub(crate) const TEST_ECH_CONFIG: &str = "AEX+DQBBBwAgACABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fIAAEAAEAAQAScHVibGljLmV4YW1wbGUuY29tAAA=";

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
      ech-config: AEX+DQBBBwAgACABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fIAAEAAEAAQAScHVibGljLmV4YW1wbGUuY29tAAA=
      identity-version: 2
      legacy-fallback: false
      skip-cert-verify: false
      preconnect: 0
"#;

    #[test]
    fn filters_allowed_node_names_in_original_order() {
        let mut managed = ManagedConfig::parse(YAML.as_bytes()).unwrap();
        let template = managed.proxies.pop().unwrap();
        managed.proxies = [
            "Hong Kong 01",
            "Hong Kong Fusion 01",
            "United States cia 01",
            "Japan IxP 01",
            "United States Special 01",
            "Singapore 01",
        ]
        .into_iter()
        .map(|name| {
            let mut proxy = template.clone();
            proxy.name = name.to_owned();
            proxy
        })
        .collect();

        let allowed = managed.allowed_proxies();
        assert_eq!(
            allowed
                .iter()
                .map(|proxy| proxy.name.as_str())
                .collect::<Vec<_>>(),
            ["Hong Kong Fusion 01", "United States cia 01"]
        );
        assert_eq!(managed.proxies.len(), 6);

        let filtered = managed.filter_allowed_nodes().unwrap();
        assert_eq!(
            filtered
                .proxies
                .iter()
                .map(|proxy| proxy.name.as_str())
                .collect::<Vec<_>>(),
            ["Hong Kong Fusion 01", "United States cia 01"]
        );
    }

    #[test]
    fn rejects_catalog_without_allowed_node_names() {
        let mut managed = ManagedConfig::parse(YAML.as_bytes()).unwrap();
        managed.proxies[0].name = "Hong Kong 01".to_owned();
        assert!(managed.filter_allowed_nodes().is_err());
    }

    fn with_second_proxy(second: &str) -> String {
        let first = YAML.trim_start_matches("\nproxies:\n");
        format!("proxies:\n{first}{second}")
    }

    #[test]
    fn skips_unusable_proxies_and_keeps_the_rest() {
        let valid_second = YAML
            .trim_start_matches("\nproxies:\n")
            .replace("Hong Kong Fusion 01", "Japan Fusion 02");
        for second in [
            valid_second.replace("    udp: true", "    unexpected: true"),
            valid_second.replace("port: 443", "port: not-a-port"),
            valid_second.replace("mode: ech-tls", "mode: tls"),
            valid_second.replace("Japan Fusion 02", "Hong Kong Fusion 01"),
            "  - just a string\n".to_owned(),
            valid_second.replace(TEST_ECH_CONFIG, "AAAA"),
            valid_second.replace("Japan Fusion 02", &"x".repeat(200)),
        ] {
            let managed = ManagedConfig::parse(with_second_proxy(&second).as_bytes()).unwrap();
            assert_eq!(managed.proxies.len(), 1, "{second}");
            assert_eq!(managed.proxies[0].name, "Hong Kong Fusion 01");
        }
        let managed = ManagedConfig::parse(with_second_proxy(&valid_second).as_bytes()).unwrap();
        assert_eq!(managed.proxies.len(), 2);
    }

    #[test]
    fn ignores_unknown_top_level_keys() {
        let content = format!("{YAML}rules: []\n");
        assert_eq!(
            ManagedConfig::parse(content.as_bytes())
                .unwrap()
                .proxies
                .len(),
            1
        );
    }

    #[test]
    fn rejects_catalog_without_usable_proxies() {
        let content = YAML.replace("    udp: true", "    unexpected: true");
        assert!(ManagedConfig::parse(content.as_bytes()).is_err());
        assert!(ManagedConfig::parse(b"proxies: []\n").is_err());
        assert!(ManagedConfig::parse(b"other: true\n").is_err());
    }
}
