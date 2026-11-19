use std::collections::HashSet;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

const MAX_MANAGED_CONFIG_BYTES: usize = 8 << 20;

/// Only a successfully authenticated/decrypted document with an explicitly
/// empty array is authoritative. An all-invalid array is still a parse failure.
#[derive(Debug, thiserror::Error)]
#[error("remote catalog explicitly contains no nodes")]
pub(crate) struct EmptyCatalog;

#[derive(Clone, Debug, Default)]
pub struct NodeFilter {
    lines: Vec<String>,
    regions: Vec<String>,
    include: Vec<String>,
    exclude: Vec<String>,
}

#[derive(Serialize)]
pub struct FilterPreview {
    pub mode: &'static str,
    pub total: usize,
    pub kept: usize,
    pub excluded: usize,
    pub nodes: Vec<String>,
}

impl NodeFilter {
    pub fn new(lines: &str, regions: &str, include: &str, exclude: &str) -> Result<Self> {
        fn alternatives(value: &str) -> Result<Vec<String>> {
            if value.is_empty() {
                return Ok(Vec::new());
            }
            if value.len() > 4096 || value.chars().any(char::is_control) {
                bail!("node filter is too long or contains control characters");
            }
            let parts = value
                .split('|')
                .map(|p| p.trim().to_lowercase())
                .collect::<Vec<_>>();
            if parts.len() > 64 || parts.iter().any(String::is_empty) {
                bail!("node filter requires at most 64 nonempty alternatives separated by |");
            }
            Ok(parts)
        }
        let lines = alternatives(lines)?;
        if lines
            .iter()
            .any(|line| !line.chars().all(|c| c.is_ascii_alphanumeric()))
        {
            bail!(
                "node filter lines must be ASCII alphanumeric markers, such as Fusion, CIA or IXP"
            );
        }
        Ok(Self {
            lines,
            regions: alternatives(regions)?,
            include: alternatives(include)?,
            exclude: alternatives(exclude)?,
        })
    }

    pub fn is_custom(&self) -> bool {
        !self.lines.is_empty()
            || !self.regions.is_empty()
            || !self.include.is_empty()
            || !self.exclude.is_empty()
    }

    pub fn matches(&self, name: &str) -> bool {
        if !self.is_custom() {
            return is_allowed_node_name(name);
        }
        let lower = name.to_lowercase();
        let contains_any = |patterns: &[String]| patterns.iter().any(|p| lower.contains(p));
        let line_matches = self.lines.is_empty()
            || name
                .split(|c: char| !c.is_ascii_alphanumeric())
                .any(|token| {
                    self.lines
                        .iter()
                        .any(|line| token.eq_ignore_ascii_case(line))
                });
        line_matches
            && (self.regions.is_empty() || contains_any(&self.regions))
            && (self.include.is_empty() || contains_any(&self.include))
            && !contains_any(&self.exclude)
    }

    pub fn preview(&self, proxies: &[Proxy], all: bool) -> FilterPreview {
        let nodes = proxies
            .iter()
            .filter(|p| all || self.matches(&p.name))
            .map(|p| p.name.clone())
            .collect::<Vec<_>>();
        FilterPreview {
            mode: if all {
                "all"
            } else if self.is_custom() {
                "custom"
            } else {
                "default"
            },
            total: proxies.len(),
            kept: nodes.len(),
            excluded: proxies.len() - nodes.len(),
            nodes,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ManagedConfig {
    pub proxies: Vec<Proxy>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct Proxy {
    pub name: String,
    #[serde(rename = "type")]
    pub proxy_type: String,
    pub server: String,
    pub port: u16,
    #[serde(default, alias = "password")]
    pub psk: String,
    #[serde(default)]
    pub version: u8,
    #[serde(default)]
    pub udp: bool,
    #[serde(default)]
    pub tfo: bool,
    #[serde(default)]
    pub reuse: bool,
    #[serde(default)]
    pub identity: bool,
    #[serde(rename = "obfs-opts", default)]
    pub obfs: ObfsOptions,
    #[serde(
        default,
        alias = "anytls-opts",
        skip_serializing_if = "Option::is_none"
    )]
    pub anytls: Option<AnyTlsOptions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oixcloud: Option<OixcloudMetadata>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
pub struct ObfsOptions {
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub sni: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub alpn: String,
    #[serde(rename = "ech-config", default)]
    pub ech_config: String,
    // New subscriptions omit this retired migration field. The wire protocol
    // remains Identity v2; an explicitly incompatible value is still rejected.
    #[serde(rename = "identity-version", default = "default_identity_version")]
    pub identity_version: u8,
    #[serde(rename = "legacy-fallback", default)]
    pub legacy_fallback: bool,
    #[serde(rename = "skip-cert-verify", default)]
    pub skip_cert_verify: bool,
    #[serde(default)]
    pub preconnect: u8,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
pub struct AnyTlsOptions {
    #[serde(default, rename = "webSocketPath", alias = "websocket-path")]
    pub websocket_path: Option<String>,
    #[serde(default, rename = "usesCDN", alias = "uses-cdn")]
    pub uses_cdn: bool,
    #[serde(default)]
    pub udp: bool,
}

/// Advisory subscription metadata, never used for authentication or billing.
/// Unknown fields are intentionally ignored, as with the rest of the catalog.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct OixcloudMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traffic_rate: Option<serde_json::Number>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warp: Option<bool>,
}

fn default_identity_version() -> u8 {
    2
}

/// The API document is parsed per node so that one node the client cannot
/// use does not take every other node offline. Unknown extension fields are
/// ignored; known connection settings are still validated strictly.
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
        if remote.proxies.is_empty() {
            return Err(EmptyCatalog.into());
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

    pub fn filtered_proxies(&self, filter: &NodeFilter) -> Result<Vec<Proxy>> {
        let proxies = self
            .proxies
            .iter()
            .filter(|p| filter.matches(&p.name))
            .cloned()
            .collect::<Vec<_>>();
        if proxies.is_empty() {
            bail!("node filter kept no nodes; use preview-nodes to inspect the selection");
        }
        Ok(proxies)
    }

    pub fn filter_allowed_nodes(self) -> Result<Self> {
        let proxies = self.allowed_proxies();
        if proxies.is_empty() {
            bail!("managed config contains no allowed Fusion/CIA proxies");
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
    /// Metadata-only updates must not discard live clients or idle connections.
    pub(crate) fn same_connection_settings(&self, other: &Self) -> bool {
        self.name == other.name
            && self.proxy_type == other.proxy_type
            && self.server == other.server
            && self.port == other.port
            && self.psk == other.psk
            && self.version == other.version
            && self.udp == other.udp
            && self.tfo == other.tfo
            && self.reuse == other.reuse
            && self.identity == other.identity
            && self.obfs == other.obfs
            && self.anytls == other.anytls
    }

    fn from_value(mut value: serde_yaml::Value) -> Result<Self> {
        // Normalize the standard AnyTLS subscription fields into our cache model.
        if value.get("type").and_then(serde_yaml::Value::as_str) == Some("anytls") {
            if let Some(transport) = value.get("transport")
                && !matches!(transport.as_str(), Some("tcp" | "auto"))
            {
                bail!("unsupported AnyTLS transport");
            }
            if value.get("tls").is_some_and(|v| v.as_bool() != Some(true)) {
                bail!("AnyTLS requires TLS");
            }
            if let Some(network) = value.get("network") {
                match network.as_str() {
                    Some("tcp") => {}
                    Some("ws") => {
                        let path = value
                            .get("ws-opts")
                            .and_then(|v| v.get("path"))
                            .and_then(serde_yaml::Value::as_str)
                            .ok_or_else(|| anyhow::anyhow!("AnyTLS WebSocket path is required"))?
                            .to_owned();
                        if let Some(headers) = value.get("ws-opts").and_then(|v| v.get("headers"))
                            && !headers.as_mapping().is_some_and(|map| {
                                map.iter().all(|(k, v)| {
                                    k.as_str().is_some_and(|k| k.eq_ignore_ascii_case("host"))
                                        && v == value
                                            .get("server")
                                            .unwrap_or(&serde_yaml::Value::Null)
                                })
                            })
                        {
                            bail!("unsupported AnyTLS WebSocket headers");
                        }
                        let options = AnyTlsOptions {
                            websocket_path: Some(path),
                            uses_cdn: true,
                            udp: false,
                        };
                        value
                            .as_mapping_mut()
                            .unwrap()
                            .insert("anytls".into(), serde_yaml::to_value(options)?);
                    }
                    _ => bail!("unsupported AnyTLS transport"),
                }
            }
            let sni = value.get("sni").cloned();
            let skip = value.get("skip-cert-verify").cloned();
            if let Some(map) = value.as_mapping_mut() {
                let obfs = map
                    .entry(serde_yaml::Value::from("obfs-opts"))
                    .or_insert_with(|| serde_yaml::Value::Mapping(Default::default()));
                if let Some(obfs) = obfs.as_mapping_mut() {
                    if let Some(v) = sni {
                        obfs.insert("sni".into(), v);
                    }
                    if let Some(v) = skip {
                        obfs.insert("skip-cert-verify".into(), v);
                    }
                }
            }
        }
        // serde errors can quote field values such as the PSK.
        let mut proxy: Self = serde_yaml::from_value(value)
            .map_err(|_| anyhow::anyhow!("does not match the expected schema"))?;
        if proxy.proxy_type == "anytls" {
            proxy.udp |= proxy.anytls.as_ref().is_some_and(|o| o.udp);
        }
        proxy.validate()?;
        Ok(proxy)
    }

    fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            bail!("name is required");
        }
        if let Some(rate) = self
            .oixcloud
            .as_ref()
            .and_then(|meta| meta.traffic_rate.as_ref())
            && !rate
                .as_f64()
                .is_some_and(|value| value.is_finite() && value >= 0.0)
        {
            bail!("invalid oixcloud traffic rate");
        }
        if self.proxy_type == "anytls" {
            if self.server.trim().is_empty() || self.port == 0 || self.psk.is_empty() {
                bail!("AnyTLS server, port and password are required");
            }
            if self.obfs.skip_cert_verify {
                bail!("AnyTLS requires certificate verification");
            }
            if !matches!(self.version, 0 | 2)
                || !matches!(self.obfs.mode.as_str(), "" | "tls")
                || !self.obfs.ech_config.is_empty()
                || !self.obfs.alpn.is_empty()
                || self.obfs.legacy_fallback
            {
                bail!("unsupported AnyTLS TLS settings");
            }
            if let Some(options) = &self.anytls {
                if let Some(path) = &options.websocket_path {
                    crate::transport::websocket::validate_path(path)?;
                }
                if options.uses_cdn && options.websocket_path.is_none() {
                    bail!("AnyTLS CDN requires a WebSocket path");
                }
            }
            crate::surge::node_selector(&self.name)?;
            return Ok(());
        }
        if self.proxy_type != "snell" || self.version != 4 || self.anytls.is_some() {
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
        if let Some(rate) = self
            .oixcloud
            .as_ref()
            .and_then(|meta| meta.traffic_rate.as_ref())
            && !rate
                .as_f64()
                .is_some_and(|value| value.is_finite() && value >= 0.0)
        {
            bail!("invalid oixcloud traffic rate");
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) const TEST_ECH_CONFIG: &str = "AEX+DQBBBwAgACABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fIAAEAAEAAQAScHVibGljLmV4YW1wbGUuY29tAAA=";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anytls_nodes_normalize_standard_fields_and_cache_without_losing_cdn_options() {
        let direct=b"proxies:\n- name: AnyTLS Fusion\n  type: anytls\n  server: example.com\n  port: 443\n  password: test-password\n  sni: origin.example.com\n  anytls:\n    webSocketPath: /carrier\n    usesCDN: true\n    udp: true\n  future-extension: true\n";
        let managed = ManagedConfig::parse(direct).unwrap();
        let node = &managed.proxies[0];
        assert_eq!(node.psk, "test-password");
        assert_eq!(node.obfs.sni, "origin.example.com");
        assert!(node.udp);
        assert_eq!(
            node.anytls.as_ref().unwrap().websocket_path.as_deref(),
            Some("/carrier")
        );
        let cached: ManagedConfig =
            serde_yaml::from_slice(&serde_yaml::to_string(&managed).unwrap().into_bytes()).unwrap();
        cached.validate().unwrap();
        assert_eq!(managed, cached);
        let ws=b"proxies:\n- name: WS\n  type: anytls\n  server: example.com\n  port: 443\n  password: secret\n  tls: true\n  network: ws\n  ws-opts:\n    path: /carrier\n    headers:\n      Host: example.com\n";
        assert_eq!(
            ManagedConfig::parse(ws).unwrap().proxies[0]
                .anytls
                .as_ref()
                .unwrap()
                .websocket_path
                .as_deref(),
            Some("/carrier")
        );
        for (old, new) in [
            ("tls: true", "tls: false"),
            ("network: ws", "network: grpc"),
            ("path: /carrier", "path: invalid"),
            ("Host: example.com", "Host: other.example.com"),
        ] {
            assert!(
                ManagedConfig::parse(
                    String::from_utf8(ws.to_vec())
                        .unwrap()
                        .replace(old, new)
                        .as_bytes()
                )
                .is_err()
            );
        }
        let invalid = String::from_utf8(direct.to_vec())
            .unwrap()
            .replace("  sni:", "  skip-cert-verify: true\n  sni:");
        assert!(ManagedConfig::parse(invalid.as_bytes()).is_err());
    }

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
    fn omitted_migration_fields_default_to_secure_identity_v2() {
        let modern = YAML
            .replace("      identity-version: 2\n", "")
            .replace("      legacy-fallback: false\n", "");
        let current = ManagedConfig::parse(modern.as_bytes()).unwrap();
        assert_eq!(current, ManagedConfig::parse(YAML.as_bytes()).unwrap());
        assert_eq!(current.proxies[0].obfs.identity_version, 2);
        assert!(!current.proxies[0].obfs.legacy_fallback);
        for (from, to) in [
            ("      alpn: snell-ech/1", "      alpn: h2"),
            ("      mode: ech-tls", "      mode: tls"),
            (
                "      skip-cert-verify: false",
                "      skip-cert-verify: true",
            ),
            ("    identity: true", "    identity: false"),
            ("    version: 4", "    version: 6"),
        ] {
            assert!(ManagedConfig::parse(modern.replace(from, to).as_bytes()).is_err());
        }
        for explicit in ["0", "1", "3", "null", "\"2\""] {
            let invalid = modern.replace(
                "      preconnect: 0",
                &format!("      preconnect: 0\n      identity-version: {explicit}"),
            );
            assert!(ManagedConfig::parse(invalid.as_bytes()).is_err());
        }
        let legacy = modern.replace(
            "      preconnect: 0",
            "      preconnect: 0\n      legacy-fallback: true",
        );
        assert!(ManagedConfig::parse(legacy.as_bytes()).is_err());
    }

    #[test]
    fn custom_filters_combine_groups_and_preview_empty_results() {
        let mut managed = ManagedConfig::parse(YAML.as_bytes()).unwrap();
        let template = managed.proxies[0].clone();
        managed.proxies = [
            "香港 Fusion 01",
            "香港 Fusion 维护",
            "日本 CIA 01",
            "Japan IXP 01",
            "香港 Special 01",
        ]
        .into_iter()
        .map(|name| {
            let mut proxy = template.clone();
            proxy.name = name.to_owned();
            proxy
        })
        .collect();
        let filter = NodeFilter::new("Fusion|CIA", "香港|日本", "01", "维护").unwrap();
        let preview = filter.preview(&managed.proxies, false);
        assert_eq!(preview.mode, "custom");
        assert_eq!(preview.kept, 2);
        assert_eq!(preview.nodes, ["香港 Fusion 01", "日本 CIA 01"]);
        assert_eq!(filter.preview(&managed.proxies, true).kept, 5);
        assert!(
            !NodeFilter::new("CIA", "", "", "")
                .unwrap()
                .matches("香港 Special 01")
        );
        assert!(
            NodeFilter::new("IXP", "Japan", "", "")
                .unwrap()
                .matches("Japan IxP 01")
        );
        let empty = NodeFilter::new("", "不存在", "", "").unwrap();
        assert_eq!(empty.preview(&managed.proxies, false).kept, 0);
        assert!(managed.filtered_proxies(&empty).is_err());
        assert_eq!(
            NodeFilter::default().preview(&managed.proxies, false).kept,
            3
        );
        for invalid in ["香港|", "|日本", "香港||日本", "香港\n日本"] {
            assert!(NodeFilter::new("", invalid, "", "").is_err());
        }
    }

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
        let content = YAML.replace("port: 443", "port: 0");
        assert!(ManagedConfig::parse(content.as_bytes()).is_err());
        assert!(ManagedConfig::parse(b"proxies: []\n").is_err());
        assert!(ManagedConfig::parse(b"other: true\n").is_err());
        assert!(
            ManagedConfig::parse(b"proxies: []\n")
                .unwrap_err()
                .is::<EmptyCatalog>()
        );
        assert!(
            !ManagedConfig::parse(content.as_bytes())
                .unwrap_err()
                .is::<EmptyCatalog>()
        );
    }

    #[test]
    fn ignores_extensions_at_document_node_and_obfs_levels() {
        let expected = ManagedConfig::parse(YAML.as_bytes()).unwrap();
        let mut document: serde_yaml::Value = serde_yaml::from_str(YAML).unwrap();
        document["future-document"] = serde_yaml::from_str("{nested: [true, 42]}").unwrap();
        document["proxies"][0]["future-node"] = "future-private-value".into();
        document["proxies"][0]["obfs-opts"]["future-obfs"] =
            serde_yaml::from_str("[1, {new: true}]").unwrap();
        let yaml = serde_yaml::to_string(&document).unwrap();
        assert_eq!(ManagedConfig::parse(yaml.as_bytes()).unwrap(), expected);
        assert_eq!(
            serde_yaml::from_str::<ManagedConfig>(&yaml).unwrap(),
            expected
        );
        // An unknown key is not an unusable node, even in a mixed catalog.
        let second = YAML
            .trim_start_matches("\nproxies:\n")
            .replace("Hong Kong Fusion 01", "Japan Fusion 02")
            .replace("    udp: true", "    udp: true\n    future-node: true");
        assert_eq!(
            ManagedConfig::parse(with_second_proxy(&second).as_bytes())
                .unwrap()
                .proxies
                .len(),
            2
        );
    }

    #[test]
    fn oixcloud_metadata_is_optional_extensible_and_round_trips_decimal_rates() {
        let original = ManagedConfig::parse(YAML.as_bytes()).unwrap();
        assert!(original.proxies[0].oixcloud.is_none());
        for rate in ["0", "0.5", "1", "1.0", "2", "2.75"] {
            let yaml = format!(
                "{YAML}    oixcloud:\n      traffic-rate: {rate}\n      warp: true\n      future-metadata: {{nested: [true, 42]}}\n"
            );
            let parsed = ManagedConfig::parse(yaml.as_bytes()).unwrap();
            let meta = parsed.proxies[0].oixcloud.as_ref().unwrap();
            assert_eq!(
                meta.traffic_rate.as_ref().unwrap().as_f64().unwrap(),
                rate.parse::<f64>().unwrap()
            );
            assert_eq!(meta.warp, Some(true));
            assert_eq!(
                ManagedConfig::parse(serde_yaml::to_string(&parsed).unwrap().as_bytes()).unwrap(),
                parsed
            );
            assert!(original.proxies[0].same_connection_settings(&parsed.proxies[0]));
        }
        let partial =
            ManagedConfig::parse(format!("{YAML}    oixcloud:\n      warp: false\n").as_bytes())
                .unwrap();
        assert_eq!(
            partial.proxies[0].oixcloud.as_ref().unwrap().warp,
            Some(false)
        );
        assert!(
            partial.proxies[0]
                .oixcloud
                .as_ref()
                .unwrap()
                .traffic_rate
                .is_none()
        );
    }

    #[test]
    fn unknown_fields_do_not_bypass_validation_of_known_fields() {
        let extensible = format!(
            "{YAML}    future-node: true\n    oixcloud:\n      traffic-rate: 1\n      warp: false\n      future-metadata: true\n"
        );
        for (from, to) in [
            ("port: 443", "port: 0"),
            ("port: 443", "port: not-a-port"),
            ("psk: secret", "psk: ''"),
            ("sni: example.com", "sni: ''"),
            ("version: 4", "version: 6"),
            ("identity: true", "identity: false"),
            ("identity-version: 2", "identity-version: 1"),
            ("legacy-fallback: false", "legacy-fallback: true"),
            ("skip-cert-verify: false", "skip-cert-verify: true"),
            ("mode: ech-tls", "mode: tls"),
            ("alpn: snell-ech/1", "alpn: h2"),
            (TEST_ECH_CONFIG, "AAAA"),
            ("traffic-rate: 1", "traffic-rate: -1"),
            ("traffic-rate: 1", "traffic-rate: .nan"),
            ("traffic-rate: 1", "traffic-rate: .inf"),
            ("traffic-rate: 1", "traffic-rate: '2'"),
            ("warp: false", "warp: 'false'"),
        ] {
            let error = ManagedConfig::parse(extensible.replace(from, to).as_bytes()).unwrap_err();
            assert!(!format!("{error:#}").contains("psk: secret"));
        }
        assert!(
            ManagedConfig::parse(extensible.replace("    psk: secret\n", "").as_bytes()).is_err()
        );
    }
}
