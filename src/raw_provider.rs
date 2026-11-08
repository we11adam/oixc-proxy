//! Sensitive, opt-in Surge export. Never logs parameters or resolver failures.
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::sync::{Mutex, Semaphore};
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::nodes::Proxy;
use crate::surge::{node_selector, sanitize_policy_name};

const CONCURRENCY: usize = 8;
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);

pub(crate) struct RawNodes {
    nodes: Vec<RawNode>,
    pub skipped: usize,
}

struct RawNode {
    policy: String,
    proxy: Proxy,
}

impl RawNodes {
    pub fn new(proxies: &[Proxy]) -> Self {
        let mut nodes = Vec::new();
        let mut names = HashMap::<String, usize>::new();
        let mut selectors = HashSet::new();
        for proxy in proxies {
            if !supported(proxy) {
                continue;
            }
            let Ok(selector) = node_selector(&proxy.name) else {
                continue;
            };
            if !selectors.insert(selector) {
                continue;
            }
            let policy = sanitize_policy_name(&proxy.name);
            if policy.chars().any(|c| "#;\"'\\".contains(c)) {
                continue;
            }
            *names.entry(policy.clone()).or_default() += 1;
            nodes.push(RawNode {
                policy,
                proxy: proxy.clone(),
            });
        }
        for node in &mut nodes {
            if names[&node.policy] > 1 {
                // Validation above guarantees the selector is usable.
                write!(
                    node.policy,
                    " [{}]",
                    node_selector(&node.proxy.name).unwrap()
                )
                .unwrap();
            }
        }
        Self {
            skipped: proxies.len() - nodes.len(),
            nodes,
        }
    }
}

fn safe_parameter(value: &str) -> bool {
    !value.is_empty()
        && !value
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || ",\"'\\#;".contains(c))
}

fn safe_host(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok()
        || (!host.is_empty()
            && host.len() <= 253
            && host
                .strip_suffix('.')
                .unwrap_or(host)
                .split('.')
                .all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && !label.starts_with('-')
                        && !label.ends_with('-')
                        && label
                            .bytes()
                            // Private DNS also uses underscore-bearing labels.
                            // They are safe in Surge fields even though stricter
                            // hostname grammars disallow them.
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                }))
}

fn supported(proxy: &Proxy) -> bool {
    if proxy.port == 0
        || !safe_host(&proxy.server)
        || (!proxy.obfs.sni.is_empty() && !safe_host(&proxy.obfs.sni))
        || !safe_parameter(&proxy.psk)
    {
        return false;
    }
    if proxy.proxy_type == "anytls" {
        return matches!(proxy.version, 0 | 2)
            && matches!(proxy.obfs.mode.as_str(), "" | "tls")
            && proxy.obfs.alpn.is_empty()
            && proxy.obfs.ech_config.is_empty()
            && !proxy.obfs.skip_cert_verify
            && !proxy.obfs.legacy_fallback
            && proxy.anytls.as_ref().is_none_or(|options| {
                (!options.uses_cdn || options.websocket_path.is_some())
                    && options.websocket_path.as_ref().is_none_or(|path| {
                        crate::transport::websocket::validate_path(path).is_ok()
                            && safe_parameter(path)
                    })
            });
    }
    proxy.proxy_type == "snell"
        && proxy.version == 4
        && proxy.obfs.mode == "ech-tls"
        && proxy.obfs.identity_version == 2
        && proxy.port != 0
        && safe_host(&proxy.server)
        && (proxy.obfs.sni.is_empty() || safe_host(&proxy.obfs.sni))
        && safe_parameter(&proxy.psk)
        && crate::transport::parse_ech_config(&proxy.obfs.ech_config).is_ok()
}

#[derive(Clone)]
pub(crate) struct RawProvider {
    last_good: Arc<Mutex<HashMap<String, IpAddr>>>,
    // Shared across requests, not just across workers of a single request.
    limit: Arc<Semaphore>,
}

impl Default for RawProvider {
    fn default() -> Self {
        Self {
            last_good: Arc::default(),
            limit: Arc::new(Semaphore::new(CONCURRENCY)),
        }
    }
}

impl RawProvider {
    async fn resolve<F, Fut>(&self, host: String, lookup: F) -> String
    where
        F: FnOnce(String) -> Fut,
        Fut: Future<Output = Result<Vec<IpAddr>>>,
    {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return ip.to_string();
        }
        let key = host.trim_end_matches('.').to_ascii_lowercase();
        let _permit = self.limit.acquire().await.expect("raw resolver stays open");
        let fresh = timeout(LOOKUP_TIMEOUT, lookup(host.clone())).await;
        if let Ok(Ok(addresses)) = fresh
            && let Some(ip) = addresses
                .iter()
                .find(|ip| ip.is_ipv4())
                .or(addresses.first())
        {
            self.last_good.lock().await.insert(key, *ip);
            return ip.to_string();
        }
        self.last_good
            .lock()
            .await
            .get(&key)
            .map(ToString::to_string)
            .unwrap_or(host)
    }

    pub async fn render<F, Fut>(&self, nodes: &RawNodes, lookup: F) -> Vec<u8>
    where
        F: Fn(String) -> Fut + Clone + Send + 'static,
        Fut: Future<Output = Result<Vec<IpAddr>>> + Send + 'static,
    {
        let mut seen = HashSet::new();
        let mut hosts = nodes
            .nodes
            .iter()
            .map(|n| n.proxy.server.clone())
            .filter(|host| seen.insert(host.clone()));
        let mut tasks = JoinSet::new();
        let mut addresses = HashMap::new();
        // Do not spawn one waiting task per node in a potentially large catalog.
        loop {
            while tasks.len() < CONCURRENCY {
                let Some(host) = hosts.next() else { break };
                let resolver = self.clone();
                let lookup = lookup.clone();
                tasks.spawn(async move {
                    let address = resolver.resolve(host.clone(), lookup).await;
                    (host, address)
                });
            }
            let Some(result) = tasks.join_next().await else {
                break;
            };
            if let Ok((host, address)) = result {
                addresses.insert(host, address);
            }
        }
        let mut output = String::new();
        for node in &nodes.nodes {
            let proxy = &node.proxy;
            let server = addresses.get(&proxy.server).unwrap_or(&proxy.server);
            let sni = if proxy.obfs.sni.is_empty() {
                &proxy.server
            } else {
                &proxy.obfs.sni
            };
            if proxy.proxy_type == "anytls" {
                write!(
                    output,
                    "{} = anytls, {server}, {}, password={}, sni={sni}",
                    node.policy, proxy.port, proxy.psk
                )
                .unwrap();
                if let Some(path) = proxy
                    .anytls
                    .as_ref()
                    .and_then(|options| options.websocket_path.as_ref())
                {
                    // The socket address may be an IP. Keep the source hostname
                    // for outer TLS verification and HTTP Host independently.
                    write!(
                        output,
                        ", obfs=wss-tls, obfs-host={}, obfs-uri={path}",
                        proxy.server
                    )
                    .unwrap();
                }
                let udp = proxy.udp || proxy.anytls.as_ref().is_some_and(|options| options.udp);
                // AnyTLS defaults to session reuse, unlike the Snell flag.
                writeln!(output, ", reuse=true, udp-relay={udp}").unwrap();
                continue;
            }
            writeln!(output,
                "{} = snell, {server}, {}, psk={}, version=4, obfs=ech-tls, obfs-host={sni}, ech-config={}, reuse={}, udp-relay={}{}{}",
                node.policy, proxy.port, proxy.psk, proxy.obfs.ech_config, proxy.reuse, proxy.udp,
                if proxy.tfo { ", tfo=true" } else { "" },
                if proxy.obfs.skip_cert_verify { ", skip-cert-verify=true" } else { "" },
            ).unwrap();
        }
        output.into_bytes()
    }
}

#[cfg(test)]
pub(crate) fn test_proxy(name: &str) -> Proxy {
    use base64::Engine as _;
    // Synthetic X25519 key and reserved ECH public name, not a deployed config.
    let mut content = vec![7, 0, 32, 0, 32];
    content.extend(1..=32);
    content.extend([0, 4, 0, 1, 0, 1, 0, 19]);
    content.extend(b"public.example.test");
    content.extend([0, 0]);
    let mut entry = vec![0xfe, 0x0d];
    entry.extend((content.len() as u16).to_be_bytes());
    entry.extend(content);
    let mut list = (entry.len() as u16).to_be_bytes().to_vec();
    list.extend(entry);
    Proxy {
        name: name.into(),
        proxy_type: "snell".into(),
        server: "node.example.test".into(),
        port: 443,
        psk: "mock-secret".into(),
        version: 4,
        udp: true,
        tfo: false,
        reuse: true,
        identity: true,
        oixcloud: None,
        anytls: None,
        obfs: crate::nodes::ObfsOptions {
            mode: "ech-tls".into(),
            sni: "sni.example.test".into(),
            path: "/".into(),
            alpn: "snell-ech/1".into(),
            ech_config: base64::engine::general_purpose::STANDARD.encode(list),
            identity_version: 2,
            legacy_fallback: false,
            skip_cert_verify: false,
            preconnect: 0,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn anytls(name: &str, path: Option<&str>) -> Proxy {
        Proxy {
            name: name.into(),
            proxy_type: "anytls".into(),
            server: "cdn.example.test".into(),
            port: 443,
            psk: "mock-secret".into(),
            version: 0,
            udp: false,
            tfo: false,
            reuse: false,
            identity: false,
            oixcloud: None,
            anytls: Some(crate::nodes::AnyTlsOptions {
                websocket_path: path.map(str::to_owned),
                uses_cdn: path.is_some(),
                udp: true,
            }),
            obfs: crate::nodes::ObfsOptions {
                sni: "origin.example.test".into(),
                ..Default::default()
            },
        }
    }

    #[tokio::test]
    async fn mixed_protocol_export_preserves_order_and_both_tls_names() {
        let proxies = [
            test_proxy("Snell Fusion"),
            anytls("Plain AnyTLS", None),
            anytls("CDN AnyTLS", Some("/carrier?route=1&mode=tls")),
        ];
        let nodes = RawNodes::new(&proxies);
        assert_eq!(nodes.skipped, 0);
        let output = RawProvider::default()
            .render(&nodes, |_| async {
                Ok(vec!["203.0.113.10".parse().unwrap()])
            })
            .await;
        let output = String::from_utf8(output).unwrap();
        let lines: Vec<_> = output.lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(
            format!("{}\n", lines[1..].join("\n")),
            include_str!("../testdata/anytls-raw-provider.conf")
        );
        assert!(lines[0].starts_with(
            "Snell Fusion = snell, 203.0.113.10, 443, psk=mock-secret, version=4, obfs=ech-tls,"
        ));
        assert_eq!(
            lines[1],
            "Plain AnyTLS = anytls, 203.0.113.10, 443, password=mock-secret, sni=origin.example.test, reuse=true, udp-relay=true"
        );
        assert_eq!(
            lines[2],
            "CDN AnyTLS = anytls, 203.0.113.10, 443, password=mock-secret, sni=origin.example.test, obfs=wss-tls, obfs-host=cdn.example.test, obfs-uri=/carrier?route=1&mode=tls, reuse=true, udp-relay=true"
        );
        assert!(!lines[1].contains("obfs="));
        for line in &lines[1..] {
            for forbidden in ["psk=", "version=", "ech-config=", "identity="] {
                assert!(!line.contains(forbidden));
            }
        }
    }

    #[tokio::test]
    async fn anytls_dns_fallback_and_ipv6_keep_original_sni_and_cdn_host() {
        let mut plain = anytls("Plain", None);
        plain.obfs.sni.clear();
        plain.anytls = None;
        let nodes = RawNodes::new(&[plain, anytls("CDN", Some("/carrier"))]);
        let resolver = RawProvider::default();
        let lookup_fail = |_| async { anyhow::bail!("mock DNS failure") };
        let unresolved = String::from_utf8(resolver.render(&nodes, lookup_fail).await).unwrap();
        assert!(unresolved.contains("Plain = anytls, cdn.example.test, 443, password=mock-secret, sni=cdn.example.test, reuse=true, udp-relay=false"));
        let resolved = resolver
            .render(&nodes, |_| async {
                Ok(vec!["2001:db8::1".parse().unwrap()])
            })
            .await;
        assert_eq!(resolver.render(&nodes, lookup_fail).await, resolved);
        let resolved = String::from_utf8(resolved).unwrap();
        assert!(resolved.contains(
            "Plain = anytls, 2001:db8::1, 443, password=mock-secret, sni=cdn.example.test,"
        ));
        assert!(resolved.contains("CDN = anytls, 2001:db8::1, 443, password=mock-secret, sni=origin.example.test, obfs=wss-tls, obfs-host=cdn.example.test, obfs-uri=/carrier,"));
    }

    #[test]
    fn anytls_rejects_partial_cdn_profiles_and_unrepresentable_fields() {
        let base = anytls("Mock", Some("/carrier"));
        let mut invalid = Vec::new();
        let mut p = base.clone();
        p.anytls.as_mut().unwrap().websocket_path = None;
        invalid.push(p);
        let mut p = base.clone();
        p.obfs.skip_cert_verify = true;
        invalid.push(p);
        let mut p = base.clone();
        p.obfs.mode = "ech-tls".into();
        invalid.push(p);
        let mut p = base.clone();
        p.obfs.alpn = "h3".into();
        invalid.push(p);
        let mut p = base.clone();
        p.obfs.ech_config = "unexpected".into();
        invalid.push(p);
        let mut p = base.clone();
        p.version = 6;
        invalid.push(p);
        for path in [
            "/path,other=value",
            "/path\nInjected = direct",
            "/path#fragment",
            "/path;comment",
            "/path with space",
            "/path\\escape",
            "/path\"quoted",
        ] {
            let mut p = base.clone();
            p.anytls.as_mut().unwrap().websocket_path = Some(path.into());
            invalid.push(p);
        }
        for password in ["", "mock,value", "mock\nvalue", "mock value", "mock\"value"] {
            let mut p = base.clone();
            p.psk = password.into();
            invalid.push(p);
        }
        let nodes = RawNodes::new(&invalid);
        assert_eq!(nodes.skipped, invalid.len());
        assert!(nodes.nodes.is_empty());
        assert_eq!(RawNodes::new(&[base]).skipped, 0);
    }

    #[tokio::test]
    async fn anytls_policy_collisions_and_optional_cdn_marker_follow_existing_contract() {
        let mut a = anytls("Mock,A", Some("/carrier"));
        a.anytls.as_mut().unwrap().uses_cdn = false;
        let b = anytls("Mock=A", None);
        let nodes = RawNodes::new(&[a, b]);
        let output = RawProvider::default()
            .render(&nodes, |_| async { anyhow::bail!("offline") })
            .await;
        let output = String::from_utf8(output).unwrap();
        let lines: Vec<_> = output.lines().collect();
        assert_eq!(lines.len(), 2);
        for (line, name) in lines.iter().zip(["Mock,A", "Mock=A"]) {
            assert!(line.starts_with(&format!(
                "Mock A [{}] = anytls,",
                node_selector(name).unwrap()
            )));
        }
        assert!(lines[0].contains("obfs=wss-tls"));
        assert!(!lines[1].contains("obfs="));
    }

    #[tokio::test]
    async fn renders_exact_snell_parameters_and_prefers_ipv4() {
        let mut proxy = test_proxy("Mock Fusion 01");
        proxy.oixcloud = Some(crate::nodes::OixcloudMetadata {
            traffic_rate: Some(2.into()),
            warp: Some(true),
        });
        let expected = format!(
            "Mock Fusion 01 = snell, 192.0.2.1, 443, psk=mock-secret, version=4, obfs=ech-tls, obfs-host=sni.example.test, ech-config={}, reuse=true, udp-relay=true\n",
            proxy.obfs.ech_config
        );
        let nodes = RawNodes::new(&[proxy]);
        assert_eq!(nodes.skipped, 0);
        let output = RawProvider::default()
            .render(&nodes, |_| async {
                Ok(vec![
                    "2001:db8::1".parse().unwrap(),
                    "192.0.2.1".parse().unwrap(),
                ])
            })
            .await;
        assert_eq!(String::from_utf8(output).unwrap(), expected);
    }

    #[tokio::test]
    async fn renders_underscore_dns_labels_without_skipping_private_dns_nodes() {
        let mut proxy = test_proxy("Mock Fusion 01");
        proxy.server = "node_fusion.example.test".into();
        let nodes = RawNodes::new(&[proxy]);
        assert_eq!(nodes.skipped, 0);
        let resolver = RawProvider::default();
        let resolved = resolver
            .render(&nodes, |host| async move {
                assert_eq!(host, "node_fusion.example.test");
                Ok(vec!["192.0.2.1".parse().unwrap()])
            })
            .await;
        let resolved = String::from_utf8(resolved).unwrap();
        assert!(resolved.starts_with("Mock Fusion 01 = snell, 192.0.2.1, 443,"));
        let failed = resolver
            .render(&nodes, |_| async { anyhow::bail!("mock failure") })
            .await;
        assert_eq!(String::from_utf8(failed).unwrap(), resolved);
        let uncached = RawProvider::default()
            .render(&nodes, |_| async { anyhow::bail!("mock failure") })
            .await;
        assert!(
            String::from_utf8(uncached)
                .unwrap()
                .starts_with("Mock Fusion 01 = snell, node_fusion.example.test, 443,")
        );
    }

    #[tokio::test]
    async fn ipv6_optional_flags_and_original_hostname_sni() {
        let mut proxy = test_proxy("Mock Fusion 01");
        proxy.obfs.sni.clear();
        proxy.reuse = false;
        proxy.udp = false;
        proxy.tfo = true;
        proxy.obfs.skip_cert_verify = true;
        let nodes = RawNodes::new(&[proxy]);
        let output = RawProvider::default()
            .render(&nodes, |_| async {
                Ok(vec!["2001:db8::1".parse().unwrap()])
            })
            .await;
        let output = String::from_utf8(output).unwrap();
        assert!(output.starts_with("Mock Fusion 01 = snell, 2001:db8::1, 443, psk=mock-secret,"));
        assert!(output.contains("obfs-host=node.example.test,"));
        assert!(
            output.ends_with("reuse=false, udp-relay=false, tfo=true, skip-cert-verify=true\n")
        );
        for forbidden in ["path=", "preconnect=", "identity", "["] {
            assert!(!output.contains(forbidden));
        }
    }

    #[tokio::test]
    async fn sanitizes_policy_names_and_suffixes_collisions_like_normal_provider() {
        let names = ["Mock,Name", "Mock=Name", "Mock\nName"];
        let proxies = names.map(test_proxy);
        let nodes = RawNodes::new(&proxies);
        let output = RawProvider::default()
            .render(&nodes, |_| async { anyhow::bail!("mock failure") })
            .await;
        let output = String::from_utf8(output).unwrap();
        assert_eq!(output.lines().count(), 3);
        for (line, name) in output.lines().zip(names) {
            assert!(line.starts_with(&format!(
                "Mock Name [{}] = snell, node.example.test,",
                node_selector(name).unwrap()
            )));
        }
    }

    #[test]
    fn skips_unsupported_profiles_and_unsafe_values_without_rendering_partial_lines() {
        let base = test_proxy("Mock Fusion 01");
        let mut invalid = Vec::new();
        for version in [0, 5, 6] {
            let mut p = base.clone();
            p.version = version;
            invalid.push(p);
        }
        for mode in ["tls", "http", "ech-tls\n"] {
            let mut p = base.clone();
            p.obfs.mode = mode.into();
            invalid.push(p);
        }
        let mut p = base.clone();
        p.obfs.identity_version = 1;
        invalid.push(p);
        let mut p = base.clone();
        p.proxy_type = "other".into();
        invalid.push(p);
        for value in [
            "",
            "mock,psk=other",
            "mock\nother",
            "mock\rvalue",
            "mock value",
            "mock#comment",
            "mock\\value",
            "mock\"value",
        ] {
            let mut p = base.clone();
            p.psk = value.into();
            invalid.push(p);
        }
        for value in [
            "",
            "bad,host",
            "node.example.test\n",
            "node=bad",
            "[2001:db8::1]",
        ] {
            let mut p = base.clone();
            p.server = value.into();
            invalid.push(p);
        }
        for value in ["bad,host", "sni.example.test\n", "sni=bad"] {
            let mut p = base.clone();
            p.obfs.sni = value.into();
            invalid.push(p);
        }
        for value in ["", "not-base64", "AQID", "AQ==\n,other=true"] {
            let mut p = base.clone();
            p.obfs.ech_config = value.into();
            invalid.push(p);
        }
        let mut p = base.clone();
        p.port = 0;
        invalid.push(p);
        let mut p = base.clone();
        p.name = "Mock#comment".into();
        invalid.push(p);
        let nodes = RawNodes::new(&invalid);
        assert_eq!(nodes.skipped, invalid.len());
        assert!(nodes.nodes.is_empty());
        assert_eq!(RawNodes::new(&[base]).skipped, 0);
    }

    #[tokio::test]
    async fn fresh_then_last_good_then_original_and_updates_across_requests() {
        let resolver = RawProvider::default();
        let fail = |_| async { anyhow::bail!("mock resolution failure") };
        assert_eq!(
            resolver.resolve("node.example.test".into(), fail).await,
            "node.example.test"
        );
        assert_eq!(
            resolver
                .resolve("node.example.test".into(), |_| async {
                    Ok(vec!["192.0.2.1".parse().unwrap()])
                })
                .await,
            "192.0.2.1"
        );
        assert_eq!(
            resolver.resolve("NODE.EXAMPLE.TEST.".into(), fail).await,
            "192.0.2.1"
        );
        assert_eq!(
            resolver
                .resolve("node.example.test".into(), |_| async {
                    Ok(vec!["192.0.2.2".parse().unwrap()])
                })
                .await,
            "192.0.2.2"
        );
        assert_eq!(
            resolver
                .resolve("node.example.test".into(), |_| async { Ok(vec![]) })
                .await,
            "192.0.2.2"
        );
        assert_eq!(
            resolver.resolve("other.example.test".into(), fail).await,
            "other.example.test"
        );
        assert_eq!(
            resolver
                .resolve("2001:db8::1".into(), |_| async {
                    panic!("IP literals must not perform DNS")
                })
                .await,
            "2001:db8::1"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn lookup_timeout_fails_open_with_and_without_last_good() {
        let resolver = RawProvider::default();
        resolver
            .resolve("node.example.test".into(), |_| async {
                Ok(vec!["192.0.2.1".parse().unwrap()])
            })
            .await;
        let start = tokio::time::Instant::now();
        let pending = |_| std::future::pending::<Result<Vec<IpAddr>>>();
        assert_eq!(
            resolver.resolve("node.example.test".into(), pending).await,
            "192.0.2.1"
        );
        assert_eq!(
            resolver.resolve("other.example.test".into(), pending).await,
            "other.example.test"
        );
        assert_eq!(start.elapsed(), LOOKUP_TIMEOUT * 2);
    }

    #[tokio::test]
    async fn rendered_requests_share_last_good_and_keep_unresolved_nodes() {
        let resolver = RawProvider::default();
        let mut other = test_proxy("Mock Fusion 02");
        other.server = "other.example.test".into();
        let nodes = RawNodes::new(&[test_proxy("Mock Fusion 01"), other]);
        let first = resolver
            .render(&nodes, |host| async move {
                if host == "node.example.test" {
                    Ok(vec!["192.0.2.1".parse().unwrap()])
                } else {
                    anyhow::bail!("mock resolution failure")
                }
            })
            .await;
        let second = resolver
            .render(&nodes, |_| async {
                anyhow::bail!("mock resolution failure")
            })
            .await;
        assert_eq!(first, second);
        let output = String::from_utf8(second).unwrap();
        assert_eq!(output.lines().count(), 2);
        assert!(output.contains("Mock Fusion 01 = snell, 192.0.2.1,"));
        assert!(output.contains("Mock Fusion 02 = snell, other.example.test,"));
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_requests_share_a_limit_deduplicate_hosts_and_keep_node_order() {
        let resolver = RawProvider::default();
        let nodes = RawNodes::new(
            &(0..20)
                .map(|i| {
                    let mut p = test_proxy(&format!("Mock Fusion {i}"));
                    p.server = format!("node-{}.example.test", i % 10);
                    p
                })
                .collect::<Vec<_>>(),
        );
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let lookup = {
            let (active, peak, calls) = (active.clone(), peak.clone(), calls.clone());
            move |_| {
                let (active, peak, calls) = (active.clone(), peak.clone(), calls.clone());
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    peak.fetch_max(active.fetch_add(1, Ordering::SeqCst) + 1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    active.fetch_sub(1, Ordering::SeqCst);
                    Ok(vec!["192.0.2.1".parse().unwrap()])
                }
            }
        };
        let (a, b) = tokio::join!(
            resolver.render(&nodes, lookup.clone()),
            resolver.render(&nodes, lookup)
        );
        assert_eq!(peak.load(Ordering::SeqCst), CONCURRENCY);
        assert_eq!(calls.load(Ordering::SeqCst), 20);
        assert_eq!(a, b);
        let text = String::from_utf8(a).unwrap();
        assert_eq!(text.lines().count(), 20);
        for (i, line) in text.lines().enumerate() {
            assert!(line.starts_with(&format!("Mock Fusion {i} = snell, 192.0.2.1,")));
        }
    }
}
