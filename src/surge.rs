use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::net::IpAddr;

use anyhow::{Result, bail};
use base64::Engine as _;

use crate::nodes::Proxy;

const NODE_SELECTOR_PREFIX: &str = "name-";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderProtocol {
    Http,
    Socks5,
}

pub fn render_provider(
    proxies: &[Proxy],
    listen_address: &str,
    port: u16,
    routing_secret: &str,
    protocol: ProviderProtocol,
) -> Result<Vec<u8>> {
    let ip: IpAddr = listen_address
        .parse()
        .map_err(|_| anyhow::anyhow!("Surge provider requires a specific numeric listen IP"))?;
    if ip.is_unspecified() || ip.is_multicast() {
        bail!("Surge provider requires a specific numeric listen IP");
    }
    if port == 0 {
        bail!("Surge provider listen port cannot be zero");
    }
    if proxies.is_empty() {
        bail!("Surge provider requires at least one node");
    }
    if !is_safe_credential(routing_secret) {
        bail!("Surge provider routing secret is invalid");
    }

    let mut selectors = HashSet::with_capacity(proxies.len());
    let mut names = HashMap::<String, usize>::with_capacity(proxies.len());
    let mut rendered = Vec::with_capacity(proxies.len());
    for proxy in proxies {
        let selector = node_selector(&proxy.name)?;
        if !selectors.insert(selector.clone()) {
            bail!("Surge provider selector collision");
        }
        let policy_name = sanitize_policy_name(&proxy.name);
        *names.entry(policy_name.clone()).or_default() += 1;
        rendered.push((policy_name, selector));
    }

    let mut output = String::new();
    for (proxy, (mut policy_name, selector)) in proxies.iter().zip(rendered) {
        if names[&policy_name] > 1 {
            write!(policy_name, " [{selector}]")?;
        }
        match protocol {
            ProviderProtocol::Http => write!(
                output,
                "{policy_name} = http, {listen_address}, {port}, {selector}, {routing_secret}"
            )?,
            ProviderProtocol::Socks5 => {
                write!(
                    output,
                    "{policy_name} = socks5, {listen_address}, {port}, {selector}, {routing_secret}"
                )?;
                if proxy.udp {
                    output.push_str(", udp-relay=true, test-udp=example.com@1.1.1.1");
                }
            }
        }
        output.push('\n');
    }
    Ok(output.into_bytes())
}

pub fn node_selector(name: &str) -> Result<String> {
    if name.is_empty() {
        bail!("managed proxy name is invalid");
    }
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(name.as_bytes());
    let selector = format!("{NODE_SELECTOR_PREFIX}{encoded}");
    if !is_safe_credential(&selector) {
        bail!("managed proxy name is too long for a SOCKS5 selector");
    }
    Ok(selector)
}

pub fn node_name_from_selector(selector: &str) -> Result<String> {
    let encoded = selector
        .strip_prefix(NODE_SELECTOR_PREFIX)
        .ok_or_else(|| anyhow::anyhow!("node selector prefix is invalid"))?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| anyhow::anyhow!("node selector encoding is invalid"))?;
    if decoded.is_empty() {
        bail!("node selector encoding is invalid");
    }
    String::from_utf8(decoded).map_err(|_| anyhow::anyhow!("node selector encoding is invalid"))
}

fn is_safe_credential(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

pub(crate) fn sanitize_policy_name(name: &str) -> String {
    let replaced = name
        .chars()
        .map(|character| {
            if character == '=' || character == ',' || character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>();
    let sanitized = replaced.split_whitespace().collect::<Vec<_>>().join(" ");
    if sanitized.is_empty() {
        "Node".to_owned()
    } else {
        sanitized
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_round_trip_matches_go_contract() {
        let name = "🇭🇰 Hong Kong 01";
        let selector = node_selector(name).unwrap();
        assert_eq!(node_name_from_selector(&selector).unwrap(), name);
        assert!(selector.len() <= 255);
    }

    fn proxy(name: &str, udp: bool) -> Proxy {
        use crate::nodes::ObfsOptions;
        Proxy {
            name: name.to_owned(),
            proxy_type: "snell".to_owned(),
            server: "node.example.com".to_owned(),
            port: 443,
            psk: "psk".to_owned(),
            version: 4,
            udp,
            tfo: false,
            reuse: true,
            identity: true,
            obfs: ObfsOptions {
                mode: "ech-tls".to_owned(),
                sni: "sni.example.com".to_owned(),
                path: "/".to_owned(),
                alpn: "snell-ech/1".to_owned(),
                ech_config: "config".to_owned(),
                identity_version: 2,
                legacy_fallback: false,
                skip_cert_verify: false,
                preconnect: 0,
            },
        }
    }

    #[test]
    fn renders_http_by_default_and_socks_on_request() {
        let proxies = [proxy("🇭🇰 Hong Kong 01", true)];
        let http = String::from_utf8(
            render_provider(
                &proxies,
                "127.0.0.1",
                6178,
                "secret-1",
                ProviderProtocol::Http,
            )
            .unwrap(),
        )
        .unwrap();
        assert!(http.contains(" = http, 127.0.0.1, 6178, "));
        assert!(!http.contains("socks5"));
        assert!(!http.contains("udp-relay"));
        assert!(!http.contains("test-timeout"));

        let socks = String::from_utf8(
            render_provider(
                &proxies,
                "127.0.0.1",
                6178,
                "secret-1",
                ProviderProtocol::Socks5,
            )
            .unwrap(),
        )
        .unwrap();
        assert!(socks.contains(" = socks5, 127.0.0.1, 6178, "));
        assert!(socks.contains("udp-relay=true"));
        assert!(!socks.contains("test-timeout"));
    }
}
