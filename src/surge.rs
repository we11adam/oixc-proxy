use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::net::IpAddr;

use anyhow::{Result, bail};
use base64::Engine as _;

use crate::nodes::Proxy;

const NODE_SELECTOR_PREFIX: &str = "name-";

pub fn render_provider(
    proxies: &[Proxy],
    listen_address: &str,
    port: u16,
    routing_secret: &str,
) -> Result<Vec<u8>> {
    let ip: IpAddr = listen_address
        .parse()
        .map_err(|_| anyhow::anyhow!("Surge provider requires a specific numeric SOCKS5 IP"))?;
    if ip.is_unspecified() || ip.is_multicast() {
        bail!("Surge provider requires a specific numeric SOCKS5 IP");
    }
    if port == 0 {
        bail!("Surge provider SOCKS5 port cannot be zero");
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
        write!(
            output,
            "{policy_name} = socks5, {listen_address}, {port}, {selector}, {routing_secret}, test-timeout=45"
        )?;
        if proxy.udp {
            output.push_str(", udp-relay=true, test-udp=example.com@1.1.1.1");
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
}
