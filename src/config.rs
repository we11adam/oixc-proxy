use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use url::Url;

pub const DEFAULT_API_BASE_URL: &str = "https://oix-api.dler.io";
pub const DEFAULT_APP_SECRET: &str = "4a7f27227e2779e5d3e9cd968ba06ceb";
const DEFAULT_LISTEN: &str = "127.0.0.1:6172";
const DEFAULT_NODELIST_LISTEN: &str = "127.0.0.1:6173";
const MAX_PROXY_CONFIG_BYTES: usize = 64 << 10;

#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    pub access_token: String,
    pub app_secret: String,
    pub api_base_url: Url,
    pub listen_address: IpAddr,
    pub serve_port: u16,
    pub map_base_port: u16,
    pub request_timeout: Duration,
    pub udp_idle_timeout: Duration,
    pub allow_remote_access: bool,
    pub socks_username: String,
    pub socks_password: String,
    pub max_client_connections: usize,
    pub reuse_max_idle: usize,
    pub reuse_max_uses: usize,
    pub reuse_idle_timeout: Duration,
}

#[derive(Clone, Debug)]
pub struct ProxyConfig {
    pub runtime: RuntimeConfig,
    pub listen: SocketAddr,
    pub nodelist_listen: SocketAddr,
    pub outbound_ip: IpAddr,
    pub node_refresh_interval: Duration,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
struct FileConfig {
    access_token: String,
    access_token_file: String,
    app_secret: String,
    api_base_url: String,
    listen_address: String,
    serve_port: u16,
    map_base_port: u16,
    request_timeout: String,
    udp_idle_timeout: String,
    allow_remote_access: bool,
    socks_username: String,
    socks_password_file: String,
    max_client_connections: usize,
    reuse_max_idle: usize,
    reuse_max_uses: usize,
    reuse_idle_timeout: String,
    allow_insecure_file_permissions: bool,
}

pub fn default_proxy_config_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .context("locate home directory")?;
    Ok(home.join(".config/oixc-proxy/oixc-proxy.conf"))
}

pub fn load_proxy_config(path: &Path) -> Result<ProxyConfig> {
    require_private_file(path, false).context("validate proxy config permissions")?;
    let content = read_limited(path, MAX_PROXY_CONFIG_BYTES, "proxy config")?;
    let values = parse_proxy_config(&content)?;
    let token = values
        .get("token")
        .filter(|value| !value.is_empty())
        .cloned()
        .context("proxy config requires token")?;

    let listen = parse_listen("listen", listen_value(&values)?, DEFAULT_LISTEN)?;
    let nodelist_listen = parse_listen(
        "nodelist-listen",
        values.get("nodelist-listen").map(String::as_str),
        DEFAULT_NODELIST_LISTEN,
    )?;
    if listens_conflict(listen, nodelist_listen) {
        bail!("listen and nodelist-listen conflict");
    }
    let outbound_ip =
        parse_outbound_ip(values.get("outbound-ip").map(String::as_str), listen.ip())?;
    let node_refresh_interval = match values.get("node-refresh-interval") {
        Some(value) => {
            let duration =
                parse_go_duration(value).with_context(|| "parse node-refresh-interval")?;
            if !(Duration::from_secs(60)..=Duration::from_secs(24 * 3600)).contains(&duration) {
                bail!("node-refresh-interval must be between 1m0s and 24h0m0s");
            }
            duration
        }
        None => Duration::from_secs(3600),
    };

    let mut runtime = runtime_from_raw(
        Path::new(""),
        FileConfig {
            access_token: token,
            listen_address: "127.0.0.1".to_owned(),
            serve_port: listen.port(),
            ..FileConfig::default()
        },
    )?;
    runtime.listen_address = listen.ip();
    runtime.serve_port = listen.port();
    runtime.allow_remote_access = !listen.ip().is_loopback();

    Ok(ProxyConfig {
        runtime,
        listen,
        nodelist_listen,
        outbound_ip,
        node_refresh_interval,
    })
}

pub fn load_json_config(path: &Path) -> Result<RuntimeConfig> {
    require_private_file(path, true).context("validate config file")?;
    let content = read_limited(path, 1 << 20, "config")?;
    let mut deserializer = serde_json::Deserializer::from_slice(&content);
    let raw = FileConfig::deserialize(&mut deserializer).context("decode config")?;
    deserializer.end().context("decode trailing config data")?;
    if !raw.allow_insecure_file_permissions {
        require_private_file(path, false).context("validate config permissions")?;
    }
    runtime_from_raw(path.parent().unwrap_or_else(|| Path::new("")), raw)
}

pub fn load_token_file(path: &Path) -> Result<RuntimeConfig> {
    runtime_from_raw(
        Path::new(""),
        FileConfig {
            access_token_file: path.to_string_lossy().into_owned(),
            ..FileConfig::default()
        },
    )
}

fn runtime_from_raw(config_dir: &Path, raw: FileConfig) -> Result<RuntimeConfig> {
    let inline_token = raw.access_token.trim();
    let token_path = raw.access_token_file.trim();
    if inline_token.is_empty() == token_path.is_empty() {
        bail!("configure exactly one of accessToken or accessTokenFile");
    }
    let access_token = if !inline_token.is_empty() {
        inline_token.to_owned()
    } else {
        let path = resolve_path(config_dir, token_path);
        require_private_file(&path, raw.allow_insecure_file_permissions)
            .context("validate token file permissions")?;
        let token = fs::read_to_string(&path).context("read access token file")?;
        let token = token.trim().to_owned();
        if token.is_empty() {
            bail!("access token file is empty");
        }
        token
    };

    let app_secret = if raw.app_secret.trim().is_empty() {
        DEFAULT_APP_SECRET.to_owned()
    } else {
        raw.app_secret.trim().to_owned()
    };
    let api_base_url = Url::parse(if raw.api_base_url.is_empty() {
        DEFAULT_API_BASE_URL
    } else {
        &raw.api_base_url
    })
    .context("parse apiBaseURL")?;
    if api_base_url.scheme() != "https"
        || api_base_url.host_str().is_none()
        || !api_base_url.username().is_empty()
        || api_base_url.password().is_some()
        || api_base_url.query().is_some()
        || api_base_url.fragment().is_some()
    {
        bail!("apiBaseURL must be an absolute HTTPS URL without credentials, query, or fragment");
    }

    let request_timeout = parse_bounded_duration(
        "requestTimeout",
        &raw.request_timeout,
        Duration::from_secs(15),
        Duration::from_nanos(1),
        Duration::from_secs(120),
    )?;
    let udp_idle_timeout = parse_bounded_duration(
        "udpIdleTimeout",
        &raw.udp_idle_timeout,
        Duration::from_secs(300),
        Duration::from_secs(1),
        Duration::from_secs(24 * 3600),
    )?;
    let reuse_idle_timeout = parse_bounded_duration(
        "reuseIdleTimeout",
        &raw.reuse_idle_timeout,
        Duration::from_secs(90),
        Duration::from_secs(1),
        Duration::from_secs(600),
    )?;

    let listen_address: IpAddr = if raw.listen_address.is_empty() {
        "127.0.0.1"
    } else {
        &raw.listen_address
    }
    .parse()
    .map_err(|_| anyhow::anyhow!("listenAddress must be a specific numeric IP"))?;
    if listen_address.is_unspecified() {
        bail!("listenAddress must be a specific numeric IP");
    }

    let (socks_username, socks_password) = resolve_socks_credentials(config_dir, &raw)?;
    if !listen_address.is_loopback() {
        if !raw.allow_remote_access {
            bail!("non-loopback listenAddress requires allowRemoteAccess");
        }
        if socks_username.is_empty() || socks_password.is_empty() {
            bail!("non-loopback listenAddress requires SOCKS5 authentication");
        }
    }

    Ok(RuntimeConfig {
        access_token,
        app_secret,
        api_base_url,
        listen_address,
        serve_port: nonzero_or(raw.serve_port, 6172),
        map_base_port: nonzero_or(raw.map_base_port, 7200),
        request_timeout,
        udp_idle_timeout,
        allow_remote_access: raw.allow_remote_access,
        socks_username,
        socks_password,
        max_client_connections: bounded_or_default(
            "maxClientConnections",
            raw.max_client_connections,
            256,
            1,
            4096,
        )?,
        reuse_max_idle: bounded_or_default("reuseMaxIdle", raw.reuse_max_idle, 8, 1, 128)?,
        reuse_max_uses: bounded_or_default("reuseMaxUses", raw.reuse_max_uses, 32, 1, 1024)?,
        reuse_idle_timeout,
    })
}

fn parse_proxy_config(content: &[u8]) -> Result<HashMap<String, String>> {
    let text = std::str::from_utf8(content).context("read proxy config")?;
    let allowed = [
        "token",
        "listen",
        "socks5-listen",
        "nodelist-listen",
        "outbound-ip",
        "node-refresh-interval",
    ];
    let mut values = HashMap::with_capacity(6);
    for (index, original) in text.lines().enumerate() {
        let line_number = index + 1;
        let line = original.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            bail!("proxy config line {line_number} must use key=value");
        };
        let key = key.trim();
        let value = value.trim();
        if key.is_empty() || value.is_empty() {
            bail!("proxy config line {line_number} must use key=value");
        }
        if !allowed.contains(&key) {
            bail!("proxy config line {line_number} has unknown key {key:?}");
        }
        if values.insert(key.to_owned(), value.to_owned()).is_some() {
            bail!("proxy config line {line_number} duplicates key {key:?}");
        }
    }
    Ok(values)
}

fn listen_value(values: &HashMap<String, String>) -> Result<Option<&str>> {
    match (values.get("listen"), values.get("socks5-listen")) {
        (Some(_), Some(_)) => {
            bail!("proxy config cannot set both listen and socks5-listen")
        }
        (Some(value), None) | (None, Some(value)) => Ok(Some(value.as_str())),
        (None, None) => Ok(None),
    }
}

fn parse_listen(name: &str, value: Option<&str>, default: &str) -> Result<SocketAddr> {
    let value = value.unwrap_or(default);
    let address: SocketAddr = value.parse().map_err(|_| {
        anyhow::anyhow!("{name} must be a numeric IP:port with a port between 1 and 65535")
    })?;
    if address.port() == 0 {
        bail!("{name} must be a numeric IP:port with a port between 1 and 65535");
    }
    if address.ip().is_multicast() {
        bail!("{name} must not use a multicast IP");
    }
    Ok(address)
}

fn listens_conflict(first: SocketAddr, second: SocketAddr) -> bool {
    first.port() == second.port()
        && (first.ip() == second.ip()
            || first.ip().is_unspecified()
            || second.ip().is_unspecified())
}

fn parse_outbound_ip(value: Option<&str>, socks5_ip: IpAddr) -> Result<IpAddr> {
    let Some(value) = value else {
        if socks5_ip.is_unspecified() {
            bail!("outbound-ip is required when listen uses an unspecified IP");
        }
        return Ok(socks5_ip);
    };
    let outbound: IpAddr = value
        .parse()
        .map_err(|_| anyhow::anyhow!("outbound-ip must be a specific, non-multicast numeric IP"))?;
    if outbound.is_unspecified() || outbound.is_multicast() {
        bail!("outbound-ip must be a specific, non-multicast numeric IP");
    }
    if outbound.is_ipv4() != socks5_ip.is_ipv4() {
        bail!("outbound-ip and listen must use the same IP family");
    }
    Ok(outbound)
}

fn resolve_socks_credentials(config_dir: &Path, raw: &FileConfig) -> Result<(String, String)> {
    let username = raw.socks_username.trim();
    let password_path = raw.socks_password_file.trim();
    if username.is_empty() && password_path.is_empty() {
        return Ok((String::new(), String::new()));
    }
    if username.is_empty() || password_path.is_empty() {
        bail!("configure both socksUsername and socksPasswordFile");
    }
    if username.len() > 255 {
        bail!("socksUsername is longer than 255 bytes");
    }
    let path = resolve_path(config_dir, password_path);
    require_private_file(&path, raw.allow_insecure_file_permissions)
        .context("validate SOCKS5 password file")?;
    let password = fs::read_to_string(path).context("read SOCKS5 password file")?;
    let password = password.trim().to_owned();
    if password.is_empty() || password.len() > 255 {
        bail!("SOCKS5 password must contain 1 to 255 bytes");
    }
    Ok((username.to_owned(), password))
}

pub fn parse_go_duration(value: &str) -> Result<Duration> {
    if value.is_empty() {
        bail!("invalid duration");
    }
    let bytes = value.as_bytes();
    let mut index = 0;
    let mut total_nanos = 0f64;
    while index < bytes.len() {
        let number_start = index;
        let mut dot_seen = false;
        while index < bytes.len()
            && (bytes[index].is_ascii_digit() || (!dot_seen && bytes[index] == b'.'))
        {
            dot_seen |= bytes[index] == b'.';
            index += 1;
        }
        if index == number_start {
            bail!("invalid duration");
        }
        let number: f64 = value[number_start..index]
            .parse()
            .context("invalid duration")?;
        let unit_start = index;
        while index < bytes.len() && !bytes[index].is_ascii_digit() && bytes[index] != b'.' {
            index += 1;
        }
        let unit = &value[unit_start..index];
        let multiplier = match unit {
            "ns" => 1.0,
            "us" | "µs" | "μs" => 1_000.0,
            "ms" => 1_000_000.0,
            "s" => 1_000_000_000.0,
            "m" => 60_000_000_000.0,
            "h" => 3_600_000_000_000.0,
            _ => bail!("invalid duration"),
        };
        total_nanos += number * multiplier;
    }
    if !total_nanos.is_finite() || total_nanos < 0.0 || total_nanos > u64::MAX as f64 {
        bail!("invalid duration");
    }
    Ok(Duration::from_nanos(total_nanos.round() as u64))
}

fn parse_bounded_duration(
    name: &str,
    value: &str,
    default: Duration,
    minimum: Duration,
    maximum: Duration,
) -> Result<Duration> {
    if value.is_empty() {
        return Ok(default);
    }
    let parsed = parse_go_duration(value).with_context(|| format!("parse {name}"))?;
    if parsed < minimum || parsed > maximum {
        bail!("{name} is outside the supported range");
    }
    Ok(parsed)
}

fn bounded_or_default(
    name: &str,
    value: usize,
    default: usize,
    minimum: usize,
    maximum: usize,
) -> Result<usize> {
    let value = if value == 0 { default } else { value };
    if value < minimum || value > maximum {
        bail!("{name} must be between {minimum} and {maximum}");
    }
    Ok(value)
}

fn nonzero_or(value: u16, default: u16) -> u16 {
    if value == 0 { default } else { value }
}

fn resolve_path(base: &Path, value: &str) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        path
    } else {
        base.join(path)
    }
}

fn read_limited(path: &Path, maximum: usize, name: &str) -> Result<Vec<u8>> {
    let mut file = fs::File::open(path).with_context(|| format!("open {name}"))?;
    let mut content = Vec::new();
    file.by_ref()
        .take((maximum + 1) as u64)
        .read_to_end(&mut content)
        .with_context(|| format!("read {name}"))?;
    if content.len() > maximum {
        bail!("{name} is too large");
    }
    Ok(content)
}

pub(crate) fn require_private_file(path: &Path, allow_insecure: bool) -> Result<()> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        bail!("path is not a regular file");
    }
    #[cfg(unix)]
    if !allow_insecure {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            bail!(
                "{:?} has permissions {:04o}; expected 0600 or stricter",
                path,
                mode
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listen_accepts_legacy_socks5_listen_alias() {
        let mut values = HashMap::new();
        values.insert("socks5-listen".to_owned(), "127.0.0.1:6178".to_owned());
        assert_eq!(listen_value(&values).unwrap(), Some("127.0.0.1:6178"));

        values.insert("listen".to_owned(), "127.0.0.1:6172".to_owned());
        assert!(
            listen_value(&values)
                .unwrap_err()
                .to_string()
                .contains("both")
        );
    }

    #[test]
    fn go_duration_grammar_is_supported() {
        assert_eq!(
            parse_go_duration("1h30m5.5s").unwrap(),
            Duration::from_millis(5_405_500)
        );
        assert_eq!(
            parse_go_duration("250ms").unwrap(),
            Duration::from_millis(250)
        );
    }
}
