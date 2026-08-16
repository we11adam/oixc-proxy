use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::api::Client as ApiClient;
use crate::catalog_cache::CatalogCache;
use crate::config::{RuntimeConfig, default_proxy_config_path, load_proxy_config, load_token_file};
use crate::gateway::{
    CLASH_PROVIDER_PATH, GatewayManager, PROVIDER_PATH, Route, Router, derive_routing_secret,
};
use crate::http_server;
use crate::nodes::{ManagedConfig, Proxy};
use crate::rlimit;
use crate::snell::{SnellClient, SnellClientOptions};
use crate::socks5::{self, Credentials, Mode};
use crate::transport::EchDialer;

const USAGE: &str = "Usage:
  oixc-proxy information [--config PATH] --output PATH
  oixc-proxy serve [--config PATH] [--disable-node-filter]
  oixc-proxy serve-map [--token-file PATH] [--listen IP] [--base-port PORT] [--disable-node-filter]
  oixc-proxy version
  oixc-proxy install-launch-agent [--config PATH]
  oixc-proxy install-systemd [--config PATH]

The information command is read-only. Its output file is created with mode
0600 and must not already exist.

--disable-node-filter publishes all managed nodes instead of only those
whose names contain Fusion, CIA, or IXP markers. Use this when your
account does not include any Fusion/CIA/IXP nodes.

GET /surge-proxies.conf?all=1 and /clash-proxies.yaml?all=1 publish the
full catalog without changing the default filtered listing. Provider
entries are HTTP proxies by default; append socks=1 to advertise SOCKS5
instead. The local listener accepts both HTTP and SOCKS5.
";

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct UsageError(String);

pub async fn run(args: Vec<String>) -> i32 {
    if args.is_empty() {
        eprint!("{USAGE}");
        return 2;
    }
    let result = match args[0].as_str() {
        "information" => run_information(&args[1..]).await,
        "serve" => run_serve(&args[1..]).await,
        "serve-map" => run_serve_map(&args[1..]).await,
        "install-launch-agent" => run_install_launch_agent(&args[1..]),
        "install-systemd" => run_install_systemd(&args[1..]),
        "version" | "-V" | "--version" => run_version(&args[1..]),
        "help" | "-h" | "--help" => {
            print!("{USAGE}");
            return 0;
        }
        command => {
            eprintln!("unknown command {command:?}\n\n{USAGE}");
            return 2;
        }
    };
    match result {
        Ok(()) => 0,
        Err(error) if error.downcast_ref::<UsageError>().is_some() => {
            eprintln!("error: {error}");
            2
        }
        Err(error) => {
            eprintln!("error: {error:#}");
            1
        }
    }
}

fn run_version(args: &[String]) -> Result<()> {
    if !args.is_empty() {
        bail!("version takes no arguments");
    }
    println!("{}", version_string());
    Ok(())
}

fn version_string() -> String {
    format!(
        "oixc-proxy {} (commit {}, built {})",
        env!("CARGO_PKG_VERSION"),
        option_env!("OIXC_COMMIT_ID").unwrap_or("unknown"),
        option_env!("OIXC_BUILD_TIME").unwrap_or("unknown")
    )
}

async fn run_information(args: &[String]) -> Result<()> {
    let default = default_proxy_config_path()?;
    let flags = parse_flags(args, &[("config", true), ("output", true)])?;
    let config_path = flag_path(&flags, "config", &default);
    let output = flags
        .get("output")
        .and_then(|value| value.as_ref())
        .map(PathBuf::from)
        .ok_or_else(|| UsageError("--output is required".to_owned()))?;
    let service = load_proxy_config(&config_path)?;
    let client = api_client(&service.runtime)?;
    let content = client.information().await?;
    write_exclusive(&output, &content)?;
    println!("Wrote API response to {}", output.display());
    Ok(())
}

async fn run_serve(args: &[String]) -> Result<()> {
    rlimit::raise_nofile_limit();
    let default = default_proxy_config_path()?;
    let flags = parse_flags(args, &[("config", true), ("disable-node-filter", false)])?;
    let config_path = flag_path(&flags, "config", &default);
    let disable_node_filter = flags.contains_key("disable-node-filter");
    let service = load_proxy_config(&config_path)?;
    let cache = CatalogCache::beside_config(&config_path);
    let (mut managed, from_cache) = if let Some(cached) = cache.load() {
        (cached, true)
    } else {
        let fetched = load_managed_nodes(&service.runtime, true).await?;
        cache.store_or_log(&fetched);
        (fetched, false)
    };
    let published = published_proxies(&managed, disable_node_filter)?;
    let routing_secret = derive_routing_secret(&service.runtime.access_token)?;
    let dial_limit = Arc::new(Semaphore::new(32));
    let router = Router::build(
        &managed.proxies,
        &published,
        &service.runtime,
        service.outbound_ip,
        &routing_secret,
        dial_limit.clone(),
        None,
    )?;
    let manager = Arc::new(GatewayManager::new(router));
    let socks_listener = TcpListener::bind(service.listen)
        .await
        .map_err(|_| anyhow::anyhow!("listen on local SOCKS5 address"))?;
    let nodelist_listener = TcpListener::bind(service.nodelist_listen)
        .await
        .map_err(|_| anyhow::anyhow!("listen on local nodelist HTTP address"))?;
    println!(
        "Proxy ready: mixed {}; nodelist http://{}{}; clash http://{}{}; {}; refresh {}",
        service.listen,
        service.nodelist_listen,
        PROVIDER_PATH,
        service.nodelist_listen,
        CLASH_PROVIDER_PATH,
        format_node_count(published.len(), managed.proxies.len()),
        format_duration(service.node_refresh_interval),
    );
    if from_cache {
        println!("Started from cached catalog; refreshing in background");
    }

    let mut socks_task = tokio::spawn(serve_socks_listener(
        socks_listener,
        socks5::Options {
            handshake_timeout: service.runtime.request_timeout.max(Duration::from_secs(45)),
            udp_idle_timeout: service.runtime.udp_idle_timeout,
            udp_bind_address: service.outbound_ip,
            mode: Mode::Dynamic(manager.clone()),
        },
        service.runtime.max_client_connections,
    ));
    let mut http_task = tokio::spawn(http_server::serve(nodelist_listener, manager.clone()));
    let mut refresh = tokio::time::interval(service.node_refresh_interval);
    if !from_cache {
        refresh.tick().await;
    }
    loop {
        tokio::select! {
            result = &mut socks_task => {
                return result.context("SOCKS5 server task failed")?;
            }
            result = &mut http_task => {
                return result.context("nodelist HTTP task failed")?;
            }
            _ = refresh.tick() => {
                let refreshed = match load_managed_nodes(&service.runtime, true).await {
                    Ok(value) => value,
                    Err(error) => {
                        eprintln!("node catalog refresh failed: {error:#}");
                        continue;
                    }
                };
                if refreshed.proxies == managed.proxies {
                    continue;
                }
                let published = match published_proxies(&refreshed, disable_node_filter) {
                    Ok(value) => value,
                    Err(error) => {
                        eprintln!("node catalog refresh failed: {error:#}");
                        continue;
                    }
                };
                let previous = manager.current().await?;
                let replacement = match Router::build(
                    &refreshed.proxies,
                    &published,
                    &service.runtime,
                    service.outbound_ip,
                    &routing_secret,
                    dial_limit.clone(),
                    Some(previous.as_ref()),
                ) {
                    Ok(value) => value,
                    Err(error) => {
                        eprintln!("node catalog refresh failed: {error:#}");
                        continue;
                    }
                };
                if let Err(error) = manager.replace(replacement).await {
                    eprintln!("retire previous node catalog: {error:#}");
                    continue;
                }
                let published_count = published.len();
                let total_count = refreshed.proxies.len();
                managed = refreshed;
                cache.store_or_log(&managed);
                println!(
                    "Refreshed node catalog ({})",
                    format_node_count(published_count, total_count)
                );
            }
        }
    }
}

async fn run_serve_map(args: &[String]) -> Result<()> {
    rlimit::raise_nofile_limit();
    let flags = parse_flags(
        args,
        &[
            ("token-file", true),
            ("listen", true),
            ("base-port", true),
            ("disable-node-filter", false),
        ],
    )?;
    let disable_node_filter = flags.contains_key("disable-node-filter");
    let token_file = flags
        .get("token-file")
        .and_then(|value| value.as_ref())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("token.txt"));
    if token_file.as_os_str().is_empty() {
        return Err(UsageError("--token-file cannot be empty".to_owned()).into());
    }
    let mut runtime = load_token_file(&token_file)?;
    let listen: IpAddr = flags
        .get("listen")
        .and_then(|value| value.as_ref())
        .map(String::as_str)
        .unwrap_or("127.0.0.1")
        .parse()
        .map_err(|_| UsageError("SOCKS5 map must use a numeric loopback IP".to_owned()))?;
    if !listen.is_loopback() {
        return Err(UsageError("SOCKS5 map must use a numeric loopback IP".to_owned()).into());
    }
    runtime.listen_address = listen;
    let requested_base_port = match flags.get("base-port").and_then(|value| value.as_ref()) {
        Some(value) => value
            .parse::<u16>()
            .map_err(|_| UsageError("--base-port must be between 1 and 65535".to_owned()))?,
        None => 0,
    };
    let base_port = if requested_base_port == 0 {
        runtime.map_base_port
    } else {
        requested_base_port
    };
    let managed = load_managed_nodes(&runtime, disable_node_filter).await?;
    if base_port as usize + managed.proxies.len() - 1 > u16::MAX as usize {
        bail!("SOCKS5 map port range exceeds 65535");
    }

    let mut listeners = Vec::with_capacity(managed.proxies.len());
    let mut routes = Vec::with_capacity(managed.proxies.len());
    for (index, proxy) in managed.proxies.iter().enumerate() {
        let port = base_port + index as u16;
        listeners.push(
            TcpListener::bind(SocketAddr::new(listen, port))
                .await
                .with_context(|| format!("listen on local SOCKS5 map port {port}"))?,
        );
        routes.push(build_fixed_route(proxy, &runtime)?);
    }
    let credentials = if runtime.socks_username.is_empty() {
        None
    } else {
        Some(Credentials {
            username: runtime.socks_username.clone(),
            password: runtime.socks_password.clone(),
        })
    };
    println!(
        "SOCKS5 map ready on {} ports {}-{} ({} nodes)",
        listen,
        base_port,
        base_port as usize + listeners.len() - 1,
        listeners.len()
    );
    let (error_tx, mut error_rx) = tokio::sync::mpsc::channel(1);
    for (listener, route) in listeners.into_iter().zip(routes) {
        let sender = error_tx.clone();
        let options = socks5::Options {
            handshake_timeout: runtime.request_timeout,
            udp_idle_timeout: runtime.udp_idle_timeout,
            udp_bind_address: listen,
            mode: Mode::Fixed {
                route,
                credentials: credentials.clone(),
            },
        };
        tokio::spawn(async move {
            let error =
                serve_socks_listener(listener, options, runtime.max_client_connections).await;
            let _ = sender.send(error).await;
        });
    }
    drop(error_tx);
    error_rx
        .recv()
        .await
        .context("SOCKS5 map listener stopped")?
}

async fn serve_socks_listener(
    listener: TcpListener,
    options: socks5::Options,
    max_connections: usize,
) -> Result<()> {
    let slots = Arc::new(Semaphore::new(max_connections));
    loop {
        let permit = slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| anyhow::anyhow!("SOCKS5 connection limiter is closed"))?;
        let (connection, _) = listener
            .accept()
            .await
            .map_err(|_| anyhow::anyhow!("accept local SOCKS5 connection"))?;
        let options = options.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = crate::perftrace::scope(socks5::serve_connection(connection, options)).await;
        });
    }
}

fn build_fixed_route(proxy: &Proxy, runtime: &RuntimeConfig) -> Result<Route> {
    let dialer = EchDialer::new(proxy, runtime.request_timeout)?;
    Ok(Route {
        client: SnellClient::new(SnellClientOptions {
            node_name: proxy.name.clone(),
            psk: proxy.psk.clone(),
            reuse: proxy.reuse,
            max_idle: runtime.reuse_max_idle,
            max_uses: runtime.reuse_max_uses,
            idle_timeout: runtime.reuse_idle_timeout,
            handshake_timeout: runtime.request_timeout,
            close_timeout: Duration::from_secs(2),
            dialer: dialer.into(),
            dial_limit: None,
            dial_limit_timeout: runtime.request_timeout,
        })?,
        udp: proxy.udp,
    })
}

fn published_proxies(managed: &ManagedConfig, include_all: bool) -> Result<Vec<Proxy>> {
    if include_all {
        return Ok(managed.proxies.clone());
    }
    let proxies = managed.allowed_proxies();
    if proxies.is_empty() {
        bail!("managed config contains no allowed Fusion/CIA/IXP proxies");
    }
    Ok(proxies)
}

fn format_node_count(published: usize, total: usize) -> String {
    if published == total {
        format!("{published} named nodes")
    } else {
        format!("{published} named nodes ({total} total)")
    }
}

async fn load_managed_nodes(
    runtime: &RuntimeConfig,
    disable_filter: bool,
) -> Result<ManagedConfig> {
    let client = api_client(runtime)?;
    let plaintext = client.dump_managed_config().await?;
    let managed = ManagedConfig::parse(&plaintext)?;
    if disable_filter {
        Ok(managed)
    } else {
        managed.filter_allowed_nodes()
    }
}

fn api_client(runtime: &RuntimeConfig) -> Result<ApiClient> {
    ApiClient::new(
        runtime.api_base_url.clone(),
        runtime.access_token.clone(),
        runtime.app_secret.clone(),
        runtime.request_timeout,
    )
}

fn parse_flags(
    args: &[String],
    definitions: &[(&str, bool)],
) -> Result<HashMap<String, Option<String>>> {
    let allowed = definitions.iter().copied().collect::<HashMap<_, _>>();
    let mut parsed = HashMap::new();
    let mut index = 0;
    while index < args.len() {
        let argument = &args[index];
        if argument == "-h" || argument == "--help" {
            return Err(UsageError("help requested".to_owned()).into());
        }
        if !argument.starts_with('-') {
            return Err(UsageError("unexpected positional arguments".to_owned()).into());
        }
        let trimmed = argument.trim_start_matches('-');
        let (name, inline) = match trimmed.split_once('=') {
            Some((name, value)) => (name, Some(value.to_owned())),
            None => (trimmed, None),
        };
        let Some(needs_value) = allowed.get(name) else {
            return Err(UsageError(format!("flag provided but not defined: -{name}")).into());
        };
        if parsed.contains_key(name) {
            return Err(UsageError(format!("flag provided more than once: -{name}")).into());
        }
        let value = if *needs_value {
            match inline {
                Some(value) if !value.is_empty() => Some(value),
                Some(_) => {
                    return Err(UsageError(format!("flag needs an argument: -{name}")).into());
                }
                None => {
                    index += 1;
                    Some(
                        args.get(index)
                            .filter(|value| !value.starts_with('-'))
                            .cloned()
                            .ok_or_else(|| {
                                UsageError(format!("flag needs an argument: -{name}"))
                            })?,
                    )
                }
            }
        } else {
            None
        };
        parsed.insert(name.to_owned(), value);
        index += 1;
    }
    Ok(parsed)
}

fn flag_path(flags: &HashMap<String, Option<String>>, name: &str, default: &Path) -> PathBuf {
    flags
        .get(name)
        .and_then(|value| value.as_ref())
        .map(PathBuf::from)
        .unwrap_or_else(|| default.to_owned())
}

fn write_exclusive(path: &Path, content: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("create output file {}", path.display()))?;
    file.write_all(content)?;
    file.sync_all()?;
    Ok(())
}

fn run_install_launch_agent(args: &[String]) -> Result<()> {
    if std::env::consts::OS != "macos" {
        bail!("LaunchAgent installation is supported only on macOS");
    }
    ensure_not_root("install-launch-agent")?;
    let default = default_proxy_config_path()?;
    let flags = parse_flags(args, &[("config", true)])?;
    let config = absolute_path(&flag_path(&flags, "config", &default))?;
    load_proxy_config(&config)?;
    let installed = install_current_executable()?;
    let home = home_directory()?;
    let plist = home.join("Library/LaunchAgents/io.oixc.proxy.plist");
    let logs = home.join("Library/Logs");
    fs::create_dir_all(&logs)?;
    let content = render_launch_agent(
        &installed,
        &config,
        config.parent().unwrap_or(Path::new("/")),
        &logs.join("oixc-proxy.stdout.log"),
        &logs.join("oixc-proxy.stderr.log"),
    );
    write_service_file(&plist, content.as_bytes())?;
    let domain = format!("gui/{}", unsafe { libc::getuid() });
    if let Err(error) = run_command(
        "launchctl",
        &["bootstrap", &domain, &plist.to_string_lossy()],
    ) {
        let _ = fs::remove_file(&plist);
        return Err(error);
    }
    run_command(
        "launchctl",
        &["kickstart", "-k", &format!("{domain}/io.oixc.proxy")],
    )?;
    println!(
        "Installed {} and started LaunchAgent io.oixc.proxy from {}",
        installed.display(),
        plist.display()
    );
    Ok(())
}

fn run_install_systemd(args: &[String]) -> Result<()> {
    if std::env::consts::OS != "linux" {
        bail!("systemd installation is supported only on Linux");
    }
    ensure_not_root("install-systemd")?;
    let default = default_proxy_config_path()?;
    let flags = parse_flags(args, &[("config", true)])?;
    let config = absolute_path(&flag_path(&flags, "config", &default))?;
    load_proxy_config(&config)?;
    let installed = install_current_executable()?;
    let unit = home_directory()?.join(".config/systemd/user/oixc-proxy.service");
    let content = render_systemd(
        &installed,
        &config,
        config.parent().unwrap_or(Path::new("/")),
    );
    write_service_file(&unit, content.as_bytes())?;
    if let Err(error) = run_command("systemctl", &["--user", "daemon-reload"]) {
        let _ = fs::remove_file(&unit);
        return Err(error);
    }
    if let Err(error) = run_command(
        "systemctl",
        &["--user", "enable", "--now", "oixc-proxy.service"],
    ) {
        let _ = run_command(
            "systemctl",
            &["--user", "disable", "--now", "oixc-proxy.service"],
        );
        let _ = fs::remove_file(&unit);
        let _ = run_command("systemctl", &["--user", "daemon-reload"]);
        return Err(error);
    }
    println!(
        "Installed {} and started systemd user service oixc-proxy.service from {}",
        installed.display(),
        unit.display()
    );
    Ok(())
}

fn ensure_not_root(command: &str) -> Result<()> {
    if unsafe { libc::geteuid() } == 0 {
        bail!(
            "do not run {command} with sudo; run it as the login user (sudo is requested only for installing /usr/local/bin/oixc-proxy)"
        );
    }
    Ok(())
}

fn install_current_executable() -> Result<PathBuf> {
    let source = std::env::current_exe()?.canonicalize()?;
    let destination = PathBuf::from("/usr/local/bin/oixc-proxy");
    if source == destination {
        return Ok(destination);
    }
    match install_executable(&source, &destination) {
        Ok(()) => Ok(destination),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::PermissionDenied) =>
        {
            eprintln!(
                "Administrator privileges are required to install {}; requesting sudo for the binary copy only.",
                destination.display()
            );
            let status = std::process::Command::new("/usr/bin/sudo")
                .args([
                    "/usr/bin/install",
                    "-m",
                    "0755",
                    &source.to_string_lossy(),
                    &destination.to_string_lossy(),
                ])
                .status()?;
            if !status.success() {
                bail!("sudo install failed");
            }
            Ok(destination)
        }
        Err(error) => Err(error),
    }
}

fn install_executable(source: &Path, destination: &Path) -> Result<()> {
    let parent = destination
        .parent()
        .context("destination has no directory")?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(".oixc-proxy-install-{}", std::process::id()));
    fs::copy(source, &temporary)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o755))?;
    }
    let file = fs::File::open(&temporary)?;
    file.sync_all()?;
    fs::rename(&temporary, destination)?;
    Ok(())
}

fn write_service_file(path: &Path, content: &[u8]) -> Result<()> {
    fs::create_dir_all(path.parent().context("service file has no parent")?)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("service definition already exists: {}", path.display()))?;
    file.write_all(content)?;
    file.sync_all()?;
    Ok(())
}

fn render_launch_agent(
    executable: &Path,
    config: &Path,
    working: &Path,
    stdout: &Path,
    stderr: &Path,
) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>io.oixc.proxy</string>
  <key>ProgramArguments</key>
  <array>
    <string>{}</string>
    <string>serve</string>
    <string>--config</string>
    <string>{}</string>
  </array>
  <key>WorkingDirectory</key>
  <string>{}</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ProcessType</key>
  <string>Background</string>
  <key>ThrottleInterval</key>
  <integer>10</integer>
  <key>StandardOutPath</key>
  <string>{}</string>
  <key>StandardErrorPath</key>
  <string>{}</string>
</dict>
</plist>
"#,
        xml_escape(executable),
        xml_escape(config),
        xml_escape(working),
        xml_escape(stdout),
        xml_escape(stderr)
    )
}

fn render_systemd(executable: &Path, config: &Path, working: &Path) -> String {
    format!(
        r#"[Unit]
Description=oixc-proxy named-node SOCKS5 gateway
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStart="{}" serve --config "{}"
WorkingDirectory={}
Restart=on-failure
RestartSec=5s
TimeoutStopSec=10s
LimitNOFILE=infinity
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LockPersonality=true
MemoryDenyWriteExecute=true

[Install]
WantedBy=default.target
"#,
        systemd_quote(executable),
        systemd_quote(config),
        systemd_path(working)
    )
}

fn xml_escape(path: &Path) -> String {
    path.to_string_lossy()
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn systemd_quote(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('%', "%%")
        .replace('$', "$$")
}

fn systemd_path(path: &Path) -> String {
    path.to_string_lossy()
        .bytes()
        .map(|byte| match byte {
            b'%' => "%%".to_owned(),
            b' ' | b'\t' | b'"' | b'\'' | b'\\' => format!("\\x{byte:02x}"),
            _ => (byte as char).to_string(),
        })
        .collect()
}

fn run_command(program: &str, arguments: &[&str]) -> Result<()> {
    let output = std::process::Command::new(program)
        .args(arguments)
        .output()
        .with_context(|| format!("run {program}"))?;
    if output.status.success() {
        return Ok(());
    }
    let message = String::from_utf8_lossy(&output.stderr);
    bail!("{program} failed: {}", message.trim());
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_owned())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn home_directory() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("locate home directory")
}

fn format_duration(duration: Duration) -> String {
    if duration.as_secs() % 3600 == 0 {
        format!("{}h0m0s", duration.as_secs() / 3600)
    } else if duration.as_secs() % 60 == 0 {
        format!("{}m0s", duration.as_secs() / 60)
    } else {
        format!("{duration:?}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removed_config_flag_for_serve_map_is_rejected() {
        let result = parse_flags(
            &["--config".to_owned(), "config.json".to_owned()],
            &[("token-file", true), ("listen", true), ("base-port", true)],
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("flag provided but not defined")
        );
    }

    #[test]
    fn version_string_reports_build_metadata() {
        let version = version_string();
        assert!(version.starts_with("oixc-proxy "), "{version}");
        assert!(version.contains("(commit "), "{version}");
        assert!(version.contains(", built "), "{version}");
        assert!(version.ends_with(")"), "{version}");
    }

    #[test]
    fn version_rejects_arguments() {
        let error = run_version(&["--help".to_owned()]).unwrap_err();
        assert!(error.to_string().contains("takes no arguments"));
    }

    #[test]
    fn format_node_count_mentions_total_when_filtered() {
        assert_eq!(format_node_count(12, 12), "12 named nodes");
        assert_eq!(format_node_count(12, 40), "12 named nodes (40 total)");
    }
}
