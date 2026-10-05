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
use crate::catalog_cache::{CatalogCache, CatalogSnapshot};
use crate::config::{RuntimeConfig, default_proxy_config_path, load_proxy_config, load_token_file};
use crate::gateway::{
    CLASH_PROVIDER_PATH, GatewayContext, GatewayManager, PROVIDER_PATH, Route, Router,
    derive_routing_secret,
};
use crate::http_server;
use crate::network::NetworkMonitor;
use crate::nodes::{ManagedConfig, Proxy};
use crate::rlimit;
use crate::snell::{SnellClient, SnellClientOptions};
use crate::socks5::{self, Credentials, FixedRoute, Mode, UdpRelay};
use crate::transport::{EchDialer, TransportContext};

const SERVE_MAP_REFRESH_INTERVAL: Duration = Duration::from_secs(3600);

const USAGE: &str = "Usage:
  oixc-proxy information [--config PATH] --output PATH
  oixc-proxy preview-nodes [--config PATH] [--refresh] [--disable-node-filter]
  oixc-proxy refresh-nodes [--config PATH]
  oixc-proxy reload-config [--config PATH]
  oixc-proxy diagnose [--config PATH] --output PATH
  oixc-proxy serve [--config PATH] [--disable-node-filter]
  oixc-proxy serve-map [--token-file PATH] [--listen IP] [--base-port PORT] [--disable-node-filter]
  oixc-proxy version
  oixc-proxy install-launch-agent [--config PATH]
  oixc-proxy install-systemd [--config PATH]

The information command is read-only. Its output file is created with mode
0600 and must not already exist.

--disable-node-filter publishes all managed nodes instead of only those
whose names contain Fusion or CIA markers. Use this when your
account does not include any Fusion/CIA nodes.

GET /surge-proxies.conf?all=1 and /clash-proxies.yaml?all=1 publish the
full catalog without changing the default filtered listing. Provider
entries are HTTP proxies by default; append socks=1 to advertise SOCKS5
instead. The local listener accepts both HTTP and SOCKS5.

preview-nodes prints the effective selection without modifying the service,
cache or panel settings. Use --refresh to fetch instead of reading the cache.
serve-map also accepts --node-filter-lines, --node-filter-regions,
--node-filter-include and --node-filter-exclude (alternatives separated by |).
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
        "preview-nodes" => run_preview_nodes(&args[1..]).await,
        "refresh-nodes" => run_control(&args[1..], crate::control::Command::RefreshNodes).await,
        "reload-config" => run_control(&args[1..], crate::control::Command::ReloadConfig).await,
        "diagnose" => run_diagnose(&args[1..]).await,
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
    let network = service_network(service.outbound_ip);
    let client = api_client(&service.runtime, &network).await?;
    let content = client.information().await?;
    write_exclusive(&output, &content)?;
    println!("Wrote API response to {}", output.display());
    Ok(())
}

async fn run_preview_nodes(args: &[String]) -> Result<()> {
    let default = default_proxy_config_path()?;
    let flags = parse_flags(
        args,
        &[
            ("config", true),
            ("refresh", false),
            ("disable-node-filter", false),
        ],
    )?;
    let config_path = flag_path(&flags, "config", &default);
    let service = load_proxy_config(&config_path)?;
    let cache = CatalogCache::beside_config(&config_path, &service.runtime.access_token);
    let cached = if flags.contains_key("refresh") {
        None
    } else {
        cache.load()
    };
    let managed = match cached {
        Some(cached) => cached,
        None => {
            load_managed_nodes(
                &service.runtime,
                true,
                &service_network(service.outbound_ip),
            )
            .await?
        }
    };
    let preview = service
        .runtime
        .node_filter
        .preview(&managed.proxies, flags.contains_key("disable-node-filter"));
    println!("{}", serde_json::to_string_pretty(&preview)?);
    Ok(())
}

async fn run_control(args: &[String], command: crate::control::Command) -> Result<()> {
    let default = default_proxy_config_path()?;
    let flags = parse_flags(args, &[("config", true)])?;
    let response = crate::control::send(&flag_path(&flags, "config", &default), command).await?;
    let value = serde_json::to_string_pretty(&response)?;
    if !response.ok {
        bail!("{value}");
    }
    println!("{value}");
    Ok(())
}

async fn run_diagnose(args: &[String]) -> Result<()> {
    let default = default_proxy_config_path()?;
    let flags = parse_flags(args, &[("config", true), ("output", true)])?;
    let output = flags
        .get("output")
        .and_then(|v| v.as_ref())
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| UsageError("diagnose requires --output PATH".to_owned()))?;
    let response = crate::control::send(
        &flag_path(&flags, "config", &default),
        crate::control::Command::Diagnostics,
    )
    .await?;
    if !response.ok {
        bail!("diagnostic export failed");
    }
    write_exclusive(&output, &serde_json::to_vec_pretty(&response.payload)?)?;
    println!("Diagnostic bundle written to {}", output.display());
    Ok(())
}

struct CatalogService {
    service: crate::config::ProxyConfig,
    managed: ManagedConfig,
    fetched_at: Option<u64>,
    network: NetworkMonitor,
    cache: CatalogCache,
    context: GatewayContext,
    manager: Arc<GatewayManager>,
    disable_filter: bool,
    events: crate::diagnostics::EventLog,
}

impl CatalogService {
    async fn bundle(&self) -> serde_json::Value {
        serde_json::json!({
            "schema_version":1, "collected_at":crate::diagnostics::unix_now(),
            "process":{"version":crate::VERSION,"commit":env!("OIXC_COMMIT_ID"),
                "build_time":env!("OIXC_BUILD_TIME"), "os":std::env::consts::OS,
                "arch":std::env::consts::ARCH,"pid":std::process::id()},
            "active_config":crate::diagnostics::config_summary(&self.service,self.disable_filter),
            "status":crate::diagnostics::bundle_status(&self.manager.status().await),
            "service":self.events.snapshot(),
        })
    }

    async fn reload(&mut self, path: &Path) -> Result<()> {
        let result = self.reload_inner(path).await;
        self.events.record(
            crate::diagnostics::EventKind::ConfigReload,
            result.as_ref().err(),
        );
        result
    }

    async fn reload_inner(&mut self, path: &Path) -> Result<()> {
        let next = load_proxy_config(path)
            .map_err(|_| anyhow::anyhow!("invalid configuration; active configuration retained"))?;
        if next.listen != self.service.listen
            || next.nodelist_listen != self.service.nodelist_listen
            || next.outbound_ip != self.service.outbound_ip
            || next.udp_port_range != self.service.udp_port_range
            || next.udp_advertise_address != self.service.udp_advertise_address
        {
            bail!("listener, egress and UDP binding changes require a restart");
        }
        let account_changed = next.runtime.access_token != self.service.runtime.access_token;
        let api_changed = next.runtime.api_base_url != self.service.runtime.api_base_url
            || next.runtime.api_fallback_urls != self.service.runtime.api_fallback_urls
            || next.runtime.app_secret != self.service.runtime.app_secret;
        let fetched = if account_changed || api_changed {
            Some(load_managed_catalog(&next.runtime, true, &self.network).await?)
        } else {
            None
        };
        let managed = fetched
            .as_ref()
            .map(|s| &s.managed)
            .unwrap_or(&self.managed);
        let published = published_proxies(managed, self.disable_filter, &next.runtime.node_filter)?;
        let context = self
            .context
            .reconfigured(&self.service.runtime, &next.runtime)?;
        let previous = self.manager.current().await?;
        let reusable = self.service.runtime.same_client_settings(&next.runtime);
        let router = Router::build(
            &managed.proxies,
            &published,
            &next.runtime,
            &context,
            if reusable { Some(&previous) } else { None },
        )?;
        let cache = CatalogCache::beside_config(path, &next.runtime.access_token);
        self.manager.replace(router).await?;
        if let Some(snapshot) = fetched {
            self.manager
                .update_subscription(snapshot.userinfo.clone(), snapshot.fetched_at)
                .await;
            self.manager.initialize_status(false, snapshot.fetched_at);
            cache.store_snapshot_or_log(&snapshot);
            self.fetched_at = snapshot.fetched_at;
            self.managed = snapshot.managed;
        }
        self.cache = cache;
        self.context = context;
        self.service = next;
        crate::perftrace::configure(self.service.runtime.perf_trace_sample_every);
        Ok(())
    }

    async fn refresh(&mut self) -> Result<()> {
        self.manager.refresh_started();
        let result = self.refresh_inner().await;
        self.manager.refresh_finished(result.as_ref().err());
        self.events.record(
            crate::diagnostics::EventKind::CatalogRefresh,
            result.as_ref().err(),
        );
        if let Err(error) = &result {
            if matches!(
                crate::diagnostics::classify(error),
                crate::diagnostics::ErrorKind::Authentication
                    | crate::diagnostics::ErrorKind::Forbidden
            ) {
                self.manager.update_subscription(None, None).await;
                if let Err(error) = self
                    .cache
                    .store_snapshot(&self.managed, None, self.fetched_at)
                {
                    eprintln!("clear cached account metadata: {error:#}");
                }
            }
        }
        result
    }

    async fn refresh_inner(&mut self) -> Result<()> {
        let refreshed = load_managed_catalog(&self.service.runtime, true, &self.network).await?;
        if refreshed.managed.proxies != self.managed.proxies {
            let published = published_proxies(
                &refreshed.managed,
                self.disable_filter,
                &self.service.runtime.node_filter,
            )?;
            let previous = self.manager.current().await?;
            let replacement = Router::build(
                &refreshed.managed.proxies,
                &published,
                &self.service.runtime,
                &self.context,
                Some(previous.as_ref()),
            )?;
            self.manager.replace(replacement).await?;
            println!(
                "Refreshed node catalog ({})",
                format_node_count(published.len(), refreshed.managed.proxies.len())
            );
        }
        self.manager
            .update_subscription(refreshed.userinfo.clone(), refreshed.fetched_at)
            .await;
        self.fetched_at = refreshed.fetched_at;
        self.cache.store_snapshot_or_log(&refreshed);
        self.managed = refreshed.managed;
        Ok(())
    }
}

async fn run_serve(args: &[String]) -> Result<()> {
    rlimit::raise_nofile_limit();
    let default = default_proxy_config_path()?;
    let flags = parse_flags(args, &[("config", true), ("disable-node-filter", false)])?;
    let config_path = flag_path(&flags, "config", &default);
    let disable_node_filter = flags.contains_key("disable-node-filter");
    let service = load_proxy_config(&config_path)?;
    let events = crate::diagnostics::EventLog::default();
    crate::perftrace::configure(service.runtime.perf_trace_sample_every);
    let network = service_network(service.outbound_ip);
    let cache = CatalogCache::beside_config(&config_path, &service.runtime.access_token);
    let (initial, from_cache) = if let Some(cached) = cache.load_snapshot() {
        (cached, true)
    } else {
        let fetched = load_managed_catalog(&service.runtime, true, &network).await?;
        cache.store_snapshot_or_log(&fetched);
        (fetched, false)
    };
    let managed = initial.managed;
    let published = published_proxies(&managed, disable_node_filter, &service.runtime.node_filter)?;
    let routing_secret = derive_routing_secret(&service.runtime.access_token)?;
    let transport = Arc::new(TransportContext::built_in_with_network(network.clone())?);
    let catalog_refresh = transport.catalog_refresh.clone();
    let dial_limit = Arc::new(Semaphore::new(service.runtime.dial_concurrency));
    let udp_relay_advertised = service.listen.ip().is_loopback()
        || (service.udp_port_range.is_some() && service.udp_advertise_address.is_some());
    let gateway_context = GatewayContext::new(
        service.outbound_ip,
        udp_relay_advertised,
        routing_secret,
        dial_limit,
        transport.clone(),
    );
    let router = Router::build(
        &managed.proxies,
        &published,
        &service.runtime,
        &gateway_context,
        None,
    )?;
    let manager = Arc::new(GatewayManager::new(router).with_transport(transport));
    manager.initialize_status(
        from_cache,
        if from_cache {
            initial.fetched_at.or_else(|| cache.modified_at())
        } else {
            Some(crate::diagnostics::unix_now())
        },
    );
    manager
        .update_subscription(initial.userinfo, initial.fetched_at)
        .await;
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

    let udp_relay = match (service.udp_port_range, service.udp_advertise_address) {
        (Some(range), Some(advertise_address)) => {
            UdpRelay::fixed(service.outbound_ip, advertise_address, range)?
        }
        (None, None) => UdpRelay::ephemeral(service.outbound_ip),
        _ => unreachable!("paired UDP relay configuration was validated"),
    };
    let options = socks5::Options {
        handshake_timeout: service.runtime.request_timeout.max(Duration::from_secs(45)),
        tcp_idle_timeout: service.runtime.tcp_idle_timeout,
        udp_idle_timeout: service.runtime.udp_idle_timeout,
        udp_relay,
        mode: Mode::Dynamic(manager.clone()),
    };
    let (settings_tx, settings_rx) = tokio::sync::watch::channel(AcceptSettings {
        options,
        max_connections: service.runtime.max_client_connections,
    });
    let mut socks_task = tokio::spawn(serve_dynamic_listener(socks_listener, settings_rx));
    let mut http_task = tokio::spawn(http_server::serve(nodelist_listener, manager.clone()));
    let control = crate::control::Server::bind(&config_path).await?;
    let (control_tx, mut control_rx) = tokio::sync::mpsc::channel::<crate::control::Request>(8);
    let mut control_task = tokio::spawn(control.serve(control_tx));
    let mut refresh = tokio::time::interval(service.node_refresh_interval);
    if !from_cache {
        refresh.tick().await;
    }
    let mut catalog = CatalogService {
        service,
        managed,
        fetched_at: initial.fetched_at,
        network,
        cache,
        context: gateway_context,
        manager: manager.clone(),
        disable_filter: disable_node_filter,
        events,
    };
    loop {
        let request = tokio::select! {
            result = &mut socks_task => {
                return result.context("SOCKS5 server task failed")?;
            }
            result = &mut http_task => {
                return result.context("nodelist HTTP task failed")?;
            }
            result = &mut control_task => { return result.context("service control task failed")?; }
            request = control_rx.recv() => Some(request.context("service control queue closed")?),
            _ = refresh.tick() => None,
            _ = catalog_refresh.notified() => None,
        };
        if request
            .as_ref()
            .is_some_and(|request| request.reply.is_closed())
        {
            continue;
        }
        if request
            .as_ref()
            .is_some_and(|r| matches!(r.command, crate::control::Command::Diagnostics))
        {
            if let Some(request) = request {
                let response = crate::control::Response::success(
                    "sanitized diagnostic bundle",
                    catalog.bundle().await,
                );
                let _ = request.reply.send(response);
            }
            continue;
        }
        let reloading = request
            .as_ref()
            .is_some_and(|r| matches!(r.command, crate::control::Command::ReloadConfig));
        let result = if reloading {
            catalog.reload(&config_path).await
        } else {
            catalog.refresh().await
        };
        if reloading && result.is_ok() {
            let mut settings = settings_tx.borrow().clone();
            settings.options.handshake_timeout = catalog
                .service
                .runtime
                .request_timeout
                .max(Duration::from_secs(45));
            settings.options.tcp_idle_timeout = catalog.service.runtime.tcp_idle_timeout;
            settings.options.udp_idle_timeout = catalog.service.runtime.udp_idle_timeout;
            settings.max_connections = catalog.service.runtime.max_client_connections;
            settings_tx.send_replace(settings);
            refresh = tokio::time::interval(catalog.service.node_refresh_interval);
            refresh.tick().await;
        }
        if let Some(request) = request {
            let response = match &result {
                Ok(()) => crate::control::Response::success(
                    if reloading {
                        "configuration reloaded"
                    } else {
                        "node catalog refreshed"
                    },
                    manager.status().await,
                ),
                Err(error) => crate::control::Response::failure(
                    if reloading {
                        "reload failed; active configuration retained; check config validity and restart-only fields"
                    } else {
                        "refresh failed; previous catalog retained"
                    },
                    crate::diagnostics::classify(error),
                ),
            };
            let _ = request.reply.send(response);
        }
        if let Err(error) = result {
            if reloading {
                eprintln!(
                    "configuration reload failed: {:?}",
                    crate::diagnostics::classify(&error)
                );
            } else {
                eprintln!("node catalog refresh failed: {error:#}");
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
            ("node-filter-lines", true),
            ("node-filter-regions", true),
            ("node-filter-include", true),
            ("node-filter-exclude", true),
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
    runtime.node_filter = crate::nodes::NodeFilter::new(
        flags
            .get("node-filter-lines")
            .and_then(Option::as_deref)
            .unwrap_or(""),
        flags
            .get("node-filter-regions")
            .and_then(Option::as_deref)
            .unwrap_or(""),
        flags
            .get("node-filter-include")
            .and_then(Option::as_deref)
            .unwrap_or(""),
        flags
            .get("node-filter-exclude")
            .and_then(Option::as_deref)
            .unwrap_or(""),
    )?;
    crate::perftrace::configure(runtime.perf_trace_sample_every);
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
    let network = NetworkMonitor::new(None);
    let managed = load_managed_nodes(&runtime, disable_node_filter, &network).await?;
    if base_port as usize + managed.proxies.len() > u16::MAX as usize + 1 {
        bail!("SOCKS5 map port range exceeds 65535");
    }

    let transport = Arc::new(TransportContext::built_in_with_network(network.clone())?);
    let dial_limit = Arc::new(Semaphore::new(runtime.dial_concurrency));
    let connection_limit = Arc::new(Semaphore::new(runtime.max_client_connections));
    let mut listeners = Vec::with_capacity(managed.proxies.len());
    let mut routes = Vec::with_capacity(managed.proxies.len());
    for (index, proxy) in managed.proxies.iter().enumerate() {
        let port = base_port + index as u16;
        listeners.push(
            TcpListener::bind(SocketAddr::new(listen, port))
                .await
                .with_context(|| format!("listen on local SOCKS5 map port {port}"))?,
        );
        routes.push(FixedRoute::new(build_fixed_route(
            proxy,
            &runtime,
            transport.clone(),
            dial_limit.clone(),
        )?));
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
    for (listener, route) in listeners.into_iter().zip(routes.iter().cloned()) {
        let sender = error_tx.clone();
        let connection_limit = connection_limit.clone();
        let options = socks5::Options {
            handshake_timeout: runtime.request_timeout,
            tcp_idle_timeout: runtime.tcp_idle_timeout,
            udp_idle_timeout: runtime.udp_idle_timeout,
            udp_relay: UdpRelay::ephemeral(listen),
            mode: Mode::Fixed {
                route,
                credentials: credentials.clone(),
            },
        };
        tokio::spawn(async move {
            let error = serve_socks_listener(listener, options, connection_limit).await;
            let _ = sender.send(error).await;
        });
    }
    drop(error_tx);

    let mut mapped = managed.proxies;
    let mut refresh = tokio::time::interval(SERVE_MAP_REFRESH_INTERVAL);
    refresh.tick().await;
    loop {
        tokio::select! {
            error = error_rx.recv() => {
                return error.context("SOCKS5 map listener stopped")?;
            }
            _ = async {
                tokio::select! {
                    _ = refresh.tick() => {},
                    _ = transport.catalog_refresh.notified() => {},
                }
            } => {
                let refreshed = match load_managed_nodes(&runtime, disable_node_filter, &network).await {
                    Ok(value) => value,
                    Err(error) => {
                        eprintln!("node catalog refresh failed: {error:#}");
                        continue;
                    }
                };
                let plan = plan_map_refresh(&mapped, &refreshed.proxies);
                let mut updated = 0;
                for (index, proxy) in plan.updates {
                    let route = match build_fixed_route(
                        &proxy,
                        &runtime,
                        transport.clone(),
                        dial_limit.clone(),
                    ) {
                        Ok(value) => value,
                        Err(error) => {
                            eprintln!("node catalog refresh failed for port {}: {error:#}", base_port as usize + index);
                            continue;
                        }
                    };
                    routes[index].replace(route).client.close().await;
                    mapped[index] = proxy;
                    updated += 1;
                }
                if updated > 0 {
                    println!("Refreshed SOCKS5 map ({updated} nodes updated)");
                }
                if plan.added > 0 || plan.removed > 0 {
                    eprintln!(
                        "node catalog has {} new and {} removed nodes; restart serve-map to remap ports",
                        plan.added, plan.removed
                    );
                }
            }
        }
    }
}

/// Changes a refreshed catalog makes to a running SOCKS5 map.
#[derive(Debug, PartialEq)]
struct MapRefresh {
    /// Ports, by index, whose node keeps its name but changed connection details.
    updates: Vec<(usize, Proxy)>,
    added: usize,
    removed: usize,
}

/// Ports stay bound to node names, so nodes that appear or disappear are only
/// reported: renumbering ports would silently send clients to other nodes.
fn plan_map_refresh(mapped: &[Proxy], refreshed: &[Proxy]) -> MapRefresh {
    let mut updates = Vec::new();
    let mut removed = 0;
    for (index, current) in mapped.iter().enumerate() {
        match refreshed.iter().find(|proxy| proxy.name == current.name) {
            Some(proxy) if proxy != current => updates.push((index, proxy.clone())),
            Some(_) => {}
            None => removed += 1,
        }
    }
    let added = refreshed
        .iter()
        .filter(|proxy| !mapped.iter().any(|current| current.name == proxy.name))
        .count();
    MapRefresh {
        updates,
        added,
        removed,
    }
}

#[derive(Clone)]
struct AcceptSettings {
    options: socks5::Options,
    max_connections: usize,
}

#[derive(Default)]
struct ActiveConnections {
    count: std::sync::atomic::AtomicUsize,
    changed: tokio::sync::Notify,
}

struct ActiveConnection(Arc<ActiveConnections>);

impl Drop for ActiveConnection {
    fn drop(&mut self) {
        self.0
            .count
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        self.0.changed.notify_one();
    }
}

async fn admit_connection(
    settings: &mut tokio::sync::watch::Receiver<AcceptSettings>,
    active: &Arc<ActiveConnections>,
) -> Result<(ActiveConnection, socks5::Options)> {
    loop {
        let current = settings.borrow_and_update().clone();
        if active.count.load(std::sync::atomic::Ordering::Acquire) < current.max_connections {
            active
                .count
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            return Ok((ActiveConnection(active.clone()), current.options));
        }
        tokio::select! {
            result = settings.changed() => result.context("listener settings closed")?,
            _ = active.changed.notified() => {},
        }
    }
}

async fn serve_dynamic_listener(
    listener: TcpListener,
    mut settings: tokio::sync::watch::Receiver<AcceptSettings>,
) -> Result<()> {
    let active = Arc::new(ActiveConnections::default());
    loop {
        let connection = crate::accept::accept(&listener, "local proxy").await?;
        let (permit, options) = admit_connection(&mut settings, &active).await?;
        tokio::spawn(async move {
            let _permit = permit;
            let _ = crate::perftrace::scope(socks5::serve_connection(connection, options)).await;
        });
    }
}

async fn serve_socks_listener(
    listener: TcpListener,
    options: socks5::Options,
    slots: Arc<Semaphore>,
) -> Result<()> {
    loop {
        let connection = crate::accept::accept(&listener, "local proxy")
            .await
            .context("accept local proxy connection")?;
        let permit = slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| anyhow::anyhow!("SOCKS5 connection limiter is closed"))?;
        let options = options.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = crate::perftrace::scope(socks5::serve_connection(connection, options)).await;
        });
    }
}

fn build_fixed_route(
    proxy: &Proxy,
    runtime: &RuntimeConfig,
    transport: Arc<TransportContext>,
    dial_limit: Arc<Semaphore>,
) -> Result<Route> {
    let dialer = EchDialer::new_with_context(proxy, runtime.request_timeout, transport)?;
    Ok(Route {
        client: SnellClient::new_with_node_dial_limit(
            SnellClientOptions {
                node_name: proxy.name.clone(),
                psk: proxy.psk.clone(),
                reuse: proxy.reuse,
                max_idle: runtime.reuse_max_idle,
                max_uses: runtime.reuse_max_uses,
                idle_timeout: runtime.reuse_idle_timeout,
                handshake_timeout: runtime.request_timeout,
                close_timeout: Duration::from_secs(2),
                dialer: dialer.into(),
                dial_limit: Some(dial_limit),
                dial_limit_timeout: runtime.request_timeout,
            },
            Some(Arc::new(Semaphore::new(runtime.per_node_dial_concurrency))),
        )?,
        udp: proxy.udp,
    })
}

fn published_proxies(
    managed: &ManagedConfig,
    include_all: bool,
    filter: &crate::nodes::NodeFilter,
) -> Result<Vec<Proxy>> {
    if include_all {
        return Ok(managed.proxies.clone());
    }
    managed.filtered_proxies(filter)
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
    network: &NetworkMonitor,
) -> Result<ManagedConfig> {
    Ok(load_managed_catalog(runtime, disable_filter, network)
        .await?
        .managed)
}

async fn load_managed_catalog(
    runtime: &RuntimeConfig,
    disable_filter: bool,
    network: &NetworkMonitor,
) -> Result<CatalogSnapshot> {
    let client = api_client(runtime, network).await?;
    let response = client.fetch_managed().await?;
    let managed = ManagedConfig::parse(&response.config).map_err(|error| {
        error.context(crate::diagnostics::ApiFailure {
            kind: crate::diagnostics::ErrorKind::InvalidResponse,
            status: None,
            retry_after_seconds: None,
        })
    })?;
    let managed = if disable_filter {
        managed
    } else {
        ManagedConfig {
            proxies: managed.filtered_proxies(&runtime.node_filter)?,
        }
    };
    Ok(CatalogSnapshot {
        managed,
        userinfo: response.userinfo,
        fetched_at: Some(crate::diagnostics::unix_now()),
    })
}

async fn api_client(runtime: &RuntimeConfig, network: &NetworkMonitor) -> Result<ApiClient> {
    let snapshot = network.snapshot().await;
    ApiClient::new_with_network(
        runtime.api_base_url.clone(),
        runtime.access_token.clone(),
        runtime.app_secret.clone(),
        runtime.request_timeout,
        &snapshot,
    )?
    .with_fallback_urls(runtime.api_fallback_urls.clone())
}

fn service_network(outbound_ip: IpAddr) -> NetworkMonitor {
    NetworkMonitor::new((!outbound_ip.is_loopback()).then_some(outbound_ip))
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
RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX
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

    fn node(name: &str) -> Proxy {
        let yaml = format!(
            "proxies:
  - name: {name}
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
      ech-config: {}
      identity-version: 2
      legacy-fallback: false
      skip-cert-verify: false
      preconnect: 0
",
            crate::nodes::TEST_ECH_CONFIG
        );
        ManagedConfig::parse(yaml.as_bytes())
            .unwrap()
            .proxies
            .remove(0)
    }

    #[test]
    fn map_refresh_updates_ports_in_place_and_reports_membership_changes() {
        let mapped = vec![node("A Fusion"), node("B Fusion"), node("C Fusion")];
        let mut rotated = node("B Fusion");
        rotated.psk = "rotated".to_owned();
        let refreshed = vec![node("D Fusion"), rotated.clone(), node("A Fusion")];
        assert_eq!(
            plan_map_refresh(&mapped, &refreshed),
            MapRefresh {
                updates: vec![(1, rotated)],
                added: 1,
                removed: 1,
            }
        );
        assert_eq!(
            plan_map_refresh(&mapped, &mapped),
            MapRefresh {
                updates: Vec::new(),
                added: 0,
                removed: 0,
            }
        );
    }

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

    #[test]
    fn publishing_uses_custom_filter_and_all_bypasses_it() {
        let managed = ManagedConfig {
            proxies: vec![node("香港 Fusion 01"), node("Japan IXP 01")],
        };
        let filter = crate::nodes::NodeFilter::new("IXP", "Japan", "", "").unwrap();
        assert_eq!(
            published_proxies(&managed, false, &filter).unwrap()[0].name,
            "Japan IXP 01"
        );
        assert_eq!(published_proxies(&managed, true, &filter).unwrap().len(), 2);
    }

    #[tokio::test]
    async fn failed_refresh_and_reload_preserve_state_and_valid_reload_applies() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("test.conf");
        std::fs::write(
            &path,
            "token=test\napi-base-url=https://127.0.0.1:9\nrequest-timeout=100ms\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let service = load_proxy_config(&path).unwrap();
        let managed = ManagedConfig {
            proxies: vec![node("香港 Fusion 01")],
        };
        let network = NetworkMonitor::new(None);
        let transport = Arc::new(TransportContext::built_in_with_network(network.clone()).unwrap());
        let context = GatewayContext::new(
            service.outbound_ip,
            false,
            derive_routing_secret("test").unwrap(),
            Arc::new(Semaphore::new(1)),
            transport,
        );
        let router = Router::build(
            &managed.proxies,
            &managed.proxies,
            &service.runtime,
            &context,
            None,
        )
        .unwrap();
        let manager = Arc::new(GatewayManager::new(router));
        let previous = manager.current().await.unwrap();
        let cache = CatalogCache::beside_config(&path, "test");
        cache.store(&managed).unwrap();
        let mut catalog = CatalogService {
            service,
            managed: managed.clone(),
            fetched_at: Some(1),
            network,
            cache,
            context,
            manager: manager.clone(),
            disable_filter: false,
            events: crate::diagnostics::EventLog::default(),
        };
        assert!(catalog.refresh().await.is_err());
        assert!(Arc::ptr_eq(&previous, &manager.current().await.unwrap()));
        assert_eq!(catalog.cache.load().unwrap(), managed);
        assert_eq!(manager.status().await["catalog"]["refresh_failures"], 1);
        for content in [
            "token=test\nunknown-key=secret\n",
            "token=test\nlisten=127.0.0.1:6174\n",
            "token=new-account\napi-base-url=https://127.0.0.1:9\nrequest-timeout=100ms\n",
        ] {
            std::fs::write(&path, content).unwrap();
            assert!(catalog.reload(&path).await.is_err());
            assert!(Arc::ptr_eq(&previous, &manager.current().await.unwrap()));
            assert_eq!(catalog.service.runtime.access_token, "test");
            assert_eq!(catalog.cache.load().unwrap(), managed);
            let bundle = catalog.bundle().await;
            assert_eq!(bundle["active_config"]["request_timeout_ms"], 100);
            assert_eq!(bundle["status"]["nodes"][0]["id"], "node-1");
            let serialized = bundle.to_string();
            for private in [
                "香港 Fusion 01",
                "https://127.0.0.1:9",
                "new-account",
                "unknown-key",
                "\"test\"",
            ] {
                assert!(!serialized.contains(private));
            }
            assert!(!serialized.contains(&directory.path().to_string_lossy().to_string()));
        }
        std::fs::write(&path, "token=test\napi-base-url=https://127.0.0.1:9\nrequest-timeout=200ms\nnode-filter-lines=Fusion\nmax-client-connections=2\ndial-concurrency=3\nper-node-dial-concurrency=2\ntcp-idle-timeout=2m\nnode-refresh-interval=2m\n").unwrap();
        catalog.reload(&path).await.unwrap();
        assert!(!Arc::ptr_eq(&previous, &manager.current().await.unwrap()));
        assert_eq!(
            catalog.service.runtime.request_timeout,
            Duration::from_millis(200)
        );
        assert_eq!(catalog.service.runtime.max_client_connections, 2);
        assert_eq!(catalog.service.runtime.dial_concurrency, 3);
        assert_eq!(catalog.service.runtime.per_node_dial_concurrency, 2);
        assert_eq!(
            catalog.service.node_refresh_interval,
            Duration::from_secs(120)
        );
        assert_eq!(manager.status().await["published_nodes"], 1);
        assert_eq!(catalog.cache.load().unwrap(), managed);
    }

    #[tokio::test]
    async fn connection_limit_reload_counts_existing_connections_and_wakes_waiters() {
        let options = socks5::Options {
            handshake_timeout: Duration::from_secs(45),
            tcp_idle_timeout: Duration::from_secs(60),
            udp_idle_timeout: Duration::from_secs(10),
            udp_relay: UdpRelay::ephemeral("127.0.0.1".parse().unwrap()),
            mode: Mode::Dynamic(Arc::new(GatewayManager::empty_for_test())),
        };
        let (tx, mut rx) = tokio::sync::watch::channel(AcceptSettings {
            options,
            max_connections: 2,
        });
        let active = Arc::new(ActiveConnections::default());
        let first = admit_connection(&mut rx, &active).await.unwrap().0;
        let second = admit_connection(&mut rx, &active).await.unwrap().0;
        tx.send_modify(|s| s.max_connections = 1);
        drop(first);
        assert!(
            tokio::time::timeout(
                Duration::from_millis(20),
                admit_connection(&mut rx, &active)
            )
            .await
            .is_err()
        );
        drop(second);
        let third =
            tokio::time::timeout(Duration::from_secs(1), admit_connection(&mut rx, &active))
                .await
                .unwrap()
                .unwrap()
                .0;
        let waiting = tokio::spawn(async move { admit_connection(&mut rx, &active).await });
        tx.send_modify(|s| {
            s.max_connections = 2;
            s.options.tcp_idle_timeout = Duration::from_secs(120);
        });
        let (_, updated) = tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(updated.tcp_idle_timeout, Duration::from_secs(120));
        drop(third);
    }

    #[test]
    fn diagnostic_output_is_private_and_refuses_overwrites() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("diagnostics.json");
        write_exclusive(&output, b"{}").unwrap();
        assert!(write_exclusive(&output, b"replacement").is_err());
        assert_eq!(std::fs::read(&output).unwrap(), b"{}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn systemd_unit_allows_interface_discovery() {
        let unit = render_systemd(
            Path::new("/usr/local/bin/oixc-proxy"),
            Path::new("/home/user/.config/oixc-proxy/oixc-proxy.conf"),
            Path::new("/home/user/.config/oixc-proxy"),
        );
        assert!(unit.contains("RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX"));
    }
}
