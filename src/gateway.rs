use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use anyhow::{Result, bail};
use base64::Engine as _;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::sync::{RwLock, Semaphore};

use crate::config::RuntimeConfig;
use crate::nodes::Proxy;
use crate::snell::{SnellClient, SnellClientOptions};
use crate::surge::{ProviderProtocol, node_selector, render_provider};
use crate::transport::{EchDialer, TransportContext};

pub const PROVIDER_PATH: &str = "/surge-proxies.conf";
pub const CLASH_PROVIDER_PATH: &str = "/clash-proxies.yaml";
pub const HEALTH_PATH: &str = "/healthz";
pub const STATUS_PATH: &str = "/status";
const ROUTING_SECRET_CONTEXT: &[u8] = b"oixc-proxy/provider-routing/v1";

#[derive(Clone)]
pub struct Route {
    pub client: SnellClient,
    pub udp: bool,
}

struct NodeRuntime {
    proxy: Proxy,
    route: Route,
}

#[derive(Clone)]
struct ProviderDocs {
    surge_http: Arc<[u8]>,
    surge_socks: Arc<[u8]>,
    clash_http: Arc<[u8]>,
    clash_socks: Arc<[u8]>,
}

pub struct Router {
    routes: HashMap<String, Route>,
    runtimes: HashMap<String, Arc<NodeRuntime>>,
    filtered: ProviderDocs,
    all: ProviderDocs,
    routing_secret: String,
    published_count: usize,
}

pub struct GatewayManager {
    router: RwLock<Option<Arc<Router>>>,
    catalog_status: Mutex<crate::diagnostics::CatalogStatus>,
    transport: Option<Arc<TransportContext>>,
    subscription: RwLock<Option<(crate::subscription::UserInfo, Option<u64>)>>,
}

pub struct GatewayContext {
    outbound_ip: IpAddr,
    udp_relay_advertised: bool,
    routing_secret: String,
    dial_limit: Arc<Semaphore>,
    transport: Arc<TransportContext>,
}

impl GatewayContext {
    pub fn new(
        outbound_ip: IpAddr,
        udp_relay_advertised: bool,
        routing_secret: String,
        dial_limit: Arc<Semaphore>,
        transport: Arc<TransportContext>,
    ) -> Self {
        Self {
            outbound_ip,
            udp_relay_advertised,
            routing_secret,
            dial_limit,
            transport,
        }
    }
}

impl Router {
    pub fn build(
        proxies: &[Proxy],
        published: &[Proxy],
        runtime: &RuntimeConfig,
        context: &GatewayContext,
        previous: Option<&Router>,
    ) -> Result<Self> {
        let listen_address = context.outbound_ip.to_string();
        let filtered = render_provider_docs(
            published,
            &listen_address,
            runtime.serve_port,
            &context.routing_secret,
            context.udp_relay_advertised,
        )?;
        let all = if same_proxy_list(proxies, published) {
            filtered.clone()
        } else {
            render_provider_docs(
                proxies,
                &listen_address,
                runtime.serve_port,
                &context.routing_secret,
                context.udp_relay_advertised,
            )?
        };
        let mut routes = HashMap::with_capacity(proxies.len());
        let mut runtimes = HashMap::with_capacity(proxies.len());
        for proxy in proxies {
            let node_runtime = if let Some(existing) = previous
                .and_then(|catalog| catalog.runtimes.get(&proxy.name))
                .filter(|existing| existing.proxy == *proxy)
            {
                existing.clone()
            } else {
                let dialer = EchDialer::new_with_context(
                    proxy,
                    runtime.request_timeout,
                    context.transport.clone(),
                )?;
                let client = SnellClient::new_with_node_dial_limit(
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
                        dial_limit: Some(context.dial_limit.clone()),
                        dial_limit_timeout: runtime.request_timeout.max(Duration::from_secs(45)),
                    },
                    Some(Arc::new(Semaphore::new(runtime.per_node_dial_concurrency))),
                )?;
                Arc::new(NodeRuntime {
                    proxy: proxy.clone(),
                    route: Route {
                        client,
                        udp: proxy.udp,
                    },
                })
            };
            let selector = node_selector(&proxy.name)?;
            if routes
                .insert(selector, node_runtime.route.clone())
                .is_some()
            {
                bail!("gateway selector collision");
            }
            runtimes.insert(proxy.name.clone(), node_runtime);
        }
        Ok(Self {
            routes,
            runtimes,
            filtered,
            all,
            routing_secret: context.routing_secret.clone(),
            published_count: published.len(),
        })
    }

    pub fn provider(&self, include_all: bool, socks: bool) -> Arc<[u8]> {
        self.docs(include_all).surge(socks)
    }

    pub fn clash_provider(&self, include_all: bool, socks: bool) -> Arc<[u8]> {
        self.docs(include_all).clash(socks)
    }

    fn docs(&self, include_all: bool) -> &ProviderDocs {
        if include_all {
            &self.all
        } else {
            &self.filtered
        }
    }

    fn authenticate(&self, selector: &str, secret: &str) -> Result<Route> {
        if !constant_time_equal(secret.as_bytes(), self.routing_secret.as_bytes()) {
            bail!("gateway authentication failed");
        }
        self.routes
            .get(selector)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("gateway authentication failed"))
    }

    async fn retire_exclusive_runtimes(&self, replacement: Option<&Router>) {
        for (name, runtime) in &self.runtimes {
            let shared = replacement
                .and_then(|catalog| catalog.runtimes.get(name))
                .is_some_and(|other| Arc::ptr_eq(runtime, other));
            if !shared {
                runtime.route.client.close().await;
            }
        }
    }
}

impl GatewayManager {
    #[cfg(test)]
    pub(crate) fn empty_for_test() -> Self {
        Self {
            router: RwLock::new(None),
            catalog_status: Mutex::new(crate::diagnostics::CatalogStatus::default()),
            transport: None,
            subscription: RwLock::new(None),
        }
    }

    #[cfg(test)]
    pub(crate) fn provider_for_test() -> Self {
        let doc: Arc<[u8]> = b"proxies: []\n".as_slice().into();
        let docs = ProviderDocs {
            surge_http: doc.clone(),
            surge_socks: doc.clone(),
            clash_http: doc.clone(),
            clash_socks: doc,
        };
        Self::new(Router {
            routes: HashMap::new(),
            runtimes: HashMap::new(),
            filtered: docs.clone(),
            all: docs,
            routing_secret: "test".to_owned(),
            published_count: 0,
        })
    }

    pub fn with_transport(mut self, transport: Arc<TransportContext>) -> Self {
        self.transport = Some(transport);
        self
    }

    pub fn initialize_status(&self, from_cache: bool, last_success_at: Option<u64>) {
        let mut status = self
            .catalog_status
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        status.started_from_cache = from_cache;
        status.last_success_at = last_success_at;
    }

    pub fn refresh_started(&self) {
        self.catalog_status
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .last_attempt_at = Some(crate::diagnostics::unix_now());
    }

    pub fn refresh_finished(&self, error: Option<&anyhow::Error>) {
        let mut status = self
            .catalog_status
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        status.last_error = error.map(crate::diagnostics::classify);
        if error.is_some() {
            status.refresh_failures += 1;
        } else {
            status.last_success_at = Some(crate::diagnostics::unix_now());
        }
    }

    pub async fn status(&self) -> serde_json::Value {
        let mut catalog = self
            .catalog_status
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        catalog.cache_age_seconds = catalog
            .last_success_at
            .map(|time| crate::diagnostics::unix_now().saturating_sub(time));
        let (ready, total, published) = {
            let router = self.router.read().await;
            router
                .as_ref()
                .map(|r| (true, r.runtimes.len(), r.published_count))
                .unwrap_or((false, 0, 0))
        };
        let transport = match &self.transport {
            Some(transport) => transport.status().await,
            None => serde_json::Value::Null,
        };
        serde_json::json!({"version": crate::VERSION, "ready": ready, "total_nodes": total, "published_nodes": published, "catalog": catalog, "transport": transport})
    }

    pub fn new(router: Router) -> Self {
        Self {
            router: RwLock::new(Some(Arc::new(router))),
            catalog_status: Mutex::new(crate::diagnostics::CatalogStatus::default()),
            transport: None,
            subscription: RwLock::new(None),
        }
    }

    pub async fn authenticate(&self, selector: &str, secret: &str) -> Result<Route> {
        let router = self.router.read().await;
        router
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("gateway is closed"))?
            .authenticate(selector, secret)
    }

    pub async fn provider(&self, include_all: bool, socks: bool) -> Result<Arc<[u8]>> {
        self.router
            .read()
            .await
            .as_ref()
            .map(|router| router.provider(include_all, socks))
            .ok_or_else(|| anyhow::anyhow!("gateway unavailable"))
    }

    pub async fn clash_provider(&self, include_all: bool, socks: bool) -> Result<Arc<[u8]>> {
        self.router
            .read()
            .await
            .as_ref()
            .map(|router| router.clash_provider(include_all, socks))
            .ok_or_else(|| anyhow::anyhow!("gateway unavailable"))
    }

    pub async fn update_subscription(
        &self,
        info: Option<crate::subscription::UserInfo>,
        fetched_at: Option<u64>,
    ) {
        *self.subscription.write().await = info.map(|info| (info, fetched_at));
    }

    pub async fn subscription_header(&self) -> Option<String> {
        self.subscription
            .read()
            .await
            .as_ref()
            .and_then(|(info, at)| info.header(*at, crate::diagnostics::unix_now()))
    }

    pub async fn current(&self) -> Result<Arc<Router>> {
        self.router
            .read()
            .await
            .clone()
            .ok_or_else(|| anyhow::anyhow!("gateway is closed"))
    }

    pub async fn replace(&self, replacement: Router) -> Result<()> {
        let replacement = Arc::new(replacement);
        let previous = {
            let mut current = self.router.write().await;
            current
                .replace(replacement.clone())
                .ok_or_else(|| anyhow::anyhow!("gateway is closed"))?
        };
        previous
            .retire_exclusive_runtimes(Some(replacement.as_ref()))
            .await;
        Ok(())
    }

    pub async fn close(&self) {
        *self.subscription.write().await = None;
        let previous = self.router.write().await.take();
        if let Some(previous) = previous {
            previous.retire_exclusive_runtimes(None).await;
        }
    }
}

pub fn derive_routing_secret(key_material: &str) -> Result<String> {
    if key_material.trim().is_empty() {
        bail!("gateway routing key material is required");
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(key_material.as_bytes())
        .expect("HMAC accepts every key length");
    mac.update(ROUTING_SECRET_CONTEXT);
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

impl ProviderDocs {
    fn surge(&self, socks: bool) -> Arc<[u8]> {
        if socks {
            self.surge_socks.clone()
        } else {
            self.surge_http.clone()
        }
    }

    fn clash(&self, socks: bool) -> Arc<[u8]> {
        if socks {
            self.clash_socks.clone()
        } else {
            self.clash_http.clone()
        }
    }
}

fn render_provider_docs(
    proxies: &[Proxy],
    listen_address: &str,
    port: u16,
    routing_secret: &str,
    udp_relay_advertised: bool,
) -> Result<ProviderDocs> {
    Ok(ProviderDocs {
        surge_http: render_provider(
            proxies,
            listen_address,
            port,
            routing_secret,
            ProviderProtocol::Http,
            false,
        )?
        .into(),
        surge_socks: render_provider(
            proxies,
            listen_address,
            port,
            routing_secret,
            ProviderProtocol::Socks5,
            udp_relay_advertised,
        )?
        .into(),
        clash_http: crate::clash::render_provider(
            proxies,
            listen_address,
            port,
            routing_secret,
            ProviderProtocol::Http,
            false,
        )?
        .into(),
        clash_socks: crate::clash::render_provider(
            proxies,
            listen_address,
            port,
            routing_secret,
            ProviderProtocol::Socks5,
            udp_relay_advertised,
        )?
        .into(),
    })
}

fn same_proxy_list(left: &[Proxy], right: &[Proxy]) -> bool {
    std::ptr::eq(left, right) || left == right
}

fn constant_time_equal(first: &[u8], second: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    first.ct_eq(second).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routing_secret_is_stable_and_url_safe() {
        let secret = derive_routing_secret("token").unwrap();
        assert!(!secret.is_empty());
        assert!(
            secret
                .bytes()
                .all(|value| value.is_ascii_alphanumeric() || b"-_".contains(&value))
        );
    }
}
