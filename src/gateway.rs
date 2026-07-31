use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, bail};
use base64::Engine as _;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::sync::{RwLock, Semaphore};

use crate::config::RuntimeConfig;
use crate::nodes::Proxy;
use crate::snell::{SnellClient, SnellClientOptions};
use crate::surge::{node_selector, render_provider};
use crate::transport::EchDialer;

pub const PROVIDER_PATH: &str = "/surge-proxies.conf";
pub const CLASH_PROVIDER_PATH: &str = "/clash-proxies.yaml";
pub const HEALTH_PATH: &str = "/healthz";
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

pub struct Router {
    routes: HashMap<String, Route>,
    runtimes: HashMap<String, Arc<NodeRuntime>>,
    provider: Arc<[u8]>,
    clash_provider: Arc<[u8]>,
    routing_secret: String,
}

pub struct GatewayManager {
    router: RwLock<Option<Arc<Router>>>,
}

impl Router {
    pub fn build(
        proxies: &[Proxy],
        runtime: &RuntimeConfig,
        outbound_ip: IpAddr,
        routing_secret: &str,
        dial_limit: Arc<Semaphore>,
        previous: Option<&Router>,
    ) -> Result<Self> {
        let provider = render_provider(
            proxies,
            &outbound_ip.to_string(),
            runtime.serve_port,
            routing_secret,
        )?;
        let clash_provider = crate::clash::render_provider(
            proxies,
            &outbound_ip.to_string(),
            runtime.serve_port,
            routing_secret,
        )?;
        let mut routes = HashMap::with_capacity(proxies.len());
        let mut runtimes = HashMap::with_capacity(proxies.len());
        for proxy in proxies {
            let node_runtime = if let Some(existing) = previous
                .and_then(|catalog| catalog.runtimes.get(&proxy.name))
                .filter(|existing| existing.proxy == *proxy)
            {
                existing.clone()
            } else {
                let dialer = EchDialer::new(proxy, runtime.request_timeout)?;
                let client = SnellClient::new(SnellClientOptions {
                    node_name: proxy.name.clone(),
                    psk: proxy.psk.clone(),
                    reuse: proxy.reuse,
                    max_idle: runtime.reuse_max_idle,
                    max_uses: runtime.reuse_max_uses,
                    idle_timeout: runtime.reuse_idle_timeout,
                    handshake_timeout: runtime.request_timeout,
                    close_timeout: Duration::from_secs(2),
                    dialer: dialer.into(),
                    dial_limit: Some(dial_limit.clone()),
                    dial_limit_timeout: runtime.request_timeout.max(Duration::from_secs(45)),
                })?;
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
            provider: provider.into(),
            clash_provider: clash_provider.into(),
            routing_secret: routing_secret.to_owned(),
        })
    }

    pub fn provider(&self) -> Arc<[u8]> {
        self.provider.clone()
    }

    pub fn clash_provider(&self) -> Arc<[u8]> {
        self.clash_provider.clone()
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
    pub fn new(router: Router) -> Self {
        Self {
            router: RwLock::new(Some(Arc::new(router))),
        }
    }

    pub async fn authenticate(&self, selector: &str, secret: &str) -> Result<Route> {
        let router = self.router.read().await;
        router
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("gateway is closed"))?
            .authenticate(selector, secret)
    }

    pub async fn provider(&self) -> Result<Arc<[u8]>> {
        self.router
            .read()
            .await
            .as_ref()
            .map(|router| router.provider())
            .ok_or_else(|| anyhow::anyhow!("gateway unavailable"))
    }

    pub async fn clash_provider(&self) -> Result<Arc<[u8]>> {
        self.router
            .read()
            .await
            .as_ref()
            .map(|router| router.clash_provider())
            .ok_or_else(|| anyhow::anyhow!("gateway unavailable"))
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
