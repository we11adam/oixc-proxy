use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::sync::{Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    Timeout,
    Network,
    Authentication,
    Forbidden,
    ProxyAuthentication,
    RateLimited,
    Server,
    InvalidResponse,
    Signature,
    TlsUnknownIssuer,
    TlsCertificate,
    EchRejected,
    Other,
}

/// Sanitized control-plane failure. Never expose remote error bodies.
#[derive(Debug, thiserror::Error)]
#[error("API failure: {kind:?} (HTTP {status:?}, retry after {retry_after_seconds:?} seconds)")]
pub struct ApiFailure {
    pub kind: ErrorKind,
    pub status: Option<u16>,
    pub retry_after_seconds: Option<u64>,
}

pub fn http_error_kind(status: u16) -> ErrorKind {
    match status {
        401 => ErrorKind::Authentication,
        403 => ErrorKind::Forbidden,
        407 => ErrorKind::ProxyAuthentication,
        429 => ErrorKind::RateLimited,
        500..=599 => ErrorKind::Server,
        _ => ErrorKind::InvalidResponse,
    }
}

pub fn classify(error: &anyhow::Error) -> ErrorKind {
    for cause in error.chain() {
        if let Some(api) = cause.downcast_ref::<ApiFailure>() {
            return api.kind;
        }
        let tls = cause.downcast_ref::<rustls::Error>().or_else(|| {
            cause
                .downcast_ref::<io::Error>()?
                .get_ref()?
                .downcast_ref::<rustls::Error>()
        });
        match tls {
            Some(rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)) => {
                return ErrorKind::TlsUnknownIssuer;
            }
            Some(rustls::Error::InvalidCertificate(_)) => return ErrorKind::TlsCertificate,
            Some(rustls::Error::PeerIncompatible(
                rustls::PeerIncompatible::ServerRejectedEncryptedClientHello(_),
            )) => return ErrorKind::EchRejected,
            _ => {}
        }
    }
    // reqwest wraps TLS failures as connection errors. Look for a more specific
    // certificate/ECH cause first, so these cannot trigger API fallback.
    for cause in error.chain() {
        if let Some(http) = cause.downcast_ref::<reqwest::Error>() {
            if http.is_timeout() {
                return ErrorKind::Timeout;
            }
            if http.is_connect() || http.is_body() {
                return ErrorKind::Network;
            }
        }
        if let Some(io) = cause.downcast_ref::<io::Error>() {
            match io.kind() {
                io::ErrorKind::TimedOut => return ErrorKind::Timeout,
                io::ErrorKind::ConnectionRefused
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::NotConnected
                | io::ErrorKind::AddrNotAvailable
                | io::ErrorKind::UnexpectedEof => return ErrorKind::Network,
                _ => {}
            }
        }
    }
    ErrorKind::Other
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Default, Clone, Serialize)]
pub struct DialSnapshot {
    pub succeeded: u64,
    pub failed: u64,
    pub failures_by_kind: BTreeMap<ErrorKind, u64>,
    pub last_error: Option<ErrorKind>,
    pub last_success_at: Option<u64>,
    pub last_failure_at: Option<u64>,
}

#[derive(Default)]
pub struct DialDiagnostics(Mutex<DialSnapshot>);

impl DialDiagnostics {
    pub fn record(&self, result: Result<(), &anyhow::Error>) {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        match result {
            Ok(()) => {
                state.succeeded += 1;
                state.last_success_at = Some(unix_now());
            }
            Err(error) => {
                let kind = classify(error);
                state.failed += 1;
                *state.failures_by_kind.entry(kind).or_default() += 1;
                state.last_error = Some(kind);
                state.last_failure_at = Some(unix_now());
            }
        }
    }

    pub fn snapshot(&self) -> DialSnapshot {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[derive(Default, Clone, Serialize)]
pub struct CatalogStatus {
    pub started_from_cache: bool,
    pub last_attempt_at: Option<u64>,
    pub last_success_at: Option<u64>,
    pub last_error: Option<ErrorKind>,
    pub refresh_failures: u64,
    pub cache_age_seconds: Option<u64>,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DialStage {
    Dns,
    Tcp,
    Tls,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct DialTimings {
    pub dns_ms: Option<u64>,
    pub tcp_ms: Option<u64>,
    pub tls_ms: Option<u64>,
    pub total_ms: u64,
    #[serde(skip)]
    pub last_stage: Option<DialStage>,
    #[serde(skip)]
    active: Option<(DialStage, std::time::Instant)>,
}

impl DialTimings {
    pub fn start(&mut self, stage: DialStage) {
        self.finish();
        self.last_stage = Some(stage);
        self.active = Some((stage, std::time::Instant::now()));
    }
    pub fn finish(&mut self) {
        if let Some((stage, started)) = self.active.take() {
            let slot = match stage {
                DialStage::Dns => &mut self.dns_ms,
                DialStage::Tcp => &mut self.tcp_ms,
                DialStage::Tls => &mut self.tls_ms,
            };
            *slot =
                Some(slot.unwrap_or(0).saturating_add(
                    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                ));
        }
    }
}

#[derive(Default)]
struct NodeState {
    dials: DialSnapshot,
    consecutive_failures: u64,
    last_timings: Option<DialTimings>,
    last_failure_stage: Option<DialStage>,
    samples: VecDeque<u64>,
    events: VecDeque<DialEvent>,
}

#[derive(Serialize)]
struct DialEvent {
    at: u64,
    error: Option<ErrorKind>,
    stage: Option<DialStage>,
}

#[derive(Default)]
pub struct NodeDiagnostics(Mutex<NodeState>);

impl NodeDiagnostics {
    pub fn record(&self, result: Result<(), &anyhow::Error>, timings: DialTimings) {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if state.events.len() == 16 {
            state.events.pop_front();
        }
        state.events.push_back(DialEvent {
            at: unix_now(),
            error: result.as_ref().err().map(|error| classify(error)),
            stage: if result.is_err() {
                timings.last_stage
            } else {
                None
            },
        });
        match result {
            Ok(()) => {
                state.dials.succeeded += 1;
                state.dials.last_success_at = Some(unix_now());
                state.consecutive_failures = 0;
                if state.samples.len() == 64 {
                    state.samples.pop_front();
                }
                state.samples.push_back(timings.total_ms);
            }
            Err(error) => {
                let kind = classify(error);
                state.dials.failed += 1;
                state.dials.last_failure_at = Some(unix_now());
                state.dials.last_error = Some(kind);
                *state.dials.failures_by_kind.entry(kind).or_default() += 1;
                state.consecutive_failures += 1;
                state.last_failure_stage = timings.last_stage;
            }
        }
        state.last_timings = Some(timings);
    }

    pub fn snapshot(&self) -> serde_json::Value {
        let state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let mut samples: Vec<_> = state.samples.iter().copied().collect();
        samples.sort_unstable();
        let percentile = |percent: usize| {
            samples
                .get((samples.len() * percent).div_ceil(100).saturating_sub(1))
                .copied()
        };
        let health = if state.consecutive_failures > 0 {
            "degraded"
        } else if state.dials.succeeded > 0 {
            "healthy"
        } else {
            "unobserved"
        };
        serde_json::json!({"health":health, "ech_dials":state.dials,
            "consecutive_failures":state.consecutive_failures, "last_timings":state.last_timings,
            "last_failure_stage":state.last_failure_stage,
            "successful_latency_ms":{"samples":samples.len(),"p50":percentile(50),"p95":percentile(95)},
            "recent_events":state.events})
    }
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    CatalogRefresh,
    ConfigReload,
}

#[derive(Serialize)]
struct ServiceEvent {
    at: u64,
    kind: EventKind,
    error: Option<ErrorKind>,
}

pub struct EventLog {
    started_at: u64,
    events: Mutex<VecDeque<ServiceEvent>>,
}

impl Default for EventLog {
    fn default() -> Self {
        Self {
            started_at: unix_now(),
            events: Mutex::new(VecDeque::new()),
        }
    }
}

impl EventLog {
    pub fn record(&self, kind: EventKind, error: Option<&anyhow::Error>) {
        let mut events = self.events.lock().unwrap_or_else(PoisonError::into_inner);
        if events.len() == 128 {
            events.pop_front();
        }
        events.push_back(ServiceEvent {
            at: unix_now(),
            kind,
            error: error.map(classify),
        });
    }
    pub fn snapshot(&self) -> serde_json::Value {
        let events = self.events.lock().unwrap_or_else(PoisonError::into_inner);
        serde_json::json!({"started_at":self.started_at,
            "uptime_seconds":unix_now().saturating_sub(self.started_at), "recent_events":*events})
    }
}

/// Positive field selection: new status fields must opt into bundle export.
fn select_fields(value: &serde_json::Value, keys: &[&str]) -> serde_json::Value {
    serde_json::Value::Object(
        keys.iter()
            .filter_map(|key| value.get(*key).map(|v| ((*key).to_owned(), v.clone())))
            .collect(),
    )
}

pub fn bundle_status(status: &serde_json::Value) -> serde_json::Value {
    let mut safe = select_fields(status, &["ready", "total_nodes", "published_nodes"]);
    safe["catalog"] = select_fields(
        &status["catalog"],
        &[
            "started_from_cache",
            "last_attempt_at",
            "last_success_at",
            "last_error",
            "refresh_failures",
            "cache_age_seconds",
        ],
    );
    const DIAL_KEYS: &[&str] = &[
        "succeeded",
        "failed",
        "failures_by_kind",
        "last_error",
        "last_success_at",
        "last_failure_at",
    ];
    safe["transport"] = serde_json::json!({
        "network":select_fields(&status["transport"]["network"], &["generation", "mode"]),
        "tls_roots":select_fields(&status["transport"]["tls_roots"], &["count", "generation", "last_load_complete", "auto_reload_pending"]),
        "ech_dials":select_fields(&status["transport"]["ech_dials"], DIAL_KEYS),
    });
    safe["nodes"] = serde_json::Value::Array(
        status["nodes"]
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
            .map(|(index, node)| {
                let transport = &node["transport"];
                let mut data = select_fields(
                    transport,
                    &["health", "consecutive_failures", "last_failure_stage"],
                );
                data["ech_dials"] = select_fields(&transport["ech_dials"], DIAL_KEYS);
                data["last_timings"] = if transport["last_timings"].is_null() {
                    serde_json::Value::Null
                } else {
                    select_fields(
                        &transport["last_timings"],
                        &["dns_ms", "tcp_ms", "tls_ms", "total_ms"],
                    )
                };
                data["successful_latency_ms"] = select_fields(
                    &transport["successful_latency_ms"],
                    &["samples", "p50", "p95"],
                );
                data["recent_events"] = serde_json::Value::Array(
                    transport["recent_events"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .map(|event| select_fields(event, &["at", "error", "stage"]))
                        .collect(),
                );
                serde_json::json!({"id":format!("node-{}",index+1),"transport":data})
            })
            .collect(),
    );
    safe
}

pub fn config_summary(
    config: &crate::config::ProxyConfig,
    disable_filter: bool,
) -> serde_json::Value {
    let runtime = &config.runtime;
    serde_json::json!({
        "remote_listener":!config.listen.ip().is_loopback(),
        "pinned_egress":!config.outbound_ip.is_loopback(),
        "fixed_udp_port_count":config.udp_port_range.map(|range| range.port_count()),
        "api_fallback_count":runtime.api_fallback_urls.len(),
        "filter":if disable_filter { "disabled" } else if runtime.node_filter.is_custom() { "custom" } else { "default" },
        "request_timeout_ms":runtime.request_timeout.as_millis(),
        "tcp_idle_timeout_ms":runtime.tcp_idle_timeout.as_millis(),
        "udp_idle_timeout_ms":runtime.udp_idle_timeout.as_millis(),
        "node_refresh_interval_ms":config.node_refresh_interval.as_millis(),
        "max_client_connections":runtime.max_client_connections,
        "dial_concurrency":runtime.dial_concurrency,
        "per_node_dial_concurrency":runtime.per_node_dial_concurrency,
        "reuse_max_idle":runtime.reuse_max_idle,"reuse_max_uses":runtime.reuse_max_uses,
        "reuse_idle_timeout_ms":runtime.reuse_idle_timeout.as_millis(),
        "perf_trace_sample_every":runtime.perf_trace_sample_every,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn node_health_recovers_and_latency_window_is_bounded() {
        let stats = NodeDiagnostics::default();
        assert_eq!(stats.snapshot()["health"], "unobserved");
        assert!(stats.snapshot()["successful_latency_ms"]["p50"].is_null());
        let error = anyhow::Error::new(io::Error::from(io::ErrorKind::TimedOut));
        let mut timings = DialTimings::default();
        timings.start(DialStage::Tcp);
        timings.finish();
        stats.record(Err(&error), timings);
        assert_eq!(stats.snapshot()["health"], "degraded");
        assert_eq!(stats.snapshot()["last_failure_stage"], "tcp");
        for total_ms in 1..=100 {
            stats.record(
                Ok(()),
                DialTimings {
                    total_ms,
                    ..Default::default()
                },
            );
        }
        let value = stats.snapshot();
        assert_eq!(value["health"], "healthy");
        assert_eq!(value["consecutive_failures"], 0);
        assert_eq!(value["ech_dials"]["failed"], 1);
        assert_eq!(value["successful_latency_ms"]["samples"], 64);
        assert_eq!(value["successful_latency_ms"]["p50"], 68);
        assert_eq!(value["successful_latency_ms"]["p95"], 97);
        assert_eq!(value["recent_events"].as_array().unwrap().len(), 16);
    }

    #[test]
    fn bundle_uses_an_allowlist_and_events_never_store_error_text() {
        let secret = "SECRET_TOKEN_HOST_PATH_NODE";
        let status = serde_json::json!({"ready":true,"token":secret,
            "catalog":{"refresh_failures":1,"raw_error":secret},
            "transport":{"network":{"generation":"3","mode":"automatic","ipv4":secret,"interface":secret},
                "tls_roots":{"count":42,"path":secret},"ech_dials":{"failed":1,"extra":secret}},
            "nodes":[{"name":secret,"server":secret,"transport":{"health":"degraded",
                "last_timings":{"total_ms":10,"address":secret},"psk":secret,
                "recent_events":[{"at":1,"error":"timeout","stage":"tcp","message":secret}]}}]});
        let bundle = bundle_status(&status);
        assert!(!bundle.to_string().contains(secret));
        assert_eq!(bundle["nodes"][0]["id"], "node-1");
        assert_eq!(bundle["transport"]["tls_roots"]["count"], 42);
        assert_eq!(
            bundle["nodes"][0]["transport"]["recent_events"][0]["error"],
            "timeout"
        );
        let events = EventLog::default();
        let error = anyhow::anyhow!("{secret}");
        for _ in 0..200 {
            events.record(EventKind::ConfigReload, Some(&error));
        }
        let snapshot = events.snapshot();
        assert_eq!(snapshot["recent_events"].as_array().unwrap().len(), 128);
        assert!(!snapshot.to_string().contains(secret));
        assert_eq!(snapshot["recent_events"][0]["kind"], "config_reload");
    }

    #[test]
    fn categorizes_http_and_tls_without_publishing_error_text() {
        for (status, kind) in [
            (401, ErrorKind::Authentication),
            (403, ErrorKind::Forbidden),
            (407, ErrorKind::ProxyAuthentication),
            (429, ErrorKind::RateLimited),
        ] {
            assert_eq!(http_error_kind(status), kind);
        }
        let error = anyhow::Error::new(io::Error::other(rustls::Error::InvalidCertificate(
            rustls::CertificateError::UnknownIssuer,
        )))
        .context("private upstream");
        let stats = DialDiagnostics::default();
        stats.record(Err(&error));
        stats.record(Ok(()));
        let value = serde_json::to_string(&stats.snapshot()).unwrap();
        assert!(value.contains("tls_unknown_issuer"));
        assert!(!value.contains("private upstream"));
        assert_eq!(
            (stats.snapshot().failed, stats.snapshot().succeeded),
            (1, 1)
        );
    }
}
