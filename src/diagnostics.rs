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
}

#[derive(Default)]
pub struct NodeDiagnostics(Mutex<NodeState>);

impl NodeDiagnostics {
    pub fn record(&self, result: Result<(), &anyhow::Error>, timings: DialTimings) {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
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
            "successful_latency_ms":{"samples":samples.len(),"p50":percentile(50),"p95":percentile(95)}})
    }
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
