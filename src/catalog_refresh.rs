use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use tokio::sync::Notify;
use tokio::time::Instant;

const COOLDOWN: Duration = Duration::from_secs(30);

/// Shared by periodic, ECH-triggered, manual and provider refresh requests.
#[derive(Default)]
pub(crate) struct RefreshBackoff {
    failures: u32,
    next: Option<Instant>,
    server_until: Option<Instant>,
}

impl RefreshBackoff {
    pub(crate) fn check(&self) -> anyhow::Result<()> {
        let now = Instant::now();
        if let Some(until) = self.next
            && until > now
        {
            return Err(crate::diagnostics::ApiFailure {
                kind: crate::diagnostics::ErrorKind::RateLimited,
                status: None,
                retry_after_seconds: Some(until.duration_since(now).as_secs().saturating_add(1)),
            }
            .into());
        }
        Ok(())
    }

    pub(crate) async fn wait(&self) {
        match self.next {
            Some(next) => tokio::time::sleep_until(next).await,
            None => std::future::pending().await,
        }
    }

    pub(crate) fn record(&mut self, error: Option<&anyhow::Error>) {
        let Some(error) = error else {
            *self = Self::default();
            return;
        };
        use crate::diagnostics::ErrorKind;
        if !matches!(
            crate::diagnostics::classify(error),
            ErrorKind::Network | ErrorKind::Timeout | ErrorKind::RateLimited | ErrorKind::Server
        ) {
            self.next = None;
            return;
        }
        self.failures = self.failures.saturating_add(1);
        let delay = Duration::from_secs((5u64 << self.failures.saturating_sub(1).min(6)).min(300));
        let now = Instant::now();
        let server = error
            .chain()
            .filter_map(|e| e.downcast_ref::<crate::diagnostics::ApiFailure>())
            .filter_map(|e| e.retry_after_seconds)
            .max();
        self.server_until = server.map(|seconds| {
            now.checked_add(Duration::from_secs(seconds))
                .unwrap_or(now + Duration::from_secs(365 * 86400))
        });
        self.next = Some((now + delay).max(self.server_until.unwrap_or(now)));
    }

    pub(crate) fn network_changed(&mut self) {
        self.failures = 0;
        self.next = self.server_until.filter(|until| *until > Instant::now());
    }
}

/// One pending wakeup across all nodes. The service loop owns the refresh,
/// so API calls never run in a dial task and cannot overlap each other.
#[derive(Default)]
pub struct CatalogRefresh {
    wakeup: Notify,
    last_request: Mutex<Option<Instant>>,
}

impl CatalogRefresh {
    pub fn request(&self) -> bool {
        let mut last = self
            .last_request
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if last.is_some_and(|time| time.elapsed() < COOLDOWN) {
            return false;
        }
        *last = Some(Instant::now());
        self.wakeup.notify_one();
        true
    }

    pub async fn notified(&self) {
        self.wakeup.notified().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn retries_respect_server_waits_across_network_changes_and_reset_on_success() {
        let mut policy = RefreshBackoff::default();
        let temporary = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::TimedOut));
        policy.record(Some(&temporary));
        assert!(policy.check().is_err());
        tokio::time::advance(Duration::from_secs(5)).await;
        assert!(policy.check().is_ok());
        policy.record(Some(&temporary));
        assert_eq!(
            policy.next.unwrap() - Instant::now(),
            Duration::from_secs(10)
        );
        let limited = crate::diagnostics::ApiFailure {
            kind: crate::diagnostics::ErrorKind::RateLimited,
            status: Some(429),
            retry_after_seconds: Some(120),
        }
        .into();
        policy.record(Some(&limited));
        policy.network_changed();
        assert_eq!(
            policy.next.unwrap() - Instant::now(),
            Duration::from_secs(120)
        );
        tokio::time::advance(Duration::from_secs(119)).await;
        assert!(policy.check().is_err());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(policy.check().is_ok());
        policy.record(None);
        assert!(policy.next.is_none());
        policy.record(Some(&temporary));
        policy.network_changed();
        assert!(policy.check().is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn failures_coalesce_and_respect_cooldown() {
        let refresh = CatalogRefresh::default();
        assert!(refresh.request());
        for _ in 0..100 {
            assert!(!refresh.request());
        }
        refresh.notified().await;
        assert!(
            tokio::time::timeout(Duration::from_secs(1), refresh.notified())
                .await
                .is_err()
        );
        tokio::time::advance(COOLDOWN).await;
        assert!(refresh.request());
        refresh.notified().await;
    }
}
