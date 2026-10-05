use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use tokio::sync::Notify;
use tokio::time::Instant;

const COOLDOWN: Duration = Duration::from_secs(30);

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
