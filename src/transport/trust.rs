use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use rustls::RootCertStore;
use tokio::sync::Mutex;

const RELOAD_INTERVAL: Duration = Duration::from_secs(30);

pub(super) struct LoadedRoots {
    roots: RootCertStore,
    complete: bool,
}

#[derive(Clone)]
pub(super) struct TrustSnapshot {
    pub roots: Arc<RootCertStore>,
    pub generation: u64,
}

struct State {
    snapshot: TrustSnapshot,
    complete: bool,
    last_attempt: Option<Instant>,
}

/// Shared across nodes. A failed or partial reload never replaces a usable store.
pub(super) struct TrustStore {
    state: Arc<Mutex<State>>,
    loader: fn() -> LoadedRoots,
}

impl TrustStore {
    pub fn new() -> Result<Self> {
        Self::with_loader(load_native)
    }

    fn with_loader(loader: fn() -> LoadedRoots) -> Result<Self> {
        let loaded = loader();
        if loaded.roots.is_empty() {
            bail!("no usable system TLS roots; see tls.roots diagnostics");
        }
        Ok(Self {
            state: Arc::new(Mutex::new(State {
                snapshot: TrustSnapshot {
                    roots: Arc::new(loaded.roots),
                    generation: 1,
                },
                complete: loaded.complete,
                last_attempt: None,
            })),
            loader,
        })
    }

    pub async fn snapshot(&self) -> TrustSnapshot {
        let state = self.state.lock().await;
        let snapshot = state.snapshot.clone();
        let incomplete = !state.complete;
        drop(state);
        if incomplete {
            self.refresh(snapshot.generation).await
        } else {
            snapshot
        }
    }

    pub async fn refresh(&self, observed_generation: u64) -> TrustSnapshot {
        let mut state = self.state.clone().lock_owned().await;
        if state.snapshot.generation != observed_generation
            || state
                .last_attempt
                .is_some_and(|last| last.elapsed() < RELOAD_INTERVAL)
        {
            return state.snapshot.clone();
        }
        state.last_attempt = Some(Instant::now());
        eprintln!(
            "tls.roots reload requested count={} generation={}",
            state.snapshot.roots.len(),
            state.snapshot.generation
        );
        let fallback = state.snapshot.clone();
        let loader = self.loader;
        // The worker owns the lock: even when a dial times out, its reload finishes
        // and other nodes cannot start duplicate keychain scans.
        tokio::task::spawn_blocking(move || {
            let loaded = loader();
            if loaded.complete && !loaded.roots.is_empty() {
                if state.snapshot.roots.roots != loaded.roots.roots {
                    state.snapshot = TrustSnapshot {
                        roots: Arc::new(loaded.roots),
                        generation: state.snapshot.generation + 1,
                    };
                    eprintln!(
                        "tls.roots refreshed count={} generation={}",
                        state.snapshot.roots.len(),
                        state.snapshot.generation
                    );
                }
                state.complete = true;
            } else {
                eprintln!(
                    "tls.roots reload incomplete; retained count={}",
                    state.snapshot.roots.len()
                );
            }
            state.snapshot.clone()
        })
        .await
        .unwrap_or(fallback)
    }

    #[cfg(test)]
    pub(super) async fn replace_for_test(&self, roots: RootCertStore) {
        let mut state = self.state.lock().await;
        state.snapshot.roots = Arc::new(roots);
    }
}

fn load_native() -> LoadedRoots {
    let mut native = rustls_native_certs::load_native_certs();
    let load_errors = native.errors.len();
    for error in &native.errors {
        eprintln!("tls.roots load error: {error}");
    }
    let mut roots = RootCertStore::empty();
    // macOS native loading uses a HashMap; iteration order must not cause a
    // spurious generation change when the actual trust set is unchanged.
    native.certs.sort_by(|a, b| a.as_ref().cmp(b.as_ref()));
    let (accepted, rejected) = roots.add_parsable_certificates(native.certs);
    eprintln!("tls.roots loaded count={accepted} rejected={rejected} load_errors={load_errors}");
    LoadedRoots {
        roots,
        complete: load_errors == 0 && rejected == 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{Der, TrustAnchor};

    fn roots(count: usize, complete: bool) -> LoadedRoots {
        LoadedRoots {
            roots: RootCertStore {
                roots: (0..count)
                    .map(|_| TrustAnchor {
                        subject: Der::from(vec![1]),
                        subject_public_key_info: Der::from(vec![2]),
                        name_constraints: None,
                    })
                    .collect(),
            },
            complete,
        }
    }

    #[tokio::test]
    async fn recovers_partial_store_and_coalesces_concurrent_failures() {
        let store = TrustStore::with_loader(|| roots(5, false)).unwrap();
        let store = TrustStore {
            loader: || roots(162, true),
            ..store
        };
        let (a, b) = tokio::join!(store.refresh(1), store.refresh(1));
        assert_eq!(a.roots.len(), 162);
        assert_eq!(a.generation, 2);
        assert_eq!(b.generation, 2);
        assert!(Arc::ptr_eq(&a.roots, &b.roots));
        assert_eq!(store.snapshot().await.generation, 2);
    }

    #[tokio::test]
    async fn partial_reload_retains_store_and_is_rate_limited() {
        let store = TrustStore::with_loader(|| roots(162, true)).unwrap();
        let mut store = TrustStore {
            loader: || roots(5, false),
            ..store
        };
        assert_eq!(store.refresh(1).await.roots.len(), 162);
        store.loader = || panic!("must respect cooldown");
        assert_eq!(store.refresh(1).await.generation, 1);
    }

    #[tokio::test]
    async fn complete_reload_can_remove_trust_anchors() {
        let store = TrustStore::with_loader(|| roots(162, true)).unwrap();
        let store = TrustStore {
            loader: || roots(5, true),
            ..store
        };
        assert_eq!(store.refresh(1).await.roots.len(), 5);
    }

    #[test]
    fn empty_initial_store_is_rejected() {
        assert!(TrustStore::with_loader(|| roots(0, false)).is_err());
    }
}
