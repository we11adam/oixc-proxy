use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use rustls::RootCertStore;
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};
use tokio::task::JoinHandle;

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
    /// No background reload is needed: the last load was complete, or a
    /// reload produced the same roots so the platform store is stable.
    settled: bool,
}

/// Shared across nodes. A failed or partial reload never replaces a usable store.
pub(super) struct TrustStore {
    state: Arc<Mutex<State>>,
    /// Held for the duration of a reload; stores when the last one started.
    reload: Arc<AsyncMutex<Option<Instant>>>,
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
                settled: loaded.complete,
            })),
            reload: Arc::new(AsyncMutex::new(None)),
            loader,
        })
    }

    /// Returns the current roots without waiting. An unsettled store starts a
    /// background reload, so a slow keychain scan never delays other dials.
    pub async fn snapshot(&self) -> TrustSnapshot {
        let (snapshot, settled) = {
            let state = lock(&self.state);
            (state.snapshot.clone(), state.settled)
        };
        if !settled {
            if let Ok(last_attempt) = self.reload.clone().try_lock_owned() {
                if !cooling_down(&last_attempt) {
                    drop(self.start_reload(last_attempt));
                }
            }
        }
        snapshot
    }

    /// Reloads after `observed_generation` failed verification, waiting for
    /// the result. Concurrent callers share a single reload.
    pub async fn refresh(&self, observed_generation: u64) -> TrustSnapshot {
        let last_attempt = self.reload.clone().lock_owned().await;
        let current = lock(&self.state).snapshot.clone();
        if current.generation != observed_generation || cooling_down(&last_attempt) {
            return current;
        }
        self.start_reload(last_attempt).await.unwrap_or(current)
    }

    fn start_reload(
        &self,
        mut last_attempt: OwnedMutexGuard<Option<Instant>>,
    ) -> JoinHandle<TrustSnapshot> {
        *last_attempt = Some(Instant::now());
        let state = self.state.clone();
        let loader = self.loader;
        {
            let state = lock(&state);
            eprintln!(
                "tls.roots reload requested count={} generation={}",
                state.snapshot.roots.len(),
                state.snapshot.generation
            );
        }
        // The worker owns the reload lock: even when a dial times out, its reload
        // finishes and other nodes cannot start duplicate keychain scans.
        tokio::task::spawn_blocking(move || {
            let _last_attempt = last_attempt;
            let loaded = loader();
            apply_reload(&mut lock(&state), loaded)
        })
    }

    #[cfg(test)]
    pub(super) async fn replace_for_test(&self, roots: RootCertStore) {
        lock(&self.state).snapshot.roots = Arc::new(roots);
    }
}

fn lock(state: &Mutex<State>) -> std::sync::MutexGuard<'_, State> {
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

fn cooling_down(last_attempt: &Option<Instant>) -> bool {
    last_attempt.is_some_and(|last| last.elapsed() < RELOAD_INTERVAL)
}

fn apply_reload(state: &mut State, loaded: LoadedRoots) -> TrustSnapshot {
    let current = &state.snapshot.roots.roots;
    let unchanged = loaded.roots.roots == *current;
    // A partial load can still add anchors; it must not remove any.
    let usable = !loaded.roots.is_empty()
        && (loaded.complete
            || (loaded.roots.len() > current.len()
                && current.iter().all(|root| loaded.roots.roots.contains(root))));
    if unchanged {
        state.settled = true;
    } else if usable {
        state.snapshot = TrustSnapshot {
            roots: Arc::new(loaded.roots),
            generation: state.snapshot.generation + 1,
        };
        state.settled = loaded.complete;
        eprintln!(
            "tls.roots refreshed count={} generation={}",
            state.snapshot.roots.len(),
            state.snapshot.generation
        );
    } else {
        eprintln!(
            "tls.roots reload incomplete; retained count={}",
            state.snapshot.roots.len()
        );
    }
    state.snapshot.clone()
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
                    .map(|index| TrustAnchor {
                        subject: Der::from(vec![index as u8]),
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

    #[tokio::test]
    async fn snapshot_does_not_wait_for_background_reload() {
        let store = TrustStore::with_loader(|| roots(5, false)).unwrap();
        let store = TrustStore {
            loader: || {
                std::thread::sleep(Duration::from_millis(300));
                roots(162, true)
            },
            ..store
        };
        let snapshot = tokio::time::timeout(Duration::from_millis(100), store.snapshot())
            .await
            .expect("snapshot must not wait for the keychain scan");
        assert_eq!(snapshot.generation, 1);
        let snapshot = tokio::time::timeout(Duration::from_millis(100), store.snapshot())
            .await
            .unwrap();
        assert_eq!(snapshot.generation, 1);
        // A verification failure waits for the reload already in flight.
        assert_eq!(store.refresh(1).await.roots.len(), 162);
        assert_eq!(store.snapshot().await.generation, 2);
    }

    fn state(count: usize) -> State {
        State {
            snapshot: TrustSnapshot {
                roots: Arc::new(roots(count, false).roots),
                generation: 1,
            },
            settled: false,
        }
    }

    #[test]
    fn partial_reloads_only_add_roots_and_settle_when_stable() {
        let mut current = state(5);
        assert_eq!(apply_reload(&mut current, roots(5, false)).generation, 1);
        assert!(
            current.settled,
            "a stable partial store must stop rescanning"
        );

        let mut current = state(5);
        let grown = apply_reload(&mut current, roots(8, false));
        assert_eq!((grown.generation, grown.roots.len()), (2, 8));
        assert!(!current.settled);

        let mut current = state(5);
        let shrunk = apply_reload(&mut current, roots(3, false));
        assert_eq!((shrunk.generation, shrunk.roots.len()), (1, 5));
        assert!(!current.settled);
    }
}
