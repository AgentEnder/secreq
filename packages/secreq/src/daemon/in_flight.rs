//! Singleflight coordination for concurrent secret resolutions.
//!
//! ## Why
//!
//! When `scanner` fires N `gh pr view` calls in parallel, N wrap
//! processes arrive at the daemon almost simultaneously, each asking
//! for the same secret. Even with a populated cache, the *first*
//! batch lands with the cache empty — every thread independently
//! checks it, finds nothing, and independently invokes the provider.
//! That's N biometric prompts where one would do.
//!
//! [`InFlightMap`] closes the gap between "I observed a cache miss"
//! and "I populated the cache." The first thread per cache key wins
//! the right to resolve; later threads asking for the same key park
//! on a [`Condvar`] until the resolver finishes, then re-check the
//! cache.
//!
//! ## Failure semantics
//!
//! - **Resolver succeeds**: waiters wake with [`Acquired::Ready`] and
//!   re-read the (now-populated) cache.
//! - **Resolver fails**: waiters wake with [`Acquired::Failed`]
//!   carrying the resolver's error string. They propagate the
//!   failure instead of silently retrying, because retrying a
//!   provider that just failed is almost always wasted effort (and
//!   in the biometric case, would re-prompt the user immediately —
//!   exactly the noise we're trying to eliminate).
//! - **A new ask arriving _after_ the resolver dropped its guard**
//!   sees no slot and starts fresh — i.e. transient failures get a
//!   real retry on the next caller, just not from the parked
//!   waiters from the original race.
//!
//! ## Lifetime
//!
//! Slots are removed from the map the moment the resolver drops its
//! guard, so the map size is bounded by "currently in-flight keys"
//! — not by lifetime cardinality. No cleanup task needed.

use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex};

use super::cache::CacheKey;

/// The coordinator. Cheap to clone (it's just an `Arc` wrapper) —
/// pass clones to every thread that resolves secrets.
#[derive(Default)]
pub struct InFlightMap {
    inner: Mutex<HashMap<CacheKey, Arc<Slot>>>,
}

struct Slot {
    state: Mutex<SlotState>,
    cv: Condvar,
}

enum SlotState {
    /// Resolver hasn't finished yet.
    Pending,
    /// Resolver succeeded; the cache should now contain the value.
    Ready,
    /// Resolver failed. Waiters propagate the message instead of
    /// re-trying.
    Failed(String),
}

/// Outcome of [`InFlightMap::acquire`].
pub enum Acquired {
    /// You are the resolver. Run the provider, populate the cache,
    /// then call [`InFlightGuard::mark_ready`]. Dropping the guard
    /// without `mark_ready` (or via panic) wakes waiters with a
    /// generic failure message; call [`InFlightGuard::mark_failed`]
    /// to give them a real error string.
    Resolver(InFlightGuard),
    /// A previous resolver finished successfully. Re-check the
    /// cache; the value should be there.
    Ready,
    /// A previous resolver failed with this error. Propagate it
    /// rather than retrying.
    Failed(String),
}

impl InFlightMap {
    /// Construct an empty map wrapped in `Arc` (the usual way to
    /// share it). The bare `new()` exists for tests; production
    /// callers want the `Arc` so they can hand clones to worker
    /// threads.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Either become the resolver for `key`, or wait for an existing
    /// resolver to finish.
    ///
    /// Takes `self: &Arc<Self>` so the returned guard can keep the
    /// map alive long enough to remove its own slot on drop.
    pub fn acquire(self: &Arc<Self>, key: &CacheKey) -> Acquired {
        let mut map = self.inner.lock().expect("in-flight map mutex");
        if let Some(slot) = map.get(key).cloned() {
            // Drop the map lock before parking; otherwise we'd block
            // every other key's acquire path while we wait.
            drop(map);
            let mut state = slot.state.lock().expect("slot state mutex");
            while matches!(*state, SlotState::Pending) {
                state = slot.cv.wait(state).expect("condvar wait");
            }
            match &*state {
                SlotState::Ready => Acquired::Ready,
                SlotState::Failed(msg) => Acquired::Failed(msg.clone()),
                SlotState::Pending => unreachable!("loop exited on non-Pending"),
            }
        } else {
            let slot = Arc::new(Slot {
                state: Mutex::new(SlotState::Pending),
                cv: Condvar::new(),
            });
            map.insert(key.clone(), slot.clone());
            // Drop the map lock before returning so the resolver
            // doesn't hold it through the (slow) provider call.
            drop(map);
            Acquired::Resolver(InFlightGuard {
                slot,
                key: key.clone(),
                map: Arc::clone(self),
                final_state: None,
            })
        }
    }
}

/// RAII handle for a resolver. Call [`Self::mark_ready`] on success
/// or [`Self::mark_failed`] on failure; if the guard drops without
/// either (e.g. on panic), waiters get a generic failure.
pub struct InFlightGuard {
    slot: Arc<Slot>,
    key: CacheKey,
    map: Arc<InFlightMap>,
    /// Set explicitly via `mark_ready`/`mark_failed`. `Drop` reads
    /// this; absence ⇒ panic / forgotten-call path.
    final_state: Option<SlotState>,
}

impl InFlightGuard {
    /// Resolver succeeded and populated the cache. Waiters wake with
    /// [`Acquired::Ready`].
    pub fn mark_ready(mut self) {
        self.final_state = Some(SlotState::Ready);
        // Drop runs.
    }

    /// Resolver failed with `msg`. Waiters wake with
    /// [`Acquired::Failed(msg)`] and propagate the error.
    pub fn mark_failed(mut self, msg: String) {
        self.final_state = Some(SlotState::Failed(msg));
        // Drop runs.
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        // Remove from the map first. Doing this before the notify
        // means a thread arriving in the post-notify window sees no
        // slot at all and starts fresh — i.e. a transient failure
        // doesn't poison future asks for the same key.
        {
            let mut map = self.map.inner.lock().expect("in-flight map mutex");
            map.remove(&self.key);
        }
        // Then publish the final state and wake waiters. Default is
        // a generic failure (handles panic / forgotten-call paths).
        let mut state = self.slot.state.lock().expect("slot state mutex");
        *state = self
            .final_state
            .take()
            .unwrap_or_else(|| SlotState::Failed("resolver did not signal completion".into()));
        self.slot.cv.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;
    use std::time::Duration;

    fn key(wrap: &str) -> CacheKey {
        CacheKey {
            wrap: wrap.to_owned(),
            provider: "op".to_owned(),
            locator: "x".to_owned(),
        }
    }

    #[test]
    fn concurrent_acquires_for_same_key_make_only_one_resolver() {
        // The whole point: N threads racing for the same secret
        // result in exactly 1 provider invocation, not N.
        let map = InFlightMap::new();
        let resolver_count = Arc::new(AtomicUsize::new(0));
        let waiter_count = Arc::new(AtomicUsize::new(0));

        let mut handles = vec![];
        for _ in 0..10 {
            let map = Arc::clone(&map);
            let resolver_count = Arc::clone(&resolver_count);
            let waiter_count = Arc::clone(&waiter_count);
            handles.push(thread::spawn(move || match map.acquire(&key("gh")) {
                Acquired::Resolver(g) => {
                    resolver_count.fetch_add(1, Ordering::SeqCst);
                    // Simulate provider latency so the other threads
                    // have time to pile up on the slot.
                    thread::sleep(Duration::from_millis(50));
                    g.mark_ready();
                }
                Acquired::Ready => {
                    waiter_count.fetch_add(1, Ordering::SeqCst);
                }
                Acquired::Failed(msg) => panic!("unexpected fail: {msg}"),
            }));
        }
        for h in handles {
            h.join().expect("thread");
        }
        assert_eq!(resolver_count.load(Ordering::SeqCst), 1);
        assert_eq!(waiter_count.load(Ordering::SeqCst), 9);
    }

    #[test]
    fn different_keys_do_not_block_each_other() {
        // Resolver for key "a" should not stall acquire for key "b".
        let map = InFlightMap::new();
        let map_b = Arc::clone(&map);
        let a_started = Arc::new(AtomicUsize::new(0));
        let a_started_clone = Arc::clone(&a_started);
        let a_thread = thread::spawn(move || {
            let Acquired::Resolver(g) = map.acquire(&key("a")) else {
                panic!("expected resolver")
            };
            a_started_clone.store(1, Ordering::SeqCst);
            // Hold the slot for long enough that the b-thread must
            // not be blocked on us.
            thread::sleep(Duration::from_millis(100));
            g.mark_ready();
        });

        // Wait until A is the resolver for "a".
        while a_started.load(Ordering::SeqCst) == 0 {
            thread::sleep(Duration::from_millis(1));
        }
        // Now acquire "b" — should return Resolver immediately, not
        // wait on A.
        let start = std::time::Instant::now();
        match map_b.acquire(&key("b")) {
            Acquired::Resolver(g) => g.mark_ready(),
            _ => panic!("expected resolver for b"),
        }
        assert!(
            start.elapsed() < Duration::from_millis(50),
            "acquire for distinct key blocked behind another key's resolver"
        );
        a_thread.join().expect("thread");
    }

    #[test]
    fn waiter_sees_resolver_failure_message() {
        let map = InFlightMap::new();
        let map_w = Arc::clone(&map);
        let resolver_started = Arc::new(AtomicUsize::new(0));
        let resolver_started_clone = Arc::clone(&resolver_started);
        let r_thread = thread::spawn(move || {
            let Acquired::Resolver(g) = map.acquire(&key("gh")) else {
                panic!("expected resolver")
            };
            resolver_started_clone.store(1, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(20));
            g.mark_failed("op exited 1: vault locked".into());
        });

        while resolver_started.load(Ordering::SeqCst) == 0 {
            thread::sleep(Duration::from_millis(1));
        }
        match map_w.acquire(&key("gh")) {
            Acquired::Failed(msg) => assert!(msg.contains("vault locked"), "got: {msg}"),
            other => panic!(
                "expected Failed, got {:?}",
                match other {
                    Acquired::Resolver(_) => "Resolver",
                    Acquired::Ready => "Ready",
                    Acquired::Failed(_) => unreachable!(),
                }
            ),
        }
        r_thread.join().expect("thread");
    }

    #[test]
    fn new_acquire_after_failed_resolver_starts_fresh() {
        // A waiter from the failed batch sees Failed and propagates.
        // But the *next* caller — arriving after the resolver
        // dropped — should get a fresh shot at being the resolver.
        let map = InFlightMap::new();
        match map.acquire(&key("gh")) {
            Acquired::Resolver(g) => g.mark_failed("transient".into()),
            _ => panic!("expected resolver"),
        }
        // Slot should be gone; next acquire is a fresh Resolver.
        match map.acquire(&key("gh")) {
            Acquired::Resolver(g) => g.mark_ready(),
            Acquired::Failed(msg) => panic!("unexpected Failed: {msg}"),
            Acquired::Ready => panic!("unexpected Ready"),
        }
    }

    #[test]
    fn dropped_guard_without_mark_wakes_waiters_with_failure() {
        // A panicking resolver shouldn't leave waiters parked
        // forever. Drop without mark_ready/mark_failed propagates as
        // a generic failure.
        let map = InFlightMap::new();
        let map_w = Arc::clone(&map);
        let resolver_started = Arc::new(AtomicUsize::new(0));
        let resolver_started_clone = Arc::clone(&resolver_started);
        let r_thread = thread::spawn(move || {
            let Acquired::Resolver(g) = map.acquire(&key("gh")) else {
                panic!("expected resolver")
            };
            resolver_started_clone.store(1, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(20));
            drop(g); // simulated panic / forgotten call
        });
        while resolver_started.load(Ordering::SeqCst) == 0 {
            thread::sleep(Duration::from_millis(1));
        }
        match map_w.acquire(&key("gh")) {
            Acquired::Failed(_) => {}
            _ => panic!("expected Failed"),
        }
        r_thread.join().expect("thread");
    }
}
