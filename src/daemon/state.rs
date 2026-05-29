//! Daemon-side state: pending queue + persisted approvals cache.
//!
//! Threading model:
//! - The socket accept loop calls [`State::submit_ask`] from worker threads
//!   (one per client connection).
//! - The egui main thread reads the queue snapshot via [`State::snapshot`]
//!   and resolves entries via [`State::resolve`].
//! - Both sides synchronize through the inner `Mutex`. Repaints are nudged
//!   via the egui `Context` handle passed in at startup.
//!
//! The "wait for decision" side of an ask is implemented with a per-ask
//! `mpsc` channel used as one-shot. The accept thread parks on the
//! receiver; the UI thread sends through the sender when the user decides
//! (or when resolution fails after approval).

use std::collections::HashMap;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::consent::{ApprovalEntry, Decision};
use crate::manifest::{BatchRetrieve, Manifest, Provider};
use crate::resolve::{self, ResolutionPlan, SecretRequest, Source};

use super::cache::{CacheKey, SecretCache};
use super::proto::{Ask, DedupeKey, WireProvider};

/// One coalesced queue entry. Multiple clients with the same dedupe key
/// share a single entry; resolving it sends the same outcome to every
/// waiter — one provider invocation per approved batch, not N.
pub struct QueueEntry {
    pub key: DedupeKey,
    /// The first ask we saw for this key. Provides the metadata the UI
    /// renders *and* the provider definitions used to resolve. Later asks
    /// with the same key are assumed to be equivalent (same wrap, same
    /// providers); we keep their reply channels but not their Asks.
    pub representative: Ask,
    /// Senders, one per still-waiting client.
    pub waiters: Vec<mpsc::Sender<WaiterReply>>,
    /// When this entry was first inserted — drives the UI's "Xs ago" label.
    pub first_seen: Instant,
}

impl QueueEntry {
    pub fn waiter_count(&self) -> usize {
        self.waiters.len()
    }
}

/// What the connection thread is parked on. On approval the daemon runs
/// resolution once and broadcasts the resulting map to all waiters; on
/// deny it broadcasts `Deny` with an empty map; on resolution failure it
/// broadcasts `Err` so the client surfaces a real error rather than
/// silently exiting 1.
#[derive(Debug, Clone)]
pub enum WaiterReply {
    Decision {
        decision: Decision,
        secrets: HashMap<String, String>,
    },
    Err {
        message: String,
    },
}

/// Snapshot of the queue for the UI. Cheap to clone: only metadata, no
/// senders or live state.
#[derive(Debug, Clone)]
pub struct QueueSnapshot {
    pub entries: Vec<QueueRow>,
}

#[derive(Debug, Clone)]
pub struct QueueRow {
    pub key: DedupeKey,
    pub representative: Ask,
    pub waiter_count: usize,
    pub first_seen: Instant,
}

/// Daemon state. Wrap in `Arc<Mutex<_>>` for sharing.
pub struct State {
    queue: HashMap<DedupeKey, QueueEntry>,
    /// "Approve all from X" decisions for the daemon's lifetime. No disk
    /// backing — `secreq daemon stop` is the canonical reset.
    approvals: Vec<ApprovalEntry>,
    /// Encrypted in-memory cache of resolved secret values. Wrapped in
    /// its own `Arc<Mutex>` so worker threads can pull from / push to
    /// it without holding the outer `State` mutex (which the UI thread
    /// is contending for).
    secret_cache: Arc<Mutex<SecretCache>>,
    last_activity: Instant,
    egui_ctx: Option<egui::Context>,
    window_visible: bool,
    /// "Pinned" mode set by `ClientMsg::ShowViewer` (the `secreq view`
    /// command). While true, the UI suppresses its empty-queue
    /// auto-hide so the user can browse the audit log. Cleared on any
    /// hide so a subsequent `secreq pending` from a different terminal
    /// doesn't inherit the pin.
    viewer_mode: bool,
    /// Set by the socket thread on `ClientMsg::Shutdown` (or by the UI
    /// thread on idle-exit). The UI tick converts a set flag into a
    /// `ViewportCommand::Close` which returns control to `eframe::run`.
    shutdown_flag: Arc<std::sync::atomic::AtomicBool>,
}

impl Default for State {
    fn default() -> Self {
        State {
            queue: HashMap::new(),
            approvals: Vec::new(),
            secret_cache: Arc::new(Mutex::new(SecretCache::new())),
            last_activity: Instant::now(),
            egui_ctx: None,
            window_visible: false,
            viewer_mode: false,
            shutdown_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }
}

impl State {
    pub fn new() -> State {
        State::default()
    }

    /// Hand the shutdown flag to whichever component needs to observe or
    /// set it (the UI thread, `daemon::run`'s cleanup). Cloning the Arc
    /// keeps a single source of truth.
    pub fn shutdown_flag(&self) -> Arc<std::sync::atomic::AtomicBool> {
        self.shutdown_flag.clone()
    }

    /// Mark the daemon for exit. Called by the socket thread when a
    /// `ClientMsg::Shutdown` arrives; the UI tick picks it up on the
    /// next paint and closes the viewport.
    pub fn request_shutdown(&self) {
        self.shutdown_flag
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.repaint();
    }

    pub fn attach_egui(&mut self, ctx: egui::Context) {
        self.egui_ctx = Some(ctx);
    }

    /// Try to short-circuit an ask from the approvals cache. Returns
    /// the resolved-secret reply if the user previously approved at any
    /// level of the caller chain; the caller should *not* enqueue.
    ///
    /// The flow:
    /// 1. Walk the caller chain looking for an approval (direct parent
    ///    first, then each ancestor outwards).
    /// 2. If found, use that scope to look up each secret in the
    ///    encrypted in-memory cache.
    /// 3. Any cache misses get resolved via the provider, and the
    ///    fresh values are stored in the cache under this scope for
    ///    future asks from descendants of the same scope.
    pub fn try_cache_hit(&self, ask: &Ask) -> Option<WaiterReply> {
        let scope = approval_scope_for(&self.approvals, ask)?;
        Some(resolve_for_ask_at_scope(
            ask,
            scope,
            self.secret_cache.clone(),
        ))
    }

    /// Add a waiter for `key`, either folding into an existing queue entry
    /// or creating a new one with `ask` as the representative.
    pub fn submit_ask(&mut self, ask: Ask, waiter: mpsc::Sender<WaiterReply>) -> SubmitResult {
        self.last_activity = Instant::now();
        let key = ask.dedupe_key.clone();
        let is_new = !self.queue.contains_key(&key);
        let entry = self.queue.entry(key.clone()).or_insert_with(|| QueueEntry {
            key: key.clone(),
            representative: ask.clone(),
            waiters: Vec::new(),
            first_seen: Instant::now(),
        });
        entry.waiters.push(waiter);
        self.show_window();
        self.repaint();
        if is_new {
            SubmitResult::NewEntry
        } else {
            SubmitResult::Coalesced
        }
    }

    /// Resolve a queue entry. **Returns immediately** — the UI must not
    /// block on a provider invocation.
    ///
    /// `scope` is the `(pid, start_time)` tuple recorded in the approvals
    /// cache when `decision == ApproveRemember`. For per-row approve
    /// it's just the wrap's direct parent; for "Approve all from
    /// ancestor X" it's X's pid/start_time, so any future descendant
    /// of X can ride the approval.
    ///
    /// What happens synchronously here, under the state mutex:
    /// - Remove the entry from the queue.
    /// - Update the in-memory approvals cache if `ApproveRemember`.
    /// - Request a repaint (so the card disappears on the next frame).
    /// - For deny, broadcast `Deny` directly to the waiters.
    ///
    /// What happens on a spawned worker thread (no mutex held):
    /// - For approve, run `resolve_for_ask` (which may shell out to
    ///   `op read` and friends) and broadcast the result to waiters.
    pub fn resolve(&mut self, key: &DedupeKey, decision: Decision, scope: ApprovalScope) {
        self.last_activity = Instant::now();
        let Some(entry) = self.queue.remove(key) else {
            self.repaint();
            return;
        };

        if decision == Decision::ApproveRemember {
            let new = ApprovalEntry {
                wrap: key.wrap.clone(),
                ppid: scope.pid,
                parent_start_time: scope.start_time,
            };
            if !self.approvals.contains(&new) {
                self.approvals.push(new);
            }
        }

        self.repaint();

        if decision.approved() {
            // Resolution lives off-thread so the UI never blocks on a
            // provider invocation. The worker owns the entry (and thus
            // the waiter senders); when it finishes, secrets land on the
            // socket connection threads parked on the channel.
            let cache = self.secret_cache.clone();
            std::thread::spawn(move || {
                let reply = resolve_for_ask_at_scope(&entry.representative, scope, cache)
                    .map_decision(|d| if d == Decision::Approve { decision } else { d });
                for w in &entry.waiters {
                    let _ = w.send(reply.clone());
                }
            });
        } else {
            // Deny is just message-passing; no need to spawn for it.
            let reply = WaiterReply::Decision {
                decision,
                secrets: HashMap::new(),
            };
            for w in &entry.waiters {
                let _ = w.send(reply.clone());
            }
        }
    }

    pub fn snapshot(&self) -> QueueSnapshot {
        let mut entries: Vec<QueueRow> = self
            .queue
            .values()
            .map(|e| QueueRow {
                key: e.key.clone(),
                representative: e.representative.clone(),
                waiter_count: e.waiter_count(),
                first_seen: e.first_seen,
            })
            .collect();
        entries.sort_by_key(|r| r.first_seen);
        QueueSnapshot { entries }
    }

    pub fn show_window(&mut self) {
        self.window_visible = true;
    }

    /// `secreq view`: open the window AND pin it so the empty-queue
    /// auto-hide is suppressed.
    pub fn enter_viewer_mode(&mut self) {
        self.window_visible = true;
        self.viewer_mode = true;
    }

    /// Always pairs viewer-mode reset with hide. A user-initiated close
    /// (via the close button) ends the "pinned" state — otherwise a
    /// later `secreq pending` would inherit the pin.
    pub fn hide_window(&mut self) {
        self.window_visible = false;
        self.viewer_mode = false;
    }

    pub fn window_visible(&self) -> bool {
        self.window_visible
    }

    pub fn viewer_mode(&self) -> bool {
        self.viewer_mode
    }

    pub fn queue_is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub fn last_activity(&self) -> Instant {
        self.last_activity
    }

    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    fn repaint(&self) {
        if let Some(ctx) = &self.egui_ctx {
            ctx.request_repaint();
        }
    }
}

impl WaiterReply {
    fn map_decision<F: FnOnce(Decision) -> Decision>(self, f: F) -> WaiterReply {
        match self {
            WaiterReply::Decision { decision, secrets } => WaiterReply::Decision {
                decision: f(decision),
                secrets,
            },
            err @ WaiterReply::Err { .. } => err,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmitResult {
    /// First waiter for this key — UI gets a new row.
    NewEntry,
    /// Folded into an existing row — UI just bumps the waiter count.
    Coalesced,
}

pub type SharedState = Arc<Mutex<State>>;

// ── Resolution ────────────────────────────────────────────────────────────
//
// One invocation per approved batch. `resolve::resolve_all` already
// handles same-provider batching across multiple secrets in the wrap.

/// The `(scope_pid, scope_start_time)` pair that authorized `ask` —
/// either the direct parent or some ancestor the user previously
/// approved at. Returned so the upcoming secret cache can key on the
/// scope that granted the access (so a future ask from a *different*
/// descendant of the same ancestor can ride the same cached value).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ApprovalScope {
    pub pid: u32,
    pub start_time: u64,
}

/// Walk the caller chain, return the first `(pid, start_time)` that has
/// a matching `ApprovalEntry` for this wrap. Returns `None` if no
/// ancestor is approved for the wrap.
///
/// Order: direct parent first, then each ancestor outwards. Direct
/// parent wins ties — most-specific approval scope is the most informative.
pub fn approval_scope_for(approvals: &[ApprovalEntry], ask: &Ask) -> Option<ApprovalScope> {
    // Direct parent: encoded in the dedupe key (it's the same data as
    // callers[0] but stored separately because the wire format predates
    // start_time on Caller). Check it first so legacy clients (whose
    // Caller.start_time is 0) still hit the cache.
    let direct = ApprovalScope {
        pid: ask.dedupe_key.ppid,
        start_time: ask.dedupe_key.parent_start_time,
    };
    if has_entry(approvals, &ask.dedupe_key.wrap, direct) {
        return Some(direct);
    }
    // Then each ancestor past the direct parent.
    for caller in ask.callers.iter().skip(1) {
        let scope = ApprovalScope {
            pid: caller.pid,
            start_time: caller.start_time,
        };
        if has_entry(approvals, &ask.dedupe_key.wrap, scope) {
            return Some(scope);
        }
    }
    None
}

fn has_entry(approvals: &[ApprovalEntry], wrap: &str, scope: ApprovalScope) -> bool {
    approvals
        .iter()
        .any(|e| e.wrap == wrap && e.ppid == scope.pid && e.parent_start_time == scope.start_time)
}

/// Resolve every secret in `ask` under `scope`. Cache-aware:
/// - For each secret, look in the encrypted in-memory cache under
///   `(scope, provider, locator)`. Hits short-circuit the provider call.
/// - Anything missing gets resolved via the provider in one batched
///   `resolve::resolve_all` invocation (existing same-provider batching
///   in `resolve_all` still applies to the still-needed requests).
/// - Fresh resolutions are stored in the cache under `scope` so a future
///   ask from any descendant of `scope` can hit.
///
/// Running off-thread, so blocking on `op read` etc. is fine here.
fn resolve_for_ask_at_scope(
    ask: &Ask,
    scope: ApprovalScope,
    cache: Arc<Mutex<SecretCache>>,
) -> WaiterReply {
    let mut secrets: HashMap<String, String> = HashMap::new();
    let mut needs_resolve: Vec<&super::proto::SecretAsk> = Vec::new();

    {
        let guard = cache.lock().expect("secret cache mutex");
        for s in &ask.secrets {
            let key = CacheKey {
                scope_pid: scope.pid,
                scope_start_time: scope.start_time,
                provider: s.provider.clone(),
                locator: s.locator.clone(),
            };
            if let Some(value) = guard.get(&key) {
                secrets.insert(s.name.clone(), (*value).clone());
            } else {
                needs_resolve.push(s);
            }
        }
    }

    if needs_resolve.is_empty() {
        return WaiterReply::Decision {
            decision: Decision::Approve,
            secrets,
        };
    }

    let manifest = build_manifest(&ask.providers);
    let plan = ResolutionPlan {
        requests: needs_resolve
            .iter()
            .map(|s| SecretRequest {
                name: s.name.clone(),
                provider: s.provider.clone(),
                locator: s.locator.clone(),
                group: None,
                reason: s.reason.clone(),
                description: s.description.clone(),
                default: s.default.clone(),
                source: Source::Eager,
            })
            .collect(),
    };
    match resolve::resolve_all(&manifest, &plan) {
        Ok(resolved) => {
            let by_name: HashMap<String, _> =
                resolved.into_iter().map(|r| (r.name, r.value)).collect();
            // Map results back to the secrets we asked for, populating
            // the cache and the reply in one pass.
            let mut guard = cache.lock().expect("secret cache mutex");
            // Cheap opportunistic eviction so the cache doesn't grow
            // unbounded under heavy churn.
            guard.evict_expired();
            for s in &needs_resolve {
                let Some(value) = by_name.get(&s.name) else {
                    continue;
                };
                let exposed = value.expose().to_owned();
                let key = CacheKey {
                    scope_pid: scope.pid,
                    scope_start_time: scope.start_time,
                    provider: s.provider.clone(),
                    locator: s.locator.clone(),
                };
                guard.put(key, &exposed);
                secrets.insert(s.name.clone(), exposed);
            }
            WaiterReply::Decision {
                decision: Decision::Approve,
                secrets,
            }
        }
        Err(err) => WaiterReply::Err {
            message: format!("{err:#}"),
        },
    }
}

fn build_manifest(providers: &HashMap<String, WireProvider>) -> Manifest {
    let mut out_providers = std::collections::BTreeMap::new();
    for (name, wp) in providers {
        out_providers.insert(
            name.clone(),
            Provider {
                name: wp.name.clone(),
                retrieve: wp.retrieve.clone(),
                store: None,
                retrieve_batch: wp.retrieve_batch.as_ref().map(|b| BatchRetrieve {
                    command: b.command.clone(),
                    env_value_template: b.env_value_template.clone(),
                }),
            },
        );
    }
    Manifest {
        groups: std::collections::BTreeMap::new(),
        providers: out_providers,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::proto::{Caller, DedupeKey};

    fn mk_ask(wrap: &str, callers: Vec<(u32, u64)>) -> Ask {
        let dedupe_key = DedupeKey {
            wrap: wrap.to_owned(),
            ppid: callers.first().map(|c| c.0).unwrap_or(0),
            parent_start_time: callers.first().map(|c| c.1).unwrap_or(0),
        };
        Ask {
            command: vec![wrap.to_owned()],
            cwd: String::new(),
            callers: callers
                .into_iter()
                .map(|(pid, start_time)| Caller {
                    pid,
                    name: String::new(),
                    command: String::new(),
                    start_time,
                })
                .collect(),
            secrets: vec![],
            providers: HashMap::new(),
            dedupe_key,
        }
    }

    #[test]
    fn approval_at_direct_parent_hits_with_scope_of_direct_parent() {
        let approvals = vec![ApprovalEntry {
            wrap: "gh".into(),
            ppid: 7926,
            parent_start_time: 1_700_000_000,
        }];
        let ask = mk_ask("gh", vec![(7926, 1_700_000_000)]);
        let scope = approval_scope_for(&approvals, &ask).expect("hit");
        assert_eq!(scope.pid, 7926);
        assert_eq!(scope.start_time, 1_700_000_000);
    }

    #[test]
    fn approval_at_ancestor_hits_from_a_descendant_ask() {
        // User clicked "Approve all from Superset.app [pid 2831]". A
        // grandchild zsh now asks for `gh`; the cache lookup should walk
        // up to Superset and hit.
        let approvals = vec![ApprovalEntry {
            wrap: "gh".into(),
            ppid: 2831,
            parent_start_time: 1_600_000_000,
        }];
        let ask = mk_ask(
            "gh",
            vec![
                (7926, 1_700_000_000), // direct: zsh
                (8003, 1_650_000_000), // grandparent: Superset shell
                (2831, 1_600_000_000), // approved: Superset.app
            ],
        );
        let scope = approval_scope_for(&approvals, &ask).expect("hit at ancestor");
        assert_eq!(scope.pid, 2831);
    }

    #[test]
    fn approval_for_a_different_wrap_does_not_hit() {
        // Scope match but wrong wrap name — must miss.
        let approvals = vec![ApprovalEntry {
            wrap: "aws".into(),
            ppid: 7926,
            parent_start_time: 1_700_000_000,
        }];
        let ask = mk_ask("gh", vec![(7926, 1_700_000_000)]);
        assert!(approval_scope_for(&approvals, &ask).is_none());
    }

    #[test]
    fn approval_with_recycled_pid_but_different_start_time_does_not_hit() {
        // The pid-recycle safety property: same pid, different start_time
        // means a different process and the approval must not transfer.
        let approvals = vec![ApprovalEntry {
            wrap: "gh".into(),
            ppid: 7926,
            parent_start_time: 1_500_000_000,
        }];
        let ask = mk_ask("gh", vec![(7926, 1_700_000_000)]);
        assert!(approval_scope_for(&approvals, &ask).is_none());
    }

    #[test]
    fn direct_parent_wins_over_ancestor_when_both_approved() {
        // Most-specific scope is preferred. Useful later: the secret
        // cache will key on scope, so we want consistent lookup.
        let approvals = vec![
            ApprovalEntry {
                wrap: "gh".into(),
                ppid: 7926, // zsh — direct
                parent_start_time: 1_700_000_000,
            },
            ApprovalEntry {
                wrap: "gh".into(),
                ppid: 2831, // Superset — ancestor
                parent_start_time: 1_600_000_000,
            },
        ];
        let ask = mk_ask("gh", vec![(7926, 1_700_000_000), (2831, 1_600_000_000)]);
        let scope = approval_scope_for(&approvals, &ask).expect("hit");
        assert_eq!(scope.pid, 7926, "direct parent wins");
    }
}
