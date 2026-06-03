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
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use anyhow::Result;

use crate::consent::{ApprovalEntry, Decision};
use crate::manifest::{BatchRetrieve, Manifest, Provider};
use crate::resolve::{self, ResolutionPlan, SecretRequest, Source};
use crate::rules::{self, EvalCtx, Rule, RuleHit};

use super::cache::{CacheKey, SecretCache};
use super::in_flight::{Acquired, InFlightGuard, InFlightMap};
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
    /// Encrypted in-memory cache of resolved secret values.
    secret_cache: Arc<Mutex<SecretCache>>,
    /// Singleflight coordinator. Ensures concurrent asks for the same
    /// `(wrap, provider, locator)` trigger exactly one provider
    /// invocation; the rest park on a condvar until the cache lands.
    /// Without this, a parallel burst of N asks (e.g. scanner sweeping
    /// PRs) each observes an empty cache and each invokes the provider
    /// — N biometric prompts where one would do.
    in_flight: Arc<InFlightMap>,
    last_activity: Instant,
    /// `true` while at least one consent-window child should be on
    /// screen — set by `submit_ask` / `enter_viewer_mode` /
    /// `show_window`, cleared by `hide_window` (which the daemon
    /// runs when the queue drains + viewer mode is off + grace
    /// period elapsed, or when the user closes the child window).
    window_visible: bool,
    /// "Pinned" mode set by `ClientMsg::ShowViewer` (the `secreq
    /// view` command). While true, the daemon doesn't ask the
    /// consent window to exit even if the queue is empty — the user
    /// is browsing the audit log.
    viewer_mode: bool,
    /// Set by the socket thread on `ClientMsg::Shutdown`. The daemon
    /// main loop checks this flag and exits cleanly.
    shutdown_flag: Arc<std::sync::atomic::AtomicBool>,

    // ── Consent-window streaming subscribers ──────────────────────
    //
    // Each attached consent-window child has one `Sender<DaemonMsg>`
    // here, owned by the daemon's per-connection writer thread.
    // `broadcast_consent_update` pushes a fresh `ConsentUpdate` onto
    // every sender; senders whose receiver has been dropped (child
    // exited / crashed) are removed lazily on the next broadcast.
    consent_subscribers: Vec<ConsentSubscriber>,
    /// Source for unique subscriber IDs. Wraps would be fine — we'd
    /// need a daemon that ran for decades to overflow u64 — but a
    /// fresh monotonic counter per daemon keeps the IDs grep-able
    /// across daemon restarts.
    consent_next_subscriber_id: u64,
    /// Set by the spawn path between `Command::spawn` and the child's
    /// `ConsentWindowAttach` so a burst of Asks doesn't launch N
    /// children. Cleared when the first child attaches OR after a
    /// timeout (so a failed spawn doesn't permanently block).
    consent_spawn_in_flight_since: Option<Instant>,
    /// `true` between `initiate_consent_restart()` and the moment the
    /// dying child's detach is processed. Tells the detach handler
    /// "this isn't a user-initiated close — preserve viewer_mode and
    /// window_visible, then spawn a fresh child." Without this, the
    /// kill-and-respawn flow would lose `viewer_mode` and never
    /// re-show the audit log after `secreq view` re-fires.
    consent_restart_pending: bool,
    /// `Some(t)` if the queue is currently empty, where `t` is when
    /// it became empty. `None` when there's at least one pending
    /// entry. Drives the auto-hide grace period — we leave the
    /// "All clear" state on screen for a moment so the user sees
    /// confirmation, then ask the consent window to exit.
    /// Cleared when we send `ConsentExitPlease` so we don't keep
    /// re-sending it every tick while the child is winding down.
    queue_empty_since: Option<Instant>,

    // ── Auto-rules ────────────────────────────────────────────────
    //
    // Persisted policy that fires before the consent prompt. See
    // `src/rules.rs` and `dev-docs/plans/2026-06-02-auto-rules.md`.
    /// Path to the rules file. `None` in default state (test/legacy
    /// constructor). Set by [`State::with_rules_path`] at daemon
    /// startup.
    rules_path: Option<PathBuf>,
    /// In-memory copy of the ruleset. Mutated by AddRule / UpdateRule /
    /// DeleteRule / SetRuleEnabled, kept in sync with the on-disk
    /// file by every mutation path that writes the file.
    rules: Vec<Rule>,
    /// The file's `mtime` at the moment we loaded it. The freshness
    /// check compares this against the live `mtime`; an advance means
    /// the user hand-edited the file, so we shut down so the next ask
    /// respawns a fresh daemon. UI-write paths refresh this in-place
    /// so they never trigger the shutdown.
    rules_loaded_at: Option<SystemTime>,
}

impl Default for State {
    fn default() -> Self {
        State {
            queue: HashMap::new(),
            approvals: Vec::new(),
            secret_cache: Arc::new(Mutex::new(SecretCache::new())),
            in_flight: InFlightMap::new(),
            last_activity: Instant::now(),
            window_visible: false,
            viewer_mode: false,
            shutdown_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            consent_subscribers: Vec::new(),
            consent_next_subscriber_id: 1,
            consent_spawn_in_flight_since: None,
            consent_restart_pending: false,
            // Queue starts empty; record the moment so the auto-hide
            // logic has a stable "started counting" anchor.
            queue_empty_since: Some(Instant::now()),
            rules_path: None,
            rules: Vec::new(),
            rules_loaded_at: None,
        }
    }
}

/// How long we treat `consent_spawn_in_flight_since` as "still
/// pending" before assuming the spawn failed silently and allowing a
/// new attempt.
const CONSENT_SPAWN_TIMEOUT: Duration = Duration::from_secs(3);

/// One attached consent-window child, with a stable ID so the
/// streaming connection handler can detach itself precisely on exit
/// instead of waiting for a broadcast to lazy-prune the dead sender
/// (which deadlocks the writer thread on `Receiver::recv()` — see
/// the "every other view works" bug fix).
struct ConsentSubscriber {
    id: u64,
    /// OS pid of the consent-window child. The CLI uses this to call
    /// `NSRunningApplication.activate(...)` from the user-intent context
    /// — see `ConsentWindowAttach` in `proto.rs` for why.
    pid: u32,
    tx: mpsc::Sender<super::proto::DaemonMsg>,
    /// Latest reported window focus state. Defaults to `true` at attach
    /// because a freshly-spawned child gets foreground intent on macOS;
    /// the child overwrites this whenever the OS reports a focus change
    /// via `ClientMsg::ConsentWindowFocus`.
    focused: bool,
}

impl State {
    pub fn new() -> State {
        State::default()
    }

    /// Construct a State pre-loaded with rules from `rules_path`. The
    /// daemon's `run()` calls this so freshness checks and CRUD
    /// operations have a target. Load failures are non-fatal here:
    /// they're logged via the daemon log and the daemon proceeds with
    /// an empty ruleset, matching the design's "broken file shouldn't
    /// block consent" contract. The mtime is still recorded so the
    /// freshness check can detect when the user fixes the file.
    pub fn with_rules_path(rules_path: PathBuf) -> State {
        let mut state = State::new();
        match rules::load_rules(&rules_path) {
            Ok(loaded) => {
                state.rules = loaded.rules;
                state.rules_loaded_at = loaded.mtime;
            }
            Err(err) => {
                super::log::log_at(
                    "state",
                    format_args!(
                        "WARN: failed to load {}: {err:#} — continuing with no auto-rules",
                        rules_path.display()
                    ),
                );
                // Stamp current mtime so we don't re-warn every ask
                // while the file remains broken.
                state.rules_loaded_at = rules::file_mtime(&rules_path);
            }
        }
        state.rules_path = Some(rules_path);
        state
    }

    /// Hand the shutdown flag to whichever component needs to observe or
    /// set it (the UI thread, `daemon::run`'s cleanup). Cloning the Arc
    /// keeps a single source of truth.
    pub fn shutdown_flag(&self) -> Arc<std::sync::atomic::AtomicBool> {
        self.shutdown_flag.clone()
    }

    /// Mark the daemon for exit. Called by the socket thread when a
    /// `ClientMsg::Shutdown` arrives; the daemon's main loop picks it
    /// up and shuts down.
    pub fn request_shutdown(&mut self) {
        self.shutdown_flag
            .store(true, std::sync::atomic::Ordering::SeqCst);
        // Tell every consent-window child to close so they don't
        // outlive the daemon.
        self.broadcast(super::proto::DaemonMsg::ConsentExitPlease);
    }

    // ── Consent-window subscriber API ────────────────────────────

    /// Register a consent-window child as a subscriber. Returns the
    /// subscriber's ID — the streaming connection handler **must**
    /// pass this back to [`detach_consent_window`] when its read loop
    /// exits, otherwise the held `Sender` keeps the writer thread's
    /// `Receiver` alive and the connection handler hangs on
    /// `writer_handle.join()`. The accompanying [`WireSnapshot`] is
    /// the initial state the caller should ship to the child
    /// immediately so it can paint frame 1 without a round-trip.
    pub fn attach_consent_window(
        &mut self,
        pid: u32,
        sender: mpsc::Sender<super::proto::DaemonMsg>,
    ) -> (u64, super::proto::WireSnapshot) {
        let id = self.consent_next_subscriber_id;
        self.consent_next_subscriber_id = id.wrapping_add(1);
        self.consent_spawn_in_flight_since = None;
        self.consent_subscribers.push(ConsentSubscriber {
            id,
            pid,
            tx: sender,
            focused: true,
        });
        super::log::log_at(
            "state",
            format_args!(
                "consent window attached (id={id}, pid={pid}, subscribers={})",
                self.consent_subscribers.len()
            ),
        );
        (id, self.snapshot_for_wire())
    }

    /// First attached child's pid, if any. The CLI uses this to drive
    /// `NSRunningApplication.activate(...)` from its own user-intent
    /// context — see the doc comment on `ConsentWindowAttach` in
    /// `proto.rs` for why the CLI has to do the activation, not the
    /// child itself.
    pub fn consent_child_pid(&self) -> Option<u32> {
        self.consent_subscribers.first().map(|s| s.pid)
    }

    /// "Kill the existing consent child and respawn a fresh one."
    ///
    /// This is the workaround for macOS aggressively suspending the
    /// run loop of background, occluded apps: a child that's been put
    /// to sleep can't process raise commands, so we can't bring it
    /// forward. A *new* process gets foreground intent at launch, so
    /// the fresh window naturally appears in front.
    ///
    /// Mechanism:
    ///   1. Broadcast `ConsentExitPlease` to every subscriber. The
    ///      child's reader thread receives it and `process::exit`s
    ///      directly — bypassing the suspended main loop.
    ///   2. Clear the subscriber list, so the dying child no longer
    ///      gets state broadcasts (its writer thread's `rx.recv()`
    ///      will return `Err` after the connection handler's local
    ///      `tx` is also dropped at function exit, but we don't wait
    ///      for that).
    ///   3. Set `consent_restart_pending` so the detach handler knows
    ///      to call `ensure_consent_window` (spawning the fresh
    ///      child) instead of `hide_window` (resetting viewer state).
    ///
    /// Just dropping the subscriber senders here is NOT enough on its
    /// own — the connection handler in `server.rs` keeps a local `tx`
    /// alive until normal detach, so the channel never closes from
    /// the daemon side. Sending an explicit exit signal is the only
    /// way to trigger the child to release its socket.
    ///
    /// No-op if no subscriber is currently attached.
    pub fn initiate_consent_restart(&mut self) {
        if self.consent_subscribers.is_empty() {
            return;
        }
        super::log::log_at(
            "state",
            format_args!(
                "consent restart requested ({} subscriber(s) → ConsentExitPlease)",
                self.consent_subscribers.len()
            ),
        );
        self.consent_restart_pending = true;
        // Send the exit message before clearing. After clearing, the
        // sender clones are dropped and we'd lose the ability to push
        // anything to the writer threads.
        self.broadcast(super::proto::DaemonMsg::ConsentExitPlease);
        self.consent_subscribers.clear();
    }

    /// Detach handler hook. Returns and clears the restart-pending
    /// flag — `true` means the detach was daemon-initiated and the
    /// caller should preserve `viewer_mode` / `window_visible` and
    /// `ensure_consent_window` afterward. `false` means a normal
    /// user-initiated close, where `hide_window` should run.
    pub fn take_consent_restart_pending(&mut self) -> bool {
        std::mem::take(&mut self.consent_restart_pending)
    }

    /// Non-consuming peek at `consent_restart_pending`. Used by
    /// `ensure_consent_window` to defer its spawn while a restart is
    /// in progress — the dying child's detach handler will perform the
    /// spawn instead, guaranteeing only one consent window exists at
    /// any moment (no "old child still on screen while new child
    /// opens" race).
    pub fn is_consent_restart_pending(&self) -> bool {
        self.consent_restart_pending
    }

    /// Remove a subscriber by ID. Must be called by the streaming
    /// connection handler when it exits its read loop, *before*
    /// joining the writer thread — see [`attach_consent_window`] for
    /// the deadlock this avoids.
    pub fn detach_consent_window(&mut self, id: u64) {
        let before = self.consent_subscribers.len();
        self.consent_subscribers.retain(|s| s.id != id);
        let after = self.consent_subscribers.len();
        super::log::log_at(
            "state",
            format_args!("consent window detached (id={id}, subscribers {before}→{after})"),
        );
    }

    /// Number of currently-attached consent-window children.
    pub fn consent_subscriber_count(&self) -> usize {
        self.consent_subscribers.len()
    }

    /// Record a focus-state update for one attached child. Called by
    /// the streaming connection handler when a `ConsentWindowFocus`
    /// arrives. Unknown IDs are ignored — the subscriber may have
    /// detached between the child sending the message and us draining
    /// it.
    pub fn set_consent_focused(&mut self, id: u64, focused: bool) {
        for s in &mut self.consent_subscribers {
            if s.id == id {
                s.focused = focused;
                return;
            }
        }
    }

    /// `true` if any attached consent-window child currently reports
    /// itself as focused (OS keyboard focus). Used to gate the
    /// kill-and-respawn raise — when the UI is already in front, a
    /// new ask just needs the streaming snapshot to land, not a
    /// fresh process — and to suppress the auto-hide grace exit
    /// while the user is interacting with the window.
    pub fn any_consent_focused(&self) -> bool {
        self.consent_subscribers.iter().any(|s| s.focused)
    }

    /// One-shot toast push for an auto-deny event. Best-effort —
    /// dropped if no child is attached at this moment.
    pub fn broadcast_auto_deny_toast(&mut self, rule_name: String, deny_message: Option<String>) {
        if self.consent_subscribers.is_empty() {
            return;
        }
        self.broadcast(super::proto::DaemonMsg::AutoDenyToast {
            rule_name,
            deny_message,
        });
    }

    /// Broadcast `ConsentExitPlease` to every attached consent window.
    /// Used by the daemon's shutdown sequence — both the explicit
    /// `request_shutdown` path and the idle-exit path that runs on
    /// the main loop. A no-op if no subscribers are attached.
    pub fn broadcast_consent_exit_please(&mut self) {
        if self.consent_subscribers.is_empty() {
            return;
        }
        self.broadcast(super::proto::DaemonMsg::ConsentExitPlease);
        // Clear the grace timer so the main loop doesn't keep
        // re-broadcasting on every tick while the child winds down.
        self.queue_empty_since = None;
    }

    /// When did the queue most recently become empty? `None` means
    /// the queue currently has at least one entry. Used by the
    /// daemon main loop to time the auto-hide grace period.
    pub fn queue_empty_since(&self) -> Option<Instant> {
        self.queue_empty_since
    }

    /// Sync `queue_empty_since` to the current queue state. Called
    /// from `submit_ask` and `resolve` whenever the queue might have
    /// crossed the empty/non-empty boundary. Idempotent: re-calling
    /// while the state hasn't changed leaves the timestamp alone.
    fn refresh_queue_empty_since(&mut self) {
        if self.queue.is_empty() {
            if self.queue_empty_since.is_none() {
                self.queue_empty_since = Some(Instant::now());
            }
        } else {
            self.queue_empty_since = None;
        }
    }

    /// True if a `Command::spawn` is in flight and we shouldn't
    /// start another. Stale entries auto-clear after
    /// `CONSENT_SPAWN_TIMEOUT`.
    pub fn consent_spawn_in_flight(&mut self) -> bool {
        if let Some(at) = self.consent_spawn_in_flight_since {
            if at.elapsed() < CONSENT_SPAWN_TIMEOUT {
                return true;
            }
            // Timed out — assume the spawn failed silently and allow
            // a retry on the next state change.
            self.consent_spawn_in_flight_since = None;
        }
        false
    }

    /// Record that a `Command::spawn` for a consent-window child has
    /// just been kicked off. Subsequent calls will see
    /// `consent_spawn_in_flight()` return `true` until the child
    /// attaches or `CONSENT_SPAWN_TIMEOUT` elapses.
    pub fn mark_consent_spawn_in_flight(&mut self) {
        self.consent_spawn_in_flight_since = Some(Instant::now());
    }

    /// Should the daemon ensure a consent-window child is running?
    /// True iff there's something for the user to see *and* nobody is
    /// already there to see it.
    pub fn needs_consent_window(&self) -> bool {
        (!self.queue.is_empty() || self.viewer_mode) && self.consent_subscribers.is_empty()
    }

    /// Push the current snapshot to every attached consent window.
    /// Senders whose receiver has been dropped (child exited) are
    /// pruned out.
    pub fn broadcast_consent_update(&mut self) {
        let snapshot = self.snapshot_for_wire();
        self.broadcast(super::proto::DaemonMsg::ConsentUpdate { snapshot });
    }

    fn broadcast(&mut self, msg: super::proto::DaemonMsg) {
        self.consent_subscribers
            .retain(|s| s.tx.send(msg.clone()).is_ok());
    }

    /// Build a wire-form snapshot for the consent UI.
    pub fn snapshot_for_wire(&self) -> super::proto::WireSnapshot {
        let now = Instant::now();
        let queue: Vec<super::proto::WireQueueRow> = self
            .queue
            .values()
            .map(|e| super::proto::WireQueueRow {
                key: e.key.clone(),
                representative: e.representative.clone(),
                waiter_count: e.waiter_count(),
                first_seen_secs_ago: now.saturating_duration_since(e.first_seen).as_secs(),
            })
            .collect();
        super::proto::WireSnapshot {
            queue,
            viewer_mode: self.viewer_mode,
            rules: self.rules.clone(),
        }
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
        // Authorization gate: only short-circuit the prompt if some
        // ancestor in the caller chain has a remembered approval for
        // this wrap. The matched scope itself isn't used downstream —
        // the secret cache keys on `(wrap, provider, locator)`, not on
        // which parent process happened to be approved.
        approval_scope_for(&self.approvals, ask)?;
        // The approvals cache had a hit — the user is never prompted.
        // Rewrite the reply's decision to `ApproveCached` so the audit
        // log distinguishes "we used a remembered approval" from "the
        // user just clicked Approve". The encrypted-secret cache may or
        // may not also hit (it usually does, since `ApproveRemember`
        // populates it during the original resolve); either way the
        // *approval* was cached and that's what the audit pill reports.
        Some(
            resolve_for_ask(ask, self.secret_cache.clone(), self.in_flight.clone()).map_decision(
                |d| {
                    if d == Decision::Approve {
                        Decision::ApproveCached
                    } else {
                        d
                    }
                },
            ),
        )
    }

    /// Add a waiter for `key`, either folding into an existing queue entry
    /// or creating a new one with `ask` as the representative.
    pub fn submit_ask(&mut self, ask: Ask, waiter: mpsc::Sender<WaiterReply>) -> SubmitResult {
        self.last_activity = Instant::now();
        // Queue is about to become non-empty (or stay non-empty);
        // either way the auto-hide grace clock should be reset.
        self.queue_empty_since = None;
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
        self.broadcast_consent_update();
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
            self.broadcast_consent_update();
            self.refresh_queue_empty_since();
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

        self.broadcast_consent_update();
        // Queue may have just emptied — set the timestamp so the
        // auto-hide grace period starts counting. Main loop reads
        // this each tick and broadcasts `ConsentExitPlease` once the
        // grace elapses.
        self.refresh_queue_empty_since();

        if decision.approved() {
            // Resolution lives off-thread so the UI never blocks on a
            // provider invocation. The worker owns the entry (and thus
            // the waiter senders); when it finishes, secrets land on the
            // socket connection threads parked on the channel.
            let cache = self.secret_cache.clone();
            let in_flight = self.in_flight.clone();
            std::thread::spawn(move || {
                let reply =
                    resolve_for_ask(&entry.representative, cache, in_flight).map_decision(|d| {
                        if d == Decision::Approve {
                            decision
                        } else {
                            d
                        }
                    });
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

    /// Make the window visible. **Always nudges egui to repaint** so
    /// the socket-thread callers (`ClientMsg::ShowWindow`, the
    /// `submit_ask` path) actually wake the UI loop — without this,
    /// the daemon's `ConsentApp::ui` never runs, never sees the
    /// `window_visible = true` flip, and never sends the
    /// `ViewportCommand::Visible(true)` that the OS needs to put the
    /// window on screen.
    pub fn show_window(&mut self) {
        self.window_visible = true;
        self.broadcast_consent_update();
    }

    /// `secreq view`: open the window AND pin it so the empty-queue
    /// auto-hide is suppressed.
    pub fn enter_viewer_mode(&mut self) {
        self.window_visible = true;
        self.viewer_mode = true;
        self.broadcast_consent_update();
    }

    /// Called when the consent-window child detaches (close button,
    /// process exit, crash). Clears viewer-mode so a subsequent ask
    /// doesn't inherit the pin.
    pub fn hide_window(&mut self) {
        self.window_visible = false;
        self.viewer_mode = false;
        self.broadcast_consent_update();
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

    // ── Auto-rules API ────────────────────────────────────────────

    /// The current ruleset, cloned for the caller. Used by the
    /// `ListRules` IPC handler and by [`State::snapshot_for_wire`] so
    /// the consent UI sees the Rules tab content.
    pub fn rules_snapshot(&self) -> Vec<Rule> {
        self.rules.clone()
    }

    /// Reload the auto-rules file if its `mtime` has advanced since
    /// we last loaded it. Called at the top of every `handle_message`
    /// so any subsequent rule evaluation, list, or UI snapshot reflects
    /// the user's latest hand-edits.
    ///
    /// **Why reload-in-place rather than restart-on-change?** The
    /// original design used a daemon shutdown to ensure the in-memory
    /// approvals cache was also cleared when policy changed. But the
    /// approvals cache is checked *before* rules evaluate (in
    /// `try_cache_hit`), so a rule edit doesn't actually invalidate
    /// past approvals — past approvals are tied to a specific `(wrap,
    /// pid, start_time)` and remain semantically valid. The explicit
    /// revoke primitive (`secreq daemon stop`) stays as the way to
    /// clear approvals.
    ///
    /// Reload errors (a parse failure on the user's hand-edit) leave
    /// the previous ruleset in place and log a warning to stderr —
    /// matches the design's "broken file shouldn't block consent"
    /// contract.
    pub fn reload_rules_if_changed(&mut self) {
        let Some(path) = self.rules_path.clone() else {
            return;
        };
        let live_mtime = rules::file_mtime(&path);
        if live_mtime == self.rules_loaded_at {
            return;
        }
        super::log::log_at(
            "state",
            format_args!(
                "auto-rules file changed on disk ({:?} -> {:?}); reloading",
                self.rules_loaded_at, live_mtime,
            ),
        );
        match rules::load_rules(&path) {
            Ok(loaded) => {
                self.rules = loaded.rules;
                self.rules_loaded_at = loaded.mtime;
                // Push the new ruleset to any attached consent window so
                // the Rules tab UI reflects the edit immediately.
                self.broadcast_consent_update();
            }
            Err(err) => {
                super::log::log_at(
                    "state",
                    format_args!(
                        "WARN: failed to reload {}: {err:#} — keeping previous ruleset",
                        path.display()
                    ),
                );
                // Still bump our remembered mtime so we don't re-warn
                // every request while the file remains broken.
                self.rules_loaded_at = live_mtime;
            }
        }
    }

    /// Evaluate the current ruleset against `ask`. Returns `Some(hit)`
    /// for an auto-approve / auto-deny that should bypass the queue,
    /// `None` for "fall through to the interactive prompt." The
    /// caller (server.rs) consumes the hit and builds the
    /// `DaemonMsg::Decision`.
    pub fn evaluate_rules_for_ask(&self, ask: &Ask) -> Option<RuleHit> {
        if self.rules.is_empty() {
            return None;
        }
        let joined_argv = ask.command.join(" ");
        let callers: Vec<(&str, &str)> = ask
            .callers
            .iter()
            .map(|c| (c.name.as_str(), c.command.as_str()))
            .collect();
        let requested: Vec<&str> = ask.secrets.iter().map(|s| s.name.as_str()).collect();
        let ctx = EvalCtx {
            wrap: &ask.dedupe_key.wrap,
            joined_argv: &joined_argv,
            callers: &callers,
            cwd: &ask.cwd,
            requested_secret_names: &requested,
        };
        rules::evaluate(&self.rules, &ctx)
    }

    /// Insert a new rule, persist, and refresh `rules_loaded_at` so
    /// the freshness check doesn't trigger on our own write. Returns
    /// an error if the id collides with an existing rule.
    pub fn add_rule(&mut self, rule: Rule) -> Result<()> {
        if self.rules.iter().any(|r| r.id == rule.id) {
            anyhow::bail!("rule with id `{}` already exists", rule.id);
        }
        self.rules.push(rule);
        self.persist_rules_and_refresh()?;
        self.broadcast_consent_update();
        Ok(())
    }

    /// Replace the rule whose id matches `rule.id`. Errors if no such
    /// rule exists. Used by the UI's edit-form save path.
    pub fn update_rule(&mut self, rule: Rule) -> Result<()> {
        let Some(slot) = self.rules.iter_mut().find(|r| r.id == rule.id) else {
            anyhow::bail!("no rule with id `{}`", rule.id);
        };
        *slot = rule;
        self.persist_rules_and_refresh()?;
        self.broadcast_consent_update();
        Ok(())
    }

    /// Delete the rule with this id. Errors if no such rule exists.
    pub fn delete_rule(&mut self, id: &str) -> Result<()> {
        let before = self.rules.len();
        self.rules.retain(|r| r.id != id);
        if self.rules.len() == before {
            anyhow::bail!("no rule with id `{id}`");
        }
        self.persist_rules_and_refresh()?;
        self.broadcast_consent_update();
        Ok(())
    }

    /// Toggle the `enabled` bit on this rule. Cheaper-path equivalent
    /// of an update for the common "pause this rule" affordance.
    pub fn set_rule_enabled(&mut self, id: &str, enabled: bool) -> Result<()> {
        let Some(rule) = self.rules.iter_mut().find(|r| r.id == id) else {
            anyhow::bail!("no rule with id `{id}`");
        };
        rule.enabled = enabled;
        self.persist_rules_and_refresh()?;
        self.broadcast_consent_update();
        Ok(())
    }

    /// Hand back the encrypted-secret-cache Arc so the auto-approve
    /// path in server.rs can call `resolve_for_ask` directly without
    /// re-walking the in-memory approvals cache.
    pub fn secret_cache_arc(&self) -> Arc<Mutex<SecretCache>> {
        self.secret_cache.clone()
    }

    /// Hand back the singleflight Arc alongside the cache. Both are
    /// passed together to `resolve_for_ask`; pairing the accessors
    /// makes the call site at the rule-hit path symmetric with the
    /// interactive-approval path.
    pub fn in_flight_arc(&self) -> Arc<InFlightMap> {
        self.in_flight.clone()
    }

    /// Write `self.rules` to the rules file and stamp the new mtime.
    /// Internal helper used by every CRUD path so freshness state
    /// stays consistent with the disk.
    fn persist_rules_and_refresh(&mut self) -> Result<()> {
        let Some(path) = self.rules_path.clone() else {
            // No path configured (test path or the legacy
            // `State::new()` constructor). Mutation succeeds in
            // memory; nothing to write.
            return Ok(());
        };
        rules::save_rules(&path, &self.rules)?;
        self.rules_loaded_at = rules::file_mtime(&path);
        Ok(())
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

/// Resolve every secret in `ask`. Cache-aware AND singleflight-aware:
///
/// 1. Cache check per secret. Hits short-circuit the provider call.
/// 2. For each miss, acquire the singleflight slot for that
///    `(wrap, provider, locator)` key:
///    - **Resolver**: this thread will run the provider for that key.
///      Multiple keys this thread owns are batched into one
///      `resolve::resolve_all` invocation (preserving existing
///      same-provider batching).
///    - **Ready (waiter)**: another thread already resolved this key.
///      Re-check the cache and pick up the value.
///    - **Failed (waiter)**: another thread tried and failed. Propagate
///      the same error rather than re-trying — the user just answered
///      "no" on a biometric prompt or `op` is broken, and immediately
///      reprompting them is exactly the noise we're trying to avoid.
/// 3. Resolver populates the cache and calls `mark_ready` on each
///    guard; waiters wake, re-check the cache, and reply.
///
/// Callers are responsible for authorization — this function never
/// gates a lookup. Both the interactive path (`try_cache_hit` after
/// `approval_scope_for` matches) and the auto-rule path (`handle_rule_hit`
/// after the rule fires) call in only once they've confirmed the ask is
/// allowed.
///
/// Running off-thread, so blocking on `op read` etc. is fine here.
///
/// `pub(super)` so the auto-rule path in `server.rs` can call this
/// directly — auto-decisions bypass the queue, so they don't go
/// through `State::resolve`.
pub(super) fn resolve_for_ask(
    ask: &Ask,
    cache: Arc<Mutex<SecretCache>>,
    in_flight: Arc<InFlightMap>,
) -> WaiterReply {
    let mut secrets: HashMap<String, String> = HashMap::new();
    let mut needs_resolve: Vec<&super::proto::SecretAsk> = Vec::new();
    let mut guards: Vec<InFlightGuard> = Vec::new();

    for s in &ask.secrets {
        let key = CacheKey {
            wrap: ask.dedupe_key.wrap.clone(),
            provider: s.provider.clone(),
            locator: s.locator.clone(),
        };
        // Cache check — held only for the lookup itself.
        {
            let guard = cache.lock().expect("secret cache mutex");
            if let Some(value) = guard.get(&key) {
                secrets.insert(s.name.clone(), (*value).clone());
                continue;
            }
        }
        // Miss → singleflight.
        match in_flight.acquire(&key) {
            Acquired::Resolver(g) => {
                needs_resolve.push(s);
                guards.push(g);
            }
            Acquired::Ready => {
                // Re-check the cache; the previous resolver should
                // have populated it. If somehow it didn't, treat as
                // a failure rather than retrying — see the
                // "ready-but-empty" comment below.
                let guard = cache.lock().expect("secret cache mutex");
                if let Some(value) = guard.get(&key) {
                    secrets.insert(s.name.clone(), (*value).clone());
                } else {
                    // Mark this thread's other guards as failed
                    // before bailing so any concurrent waiters
                    // *on those* keys also see a clean failure
                    // instead of "resolver did not signal".
                    let msg = format!(
                        "in-flight slot for {}/{} signalled ready but cache was empty",
                        s.provider, s.locator,
                    );
                    fail_guards(guards, &msg);
                    return WaiterReply::Err { message: msg };
                }
            }
            Acquired::Failed(msg) => {
                fail_guards(guards, &msg);
                return WaiterReply::Err { message: msg };
            }
        }
    }

    if needs_resolve.is_empty() {
        // No guards to release (we only push guards alongside
        // needs_resolve entries), so we can just return.
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
            {
                let mut guard = cache.lock().expect("secret cache mutex");
                for s in &needs_resolve {
                    let Some(value) = by_name.get(&s.name) else {
                        continue;
                    };
                    let exposed = value.expose().to_owned();
                    let key = CacheKey {
                        wrap: ask.dedupe_key.wrap.clone(),
                        provider: s.provider.clone(),
                        locator: s.locator.clone(),
                    };
                    guard.put(key, &exposed);
                    secrets.insert(s.name.clone(), exposed);
                }
            }
            // Cache is populated; signal waiters. mark_ready consumes
            // the guard so this also drops the InFlight slot entries.
            for g in guards {
                g.mark_ready();
            }
            WaiterReply::Decision {
                decision: Decision::Approve,
                secrets,
            }
        }
        Err(err) => {
            let msg = format!("{err:#}");
            // Propagate the real provider error to any waiters
            // rather than the generic "did not signal" default.
            fail_guards(guards, &msg);
            WaiterReply::Err { message: msg }
        }
    }
}

/// Consume `guards` and propagate `msg` to all waiters parked on
/// their slots. Used in the failure paths of `resolve_for_ask` so
/// concurrent asks for the same keys get a real error string.
fn fail_guards(guards: Vec<InFlightGuard>, msg: &str) {
    for g in guards {
        g.mark_failed(msg.to_owned());
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

    #[test]
    fn try_cache_hit_returns_approve_cached_so_audit_log_can_distinguish() {
        // A remembered approval (in `state.approvals`) plus an ask
        // whose direct parent matches the scope should short-circuit
        // the prompt. The reply must carry `ApproveCached`, not
        // `Approve`, so the audit-log writer downstream can render
        // "the user wasn't asked again" rather than implying a fresh
        // user click. (Previously both paths returned `Approve` and
        // the audit log couldn't tell the difference.)
        let mut state = State::new();
        state.approvals.push(ApprovalEntry {
            wrap: "gh".into(),
            ppid: 7926,
            parent_start_time: 1_700_000_000,
        });
        let ask = mk_ask("gh", vec![(7926, 1_700_000_000)]);
        let reply = state.try_cache_hit(&ask).expect("approval hit");
        match reply {
            WaiterReply::Decision { decision, .. } => {
                assert_eq!(decision, Decision::ApproveCached);
            }
            WaiterReply::Err { message } => panic!("unexpected err reply: {message}"),
        }
    }

    // ── Auto-rules path ───────────────────────────────────────────────

    use crate::rules::{Rule, RuleDecision, RuleMatch};

    fn mk_rule(id: &str, wrap: &str, decide: RuleDecision, argv: Option<&str>) -> Rule {
        Rule {
            id: id.to_owned(),
            name: id.to_owned(),
            enabled: true,
            decide,
            r#match: RuleMatch {
                wrap: wrap.to_owned(),
                argv: argv.map(crate::rules::Pattern::parse),
                ancestor: None,
                cwd: None,
            },
            trained_secrets: ["GITHUB_TOKEN".to_owned()].into_iter().collect(),
            deny_message: None,
            created_at_unix: 0,
        }
    }

    fn ask_with_secret(wrap: &str, argv: &[&str], secret: &str) -> Ask {
        Ask {
            command: argv.iter().map(|s| (*s).to_owned()).collect(),
            cwd: String::new(),
            callers: vec![],
            secrets: vec![super::super::proto::SecretAsk {
                name: secret.to_owned(),
                provider: "fake".to_owned(),
                locator: "x".to_owned(),
                default: None,
                description: None,
                reason: None,
            }],
            providers: HashMap::new(),
            dedupe_key: DedupeKey {
                wrap: wrap.to_owned(),
                ppid: 0,
                parent_start_time: 0,
            },
        }
    }

    #[test]
    fn with_rules_path_loads_existing_rules() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("auto-rules.json5");
        let rule = mk_rule("01", "gh", RuleDecision::Approve, Some("gh api *"));
        crate::rules::save_rules(&path, std::slice::from_ref(&rule)).expect("save");
        let state = State::with_rules_path(path);
        let loaded = state.rules_snapshot();
        assert_eq!(loaded, vec![rule]);
    }

    #[test]
    fn with_rules_path_tolerates_missing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nope.json5");
        let state = State::with_rules_path(path);
        assert!(state.rules_snapshot().is_empty());
    }

    #[test]
    fn resolve_for_ask_hits_cache_for_sibling_with_a_different_ppid() {
        // Regression: rule-based ApproveAuto used to key the secret
        // cache by the asking process's direct-parent (pid, start_time).
        // Two siblings launched from different short-lived shells would
        // each have a distinct ppid, miss the cache, and trigger a
        // fresh provider invocation (on 1Password, a fresh biometric
        // prompt). Post-fix the cache keys on (wrap, provider,
        // locator) only — any authorized ask for the same wrap+secret
        // reuses the cached value regardless of ppid.
        //
        // Setup: pre-seed the cache as if a prior ask had resolved the
        // secret, then call resolve_for_ask with an ask carrying an
        // arbitrarily-different ppid. The ask has no providers in it,
        // so a cache *miss* would propagate as a resolution error
        // rather than silently invoking anything — making this a
        // strict assertion that we actually hit the cache.
        let state = State::new();
        let cache = state.secret_cache_arc();
        let in_flight = state.in_flight_arc();
        {
            let mut guard = cache.lock().expect("secret cache mutex");
            guard.put(
                CacheKey {
                    wrap: "gh".into(),
                    provider: "fake".into(),
                    locator: "x".into(),
                },
                "ghp_value",
            );
        }
        let mut ask = ask_with_secret("gh", &["gh", "api"], "GITHUB_TOKEN");
        ask.dedupe_key.ppid = 9999;
        ask.dedupe_key.parent_start_time = 9999;
        match super::resolve_for_ask(&ask, cache, in_flight) {
            WaiterReply::Decision { decision, secrets } => {
                assert_eq!(decision, Decision::Approve);
                assert_eq!(
                    secrets.get("GITHUB_TOKEN").map(String::as_str),
                    Some("ghp_value"),
                );
            }
            WaiterReply::Err { message } => {
                panic!("expected cache hit, got err: {message}");
            }
        }
    }

    #[test]
    fn concurrent_resolve_for_ask_invokes_provider_once_per_key() {
        // The actual user-facing regression: N parallel asks for the
        // same wrap+secret used to each invoke the provider (= N
        // biometric prompts). Singleflight should reduce that to 1.
        //
        // We exercise the real `resolve_for_ask` path with a real
        // shell-invokable provider whose `retrieve` command appends a
        // line to a tempfile *atomically* via flock, then prints a
        // synthetic secret. After all threads finish, the line count
        // tells us how many times the provider was actually invoked.
        use std::sync::Arc;
        use std::thread;

        let tmp = tempfile::tempdir().expect("tempdir");
        let counter = tmp.path().join("invocations");
        // Pre-create the file so we don't race on first-touch.
        std::fs::write(&counter, b"").expect("create counter");

        // The retrieve command: append a marker line, sleep briefly
        // (so concurrent acquirers have time to pile up on the
        // singleflight slot), then print the synthetic secret.
        // {locator} is substituted by `provider::retrieve`.
        //
        // No explicit lock needed: POSIX guarantees `>>` appends are
        // atomic for writes under PIPE_BUF (typically 512+ bytes), so
        // concurrent `echo invoked` calls each produce one well-formed
        // line in the counter file.
        let script = format!(
            "echo invoked >> {counter}; sleep 0.05; echo secret-{{locator}}",
            counter = counter.display(),
        );

        let mut providers = HashMap::new();
        providers.insert(
            "fake".to_owned(),
            super::super::proto::WireProvider {
                name: "fake".to_owned(),
                retrieve: vec!["sh".to_owned(), "-c".to_owned(), script],
                retrieve_batch: None,
            },
        );

        let make_ask = || Ask {
            command: vec!["gh".to_owned(), "api".to_owned()],
            cwd: String::new(),
            callers: vec![],
            secrets: vec![super::super::proto::SecretAsk {
                name: "GITHUB_TOKEN".to_owned(),
                provider: "fake".to_owned(),
                locator: "x".to_owned(),
                default: None,
                description: None,
                reason: None,
            }],
            providers: providers.clone(),
            dedupe_key: DedupeKey {
                wrap: "gh".to_owned(),
                ppid: 0,
                parent_start_time: 0,
            },
        };

        let state = State::new();
        let cache = state.secret_cache_arc();
        let in_flight = state.in_flight_arc();

        let n = 8;
        let mut handles = Vec::with_capacity(n);
        for _ in 0..n {
            let cache = Arc::clone(&cache);
            let in_flight = Arc::clone(&in_flight);
            let ask = make_ask();
            handles.push(thread::spawn(move || {
                super::resolve_for_ask(&ask, cache, in_flight)
            }));
        }
        let replies: Vec<WaiterReply> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // Every reply must be Approve with the synthetic value — no
        // waiter should see Failed or empty.
        for reply in &replies {
            match reply {
                WaiterReply::Decision { decision, secrets } => {
                    assert_eq!(*decision, Decision::Approve);
                    assert_eq!(
                        secrets.get("GITHUB_TOKEN").map(String::as_str),
                        Some("secret-x"),
                    );
                }
                WaiterReply::Err { message } => panic!("unexpected error reply: {message}"),
            }
        }

        // The provider script appends one line per invocation. With
        // singleflight working, this should be exactly 1 — N threads
        // raced the empty cache, one won, the rest waited.
        let invocations = std::fs::read_to_string(&counter)
            .expect("read counter")
            .lines()
            .count();
        assert_eq!(
            invocations, 1,
            "provider should have been invoked exactly once across {n} concurrent asks; got {invocations}"
        );
    }

    #[test]
    fn evaluate_rules_for_ask_translates_ask_into_a_hit() {
        // End-to-end check that an Ask flowing through
        // State::evaluate_rules_for_ask actually hits a configured
        // rule. The rule's argv pattern is the literal-prefix kind,
        // which makes this also a sanity test that the Ask's
        // `command.join(" ")` lines up with what the evaluator expects.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("auto-rules.json5");
        let rule = mk_rule("01", "gh", RuleDecision::Approve, Some("gh api"));
        crate::rules::save_rules(&path, &[rule]).expect("save");
        let state = State::with_rules_path(path);
        let ask = ask_with_secret("gh", &["gh", "api", "--get", "/repos/x"], "GITHUB_TOKEN");
        let hit = state
            .evaluate_rules_for_ask(&ask)
            .expect("rule should fire");
        assert_eq!(hit.rule_id, "01");
        assert_eq!(hit.decide, RuleDecision::Approve);
    }

    #[test]
    fn add_rule_persists_to_disk_and_does_not_reload_itself() {
        // The crucial property: when the daemon writes a rule via the
        // UI path, the reload check must NOT subsequently reread the
        // file as if it were externally modified. We verify by adding
        // a rule, then asserting the reload is a no-op (rules vec
        // unchanged in length, mtime unchanged).
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("auto-rules.json5");
        let mut state = State::with_rules_path(path.clone());
        let rule = mk_rule("01", "gh", RuleDecision::Approve, Some("gh api"));
        state.add_rule(rule.clone()).expect("add");

        // On-disk content matches.
        let loaded = crate::rules::load_rules(&path).expect("reload");
        assert_eq!(loaded.rules, vec![rule.clone()]);

        let mtime_before = state.rules_loaded_at;
        let len_before = state.rules.len();
        state.reload_rules_if_changed();
        assert_eq!(state.rules.len(), len_before);
        assert_eq!(state.rules_loaded_at, mtime_before);
        assert_eq!(state.rules, vec![rule]);
    }

    #[test]
    fn external_edit_is_reloaded_in_place() {
        // Simulate the hand-edit-while-running case: load an empty
        // ruleset, then have something OTHER than the daemon mutate
        // the file. The next call to reload_rules_if_changed should
        // pick up the new content WITHOUT shutting down or returning
        // an error.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("auto-rules.json5");
        crate::rules::save_rules(&path, &[]).expect("seed");
        let mut state = State::with_rules_path(path.clone());
        assert!(state.rules.is_empty());

        // Wait long enough that mtime granularity sees the change,
        // then write fresh content. (1-second sleep handles even
        // filesystems with second-resolution mtimes.)
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let rule = mk_rule("01", "gh", RuleDecision::Approve, None);
        crate::rules::save_rules(&path, std::slice::from_ref(&rule)).expect("external write");

        state.reload_rules_if_changed();
        assert_eq!(
            state.rules,
            vec![rule],
            "external mtime advance must reload the file in place"
        );
        // The daemon is NOT shut down; the shutdown flag stays clear.
        assert!(
            !state
                .shutdown_flag()
                .load(std::sync::atomic::Ordering::SeqCst),
            "reload must not flip the shutdown flag — the old design did and that broke `secreq view`"
        );
    }

    #[test]
    fn malformed_external_edit_keeps_previous_ruleset() {
        // The reload's error contract: a broken hand-edit must not
        // wipe the in-memory ruleset. We start with one good rule,
        // truncate the file to garbage, then verify the old ruleset
        // survives.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("auto-rules.json5");
        let rule = mk_rule("01", "gh", RuleDecision::Approve, None);
        crate::rules::save_rules(&path, std::slice::from_ref(&rule)).expect("seed");
        let mut state = State::with_rules_path(path.clone());
        assert_eq!(state.rules, vec![rule.clone()]);

        std::thread::sleep(std::time::Duration::from_millis(1100));
        std::fs::write(&path, "{ this is not json5 }").expect("corrupt write");

        state.reload_rules_if_changed();
        assert_eq!(
            state.rules,
            vec![rule],
            "a parse failure during reload must NOT clobber the in-memory ruleset"
        );
    }

    #[test]
    fn delete_rule_removes_from_disk() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("auto-rules.json5");
        let mut state = State::with_rules_path(path.clone());
        let rule = mk_rule("01", "gh", RuleDecision::Approve, None);
        state.add_rule(rule).expect("add");

        state.delete_rule("01").expect("delete");
        let loaded = crate::rules::load_rules(&path).expect("reload");
        assert!(loaded.rules.is_empty());
    }

    #[test]
    fn set_rule_enabled_toggles_in_place() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("auto-rules.json5");
        let mut state = State::with_rules_path(path);
        let rule = mk_rule("01", "gh", RuleDecision::Approve, None);
        state.add_rule(rule).expect("add");

        state.set_rule_enabled("01", false).expect("disable");
        assert!(!state.rules_snapshot()[0].enabled);

        state.set_rule_enabled("01", true).expect("re-enable");
        assert!(state.rules_snapshot()[0].enabled);
    }

    #[test]
    fn add_rule_rejects_duplicate_ids() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("auto-rules.json5");
        let mut state = State::with_rules_path(path);
        let rule = mk_rule("01", "gh", RuleDecision::Approve, None);
        state.add_rule(rule.clone()).expect("first add");
        let err = state.add_rule(rule).expect_err("duplicate add must fail");
        assert!(err.to_string().contains("already exists"));
    }

    /// Newly-attached subscribers default to `focused = true` — macOS
    /// gives a freshly-spawned process foreground intent, so until the
    /// child sends a `ConsentWindowFocus { focused: false }` we treat
    /// the window as in front. This keeps the very first ask after a
    /// fresh window from triggering a redundant restart.
    #[test]
    fn attach_consent_window_defaults_to_focused() {
        let mut state = State::new();
        let (_tx, _rx) = mpsc::channel();
        let (_id, _snap) = state.attach_consent_window(4242, _tx);
        assert!(state.any_consent_focused());
    }

    #[test]
    fn set_consent_focused_flips_per_subscriber_state() {
        let mut state = State::new();
        let (tx, _rx) = mpsc::channel();
        let (id, _snap) = state.attach_consent_window(4242, tx);

        state.set_consent_focused(id, false);
        assert!(!state.any_consent_focused());

        state.set_consent_focused(id, true);
        assert!(state.any_consent_focused());
    }

    /// Unknown subscriber ids must be a no-op: the streaming handler
    /// may drain a focus message after the subscriber has already
    /// detached, and we don't want a panic or a phantom entry from
    /// that race.
    #[test]
    fn set_consent_focused_for_unknown_id_is_a_noop() {
        let mut state = State::new();
        let (tx, _rx) = mpsc::channel();
        let (_id, _snap) = state.attach_consent_window(4242, tx);
        state.set_consent_focused(9999, false);
        // The real subscriber's default `focused = true` survives.
        assert!(state.any_consent_focused());
    }

    /// With no subscriber attached the gate must report false — the
    /// "is the UI alive AND focused" check is what callers actually
    /// want, and "alive" is implied by `any_consent_focused`.
    #[test]
    fn any_consent_focused_is_false_when_no_subscriber_attached() {
        let state = State::new();
        assert!(!state.any_consent_focused());
    }
}
