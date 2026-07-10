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

use anyhow::{Context, Result};
use zeroize::Zeroizing;

use crate::audit::{self, AuditCaller, AuditEntry};
use crate::consent::{ApprovalEntry, Decision, SshGrant};
use crate::manifest::{BatchRetrieve, Manifest, Provider};
use crate::resolve::{self, ResolutionPlan, SecretRequest, Source};
use crate::rules::{self, EvalCtx, Rule, RuleHit};

use super::cache::{CacheKey, SecretCache};
use super::in_flight::{Acquired, InFlightGuard, InFlightMap};
use super::proto::{Ask, DedupeKey, RowStatus, WireProvider};

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
    /// One per still-waiting client — each carries its own reply channel
    /// plus the secrets and command that client asked for.
    pub waiters: Vec<Waiter>,
    /// When this entry was first inserted — drives the UI's "Xs ago" label.
    pub first_seen: Instant,
}

/// A stable per-waiter handle, minted by [`State::submit_ask`]. Lets the
/// connection thread name *its own* waiter when the client hangs up (so
/// [`State::withdraw_waiter`] removes exactly that one, not a sibling that
/// coalesced onto the same entry). Monotonic per daemon; a `u64` counter
/// never realistically overflows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WaiterId(u64);

/// One parked client on a queue entry: where to send its reply, the
/// secrets *it* asked for (so a per-waiter slice can be handed back), the
/// command it's running (for the card's per-secret provenance), plus the
/// `cwd` and caller chain needed to write an audit row if this client
/// exits before the user decides (see [`State::withdraw_waiter`]).
pub struct Waiter {
    /// Stable id so a specific parked client can be withdrawn on hang-up.
    pub id: WaiterId,
    pub sender: mpsc::Sender<WaiterReply>,
    pub requested: Vec<super::proto::SecretAsk>,
    pub command: Vec<String>,
    /// The requesting process's working directory, carried so an
    /// abandoned-ask audit row records *its* cwd, not the daemon's.
    pub cwd: String,
    /// The caller chain at ask time, kept for the abandoned-ask audit row.
    pub callers: Vec<super::proto::Caller>,
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
    /// Awaiting a decision, or already approved with resolution in
    /// flight. Resolving rows render read-only (no Approve/Deny).
    pub status: RowStatus,
}

/// An approved ask whose secrets are being resolved off the queue. We
/// keep it visible as a "Resolving…" card so a biometric prompt the
/// provider fires (on a cold cache) has its provenance on screen
/// instead of popping over an empty window.
struct PendingEntry {
    representative: Ask,
    /// When resolution began — drives the card's "Ns ago" label.
    since: Instant,
}

/// Daemon state. Wrap in `Arc<Mutex<_>>` for sharing.
pub struct State {
    queue: HashMap<DedupeKey, QueueEntry>,
    /// Asks that have been authorized and are now resolving off the
    /// queue (provider call / biometric in flight). Rendered as
    /// read-only "Resolving…" cards. Keyed by dedupe key so sibling
    /// auto-approved asks coalesce into one card.
    pending: HashMap<DedupeKey, PendingEntry>,
    /// "Approve all from X" decisions for the daemon's lifetime. No disk
    /// backing — `secreq daemon stop` is the canonical reset.
    approvals: Vec<ApprovalEntry>,
    /// Remembered SSH sign session grants. Parallel to `approvals` but each
    /// grant carries a wall-clock `expires_at` and a key scope (one key or
    /// all keys): an SSH anchor (shell / IDE / git session) can live for
    /// hours, so a SIGN grant is time-bounded rather than tied to anchor
    /// lifetime alone. See [`SshGrant`] for the rationale behind the
    /// divergences. No disk backing — same `secreq daemon stop` reset as
    /// `approvals`.
    ssh_grants: Vec<SshGrant>,
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
    /// Set by `ClientMsg::ShowViewer` (the `secreq view` command).
    /// Carried on the snapshot stream so a freshly-attached manager
    /// window opens on the Audit view. Cleared when the last manager
    /// window detaches.
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

    // ── Manager-window streaming subscribers ──────────────────────
    //
    // The persistent Rules + Audit window. A separate list from
    // `consent_subscribers` because the manager has a deliberately
    // different lifecycle: it opens on user intent (`secreq view`, the
    // prompt's "Open Manager…"), closes when the user closes it, and is
    // never touched by the prompt's auto-hide / restart-to-raise
    // machinery. It receives the same `ConsentUpdate` snapshot stream
    // (it needs live rules + the viewer-mode flag).
    manager_subscribers: Vec<ManagerSubscriber>,
    /// Monotonic ID source for manager subscribers, independent of the
    /// other counters so the ID spaces stay grep-distinguishable.
    manager_next_subscriber_id: u64,
    /// Spawn-debounce for the manager child, mirroring
    /// `consent_spawn_in_flight_since`.
    manager_spawn_in_flight_since: Option<Instant>,

    // ── Pending-badge streaming subscribers ───────────────────────
    //
    // The always-on-top "N pending" badge child(ren). A separate list
    // from `consent_subscribers` because the badge has a deliberately
    // different lifecycle: it persists while the queue is non-empty
    // (even when the consent window is closed/backgrounded — that's the
    // whole point), never restarts-to-raise, and never reports focus.
    // Keeping it parallel means none of the consent-window focus /
    // restart / auto-hide logic accidentally tears the badge down.
    badge_subscribers: Vec<BadgeSubscriber>,
    /// Monotonic ID source for badge subscribers. Independent of the
    /// consent counter so the two ID spaces stay grep-distinguishable.
    badge_next_subscriber_id: u64,
    /// Spawn-debounce for the badge child, mirroring
    /// `consent_spawn_in_flight_since`: set between `Command::spawn`
    /// and the child's `BadgeWindowAttach` so a burst of asks doesn't
    /// launch N badges. Cleared on attach or after `CONSENT_SPAWN_TIMEOUT`.
    badge_spawn_in_flight_since: Option<Instant>,
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
    /// Monotonic source of [`WaiterId`]s. Independent of the subscriber
    /// counters so the id spaces stay grep-distinguishable.
    waiter_next_id: u64,
}

impl Default for State {
    fn default() -> Self {
        State {
            queue: HashMap::new(),
            pending: HashMap::new(),
            approvals: Vec::new(),
            ssh_grants: Vec::new(),
            secret_cache: Arc::new(Mutex::new(SecretCache::new())),
            in_flight: InFlightMap::new(),
            last_activity: Instant::now(),
            window_visible: false,
            viewer_mode: false,
            shutdown_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            consent_subscribers: Vec::new(),
            consent_next_subscriber_id: 1,
            consent_spawn_in_flight_since: None,
            manager_subscribers: Vec::new(),
            manager_next_subscriber_id: 1,
            manager_spawn_in_flight_since: None,
            badge_subscribers: Vec::new(),
            badge_next_subscriber_id: 1,
            badge_spawn_in_flight_since: None,
            consent_restart_pending: false,
            // Queue starts empty; record the moment so the auto-hide
            // logic has a stable "started counting" anchor.
            queue_empty_since: Some(Instant::now()),
            rules_path: None,
            rules: Vec::new(),
            rules_loaded_at: None,
            waiter_next_id: 1,
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

/// One attached manager-window child (the persistent Rules + Audit
/// surface). Leaner than [`ConsentSubscriber`]: the manager never
/// reports focus and is never kill-and-respawn raised, so it carries
/// only the streaming sender, a detach ID, and the pid the CLI can
/// activate on `secreq view`.
struct ManagerSubscriber {
    id: u64,
    pid: u32,
    tx: mpsc::Sender<super::proto::DaemonMsg>,
}

/// One attached pending-badge child. Deliberately leaner than
/// [`ConsentSubscriber`]: the badge never reports focus and never
/// restarts, so it carries only the streaming sender and a detach ID.
struct BadgeSubscriber {
    id: u64,
    tx: mpsc::Sender<super::proto::DaemonMsg>,
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
        // Same for the badge child(ren) — it reuses `ConsentExitPlease`
        // as its "please exit" signal.
        self.broadcast_badge(super::proto::DaemonMsg::ConsentExitPlease);
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

    // ── Pending-badge subscriber API ─────────────────────────────

    /// Register a pending-badge child. Returns its detach ID and the
    /// initial snapshot to ship immediately so it can paint frame 1
    /// without a round-trip. Mirrors [`attach_consent_window`] but with
    /// no focus state and no foreground intent — the badge is never the
    /// thing the user is "in".
    pub fn attach_badge_window(
        &mut self,
        sender: mpsc::Sender<super::proto::DaemonMsg>,
    ) -> (u64, super::proto::WireSnapshot) {
        let id = self.badge_next_subscriber_id;
        self.badge_next_subscriber_id = id.wrapping_add(1);
        self.badge_spawn_in_flight_since = None;
        self.badge_subscribers
            .push(BadgeSubscriber { id, tx: sender });
        super::log::log_at(
            "state",
            format_args!(
                "badge window attached (id={id}, subscribers={})",
                self.badge_subscribers.len()
            ),
        );
        (id, self.snapshot_for_wire())
    }

    /// Remove a badge subscriber by ID. Called by the badge streaming
    /// connection handler when its read loop exits — same detach-order
    /// contract as [`detach_consent_window`].
    pub fn detach_badge_window(&mut self, id: u64) {
        let before = self.badge_subscribers.len();
        self.badge_subscribers.retain(|s| s.id != id);
        let after = self.badge_subscribers.len();
        super::log::log_at(
            "state",
            format_args!("badge window detached (id={id}, subscribers {before}→{after})"),
        );
    }

    /// Number of currently-attached badge children.
    pub fn badge_subscriber_count(&self) -> usize {
        self.badge_subscribers.len()
    }

    /// Should the daemon ensure a pending-badge child is running? True
    /// iff there's at least one ask awaiting a decision and no badge is
    /// already up. Resolving (already-approved) cards don't count — the
    /// badge surfaces *undecided* requests, the ones a process is hung
    /// on, not work that's merely finishing.
    pub fn needs_badge_window(&self) -> bool {
        !self.queue.is_empty() && self.badge_subscribers.is_empty()
    }

    /// True if a badge `Command::spawn` is in flight and we shouldn't
    /// start another. Stale entries auto-clear after
    /// [`CONSENT_SPAWN_TIMEOUT`] (shared constant — the spawn race is
    /// identical to the consent window's).
    pub fn badge_spawn_in_flight(&mut self) -> bool {
        if let Some(at) = self.badge_spawn_in_flight_since {
            if at.elapsed() < CONSENT_SPAWN_TIMEOUT {
                return true;
            }
            self.badge_spawn_in_flight_since = None;
        }
        false
    }

    /// Record that a badge `Command::spawn` has just been kicked off.
    pub fn mark_badge_spawn_in_flight(&mut self) {
        self.badge_spawn_in_flight_since = Some(Instant::now());
    }

    /// Tell every attached badge child to exit. Sent when the queue
    /// drains — the badge has nothing left to count, so it should
    /// vanish. No-op if no badge is attached. Unlike
    /// [`broadcast_consent_exit_please`] this doesn't touch
    /// `queue_empty_since`: the badge has no auto-hide grace period, it
    /// just goes the moment the last awaiting ask resolves.
    pub fn broadcast_badge_exit_please(&mut self) {
        if self.badge_subscribers.is_empty() {
            return;
        }
        self.broadcast_badge(super::proto::DaemonMsg::ConsentExitPlease);
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
    /// fresh process.
    pub fn any_consent_focused(&self) -> bool {
        self.consent_subscribers.iter().any(|s| s.focused)
    }

    // ── Manager-window subscriber API ────────────────────────────

    /// Register a manager-window child. Returns its detach ID and the
    /// initial snapshot to ship immediately so it can paint frame 1
    /// without a round-trip. Mirrors [`attach_consent_window`] but the
    /// manager carries no focus state — it's never restart-raised.
    pub fn attach_manager_window(
        &mut self,
        pid: u32,
        sender: mpsc::Sender<super::proto::DaemonMsg>,
    ) -> (u64, super::proto::WireSnapshot) {
        let id = self.manager_next_subscriber_id;
        self.manager_next_subscriber_id = id.wrapping_add(1);
        self.manager_spawn_in_flight_since = None;
        self.manager_subscribers.push(ManagerSubscriber {
            id,
            pid,
            tx: sender,
        });
        super::log::log_at(
            "state",
            format_args!(
                "manager window attached (id={id}, pid={pid}, subscribers={})",
                self.manager_subscribers.len()
            ),
        );
        (id, self.snapshot_for_wire())
    }

    /// Remove a manager subscriber by ID — same detach-order contract
    /// as [`detach_consent_window`]. When the last manager detaches,
    /// viewer mode clears: the pin belonged to the window the user just
    /// closed, and the next `secreq view` re-sets it.
    pub fn detach_manager_window(&mut self, id: u64) {
        let before = self.manager_subscribers.len();
        self.manager_subscribers.retain(|s| s.id != id);
        let after = self.manager_subscribers.len();
        super::log::log_at(
            "state",
            format_args!("manager window detached (id={id}, subscribers {before}→{after})"),
        );
        if self.manager_subscribers.is_empty() {
            self.viewer_mode = false;
        }
    }

    /// Number of currently-attached manager-window children.
    pub fn manager_subscriber_count(&self) -> usize {
        self.manager_subscribers.len()
    }

    /// First attached manager child's pid, if any — handed back on
    /// `ShowViewer` so the CLI can activate the existing window.
    pub fn manager_child_pid(&self) -> Option<u32> {
        self.manager_subscribers.first().map(|s| s.pid)
    }

    /// Should `ensure_manager_window` spawn a child? True iff none is
    /// attached (the manager spawns on demand, never from queue state).
    pub fn needs_manager_window(&self) -> bool {
        self.manager_subscribers.is_empty()
    }

    /// True if a manager `Command::spawn` is in flight and we shouldn't
    /// start another. Stale entries auto-clear after
    /// [`CONSENT_SPAWN_TIMEOUT`] (shared constant — same race shape).
    pub fn manager_spawn_in_flight(&mut self) -> bool {
        if let Some(at) = self.manager_spawn_in_flight_since {
            if at.elapsed() < CONSENT_SPAWN_TIMEOUT {
                return true;
            }
            self.manager_spawn_in_flight_since = None;
        }
        false
    }

    /// Record that a manager `Command::spawn` has just been kicked off.
    pub fn mark_manager_spawn_in_flight(&mut self) {
        self.manager_spawn_in_flight_since = Some(Instant::now());
    }

    /// Push `msg` to every attached manager child, pruning dead senders.
    fn broadcast_manager(&mut self, msg: super::proto::DaemonMsg) {
        self.manager_subscribers
            .retain(|s| s.tx.send(msg.clone()).is_ok());
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
        // "Empty" for auto-hide purposes means nothing for the user to
        // look at — neither awaiting nor resolving cards. A resolving
        // card must keep the window up (and the grace clock unstarted)
        // until its biometric prompt clears.
        if self.queue.is_empty() && self.pending.is_empty() {
            if self.queue_empty_since.is_none() {
                self.queue_empty_since = Some(Instant::now());
            }
        } else {
            self.queue_empty_since = None;
        }
    }

    /// Close the prompt window *immediately* on drain. Called right
    /// after the queue-empty timestamp is refreshed on the resolve path.
    ///
    /// The main loop's [`AUTO_HIDE_GRACE`](super::AUTO_HIDE_GRACE) exists
    /// to leave a confirmation on screen for a beat — but the prompt is a
    /// pure decision surface now (Rules/Audit live in the manager
    /// window), so there's nothing to linger over once the last ask
    /// resolves. The grace-timed main-loop path remains as a fallback
    /// for a prompt that attaches after the drain. No subscribers
    /// attached → nothing to close (the broadcast is a no-op and leaves
    /// the grace clock armed).
    fn maybe_immediate_auto_hide(&mut self) {
        if self.queue_empty_since.is_none() {
            return;
        }
        self.broadcast_consent_exit_please();
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

    /// Should the daemon ensure a consent-prompt child is running?
    /// True iff there's a decision (or a resolving card) for the user
    /// to see *and* nobody is already there to see it. Viewer mode is
    /// the manager window's business, not the prompt's.
    pub fn needs_consent_window(&self) -> bool {
        (!self.queue.is_empty() || !self.pending.is_empty()) && self.consent_subscribers.is_empty()
    }

    /// Push the current snapshot to every attached consent window.
    /// Senders whose receiver has been dropped (child exited) are
    /// pruned out.
    pub fn broadcast_consent_update(&mut self) {
        let snapshot = self.snapshot_for_wire();
        let msg = super::proto::DaemonMsg::ConsentUpdate { snapshot };
        // Same snapshot feeds all three surfaces: the prompt renders
        // the queue, the manager needs the live rules + viewer-mode
        // flag, and the badge just counts `Awaiting` rows.
        self.broadcast(msg.clone());
        self.broadcast_manager(msg.clone());
        self.broadcast_badge(msg);
    }

    fn broadcast(&mut self, msg: super::proto::DaemonMsg) {
        self.consent_subscribers
            .retain(|s| s.tx.send(msg.clone()).is_ok());
    }

    /// Push `msg` to every attached badge child, pruning senders whose
    /// receiver has dropped (badge exited / crashed).
    fn broadcast_badge(&mut self, msg: super::proto::DaemonMsg) {
        self.badge_subscribers
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
                status: RowStatus::Awaiting,
            })
            .chain(self.pending.values().map(|p| super::proto::WireQueueRow {
                key: p.representative.dedupe_key.clone(),
                representative: p.representative.clone(),
                waiter_count: 0,
                first_seen_secs_ago: now.saturating_duration_since(p.since).as_secs(),
                status: RowStatus::Resolving,
            }))
            .collect();
        super::proto::WireSnapshot {
            queue,
            viewer_mode: self.viewer_mode,
            rules: self.rules.clone(),
        }
    }

    /// True if some ancestor in the caller chain has a remembered
    /// approval for this wrap — i.e. the ask can be short-circuited
    /// without prompting. The matched scope itself isn't used
    /// downstream (the secret cache keys on `(wrap, provider, locator)`,
    /// not on which parent was approved), so we return a bool. The
    /// caller resolves via [`resolve_approved_with_pending`] so the
    /// provider call runs *without* the state lock held — and shows a
    /// "Resolving…" card if the secret cache is cold.
    pub fn has_cached_approval(&self, ask: &Ask) -> bool {
        approval_scope_for(&self.approvals, ask).is_some()
    }

    // ── SSH sign session grants ──────────────────────────────────────
    //
    // The SSH analogue of the wrap approvals cache above. Same in-memory,
    // no-disk-backing model — but each grant carries a wall-clock TTL and a
    // key scope (see [`SshGrant`]). The wrap cache reads no clock (the parent
    // process's lifetime is its natural expiry); the SSH cache does, so its
    // lookup is split into a public `has_ssh_grant` that reads
    // `SystemTime::now()` and a private `has_ssh_grant_at(now)` that takes
    // the clock explicitly — the latter is what the unit test drives.

    /// True if a non-expired SSH grant covers `(key_id, anchor_pid,
    /// anchor_start_time)` as of *now*. Prunes expired grants on access.
    /// Reads the wall clock; see [`State::has_ssh_grant_at`] for the
    /// clock-injectable form the tests use.
    pub fn has_ssh_grant(&mut self, key_id: &str, anchor_pid: u32, anchor_start_time: u64) -> bool {
        self.has_ssh_grant_at(key_id, anchor_pid, anchor_start_time, now_unix_secs())
    }

    /// Clock-injectable core of [`State::has_ssh_grant`]. Prunes every grant
    /// that has expired as of `now`, then reports whether any surviving grant
    /// covers the anchor + key.
    fn has_ssh_grant_at(
        &mut self,
        key_id: &str,
        anchor_pid: u32,
        anchor_start_time: u64,
        now: u64,
    ) -> bool {
        self.ssh_grants.retain(|g| now < g.expires_at);
        self.ssh_grants
            .iter()
            .any(|g| g.matches(key_id, anchor_pid, anchor_start_time, now))
    }

    /// Remember an SSH sign session grant. Dedupes on the full grant so a
    /// re-approval with the same scope/anchor/expiry is a no-op; a re-approval
    /// with a later expiry is a distinct grant and both coexist harmlessly —
    /// the latest still-valid one wins on lookup.
    pub fn remember_ssh_grant(&mut self, grant: SshGrant) {
        if !self.ssh_grants.contains(&grant) {
            self.ssh_grants.push(grant);
        }
    }

    /// Mark an authorized ask as resolving: show a read-only card in
    /// the consent window while its provider call (and any biometric
    /// prompt) runs. Idempotent per dedupe key so a burst of sibling
    /// auto-approved asks coalesces into one card. Keeps the window up
    /// and the auto-hide clock unstarted until [`end_pending`].
    pub fn begin_pending(&mut self, ask: Ask) {
        self.last_activity = Instant::now();
        self.queue_empty_since = None;
        self.pending
            .entry(ask.dedupe_key.clone())
            .or_insert_with(|| PendingEntry {
                representative: ask,
                since: Instant::now(),
            });
        self.show_window();
        self.broadcast_consent_update();
    }

    /// Clear a resolving card once its secrets have landed (or failed).
    /// No-op if the key was already cleared by a coalesced sibling.
    pub fn end_pending(&mut self, key: &DedupeKey) {
        if self.pending.remove(key).is_some() {
            self.last_activity = Instant::now();
            self.broadcast_consent_update();
            self.refresh_queue_empty_since();
            self.maybe_immediate_auto_hide();
        }
    }

    /// Add a waiter for `key`, either folding into an existing queue entry
    /// or creating a new one with `ask` as the representative.
    /// Enqueue (or coalesce) an ask and park a waiter on it. Returns the
    /// [`SubmitResult`] (new entry vs. coalesced onto an existing one) and
    /// the [`WaiterId`] the caller passes to [`State::withdraw_waiter`] if
    /// its client hangs up before the user decides.
    pub fn submit_ask(
        &mut self,
        ask: Ask,
        waiter: mpsc::Sender<WaiterReply>,
    ) -> (SubmitResult, WaiterId) {
        self.last_activity = Instant::now();
        // Queue is about to become non-empty (or stay non-empty);
        // either way the auto-hide grace clock should be reset.
        self.queue_empty_since = None;
        let key = ask.dedupe_key.clone();
        let is_new = !self.queue.contains_key(&key);
        // Command label stamped onto each merged secret's provenance. The
        // plan uses the full joined command; the UI truncates it.
        let command_label = ask.command.join(" ");
        let entry = self.queue.entry(key.clone()).or_insert_with(|| QueueEntry {
            key: key.clone(),
            // Build the representative's secrets by folding the creating
            // ask's own secrets through `merge_secret`, so even the first
            // ask's secrets carry `← command` provenance.
            representative: Ask {
                secrets: {
                    let mut rep = Vec::new();
                    for s in &ask.secrets {
                        merge_secret(&mut rep, s, &command_label);
                    }
                    rep
                },
                ..ask.clone()
            },
            waiters: Vec::new(),
            first_seen: Instant::now(),
        });
        if !is_new {
            // Coalesce: union this ask's secrets into the growing
            // representative, stamping each with this ask's command.
            for s in &ask.secrets {
                merge_secret(&mut entry.representative.secrets, s, &command_label);
            }
        }
        let waiter_id = WaiterId(self.waiter_next_id);
        self.waiter_next_id += 1;
        entry.waiters.push(Waiter {
            id: waiter_id,
            sender: waiter,
            requested: ask.secrets.clone(),
            command: ask.command.clone(),
            cwd: ask.cwd.clone(),
            callers: ask.callers.clone(),
        });
        self.show_window();
        self.broadcast_consent_update();
        let result = if is_new {
            SubmitResult::NewEntry
        } else {
            SubmitResult::Coalesced
        };
        (result, waiter_id)
    }

    /// Read a queue entry by key. Test-only: lets the state tests inspect
    /// the parked waiters (their recorded `requested` / `command`) without
    /// exposing the private `queue` map in production.
    #[cfg(test)]
    fn queue_entry_for_test(&self, key: &DedupeKey) -> Option<&QueueEntry> {
        self.queue.get(key)
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
    ///
    /// On an approved ask with a **cold** secret cache, the entry is
    /// moved into `pending` (a "Resolving…" card) rather than dropped,
    /// so the biometric prompt the provider fires has its provenance on
    /// screen; the worker clears the card via `shared` once the value
    /// lands. `shared` is the daemon's own `Arc<Mutex<State>>` — the
    /// sole caller already holds it, so we take it explicitly rather
    /// than keep a self-referential handle.
    pub fn resolve(
        &mut self,
        key: &DedupeKey,
        decision: Decision,
        scope: ApprovalScope,
        shared: &SharedState,
    ) {
        self.last_activity = Instant::now();
        let Some(entry) = self.queue.remove(key) else {
            self.broadcast_consent_update();
            self.refresh_queue_empty_since();
            self.maybe_immediate_auto_hide();
            return;
        };

        // SSH asks track their session grants separately via `SshGrant`
        // (keyed on the anchor, inserted on the SSH path); the wrap approvals
        // cache is never read for them, so skip the insert to avoid polluting
        // it with dead entries.
        if decision == Decision::ApproveRemember
            && entry.representative.ssh.is_none()
            && entry.representative.allow_remember
        {
            let new = ApprovalEntry {
                wrap: key.wrap.clone(),
                ppid: scope.pid,
                parent_start_time: scope.start_time,
            };
            if !self.approvals.contains(&new) {
                self.approvals.push(new);
            }
        }

        // Cold cache → a provider call (and maybe a biometric) is
        // imminent. Keep the card on screen as "Resolving…" so the
        // prompt isn't orphaned; the worker clears it when done.
        let cold =
            decision.approved() && !ask_fully_cached(&entry.representative, &self.secret_cache);
        if cold {
            self.pending.insert(
                key.clone(),
                PendingEntry {
                    representative: entry.representative.clone(),
                    since: Instant::now(),
                },
            );
        }

        self.broadcast_consent_update();
        // Queue may have just emptied — set the timestamp so the
        // auto-hide grace period starts counting (suppressed while a
        // resolving card is up). Main loop reads this each tick and
        // broadcasts `ConsentExitPlease` once the grace elapses.
        self.refresh_queue_empty_since();
        // For a decision-only window, skip the grace entirely and close
        // now. A cold approve keeps a resolving card up (queue not yet
        // "empty"), so this fires from `end_pending` once the value lands.
        self.maybe_immediate_auto_hide();

        if decision.approved() {
            // Resolution lives off-thread so the UI never blocks on a
            // provider invocation. The worker owns the entry (and thus
            // the waiter senders); when it finishes, secrets land on the
            // socket connection threads parked on the channel.
            let cache = self.secret_cache.clone();
            let in_flight = self.in_flight.clone();
            let shared = shared.clone();
            let key = key.clone();
            std::thread::spawn(move || {
                // Resolve the union once (singleflight dedupes provider
                // calls across the batch), keyed by (provider, locator).
                let union = resolve_union(&entry.representative, cache, in_flight);
                // Then hand each waiter back ONLY the secrets its own ask
                // requested — looked up by (provider, locator) so a
                // same-name-different-ref sibling never leaks in. A waiter
                // whose full slice resolved gets Decision; one missing any
                // of its keys gets Err (per-waiter, not all-or-nothing).
                for w in &entry.waiters {
                    let mut secrets = HashMap::new();
                    let mut failure: Option<String> = None;
                    for s in &w.requested {
                        match union.get(&(s.provider.clone(), s.locator.clone())) {
                            Some(Ok(value)) => {
                                secrets.insert(s.name.clone(), value.clone());
                            }
                            Some(Err(msg)) => {
                                failure.get_or_insert_with(|| msg.clone());
                            }
                            None => {
                                failure.get_or_insert_with(|| {
                                    format!("secret `{}` was not resolved for this session", s.name)
                                });
                            }
                        }
                    }
                    let reply = match failure {
                        Some(message) => WaiterReply::Err { message },
                        None => WaiterReply::Decision { decision, secrets },
                    };
                    let _ = w.sender.send(reply);
                }
                // Clear the "Resolving…" card now that the value is
                // cached (or the resolve failed). Skipped when warm
                // (no card was shown). Best-effort: a daemon mid-
                // shutdown may have poisoned/dropped the mutex.
                if cold {
                    if let Ok(mut guard) = shared.lock() {
                        guard.end_pending(&key);
                    }
                }
            });
        } else {
            // Deny is just message-passing; no need to spawn for it.
            let reply = WaiterReply::Decision {
                decision,
                secrets: HashMap::new(),
            };
            for w in &entry.waiters {
                let _ = w.sender.send(reply.clone());
            }
        }
    }

    /// Build the `abandoned` audit row for a withdrawn waiter. The wrap
    /// name comes from the dedupe key; `args` is the waiter's command with
    /// a leading element stripped iff it duplicates the wrap name — `x`
    /// asks send `[wrap, args…]` (so we drop the wrap), while `run`/`read`
    /// send the bare command (nothing to drop), reconstructing exactly the
    /// `args` the live client would have logged.
    fn abandoned_audit_entry(key: &DedupeKey, waiter: &Waiter) -> AuditEntry {
        let args: &[String] = match waiter.command.split_first() {
            Some((first, rest)) if first == &key.wrap => rest,
            _ => &waiter.command,
        };
        let callers: Vec<AuditCaller> = waiter
            .callers
            .iter()
            .map(|c| AuditCaller {
                pid: c.pid,
                name: c.name.clone(),
                command: c.command.clone(),
            })
            .collect();
        let secret_names: Vec<String> = waiter.requested.iter().map(|s| s.name.clone()).collect();
        AuditEntry::abandoned(&key.wrap, args, &waiter.cwd, &callers, &secret_names)
    }

    /// Remove a single parked waiter whose client exited before the user
    /// decided. Writes an `abandoned` audit row for that command (the
    /// daemon does this itself — there's no live client left to write it,
    /// the second documented exception to "the daemon never writes audit
    /// rows", alongside SSH signs), drops the waiter (closing its reply
    /// channel, which unblocks the parked connection thread), and — if it
    /// was the last waiter on the entry — removes the entry so the card
    /// leaves the requests view and the window can auto-hide.
    ///
    /// Idempotent: a no-op if the key or waiter id is gone (the user just
    /// resolved it, or a duplicate hang-up already fired). Both this and
    /// [`State::resolve`] run under the state mutex, so the "user approves
    /// at the same instant the client dies" race collapses to whichever
    /// wins — the loser finds the entry already gone and does nothing.
    pub fn withdraw_waiter(&mut self, key: &DedupeKey, waiter_id: WaiterId) {
        self.last_activity = Instant::now();
        // Already resolved (moved to `pending`) or never here → nothing to do.
        let Some(entry) = self.queue.get_mut(key) else {
            return;
        };
        let Some(pos) = entry.waiters.iter().position(|w| w.id == waiter_id) else {
            return;
        };
        // Removing the waiter drops its `Sender`; the reply-writer thread's
        // `recv()` then returns `Err` and that thread exits cleanly.
        let waiter = entry.waiters.remove(pos);

        let audit_entry = State::abandoned_audit_entry(key, &waiter);
        if let Err(err) = audit::append(&audit_entry) {
            super::log::log_at(
                "state",
                format_args!("audit append failed for abandoned ask: {err:#}"),
            );
        }

        // Drop the whole entry once its last waiter is gone. A still-
        // populated entry stays (coalesced siblings are still waiting),
        // just with a smaller waiter count.
        if entry.waiters.is_empty() {
            self.queue.remove(key);
        }

        self.broadcast_consent_update();
        self.refresh_queue_empty_since();
        self.maybe_immediate_auto_hide();
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
                status: RowStatus::Awaiting,
            })
            .chain(self.pending.values().map(|p| QueueRow {
                key: p.representative.dedupe_key.clone(),
                representative: p.representative.clone(),
                waiter_count: 0,
                first_seen: p.since,
                status: RowStatus::Resolving,
            }))
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

    /// `secreq view`: flag viewer mode so a freshly-attached manager
    /// child opens on the Audit view (the flag rides the snapshot
    /// stream). Cleared when the last manager window detaches.
    pub fn enter_viewer_mode(&mut self) {
        self.viewer_mode = true;
        self.broadcast_consent_update();
    }

    /// Called when the consent-prompt child detaches (close button,
    /// process exit, crash).
    pub fn hide_window(&mut self) {
        self.window_visible = false;
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
    /// approvals cache is checked *before* rules evaluate (via
    /// `has_cached_approval`), so a rule edit doesn't actually invalidate
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
    pub(super) fn map_decision<F: FnOnce(Decision) -> Decision>(self, f: F) -> WaiterReply {
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

/// Current Unix time in whole seconds. Used by the public SSH-approval
/// lookup; the clock-injectable `*_at` form takes `now` directly so tests
/// never touch the real clock.
fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Merge `incoming` into the union `rep`, deduped by `(name, provider,
/// locator)`. A duplicate appends `command` to the existing entry's
/// `requested_by` (deduped); a new secret is pushed, stamped with
/// `command`.
fn merge_secret(
    rep: &mut Vec<super::proto::SecretAsk>,
    incoming: &super::proto::SecretAsk,
    command: &str,
) {
    if let Some(existing) = rep.iter_mut().find(|s| {
        s.name == incoming.name && s.provider == incoming.provider && s.locator == incoming.locator
    }) {
        if !existing.requested_by.iter().any(|c| c == command) {
            existing.requested_by.push(command.to_owned());
        }
    } else {
        let mut secret = incoming.clone();
        secret.requested_by = vec![command.to_owned()];
        rep.push(secret);
    }
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
/// gates a lookup. The approvals-cache path (`has_cached_approval`
/// matched), the manual-approve path (`State::resolve`), and the
/// auto-rule path (`handle_rule_hit` after the rule fires) all call in
/// only once they've confirmed the ask is allowed.
///
/// Running off-thread, so blocking on `op read` etc. is fine here.
///
/// True if every secret the ask needs is already in the cache — i.e.
/// resolving it will invoke no provider and so trigger no biometric
/// prompt. Vacuously true for a gate-only ask (no secrets). Used to
/// decide whether a "Resolving…" card is worth showing: if the value
/// is already cached, resolution is instant and silent.
pub(super) fn ask_fully_cached(ask: &Ask, cache: &Arc<Mutex<SecretCache>>) -> bool {
    let guard = cache.lock().expect("secret cache mutex");
    ask.secrets.iter().all(|s| {
        guard
            .get(&CacheKey {
                wrap: ask.dedupe_key.wrap.clone(),
                provider: s.provider.clone(),
                locator: s.locator.clone(),
            })
            .is_some()
    })
}

/// Should a nested `run` be served straight from the secret cache without
/// showing the consent window? True **only** when the ask is marked
/// `nested_run` (an inner `run` that detected an ancestor run's session
/// marker) **and** every value is already cached, so resolution invokes
/// no provider. An unnested run (`nested_run == false`) or any uncached
/// secret returns false → the ask prompts. This is the sole window-skip
/// for `run`: gating it on nesting guarantees a fresh top-level run
/// always prompts, no matter how warm the cache is.
pub(super) fn nested_run_fully_cached(ask: &Ask, cache: &Arc<Mutex<SecretCache>>) -> bool {
    ask.nested_run && ask_fully_cached(ask, cache)
}

/// Run [`resolve::resolve_all`], logging its wall-clock cost to
/// `daemon.log` under the `resolve` tag.
///
/// This is the daemon's window into a slow 1Password read: `resolve_all`
/// spawns one `op run … printenv` per provider group, and that subprocess
/// dominates the elapsed time (parsing its output is negligible). The line
/// records the batch size, the providers involved, the total wall time, and
/// the per-secret average — enough to see "N secrets cost T seconds, so each
/// `op://` reference is ~T/N" without attaching a profiler. Both resolver
/// call sites (`resolve_for_ask`, `resolve_union`) go through here so the
/// timing line is identical regardless of path.
fn resolve_all_logged(
    manifest: &Manifest,
    plan: &ResolutionPlan,
) -> Result<Vec<resolve::ResolvedSecret>> {
    let secret_count = plan.requests.len();
    let mut providers: Vec<&str> = plan.requests.iter().map(|r| r.provider.as_str()).collect();
    providers.sort_unstable();
    providers.dedup();

    let started = Instant::now();
    let result = resolve::resolve_all(manifest, plan);
    let elapsed = started.elapsed();

    let per_secret_ms = if secret_count > 0 {
        elapsed.as_secs_f64() * 1000.0 / secret_count as f64
    } else {
        0.0
    };
    match &result {
        Ok((_resolved, stats)) => super::log::log_at(
            "resolve",
            format_args!(
                "resolve_all: {secret_count} secret(s) across {} provider(s) [{}] in {:.3}s ({per_secret_ms:.0}ms/secret): \
                 batch subprocess {:.3}s + parse {:.1}ms, {} batched / {} per-secret → ok",
                providers.len(),
                providers.join(","),
                elapsed.as_secs_f64(),
                stats.batch_subprocess.as_secs_f64(),
                stats.batch_parse.as_secs_f64() * 1000.0,
                stats.batched,
                stats.per_secret,
            ),
        ),
        Err(err) => super::log::log_at(
            "resolve",
            format_args!(
                "resolve_all: {secret_count} secret(s) across {} provider(s) [{}] in {:.3}s → err: {err:#}",
                providers.len(),
                providers.join(","),
                elapsed.as_secs_f64(),
            ),
        ),
    }
    result.map(|(resolved, _stats)| resolved)
}

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
    match resolve_all_logged(&manifest, &plan) {
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

/// Resolve the distinct `(provider, locator)` pairs of `rep`'s secrets,
/// returning a map keyed by `(provider, locator)` so the caller can hand
/// each waiter back exactly the values *it* asked for. The key isolation
/// primitive for session aggregation: a name-keyed map would collapse two
/// union entries that share a name but differ by ref (`FOO=…/a` vs
/// `FOO=…/b`); `(provider, locator)` keeps them distinct.
///
/// Reuses the same cache + singleflight machinery as [`resolve_for_ask`]
/// (the cache key is already `(wrap, provider, locator)`): a hit
/// short-circuits, a miss acquires the singleflight slot, and this thread's
/// resolver-owned keys batch into one `resolve::resolve_all` invocation.
/// Never resolves a `(provider, locator)` more than once even if several
/// union entries share it — distinct pairs are collected up front.
///
/// Each entry in the returned map is `Ok(value)` or `Err(message)` for that
/// specific pair, so a caller can succeed a waiter whose slice resolved
/// cleanly while erroring only the waiters that needed a failed pair.
fn resolve_union(
    rep: &Ask,
    cache: Arc<Mutex<SecretCache>>,
    in_flight: Arc<InFlightMap>,
) -> HashMap<(String, String), Result<String, String>> {
    let wrap = rep.dedupe_key.wrap.clone();

    // Collect the distinct (provider, locator) pairs, remembering the first
    // SecretAsk seen for each so provider-facing metadata (reason,
    // description, default) is preserved. Insertion order is stable so the
    // resolve batch mirrors arrival order.
    let mut order: Vec<(String, String)> = Vec::new();
    let mut first_ask: HashMap<(String, String), &super::proto::SecretAsk> = HashMap::new();
    for s in &rep.secrets {
        let pl = (s.provider.clone(), s.locator.clone());
        first_ask.entry(pl.clone()).or_insert_with(|| {
            order.push(pl);
            s
        });
    }

    let mut out: HashMap<(String, String), Result<String, String>> = HashMap::new();
    // Keys this thread owns the singleflight slot for, paired with the
    // synthetic request name we resolve them under (unique per pair, so a
    // shared user-facing name never collapses two pairs in the resolver
    // output map).
    let mut needs_resolve: Vec<((String, String), String)> = Vec::new();
    let mut guards: Vec<InFlightGuard> = Vec::new();

    for pl in &order {
        let (provider, locator) = pl;
        let key = CacheKey {
            wrap: wrap.clone(),
            provider: provider.clone(),
            locator: locator.clone(),
        };
        // Cache check — held only for the lookup.
        {
            let guard = cache.lock().expect("secret cache mutex");
            if let Some(value) = guard.get(&key) {
                out.insert(pl.clone(), Ok((*value).clone()));
                continue;
            }
        }
        // Miss → singleflight.
        match in_flight.acquire(&key) {
            Acquired::Resolver(g) => {
                // Unique synthetic name so `resolve_all`'s name-keyed output
                // can't collapse two same-user-name pairs. It must be a valid
                // **environment variable name**: the batch path
                // (`retrieve_batch`, e.g. `op run -- printenv`) sets one env
                // var per request keyed on this name, and `Command::env`
                // rejects NUL bytes — an index keeps it unique *and* legal
                // (a `provider\0locator` join silently broke every batch,
                // forcing slow per-secret fallback).
                let req_name = format!("secreq_req_{}", needs_resolve.len());
                needs_resolve.push((pl.clone(), req_name));
                guards.push(g);
            }
            Acquired::Ready => {
                let guard = cache.lock().expect("secret cache mutex");
                match guard.get(&key) {
                    Some(value) => {
                        out.insert(pl.clone(), Ok((*value).clone()));
                    }
                    None => {
                        // Ready-but-empty: treat as a per-pair failure. Do
                        // NOT fail this thread's other guards — those pairs
                        // may still resolve fine; the batch runs below.
                        out.insert(
                            pl.clone(),
                            Err(format!(
                                "in-flight slot for {provider}/{locator} signalled ready but cache was empty",
                            )),
                        );
                    }
                }
            }
            Acquired::Failed(msg) => {
                out.insert(pl.clone(), Err(msg));
            }
        }
    }

    if needs_resolve.is_empty() {
        return out;
    }

    let manifest = build_manifest(&rep.providers);
    let plan = ResolutionPlan {
        requests: needs_resolve
            .iter()
            .map(|((provider, locator), req_name)| {
                let ask = first_ask[&(provider.clone(), locator.clone())];
                SecretRequest {
                    name: req_name.clone(),
                    provider: provider.clone(),
                    locator: locator.clone(),
                    group: None,
                    reason: ask.reason.clone(),
                    description: ask.description.clone(),
                    default: ask.default.clone(),
                    source: Source::Eager,
                }
            })
            .collect(),
    };
    match resolve_all_logged(&manifest, &plan) {
        Ok(resolved) => {
            let by_req: HashMap<String, _> =
                resolved.into_iter().map(|r| (r.name, r.value)).collect();
            let mut guard = cache.lock().expect("secret cache mutex");
            for ((provider, locator), req_name) in &needs_resolve {
                let pl = (provider.clone(), locator.clone());
                match by_req.get(req_name) {
                    Some(value) => {
                        let exposed = value.expose().to_owned();
                        guard.put(
                            CacheKey {
                                wrap: wrap.clone(),
                                provider: provider.clone(),
                                locator: locator.clone(),
                            },
                            &exposed,
                        );
                        out.insert(pl, Ok(exposed));
                    }
                    None => {
                        out.insert(
                            pl,
                            Err(format!(
                                "provider {provider} returned no value for {locator}"
                            )),
                        );
                    }
                }
            }
            drop(guard);
            // Cache populated → wake parked waiters (also drops the slots).
            for g in guards {
                g.mark_ready();
            }
        }
        Err(err) => {
            let msg = format!("{err:#}");
            // The whole batch failed: every resolver-owned pair failed.
            // Fail the slots so concurrent waiters on those keys see a real
            // error rather than the "did not signal" default.
            fail_guards(guards, &msg);
            for ((provider, locator), _req_name) in &needs_resolve {
                out.insert((provider.clone(), locator.clone()), Err(msg.clone()));
            }
        }
    }

    out
}

/// Resolve a **single** secret through the shared encrypted cache + the
/// singleflight coordinator, returning the value in a [`Zeroizing`] buffer.
///
/// This is the single-key analogue of [`resolve_for_ask`], used by the SSH
/// sign path so a resolved private key is cached under
/// `CacheKey { wrap: "ssh:<key_id>", provider, locator }` exactly like any
/// other secret — the provider (and its biometric prompt) is invoked at most
/// once per key per daemon lifetime, instead of on every sign. The wrap path
/// keeps using `resolve_for_ask` so it can batch multiple secrets into one
/// provider call; the SSH path only ever has one key, so it doesn't need the
/// batch machinery, but it does need the cache + singleflight, which this
/// function provides without the plaintext-`String` reply map.
///
/// On a cache hit it returns immediately. On a miss it either becomes the
/// resolver (invokes the provider, populates the cache, signals waiters) or
/// parks until another thread's resolve completes and reads the freshly
/// cached value. Every error path marks the in-flight slot failed so parked
/// waiters get a real error instead of hanging.
pub(super) fn resolve_single_cached(
    cache: &Arc<Mutex<SecretCache>>,
    in_flight: &Arc<InFlightMap>,
    key: CacheKey,
    name: &str,
    reason: Option<&str>,
    providers: &std::collections::BTreeMap<String, Provider>,
) -> Result<Zeroizing<String>> {
    // Cache check — lock held only for the lookup.
    {
        let guard = cache.lock().expect("secret cache mutex");
        if let Some(value) = guard.get(&key) {
            return Ok(value);
        }
    }
    // Miss → singleflight, mirroring `resolve_for_ask`.
    match in_flight.acquire(&key) {
        Acquired::Resolver(g) => {
            let manifest = Manifest {
                groups: std::collections::BTreeMap::new(),
                providers: providers.clone(),
            };
            let plan = ResolutionPlan {
                requests: vec![SecretRequest {
                    name: name.to_owned(),
                    provider: key.provider.clone(),
                    locator: key.locator.clone(),
                    group: None,
                    reason: reason.map(str::to_owned),
                    description: None,
                    default: None,
                    source: Source::Eager,
                }],
            };
            let resolved = resolve::resolve_all(&manifest, &plan).and_then(|(rows, _stats)| {
                rows.into_iter()
                    .next()
                    .map(|r| r.value)
                    .with_context(|| format!("provider returned no value for {name:?}"))
            });
            match resolved {
                Ok(secret) => {
                    let exposed = Zeroizing::new(secret.expose().to_owned());
                    {
                        let mut guard = cache.lock().expect("secret cache mutex");
                        guard.put(key, exposed.as_str());
                    }
                    // Cache populated → wake any parked waiters (also drops
                    // the in-flight slot).
                    g.mark_ready();
                    Ok(exposed)
                }
                Err(err) => {
                    let msg = format!("{err:#}");
                    g.mark_failed(msg);
                    Err(err)
                }
            }
        }
        Acquired::Ready => {
            // Another thread resolved while we waited; the value should be in
            // the cache now. Treat a "ready but empty" cache as a failure
            // rather than retrying, matching `resolve_for_ask`.
            let guard = cache.lock().expect("secret cache mutex");
            guard.get(&key).ok_or_else(|| {
                anyhow::anyhow!(
                    "in-flight slot for {}/{} signalled ready but cache was empty",
                    key.provider,
                    key.locator,
                )
            })
        }
        Acquired::Failed(msg) => Err(anyhow::anyhow!(msg)),
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
    use crate::daemon::proto::{Caller, DedupeKey, SshAskInfo};

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
            ssh: None,
            allow_remember: true,
            nested_run: false,
        }
    }

    #[test]
    fn ssh_grant_insert_hit_then_expiry_miss() {
        use crate::consent::{SshAnchor, SshGrantScope};
        let mut state = State::new();
        state.remember_ssh_grant(SshGrant {
            scope: SshGrantScope::OneKey("github".into()),
            anchor: SshAnchor {
                pid: 99,
                start_time: 1_700_000_000,
            },
            expires_at: 5000,
        });

        // Inside the window, matching anchor + key: hit. `now` is passed
        // explicitly so the test never reads the real clock.
        assert!(state.has_ssh_grant_at("github", 99, 1_700_000_000, /*now=*/ 4999));
        // Wrong anchor pid: miss even before expiry.
        assert!(!state.has_ssh_grant_at("github", 100, 1_700_000_000, 4999));
        // Past expiry: miss. This also prunes the grant.
        assert!(!state.has_ssh_grant_at("github", 99, 1_700_000_000, 5001));
        // The expired grant was pruned on the last access, so even a
        // pre-expiry `now` no longer hits.
        assert!(!state.has_ssh_grant_at("github", 99, 1_700_000_000, 4999));
    }

    #[test]
    fn ssh_all_keys_grant_covers_any_key_on_the_anchor() {
        use crate::consent::{SshAnchor, SshGrantScope};
        let mut state = State::new();
        state.remember_ssh_grant(SshGrant {
            scope: SshGrantScope::AllKeys,
            anchor: SshAnchor {
                pid: 99,
                start_time: 1_700_000_000,
            },
            expires_at: 5000,
        });
        // Any key id on the granted anchor is covered.
        assert!(state.has_ssh_grant_at("github", 99, 1_700_000_000, 4999));
        assert!(state.has_ssh_grant_at("gitlab", 99, 1_700_000_000, 4999));
        // A different anchor is not.
        assert!(!state.has_ssh_grant_at("github", 100, 1_700_000_000, 4999));
    }

    #[test]
    fn resolve_ssh_ask_remember_does_not_write_wrap_cache_but_normal_ask_does() {
        // SSH approvals are remembered via `SshGrant` (keyed on
        // the anchor), so resolving an SSH ask with ApproveRemember must
        // NOT add anything to the wrap approvals cache — that entry would
        // be dead data. A normal wrap ask, by contrast, still populates it.
        use std::sync::mpsc;

        let shared: SharedState = Arc::new(Mutex::new(State::new()));
        let scope = ApprovalScope {
            pid: 4242,
            start_time: 1_700_000_000,
        };

        // SSH ask: carries an `SshAskInfo` marker, no secrets.
        let mut ssh_ask = mk_ask("ssh:github", vec![(4242, 1_700_000_000)]);
        ssh_ask.ssh = Some(SshAskInfo {
            key_id: "github".into(),
            fingerprint: "SHA256:deadbeef".into(),
            reason: None,
        });
        let ssh_key = ssh_ask.dedupe_key.clone();
        let (tx, _rx) = mpsc::channel();
        {
            let mut guard = shared.lock().expect("state mutex");
            guard.submit_ask(ssh_ask, tx);
            guard.resolve(&ssh_key, Decision::ApproveRemember, scope, &shared);
            assert!(
                guard.approvals.is_empty(),
                "an SSH ask must not write the wrap approvals cache"
            );
        }

        // Normal wrap ask: no `ssh` marker → the wrap cache IS populated.
        let wrap_ask = mk_ask("gh", vec![(4242, 1_700_000_000)]);
        let wrap_key = wrap_ask.dedupe_key.clone();
        let (tx, _rx) = mpsc::channel();
        {
            let mut guard = shared.lock().expect("state mutex");
            guard.submit_ask(wrap_ask, tx);
            guard.resolve(&wrap_key, Decision::ApproveRemember, scope, &shared);
            assert_eq!(
                guard.approvals.len(),
                1,
                "a normal wrap ask must still populate the wrap approvals cache"
            );
            assert_eq!(guard.approvals[0].wrap, "gh");
        }
    }

    #[test]
    fn ask_with_allow_remember_false_does_not_persist_approval() {
        // A `run` ask (allow_remember = false) given ApproveRemember must
        // NOT write the approvals cache — every run re-prompts.
        use std::sync::mpsc;

        let shared: SharedState = Arc::new(Mutex::new(State::new()));
        let scope = ApprovalScope {
            pid: 4242,
            start_time: 1_700_000_000,
        };

        let mut ask = mk_ask("run", vec![(4242, 1_700_000_000)]);
        ask.allow_remember = false;
        let key = ask.dedupe_key.clone();
        let (tx, _rx) = mpsc::channel();
        let mut guard = shared.lock().expect("state mutex");
        guard.submit_ask(ask, tx);
        guard.resolve(&key, Decision::ApproveRemember, scope, &shared);
        assert!(
            guard.approvals.is_empty(),
            "a run ask must not persist an approval even on ApproveRemember"
        );
    }

    #[test]
    fn badge_window_lifecycle_tracks_the_awaiting_queue() {
        use std::sync::mpsc;

        let shared: SharedState = Arc::new(Mutex::new(State::new()));

        // Empty queue: no badge needed, none attached.
        {
            let guard = shared.lock().expect("state mutex");
            assert!(!guard.needs_badge_window());
            assert_eq!(guard.badge_subscriber_count(), 0);
        }

        // An ask awaiting a decision → a badge is needed (but not yet up).
        let ask = mk_ask("gh", vec![(100, 1_700_000_000)]);
        let key = ask.dedupe_key.clone();
        let (tx, _rx) = mpsc::channel();
        shared.lock().expect("state mutex").submit_ask(ask, tx);
        assert!(shared.lock().unwrap().needs_badge_window());

        // Attach a badge → it's up now, so we don't need to spawn another.
        let (btx, brx) = mpsc::channel();
        let id = {
            let mut guard = shared.lock().expect("state mutex");
            let (id, _snap) = guard.attach_badge_window(btx);
            assert_eq!(guard.badge_subscriber_count(), 1);
            assert!(!guard.needs_badge_window());
            id
        };
        // The attach pushed an initial snapshot; the queue change pushed
        // another. Both are `ConsentUpdate`s — drain them.
        while let Ok(msg) = brx.try_recv() {
            assert!(matches!(
                msg,
                crate::daemon::proto::DaemonMsg::ConsentUpdate { .. }
            ));
        }

        // Drain the queue (deny the only ask). The badge is no longer
        // needed once nothing awaits a decision.
        {
            let mut guard = shared.lock().expect("state mutex");
            guard.resolve(
                &key,
                Decision::Deny,
                ApprovalScope {
                    pid: 100,
                    start_time: 1_700_000_000,
                },
                &shared,
            );
            assert!(guard.queue_is_empty());
            // A badge is still attached, but `needs_badge_window` is false
            // because the queue is empty — the daemon's main loop will send
            // the exit signal on its next tick.
            assert!(!guard.needs_badge_window());
        }

        // The exit broadcast reaches the attached badge.
        {
            let mut guard = shared.lock().expect("state mutex");
            guard.broadcast_badge_exit_please();
        }
        // Skip any trailing snapshot pushes; the exit signal must arrive.
        let mut saw_exit = false;
        while let Ok(msg) = brx.try_recv() {
            if matches!(msg, crate::daemon::proto::DaemonMsg::ConsentExitPlease) {
                saw_exit = true;
            }
        }
        assert!(saw_exit, "badge must receive ConsentExitPlease on drain");

        // Detaching with an empty queue leaves no badge needed.
        shared.lock().expect("state mutex").detach_badge_window(id);
        assert!(!shared.lock().unwrap().needs_badge_window());
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
    fn has_cached_approval_matches_a_remembered_scope() {
        // A remembered approval (in `state.approvals`) whose scope
        // matches the ask's direct parent should short-circuit the
        // prompt. The server then resolves via
        // `resolve_approved_with_pending`, which stamps `ApproveCached`
        // (not `Approve`) so the audit-log writer can render "the user
        // wasn't asked again" rather than implying a fresh click.
        let mut state = State::new();
        state.approvals.push(ApprovalEntry {
            wrap: "gh".into(),
            ppid: 7926,
            parent_start_time: 1_700_000_000,
        });
        let ask = mk_ask("gh", vec![(7926, 1_700_000_000)]);
        assert!(state.has_cached_approval(&ask), "matching scope hits");

        // A different parent identity is not authorized.
        let other = mk_ask("gh", vec![(9999, 1_700_000_000)]);
        assert!(
            !state.has_cached_approval(&other),
            "non-matching scope misses"
        );
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
                requested_by: vec![],
            }],
            providers: HashMap::new(),
            dedupe_key: DedupeKey {
                wrap: wrap.to_owned(),
                ppid: 0,
                parent_start_time: 0,
            },
            ssh: None,
            allow_remember: true,
            nested_run: false,
        }
    }

    /// Like [`ask_with_secret`] but with an explicit `(provider, locator)`
    /// so two asks can carry *distinct* secrets that still coalesce (when
    /// keyed the same). Used to exercise the union merge.
    fn ask_with_secret_named(
        wrap: &str,
        argv: &[&str],
        name: &str,
        provider: &str,
        locator: &str,
    ) -> Ask {
        let mut ask = ask_with_secret(wrap, argv, name);
        ask.secrets[0].provider = provider.to_owned();
        ask.secrets[0].locator = locator.to_owned();
        ask
    }

    /// Override an ask's dedupe key (so a sibling coalesces into an
    /// existing entry).
    fn with_dedupe_key(mut ask: Ask, key: DedupeKey) -> Ask {
        ask.dedupe_key = key;
        ask
    }

    #[test]
    fn submit_ask_records_waiter_requested_and_command() {
        let mut state = State::new();
        let ask = ask_with_secret("run", &["run", "./worker"], "TOKEN");
        let (tx, _rx) = mpsc::channel();
        state.submit_ask(ask.clone(), tx);
        let entry = state
            .queue_entry_for_test(&ask.dedupe_key)
            .expect("entry exists after submit_ask");
        assert_eq!(entry.waiters.len(), 1);
        // `SecretAsk` has no `PartialEq`; compare by identity fields
        // (name / provider / locator) — enough to prove the waiter
        // recorded its own requested set rather than an empty one.
        let recorded: Vec<(&str, &str, &str)> = entry.waiters[0]
            .requested
            .iter()
            .map(|s| (s.name.as_str(), s.provider.as_str(), s.locator.as_str()))
            .collect();
        let expected: Vec<(&str, &str, &str)> = ask
            .secrets
            .iter()
            .map(|s| (s.name.as_str(), s.provider.as_str(), s.locator.as_str()))
            .collect();
        assert_eq!(recorded, expected);
        assert_eq!(entry.waiters[0].command, ask.command);
    }

    #[test]
    fn withdraw_waiter_removes_sole_waiter_writes_row_and_closes_channel() {
        crate::audit::with_temp_log(|| {
            let mut state = State::new();
            let ask = ask_with_secret("gh", &["gh", "pr", "view"], "GITHUB_TOKEN");
            let (tx, rx) = mpsc::channel();
            let (_result, id) = state.submit_ask(ask.clone(), tx);
            assert!(state.queue_entry_for_test(&ask.dedupe_key).is_some());

            state.withdraw_waiter(&ask.dedupe_key, id);

            // Entry gone → the card leaves the requests view.
            assert!(
                state.queue_entry_for_test(&ask.dedupe_key).is_none(),
                "the entry is removed when its last waiter withdraws"
            );
            // The daemon wrote exactly one abandoned row for the dead command.
            let rows = crate::audit::read_history(None).expect("read audit log");
            assert_eq!(rows.len(), 1, "one abandoned row written");
            assert_eq!(rows[0].decision, "abandoned");
            assert_eq!(rows[0].wrap, "gh");
            assert_eq!(rows[0].args, vec!["pr", "view"]);
            // The parked connection thread's channel is closed (sender dropped),
            // so its `recv()` unblocks with an error instead of hanging.
            assert!(
                rx.recv().is_err(),
                "withdrawing drops the waiter's sender, unblocking its recv"
            );
        });
    }

    #[test]
    fn withdraw_waiter_keeps_entry_while_a_sibling_waits() {
        crate::audit::with_temp_log(|| {
            let mut state = State::new();
            let a = ask_with_secret("run", &["run", "./migrate"], "DB");
            let b = with_dedupe_key(
                ask_with_secret("run", &["run", "./worker"], "API"),
                a.dedupe_key.clone(),
            );
            let (tx_a, rx_a) = mpsc::channel();
            let (tx_b, rx_b) = mpsc::channel();
            let (_r1, id_a) = state.submit_ask(a.clone(), tx_a);
            let (_r2, _id_b) = state.submit_ask(b.clone(), tx_b);
            assert_eq!(
                state
                    .queue_entry_for_test(&a.dedupe_key)
                    .unwrap()
                    .waiters
                    .len(),
                2,
                "coalesced: one entry, two waiters"
            );

            state.withdraw_waiter(&a.dedupe_key, id_a);

            let entry = state
                .queue_entry_for_test(&a.dedupe_key)
                .expect("entry survives while a sibling waiter remains");
            assert_eq!(
                entry.waiters.len(),
                1,
                "only the withdrawn waiter is removed"
            );
            assert!(rx_a.recv().is_err(), "withdrawn waiter's channel closed");
            assert!(
                matches!(rx_b.try_recv(), Err(mpsc::TryRecvError::Empty)),
                "the sibling waiter is still parked with its channel open"
            );
        });
    }

    #[test]
    fn withdraw_waiter_is_noop_on_unknown_key_or_id() {
        crate::audit::with_temp_log(|| {
            let mut state = State::new();
            let ask = ask_with_secret("gh", &["gh", "auth"], "GITHUB_TOKEN");
            let (tx, _rx) = mpsc::channel();
            let (_result, id) = state.submit_ask(ask.clone(), tx);

            // Unknown key: nothing removed, no panic.
            let bogus_key = DedupeKey {
                wrap: "nope".to_owned(),
                ppid: 999,
                parent_start_time: 1,
            };
            state.withdraw_waiter(&bogus_key, id);
            assert_eq!(
                state
                    .queue_entry_for_test(&ask.dedupe_key)
                    .unwrap()
                    .waiters
                    .len(),
                1
            );

            // Known key, unknown waiter id: still nothing removed.
            state.withdraw_waiter(&ask.dedupe_key, WaiterId(9_999));
            assert_eq!(
                state
                    .queue_entry_for_test(&ask.dedupe_key)
                    .unwrap()
                    .waiters
                    .len(),
                1,
                "an unknown waiter id withdraws nothing"
            );
        });
    }

    #[test]
    fn abandoned_audit_entry_reconstructs_client_args() {
        // `x` asks send `[wrap, args…]`; the leading wrap name is stripped so
        // the row's args match what the live client would have logged.
        let x_ask = ask_with_secret("gh", &["gh", "pr", "view"], "GITHUB_TOKEN");
        let (tx, _rx) = mpsc::channel();
        let waiter = Waiter {
            id: WaiterId(1),
            sender: tx,
            requested: x_ask.secrets.clone(),
            command: x_ask.command.clone(),
            cwd: "/work".to_owned(),
            callers: x_ask.callers.clone(),
        };
        let entry = State::abandoned_audit_entry(&x_ask.dedupe_key, &waiter);
        assert_eq!(entry.wrap, "gh");
        assert_eq!(entry.args, vec!["pr", "view"]);
        assert_eq!(entry.decision, "abandoned");
        assert_eq!(entry.secrets, vec!["GITHUB_TOKEN"]);
        assert_eq!(entry.cwd, "/work");

        // `run`/`read` asks send the bare command (command[0] != wrap), so
        // nothing is stripped.
        let run_ask = ask_with_secret("run", &["./deploy.sh", "--prod"], "TOKEN");
        let (tx2, _rx2) = mpsc::channel();
        let waiter2 = Waiter {
            id: WaiterId(2),
            sender: tx2,
            requested: run_ask.secrets.clone(),
            command: run_ask.command.clone(),
            cwd: String::new(),
            callers: vec![],
        };
        let entry2 = State::abandoned_audit_entry(&run_ask.dedupe_key, &waiter2);
        assert_eq!(entry2.wrap, "run");
        assert_eq!(entry2.args, vec!["./deploy.sh", "--prod"]);
    }

    #[test]
    fn coalescing_unions_heterogeneous_secrets_with_provenance() {
        let mut state = State::new();
        let a = ask_with_secret_named("run", &["run", "./migrate"], "DB", "op", "pg");
        let b = ask_with_secret_named("run", &["run", "./worker"], "API", "op", "stripe");
        // Same dedupe key (same session) so they coalesce:
        let b = with_dedupe_key(b, a.dedupe_key.clone());
        let (tx1, _r1) = mpsc::channel();
        let (tx2, _r2) = mpsc::channel();
        state.submit_ask(a.clone(), tx1);
        state.submit_ask(b.clone(), tx2);
        let entry = state.queue_entry_for_test(&a.dedupe_key).unwrap();
        let names: Vec<&str> = entry
            .representative
            .secrets
            .iter()
            .map(|s| s.name.as_str())
            .collect();
        assert_eq!(
            names,
            vec!["DB", "API"],
            "union preserves both, in arrival order"
        );
        // provenance stamped with each requesting command:
        assert!(entry.representative.secrets[0]
            .requested_by
            .contains(&"run ./migrate".to_owned()));
        assert!(entry.representative.secrets[1]
            .requested_by
            .contains(&"run ./worker".to_owned()));
    }

    #[test]
    fn nested_run_skips_window_only_when_nested_and_fully_cached() {
        // The value the ask needs, cached under (wrap="run", fake, x) —
        // the key `ask_with_secret` produces.
        let cache = Arc::new(Mutex::new(SecretCache::new()));
        cache.lock().unwrap().put(
            CacheKey {
                wrap: "run".to_owned(),
                provider: "fake".to_owned(),
                locator: "x".to_owned(),
            },
            "cached-value",
        );

        // Unnested run, even fully cached → must NOT skip. This is the
        // load-bearing invariant: a top-level run always prompts.
        let mut unnested = ask_with_secret("run", &["run", "cmd"], "TOKEN");
        unnested.nested_run = false;
        assert!(
            !nested_run_fully_cached(&unnested, &cache),
            "an unnested run must always prompt, even when fully cached"
        );

        // Nested + fully cached → skip the window.
        let mut nested = ask_with_secret("run", &["run", "cmd"], "TOKEN");
        nested.nested_run = true;
        assert!(
            nested_run_fully_cached(&nested, &cache),
            "a nested, fully-cached run should resolve without prompting"
        );

        // Nested but one secret uncached → must NOT skip (prompts for the
        // uncached var).
        let mut nested_uncached = ask_with_secret("run", &["run", "cmd"], "TOKEN");
        nested_uncached.nested_run = true;
        nested_uncached
            .secrets
            .push(super::super::proto::SecretAsk {
                name: "OTHER".to_owned(),
                provider: "fake".to_owned(),
                locator: "uncached".to_owned(),
                default: None,
                description: None,
                reason: None,
                requested_by: vec![],
            });
        assert!(
            !nested_run_fully_cached(&nested_uncached, &cache),
            "a nested run with any uncached secret must still prompt"
        );
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
                requested_by: vec![],
            }],
            providers: providers.clone(),
            dedupe_key: DedupeKey {
                wrap: "gh".to_owned(),
                ppid: 0,
                parent_start_time: 0,
            },
            ssh: None,
            allow_remember: true,
            nested_run: false,
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
    fn resolve_single_cached_resolves_once_then_serves_from_cache() {
        // The SSH-key regression in one test: the first sign resolves the
        // private key through the provider (one biometric); a second sign for
        // the same key must hit the encrypted cache and NOT re-invoke the
        // provider. The retrieve script appends one line per invocation, so
        // the line count is the invocation count.
        let tmp = tempfile::tempdir().expect("tempdir");
        let counter = tmp.path().join("invocations");
        std::fs::write(&counter, b"").expect("create counter");
        let script = format!(
            "echo invoked >> {counter}; echo secret-{{locator}}",
            counter = counter.display(),
        );
        let mut providers = std::collections::BTreeMap::new();
        providers.insert(
            "fake".to_owned(),
            Provider {
                name: "fake".to_owned(),
                retrieve: vec!["sh".to_owned(), "-c".to_owned(), script],
                store: None,
                retrieve_batch: None,
            },
        );

        let state = State::new();
        let cache = state.secret_cache_arc();
        let in_flight = state.in_flight_arc();
        let key = CacheKey {
            wrap: "ssh:github".into(),
            provider: "fake".into(),
            locator: "x".into(),
        };

        let first = super::resolve_single_cached(
            &cache,
            &in_flight,
            key.clone(),
            "github",
            None,
            &providers,
        )
        .expect("first resolve");
        assert_eq!(&*first, "secret-x");

        let second =
            super::resolve_single_cached(&cache, &in_flight, key, "github", None, &providers)
                .expect("second resolve");
        assert_eq!(&*second, "secret-x");

        let invocations = std::fs::read_to_string(&counter)
            .expect("read counter")
            .lines()
            .count();
        assert_eq!(
            invocations, 1,
            "provider must be invoked once; the second sign must hit the cache, got {invocations}"
        );
    }

    /// A `WireProvider` map with a single `fake` provider whose `retrieve`
    /// echoes `resolved-<locator>`. Lets per-waiter resolution tests drive
    /// the real `resolve` path (submit → approve → recv) without a cache
    /// pre-seed, so each `(provider, locator)` is genuinely resolved.
    fn fake_echo_providers() -> HashMap<String, WireProvider> {
        let mut providers = HashMap::new();
        providers.insert(
            "fake".to_owned(),
            WireProvider {
                name: "fake".to_owned(),
                retrieve: vec![
                    "sh".to_owned(),
                    "-c".to_owned(),
                    "echo resolved-{locator}".to_owned(),
                ],
                retrieve_batch: None,
            },
        );
        providers
    }

    /// A batch-capable fake provider. Per-secret `retrieve` yields
    /// `persecret-<locator>`; the batch path (`printenv` over synthetic env)
    /// yields `batched-<locator>`. The two sentinels differ so a resolve
    /// test can tell which path actually ran — the batch env-var name must
    /// be valid for `retrieve_batch` to succeed.
    fn batch_fake_providers() -> HashMap<String, WireProvider> {
        let mut providers = HashMap::new();
        providers.insert(
            "bat".to_owned(),
            WireProvider {
                name: "bat".to_owned(),
                retrieve: vec![
                    "sh".to_owned(),
                    "-c".to_owned(),
                    "echo persecret-{locator}".to_owned(),
                ],
                retrieve_batch: Some(super::super::proto::WireBatchRetrieve {
                    // Echo the whole env; resolve_all keeps only our request
                    // names. This only works if those names are valid env
                    // var names (no NUL).
                    command: vec!["sh".to_owned(), "-c".to_owned(), "printenv".to_owned()],
                    env_value_template: "batched-{locator}".to_owned(),
                }),
            },
        );
        providers
    }

    #[test]
    fn resolve_union_batches_when_the_provider_declares_a_batch_capability() {
        // Regression: `resolve_union` used to name each request with a NUL
        // separator (`provider\0locator`). `resolve_all`'s batch path feeds
        // that name to `Command::env` as an *env var name*, and NUL bytes
        // are rejected there — so `op run` never spawned and every op resolve
        // silently fell back to N per-secret reads (30s+ for a big run).
        // Two secrets through the batch-capable provider must resolve via the
        // BATCH (`batched-*`), not the per-secret fallback (`persecret-*`).
        let mut ask = ask_with_secret_named("run", &["run", "x"], "S1", "bat", "loc-a");
        ask.secrets.push(super::super::proto::SecretAsk {
            name: "S2".to_owned(),
            provider: "bat".to_owned(),
            locator: "loc-b".to_owned(),
            default: None,
            description: None,
            reason: None,
            requested_by: vec![],
        });
        ask.providers = batch_fake_providers();

        let cache = Arc::new(Mutex::new(SecretCache::new()));
        let in_flight = InFlightMap::new();
        let out = resolve_union(&ask, cache, in_flight);

        let a = out
            .get(&("bat".to_owned(), "loc-a".to_owned()))
            .expect("loc-a resolved")
            .as_ref()
            .expect("loc-a ok");
        let b = out
            .get(&("bat".to_owned(), "loc-b".to_owned()))
            .expect("loc-b resolved")
            .as_ref()
            .expect("loc-b ok");
        assert_eq!(
            a, "batched-loc-a",
            "must resolve via the batch, not fallback"
        );
        assert_eq!(
            b, "batched-loc-b",
            "must resolve via the batch, not fallback"
        );
    }

    /// Build a `run` ask carrying one secret `{name = provider/locator}`
    /// wired to [`fake_echo_providers`], with an explicit dedupe key so
    /// siblings coalesce.
    fn run_ask_with_secret(
        argv: &[&str],
        name: &str,
        provider: &str,
        locator: &str,
        key: DedupeKey,
    ) -> Ask {
        let mut ask = ask_with_secret_named("run", argv, name, provider, locator);
        ask.providers = fake_echo_providers();
        ask.dedupe_key = key;
        ask
    }

    /// Session dedupe key shared by coalescing siblings in the tests below.
    fn session_key() -> DedupeKey {
        DedupeKey {
            wrap: "run".to_owned(),
            ppid: 6042,
            parent_start_time: 12345,
        }
    }

    #[test]
    fn each_waiter_receives_only_its_own_secret() {
        // A wants DB (fake/pg), B wants API (fake/stripe); same session key
        // → they coalesce. On approve, A's reply must carry DB and NOT API;
        // B's must carry API and NOT DB.
        let shared: SharedState = Arc::new(Mutex::new(State::new()));
        let key = session_key();
        let a = run_ask_with_secret(&["run", "./migrate"], "DB", "fake", "pg", key.clone());
        let b = run_ask_with_secret(&["run", "./worker"], "API", "fake", "stripe", key.clone());

        let (tx_a, rx_a) = mpsc::channel();
        let (tx_b, rx_b) = mpsc::channel();
        {
            let mut guard = shared.lock().expect("state mutex");
            guard.submit_ask(a, tx_a);
            guard.submit_ask(b, tx_b);
            guard.resolve(
                &key,
                Decision::Approve,
                ApprovalScope {
                    pid: 6042,
                    start_time: 12345,
                },
                &shared,
            );
        }

        let reply_a = rx_a.recv().expect("A reply");
        let reply_b = rx_b.recv().expect("B reply");

        let secrets_a = match reply_a {
            WaiterReply::Decision { secrets, .. } => secrets,
            WaiterReply::Err { message } => panic!("A got err: {message}"),
        };
        let secrets_b = match reply_b {
            WaiterReply::Decision { secrets, .. } => secrets,
            WaiterReply::Err { message } => panic!("B got err: {message}"),
        };

        // The load-bearing isolation assertions: each waiter sees only its
        // own secret, never the sibling's.
        assert_eq!(secrets_a.get("DB").map(String::as_str), Some("resolved-pg"));
        assert!(
            !secrets_a.contains_key("API"),
            "A must NOT receive B's secret"
        );
        assert_eq!(
            secrets_b.get("API").map(String::as_str),
            Some("resolved-stripe")
        );
        assert!(
            !secrets_b.contains_key("DB"),
            "B must NOT receive A's secret"
        );
    }

    #[test]
    fn x_style_identical_asks_each_get_the_full_set() {
        // Two asks with the SAME secret {TOKEN = fake/t} coalesce → both
        // replies carry TOKEN. Proves no regression for wrap coalescing.
        let shared: SharedState = Arc::new(Mutex::new(State::new()));
        let key = session_key();
        let a = run_ask_with_secret(&["run", "./a"], "TOKEN", "fake", "t", key.clone());
        let b = run_ask_with_secret(&["run", "./b"], "TOKEN", "fake", "t", key.clone());

        let (tx_a, rx_a) = mpsc::channel();
        let (tx_b, rx_b) = mpsc::channel();
        {
            let mut guard = shared.lock().expect("state mutex");
            guard.submit_ask(a, tx_a);
            guard.submit_ask(b, tx_b);
            guard.resolve(
                &key,
                Decision::Approve,
                ApprovalScope {
                    pid: 6042,
                    start_time: 12345,
                },
                &shared,
            );
        }

        for rx in [rx_a, rx_b] {
            match rx.recv().expect("reply") {
                WaiterReply::Decision { secrets, .. } => {
                    assert_eq!(secrets.get("TOKEN").map(String::as_str), Some("resolved-t"));
                }
                WaiterReply::Err { message } => panic!("unexpected err: {message}"),
            }
        }
    }

    #[test]
    fn same_name_different_ref_across_siblings_stays_isolated() {
        // A wants FOO = fake/a, B wants FOO = fake/b (same name, different
        // ref!). Each waiter's FOO must be its own value — keying by
        // (provider, locator) keeps the same-name union entries distinct.
        let shared: SharedState = Arc::new(Mutex::new(State::new()));
        let key = session_key();
        let a = run_ask_with_secret(&["run", "./a"], "FOO", "fake", "a", key.clone());
        let b = run_ask_with_secret(&["run", "./b"], "FOO", "fake", "b", key.clone());

        let (tx_a, rx_a) = mpsc::channel();
        let (tx_b, rx_b) = mpsc::channel();
        {
            let mut guard = shared.lock().expect("state mutex");
            guard.submit_ask(a, tx_a);
            guard.submit_ask(b, tx_b);
            guard.resolve(
                &key,
                Decision::Approve,
                ApprovalScope {
                    pid: 6042,
                    start_time: 12345,
                },
                &shared,
            );
        }

        let secrets_a = match rx_a.recv().expect("A reply") {
            WaiterReply::Decision { secrets, .. } => secrets,
            WaiterReply::Err { message } => panic!("A got err: {message}"),
        };
        let secrets_b = match rx_b.recv().expect("B reply") {
            WaiterReply::Decision { secrets, .. } => secrets,
            WaiterReply::Err { message } => panic!("B got err: {message}"),
        };

        assert_eq!(secrets_a.get("FOO").map(String::as_str), Some("resolved-a"));
        assert_eq!(secrets_b.get("FOO").map(String::as_str), Some("resolved-b"));
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

    /// Manager subscribers track attach/detach independently of the
    /// prompt's, and the last manager detach clears viewer mode (the
    /// pin belonged to the window the user just closed).
    #[test]
    fn manager_attach_detach_lifecycle_clears_viewer_mode() {
        let mut state = State::new();
        assert!(state.needs_manager_window());

        let (tx, _rx) = mpsc::channel();
        let (id, _snap) = state.attach_manager_window(777, tx);
        assert_eq!(state.manager_subscriber_count(), 1);
        assert_eq!(state.manager_child_pid(), Some(777));
        assert!(!state.needs_manager_window());

        state.enter_viewer_mode();
        assert!(state.viewer_mode());

        state.detach_manager_window(id);
        assert_eq!(state.manager_subscriber_count(), 0);
        assert!(state.needs_manager_window());
        assert!(
            !state.viewer_mode(),
            "last manager detach must clear viewer mode"
        );
    }

    /// The prompt is a pure decision surface: it is told to exit the
    /// instant the queue drains — we don't wait out the main-loop grace
    /// for a confirmation nobody needs.
    #[test]
    fn resolve_draining_queue_exits_window_immediately_when_only_decisions_made() {
        let shared: SharedState = Arc::new(Mutex::new(State::new()));
        let (tx, rx) = mpsc::channel();
        let ask = mk_ask("gh", vec![(100, 1_700_000_000)]);
        let key = ask.dedupe_key.clone();
        {
            let mut guard = shared.lock().expect("state mutex");
            guard.attach_consent_window(321, tx);
            let (wtx, _wrx) = mpsc::channel();
            guard.submit_ask(ask, wtx);
            guard.resolve(
                &key,
                Decision::Deny,
                ApprovalScope {
                    pid: 100,
                    start_time: 1_700_000_000,
                },
                &shared,
            );
        }

        let mut saw_exit = false;
        while let Ok(msg) = rx.try_recv() {
            if matches!(msg, crate::daemon::proto::DaemonMsg::ConsentExitPlease) {
                saw_exit = true;
            }
        }
        assert!(
            saw_exit,
            "a decision-only window must be asked to exit the instant the queue drains"
        );
    }

    /// The manager window must never receive the prompt's exit signal
    /// on drain — it's a browsing surface the user closes themselves.
    #[test]
    fn resolve_draining_queue_never_exits_the_manager_window() {
        let shared: SharedState = Arc::new(Mutex::new(State::new()));
        let (tx, rx) = mpsc::channel();
        let ask = mk_ask("gh", vec![(100, 1_700_000_000)]);
        let key = ask.dedupe_key.clone();
        {
            let mut guard = shared.lock().expect("state mutex");
            let (_id, _snap) = guard.attach_manager_window(321, tx);
            let (wtx, _wrx) = mpsc::channel();
            guard.submit_ask(ask, wtx);
            guard.resolve(
                &key,
                Decision::Deny,
                ApprovalScope {
                    pid: 100,
                    start_time: 1_700_000_000,
                },
                &shared,
            );
        }

        while let Ok(msg) = rx.try_recv() {
            assert!(
                !matches!(msg, crate::daemon::proto::DaemonMsg::ConsentExitPlease),
                "the manager window must never be asked to exit on queue drain"
            );
        }
    }
}
