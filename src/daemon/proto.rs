//! Wire protocol between `secreq` clients and the consent daemon.
//!
//! One JSON object per line, both directions. The client opens the socket,
//! writes a [`ClientMsg`], reads a [`DaemonMsg`], closes. The daemon's reply
//! may arrive seconds later (waiting on the user) but no keep-alive is
//! needed — the socket stays open across the wait.
//!
//! ## What crosses this socket
//!
//! - **Metadata** (always): command, cwd, caller chain, env-var names,
//!   provider schemes, locators, provider invocation templates.
//! - **Resolved secret values** (on Approve): the daemon runs the
//!   providers itself and ships the values back to every waiter. This is
//!   the load-bearing reason the daemon exists — it collapses N parallel
//!   client-side `op read` invocations (and their biometric prompts) into
//!   exactly one.
//!
//! The trust boundary is the per-user `0600` socket. Any process running
//! as the user already has the same access the daemon does, so adding
//! resolved values to the wire doesn't expand the threat surface — it
//! consolidates work that would otherwise happen N times in N clients.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::consent::Decision;
use crate::rules::Rule;

/// One message from client → daemon.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ClientMsg {
    // ── One-shot request/reply (legacy wrap / admin commands) ──
    /// "Decide whether this wrap can run, and if so resolve the secrets."
    /// The daemon either replies immediately from cache (with resolution
    /// done daemon-side) or queues the ask for the user's review.
    Ask(Ask),
    /// "Show the pending-requests window." Used by `secreq pending`.
    /// Returns [`DaemonMsg::Ok`] immediately. The window will auto-hide
    /// once the queue empties (after a short grace period).
    ShowWindow,
    /// "Show the window in viewer mode" — same as `ShowWindow` but the
    /// auto-hide is suppressed so the user can browse the audit log.
    /// Used by `secreq view`. Viewer mode clears on manual close.
    ShowViewer,
    /// "Are you alive?" Used by the auto-spawn poll loop. Replies with `Ok`.
    Ping,
    /// "Exit cleanly." Used by `secreq daemon stop` to forget the
    /// in-memory approvals cache (and free the singleton pidfile lock).
    /// Replies with `Ok` immediately; the actual exit happens shortly
    /// after.
    Shutdown,

    // ── Streaming protocol for the consent-window child process ──
    //
    // After `ConsentWindowAttach`, the daemon switches this connection
    // into push mode: it sends a stream of `DaemonMsg::ConsentUpdate`s
    // (one whenever state changes), and the child sends decisions back
    // as `ConsentDecision`. Connection drop (child crashed / exited
    // without sending `ConsentWindowDetach`) is treated the same as
    // detach — the daemon clears the subscriber and may spawn a new
    // child on the next state change that needs UI.
    /// "I'm the consent-window child process; please send me state
    /// updates and accept decisions from me." Daemon replies with an
    /// immediate `ConsentUpdate` carrying the current snapshot.
    ///
    /// `pid` is the child's OS process id. The daemon records it so a
    /// later `ShowWindow` / `ShowViewer` from the CLI can reply with
    /// the child's pid; the CLI then calls
    /// `NSRunningApplication.activate(options:)` against it. That's
    /// the only path that bypasses macOS 14+'s "background apps can't
    /// steal focus" rule — the activation has to originate from the
    /// process the user just typed a command into (the CLI), not from
    /// the background app being activated.
    ConsentWindowAttach { pid: u32 },
    /// "User has decided this entry." The daemon resolves it using the
    /// same machinery as a button-click in the old in-process UI.
    ConsentDecision {
        key: DedupeKey,
        decision: crate::consent::Decision,
        scope_pid: u32,
        scope_start_time: u64,
    },
    /// "I'm closing cleanly." Daemon removes me from its subscriber list.
    ConsentWindowDetach,
    /// "My OS focus state just changed." Sent by the consent-window
    /// child whenever `egui::InputState.focused` transitions; lets the
    /// daemon distinguish "UI is alive AND in front" from "UI is alive
    /// but the user has tabbed away." Used to:
    ///
    ///   - skip the kill-and-respawn raise on a new ask when the
    ///     existing window is already focused (the streaming snapshot
    ///     already paints the new entry — no need to disrupt the user),
    ///   - suppress the auto-hide grace-period exit while the user is
    ///     interacting with the UI (e.g. scrolling the Audit tab after
    ///     clearing the queue).
    ///
    /// Default at attach is `focused = true`: a freshly-spawned child
    /// gets foreground intent on macOS, so until we hear otherwise the
    /// safe assumption is that it's in front.
    ConsentWindowFocus { focused: bool },

    // ── Auto-rules management ─────────────────────────────────────
    //
    // These messages are sent by the UI (the consent-window child) and
    // by the `secreq rules …` CLI verbs. The daemon is the single
    // writer of the rules file — clients never poke the file directly.
    // See `src/rules.rs` and `dev-docs/plans/2026-06-02-auto-rules.md`.
    /// "Give me the current ruleset." Daemon replies with
    /// [`DaemonMsg::RulesList`].
    ListRules,
    /// "Create this rule." The daemon validates the rule, persists it,
    /// and refreshes the in-memory ruleset. Replies `Ok` on success
    /// or `Err` on validation failure.
    AddRule { rule: Rule },
    /// "Replace the rule with this `id` with the supplied content."
    /// Replies `Ok` on success, `Err` if the id is unknown.
    UpdateRule { rule: Rule },
    /// "Remove the rule with this `id`."
    DeleteRule { id: String },
    /// "Toggle the enabled bit on this rule." Cheaper-and-clearer than
    /// `UpdateRule` for the common "pause this rule" UI affordance.
    SetRuleEnabled { id: String, enabled: bool },
}

/// Everything the daemon needs to render the prompt **and** resolve the
/// secrets after the user approves. Carries no secret *values* — only
/// addresses (locators) and the templates needed to fetch them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ask {
    /// Argv of the command the wrap will exec.
    pub command: Vec<String>,
    /// Working directory of the requesting process.
    pub cwd: String,
    /// Parent-process chain, nearest-first.
    pub callers: Vec<Caller>,
    /// Secrets to be granted: name + reference + reason. The locator is
    /// not a value, so it's safe on the wire — and the daemon needs it to
    /// invoke the provider's `retrieve` template.
    pub secrets: Vec<SecretAsk>,
    /// The provider definitions the daemon needs to run resolution. Each
    /// `SecretAsk.provider` must be a key here. We send a *snapshot* per
    /// ask so the daemon doesn't have to re-read the user's config file
    /// (and so coalesced asks all agree on what to run).
    pub providers: HashMap<String, WireProvider>,
    /// Coalescing key: parallel asks with the same key fold into one queue
    /// entry. Today: `(wrap_name, ppid, parent_start_time)`.
    pub dedupe_key: DedupeKey,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct DedupeKey {
    pub wrap: String,
    pub ppid: u32,
    pub parent_start_time: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Caller {
    pub pid: u32,
    pub name: String,
    pub command: String,
    /// Process start time as `sysinfo` reports it. The `(pid, start_time)`
    /// pair is what makes an ancestor cache hit pid-recycle-safe — a new
    /// process inheriting the same pid will have a different start_time,
    /// so it can't ride an old approval. Default 0 for any client that
    /// hasn't been updated yet; matching against 0 just falls through.
    #[serde(default)]
    pub start_time: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretAsk {
    pub name: String,
    pub provider: String,
    pub locator: String,
    pub default: Option<String>,
    pub description: Option<String>,
    pub reason: Option<String>,
}

/// Wire-form provider definition. Mirrors [`crate::manifest::Provider`]
/// but with serde derives and only the fields the daemon needs to do
/// retrieval. We don't ship `store` capabilities — the daemon never
/// writes secrets, only reads them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireProvider {
    pub name: String,
    pub retrieve: Vec<String>,
    pub retrieve_batch: Option<WireBatchRetrieve>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireBatchRetrieve {
    pub command: Vec<String>,
    pub env_value_template: String,
}

/// One message from daemon → client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DaemonMsg {
    /// The decision plus, on approve, the resolved secret values keyed by
    /// env-var name. On `Deny`, `secrets` is empty.
    ///
    /// `rule_id` / `rule_name` are `Some` when a matching auto-rule fired
    /// (decision is `ApproveAuto` or `DenyAuto`); the client uses them
    /// for the audit row and the auto-deny stderr message.
    /// `deny_message` is the rule's configured message on auto-deny.
    /// All three are `#[serde(default)]` so older daemons that don't
    /// emit them still deserialize cleanly here.
    Decision {
        decision: Decision,
        secrets: HashMap<String, String>,
        #[serde(default)]
        rule_id: Option<String>,
        #[serde(default)]
        rule_name: Option<String>,
        #[serde(default)]
        deny_message: Option<String>,
    },
    /// Generic acknowledgement (Ping / ConsentWindowDetach / Shutdown).
    Ok,
    /// Reply to `ShowWindow` / `ShowViewer`. Carries the consent-window
    /// child's pid if one is already attached, so the CLI can call
    /// `NSRunningApplication.activate(...)` on it. `None` means the
    /// daemon will spawn a fresh child shortly — a brand-new process
    /// gets foreground focus naturally on launch, no extra activation
    /// needed.
    WindowOpened { child_pid: Option<u32> },
    /// Daemon-side error (resolution failed, etc.). Client should treat
    /// as a hard error, not a silent deny — the user approved and the
    /// fetch then failed, which is different from "user said no."
    Err { message: String },

    // ── Streaming pushes to an attached consent-window child ──
    /// Latest queue + viewer-mode state. Pushed after attach and again
    /// whenever the daemon's state changes (Ask / Resolve / ShowViewer
    /// / etc.). The child diffs the snapshot into its egui state.
    ConsentUpdate { snapshot: WireSnapshot },
    /// "Please exit cleanly." Sent when the daemon decides the consent
    /// window is no longer needed (queue drained, viewer mode off,
    /// grace period elapsed). The child should close its window and
    /// exit; the alternative — daemon force-closing the socket — works
    /// too but produces noisier logs.
    ConsentExitPlease,

    /// Reply to [`ClientMsg::ListRules`]. Carries the current ruleset.
    RulesList { rules: Vec<Rule> },

    /// One-shot toast push, sent the moment an auto-deny rule fires.
    /// The child stores it and renders a transient banner at the top
    /// of the Pending tab for a few seconds, then drops it. If no
    /// child is attached at the moment of the deny, the toast is
    /// simply not seen — the terminal message and the audit row
    /// remain authoritative.
    AutoDenyToast {
        rule_name: String,
        deny_message: Option<String>,
    },
}

/// Wire-form snapshot of state the consent-window child needs to render.
/// Audit history lives in `audit.log` and the child reads it on its own
/// via `AuditCache`, so it's not in this struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireSnapshot {
    pub queue: Vec<WireQueueRow>,
    pub viewer_mode: bool,
    /// Current auto-rules ruleset. Pushed alongside queue snapshots so
    /// the Rules tab in the consent window stays in sync without an
    /// explicit `ListRules` round-trip on every state change.
    /// `#[serde(default)]` for back-compat with older daemons.
    #[serde(default)]
    pub rules: Vec<Rule>,
}

/// Wire-form `QueueRow`. `first_seen_secs_ago` is daemon-local elapsed
/// seconds since the entry was queued; the child uses it as a fixed
/// offset for "N s ago" labels (re-elapsed against its own clock).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireQueueRow {
    pub key: DedupeKey,
    pub representative: Ask,
    pub waiter_count: usize,
    pub first_seen_secs_ago: u64,
}
