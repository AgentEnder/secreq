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

use crate::provenance::{ProcessIdentity, SignAnchorKind};

use std::collections::BTreeSet;

use crate::consent::Decision;
use crate::rules::{Rule, RuleListing, RuleRefusals};

/// Which manager view a window should open on. Carried on the wire when
/// the prompt's "Open Manager…" affordance is clicked
/// ([`ClientMsg::OpenManager`]) and by the `secreq manager-window
/// --view` flag the daemon passes at spawn time. Lives in proto because
/// it crosses the socket; the UI modules re-export it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagerFocus {
    Rules,
    Audit,
}

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
    /// "Open the manager window on the audit log." Used by `secreq
    /// view`. Sets `viewer_mode` (which tells a freshly-attached
    /// manager child to start on the Audit view) and spawns/raises the
    /// manager window. Viewer mode clears when the manager closes.
    ShowViewer,
    /// "Are you alive?" Used by the auto-spawn poll loop. Replies with `Ok`.
    Ping,
    /// "What build are you?" Version handshake the CLI sends right after
    /// connecting to an *already-running* daemon. The daemon replies with
    /// [`DaemonMsg::Hello`] carrying its compile-time [`crate::BUILD_ID`].
    /// The CLI compares it against its own; a mismatch means the installed
    /// binary was updated under a stale daemon, so the CLI restarts it.
    /// Carries the CLI's own build id purely so the daemon can log the
    /// mismatch from its side (it doesn't act on it — the CLI drives the
    /// restart).
    Hello { build_id: String },
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
        /// Optional explanation for a manual denial. Empty input is sent as
        /// `None`, preserving the one-keystroke deny path.
        #[serde(default)]
        reason: Option<String>,
        /// The process a remembered approval is written against. One value
        /// rather than a `scope_pid` / `scope_start_time` pair: what lands in
        /// the approvals cache is a [`ProcessIdentity`], and every hop that
        /// takes it apart is a hop that can put it back together wrong.
        ///
        /// `None` when the row's [`AskAnchor`] is not a process — a `run`
        /// session or a scoped agent's socket. The prompt used to coerce
        /// those into a `ProcessIdentity` anyway and send it; there was
        /// nothing honest to send, so now it sends nothing.
        scope: Option<ProcessIdentity>,
    },
    /// "I'm closing cleanly." Daemon removes me from its subscriber list.
    ConsentWindowDetach,

    // ── Streaming protocol for the pending-badge child process ──
    //
    // The badge is a second, much smaller always-on-top child the
    // daemon spawns while requests are pending — a "N pending" pill
    // floating over other apps so a backgrounded consent window can't
    // be forgotten with processes still hung on a decision. Unlike the
    // consent window it never restarts-to-raise and never reports
    // focus; it just subscribes to the same snapshot stream (reusing
    // `DaemonMsg::ConsentUpdate`, counting `RowStatus::Awaiting` rows)
    // and exits on `DaemonMsg::ConsentExitPlease` when the queue drains.
    /// "I'm the pending-badge child process; subscribe me to snapshot
    /// updates." Daemon registers the badge as a separate subscriber
    /// kind and replies with an immediate `ConsentUpdate`.
    BadgeWindowAttach { pid: u32 },
    /// "I'm closing cleanly." Daemon removes me from its badge
    /// subscriber list.
    BadgeWindowDetach,
    /// "The user clicked the badge — bring the consent window
    /// forward." The daemon ensures a consent-window child exists and
    /// raises it (the same kill-and-respawn foreground path a new ask
    /// or `secreq pending` takes). The badge itself never opens the
    /// consent UI — it only asks the daemon to.
    RaiseConsentRequested,
    /// "My OS focus state just changed." Sent by the consent-window
    /// child whenever `egui::InputState.focused` transitions; lets the
    /// daemon distinguish "UI is alive AND in front" from "UI is alive
    /// but the user has tabbed away." Used to skip the kill-and-respawn
    /// raise on a new ask when the existing window is already focused
    /// (the streaming snapshot already paints the new entry — no need to
    /// disrupt the user).
    ///
    /// Default at attach is `focused = true`: a freshly-spawned child
    /// gets foreground intent on macOS, so until we hear otherwise the
    /// safe assumption is that it's in front.
    ConsentWindowFocus { focused: bool },

    // ── Streaming protocol for the manager-window child process ──
    //
    // The manager is the persistent Rules + Audit surface, a separate
    // child process from the transient prompt. It subscribes to the
    // same `ConsentUpdate` snapshot stream (it needs live rules and the
    // viewer-mode flag) but is never subject to the prompt's auto-hide
    // or kill-and-respawn raise machinery: it closes when the user
    // closes it, or on daemon shutdown.
    /// "I'm the manager-window child process; subscribe me to snapshot
    /// updates and accept rule mutations from me." Daemon replies with
    /// an immediate `ConsentUpdate` carrying the current snapshot.
    /// `pid` serves the same CLI-activation purpose as
    /// [`ConsentWindowAttach`]'s.
    ManagerWindowAttach { pid: u32 },
    /// "The user clicked 'Open Manager…' in the prompt." The daemon
    /// spawns a manager-window child (opening on `focus`) if none is
    /// attached; if one is already up, the request is logged and the
    /// existing window is left alone (raising it is the CLI's job on
    /// the `secreq view` path).
    OpenManager { focus: ManagerFocus },

    // ── Auto-rules management ─────────────────────────────────────
    //
    // These messages are sent by the UI (the consent-window child) and
    // by the `secreq rules …` CLI verbs. The daemon is the single
    // writer of the rules file — clients never poke the file directly.
    // See `src/rules.rs` and `brain: areas/secreq/design/2026-06-02-auto-rules.md`.
    /// "Give me the current ruleset." Daemon replies with
    /// [`DaemonMsg::RulesList`].
    ListRules,
    /// "Create this rule." The daemon validates the rule, persists it,
    /// and refreshes the in-memory ruleset. Replies `Ok` on success
    /// or `Err` on validation failure.
    ///
    /// A *wasm* rule with an empty `trained_secrets` snapshot is
    /// refused on this path: an empty snapshot disables the
    /// trained-secrets guard (unlimited blast radius), and the only
    /// door that accepts it is [`ClientMsg::AddWasmRule`] with its
    /// explicit `allow_all_secrets` opt-in — both doors carry the
    /// same lock.
    AddRule { rule: Rule },
    /// "Register this compiled wasm module as a new rule." Sent by
    /// `secreq rules add-wasm`. Carries the module's *path*, not its
    /// bytes: daemon and CLI run as the same user on the same machine,
    /// so the daemon reading the file directly is the simpler correct
    /// path (no binary payload on the line-based JSON wire). The CLI
    /// canonicalizes to an absolute path first — the daemon's cwd is
    /// not the caller's.
    ///
    /// The daemon vets the module in the wasm sandbox
    /// (registration-time checks: imports, abort signature, memory
    /// cap, exports), copies it into the canonical store
    /// (`rules/<id>.wasm` under the secreq root), records its sha256,
    /// and persists the rule. Replies [`DaemonMsg::RuleAdded`] with
    /// the created rule, or `Err` — in which case nothing was
    /// registered and no file was left behind.
    ///
    /// `trained_secrets` is the env-var-name snapshot the rule is
    /// allowed to decide (the same guard UI-created rules get from the
    /// ask they were trained on; the CLI sources it from `--secret`
    /// flags). An empty set disables the guard — unlimited blast
    /// radius — so it requires the explicit `allow_all_secrets` opt-in
    /// or the daemon refuses the registration.
    AddWasmRule {
        name: String,
        module_path: String,
        trained_secrets: BTreeSet<String>,
        #[serde(default)]
        allow_all_secrets: bool,
    },
    /// "Replace the rule with this `id` with the supplied content."
    /// Replies `Ok` on success, `Err` if the id is unknown.
    UpdateRule { rule: Rule },
    /// "Remove the rule with this `id`."
    DeleteRule { id: String },
    /// "Toggle the enabled bit on this rule." Cheaper-and-clearer than
    /// `UpdateRule` for the common "pause this rule" UI affordance.
    SetRuleEnabled { id: String, enabled: bool },
}

impl ClientMsg {
    /// The Rust variant name, for the daemon's `← ClientMsg::…` log line.
    ///
    /// Deliberately *not* the `snake_case` wire name serde derives from
    /// `#[serde(tag = "kind")]`: the log is read against this source, and
    /// the only way to recover the derived name is to serialize the whole
    /// message — which on an [`ClientMsg::Ask`] means walking payload the
    /// daemon has no business writing to a log to name it.
    ///
    /// Lives here rather than in the server so that adding a variant is one
    /// file's edit; the `match` is exhaustive, so forgetting one is a
    /// compile error rather than a silently wrong log line.
    pub fn tag(&self) -> &'static str {
        match self {
            ClientMsg::Ping => "Ping",
            ClientMsg::Hello { .. } => "Hello",
            ClientMsg::ShowWindow => "ShowWindow",
            ClientMsg::ShowViewer => "ShowViewer",
            ClientMsg::Ask(_) => "Ask",
            ClientMsg::Shutdown => "Shutdown",
            ClientMsg::ConsentWindowAttach { .. } => "ConsentWindowAttach",
            ClientMsg::ConsentDecision { .. } => "ConsentDecision",
            ClientMsg::ConsentWindowDetach => "ConsentWindowDetach",
            ClientMsg::ConsentWindowFocus { .. } => "ConsentWindowFocus",
            ClientMsg::ManagerWindowAttach { .. } => "ManagerWindowAttach",
            ClientMsg::OpenManager { .. } => "OpenManager",
            ClientMsg::BadgeWindowAttach { .. } => "BadgeWindowAttach",
            ClientMsg::BadgeWindowDetach => "BadgeWindowDetach",
            ClientMsg::RaiseConsentRequested => "RaiseConsentRequested",
            ClientMsg::ListRules => "ListRules",
            ClientMsg::AddRule { .. } => "AddRule",
            ClientMsg::AddWasmRule { .. } => "AddWasmRule",
            ClientMsg::UpdateRule { .. } => "UpdateRule",
            ClientMsg::DeleteRule { .. } => "DeleteRule",
            ClientMsg::SetRuleEnabled { .. } => "SetRuleEnabled",
        }
    }
}

/// Everything the daemon needs to render the prompt **and** resolve the
/// secrets after the user approves. Carries no secret *values* — only
/// addresses (locators) and the templates needed to fetch them.
///
/// The three fields here are the ones every ask has whatever it is asking
/// for. Everything else hangs off [`Ask::subject`], because the three kinds
/// of ask do not share a field set — see [`AskSubject`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ask {
    /// Argv of the command the wrap will exec. Synthesized on the two
    /// non-wrap paths (`ssh-sign <key_id>`, `agent-resolve <ref>`) so the
    /// prompt's subtitle and the audit row have something to print.
    pub command: Vec<String>,
    /// Coalescing key: parallel asks with the same key fold into one queue
    /// entry. Today: `(wrap_name, anchor, subject_digest)`, where the anchor
    /// is a process, a `run` session, or a scoped agent's socket — see
    /// [`AskAnchor`].
    pub dedupe_key: DedupeKey,
    /// What is being asked for, and everything that is only meaningful for
    /// that kind of request.
    pub subject: AskSubject,
}

/// The three genuinely different things an [`Ask`] can be.
///
/// These used to be a `Vec<Caller>`, a `Vec<SecretAsk>` and two `Option`s on
/// `Ask` itself, with the emptiness rules ("`callers` is empty for a guest",
/// "`secrets` is empty for a sign") written in doc comments and enforced by
/// each producer remembering them. Two of those rules are load-bearing for
/// security, so they are fields' *presence* now rather than prose:
///
/// - **A guest ask has no `callers` field at all.** `callers` is
///   kernel-sourced, is what `rules.rs` matches on, and is what the prompt
///   renders as `ASKED BY`. A guest has no host pid to walk (see the
///   provenance section of
///   `brain: areas/secreq/design/2026-07-16-remote-secret-agent.md`), so what it
///   claims about itself rides [`AgentAskInfo::guest_chain`] — display-only,
///   marked unverifiable on screen. There is no longer anywhere to write a
///   guest's story that provenance code would read.
/// - **Only a wrap ask has `secrets` and `providers`.** Those two fields
///   are the resolution payload: the daemon runs the provider's `retrieve`
///   template against them after an approve and ships the values back. A
///   sign resolves its key in-process; a guest resolves its own ref in the
///   `agent open` process. Neither may name a secret for the daemon to
///   fetch, and now neither can.
///
/// The old shape also admitted `(Some(ssh), Some(agent))`, which meant
/// nothing: consumers disagreed about which `Option` to test first, so two
/// of them could render the same ask as two different requests. That state
/// no longer exists.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AskSubject {
    /// A wrap (`secreq x …`), a `secreq run`, or a `secreq read`: a local
    /// process asking for secrets to be injected.
    Wrap(WrapSubject),
    /// An SSH-agent sign request. The daemon *is* the agent here, so there
    /// is no client — but there is a real socket peer, and therefore a real
    /// caller chain.
    SshSign(SshSubject),
    /// A guest (VM) resolving a `secret://` ref through
    /// [`crate::scoped_agent`]. The host-declared scope is the principal;
    /// there is no host process behind the request to describe.
    ScopedAgent(AgentAskInfo),
}

/// The wrap ask's payload: who is asking, and what they want injected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrapSubject {
    /// Working directory of the requesting process.
    pub cwd: String,
    /// Parent-process chain, nearest-first.
    pub callers: Vec<Caller>,
    /// True when the walk that produced `callers` stopped at its own ceiling
    /// with an ancestor still above the outermost frame. See
    /// [`Ask::callers_truncated`].
    #[serde(default)]
    pub callers_truncated: bool,
    /// Secrets to be granted: name + reference + reason. The locator is
    /// not a value, so it's safe on the wire — and the daemon needs it to
    /// invoke the provider's `retrieve` template.
    pub secrets: Vec<SecretAsk>,
    /// The provider definitions the daemon needs to run resolution. Each
    /// `SecretAsk.provider` must be a key here. We send a *snapshot* per
    /// ask so the daemon doesn't have to re-read the user's config file
    /// (and so coalesced asks all agree on what to run).
    pub providers: HashMap<String, WireProvider>,
    /// Whether an `ApproveRemember` decision on this ask may persist a
    /// remembered approval. `true` for wrap (`x`) asks; `false` for
    /// `secreq run`, whose fixed `"run"` identity would otherwise let one
    /// remembered approval cover any later command in the same shell.
    ///
    /// Lives here rather than on [`Ask`] because the approvals cache is
    /// keyed on `(wrap, parent ProcessIdentity)` and only wrap asks are
    /// ever looked up in it. An SSH sign remembers through `SshGrant`; a
    /// guest remembers through the `agent open` process's own
    /// `ScopeApprovals`. Neither used to read this field, and both had to
    /// pick a value for it anyway.
    pub allow_remember: bool,
    /// `true` when this ask is a `secreq run` invoked under an already-
    /// consented run (the inner run saw the [`crate::RUN_SESSION_ENV`]
    /// marker its parent set). The daemon may then serve the ask straight
    /// from the secret cache without showing the consent window — but
    /// *only* when every value is already cached (`ask_fully_cached`), so
    /// any uncached secret still prompts. A top-level run never sets this,
    /// so it always prompts.
    pub nested_run: bool,
    /// Ignore any remembered approval for this ask: prompt even on a cache
    /// hit, and do not persist a new entry.
    ///
    /// What `--no-remember` / `--sq-no-remember` means. The flag was parsed
    /// into `WrapRunOpts` and then never read by anything, while both doc
    /// pages promised "don't read or write the remembered-approval cache" —
    /// so a user asking for one specific invocation to be gated got the
    /// silent cached release instead, audited as `approve+cached` with
    /// nothing recording that they had asked.
    ///
    /// The write half needs no field: the client sets `allow_remember` to
    /// false alongside this.
    pub ignore_remembered: bool,
}

/// The SSH sign ask's payload.
///
/// No `secrets` and no `providers`: the SSH path resolves the private key
/// in-process after consent (`daemon::ssh_agent::resolve_and_sign`) rather
/// than handing a value back to a client, which is what keeps the key out of
/// the wire reply entirely.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshSubject {
    /// Working directory of the socket peer, when the platform will say.
    /// May be empty — the prompt omits the `IN` row rather than rendering a
    /// blank one.
    pub cwd: String,
    /// Parent-process chain of the socket peer, nearest-first. Kernel-
    /// sourced, exactly like a wrap ask's: this path has always derived
    /// provenance from `SO_PEERCRED` rather than trusting a client.
    pub callers: Vec<Caller>,
    /// True when the walk that produced `callers` stopped at its own ceiling
    /// with an ancestor still above the outermost frame. See
    /// [`Ask::callers_truncated`].
    #[serde(default)]
    pub callers_truncated: bool,
    /// The key identity, its fingerprint, and the session a grant binds to.
    pub info: SshAskInfo,
}

impl Ask {
    /// The caller chain, or `&[]` for a guest ask that structurally has
    /// none.
    ///
    /// Every reader of this wants "the kernel-sourced chain behind this
    /// request, if there is one". A guest ask returning empty is the same
    /// answer the old `Ask::callers` gave — the difference is that a guest
    /// ask can no longer be *given* a chain, so an empty result here is a
    /// fact about the ask's kind rather than a field nobody filled in.
    pub fn callers(&self) -> &[Caller] {
        match &self.subject {
            AskSubject::Wrap(w) => &w.callers,
            AskSubject::SshSign(s) => &s.callers,
            AskSubject::ScopedAgent(_) => &[],
        }
    }

    /// Whether [`Ask::callers`] is the whole ancestry or only its innermost
    /// part.
    ///
    /// `provenance`'s walk stops after a fixed number of frames. Storage is
    /// nearest-first, so the frames it gives up are the *outermost* ones —
    /// exactly the ones that answer "where did this ultimately come from".
    /// The prompt draws the chain root-first and had no way to tell a real
    /// root from the walk's stopping point, so a caller deep enough inside its
    /// own ancestry could put the frame of its choosing at the top of the
    /// tree and have the user read it as the origin.
    ///
    /// A guest ask has no chain to have walked past, so nothing can be
    /// missing from it.
    pub fn callers_truncated(&self) -> bool {
        match &self.subject {
            AskSubject::Wrap(w) => w.callers_truncated,
            AskSubject::SshSign(s) => s.callers_truncated,
            AskSubject::ScopedAgent(_) => false,
        }
    }

    /// The local process the daemon saw naming this ask's scope, on a
    /// scoped-agent ask; `None` on every other kind.
    ///
    /// Stamped by `server::adopt_peer_provenance` before anything reads the
    /// ask, so this is the kernel's answer and not the client's. `Some(Gone)`
    /// when the peer had already exited — a distinction the audit row keeps,
    /// because a row that looks the same whether or not anything checked is
    /// the failure the field exists to fix.
    pub fn declared_by(&self) -> Option<crate::audit::ScopeDeclarant> {
        match &self.subject {
            AskSubject::ScopedAgent(agent) => Some(match &agent.declared_by {
                Some(peer) => crate::audit::ScopeDeclarant::Peer(crate::audit::AuditLocalPeer {
                    pid: peer.pid,
                    name: peer.name.clone(),
                    command: peer.command.clone(),
                    exe: peer.exe.clone(),
                }),
                None => crate::audit::ScopeDeclarant::Gone,
            }),
            AskSubject::Wrap(_) | AskSubject::SshSign(_) => None,
        }
    }

    /// The frame a sign grant would bind to, on a sign ask; `None` on every
    /// other kind.
    ///
    /// Read by [`crate::daemon::state::State::withdraw_waiter`]'s audit row: a
    /// sign whose requester gave up still writes an `ssh:` row, and that row
    /// has to say whether the sign was arriving through a forwarded agent for
    /// the same reason a completed one does. It cannot be re-derived there —
    /// the forwarding client is the socket peer, and [`Ask::callers`] starts
    /// above it.
    pub fn sign_anchor(&self) -> Option<&SshAnchorInfo> {
        match &self.subject {
            AskSubject::SshSign(s) => s.info.anchor.as_ref(),
            AskSubject::Wrap(_) | AskSubject::ScopedAgent(_) => None,
        }
    }

    /// Secrets the daemon is being asked to resolve, or `&[]` when this ask
    /// resolves nothing daemon-side (every non-wrap kind).
    pub fn secrets(&self) -> &[SecretAsk] {
        match &self.subject {
            AskSubject::Wrap(w) => &w.secrets,
            AskSubject::SshSign(_) | AskSubject::ScopedAgent(_) => &[],
        }
    }

    /// The requesting process's working directory, or `""` when there is no
    /// host process to have one (a guest's cwd is in another kernel).
    pub fn cwd(&self) -> &str {
        match &self.subject {
            AskSubject::Wrap(w) => &w.cwd,
            AskSubject::SshSign(s) => &s.cwd,
            AskSubject::ScopedAgent(_) => "",
        }
    }

    /// Whether an `ApproveRemember` on this ask may write the approvals
    /// cache. Only a wrap ask is ever looked up there.
    pub fn allow_remember(&self) -> bool {
        match &self.subject {
            AskSubject::Wrap(w) => w.allow_remember,
            AskSubject::SshSign(_) | AskSubject::ScopedAgent(_) => false,
        }
    }

    /// The provider definitions resolution runs against, or an empty map for
    /// a kind that resolves nothing daemon-side.
    ///
    /// Both callers reach this only after finding something in
    /// [`Ask::secrets`] to resolve, so the empty map is unreachable in
    /// practice — it exists so neither has to carry an "impossible" branch.
    pub fn providers(&self) -> &HashMap<String, WireProvider> {
        static EMPTY: std::sync::LazyLock<HashMap<String, WireProvider>> =
            std::sync::LazyLock::new(HashMap::new);
        match &self.subject {
            AskSubject::Wrap(w) => &w.providers,
            AskSubject::SshSign(_) | AskSubject::ScopedAgent(_) => &EMPTY,
        }
    }

    /// Whether this ask asked to be gated even where a remembered approval
    /// exists (`--no-remember`). Only a wrap ask reads that cache, so every
    /// other kind answers `false` — the value they used to carry and nothing
    /// consulted.
    pub fn ignore_remembered(&self) -> bool {
        match &self.subject {
            AskSubject::Wrap(w) => w.ignore_remembered,
            AskSubject::SshSign(_) | AskSubject::ScopedAgent(_) => false,
        }
    }

    /// Whether this is a `secreq run` nested under an already-consented run.
    /// Only a wrap ask can be.
    pub fn nested_run(&self) -> bool {
        match &self.subject {
            AskSubject::Wrap(w) => w.nested_run,
            AskSubject::SshSign(_) | AskSubject::ScopedAgent(_) => false,
        }
    }

    /// Mutable access to the wrap payload, for the two places that amend an
    /// ask after building it: the `run` path stamping `nested_run`, and the
    /// daemon merging a coalesced ask's secrets into the queue entry's
    /// representative.
    ///
    /// Deliberately the only mutable door into a subject, and deliberately
    /// one that can only ever hand back a [`WrapSubject`]. Nothing can reach
    /// through it to give a sign or a guest ask a caller chain, because
    /// neither variant is reachable from here.
    pub fn wrap_mut(&mut self) -> Option<&mut WrapSubject> {
        match &mut self.subject {
            AskSubject::Wrap(w) => Some(w),
            AskSubject::SshSign(_) | AskSubject::ScopedAgent(_) => None,
        }
    }
}

/// SSH-specific metadata carried on an [`Ask`] so the consent window can
/// render a sign request distinctly. Holds only display addresses — the
/// identity name and the public key's SHA256 fingerprint — never the
/// private key or any secret value. The SSH path resolves the private key
/// in-process after consent (see `daemon::ssh_agent`), so nothing secret
/// rides this struct or the wire.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SshAskInfo {
    /// The configured identity name (`ssh.<key_id>`), shown as the request's
    /// identity label.
    pub key_id: String,
    /// The public key's SHA256 fingerprint, e.g.
    /// `SHA256:Nh0Me49Zh9fDw/VYUfq43IJmI1T+XrjiYONPND8GzaM` — what
    /// `ssh-add -l` prints, so the user can match it against a key they know.
    pub fingerprint: String,
    /// The identity's configured `reason`, shown in the prompt to explain
    /// what the key is for (e.g. "git pushes"). `None` when the identity has
    /// no reason set. Lives here rather than on a `SecretAsk` because SSH
    /// signs carry no secrets to inject.
    #[serde(default)]
    pub reason: Option<String>,
    /// The session a 30-minute grant would attach to — the frame
    /// `provenance::select_anchor` picked out of the caller chain.
    ///
    /// Carried so the prompt can name it. The grant buttons are the only
    /// controls in the UI whose effect outlives the request on screen, and
    /// what they bind to is neither the command in the header nor the
    /// nearest caller: it is the shell or multiplexer further up. Without
    /// this the user is asked to approve a session the prompt never
    /// identifies.
    ///
    /// `None` on an ask with no anchor — a shape the SSH path refuses
    /// before it builds one, but the field is optional so no other ask
    /// producer has to invent a session it does not have.
    #[serde(default)]
    pub anchor: Option<SshAnchorInfo>,
}

/// The session an [`SshAskInfo`]'s grant buttons would bind to, in the terms
/// the prompt shows it: the process's name, its pid, and which of the two
/// kinds of session it is.
///
/// For a [`SignAnchorKind::Session`] anchor the pid is here to be *matched by
/// eye*: it also appears on that frame's row in the ASKED BY tree, so
/// "Session: zsh · 7926" points at a line the user is already reading rather
/// than asserting something they have to take on faith.
///
/// A [`SignAnchorKind::ForwardedSsh`] anchor cannot be matched that way — it
/// is the socket peer, and the chain starts above the peer — so that case
/// carries its `command` and the prompt draws the frame itself. A grant row
/// naming a process the window does not otherwise show would be worse than
/// the bug it replaced.
///
/// `name` is the sanitized `comm` (see `provenance::sanitize_display`), the
/// same string the tree renders for that frame, so the two agree
/// character-for-character. Which process is *selected* no longer depends on
/// that name — see `provenance::frame_identity`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SshAnchorInfo {
    pub name: String,
    pub pid: u32,
    /// Why this frame, which decides how the prompt labels the grant. A grant
    /// that says "Session" and attaches to an `ssh` client would be a prompt
    /// telling the truth about nothing.
    #[serde(default)]
    pub kind: SignAnchorKind,
    /// The anchor's own command line, carried only when the anchor is a frame
    /// the ASKED BY tree does not draw. `None` for a session anchor, which
    /// the tree already shows with its argv.
    #[serde(default)]
    pub command: Option<String>,
}

/// Scoped-agent metadata carried on an [`Ask`] so the consent window can
/// render a guest's request distinctly.
///
/// Holds only display addresses — the host-declared scope name and the
/// requested `secret://` ref — never a value. The scoped agent resolves the
/// ref itself *after* consent (see [`crate::scoped_agent::DaemonGate`]), so
/// nothing secret rides this struct or the wire.
///
/// Note which fields are **host-verifiable** and which is not, because the
/// prompt says so out loud. `scope` comes from the `agent open` invocation
/// and `reference` from an allowlist the host declared, so both are things
/// the host itself asserted. `guest_chain` is the one piece the *guest*
/// supplied, and it is display-only.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentAskInfo {
    /// The host-declared scope name (e.g. a sandbox name like
    /// `brain-nx-t5`) — the principal the prompt gates on.
    pub scope: String,
    /// The `secret://provider/locator` ref the guest asked for. Always one
    /// the scope's allowlist admits: out-of-scope refs are denied before any
    /// ask is built.
    pub reference: String,
    /// What the guest **claimed** is asking, already sanitized and rendered
    /// for display (`"node → pnpm → postinstall"`); `None` when it claimed
    /// nothing.
    ///
    /// **Display-only, and rendered with an explicit "not verifiable"
    /// marker.** The host cannot check a word of it — that is the provenance
    /// problem this whole design starts from — so it is offered to the *user*
    /// as a hint and to nothing else as a fact. It is carried here precisely
    /// so it cannot be mistaken for provenance: a caller chain is
    /// kernel-sourced and is what `rules.rs` matches on, and a guest able to
    /// write there could name a process that fires an auto-approve rule.
    /// [`AskSubject::ScopedAgent`] has no `callers` field for it to reach,
    /// which is the strongest form that separation can take.
    ///
    /// A pre-rendered `String` rather than a `Vec`: by the time a claim
    /// crosses this socket it is a label, and handing it back the shape of a
    /// caller list would only invite code to treat it like one.
    pub guest_chain: Option<String>,
    /// The local process that spoke this ask onto `consent.sock`, as the
    /// kernel reports it.
    ///
    /// **Stamped by the daemon, never by the client.**
    /// `server::adopt_peer_provenance` overwrites whatever arrives here
    /// before the prompt sees it, exactly as it overwrites a wrap ask's
    /// `callers` — the field is on the client's payload struct only because
    /// that is where the variant's data lives, not because a client may fill
    /// it in.
    ///
    /// This is the whole of the kind-forgery remainder. The daemon cannot
    /// tell a genuine `secreq agent open` from a local process claiming the
    /// guest kind — both arrive as the same `ClientMsg::Ask` on the same
    /// socket — so it does not try. It states what it *does* know: which
    /// local process is on the other end. A genuine ask names an `agent open`
    /// the user started; a forger names itself. Neither is refused, and the
    /// reader decides.
    ///
    /// **It is not the principal and must never become one.** The scope stays
    /// the gating identity, the grant anchor and the audit label, per the
    /// provenance section of
    /// `brain: areas/secreq/design/2026-07-16-remote-secret-agent.md`. This is a
    /// display fact about a *host* socket — `consent.sock`, which is
    /// per-user, `0600` and never forwarded — and says nothing whatever about
    /// the guest, which is in another kernel and behind whatever tunnel the
    /// scoped socket runs over.
    ///
    /// `None` when the peer could not be read at all (it exited between the
    /// `SO_PEERCRED` call and the lookup). Rendered as a refusal to guess,
    /// never as absence.
    #[serde(default)]
    pub declared_by: Option<LocalPeer>,
}

/// A local process as the kernel describes it, for a prompt that has to name
/// who is on the other end of a socket.
///
/// Deliberately not a [`Caller`]: a caller frame is part of an *ancestry*,
/// which is what `rules.rs` matches on and what `ASKED BY` renders. This is
/// one process on one socket, it reaches no rule and no cache key, and giving
/// it the shape of a chain frame would be an invitation to treat it as one.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalPeer {
    pub pid: u32,
    /// Sanitized `comm` — which the process chose for itself.
    pub name: String,
    /// Sanitized command line — which the process also chose for itself.
    pub command: String,
    /// Absolute path to the executable, when the kernel will say. **The only
    /// field here the process did not pick**, which is why the prompt renders
    /// it on its own line rather than folding it into the name.
    pub exe: Option<String>,
}

/// What an ask's queue identity hangs off — and, for exactly one variant,
/// what a remembered approval may be written against.
///
/// This used to be a bare `(ppid: u32, parent_start_time: u64)` pair on
/// [`DedupeKey`], and three producers put three different things in it: a
/// wrap or sign ask's kernel-verified parent, a `run` tree's `(outer pid,
/// random session nonce)`, and a scoped agent's own socket pid beside a
/// placeholder zero. Four consumers then read it, and they disagreed
/// visibly, in the names they bound it to — `RunSession { pid, nonce }` in
/// one place, `ProcessIdentity { pid, start_time }` in three others.
///
/// The three that read it as a [`ProcessIdentity`] did so *unconditionally*,
/// so a session nonce was looked up in the approvals cache as if it were a
/// start time, and the prompt offered that same coerced pair back to the
/// daemon as the scope to remember at. Neither misfired, and the reason was
/// never the type: `run` and scoped-agent asks set `allow_remember: false`,
/// so no [`crate::consent::ApprovalEntry`] under those wraps is ever stored
/// and a lookup needs an entry to hit. A flag in another file was all that
/// stood between a random `u64` and a cache key.
///
/// As a sum type the coercion has nowhere to happen:
/// [`AskAnchor::process_identity`] is the only door into
/// [`ProcessIdentity`], and it is shut for the two variants that are not
/// processes. The scope a decision may be remembered at is `Option` all the
/// way out to the prompt and back, so a session row has no honest value to
/// send and does not send one.
///
/// It also retires two `wrap == "run"` string comparisons —
/// `state::RunSession::of` and `server::adopt_peer_provenance` — that had to
/// agree with each other and with the producer, across three files, to keep
/// a run tree coalescing into one queue entry.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AskAnchor {
    /// The requesting process's direct parent, as the kernel described it.
    /// Wrap asks (re-derived from the socket peer by
    /// `server::adopt_peer_provenance`, never trusted from the client) and
    /// SSH sign asks (the sign anchor the daemon selected itself).
    ///
    /// **The only variant that reaches the approvals cache**, which is the
    /// whole point of the enum.
    Process(ProcessIdentity),
    /// A `secreq run` tree: the outer run's pid plus a random nonce minted
    /// by `commands::run::mint_session_token` and inherited verbatim by
    /// every nested run through [`crate::RUN_SESSION_ENV`].
    ///
    /// A session, not a process. The pid is here to make a queue entry
    /// legible to a human reading a log, not to identify anything; the nonce
    /// is what makes two trees never collide and one tree always coalesce.
    /// `server::adopt_peer_provenance` leaves it alone — re-deriving it per
    /// process would dissolve the tree into one entry per nested run — and
    /// `state::RunSession::of` is its only reader.
    RunSession { pid: u32, nonce: u64 },
    /// A scoped agent's socket, named by the agent process's own pid.
    ///
    /// Neither a process identity nor a session. The scoped agent's
    /// principal is the host-declared scope (see
    /// `brain: areas/secreq/design/2026-07-16-remote-secret-agent.md`), and
    /// its grants live in `scoped_agent::ScopeApprovals` rather than the
    /// daemon's parent-keyed cache. The pid is the honest answer to "who is
    /// parked on this decision" and nothing more: the socket's lifetime is
    /// this process's lifetime.
    AgentSocket { pid: u32 },
}

impl AskAnchor {
    /// The process a remembered approval may be written against, or `None`
    /// when this ask is not anchored to a process at all.
    ///
    /// The single door from an anchor to a [`ProcessIdentity`]. Everything
    /// that keys the approvals cache goes through it, so "a session nonce
    /// cannot become a start time" is a fact about the type rather than a
    /// convention held up by `allow_remember`.
    pub fn process_identity(self) -> Option<ProcessIdentity> {
        match self {
            AskAnchor::Process(identity) => Some(identity),
            AskAnchor::RunSession { .. } | AskAnchor::AgentSocket { .. } => None,
        }
    }

    /// The pid this anchor names, for display and for checking that a
    /// prompt's label describes the row it belongs to.
    ///
    /// **Not an identity**, and deliberately not convertible into one: a
    /// freed pid goes to whatever starts next, which is why
    /// [`ProcessIdentity`] exists at all. Nothing may key a cache on this.
    pub fn pid(self) -> u32 {
        match self {
            AskAnchor::Process(identity) => identity.pid,
            AskAnchor::RunSession { pid, .. } | AskAnchor::AgentSocket { pid } => pid,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct DedupeKey {
    pub wrap: String,
    /// What this ask's queue identity hangs off — a process, a `run`
    /// session, or a scoped agent's socket. See [`AskAnchor`] for why the
    /// three are a sum type rather than a pid beside a `u64`.
    pub anchor: AskAnchor,
    /// Distinguishes asks that agree on every other field but authorize
    /// different things.
    ///
    /// Coalescing folds asks with an equal key into one queue entry answered
    /// by one decision. That is correct when the key determines *what* is
    /// being authorized — for a wrap or `run` ask the secret set is the
    /// subject, it is rendered on the card, and merging two asks for it is
    /// the whole point.
    ///
    /// An SSH sign breaks that assumption. What it authorizes is the
    /// challenge blob, which is not in the key, not on the card, and not
    /// anywhere the user can see. Two signs for the same key from the same
    /// shell over completely different payloads were one request as far as
    /// the queue and the UI were concerned, so one Approve signed both.
    ///
    /// Set to a digest of the payload on that path, so identical bytes still
    /// coalesce (a genuine retry) and different bytes never do. `None`
    /// elsewhere. Kept out of `wrap`, which rules match on as
    /// `ssh:<key_id>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_digest: Option<String>,
}

/// One process in an ask's caller chain, on the wire.
///
/// **Field-identical to [`crate::provenance::Caller`], and deliberately not
/// merged with it.** A `pub use` would absorb the whole rename — three
/// hand-written `.map(|c| proto::Caller { … })` blocks and nothing else — so
/// the cost of keeping them apart is thirty lines, and the reason is worth
/// more than thirty lines:
///
/// - **The conversion is one-directional, and the direction is the security
///   property.** `server::adopt_peer_provenance` replaces what a client sent
///   with what the daemon walked. One type makes `ask.callers` and
///   `chain.frames` assignment-compatible *both* ways, so the compiler stops
///   telling a reader which of the two a value is. Today
///   `chain.frames = ask.callers().to_vec()` does not compile, at the one
///   site where writing it would undo the fix.
/// - **They are allowed to diverge, and the pressure is real rather than
///   hypothetical.** The walk already knows things the wire must not carry:
///   `provenance::PeerProcess` hangs `forwards_agent` off a `Caller` instead
///   of adding a field, precisely because a wire field there would turn a
///   fact derived from raw argv into a claim a client could write. Merging
///   makes every future addition to the walk a protocol change by default,
///   in a file whose job is to be the readable list of what crosses this
///   socket.
///
/// [`crate::audit::AuditCaller`] is the third of these on purpose and for a
/// third reason: it is a *persisted* record and keeps only what a reader
/// months later can use.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Caller {
    pub pid: u32,
    pub name: String,
    pub command: String,
    /// Process start time as `sysinfo` reports it. Paired with `pid` it is
    /// what makes an ancestor cache hit pid-recycle-safe — a new process
    /// inheriting the same pid will have a different start_time, so it can't
    /// ride an old approval. Read the pair through [`Caller::identity`], not
    /// field by field. Default 0 for any client that hasn't been updated yet;
    /// matching against 0 just falls through.
    #[serde(default)]
    pub start_time: u64,
    /// Absolute path to the executable, when the kernel will say.
    ///
    /// The identity that cannot be chosen by the process it names. `name` is
    /// `comm`, which a process sets on itself with one `prctl(PR_SET_NAME)`
    /// on Linux, or by being a file called `zsh` on macOS — so anything that
    /// keys on the name inherits whatever the namer wanted. `exe` is what was
    /// loaded.
    ///
    /// `Option` because sysinfo cannot always resolve it (short-lived
    /// processes, some platforms). Consumers fall back to `name` when it is
    /// absent rather than dropping the frame, so an unresolvable exe degrades
    /// to the old behaviour instead of erasing the caller.
    #[serde(default)]
    pub exe: Option<String>,
}

impl Caller {
    /// This frame's [`ProcessIdentity`] — the wire twin of
    /// [`crate::provenance::Caller::identity`], and the only way the daemon
    /// should turn a frame into a cache scope. Reading `pid` and `start_time`
    /// separately at a call site is how one of them gets left behind.
    pub fn identity(&self) -> ProcessIdentity {
        ProcessIdentity {
            pid: self.pid,
            start_time: self.start_time,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretAsk {
    pub name: String,
    pub provider: String,
    pub locator: String,
    pub default: Option<String>,
    pub description: Option<String>,
    pub reason: Option<String>,
    /// Commands that requested this secret, for the session card's
    /// `← command` provenance. Empty from the client; the daemon stamps
    /// it as asks merge. `#[serde(default)]`.
    #[serde(default)]
    pub requested_by: Vec<String>,
    /// The name this secret is declared under in the host's `secrets`
    /// block, when the config referenced it as `secret://<name>`. `None`
    /// for an inline `secret://provider/locator`, which names nothing.
    ///
    /// Display metadata only — resolution and the cache key are still
    /// `provider` + `locator`, so nothing downstream learns a second kind
    /// of reference. `#[serde(default)]`.
    #[serde(default)]
    pub declared_as: Option<String>,
    /// How long the daemon may serve this secret from its value cache.
    /// Read from the declaration alongside `declared_as`; defaults to
    /// [`CacheTtl::DaemonLifetime`], which is what an inline reference and
    /// an undeclared `ttl` both mean.
    ///
    /// Client-supplied, like the `providers` block on the same ask — and
    /// for the same reason it is not a new trust surface: this ask already
    /// tells the daemon which *command to execute* to fetch the value, so
    /// a field that can only make the daemon re-fetch more often adds
    /// nothing an attacker did not have. `#[serde(default)]`.
    #[serde(default)]
    pub ttl: crate::wraps::CacheTtl,
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
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DaemonMsg {
    /// The decision plus, on approve, the resolved secret values keyed by
    /// env-var name. On `Deny`, `secrets` is empty.
    ///
    /// `rule_id` / `rule_name` are `Some` when a matching auto-rule fired
    /// (decision is `ApproveAuto` or `DenyAuto`); the client uses them
    /// for the audit row and the auto-deny stderr message.
    /// `reason` is the explanation on a manual denial or the rule's
    /// configured message on auto-deny.
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
        reason: Option<String>,
        /// On a scoped-agent ask, the peer the daemon stamped onto
        /// [`AgentAskInfo::declared_by`]; `None` on every other kind.
        ///
        /// Sent back because the scoped agent is a *client* and writes its own
        /// audit rows, and this is the one thing on such a row that the client
        /// cannot honestly supply: a process writing its own pid here would
        /// make the row a claim, where the whole value is that it is the
        /// kernel's answer. See [`crate::audit::AuditEntry::declared_by`].
        #[serde(default)]
        declared_by: Option<crate::audit::ScopeDeclarant>,
        /// Per-secret approver attribution on an `ApproveAuto`: each
        /// granted secret name → the id of the rule that blessed it. The
        /// client records it in the audit row. Empty on every other
        /// decision (a deny grants nothing); `#[serde(default,
        /// skip_serializing_if)]` so older daemons and non-approve
        /// replies round-trip unchanged.
        #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
        approvers: std::collections::BTreeMap<String, String>,
    },
    /// Generic acknowledgement (Ping / ConsentWindowDetach / Shutdown).
    Ok,
    /// Reply to [`ClientMsg::Hello`]: the daemon's compile-time
    /// [`crate::BUILD_ID`]. The CLI compares it to its own to decide
    /// whether the running daemon is stale and should be restarted.
    Hello { build_id: String },
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

    /// Reply to [`ClientMsg::ListRules`]. Carries the current ruleset
    /// plus every refusal recorded against it — a wasm module that would
    /// not load, a match pattern that would not compile. A refused rule
    /// stays in `rules` but cannot fire as written, and list/show render
    /// the refusal so it's visible outside the daemon log.
    ///
    /// A newtype around [`RuleListing`] rather than loose fields: the
    /// two halves are not interchangeable, and the client used to hand
    /// them back as an unnamed tuple.
    RulesList(RuleListing),
    /// Reply to [`ClientMsg::AddWasmRule`]: the rule as registered
    /// (with its minted id, stored module path, and recorded sha256)
    /// so the CLI can print what was created. Boxed so this one-shot
    /// admin reply doesn't inflate every `DaemonMsg` on the hot paths
    /// (clippy: large_enum_variant).
    RuleAdded { rule: Box<Rule> },

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

impl DaemonMsg {
    /// The Rust variant name, for the daemon's `→ DaemonMsg::…` log line.
    ///
    /// The counterpart to [`ClientMsg::tag`], and here for the same reason:
    /// naming a reply is the protocol's business, not the server's, so
    /// adding a variant is one file's edit.
    ///
    /// Two variants say more than their name. `WindowOpened` distinguishes
    /// the pid-carrying "a child was already up" reply from the `None`
    /// "one is being spawned" reply, which is the only way to read a raise
    /// out of the log. And a [`DaemonMsg::Decision`] is named by its
    /// [`Decision`] — the outcome is the whole content of that reply, and
    /// a log full of undifferentiated `Decision` would say nothing.
    ///
    /// Several `Decision` variants can never appear on this reply: the SSH
    /// ones ride the in-process sign waiter, and the scoped-agent ones are
    /// either acted on by the agent process or refused before an ask is
    /// made. They are named anyway because [`Decision`] is shared and the
    /// match is exhaustive.
    pub fn tag(&self) -> &'static str {
        match self {
            DaemonMsg::Ok => "Ok",
            DaemonMsg::Hello { .. } => "Hello",
            DaemonMsg::WindowOpened { child_pid } => match child_pid {
                Some(_) => "WindowOpened(existing)",
                None => "WindowOpened(spawning)",
            },
            DaemonMsg::Decision { decision, .. } => match decision {
                Decision::Approve => "Decision::Approve",
                Decision::ApproveRemember => "Decision::ApproveRemember",
                Decision::ApproveCached => "Decision::ApproveCached",
                Decision::ApproveAuto => "Decision::ApproveAuto",
                Decision::ApproveSshSession => "Decision::ApproveSshSession",
                Decision::ApproveSshSessionAll => "Decision::ApproveSshSessionAll",
                Decision::ApproveAgentSession => "Decision::ApproveAgentSession",
                Decision::Deny => "Decision::Deny",
                Decision::DenyAuto => "Decision::DenyAuto",
                Decision::DenyOutOfScope => "Decision::DenyOutOfScope",
                Decision::Abandoned => "Decision::Abandoned",
            },
            DaemonMsg::Err { .. } => "Err",
            DaemonMsg::ConsentUpdate { .. } => "ConsentUpdate",
            DaemonMsg::ConsentExitPlease => "ConsentExitPlease",
            DaemonMsg::RulesList(_) => "RulesList",
            DaemonMsg::RuleAdded { .. } => "RuleAdded",
            DaemonMsg::AutoDenyToast { .. } => "AutoDenyToast",
        }
    }
}

/// Hand-written so `{:?}` cannot print resolved secret values.
///
/// [`SecretValue`](crate::secret::SecretValue) goes to real trouble to redact
/// its own `Debug`, but by the time values reach [`DaemonMsg::Decision`] they
/// are plain `String`s in a map, and a derive would print all of them. Five
/// call sites in `daemon::client` end with `other => bail!("… {other:?}")`,
/// so any protocol desync — a stale daemon, a reply-routing bug, a future
/// connection-reuse optimisation — would put the whole secret set into an
/// error, which reaches stderr and, daemon-side, `daemon.log`.
///
/// Names are kept: they are what the audit log records anyway, and an error
/// naming which secrets were in flight is worth having.
impl std::fmt::Debug for DaemonMsg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DaemonMsg::Decision {
                decision,
                secrets,
                rule_id,
                rule_name,
                reason,
                declared_by,
                approvers,
            } => f
                .debug_struct("Decision")
                .field("decision", decision)
                .field("secrets", &RedactedNames(secrets))
                .field("rule_id", rule_id)
                .field("rule_name", rule_name)
                .field("reason", reason)
                .field("declared_by", declared_by)
                // Secret *names* → rule ids. No values, so it prints in
                // full — the same reasoning that keeps names above.
                .field("approvers", approvers)
                .finish(),
            DaemonMsg::Ok => f.write_str("Ok"),
            DaemonMsg::Hello { build_id } => {
                f.debug_struct("Hello").field("build_id", build_id).finish()
            }
            DaemonMsg::WindowOpened { child_pid } => f
                .debug_struct("WindowOpened")
                .field("child_pid", child_pid)
                .finish(),
            DaemonMsg::Err { message } => f.debug_struct("Err").field("message", message).finish(),
            DaemonMsg::ConsentUpdate { .. } => f.write_str("ConsentUpdate { .. }"),
            DaemonMsg::ConsentExitPlease => f.write_str("ConsentExitPlease"),
            DaemonMsg::RulesList(_) => f.write_str("RulesList { .. }"),
            DaemonMsg::RuleAdded { rule } => {
                f.debug_struct("RuleAdded").field("rule", rule).finish()
            }
            DaemonMsg::AutoDenyToast { .. } => f.write_str("AutoDenyToast { .. }"),
        }
    }
}

/// Renders a secret map as its key names, never its values.
struct RedactedNames<'a>(&'a HashMap<String, String>);

impl std::fmt::Debug for RedactedNames<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut names: Vec<&str> = self.0.keys().map(String::as_str).collect();
        names.sort_unstable();
        write!(f, "{{{} redacted: {names:?}}}", names.len())
    }
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
    /// Everything refused about those rules — an unloadable wasm module,
    /// a pattern that is not a valid glob — so the manager's Rules tab
    /// can badge them. `#[serde(default)]` for back-compat.
    #[serde(default)]
    pub refusals: RuleRefusals,
}

/// Lifecycle state of a row the consent window renders.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum RowStatus {
    /// Queued and awaiting a user decision — Approve/Deny buttons shown.
    #[default]
    Awaiting,
    /// Already authorized (manual approve, approvals-cache hit, or
    /// auto-rule), with a provider call (and possibly a biometric
    /// prompt) in flight on a cold cache. Rendered as a read-only
    /// "Resolving…" card so the prompt keeps its provenance on screen.
    Resolving,
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
    /// Awaiting (queued) vs Resolving (approved, value in flight).
    /// `#[serde(default)]` so an older child decoding a newer daemon's
    /// snapshot treats unknown rows as the common Awaiting case.
    #[serde(default)]
    pub status: RowStatus,
}

#[cfg(test)]
mod anchor_tests {
    use super::{AskAnchor, DedupeKey};
    use crate::provenance::ProcessIdentity;

    fn key(anchor: AskAnchor) -> DedupeKey {
        DedupeKey {
            wrap: "gh".to_owned(),
            anchor,
            subject_digest: None,
        }
    }

    const PROCESS: AskAnchor = AskAnchor::Process(ProcessIdentity {
        pid: 6042,
        start_time: 12345,
    });
    const SESSION: AskAnchor = AskAnchor::RunSession {
        pid: 6042,
        nonce: 12345,
    };
    const SOCKET: AskAnchor = AskAnchor::AgentSocket { pid: 6042 };

    /// The anchor crosses `consent.sock` inside every `Ask`, so its encoding
    /// is the ask protocol. Tagged rather than positional, so a daemon log
    /// or a packet capture says which of the three a row is holding.
    #[test]
    fn each_anchor_round_trips_through_the_wire_form() {
        for anchor in [PROCESS, SESSION, SOCKET] {
            let json = serde_json::to_string(&key(anchor)).expect("serialize");
            let back: DedupeKey = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back.anchor, anchor, "{json}");
        }
        let json = serde_json::to_string(&key(SESSION)).expect("serialize");
        assert!(json.contains("run_session"), "{json}");
    }

    /// Coalescing folds asks with an equal [`DedupeKey`] into one queue entry
    /// answered by one decision, so what counts as "equal" here is what
    /// counts as "the same authorization".
    ///
    /// Three anchors carrying the same pid and the same second number are
    /// three different things, and the enum is what makes them three
    /// different values. Under the old `(ppid, parent_start_time)` pair the
    /// first two below were byte-identical, and `wrap == "run"` — checked in
    /// two other files — was the only thing telling them apart.
    #[test]
    fn anchors_of_different_kinds_never_coalesce() {
        assert_ne!(PROCESS, SESSION);
        assert_ne!(PROCESS, SOCKET);
        assert_ne!(SESSION, SOCKET);
        assert_ne!(key(PROCESS), key(SESSION));
    }

    /// The property the rest of the daemon leans on: only a process anchor
    /// yields a [`ProcessIdentity`], which is the only thing the approvals
    /// cache can be keyed on.
    #[test]
    fn only_a_process_anchor_yields_a_process_identity() {
        assert_eq!(
            PROCESS.process_identity(),
            Some(ProcessIdentity {
                pid: 6042,
                start_time: 12345,
            })
        );
        assert_eq!(SESSION.process_identity(), None);
        assert_eq!(SOCKET.process_identity(), None);
        // All three still name a pid, which is display and nothing else.
        for anchor in [PROCESS, SESSION, SOCKET] {
            assert_eq!(anchor.pid(), 6042);
        }
    }
}

#[cfg(test)]
mod debug_redaction_tests {
    use super::*;

    /// `SecretValue` redacts its own `Debug`, but resolved values reach
    /// `DaemonMsg::Decision` as plain `String`s in a map. Five call sites in
    /// `daemon::client` end with `bail!("… {other:?}")`, so a derived Debug
    /// would put the whole secret set into an error that reaches stderr and
    /// `daemon.log`.
    #[test]
    fn decision_debug_shows_names_but_never_values() {
        let mut secrets = HashMap::new();
        secrets.insert("GITHUB_TOKEN".to_owned(), "ghp_supersecretvalue".to_owned());
        secrets.insert("NPM_TOKEN".to_owned(), "npm_anothersecret".to_owned());

        let rendered = format!(
            "{:?}",
            DaemonMsg::Decision {
                decision: Decision::Approve,
                secrets,
                rule_id: None,
                rule_name: None,
                reason: None,
                declared_by: None,
                approvers: std::collections::BTreeMap::new(),
            }
        );

        assert!(!rendered.contains("ghp_supersecretvalue"), "{rendered}");
        assert!(!rendered.contains("npm_anothersecret"), "{rendered}");
        // The names survive: they are what the audit log records anyway, and
        // an error naming which secrets were in flight is worth having.
        assert!(rendered.contains("GITHUB_TOKEN"), "{rendered}");
        assert!(rendered.contains("NPM_TOKEN"), "{rendered}");
    }
}
