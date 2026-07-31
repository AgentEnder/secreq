//! Screenshot harness for the secreq window UIs.
//!
//! This test target renders the egui surfaces in a set of
//! representative states and writes PNGs to `dev-docs/ui-screenshots/`
//! so an agent (or a human) can iterate on visuals without a real
//! daemon running on a real desktop.
//!
//! **Every fixture does two things, and only one of them needs a GPU.**
//!
//! - It lays its window out on the CPU through [`ui_layout`] and compares
//!   the result against the `layout.json` committed beside that fixture's
//!   renders. This is the default: it runs on an ordinary `cargo test`, needs
//!   no display, and is what turns "changed the UI, forgot the regen" from a
//!   silent mistake into a red build.
//! - It renders the PNGs through `egui_kittest` + wgpu. That half only runs
//!   when `$SECREQ_BLESS_SHOTS` is set, because it needs a GPU and it rewrites
//!   published assets — neither of which belongs in a test run nobody asked for
//!   it.
//!
//! ```sh
//! # check (the default; no GPU, no writes)
//! cargo test --test ui_screenshots
//! # regenerate everything: PNGs and the layout.json beside them
//! SECREQ_BLESS_SHOTS=1 cargo test --test ui_screenshots -- --nocapture --test-threads=1
//! # rewrite only layout.json, leaving the committed PNGs untouched
//! SECREQ_BLESS_SHOTS=layout cargo test --test ui_screenshots -- --nocapture --test-threads=1
//! ```
//!
//! Two window kinds, two harness drivers — mirroring the production
//! two-window architecture:
//!
//! - **Prompt** fixtures drive the real
//!   [`secreq::daemon::prompt_ui::render_prompt_panel`] with a
//!   `QueueSnapshot` built through the daemon's own `submit_ask` path
//!   (so coalescing / union / provenance are the real thing), at the
//!   prompt's production viewport size.
//! - **Manager** fixtures drive the real
//!   [`secreq::daemon::manager_ui::render_manager_panel`] with rules
//!   passed directly and audit history read from a synthetic
//!   `audit.log` in a [`common::Sandbox`] (via `$SECREQ_HOME`, the
//!   normal `AuditCache` path), at the manager's production viewport
//!   size.

// Every line in this crate is test code, so an `unwrap` is an assertion —
// which is what `clippy.toml`'s `allow-unwrap-in-tests` already says. That key
// only reaches inside a `#[test]` fn, and an integration test has no
// `#[cfg(test)]` module for it to recognise, so the fixture builders the tests
// call fall outside it. Said once here rather than at each helper.
#![allow(clippy::unwrap_used)]

mod common;
mod ui_layout;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex, Once};

use egui::Vec2;
use egui_kittest::Harness;

use secreq::audit::{AuditEntry, AuditLocalPeer, ScopeDeclarant};
use secreq::consent::Decision;
use secreq::daemon::manager_ui::{render_manager_panel, ManagerWindowState};
use secreq::daemon::prompt_ui::{render_prompt_panel, PromptWindowState, PROMPT_DEFAULT_SIZE};
use secreq::daemon::proto::{
    AgentAskInfo, Ask, AskAnchor, AskSubject, Caller, DedupeKey, SecretAsk, SshAskInfo, SshSubject,
    WrapSubject,
};
use secreq::daemon::state::{SharedState, State};
use secreq::daemon::theme::OsFlavor;
use secreq::daemon::ui::{AutoDenyToastView, RuleAction, RuleSort};
use secreq::provenance::ProcessIdentity;
use secreq::recommendations::SuggestionSort;
use secreq::rule_scaffold::Editor;
use secreq::rules::{
    Pattern, Rule, RuleBody, RuleDecision, RuleMatch, RuleRefusals, StaticDecision, WasmRefusal,
    WasmRefusalCategory, WasmRule,
};

/// Where the regenerated PNGs land. Relative to the package root,
/// which is `cargo test`'s CWD.
const OUT_DIR: &str = "../../dev-docs/ui-screenshots";

/// Where [`Shot::exercise_only`] renders land: gitignored, unpublished, and
/// carrying no `layout.json`. Named for its only current occupant, the resize
/// sweep; if a non-resize exercise-only fixture ever appears, rename it — the
/// directory is scratch, so nothing depends on the name.
const SCRATCH_DIR: &str = "../../tmp/resize-screenshots";

/// Logical prompt-window size — matches the production viewport
/// (`prompt_ui::PROMPT_DEFAULT_SIZE`, used by `daemon/child.rs`).
const PROMPT_SIZE: Vec2 = Vec2::new(PROMPT_DEFAULT_SIZE[0], PROMPT_DEFAULT_SIZE[1]);

/// Logical manager-window size — matches the production viewport
/// (`manager_ui::MANAGER_DEFAULT_SIZE`, used by `daemon/child.rs`).
const MANAGER_SIZE: Vec2 = Vec2::new(
    secreq::daemon::manager_ui::MANAGER_DEFAULT_SIZE[0],
    secreq::daemon::manager_ui::MANAGER_DEFAULT_SIZE[1],
);

/// Render at 2x for crisp text — the child picks this up from the OS
/// in production; in the harness we force it so the PNGs are legible
/// regardless of where they're regenerated.
///
/// Rasterisation only. The layout capture runs in **points** — see
/// [`ui_layout`] for why setting a pixel scale there truncates text.
const PIXELS_PER_POINT: f32 = 2.0;

/// The one command every failure message points at.
const REGEN: &str =
    "SECREQ_BLESS_SHOTS=1 cargo test --test ui_screenshots -- --nocapture --test-threads=1";

// ── Bless mode ────────────────────────────────────────────────────────────

/// What a run is allowed to overwrite.
///
/// Checking is free and safe, so it is the default and needs no opt-in;
/// everything that writes a published asset is behind `$SECREQ_BLESS_SHOTS`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Bless {
    /// Lay out and compare. No GPU, no writes — what CI runs.
    Off,
    /// Rewrite each fixture's `layout.json`, leave the PNGs alone.
    ///
    /// This is also how a re-worded caption reaches the docs site without a
    /// re-render: the caption is authored in Rust and published from
    /// `layout.json`, and nothing about changing prose needs a GPU.
    ///
    /// The layout pass is independent of wgpu, so a machine that cannot render
    /// (no GPU, a headless container, a driver that will not initialise) can
    /// still re-bless the guard. It is also the mode to use for a change that
    /// moves layout without changing pixels you intend to publish.
    Layout,
    /// Rewrite everything: the PNGs and the `layout.json` beside them.
    All,
}

fn bless() -> Bless {
    match std::env::var("SECREQ_BLESS_SHOTS").as_deref() {
        Ok("layout") => Bless::Layout,
        Ok("") | Ok("0") | Err(_) => Bless::Off,
        Ok(_) => Bless::All,
    }
}

// ── Fixture-state plumbing ────────────────────────────────────────────────

/// The instant every fixture pretends it is running at: 2026-01-15 12:00:00Z.
///
/// The audit views bucket rows by calendar day, so a row six hours old reads
/// "Today" at noon and "Yesterday" at 3am. Fixtures date their rows relative to
/// "now", which would leave both the PNGs and the layout snapshots depending on
/// the hour the run happened at — a snapshot blessed at noon would fail for
/// anyone running the suite before 6am UTC. Midday keeps every fixture's
/// intended bucket well clear of a boundary.
const CLOCK_PIN: u64 = 1_768_478_400;

/// Pin the renderer's clock to [`CLOCK_PIN`]. Idempotent, and called from
/// both directions — every harness before its first frame, and `now_unix`
/// whenever a fixture dates a row — so the two halves cannot disagree about
/// what "now" is no matter which fixture a filtered run happens to reach first.
fn pin_clock() {
    static PIN: Once = Once::new();
    PIN.call_once(|| secreq::daemon::ui::pin_clock(CLOCK_PIN));
}

/// What a fixture's synthetic audit rows are dated against.
fn now_unix() -> u64 {
    pin_clock();
    CLOCK_PIN
}

fn caller(pid: u32, name: &str, start_time: u64) -> Caller {
    Caller {
        pid,
        name: name.to_owned(),
        command: name.to_owned(),
        start_time,
        exe: None,
    }
}

/// A caller frame that also carries the kernel's record of what was loaded.
///
/// `exe` is never rendered, so it changes no pixel — but it *is* what
/// `provenance::select_anchor` reads to decide which frame an SSH session
/// grant binds to, so an SSH fixture that wants a realistic anchor has to
/// supply it.
fn caller_exe(pid: u32, name: &str, start_time: u64, exe: &str) -> Caller {
    Caller {
        exe: Some(exe.to_owned()),
        ..caller(pid, name, start_time)
    }
}

/// The session an SSH ask's grant buttons would bind to, chosen exactly the
/// way `daemon::ssh_agent::sign_ask` chooses it — through
/// `provenance::select_sign_anchor` — so a fixture cannot document a session
/// the daemon would not have picked.
///
/// `peer` is the process on the other end of the agent socket: the local
/// `ssh` client. The chain walk starts *above* it, so it is never one of
/// `callers`, and it is the only frame that knows whether the agent is being
/// forwarded. Passing `None` is the ordinary case; a forwarding fixture
/// passes the `ssh` client itself.
fn anchor_of(
    peer: Option<&Caller>,
    callers: &[Caller],
) -> Option<secreq::daemon::proto::SshAnchorInfo> {
    let to_runtime = |c: &Caller| secreq::provenance::Caller {
        pid: c.pid,
        name: c.name.clone(),
        command: c.command.clone(),
        exe: c.exe.clone(),
        start_time: c.start_time,
    };
    let chain: Vec<secreq::provenance::Caller> = callers.iter().map(to_runtime).collect();
    let peer = peer.map(|p| secreq::provenance::PeerProcess {
        forwards_agent: secreq::provenance::requests_agent_forwarding(&p.command),
        caller: to_runtime(p),
    });
    secreq::provenance::select_sign_anchor(peer.as_ref(), &chain).map(|a| {
        secreq::daemon::proto::SshAnchorInfo {
            name: a.name.clone(),
            pid: a.identity.pid,
            kind: a.kind,
            command: match a.kind {
                secreq::provenance::SignAnchorKind::ForwardedSsh => Some(a.command.clone()),
                secreq::provenance::SignAnchorKind::Session => None,
            },
        }
    })
}

fn secret(name: &str, provider: &str, locator: &str) -> SecretAsk {
    SecretAsk {
        declared_as: None,
        ttl: secreq::wraps::CacheTtl::default(),
        name: name.to_owned(),
        provider: provider.to_owned(),
        locator: locator.to_owned(),
        default: None,
        description: None,
        reason: None,
        requested_by: vec![],
    }
}

/// Build a single `Ask` and submit it through the same path the daemon
/// uses at runtime. Returns the (kept-alive) receiver so the channel
/// stays open across the render — closing it early would just leak a
/// `SendError` later but the rendered frame is unaffected.
fn submit(
    state: &SharedState,
    wrap: &str,
    command: Vec<&str>,
    callers: impl Into<Chain>,
    secrets: Vec<SecretAsk>,
) -> mpsc::Receiver<secreq::daemon::state::WaiterReply> {
    let Chain { frames, truncated } = callers.into();
    let dedupe_key = DedupeKey {
        wrap: wrap.to_owned(),
        anchor: AskAnchor::Process(ProcessIdentity {
            pid: frames.first().map_or(0, |c| c.pid),
            start_time: frames.first().map_or(0, |c| c.start_time),
        }),
        subject_digest: None,
    };
    let ask = Ask {
        command: command.into_iter().map(String::from).collect(),
        dedupe_key,
        subject: AskSubject::Wrap(WrapSubject {
            cwd: "~/repos/acme".to_owned(),
            callers: frames,
            callers_truncated: truncated,
            secrets,
            providers: HashMap::new(),
            allow_remember: true,
            nested_run: false,
            ignore_remembered: false,
        }),
    };
    let (tx, rx) = mpsc::channel();
    state.lock().unwrap().submit_ask(ask, tx);
    rx
}

/// A caller chain as an ask carries it: the frames, plus whether the walk
/// that produced them reached the top of the ancestry.
///
/// Mirrors `provenance::CallerChain`, and exists so a fixture that cares can
/// say `Chain::clipped(…)` while the fifteen that don't keep passing a bare
/// `vec![…]` — the `From` impl below reads a plain vec as a whole ancestry,
/// which is what every fixture predating the flag meant.
struct Chain {
    frames: Vec<Caller>,
    truncated: bool,
}

impl Chain {
    /// A chain the walk abandoned at its ceiling: real ancestors exist above
    /// the outermost frame here and were never read.
    fn clipped(frames: Vec<Caller>) -> Self {
        Chain {
            frames,
            truncated: true,
        }
    }
}

impl From<Vec<Caller>> for Chain {
    fn from(frames: Vec<Caller>) -> Self {
        Chain {
            frames,
            truncated: false,
        }
    }
}

/// Submit a `secreq run` ask. Mirrors `submit` but pins the dedupe
/// identity to the fixed `"run"` wrap and sets `allow_remember = false`
/// — the two things that distinguish a `run` consent from a wrap (`x`)
/// consent.
fn submit_run(
    state: &SharedState,
    command: Vec<&str>,
    callers: Vec<Caller>,
    secrets: Vec<SecretAsk>,
) -> mpsc::Receiver<secreq::daemon::state::WaiterReply> {
    let dedupe_key = DedupeKey {
        wrap: "run".to_owned(),
        anchor: AskAnchor::RunSession {
            pid: callers.first().map_or(0, |c| c.pid),
            nonce: callers.first().map_or(0, |c| c.start_time),
        },
        subject_digest: None,
    };
    let ask = Ask {
        command: command.into_iter().map(String::from).collect(),
        dedupe_key,
        subject: AskSubject::Wrap(WrapSubject {
            cwd: "~/repos/acme".to_owned(),
            callers,
            callers_truncated: false,
            secrets,
            providers: HashMap::new(),
            allow_remember: false,
            nested_run: false,
            ignore_remembered: false,
        }),
    };
    let (tx, rx) = mpsc::channel();
    state.lock().unwrap().submit_ask(ask, tx);
    rx
}

/// Submit an SSH-sign ask — the in-process consent prompt the SSH agent
/// raises on a cache-miss SIGN_REQUEST. Mirrors the daemon's `sign_ask`:
/// the `wrap` is `ssh:<key_id>`, the command is the synthetic
/// `ssh-sign <key_id>` label, there are no secrets to inject, and the
/// `ssh` marker carries the identity name + SHA256 fingerprint the UI
/// renders.
///
/// `cwd` is a parameter rather than a constant because the SSH path is the
/// one that can genuinely come back without it: there is no wrap client to
/// self-report a cwd, so the daemon reads it off the socket peer
/// (`provenance::cwd_for_pid`), which returns `None` when the process is gone
/// or the platform won't say. An empty string renders no `IN` row at all —
/// the prompt omits it rather than heading a blank (see
/// `render_evidence_well`).
fn submit_ssh(
    state: &SharedState,
    key_id: &str,
    fingerprint: &str,
    reason: Option<&str>,
    cwd: &str,
    peer: Option<Caller>,
    callers: Vec<Caller>,
) -> mpsc::Receiver<secreq::daemon::state::WaiterReply> {
    // The real sign path keys the ask on the *anchor*, not on the nearest
    // caller — that is the whole point of `select_sign_anchor`, and it is
    // what the prompt's "Session:" / "Forwarded:" row names.
    let anchor = anchor_of(peer.as_ref(), &callers);
    let dedupe_key = DedupeKey {
        wrap: format!("ssh:{key_id}"),
        anchor: AskAnchor::Process(ProcessIdentity {
            pid: anchor.as_ref().map_or(0, |a| a.pid),
            start_time: peer
                .iter()
                .chain(callers.iter())
                .find(|c| Some(c.pid) == anchor.as_ref().map(|a| a.pid))
                .map_or(0, |c| c.start_time),
        }),
        subject_digest: None,
    };
    let ask = Ask {
        command: vec![format!("ssh-sign {key_id}")],
        dedupe_key,
        subject: AskSubject::SshSign(SshSubject {
            cwd: cwd.to_owned(),
            callers,
            callers_truncated: false,
            info: SshAskInfo {
                key_id: key_id.to_owned(),
                fingerprint: fingerprint.to_owned(),
                reason: reason.map(str::to_owned),
                anchor,
            },
        }),
    };
    let (tx, rx) = mpsc::channel();
    state.lock().unwrap().submit_ask(ask, tx);
    rx
}

/// Submit a scoped-agent ask — a guest VM resolving a `secret://` ref
/// through a scoped socket. Mirrors `scoped_agent::agent_ask`: the dedupe
/// wrap is `agent:<scope>:<ref>` (per-ref, so two refs from one scope can't
/// coalesce into one prompt), there are no secrets for the daemon to
/// resolve, and — the load-bearing part — **`callers` is empty**: a guest
/// has no host process tree, so the `agent` marker carries the host-declared
/// scope as the principal instead.
///
/// `guest_chain` is what the guest *claimed* about itself — display-only,
/// and rendered by the prompt behind an explicit "not verifiable" marker.
/// It is passed as an already-rendered string exactly as
/// `scoped_agent::GuestChain::display` produces one.
fn submit_agent(
    state: &SharedState,
    scope: &str,
    reference: &str,
    guest_chain: Option<&str>,
    declared_by: Option<secreq::daemon::proto::LocalPeer>,
) -> mpsc::Receiver<secreq::daemon::state::WaiterReply> {
    let dedupe_key = DedupeKey {
        wrap: format!("agent:{scope}:{reference}"),
        anchor: AskAnchor::AgentSocket { pid: 4242 },
        subject_digest: None,
    };
    let ask = Ask {
        command: vec![format!("agent-resolve {reference}")],
        // No cwd, no callers, no secrets: the variant has nowhere to put
        // any of them, which is the point.
        dedupe_key,
        subject: AskSubject::ScopedAgent(AgentAskInfo {
            scope: scope.to_owned(),
            reference: reference.to_owned(),
            guest_chain: guest_chain.map(str::to_owned),
            // In production this is stamped by the daemon from the socket
            // peer, never by the client — `server::adopt_peer_provenance`.
            // A fixture supplies it directly because it has no socket, which
            // is also what lets one fixture show the genuine peer and another
            // show a forger's.
            declared_by,
        }),
    };
    let (tx, rx) = mpsc::channel();
    state.lock().unwrap().submit_ask(ask, tx);
    rx
}

/// Inject a *resolving* card: an ask that has already been authorized
/// (auto-rule, approvals-cache, or a manual approve) and whose secret
/// is being fetched, with a provider biometric prompt potentially in
/// flight. Drives the prompt's read-only "Resolving…" state. No waiter
/// channel — in production this path resolves off the queue, not
/// through it.
fn pending(
    state: &SharedState,
    wrap: &str,
    command: Vec<&str>,
    callers: Vec<Caller>,
    secrets: Vec<SecretAsk>,
) {
    let dedupe_key = DedupeKey {
        wrap: wrap.to_owned(),
        anchor: AskAnchor::Process(ProcessIdentity {
            pid: callers.first().map_or(0, |c| c.pid),
            start_time: callers.first().map_or(0, |c| c.start_time),
        }),
        subject_digest: None,
    };
    let ask = Ask {
        command: command.into_iter().map(String::from).collect(),
        dedupe_key,
        subject: AskSubject::Wrap(WrapSubject {
            cwd: "~/repos/acme".to_owned(),
            callers,
            callers_truncated: false,
            secrets,
            providers: HashMap::new(),
            allow_remember: true,
            nested_run: false,
            ignore_remembered: false,
        }),
    };
    state.lock().unwrap().begin_pending(ask);
}

fn audit_line(
    secs_ago: u64,
    wrap: &str,
    caller_name: &str,
    secrets: &[&str],
    decision: &str,
) -> AuditEntry {
    AuditEntry {
        ts_unix: now_unix().saturating_sub(secs_ago),
        cwd: "~/repos/acme".to_owned(),
        wrap: wrap.to_owned(),
        args: vec![],
        callers: vec![secreq::audit::AuditCaller {
            pid: 1000,
            name: caller_name.to_owned(),
            command: caller_name.to_owned(),
            exe: None,
        }],
        callers_truncated: Some(false),
        secrets: secrets.iter().map(|s| (*s).to_owned()).collect(),
        decision: decision.to_owned(),
        reason: None,
        rule_id: None,
        approvers: Default::default(),
        fingerprint: None,
        sign_anchor: None,
        declared_by: None,
        unverified_guest_chain: None,
    }
}

/// A scoped-agent audit row, built through the **production constructor**
/// rather than by hand — so the fixture can't quietly misrepresent the shape
/// (no caller chain, no cwd, ref in `secrets`, `agent:<scope>` as the wrap).
/// That's the whole thing this fixture exists to show.
///
/// `declared_by` says which local process the daemon saw naming the scope, or
/// that nothing read one.
/// The declarant a genuine `secreq agent open` produces: the installed
/// binary, at the path the user installed it to, as the kernel reports it.
fn genuine_agent_peer() -> ScopeDeclarant {
    ScopeDeclarant::Peer(AuditLocalPeer {
        pid: 4711,
        name: "secreq".to_owned(),
        command: "secreq agent open brain-nx-t5".to_owned(),
        exe: Some("/usr/local/bin/secreq".to_owned()),
    })
}

fn agent_audit_line(
    secs_ago: u64,
    scope: &str,
    reference: &str,
    decision: Decision,
    declared_by: ScopeDeclarant,
) -> AuditEntry {
    let mut entry = AuditEntry::agent_resolve(scope, reference, decision, None, declared_by);
    entry.ts_unix = now_unix().saturating_sub(secs_ago);
    entry
}

/// Richer variant for fixtures that want to exercise the audit view's
/// process-tree rendering (multi-caller chains with their argv) and
/// the wrap-args display.
///
/// `chain` is nearest-first (same order as the runtime
/// `provenance::caller_chain()` and on-disk storage): index 0 is the
/// direct parent of the wrap, last index is the outermost ancestor.
fn audit_line_traced(
    secs_ago: u64,
    wrap: &str,
    args: &[&str],
    chain: &[(u32, &str, &str)],
    secrets: &[&str],
    decision: &str,
) -> AuditEntry {
    AuditEntry {
        ts_unix: now_unix().saturating_sub(secs_ago),
        cwd: "~/repos/acme".to_owned(),
        wrap: wrap.to_owned(),
        args: args.iter().map(|s| (*s).to_owned()).collect(),
        callers: chain
            .iter()
            .map(|(pid, name, cmd)| secreq::audit::AuditCaller {
                pid: *pid,
                name: (*name).to_owned(),
                command: (*cmd).to_owned(),
                exe: None,
            })
            .collect(),
        callers_truncated: Some(false),
        secrets: secrets.iter().map(|s| (*s).to_owned()).collect(),
        decision: decision.to_owned(),
        reason: None,
        rule_id: None,
        approvers: Default::default(),
        fingerprint: None,
        sign_anchor: None,
        declared_by: None,
        unverified_guest_chain: None,
    }
}

/// An SSH-agent sign row, built through the **production constructor** so the
/// fixture cannot quietly misrepresent the shape: no secrets named, the
/// public-key fingerprint present, and the anchor the grant bound to recorded
/// beside a caller chain that — under forwarding — does not contain it.
///
/// `via` is the forwarding `ssh` client's command line, or `None` for an
/// ordinary local sign.
fn ssh_audit_line(
    secs_ago: u64,
    key_id: &str,
    chain: &[(u32, &str, &str)],
    via: Option<(u32, &str)>,
    decision: Decision,
) -> AuditEntry {
    let chain = secreq::provenance::CallerChain {
        frames: chain
            .iter()
            .map(|(pid, name, cmd)| secreq::provenance::Caller {
                pid: *pid,
                name: (*name).to_owned(),
                command: (*cmd).to_owned(),
                exe: None,
                start_time: 1,
            })
            .collect(),
        truncated: false,
    };
    let anchor = if let Some((pid, command)) = via {
        secreq::provenance::SignAnchor {
            identity: secreq::provenance::ProcessIdentity { pid, start_time: 1 },
            name: "ssh".to_owned(),
            command: command.to_owned(),
            kind: secreq::provenance::SignAnchorKind::ForwardedSsh,
        }
    } else {
        let outermost = chain.frames.last().expect("a chain to anchor on");
        secreq::provenance::SignAnchor {
            identity: secreq::provenance::ProcessIdentity {
                pid: outermost.pid,
                start_time: 1,
            },
            name: outermost.name.clone(),
            command: outermost.command.clone(),
            kind: secreq::provenance::SignAnchorKind::Session,
        }
    };
    let mut entry = AuditEntry::ssh_sign(
        key_id,
        "SHA256:Nh0Me49Zh9fDwabcQ2VqLm",
        &chain,
        &anchor,
        "~/repos/acme",
        decision,
    );
    entry.ts_unix = now_unix().saturating_sub(secs_ago);
    entry
}

/// The same sign row as an **older** `secreq` wrote it, before the log
/// recorded which process the grant bound to. `None` is not "this was local" —
/// it is "nobody wrote it down", and the row says so rather than letting a
/// forwarded sign pass for one the user drove.
fn sign_anchor_unrecorded(mut entry: AuditEntry) -> AuditEntry {
    entry.sign_anchor = None;
    entry
}

/// The same row, but written by a walk that stopped at its own ceiling: real
/// ancestors exist above the outermost frame and were never read. The audit
/// tree draws a `… more above` row for it.
fn chain_clipped(mut entry: AuditEntry) -> AuditEntry {
    entry.callers_truncated = Some(true);
    entry
}

/// The same row as an **older** `secreq` wrote it, before the log recorded
/// whether the walk reached the top. `None` is not "not truncated" — it is
/// "nobody wrote it down" — and the audit tree renders it as its own third
/// state (`… may be more above`) rather than as a complete chain.
///
/// Every row the current code writes carries the field, so this state can only
/// come off disk. It is worth a fixture precisely because it is the one an
/// existing install sees on every row it already has.
fn chain_unrecorded(mut entry: AuditEntry) -> AuditEntry {
    entry.callers_truncated = None;
    entry
}

/// An audit row recording a rule auto-firing. The Rules view aggregates
/// these by `rule_id` to show each rule's auto-fire count and last-fired
/// time, so `rule_id` is the field that matters here; `decision` carries
/// the matching `+auto` suffix the daemon writes in production.
fn audit_auto_fire(secs_ago: u64, rule_id: &str, decision: &str) -> AuditEntry {
    AuditEntry {
        ts_unix: now_unix().saturating_sub(secs_ago),
        cwd: "~/repos/acme".to_owned(),
        wrap: "gh".to_owned(),
        args: vec!["api".to_owned()],
        callers: vec![secreq::audit::AuditCaller {
            pid: 4242,
            name: "Cursor.app".to_owned(),
            command: "Cursor.app".to_owned(),
            exe: None,
        }],
        callers_truncated: Some(false),
        secrets: vec!["GITHUB_TOKEN".to_owned()],
        decision: decision.to_owned(),
        reason: None,
        rule_id: Some(rule_id.to_owned()),
        approvers: Default::default(),
        fingerprint: None,
        sign_anchor: None,
        declared_by: None,
        unverified_guest_chain: None,
    }
}

/// Sandbox this process and write `audit_entries` as the sandbox's
/// `audit.log`, so `AuditCache::refresh_if_stale` reads our synthetic history
/// through the normal path. Returns `(env guard, sandbox)` — keep both alive
/// across the render: env reads happen while rendering, and the tempdir must
/// outlive them. Tuple drop order restores the environment first, then
/// deletes the tempdir.
///
/// The audit log lands at `<sandbox root>/audit.log` (i.e.
/// `$SECREQ_HOME/audit.log`): `paths::audit_log_path()` is `<root>/audit.log`
/// directly, with no `secreq` component of its own (that was the old
/// `$XDG_STATE_HOME/secreq/…` layout). Writing anywhere else would leave the
/// fixture reading an empty history and rendering a blank audit tab.
///
/// Env mutation: [`common::Sandbox::enter`] pins the *complete* isolation
/// set (`SECREQ_HOME`, the XDG vars, `HOME`, …) under a global lock and
/// restores prior values on drop. That lock is an addition to — not a
/// replacement for — the `--test-threads=1` serialization the regen
/// instructions require: the wgpu fixtures still must run one at a time.
fn install_audit_log(audit_entries: &[AuditEntry]) -> (common::EnvGuard, common::Sandbox) {
    let sandbox = common::Sandbox::new();
    let mut buf = String::new();
    for entry in audit_entries {
        buf.push_str(&serde_json::to_string(entry).expect("serialize entry"));
        buf.push('\n');
    }
    std::fs::write(sandbox.root().join("audit.log"), buf).expect("write audit.log");
    let guard = sandbox.enter();
    (guard, sandbox)
}

/// One fixture's identity and everything the docs site needs to publish
/// it, declared at the fixture that renders it.
///
/// The docs site reads what lands in `<id>/layout.json` and adds nothing
/// of its own, so this is the only place a screenshot is described. A
/// fixture with nothing to say to a reader is spelled `"id".into()` and
/// simply ships without a caption — the resize sweep, for instance,
/// exists to catch panics and is not documentation.
struct Shot {
    /// PNG basename stem, without the chrome suffix or extension.
    id: String,
    /// What a reader should take from the image, in the voice of the
    /// docs rather than the test suite. `<code>` and `<b>` are the only
    /// markup the site renders.
    caption: Option<&'static str>,
    /// Whether this fixture renders across the full chrome matrix.
    ///
    /// True for anything the docs publish. False for a fixture that
    /// *exercises* the UI rather than documenting it — see
    /// [`Shot::exercise_only`].
    matrix: bool,
}

impl Shot {
    fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            caption: None,
            matrix: true,
        }
    }

    fn caption(mut self, caption: &'static str) -> Self {
        self.caption = Some(caption);
        self
    }

    /// Render this fixture once (macOS dark) instead of across the
    /// chrome matrix.
    ///
    /// For fixtures that exist to catch a regression rather than to
    /// illustrate anything: the resize sweep drives eleven viewport
    /// sizes looking for layout panics, and rendering each of those six
    /// ways would produce sixty-six PNGs nobody will ever open.
    fn exercise_only(mut self) -> Self {
        self.matrix = false;
        self
    }
}

impl From<&str> for Shot {
    fn from(id: &str) -> Self {
        Shot::new(id)
    }
}

impl From<String> for Shot {
    fn from(id: String) -> Self {
        Shot::new(id)
    }
}

/// Which secreq window a fixture drives. Recorded in the fixture's
/// `layout.json` so consumers can label a PNG without pattern-matching on
/// its filename.
#[derive(Clone, Copy)]
enum ShotKind {
    Prompt,
    Manager,
    Badge,
}

impl ShotKind {
    fn as_str(self) -> &'static str {
        match self {
            ShotKind::Prompt => "prompt",
            ShotKind::Manager => "manager",
            ShotKind::Badge => "badge",
        }
    }
}

fn os_flavor_str(flavor: OsFlavor) -> &'static str {
    match flavor {
        OsFlavor::MacOs => "macos",
        OsFlavor::Windows => "windows",
        OsFlavor::Gnome => "gnome",
    }
}

/// Every documented fixture renders across the full chrome matrix:
/// three OS flavors by two appearances, six PNGs per fixture.
///
/// secreq's windows are natively themed and follow the host — its
/// chrome is a macOS sheet, a Windows ContentDialog or a GNOME
/// AdwMessageDialog depending on where it runs, in whichever appearance
/// the OS is set to. None of that is a setting the user picks, so no
/// combination is the "real" one and none is a variant of another.
///
/// Rendering the whole matrix unconditionally is what lets the docs show
/// a reader their own desktop: no fixture has to declare a counterpart,
/// nothing goes stale by regenerating one corner of the grid, and a
/// screenshot can never depict chrome the reader has never seen.
const FLAVORS: [OsFlavor; 3] = [OsFlavor::MacOs, OsFlavor::Windows, OsFlavor::Gnome];
const APPEARANCES: [(&str, bool); 2] = [("dark", true), ("light", false)];

/// The single cell rendered for a fixture that opts out of the matrix.
const BASELINE: (OsFlavor, bool) = (OsFlavor::MacOs, true);

/// Filename of one cell of the matrix, within its fixture's directory.
///
/// Every render is named for its chrome, including the baseline — a bare
/// `render.png` would quietly privilege one chrome as the canonical look,
/// which is exactly the assumption this sweep exists to remove.
fn variant_name(flavor: OsFlavor, dark: bool) -> String {
    let appearance = if dark { "dark" } else { "light" };
    format!("{}-{appearance}", os_flavor_str(flavor))
}

/// Path of one render relative to [`OUT_DIR`]: `<id>/<os>-<appearance>.png`.
///
/// A fixture's id *is* its directory name: one folder per fixture, holding
/// its six renders and the `layout.json` that guards them, so everything
/// about a fixture moves as one hunk in a diff.
fn render_rel_path(id: &str, flavor: OsFlavor, dark: bool) -> String {
    format!("{id}/{}.png", variant_name(flavor, dark))
}

/// The `(flavor, dark)` cells a fixture renders.
fn cells_for(shot: &Shot) -> Vec<(OsFlavor, bool)> {
    if !shot.matrix {
        return vec![BASELINE];
    }
    FLAVORS
        .iter()
        .flat_map(|&flavor| APPEARANCES.iter().map(move |&(_, dark)| (flavor, dark)))
        .collect()
}

fn save_png(shot: &Shot, flavor: OsFlavor, dark: bool, img: &image::RgbaImage) {
    // An exercise-only fixture has no reader: it drives a code path looking
    // for a layout panic, nothing publishes it, and nobody opens it unless a
    // run fails. Persisting one would put a file in git forever for a render
    // whose only job was to not crash — so it goes to a gitignored scratch
    // dir, where it is still there to *look* at when a resize does break.
    let out_dir = Path::new(if shot.matrix { OUT_DIR } else { SCRATCH_DIR });
    let out = out_dir.join(render_rel_path(&shot.id, flavor, dark));
    std::fs::create_dir_all(out.parent().expect("render path has a parent")).expect("mkdir out");

    // Scratch renders skip the (not free) lossless re-encode; bytes only
    // matter for the ones that live in git.
    if !shot.matrix {
        img.save(&out).expect("save png");
        eprintln!(
            "wrote {} ({}x{}, scratch)",
            out.display(),
            img.width(),
            img.height()
        );
        return;
    }

    // `image`'s encoder writes a serviceable but unoptimized PNG; every one of
    // these files is a *published* asset (the docs site serves all of them)
    // and lives in git forever, so it's worth re-encoding. oxipng is lossless
    // — same pixels, better filters and deflate — which measured ~70% off this
    // corpus. Lossy quantization went further but these are documentation
    // screenshots of antialiased UI text; there is no case for risking banding
    // to save bytes we can get for free.
    //
    // It runs in-process via the crate rather than shelling out to the
    // `oxipng` binary on purpose: the committed bytes must not depend on
    // whether a contributor has the tool installed, or which version.
    //
    // **Preset 2, not the maximum.** Measured on one prompt cell: preset 2
    // takes 896ms and lands 33,316 bytes; preset 4 takes 2.38s and lands
    // 32,621 — 2.6x the time to shave 2.1%. Across 216 published cells that
    // is minutes of every regen bought with a rounding error of bandwidth,
    // and a regen nobody wants to sit through is a regen that gets skipped.
    // (Preset 3 is strictly dominated: byte-identical to 2 at twice the
    // cost.) Changing this rewrites every committed PNG, so it is a decision
    // to make deliberately and then leave alone.
    let mut raw = std::io::Cursor::new(Vec::new());
    img.write_to(&mut raw, image::ImageFormat::Png)
        .expect("encode png");

    let opts = oxipng::Options {
        // `strip safe` — drop non-rendering ancillary chunks (timestamps and
        // the like) but keep anything that affects display. Also makes the
        // output byte-stable across runs, which the freshness guard needs.
        strip: oxipng::StripChunks::Safe,
        ..oxipng::Options::from_preset(2)
    };
    let optimized = oxipng::optimize_from_memory(raw.get_ref(), &opts).expect("optimize png");

    std::fs::write(&out, &optimized).expect("save png");
    eprintln!(
        "wrote {} ({}x{}, {} KiB)",
        out.display(),
        img.width(),
        img.height(),
        optimized.len() / 1024
    );
}

/// Hand the renderer the whole window, the way production does.
///
/// `egui_kittest` wraps every `build_ui*` closure in a central-panel
/// frame with a hardcoded 8px **outer** margin, so `ui.max_rect()`
/// arrives inset on all four sides. Production has no such frame:
/// eframe calls `App::ui` with the root `Ui` straight out of
/// `Context::run_ui`, whose `max_rect` is the entire window. Without
/// this the fixtures document a window 16px narrower and shorter than
/// the real one, and anything that bleeds to an edge off `max_rect` —
/// the Windows footer band, the pending badge — stops short of it.
///
/// Only the layout rect is inset; the clip rect is already the full
/// window, so widening `max_rect` is the whole fix. The fixtures host
/// no side or top panels, so the content rect is the same rect
/// `Context::run_ui` hands the root `Ui` in production.
fn full_window_ui<R>(ui: &mut egui::Ui, add_contents: impl FnOnce(&mut egui::Ui) -> R) -> R {
    let full = ui.ctx().content_rect();
    ui.scope_builder(egui::UiBuilder::new().max_rect(full), add_contents)
        .inner
}

/// Everything one fixture does with a cell of the chrome matrix, in the order
/// the two consumers need it.
///
/// The layout capture and the PNG render must run the *same* UI code — a
/// capture of some other closure would guard nothing — so every harness hands
/// its per-frame body to this instead of writing it inline for `egui_kittest`.
/// Each cell is laid out on the CPU regardless (which is also what makes the
/// resize sweep catch a layout panic without a GPU) and rendered only when
/// blessing.
///
/// `state` is a factory, not a value: the two passes and each cell of the
/// matrix all start from a fresh window state, the way a freshly-opened window
/// does.
fn run_cells<S>(
    shot: &Shot,
    kind: ShotKind,
    size: Vec2,
    state: impl Fn() -> S,
    draw: impl Fn(&mut egui::Ui, &mut S, OsFlavor, bool),
) {
    pin_clock();
    let mode = bless();
    let mut record = ui_layout::Fixture::new(&shot.id, kind.as_str(), shot.caption);

    // Rendered cells wait here to be compressed together. Compression is
    // where a regen actually spends its life: measured on one prompt cell,
    // `image` encodes in 156ms and oxipng at preset 4 then takes **2.38s** —
    // so 216 published cells is roughly nine minutes of squeezing against
    // half a minute of encoding.
    //
    // The renders cannot escape being serial: wgpu wants one harness at a
    // time and the whole target runs `--test-threads=1` to keep `$SECREQ_HOME`
    // mutation ordered. Compression is under neither constraint — it is pure
    // bytes-to-bytes with no environment and no GPU — so a fixture renders
    // its six chrome cells one after another and then squeezes all six at
    // once, turning ~14s of waiting per fixture into ~2.4s.
    let mut rendered: Vec<(OsFlavor, bool, image::RgbaImage)> = Vec::new();

    for (flavor, dark) in cells_for(shot) {
        let capture = ui_layout::capture(size, state(), |ui, ws| draw(ui, ws, flavor, dark));
        record.record(&variant_name(flavor, dark), &capture);

        if mode == Bless::All {
            let mut harness = Harness::builder()
                .with_size(size)
                .with_pixels_per_point(PIXELS_PER_POINT)
                .wgpu()
                .build_ui_state(|ui, ws: &mut S| draw(ui, ws, flavor, dark), state());
            harness.run();
            rendered.push((flavor, dark, harness.render().expect("render wgpu")));
        }
    }

    // Scoped threads so the images can be borrowed rather than cloned — six
    // 1000x940 buffers is 22MB for a prompt and 52MB for a manager, and
    // copying them to satisfy `'static` would trade the memory back for the
    // time this is meant to save. The scope joins before it returns, so no
    // fixture can leave a write racing the next one's.
    if !rendered.is_empty() {
        std::thread::scope(|scope| {
            for (flavor, dark, img) in &rendered {
                scope.spawn(move || save_png(shot, *flavor, *dark, img));
            }
        });
    }

    // An exercise-only fixture renders to a gitignored scratch dir and is
    // published nowhere, so there is nowhere to keep a snapshot and nothing to
    // compare one against — and a `layout.json` in the published tree would
    // announce a fixture the docs site would then look for renders of. It was
    // still laid out above, which is the half of it that ever mattered: the
    // resize sweep exists to catch a panic, not to be read.
    if !shot.matrix {
        return;
    }
    match mode {
        Bless::Off => record.check(Path::new(OUT_DIR), REGEN),
        Bless::Layout | Bless::All => record.write(Path::new(OUT_DIR)),
    }
}

// ── Prompt harness ────────────────────────────────────────────────────────

/// Drive the real `render_prompt_panel` for one frame and write a PNG.
/// `setup` populates the daemon-side queue through the production
/// `submit_ask` / `begin_pending` paths; `toast` renders the transient
/// auto-deny banner.
fn render_prompt_fixture(
    shot: impl Into<Shot>,
    audit_entries: Vec<AuditEntry>,
    setup: impl FnOnce(&SharedState) -> Vec<mpsc::Receiver<secreq::daemon::state::WaiterReply>>,
) {
    render_prompt_fixture_full(shot, PROMPT_SIZE, audit_entries, None, None, setup);
}

type PromptStateSetup<'a> = Box<dyn Fn(&mut PromptWindowState) + 'a>;

/// Pin the OS chrome and one appearance. Fixtures pin the flavor so the
/// PNGs are deterministic regardless of the host OS; the appearance is
/// swept by the caller rather than chosen, because production has no
/// appearance setting to choose with.
fn apply_theme_pin(ctx: &egui::Context, flavor: OsFlavor, dark: bool) {
    OsFlavor::install_override(ctx, flavor);
    ctx.set_theme(if dark {
        egui::ThemePreference::Dark
    } else {
        egui::ThemePreference::Light
    });
}

fn render_prompt_fixture_full(
    shot: impl Into<Shot>,
    size: Vec2,
    audit_entries: Vec<AuditEntry>,
    toast: Option<AutoDenyToastView>,
    window_state: Option<PromptStateSetup<'_>>,
    setup: impl FnOnce(&SharedState) -> Vec<mpsc::Receiver<secreq::daemon::state::WaiterReply>>,
) {
    let shot = shot.into();
    // Held until after the last pass — env reads happen while laying out and
    // while rendering, so the guard's lifetime must cover every one of them.
    let sandbox = install_audit_log(&audit_entries);

    let state: SharedState = Arc::new(Mutex::new(State::new()));
    state.lock().unwrap().show_window();
    let _keep_alive = setup(&state);

    // Snapshot the state outside the closure (the renderer takes the
    // plain `QueueSnapshot`, the same shape the prompt child rebuilds
    // from the daemon's wire snapshot), so every pass sees identical input.
    let snapshot = state.lock().unwrap().snapshot();

    run_cells(
        &shot,
        ShotKind::Prompt,
        size,
        || {
            let mut state = PromptWindowState::new();
            if let Some(setup) = &window_state {
                setup(&mut state);
            }
            state
        },
        |ui, ws: &mut PromptWindowState, flavor, dark| {
            let ctx = ui.ctx().clone();
            apply_theme_pin(&ctx, flavor, dark);
            secreq::daemon::ui::install_style(&ctx);
            // The screenshot harness ignores action output — no user is
            // clicking, and we don't need to dispatch anywhere.
            let mut actions: Vec<secreq::daemon::ui::PendingAction> = Vec::new();
            full_window_ui(ui, |ui| {
                render_prompt_panel(&ctx, ui, &snapshot, toast.as_ref(), ws, &mut actions);
            });
        },
    );

    drop(sandbox);
}

// ── Manager harness ───────────────────────────────────────────────────────

/// Type alias for the per-fixture `ManagerWindowState` setup hook.
///
/// `Fn`, not `FnOnce`: each appearance renders from its own fresh
/// `ManagerWindowState`, so the hook runs once per pass.
type ManagerStateSetup<'a> = Box<dyn Fn(&mut ManagerWindowState) + 'a>;

/// Extra fixture inputs for the manager window. Each field has a
/// sensible default so most fixtures only set what they need.
#[derive(Default)]
struct ManagerExtras<'a> {
    /// Rules to pass to `render_manager_panel` (the Rules view content).
    rules: Vec<Rule>,
    /// Everything the daemon refused about those rules at its last
    /// load — an unloadable wasm module, a pattern that is not a valid
    /// glob. Empty for almost every fixture: a refusal is the abnormal
    /// state, and it is the one the docs most need a picture of, because
    /// a refused rule looks exactly like a working one everywhere except
    /// here.
    refusals: RuleRefusals,
    /// Wire viewer-mode flag: `secreq view` sets it, and a fresh
    /// manager state rising-edges onto the Audit view when it's set.
    viewer_mode: bool,
    /// Mutate the `ManagerWindowState` before the first frame — used
    /// to focus a specific view, open a rule form, or pre-fill the
    /// audit search. Defaults to no-op.
    window_state: Option<ManagerStateSetup<'a>>,
}

/// Drive the real `render_manager_panel` for one frame and write a PNG.
fn render_manager_fixture(
    shot: impl Into<Shot>,
    audit_entries: Vec<AuditEntry>,
    extras: ManagerExtras<'_>,
) {
    let shot = shot.into();
    // Held until after the last pass — env reads happen while laying out and
    // while rendering, so the guard's lifetime must cover every one of them.
    let sandbox = install_audit_log(&audit_entries);

    let ManagerExtras {
        rules,
        refusals,
        viewer_mode,
        window_state,
    } = extras;

    run_cells(
        &shot,
        ShotKind::Manager,
        MANAGER_SIZE,
        || {
            let mut initial_state = ManagerWindowState::new();
            if let Some(f) = &window_state {
                f(&mut initial_state);
            }
            initial_state
        },
        |ui, ws: &mut ManagerWindowState, flavor, dark| {
            let ctx = ui.ctx().clone();
            apply_theme_pin(&ctx, flavor, dark);
            secreq::daemon::ui::install_style(&ctx);
            let mut rule_actions: Vec<RuleAction> = Vec::new();
            full_window_ui(ui, |ui| {
                render_manager_panel(
                    &ctx,
                    ui,
                    &rules,
                    &refusals,
                    viewer_mode,
                    ws,
                    &mut rule_actions,
                );
            });
        },
    );

    drop(sandbox);
}

// ── Prompt fixtures ───────────────────────────────────────────────────────

#[test]
fn empty_state() {
    render_prompt_fixture(
        Shot::new("01-empty-all-clear")
            .caption("Nothing is waiting on you. The manager stays one click away in the footer."),
        vec![],
        |_state| Vec::new(),
    );
}

#[test]
fn empty_state_viewer() {
    // The `secreq view` surface is the *manager* window now: it opens
    // on the Audit view (viewer-mode rising edge) with no history yet.
    // This fixture documents the viewer's empty state — the prompt no
    // longer has a viewer variant.
    render_manager_fixture(
        Shot::new("01b-empty-all-clear-viewer").caption(
            "<code>secreq view</code> opens straight to the audit log. With no history \
             yet, it says so.",
        ),
        vec![],
        ManagerExtras {
            viewer_mode: true,
            ..ManagerExtras::default()
        },
    );
}

#[test]
fn single_pending() {
    render_prompt_fixture(
        Shot::new("02-single-pending").caption(
            "The whole idea in one window. <b>Before</b> <code>gh</code> receives \
             <code>GITHUB_TOKEN</code>, you see which secret is being released, which \
             process asked for it, the directory it asked from, and how you answered \
             last time.",
        ),
        vec![],
        |state| {
            vec![submit(
                state,
                "gh",
                vec!["gh", "auth", "login"],
                vec![caller(7926, "zsh", 1_700_000_000)],
                vec![secret(
                    "GITHUB_TOKEN",
                    "op",
                    "op://Personal/GitHub/credential",
                )],
            )]
        },
    );
}

#[test]
fn pending_with_denial_reason() {
    render_prompt_fixture_full(
        Shot::new("51-pending-denial-reason").caption(
            "A denial can carry an optional explanation into the audit log. Leave the \
             field empty and Deny is still one click.",
        ),
        PROMPT_SIZE,
        vec![],
        None,
        Some(Box::new(|state| {
            state.set_denial_reason("Wrong repository");
        })),
        |state| {
            vec![submit(
                state,
                "gh",
                vec!["gh", "repo", "delete", "acme/api"],
                vec![caller(7926, "zsh", 1_700_000_000)],
                vec![secret(
                    "GITHUB_TOKEN",
                    "op",
                    "op://Personal/GitHub/credential",
                )],
            )]
        },
    );
}

#[test]
fn run_consent_card() {
    // A `secreq run` consent: the ambient mirror of `x`. Instead of a
    // named wrap, the dedupe identity is the fixed `"run"` and the
    // prompt headlines the free-form command the user typed
    // (`./deploy.sh --prod`). The two secrets exercise the prompt's
    // mixed-provider secret list.
    render_prompt_fixture(
        Shot::new("run-consent").caption(
            "A <code>secreq run</code> request: a free-form command with secrets \
             resolved from the ambient environment. There is no wrap to remember an \
             answer against, so this one asks every time.",
        ),
        vec![],
        |state| {
            vec![submit_run(
                state,
                vec!["./deploy.sh", "--prod"],
                vec![caller(7926, "zsh", 1_700_000_000)],
                vec![
                    secret("DATABASE_URL", "op", "Work/PG/url"),
                    secret("STRIPE_KEY", "keychain", "stripe-key"),
                ],
            )]
        },
    );
}

#[test]
fn run_session_card() {
    // A *coalesced* `secreq run` session: three sibling `run` asks land
    // under the same process (the same first caller → the same dedupe
    // key), so they merge into one prompt. The representative's secret
    // list is the *union* of what each sibling requested, and each
    // entry remembers the command that asked for it (hover provenance).
    // Because coalescing happens inside `submit_ask`, we simply submit
    // the three asks and let the real merge path build the ask.
    render_prompt_fixture(
        Shot::new("run-session-card").caption(
            "Three sibling requests from one run, merged into a single decision. Hover \
             a secret to see which command wanted it.",
        ),
        vec![],
        |state| {
            let sibling_caller = || caller(6042, "deploy.sh", 1_700_000_000);
            vec![
                submit_run(
                    state,
                    vec!["./migrate"],
                    vec![sibling_caller()],
                    vec![secret("DATABASE_URL", "op", "Work/PG/url")],
                ),
                submit_run(
                    state,
                    vec!["./worker"],
                    vec![sibling_caller()],
                    vec![secret("STRIPE_KEY", "keychain", "stripe-live")],
                ),
                submit_run(
                    state,
                    vec!["./worker"],
                    vec![sibling_caller()],
                    vec![secret("REDIS_URL", "op", "Work/Redis/url")],
                ),
            ]
        },
    );
}

#[test]
fn gate_only_pending() {
    // A *gate-only* wrap: `op` has no secret to inject, so the request
    // exists purely to require consent before the command runs. The
    // prompt shows the command + caller chain; the SECRETS well row is
    // simply absent.
    render_prompt_fixture(
        Shot::new("21-gate-only-pending").caption(
            "A wrap can inject nothing and still ask. Gate-only wraps put a consent \
             step in front of a command without holding any secret for it.",
        ),
        vec![],
        |state| {
            vec![submit(
                state,
                "op",
                vec!["op", "read", "op://Personal/AWS/credential"],
                vec![caller(7926, "zsh", 1_700_000_000)],
                vec![],
            )]
        },
    );
}

#[test]
fn pending_resolving() {
    // An auto-approved (or approvals-cached) ask whose secret isn't yet
    // cached: the provider is being invoked — a biometric prompt may be
    // up — so the prompt renders read-only as "Resolving…". This is the
    // surface that gives that biometric prompt its provenance.
    render_prompt_fixture(
        Shot::new("23-pending-resolving").caption(
            "After you approve, the prompt goes read-only and reports \
             <b>Resolving…</b>. That is your provider being called, and why a \
             biometric prompt may appear next.",
        ),
        vec![],
        |state| {
            pending(
                state,
                "gh",
                vec!["gh", "pr", "view", "42"],
                vec![
                    caller(7926, "zsh", 1_700_000_000),
                    caller(2831, "Cursor.app", 1_650_000_000),
                ],
                vec![secret(
                    "GITHUB_TOKEN",
                    "op",
                    "op://Personal/GitHub/credential",
                )],
            );
            Vec::new()
        },
    );
}

#[test]
fn ssh_sign_pending() {
    // The SSH-agent sign prompt: `git push` over SSH triggered a
    // SIGN_REQUEST the daemon couldn't serve from a session grant, so
    // it raised the prompt. The header reads "git wants to sign with
    // github", the well carries the SHA256 fingerprint, and the session
    // grant row offers the 30-minute TTL choices.
    render_prompt_fixture(
        Shot::new("24-ssh-sign-pending").caption(
            "Point <code>SSH_AUTH_SOCK</code> at secreq and every signature is gated. \
             You see the key fingerprint and the reason before <code>git push</code> \
             signs, plus quiet grants covering a 30-minute session.",
        ),
        vec![],
        |state| {
            vec![submit_ssh(
                state,
                "github",
                "SHA256:Nh0Me49Zh9fDw/VYUfq43IJmI1T+XrjiYONPND8GzaM",
                Some("git pushes to github.com"),
                // For a `git push` the peer's cwd is the repository being
                // pushed — the fact that separates a push you started from
                // one a script started.
                "~/repos/acme",
                // No forwarding: an ordinary local push, so the anchor stays
                // on the shell and the grant row reads "Session:".
                None,
                vec![
                    caller(8120, "git", 1_700_002_000),
                    caller(7926, "zsh", 1_700_000_000),
                ],
            )]
        },
    );
}

#[test]
fn ssh_forwarded_agent_pending() {
    // The same sign, arriving under `ssh -A`. What the user is deciding is
    // not what the rest of the card says: the tree shows their own shell, the
    // header shows `ssh`, and the machine that can actually use the key is at
    // the far end of a connection nothing on screen mentioned.
    //
    // Two rows carry the difference. `FORWARDED BY` draws the `ssh` client
    // itself — the socket peer, and the one frame the caller chain
    // structurally cannot contain, since the walk starts at the peer's parent
    // — with the argv that names the host. And the grant row says
    // `Forwarded:` instead of `Session:`, because the 30 minutes now attach to
    // that ssh client and expire with the SSH session rather than lasting as
    // long as the terminal.
    render_prompt_fixture(
        Shot::new("41-ssh-forwarded-agent").caption(
            "A sign request that arrived under <code>ssh -A</code>. secreq names the \
             <code>ssh</code> client that forwarded your agent and the host it \
             forwarded to — and <b>Approve for 30 min</b> attaches to that session, so \
             it ends when you log out rather than lasting as long as the terminal.",
        ),
        vec![],
        |state| {
            let mut ssh = caller_exe(9200, "ssh", 1_700_003_000, "/usr/bin/ssh");
            ssh.command = "ssh -A build-box".to_owned();
            vec![submit_ssh(
                state,
                "github",
                "SHA256:Nh0Me49Zh9fDw/VYUfq43IJmI1T+XrjiYONPND8GzaM",
                Some("git pushes to github.com"),
                "~/repos/acme",
                Some(ssh),
                // Everything the walk can see is the user's own terminal —
                // which is exactly why the shell used to be the anchor.
                vec![caller_exe(7926, "-zsh", 1_700_000_000, "/bin/zsh")],
            )]
        },
    );
}

#[test]
fn ssh_session_anchor_pending() {
    // The same sign prompt, but with the session grant's subject visible
    // and *not* obvious from the rest of the card. `git push` runs inside
    // an `ssh` inside a `nvim` terminal inside a tmux server, and the
    // 30-minute grant binds to the tmux server — three rows up from the
    // command in the header, and not the frame anyone would guess.
    //
    // This is the state `24-ssh-sign-pending` cannot show: there, the
    // anchor is the caller's immediate parent, so naming it looks like
    // restating the tree. Here the "Session:" row is the only place the
    // prompt says what "Approve for 30 min" would actually cover.
    //
    // `caller_exe` matters: `select_anchor` reads the kernel's `exe`, not
    // the name a process reported, so the tmux frame needs one to be
    // chosen the way production would choose it.
    render_prompt_fixture(
        Shot::new("29-ssh-session-anchor").caption(
            "The session grants name what they attach to. Here <code>git push</code> \
             runs several frames deep, and <b>Approve for 30 min</b> would cover every \
             process under the <code>tmux</code> server — so the prompt says which one, \
             with a pid you can match against the tree above.",
        ),
        vec![],
        |state| {
            let mut git = caller_exe(9310, "git", 1_700_003_400, "/usr/bin/git");
            git.command = "git push origin main".to_owned();
            // Not a session frame, so the anchor resolves *past* it — which
            // is what makes the "Session:" row say something the tree does
            // not already say.
            let mut nvim = caller_exe(9308, "nvim", 1_700_003_000, "/opt/homebrew/bin/nvim");
            nvim.command = "nvim src/main.rs".to_owned();
            // tmux reports `comm` as "tmux: server" while its exe is a plain
            // `tmux`; `select_anchor` reads the exe, so this is the frame the
            // grant binds to.
            let mut tmux = caller_exe(
                7710,
                "tmux: server",
                1_700_000_000,
                "/opt/homebrew/bin/tmux",
            );
            tmux.command = "tmux new-session -s dev".to_owned();
            vec![submit_ssh(
                state,
                "github",
                "SHA256:Nh0Me49Zh9fDw/VYUfq43IJmI1T+XrjiYONPND8GzaM",
                Some("git pushes to github.com"),
                // The peer's cwd was unreadable — the process had already
                // exited by the time the daemon looked. A real state on this
                // path, and the only fixture that shows it: the well omits
                // the `IN` row rather than heading a blank one. It was also
                // load-bearing for height until the grants moved into the
                // pinned band; it is now here on its own merits.
                "",
                None,
                vec![git, nvim, tmux],
            )]
        },
    );
}

#[test]
fn deep_caller_chain_pending() {
    // A chain at the walk's own ceiling: `provenance::caller_chain` stops
    // after 16 useful frames, and this is what 16 looks like — a postinstall
    // buried under a stack of package-manager and node wrappers.
    //
    // The fixture exists for one row: `… 10 more`. The prompt used to draw
    // every frame it was handed, which read as the complete ancestry when it
    // was not, and left the audit view — the surface for *reviewing* a
    // decision — as the only one that admitted to eliding anything. Now the
    // tree keeps the outermost frame and the asking leaf, counts the middle,
    // and lists it on hover.
    render_prompt_fixture(
        Shot::new("30-deep-caller-chain").caption(
            "A request from the bottom of a deep wrapper stack. The tree keeps the \
             outermost process and the one actually asking, and collapses the middle \
             into <code>… 10 more</code> — hover it to read every frame it stands for.",
        ),
        vec![],
        |state| {
            let mut callers = vec![
                caller(9440, "sh", 1_700_004_000),
                caller(9438, "postinstall.js", 1_700_003_900),
                caller(9430, "node", 1_700_003_800),
                caller(9425, "pnpm", 1_700_003_700),
                caller(9418, "node", 1_700_003_600),
                caller(9411, "turbo", 1_700_003_500),
            ];
            callers.extend(
                (0..8).map(|i| caller(9300 - i * 7, "node", 1_700_003_000 - u64::from(i) * 60)),
            );
            callers.push(caller(8120, "make", 1_700_001_000));
            callers.push(caller(7926, "zsh", 1_700_000_000));
            assert_eq!(callers.len(), 16, "the chain walk's own ceiling");
            vec![submit(
                state,
                "npm",
                vec!["npm", "publish"],
                callers,
                vec![secret("NPM_TOKEN", "op", "op://Dev/npm/token")],
            )]
        },
    );
}

#[test]
fn walk_truncated_chain_pending() {
    // The same 16 frames as `30-deep-caller-chain`, but this time the walk
    // stopped *because* it hit its ceiling rather than because it ran out of
    // ancestors — so the outermost frame here is not the origin, it is
    // wherever secreq quit looking.
    //
    // The fixture exists for the top row: `… more above`. The two elisions in
    // the tree say different things and the difference is the whole point.
    // `… 10 more` counts frames the tree holds and hides; `… more above`
    // stands in for frames nothing ever read, which is why it carries no
    // number. Without it, the outermost frame the walk happened to stop on
    // draws exactly like a real root — and a caller that puts sixteen
    // processes between itself and the terminal chooses which one that is.
    render_prompt_fixture(
        Shot::new("31-walk-truncated-chain").caption(
            "secreq stops walking the process tree after 16 frames. When it does, the \
             prompt says so — <code>… more above</code> means the ancestry continues \
             past the top row and was not read, so the process shown there is where \
             the walk stopped, not where the request came from.",
        ),
        vec![],
        |state| {
            let mut callers = vec![
                caller(9440, "sh", 1_700_004_000),
                caller(9438, "postinstall.js", 1_700_003_900),
                caller(9430, "node", 1_700_003_800),
                caller(9425, "pnpm", 1_700_003_700),
                caller(9418, "node", 1_700_003_600),
                caller(9411, "turbo", 1_700_003_500),
            ];
            callers.extend(
                (0..10).map(|i| caller(9300 - i * 7, "node", 1_700_003_000 - u64::from(i) * 60)),
            );
            assert_eq!(callers.len(), 16, "the chain walk's own ceiling");
            vec![submit(
                state,
                "npm",
                vec!["npm", "publish"],
                Chain::clipped(callers),
                vec![secret("NPM_TOKEN", "op", "op://Dev/npm/token")],
            )]
        },
    );
}

#[test]
fn ssh_deep_chain_pinned_grants() {
    // The viewport property, on the ask that has the most to lose from it:
    // an SSH sign whose caller chain overflows the well.
    //
    // Everything the requester supplies — the tree, the argv column, the cwd
    // — scrolls inside the well. Everything the user needs in order to decide
    // sits below it in a band the well cannot reach: HISTORY, both TTL
    // grants, and Approve/Deny. Before that split, a chain this deep pushed
    // the grant buttons off the bottom of the prompt window, which is a control
    // handing out thirty minutes of signing that the user never saw.
    // `29-ssh-session-anchor` had to give up its `IN` row to fit them.
    render_prompt_fixture(
        Shot::new("32-ssh-deep-chain-pinned").caption(
            "Whatever the request brings with it, the decision stays on screen. The \
             evidence scrolls; <b>HISTORY</b>, the session grants and Approve/Deny do \
             not — so no caller can make the prompt say less than it appears to by \
             being deep enough.",
        ),
        vec![],
        |state| {
            let mut git = caller_exe(9310, "git", 1_700_003_400, "/usr/bin/git");
            git.command = "git push origin main".to_owned();
            let mut make = caller_exe(9308, "make", 1_700_003_000, "/usr/bin/make");
            make.command = "make release".to_owned();
            let mut turbo = caller_exe(9301, "turbo", 1_700_002_800, "/usr/local/bin/turbo");
            turbo.command = "turbo run publish".to_owned();
            let mut nvim = caller_exe(9280, "nvim", 1_700_002_000, "/opt/homebrew/bin/nvim");
            nvim.command = "nvim src/main.rs".to_owned();
            let mut tmux = caller_exe(
                7710,
                "tmux: server",
                1_700_000_000,
                "/opt/homebrew/bin/tmux",
            );
            tmux.command = "tmux new-session -s dev".to_owned();
            let mut callers = vec![git, make, turbo];
            callers.extend(
                (0..5).map(|i| caller(9270 - i * 3, "node", 1_700_002_500 - u64::from(i) * 30)),
            );
            callers.push(nvim);
            callers.push(tmux);
            vec![submit_ssh(
                state,
                "github",
                "SHA256:Nh0Me49Zh9fDw/VYUfq43IJmI1T+XrjiYONPND8GzaM",
                Some("git pushes to github.com"),
                "~/repos/acme",
                None,
                callers,
            )]
        },
    );
}

#[test]
fn agent_scope_pending() {
    // A guest VM asked a scoped agent socket for a ref on its allowlist.
    // This is the prompt's third variant, and the one where what's *absent*
    // is the point: the header leads with the sandbox (the scope IS the
    // principal), the well shows SECRET + SCOPE, and there is deliberately
    // no ASKED BY tree and no IN row — a guest has no host process tree or
    // cwd, and rendering a chain-shaped widget here would imply we verified
    // something we cannot. See `src/scoped_agent/mod.rs`.
    //
    // This guest claimed nothing, so there is no GUEST SAYS row either
    // (contrast `36-agent-guest-chain-pending`). The "Scope: Approve for 5
    // min" action is the TTL grant that anchors an approval to the sandbox.
    //
    // DECLARED BY is the genuine case: the socket peer is a `secreq agent
    // open` the user started, in the executable they installed. Contrast
    // `42-agent-declared-by-impostor`, which is the same prompt when the peer
    // is anything else.
    render_prompt_fixture(
        Shot::new("34-agent-scope-pending").caption(
            "A request from a guest VM. The headline is the <b>sandbox</b>, because a \
             guest has no host process tree — the scope you declared is the principal, \
             and there is deliberately no caller chain to read. <b>DECLARED BY</b> is \
             the local process that opened the socket, which here is the \
             <code>secreq agent open</code> you started.",
        ),
        vec![],
        |state| {
            vec![submit_agent(
                state,
                "brain-nx-t5",
                "secret://op/Dev/gh/token",
                None,
                Some(agent_open_peer()),
            )]
        },
    );
}

/// The socket peer of a *genuine* scoped-agent ask: the `secreq agent open`
/// the user ran to declare the scope, at the path they installed it to.
fn agent_open_peer() -> secreq::daemon::proto::LocalPeer {
    secreq::daemon::proto::LocalPeer {
        pid: 4711,
        name: "secreq".to_owned(),
        command: "secreq agent open --scope brain-nx-t5 --allow secret://op/Dev/gh/token"
            .to_owned(),
        exe: Some("/usr/local/bin/secreq".to_owned()),
    }
}

#[test]
fn agent_declared_by_impostor_pending() {
    // The kind-forgery residue, rendered. Any local process can send an ask
    // claiming the scoped-agent kind — a guest ask and a wrap ask arrive as
    // the same message on the same socket, and `SO_PEERCRED` answers for the
    // sender, not for a guest that may not exist. It can no longer carry
    // secrets or a forged caller chain (`AskSubject` closed that), but until
    // now it could still *decline to say who it is*: with no ASKED BY row, a
    // forgery looked exactly like the design working as intended.
    //
    // Everything above DECLARED BY here is the forger's to write — the scope
    // name, the ref, its own `comm`, its own argv. The executable path is
    // not, and neither is the fact that a row appears at all. Set this beside
    // `34-agent-scope-pending`, which is the same prompt with a real
    // `agent open` on the socket, and the two are no longer the same picture.
    //
    // secreq does not refuse this ask. Refusing would mean deciding which
    // executables may speak for a guest, which is fail-closed, breaks a
    // `cargo run` daemon talking to an installed `agent open`, and needs an
    // exception list that is a hole with a nicer name.
    render_prompt_fixture(
        Shot::new("42-agent-declared-by-impostor").caption(
            "Any local program can send a request that claims to be a sandbox. It cannot \
             carry secrets and it cannot invent a caller chain — and now it cannot be \
             anonymous either. <b>DECLARED BY</b> names the process that actually opened \
             the socket, with the executable path it is running from, which is the one \
             line on this prompt the sender did not choose.",
        ),
        vec![],
        |state| {
            vec![submit_agent(
                state,
                "brain-nx-t5",
                "secret://op/Dev/gh/token",
                None,
                Some(secreq::daemon::proto::LocalPeer {
                    pid: 9931,
                    // A name and an argv it picked to look like the real
                    // thing. Both render; neither is checked.
                    name: "secreq".to_owned(),
                    command: "secreq agent open --scope brain-nx-t5".to_owned(),
                    // The kernel's answer, and the only one it could not
                    // write for itself.
                    exe: Some("/tmp/.build-cache/postinstall".to_owned()),
                }),
            )]
        },
    );
}

#[test]
fn agent_guest_chain_pending() {
    // The same scoped-agent prompt, but the guest volunteered a caller
    // chain. This fixture exists to show the **marker**, which is the entire
    // point of the surface: GUEST SAYS renders the claim, and the red
    // "⚠ guest-reported — NOT verifiable" sits directly under it.
    //
    // Read the well top-to-bottom and it tells the truth in order: SECRET
    // and SCOPE are host-declared facts, then — below them, dimmer, and
    // explicitly disclaimed — what the guest says about itself. The chain
    // never touches the decision or the approval cache; it is here for a
    // human to weigh and for the audit log to record as a claim. See the
    // "Decision: the sandbox is the principal" section of
    // `brain: areas/secreq/design/2026-07-16-remote-secret-agent.md`.
    render_prompt_fixture(
        Shot::new("36-agent-guest-chain-pending").caption(
            "The same request when the guest volunteers a caller chain. It renders \
             dimmed under <b>GUEST SAYS</b> and marked <b>not verifiable</b> — \
             recorded as a claim, never used to make the decision.",
        ),
        vec![],
        |state| {
            vec![submit_agent(
                state,
                "brain-nx-t5",
                "secret://op/Dev/gh/token",
                Some("node → pnpm → postinstall"),
                Some(agent_open_peer()),
            )]
        },
    );
}

#[test]
fn nested_tree() {
    // Two child shells under one Superset.app root. The prompt shows
    // the oldest ask big (Focus Stack) with the full caller chain in
    // its ASKED BY well row; the second ask shows as "1 more waiting".
    render_prompt_fixture(
        Shot::new("03-nested-tree").caption(
            "A deeper ancestry. Every process between your shell and the asking binary \
             is listed with its argv and pid, so a request from a build script never \
             looks like one you typed.",
        ),
        vec![],
        |state| {
            vec![
                submit(
                    state,
                    "gh",
                    vec!["gh", "repo", "list"],
                    vec![
                        caller(7926, "zsh", 1_700_000_000),
                        caller(2831, "Superset.app", 1_650_000_000),
                    ],
                    vec![secret(
                        "GITHUB_TOKEN",
                        "op",
                        "op://Personal/GitHub/credential",
                    )],
                ),
                submit(
                    state,
                    "aws",
                    vec!["aws", "s3", "ls"],
                    vec![
                        caller(7927, "zsh", 1_700_000_100),
                        caller(2831, "Superset.app", 1_650_000_000),
                    ],
                    vec![
                        secret("AWS_ACCESS_KEY_ID", "op", "op://Work/AWS/access_key_id"),
                        secret(
                            "AWS_SECRET_ACCESS_KEY",
                            "op",
                            "op://Work/AWS/secret_access_key",
                        ),
                    ],
                ),
            ]
        },
    );
}

#[test]
fn multi_root() {
    // Two unrelated callers. The prompt renders the older ask; the
    // unrelated second one is the "1 more waiting" line in the footer.
    render_prompt_fixture(
        Shot::new("04-multi-root").caption(
            "Two unrelated commands asked at once. You answer the oldest first; the \
             rest wait behind <b>1 more waiting</b> rather than stacking windows.",
        ),
        vec![],
        |state| {
            vec![
                submit(
                    state,
                    "gh",
                    vec!["gh", "pr", "create"],
                    vec![caller(7926, "zsh", 1_700_000_000)],
                    vec![secret(
                        "GITHUB_TOKEN",
                        "op",
                        "op://Personal/GitHub/credential",
                    )],
                ),
                submit(
                    state,
                    "aws",
                    vec!["aws", "lambda", "deploy"],
                    vec![
                        caller(8400, "node", 1_700_001_000),
                        caller(8001, "npm", 1_700_000_500),
                    ],
                    vec![secret("AWS_SESSION_TOKEN", "keychain", "AWS-session-token")],
                ),
            ]
        },
    );
}

#[test]
fn folded_run() {
    // Four-deep gh→gh→gh→gh chain — the prompt's ASKED BY tree shows
    // the whole ancestry with the asking leaf in accent.
    render_prompt_fixture(
        Shot::new("05-folded-run").caption(
            "A binary that re-executes itself would otherwise stack four identical \
             rows. The chain folds to one entry per distinct process.",
        ),
        vec![],
        |state| {
            vec![submit(
                state,
                "gh",
                vec!["gh", "api", "/repos"],
                vec![
                    caller(9000, "gh", 1_700_010_000),
                    caller(8999, "gh", 1_700_009_900),
                    caller(8998, "gh", 1_700_009_800),
                    caller(8997, "gh", 1_700_009_700),
                    caller(7926, "zsh", 1_700_000_000),
                ],
                vec![secret(
                    "GITHUB_TOKEN",
                    "op",
                    "op://Personal/GitHub/credential",
                )],
            )]
        },
    );
}

#[test]
fn pending_with_deny_history() {
    // A wrap whose audit history's last decision is `deny` colours the
    // prompt's HISTORY row — the load-bearing "second look" cue before
    // the user accidentally approves something they previously rejected.
    let audit = vec![
        audit_line(60 * 5, "gh", "zsh", &["GITHUB_TOKEN"], "deny"),
        audit_line(60 * 60 * 24, "gh", "zsh", &["GITHUB_TOKEN"], "approve"),
        audit_line(
            60 * 60 * 24 * 2,
            "gh",
            "zsh",
            &["GITHUB_TOKEN"],
            "approve+remember",
        ),
    ];
    render_prompt_fixture(
        Shot::new("06-pending-denied-last").caption(
            "The HISTORY row carries your last decision for this wrap and caller. A \
             previous deny is tinted, so a repeat request from something you already \
             turned down is hard to approve by reflex.",
        ),
        audit,
        |state| {
            vec![submit(
                state,
                "gh",
                vec!["gh", "auth", "refresh"],
                vec![caller(7926, "zsh", 1_700_000_000)],
                vec![secret(
                    "GITHUB_TOKEN",
                    "op",
                    "op://Personal/GitHub/credential",
                )],
            )]
        },
    );
}

#[test]
fn auto_deny_toast_on_pending() {
    // The transient toast the renderer draws at the top of the prompt
    // when handed an auto-deny badge. Caller in the production child is
    // the reader thread; here we just hand the harness a synthetic toast
    // to exercise the primitive. (In production the child suppresses the
    // toast the moment an ask is on screen — see `toast_to_render` — so
    // this exact "badge over a live approval" composition is a
    // renderer-level unit, not a state the running app presents.)
    let toast = AutoDenyToastView {
        rule_name: "Block gh destructive ops".to_owned(),
        deny_message: Some("Destructive gh operations are policy-denied.".to_owned()),
    };
    render_prompt_fixture_full(
        Shot::new("12-auto-deny-toast").caption(
            "A rule denied a request without asking. The banner names the rule that \
             fired and the message it was configured with.",
        ),
        PROMPT_SIZE,
        vec![],
        Some(toast),
        None,
        |state| {
            vec![submit(
                state,
                "gh",
                vec!["gh", "api", "/repos"],
                vec![caller(7926, "zsh", 1_700_000_000)],
                vec![secret(
                    "GITHUB_TOKEN",
                    "op",
                    "op://Personal/GitHub/credential",
                )],
            )]
        },
    );
}

#[test]
fn pending_arrival_highlight() {
    // Two asks queued: the prompt renders the oldest big and counts the
    // rest in the footer's "1 more waiting" line. (The old tabbed
    // window's arrival *pulse* died with the tab bar — the queue-depth
    // line is the two-window replacement for "something else arrived".)
    render_prompt_fixture("22-pending-arrival-highlight", vec![], |state| {
        vec![
            submit(
                state,
                "gh",
                vec!["gh", "auth", "refresh"],
                vec![caller(7926, "zsh", 1_700_000_000)],
                vec![secret(
                    "GITHUB_TOKEN",
                    "op",
                    "op://Personal/GitHub/credential",
                )],
            ),
            submit(
                state,
                "aws",
                vec!["aws", "s3", "ls"],
                vec![caller(7927, "zsh", 1_700_000_100)],
                vec![secret("AWS_ACCESS_KEY_ID", "op", "op://Work/AWS/key")],
            ),
        ]
    });
}

// ── Manager fixtures: Audit view ──────────────────────────────────────────

#[test]
fn audit_tab_populated() {
    // Viewer mode: the user opened the manager via `secreq view` to
    // browse history — the viewer-mode rising edge lands them on the
    // Audit view, rendered as hairline-separated flat rows with
    // dot+text verdicts.
    let audit = vec![
        audit_line_traced(
            60,
            "gh",
            &["pr", "view", "9421"],
            &[
                (52310, "zsh", "-zsh"),
                (51200, "Terminal", "/Applications/Utilities/Terminal.app"),
            ],
            &["GITHUB_TOKEN"],
            "approve+remember",
        ),
        audit_line_traced(
            60 * 7,
            "aws",
            &["s3", "ls", "s3://prod-backups/"],
            &[
                (52312, "zsh", "-zsh"),
                (51200, "Terminal", "/Applications/Utilities/Terminal.app"),
            ],
            &["AWS_ACCESS_KEY_ID"],
            "approve",
        ),
        audit_line_traced(
            60 * 17,
            "kubectl",
            &["apply", "-f", "deploy/prod.yaml"],
            &[
                (52314, "make", "make ci-deploy"),
                (52313, "zsh", "-zsh"),
                (51200, "Terminal", "/Applications/Utilities/Terminal.app"),
            ],
            &["KUBECONFIG_TOKEN"],
            "deny",
        )
        .with_reason(Some("Wrong production repository".to_owned())),
        audit_line_traced(
            60 * 60,
            "psql",
            &["-h", "db.internal", "-U", "analytics"],
            &[(52320, "node", "node ./scripts/import.js")],
            &["PGPASSWORD"],
            "approve+remember",
        ),
        audit_line_traced(
            60 * 60 * 6,
            "gh",
            &["api", "/repos/acme/web/issues"],
            &[(52330, "npm", "npm run sync")],
            &["GITHUB_TOKEN"],
            "approve",
        ),
    ];
    render_manager_fixture(
        Shot::new("07-audit-tab").caption(
            "Every decision is written down: what asked, what it wanted, where from, \
             and how it went. Your answers and rule auto-fires land in the same list.",
        ),
        audit,
        ManagerExtras {
            viewer_mode: true,
            ..ManagerExtras::default()
        },
    );
}

#[test]
fn audit_tab_with_pending() {
    // The manager's Audit view opened deliberately (not viewer-pinned):
    // the user pulled up the manager from the prompt's "Open Manager…"
    // link to remind themselves what happened the last few times this
    // same wrap ran. (Queue state lives in the prompt window now; the
    // manager renders history regardless.)
    let audit = vec![
        audit_line_traced(
            60 * 3,
            "gh",
            &["pr", "view", "9421"],
            &[
                (52310, "zsh", "-zsh"),
                (51200, "Terminal", "/Applications/Utilities/Terminal.app"),
            ],
            &["GITHUB_TOKEN"],
            "approve+remember",
        ),
        audit_line_traced(
            60 * 8,
            "gh",
            &[
                "api",
                "--method",
                "GET",
                "repos/acme/web/commits/abc123/statuses",
                "-f",
                "per_page=100",
            ],
            &[(
                15334,
                "Superset",
                "/Applications/Superset.app/Contents/MacOS/Superset",
            )],
            &["GITHUB_TOKEN"],
            "approve+auto",
        ),
        audit_line_traced(
            60 * 15,
            "aws",
            &["s3", "ls", "s3://prod-backups/"],
            &[
                (52312, "zsh", "-zsh"),
                (51200, "Terminal", "/Applications/Utilities/Terminal.app"),
            ],
            &["AWS_ACCESS_KEY_ID"],
            "approve",
        ),
        audit_line_traced(
            60 * 22,
            "gh",
            &["auth", "token", "--hostname", "github.com"],
            &[(72964, "claude", "claude --resume bbb3cb6d")],
            &["GITHUB_TOKEN"],
            "deny+auto",
        ),
        audit_line_traced(
            60 * 60,
            "psql",
            &["-h", "db.internal", "-U", "analytics"],
            &[(52320, "node", "node ./scripts/import.js")],
            &["PGPASSWORD"],
            "approve+remember",
        ),
    ];
    render_manager_fixture(
        Shot::new("14-audit-tab-with-pending").caption(
            "You can read the log while a request is still queued — the prompt window \
             holds the decision, so browsing history never blocks it.",
        ),
        audit,
        ManagerExtras {
            window_state: Some(Box::new(
                secreq::daemon::manager_ui::ManagerWindowState::focus_audit_view,
            )),
            ..ManagerExtras::default()
        },
    );
}

/// Shared audit log for the search fixtures.
fn search_fixture_audit() -> Vec<AuditEntry> {
    vec![
        audit_line_traced(
            60 * 2,
            "gh",
            &["pr", "view", "9421"],
            &[(52310, "zsh", "-zsh")],
            &["GITHUB_TOKEN"],
            "approve+remember",
        ),
        audit_line_traced(
            60 * 8,
            "gh",
            &[
                "api",
                "--method",
                "GET",
                "repos/acme/web/commits/abc123/statuses",
                "-f",
                "per_page=100",
            ],
            &[(
                15334,
                "Superset",
                "/Applications/Superset.app/Contents/MacOS/Superset",
            )],
            &["GITHUB_TOKEN"],
            "approve+auto",
        ),
        audit_line_traced(
            60 * 15,
            "aws",
            &["s3", "ls", "s3://prod-backups/"],
            &[(52312, "zsh", "-zsh")],
            &["AWS_ACCESS_KEY_ID"],
            "approve",
        ),
        audit_line_traced(
            60 * 22,
            "gh",
            &["auth", "token", "--hostname", "github.com"],
            &[(72964, "claude", "claude --resume bbb3cb6d")],
            &["GITHUB_TOKEN"],
            "deny+auto",
        ),
        audit_line_traced(
            60 * 60,
            "kubectl",
            &["apply", "-f", "deploy/prod.yaml"],
            &[(52314, "make", "make ci-deploy")],
            &["KUBECONFIG_TOKEN"],
            "deny",
        ),
    ]
}

#[test]
fn audit_tab_search_filtering() {
    // The Audit view with an active query (typed into the header's
    // search box) that filters down to a subset. Exercises the "N of M"
    // count line and the filtered rendering.
    render_manager_fixture(
        Shot::new("15-audit-tab-search-filtering").caption(
            "Search narrows the log across every field at once, and reports how much \
             of it you are looking at.",
        ),
        search_fixture_audit(),
        ManagerExtras {
            window_state: Some(Box::new(|ws| {
                ws.focus_audit_view();
                // "gh" matches three of the five entries; the aws /
                // kubectl rows fall out so the count reads "3 of 5".
                ws.set_audit_search("gh");
            })),
            ..ManagerExtras::default()
        },
    );
}

#[test]
fn audit_tab_abandoned_row() {
    // The Audit tab showing an `abandoned` row — a wrap that exited before
    // the user decided, so the daemon reaped the ask and logged it itself.
    // Placed between an approve and a deny so the faint "abandoned"
    // dot+text verdict reads as a non-event, distinct from either real
    // verdict.
    let audit = vec![
        audit_line_traced(
            60 * 3,
            "gh",
            &["pr", "view", "9421"],
            &[(52310, "zsh", "-zsh")],
            &["GITHUB_TOKEN"],
            "approve+remember",
        ),
        audit_line_traced(
            60 * 6,
            "gh",
            &["pr", "checkout", "9420"],
            &[(52311, "zsh", "-zsh")],
            &["GITHUB_TOKEN"],
            "abandoned",
        ),
        audit_line_traced(
            60 * 12,
            "aws",
            &["s3", "ls", "s3://prod-backups/"],
            &[(52312, "make", "make ci-deploy")],
            &["AWS_ACCESS_KEY_ID"],
            "deny",
        ),
    ];
    render_manager_fixture(
        Shot::new("27-audit-tab-abandoned").caption(
            "A command that exited before you answered is logged as <b>abandoned</b>. \
             The faint verdict reads as a non-event — it is not a denial, and nothing \
             was released.",
        ),
        audit,
        ManagerExtras {
            window_state: Some(Box::new(
                secreq::daemon::manager_ui::ManagerWindowState::focus_audit_view,
            )),
            ..ManagerExtras::default()
        },
    );
}

#[test]
fn audit_tab_agent_out_of_scope_row() {
    // The Audit view showing a scoped agent's rows. The `deny+out-of-scope`
    // row is the reason this verdict exists: the guest asked for a ref its
    // socket was never opened with, so it was refused *without a prompt* —
    // the "out of scope" tag says the user was never asked, distinguishing
    // it from the plain `deny` below (a ref that was offered and refused).
    // A run of these rows is what a probing sandbox looks like.
    //
    // Note the rows carry no caller chain: a guest has no host process tree.
    let audit = vec![
        agent_audit_line(
            60 * 2,
            "brain-nx-t5",
            "secret://op/Dev/gh/token",
            Decision::Approve,
            genuine_agent_peer(),
        ),
        agent_audit_line(
            60 * 4,
            "brain-nx-t5",
            "secret://op/Prod/aws/root_key",
            Decision::DenyOutOfScope,
            // The allowlist refused this one before any daemon was dialled,
            // so nothing read a peer for it. That is what the production path
            // records, and what the row must not dress up as a reading.
            ScopeDeclarant::NotRead,
        ),
        audit_line_traced(
            60 * 9,
            "aws",
            &["s3", "ls", "s3://prod-backups/"],
            &[(52312, "make", "make ci-deploy")],
            &["AWS_ACCESS_KEY_ID"],
            "deny",
        ),
    ];
    render_manager_fixture(
        Shot::new("35-audit-tab-agent-out-of-scope").caption(
            "A guest asked for a secret outside its declared scope. The agent refused \
             without prompting you, and the attempt is on the record.",
        ),
        audit,
        ManagerExtras {
            window_state: Some(Box::new(
                secreq::daemon::manager_ui::ManagerWindowState::focus_audit_view,
            )),
            ..ManagerExtras::default()
        },
    );
}

#[test]
fn audit_tab_chain_completeness() {
    // The two ways a row admits its tree is not the whole ancestry, one above
    // the other so the wording difference is legible:
    //
    //   `… may be more above` — the row predates the field; nothing recorded
    //                           whether the walk reached the top.
    //   `… more above`        — the walk stopped at its own ceiling; there IS
    //                           ancestry above and secreq did not read it.
    //
    // Rows in that order because that is the order they occur in: the unknown
    // ones are the ones already in your log. The third state — a walk that
    // reached the top — draws no marker at all, which is what every other
    // audit fixture here is showing; adding a row for it would only push one
    // of these two below the fold.
    let audit = vec![
        chain_unrecorded(audit_line_traced(
            60 * 60 * 30,
            "aws",
            &["s3", "ls", "s3://prod-backups/"],
            &[
                (49220, "zsh", "-zsh"),
                (49100, "Terminal", "/Applications/Utilities/Terminal.app"),
            ],
            &["AWS_ACCESS_KEY_ID"],
            "approve+remember",
        )),
        chain_clipped(audit_line_traced(
            60 * 4,
            "gh",
            &["api", "/repos/acme/web/issues"],
            &[
                (52318, "node", "node ./scripts/publish.js"),
                (52317, "npm", "npm run release"),
                (52316, "make", "make ci-deploy"),
            ],
            &["GITHUB_TOKEN"],
            "approve",
        )),
    ];
    render_manager_fixture(
        Shot::new("40-audit-chain-completeness").caption(
            "A row says how much of the ancestry secreq actually saw. \
             <b>… more above</b> means the walk stopped before the top, so whatever \
             launched the command is not shown here. <b>… may be more above</b> is an \
             older row, written before secreq recorded which of the two it was — the \
             log cannot say, so neither does the tree.",
        ),
        audit,
        ManagerExtras {
            window_state: Some(Box::new(
                secreq::daemon::manager_ui::ManagerWindowState::focus_audit_view,
            )),
            ..ManagerExtras::default()
        },
    );
}

#[test]
fn audit_tab_agent_declared_by() {
    // The audit counterpart to fixtures 34 and 42, which show the same
    // comparison live. Two guest releases against one scope, alike in every
    // field the log kept until now — same scope, same ref, same verdict — and
    // the `named by` line is the whole difference:
    //
    //   `secreq  /usr/local/bin/secreq` — the agent the user started.
    //   `secreq  /tmp/.build-cache/…`   — a process that chose that `comm`.
    //
    // Newest first, so the forgery is the row on top: the reader meets the
    // odd one and then finds what an ordinary one looks like directly beneath
    // it, rather than having to remember an ordinary one from elsewhere.
    let audit = vec![
        agent_audit_line(
            60 * 60 * 5,
            "brain-nx-t5",
            "secret://op/Dev/gh/token",
            Decision::Approve,
            genuine_agent_peer(),
        ),
        agent_audit_line(
            60 * 6,
            "brain-nx-t5",
            "secret://op/Dev/gh/token",
            Decision::Approve,
            ScopeDeclarant::Peer(AuditLocalPeer {
                pid: 82702,
                name: "secreq".to_owned(),
                command: "secreq agent open brain-nx-t5".to_owned(),
                exe: Some("/tmp/.build-cache/postinstall".to_owned()),
            }),
        ),
    ];
    render_manager_fixture(
        Shot::new("44-audit-agent-declared-by").caption(
            "A sandbox request records which local process put its scope name on the \
             wire. A genuine request names the <code>secreq agent open</code> you \
             started, at the path you installed it to; the one above it names \
             <code>secreq</code> too, and an executable you did not install. secreq \
             cannot tell the two apart and does not guess — it writes down what the \
             kernel said, so the difference is still there when you come back to it.",
        ),
        audit,
        ManagerExtras {
            window_state: Some(Box::new(
                secreq::daemon::manager_ui::ManagerWindowState::focus_audit_view,
            )),
            ..ManagerExtras::default()
        },
    );
}

/// Attach a chain the guest claimed about itself. Separate from
/// [`agent_audit_line`] because most guest rows carry none, and a helper that
/// made every fixture pass `None` would make the claim look ordinary.
fn with_guest_chain(mut entry: AuditEntry, chain: &str) -> AuditEntry {
    entry.unverified_guest_chain = Some(chain.to_owned());
    entry
}

/// A guest's claimed chain in the audit view, above a wrap row whose chain the
/// host actually walked.
///
/// The audit counterpart to fixture 36, which shows the same claim live on the
/// prompt. It was written, documented and asserted for a long time before
/// anything drew it, so a guest's story was visible on the prompt and invisible
/// in the log — the review surface silently disagreeing with the consent UI
/// about what happened.
///
/// The wrap row beneath it is the substance rather than filler. The hazard in
/// drawing a guest's claim at all is that it reads as ancestry, and the only
/// way to show that it does not is to put real ancestry directly under it: one
/// is a tree the kernel answered for, the other is a line of text a sandbox
/// sent over a socket with a red caveat under it. A reader who sees them
/// adjacent never has to be told which is which.
#[test]
fn audit_tab_guest_chain() {
    let audit = vec![
        audit_line_traced(
            60 * 60 * 3,
            "gh",
            &["api", "/repos/acme/web/issues"],
            &[
                (52318, "node", "node ./scripts/publish.js"),
                (52317, "make", "make ci-deploy"),
            ],
            &["GITHUB_TOKEN"],
            "approve",
        ),
        with_guest_chain(
            agent_audit_line(
                60 * 4,
                "brain-nx-t5",
                "secret://op/Dev/gh/token",
                Decision::Approve,
                genuine_agent_peer(),
            ),
            // A postinstall script reaching for a token is the shape worth
            // recording: useful if the guest is honest, interesting if it is
            // not, and evidence either way it is not.
            "node → pnpm → postinstall",
        ),
    ];
    render_manager_fixture(
        Shot::new("46-audit-guest-chain").caption(
            "A sandbox can volunteer what it says was running inside it. secreq \
             writes the claim down and marks it, because nothing on the host can \
             check it: a guest that wanted to name a different ancestry would say \
             exactly this. The <code>gh</code> row below it carries the other kind \
             of chain, the one secreq walked itself. Never read the marked one as \
             the unmarked one.",
        ),
        audit,
        ManagerExtras {
            window_state: Some(Box::new(
                secreq::daemon::manager_ui::ManagerWindowState::focus_audit_view,
            )),
            ..ManagerExtras::default()
        },
    );
}

/// Searching the log by a process name, where one of the hits is a name only
/// a guest claimed.
///
/// The gap this closes is narrow and easy to miss: fixture 46 shows the claim
/// drawn on the row, and the search box could not reach it. A reviewer who has
/// read an incident report types the process name, and the one row where
/// something *said* it was that process was the one row that did not come
/// back.
///
/// The picture has to be the search results rather than the claim, because the
/// hazard lives in the results: a guest picks that string, so a guest can put
/// its row in the results for any term it likes. The row still arrives wearing
/// `guest says` and the red caveat — the search reads the claim through the
/// same accessor the row draws from — and the `gh` row beside it is what a hit
/// on a walked chain looks like for the same query.
#[test]
fn audit_tab_search_finds_guest_claim() {
    let audit = vec![
        audit_line_traced(
            60 * 60 * 5,
            "aws",
            &["s3", "ls", "s3://prod-backups/"],
            &[(52312, "zsh", "-zsh")],
            &["AWS_ACCESS_KEY_ID"],
            "approve",
        ),
        audit_line_traced(
            60 * 60 * 2,
            "gh",
            &["api", "/repos/acme/web/issues"],
            &[
                (52318, "node", "node ./scripts/postinstall.js"),
                (52317, "pnpm", "pnpm install"),
            ],
            &["GITHUB_TOKEN"],
            "approve",
        ),
        with_guest_chain(
            agent_audit_line(
                60 * 6,
                "brain-nx-t5",
                "secret://op/Dev/gh/token",
                Decision::Approve,
                genuine_agent_peer(),
            ),
            "node → pnpm → postinstall",
        ),
    ];
    render_manager_fixture(
        Shot::new("48-audit-search-guest-claim").caption(
            "Search reaches a guest's claimed chain too, so filtering the log by a \
             process name cannot quietly skip the rows where something only said \
             it was that process. A row found that way still arrives marked: \
             <code>guest says</code> is a claim, the tree above it is not.",
        ),
        audit,
        ManagerExtras {
            window_state: Some(Box::new(|ws| {
                ws.focus_audit_view();
                // Two of the three rows hold `postinstall` — one in a chain
                // secreq walked, one in a chain a guest sent it.
                ws.set_audit_search("postinstall");
            })),
            ..ManagerExtras::default()
        },
    );
}

/// The timeline these two burst fixtures share: a probing sandbox, and the
/// ordinary history it would otherwise bury.
///
/// **Written oldest-first**, which is what an append-only `audit.log` actually
/// holds and what the view reverses to put the newest row on top. Several
/// older audit fixtures here write their vec newest-first and so publish their
/// timeline upside down; a burst cannot borrow that, because the run's span is
/// the thing the fixture is documenting.
///
/// Four refusals rather than the forty-odd a real probe would produce, because
/// the expanded fixture has to show the group *ending* — the indent stopping
/// and an ungrouped row resuming under it is half of what that fixture is for,
/// and a burst that runs past the fold shows a list instead of a group. The
/// count and the span in the header are what stand in for scale.
fn probing_guest_timeline() -> Vec<AuditEntry> {
    let mut audit = vec![audit_line_traced(
        60 * 12,
        "gh",
        &["api", "/repos/acme/web/issues"],
        &[(52318, "node", "node ./scripts/publish.js")],
        &["GITHUB_TOKEN"],
        "approve+remember",
    )];
    // The burst: same scope, same ref, same refusal, one per second.
    // `NotRead` because the scope's own allowlist refused these before any
    // daemon was dialled — nothing read a peer, and the row must not dress
    // that up as a reading.
    for secs_ago in [18u64, 17, 16, 15] {
        audit.push(agent_audit_line(
            secs_ago,
            "brain-nx-t5",
            "secret://op/Prod/aws/root_key",
            Decision::DenyOutOfScope,
            ScopeDeclarant::NotRead,
        ));
    }
    audit
}

#[test]
fn audit_tab_burst_collapsed() {
    // A guest that can ask as often as it likes used to be able to push
    // everything else off the page one identical row at a time. It now costs
    // one row and a count, and the `gh` grant from twelve minutes ago is still
    // where a reader would look for it.
    //
    // The count and the span are the whole header: four attempts inside three
    // seconds is a loop hammering the socket, and the same four spread over
    // three hours would be something on a timer. Nothing is dropped — the
    // rows are still in `audit.log`, and the caret opens them (fixture 50).
    render_manager_fixture(
        Shot::new("49-audit-burst-collapsed").caption(
            "A sandbox asking over and over for a secret outside its scope folds \
             into one row. The count and the span say how hard it tried and for \
             how long, so a flood cannot push the rest of your history off the \
             page. Every attempt is still its own line in <code>audit.log</code>.",
        ),
        probing_guest_timeline(),
        ManagerExtras {
            window_state: Some(Box::new(
                secreq::daemon::manager_ui::ManagerWindowState::focus_audit_view,
            )),
            ..ManagerExtras::default()
        },
    );
}

#[test]
fn audit_tab_burst_expanded() {
    // The other half, and the reason the collapsing is honest: the view is
    // folding rows, not withholding them. Opened, each attempt is back with
    // its own timestamp, under an indent that says where the group ends.
    let audit = probing_guest_timeline();
    // The burst is keyed on its oldest member — the first agent row in the
    // vec, since this timeline is written oldest-first.
    let oldest_of_burst = audit
        .iter()
        .find(|e| e.decision == "deny+out-of-scope")
        .expect("the timeline's burst")
        .clone();
    render_manager_fixture(
        Shot::new("50-audit-burst-expanded").caption(
            "Opening the group puts every attempt back, each with its own time. \
             The view folds rows together; it never withholds them.",
        ),
        audit,
        ManagerExtras {
            window_state: Some(Box::new(move |ws| {
                ws.focus_audit_view();
                ws.expand_audit_burst(&oldest_of_burst);
            })),
            ..ManagerExtras::default()
        },
    );
}

#[test]
fn audit_tab_forwarded_sign() {
    // The two things an SSH sign row can say about agent forwarding that a
    // reader would otherwise get wrong, one above the other:
    //
    //   `⚠ signed through a forwarded agent` — the request came from the host
    //                                          at the other end of an `ssh -A`
    //                                          session, and the argv names it.
    //   `⚠ agent forwarding not recorded`    — the row predates the field, so
    //                                          the log cannot say which it was.
    //
    // The third state — an ordinary local sign — draws no marker, exactly the
    // way a whole caller chain draws no `… more above`. Giving it a row here
    // would push one of these two below the fold and teach nothing: the
    // caller tree in both rows is the same, which is the point.
    let audit = vec![
        sign_anchor_unrecorded(ssh_audit_line(
            60 * 60 * 26,
            "github",
            &[(8120, "git", "git push origin main"), (7926, "zsh", "-zsh")],
            None,
            Decision::ApproveCached,
        )),
        ssh_audit_line(
            60 * 3,
            "github",
            &[(8120, "git", "git push origin main"), (7926, "zsh", "-zsh")],
            Some((9310, "ssh -A build-box")),
            // Plain `Approve`, not `ApproveSshSession`: the session-grant
            // decisions currently fall through `AuditVerdict::from_decision`
            // to a faint "seen", and a fixture is not the place to publish
            // that. See the handoff note.
            Decision::Approve,
        ),
    ];
    render_manager_fixture(
        Shot::new("43-audit-forwarded-sign").caption(
            "An SSH signature says whether it was asked for from this machine or \
             through an agent you forwarded. <b>signed through a forwarded agent</b> \
             names the session that could have been asking — that <code>ssh</code> is \
             the process on the socket, so it is never in the tree above it. \
             <b>agent forwarding not recorded</b> is an older row, written before \
             secreq kept the difference.",
        ),
        audit,
        ManagerExtras {
            window_state: Some(Box::new(
                secreq::daemon::manager_ui::ManagerWindowState::focus_audit_view,
            )),
            ..ManagerExtras::default()
        },
    );
}

#[test]
fn audit_tab_search_no_matches() {
    // The "your query found nothing" empty state: a query that misses
    // every row falls through to the centered "No matching entries"
    // message instead of the day-bucket loop.
    render_manager_fixture(
        "16-audit-tab-search-no-matches",
        search_fixture_audit(),
        ManagerExtras {
            window_state: Some(Box::new(|ws| {
                ws.focus_audit_view();
                ws.set_audit_search("postgres");
            })),
            ..ManagerExtras::default()
        },
    );
}

#[test]
fn audit_tab_search_multi_term() {
    // Multi-term search: each whitespace-separated term must hit some
    // field, so "gh auth" narrows to the single row whose wrap is `gh`
    // AND whose argv contains `auth` — even though no single field
    // holds the literal "gh auth". Regression guard for the reported
    // bug where "gh auth" wrongly filtered out `gh auth token`.
    render_manager_fixture(
        Shot::new("17-audit-tab-search-multi-term").caption(
            "Each term can match a different field, so <code>gh auth</code> finds the \
             row where both are true.",
        ),
        search_fixture_audit(),
        ManagerExtras {
            window_state: Some(Box::new(|ws| {
                ws.focus_audit_view();
                ws.set_audit_search("gh auth");
            })),
            ..ManagerExtras::default()
        },
    );
}

// ── Manager fixtures: Rules view ──────────────────────────────────────────

/// Helper for building a representative rule the harness can drop
/// onto the Rules view without going through the full UI.
fn sample_rule(id: &str, name: &str, decide: RuleDecision, argv: Option<&str>) -> Rule {
    Rule {
        id: id.to_owned(),
        name: name.to_owned(),
        enabled: true,
        wraps: None,
        trained_secrets: ["GITHUB_TOKEN".to_owned()].into_iter().collect(),
        created_at_unix: 0,
        body: RuleBody::Declarative {
            r#match: RuleMatch {
                wrap: "gh".to_owned(),
                argv: argv.map(Pattern::parse),
                ancestor: Some(Pattern::parse("Cursor.app")),
                cwd: None,
            },
            decide: match decide {
                RuleDecision::Approve => StaticDecision::Approve,
                RuleDecision::Deny => StaticDecision::Deny {
                    message: Some("Destructive gh operations are policy-denied.".to_owned()),
                },
            },
        },
    }
}

#[test]
fn rules_tab_empty() {
    // Land on the Rules view with no rules configured — the empty
    // state should be inviting, not blank.
    render_manager_fixture(
        Shot::new("08-rules-tab-empty")
            .caption("No rules yet — every request comes to you until you save one."),
        vec![],
        ManagerExtras {
            window_state: Some(Box::new(
                secreq::daemon::manager_ui::ManagerWindowState::focus_rules_view,
            )),
            ..ManagerExtras::default()
        },
    );
}

#[test]
fn rules_tab_list_populated() {
    // The list view with a representative mix: enabled approve, an
    // enabled deny with a configured deny message, and a disabled
    // rule (verifies the toggle's "off" state visual). The audit log
    // is seeded with auto-fires so each row's usage footnote is
    // populated; the disabled rule has none ("No auto-fires yet").
    let mut disabled = sample_rule(
        "01abc",
        "old cursor rule",
        RuleDecision::Approve,
        Some("gh api"),
    );
    disabled.enabled = false;
    let rules = vec![
        sample_rule(
            "02def",
            "Cursor reads via gh",
            RuleDecision::Approve,
            Some("gh api --get /repos/*/pulls*"),
        ),
        sample_rule(
            "03ghi",
            "Block gh destructive ops",
            RuleDecision::Deny,
            Some("gh repo delete *"),
        ),
        disabled,
    ];
    // 14 recent approves for the read rule, 3 older denies for the
    // block rule. Default "Most used" order: read (14) above block (3)
    // above the never-fired disabled rule.
    let mut audit = Vec::new();
    for i in 0..14 {
        audit.push(audit_auto_fire(60 * (i + 1), "02def", "approve+auto"));
    }
    for i in 0..3 {
        audit.push(audit_auto_fire(
            4 * 86400 + 60 * (i + 1),
            "03ghi",
            "deny+auto",
        ));
    }
    render_manager_fixture(
        Shot::new("09-rules-tab-list").caption(
            "Saved rules answer for you. Each row shows what it matches, whether it \
             approves or denies, how often it has fired, and which secrets it was \
             trained on.",
        ),
        audit,
        ManagerExtras {
            rules,
            window_state: Some(Box::new(
                secreq::daemon::manager_ui::ManagerWindowState::focus_rules_view,
            )),
            ..ManagerExtras::default()
        },
    );
}

#[test]
fn rules_tab_stale_mutation_rejected() {
    let deny = sample_rule(
        "deny-pat-release",
        "No github token",
        RuleDecision::Deny,
        Some("gh auth token"),
    );
    render_manager_fixture(
        Shot::new("51-rules-stale-mutation").caption(
            "This rule changed outside the open window, so secreq rejected the stale \
             edit instead of replacing newer policy. Reload the Rules view before \
             trying again.",
        ),
        vec![],
        ManagerExtras {
            rules: vec![deny],
            window_state: Some(Box::new(|state| {
                state.focus_rules_view();
                state.set_rule_mutation_error(Some(
                    "Rule `No github token` changed since the Rules view loaded it; \
                     reload the Rules view and try again"
                        .to_owned(),
                ));
            })),
            ..ManagerExtras::default()
        },
    );
}

/// A wasm rule whose stored module no longer hashes to what was pinned.
///
/// This is the only state in the whole UI where a rule that looks entirely
/// normal cannot fire, which is exactly why it needs a picture: every other
/// way of learning about it (`rules list`, `rules show`, the daemon log)
/// requires already suspecting something is wrong. The docs claim the Rules
/// view badges it; this is that claim, rendered.
///
/// The healthy wasm rule beside it is load-bearing rather than decorative.
/// A refusal badge means nothing without the row it is *not* on, and the
/// pair is also the answer to the question a reader has next: a tampered
/// module silences its own rule and nothing else, so protective denies keep
/// working.
#[test]
fn rules_tab_wasm_refused() {
    let wasm_rule = |id: &str, name: &str, sha: &str| Rule {
        id: id.to_owned(),
        name: name.to_owned(),
        enabled: true,
        wraps: None,
        trained_secrets: ["NPM_TOKEN".to_owned()].into_iter().collect(),
        created_at_unix: 0,
        body: RuleBody::Wasm(WasmRule {
            path: format!("rules/{id}.wasm"),
            sha256: sha.to_owned(),
            declared_secrets: None,
        }),
    };

    let rules = vec![
        wasm_rule(
            "4a1c8e0b21d3",
            "npm publish guard",
            "9c0e0f6c1d2b3a4857e6f0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5",
        ),
        wasm_rule(
            "5b2d9f1c32e4",
            "block agent-driven deploys",
            "1f2e3d4c5b6a798807162534435261708f9e0d1c2b3a49586776859403a2b1c0",
        ),
    ];

    let refusals = RuleRefusals {
        wasm: vec![WasmRefusal {
            rule_id: "5b2d9f1c32e4".to_owned(),
            category: WasmRefusalCategory::Sha256Mismatch,
            reason: "module `rules/5b2d9f1c32e4.wasm` hashes to \
                     7d4a…c19f, not the pinned 1f2e…b1c0 — it changed on disk \
                     since it was registered"
                .to_owned(),
        }],
        patterns: Vec::new(),
        scopes: Vec::new(),
    };

    let audit = (0..6)
        .map(|i| audit_auto_fire(60 * (i + 1), "4a1c8e0b21d3", "approve+auto"))
        .collect();

    render_manager_fixture(
        Shot::new("39-rules-wasm-refused").caption(
            "A wasm rule is pinned to the hash of the module you registered. If \
             the file changes, the daemon refuses that rule at its next load and \
             badges it here: it stays in your ruleset but can never fire. Only \
             that rule is refused — the one above it keeps working, so a tampered \
             module cannot switch off the rest of your policy.",
        ),
        audit,
        ManagerExtras {
            rules,
            refusals,
            window_state: Some(Box::new(
                secreq::daemon::manager_ui::ManagerWindowState::focus_rules_view,
            )),
            ..ManagerExtras::default()
        },
    );
}

/// A declarative deny whose `argv` glob does not compile.
///
/// The sibling of `rules_tab_wasm_refused`, and needed for the same reason
/// one step further in: this rule was authored entirely inside secreq, has
/// no module, no hash and nothing on disk to tamper with, and still cannot
/// fire. The pattern line reads back exactly as the operator typed it —
/// that is the trap — so the badge is the only thing on the row that says
/// so.
///
/// The pair is deliberate and is the substance of the fixture. The approve
/// above carries the *same* typo, and the two rows are badged identically
/// while meaning opposite things: a refused approve simply stops approving,
/// a refused deny sends every ask it covered to this window instead of
/// letting the approve carry it. The hover text is where that difference
/// lives, which is why both rows are here rather than one.
#[test]
fn rules_tab_pattern_refused() {
    let rules = vec![
        sample_rule(
            "6c3e0a2b43f5",
            "Cursor reads via gh",
            RuleDecision::Approve,
            // `[` opens a character class that is never closed.
            Some("gh api --get /repos/*/pulls*["),
        ),
        sample_rule(
            "7d4f1b3c54a6",
            "Block repo secret writes",
            RuleDecision::Deny,
            Some("gh api /repos/*/actions/secrets*["),
        ),
    ];
    // Both rules are refused, so neither has ever fired; the usage
    // footnote reading "No auto-fires yet" on both is itself part of what
    // the picture shows.
    let refusals = RuleRefusals {
        wasm: Vec::new(),
        patterns: secreq::rules::pattern_refusals(&rules),
        scopes: Vec::new(),
    };
    assert_eq!(refusals.patterns.len(), 2, "both globs must be refused");

    render_manager_fixture(
        Shot::new("45-rules-pattern-refused").caption(
            "A match pattern that is not a valid glob is refused rather than \
             quietly reread as plain text. secreq badges the rule here and the \
             rule never matches. That matters most on a <b>deny</b>: rather than \
             let another rule's approve carry an ask your deny was written to \
             stop, secreq asks you.",
        ),
        Vec::new(),
        ManagerExtras {
            rules,
            refusals,
            window_state: Some(Box::new(
                secreq::daemon::manager_ui::ManagerWindowState::focus_rules_view,
            )),
            ..ManagerExtras::default()
        },
    );
}

/// The form refusing the glob fixture 45 shows already saved — which is the
/// point of having both. Fixture 45 is what a refused pattern looks like once
/// it is in the ruleset: a badge on a row, correct and honest and reached only
/// by someone who went back to look. This is the same typo caught where it is
/// still free, with the parser's own complaint under the field that has it and
/// Save greyed out until it is gone.
///
/// The draft is a **deny**, because that is the direction where a refused
/// pattern is dangerous: the line under the field says the asks this rule
/// would have blocked now come to the consent window rather than being
/// released by some other rule's approve. An approve is refused by the same
/// check and says the milder thing.
#[test]
fn rules_form_bad_glob() {
    let rule = sample_rule(
        "7d4f1b3c54a6",
        "Block repo secret writes",
        RuleDecision::Deny,
        // The same unterminated character class fixture 45 carries.
        Some("gh api /repos/*/actions/secrets*["),
    );
    render_manager_fixture(
        Shot::new("47-rules-form-bad-glob").caption(
            "A match pattern that is not a valid glob cannot be saved. secreq \
             refuses the same patterns here that it refuses when it reads the \
             rules back, so a rule that saves is a rule that runs — and on a \
             <b>deny</b>, where a pattern it cannot evaluate would send every ask \
             to this window, the form says so before you save it.",
        ),
        Vec::new(),
        ManagerExtras {
            window_state: Some(Box::new(move |ws| ws.open_edit_rule_form(&rule))),
            ..ManagerExtras::default()
        },
    );
}

#[test]
fn rules_tab_wrap_scope() {
    let mut rule = sample_rule(
        "8e5a2c4d65b7",
        "GitHub API guard",
        RuleDecision::Deny,
        Some("gh api *"),
    );
    rule.wraps = Some(["gh".to_owned()].into_iter().collect());
    render_manager_fixture(
        Shot::new("51-rules-wrap-scope").caption(
            "A rule's consultation scope is separate from its match. The scope chip \
             says which asks may consult it at all; the summary keeps the declarative \
             match wrap visible beside that gate.",
        ),
        Vec::new(),
        ManagerExtras {
            rules: vec![rule],
            window_state: Some(Box::new(
                secreq::daemon::manager_ui::ManagerWindowState::focus_rules_view,
            )),
            ..ManagerExtras::default()
        },
    );
}

#[test]
fn rules_form_wrap_scope_conflict() {
    let mut rule = sample_rule(
        "9f6b3d5e76c8",
        "GitHub API guard",
        RuleDecision::Deny,
        Some("aws secretsmanager *"),
    );
    rule.wraps = Some(["gh".to_owned()].into_iter().collect());
    let RuleBody::Declarative { r#match, .. } = &mut rule.body else {
        unreachable!("sample rule is declarative");
    };
    r#match.wrap = "aws".to_owned();

    render_manager_fixture(
        Shot::new("52-rules-form-wrap-scope-conflict").caption(
            "The declarative editor keeps consultation scope read-only and refuses a \
             match wrap outside it. Without this warning, saving <code>match wrap: \
             aws</code> behind <code>scope: gh</code> would create a rule no ask can \
             ever reach.",
        ),
        Vec::new(),
        ManagerExtras {
            window_state: Some(Box::new(move |ws| ws.open_edit_rule_form(&rule))),
            ..ManagerExtras::default()
        },
    );
}

#[test]
fn rules_tab_by_recency() {
    // The Rules list with the sort toggle flipped to "Recent". The two
    // rules are crafted so count and recency disagree, making the
    // re-order visible.
    let rules = vec![
        sample_rule(
            "02def",
            "Cursor reads via gh",
            RuleDecision::Approve,
            Some("gh api --get /repos/*/pulls*"),
        ),
        sample_rule(
            "04jkl",
            "Deploy token denies",
            RuleDecision::Deny,
            Some("gh secret set *"),
        ),
    ];
    let mut audit = Vec::new();
    for i in 0..12 {
        audit.push(audit_auto_fire(
            5 * 86400 + 60 * (i + 1),
            "02def",
            "approve+auto",
        ));
    }
    for i in 0..2 {
        audit.push(audit_auto_fire(60 * (i + 1), "04jkl", "deny+auto"));
    }
    render_manager_fixture(
        "19-rules-tab-by-recency",
        audit,
        ManagerExtras {
            rules,
            window_state: Some(Box::new(|ws| {
                ws.focus_rules_view();
                ws.set_rule_sort(RuleSort::MostRecent);
            })),
            ..ManagerExtras::default()
        },
    );
}

#[test]
fn rules_form_new() {
    // The blank-form view — same state as the user just clicked
    // "+ New rule". Exercises the decide toggle, text inputs,
    // deny-message hidden (only shown when decide == Deny).
    render_manager_fixture(
        Shot::new("10-rules-form-new").caption(
            "A blank rule. Match on the wrap, the argv and the ancestor process, then \
             choose whether a match approves or denies.",
        ),
        vec![],
        ManagerExtras {
            window_state: Some(Box::new(
                secreq::daemon::manager_ui::ManagerWindowState::open_new_rule_form,
            )),
            ..ManagerExtras::default()
        },
    );
}

#[test]
fn rules_form_edit_deny() {
    // The edit form pre-filled from an existing deny rule. The
    // deny_message field is visible (decide == Deny) and the trained-
    // secrets chip shows underneath.
    let rule = sample_rule(
        "03ghi",
        "Block gh destructive ops",
        RuleDecision::Deny,
        Some("gh repo delete *"),
    );
    render_manager_fixture(
        Shot::new("11-rules-form-edit-deny").caption(
            "A deny rule carries a message. That text is what you see in the banner \
             when the rule fires, so write it as a reminder to your future self.",
        ),
        vec![],
        ManagerExtras {
            window_state: Some(Box::new(move |ws| ws.open_edit_rule_form(&rule))),
            ..ManagerExtras::default()
        },
    );
}

/// A deterministic editor set for the scaffold fixtures, so the PNGs
/// don't depend on what's installed on the regenerating machine.
fn sample_editors() -> Vec<Editor> {
    vec![
        Editor::new("code", "VS Code", "code"),
        Editor::new("cursor", "Cursor", "cursor"),
        Editor::new("zed", "Zed", "zed"),
        Editor::new("nvim", "Neovim", "nvim"),
    ]
}

#[test]
fn rules_scaffold_open_in_editor() {
    // The programmatic-rule scaffold card in its post-scaffold state: a
    // rule has been scaffolded, so the GitHub-style "Open in editor"
    // split-button is showing, defaulting to the persisted preference
    // (Cursor). Seeded editors keep the button deterministic.
    render_manager_fixture(
        Shot::new("37-rules-scaffold-open-in-editor").caption(
            "When a rule needs more than pattern matching, secreq scaffolds a \
             programmable one and hands it to your editor.",
        ),
        vec![],
        ManagerExtras {
            window_state: Some(Box::new(|ws| {
                ws.focus_rules_view();
                ws.seed_scaffold_editors(sample_editors(), Some("cursor".to_owned()));
                ws.mark_scaffolded(PathBuf::from(
                    "/Users/example/.secreq/rule-drafts/rule-1a2b3c4d/rule.ts",
                ));
            })),
            ..ManagerExtras::default()
        },
    );
}

#[test]
fn rules_scaffold_editor_picker() {
    // The split-button's dropdown expanded — the editor picker. The
    // currently-selected editor (Cursor) carries a check; picking a
    // different one makes it the new default.
    render_manager_fixture(
        Shot::new("38-rules-scaffold-editor-picker").caption(
            "Pick from the editors secreq detected. Your choice becomes the default \
             for next time.",
        ),
        vec![],
        ManagerExtras {
            window_state: Some(Box::new(|ws| {
                ws.focus_rules_view();
                ws.seed_scaffold_editors(sample_editors(), Some("cursor".to_owned()));
                ws.mark_scaffolded(PathBuf::from(
                    "/Users/example/.secreq/rule-drafts/rule-1a2b3c4d/rule.ts",
                ));
                ws.open_scaffold_dropdown();
            })),
            ..ManagerExtras::default()
        },
    );
}

#[test]
fn rules_tab_suggestions() {
    // The recommendation engine clusters recent decisions by
    // (wrap, ancestor, side) and proposes one rule per cluster.
    // Here we plant three clusters in the audit log:
    //
    // - 4× `gh api … /commits/<sha>/statuses` approvals from Superset
    //   that the merger collapses to the segment-aligned glob.
    // - 3× `gh auth token` denials from claude — identical argvs,
    //   no glob in the suggestion.
    // - 2× `aws s3 ls` approvals — below the MIN_CLUSTER_SIZE
    //   threshold, deliberately excluded so the fixture also
    //   documents the "≥ 3 to surface" rule.
    let mut audit = Vec::new();
    for (i, sha) in [
        "ac00920844c348da5aff2229bb8d93292cf5ec3a",
        "bcd953e87ffa7b28790968005edb1665c212f373",
        "ed89bf6b2adfa4e3fbccda2c68e780e22db16545",
        "cad3c0a7aa97fdb7e345f4008f2e75bf8b4225a2",
    ]
    .iter()
    .enumerate()
    {
        let path = format!("repos/AgentEnder/cli-forge/commits/{sha}/statuses");
        audit.push(audit_line_traced(
            (60 * 5 * (i as u64 + 1)).max(60),
            "gh",
            &["api", "--method", "GET", &path, "-f", "per_page=100"],
            &[(
                15334,
                "Superset",
                "/Applications/Superset.app/Contents/MacOS/Superset",
            )],
            &["GITHUB_TOKEN"],
            "approve",
        ));
    }
    // Aged a few days back so the card's "last seen …" line reads
    // "3 days ago" next to the approve cluster's "today".
    for i in 0..3 {
        audit.push(audit_line_traced(
            3 * 86400 + 60 * 10 * (i as u64 + 1),
            "gh",
            &["auth", "token", "--hostname", "github.com"],
            &[(72964, "claude", "claude --resume bbb3cb6d")],
            &["GITHUB_TOKEN"],
            "deny",
        ));
    }
    // Below threshold — must NOT appear as a suggestion.
    for i in 0..2 {
        audit.push(audit_line_traced(
            60 * 20 * (i as u64 + 1),
            "aws",
            &["s3", "ls"],
            &[(52310, "zsh", "-zsh")],
            &["AWS_ACCESS_KEY_ID"],
            "approve",
        ));
    }
    render_manager_fixture(
        Shot::new("13-rules-tab-suggestions").caption(
            "secreq watches what you keep approving and offers the rule you were about \
             to write, along with the cluster of decisions it drew from.",
        ),
        audit,
        ManagerExtras {
            window_state: Some(Box::new(
                secreq::daemon::manager_ui::ManagerWindowState::focus_rules_view,
            )),
            ..ManagerExtras::default()
        },
    );
}

#[test]
fn rules_tab_suggestions_by_recency() {
    // Same Rules view, but with the suggestion sort toggle flipped to
    // "Recent". The two clusters are crafted so count and recency
    // *disagree*, making the re-order visible.
    let mut audit = Vec::new();
    for (i, sha) in [
        "ac00920844c348da5aff2229bb8d93292cf5ec3a",
        "bcd953e87ffa7b28790968005edb1665c212f373",
        "ed89bf6b2adfa4e3fbccda2c68e780e22db16545",
        "cad3c0a7aa97fdb7e345f4008f2e75bf8b4225a2",
        "f0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9",
    ]
    .iter()
    .enumerate()
    {
        let path = format!("repos/AgentEnder/cli-forge/commits/{sha}/statuses");
        audit.push(audit_line_traced(
            5 * 86400 + 60 * 5 * (i as u64 + 1),
            "gh",
            &["api", "--method", "GET", &path, "-f", "per_page=100"],
            &[(
                15334,
                "Superset",
                "/Applications/Superset.app/Contents/MacOS/Superset",
            )],
            &["GITHUB_TOKEN"],
            "approve",
        ));
    }
    for i in 0..3 {
        audit.push(audit_line_traced(
            60 * (i as u64 + 1),
            "aws",
            &["s3", "ls"],
            &[(52310, "zsh", "-zsh")],
            &["AWS_ACCESS_KEY_ID"],
            "approve",
        ));
    }
    render_manager_fixture(
        "18-rules-tab-suggestions-by-recency",
        audit,
        ManagerExtras {
            window_state: Some(Box::new(|ws| {
                ws.focus_rules_view();
                ws.set_suggestion_sort(SuggestionSort::MostRecent);
            })),
            ..ManagerExtras::default()
        },
    );
}

#[test]
fn rules_tab_rules_and_suggestions() {
    // Both sections at once: the configured "Your rules" list on top
    // (with its usage footnotes + sort toggle) and the "Suggested
    // rules" section beneath it. Documents the ordering — saved rules
    // come first, proposals follow — and that both sections carry a
    // header so neither reads as an unlabelled slab.
    let rules = vec![sample_rule(
        "02def",
        "Cursor reads via gh",
        RuleDecision::Approve,
        Some("gh api --get /repos/*/pulls*"),
    )];
    let mut audit = Vec::new();
    // Auto-fires for the configured rule → its usage footnote. These
    // are `+auto` rows, which the suggestion engine ignores, so they
    // don't also surface as a suggestion.
    for i in 0..9 {
        audit.push(audit_auto_fire(60 * (i + 1), "02def", "approve+auto"));
    }
    // Two uncovered clusters → two suggestion cards beneath the rules.
    for i in 0..3 {
        audit.push(audit_line_traced(
            60 * 10 * (i as u64 + 1),
            "gh",
            &["auth", "token", "--hostname", "github.com"],
            &[(72964, "claude", "claude --resume bbb3cb6d")],
            &["GITHUB_TOKEN"],
            "deny",
        ));
    }
    for i in 0..3 {
        audit.push(audit_line_traced(
            60 * 20 * (i as u64 + 1),
            "aws",
            &["s3", "ls"],
            &[(52310, "zsh", "-zsh")],
            &["AWS_ACCESS_KEY_ID"],
            "approve",
        ));
    }
    render_manager_fixture(
        Shot::new("20-rules-tab-rules-and-suggestions").caption(
            "Saved rules first, then suggestions — what you decided, above what you \
             keep deciding.",
        ),
        audit,
        ManagerExtras {
            rules,
            window_state: Some(Box::new(
                secreq::daemon::manager_ui::ManagerWindowState::focus_rules_view,
            )),
            ..ManagerExtras::default()
        },
    );
}

// ── Pending-badge fixtures ────────────────────────────────────────────────

/// The always-on-top pending badge renders in its own tiny borderless
/// window (`secreq pending-badge`), not the prompt panel — so it gets a
/// dedicated, much simpler harness path: no daemon state, no audit log.
/// Just `render_badge` at the production badge size.
fn render_badge_fixture(shot: impl Into<Shot>, count: usize) {
    let shot = shot.into();
    // Matches `daemon/badge.rs::BADGE_SIZE`.
    let size = Vec2::new(184.0, 44.0);

    run_cells(
        &shot,
        ShotKind::Badge,
        size,
        || (),
        |ui, (), flavor, dark| {
            let ctx = ui.ctx().clone();
            // Pinned like every other fixture: the badge used to inherit the
            // harness's fallback theme, which left its PNGs dependent on the
            // host they were generated on.
            apply_theme_pin(&ctx, flavor, dark);
            secreq::daemon::ui::install_style(&ctx);
            full_window_ui(ui, |ui| secreq::daemon::ui::render_badge(ui, count));
        },
    );
}

#[test]
fn badge_one_pending() {
    // Singular case — exercises the "1 pending" (not "1 pendings")
    // branch in `render_badge`.
    render_badge_fixture(
        Shot::new("25-badge-one-pending").caption(
            "One request waiting, shown as a badge when the prompt is not in front of you.",
        ),
        1,
    );
}

#[test]
fn badge_three_pending() {
    // The common multi-request case: "3 pending" floating over other
    // apps, indicator dot + count, the whole pill a click target.
    render_badge_fixture(
        Shot::new("26-badge-three-pending")
            .caption("Three waiting. The count is the whole message."),
        3,
    );
}

/// Stress test: lay the prompt out at progressively smaller viewport
/// sizes to catch panics from hand-painted rects and scope_builder
/// layouts when the user drags the window down. A user-reported
/// "crashes on resize" symptom reproduces here as the layout pass
/// panicking inside the egui pipeline — which is CPU work, so this runs
/// on every `cargo test` and needs no GPU to fail.
#[test]
fn resize_stress() {
    let sizes = [
        PROMPT_SIZE,               // production baseline
        Vec2::new(360.0, 320.0),   // moderately small
        Vec2::new(220.0, 240.0),   // small
        Vec2::new(120.0, 160.0),   // very small
        Vec2::new(60.0, 100.0),    // tiny
        Vec2::new(30.0, 80.0),     // pathological
        Vec2::new(800.0, 600.0),   // bigger
        Vec2::new(1200.0, 800.0),  // ~laptop
        Vec2::new(1600.0, 1000.0), // ~external display
        Vec2::new(2400.0, 1400.0), // ~4K
        Vec2::new(3840.0, 2160.0), // 4K
    ];
    for (i, size) in sizes.iter().enumerate() {
        let name = format!("99-resize-{:02}-{}x{}", i, size.x as u32, size.y as u32);
        render_prompt_fixture_full(
            Shot::new(name).exercise_only(),
            *size,
            vec![],
            None,
            None,
            |state| {
                vec![submit(
                    state,
                    "gh",
                    vec!["gh", "auth", "login"],
                    vec![caller(7926, "zsh", 1_700_000_000)],
                    vec![secret(
                        "GITHUB_TOKEN",
                        "op",
                        "op://Personal/GitHub/credential",
                    )],
                )]
            },
        );
    }
}

// ── New-surface fixtures ─────────────────────────────────────────────────

/// The `secreq run` 40-plus-vars case: secrets collapse into
/// locator-prefix groups inside a scroll-capped grid, the count is the
/// headline, and the well stays legible.
#[test]
fn prompt_many_secrets() {
    const WORK: &[&str] = &[
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_REGION",
        "DATABASE_URL",
        "PGPASSWORD",
        "PGUSER",
        "REDIS_URL",
        "KAFKA_BROKER_URL",
        "KAFKA_SASL_PASSWORD",
        "SENTRY_DSN",
        "SENTRY_AUTH_TOKEN",
        "DATADOG_API_KEY",
        "STRIPE_SECRET_KEY",
        "STRIPE_WEBHOOK_SECRET",
        "TWILIO_AUTH_TOKEN",
        "SENDGRID_API_KEY",
        "S3_UPLOAD_BUCKET_KEY",
        "CDN_SIGNING_KEY",
        "JWT_SIGNING_SECRET",
        "SESSION_SECRET",
        "ENCRYPTION_KEY",
        "ANALYTICS_WRITE_KEY",
        "FEATURE_FLAG_SDK_KEY",
        "MAPS_API_KEY",
        "ELASTIC_CLOUD_ID",
        "ELASTIC_API_KEY",
        "SMTP_PASSWORD",
        "OAUTH_CLIENT_SECRET",
        "WEBHOOK_HMAC_KEY",
        "VAULT_ROLE_ID",
        "VAULT_SECRET_ID",
    ];
    const PERSONAL: &[&str] = &[
        "GITHUB_TOKEN",
        "NPM_TOKEN",
        "CARGO_REGISTRY_TOKEN",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "HOMEBREW_GITHUB_TOKEN",
        "DOCKER_HUB_TOKEN",
    ];
    const ENV: &[&str] = &["NODE_ENV", "LOG_LEVEL", "PORT", "CI"];
    render_prompt_fixture(
        Shot::new("28-prompt-many-secrets").caption(
            "A <code>secreq run</code> carrying 42 variables leads with the count and \
             groups the secrets by locator prefix. The body scrolls; the decision \
             buttons never leave the window.",
        ),
        vec![],
        |state| {
            let mut secrets = Vec::new();
            for name in WORK {
                secrets.push(secret(name, "op", &format!("op://Work/Acme/{name}")));
            }
            for name in PERSONAL {
                secrets.push(secret(name, "op", &format!("op://Personal/{name}")));
            }
            for name in ENV {
                secrets.push(secret(name, "env", name));
            }
            vec![submit_run(
                state,
                vec!["secreq", "run", "--", "npm", "run", "dev"],
                vec![caller(7926, "zsh", 1_700_000_000)],
                secrets,
            )]
        },
    );
}

// The per-flavor fixtures that used to live here — `30-prompt-windows`,
// `31-prompt-linux`, `32-manager-audit-windows`, `33-manager-rules-gnome`
// — are gone. They existed to show that the chrome follows the host OS,
// which every fixture now demonstrates for itself: the matrix renders
// each of them under all three flavors. A fixture whose only distinction
// was its `OsFlavor` is now a duplicate of one cell of another fixture's
// grid.
