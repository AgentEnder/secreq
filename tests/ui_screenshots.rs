//! Screenshot harness for the secreq window UIs.
//!
//! This test target renders the egui surfaces in a set of
//! representative states and writes PNGs to `dev-docs/ui-screenshots/`
//! so an agent (or a human) can iterate on visuals without a real
//! daemon running on a real desktop.
//!
//! All tests are `#[ignore]` so a normal `cargo test` run isn't slowed
//! down by wgpu rendering. Regenerate the screenshots with:
//!
//! ```sh
//! cargo test --test ui_screenshots -- --ignored --nocapture --test-threads=1
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
//!   `audit.log` in a tempdir (via `$XDG_STATE_HOME`, the normal
//!   `AuditCache` path), at the manager's production viewport size.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{mpsc, Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use egui::Vec2;
use egui_kittest::Harness;

use secreq::audit::AuditEntry;
use secreq::consent::Decision;
use secreq::daemon::manager_ui::{render_manager_panel, ManagerWindowState};
use secreq::daemon::prompt_ui::{render_prompt_panel, PromptWindowState, PROMPT_DEFAULT_SIZE};
use secreq::daemon::proto::{AgentAskInfo, Ask, Caller, DedupeKey, SecretAsk, SshAskInfo};
use secreq::daemon::state::{SharedState, State};
use secreq::daemon::theme::OsFlavor;
use secreq::daemon::ui::{AutoDenyToastView, RuleAction, RuleSort};
use secreq::recommendations::SuggestionSort;
use secreq::rules::{Pattern, Rule, RuleDecision, RuleMatch};

/// Where the regenerated PNGs land. Relative to the workspace root,
/// which is `cargo test`'s CWD.
const OUT_DIR: &str = "dev-docs/ui-screenshots";

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
const PIXELS_PER_POINT: f32 = 2.0;

// ── Fixture-state plumbing ────────────────────────────────────────────────

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn caller(pid: u32, name: &str, start_time: u64) -> Caller {
    Caller {
        pid,
        name: name.to_owned(),
        command: name.to_owned(),
        start_time,
    }
}

fn secret(name: &str, provider: &str, locator: &str) -> SecretAsk {
    SecretAsk {
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
    callers: Vec<Caller>,
    secrets: Vec<SecretAsk>,
) -> mpsc::Receiver<secreq::daemon::state::WaiterReply> {
    let dedupe_key = DedupeKey {
        wrap: wrap.to_owned(),
        ppid: callers.first().map(|c| c.pid).unwrap_or(0),
        parent_start_time: callers.first().map(|c| c.start_time).unwrap_or(0),
    };
    let ask = Ask {
        command: command.into_iter().map(String::from).collect(),
        cwd: "/Users/example/project".to_owned(),
        callers,
        secrets,
        providers: HashMap::new(),
        dedupe_key,
        ssh: None,
        agent: None,
        allow_remember: true,
        nested_run: false,
    };
    let (tx, rx) = mpsc::channel();
    state.lock().unwrap().submit_ask(ask, tx);
    rx
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
        ppid: callers.first().map(|c| c.pid).unwrap_or(0),
        parent_start_time: callers.first().map(|c| c.start_time).unwrap_or(0),
    };
    let ask = Ask {
        command: command.into_iter().map(String::from).collect(),
        cwd: "/Users/example/project".to_owned(),
        callers,
        secrets,
        providers: HashMap::new(),
        dedupe_key,
        ssh: None,
        agent: None,
        allow_remember: false,
        nested_run: false,
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
fn submit_ssh(
    state: &SharedState,
    key_id: &str,
    fingerprint: &str,
    reason: Option<&str>,
    callers: Vec<Caller>,
) -> mpsc::Receiver<secreq::daemon::state::WaiterReply> {
    let dedupe_key = DedupeKey {
        wrap: format!("ssh:{key_id}"),
        ppid: callers.first().map(|c| c.pid).unwrap_or(0),
        parent_start_time: callers.first().map(|c| c.start_time).unwrap_or(0),
    };
    let ask = Ask {
        command: vec![format!("ssh-sign {key_id}")],
        // SSH signs have no requesting cwd — the peer is a socket
        // connection, not a wrapped exec — so leave it empty.
        cwd: String::new(),
        callers,
        secrets: vec![],
        providers: HashMap::new(),
        dedupe_key,
        ssh: Some(SshAskInfo {
            key_id: key_id.to_owned(),
            fingerprint: fingerprint.to_owned(),
            reason: reason.map(str::to_owned),
        }),
        agent: None,
        allow_remember: true,
        nested_run: false,
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
fn submit_agent(
    state: &SharedState,
    scope: &str,
    reference: &str,
) -> mpsc::Receiver<secreq::daemon::state::WaiterReply> {
    let dedupe_key = DedupeKey {
        wrap: format!("agent:{scope}:{reference}"),
        ppid: 4242,
        parent_start_time: 0,
    };
    let ask = Ask {
        command: vec![format!("agent-resolve {reference}")],
        // A guest has no host cwd.
        cwd: String::new(),
        callers: vec![],
        secrets: vec![],
        providers: HashMap::new(),
        dedupe_key,
        ssh: None,
        agent: Some(AgentAskInfo {
            scope: scope.to_owned(),
            reference: reference.to_owned(),
        }),
        allow_remember: false,
        nested_run: false,
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
        ppid: callers.first().map(|c| c.pid).unwrap_or(0),
        parent_start_time: callers.first().map(|c| c.start_time).unwrap_or(0),
    };
    let ask = Ask {
        command: command.into_iter().map(String::from).collect(),
        cwd: "/Users/example/project".to_owned(),
        callers,
        secrets,
        providers: HashMap::new(),
        dedupe_key,
        ssh: None,
        agent: None,
        allow_remember: true,
        nested_run: false,
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
        cwd: "/Users/example/project".to_owned(),
        wrap: wrap.to_owned(),
        args: vec![],
        callers: vec![secreq::audit::AuditCaller {
            pid: 1000,
            name: caller_name.to_owned(),
            command: caller_name.to_owned(),
        }],
        secrets: secrets.iter().map(|s| (*s).to_owned()).collect(),
        decision: decision.to_owned(),
        rule_id: None,
        fingerprint: None,
    }
}

/// A scoped-agent audit row, built through the **production constructor**
/// rather than by hand — so the fixture can't quietly misrepresent the shape
/// (no caller chain, no cwd, ref in `secrets`, `agent:<scope>` as the wrap).
/// That's the whole thing this fixture exists to show.
fn agent_audit_line(secs_ago: u64, scope: &str, reference: &str, decision: Decision) -> AuditEntry {
    let mut entry = AuditEntry::agent_resolve(scope, reference, decision);
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
        cwd: "/Users/example/project".to_owned(),
        wrap: wrap.to_owned(),
        args: args.iter().map(|s| (*s).to_owned()).collect(),
        callers: chain
            .iter()
            .map(|(pid, name, cmd)| secreq::audit::AuditCaller {
                pid: *pid,
                name: (*name).to_owned(),
                command: (*cmd).to_owned(),
            })
            .collect(),
        secrets: secrets.iter().map(|s| (*s).to_owned()).collect(),
        decision: decision.to_owned(),
        rule_id: None,
        fingerprint: None,
    }
}

/// An audit row recording a rule auto-firing. The Rules view aggregates
/// these by `rule_id` to show each rule's auto-fire count and last-fired
/// time, so `rule_id` is the field that matters here; `decision` carries
/// the matching `+auto` suffix the daemon writes in production.
fn audit_auto_fire(secs_ago: u64, rule_id: &str, decision: &str) -> AuditEntry {
    AuditEntry {
        ts_unix: now_unix().saturating_sub(secs_ago),
        cwd: "/Users/example/project".to_owned(),
        wrap: "gh".to_owned(),
        args: vec!["api".to_owned()],
        callers: vec![secreq::audit::AuditCaller {
            pid: 4242,
            name: "Cursor.app".to_owned(),
            command: "Cursor.app".to_owned(),
        }],
        secrets: vec!["GITHUB_TOKEN".to_owned()],
        decision: decision.to_owned(),
        rule_id: Some(rule_id.to_owned()),
        fingerprint: None,
    }
}

/// Point `$XDG_STATE_HOME` at a fresh tempdir and write `audit_entries`
/// as its `audit.log`, so `AuditCache::refresh_if_stale` reads our
/// synthetic history through the normal path. Returns the tempdir guard
/// — keep it alive across the render.
///
/// SAFETY of the env mutation: the fixtures run sequentially
/// (`--test-threads=1` per the regen instructions); each fixture sets
/// the var, renders, and the next overwrites it.
fn install_audit_log(audit_entries: &[AuditEntry]) -> tempfile::TempDir {
    let tmp = tempfile::tempdir().expect("tempdir");
    let secreq_state = tmp.path().join("secreq");
    std::fs::create_dir_all(&secreq_state).expect("mkdir secreq state");
    let audit_path = secreq_state.join("audit.log");
    let mut buf = String::new();
    for entry in audit_entries {
        buf.push_str(&serde_json::to_string(entry).expect("serialize entry"));
        buf.push('\n');
    }
    std::fs::write(&audit_path, buf).expect("write audit.log");
    std::env::set_var("SECREQ_HOME", tmp.path());
    tmp
}

fn save_png(name: &str, img: &image::RgbaImage) {
    let out_dir = Path::new(OUT_DIR);
    std::fs::create_dir_all(out_dir).expect("mkdir out");
    let out = out_dir.join(format!("{name}.png"));
    img.save(&out).expect("save png");
    eprintln!("wrote {} ({}x{})", out.display(), img.width(), img.height());
}

// ── Prompt harness ────────────────────────────────────────────────────────

/// Drive the real `render_prompt_panel` for one frame and write a PNG.
/// `setup` populates the daemon-side queue through the production
/// `submit_ask` / `begin_pending` paths; `toast` renders the transient
/// auto-deny banner.
fn render_prompt_fixture(
    name: &str,
    audit_entries: Vec<AuditEntry>,
    setup: impl FnOnce(&SharedState) -> Vec<mpsc::Receiver<secreq::daemon::state::WaiterReply>>,
) {
    render_prompt_fixture_full(name, PROMPT_SIZE, audit_entries, None, MACOS_DARK, setup);
}

/// `(flavor, dark)` pin for a fixture. Fixtures always pin both so the
/// PNGs are deterministic regardless of the host OS and the harness's
/// fallback theme.
type ThemePin = (OsFlavor, bool);
const MACOS_DARK: ThemePin = (OsFlavor::MacOs, true);

fn apply_theme_pin(ctx: &egui::Context, pin: ThemePin) {
    let (flavor, dark) = pin;
    OsFlavor::install_override(ctx, flavor);
    ctx.set_theme(if dark {
        egui::ThemePreference::Dark
    } else {
        egui::ThemePreference::Light
    });
}

fn render_prompt_fixture_full(
    name: &str,
    size: Vec2,
    audit_entries: Vec<AuditEntry>,
    toast: Option<AutoDenyToastView>,
    theme_pin: ThemePin,
    setup: impl FnOnce(&SharedState) -> Vec<mpsc::Receiver<secreq::daemon::state::WaiterReply>>,
) {
    let tmp = install_audit_log(&audit_entries);

    let state: SharedState = Arc::new(Mutex::new(State::new()));
    state.lock().unwrap().show_window();
    let _keep_alive = setup(&state);

    // Snapshot the state outside the closure (the renderer takes the
    // plain `QueueSnapshot`, the same shape the prompt child rebuilds
    // from the daemon's wire snapshot).
    let snapshot = state.lock().unwrap().snapshot();
    let toast_ref = toast.clone();
    let mut harness = Harness::builder()
        .with_size(size)
        .with_pixels_per_point(PIXELS_PER_POINT)
        .wgpu()
        .build_ui_state(
            move |ui, ws: &mut PromptWindowState| {
                let ctx = ui.ctx().clone();
                apply_theme_pin(&ctx, theme_pin);
                secreq::daemon::ui::install_style(&ctx);
                // The screenshot harness ignores action output — no
                // user is clicking, and we don't need to dispatch
                // anywhere.
                let mut actions: Vec<secreq::daemon::ui::PendingAction> = Vec::new();
                let _out =
                    render_prompt_panel(&ctx, ui, &snapshot, toast_ref.as_ref(), ws, &mut actions);
            },
            PromptWindowState::new(),
        );
    harness.run();
    let img = harness.render().expect("render wgpu");
    save_png(name, &img);
    drop(tmp);
}

// ── Manager harness ───────────────────────────────────────────────────────

/// Type alias for the per-fixture `ManagerWindowState` setup hook.
type ManagerStateSetup<'a> = Box<dyn FnOnce(&mut ManagerWindowState) + 'a>;

/// Extra fixture inputs for the manager window. Each field has a
/// sensible default so most fixtures only set what they need.
#[derive(Default)]
struct ManagerExtras<'a> {
    /// Rules to pass to `render_manager_panel` (the Rules view content).
    rules: Vec<Rule>,
    /// Wire viewer-mode flag: `secreq view` sets it, and a fresh
    /// manager state rising-edges onto the Audit view when it's set.
    viewer_mode: bool,
    /// Mutate the `ManagerWindowState` before the first frame — used
    /// to focus a specific view, open a rule form, or pre-fill the
    /// audit search. Defaults to no-op.
    window_state: Option<ManagerStateSetup<'a>>,
    /// `(flavor, dark)` pin; `None` means macOS dark, the canonical
    /// fixture appearance.
    theme_pin: Option<ThemePin>,
}

/// Drive the real `render_manager_panel` for one frame and write a PNG.
fn render_manager_fixture(name: &str, audit_entries: Vec<AuditEntry>, extras: ManagerExtras<'_>) {
    let tmp = install_audit_log(&audit_entries);

    let ManagerExtras {
        rules,
        viewer_mode,
        window_state,
        theme_pin,
    } = extras;
    let theme_pin = theme_pin.unwrap_or(MACOS_DARK);
    let mut initial_state = ManagerWindowState::new();
    if let Some(f) = window_state {
        f(&mut initial_state);
    }
    let mut harness = Harness::builder()
        .with_size(MANAGER_SIZE)
        .with_pixels_per_point(PIXELS_PER_POINT)
        .wgpu()
        .build_ui_state(
            move |ui, ws: &mut ManagerWindowState| {
                let ctx = ui.ctx().clone();
                apply_theme_pin(&ctx, theme_pin);
                secreq::daemon::ui::install_style(&ctx);
                let mut rule_actions: Vec<RuleAction> = Vec::new();
                render_manager_panel(&ctx, ui, &rules, viewer_mode, ws, &mut rule_actions);
            },
            initial_state,
        );
    harness.run();
    let img = harness.render().expect("render wgpu");
    save_png(name, &img);
    drop(tmp);
}

// ── Prompt fixtures ───────────────────────────────────────────────────────

#[test]
#[ignore = "screenshot harness — run with --ignored to regenerate"]
fn empty_state() {
    render_prompt_fixture("01-empty-all-clear", vec![], |_state| Vec::new());
}

#[test]
#[ignore = "screenshot harness"]
fn empty_state_viewer() {
    // The `secreq view` surface is the *manager* window now: it opens
    // on the Audit view (viewer-mode rising edge) with no history yet.
    // This fixture documents the viewer's empty state — the prompt no
    // longer has a viewer variant.
    render_manager_fixture(
        "01b-empty-all-clear-viewer",
        vec![],
        ManagerExtras {
            viewer_mode: true,
            ..ManagerExtras::default()
        },
    );
}

#[test]
#[ignore = "screenshot harness"]
fn single_pending() {
    render_prompt_fixture("02-single-pending", vec![], |state| {
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
    });
}

#[test]
#[ignore = "screenshot harness"]
fn run_consent_card() {
    // A `secreq run` consent: the ambient mirror of `x`. Instead of a
    // named wrap, the dedupe identity is the fixed `"run"` and the
    // prompt headlines the free-form command the user typed
    // (`./deploy.sh --prod`). The two secrets exercise the prompt's
    // mixed-provider secret list.
    render_prompt_fixture("run-consent", vec![], |state| {
        vec![submit_run(
            state,
            vec!["./deploy.sh", "--prod"],
            vec![caller(7926, "zsh", 1_700_000_000)],
            vec![
                secret("DATABASE_URL", "op", "Work/PG/url"),
                secret("STRIPE_KEY", "keychain", "stripe-key"),
            ],
        )]
    });
}

#[test]
#[ignore = "screenshot harness"]
fn run_session_card() {
    // A *coalesced* `secreq run` session: three sibling `run` asks land
    // under the same process (the same first caller → the same dedupe
    // key), so they merge into one prompt. The representative's secret
    // list is the *union* of what each sibling requested, and each
    // entry remembers the command that asked for it (hover provenance).
    // Because coalescing happens inside `submit_ask`, we simply submit
    // the three asks and let the real merge path build the ask.
    render_prompt_fixture("run-session-card", vec![], |state| {
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
    });
}

#[test]
#[ignore = "screenshot harness"]
fn gate_only_pending() {
    // A *gate-only* wrap: `op` has no secret to inject, so the request
    // exists purely to require consent before the command runs. The
    // prompt shows the command + caller chain; the SECRETS well row is
    // simply absent.
    render_prompt_fixture("21-gate-only-pending", vec![], |state| {
        vec![submit(
            state,
            "op",
            vec!["op", "read", "op://Personal/AWS/credential"],
            vec![caller(7926, "zsh", 1_700_000_000)],
            vec![],
        )]
    });
}

#[test]
#[ignore = "screenshot harness"]
fn pending_resolving() {
    // An auto-approved (or approvals-cached) ask whose secret isn't yet
    // cached: the provider is being invoked — a biometric prompt may be
    // up — so the prompt renders read-only as "Resolving…". This is the
    // surface that gives that biometric prompt its provenance.
    render_prompt_fixture("23-pending-resolving", vec![], |state| {
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
    });
}

#[test]
#[ignore = "screenshot harness"]
fn ssh_sign_pending() {
    // The SSH-agent sign prompt: `git push` over SSH triggered a
    // SIGN_REQUEST the daemon couldn't serve from a session grant, so
    // it raised the prompt. The header reads "git wants to sign with
    // github", the well carries the SHA256 fingerprint, and the session
    // grant row offers the 30-minute TTL choices.
    render_prompt_fixture("24-ssh-sign-pending", vec![], |state| {
        vec![submit_ssh(
            state,
            "github",
            "SHA256:Nh0Me49Zh9fDw/VYUfq43IJmI1T+XrjiYONPND8GzaM",
            Some("git pushes to github.com"),
            vec![
                caller(8120, "git", 1_700_002_000),
                caller(7926, "zsh", 1_700_000_000),
            ],
        )]
    });
}

#[test]
#[ignore = "screenshot harness"]
fn agent_scope_pending() {
    // A guest VM asked a scoped agent socket for a ref on its allowlist.
    // This is the prompt's third variant, and the one where what's *absent*
    // is the point: the header leads with the sandbox (the scope IS the
    // principal), the well shows SECRET + SCOPE, and there is deliberately
    // no ASKED BY tree and no IN row — a guest has no host process tree or
    // cwd, and rendering a chain-shaped widget here would imply we verified
    // something we cannot. See `src/scoped_agent/mod.rs`.
    render_prompt_fixture("34-agent-scope-pending", vec![], |state| {
        vec![submit_agent(
            state,
            "brain-nx-t5",
            "secret://op/Dev/gh/token",
        )]
    });
}

#[test]
#[ignore = "screenshot harness"]
fn nested_tree() {
    // Two child shells under one Superset.app root. The prompt shows
    // the oldest ask big (Focus Stack) with the full caller chain in
    // its ASKED BY well row; the second ask shows as "1 more waiting".
    render_prompt_fixture("03-nested-tree", vec![], |state| {
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
    });
}

#[test]
#[ignore = "screenshot harness"]
fn multi_root() {
    // Two unrelated callers. The prompt renders the older ask; the
    // unrelated second one is the "1 more waiting" line in the footer.
    render_prompt_fixture("04-multi-root", vec![], |state| {
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
    });
}

#[test]
#[ignore = "screenshot harness"]
fn folded_run() {
    // Four-deep gh→gh→gh→gh chain — the prompt's ASKED BY tree shows
    // the whole ancestry with the asking leaf in accent.
    render_prompt_fixture("05-folded-run", vec![], |state| {
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
    });
}

#[test]
#[ignore = "screenshot harness"]
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
    render_prompt_fixture("06-pending-denied-last", audit, |state| {
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
    });
}

#[test]
#[ignore = "screenshot harness"]
fn auto_deny_toast_on_pending() {
    // The transient toast that appears at the top of the prompt when an
    // auto-deny rule fires. Caller in the production child is the
    // reader thread; here we just hand the harness a synthetic toast.
    let toast = AutoDenyToastView {
        rule_name: "Block gh destructive ops".to_owned(),
        deny_message: Some("Destructive gh operations are policy-denied.".to_owned()),
    };
    render_prompt_fixture_full(
        "12-auto-deny-toast",
        PROMPT_SIZE,
        vec![],
        Some(toast),
        MACOS_DARK,
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
#[ignore = "screenshot harness"]
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
#[ignore = "screenshot harness"]
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
        ),
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
        "07-audit-tab",
        audit,
        ManagerExtras {
            viewer_mode: true,
            ..ManagerExtras::default()
        },
    );
}

#[test]
#[ignore = "screenshot harness"]
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
        "14-audit-tab-with-pending",
        audit,
        ManagerExtras {
            window_state: Some(Box::new(|ws| ws.focus_audit_view())),
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
#[ignore = "screenshot harness"]
fn audit_tab_search_filtering() {
    // The Audit view with an active query (typed into the header's
    // search box) that filters down to a subset. Exercises the "N of M"
    // count line and the filtered rendering.
    render_manager_fixture(
        "15-audit-tab-search-filtering",
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
#[ignore = "screenshot harness"]
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
        "27-audit-tab-abandoned",
        audit,
        ManagerExtras {
            window_state: Some(Box::new(|ws| ws.focus_audit_view())),
            ..ManagerExtras::default()
        },
    );
}

#[test]
#[ignore = "screenshot harness"]
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
        ),
        agent_audit_line(
            60 * 4,
            "brain-nx-t5",
            "secret://op/Prod/aws/root_key",
            Decision::DenyOutOfScope,
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
        "35-audit-tab-agent-out-of-scope",
        audit,
        ManagerExtras {
            window_state: Some(Box::new(|ws| ws.focus_audit_view())),
            ..ManagerExtras::default()
        },
    );
}

#[test]
#[ignore = "screenshot harness"]
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
#[ignore = "screenshot harness"]
fn audit_tab_search_multi_term() {
    // Multi-term search: each whitespace-separated term must hit some
    // field, so "gh auth" narrows to the single row whose wrap is `gh`
    // AND whose argv contains `auth` — even though no single field
    // holds the literal "gh auth". Regression guard for the reported
    // bug where "gh auth" wrongly filtered out `gh auth token`.
    render_manager_fixture(
        "17-audit-tab-search-multi-term",
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
        decide,
        r#match: RuleMatch {
            wrap: "gh".to_owned(),
            argv: argv.map(Pattern::parse),
            ancestor: Some(Pattern::parse("Cursor.app")),
            cwd: None,
        },
        trained_secrets: ["GITHUB_TOKEN".to_owned()].into_iter().collect(),
        deny_message: if decide == RuleDecision::Deny {
            Some("Destructive gh operations are policy-denied.".to_owned())
        } else {
            None
        },
        created_at_unix: 0,
    }
}

#[test]
#[ignore = "screenshot harness"]
fn rules_tab_empty() {
    // Land on the Rules view with no rules configured — the empty
    // state should be inviting, not blank.
    render_manager_fixture(
        "08-rules-tab-empty",
        vec![],
        ManagerExtras {
            window_state: Some(Box::new(|ws| ws.focus_rules_view())),
            ..ManagerExtras::default()
        },
    );
}

#[test]
#[ignore = "screenshot harness"]
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
        "09-rules-tab-list",
        audit,
        ManagerExtras {
            rules,
            window_state: Some(Box::new(|ws| ws.focus_rules_view())),
            ..ManagerExtras::default()
        },
    );
}

#[test]
#[ignore = "screenshot harness"]
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
#[ignore = "screenshot harness"]
fn rules_form_new() {
    // The blank-form view — same state as the user just clicked
    // "+ New rule". Exercises the decide toggle, text inputs,
    // deny-message hidden (only shown when decide == Deny).
    render_manager_fixture(
        "10-rules-form-new",
        vec![],
        ManagerExtras {
            window_state: Some(Box::new(|ws| ws.open_new_rule_form())),
            ..ManagerExtras::default()
        },
    );
}

#[test]
#[ignore = "screenshot harness"]
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
        "11-rules-form-edit-deny",
        vec![],
        ManagerExtras {
            window_state: Some(Box::new(move |ws| ws.open_edit_rule_form(&rule))),
            ..ManagerExtras::default()
        },
    );
}

#[test]
#[ignore = "screenshot harness"]
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
        "13-rules-tab-suggestions",
        audit,
        ManagerExtras {
            window_state: Some(Box::new(|ws| ws.focus_rules_view())),
            ..ManagerExtras::default()
        },
    );
}

#[test]
#[ignore = "screenshot harness"]
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
#[ignore = "screenshot harness"]
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
        "20-rules-tab-rules-and-suggestions",
        audit,
        ManagerExtras {
            rules,
            window_state: Some(Box::new(|ws| ws.focus_rules_view())),
            ..ManagerExtras::default()
        },
    );
}

// ── Pending-badge fixtures ────────────────────────────────────────────────

/// The always-on-top pending badge renders in its own tiny borderless
/// window (`secreq pending-badge`), not the prompt panel — so it gets a
/// dedicated, much simpler harness path: no daemon state, no audit log.
/// Just `render_badge` at the production badge size.
fn render_badge_fixture(name: &str, count: usize) {
    // Matches `daemon/badge.rs::BADGE_SIZE`.
    let size = Vec2::new(184.0, 44.0);
    let mut harness = Harness::builder()
        .with_size(size)
        .with_pixels_per_point(PIXELS_PER_POINT)
        .wgpu()
        .build_ui(move |ui| {
            let ctx = ui.ctx().clone();
            secreq::daemon::ui::install_style(&ctx);
            secreq::daemon::ui::render_badge(ui, count);
        });
    harness.run();
    let img = harness.render().expect("render wgpu");
    save_png(name, &img);
}

#[test]
#[ignore = "screenshot harness"]
fn badge_one_pending() {
    // Singular case — exercises the "1 pending" (not "1 pendings")
    // branch in `render_badge`.
    render_badge_fixture("25-badge-one-pending", 1);
}

#[test]
#[ignore = "screenshot harness"]
fn badge_three_pending() {
    // The common multi-request case: "3 pending" floating over other
    // apps, indicator dot + count, the whole pill a click target.
    render_badge_fixture("26-badge-three-pending", 3);
}

/// Stress test: render the prompt at progressively smaller viewport
/// sizes to catch panics from hand-painted rects and scope_builder
/// layouts when the user drags the window down. A user-reported
/// "crashes on resize" symptom reproduces here as `Harness::run()`
/// panicking inside the egui pipeline.
#[test]
#[ignore = "screenshot harness — resize stress, not visual"]
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
        render_prompt_fixture_full(&name, *size, vec![], None, MACOS_DARK, |state| {
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
        });
    }
}

// ── New-surface fixtures: many-secrets, appearance, OS flavors ────────────

/// The `secreq run` 40-plus-vars case: secrets collapse into
/// locator-prefix groups inside a scroll-capped grid, the count is the
/// headline, and the well stays legible.
#[test]
#[ignore = "screenshot harness"]
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
    render_prompt_fixture("28-prompt-many-secrets", vec![], |state| {
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
    });
}

/// The same single-pending prompt as fixture 02, following a light OS
/// appearance — appearance is not a setting; the window tracks the OS.
#[test]
#[ignore = "screenshot harness"]
fn prompt_macos_light() {
    render_prompt_fixture_full(
        "29-prompt-macos-light",
        PROMPT_SIZE,
        vec![],
        None,
        (OsFlavor::MacOs, false),
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

/// The Windows 11 ContentDialog idiom: equal-width footer strip,
/// affirmative first. Rendered via the fixture flavor override; on a
/// real Windows build this is the default treatment.
#[test]
#[ignore = "screenshot harness"]
fn prompt_windows_dark() {
    render_prompt_fixture_full(
        "30-prompt-windows-dark",
        PROMPT_SIZE,
        vec![],
        None,
        (OsFlavor::Windows, true),
        |state| {
            vec![submit(
                state,
                "gh",
                vec!["gh", "auth", "login"],
                vec![caller(7926, "pwsh.exe", 1_700_000_000)],
                vec![secret(
                    "GITHUB_TOKEN",
                    "op",
                    "op://Personal/GitHub/credential",
                )],
            )]
        },
    );
}

/// The GNOME AdwMessageDialog idiom: full-width response row with
/// hairline separators, Approve as the suggested action.
#[test]
#[ignore = "screenshot harness"]
fn prompt_linux_dark() {
    render_prompt_fixture_full(
        "31-prompt-linux-dark",
        PROMPT_SIZE,
        vec![],
        None,
        (OsFlavor::Gnome, true),
        |state| {
            vec![submit(
                state,
                "gh",
                vec!["gh", "auth", "login"],
                vec![caller(7926, "bash", 1_700_000_000)],
                vec![secret(
                    "GITHUB_TOKEN",
                    "op",
                    "op://Personal/GitHub/credential",
                )],
            )]
        },
    );
}

/// Manager audit view in the Windows treatment: SelectorBar tabs with
/// the accent underline over hairline-separated rows.
#[test]
#[ignore = "screenshot harness"]
fn manager_audit_windows_dark() {
    let audit = vec![
        audit_line_traced(
            60,
            "gh",
            &["api", "/repos/acme/web/issues"],
            &[(52310, "pwsh.exe", "pwsh.exe -NoLogo")],
            &["GITHUB_TOKEN"],
            "approve",
        ),
        audit_line_traced(
            60 * 9,
            "aws",
            &["s3", "ls", "s3://acme-logs"],
            &[(52312, "pwsh.exe", "pwsh.exe -NoLogo")],
            &["AWS_ACCESS_KEY_ID"],
            "deny",
        ),
    ];
    render_manager_fixture(
        "32-manager-audit-windows-dark",
        audit,
        ManagerExtras {
            viewer_mode: true,
            theme_pin: Some((OsFlavor::Windows, true)),
            ..ManagerExtras::default()
        },
    );
}

/// Manager rules view in the GNOME light treatment: boxed lists on the
/// Adwaita palette under the headerbar view switcher.
#[test]
#[ignore = "screenshot harness"]
fn manager_rules_gnome_light() {
    let rules = vec![
        sample_rule(
            "01aaa",
            "Cursor reads via gh",
            RuleDecision::Approve,
            Some("gh api --get /repos/*/pulls*"),
        ),
        sample_rule(
            "01bbb",
            "Block gh destructive ops",
            RuleDecision::Deny,
            Some("gh repo delete *"),
        ),
    ];
    render_manager_fixture(
        "33-manager-rules-gnome-light",
        vec![],
        ManagerExtras {
            rules,
            theme_pin: Some((OsFlavor::Gnome, false)),
            ..ManagerExtras::default()
        },
    );
}
