//! Screenshot harness for the consent-window UI.
//!
//! This test target renders the egui consent daemon UI in a set of
//! representative states and writes PNGs to `dev-docs/ui-screenshots/`
//! so an agent (or a human) can iterate on visuals without a real
//! daemon running on a real desktop.
//!
//! All tests are `#[ignore]` so a normal `cargo test` run isn't slowed
//! down by wgpu rendering. Regenerate the screenshots with:
//!
//! ```sh
//! cargo test --test ui_screenshots -- --ignored --nocapture
//! ```
//!
//! The harness drives the **real** `ConsentApp` via `egui_kittest`'s
//! eframe builder — no internal render helpers are exposed, so the
//! screenshots are the same code path the daemon runs at runtime.
//! State is shaped per fixture by:
//!
//! - building a `SharedState` and calling `submit_ask` to populate the
//!   pending queue (so `ProcessTree` construction sees real `Ask`s);
//! - pointing `$XDG_STATE_HOME` at a tempdir and writing synthetic
//!   `audit.log` JSONL there (so `AuditCache::refresh_if_stale` picks
//!   up the entries through the normal path);
//! - optionally flipping `enter_viewer_mode()` for the audit-tab
//!   fixtures (which is also what `secreq view` does in production).

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::{mpsc, Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use egui::Vec2;
use egui_kittest::Harness;

use secreq::audit::AuditEntry;
use secreq::daemon::proto::{Ask, Caller, DedupeKey, SecretAsk, SshAskInfo};
use secreq::daemon::state::{SharedState, State};
use secreq::daemon::ui::{
    render_consent_panel, AutoDenyToastView, ConsentWindowState, RuleAction, RuleSort,
};
use secreq::recommendations::SuggestionSort;
use secreq::rules::{Pattern, Rule, RuleDecision, RuleMatch};

/// Where the regenerated PNGs land. Relative to the workspace root,
/// which is `cargo test`'s CWD.
const OUT_DIR: &str = "dev-docs/ui-screenshots";

/// Logical window size — matches the daemon's production viewport
/// (`with_inner_size([760.0, 560.0])` in `daemon/child.rs`).
const SIZE: Vec2 = Vec2::new(760.0, 560.0);

/// Render at 2x for crisp text — the daemon picks this up from the OS
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
/// renders. `reason` populates the SecretAsk-less ask's display reason via
/// the `ssh` variant's renderer.
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
    };
    let (tx, rx) = mpsc::channel();
    state.lock().unwrap().submit_ask(ask, tx);
    rx
}

/// Inject a *resolving* card: an ask that has already been authorized
/// (auto-rule, approvals-cache, or a manual approve) and whose secret
/// is being fetched, with a provider biometric prompt potentially in
/// flight. Drives the read-only "Resolving…" card. No waiter channel —
/// in production this path resolves off the queue, not through it.
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

/// An audit row recording a rule auto-firing. The Rules tab aggregates
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

/// Type alias for the per-fixture `ConsentWindowState` setup hook.
/// Keeps the `FixtureExtras` struct readable (clippy::type_complexity).
type WindowStateSetup<'a> = Box<dyn FnOnce(&mut ConsentWindowState) + 'a>;

/// Extra fixture inputs that don't fit into the `setup` callback
/// (because they live on `ConsentWindowState`, not `SharedState`).
/// Each field has a sensible default so most fixtures can use
/// `FixtureExtras::default()` and only set what they need.
#[derive(Default)]
struct FixtureExtras<'a> {
    /// Rules to pass to `render_consent_panel`. Used by the Rules-tab
    /// fixtures.
    rules: Vec<Rule>,
    /// Toast to render at the top of the Pending tab.
    toast: Option<AutoDenyToastView>,
    /// Mutate the `ConsentWindowState` before the first frame — used
    /// to focus a specific tab or open a rule form. Defaults to no-op.
    window_state: Option<WindowStateSetup<'a>>,
}

/// Core harness driver. Sets `XDG_STATE_HOME` to a tempdir, writes the
/// audit log, builds a `SharedState` via `setup`, then drives the real
/// `ConsentApp` for one frame via `egui_kittest` and writes a PNG.
fn render_fixture(
    name: &str,
    audit_entries: Vec<AuditEntry>,
    setup: impl FnOnce(&SharedState) -> Vec<mpsc::Receiver<secreq::daemon::state::WaiterReply>>,
) {
    render_fixture_at_size(name, SIZE, audit_entries, FixtureExtras::default(), setup);
}

fn render_fixture_with_extras(
    name: &str,
    audit_entries: Vec<AuditEntry>,
    extras: FixtureExtras<'_>,
    setup: impl FnOnce(&SharedState) -> Vec<mpsc::Receiver<secreq::daemon::state::WaiterReply>>,
) {
    render_fixture_at_size(name, SIZE, audit_entries, extras, setup);
}

fn render_fixture_at_size(
    name: &str,
    size: Vec2,
    audit_entries: Vec<AuditEntry>,
    extras: FixtureExtras<'_>,
    setup: impl FnOnce(&SharedState) -> Vec<mpsc::Receiver<secreq::daemon::state::WaiterReply>>,
) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let secreq_state = tmp.path().join("secreq");
    std::fs::create_dir_all(&secreq_state).expect("mkdir secreq state");
    let audit_path = secreq_state.join("audit.log");
    let mut buf = String::new();
    for entry in &audit_entries {
        buf.push_str(&serde_json::to_string(entry).expect("serialize entry"));
        buf.push('\n');
    }
    std::fs::write(&audit_path, buf).expect("write audit.log");

    // Audit + state paths are looked up via `state_dir()` which honours
    // `$XDG_STATE_HOME`. Override it process-wide *before* the harness
    // runs its first frame so `AuditCache::refresh_if_stale` reads from
    // our tempdir, not the real user state dir.
    //
    // SAFETY: in this binary tests run sequentially within the runtime
    // tokio doesn't exist; each fixture sets the var, renders, and the
    // next fixture overwrites it. Concurrent harness use would need a
    // lock; we don't have any here.
    std::env::set_var("XDG_STATE_HOME", tmp.path());

    let state: SharedState = Arc::new(Mutex::new(State::new()));
    state.lock().unwrap().show_window();
    let _keep_alive = setup(&state);

    let _shutdown_flag = Arc::new(AtomicBool::new(false));
    // Snapshot the state outside the closure (the renderer no longer
    // takes `SharedState` — it takes the plain `QueueSnapshot` +
    // `viewer_mode` flag, same shape the consent-window child receives
    // from the daemon over the socket).
    let (snapshot, viewer_mode) = {
        let g = state.lock().unwrap();
        (g.snapshot(), g.viewer_mode())
    };
    // Drop the FnOnce into a regular Option so it can move into the
    // closure (the closure is `move` because the harness needs to own
    // it; we run only once so an Option<FnOnce>::take is fine).
    let FixtureExtras {
        rules,
        toast,
        window_state,
    } = extras;
    let mut window_state_setup = window_state;
    let mut initial_state = ConsentWindowState::new();
    if let Some(f) = window_state_setup.take() {
        f(&mut initial_state);
    }
    let toast_ref = toast.clone();
    let mut harness = Harness::builder()
        .with_size(size)
        .with_pixels_per_point(PIXELS_PER_POINT)
        .wgpu()
        .build_ui_state(
            move |ui, ws: &mut ConsentWindowState| {
                let ctx = ui.ctx().clone();
                secreq::daemon::ui::install_style(&ctx);
                // The screenshot harness ignores action output — no
                // user is clicking, and we don't need to dispatch
                // anywhere.
                let mut actions: Vec<secreq::daemon::ui::PendingAction> = Vec::new();
                let mut rule_actions: Vec<RuleAction> = Vec::new();
                render_consent_panel(
                    &ctx,
                    ui,
                    &snapshot,
                    viewer_mode,
                    &rules,
                    toast_ref.as_ref(),
                    ws,
                    &mut actions,
                    &mut rule_actions,
                );
            },
            initial_state,
        );
    harness.run();
    let img = harness.render().expect("render wgpu");

    let out_dir = Path::new(OUT_DIR);
    std::fs::create_dir_all(out_dir).expect("mkdir out");
    let out = out_dir.join(format!("{name}.png"));
    img.save(&out).expect("save png");
    eprintln!("wrote {} ({}x{})", out.display(), img.width(), img.height());

    drop(tmp);
}

// ── Fixtures ──────────────────────────────────────────────────────────────

#[test]
#[ignore = "screenshot harness — run with --ignored to regenerate"]
fn empty_state() {
    render_fixture("01-empty-all-clear", vec![], |_state| Vec::new());
}

#[test]
#[ignore = "screenshot harness"]
fn single_pending() {
    render_fixture("02-single-pending", vec![], |state| {
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
fn gate_only_pending() {
    // A *gate-only* wrap: `op` has no secret to inject, so the request
    // exists purely to require consent before the command runs. The card
    // shows the command + caller chain (the "why am I getting this?"
    // context) and the "Gate only — no secrets injected" marker in place
    // of the secret list.
    render_fixture("21-gate-only-pending", vec![], |state| {
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
    // up — so the card renders read-only as "Resolving…". This is the
    // surface that gives that prompt its provenance instead of letting
    // it pop over an empty window. Node-level Approve/Deny buttons are
    // suppressed because there's nothing left to decide.
    render_fixture("23-pending-resolving", vec![], |state| {
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
    // SIGN_REQUEST the daemon couldn't serve from cache, so it raised a
    // consent prompt. The card reads "SSH key request" with the identity
    // name + SHA256 fingerprint and the configured `$reason`, and shows the
    // caller chain (git under the shell). No secret list — an SSH sign
    // releases a signature, not an env var.
    render_fixture("24-ssh-sign-pending", vec![], |state| {
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
fn nested_tree() {
    // Two child shells under one Superset.app root — the load-bearing
    // case for the "Approve all from Superset" decision.
    render_fixture("03-nested-tree", vec![], |state| {
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
    // Two unrelated callers — separate roots, with a separator between.
    render_fixture("04-multi-root", vec![], |state| {
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
    // Four-deep gh→gh→gh→gh chain triggers the "× 4" fold badge.
    render_fixture("05-folded-run", vec![], |state| {
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
    // A wrap whose audit history's last decision is `deny` gets the
    // orange "↳ denied 5m ago" tint under the leaf — the load-bearing
    // "second look" cue before the user accidentally approves something
    // they previously rejected.
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
    render_fixture("06-pending-denied-last", audit, |state| {
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
fn audit_tab_populated() {
    // Viewer mode: queue is empty, but the user opened the window via
    // `secreq view` to browse history — the rising-edge logic in
    // ConsentApp lands them on the Audit tab and the subtitle reads
    // "viewer (pinned)".
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
    render_fixture("07-audit-tab", audit, |state| {
        state.lock().unwrap().enter_viewer_mode();
        Vec::new()
    });
}

// ── Auto-rules fixtures ──────────────────────────────────────────────────

/// Helper for building a representative rule the harness can drop
/// onto the Rules tab without going through the full UI.
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
    // Land on the Rules tab with no rules configured — the empty
    // state should be inviting, not blank.
    render_fixture_with_extras(
        "08-rules-tab-empty",
        vec![],
        FixtureExtras {
            window_state: Some(Box::new(|ws| ws.focus_rules_tab())),
            ..FixtureExtras::default()
        },
        |_state| Vec::new(),
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
    render_fixture_with_extras(
        "09-rules-tab-list",
        audit,
        FixtureExtras {
            rules,
            window_state: Some(Box::new(|ws| ws.focus_rules_tab())),
            ..FixtureExtras::default()
        },
        |_state| Vec::new(),
    );
}

#[test]
#[ignore = "screenshot harness"]
fn rules_tab_by_recency() {
    // The Rules list with the sort toggle flipped to "Recent". The two
    // rules are crafted so count and recency disagree, making the
    // re-order visible:
    //
    // - "Cursor reads via gh": 12 auto-fires but older (~5 days ago).
    //   Wins under the default "Most used".
    // - "Deploy token denies": only 2 fires, both within the hour.
    //   Promoted to the top here because it fired most recently.
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
    render_fixture_with_extras(
        "19-rules-tab-by-recency",
        audit,
        FixtureExtras {
            rules,
            window_state: Some(Box::new(|ws| {
                ws.focus_rules_tab();
                ws.set_rule_sort(RuleSort::MostRecent);
            })),
            ..FixtureExtras::default()
        },
        |_state| Vec::new(),
    );
}

#[test]
#[ignore = "screenshot harness"]
fn rules_form_new() {
    // The blank-form view — same state as the user just clicked
    // "+ New rule". Exercises radio buttons, text inputs, deny-message
    // hidden (only shown when decide == Deny).
    render_fixture_with_extras(
        "10-rules-form-new",
        vec![],
        FixtureExtras {
            window_state: Some(Box::new(|ws| ws.open_new_rule_form())),
            ..FixtureExtras::default()
        },
        |_state| Vec::new(),
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
    render_fixture_with_extras(
        "11-rules-form-edit-deny",
        vec![],
        FixtureExtras {
            window_state: Some(Box::new(move |ws| ws.open_edit_rule_form(&rule))),
            ..FixtureExtras::default()
        },
        |_state| Vec::new(),
    );
}

#[test]
#[ignore = "screenshot harness"]
fn audit_tab_with_pending() {
    // The "user has a fresh ask AND a populated history" state: the
    // daemon was woken by a new `gh` request, the user pulls up the
    // window and clicks over to Audit to remind themselves of what
    // happened the last few times this same wrap ran. Distinct from
    // `audit_tab_populated` (which is `secreq view` viewer-pinned
    // mode); here the title bar still reads "Consent requests" and
    // both tab badges show counts.
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
    render_fixture_with_extras(
        "14-audit-tab-with-pending",
        audit,
        FixtureExtras {
            window_state: Some(Box::new(|ws| ws.focus_audit_tab())),
            ..FixtureExtras::default()
        },
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
#[ignore = "screenshot harness"]
fn audit_tab_search_filtering() {
    // The Audit tab with an active query that filters down to a
    // subset. Exercises the search bar's "N of M" count badge and
    // the filtered rendering — both day-bucket headers and audit
    // cards should only show entries that match.
    let audit = vec![
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
    ];
    render_fixture_with_extras(
        "15-audit-tab-search-filtering",
        audit,
        FixtureExtras {
            window_state: Some(Box::new(|ws| {
                ws.focus_audit_tab();
                // "gh" matches three of the five entries (two
                // `gh api`/`gh pr` rows + the deny+auto on
                // `gh auth token`). The aws / kubectl rows fall
                // out so the count badge reads "3 of 5".
                ws.set_audit_search("gh");
            })),
            ..FixtureExtras::default()
        },
        |_state| Vec::new(),
    );
}

#[test]
#[ignore = "screenshot harness"]
fn audit_tab_search_no_matches() {
    // The "your query found nothing" empty state. Same audit log as
    // the filtering fixture but with a query that misses every row,
    // so the renderer falls through to the centered "No matching
    // entries" message instead of the day-bucket loop.
    let audit = vec![
        audit_line_traced(
            60 * 2,
            "gh",
            &["pr", "view", "9421"],
            &[(52310, "zsh", "-zsh")],
            &["GITHUB_TOKEN"],
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
    ];
    render_fixture_with_extras(
        "16-audit-tab-search-no-matches",
        audit,
        FixtureExtras {
            window_state: Some(Box::new(|ws| {
                ws.focus_audit_tab();
                ws.set_audit_search("postgres");
            })),
            ..FixtureExtras::default()
        },
        |_state| Vec::new(),
    );
}

#[test]
#[ignore = "screenshot harness"]
fn audit_tab_search_multi_term() {
    // Multi-term search: each whitespace-separated term must hit some
    // field, so "gh auth" narrows to the single row whose wrap is `gh`
    // AND whose argv contains `auth` — even though no single field
    // holds the literal "gh auth". This is the regression guard for the
    // reported bug where "gh auth" wrongly filtered out `gh auth token`.
    let audit = vec![
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
    ];
    render_fixture_with_extras(
        "17-audit-tab-search-multi-term",
        audit,
        FixtureExtras {
            window_state: Some(Box::new(|ws| {
                ws.focus_audit_tab();
                // "gh auth" → only the `gh auth token` row, so the count
                // badge reads "1 of 5". Before the multi-term fix this
                // matched nothing (no field held the literal "gh auth").
                ws.set_audit_search("gh auth");
            })),
            ..FixtureExtras::default()
        },
        |_state| Vec::new(),
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
    // "3 days ago" next to the approve cluster's "today" — the fixture
    // documents the recency dimension, not just the count.
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
    render_fixture_with_extras(
        "13-rules-tab-suggestions",
        audit,
        FixtureExtras {
            window_state: Some(Box::new(|ws| ws.focus_rules_tab())),
            ..FixtureExtras::default()
        },
        |_state| Vec::new(),
    );
}

#[test]
#[ignore = "screenshot harness"]
fn rules_tab_suggestions_by_recency() {
    // Same Rules tab, but with the suggestion sort toggle flipped to
    // "Recent". The two clusters are crafted so count and recency
    // *disagree*, making the re-order visible:
    //
    // - 5× `gh api … /statuses` approvals from Superset, aged ~5 days.
    //   Higher count, older — ranks first under the default "Most used".
    // - 3× `aws s3 ls` approvals from zsh, all within the last few
    //   minutes. Lower count, fresher — promoted to the top here.
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
    render_fixture_with_extras(
        "18-rules-tab-suggestions-by-recency",
        audit,
        FixtureExtras {
            window_state: Some(Box::new(|ws| {
                ws.focus_rules_tab();
                ws.set_suggestion_sort(SuggestionSort::MostRecent);
            })),
            ..FixtureExtras::default()
        },
        |_state| Vec::new(),
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
    render_fixture_with_extras(
        "20-rules-tab-rules-and-suggestions",
        audit,
        FixtureExtras {
            rules,
            window_state: Some(Box::new(|ws| ws.focus_rules_tab())),
            ..FixtureExtras::default()
        },
        |_state| Vec::new(),
    );
}

#[test]
#[ignore = "screenshot harness"]
fn auto_deny_toast_on_pending() {
    // The transient toast that appears at the top of the Pending tab
    // when an auto-deny rule fires. Caller in the production daemon
    // is the child's reader thread; here we just hand the harness a
    // synthetic toast.
    let toast = AutoDenyToastView {
        rule_name: "Block gh destructive ops".to_owned(),
        deny_message: Some("Destructive gh operations are policy-denied.".to_owned()),
    };
    render_fixture_with_extras(
        "12-auto-deny-toast",
        vec![],
        FixtureExtras {
            toast: Some(toast),
            ..FixtureExtras::default()
        },
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
    // A new ask landed while the user was reading the Audit tab and the
    // window was focused — so instead of yanking them to Pending, the
    // title-bar count badge and the Pending tab flash to pull their eye.
    // Captured at peak intensity (pulse = 1.0); in production the child's
    // frame loop decays it back to rest over ~1s. The Audit tab stays
    // active underneath, demonstrating that the user's context is kept.
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
            60 * 15,
            "aws",
            &["s3", "ls", "s3://prod-backups/"],
            &[(52312, "zsh", "-zsh")],
            &["AWS_ACCESS_KEY_ID"],
            "approve",
        ),
    ];
    render_fixture_with_extras(
        "22-pending-arrival-highlight",
        audit,
        FixtureExtras {
            window_state: Some(Box::new(|ws| {
                ws.focus_audit_tab();
                ws.set_pending_pulse(1.0);
            })),
            ..FixtureExtras::default()
        },
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

// ── Pending-badge fixtures ────────────────────────────────────────────────

/// The always-on-top pending badge renders in its own tiny borderless
/// window (`secreq pending-badge`), not the consent panel — so it gets a
/// dedicated, much simpler harness path: no daemon state, no audit log,
/// no tabs. Just `render_badge` at the production badge size with a
/// `inner_margin(0.0)` central panel, so the pill fills the frame exactly
/// as the real borderless window does.
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

    let out_dir = Path::new(OUT_DIR);
    std::fs::create_dir_all(out_dir).expect("mkdir out");
    let out = out_dir.join(format!("{name}.png"));
    img.save(&out).expect("save png");
    eprintln!("wrote {} ({}x{})", out.display(), img.width(), img.height());
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

/// Stress test: render at progressively smaller viewport sizes to
/// catch panics from the hand-painted title bar, card layouts, and
/// scope_builder rects when the user drags the window down. A user-
/// reported "crashes on resize" symptom is reproduced here as
/// `Harness::run()` panicking inside the egui pipeline.
#[test]
#[ignore = "screenshot harness — resize stress, not visual"]
fn resize_stress() {
    let sizes = [
        Vec2::new(760.0, 560.0),   // production baseline
        Vec2::new(360.0, 320.0),   // moderately small
        Vec2::new(220.0, 240.0),   // small
        Vec2::new(120.0, 160.0),   // very small
        Vec2::new(60.0, 100.0),    // tiny — below 2× WINDOW_INSET_X
        Vec2::new(30.0, 80.0),     // pathological
        Vec2::new(800.0, 600.0),   // bigger
        Vec2::new(1200.0, 800.0),  // ~laptop
        Vec2::new(1600.0, 1000.0), // ~external display
        Vec2::new(2400.0, 1400.0), // ~4K
        Vec2::new(3840.0, 2160.0), // 4K
    ];
    for (i, size) in sizes.iter().enumerate() {
        let name = format!("99-resize-{:02}-{}x{}", i, size.x as u32, size.y as u32);
        render_fixture_at_size(&name, *size, vec![], FixtureExtras::default(), |state| {
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
