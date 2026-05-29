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
use secreq::daemon::proto::{Ask, Caller, DedupeKey, SecretAsk};
use secreq::daemon::state::{SharedState, State};
use secreq::daemon::ui::ConsentApp;

/// Where the regenerated PNGs land. Relative to the workspace root,
/// which is `cargo test`'s CWD.
const OUT_DIR: &str = "dev-docs/ui-screenshots";

/// Logical window size — matches the daemon's production viewport
/// (`with_inner_size([520.0, 480.0])` in `daemon/mod.rs`).
const SIZE: Vec2 = Vec2::new(520.0, 480.0);

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
    };
    let (tx, rx) = mpsc::channel();
    state.lock().unwrap().submit_ask(ask, tx);
    rx
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
        command: vec![format!("wrap {wrap}")],
        callers: vec![caller_name.to_owned()],
        secrets: secrets.iter().map(|s| (*s).to_owned()).collect(),
        decision: decision.to_owned(),
    }
}

/// Core harness driver. Sets `XDG_STATE_HOME` to a tempdir, writes the
/// audit log, builds a `SharedState` via `setup`, then drives the real
/// `ConsentApp` for one frame via `egui_kittest` and writes a PNG.
fn render_fixture(
    name: &str,
    audit_entries: Vec<AuditEntry>,
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

    let shutdown_flag = Arc::new(AtomicBool::new(false));
    let app_state = state.clone();
    let sf = shutdown_flag.clone();
    let mut harness = Harness::builder()
        .with_size(SIZE)
        .with_pixels_per_point(PIXELS_PER_POINT)
        .wgpu()
        .build_eframe(move |cc| {
            // Install the same Proportional-fallback chain the daemon
            // uses in production so symbol glyphs (✓ ⊙ ▾ ↳ ⏎) render
            // in the screenshots instead of tofu boxes.
            secreq::daemon::ui::install_fonts(&cc.egui_ctx);
            ConsentApp::new(app_state, sf)
        });
    // `build_eframe` already runs one frame; `run()` keeps stepping
    // until egui reports no immediate repaint is needed. ConsentApp
    // asks for a 500ms-deferred repaint, which counts as "settled" for
    // the loop — so this returns after a handful of frames at most.
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
        audit_line(60, "gh", "zsh", &["GITHUB_TOKEN"], "approve+remember"),
        audit_line(60 * 7, "aws", "zsh", &["AWS_ACCESS_KEY_ID"], "approve"),
        audit_line(60 * 17, "kubectl", "make", &["KUBECONFIG_TOKEN"], "deny"),
        audit_line(60 * 60, "psql", "node", &["PGPASSWORD"], "approve+remember"),
        audit_line(60 * 60 * 6, "gh", "npm", &["GITHUB_TOKEN"], "approve"),
    ];
    render_fixture("07-audit-tab", audit, |state| {
        state.lock().unwrap().enter_viewer_mode();
        Vec::new()
    });
}
