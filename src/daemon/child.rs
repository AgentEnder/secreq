//! The daemon's window child processes: `secreq consent-window` (the
//! transient decision **prompt**) and `secreq manager-window` (the
//! persistent Rules + Audit **manager**).
//!
//! Both kinds share one skeleton: connect to the daemon's Unix socket,
//! send an attach message, run a background reader thread that feeds a
//! snapshot mailbox, and drive a single-viewport `eframe::run_native`
//! whose `App::update`:
//!
//! - reads the latest `WireSnapshot` from the reader thread,
//! - renders its kind's panel ([`super::prompt_ui::render_prompt_panel`]
//!   or [`super::manager_ui::render_manager_panel`]),
//! - ships its kind's outputs back over the socket (decisions and
//!   "Open Manager" requests from the prompt; rule mutations from the
//!   manager),
//! - exits cleanly when the user closes the window (or, prompt only,
//!   when the daemon sends `ConsentExitPlease`).
//!
//! The differences are deliberate policy, not accident:
//!
//! - **Attach**: prompt → `ConsentWindowAttach`; manager →
//!   `ManagerWindowAttach`. The daemon tracks the two subscriber kinds
//!   separately so the prompt's auto-hide / kill-and-respawn raise
//!   machinery can never touch the manager.
//! - **Always-on-top**: the prompt floats (it demands a decision); the
//!   manager never does (it's a browsing surface).
//! - **Focus reporting**: prompt only — it gates the daemon's
//!   restart-to-raise. The manager is never raised that way.
//! - **Exit**: only the prompt is ever told to exit
//!   (`ConsentExitPlease`); the manager closes when the user closes it
//!   or the daemon's socket drops at shutdown.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use super::manager_ui::{self, ManagerWindowState};
use super::prompt_ui::{self, PromptWindowState};
use super::proto::{ClientMsg, DaemonMsg, ManagerFocus, WireSnapshot};
use super::server;
use super::state::{QueueRow, QueueSnapshot};

/// Which window this child process is. Carried through `run` so the
/// shared socket/eframe skeleton can branch on the few kind-specific
/// policies (attach message, viewport, per-frame renderer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowKind {
    /// The transient consent prompt: one ask at a time, always-on-top,
    /// auto-hidden by the daemon when the queue drains.
    Prompt,
    /// The persistent Rules + Audit manager. `initial_view` comes from
    /// the `--view` CLI flag the daemon passes at spawn (an explicit
    /// target from `OpenManager` / `secreq view`); `None` lets the
    /// window pick — Rules, or Audit when the first snapshot carries
    /// `viewer_mode`.
    Manager { initial_view: Option<ManagerFocus> },
}

/// Entry point for `secreq consent-window` / `secreq manager-window`.
///
/// `always_on_top` applies to the prompt only (the daemon always passes
/// it there — the prompt exists to demand a decision); the manager
/// ignores it by construction.
pub fn run(kind: WindowKind, always_on_top: bool) -> Result<i32> {
    let kind_name = match kind {
        WindowKind::Prompt => "consent-window",
        WindowKind::Manager { .. } => "manager-window",
    };
    super::log::log_at(
        "child",
        format_args!(
            "{kind_name} child starting (pid={}, always_on_top={always_on_top})",
            std::process::id()
        ),
    );

    // Opt out of macOS App Nap. macOS throttles the run loop of
    // backgrounded UI apps — including dropping queued
    // `request_repaint` events on the floor — which means reader-thread
    // wakes don't land until the user manually activates the window.
    // `beginActivity(UserInteractive, ...)` registers a "stay awake"
    // assertion that keeps the run loop ticking even when we're not the
    // foreground app.
    macos_disable_app_nap();

    let socket_path = server::default_socket_path()?;
    let read_stream = UnixStream::connect(&socket_path).with_context(|| {
        format!(
            "connect to daemon socket {}; is the daemon running?",
            socket_path.display()
        )
    })?;
    let write_stream = read_stream.try_clone().context("clone socket for writer")?;
    let writer = Arc::new(Mutex::new(write_stream));

    // Attach handshake. Ships our pid so the daemon can hand it back to
    // the CLI on the next `ShowWindow` / `ShowViewer` — the CLI is the
    // only context macOS 14+ will accept a cross-app
    // `NSRunningApplication.activate(...)` from.
    {
        let mut w = writer.lock().expect("writer mutex");
        let attach = match kind {
            WindowKind::Prompt => ClientMsg::ConsentWindowAttach {
                pid: std::process::id(),
            },
            WindowKind::Manager { .. } => ClientMsg::ManagerWindowAttach {
                pid: std::process::id(),
            },
        };
        let json = serde_json::to_string(&attach)?;
        writeln!(w, "{json}").context("write window attach message")?;
    }

    // Shared mailbox: reader thread pushes snapshots in, eframe pulls
    // them on each frame.
    let snapshot: Arc<Mutex<WireSnapshot>> = Arc::new(Mutex::new(WireSnapshot {
        queue: Vec::new(),
        viewer_mode: false,
        rules: Vec::new(),
    }));
    // Shared with the reader: the latest auto-deny toast and the local
    // wall-clock time we received it. Only the prompt renders it; the
    // manager's reader stores-and-ignores.
    let auto_deny_toast: Arc<Mutex<Option<AutoDenyToastState>>> = Arc::new(Mutex::new(None));
    let exit_requested = Arc::new(AtomicBool::new(false));
    // The egui context is filled in once eframe's CreationContext runs.
    let egui_ctx: Arc<Mutex<Option<egui::Context>>> = Arc::new(Mutex::new(None));

    spawn_reader(
        read_stream,
        snapshot.clone(),
        auto_deny_toast.clone(),
        egui_ctx.clone(),
    )?;

    let ui_state = match kind {
        WindowKind::Prompt => ChildUiState::Prompt(PromptWindowState::new()),
        WindowKind::Manager { initial_view } => {
            ChildUiState::Manager(Box::new(match initial_view {
                Some(focus) => ManagerWindowState::with_initial_view(focus),
                None => ManagerWindowState::new(),
            }))
        }
    };

    let app = ChildApp {
        kind,
        snapshot,
        auto_deny_toast,
        writer: writer.clone(),
        exit_requested: exit_requested.clone(),
        ui_state,
        // The daemon defaults attached prompt subscribers to
        // `focused = true` (a freshly-spawned process gets foreground
        // intent on macOS). We match that here so the first frame
        // doesn't send a redundant `focused = true` message before the
        // OS has had a chance to settle the state.
        last_reported_focused: true,
    };

    let mut viewport = match kind {
        WindowKind::Prompt => egui::ViewportBuilder::default()
            .with_title("secreq")
            .with_inner_size(prompt_ui::PROMPT_DEFAULT_SIZE)
            .with_decorations(true),
        WindowKind::Manager { .. } => egui::ViewportBuilder::default()
            .with_title("secreq Manager")
            .with_inner_size(manager_ui::MANAGER_DEFAULT_SIZE)
            .with_decorations(true),
    };
    if kind == WindowKind::Prompt && always_on_top {
        if super::always_on_top_supported() {
            viewport = viewport.with_always_on_top();
        } else {
            super::log::log_at(
                "child",
                format_args!(
                    "always-on-top requested but unavailable (Wayland?); opening a normal window"
                ),
            );
        }
    }
    let native_opts = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };

    let ctx_slot = egui_ctx.clone();
    let result = eframe::run_native(
        match kind {
            WindowKind::Prompt => "secreq consent",
            WindowKind::Manager { .. } => "secreq manager",
        },
        native_opts,
        Box::new(move |cc| {
            // Follow the OS appearance; `install_style` re-resolves the
            // theme tokens from the OS-driven light/dark state.
            cc.egui_ctx.set_theme(egui::ThemePreference::System);
            super::ui::install_style(&cc.egui_ctx);
            *ctx_slot.lock().expect("egui_ctx mutex") = Some(cc.egui_ctx.clone());
            Ok(Box::new(app))
        }),
    );
    super::log::log_at(
        "child",
        format_args!("eframe::run_native returned: {result:?}"),
    );

    // Best-effort detach notice for the prompt; the daemon also handles
    // socket drop (which is the manager's only close signal — it has no
    // detach message).
    if kind == WindowKind::Prompt && !exit_requested.load(Ordering::SeqCst) {
        let _ = send_msg(&writer, &ClientMsg::ConsentWindowDetach);
    }

    Ok(0)
}

/// One auto-deny toast in flight in the child. Stored in shared
/// state between the reader thread (writes on `AutoDenyToast`) and
/// the UI thread (reads, ages out after [`AUTO_DENY_TOAST_LIFETIME`]).
#[derive(Debug, Clone)]
pub struct AutoDenyToastState {
    pub rule_name: String,
    pub deny_message: Option<String>,
    pub received_at: Instant,
}

/// How long an auto-deny toast remains visible after it arrived.
/// Picked to be long enough to read a one-line rule name + message,
/// short enough not to clutter the prompt while the user is actively
/// triaging.
pub const AUTO_DENY_TOAST_LIFETIME: Duration = Duration::from_secs(5);

fn spawn_reader(
    stream: UnixStream,
    snapshot: Arc<Mutex<WireSnapshot>>,
    auto_deny_toast: Arc<Mutex<Option<AutoDenyToastState>>>,
    egui_ctx: Arc<Mutex<Option<egui::Context>>>,
) -> Result<()> {
    thread::Builder::new()
        .name("window-child-reader".to_owned())
        .spawn(move || {
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) => {
                        super::log::log_at("child", format_args!("daemon closed socket; exiting"));
                        // Hard exit instead of signalling the main
                        // thread — see ConsentExitPlease handler.
                        std::process::exit(0);
                    }
                    Ok(_) => {}
                    Err(err) => {
                        super::log::log_at(
                            "child",
                            format_args!("socket read error: {err}; exiting"),
                        );
                        std::process::exit(0);
                    }
                }
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let msg: DaemonMsg = match serde_json::from_str(trimmed) {
                    Ok(m) => m,
                    Err(err) => {
                        super::log::log_at(
                            "child",
                            format_args!("malformed daemon msg: {err}; line=[{trimmed}]"),
                        );
                        continue;
                    }
                };
                match msg {
                    DaemonMsg::ConsentUpdate { snapshot: snap } => {
                        super::log::log_at(
                            "child",
                            format_args!(
                                "← ConsentUpdate (queue_len={}, viewer_mode={})",
                                snap.queue.len(),
                                snap.viewer_mode
                            ),
                        );
                        *snapshot.lock().expect("snapshot mutex") = snap;
                        wake(&egui_ctx);
                    }
                    DaemonMsg::ConsentExitPlease => {
                        super::log::log_at("child", format_args!("← ConsentExitPlease"));
                        // Force exit from the reader thread. The egui
                        // main loop is suspended when the window is
                        // backgrounded/occluded on macOS, so signalling
                        // `exit_requested` and waiting for App::ui to
                        // flush `ViewportCommand::Close` would hang
                        // indefinitely. The daemon only ever sends this
                        // to prompt subscribers.
                        std::process::exit(0);
                    }
                    DaemonMsg::AutoDenyToast {
                        rule_name,
                        deny_message,
                    } => {
                        super::log::log_at(
                            "child",
                            format_args!("← AutoDenyToast rule={rule_name}"),
                        );
                        *auto_deny_toast.lock().expect("toast mutex") = Some(AutoDenyToastState {
                            rule_name,
                            deny_message,
                            received_at: Instant::now(),
                        });
                        wake(&egui_ctx);
                    }
                    DaemonMsg::Ok
                    | DaemonMsg::Hello { .. }
                    | DaemonMsg::WindowOpened { .. }
                    | DaemonMsg::Decision { .. }
                    | DaemonMsg::Err { .. }
                    | DaemonMsg::RulesList { .. } => {
                        // Belong to the one-shot path; ignore quietly.
                    }
                }
            }
        })
        .context("spawn window-child reader thread")?;
    Ok(())
}

fn wake(ctx: &Arc<Mutex<Option<egui::Context>>>) {
    if let Some(c) = ctx.lock().expect("egui_ctx mutex").as_ref() {
        c.request_repaint();
    }
}

fn send_msg(writer: &Arc<Mutex<UnixStream>>, msg: &ClientMsg) -> Result<()> {
    let json = serde_json::to_string(msg).context("serialize ClientMsg")?;
    let mut w = writer.lock().expect("writer mutex");
    writeln!(w, "{json}").context("write to daemon")?;
    Ok(())
}

/// Per-kind persistent UI state. One variant per window kind; the
/// `App::update` dispatch matches on it alongside `kind`. The manager
/// state is boxed — it's several hundred bytes of browsing state, and
/// boxing keeps the enum (and thus the prompt path) small.
enum ChildUiState {
    Prompt(PromptWindowState),
    Manager(Box<ManagerWindowState>),
}

struct ChildApp {
    kind: WindowKind,
    snapshot: Arc<Mutex<WireSnapshot>>,
    auto_deny_toast: Arc<Mutex<Option<AutoDenyToastState>>>,
    writer: Arc<Mutex<UnixStream>>,
    exit_requested: Arc<AtomicBool>,
    ui_state: ChildUiState,
    /// Last focus value we shipped to the daemon (prompt only). We only
    /// send on transitions so the daemon log stays quiet and we don't
    /// flood the socket with one message per frame.
    last_reported_focused: bool,
}

impl eframe::App for ChildApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        // Re-derive the style each frame so an OS light/dark flip
        // mid-session restyles the window immediately (the theme
        // tokens resolve from egui's OS-followed theme).
        super::ui::install_style(&ctx);

        // External "please exit" — either the daemon told us to go or
        // the socket dropped. The reader thread already `process::exit`s
        // on both, but if for some reason we got here via the egui
        // path, still honour it.
        if self.exit_requested.load(Ordering::SeqCst) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }

        // Native close button: let it close. The prompt sends its
        // detach notice on the way out of `run`; the manager's close is
        // its socket dropping.
        if ctx.input(|i| i.viewport().close_requested()) {
            super::log::log_at("child", format_args!("close_requested → honouring"));
            if self.kind == WindowKind::Prompt {
                // Best-effort early notify; `run` will also try.
                let _ = send_msg(&self.writer, &ClientMsg::ConsentWindowDetach);
            }
            return;
        }

        let wire = self.snapshot.lock().expect("snapshot mutex").clone();
        match &mut self.ui_state {
            ChildUiState::Prompt(prompt_state) => {
                // Report focus changes to the daemon. The daemon uses
                // this to decide whether a new ask should
                // kill-and-respawn this window (raising it to the
                // foreground) or just push a snapshot update. Only sent
                // on transitions; the steady-state cost is zero.
                let focused = ctx.input(|i| i.focused);
                if focused != self.last_reported_focused {
                    if let Err(err) =
                        send_msg(&self.writer, &ClientMsg::ConsentWindowFocus { focused })
                    {
                        super::log::log_at(
                            "child",
                            format_args!("ConsentWindowFocus send failed: {err}"),
                        );
                    } else {
                        self.last_reported_focused = focused;
                    }
                }

                // Build a local `QueueSnapshot` from the wire form. The
                // renderer expects `Instant`-based `first_seen`; we
                // rebuild them in this process's clock so
                // `humanize_duration(...)` produces sensible "Ns ago"
                // strings.
                let now = Instant::now();
                let snapshot = QueueSnapshot {
                    entries: wire
                        .queue
                        .iter()
                        .map(|r| QueueRow {
                            key: r.key.clone(),
                            representative: r.representative.clone(),
                            waiter_count: r.waiter_count,
                            first_seen: now
                                .checked_sub(Duration::from_secs(r.first_seen_secs_ago))
                                .unwrap_or(now),
                            status: r.status,
                        })
                        .collect(),
                };

                // Age out an expired toast before passing it to the
                // renderer. Single-writer model from the reader thread;
                // we can clear here without racing.
                let toast_view = {
                    let mut guard = self.auto_deny_toast.lock().expect("toast mutex");
                    if let Some(state) = guard.as_ref() {
                        if state.received_at.elapsed() >= AUTO_DENY_TOAST_LIFETIME {
                            *guard = None;
                        }
                    }
                    guard.as_ref().map(|s| super::ui::AutoDenyToastView {
                        rule_name: s.rule_name.clone(),
                        deny_message: s.deny_message.clone(),
                    })
                };

                // Render and collect actions.
                let mut actions = Vec::new();
                let out = prompt_ui::render_prompt_panel(
                    &ctx,
                    ui,
                    &snapshot,
                    toast_view.as_ref(),
                    prompt_state,
                    &mut actions,
                );

                // Ship decisions to the daemon.
                for act in actions {
                    let msg = ClientMsg::ConsentDecision {
                        key: act.key,
                        decision: act.decision,
                        scope_pid: act.scope.pid,
                        scope_start_time: act.scope.start_time,
                    };
                    if let Err(err) = send_msg(&self.writer, &msg) {
                        super::log::log_at(
                            "child",
                            format_args!("ConsentDecision send failed: {err}"),
                        );
                    }
                }

                // "Open Manager…" — the daemon spawns (or leaves alone)
                // the manager-window child.
                if let Some(focus) = out.open_manager {
                    if let Err(err) = send_msg(&self.writer, &ClientMsg::OpenManager { focus }) {
                        super::log::log_at("child", format_args!("OpenManager send failed: {err}"));
                    }
                }
            }
            ChildUiState::Manager(manager_state) => {
                // Render and ship rule mutations. Each maps 1:1 to a
                // ClientMsg variant; the daemon validates + persists +
                // updates its in-memory ruleset, and the result shows
                // up in the next `ConsentUpdate` broadcast.
                let mut rule_actions = Vec::new();
                manager_ui::render_manager_panel(
                    &ctx,
                    ui,
                    &wire.rules,
                    wire.viewer_mode,
                    manager_state,
                    &mut rule_actions,
                );
                for act in rule_actions {
                    let msg = match act {
                        super::ui::RuleAction::Add(rule) => ClientMsg::AddRule { rule },
                        super::ui::RuleAction::Update(rule) => ClientMsg::UpdateRule { rule },
                        super::ui::RuleAction::Delete(id) => ClientMsg::DeleteRule { id },
                        super::ui::RuleAction::SetEnabled { id, enabled } => {
                            ClientMsg::SetRuleEnabled { id, enabled }
                        }
                    };
                    if let Err(err) = send_msg(&self.writer, &msg) {
                        super::log::log_at("child", format_args!("RuleAction send failed: {err}"));
                    }
                }
            }
        }

        // Gentle ongoing repaint so "Ns ago" labels tick AND so we
        // pick up external wakes (snapshot updates, ConsentExitPlease)
        // promptly even when winit's cross-thread wake isn't firing —
        // which on macOS is exactly what happens for background
        // windows. 100 ms is fast enough to feel instant on a raise;
        // the cost is one empty paint every 100 ms, which is cheap
        // because nothing changes between paints.
        ctx.request_repaint_after(Duration::from_millis(100));
    }
}

/// Register a `UserInteractive` activity so macOS doesn't put us to
/// sleep when our window is in the background. Without this, App
/// Nap throttles our run loop and the reader thread's
/// `request_repaint()` calls don't actually wake `App::ui` until the
/// user manually re-activates the window.
///
/// The activity token has to stay alive for the duration the
/// assertion is in effect. We leak it into a `Box::leak` static-
/// lifetime reference — the child process is short-lived (closes with
/// the window) so the "leak" is bounded by the process lifetime, and
/// avoiding `lazy_static` / `OnceCell` keeps this self-contained.
#[cfg(target_os = "macos")]
fn macos_disable_app_nap() {
    use objc2_foundation::{NSActivityOptions, NSProcessInfo, NSString};
    let info = NSProcessInfo::processInfo();
    let reason = NSString::from_str("secreq window must remain responsive in background");
    let options = NSActivityOptions::UserInteractive;
    let token = info.beginActivityWithOptions_reason(options, &reason);
    // Leak the token — see doc comment above. The reference would
    // otherwise drop at end-of-scope, ending the activity assertion
    // immediately and re-enabling App Nap.
    Box::leak(Box::new(token));
    super::log::log_at("child", format_args!("disabled App Nap (UserInteractive)"));
}

#[cfg(not(target_os = "macos"))]
fn macos_disable_app_nap() {}
