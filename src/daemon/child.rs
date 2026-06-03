//! `secreq consent-window` child process.
//!
//! Spawned by the daemon when an Ask is queued, `secreq view` arrives,
//! or `secreq pending` arrives and no consent window is currently
//! attached. Connects to the daemon's Unix socket, sends
//! `ConsentWindowAttach`, then runs a standard single-viewport
//! `eframe::run_native` whose `App::update`:
//!
//! - reads the latest `WireSnapshot` from a background reader thread,
//! - calls [`super::ui::render_consent_panel`] to paint it,
//! - ships any `PendingAction`s out as `ClientMsg::ConsentDecision`,
//! - exits cleanly when the user closes the window (or the daemon
//!   sends `ConsentExitPlease`).

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use super::proto::{ClientMsg, DaemonMsg, WireSnapshot};
use super::server;
use super::state::{QueueRow, QueueSnapshot};

/// Entry point for `secreq consent-window`.
pub fn run() -> Result<i32> {
    super::log::log_at(
        "child",
        format_args!("consent-window child starting (pid={})", std::process::id()),
    );

    // Opt out of macOS App Nap. macOS throttles the run loop of
    // backgrounded UI apps — including dropping queued
    // `request_repaint` events on the floor — which means our
    // `FocusWindow` handler in `App::ui` doesn't run until the user
    // manually activates the window (defeating the entire focus
    // protocol). `beginActivity(UserInteractive, ...)` registers a
    // "stay awake" assertion that keeps the run loop ticking even
    // when we're not the foreground app. The returned activity
    // token is kept alive in a `static`-lifetime slot so it stays
    // valid for the rest of the process.
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

    // Attach handshake. Ships our pid so the daemon can hand it back
    // to the CLI on the next `ShowWindow` / `ShowViewer` — the CLI is
    // the only context macOS 14+ will accept a cross-app
    // `NSRunningApplication.activate(...)` from.
    {
        let mut w = writer.lock().expect("writer mutex");
        let attach = ClientMsg::ConsentWindowAttach {
            pid: std::process::id(),
        };
        let json = serde_json::to_string(&attach)?;
        writeln!(w, "{json}").context("write ConsentWindowAttach")?;
    }

    // Shared mailbox: reader thread pushes snapshots in, eframe pulls
    // them on each frame.
    let snapshot: Arc<Mutex<WireSnapshot>> = Arc::new(Mutex::new(WireSnapshot {
        queue: Vec::new(),
        viewer_mode: false,
        rules: Vec::new(),
    }));
    // Shared with the reader: the latest auto-deny toast and the
    // local wall-clock time we received it. Reader thread overwrites
    // on each `AutoDenyToast`; UI thread checks elapsed and renders
    // until expiry.
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

    let app = ConsentChildApp {
        snapshot,
        auto_deny_toast,
        writer: writer.clone(),
        exit_requested: exit_requested.clone(),
        window_state: super::ui::ConsentWindowState::new(),
        frame_count: 0,
        // The daemon defaults attached subscribers to `focused = true`
        // (a freshly-spawned process gets foreground intent on macOS).
        // We match that here so the first frame doesn't send a
        // redundant `focused = true` message before the OS has had a
        // chance to settle the state.
        last_reported_focused: true,
    };

    let viewport = egui::ViewportBuilder::default()
        .with_title("secreq")
        // Bumped from 520x480 when the Rules tab was added — three
        // tabs need more horizontal room, and the rule form needs
        // vertical room for the match fields and the deny-message
        // text area.
        .with_inner_size([760.0, 560.0])
        .with_decorations(true);
    let native_opts = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };

    let ctx_slot = egui_ctx.clone();
    let result = eframe::run_native(
        "secreq consent",
        native_opts,
        Box::new(move |cc| {
            super::ui::install_style(&cc.egui_ctx);
            *ctx_slot.lock().expect("egui_ctx mutex") = Some(cc.egui_ctx.clone());
            Ok(Box::new(app))
        }),
    );
    super::log::log_at(
        "child",
        format_args!("eframe::run_native returned: {result:?}"),
    );

    // Best-effort detach notice; the daemon also handles socket drop.
    if !exit_requested.load(Ordering::SeqCst) {
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
/// short enough not to clutter the Pending tab when the user is
/// actively triaging.
pub const AUTO_DENY_TOAST_LIFETIME: Duration = Duration::from_secs(5);

fn spawn_reader(
    stream: UnixStream,
    snapshot: Arc<Mutex<WireSnapshot>>,
    auto_deny_toast: Arc<Mutex<Option<AutoDenyToastState>>>,
    egui_ctx: Arc<Mutex<Option<egui::Context>>>,
) -> Result<()> {
    thread::Builder::new()
        .name("consent-window-reader".to_owned())
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
                        // indefinitely.
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
                    | DaemonMsg::WindowOpened { .. }
                    | DaemonMsg::Decision { .. }
                    | DaemonMsg::Err { .. }
                    | DaemonMsg::RulesList { .. } => {
                        // Belong to the one-shot path; ignore quietly.
                    }
                }
            }
        })
        .context("spawn consent-window reader thread")?;
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

struct ConsentChildApp {
    snapshot: Arc<Mutex<WireSnapshot>>,
    auto_deny_toast: Arc<Mutex<Option<AutoDenyToastState>>>,
    writer: Arc<Mutex<UnixStream>>,
    exit_requested: Arc<AtomicBool>,
    window_state: super::ui::ConsentWindowState,
    frame_count: u64,
    /// Last focus value we shipped to the daemon. We only send on
    /// transitions so the daemon log stays quiet and we don't flood
    /// the socket with one message per frame.
    last_reported_focused: bool,
}

impl eframe::App for ConsentChildApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.frame_count = self.frame_count.wrapping_add(1);

        // External "please exit" — either the daemon told us to go or
        // the socket dropped. The reader thread already `process::exit`s
        // on both, but if for some reason we got here via the egui
        // path, still honour it.
        if self.exit_requested.load(Ordering::SeqCst) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }

        // Native close button: let it close. We'll send the detach
        // notice on the way out of `run`.
        if ctx.input(|i| i.viewport().close_requested()) {
            super::log::log_at(
                "child",
                format_args!("close_requested → honouring + sending ConsentWindowDetach"),
            );
            // Best-effort early notify; `run` will also try.
            let _ = send_msg(&self.writer, &ClientMsg::ConsentWindowDetach);
            return;
        }

        // Report focus changes to the daemon. The daemon uses this to
        // decide whether a new ask should kill-and-respawn this window
        // (raising it to the foreground) or just push a snapshot
        // update — and to suppress the auto-hide grace exit while the
        // user is actively interacting (scrolling the audit log, etc.).
        // Only sent on transitions; the steady-state cost is zero.
        let focused = ctx.input(|i| i.focused);
        if focused != self.last_reported_focused {
            if let Err(err) = send_msg(&self.writer, &ClientMsg::ConsentWindowFocus { focused }) {
                super::log::log_at(
                    "child",
                    format_args!("ConsentWindowFocus send failed: {err}"),
                );
            } else {
                self.last_reported_focused = focused;
            }
        }

        // Build a local `QueueSnapshot` from the wire form. The
        // renderer expects `Instant`-based `first_seen`; we rebuild
        // them in this process's clock so `humanize_duration(...)`
        // produces sensible "Ns ago" strings.
        let wire = self.snapshot.lock().expect("snapshot mutex").clone();
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
                })
                .collect(),
        };

        // Age out an expired toast before passing it to the
        // renderer. Single-writer model from the reader thread; we
        // can clear here without racing.
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
        let mut rule_actions = Vec::new();
        super::ui::render_consent_panel(
            &ctx,
            ui,
            &snapshot,
            wire.viewer_mode,
            &wire.rules,
            toast_view.as_ref(),
            &mut self.window_state,
            &mut actions,
            &mut rule_actions,
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
                super::log::log_at("child", format_args!("ConsentDecision send failed: {err}"));
            }
        }
        // Ship rule mutations to the daemon. Each maps 1:1 to a
        // ClientMsg variant; the daemon validates + persists +
        // updates its in-memory ruleset.
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

        // Gentle ongoing repaint so "Ns ago" labels tick AND so we
        // pick up external wakes (FocusWindow from the reader thread,
        // ConsentExitPlease, snapshot updates) promptly even when
        // winit's cross-thread wake isn't firing — which on macOS is
        // exactly what happens for background windows. 100 ms is fast
        // enough to feel instant on a focus raise; the cost is one
        // empty paint every 100 ms, which is cheap because nothing
        // changes between paints.
        ctx.request_repaint_after(Duration::from_millis(100));
    }
}

/// Register a `UserInteractive` activity so macOS doesn't put us to
/// sleep when our window is in the background. Without this, App
/// Nap throttles our run loop and the reader thread's
/// `request_repaint()` calls don't actually wake `App::ui` until the
/// user manually re-activates the window — exactly the symptom
/// we hit with the `orderFrontRegardless` path.
///
/// The activity token has to stay alive for the duration the
/// assertion is in effect. We leak it into a `Box::leak` static-
/// lifetime reference — the consent child process is short-lived
/// (closes with the window) so the "leak" is bounded by the
/// process lifetime, and avoiding `lazy_static` / `OnceCell` keeps
/// this self-contained.
#[cfg(target_os = "macos")]
fn macos_disable_app_nap() {
    use objc2_foundation::{NSActivityOptions, NSProcessInfo, NSString};
    let info = NSProcessInfo::processInfo();
    let reason = NSString::from_str("consent-window must remain responsive in background");
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
