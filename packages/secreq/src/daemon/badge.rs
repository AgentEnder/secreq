//! `secreq pending-badge` child process.
//!
//! A small always-on-top "N pending" pill that the daemon spawns while
//! requests are awaiting a decision. It floats over other apps so a
//! backgrounded or dismissed consent window can't leave a request
//! forgotten with the requesting process hung indefinitely (there is no
//! timeout on a consent wait — see `server.rs` / `ssh_agent.rs`).
//!
//! Lifecycle, orchestrated by the daemon exactly like the consent window
//! (one child per surface) but with a different trigger and no
//! focus/restart logic:
//!
//! - Spawned by [`super::ensure_badge_window`] when the queue becomes
//!   non-empty.
//! - Subscribes to the **same** `ConsentUpdate` snapshot stream as the
//!   consent window (sending `BadgeWindowAttach` instead of
//!   `ConsentWindowAttach`); it renders only the count of `Awaiting`
//!   rows.
//! - Persists until the queue drains, at which point the daemon sends
//!   `ConsentExitPlease` and this process exits. Crucially it does **not**
//!   exit on focus loss — being ignorable is the whole point.
//! - A click sends `RaiseConsentRequested`; the daemon brings the
//!   consent window forward.
//!
//! The badge is always-on-top, and only exists where that's honoured
//! (macOS and X11). On Wayland — which forbids override-redirect
//! always-on-top and also denies clients absolute positioning — it could
//! neither float nor pin itself to a corner, so the daemon doesn't spawn
//! it there at all (see `super::ensure_badge_window`); the consent window
//! still appears, it just won't be on top. Headless likewise gets no
//! badge — the daemon never spawns one (the SSH path fails closed without
//! a graphical environment; wrap asks without a display simply never reach
//! a queued state with a UI).

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};

use super::proto::{ClientMsg, DaemonMsg, RowStatus};
use super::server;

/// Default badge window size, in logical points. Wide enough for
/// "N pending" with a two- or three-digit count, short enough to read as
/// a pill rather than a window.
const BADGE_SIZE: [f32; 2] = [184.0, 44.0];

/// Inset from the right/top monitor edge when positioning the badge.
/// `TOP_MARGIN` clears the macOS menu bar (~24–37px) with room to spare.
const EDGE_MARGIN: f32 = 16.0;
const TOP_MARGIN: f32 = 40.0;

/// Entry point for `secreq pending-badge`.
pub fn run() -> Result<i32> {
    super::log::log_at(
        "badge",
        format_args!("pending-badge child starting (pid={})", std::process::id()),
    );

    // Same App-Nap opt-out as the consent window: an always-on-top window
    // whose process is napping won't repaint when the reader thread nudges
    // it, so the count would freeze while it sits in the background — which
    // is exactly where the badge lives.
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

    // Attach handshake.
    {
        let mut w = writer.lock().expect("writer mutex");
        let attach = ClientMsg::BadgeWindowAttach {
            pid: std::process::id(),
        };
        let json = serde_json::to_string(&attach)?;
        writeln!(w, "{json}").context("write BadgeWindowAttach")?;
    }

    // Shared count of `Awaiting` rows, written by the reader thread and
    // read each frame by the UI.
    let count: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
    let exit_requested = Arc::new(AtomicBool::new(false));
    let egui_ctx: Arc<Mutex<Option<egui::Context>>> = Arc::new(Mutex::new(None));

    spawn_reader(read_stream, count.clone(), egui_ctx.clone())?;

    let app = BadgeApp {
        count,
        writer: writer.clone(),
        exit_requested: exit_requested.clone(),
        positioned: false,
    };

    // Unconditionally always-on-top: the daemon only spawns this child on
    // platforms that honour it (`ensure_badge_window` skips the badge
    // entirely on Wayland), so a floating overlay is the only mode the
    // badge ever runs in.
    let viewport = egui::ViewportBuilder::default()
        .with_title("secreq pending")
        .with_inner_size(BADGE_SIZE)
        .with_decorations(false)
        .with_resizable(false)
        // Keep the badge out of the dock / taskbar — it's an overlay, not
        // an app the user switches to.
        .with_taskbar(false)
        .with_always_on_top();
    let native_opts = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };

    let ctx_slot = egui_ctx.clone();
    let result = eframe::run_native(
        "secreq pending-badge",
        native_opts,
        Box::new(move |cc| {
            // Follow the OS appearance, same as the consent window.
            cc.egui_ctx.set_theme(egui::ThemePreference::System);
            super::ui::install_style(&cc.egui_ctx);
            *ctx_slot.lock().expect("egui_ctx mutex") = Some(cc.egui_ctx.clone());
            Ok(Box::new(app))
        }),
    );
    super::log::log_at(
        "badge",
        format_args!("eframe::run_native returned: {result:?}"),
    );

    if !exit_requested.load(Ordering::SeqCst) {
        let _ = send_msg(&writer, &ClientMsg::BadgeWindowDetach);
    }
    Ok(0)
}

fn spawn_reader(
    stream: UnixStream,
    count: Arc<Mutex<usize>>,
    egui_ctx: Arc<Mutex<Option<egui::Context>>>,
) -> Result<()> {
    thread::Builder::new()
        .name("pending-badge-reader".to_owned())
        .spawn(move || {
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) => {
                        super::log::log_at("badge", format_args!("daemon closed socket; exiting"));
                        std::process::exit(0);
                    }
                    Ok(_) => {}
                    Err(err) => {
                        super::log::log_at(
                            "badge",
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
                            "badge",
                            format_args!("malformed daemon msg: {err}; line=[{trimmed}]"),
                        );
                        continue;
                    }
                };
                match msg {
                    DaemonMsg::ConsentUpdate { snapshot } => {
                        let awaiting = snapshot
                            .queue
                            .iter()
                            .filter(|r| r.status == RowStatus::Awaiting)
                            .count();
                        *count.lock().expect("count mutex") = awaiting;
                        wake(&egui_ctx);
                    }
                    DaemonMsg::ConsentExitPlease => {
                        super::log::log_at("badge", format_args!("← ConsentExitPlease"));
                        // Exit from the reader thread for the same reason
                        // the consent window does — a backgrounded macOS
                        // window's main loop may be suspended, so we can't
                        // rely on the UI thread to flush a close command.
                        std::process::exit(0);
                    }
                    // The badge subscribes to the same stream as the
                    // consent window but only cares about snapshots and the
                    // exit signal; everything else is one-shot / consent
                    // chatter it never sees in practice.
                    DaemonMsg::Ok
                    | DaemonMsg::Hello { .. }
                    | DaemonMsg::LinkPairing { .. }
                    | DaemonMsg::LinkDevices { .. }
                    | DaemonMsg::WindowOpened { .. }
                    | DaemonMsg::Decision { .. }
                    | DaemonMsg::Err { .. }
                    | DaemonMsg::RulesList(_)
                    | DaemonMsg::RuleAdded { .. }
                    | DaemonMsg::AutoDenyToast { .. } => {}
                }
            }
        })
        .context("spawn pending-badge reader thread")?;
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

struct BadgeApp {
    count: Arc<Mutex<usize>>,
    writer: Arc<Mutex<UnixStream>>,
    exit_requested: Arc<AtomicBool>,
    /// `true` once we've placed the window at the top-right corner. We
    /// can't position at build time (the monitor size isn't known until
    /// the first frame), so we send an `OuterPosition` command on the
    /// first frame `monitor_size` is available.
    positioned: bool,
}

impl eframe::App for BadgeApp {
    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        super::ui::badge_clear_color()
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        // Re-derive the style each frame so an OS light/dark flip
        // mid-session restyles the badge immediately.
        super::ui::install_style(&ctx);

        if self.exit_requested.load(Ordering::SeqCst) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }
        if ctx.input(|i| i.viewport().close_requested()) {
            let _ = send_msg(&self.writer, &ClientMsg::BadgeWindowDetach);
            return;
        }

        // Place the badge at the top-right corner once we know the
        // monitor size. macOS reports it including the menu bar, so
        // `TOP_MARGIN` keeps the pill clear of it.
        if !self.positioned {
            if let Some(monitor) = ctx.input(|i| i.viewport().monitor_size) {
                let x = (monitor.x - BADGE_SIZE[0] - EDGE_MARGIN).max(0.0);
                let pos = egui::pos2(x, TOP_MARGIN);
                ctx.send_viewport_cmd(egui::ViewportCommand::OuterPosition(pos));
                self.positioned = true;
            }
        }

        let count = *self.count.lock().expect("count mutex");
        let response = super::ui::render_badge(ui, count);
        if response.clicked() {
            super::log::log_at("badge", format_args!("clicked → RaiseConsentRequested"));
            if let Err(err) = send_msg(&self.writer, &ClientMsg::RaiseConsentRequested) {
                super::log::log_at(
                    "badge",
                    format_args!("RaiseConsentRequested send failed: {err}"),
                );
            }
        }
        // Pointer-cursor affordance over the whole pill.
        if response.hovered() {
            ctx.set_cursor_icon(egui::CursorIcon::PointingHand);
        }

        // Gentle heartbeat so reader-thread wakes land promptly even when
        // winit's cross-thread wake doesn't fire for a background window
        // (the macOS case the badge is built for).
        ctx.request_repaint_after(Duration::from_millis(100));
    }
}

/// See `child.rs::macos_disable_app_nap` — same rationale: keep the run
/// loop ticking while the badge sits in the background so the reader
/// thread's `request_repaint()` calls actually wake the UI.
#[cfg(target_os = "macos")]
fn macos_disable_app_nap() {
    use objc2_foundation::{NSActivityOptions, NSProcessInfo, NSString};
    let info = NSProcessInfo::processInfo();
    let reason = NSString::from_str("pending-badge must remain responsive in background");
    let options = NSActivityOptions::UserInteractive;
    let token = info.beginActivityWithOptions_reason(options, &reason);
    Box::leak(Box::new(token));
    super::log::log_at("badge", format_args!("disabled App Nap (UserInteractive)"));
}

#[cfg(not(target_os = "macos"))]
fn macos_disable_app_nap() {}
