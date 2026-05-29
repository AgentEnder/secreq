//! Consent daemon.
//!
//! One process per user that owns:
//! - The pending-consent queue (asks coalesce by `(wrap, ppid, start_time)`).
//! - The persistent approvals cache (loaded once, written on change).
//! - The egui window the user uses to approve / deny / bulk-resolve.
//!
//! ## Threading
//!
//! The GUI event loop must own the main thread (macOS AppKit requirement,
//! and the path of least friction on Linux/Windows). So:
//! - `main thread` = `eframe::run_native` → `ConsentApp::update` ticks.
//! - `accept thread` = `UnixListener::incoming()`; one connection worker
//!   per accept.
//! - `connection thread(s)` = block on a `mpsc::Receiver` waiting for the
//!   UI to resolve the ask.
//!
//! ## Lifecycle
//!
//! - Started by `secreq daemon` (usually auto-spawned by a wrap client
//!   that found no live socket).
//! - Singleton-enforced via a fcntl-locked pidfile: a second daemon
//!   process sees the lock held and exits 0 quietly.
//! - Idle-exits after [`ui::IDLE_EXIT_SECS`] of empty queue + no asks.

pub mod cache;
pub mod client;
pub mod proto;
pub mod server;
pub mod state;
pub mod ui;

use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};

/// Run as the daemon. Blocks until the daemon exits.
pub fn run() -> Result<i32> {
    let socket_path = server::default_socket_path()?;
    let pidfile = server::pidfile_path()?;

    // Singleton enforcement: take an exclusive fcntl lock on the pidfile.
    // If another daemon already holds it, we exit 0 — the caller can
    // simply connect to the existing socket.
    let _pid_guard = match acquire_pidfile_lock(&pidfile)? {
        Some(g) => g,
        None => {
            // Another daemon is alive. Nothing to do.
            return Ok(0);
        }
    };

    // Approvals are in-memory only — start empty, no disk load.
    let state: state::SharedState = Arc::new(Mutex::new(state::State::new()));

    let _listener =
        server::start(socket_path.clone(), state.clone()).context("start daemon socket server")?;

    // Single shutdown flag, owned by State and observed by both the
    // socket thread (via `request_shutdown`) and the UI tick.
    let shutdown_flag = state.lock().expect("state mutex").shutdown_flag();
    let app_state = state.clone();
    let app_shutdown = shutdown_flag.clone();

    let viewport = egui::ViewportBuilder::default()
        .with_title("secreq")
        .with_inner_size([520.0, 480.0])
        .with_visible(false)
        // Don't show up in the dock/taskbar until we actually need to —
        // the daemon spends most of its life hidden.
        .with_decorations(true);
    let native_opts = eframe::NativeOptions {
        viewport,
        // On macOS, hiding the window via ViewportCommand::Visible(false)
        // doesn't hide the app — it still appears in the Dock and the
        // Cmd+Tab switcher. `Accessory` activation policy removes both
        // while still letting the app gain focus when we show the
        // window for a real consent ask. Linux/BSD have no equivalent
        // problem (no app-level "always on the dock" semantics).
        #[cfg(target_os = "macos")]
        event_loop_builder: Some(Box::new(|builder| {
            use winit::platform::macos::{ActivationPolicy, EventLoopBuilderExtMacOS};
            builder.with_activation_policy(ActivationPolicy::Accessory);
        })),
        ..Default::default()
    };

    // eframe::run_native blocks the main thread until the window closes.
    // Idle-exit fires `ViewportCommand::Close`, which returns control here.
    let result = eframe::run_native(
        "secreq",
        native_opts,
        Box::new(move |cc| {
            // Attach the egui context so the socket thread can request
            // repaints when the queue changes.
            app_state
                .lock()
                .expect("state mutex")
                .attach_egui(cc.egui_ctx.clone());
            ui::install_fonts(&cc.egui_ctx);
            Ok(Box::new(ui::ConsentApp::new(app_state, app_shutdown)))
        }),
    );

    // Clean up: remove the socket file so the next daemon can bind it.
    let _ = std::fs::remove_file(&socket_path);
    drop(shutdown_flag);

    result.map_err(|e| anyhow::anyhow!("eframe run failed: {e}"))?;
    Ok(0)
}

/// RAII guard for an exclusive lock on the pidfile.
struct PidGuard {
    _file: std::fs::File,
    path: PathBuf,
}

impl Drop for PidGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Try to take the daemon-singleton lock. Returns `Ok(Some(_))` if we got
/// it (this process should run the daemon), `Ok(None)` if another daemon
/// already holds it (this process should exit).
fn acquire_pidfile_lock(path: &PathBuf) -> Result<Option<PidGuard>> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)
        .with_context(|| format!("open pidfile {}", path.display()))?;
    // Non-blocking exclusive lock. If held, another daemon owns it.
    let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
            return Ok(None);
        }
        return Err(err).context("flock pidfile");
    }
    // Write our pid for human inspection — not load-bearing for liveness.
    use std::io::Write;
    let mut writer = &file;
    let _ = writeln!(writer, "{}", std::process::id());
    Ok(Some(PidGuard {
        _file: file,
        path: path.clone(),
    }))
}
