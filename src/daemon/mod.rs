//! Consent daemon — **headless background service**.
//!
//! The daemon process owns:
//! - The pending-consent queue (asks coalesce by `(wrap, ppid, start_time)`).
//! - The in-memory approvals cache.
//! - A Unix socket where wrap clients submit `Ask`s and consent-window
//!   child processes stream snapshots back and forth.
//!
//! The daemon has **no GUI of its own**. When something needs to be
//! shown to the user (an `Ask` queued, `ShowViewer`, `ShowWindow`), the
//! socket handler calls [`ensure_consent_window`], which spawns a
//! `secreq consent-window` child process if one isn't already
//! attached. The child opens its own `eframe::run_native`, talks to the
//! daemon over the socket, and exits when the user closes its NSWindow.
//!
//! This shape exists because trying to manage a long-lived hidden
//! NSWindow inside a single eframe process fights macOS' App Nap,
//! run-loop suspension for hidden windows, and the multi-viewport
//! lifecycle bug in eframe's glow + wgpu backends. A short-lived child
//! per session is a real foreground app the OS understands.

pub mod badge;
pub mod cache;
pub mod child;
pub mod client;
pub mod in_flight;
pub mod log;
pub mod peercred;
pub mod proto;
pub mod server;
pub mod ssh_agent;
pub mod ssh_proto;
pub mod state;
pub mod ui;

use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};

/// How long the daemon stays alive with no activity AND no attached
/// consent window before exiting on its own. "Activity" is anything
/// that calls `state.touch()` — a wrap ask, a `secreq pending`, a
/// `Ping`, a resolved decision. An attached consent-window child
/// continuously suppresses the timeout via the keepalive in the
/// daemon's main loop, so leaving `secreq view` open for hours
/// won't trigger an exit.
const IDLE_EXIT_SECS: u64 = 2 * 60 * 60;

/// Cadence at which the main loop wakes to (a) check the shutdown
/// flag, (b) refresh the UI-attached keepalive, (c) evaluate
/// idle-exit, and (d) evaluate the auto-hide grace for the consent
/// window. One-second granularity is fine for a 2-hour timeout —
/// finer granularity just burns CPU on a sleeping daemon.
const MAIN_LOOP_TICK: Duration = Duration::from_secs(1);

/// How long the "All clear" empty-queue state lingers before the daemon
/// tells the consent window to exit — but *only* for a window the user
/// browsed away from (Rules/Audit) this session. A decision-only window
/// (nothing but Approve/Deny) skips this grace entirely and closes the
/// instant the queue drains, via `State::maybe_immediate_auto_hide` on
/// the resolve path; there's no confirmation worth lingering over, and
/// hanging around just reads as sluggish. This grace is the softer close
/// for the browsed case: long enough not to yank a window mid-glance,
/// short enough to still feel tidy. Suppressed entirely when
/// `viewer_mode` is set (the user pinned the audit log open).
const AUTO_HIDE_GRACE: Duration = Duration::from_secs(2);

/// Cadence at which the daemon samples its own CPU/memory and writes a
/// `resource` line to the persistent log. Coarse on purpose: the main
/// loop ticks every second, but refreshing sysinfo that often would
/// burn CPU on an otherwise-sleeping daemon (the very thing we're
/// monitoring for). One sample per minute is plenty to chart the
/// daemon's footprint over a long-lived session, and sysinfo derives
/// CPU% as the average over the gap between samples — so a 60s cadence
/// reports the daemon's mean CPU across each minute.
const RESOURCE_SAMPLE_INTERVAL: Duration = Duration::from_secs(60);

/// Decide whether the headless daemon should idle-exit on this tick.
///
/// The base idle condition is the same as it ever was: the pending
/// queue is empty (`queue_empty`) AND no activity has happened for
/// longer than [`IDLE_EXIT_SECS`] (`idle_elapsed`). But when the SSH
/// agent is enabled, `SSH_AUTH_SOCK` points at the daemon's
/// `agent.sock`; an idle-exit would yank that socket out from under
/// every SSH client, so we never idle-exit in that mode regardless of
/// how long the queue has sat empty.
///
/// `ssh_agent_enabled` is fixed for the daemon's lifetime — the config
/// is loaded exactly once at startup (see [`run`]), so capturing it as
/// a single bool there is sufficient.
fn should_idle_exit(queue_empty: bool, idle_elapsed: bool, ssh_agent_enabled: bool) -> bool {
    if ssh_agent_enabled {
        return false;
    }
    queue_empty && idle_elapsed
}

/// Run as the daemon. Blocks until `ClientMsg::Shutdown` arrives or
/// SIGTERM. There's no GUI on this thread.
pub fn run() -> Result<i32> {
    let socket_path = server::default_socket_path()?;
    let pidfile = server::pidfile_path()?;

    log::log(format_args!(
        "daemon starting (pid={}, socket={}, pidfile={})",
        std::process::id(),
        socket_path.display(),
        pidfile.display()
    ));

    let _pid_guard = match acquire_pidfile_lock(&pidfile)? {
        Some(g) => g,
        None => {
            log::log(format_args!(
                "another daemon already holds the pidfile lock — exiting 0"
            ));
            return Ok(0);
        }
    };

    let state: state::SharedState = match crate::rules::default_rules_path() {
        Some(path) => Arc::new(Mutex::new(state::State::with_rules_path(path))),
        None => Arc::new(Mutex::new(state::State::new())),
    };
    let shutdown_flag = state.lock().expect("state mutex").shutdown_flag();

    let _listener =
        server::start(socket_path.clone(), state.clone()).context("start daemon socket server")?;

    // SSH agent listener. A second socket (`agent.sock`) speaking the SSH
    // agent protocol, started only when `wraps.json5` declares any `ssh`
    // identities. Held alive for the daemon's lifetime alongside the
    // control listener; its accept thread exits when this drops. A missing
    // or unparseable config simply yields no agent (best-effort) — the
    // control socket and existing wrap flow are unaffected.
    let _agent_listener = match crate::wraps::default_config_path() {
        Some(config_path) => match crate::wraps::WrapsConfig::load(&config_path) {
            Ok(mut config) if !config.ssh.is_empty() => {
                // Overlay built-in providers so a private-key reference can
                // name a built-in scheme (e.g. `secret://op/...`) without an
                // explicit `providers` block — same resolution surface the
                // wrap path gets via `load_config_or_default`.
                config.merge_builtin_providers();
                let agent_socket = server::default_agent_socket_path()?;
                server::start_ssh_agent(
                    agent_socket,
                    &config.ssh,
                    config.providers.clone(),
                    state.clone(),
                )
                .context("start ssh agent listener")?
            }
            Ok(_) => None,
            Err(err) => {
                log::log(format_args!(
                    "ssh agent: could not load config ({err:#}); agent disabled"
                ));
                None
            }
        },
        None => None,
    };

    // Whether the SSH agent is serving on `agent.sock`. Fixed for the
    // daemon's lifetime — the config is loaded exactly once above, so a
    // single bool captured here is sufficient. When set, the idle-exit
    // path is suppressed so `SSH_AUTH_SOCK` (which points at the agent
    // socket) never goes stale under a running SSH client. See
    // `should_idle_exit`.
    let ssh_agent_enabled = _agent_listener.is_some();

    log::log(format_args!(
        "daemon ready; entering main loop (idle exit after {}s, resource sampling every {}s)",
        IDLE_EXIT_SECS,
        RESOURCE_SAMPLE_INTERVAL.as_secs()
    ));

    // Headless main loop. Wakes once per second to check the shutdown
    // flag, refresh the UI keepalive, and evaluate idle-exit. The
    // socket accept loop runs in its own thread and does the real work
    // — this loop is just a lifetime governor.
    let idle_timeout = Duration::from_secs(IDLE_EXIT_SECS);

    // Resource-usage sampler. Primed once here so the first real sample
    // has a CPU baseline to diff against; thereafter the main loop emits
    // one sample every `RESOURCE_SAMPLE_INTERVAL`. The `System` is held
    // across ticks because sysinfo computes a process's CPU% from the
    // delta between consecutive refreshes of that same `System`.
    let mut resource_sys = log::prime_resource_sampler();
    let mut last_resource_sample = std::time::Instant::now();

    while !shutdown_flag.load(Ordering::SeqCst) {
        std::thread::sleep(MAIN_LOOP_TICK);

        if last_resource_sample.elapsed() >= RESOURCE_SAMPLE_INTERVAL {
            log::sample_resources(&mut resource_sys);
            last_resource_sample = std::time::Instant::now();
        }

        let mut guard = state.lock().expect("state mutex");
        if guard.consent_subscriber_count() > 0 {
            // While a consent window is on screen the user might be
            // browsing the audit log indefinitely — keep the daemon
            // alive by resetting the idle clock every tick.
            guard.touch();

            // Auto-hide: if the queue has been empty for the grace
            // period AND we're not in viewer mode AND the user isn't
            // currently focused on the window, tell the consent
            // window to exit. The "All clear" state has been on screen
            // long enough that the user has seen the confirmation;
            // hanging the window indefinitely after a single approval
            // is noisy desktop clutter.
            //
            // Skip the auto-hide only when the user is interacting with
            // a non-Pending tab (Rules / Audit) — e.g. scrolling the
            // audit log after clearing the queue — where yanking the
            // window away mid-scroll is exactly the surprise we want to
            // avoid. A window focused on the empty Pending tab ("All
            // clear") is NOT interacting, so it still hides: there's
            // nothing there to interrupt. The grace clock isn't reset;
            // the next tick after the user leaves the other tab (or the
            // window loses focus) resumes the countdown.
            let should_auto_hide = !guard.viewer_mode()
                && !guard.any_consent_interacting()
                && guard
                    .queue_empty_since()
                    .is_some_and(|t| t.elapsed() >= AUTO_HIDE_GRACE);
            if should_auto_hide {
                log::log(format_args!(
                    "queue drained {}s ago and not in viewer mode; auto-hiding consent window",
                    AUTO_HIDE_GRACE.as_secs()
                ));
                guard.broadcast_consent_exit_please();
            }
        } else if should_idle_exit(
            guard.queue_is_empty(),
            guard.last_activity().elapsed() >= idle_timeout,
            ssh_agent_enabled,
        ) {
            log::log(format_args!(
                "no activity for {}s and no UI attached; initiating idle-exit",
                IDLE_EXIT_SECS
            ));
            // `request_shutdown` flips the flag we're observing AND
            // broadcasts `ConsentExitPlease` to any attached child
            // (defensive — we just checked there were none, but this
            // is the canonical "shut everything down" call).
            guard.request_shutdown();
        }

        // Pending-badge lifecycle — independent of the consent window.
        // The badge floats "N pending" over other apps while asks await
        // a decision, so a backgrounded or closed consent window can't
        // be forgotten with processes still hung. It vanishes the moment
        // the queue drains, and is re-spawned here if it ever crashes
        // while asks remain. Done as a separate block (not folded into
        // the consent if/else above) precisely because the badge must
        // outlive a closed consent window.
        let ensure_badge = if guard.queue_is_empty() {
            if guard.badge_subscriber_count() > 0 {
                log::log_at("badge", format_args!("queue drained; dismissing badge"));
                guard.broadcast_badge_exit_please();
            }
            false
        } else {
            guard.needs_badge_window() && !guard.badge_spawn_in_flight()
        };
        drop(guard);
        if ensure_badge {
            if let Err(err) = ensure_badge_window(&state) {
                log::log_at(
                    "badge",
                    format_args!("main-loop ensure_badge_window failed: {err:#}"),
                );
            }
        }
    }

    log::log(format_args!("shutdown flag observed; cleaning up"));
    // Defensive: if the shutdown was triggered by `ClientMsg::Shutdown`
    // (vs. our idle path), there may be a consent child still attached.
    // `request_shutdown` already broadcast `ConsentExitPlease` to it
    // — but only if it was attached at that moment. Re-broadcast here
    // to catch any child that attached between the request and now.
    {
        let mut guard = state.lock().expect("state mutex");
        guard.broadcast_consent_exit_please();
        // Same for any badge child that attached between the shutdown
        // request and now.
        guard.broadcast_badge_exit_please();
    }
    let _ = std::fs::remove_file(&socket_path);
    log::log(format_args!("daemon exiting cleanly"));
    Ok(0)
}

/// Spawn a `secreq consent-window` child process if one isn't already
/// attached and we aren't already mid-spawn. Called from the socket
/// handler after any state mutation that the user should see (Ask
/// queued, viewer requested, window requested).
///
/// The child re-uses the same binary (`std::env::current_exe()`) so a
/// dev `cargo run` and an installed `secreq` both work correctly.
pub fn ensure_consent_window(state: &state::SharedState) -> Result<()> {
    let mut guard = state.lock().expect("state mutex");
    if !guard.needs_consent_window() {
        return Ok(());
    }
    if guard.consent_spawn_in_flight() {
        return Ok(());
    }
    // Defer the spawn if a restart is pending: the dying child's
    // detach handler will fire `ensure_consent_window` once its
    // process actually exits, so by spawning then (and not now) we
    // guarantee strict "old window gone before new window appears"
    // sequencing.
    if guard.is_consent_restart_pending() {
        return Ok(());
    }
    // Float the window over other apps when it was opened to demand a
    // decision (an Ask from a wrap run or an SSH-agent sign) — those are
    // interruptions the user needs to see now. When it was opened by
    // `secreq view` (viewer mode), it's a passive inspection surface the
    // user chose to open, so leave it as a normal window.
    let always_on_top = !guard.viewer_mode();
    let exe = std::env::current_exe().context("locate current executable")?;
    log::log_at(
        "spawn",
        format_args!(
            "spawning consent-window child: {} consent-window{}",
            exe.display(),
            if always_on_top {
                " --always-on-top"
            } else {
                ""
            }
        ),
    );
    guard.mark_consent_spawn_in_flight();
    drop(guard);
    let mut command = std::process::Command::new(exe);
    command.arg("consent-window");
    if always_on_top {
        command.arg("--always-on-top");
    }
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .context("spawn consent-window child")?;
    Ok(())
}

/// Whether the platform honours an always-on-top window. macOS and X11
/// do; Wayland forbids override-redirect always-on-top, so we detect it
/// and degrade to a normal window rather than promise a behaviour the
/// compositor will silently ignore. Shared by the consent window
/// (`child.rs`) and the pending badge (`badge.rs`).
#[cfg(target_os = "macos")]
pub(crate) fn always_on_top_supported() -> bool {
    true
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn always_on_top_supported() -> bool {
    std::env::var_os("WAYLAND_DISPLAY").is_none()
}

/// Spawn a `secreq pending-badge` child if one is needed (queue
/// non-empty) and none is attached or mid-spawn. The badge is the
/// always-on-top "N pending" pill that floats over other apps so a
/// backgrounded consent window can't be forgotten with processes still
/// hung on a decision.
///
/// Skipped entirely where always-on-top isn't honoured (Wayland): a
/// badge that can neither stay on top nor pin itself to a corner is just
/// a redundant window, so it earns its keep only on platforms where it
/// can actually float. The consent window still appears there — it's the
/// real UI, not a redundant overlay.
///
/// Called both at submit time (so the badge appears immediately on the
/// first pending ask) and from the daemon's main loop (so a crashed
/// badge is re-spawned while the queue is still non-empty). The
/// `needs_badge_window` / `badge_spawn_in_flight` guards make repeated
/// calls idempotent.
pub fn ensure_badge_window(state: &state::SharedState) -> Result<()> {
    if !always_on_top_supported() {
        return Ok(());
    }
    let mut guard = state.lock().expect("state mutex");
    if !guard.needs_badge_window() {
        return Ok(());
    }
    if guard.badge_spawn_in_flight() {
        return Ok(());
    }
    let exe = std::env::current_exe().context("locate current executable")?;
    log::log_at(
        "spawn",
        format_args!(
            "spawning pending-badge child: {} pending-badge",
            exe.display()
        ),
    );
    guard.mark_badge_spawn_in_flight();
    drop(guard);
    std::process::Command::new(exe)
        .arg("pending-badge")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .context("spawn pending-badge child")?;
    Ok(())
}

/// RAII guard for the daemon-singleton lock. Holds the locked pidfile
/// open; the exclusive `flock` is released when the inner `File` drops at
/// process exit.
///
/// It deliberately does **not** unlink the pidfile. `flock` binds to the
/// file's *inode*, not its name — so removing the pidfile on exit lets the
/// next `open(O_CREAT)` mint a fresh inode, and a `flock` on that new inode
/// does not exclude a still-alive daemon holding the old (now-nameless)
/// inode's lock. That inode churn is exactly how a restart burst left
/// multiple daemons running at once. Leaving the file in place means every
/// daemon locks the *same* inode, so the flock actually enforces the
/// singleton. A leftover pidfile with no live flock is harmless — the next
/// daemon reuses it.
struct PidGuard {
    _file: std::fs::File,
}

/// Try to take the daemon-singleton lock. Returns `Ok(Some(_))` if we got
/// it (this process should run the daemon), `Ok(None)` if another daemon
/// already holds it (this process should exit).
fn acquire_pidfile_lock(path: &PathBuf) -> Result<Option<PidGuard>> {
    use std::os::unix::fs::MetadataExt;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Retry a few times to cover the narrow window between our `open` and
    // our `flock` in which another process could unlink+recreate the
    // pidfile (e.g. a concurrent `secreq daemon stop` cleanup). Each miss
    // reopens against the current file.
    for _ in 0..5 {
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
        // Verify the inode we locked is still the file living at `path`. If
        // it was unlinked+recreated between our `open` and our `flock`, our
        // lock is on a stale, nameless inode that no longer guards the
        // pidfile — drop it and retry against the current file.
        let locked = file.metadata().ok().map(|m| (m.dev(), m.ino()));
        let current = std::fs::metadata(path).ok().map(|m| (m.dev(), m.ino()));
        if locked.is_none() || locked != current {
            // `file` drops here, releasing the stale lock; the loop reopens.
            continue;
        }
        // We hold the lock on the current pidfile. Record our pid for human
        // inspection (not load-bearing for liveness) — truncate first so the
        // file shows only the live owner, not a prior generation's pid.
        use std::io::Write;
        let _ = file.set_len(0);
        let mut writer = &file;
        let _ = writeln!(writer, "{}", std::process::id());
        return Ok(Some(PidGuard { _file: file }));
    }
    // We kept losing the inode race — another daemon is actively managing
    // the pidfile. Safer to exit than to risk running a second daemon.
    log::log(format_args!(
        "pidfile inode kept changing under us; assuming another daemon owns it — exiting"
    ));
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::{acquire_pidfile_lock, should_idle_exit};

    #[test]
    fn pidfile_lock_is_exclusive_and_persists_across_release() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("daemon.pid");

        let g1 = acquire_pidfile_lock(&path).expect("acquire");
        assert!(g1.is_some(), "first acquire wins the lock");

        // A second acquire while the first is held must be refused — this is
        // the singleton invariant.
        assert!(
            acquire_pidfile_lock(&path)
                .expect("second acquire")
                .is_none(),
            "a second acquire is refused while the lock is held"
        );

        // The actual fix: releasing the guard must NOT unlink the pidfile.
        // Unlinking is what let the next open(O_CREAT) mint a fresh inode and
        // defeat flock (the 8-daemon leak); leaving the file in place means
        // every daemon locks the *same* inode, so the flock stays
        // authoritative across restarts.
        drop(g1);
        assert!(
            path.exists(),
            "the pidfile persists after the guard drops (no inode churn)"
        );

        // (We don't assert re-acquire-after-drop here: that would hinge on
        // the OS making a same-process flock *release* visible to an
        // immediate re-flock, which races under parallel test load. The
        // production path is cross-process — the prior holder is a fully
        // dead process before a new one locks — so it isn't affected.)
    }

    #[test]
    fn idle_exit_disabled_when_ssh_agent_enabled() {
        // Otherwise-idle daemon (empty queue, timeout elapsed) must
        // NOT exit while the SSH agent is enabled — `SSH_AUTH_SOCK`
        // depends on the daemon's `agent.sock` staying alive.
        assert!(!should_idle_exit(true, true, true));
    }

    #[test]
    fn wrap_only_idle_behavior_preserved() {
        // With no SSH identities the existing behavior is unchanged:
        // exit only when the queue is empty AND the timeout elapsed.
        assert!(should_idle_exit(true, true, false));
        assert!(!should_idle_exit(false, true, false));
        assert!(!should_idle_exit(true, false, false));
    }
}
