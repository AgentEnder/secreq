//! `secreq daemon …` — the daemon's own lifecycle verbs: stop, status, the
//! log tail, and the login-service installer.
//!
//! Nothing here runs the daemon; `secreq daemon --fg` is dispatched straight
//! into [`crate::daemon`] by the CLI. [`daemon_install_core`] is shared with
//! the `ssh setup` flow, which offers the login service as its second step —
//! the agent socket only exists while the daemon runs.

use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::Path;
use std::thread::sleep;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use crate::autostart;
use crate::daemon::client as daemon_client;

use super::prompt;

/// `secreq daemon stop` — tell the running daemon to exit. The daemon's
/// approvals cache lives in memory only, so this is also how you clear
/// any "approve all" decisions you made earlier — the next wrap
/// invocation auto-spawns a fresh daemon with an empty cache.
///
/// With `force=true`, skips the graceful socket protocol and SIGKILLs
/// the daemon directly. The escape hatch for when the daemon is wedged.
pub fn daemon_stop(force: bool) -> Result<i32> {
    if force {
        match daemon_client::force_stop_daemon()
            .context("could not force-stop the consent daemon")?
        {
            daemon_client::ForceStopOutcome::Killed { pid } => {
                eprintln!("secreq: daemon (pid {pid}) killed (approvals cache cleared).");
            }
            daemon_client::ForceStopOutcome::NotRunning => {
                eprintln!("secreq: no daemon was running (approvals cache already clear).");
            }
        }
        return Ok(0);
    }
    if daemon_client::stop_daemon().context("could not stop the consent daemon")? {
        eprintln!("secreq: daemon stopped (approvals cache cleared).");
        Ok(0)
    } else {
        eprintln!("secreq: no daemon was running (approvals cache already clear).");
        Ok(0)
    }
}

/// `secreq daemon status` — report whether a daemon is running, without
/// spawning one. Exit code follows the `systemctl status` convention so
/// scripts can branch on it: `0` when a daemon is running, [`STATUS_EXIT_NOT_RUNNING`]
/// when none is. The pid is decided by the pidfile flock, so it's always a
/// live process; the build id comes from the `Hello` handshake and is absent
/// when the daemon holds the lock but doesn't answer (wedged).
pub fn daemon_status() -> Result<i32> {
    let socket = crate::daemon::server::default_socket_path()?;
    let log = crate::daemon::log::log_path()?;
    match daemon_client::daemon_status().context("could not query the consent daemon")? {
        daemon_client::DaemonStatus::NotRunning => {
            println!("secreq daemon: not running");
            println!("  socket: {} (created on next spawn)", socket.display());
            println!("  log:    {}", log.display());
            Ok(STATUS_EXIT_NOT_RUNNING)
        }
        daemon_client::DaemonStatus::Running { pid, build_id } => {
            println!("secreq daemon: running");
            println!("  pid:    {pid}");
            match build_id {
                Some(id) if id == crate::BUILD_ID => {
                    println!("  build:  {id} (matches this CLI)");
                }
                Some(id) => {
                    println!("  build:  {id} (stale; this CLI is {})", crate::BUILD_ID);
                }
                None => {
                    println!("  build:  unknown (daemon holds the lock but isn't answering)");
                }
            }
            println!("  socket: {}", socket.display());
            println!("  log:    {}", log.display());
            Ok(0)
        }
    }
}

/// Exit code for `secreq daemon status` when no daemon is running. Mirrors
/// `systemctl status`'s "program is not running" code so shell scripts can
/// branch on `secreq daemon status` the same way.
const STATUS_EXIT_NOT_RUNNING: i32 = 3;

/// How many trailing lines of the existing log to print before
/// following, matching the familiar `tail -f` default feel (but a touch
/// larger — daemon lines are terse and a session's worth of context is
/// useful when you've just attached).
const TAIL_INITIAL_LINES: usize = 50;

/// Poll cadence for the log follower. The log is low-volume (a handful
/// of lines per consent flow, one resource sample per minute), so a
/// fifth-of-a-second poll feels live without busy-spinning.
const TAIL_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// How long to wait for the log file to appear after spawning a fresh
/// daemon before giving up. The daemon writes its first line within
/// milliseconds of starting.
const TAIL_OPEN_TIMEOUT: Duration = Duration::from_secs(5);

/// `secreq daemon` (the default action) — ensure a daemon is running in
/// the background (spawning a detached one if needed), then tail its
/// persistent log until interrupted. `secreq daemon --fg` runs the
/// daemon in the foreground instead (handled in the CLI dispatch).
pub fn daemon_tail() -> Result<i32> {
    daemon_client::ensure_daemon_running()
        .context("could not start or reach the consent daemon")?;
    let path = crate::daemon::log::log_path()?;
    eprintln!(
        "secreq: daemon running; tailing {} (Ctrl-C to stop)",
        path.display()
    );
    tail_follow(&path)
}

/// `secreq daemon log-path` — print the persistent daemon log path and
/// exit. Scripts use this to locate the log without knowing the XDG
/// layout; it never starts a daemon.
pub fn daemon_log_path() -> Result<i32> {
    println!("{}", crate::daemon::log::log_path()?.display());
    Ok(0)
}

/// `secreq daemon install` — install (or `--undo`) a per-user login service
/// that runs `secreq daemon --fg` at login and keeps it alive.
///
/// WHY: the SSH agent socket only exists while the daemon runs. Wraps
/// auto-spawn the daemon on demand, but an incoming SSH connection has nothing
/// to spawn it — so `SSH_AUTH_SOCK` points at a dead socket unless the daemon
/// already happens to be up. A login service keeps it live.
///
/// Writing the service file is pure ([`autostart::plan`]/[`autostart::apply`]);
/// loading it shells out to `launchctl`/`systemctl`
/// ([`autostart::load_service`]). If the load step fails (e.g. a headless
/// Linux box without a user bus), we still report the file was written and how
/// to load it by hand rather than hard-failing.
pub fn daemon_install(undo: bool, assume_yes: bool) -> Result<i32> {
    daemon_install_core(undo, assume_yes)?;
    Ok(0)
}

/// The reusable body of `secreq daemon install`, shared with the `ssh setup`
/// orchestrator's auto-start step. Returns `Ok(())` once the service file is
/// written (or undone); the standalone command wraps it for an exit code.
pub(super) fn daemon_install_core(undo: bool, assume_yes: bool) -> Result<()> {
    let platform = autostart::current_platform();
    let home = dirs::home_dir().context("could not determine $HOME")?;
    let service_file = autostart::service_file_path(&home, platform);

    crate::term::soft_reset();
    if undo {
        cliclack::intro("secreq daemon install --undo")?;
        // Best-effort unload first; an unloaded-already service isn't an error
        // we should stop on.
        if let Err(err) = autostart::unload_service(platform, &service_file) {
            cliclack::log::warning(crate::term::wrap_log_text(&format!(
                "couldn't unload the service (it may not have been loaded): {err:#}"
            )))?;
        }
        if autostart::remove(&home, platform)? {
            cliclack::log::success(crate::term::wrap_log_text(&format!(
                "Removed {}.",
                crate::daemon::ui::abbreviate_home(&service_file.display().to_string())
            )))?;
        } else {
            cliclack::log::info("No secreq login service found — nothing to remove.")?;
        }
        cliclack::outro("Done.")?;
        return Ok(());
    }

    let exe = std::env::current_exe().context("could not determine the secreq executable path")?;
    // Canonicalize when we can so the service points at a stable path (resolves
    // symlinks like a homebrew shim); fall back to the raw path otherwise.
    let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
    let log_path = crate::daemon::log::log_path()?;

    let plan = autostart::plan(&home, platform, &exe, &log_path)?;

    cliclack::intro("secreq daemon install")?;
    cliclack::note(
        "I'll install a login service",
        format!(
            "{}\n\n{}",
            crate::term::wrap_note_text(&format!(
                "Writing to {}:",
                crate::daemon::ui::abbreviate_home(&plan.service_file.display().to_string())
            )),
            plan.contents
        ),
    )?;
    if plan.already_installed {
        cliclack::log::info(crate::term::wrap_log_text(
            "A service file already exists; it'll be rewritten (the exe path may have changed).",
        ))?;
    }

    let proceed = assume_yes || prompt::confirm_default_yes("Write and load it?")?;
    if !proceed {
        cliclack::log::info("Skipped — no files changed.")?;
        cliclack::outro("Done.")?;
        return Ok(());
    }

    let changed = autostart::apply(&plan)?;
    let service_display =
        crate::daemon::ui::abbreviate_home(&plan.service_file.display().to_string());
    if changed {
        cliclack::log::success(crate::term::wrap_log_text(&format!(
            "wrote {service_display}."
        )))?;
    } else {
        cliclack::log::info(crate::term::wrap_log_text(&format!(
            "{service_display} was already up to date."
        )))?;
    }

    match autostart::load_service(platform, &plan.service_file) {
        Ok(()) => {
            cliclack::log::success(
                "Loaded the login service — the daemon is running now and will start at login.",
            )?;
            let hint = match platform {
                autostart::Platform::Macos => "launchctl list | grep secreq",
                autostart::Platform::Linux => "systemctl --user status secreq",
            };
            cliclack::log::info(format!("Check status with: {hint}"))?;
        }
        Err(err) => {
            // Don't hard-fail after writing — the file is in place; tell the
            // user how to load it manually.
            cliclack::log::warning(crate::term::wrap_log_text(&format!(
                "couldn't load the service automatically: {err:#}"
            )))?;
            let manual = match platform {
                autostart::Platform::Macos => format!(
                    "launchctl bootstrap gui/$(id -u) {}",
                    plan.service_file.display()
                ),
                autostart::Platform::Linux => {
                    "systemctl --user daemon-reload && systemctl --user enable --now secreq.service"
                        .to_owned()
                }
            };
            // Only the sentence is wrapped. `manual` is a command the reader
            // is meant to paste, and `wrap_log_text` breaks at spaces — of
            // which a shell command has plenty — so putting it through the
            // wrapper would publish a command that does not run. It keeps its
            // absolute path for the same reason `path_setup::manual_export_line`
            // does: what we hand someone to paste has to be true in whatever
            // shell they paste it into.
            cliclack::log::info(format!(
                "{}\n  {manual}",
                crate::term::wrap_log_text("The file is written; load it by hand with:")
            ))?;
        }
    }

    cliclack::outro("Done.")?;
    Ok(())
}

/// Print the tail of `path` then follow appended lines, `tail -f`-style.
/// Diverges until the process is interrupted (Ctrl-C); only an IO error
/// returns. Relies on the log sink writing whole lines atomically, so
/// every chunk we read ends on a line (and UTF-8) boundary.
fn tail_follow(path: &Path) -> Result<i32> {
    let mut file = open_log_with_retry(path)?;

    // Print the last `TAIL_INITIAL_LINES` lines of existing content.
    let mut existing = String::new();
    file.read_to_string(&mut existing)
        .with_context(|| format!("read daemon log {}", path.display()))?;
    let mut stdout = std::io::stdout();
    let lines: Vec<&str> = existing.lines().collect();
    let start = lines.len().saturating_sub(TAIL_INITIAL_LINES);
    for line in lines.iter().skip(start) {
        let _ = writeln!(stdout, "{line}");
    }
    let _ = stdout.flush();

    // Follow appends. `pos` tracks how far we've consumed; a shrink
    // means the file was truncated/replaced, so we restart from the top.
    let mut pos = file
        .stream_position()
        .with_context(|| format!("seek daemon log {}", path.display()))?;
    loop {
        sleep(TAIL_POLL_INTERVAL);
        let len = std::fs::metadata(path)
            .with_context(|| format!("stat daemon log {}", path.display()))?
            .len();
        if len < pos {
            pos = 0;
        }
        if len > pos {
            file.seek(SeekFrom::Start(pos))
                .with_context(|| format!("seek daemon log {}", path.display()))?;
            let mut chunk = String::new();
            let read = file
                .read_to_string(&mut chunk)
                .with_context(|| format!("read daemon log {}", path.display()))?;
            let _ = stdout.write_all(chunk.as_bytes());
            let _ = stdout.flush();
            pos += read as u64;
        }
    }
}

/// Open the log file, retrying briefly: a daemon we just spawned may not
/// have created it yet.
fn open_log_with_retry(path: &Path) -> Result<File> {
    let deadline = Instant::now() + TAIL_OPEN_TIMEOUT;
    loop {
        match File::open(path) {
            Ok(file) => return Ok(file),
            Err(_) if Instant::now() < deadline => sleep(Duration::from_millis(50)),
            Err(err) => {
                return Err(err).with_context(|| format!("open daemon log {}", path.display()));
            }
        }
    }
}
