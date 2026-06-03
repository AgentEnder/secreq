//! Client-side daemon protocol: auto-spawn + send + read reply.
//!
//! Used by `wrap_run` (to ask consent) and by `secreq pending` (to nudge
//! the window open).

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command};
use std::thread::sleep;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use crate::consent::Decision;

use super::proto::{Ask, ClientMsg, DaemonMsg};
use super::server;

/// Env var that disables the daemon entirely. When set to a non-empty value,
/// the client neither connects to nor spawns the daemon — every consent
/// request fails closed (the caller must use `--yes` to proceed).
///
/// Used by tests and by automation that doesn't want a GUI window to pop
/// up. Not a public CLI flag because it's a per-process kill-switch, not a
/// per-invocation preference.
pub const NO_DAEMON_ENV: &str = "SECREQ_NO_DAEMON";

/// How long the client waits for the daemon socket to appear after spawning
/// the daemon. The daemon usually binds in milliseconds; allow a generous
/// budget on cold-start (egui can take a moment to initialize).
const SPAWN_TIMEOUT: Duration = Duration::from_secs(5);

/// What the daemon's reply means to the calling wrap-and-run.
///
/// On `Approve`/`ApproveRemember`/`ApproveAuto`, `secrets` carries the
/// env-var values the daemon resolved on our behalf — the client
/// should inject them directly without re-running providers.
///
/// `rule_id` / `rule_name` are `Some` when a matching auto-rule fired,
/// so the wrap client can write a precise audit row and (on
/// `DenyAuto`) print the rule's configured `deny_message` to stderr
/// before exiting 1.
#[derive(Debug)]
pub struct ConsentOutcome {
    pub decision: Decision,
    pub secrets: HashMap<String, String>,
    pub rule_id: Option<String>,
    pub rule_name: Option<String>,
    pub deny_message: Option<String>,
}

impl ConsentOutcome {
    pub fn deny() -> ConsentOutcome {
        ConsentOutcome {
            decision: Decision::Deny,
            secrets: HashMap::new(),
            rule_id: None,
            rule_name: None,
            deny_message: None,
        }
    }
}

/// Send `ask` to the daemon, auto-spawning if no socket is live. On
/// approve, the returned outcome carries the daemon-resolved secret
/// values; on deny or any IO/parse failure, returns a deny outcome
/// (fail-closed boundary). A daemon-side resolution failure surfaces as
/// `Err` so the caller can render the real error rather than silently
/// exit 1.
pub fn request_consent(ask: Ask) -> Result<ConsentOutcome> {
    if daemon_disabled() {
        return Ok(ConsentOutcome::deny());
    }
    if !graphical_environment_available() {
        // No way to render the daemon's window — fail closed rather than
        // spawn a daemon that will exit on the spot.
        return Ok(ConsentOutcome::deny());
    }
    let socket = server::default_socket_path()?;
    let stream = connect_or_spawn(&socket)?;
    match send_and_recv(stream, ClientMsg::Ask(ask))? {
        DaemonMsg::Decision {
            decision,
            secrets,
            rule_id,
            rule_name,
            deny_message,
        } => Ok(ConsentOutcome {
            decision,
            secrets,
            rule_id,
            rule_name,
            deny_message,
        }),
        DaemonMsg::Err { message } => {
            bail!("daemon could not resolve secrets: {message}")
        }
        DaemonMsg::Ok => bail!("daemon replied Ok to an Ask (expected Decision)"),
        DaemonMsg::WindowOpened { .. } => {
            bail!("daemon replied WindowOpened to an Ask (expected Decision)")
        }
        DaemonMsg::ConsentUpdate { .. }
        | DaemonMsg::ConsentExitPlease
        | DaemonMsg::AutoDenyToast { .. } => {
            bail!("daemon sent a consent-window streaming message on a one-shot Ask connection")
        }
        DaemonMsg::RulesList { .. } => {
            bail!("daemon replied RulesList to an Ask (expected Decision)")
        }
    }
}

/// Ask the daemon to show its window. Used by `secreq pending`. Auto-
/// spawns the daemon if it isn't running; the window will auto-hide
/// once the queue empties.
///
/// The daemon's `ShowWindow` handler kills any existing consent-window
/// child and spawns a fresh one. A brand-new process gets foreground
/// focus at launch on macOS, which is the only way around macOS 14+
/// suspending the run loops of background, occluded apps (which makes
/// in-process focus-raise APIs no-ops).
pub fn show_window() -> Result<()> {
    if daemon_disabled() {
        bail!("{NO_DAEMON_ENV} is set; cannot open the consent window. Unset it and try again.");
    }
    let socket = server::default_socket_path()?;
    let stream = connect_or_spawn(&socket)?;
    expect_window_opened(send_and_recv(stream, ClientMsg::ShowWindow)?)
}

/// Ensure a daemon is running, auto-spawning a detached one if not, and
/// return once its socket is connectable. Used by bare `secreq daemon`
/// before it starts tailing the log. Sends a `Ping` (rather than just
/// dropping the connection) so the daemon doesn't log a spurious
/// "connected, sent nothing" line.
pub fn ensure_daemon_running() -> Result<()> {
    if daemon_disabled() {
        bail!(
            "{NO_DAEMON_ENV} is set; refusing to start the consent daemon. Unset it and try again."
        );
    }
    let socket = server::default_socket_path()?;
    let stream = connect_or_spawn(&socket)?;
    match send_and_recv(stream, ClientMsg::Ping)? {
        DaemonMsg::Ok => Ok(()),
        DaemonMsg::Err { message } => bail!("daemon error on ping: {message}"),
        other => bail!("unexpected reply to Ping: {other:?}"),
    }
}

/// Ask the daemon to open the window in viewer mode — pinned so the
/// auto-hide doesn't fire while the user browses the audit log. Used
/// by `secreq view`. Auto-spawns the daemon if it isn't running.
///
/// Same kill-and-respawn flow as [`show_window`]; the difference is
/// the daemon sets `viewer_mode` so the window doesn't auto-close
/// when the queue is empty.
pub fn show_viewer() -> Result<()> {
    if daemon_disabled() {
        bail!("{NO_DAEMON_ENV} is set; cannot open the consent window. Unset it and try again.");
    }
    let socket = server::default_socket_path()?;
    let stream = connect_or_spawn(&socket)?;
    expect_window_opened(send_and_recv(stream, ClientMsg::ShowViewer)?)
}

/// Type-check the daemon's reply to `ShowWindow` / `ShowViewer`.
/// We don't currently use the returned `child_pid` (the kill+respawn
/// flow makes it stale immediately) but the reply shape encodes the
/// daemon's confirmation that it accepted the request.
fn expect_window_opened(reply: DaemonMsg) -> Result<()> {
    match reply {
        DaemonMsg::WindowOpened { .. } | DaemonMsg::Ok => Ok(()),
        DaemonMsg::Err { message } => bail!("daemon error: {message}"),
        DaemonMsg::Decision { .. } => bail!("unexpected Decision reply to ShowWindow/ShowViewer"),
        DaemonMsg::ConsentUpdate { .. }
        | DaemonMsg::ConsentExitPlease
        | DaemonMsg::AutoDenyToast { .. } => {
            bail!("daemon sent a consent-window streaming message on a one-shot reply")
        }
        DaemonMsg::RulesList { .. } => {
            bail!("unexpected RulesList reply to ShowWindow/ShowViewer")
        }
    }
}

/// `secreq rules list/show`: fetch the current ruleset. Auto-spawns
/// the daemon if it isn't running so headless management works the
/// same way as wrap invocation.
pub fn list_rules() -> Result<Vec<crate::rules::Rule>> {
    if daemon_disabled() {
        bail!("{NO_DAEMON_ENV} is set; cannot reach the daemon. Unset it and try again.");
    }
    let socket = server::default_socket_path()?;
    let stream = connect_or_spawn(&socket)?;
    match send_and_recv(stream, ClientMsg::ListRules)? {
        DaemonMsg::RulesList { rules } => Ok(rules),
        DaemonMsg::Err { message } => bail!("daemon error: {message}"),
        other => bail!("unexpected reply to ListRules: {other:?}"),
    }
}

/// `secreq rules enable/disable`: flip the bit and persist.
pub fn set_rule_enabled(id: &str, enabled: bool) -> Result<()> {
    if daemon_disabled() {
        bail!("{NO_DAEMON_ENV} is set; cannot reach the daemon. Unset it and try again.");
    }
    let socket = server::default_socket_path()?;
    let stream = connect_or_spawn(&socket)?;
    let msg = ClientMsg::SetRuleEnabled {
        id: id.to_owned(),
        enabled,
    };
    match send_and_recv(stream, msg)? {
        DaemonMsg::Ok => Ok(()),
        DaemonMsg::Err { message } => bail!("daemon error: {message}"),
        other => bail!("unexpected reply to SetRuleEnabled: {other:?}"),
    }
}

/// `secreq rules rm`: delete and persist.
pub fn delete_rule(id: &str) -> Result<()> {
    if daemon_disabled() {
        bail!("{NO_DAEMON_ENV} is set; cannot reach the daemon. Unset it and try again.");
    }
    let socket = server::default_socket_path()?;
    let stream = connect_or_spawn(&socket)?;
    match send_and_recv(stream, ClientMsg::DeleteRule { id: id.to_owned() })? {
        DaemonMsg::Ok => Ok(()),
        DaemonMsg::Err { message } => bail!("daemon error: {message}"),
        other => bail!("unexpected reply to DeleteRule: {other:?}"),
    }
}

/// Tell a running daemon to exit. Used by `secreq daemon stop`, which is
/// also the way users clear the in-memory approvals cache: a fresh daemon
/// starts with an empty approvals list.
///
/// Does **not** auto-spawn: a daemon that isn't running is already in the
/// desired state (`Ok(false)` says so), so we never start one just to
/// tell it to die.
pub fn stop_daemon() -> Result<bool> {
    let socket = server::default_socket_path()?;
    let stream = match UnixStream::connect(&socket) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    match send_and_recv(stream, ClientMsg::Shutdown)? {
        DaemonMsg::Ok => Ok(true),
        DaemonMsg::Err { message } => bail!("daemon refused shutdown: {message}"),
        DaemonMsg::Decision { .. } => bail!("daemon replied Decision to Shutdown (expected Ok)"),
        DaemonMsg::WindowOpened { .. } => {
            bail!("daemon replied WindowOpened to Shutdown (expected Ok)")
        }
        DaemonMsg::ConsentUpdate { .. }
        | DaemonMsg::ConsentExitPlease
        | DaemonMsg::AutoDenyToast { .. } => {
            bail!("daemon sent a consent-window streaming message on a Shutdown reply")
        }
        DaemonMsg::RulesList { .. } => {
            bail!("daemon replied RulesList to Shutdown (expected Ok)")
        }
    }
}

/// Outcome of a force-stop. `Killed` carries the pid we SIGKILL'd so the
/// CLI can print it (useful when debugging "wait, what did we just
/// terminate?"); `NotRunning` covers both "no pidfile" and "pidfile
/// existed but the lock was free" (the previous daemon already exited).
#[derive(Debug, PartialEq, Eq)]
pub enum ForceStopOutcome {
    Killed { pid: u32 },
    NotRunning,
}

/// SIGKILL the daemon without going through the graceful protocol. The
/// escape hatch for when the daemon is wedged (UI hung, socket thread
/// deadlocked, etc.) and the polite `Shutdown` message will never get
/// processed.
///
/// Two things make this safer than a naive `kill $(cat pidfile)`:
///
/// 1. **Liveness via flock, not pid existence.** The pidfile's exclusive
///    flock is held by the daemon for as long as it runs; if *we* can
///    grab it, the daemon is gone (or never started) and the pid in the
///    file might point at an unrelated recycled process — we report
///    `NotRunning` and only clean up stale files. No `kill(pid, 0)`
///    guesswork.
///
/// 2. **RAII cleanup that the daemon itself can't do.** SIGKILL bypasses
///    the daemon's `PidGuard::drop`, so the pidfile + socket linger.
///    We remove both after a short sleep that lets the kernel release
///    the daemon's flock — otherwise the next auto-spawn would race
///    a not-yet-reaped process.
pub fn force_stop_daemon() -> Result<ForceStopOutcome> {
    let socket = server::default_socket_path()?;
    let pidfile = server::pidfile_path()?;

    match probe_pidfile_lock(&pidfile)? {
        LockState::Free => {
            // No live daemon. Clean any leftovers from a previous crash
            // so a subsequent auto-spawn has a clean slate.
            let _ = std::fs::remove_file(&pidfile);
            let _ = std::fs::remove_file(&socket);
            Ok(ForceStopOutcome::NotRunning)
        }
        LockState::Held => {
            let pid = read_pid(&pidfile)?;
            send_sigkill(pid)?;
            // Give the kernel a beat to release the daemon's flock and
            // tear down the bound socket fd. Not load-bearing for
            // correctness, but means the next auto-spawn doesn't have
            // to retry.
            sleep(Duration::from_millis(50));
            let _ = std::fs::remove_file(&pidfile);
            let _ = std::fs::remove_file(&socket);
            Ok(ForceStopOutcome::Killed { pid })
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum LockState {
    /// The flock is unheld — no daemon, or the daemon has already exited
    /// (and possibly forgotten to clean up).
    Free,
    /// Something is holding the flock — almost certainly the daemon.
    Held,
}

fn probe_pidfile_lock(path: &Path) -> Result<LockState> {
    if !path.exists() {
        return Ok(LockState::Free);
    }
    // Open without truncating so we don't disturb the running daemon's
    // pid line. The flock is per open-file-description; our fd is
    // independent of the daemon's.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(false)
        .truncate(false)
        .open(path)
        .with_context(|| format!("open pidfile {}", path.display()))?;
    let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if ret == 0 {
        // We got the lock → no daemon is running. Drop the fd to
        // release it; the file still exists for the caller to clean up.
        return Ok(LockState::Free);
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
        Ok(LockState::Held)
    } else {
        Err(err).with_context(|| format!("flock pidfile {}", path.display()))
    }
}

fn read_pid(path: &Path) -> Result<u32> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read pidfile {}", path.display()))?;
    text.trim().parse::<u32>().with_context(|| {
        format!(
            "pidfile {} contains a non-integer: {:?}",
            path.display(),
            text.trim()
        )
    })
}

fn send_sigkill(pid: u32) -> Result<()> {
    // SAFETY: libc::kill is async-signal-safe and takes a plain pid.
    let ret = unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    if ret == 0 {
        return Ok(());
    }
    let err = std::io::Error::last_os_error();
    // Race: the daemon held the lock when we probed, exited before we
    // sent the signal. Treat as "already gone" — the post-kill cleanup
    // path still removes the (now-stale) files.
    if err.raw_os_error() == Some(libc::ESRCH) {
        return Ok(());
    }
    Err(err).with_context(|| format!("kill(pid={pid}, SIGKILL)"))
}

fn daemon_disabled() -> bool {
    std::env::var_os(NO_DAEMON_ENV).is_some_and(|v| !v.is_empty())
}

/// True iff this process can plausibly render a GUI window.
///
/// macOS always has WindowServer in an interactive login; we don't try to
/// detect SSH-without-forwarding because eframe will fail loudly enough
/// for the user to recognize what happened.
///
/// On Linux/BSD we look for `$DISPLAY` (X11) or `$WAYLAND_DISPLAY`. Missing
/// both is a strong signal for "headless" — auto-spawning a daemon that
/// will crash on `winit` init wastes the spawn timeout and surprises CI.
fn graphical_environment_available() -> bool {
    if cfg!(target_os = "macos") {
        return true;
    }
    let has_x11 = std::env::var_os("DISPLAY").is_some_and(|v| !v.is_empty());
    let has_wayland = std::env::var_os("WAYLAND_DISPLAY").is_some_and(|v| !v.is_empty());
    has_x11 || has_wayland
}

fn connect_or_spawn(socket: &Path) -> Result<UnixStream> {
    // Optimistic connect first — the common case is the daemon is already
    // running.
    if let Ok(stream) = UnixStream::connect(socket) {
        return Ok(stream);
    }
    // No live daemon. Spawn one and poll for the socket. Keep the child
    // handle so we can detect early-exit (e.g. egui failing to init in a
    // headless environment) and bail without waiting the full timeout.
    let mut child = spawn_daemon().context("auto-spawn secreq daemon")?;
    let deadline = Instant::now() + SPAWN_TIMEOUT;
    let mut backoff = Duration::from_millis(20);
    while Instant::now() < deadline {
        sleep(backoff);
        if let Ok(stream) = UnixStream::connect(socket) {
            // Daemon is alive; let it run independently from here on.
            return Ok(stream);
        }
        if let Ok(Some(status)) = child.try_wait() {
            bail!(
                "consent daemon exited before binding its socket (status {status}); \
                 is a display available? try setting --yes to bypass"
            );
        }
        backoff = (backoff * 2).min(Duration::from_millis(250));
    }
    bail!(
        "consent daemon did not come up within {:?} ({} not connectable)",
        SPAWN_TIMEOUT,
        socket.display()
    )
}

/// Re-exec ourselves with the `daemon --fg` subcommand. We trust
/// `current_exe()` because the shim found us on PATH; if that's wrong,
/// the daemon would have been wrong too.
///
/// `--fg` is load-bearing: bare `secreq daemon` now means "ensure a
/// background daemon and tail its log," so spawning that form would
/// recursively launch tailers instead of an actual daemon. `--fg`
/// pins the real foreground daemon (which we detach via null stdio).
fn spawn_daemon() -> Result<Child> {
    let exe = std::env::current_exe().context("current_exe for daemon spawn")?;
    Command::new(exe)
        .arg("daemon")
        .arg("--fg")
        // Detach stdio so the daemon doesn't write to the client's tty
        // (a wrapped TUI is touchy about that).
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("spawn daemon process")
}

fn send_and_recv(stream: UnixStream, msg: ClientMsg) -> Result<DaemonMsg> {
    let line = serde_json::to_string(&msg).context("serialize client msg")?;
    let mut writer = stream.try_clone().context("clone socket for write")?;
    writeln!(writer, "{line}").context("write client msg")?;
    writer.flush().ok();

    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    if reader.read_line(&mut response)? == 0 {
        bail!("daemon closed the connection without replying");
    }
    let reply: DaemonMsg = serde_json::from_str(response.trim()).context("parse daemon reply")?;
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_pidfile_lock_reports_free_for_missing_pidfile() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("missing.pid");
        assert_eq!(
            probe_pidfile_lock(&path).expect("probe"),
            LockState::Free,
            "no pidfile means no daemon"
        );
    }

    #[test]
    fn probe_pidfile_lock_reports_free_when_lock_is_unheld() {
        // A pidfile from a crashed daemon: file exists, but nothing's
        // holding the flock. Force-stop should treat this as "not
        // running" and clean it up rather than try to kill the pid.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("stale.pid");
        std::fs::write(&path, "99999\n").expect("write pid");
        assert_eq!(probe_pidfile_lock(&path).expect("probe"), LockState::Free);
    }

    #[test]
    fn probe_pidfile_lock_reports_held_when_someone_owns_the_flock() {
        // Simulate the daemon by writing the pidfile, then holding the
        // flock on a separate fd before probing. The probe opens its own
        // fd; the flock is per-open-file-description, so its lock
        // attempt must fail with EWOULDBLOCK.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("held.pid");
        std::fs::write(&path, "12345\n").expect("write pid");
        let owner = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open owner");
        let lock_ret = unsafe { libc::flock(owner.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(lock_ret, 0, "owner takes the lock");

        assert_eq!(probe_pidfile_lock(&path).expect("probe"), LockState::Held);

        // Release for tidiness.
        let _ = unsafe { libc::flock(owner.as_raw_fd(), libc::LOCK_UN) };
    }

    #[test]
    fn read_pid_parses_a_trimmed_integer() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("ok.pid");
        std::fs::write(&path, "  42 \n").expect("write");
        assert_eq!(read_pid(&path).expect("read"), 42);
    }

    #[test]
    fn read_pid_errors_on_garbage_so_we_dont_kill_random_processes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bad.pid");
        std::fs::write(&path, "not a pid").expect("write");
        let err = read_pid(&path).expect_err("should reject garbage");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("non-integer"),
            "{msg:?} should explain the parse failure"
        );
    }
}
