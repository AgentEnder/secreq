//! Client-side daemon protocol: auto-spawn + send + read reply.
//!
//! Used by `wrap_run` (to ask consent) and by `secreq pending` (to nudge
//! the window open).

use std::collections::HashMap;
use std::io::{BufRead, BufReader, IsTerminal, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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

/// Env var that silences the wrap's stderr "waiting for approval" indicator
/// for this invocation, overriding the `$wait_indicator` config setting. Set
/// to any non-empty value to suppress the spinner / waiting line — useful in
/// CI or scripts where the config can't be edited.
pub const NO_WAIT_INDICATOR_ENV: &str = "SECREQ_NO_WAIT_INDICATOR";

/// How long the client waits for the daemon socket to appear after spawning
/// the daemon. The daemon usually binds in milliseconds; allow a generous
/// budget on cold-start (egui can take a moment to initialize).
const SPAWN_TIMEOUT: Duration = Duration::from_secs(5);

/// How long the client waits for a stale daemon to release its singleton
/// pidfile lock after being asked to shut down, before force-killing it.
/// The graceful path is near-instant (the daemon's main loop ticks every
/// second and exits on the shutdown flag); this budget covers a wedged or
/// busy daemon.
const RESTART_TIMEOUT: Duration = Duration::from_secs(5);

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
pub fn request_consent(ask: Ask, show_indicator: bool) -> Result<ConsentOutcome> {
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
    // Surface a "waiting for approval" indicator on stderr while we block on
    // the daemon's decision, so the terminal doesn't sit silent. Dropped (and
    // the line cleared) the moment the reply lands or the send/recv errors.
    // Gated by the `$wait_indicator` config (passed in) and the
    // `SECREQ_NO_WAIT_INDICATOR` env override.
    let wrap_label = ask.dedupe_key.wrap.clone();
    let _indicator = (show_indicator && !wait_indicator_silenced_by_env())
        .then(|| WaitIndicator::start(&wrap_label));
    let reply = send_and_recv(stream, ClientMsg::Ask(ask))?;
    drop(_indicator);
    match reply {
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
        DaemonMsg::RulesList { .. } | DaemonMsg::RuleAdded { .. } => {
            bail!("daemon replied a rules message to an Ask (expected Decision)")
        }
        DaemonMsg::Hello { .. } => bail!("daemon replied Hello to an Ask (expected Decision)"),
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
        DaemonMsg::RulesList { .. } | DaemonMsg::RuleAdded { .. } => {
            bail!("unexpected rules reply to ShowWindow/ShowViewer")
        }
        DaemonMsg::Hello { .. } => bail!("unexpected Hello reply to ShowWindow/ShowViewer"),
    }
}

/// `secreq rules list/show`: fetch the current ruleset plus any wasm
/// rules refused at the daemon's last rules load (so list/show can
/// render the refusal). Auto-spawns the daemon if it isn't running so
/// headless management works the same way as wrap invocation.
pub fn list_rules() -> Result<(Vec<crate::rules::Rule>, Vec<crate::rules::WasmRefusal>)> {
    if daemon_disabled() {
        bail!("{NO_DAEMON_ENV} is set; cannot reach the daemon. Unset it and try again.");
    }
    let socket = server::default_socket_path()?;
    let stream = connect_or_spawn(&socket)?;
    match send_and_recv(stream, ClientMsg::ListRules)? {
        DaemonMsg::RulesList {
            rules,
            wasm_refusals,
        } => Ok((rules, wasm_refusals)),
        DaemonMsg::Err { message } => bail!("daemon error: {message}"),
        other => bail!("unexpected reply to ListRules: {other:?}"),
    }
}

/// `secreq rules add-wasm`: register a compiled wasm module as a new
/// rule. Sends the module's absolute path — the daemon reads, vets,
/// copies into its store, and persists (see
/// [`ClientMsg::AddWasmRule`]). Returns the rule as registered.
pub fn add_wasm_rule(
    name: &str,
    module_path: &std::path::Path,
    trained_secrets: std::collections::BTreeSet<String>,
    allow_all_secrets: bool,
) -> Result<crate::rules::Rule> {
    if daemon_disabled() {
        bail!("{NO_DAEMON_ENV} is set; cannot reach the daemon. Unset it and try again.");
    }
    let socket = server::default_socket_path()?;
    let stream = connect_or_spawn(&socket)?;
    let msg = ClientMsg::AddWasmRule {
        name: name.to_owned(),
        module_path: module_path.to_string_lossy().into_owned(),
        trained_secrets,
        allow_all_secrets,
    };
    match send_and_recv(stream, msg)? {
        DaemonMsg::RuleAdded { rule } => Ok(*rule),
        DaemonMsg::Err { message } => bail!("daemon error: {message}"),
        other => bail!("unexpected reply to AddWasmRule: {other:?}"),
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
        DaemonMsg::RulesList { .. } | DaemonMsg::RuleAdded { .. } => {
            bail!("daemon replied a rules message to Shutdown (expected Ok)")
        }
        DaemonMsg::Hello { .. } => bail!("daemon replied Hello to Shutdown (expected Ok)"),
    }
}

/// Snapshot of the daemon's liveness, as reported by `secreq daemon status`.
///
/// `Running` is decided by the pidfile flock — the authoritative liveness
/// signal (see [`probe_pidfile_lock`]) — so the pid is always a *live*
/// process, never a recycled one. `build_id` is the separate, weaker
/// "responsive?" signal: `Some` when the daemon answered the `Hello`
/// handshake over its socket, `None` when it holds the lock but didn't
/// reply (a wedged UI or deadlocked socket thread). The two-level answer
/// lets the CLI distinguish "running" from "running but not responding."
#[derive(Debug, PartialEq, Eq)]
pub enum DaemonStatus {
    NotRunning,
    Running { pid: u32, build_id: Option<String> },
}

/// `secreq daemon status` — report whether a daemon is running without
/// spawning one. Resolves the real pidfile/socket paths and delegates to
/// [`status_from_paths`].
pub fn daemon_status() -> Result<DaemonStatus> {
    let pidfile = server::pidfile_path()?;
    let socket = server::default_socket_path()?;
    status_from_paths(&pidfile, &socket)
}

/// The path-parameterised core of [`daemon_status`], split out so tests can
/// drive it against a temp pidfile/socket. A free flock means no live
/// daemon; a held flock means one is running, and we then probe the socket
/// for its build id (which is `None` when the daemon is wedged or the socket
/// path doesn't point at a live listener).
fn status_from_paths(pidfile: &Path, socket: &Path) -> Result<DaemonStatus> {
    match probe_pidfile_lock(pidfile)? {
        LockState::Free => Ok(DaemonStatus::NotRunning),
        LockState::Held => {
            let pid = read_pid(pidfile)?;
            let build_id = daemon_build_id(socket);
            Ok(DaemonStatus::Running { pid, build_id })
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

/// True iff the wait indicator is silenced for this invocation via the
/// `SECREQ_NO_WAIT_INDICATOR` env override (any non-empty value).
fn wait_indicator_silenced_by_env() -> bool {
    std::env::var_os(NO_WAIT_INDICATOR_ENV).is_some_and(|v| !v.is_empty())
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
pub(crate) fn graphical_environment_available() -> bool {
    if cfg!(target_os = "macos") {
        return true;
    }
    let has_x11 = std::env::var_os("DISPLAY").is_some_and(|v| !v.is_empty());
    let has_wayland = std::env::var_os("WAYLAND_DISPLAY").is_some_and(|v| !v.is_empty());
    has_x11 || has_wayland
}

fn connect_or_spawn(socket: &Path) -> Result<UnixStream> {
    // Optimistic connect first — the common case is the daemon is already
    // running. Before using it, verify it's the same build as this CLI:
    // the daemon is long-lived, so an installed-binary update leaves a
    // newer CLI talking to a stale daemon (which is how the SSH-agent and
    // pending-badge features could silently fail to appear). A mismatch
    // gets the stale daemon restarted.
    if UnixStream::connect(socket).is_ok() {
        match daemon_build_id(socket) {
            Some(id) if id == crate::BUILD_ID => {
                // Current build — open a fresh connection for the real
                // request (the handshake consumed the probe connection).
                if let Ok(stream) = UnixStream::connect(socket) {
                    return Ok(stream);
                }
                // Raced away between probe and reconnect; fall through to
                // spawn a new one below.
            }
            Some(stale) => {
                // Stale build: restart it, then fall through to spawn a
                // fresh, current daemon.
                restart_stale_daemon(socket, &stale)?;
            }
            None => {
                // The daemon predates the `Hello` handshake (the first
                // upgrade to a version-checking build, or a transient
                // probe failure). We can't verify it, so use it as-is —
                // this is the one time a manual `secreq daemon stop` is
                // still needed to pick up the new binary.
                if let Ok(stream) = UnixStream::connect(socket) {
                    return Ok(stream);
                }
            }
        }
    }
    // No live daemon (or we just restarted a stale one). Serialize the
    // spawn: a burst of wraps that all find no daemon must not each fork
    // one — that thundering herd spawned dozens of short-lived daemons
    // (and, with the old pidfile bug, occasionally left several running).
    // Whichever client wins `daemon.spawn.lock` spawns the daemon; the
    // rest just wait for its socket to come up.
    let deadline = Instant::now() + SPAWN_TIMEOUT;
    match acquire_spawn_lock()? {
        Some(_spawn_guard) => {
            // We own the spawn. Re-check first — another client may have
            // brought the daemon up in the window before we took the lock.
            if let Ok(stream) = UnixStream::connect(socket) {
                return Ok(stream);
            }
            // Keep the child handle so we can detect early-exit (e.g. egui
            // failing to init headless) and bail without the full timeout.
            let mut child = spawn_daemon().context("auto-spawn secreq daemon")?;
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
        None => {
            // Another client holds the spawn lock and is bringing the daemon
            // up. Don't fork a competing one — just wait for its socket.
            let mut backoff = Duration::from_millis(20);
            while Instant::now() < deadline {
                sleep(backoff);
                if let Ok(stream) = UnixStream::connect(socket) {
                    return Ok(stream);
                }
                backoff = (backoff * 2).min(Duration::from_millis(250));
            }
            bail!(
                "consent daemon did not come up within {:?} while another client was \
                 spawning it ({} not connectable)",
                SPAWN_TIMEOUT,
                socket.display()
            )
        }
    }
}

/// Take the daemon-spawn lock: a non-blocking `flock` on
/// [`server::spawn_lock_path`]. `Some(file)` = we own the right to spawn
/// the daemon (hold it until the socket is up, then let it drop); `None` =
/// another client is already spawning, so we should wait rather than fork a
/// competing daemon. The lock frees when the holder's fd closes; the file
/// is never unlinked.
fn acquire_spawn_lock() -> Result<Option<std::fs::File>> {
    acquire_spawn_lock_at(&server::spawn_lock_path()?)
}

/// Core of [`acquire_spawn_lock`], split out so a test can drive it against
/// a temp path instead of the real per-user runtime dir.
fn acquire_spawn_lock_at(path: &Path) -> Result<Option<std::fs::File>> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)
        .with_context(|| format!("open spawn lock {}", path.display()))?;
    let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if ret == 0 {
        return Ok(Some(file));
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
        Ok(None)
    } else {
        Err(err).with_context(|| format!("flock spawn lock {}", path.display()))
    }
}

/// Probe a running daemon's build id via the `Hello` handshake.
///
/// Returns `Some(id)` for a daemon that answers the handshake, `None`
/// when it can't be established — either the daemon predates the
/// handshake (it fails to parse the unknown `Hello` message and closes
/// the connection without a reply) or a transient I/O error. `None` is
/// deliberately conservative: the caller treats it as "use the daemon
/// as-is" rather than restarting on a guess.
fn daemon_build_id(socket: &Path) -> Option<String> {
    let stream = UnixStream::connect(socket).ok()?;
    let hello = ClientMsg::Hello {
        build_id: crate::BUILD_ID.to_owned(),
    };
    match send_and_recv(stream, hello) {
        Ok(DaemonMsg::Hello { build_id }) => Some(build_id),
        _ => None,
    }
}

/// Restart a daemon whose build differs from this CLI's. Asks it to exit
/// cleanly, waits for it to release the singleton pidfile lock (so the
/// caller's subsequent spawn wins the lock rather than exiting 0 because
/// the stale daemon still holds it), and force-kills it if it overstays
/// [`RESTART_TIMEOUT`]. The caller spawns the replacement afterward.
fn restart_stale_daemon(socket: &Path, stale_id: &str) -> Result<()> {
    eprintln!(
        "secreq: consent daemon is build {stale_id}, this CLI is {}; restarting the daemon",
        crate::BUILD_ID
    );
    // Best-effort graceful shutdown.
    if let Ok(stream) = UnixStream::connect(socket) {
        let _ = send_and_recv(stream, ClientMsg::Shutdown);
    }
    // Wait for the old daemon to fully exit: both the socket must stop
    // accepting AND the pidfile flock must be free. The flock is the
    // load-bearing one — a fresh daemon that finds the lock held just
    // exits 0, which would silently leave the stale daemon in charge.
    let pidfile = server::pidfile_path()?;
    let deadline = Instant::now() + RESTART_TIMEOUT;
    let mut backoff = Duration::from_millis(20);
    while Instant::now() < deadline {
        let lock_free = matches!(probe_pidfile_lock(&pidfile), Ok(LockState::Free));
        let socket_dead = UnixStream::connect(socket).is_err();
        if lock_free && socket_dead {
            return Ok(());
        }
        sleep(backoff);
        backoff = (backoff * 2).min(Duration::from_millis(200));
    }
    // Overstayed (an old build ignoring Shutdown, or a wedged daemon).
    // Force it so the replacement spawn isn't blocked on a held lock.
    eprintln!("secreq: stale daemon didn't exit in time; force-stopping it");
    let _ = force_stop_daemon();
    Ok(())
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

// ── Pending-approval indicator ───────────────────────────────────────────
//
// While a wrap blocks on the daemon's decision the terminal would otherwise
// sit silent — the user can't tell whether the command hung or is waiting on
// the consent popup. We print a stderr indicator during the wait: an animated
// spinner on a TTY (plus a one-shot bell to pull the eye to the terminal),
// or a static, timestamped line on a pipe/file, reprinted every 30s so a long
// wait leaves a breadcrumb trail. A short grace period suppresses it entirely
// for fast (cached / auto-rule) approvals that resolve before it would show.

/// How long to wait before showing anything. Fast approvals (cache hit,
/// auto-rule) finish inside this window and never flash an indicator.
const INDICATOR_GRACE: Duration = Duration::from_millis(250);
/// Spinner redraw cadence on a TTY.
const SPINNER_TICK: Duration = Duration::from_millis(100);
/// How often the non-TTY static line is reprinted.
const NONTTY_REPRINT: Duration = Duration::from_secs(30);
/// Braille spinner frames (the cliclack/ora house style).
const SPINNER_FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// A background thread that paints the waiting indicator to stderr until
/// dropped. Drop stops the thread promptly (via a condvar, no polling lag)
/// and clears the spinner line so the wrap's own output starts clean.
struct WaitIndicator {
    // (stopped flag, condvar) — Drop flips the flag and notifies so the
    // render thread wakes immediately instead of sleeping out its tick.
    inner: Arc<(Mutex<bool>, Condvar)>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl WaitIndicator {
    fn start(label: &str) -> Self {
        let inner = Arc::new((Mutex::new(false), Condvar::new()));
        let tty = std::io::stderr().is_terminal();
        let label = label.to_owned();
        let inner_thread = Arc::clone(&inner);
        let handle = std::thread::Builder::new()
            .name("secreq-wait-indicator".to_owned())
            .spawn(move || run_wait_indicator(&label, tty, &inner_thread))
            .ok();
        WaitIndicator { inner, handle }
    }
}

impl Drop for WaitIndicator {
    fn drop(&mut self) {
        let (lock, cv) = &*self.inner;
        {
            let mut stopped = lock.lock().expect("indicator mutex");
            *stopped = true;
            cv.notify_all();
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Block on the indicator's condvar for `dur`, returning `true` if a stop was
/// signalled (so the caller should exit) and `false` on timeout.
fn indicator_sleep(inner: &(Mutex<bool>, Condvar), dur: Duration) -> bool {
    let (lock, cv) = inner;
    let stopped = lock.lock().expect("indicator mutex");
    // Check the flag *before* waiting: if Drop set it (and sent its notify)
    // while we were between waits, the notify would be lost and we'd block the
    // full `dur` — up to 30s for the non-TTY tick. The flag, read under the
    // lock, is the source of truth and closes that race.
    if *stopped {
        return true;
    }
    let (stopped, _) = cv
        .wait_timeout(stopped, dur)
        .expect("indicator condvar wait");
    *stopped
}

fn run_wait_indicator(label: &str, tty: bool, inner: &(Mutex<bool>, Condvar)) {
    // Grace period: stay silent if the decision arrives quickly.
    if indicator_sleep(inner, INDICATOR_GRACE) {
        return;
    }
    let mut err = std::io::stderr();
    let start = Instant::now();
    if tty {
        // One-shot bell: nudge attention to the terminal that's now blocked.
        let _ = write!(err, "\x07");
        let mut tick = 0usize;
        loop {
            let _ = write!(err, "\r\x1b[K{}", spinner_frame(label, tick));
            let _ = err.flush();
            tick += 1;
            if indicator_sleep(inner, SPINNER_TICK) {
                // Clear the spinner line so the wrap's output starts clean.
                let _ = write!(err, "\r\x1b[K");
                let _ = err.flush();
                return;
            }
        }
    } else {
        loop {
            let _ = writeln!(
                err,
                "{}",
                waiting_line(label, now_unix_secs(), start.elapsed().as_secs())
            );
            let _ = err.flush();
            if indicator_sleep(inner, NONTTY_REPRINT) {
                return;
            }
        }
    }
}

/// One spinner line's text (no leading carriage-return / clear sequence; the
/// caller adds those). Pure so it can be unit-tested.
fn spinner_frame(label: &str, tick: usize) -> String {
    let frame = SPINNER_FRAMES[tick % SPINNER_FRAMES.len()];
    format!("{frame} secreq: waiting for approval of `{label}` — approve in the popup window")
}

/// One static non-TTY waiting line, carrying a UTC timestamp and elapsed
/// seconds so a piped log shows the wait isn't wedged. Pure for testability.
fn waiting_line(label: &str, now_unix: u64, elapsed_secs: u64) -> String {
    format!(
        "[secreq {ts}] waiting for approval of `{label}` ({elapsed_secs}s elapsed) — approve in the secreq window",
        ts = utc_timestamp(now_unix),
    )
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Format Unix seconds as `YYYY-MM-DDTHH:MM:SSZ` (UTC), without pulling in a
/// datetime crate. Uses Howard Hinnant's `civil_from_days` algorithm.
fn utc_timestamp(unix_secs: u64) -> String {
    let secs = unix_secs as i64;
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (hh, mm, ss) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    let (y, mo, d) = civil_from_days(days);
    format!("{y:04}-{mo:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Days since the Unix epoch → (year, month, day). Hinnant's civil-from-days.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32; // [1, 12]
    let year = if month <= 2 { year + 1 } else { year };
    (year, month, day)
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
    fn spawn_lock_is_exclusive_and_reusable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("daemon.spawn.lock");

        // First client wins the right to spawn.
        let g1 = acquire_spawn_lock_at(&path).expect("acquire");
        assert!(g1.is_some(), "first client wins the spawn lock");

        // A concurrent client must NOT also win — it should wait instead of
        // forking a competing daemon (the thundering-herd fix).
        assert!(
            acquire_spawn_lock_at(&path).expect("contend").is_none(),
            "a second client is refused while the spawn lock is held"
        );

        // Once the winner finishes (drops the guard), the lock is reusable
        // for the next spawn cycle.
        drop(g1);
        assert!(
            acquire_spawn_lock_at(&path).expect("re-acquire").is_some(),
            "spawn lock is reusable after the holder drops it"
        );
    }

    #[test]
    fn utc_timestamp_formats_known_epochs() {
        assert_eq!(utc_timestamp(0), "1970-01-01T00:00:00Z");
        // 1700000000 = 2023-11-14T22:13:20Z (a well-known round value).
        assert_eq!(utc_timestamp(1_700_000_000), "2023-11-14T22:13:20Z");
        // 1735689600 = 2025-01-01T00:00:00Z.
        assert_eq!(utc_timestamp(1_735_689_600), "2025-01-01T00:00:00Z");
        // Leap day: 2024-02-29T12:00:00Z = 1709208000.
        assert_eq!(utc_timestamp(1_709_208_000), "2024-02-29T12:00:00Z");
    }

    #[test]
    fn spinner_frame_cycles_and_carries_the_label() {
        let a = spinner_frame("gh", 0);
        assert!(a.starts_with(SPINNER_FRAMES[0]));
        assert!(a.contains("`gh`"));
        // The tick wraps around the frame set.
        assert_eq!(
            spinner_frame("gh", 0),
            spinner_frame("gh", SPINNER_FRAMES.len())
        );
    }

    #[test]
    fn waiting_line_has_timestamp_label_and_elapsed() {
        let line = waiting_line("aws", 1_700_000_000, 30);
        assert!(line.contains("2023-11-14T22:13:20Z"));
        assert!(line.contains("`aws`"));
        assert!(line.contains("30s elapsed"));
    }

    #[test]
    fn wait_indicator_drops_promptly_without_hanging() {
        // Start then immediately drop — well inside the grace window, so it
        // prints nothing. The point is the thread joins cleanly and fast: a
        // lost-wakeup bug would block Drop's join on the full tick timeout.
        let start = Instant::now();
        {
            let _indicator = WaitIndicator::start("gh");
        } // Drop runs here (joins the thread).
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "WaitIndicator::drop should join promptly, took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn build_id_is_stamped_at_compile_time() {
        // build.rs must populate SECREQ_BUILD_ID. The '+' separates the
        // git-sha part from the build timestamp; its presence confirms the
        // composition rather than an empty/placeholder value.
        assert!(!crate::BUILD_ID.is_empty(), "BUILD_ID must not be empty");
        assert!(
            crate::BUILD_ID.contains('+'),
            "BUILD_ID should carry a build timestamp: {}",
            crate::BUILD_ID
        );
    }

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

    #[test]
    fn status_reports_not_running_when_no_pidfile() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pidfile = dir.path().join("missing.pid");
        let socket = dir.path().join("daemon.sock");
        assert_eq!(
            status_from_paths(&pidfile, &socket).expect("status"),
            DaemonStatus::NotRunning,
        );
    }

    #[test]
    fn status_reports_not_running_for_a_stale_pidfile() {
        // File left by a crashed daemon: present, but nobody holds the flock.
        let dir = tempfile::tempdir().expect("tempdir");
        let pidfile = dir.path().join("stale.pid");
        let socket = dir.path().join("daemon.sock");
        std::fs::write(&pidfile, "99999\n").expect("write pid");
        assert_eq!(
            status_from_paths(&pidfile, &socket).expect("status"),
            DaemonStatus::NotRunning,
        );
    }

    #[test]
    fn status_reports_running_with_no_build_id_when_lock_held_but_socket_dead() {
        // A held flock means the daemon is alive; with no live listener on
        // the socket the Hello handshake fails, so build_id is None — the
        // "running but not responding" shape.
        let dir = tempfile::tempdir().expect("tempdir");
        let pidfile = dir.path().join("held.pid");
        let socket = dir.path().join("daemon.sock");
        std::fs::write(&pidfile, "12345\n").expect("write pid");
        let owner = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&pidfile)
            .expect("open owner");
        let lock_ret = unsafe { libc::flock(owner.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(lock_ret, 0, "owner takes the lock");

        assert_eq!(
            status_from_paths(&pidfile, &socket).expect("status"),
            DaemonStatus::Running {
                pid: 12345,
                build_id: None,
            },
        );

        let _ = unsafe { libc::flock(owner.as_raw_fd(), libc::LOCK_UN) };
    }
}
