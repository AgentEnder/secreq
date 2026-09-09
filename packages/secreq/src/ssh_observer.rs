//! Transparent `ssh` PATH observer for pending Secreq signatures.
//!
//! The SSH-agent protocol is request/reply: once OpenSSH sends a sign request
//! it waits for the agent's final signature or failure. RFC 9987 makes that
//! constraint explicit — agents do not send unsolicited progress messages.
//! That silence is especially awkward for command-running agents, which can
//! reasonably mistake a blocked `git push` for a hung process and retry it.
//!
//! `secreq ssh setup` therefore installs a tiny managed `ssh` shim. The shim
//! re-enters this module, which spawns the real `ssh` with inherited stdio and
//! otherwise stays out of the session. The daemon mirrors only the identities
//! of callers with an SSH sign genuinely awaiting human consent into a private
//! runtime marker directory; this parent process watches the marker belonging
//! to the process that launched it and writes a heartbeat to the same stderr
//! Git/ssh was given.
//!
//! The correlation deliberately uses the process immediately *above* the
//! Secreq shim rather than the real ssh pid. The daemon's provenance walk
//! strips Secreq self-frames, so both sides independently arrive at the same
//! kernel-sourced `(pid, start_time)`:
//!
//! ```text
//! git ──> secreq ssh observer ──> /usr/bin/ssh ──> agent.sock
//!  ^                                  |
//!  |                                  └─ daemon walk skips secreq, sees git
//!  └─ observer's first caller
//! ```
//!
//! The shim is **observability, not enforcement**. Calling `/usr/bin/ssh`,
//! choosing another SSH implementation, or otherwise bypassing it only loses
//! the waiting message; the actual consent boundary remains `agent.sock`.

use std::collections::HashSet;
use std::ffi::OsString;
use std::fs;
use std::io::{IsTerminal as _, Read as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, Context as _, Result};

use crate::daemon::proto::{AskSubject, RowStatus};
use crate::daemon::state::QueueSnapshot;
use crate::provenance::ProcessIdentity;

/// Marks the special observer shim. Deliberately distinct from
/// [`crate::shim::SENTINEL`]: `secreq unwrap ssh` owns ordinary wrap shims and
/// must not silently remove a helper installed by `secreq ssh setup`.
const OBSERVER_SENTINEL: &str = "secreq-managed-ssh-observer";

/// Private handshake from the shell shim to the re-execed Secreq binary.
/// Like the other `SECREQ_*` process markers this is not a security boundary.
pub const OBSERVER_ENV: &str = "SECREQ_SSH_OBSERVER";
/// Absolute real-ssh path baked into the shim at setup time.
const REAL_SSH_ENV: &str = "SECREQ_SSH_REAL";

const POLL_TICK: Duration = Duration::from_millis(100);
const INDICATOR_GRACE: Duration = Duration::from_millis(250);
const NONTTY_REPRINT: Duration = Duration::from_secs(30);
const SPINNER_FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// Called before clap parsing. `None` means this is an ordinary Secreq
/// invocation; `Some(code)` means the process came from the managed `ssh`
/// shim and has completely handled the invocation here.
pub fn run_from_env() -> Option<i32> {
    let active = std::env::var_os(OBSERVER_ENV).is_some_and(|value| !value.is_empty());
    if !active {
        return None;
    }

    Some(match run_observer() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("secreq: could not run the SSH observer: {err:#}");
            127
        }
    })
}

fn run_observer() -> Result<i32> {
    let real_ssh = std::env::var_os(REAL_SSH_ENV)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .context("observer shim did not provide the real ssh path")?;
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();

    // Ask the kernel who launched this shim before spawning ssh. Starting the
    // walk at ourselves excludes this Secreq process by construction; any
    // other Secreq self-frames above us are filtered by provenance::walk in
    // exactly the same way as the daemon's walk from the real ssh peer.
    let caller = crate::provenance::caller_chain_from_pid(std::process::id())
        .frames
        .first()
        .map(|frame| ProcessIdentity {
            pid: frame.pid,
            start_time: frame.start_time,
        });

    // Do not leak the private re-entry marker into ssh's children. Inherited
    // stdin/stdout/stderr are deliberate: the observer is not a PTY, pipe, or
    // SSH transport proxy, so everything except the progress line remains
    // directly between the real ssh and its caller.
    let mut child = Command::new(&real_ssh)
        .args(args)
        .env_remove(OBSERVER_ENV)
        .env_remove(REAL_SSH_ENV)
        .spawn()
        .with_context(|| format!("start {}", real_ssh.display()))?;

    // Terminal-generated signals already target the foreground process group,
    // which contains both us and ssh. Supervisors, however, often terminate
    // only the pid they launched. Forward TERM/HUP so a timeout that targets
    // this transparent parent cannot orphan a live ssh process.
    let (signal_handle, signal_thread) = match signal_hook::iterator::Signals::new([
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGHUP,
    ]) {
        Ok(mut signals) => {
            let handle = signals.handle();
            let child_pid = i32::try_from(child.id()).ok();
            let thread = thread::Builder::new()
                .name("secreq-ssh-signal-forwarder".to_owned())
                .spawn(move || {
                    for signal in signals.forever() {
                        if let Some(pid) = child_pid {
                            // SAFETY: `pid` is the OS pid returned for the
                            // child we just spawned; forwarding a signal uses
                            // no borrowed memory and libc validates the pid.
                            let _ = unsafe { libc::kill(pid, signal) };
                        }
                    }
                })
                .ok();
            (Some(handle), thread)
        }
        Err(_) => (None, None),
    };

    let tty = std::io::stderr().is_terminal();
    let render = !wait_indicator_silenced();
    let mut waiting_since: Option<Instant> = None;
    let mut last_nontty_print: Option<Instant> = None;
    let mut spinner_tick = 0usize;
    let mut painted_tty = false;

    loop {
        if let Some(status) = child.try_wait().context("wait for real ssh")? {
            if painted_tty {
                clear_tty_indicator();
            }
            if let Some(handle) = signal_handle.as_ref() {
                handle.close();
            }
            if let Some(thread) = signal_thread {
                let _ = thread.join();
            }
            return Ok(status
                .code()
                .unwrap_or_else(|| 128 + status.signal().unwrap_or(1)));
        }

        let waiting = caller.is_some_and(wait_active);
        if waiting {
            let since = *waiting_since.get_or_insert_with(Instant::now);
            let elapsed = since.elapsed();
            if render && elapsed >= INDICATOR_GRACE {
                if tty {
                    paint_tty_indicator(spinner_tick);
                    spinner_tick = spinner_tick.wrapping_add(1);
                    painted_tty = true;
                } else {
                    let now = Instant::now();
                    let should_print = last_nontty_print
                        .is_none_or(|last| now.duration_since(last) >= NONTTY_REPRINT);
                    if should_print {
                        eprintln!(
                            "secreq: waiting for user approval to sign with SSH ({}s elapsed); command is still running",
                            elapsed.as_secs()
                        );
                        last_nontty_print = Some(now);
                    }
                }
            }
        } else {
            if painted_tty {
                clear_tty_indicator();
                painted_tty = false;
            }
            waiting_since = None;
            last_nontty_print = None;
            spinner_tick = 0;
        }

        thread::sleep(POLL_TICK);
    }
}

fn wait_indicator_silenced() -> bool {
    std::env::var_os(crate::daemon::client::NO_WAIT_INDICATOR_ENV)
        .is_some_and(|value| !value.is_empty())
}

fn paint_tty_indicator(tick: usize) {
    let frame = SPINNER_FRAMES[tick % SPINNER_FRAMES.len()];
    let mut err = std::io::stderr();
    let _ = write!(
        err,
        "\r\x1b[K{frame} secreq: waiting for user approval to sign with SSH — approve in the popup window"
    );
    let _ = err.flush();
}

fn clear_tty_indicator() {
    let mut err = std::io::stderr();
    let _ = write!(err, "\r\x1b[K");
    let _ = err.flush();
}

// ── Pending-sign projection ───────────────────────────────────────────────

fn wait_root() -> Result<PathBuf> {
    Ok(crate::paths::socket_dir()?.join("ssh-waits"))
}

fn marker_name(caller: ProcessIdentity) -> String {
    format!("{}-{}.wait", caller.pid, caller.start_time)
}

fn marker_path(root: &Path, caller: ProcessIdentity) -> PathBuf {
    root.join(marker_name(caller))
}

fn wait_active(caller: ProcessIdentity) -> bool {
    wait_root().is_ok_and(|root| marker_path(&root, caller).is_file())
}

/// Mirror the daemon's authoritative queue into the tiny filesystem surface
/// the PATH observer can see without extending the SSH-agent protocol or the
/// daemon control protocol. Only `Awaiting` SSH-sign rows participate; wrap
/// asks, auto-rule hits, cached grants, and already-resolving rows create no
/// marker.
pub(crate) fn sync_pending_snapshot(snapshot: &QueueSnapshot) -> Result<()> {
    let waiting = pending_callers(snapshot);
    sync_waiters_at(&wait_root()?, &waiting)
}

fn pending_callers(snapshot: &QueueSnapshot) -> HashSet<ProcessIdentity> {
    snapshot
        .entries
        .iter()
        .filter(|row| matches!(row.status, RowStatus::Awaiting))
        .filter_map(|row| match &row.representative.subject {
            AskSubject::SshSign(sign) => sign.callers.first().map(|caller| ProcessIdentity {
                pid: caller.pid,
                start_time: caller.start_time,
            }),
            AskSubject::Wrap(_) | AskSubject::ScopedAgent(_) => None,
        })
        .collect()
}

fn sync_waiters_at(root: &Path, waiting: &HashSet<ProcessIdentity>) -> Result<()> {
    crate::paths::ensure_private_dir(root)
        .with_context(|| format!("make {} private", root.display()))?;

    let wanted_names: HashSet<String> = waiting.iter().copied().map(marker_name).collect();
    for entry in fs::read_dir(root).with_context(|| format!("read {}", root.display()))? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if wanted_names.contains(&name) {
            continue;
        }
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            fs::remove_dir_all(&path)
                .with_context(|| format!("remove stale marker directory {}", path.display()))?;
        } else {
            fs::remove_file(&path)
                .with_context(|| format!("remove stale marker {}", path.display()))?;
        }
    }

    for caller in waiting {
        let path = marker_path(root, *caller);
        if path.exists() {
            continue;
        }
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(_) => {}
            // Another daemon tick cannot race us (the main loop is single
            // threaded), but tolerate an already-created marker so the helper
            // stays idempotent when unit-tested directly.
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(err) => {
                return Err(err).with_context(|| format!("create marker {}", path.display()))
            }
        }
    }
    Ok(())
}

/// A crashed daemon can leave marker files behind. A fresh daemon owns the
/// whole marker directory, so startup and clean shutdown both clear it.
pub(crate) fn reset_wait_markers() -> Result<()> {
    reset_wait_markers_at(&wait_root()?)
}

fn reset_wait_markers_at(root: &Path) -> Result<()> {
    match fs::symlink_metadata(root) {
        Ok(meta) if meta.file_type().is_symlink() => {
            fs::remove_file(root)
                .with_context(|| format!("remove stale symlink {}", root.display()))?;
        }
        Ok(_) => {
            fs::remove_dir_all(root)
                .with_context(|| format!("clear stale SSH wait markers at {}", root.display()))?;
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err).with_context(|| format!("stat {}", root.display())),
    }
    crate::paths::ensure_private_dir(root)
        .with_context(|| format!("create SSH wait marker root {}", root.display()))
}

// ── Managed PATH shim ────────────────────────────────────────────────────

/// Install/refresh the observer at `<shim_dir>/ssh`, baking in both this
/// Secreq binary and the real ssh that PATH resolves to after managed shims
/// are skipped. Refuses to replace a user-owned file or an ordinary
/// `secreq wrap ssh` shim.
pub(crate) fn install_shim(shim_dir: &Path) -> Result<PathBuf> {
    crate::shim::ensure_shim_dir(shim_dir)?;
    let real_ssh = find_real_ssh(shim_dir)?;
    let secreq = std::env::current_exe().context("determine the running secreq path")?;
    let secreq = fs::canonicalize(&secreq).unwrap_or(secreq);
    let target = shim_dir.join("ssh");

    match fs::symlink_metadata(&target) {
        Ok(meta) if meta.file_type().is_symlink() => bail!(
            "{} is a symlink, not the secreq SSH observer; refusing to follow it",
            target.display()
        ),
        Ok(_) => {
            let existing = fs::read_to_string(&target)
                .with_context(|| format!("read existing {}", target.display()))?;
            if !existing.contains(OBSERVER_SENTINEL) {
                let detail = if existing.contains(crate::shim::SENTINEL) {
                    "it is already an ordinary `secreq wrap ssh` shim"
                } else {
                    "it is not managed by the secreq SSH setup"
                };
                bail!("{} already exists and {detail}; leaving it untouched", target.display());
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err).with_context(|| format!("stat {}", target.display())),
    }

    fs::write(&target, observer_body(&secreq, &real_ssh))
        .with_context(|| format!("write SSH observer shim {}", target.display()))?;
    let mut permissions = fs::metadata(&target)?.permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&target, permissions)
        .with_context(|| format!("chmod {}", target.display()))?;
    Ok(target)
}

/// Remove only the special observer shim. An ordinary wrapped `ssh` is a
/// separate feature and `ssh setup --undo` must never delete it.
pub(crate) fn remove_shim(shim_dir: &Path) -> Result<bool> {
    let target = shim_dir.join("ssh");
    match fs::symlink_metadata(&target) {
        Ok(meta) if meta.file_type().is_symlink() => return Ok(false),
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err).with_context(|| format!("stat {}", target.display())),
    }
    let existing = fs::read_to_string(&target)
        .with_context(|| format!("read existing {}", target.display()))?;
    if !existing.contains(OBSERVER_SENTINEL) {
        return Ok(false);
    }
    fs::remove_file(&target).with_context(|| format!("remove {}", target.display()))?;
    Ok(true)
}

fn observer_body(secreq: &Path, real_ssh: &Path) -> String {
    let secreq = sh_quote(&secreq.display().to_string());
    let real_ssh = sh_quote(&real_ssh.display().to_string());
    format!(
        "#!/bin/sh\n\
         # {OBSERVER_SENTINEL}\n\
         # Created by `secreq ssh setup`. Removed by `secreq ssh setup --undo`.\n\
         # Do not edit by hand.\n\
         export {OBSERVER_ENV}=1\n\
         export {REAL_SSH_ENV}={real_ssh}\n\
         exec {secreq} \"$@\"\n"
    )
}

fn sh_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

fn find_real_ssh(shim_dir: &Path) -> Result<PathBuf> {
    let path = std::env::var_os("PATH").context("no PATH in environment")?;
    for dir in std::env::split_paths(&path) {
        if dir == shim_dir {
            continue;
        }
        let candidate = dir.join("ssh");
        if !is_executable(&candidate) || is_secreq_ssh_shim(&candidate) {
            continue;
        }
        return Ok(fs::canonicalize(&candidate).unwrap_or(candidate));
    }
    bail!("could not find a non-secreq `ssh` on PATH")
}

fn is_executable(path: &Path) -> bool {
    let Ok(meta) = fs::metadata(path) else {
        return false;
    };
    meta.is_file() && (meta.permissions().mode() & 0o111 != 0)
}

fn is_secreq_ssh_shim(path: &Path) -> bool {
    let Ok(file) = fs::File::open(path) else {
        return false;
    };
    let mut prefix = Vec::new();
    if file.take(512).read_to_end(&mut prefix).is_err() || !prefix.starts_with(b"#!") {
        return false;
    }
    let has = |needle: &str| {
        prefix
            .windows(needle.len())
            .any(|window| window == needle.as_bytes())
    };
    has(OBSERVER_SENTINEL) || has(crate::shim::SENTINEL)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(pid: u32, start_time: u64) -> ProcessIdentity {
        ProcessIdentity { pid, start_time }
    }

    #[test]
    fn sync_creates_and_removes_only_current_wait_markers() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("waits");
        let first = peer(42, 9001);
        let second = peer(43, 9002);

        sync_waiters_at(&root, &HashSet::from([first, second])).expect("first sync");
        assert!(marker_path(&root, first).is_file());
        assert!(marker_path(&root, second).is_file());

        sync_waiters_at(&root, &HashSet::from([second])).expect("second sync");
        assert!(!marker_path(&root, first).exists());
        assert!(marker_path(&root, second).is_file());
    }

    #[test]
    fn reset_removes_stale_markers() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("waits");
        let identity = peer(42, 9001);
        sync_waiters_at(&root, &HashSet::from([identity])).expect("sync");
        assert!(marker_path(&root, identity).is_file());

        reset_wait_markers_at(&root).expect("reset");
        assert!(!marker_path(&root, identity).exists());
    }

    #[test]
    fn observer_body_bakes_real_ssh_without_claiming_to_be_a_wrap_shim() {
        let body = observer_body(Path::new("/opt/secreq/bin/secreq"), Path::new("/usr/bin/ssh"));
        assert!(body.contains(OBSERVER_SENTINEL));
        assert!(!body.contains(crate::shim::SENTINEL));
        assert!(body.contains("SECREQ_SSH_OBSERVER=1"));
        assert!(body.contains("SECREQ_SSH_REAL='/usr/bin/ssh'"));
        assert!(body.contains("exec '/opt/secreq/bin/secreq' \"$@\""));
    }

    #[test]
    fn undo_does_not_remove_an_ordinary_ssh_wrap() {
        let temp = tempfile::tempdir().expect("tempdir");
        let target = temp.path().join("ssh");
        fs::write(
            &target,
            format!("#!/bin/sh\n# {}: wrap=ssh\n", crate::shim::SENTINEL),
        )
        .expect("write fixture");

        assert!(!remove_shim(temp.path()).expect("remove observer"));
        assert!(target.exists());
    }
}
