//! Transparent `ssh` PATH observer for pending Secreq signatures.
//!
//! The SSH-agent protocol is request/reply: once OpenSSH sends a sign request
//! it waits for the agent's final signature or failure. There is no portable
//! progress message the agent can send while a human consent decision is
//! pending. That silence is especially awkward for command-running agents,
//! which can reasonably mistake a blocked `git push` for a hung process.
//!
//! `secreq ssh setup` therefore installs a tiny managed `ssh` shim. The shim
//! re-enters this module, which spawns the real `ssh` with inherited stdio and
//! otherwise stays out of the session. The daemon's SSH-agent handler drops a
//! short-lived marker into the private runtime directory only while a sign is
//! genuinely parked on interactive consent. This parent process watches the
//! marker for its child and writes a heartbeat to the same stderr Git/ssh was
//! given.
//!
//! The shim is **observability, not enforcement**. Calling `/usr/bin/ssh`,
//! choosing another `IdentityAgent`, or otherwise bypassing it only loses the
//! waiting message; the actual consent boundary remains `agent.sock`.

use std::ffi::OsString;
use std::fs;
use std::io::{IsTerminal as _, Read as _, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, Context as _, Result};

use crate::provenance::ProcessIdentity;

/// Marks the managed `ssh` shim as the observer kind rather than an ordinary
/// `secreq wrap ssh` shim. Both carry [`crate::shim::SENTINEL`] so the normal
/// real-binary resolver skips either one.
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

    // Do not leak the private re-entry marker into ssh's children. Inherited
    // stdin/stdout/stderr are deliberate: the observer is not a PTY, pipe, or
    // SSH transport proxy, so everything except the progress line remains
    // byte-for-byte between the real ssh and its caller.
    let mut child = Command::new(&real_ssh)
        .args(args)
        .env_remove(OBSERVER_ENV)
        .env_remove(REAL_SSH_ENV)
        .spawn()
        .with_context(|| format!("start {}", real_ssh.display()))?;

    let tty = std::io::stderr().is_terminal();
    let render = !wait_indicator_silenced();
    let mut child_identity: Option<ProcessIdentity> = None;
    let mut waiting_since: Option<Instant> = None;
    let mut last_nontty_print: Option<Instant> = None;
    let mut spinner_tick = 0usize;
    let mut painted_tty = false;

    loop {
        if let Some(status) = child.try_wait().context("wait for real ssh")? {
            if painted_tty {
                clear_tty_indicator();
            }
            return Ok(status
                .code()
                .unwrap_or_else(|| 128 + status.signal().unwrap_or(1)));
        }

        // `describe_pid` can lose a race immediately after spawn on some
        // platforms. Keep trying while the child is alive instead of turning
        // one missed lookup into a permanently unobservable invocation.
        if child_identity.is_none() {
            child_identity = crate::provenance::describe_pid(child.id()).map(|peer| peer.caller.identity());
        }

        let waiting = child_identity.is_some_and(wait_active);
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

// ── Pending-sign markers ─────────────────────────────────────────────────

fn wait_root() -> Result<PathBuf> {
    Ok(crate::paths::socket_dir()?.join("ssh-waits"))
}

fn peer_dir(root: &Path, peer: ProcessIdentity) -> PathBuf {
    root.join(format!("{}-{}", peer.pid, peer.start_time))
}

fn wait_active(peer: ProcessIdentity) -> bool {
    wait_root().is_ok_and(|root| wait_active_at(&root, peer))
}

fn wait_active_at(root: &Path, peer: ProcessIdentity) -> bool {
    fs::read_dir(peer_dir(root, peer))
        .ok()
        .and_then(|mut entries| entries.next())
        .is_some()
}

/// RAII marker held only across the SSH agent's interactive-consent wait.
/// Drop clears exactly this sign's marker; sibling signs for the same peer
/// keep their own files, so one completion cannot make another disappear.
pub(crate) struct WaitMarker {
    path: PathBuf,
}

impl WaitMarker {
    pub(crate) fn begin(peer: ProcessIdentity) -> Result<WaitMarker> {
        begin_wait_at(&wait_root()?, peer)
    }
}

fn begin_wait_at(root: &Path, peer: ProcessIdentity) -> Result<WaitMarker> {
    crate::paths::ensure_private_dir(root)
        .with_context(|| format!("make {} private", root.display()))?;
    let dir = peer_dir(root, peer);
    crate::paths::ensure_private_dir(&dir)
        .with_context(|| format!("make {} private", dir.display()))?;

    static NEXT_MARKER: AtomicU64 = AtomicU64::new(1);
    let nonce = NEXT_MARKER.fetch_add(1, Ordering::Relaxed);
    let path = dir.join(format!("{}-{nonce}.wait", std::process::id()));
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .with_context(|| format!("create SSH wait marker {}", path.display()))?;
    Ok(WaitMarker { path })
}

impl Drop for WaitMarker {
    fn drop(&mut self) {
        // Leave the per-peer directory in place. Removing an empty directory
        // races another sign between its mkdir and marker creation; empty dirs
        // are harmless and the daemon clears the whole marker root at startup.
        let _ = fs::remove_file(&self.path);
    }
}

/// A crashed daemon can leave marker files behind. A fresh SSH-agent listener
/// owns the whole set, so it clears them before accepting requests.
pub(crate) fn reset_wait_markers() -> Result<()> {
    reset_wait_markers_at(&wait_root()?)
}

fn reset_wait_markers_at(root: &Path) -> Result<()> {
    match fs::symlink_metadata(root) {
        Ok(meta) if meta.file_type().is_symlink() => {
            fs::remove_file(root).with_context(|| format!("remove stale symlink {}", root.display()))?;
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
    let secreq = std::env::current_exe()
        .context("determine the running secreq path")?;
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
                bail!(
                    "{} already exists and is not the secreq SSH observer; leaving it untouched",
                    target.display()
                );
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

/// Remove only the special observer shim. An ordinary wrapped `ssh` also
/// carries Secreq's generic sentinel, but `ssh setup --undo` must never delete
/// that separately-requested wrap.
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
         # {}: ssh-observer\n\
         # {OBSERVER_SENTINEL}\n\
         # Created by `secreq ssh setup`. Removed by `secreq ssh setup --undo`.\n\
         # Do not edit by hand.\n\
         export {OBSERVER_ENV}=1\n\
         export {REAL_SSH_ENV}={real_ssh}\n\
         exec {secreq} \"$@\"\n",
        crate::shim::SENTINEL,
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
        if !is_executable(&candidate) || is_secreq_managed_shim(&candidate) {
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

fn is_secreq_managed_shim(path: &Path) -> bool {
    let Ok(file) = fs::File::open(path) else {
        return false;
    };
    let mut prefix = Vec::new();
    if file.take(256).read_to_end(&mut prefix).is_err() || !prefix.starts_with(b"#!") {
        return false;
    }
    prefix
        .windows(crate::shim::SENTINEL.len())
        .any(|window| window == crate::shim::SENTINEL.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(pid: u32, start_time: u64) -> ProcessIdentity {
        ProcessIdentity { pid, start_time }
    }

    #[test]
    fn wait_marker_exists_only_while_the_guard_is_alive() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("waits");
        let identity = peer(42, 9001);

        let marker = begin_wait_at(&root, identity).expect("begin wait");
        assert!(wait_active_at(&root, identity));
        drop(marker);
        assert!(!wait_active_at(&root, identity));
    }

    #[test]
    fn one_completed_sign_does_not_clear_a_sibling_wait() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("waits");
        let identity = peer(42, 9001);

        let first = begin_wait_at(&root, identity).expect("first wait");
        let second = begin_wait_at(&root, identity).expect("second wait");
        drop(first);
        assert!(wait_active_at(&root, identity));
        drop(second);
        assert!(!wait_active_at(&root, identity));
    }

    #[test]
    fn reset_removes_stale_markers() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("waits");
        let identity = peer(42, 9001);
        let marker = begin_wait_at(&root, identity).expect("begin wait");
        std::mem::forget(marker); // model a daemon crash: Drop never ran.

        reset_wait_markers_at(&root).expect("reset");
        assert!(!wait_active_at(&root, identity));
    }

    #[test]
    fn observer_body_is_a_generic_managed_shim_and_bakes_real_ssh() {
        let body = observer_body(Path::new("/opt/secreq/bin/secreq"), Path::new("/usr/bin/ssh"));
        assert!(body.contains(crate::shim::SENTINEL));
        assert!(body.contains(OBSERVER_SENTINEL));
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
