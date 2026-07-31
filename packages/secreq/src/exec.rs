//! Child execution with env injection and output masking (§8).
//!
//! Two paths:
//! - **PTY** (interactive: both stdin and stdout are terminals) — allocate a
//!   pseudo-terminal so the child behaves as if run directly, forward stdin and
//!   `SIGWINCH`, and stream the child's output through the masking filter.
//! - **Piped** (non-TTY) — no PTY, but the child's stdout/stderr are still
//!   streamed through maskers so leaked secrets are redacted (§8).
//!
//! Both paths deliberately leave background descendants alive. After the
//! direct child exits, the observable child session/process group is reported
//! and its output endpoint is kept open until that scope empties, so teardown
//! itself does not become an implicit signal.

use std::fs::OpenOptions;
use std::io::{IsTerminal, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use serde::{Deserialize, Serialize};
use sysinfo::{ProcessStatus, System};
use zeroize::Zeroizing;

use crate::audit::AuditSurvivor;
use crate::mask::Masker;
use crate::secret::SecretValue;

const IO_GUARD_SCOPE_ENV: &str = "SECREQ_INTERNAL_IO_GUARD_SCOPE";
const IO_GUARD_FDS_ENV: &str = "SECREQ_INTERNAL_IO_GUARD_FDS";
const PTY_SUPERVISOR_STATUS_ENV: &str = "SECREQ_INTERNAL_PTY_SUPERVISOR_STATUS";

#[derive(Clone, Copy)]
enum ChildScope {
    Session(u32),
    ProcessGroup(u32),
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum SupervisorStatus {
    Exited { code: i32 },
    Error { message: String },
}

/// Run `command` with `env_overrides` applied on top of the inherited
/// environment, redacting any of `secrets` that appears in the child's output.
/// Returns the child's exit code.
pub fn run(
    command: &[String],
    env_overrides: &[(String, String)],
    secrets: &[SecretValue],
    cwd: &Path,
) -> Result<i32> {
    // Plaintext, and long-lived: this copy and the clone each masking thread
    // takes of it are live for the child's whole run, so both are `Zeroizing`
    // for the reason `secret.rs` gives. `Masker::new` copies once more into
    // buffers that are `Zeroizing` too, and the clone it consumes scrubs as it
    // drops.
    let secret_bytes: Vec<Zeroizing<Vec<u8>>> = secrets
        .iter()
        .map(|s| Zeroizing::new(s.as_bytes().to_vec()))
        .collect();
    // Survivor commands can contain values expanded from the injected
    // environment. Redact every override independently of output masking
    // (`--raw` must never make the audit log contain a secret).
    let report_redactions: Vec<Zeroizing<Vec<u8>>> = env_overrides
        .iter()
        .map(|(_, value)| Zeroizing::new(value.as_bytes().to_vec()))
        .collect();

    if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
        run_pty(
            command,
            env_overrides,
            &secret_bytes,
            &report_redactions,
            cwd,
        )
    } else {
        run_piped(
            command,
            env_overrides,
            &secret_bytes,
            &report_redactions,
            cwd,
        )
    }
}

/// Build the session-leader supervisor that runs the real command inside the
/// PTY. The wrapped command cannot be the session leader itself: on macOS a
/// session leader's exit can hang up its surviving foreground process group
/// before the parent has a chance to observe it.
fn build_pty_supervisor_command(
    command: &[String],
    env_overrides: &[(String, String)],
    cwd: &Path,
) -> Result<(CommandBuilder, PathBuf)> {
    let status_path = std::env::temp_dir().join(format!(
        "secreq-pty-status-{}-{:016x}",
        std::process::id(),
        rand::random::<u64>()
    ));
    let mut cmd =
        CommandBuilder::new(std::env::current_exe().context("locate secreq for PTY supervisor")?);
    cmd.args(command);
    for (key, value) in env_overrides {
        cmd.env(key, value);
    }
    cmd.env(PTY_SUPERVISOR_STATUS_ENV, &status_path);
    cmd.cwd(cwd);
    Ok((cmd, status_path))
}

fn run_pty(
    command: &[String],
    env_overrides: &[(String, String)],
    secrets: &[Zeroizing<Vec<u8>>],
    report_redactions: &[Zeroizing<Vec<u8>>],
    cwd: &Path,
) -> Result<i32> {
    let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        })
        .context("failed to allocate PTY")?;

    // Named the way `run_piped` names it, off the same `first` element
    // the supervisor receives.
    let program = command.first().map_or("", String::as_str);
    let (cmd, status_path) = build_pty_supervisor_command(command, env_overrides, cwd)?;
    let mut child = pair
        .slave
        .spawn_command(cmd)
        .with_context(|| format!("failed to spawn `{program}`"))?;
    let child_pid = child
        .process_id()
        .context("PTY child did not report a process id")?;
    let scope = ChildScope::Session(child_pid);
    let guard_fd = duplicate_fd(
        pair.master
            .as_raw_fd()
            .context("PTY master did not expose a file descriptor")?,
    )
    .context("duplicate PTY master for survivor guard")?;

    // Independent handles taken before we hand the master to the resize thread.
    let mut reader = pair.master.try_clone_reader().context("clone pty reader")?;
    let mut writer = pair.master.take_writer().context("take pty writer")?;

    // Drop the slave so the child holds the only slave fd: when it exits, the
    // master read returns EOF and the output thread finishes.
    drop(pair.slave);

    // Put our terminal in raw mode so keystrokes (incl. Ctrl-C) reach the child;
    // the guard restores cooked mode on every exit path.
    let _raw = RawModeGuard::enable();

    // Output: pty -> mask -> our stdout.
    let mask_secrets = secrets.to_vec();
    let output_thread = thread::spawn(move || {
        let mut masker = Masker::new(mask_secrets);
        let mut stdout = std::io::stdout();
        let mut buf = [0u8; 8192];
        loop {
            // `buf.get(..n)`, not `buf[..n]`: a `Read` that over-reports what
            // it wrote should stop the pump, not panic inside a thread whose
            // job is to keep the child's output flowing.
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let Some(chunk) = buf.get(..n) else { break };
                    let masked = masker.push(chunk);
                    if stdout.write_all(&masked).is_err() || stdout.flush().is_err() {
                        break;
                    }
                }
            }
        }
        let tail = masker.finish();
        let _ = stdout.write_all(&tail);
        let _ = stdout.flush();
    });

    // Input: our stdin -> pty. Detached; ends when stdin closes or we exit.
    thread::spawn(move || {
        let mut stdin = std::io::stdin();
        let mut buf = [0u8; 8192];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let Some(chunk) = buf.get(..n) else { break };
                    if writer.write_all(chunk).is_err() || writer.flush().is_err() {
                        break;
                    }
                }
            }
        }
    });

    // Resize: own the master here and resize on SIGWINCH. Detached.
    spawn_resize_thread(pair.master);

    let exit_code = wait_for_supervised_child(child.as_mut(), &status_path)
        .with_context(|| format!("waiting for `{program}`"))?;
    let survivors = find_survivors(scope, Some(child_pid), report_redactions);
    if survivors.is_empty() {
        drop(guard_fd);
        let _ = child.wait();
        // With no survivor holding the slave, EOF follows the direct child's
        // exit. Join so the masker's tail reaches stdout before we return.
        let _ = output_thread.join();
    } else {
        // The PTY is the child session's controlling terminal. Closing its
        // final master would make the kernel deliver a hangup to that session,
        // so hand one duplicate to a scrubbed helper until the session empties.
        // The helper drains inherited output too, allowing this command to
        // return even when a survivor kept the slave open.
        spawn_io_guardian(scope, vec![guard_fd]);
        report_survivors(command, cwd, &survivors, report_redactions);
    }

    Ok(exit_code)
}

/// Run the real PTY child under a session leader that deliberately remains
/// alive while any observable process in the session survives.
///
/// `portable-pty` makes the process it spawns the session leader. If that were
/// the wrapped command, macOS could hang up its surviving process group as soon
/// as the command exited. Keeping this small supervisor alive makes PTY
/// survival match the piped path without taking terminal control away from the
/// wrapped command.
pub fn run_pty_supervisor_from_env() -> Option<i32> {
    let status_path = std::env::var_os(PTY_SUPERVISOR_STATUS_ENV).map(PathBuf::from)?;
    std::env::remove_var(PTY_SUPERVISOR_STATUS_ENV);
    let mut command = std::env::args_os().skip(1);
    let Some(program) = command.next() else {
        let _ = write_supervisor_status(
            &status_path,
            &SupervisorStatus::Error {
                message: "PTY supervisor received no command".to_owned(),
            },
        );
        return Some(2);
    };

    // Terminal-generated signals target the whole foreground process group.
    // The supervisor must remain present, while the real child restores the
    // normal dispositions and observes them exactly as a direct PTY child did.
    let forwarded_signals = [libc::SIGHUP, libc::SIGINT, libc::SIGQUIT, libc::SIGTERM];
    for signal in forwarded_signals {
        unsafe {
            libc::signal(signal, libc::SIG_IGN);
        }
    }

    let mut child_command = Command::new(program);
    child_command
        .args(command)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    unsafe {
        child_command.pre_exec(move || {
            for signal in forwarded_signals {
                libc::signal(signal, libc::SIG_DFL);
            }
            Ok(())
        });
    }
    let child = child_command.spawn();

    // The supervisor necessarily receives the whole environment so it can pass
    // it through to the real child. Scrub every value in place as soon as the
    // child has inherited it; survivor discovery must not leave an extra
    // long-lived secret holder behind. Walking `environ` avoids copying values
    // into Rust strings that would then need their own zeroization.
    scrub_environment();

    let mut child = match child {
        Ok(child) => child,
        Err(error) => {
            let _ = write_supervisor_status(
                &status_path,
                &SupervisorStatus::Error {
                    message: error.to_string(),
                },
            );
            return Some(127);
        }
    };
    let status = match child.wait() {
        Ok(status) => status,
        Err(error) => {
            let _ = write_supervisor_status(
                &status_path,
                &SupervisorStatus::Error {
                    message: error.to_string(),
                },
            );
            return Some(1);
        }
    };
    let code = status.code().unwrap_or(exit_code_from_signal(&status));
    if write_supervisor_status(&status_path, &SupervisorStatus::Exited { code }).is_err() {
        return Some(1);
    }

    let session = ChildScope::Session(std::process::id());
    while scope_has_survivors(session, Some(std::process::id())) {
        thread::sleep(Duration::from_millis(100));
    }
    Some(0)
}

fn scrub_environment() {
    unsafe extern "C" {
        static mut environ: *mut *mut libc::c_char;
    }

    unsafe {
        let mut entry_ptr = environ;
        while !entry_ptr.is_null() && !(*entry_ptr).is_null() {
            let mut byte = (*entry_ptr).cast::<u8>();
            while *byte != 0 && *byte != b'=' {
                byte = byte.add(1);
            }
            if *byte == b'=' {
                byte = byte.add(1);
                while *byte != 0 {
                    std::ptr::write_volatile(byte, 0);
                    byte = byte.add(1);
                }
            }
            entry_ptr = entry_ptr.add(1);
        }
    }
}

fn write_supervisor_status(path: &Path, status: &SupervisorStatus) -> Result<()> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .context("create PTY supervisor status")?;
    serde_json::to_writer(&mut file, status).context("write PTY supervisor status")?;
    file.flush().context("flush PTY supervisor status")
}

fn wait_for_supervised_child(
    child: &mut (dyn portable_pty::Child + Send + Sync),
    status_path: &Path,
) -> Result<i32> {
    loop {
        match std::fs::read(status_path) {
            Ok(bytes) => {
                if let Ok(status) = serde_json::from_slice::<SupervisorStatus>(&bytes) {
                    let _ = std::fs::remove_file(status_path);
                    return match status {
                        SupervisorStatus::Exited { code } => Ok(code),
                        SupervisorStatus::Error { message } => {
                            anyhow::bail!("PTY supervisor failed to spawn child: {message}")
                        }
                    };
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).context("read PTY supervisor status");
            }
        }
        if let Some(status) = child.try_wait().context("poll PTY supervisor")? {
            let _ = std::fs::remove_file(status_path);
            anyhow::bail!("PTY supervisor exited before reporting child status: {status}");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn run_piped(
    command: &[String],
    env_overrides: &[(String, String)],
    secrets: &[Zeroizing<Vec<u8>>],
    report_redactions: &[Zeroizing<Vec<u8>>],
    cwd: &Path,
) -> Result<i32> {
    let (program, args) = command.split_first().expect("command must not be empty");
    let mut cmd = Command::new(program);
    cmd.args(args)
        .current_dir(cwd)
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in env_overrides {
        cmd.env(key, value);
    }
    unsafe {
        cmd.pre_exec(|| {
            if libc::setpgid(0, 0) == -1 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }

    let mut child = cmd
        .spawn()
        .with_context(|| format!("failed to spawn `{program}`"))?;
    let child_pid = child.id();
    let scope = ChildScope::ProcessGroup(child_pid);
    // Moving the child into a reportable group must not make Ctrl-C (or an
    // explicit termination of secreq) disappear when stdin is still a TTY but
    // output is redirected. Stop forwarding before survivor discovery: after
    // the direct child exits, this process never signals the group.
    let signal_forwarder = SignalForwarder::start(child_pid);

    let child_stdout = child.stdout.take().context("capture child stdout")?;
    let child_stderr = child.stderr.take().context("capture child stderr")?;
    let guard_fds = vec![
        duplicate_fd(child_stdout.as_raw_fd()).context("duplicate child stdout pipe")?,
        duplicate_fd(child_stderr.as_raw_fd()).context("duplicate child stderr pipe")?,
    ];

    let out_thread = spawn_mask_pump(child_stdout, secrets.to_vec(), Stream::Stdout);
    let err_thread = spawn_mask_pump(child_stderr, secrets.to_vec(), Stream::Stderr);

    let status = child.wait().context("waiting for child")?;
    if let Some(forwarder) = signal_forwarder {
        forwarder.stop();
    }
    let survivors = find_survivors(scope, None, report_redactions);
    if survivors.is_empty() {
        drop(guard_fds);
        let _ = out_thread.join();
        let _ = err_thread.join();
    } else {
        // Keep inherited pipe readers alive and draining after this process
        // exits. Otherwise a survivor that later writes would receive SIGPIPE,
        // making piped execution's "survive" policy true only until its next
        // log line.
        spawn_io_guardian(scope, guard_fds);
        report_survivors(command, cwd, &survivors, report_redactions);
    }

    Ok(status.code().unwrap_or(exit_code_from_signal(&status)))
}

struct SignalForwarder {
    handle: signal_hook::iterator::Handle,
    thread: thread::JoinHandle<()>,
}

impl SignalForwarder {
    fn start(process_group: u32) -> Option<Self> {
        let signals = [
            signal_hook::consts::SIGHUP,
            signal_hook::consts::SIGINT,
            signal_hook::consts::SIGQUIT,
            signal_hook::consts::SIGTERM,
        ];
        let mut signals = signal_hook::iterator::Signals::new(signals).ok()?;
        let handle = signals.handle();
        let thread = thread::spawn(move || {
            for signal in signals.forever() {
                let _ = unsafe { libc::kill(-process_group.cast_signed(), signal) };
            }
        });
        Some(Self { handle, thread })
    }

    fn stop(self) {
        self.handle.close();
        let _ = self.thread.join();
    }
}

fn duplicate_fd(fd: RawFd) -> std::io::Result<OwnedFd> {
    let duplicate = unsafe { libc::dup(fd) };
    if duplicate == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
    }
}

fn scope_has_survivors(scope: ChildScope, exclude_pid: Option<u32>) -> bool {
    System::new_all().processes().values().any(|process| {
        Some(process.pid().as_u32()) != exclude_pid
            && !matches!(
                process.status(),
                ProcessStatus::Dead | ProcessStatus::Zombie
            )
            && process_in_scope(process, scope)
    })
}

fn find_survivors(
    scope: ChildScope,
    exclude_pid: Option<u32>,
    redactions: &[Zeroizing<Vec<u8>>],
) -> Vec<AuditSurvivor> {
    let system = System::new_all();
    let mut survivors: Vec<AuditSurvivor> = system
        .processes()
        .values()
        .filter(|process| {
            Some(process.pid().as_u32()) != exclude_pid
                && !matches!(
                    process.status(),
                    ProcessStatus::Dead | ProcessStatus::Zombie
                )
                && process_in_scope(process, scope)
        })
        .map(|process| AuditSurvivor {
            pid: process.pid().as_u32(),
            command: redact_for_display(&crate::provenance::process_command(process), redactions),
        })
        .collect();
    survivors.sort_by_key(|process| process.pid);
    survivors
}

fn process_in_scope(process: &sysinfo::Process, scope: ChildScope) -> bool {
    match scope {
        ChildScope::Session(session) => {
            process.session_id().map(sysinfo::Pid::as_u32) == Some(session)
        }
        ChildScope::ProcessGroup(group) => i32::try_from(process.pid().as_u32())
            .ok()
            .is_some_and(|pid| unsafe { libc::getpgid(pid) } == group.cast_signed()),
    }
}

fn redact_for_display(command: &str, redactions: &[Zeroizing<Vec<u8>>]) -> String {
    let mut masker = Masker::new(redactions.to_vec());
    let mut masked = masker.push(command.as_bytes());
    masked.extend(masker.finish());
    crate::provenance::command_for_display(&String::from_utf8_lossy(&masked))
}

fn report_survivors(
    command: &[String],
    cwd: &Path,
    survivors: &[AuditSurvivor],
    redactions: &[Zeroizing<Vec<u8>>],
) {
    let processes = survivors
        .iter()
        .map(|process| format!("{} {}", process.pid, process.command))
        .collect::<Vec<_>>()
        .join(", ");
    eprintln!(
        "secreq: background processes still running in child session/process group: {processes}; \
         processes that left this scope are not visible"
    );
    let redacted_command: Vec<String> = command
        .iter()
        .map(|arg| redact_for_display(arg, redactions))
        .collect();
    let _ = crate::audit::append_survivors(&redacted_command, cwd, survivors);
}

fn spawn_io_guardian(scope: ChildScope, fds: Vec<OwnedFd>) {
    let fd_list = fds
        .iter()
        .map(|fd| fd.as_raw_fd().to_string())
        .collect::<Vec<_>>()
        .join(",");
    let scope_value = match scope {
        ChildScope::Session(pid) => format!("session:{pid}"),
        ChildScope::ProcessGroup(pid) => format!("process_group:{pid}"),
    };
    let spawned = std::env::current_exe().and_then(|exe| {
        Command::new(exe)
            .env_clear()
            .env(IO_GUARD_SCOPE_ENV, scope_value)
            .env(IO_GUARD_FDS_ENV, fd_list)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
    });
    if spawned.is_err() {
        // Spawning the helper should be routine, but failure must not turn PTY
        // teardown back into a process reaper. Hold and drain in this process
        // until the observed scope empties instead.
        guard_io_until_scope_empty(scope, &fds);
    }
}

/// Run the scrubbed helper that keeps PTY/pipe readers alive until every
/// observable background process exits. `main` calls this before CLI parsing.
///
/// `None` means this is an ordinary invocation. `Some` is an internal helper
/// exit code; malformed internal state fails closed without reaching the CLI.
pub fn run_io_guardian_from_env() -> Option<i32> {
    let scope = std::env::var(IO_GUARD_SCOPE_ENV).ok()?;
    let fds = std::env::var(IO_GUARD_FDS_ENV).ok();
    std::env::remove_var(IO_GUARD_SCOPE_ENV);
    std::env::remove_var(IO_GUARD_FDS_ENV);

    let parsed_scope = scope
        .strip_prefix("session:")
        .and_then(|pid| pid.parse().ok())
        .map(ChildScope::Session)
        .or_else(|| {
            scope
                .strip_prefix("process_group:")
                .and_then(|pid| pid.parse().ok())
                .map(ChildScope::ProcessGroup)
        });
    let Some(scope) = parsed_scope else {
        return Some(2);
    };
    let Some(fds) = fds else { return Some(2) };
    let owned: Option<Vec<OwnedFd>> = fds
        .split(',')
        .map(|fd| fd.parse::<RawFd>().ok())
        .map(|fd| fd.filter(|fd| *fd >= 0))
        .map(|fd| fd.map(|fd| unsafe { OwnedFd::from_raw_fd(fd) }))
        .collect();
    let Some(owned) = owned.filter(|fds| !fds.is_empty()) else {
        return Some(2);
    };

    guard_io_until_scope_empty(scope, &owned);
    Some(0)
}

fn guard_io_until_scope_empty(scope: ChildScope, fds: &[OwnedFd]) {
    for fd in fds {
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        if flags != -1 {
            let _ = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) };
        }
    }

    let mut buffer = [0u8; 8192];
    loop {
        for fd in fds {
            loop {
                let read =
                    unsafe { libc::read(fd.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
                if read > 0 {
                    continue;
                }
                if read == -1
                    && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
                {
                    continue;
                }
                break;
            }
        }
        if !scope_has_survivors(scope, None) {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

/// Which of our output streams a pump writes to.
enum Stream {
    Stdout,
    Stderr,
}

/// Spawn a thread that masks `reader` into the chosen output stream.
fn spawn_mask_pump<R: Read + Send + 'static>(
    mut reader: R,
    secrets: Vec<Zeroizing<Vec<u8>>>,
    stream: Stream,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut masker = Masker::new(secrets);
        let mut buf = [0u8; 8192];
        let write_chunk = |bytes: &[u8]| match stream {
            Stream::Stdout => {
                let mut out = std::io::stdout();
                let _ = out.write_all(bytes);
                let _ = out.flush();
            }
            Stream::Stderr => {
                let mut err = std::io::stderr();
                let _ = err.write_all(bytes);
                let _ = err.flush();
            }
        };
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => match buf.get(..n) {
                    Some(chunk) => write_chunk(&masker.push(chunk)),
                    None => break,
                },
            }
        }
        write_chunk(&masker.finish());
    })
}

/// Own the PTY master and resize it whenever the terminal size changes.
fn spawn_resize_thread(master: Box<dyn portable_pty::MasterPty + Send>) {
    thread::spawn(move || {
        let signals = signal_hook::iterator::Signals::new([signal_hook::consts::SIGWINCH]);
        let Ok(mut signals) = signals else { return };
        for _ in signals.forever() {
            if let Ok((cols, rows)) = crossterm::terminal::size() {
                let _ = master.resize(PtySize {
                    rows,
                    cols,
                    pixel_width: 0,
                    pixel_height: 0,
                });
            }
        }
    });
}

/// On Unix, a process killed by signal N conventionally maps to exit code 128+N.
#[cfg(unix)]
fn exit_code_from_signal(status: &std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status.signal().map_or(1, |s| 128 + s)
}

#[cfg(not(unix))]
fn exit_code_from_signal(_status: &std::process::ExitStatus) -> i32 {
    1
}

/// RAII guard that enables raw mode and restores cooked mode on drop.
struct RawModeGuard {
    enabled: bool,
}

impl RawModeGuard {
    fn enable() -> RawModeGuard {
        let enabled = crossterm::terminal::enable_raw_mode().is_ok();
        RawModeGuard { enabled }
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        if self.enabled {
            let _ = crossterm::terminal::disable_raw_mode();
        }
    }
}
