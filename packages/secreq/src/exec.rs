//! Child execution with env injection and output masking (§8).
//!
//! Two paths:
//! - **PTY** (interactive: both stdin and stdout are terminals) — allocate a
//!   pseudo-terminal so the child behaves as if run directly, forward stdin and
//!   `SIGWINCH`, and stream the child's output through the masking filter.
//! - **Piped** (non-TTY) — no PTY, but the child's stdout/stderr are still
//!   streamed through maskers so leaked secrets are redacted (§8).

use std::io::{IsTerminal, Read, Write};
use std::path::Path;
use std::thread;

use anyhow::{Context, Result};
use portable_pty::{native_pty_system, CommandBuilder, PtySize};

use crate::mask::Masker;
use crate::secret::SecretValue;

/// Run `command` with `env_overrides` applied on top of the inherited
/// environment, redacting any of `secrets` that appears in the child's output.
/// Returns the child's exit code.
pub fn run(
    command: &[String],
    env_overrides: &[(String, String)],
    secrets: &[SecretValue],
    cwd: &Path,
) -> Result<i32> {
    let secret_bytes: Vec<Vec<u8>> = secrets.iter().map(|s| s.as_bytes().to_vec()).collect();

    if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
        run_pty(command, env_overrides, &secret_bytes, cwd)
    } else {
        run_piped(command, env_overrides, &secret_bytes, cwd)
    }
}

/// Build a `CommandBuilder` with args, env overrides, and cwd applied.
fn build_command(
    command: &[String],
    env_overrides: &[(String, String)],
    cwd: &Path,
) -> CommandBuilder {
    let (program, args) = command.split_first().expect("command must not be empty");
    let mut cmd = CommandBuilder::new(program);
    cmd.args(args);
    for (key, value) in env_overrides {
        cmd.env(key, value);
    }
    cmd.cwd(cwd);
    cmd
}

fn run_pty(
    command: &[String],
    env_overrides: &[(String, String)],
    secrets: &[Vec<u8>],
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

    let cmd = build_command(command, env_overrides, cwd);
    let mut child = pair
        .slave
        .spawn_command(cmd)
        .with_context(|| format!("failed to spawn `{}`", command[0]))?;

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
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let masked = masker.push(&buf[..n]);
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
                    if writer.write_all(&buf[..n]).is_err() || writer.flush().is_err() {
                        break;
                    }
                }
            }
        }
    });

    // Resize: own the master here and resize on SIGWINCH. Detached.
    spawn_resize_thread(pair.master);

    let status = child.wait().context("waiting for child")?;
    // The output thread ends at EOF (child exit); join so the tail is flushed.
    let _ = output_thread.join();

    Ok(status.exit_code() as i32)
}

fn run_piped(
    command: &[String],
    env_overrides: &[(String, String)],
    secrets: &[Vec<u8>],
    cwd: &Path,
) -> Result<i32> {
    use std::process::{Command, Stdio};

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

    let mut child = cmd
        .spawn()
        .with_context(|| format!("failed to spawn `{program}`"))?;

    let child_stdout = child.stdout.take().context("capture child stdout")?;
    let child_stderr = child.stderr.take().context("capture child stderr")?;

    let out_thread = spawn_mask_pump(child_stdout, secrets.to_vec(), Stream::Stdout);
    let err_thread = spawn_mask_pump(child_stderr, secrets.to_vec(), Stream::Stderr);

    let status = child.wait().context("waiting for child")?;
    let _ = out_thread.join();
    let _ = err_thread.join();

    Ok(status.code().unwrap_or(exit_code_from_signal(&status)))
}

/// Which of our output streams a pump writes to.
enum Stream {
    Stdout,
    Stderr,
}

/// Spawn a thread that masks `reader` into the chosen output stream.
fn spawn_mask_pump<R: Read + Send + 'static>(
    mut reader: R,
    secrets: Vec<Vec<u8>>,
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
                Ok(n) => write_chunk(&masker.push(&buf[..n])),
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
