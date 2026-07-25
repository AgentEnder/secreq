//! PTY-driven regression test for the interactive prompt flows.
//!
//! Arrow keys must move cliclack selects even when the terminal was left in
//! DECCKM "application cursor keys" mode (a crashed vim, a stray `smkx`),
//! where arrows arrive as SS3 `ESC O B` instead of CSI `ESC [ B`. The
//! `console` crate parses only CSI, so without a defense the selection
//! freezes while Enter and Escape keep working — the wrap picker becomes
//! "first item or nothing".
//!
//! secreq's defense is emitting the DECCKM reset (`ESC [ ? 1 l`) before
//! prompting. The harness below plays the part of a DECCKM-honoring
//! terminal that *starts* in application mode: it sends SS3 arrows until it
//! has seen the reset, CSI arrows after — so the test fails exactly when a
//! real stuck terminal would.
#![cfg(unix)]

mod common;

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{FromRawFd, OwnedFd};
use std::process::{Child, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::Sandbox;

/// Sequences that put a real terminal back into CSI cursor-key mode: the
/// explicit DECCKM reset (what `tput rmkx` emits) and DECSTR, the soft
/// terminal reset whose defined behavior includes DECCKM → normal.
const DECCKM_CLEARING: &[&[u8]] = &[b"\x1b[?1l", b"\x1b[!p"];

/// Open a pty pair. Returns `(master, slave)`.
fn openpty() -> (OwnedFd, OwnedFd) {
    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    let ok = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(ok, 0, "openpty failed: {}", std::io::Error::last_os_error());
    unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) }
}

/// A sandboxed secreq run wired to a pty slave as its controlling terminal
/// (console reads keys from `/dev/tty`, so stdio alone is not enough), with
/// everything the child writes accumulating in `output`.
struct PtyRun {
    child: Child,
    master: File,
    output: Arc<Mutex<Vec<u8>>>,
}

impl PtyRun {
    fn spawn(sb: &Sandbox, args: &[&str]) -> Self {
        let (master, slave) = openpty();
        let mut cmd = sb.cmd(args);
        cmd.stdin(Stdio::from(slave.try_clone().expect("dup slave")))
            .stdout(Stdio::from(slave.try_clone().expect("dup slave")))
            .stderr(Stdio::from(slave));
        unsafe {
            use std::os::unix::process::CommandExt;
            cmd.pre_exec(|| {
                // New session + adopt the pty as controlling terminal, so
                // the child's `/dev/tty` is our master's counterpart.
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = cmd.spawn().expect("spawn secreq in pty");

        let output = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&output);
        let mut reader = File::from(master.try_clone().expect("dup master"));
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            // EIO on the master means the slave side closed — normal exit.
            while let Ok(n) = reader.read(&mut buf) {
                if n == 0 {
                    break;
                }
                sink.lock().unwrap().extend_from_slice(&buf[..n]);
            }
        });

        PtyRun {
            child,
            master: File::from(master),
            output,
        }
    }

    fn output_so_far(&self) -> Vec<u8> {
        self.output.lock().unwrap().clone()
    }

    /// Block until `needle` shows up in the child's output.
    fn wait_for(&self, needle: &str, timeout: Duration) -> Vec<u8> {
        let deadline = Instant::now() + timeout;
        loop {
            let out = self.output_so_far();
            if twoway(&out, needle.as_bytes()) {
                return out;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {needle:?}; output so far:\n{}",
                String::from_utf8_lossy(&out)
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Type an arrow-down the way a DECCKM-honoring terminal would: SS3
    /// while still in application mode, CSI once the reset has been seen.
    fn press_arrow_down(&mut self) {
        let out = self.output_so_far();
        let seq: &[u8] = if DECCKM_CLEARING.iter().any(|reset| twoway(&out, reset)) {
            b"\x1b[B"
        } else {
            b"\x1bOB"
        };
        self.master.write_all(seq).expect("write arrow");
        self.master.flush().expect("flush arrow");
    }

    fn press_enter(&mut self) {
        self.master.write_all(b"\r").expect("write enter");
        self.master.flush().expect("flush enter");
    }

    /// Wait for exit, killing the child on timeout so a hung prompt fails
    /// the test instead of the harness.
    fn wait_exit(&mut self, timeout: Duration) -> std::process::ExitStatus {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                return status;
            }
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                panic!(
                    "child did not exit; output so far:\n{}",
                    String::from_utf8_lossy(&self.output_so_far())
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

fn twoway(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// `secreq wrap <bin>` in a terminal stuck in application cursor-key mode:
/// one arrow-down must reach the second item ("Gate only"), producing a
/// gate-only wrap. Before the DECCKM reset existed, the arrow degraded to
/// an `UnknownEscSeq` the select ignored, Enter took "Inject secrets", and
/// the flow wandered into the provider picker instead.
#[test]
fn wrap_select_arrows_survive_application_cursor_mode() {
    let sb = Sandbox::new();
    sb.write_config(&format!(
        r#"{{
            $shim_dir: "{shim}",
            providers: {{
                fake: {{ retrieve: ["printf", "%s", "{{locator}}"] }},
            }},
        }}"#,
        shim = sb.path().join("shims").display(),
    ));

    let mut run = PtyRun::spawn(&sb, &["wrap", "testbin"]);
    run.wait_for("What should this wrap do?", Duration::from_secs(20));
    run.press_arrow_down();
    std::thread::sleep(Duration::from_millis(150));
    run.press_enter();

    // Gate-only path goes straight to the reason prompt. Landing in the
    // provider picker means the arrow key was swallowed.
    let out = run.wait_for("Reason (shown in consent prompt)", Duration::from_secs(10));
    assert!(
        !twoway(&out, b"Provider for the next env var"),
        "arrow-down was ignored: select stayed on the first item"
    );
    run.press_enter(); // no reason

    let status = run.wait_exit(Duration::from_secs(10));
    assert!(status.success(), "wrap exited with {status:?}");

    let config = std::fs::read_to_string(sb.config_path()).expect("config written");
    assert!(
        config.contains("testbin"),
        "wrap missing from config:\n{config}"
    );
    assert!(
        !config.contains("secret://"),
        "gate-only wrap must inject nothing:\n{config}"
    );
}
