//! A sandboxed secreq run on a real pty, plus a rendered view of what a
//! terminal would be showing.
//!
//! Two callers, and they want different things from the same machinery:
//!
//! - `prompt_pty.rs` asserts on the **raw byte stream** — it is testing that
//!   a specific escape sequence (the DECCKM reset) was emitted, which a
//!   rendered screen deliberately swallows.
//! - `cli_transcripts.rs` records the **rendered screen** — what a user
//!   actually sees, with cliclack's in-place redraws already collapsed.
//!
//! So `PtyRun` keeps every byte and renders on demand through `vt100`.
//! Sessions are a few kilobytes, so re-parsing the whole buffer per query
//! costs nothing and keeps the run free of incremental-parser state that
//! could disagree with the bytes on disk.
//!
//! **The controlling terminal is the load-bearing part.** `console` (under
//! cliclack) reads keys from `/dev/tty`, not stdin, so wiring the pty slave
//! to the child's stdio is not enough — the child must `setsid()` and adopt
//! the slave via `TIOCSCTTY` or every keystroke this harness sends lands
//! nowhere and the run hangs at the first prompt.

#![cfg(unix)]

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{FromRawFd, OwnedFd};
use std::process::{Child, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::Sandbox;

/// Terminal geometry every pty run gets.
///
/// Pinned rather than inherited: cliclack wraps its prompts to the terminal
/// width, so an unpinned size would make a recorded transcript depend on the
/// window the developer happened to regenerate it in. 80 columns is the
/// width docs prose assumes.
///
/// The row count is not a viewport — it is headroom. Frames are trimmed of
/// trailing blank lines, so extra rows cost nothing, while a session that
/// outgrows them scrolls and the recording silently loses its opening
/// lines off the top (`ssh setup` did exactly that at 40). Keep this
/// comfortably above the longest flow.
pub const COLS: u16 = 80;
pub const ROWS: u16 = 80;

/// Open a pty pair sized to [`COLS`] × [`ROWS`]. Returns `(master, slave)`.
fn openpty() -> (OwnedFd, OwnedFd) {
    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    let mut size = libc::winsize {
        ws_row: ROWS,
        ws_col: COLS,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let ok = unsafe {
        libc::openpty(
            &raw mut master,
            &raw mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut size,
        )
    };
    assert_eq!(ok, 0, "openpty failed: {}", std::io::Error::last_os_error());
    unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) }
}

/// A sandboxed secreq run wired to a pty slave as its controlling terminal,
/// with everything the child writes accumulating in `output`.
pub struct PtyRun {
    child: Child,
    master: File,
    output: Arc<Mutex<Vec<u8>>>,
    redactions: Vec<(String, String)>,
}

impl PtyRun {
    pub fn spawn(sb: &Sandbox, args: &[&str]) -> Self {
        Self::spawn_with(sb.cmd(args))
    }

    /// [`PtyRun::spawn`] for a command the caller has already customised
    /// (extra env, a seeded `$PATH`). The command must already carry the
    /// sandbox's isolation set — build it from [`Sandbox::cmd`].
    pub fn spawn_with(mut cmd: std::process::Command) -> Self {
        let (master, slave) = openpty();
        cmd.stdin(Stdio::from(slave.try_clone().expect("dup slave")))
            .stdout(Stdio::from(slave.try_clone().expect("dup slave")))
            .stderr(Stdio::from(slave));
        // A pty says "terminal", but not *which* terminal. Without TERM the
        // `console` crate's feature detection falls back to a dumb terminal
        // and cliclack drops the colour that a transcript exists to show.
        cmd.env("TERM", "xterm-256color");
        unsafe {
            use std::os::unix::process::CommandExt;
            cmd.pre_exec(|| {
                // New session + adopt the pty as controlling terminal, so
                // the child's `/dev/tty` is our master's counterpart.
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::ioctl(0, libc::TIOCSCTTY.into(), 0) < 0 {
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
            redactions: Vec::new(),
        }
    }

    /// Every byte the child has written so far, unredacted.
    pub fn output_so_far(&self) -> Vec<u8> {
        self.output.lock().unwrap().clone()
    }

    /// Replace `from` with `to` in the output *before* it is rendered.
    ///
    /// The sandbox lives under a tempdir, so a recorded session is full of
    /// `/var/folders/…/.tmpS8cwq4/secreq/wraps.json5` where a reader's
    /// machine would say something human. Substituting on the byte stream
    /// rather than the rendered screen means the emulator lays out the
    /// *substituted* text, so wrapping lands where it would have on a real
    /// terminal showing that path.
    ///
    /// **Prefer a replacement the same width as what it replaces.** Text
    /// the program merely printed reflows correctly at any width, but text
    /// it *positioned* does not: `cliclack::note` draws a box sized to its
    /// longest line, and a shorter substitution leaves the right border
    /// stranded where the original text used to end. Callers that care
    /// should pin the widths — see `cli_transcripts.rs`.
    pub fn redact(&mut self, from: impl Into<String>, to: impl Into<String>) -> &mut Self {
        self.redactions.push((from.into(), to.into()));
        self
    }

    /// Everything written so far, rendered the way a terminal would render
    /// it: in-place redraws collapsed, cursor moves applied, only the final
    /// state of each cell surviving.
    pub fn screen(&self) -> vt100::Screen {
        let mut bytes = self.output_so_far();
        if !self.redactions.is_empty() {
            // Redactions are plain text on both sides, so this stays a
            // straight string substitution — no escape sequence can contain
            // a filesystem path.
            let mut text = String::from_utf8_lossy(&bytes).into_owned();
            for (from, to) in &self.redactions {
                text = text.replace(from, to);
            }
            bytes = text.into_bytes();
        }
        let mut parser = vt100::Parser::new(ROWS, COLS, 0);
        parser.process(&bytes);
        parser.screen().clone()
    }

    /// Block until `needle` shows up in the child's raw output.
    pub fn wait_for(&self, needle: &str, timeout: Duration) -> Vec<u8> {
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

    /// Block until `needle` is visible on the rendered screen.
    ///
    /// Distinct from [`PtyRun::wait_for`]: text that a later redraw erased
    /// satisfies the raw-bytes wait forever, but stops satisfying this one.
    /// A recorder wants this — it is about to photograph the screen.
    pub fn wait_for_screen(&self, needle: &str, timeout: Duration) -> vt100::Screen {
        let deadline = Instant::now() + timeout;
        loop {
            let screen = self.screen();
            if screen.contents().contains(needle) {
                return screen;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {needle:?} on screen; screen was:\n{}",
                screen.contents()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Wait until the screen stops changing, so a snapshot catches a
    /// finished frame rather than a half-drawn one.
    ///
    /// `wait_for_screen` returns the instant a string appears, which for a
    /// multi-line redraw can be mid-write. Settling on two identical reads
    /// separated by `quiet` is the cheap fix, and cliclack redraws in one
    /// burst so the window needed is small.
    pub fn wait_until_settled(&self, quiet: Duration, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        let mut last = self.output_so_far().len();
        loop {
            std::thread::sleep(quiet);
            let now = self.output_so_far().len();
            if now == last {
                return;
            }
            last = now;
            assert!(
                Instant::now() < deadline,
                "screen never settled; output so far:\n{}",
                String::from_utf8_lossy(&self.output_so_far())
            );
        }
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.master.write_all(bytes).expect("write to pty");
        self.master.flush().expect("flush pty");
    }

    pub fn press_enter(&mut self) {
        self.write_bytes(b"\r");
    }

    /// Type an arrow-down the way a DECCKM-honoring terminal would: SS3
    /// while still in application mode, CSI once the reset has been seen.
    pub fn press_arrow_down(&mut self) {
        let out = self.output_so_far();
        let seq: &[u8] = if DECCKM_CLEARING.iter().any(|reset| twoway(&out, reset)) {
            b"\x1b[B"
        } else {
            b"\x1bOB"
        };
        self.write_bytes(seq);
    }

    /// Wait for exit, killing the child on timeout so a hung prompt fails
    /// the test instead of the harness.
    pub fn wait_exit(&mut self, timeout: Duration) -> std::process::ExitStatus {
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

impl Drop for PtyRun {
    fn drop(&mut self) {
        // A fixture that panics mid-flow leaves a child parked on a prompt
        // holding the pty open; without this the test binary hangs at exit
        // instead of reporting the failure.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Sequences that put a real terminal back into CSI cursor-key mode: the
/// explicit DECCKM reset (what `tput rmkx` emits) and DECSTR, the soft
/// terminal reset whose defined behavior includes DECCKM → normal.
pub const DECCKM_CLEARING: &[&[u8]] = &[b"\x1b[?1l", b"\x1b[!p"];

pub fn twoway(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
