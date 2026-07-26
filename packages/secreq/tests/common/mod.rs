//! Shared sandboxing for every integration test binary.
//!
//! **New integration test? Start here.** Construct a [`Sandbox`] and either
//! spawn the built binary through [`Sandbox::cmd`] or pin this process's
//! environment with [`Sandbox::enter`]. Both apply the *complete* isolation
//! set below; hand-rolled `.env(...)` pinning is how tests have escaped
//! before, and every var in the set is here because its omission bit us:
//!
//! - `SECREQ_HOME` — the root. Alone it is **not** enough: migrations
//!   deliberately probe the *pre-migration* locations through the legacy
//!   `$XDG_CONFIG_HOME` / `$XDG_STATE_HOME` logic, so a run with only the
//!   root pinned probes the real `~/.config/secreq` — an earlier draft that
//!   assumed otherwise moved a developer's real config into a tempdir that
//!   was deleted moments later.
//! - `XDG_CONFIG_HOME` / `XDG_STATE_HOME` — that legacy probe.
//! - `XDG_RUNTIME_DIR` — `paths::socket_dir()` prefers it; unpinned, a test
//!   binds sockets beside the developer's live daemon sockets.
//! - `HOME` — the backstop. Every lookup above falls back to
//!   `dirs::home_dir()`, so a resolution we forgot still can't escape.
//!
//! And the live channels a test must not inherit from the developer's
//! session:
//!
//! - `SECREQ_CONSENT_SOCK` / `SECREQ_SOCK` / `SSH_AUTH_SOCK` — a live socket
//!   would route a test's asks to the real daemon/agent.
//! - `SECREQ_NO_DAEMON=1` — **default-on**. Without it a consent path
//!   auto-spawns a real daemon and pops a native window that hangs the run
//!   waiting for a click. The one test that exercises the spawn path itself
//!   opts out via [`Sandbox::cmd_with_daemon`].
//! - `SHELL` — `init`'s auto-PATH-setup would otherwise edit shell rc files.
//! - `GITHUB_TOKEN` — a wrap whose declared env is already satisfied by the
//!   parent skips consent (by design), so a developer's exported token would
//!   silently change what a test exercises.
//!
//! (Unit tests inside the lib are covered separately by
//! `paths::test_fallback_root`, which is `#[cfg(test)]` and does not apply
//! to integration binaries — that's why this module exists.)
#![allow(dead_code)] // each test binary uses a subset of the helpers

/// Driving a sandboxed run on a real pty, for the interactive flows that
/// only exist in front of a terminal.
pub mod pty;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, MutexGuard, OnceLock};

/// Path to the built `secreq` binary under test.
pub fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_secreq")
}

/// `(var, sandbox subdirectory)` — every path secreq can resolve.
const PINNED_PATHS: &[(&str, &str)] = &[
    ("SECREQ_HOME", "secreq"),
    ("XDG_CONFIG_HOME", "legacy-config"),
    ("XDG_STATE_HOME", "legacy-state"),
    ("XDG_RUNTIME_DIR", "runtime"),
    ("HOME", "home"),
];

/// Vars removed outright: inherited live channels and behavior-steering
/// leaks. See the module docs for why each is listed.
const REMOVED: &[&str] = &[
    "SECREQ_CONSENT_SOCK",
    "SECREQ_SOCK",
    "SSH_AUTH_SOCK",
    "SHELL",
    "GITHUB_TOKEN",
];

/// A tempdir standing in for everything secreq can touch, plus the two ways
/// to point secreq at it: [`Sandbox::cmd`] (spawned binary) and
/// [`Sandbox::enter`] (this process).
pub struct Sandbox {
    dir: tempfile::TempDir,
}

impl Sandbox {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().expect("sandbox tempdir");
        for (_, sub) in PINNED_PATHS {
            // Legacy dirs stay absent: migration tests seed them
            // deliberately, and pre-creating them would change what the
            // legacy probe sees.
            if !sub.starts_with("legacy-") {
                std::fs::create_dir_all(dir.path().join(sub)).expect("sandbox subdir");
            }
        }
        Sandbox { dir }
    }

    /// The tempdir itself (parent of every pinned subdirectory).
    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    /// `$SECREQ_HOME` — the sandboxed secreq root.
    pub fn root(&self) -> PathBuf {
        self.dir.path().join("secreq")
    }

    /// The post-migration config location, `<root>/wraps.json5`.
    pub fn config_path(&self) -> PathBuf {
        self.root().join("wraps.json5")
    }

    /// The pinned `$XDG_RUNTIME_DIR` (socket dir parent).
    pub fn runtime_dir(&self) -> PathBuf {
        self.dir.path().join("runtime")
    }

    pub fn write_config(&self, body: &str) {
        std::fs::write(self.config_path(), body).expect("write sandbox config");
    }

    /// A `Command` for the built binary with the full isolation set applied
    /// and the daemon disabled. Later `.env(...)` calls win over the
    /// defaults, so a test needing a variation (e.g. a custom `SECREQ_HOME`)
    /// overrides after calling this rather than hand-rolling the set.
    pub fn cmd(&self, args: &[&str]) -> Command {
        let mut cmd = self.cmd_with_daemon(args);
        cmd.env("SECREQ_NO_DAEMON", "1");
        cmd
    }

    /// [`Sandbox::cmd`] without the no-daemon default, for the rare test
    /// whose subject *is* the daemon auto-spawn path. Everything else about
    /// the sandbox still applies; the spawned daemon resolves its socket,
    /// pidfile, and log into the tempdir.
    pub fn cmd_with_daemon(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(bin());
        cmd.args(args);
        for (var, sub) in PINNED_PATHS {
            cmd.env(var, self.dir.path().join(sub));
        }
        for var in REMOVED {
            cmd.env_remove(var);
        }
        cmd
    }

    /// Run the binary to completion under [`Sandbox::cmd`].
    pub fn run(&self, args: &[&str]) -> std::process::Output {
        self.cmd(args).output().expect("run sandboxed secreq")
    }

    /// Stamp the sandbox's migration level to what this build ships, the
    /// way a user would: by running a foreground command. Service-gated
    /// commands (`daemon`, `agent`, the window children) verify-only and
    /// refuse a fresh, unstamped root — call this first in tests that
    /// exercise them. The command's own outcome is irrelevant (it may fail
    /// on a missing config); the migration gate runs before dispatch.
    pub fn stamp_migrations(&self) {
        let _ = self.run(&["wraps"]);
    }

    /// Pin this *process's* environment to the sandbox until the guard
    /// drops, for tests that call lib functions in-process rather than
    /// spawning the binary. Integration tests link the lib without
    /// `cfg(test)`, so nothing else stops in-process path resolution from
    /// reaching the developer's real home — the host half of the scoped
    /// agent tests once wrote rows into the real `~/.secreq/audit.log` this
    /// way.
    ///
    /// The guard holds a global lock: `std::env` is process-global, so two
    /// pinned sandboxes at once would clobber each other. Prior values are
    /// restored on drop, even on panic.
    pub fn enter(&self) -> EnvGuard {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let lock = LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let mut saved = Vec::new();
        for (var, sub) in PINNED_PATHS {
            saved.push((*var, std::env::var_os(var)));
            std::env::set_var(var, self.dir.path().join(sub));
        }
        for var in REMOVED {
            saved.push((*var, std::env::var_os(var)));
            std::env::remove_var(var);
        }
        saved.push(("SECREQ_NO_DAEMON", std::env::var_os("SECREQ_NO_DAEMON")));
        std::env::set_var("SECREQ_NO_DAEMON", "1");

        EnvGuard { saved, _lock: lock }
    }
}

/// Restores the pre-[`Sandbox::enter`] environment on drop.
pub struct EnvGuard {
    saved: Vec<(&'static str, Option<OsString>)>,
    _lock: MutexGuard<'static, ()>,
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (var, value) in self.saved.drain(..) {
            match value {
                Some(v) => std::env::set_var(var, v),
                None => std::env::remove_var(var),
            }
        }
    }
}

/// Where the generated UI screenshot fixtures live, relative to the crate dir
/// (`cargo test` runs with `packages/secreq` as CWD).
pub const SCREENSHOT_DIR: &str = "../../dev-docs/ui-screenshots";
