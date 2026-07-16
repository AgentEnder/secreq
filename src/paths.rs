//! Single source of truth for every path secreq touches.
//!
//! Everything hangs off one root — `$SECREQ_HOME`, defaulting to
//! `~/.secreq`:
//!
//! ```text
//! ~/.secreq/
//!   wraps.json5            config
//!   auto-rules.json5       config
//!   audit.log              append-only, daemon + wrap clients
//!   daemon.log
//!   daemon.jsonl
//!   shims/                 default $shim_dir
//!   run/                   sockets, only when $XDG_RUNTIME_DIR is unset
//!   .migration-state       machine-local, never synced
//!   .migration.lock
//!   migration-snapshots/
//! ```
//!
//! Before this module the same XDG-resolution logic lived in four places
//! (`wraps.rs`, `rules.rs`, `audit.rs`, `daemon/server.rs`), each with its
//! own base dir and its own fallback. See
//! `dev-docs/plans/2026-07-16-secreq-root-and-migrations.md`.
//!
//! **Migrations must not call into this module.** A migration is frozen
//! history: if `m0001` resolved its target through `secreq_root()` and this
//! function later changed, the migration would retroactively mean something
//! different for users who hadn't run it yet. Migrations inline their own
//! path logic.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Overrides the root. Replaces `XDG_CONFIG_HOME`/`XDG_STATE_HOME` as the
/// relocation knob — one var instead of four, which is also what lets tests
/// isolate with a single tempdir.
pub const SECREQ_HOME_ENV: &str = "SECREQ_HOME";

/// Root for all secreq state: `$SECREQ_HOME`, else `~/.secreq`.
pub fn secreq_root() -> Result<PathBuf> {
    // Safety net for the crate's own unit tests — see `test_fallback_root`.
    #[cfg(test)]
    if std::env::var_os(SECREQ_HOME_ENV).is_none_or(|v| v.is_empty()) {
        return Ok(test_fallback_root());
    }
    root_from(std::env::var_os(SECREQ_HOME_ENV), dirs::home_dir())
}

/// One tempdir per test process, standing in for `~/.secreq` when a unit
/// test hasn't pinned `$SECREQ_HOME`.
///
/// Without this, production code reached *transitively* from a unit test
/// writes to the developer's real home. `daemon::log` is the live example:
/// `daemon::state` tests call it, it resolves its path from the environment,
/// and with nothing pinned it appends to the real log — which is how
/// `~/.local/state/secreq/daemon.log` reached 473 MB of accumulated test
/// output. A test that has to remember to opt into isolation eventually
/// forgets; this makes the safe path the default.
///
/// This is test-only behavior living in production code, which is normally
/// worth avoiding. The honest alternative is injecting a sink into
/// `daemon::log` and threading it through the daemon — better, and a much
/// larger change. This is `#[cfg(test)]`, so it compiles out of the shipped
/// binary entirely, and integration tests link the lib without it and pin
/// `$SECREQ_HOME` themselves.
#[cfg(test)]
fn test_fallback_root() -> PathBuf {
    use std::sync::OnceLock;
    static DIR: OnceLock<tempfile::TempDir> = OnceLock::new();
    DIR.get_or_init(|| tempfile::tempdir().expect("test fallback tempdir"))
        .path()
        .to_path_buf()
}

/// Pure core of [`secreq_root`], split out so it's testable without
/// `set_var` — which is process-global and races across threads in the same
/// test binary.
fn root_from(override_env: Option<OsString>, home: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(raw) = override_env {
        if !raw.is_empty() {
            return Ok(PathBuf::from(raw));
        }
    }
    let home = home.context(
        "could not determine home directory for ~/.secreq (no $HOME?); \
         set $SECREQ_HOME to choose a root explicitly",
    )?;
    Ok(home.join(".secreq"))
}

pub fn wraps_path() -> Result<PathBuf> {
    Ok(secreq_root()?.join("wraps.json5"))
}

pub fn rules_path() -> Result<PathBuf> {
    Ok(secreq_root()?.join("auto-rules.json5"))
}

pub fn audit_log_path() -> Result<PathBuf> {
    Ok(secreq_root()?.join("audit.log"))
}

pub fn daemon_log_path() -> Result<PathBuf> {
    Ok(secreq_root()?.join("daemon.log"))
}

pub fn daemon_jsonl_path() -> Result<PathBuf> {
    Ok(secreq_root()?.join("daemon.jsonl"))
}

/// Default `$shim_dir` offered by `init`. Users may point `$shim_dir`
/// elsewhere in `wraps.json5`; this is only the suggestion.
pub fn default_shims_dir() -> Result<PathBuf> {
    Ok(secreq_root()?.join("shims"))
}

/// Directory holding `consent.sock`, `agent.sock`, and `daemon.pid`.
///
/// Deliberately still prefers `$XDG_RUNTIME_DIR` over the root: it is
/// spec-guaranteed mode 0700, on tmpfs, and never on NFS or a cloud-synced
/// home. `~/.secreq/run` offers none of those and the pidfile flock does not
/// substitute for them. On macOS `$XDG_RUNTIME_DIR` is typically unset, so
/// this resolves to `~/.secreq/run` — replacing the old `cache_dir()`
/// fallback, which was equally persistent and home-based but scattered.
///
/// Tests that need socket isolation must set `$XDG_RUNTIME_DIR` as well as
/// `$SECREQ_HOME`.
pub fn socket_dir() -> Result<PathBuf> {
    Ok(socket_dir_from(
        std::env::var_os("XDG_RUNTIME_DIR"),
        &secreq_root()?,
    ))
}

fn socket_dir_from(xdg_runtime: Option<OsString>, root: &Path) -> PathBuf {
    if let Some(raw) = xdg_runtime {
        if !raw.is_empty() {
            return PathBuf::from(raw).join("secreq");
        }
    }
    root.join("run")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_defaults_to_dot_secreq_under_home() {
        let root = root_from(None, Some(PathBuf::from("/home/ada"))).unwrap();
        assert_eq!(root, PathBuf::from("/home/ada/.secreq"));
    }

    #[test]
    fn secreq_home_overrides_the_root() {
        let root = root_from(
            Some(OsString::from("/tmp/custom")),
            Some(PathBuf::from("/home/ada")),
        )
        .unwrap();
        assert_eq!(root, PathBuf::from("/tmp/custom"));
    }

    #[test]
    fn empty_secreq_home_is_treated_as_unset() {
        // Matches the `.filter(|v| !v.is_empty())` convention the XDG
        // lookups already used. `SECREQ_HOME=` must not root us at "".
        let root = root_from(Some(OsString::from("")), Some(PathBuf::from("/home/ada"))).unwrap();
        assert_eq!(root, PathBuf::from("/home/ada/.secreq"));
    }

    #[test]
    fn override_works_without_a_home_dir() {
        // $SECREQ_HOME is the documented escape hatch when $HOME is absent,
        // so it must not require home_dir() to resolve.
        let root = root_from(Some(OsString::from("/tmp/custom")), None).unwrap();
        assert_eq!(root, PathBuf::from("/tmp/custom"));
    }

    #[test]
    fn no_home_and_no_override_is_an_error_naming_the_escape_hatch() {
        let err = root_from(None, None).unwrap_err().to_string();
        assert!(err.contains("SECREQ_HOME"), "unhelpful error: {err}");
    }

    #[test]
    fn socket_dir_prefers_xdg_runtime_dir() {
        let dir = socket_dir_from(
            Some(OsString::from("/run/user/1000")),
            Path::new("/home/ada/.secreq"),
        );
        assert_eq!(dir, PathBuf::from("/run/user/1000/secreq"));
    }

    #[test]
    fn socket_dir_falls_back_to_root_run() {
        let dir = socket_dir_from(None, Path::new("/home/ada/.secreq"));
        assert_eq!(dir, PathBuf::from("/home/ada/.secreq/run"));
    }

    #[test]
    fn empty_xdg_runtime_dir_is_treated_as_unset() {
        let dir = socket_dir_from(Some(OsString::from("")), Path::new("/home/ada/.secreq"));
        assert_eq!(dir, PathBuf::from("/home/ada/.secreq/run"));
    }
}
