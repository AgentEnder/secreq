//! Single source of truth for every path secreq touches.
//!
//! Everything hangs off one root — `$SECREQ_HOME`, defaulting to
//! `~/.secreq`:
//!
//! ```text
//! ~/.secreq/
//!   config.toml            config
//!   auto-rules.toml       config
//!   devices.json           paired-device credentials
//!   rules/                 compiled wasm rule modules (<rule-id>.wasm)
//!   rule-drafts/           scaffolded programmatic-rule source projects
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
//! `brain: areas/secreq/design/2026-07-16-secreq-root-and-migrations.md`.
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

/// The one process-wide lock for `$SECREQ_HOME`, for tests.
///
/// Every path in this module resolves through [`secreq_root`], which reads
/// a process-global env var (falling back to a single per-process tempdir
/// when it is unset). Two kinds of test contend for that global: ones that
/// **set** it to their own tempdir (`audit::with_temp_log`) and ones that
/// only **read** a directory beneath it (the wasm-store tests, which list
/// [`rule_wasm_dir`] before and after a rollback and compare).
///
/// Both must hold *this* lock. A lock per module — which is what used to
/// exist — leaves a reader free to run while another module repoints the
/// root out from under it, so a before/after comparison silently spans two
/// different directories and the assertion fails on a file that was never
/// orphaned. Guarding the mutation without guarding the reads is the same
/// as not guarding it at all, so the lock lives with the global it
/// protects rather than with either caller.
#[cfg(test)]
pub(crate) fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Rewrite `path` to start with `token` when it sits under `home`, leaving
/// it absolute otherwise.
///
/// **The token is the caller's because the consumers disagree about what
/// they expand.** A shell rc needs `$HOME`: a tilde inside double quotes is
/// never expanded, so `export PATH="~/.secreq/shims:$PATH"` would put a
/// directory literally named `~` on PATH. `ssh_config` is the mirror image —
/// OpenSSH tilde-expands `IdentityAgent` but performs no shell-variable
/// expansion at all, so there it must be `~`. The UI, which only displays,
/// uses `~` as well.
///
/// `home` is a parameter rather than an environment read so the planners
/// that call this — which already take `home` for exactly this reason — stay
/// testable without touching a process-global.
///
/// Rewrites only on a path boundary, so `/Users/youthful/x` under a home of
/// `/Users/you` keeps its full prefix instead of becoming `<token>thful/x`.
pub fn under_home(path: &Path, home: &Path, token: &str) -> String {
    let path = path.display().to_string();
    let home = home.display().to_string();
    let home = home.trim_end_matches('/');
    if home.is_empty() {
        return path;
    }
    match path.strip_prefix(home) {
        Some(rest) if rest.starts_with('/') => format!("{token}{rest}"),
        _ => path,
    }
}

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
///
/// **A symlinked root is accepted, and used as the user spelled it.** Pointing
/// `~/.secreq` at an encrypted volume is a reasonable thing to want, so this
/// neither refuses one nor resolves it through `fs::canonicalize`. Resolving
/// was tried and is worse on every axis that matters:
///
/// - It does not close a check-to-use window. `canonicalize` hands back a
///   *string*; every later `open` re-walks each component from `/` and
///   re-follows whatever symlink is there at that moment. Closing that window
///   means holding a directory fd and going through `openat` with
///   `O_NOFOLLOW`, which is a different shape of module than this one.
/// - It makes two secreq processes *more* likely to disagree, not less. As it
///   stands every process re-follows the link on every open, so they all track
///   the same current target. Pinning at startup gives a daemon launched
///   before a repoint and a wrap launched after it two different roots — the
///   split-brain `audit.log` that refusing a relative root exists to prevent.
/// - It rewrites every path secreq *prints* and *writes down*. On macOS
///   `/var/folders/…` becomes `/private/var/folders/…`; and because
///   [`under_home`] then no longer matches, a user who symlinked `~/.secreq`
///   onto a volume gets that volume's absolute path baked into their
///   `~/.ssh/config` `IdentityAgent` line and their shell rc — stale the
///   moment they repoint the link, which is the reason they made it one.
/// - It is skipped exactly when the root is most interesting. `canonicalize`
///   requires the path to exist, so a first run — the one that is about to
///   *create* the root — falls back to the literal path regardless.
///
/// An attacker who can plant or swap `~/.secreq` can already write `$HOME`,
/// and so can replace the target's contents, the shell rc, or a shim on
/// `$PATH`. What secreq does defend is the mode of what it creates
/// ([`ensure_private_dir`], `atomic::replace`), which holds wherever the root
/// resolves to.
fn root_from(override_env: Option<OsString>, home: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(raw) = override_env {
        if !raw.is_empty() {
            let root = PathBuf::from(raw);
            // A relative root is not one root — it is one per working
            // directory. Every secreq process resolves it against its own cwd,
            // so `SECREQ_HOME=.secreq` gives the daemon one `audit.log` and a
            // wrap launched from a checkout another, written into whatever
            // repository the user happened to be standing in. Refused rather
            // than silently absolutised against *this* process's cwd, which
            // would only move the disagreement.
            if !root.is_absolute() {
                anyhow::bail!(
                    "${SECREQ_HOME_ENV} must be an absolute path, but is {}. \
                     A relative root resolves against each process's working \
                     directory, so the daemon and your wrapped commands would \
                     not share one.",
                    root.display(),
                );
            }
            return Ok(root);
        }
    }
    let home = home.context(
        "could not determine home directory for ~/.secreq (no $HOME?); \
         set $SECREQ_HOME to choose a root explicitly",
    )?;
    Ok(home.join(".secreq"))
}

pub fn wraps_path() -> Result<PathBuf> {
    Ok(secreq_root()?.join("config.toml"))
}

pub fn rules_path() -> Result<PathBuf> {
    Ok(secreq_root()?.join("auto-rules.toml"))
}

/// The paired-device registry.
///
/// It holds public keys, not secrets, but its mode is security-relevant:
/// anyone who can replace it can enroll themselves as an approver.
/// [`crate::link::devices::load`] therefore refuses a group- or
/// world-accessible registry.
pub fn devices_path() -> Result<PathBuf> {
    Ok(secreq_root()?.join("devices.json"))
}

/// Directory holding registered wasm rule modules (`rules/<id>.wasm`).
pub fn rule_wasm_dir() -> Result<PathBuf> {
    Ok(secreq_root()?.join("rules"))
}

/// Directory holding scaffolded programmatic-rule **source** projects,
/// each a subdirectory the rule editor generates and opens in the user's
/// editor. Distinct from [`rule_wasm_dir`], which holds the compiled,
/// registered `.wasm` modules.
pub fn rule_drafts_dir() -> Result<PathBuf> {
    Ok(secreq_root()?.join("rule-drafts"))
}

/// Canonical on-disk home for rule `rule_id`'s compiled wasm module.
/// `auto-rules.toml` records the (root-relative) path alongside the
/// module's sha256; this helper is where the registration tooling puts
/// the bytes.
///
/// Ids minted by [`crate::rules::new_rule_id`] are lowercase hex, but a
/// hand-edited file can carry any string — and deriving a filename from
/// it makes "no path separators" a new constraint, exactly like the
/// scope-socket case below. Rejected, not sanitized, for the same
/// aliasing reason.
pub fn rule_wasm_path(rule_id: &str) -> Result<PathBuf> {
    let bad = rule_id.is_empty()
        || rule_id == "."
        || rule_id == ".."
        || rule_id.contains('/')
        || rule_id.contains('\0');
    if bad {
        anyhow::bail!(
            "rule id {rule_id:?} can't be used as a wasm module filename \
             (no `/`, and not `.` or `..`)"
        );
    }
    Ok(rule_wasm_dir()?.join(format!("{rule_id}.wasm")))
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

/// Default `shim_dir` offered by `init`. Users may point `shim_dir`
/// elsewhere in `config.toml`; this is only the suggestion.
pub fn default_shims_dir() -> Result<PathBuf> {
    Ok(secreq_root()?.join("shims"))
}

/// Owner-only mode for every directory secreq creates under its root.
pub(crate) const PRIVATE_DIR_MODE: u32 = 0o700;

/// Owner-only mode for every file secreq creates under its root.
pub(crate) const PRIVATE_FILE_MODE: u32 = 0o600;

/// Create `dir` and its missing parents, owner-only, narrowing an existing
/// directory that is more permissive.
///
/// Nothing under the root is low-sensitivity even though none of it holds a
/// value: `audit.log` records every wrapped command's argv, cwd, caller chain
/// and the *names* of the secrets released; `auto-rules.toml` records which
/// commands skip the prompt, which is a map of where to aim. A plain
/// `create_dir_all` applies the process umask, so this lands 0755 under the
/// common 022 and 0777 under the 000 that container and CI images often set.
///
/// The narrowing pass matters as much as the creation one: the root was
/// created 0755 by every secreq built before this, so an install that
/// predates it stays world-traversable until something tightens it. `~/.ssh`
/// gets the same treatment in `ssh_setup`, for the same reason.
pub fn ensure_private_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(PRIVATE_DIR_MODE)
        .create(dir)?;

    // `DirBuilder::mode` applies only to directories it creates, so an
    // already-existing one keeps whatever mode it had.
    let current = std::fs::metadata(dir)?.permissions().mode() & 0o777;
    if current != PRIVATE_DIR_MODE {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(PRIVATE_DIR_MODE))?;
    }
    Ok(())
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

/// The `root`-relative half of [`socket_dir`], split out so callers that must
/// not read the ambient root (migrations, tests) can pass their own.
pub(crate) fn socket_dir_from(xdg_runtime: Option<OsString>, root: &Path) -> PathBuf {
    if let Some(raw) = xdg_runtime {
        if !raw.is_empty() {
            return PathBuf::from(raw).join("secreq");
        }
    }
    root.join("run")
}

/// Default socket for a scoped secret agent (`secreq agent open --scope
/// <name>`), in [`socket_dir`] beside `consent.sock` and `agent.sock`.
///
/// Named per-scope rather than a single `scope.sock`: a host serves one
/// sandbox per scope and may well serve several at once, so a shared path
/// would mean the second `agent open` failing to bind against the first.
///
/// `scope-` rather than `agent-`: `agent.sock` is the *SSH* agent, and a
/// sibling named `agent-my-vm.sock` would read as "the SSH agent for my-vm",
/// which is the one thing this socket is not.
///
/// `agent open --sock <path>` overrides this — brain needs the socket at a
/// path it chose so it can `ssh -R` it into the guest.
pub fn scoped_agent_socket(scope: &str) -> Result<PathBuf> {
    Ok(socket_dir()?.join(scoped_agent_socket_name(scope)?))
}

/// Filename half of [`scoped_agent_socket`], split out to be testable without
/// touching the environment.
///
/// A scope name is otherwise only ever *displayed* (it is the principal in the
/// consent prompt), so it has never had to be a valid filename. Deriving a
/// path from it makes that a new constraint, and one worth enforcing loudly:
/// `--scope ../../../tmp/x` would otherwise silently bind outside
/// [`socket_dir`]. Rejected, not sanitized — mapping `a/b` and `a-b` onto one
/// filename would let two distinct scopes collide on one socket.
fn scoped_agent_socket_name(scope: &str) -> Result<String> {
    let bad = scope.is_empty()
        || scope == "."
        || scope == ".."
        || scope.contains('/')
        || scope.contains('\0');
    if bad {
        anyhow::bail!(
            "scope name {scope:?} can't be used as a socket filename \
             (no `/`, and not `.` or `..`); either rename the scope or pass \
             `--sock <path>` to choose the path yourself"
        );
    }
    Ok(format!("scope-{scope}.sock"))
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
    fn devices_path_sits_in_the_secreq_root() {
        let path = devices_path().expect("devices_path");
        assert!(path.ends_with("devices.json"), "got {path:?}");
        assert_eq!(path.parent(), Some(secreq_root().unwrap().as_path()));
    }

    #[test]
    fn override_works_without_a_home_dir() {
        // $SECREQ_HOME is the documented escape hatch when $HOME is absent,
        // so it must not require home_dir() to resolve.
        let root = root_from(Some(OsString::from("/tmp/custom")), None).unwrap();
        assert_eq!(root, PathBuf::from("/tmp/custom"));
    }

    /// A relative root is not one root — it is one per working directory. The
    /// daemon would open `audit.log` beside wherever it was launched and a
    /// wrapped command would write its rows into whatever checkout the user
    /// was standing in, so the two would never agree on the same file.
    #[test]
    fn a_relative_secreq_home_is_refused() {
        for raw in ["secreq", "./secreq", ".", "..", "../elsewhere"] {
            let err = root_from(Some(OsString::from(raw)), Some(PathBuf::from("/home/ada")))
                .unwrap_err()
                .to_string();
            assert!(err.contains("absolute"), "{raw:?} accepted, or: {err}");
        }
    }

    /// The policy boundary next to [`a_relative_secreq_home_is_refused`]: a
    /// symlinked root is taken **as spelled**, neither refused nor resolved.
    /// See the note on [`root_from`] for why; this test is here so that
    /// "resolve it, surely" fails loudly rather than landing as a tidy-up.
    #[test]
    fn a_symlinked_secreq_home_is_taken_as_spelled() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("real");
        std::fs::create_dir(&target).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let root = root_from(Some(link.clone().into_os_string()), None).unwrap();
        assert_eq!(
            root, link,
            "a symlinked root must be used as the user spelled it — resolving \
             it rewrites every path secreq prints and bakes the link's current \
             target into ~/.ssh/config and the shell rc"
        );
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

    #[test]
    fn rule_wasm_path_is_named_after_the_rule_id() {
        let path = rule_wasm_path("0a1b2c").unwrap();
        assert!(path.ends_with("rules/0a1b2c.wasm"), "{}", path.display());
    }

    /// Same constraint as scope names: an id with a separator would
    /// resolve outside `rules/` entirely.
    #[test]
    fn a_rule_id_that_would_escape_the_rules_dir_is_refused() {
        for escape in ["../../tmp/evil", "a/b", "..", ".", ""] {
            assert!(
                rule_wasm_path(escape).is_err(),
                "{escape:?} must be refused"
            );
        }
    }

    #[test]
    fn scoped_agent_socket_is_named_after_its_scope() {
        assert_eq!(
            scoped_agent_socket_name("my-vm").unwrap(),
            "scope-my-vm.sock"
        );
    }

    /// Two scopes must never land on one socket, or the second `agent open`
    /// fails to bind against the first.
    #[test]
    fn distinct_scopes_get_distinct_sockets() {
        let a = scoped_agent_socket_name("build").unwrap();
        let b = scoped_agent_socket_name("test").unwrap();
        assert_ne!(a, b);
    }

    /// The scope name is a display principal being reused as a filename;
    /// a separator in it would bind outside `socket_dir()` entirely.
    #[test]
    fn a_scope_name_that_would_escape_the_socket_dir_is_refused() {
        for escape in ["../../tmp/evil", "a/b", "..", ".", ""] {
            let err = scoped_agent_socket_name(escape).unwrap_err().to_string();
            assert!(
                err.contains("--sock"),
                "{escape:?} must be refused with a way out: {err}"
            );
        }
    }

    /// Refused, not sanitized: mapping `a/b` onto `a-b` would silently alias
    /// two different scopes onto one socket.
    #[test]
    fn a_refused_scope_name_is_not_quietly_rewritten() {
        assert!(scoped_agent_socket_name("a/b").is_err());
        assert_eq!(scoped_agent_socket_name("a-b").unwrap(), "scope-a-b.sock");
    }

    /// `create_dir_all` applies the umask, so the root landed 0755 under the
    /// common 022 and 0777 under the 000 that CI images set.
    #[test]
    fn ensure_private_dir_creates_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let nested = tmp.path().join("a/b/c");
        ensure_private_dir(&nested).unwrap();
        for dir in [tmp.path().join("a"), tmp.path().join("a/b"), nested] {
            let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{} is {mode:o}", dir.display());
        }
    }

    /// The half `DirBuilder::mode` cannot do: it applies only to directories
    /// it creates, so every install predating this kept its 0755 root until
    /// something actively narrowed it.
    #[test]
    fn ensure_private_dir_narrows_an_existing_permissive_dir() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("legacy");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        ensure_private_dir(&dir).unwrap();

        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "an existing 0755 dir must be narrowed");
    }
}
