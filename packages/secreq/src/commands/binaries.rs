//! Finding the *real* binary on `$PATH`, and telling secreq's own shims
//! apart from it.
//!
//! Every wrapped invocation arrives through a shim that re-enters `secreq`,
//! so the wrap-and-run path can only exec the program the user meant once it
//! can recognise — and skip — the shims. [`first_on_path`] answers the
//! diagnostic half of the same question for `secreq doctor`: what `execvp`
//! would actually pick.

use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context as _, Result};

/// Locate the *real* binary on `$PATH`, skipping
/// - the configured shim dir, and
/// - any other secreq-managed shim found on PATH (identified by our
///   sentinel string in the file body).
///
/// The second exclusion is load-bearing: a user can end up with stray
/// shims in `~/.local/bin`, `/usr/local/bin`, or wherever an earlier
/// `secreq wrap` left one before they moved the shim dir. Those stray
/// shims are still functional (`exec secreq x <wrap> "$@"`) but secreq
/// doesn't know about them — and if the spawned-process PATH happens
/// to put one *before* the real binary's location, find_real_binary
/// would otherwise pick up the stray and spawn `secreq` recursively,
/// producing infinite-depth `secreq gh → secreq gh → secreq gh`
/// process chains. Checking the sentinel kills that loop dead.
pub(super) fn find_real_binary(binary: &str, skip: Option<&Path>) -> Result<PathBuf> {
    let path = std::env::var_os("PATH").context("no PATH in environment")?;
    for dir in std::env::split_paths(&path) {
        if skip.is_some_and(|s| s == dir) {
            continue;
        }
        let candidate = dir.join(binary);
        if !is_executable(&candidate) {
            continue;
        }
        if is_secreq_shim(&candidate) {
            // Silently skip — duplicate shims are user-config drift, not
            // an error condition. We just don't want them in the lookup.
            continue;
        }
        return Ok(candidate);
    }
    bail!("could not find a non-shim `{binary}` on PATH. Is it installed?")
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    meta.is_file() && (meta.permissions().mode() & 0o111 != 0)
}

/// True iff the file at `path` is a secreq-managed shim — i.e. carries
/// the sentinel string our `shim::body` emits.
///
/// We read at most the first 256 bytes, which is plenty: the sentinel
/// sits on line 2 of a 5-line script. Larger files we read partially
/// and bail; native binaries we'd never bother loading.
fn is_secreq_shim(path: &Path) -> bool {
    use std::io::Read;
    let Ok(f) = std::fs::File::open(path) else {
        return false;
    };
    // `take(256)` rather than reading into a fixed array and slicing to the
    // byte count: the buffer is then exactly what was read, with no length
    // to keep honest.
    let mut prefix = Vec::new();
    if f.take(256).read_to_end(&mut prefix).is_err() {
        return false;
    }
    // Quick reject: a Mach-O / ELF binary won't start with `#!`. Saves a
    // substring search on the typical case.
    if !prefix.starts_with(b"#!") {
        return false;
    }
    prefix
        .windows(crate::shim::SENTINEL.len())
        .any(|w| w == crate::shim::SENTINEL.as_bytes())
}

/// Pass through an unwrapped binary unchanged. Used when `secreq <bin>` is
/// invoked for a binary with no configured wrap — keeps the alias-everything
/// workflow ergonomic.
pub(super) fn passthrough_unwrapped(
    binary: &str,
    args: &[String],
    skip: Option<&Path>,
) -> Result<i32> {
    let real = find_real_binary(binary, skip)?;
    let err = Command::new(real).args(args).exec();
    // exec() only returns on failure.
    Err(anyhow::anyhow!("failed to exec `{binary}`: {err}"))
}

/// What `execvp(name, …)` would resolve to: the first executable named
/// `name` on the current `PATH`, in order. Returns `None` if not found.
pub(super) fn first_on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if is_executable(&candidate) {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn make_executable(path: &Path) {
        let mut perms = std::fs::metadata(path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(path, perms).unwrap();
    }

    #[test]
    fn is_secreq_shim_detects_a_managed_shim() {
        // Mirrors what `shim::body` writes: an sh script whose second
        // line carries the SENTINEL string.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gh");
        std::fs::write(
            &path,
            "#!/bin/sh\n# secreq-managed-shim: wrap=gh\nexec secreq x gh \"$@\"\n",
        )
        .unwrap();
        make_executable(&path);
        assert!(is_secreq_shim(&path));
    }

    #[test]
    fn is_secreq_shim_rejects_a_regular_script() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gh");
        std::fs::write(&path, "#!/bin/sh\necho hello\n").unwrap();
        make_executable(&path);
        assert!(!is_secreq_shim(&path));
    }

    #[test]
    fn is_secreq_shim_rejects_a_native_binary() {
        // Mach-O / ELF headers don't start with `#!`, so our cheap reject
        // path should kick in immediately. Use a tiny binary-like fixture:
        // 4 bytes that aren't a shebang.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gh");
        std::fs::write(&path, b"\x7fELF\0\0\0\0").unwrap();
        make_executable(&path);
        assert!(!is_secreq_shim(&path));
    }

    #[test]
    fn is_secreq_shim_returns_false_for_missing_files() {
        let path = std::path::PathBuf::from("/this/does/not/exist/gh");
        assert!(!is_secreq_shim(&path));
    }
}
