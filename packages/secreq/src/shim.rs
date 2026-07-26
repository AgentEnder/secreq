//! PATH shim management for `secreq wrap` / `unwrap`.
//!
//! A shim is a tiny POSIX shell script in the user's chosen `$shim_dir` that
//! `exec`s `secreq <wrap_name> "$@"`. Because it lives on `PATH`, every
//! `execvp("gh", …)` — from interactive shells, from `npm` postinstalls,
//! from IDE-spawned subprocesses, from anything — resolves to our shim
//! first, runs through `secreq`'s consent + injection + masking, and then
//! exec's the real binary inside that wrapper.
//!
//! Every shim we write carries a sentinel comment so [`remove`] can refuse
//! to delete a `gh` file that wasn't ours. This is the structural difference
//! between "safe to undo" and "ate something the user wrote themselves."

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

/// Sentinel line we embed in every managed shim. Presence ⇒ we own the file
/// and can safely overwrite or delete it. Absence ⇒ hands off.
pub const SENTINEL: &str = "secreq-managed-shim";

/// Create the shim for `wrap_name` in `shim_dir`. Idempotent: if the shim
/// already exists and carries our sentinel, this is a no-op. If a file
/// exists at the target without the sentinel, returns an error rather than
/// clobbering.
pub fn install(shim_dir: &Path, wrap_name: &str) -> Result<PathBuf> {
    let path = shim_dir.join(wrap_name);

    if path.exists() {
        let existing = fs::read_to_string(&path)
            .with_context(|| format!("could not read existing file at {}", path.display()))?;
        if existing.contains(SENTINEL) {
            // Re-write to refresh the body in case the format changed.
            fs::write(&path, body(wrap_name))?;
            make_executable(&path)?;
            return Ok(path);
        }
        bail!(
            "{} already exists and isn't managed by secreq; refusing to overwrite. \
             Remove it manually and re-run, or rename it if you want to keep it.",
            path.display()
        );
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("could not create shim dir {}", parent.display()))?;
    }
    fs::write(&path, body(wrap_name))
        .with_context(|| format!("could not write shim to {}", path.display()))?;
    make_executable(&path)?;
    Ok(path)
}

/// Re-[`install`] the shim for every name in `wrap_names`, refreshing each
/// managed shim's body to the current format. Idempotent: `install` rewrites
/// the body when our sentinel is present, so this migrates stale bodies (e.g.
/// the old `exec secreq <wrap>` form → `exec secreq x <wrap>`). Returns the
/// path of every shim it wrote. Callers that don't want to abort on an
/// unowned file should filter to [`is_managed`] names first.
pub fn reinstall_all(
    shim_dir: &Path,
    wrap_names: impl IntoIterator<Item = String>,
) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for name in wrap_names {
        paths.push(install(shim_dir, &name)?);
    }
    Ok(paths)
}

/// Remove the shim for `wrap_name` if it exists AND carries our sentinel.
/// Returns `Ok(true)` if a shim was removed, `Ok(false)` if there was
/// nothing to remove, or `Err` if a file exists at the target without our
/// sentinel (we refuse to delete an unowned file).
pub fn remove(shim_dir: &Path, wrap_name: &str) -> Result<bool> {
    let path = shim_dir.join(wrap_name);
    if !path.exists() {
        return Ok(false);
    }
    let body =
        fs::read_to_string(&path).with_context(|| format!("could not read {}", path.display()))?;
    if !body.contains(SENTINEL) {
        bail!(
            "{} is not a secreq-managed shim (no sentinel); refusing to delete.",
            path.display()
        );
    }
    fs::remove_file(&path).with_context(|| format!("could not remove {}", path.display()))?;
    Ok(true)
}

/// True if a shim for `wrap_name` exists in `shim_dir` AND is managed by us.
pub fn is_managed(shim_dir: &Path, wrap_name: &str) -> bool {
    let path = shim_dir.join(wrap_name);
    fs::read_to_string(path).is_ok_and(|body| body.contains(SENTINEL))
}

fn body(wrap_name: &str) -> String {
    format!(
        "#!/bin/sh\n# {SENTINEL}: wrap={wrap_name}\n# Created by `secreq wrap {wrap_name}`. Removed by `secreq unwrap {wrap_name}`.\n# Do not edit by hand.\nexec secreq x {wrap_name} \"$@\"\n"
    )
}

fn make_executable(path: &Path) -> Result<()> {
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms)
        .with_context(|| format!("could not chmod {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_creates_executable_shim_with_sentinel() {
        let dir = tempfile::tempdir().unwrap();
        let path = install(dir.path(), "gh").unwrap();
        assert_eq!(path, dir.path().join("gh"));
        let body = fs::read_to_string(&path).unwrap();
        assert!(body.contains(SENTINEL));
        assert!(body.contains("exec secreq x gh"));
        // Executable bit set.
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755);
    }

    #[test]
    fn install_is_idempotent_when_we_already_own_the_file() {
        let dir = tempfile::tempdir().unwrap();
        install(dir.path(), "gh").unwrap();
        // Second install should refresh the body but not error.
        let path = install(dir.path(), "gh").unwrap();
        assert!(path.exists());
    }

    #[test]
    fn install_refuses_to_clobber_an_unowned_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("gh");
        fs::write(
            &target,
            "# someone else's gh shim\nexec /usr/local/bin/gh \"$@\"\n",
        )
        .unwrap();
        let err = install(dir.path(), "gh").unwrap_err();
        assert!(err.to_string().contains("isn't managed by secreq"));
        // The original file must be untouched.
        assert!(fs::read_to_string(&target)
            .unwrap()
            .contains("someone else"));
    }

    #[test]
    fn remove_deletes_our_shim_and_returns_true() {
        let dir = tempfile::tempdir().unwrap();
        install(dir.path(), "gh").unwrap();
        assert!(remove(dir.path(), "gh").unwrap());
        assert!(!dir.path().join("gh").exists());
    }

    #[test]
    fn remove_is_a_noop_when_nothing_exists() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!remove(dir.path(), "nope").unwrap());
    }

    #[test]
    fn remove_refuses_to_delete_an_unowned_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("gh");
        fs::write(&target, "not ours\n").unwrap();
        let err = remove(dir.path(), "gh").unwrap_err();
        assert!(err.to_string().contains("not a secreq-managed shim"));
        assert!(target.exists(), "must not have been deleted");
    }

    #[test]
    fn reinstall_all_migrates_a_stale_managed_body() {
        let dir = tempfile::tempdir().unwrap();
        // Simulate an old-format managed shim (pre-`x`, but with the sentinel
        // so we own it).
        let target = dir.path().join("gh");
        fs::write(
            &target,
            format!("#!/bin/sh\n# {SENTINEL}: wrap=gh\nexec secreq gh \"$@\"\n"),
        )
        .unwrap();

        let written = reinstall_all(dir.path(), ["gh".to_owned()]).unwrap();
        assert_eq!(written, vec![target.clone()]);
        let body = fs::read_to_string(&target).unwrap();
        assert!(body.contains("exec secreq x gh"), "got: {body}");
        assert!(!body.contains("exec secreq gh \""), "stale body remained");
    }

    #[test]
    fn is_managed_reflects_sentinel_presence() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!is_managed(dir.path(), "gh"));
        install(dir.path(), "gh").unwrap();
        assert!(is_managed(dir.path(), "gh"));
        // Overwrite with unowned content.
        fs::write(dir.path().join("gh"), "no sentinel here").unwrap();
        assert!(!is_managed(dir.path(), "gh"));
    }
}
