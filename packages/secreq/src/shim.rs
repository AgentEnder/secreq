//! PATH shim management for `secreq wrap` / `unwrap`.
//!
//! A shim is a tiny POSIX shell script in the user's chosen `$shim_dir` that
//! `exec`s `'<abs path to secreq>' x '<wrap_name>' "$@"`. Because it lives on
//! `PATH`, every
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
    validate_wrap_name(wrap_name)?;
    let exe = secreq_exe()?;
    let path = shim_dir.join(wrap_name);

    if path.exists() {
        let existing = fs::read_to_string(&path)
            .with_context(|| format!("could not read existing file at {}", path.display()))?;
        if existing.contains(SENTINEL) {
            // Re-write to refresh the body in case the format changed.
            fs::write(&path, body(&exe, wrap_name))?;
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
    fs::write(&path, body(&exe, wrap_name))
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

/// POSIX-quote `s` for the shim's `exec` line. Single quotes disable every
/// expansion `sh` performs; an embedded quote is closed, escaped, reopened.
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Absolute path to the running `secreq`, baked into every shim body.
///
/// A shim that said `exec secreq …` resolved that name through whatever PATH
/// its caller happened to have. The shim dir wins only until something
/// prepends to PATH later — direnv, asdf, `node_modules/.bin` — at which
/// point a `secreq` earlier on PATH intercepts every wrapped command with no
/// prompt and no audit row. [`crate::commands`]'s `find_real_binary` is
/// already hardened against this exact shape of hijack; the shim's own lookup
/// was not.
fn secreq_exe() -> Result<PathBuf> {
    let exe =
        std::env::current_exe().context("could not determine the running secreq's own path")?;
    // Resolve symlinks so the shim names the binary rather than a launcher
    // link that could later be repointed.
    Ok(fs::canonicalize(&exe).unwrap_or(exe))
}

/// Reject a wrap name that cannot safely be a filename *or* a shell word.
///
/// The name reaches the shim three times: as a path segment under
/// `shim_dir`, inside `#` comment lines, and as an argument on the `exec`
/// line. A newline ends a comment and starts a command; a `/` escapes the
/// shim directory. Following `paths.rs`, these are refused rather than
/// sanitized, so two distinct names can never collapse onto one file.
fn validate_wrap_name(wrap_name: &str) -> Result<()> {
    if wrap_name.is_empty() {
        bail!("a wrap name cannot be empty");
    }
    if wrap_name == "." || wrap_name == ".." || wrap_name.contains(['/', '\0', '\n', '\r']) {
        bail!(
            "invalid wrap name {wrap_name:?}: a wrap name cannot be `.`, `..`, or contain \
             `/`, NUL, or a newline"
        );
    }
    // Shimming our own name gives `exec <secreq> x secreq …`, which re-enters
    // the wrap path on every invocation and leaves no un-shimmed way to undo
    // itself.
    if wrap_name == "secreq" {
        bail!("refusing to shim `secreq` itself: the shim would re-enter secreq on every call");
    }
    Ok(())
}

fn body(exe: &Path, wrap_name: &str) -> String {
    let exe_q = sh_quote(&exe.display().to_string());
    let wrap_q = sh_quote(wrap_name);
    format!(
        "#!/bin/sh\n\
         # {SENTINEL}: wrap={wrap_name}\n\
         # Created by `secreq wrap {wrap_name}`. Removed by `secreq unwrap {wrap_name}`.\n\
         # Do not edit by hand.\n\
         exec {exe_q} x {wrap_q} \"$@\"\n"
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
        // The shim names secreq by absolute path, never by bare name.
        let exe = secreq_exe().unwrap();
        assert!(
            body.contains(&format!("exec '{}' x 'gh' \"$@\"", exe.display())),
            "got: {body}"
        );
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
        assert!(body.contains("x 'gh'"), "got: {body}");
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

    /// A shim that resolved `secreq` through the caller's PATH could be
    /// hijacked by anything that prepends to PATH later (direnv, asdf,
    /// `node_modules/.bin`), intercepting every wrapped command with no
    /// prompt and no audit row.
    #[test]
    fn the_shim_names_secreq_by_absolute_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = install(dir.path(), "gh").unwrap();
        let body = fs::read_to_string(&path).unwrap();
        let exec_line = body
            .lines()
            .find(|l| l.starts_with("exec "))
            .expect("shim has an exec line");
        assert!(
            !exec_line.starts_with("exec secreq"),
            "bare name would resolve through the caller's PATH: {exec_line}"
        );
        assert!(exec_line.contains('/'), "not an absolute path: {exec_line}");
    }

    /// The name lands in a `#` comment and on the `exec` line. A newline
    /// ends the comment and starts a command; a `/` escapes the shim dir.
    #[test]
    fn install_rejects_a_wrap_name_that_is_not_a_safe_filename_or_shell_word() {
        let dir = tempfile::tempdir().unwrap();
        for bad in ["", ".", "..", "a/b", "gh\nrm -rf ~", "gh\rwhoami"] {
            assert!(
                install(dir.path(), bad).is_err(),
                "should have refused {bad:?}"
            );
        }
    }

    /// Shimming our own name yields `exec <secreq> x secreq …`, which
    /// re-enters the wrap path on every call with no un-shimmed way out.
    #[test]
    fn install_refuses_to_shim_secreq_itself() {
        let dir = tempfile::tempdir().unwrap();
        let err = install(dir.path(), "secreq").expect_err("must refuse");
        assert!(format!("{err:#}").contains("re-enter"), "{err:#}");
    }

    /// A quote in a wrap name must not break out of the exec line.
    #[test]
    fn sh_quote_neutralises_an_embedded_single_quote() {
        assert_eq!(sh_quote("gh"), "'gh'");
        assert_eq!(sh_quote("it's"), r"'it'\''s'");
    }
}
