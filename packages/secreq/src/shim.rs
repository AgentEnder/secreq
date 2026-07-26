//! PATH shim management for `secreq wrap` / `unwrap`.
//!
//! A shim is a tiny POSIX shell script in the user's chosen `$shim_dir` that
//! `exec`s `'<abs path to secreq>' x '<wrap_name>' "$@"`. Because it lives
//! on `PATH`, every `execvp("gh", …)` — from interactive shells, from `npm`
//! postinstalls, from IDE-spawned subprocesses, from anything — resolves to
//! our shim first, runs through `secreq`'s consent + injection + masking,
//! and then exec's the real binary inside that wrapper.
//!
//! secreq is named by absolute path, not by bare name: a bare name resolves
//! through whatever `PATH` the *caller* had, and the shim dir only wins
//! until something prepends to `PATH` later. [`is_current`] detects a shim
//! written before that was true, and `secreq doctor` repairs it.
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
    // Before the shim, not only when we create the directory: a `$shim_dir`
    // left 0777 by an older secreq is repaired by the next `wrap` or `doctor`
    // refresh rather than waiting for a brand-new name.
    ensure_shim_dir(shim_dir)?;
    let path = shim_dir.join(wrap_name);

    if shim_entry(&path)?.is_some() {
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
    if shim_entry(&path)?.is_none() {
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
    // A symlink is never ours, and saying otherwise would send `install` at a
    // file it is about to refuse — a repair loop that reports an error instead
    // of doing nothing.
    matches!(shim_entry(&path), Ok(Some(_)))
        && fs::read_to_string(&path).is_ok_and(|body| body.contains(SENTINEL))
}

/// Does the managed shim for `wrap_name` match what [`install`] would write
/// right now?
///
/// Two ways a shim goes stale, both of which keep it working well enough to
/// look fine:
///
/// - It was written by a secreq that emitted `exec secreq x <wrap>`, so it
///   resolves our name through the caller's PATH and can be hijacked by any
///   `secreq` that lands earlier on it.
/// - It names an absolute path the binary has since moved away from, so it
///   fails at exec time with no hint that a stale shim is the reason.
///
/// `is_managed` cannot tell either case apart from a current shim, so
/// `secreq doctor` compares bodies. Returns `false` for a missing or unowned
/// file, which is [`install`]'s problem rather than a refresh.
pub fn is_current(shim_dir: &Path, wrap_name: &str) -> bool {
    let path = shim_dir.join(wrap_name);
    if !matches!(shim_entry(&path), Ok(Some(_))) {
        return false;
    }
    let Ok(existing) = fs::read_to_string(&path) else {
        return false;
    };
    if !existing.contains(SENTINEL) {
        return false;
    }
    secreq_exe().is_ok_and(|exe| existing == body(&exe, wrap_name))
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

/// Owner-only, for a shim dir secreq creates itself.
const SHIM_DIR_MODE: u32 = 0o700;

/// Create `$shim_dir` if it is missing, and refuse to leave a group- or
/// world-**writable** directory on the user's `PATH`.
///
/// `init` prepends this directory to `PATH` in a shell rc file and never
/// revisits the decision, so its mode is an arbitrary-code-execution control
/// for every command the user runs from then on: anyone who can create a file
/// there owns `gh`, `npm`, `ssh`. `create_dir_all` asks for 0777 and lets the
/// umask decide, which is 0755 under the common 022 and **0777** under the
/// `umask 000` that CI and container images routinely set — and nothing ever
/// looked at the result.
///
/// Two different rules, because they answer to different owners:
///
/// - **A directory we create** is ours, so it gets [`SHIM_DIR_MODE`]. Nothing
///   but the user's own processes resolves `PATH`, so no other principal needs
///   to traverse it, and the shim *names* alone say which commands the user
///   wrapped — the same reason `paths::ensure_private_dir` exists.
/// - **A directory the user already had** — `$shim_dir` may well be a shared
///   `~/.local/bin` — keeps its read and traverse bits. Narrowing that to 0700
///   would break every other tool that reads it, and read access was never the
///   finding. Only `g+w`/`o+w` come off, which cannot break a lookup.
///
/// Write access we cannot remove (a directory owned by someone else) is a hard
/// error: the alternative is prepending it to PATH anyway.
pub fn ensure_shim_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    let created = !dir.exists();
    fs::DirBuilder::new()
        .recursive(true)
        .mode(SHIM_DIR_MODE)
        .create(dir)
        .with_context(|| format!("could not create shim dir {}", dir.display()))?;

    // `DirBuilder::mode` is masked by the umask and applies only to directories
    // it creates, so neither the creating call nor a pre-existing directory can
    // be taken on trust.
    let current = fs::metadata(dir)
        .with_context(|| format!("could not stat shim dir {}", dir.display()))?
        .permissions()
        .mode()
        & 0o777;
    let wanted = if created {
        SHIM_DIR_MODE
    } else {
        current & !0o022
    };
    if current != wanted {
        fs::set_permissions(dir, fs::Permissions::from_mode(wanted)).with_context(|| {
            format!(
                "{} is group- or world-writable ({current:o}) and secreq could not narrow it; \
                 anyone who can write there controls every command on your PATH",
                dir.display()
            )
        })?;
    }
    Ok(())
}

/// Metadata for `path` **without** following a symlink, or `None` if nothing
/// is there. Errors if `path` is a symlink of any kind.
///
/// `Path::exists` stats the target, so a *dangling* symlink reads as "nothing
/// here" — which skipped the sentinel guard entirely and let the `fs::write`
/// that followed create the link's target, anywhere the user could write. A
/// symlink whose target does exist is no better: the sentinel was then read
/// out of the target, so aiming a link at any secreq-managed shim authorised
/// overwriting whatever it pointed at.
///
/// We only ever write regular files here, so a symlink at a shim path is by
/// construction not ours — the same "hands off what we did not write" rule the
/// sentinel encodes, applied one level earlier.
fn shim_entry(path: &Path) -> Result<Option<fs::Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(md) if md.file_type().is_symlink() => bail!(
            "{} is a symlink, not a secreq-managed shim; refusing to follow it. \
             Remove it manually and re-run.",
            path.display()
        ),
        Ok(md) => Ok(Some(md)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("could not stat {}", path.display())),
    }
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

    fn mode_of(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

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

    /// The upgrade path for an already-installed shim. A body written by an
    /// older secreq keeps working, so nothing surfaces it — `doctor` compares
    /// bodies rather than trusting the sentinel, and repairs what it finds.
    #[test]
    fn a_bare_name_shim_is_not_current_and_install_repairs_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gh");
        fs::write(
            &path,
            format!("#!/bin/sh\n# {SENTINEL}: wrap=gh\nexec secreq x gh \"$@\"\n"),
        )
        .unwrap();

        assert!(is_managed(dir.path(), "gh"), "sentinel says it is ours");
        assert!(!is_current(dir.path(), "gh"), "a bare-name body is stale");

        install(dir.path(), "gh").unwrap();
        assert!(is_current(dir.path(), "gh"));
        let body = fs::read_to_string(&path).unwrap();
        assert!(!body.contains("exec secreq "), "got: {body}");
    }

    /// A shim naming a path the binary has moved away from is equally stale,
    /// and fails at exec time with nothing pointing at the shim as the cause.
    #[test]
    fn a_shim_naming_a_different_binary_is_not_current() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("gh"),
            format!("#!/bin/sh\n# {SENTINEL}: wrap=gh\nexec '/opt/old/secreq' x 'gh' \"$@\"\n"),
        )
        .unwrap();
        assert!(!is_current(dir.path(), "gh"));
    }

    // ── S2: the shim dir is on PATH, so its mode is a code-execution control ──

    /// `create_dir_all` asks for 0777 and lets the umask decide, so the
    /// directory `init` prepends to PATH forever lands 0755 under the usual
    /// 022 and **0777** under the `umask 000` that CI and container images
    /// commonly set. Pinning the mode is what removes the umask from the
    /// answer; asserting the exact 0700 is what makes a regression visible
    /// under any umask, including the one this test happens to run with.
    #[test]
    fn a_shim_dir_secreq_creates_is_owner_only() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("nested/shims");

        install(&dir, "gh").unwrap();

        assert_eq!(mode_of(&dir), 0o700, "mode {:o}", mode_of(&dir));
        // The intermediate parent we conjured is ours too.
        let parent = tmp.path().join("nested");
        assert_eq!(mode_of(&parent) & 0o022, 0, "mode {:o}", mode_of(&parent));
    }

    /// Creating it right is only half of it: every install that predates this
    /// left a 0777 directory behind, and a user-chosen `$shim_dir` may have
    /// been made by something else entirely.
    #[test]
    fn an_existing_world_writable_shim_dir_is_narrowed() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("bin");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();

        install(&dir, "gh").unwrap();

        assert_eq!(mode_of(&dir) & 0o022, 0, "mode {:o}", mode_of(&dir));
    }

    /// A directory the user already had is theirs. We clear the bits that
    /// make it an execution vector and leave the rest — narrowing a shared
    /// `~/.local/bin` to 0700 would break every other tool that reads it.
    #[test]
    fn narrowing_an_existing_dir_keeps_its_read_and_traverse_bits() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("bin");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o775)).unwrap();

        ensure_shim_dir(&dir).unwrap();

        assert_eq!(mode_of(&dir), 0o755, "mode {:o}", mode_of(&dir));
    }

    // ── S3: `exists()` follows symlinks, so a dangling one is invisible ──

    /// `Path::exists` stats the *target*, so a symlink pointing at nothing
    /// reads as "no file here" — the sentinel check is skipped and the
    /// `fs::write` that follows creates the attacker's chosen target instead.
    #[test]
    fn install_refuses_a_dangling_symlink_rather_than_writing_through_it() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("planted");
        std::os::unix::fs::symlink(&target, dir.path().join("gh")).unwrap();

        let err = install(dir.path(), "gh").expect_err("must refuse a symlink");
        assert!(format!("{err:#}").contains("symlink"), "{err:#}");
        assert!(!target.exists(), "wrote through the symlink to {target:?}");
    }

    /// The same guard for a symlink whose target does exist: `exists()` is
    /// true, `read_to_string` reads the *target's* bytes, and a target that
    /// happens to carry our sentinel would be overwritten.
    #[test]
    fn install_refuses_a_live_symlink_rather_than_writing_through_it() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("planted");
        fs::write(&target, format!("# {SENTINEL}: wrap=gh\n")).unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join("gh")).unwrap();

        let err = install(dir.path(), "gh").expect_err("must refuse a symlink");
        assert!(format!("{err:#}").contains("symlink"), "{err:#}");
        assert_eq!(
            fs::read_to_string(&target).unwrap(),
            format!("# {SENTINEL}: wrap=gh\n"),
            "target was rewritten through the link"
        );
    }

    /// `remove` unlinks the link and not its target, so it was never
    /// destructive — but it read the target's bytes to decide, which means a
    /// link aimed at any sentinel-bearing file authorised the deletion.
    #[test]
    fn remove_refuses_a_symlink_rather_than_deciding_on_its_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("planted");
        fs::write(&target, format!("# {SENTINEL}: wrap=gh\n")).unwrap();
        let link = dir.path().join("gh");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let err = remove(dir.path(), "gh").expect_err("must refuse a symlink");
        assert!(format!("{err:#}").contains("symlink"), "{err:#}");
        assert!(link.symlink_metadata().is_ok(), "link was removed");
    }

    /// A freshly installed shim is current by construction; an unowned file
    /// is not ours to call stale.
    #[test]
    fn is_current_is_true_after_install_and_false_for_an_unowned_file() {
        let dir = tempfile::tempdir().unwrap();
        install(dir.path(), "gh").unwrap();
        assert!(is_current(dir.path(), "gh"));

        fs::write(dir.path().join("other"), "#!/bin/sh\necho hi\n").unwrap();
        assert!(!is_current(dir.path(), "other"));
        assert!(!is_current(dir.path(), "missing"));
    }
}
