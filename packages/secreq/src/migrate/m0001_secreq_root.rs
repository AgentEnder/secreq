//! Migration 0001 — `secreq-root`.
//!
//! Moves config out of `~/.config/secreq` and logs out of
//! `~/.local/state/secreq` into a single `~/.secreq` root, leaving
//! **file-level** symlinks behind at the old config paths.
//!
//! File-level, not a directory symlink: `rm -rf ~/.config/secreq/` against a
//! *directory* symlink deletes the target tree (verified on BSD `rm`: removed
//! the whole target, left a dangling link, exited 0). Against a directory of
//! symlinks, `rm -rf` unlinks the links and the real files survive.
//!
//! The symlinks double as downgrade compatibility: an older secreq resolving
//! `$XDG_CONFIG_HOME/secreq/wraps.json5` follows the link and reads the right
//! file.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use super::{Ctx, Outcome};
use crate::atomic;

/// The two config files. Frozen — this is the set as it existed at level 0.
const CONFIG_FILES: &[&str] = &["wraps.json5", "auto-rules.json5"];

/// Config only. Never `audit.log`: it's append-only and unbounded, so
/// snapshotting it per migration would duplicate the whole audit history each
/// time. Snapshots stay kilobytes.
pub fn snapshot_files(ctx: &Ctx) -> Vec<PathBuf> {
    let Some(dir) = &ctx.legacy_config_dir else {
        return Vec::new();
    };
    CONFIG_FILES.iter().map(|f| dir.join(f)).collect()
}

pub fn run(ctx: &Ctx) -> Result<Outcome> {
    for name in CONFIG_FILES {
        migrate_config_file(ctx, name).with_context(|| format!("migrating {name}"))?;
    }
    migrate_audit_log(ctx).context("migrating audit.log")?;
    // Nothing here is ever half-done: every case either moves the file, finds
    // it already moved, or errors on an ambiguity it refuses to guess at.
    Ok(Outcome::Done)
}

/// ```text
/// new missing, old real file  -> copy -> remove old -> symlink old->new
/// new real,    old symlink    -> no-op (already migrated)
/// new real,    old missing    -> ensure symlink
/// new real,    old real       -> identical -> resume; differ -> ERROR
/// new missing, old missing    -> nothing (fresh install)
/// ```
fn migrate_config_file(ctx: &Ctx, name: &str) -> Result<()> {
    let Some(legacy_dir) = &ctx.legacy_config_dir else {
        return Ok(());
    };
    let old = legacy_dir.join(name);
    let new = ctx.root.join(name);

    let old_is_symlink = old
        .symlink_metadata()
        .is_ok_and(|m| m.file_type().is_symlink());
    // A symlink is already-migrated, not a source to copy from.
    let old_is_file = !old_is_symlink && old.is_file();
    let new_is_file = new.is_file();

    // Already migrated. If the link points somewhere unexpected the user put
    // it there deliberately, so leave it alone rather than "fixing" it.
    if old_is_symlink {
        return Ok(());
    }

    match (new_is_file, old_is_file) {
        (false, false) => Ok(()),
        (true, false) => ensure_symlink(&old, &new),
        (true, true) => {
            // Both real. Not a conflict by default — it's the expected state
            // after a crash between copy and remove, when the two are
            // byte-identical. Erroring there would wedge the retry forever.
            let old_bytes =
                std::fs::read(&old).with_context(|| format!("read {}", old.display()))?;
            let new_bytes =
                std::fs::read(&new).with_context(|| format!("read {}", new.display()))?;
            if old_bytes == new_bytes {
                std::fs::remove_file(&old).with_context(|| format!("remove {}", old.display()))?;
                ensure_symlink(&old, &new)
            } else {
                bail!(
                    "{} and {} both exist and differ.\n\
                     secreq won't guess which one you want. Move or delete one \
                     of them, then re-run.",
                    old.display(),
                    new.display(),
                )
            }
        }
        (false, true) => {
            // Copy first (old stays truth), then remove, then link. A crash
            // after remove leaves new-present/old-absent, which the
            // (true, false) arm recovers on the next run.
            copy_atomic(&old, &new)?;
            std::fs::remove_file(&old).with_context(|| format!("remove {}", old.display()))?;
            ensure_symlink(&old, &new)
        }
    }
}

/// Copy via tmp + fsync + rename in the destination dir, so `new` never
/// exists in a partial state — **and carries `src`'s mode**, not the staging
/// file's.
///
/// The mode is the whole reason this delegates rather than staging inline. A
/// `rename` publishes a new inode, so the version of this that staged through
/// `File::create` handed every migrated `wraps.json5` and `auto-rules.json5`
/// the umask's 0644 and undid whatever the user had chosen. `audit.log` never
/// had the bug because it moves by `rename`, which keeps its inode and so keeps
/// its mode; this is that behaviour for a copy.
fn copy_atomic(src: &Path, dst: &Path) -> Result<()> {
    let bytes = std::fs::read(src).with_context(|| format!("read {}", src.display()))?;
    atomic::replace(dst, &bytes, atomic::Mode::Like(src))
}

fn ensure_symlink(link: &Path, target: &Path) -> Result<()> {
    if let Ok(md) = link.symlink_metadata() {
        if md.file_type().is_symlink() {
            if std::fs::read_link(link).ok().as_deref() == Some(target) {
                return Ok(());
            }
            std::fs::remove_file(link)
                .with_context(|| format!("remove stale symlink {}", link.display()))?;
        } else {
            bail!(
                "refusing to replace real file {} with a symlink",
                link.display()
            );
        }
    }
    if let Some(parent) = link.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    std::os::unix::fs::symlink(target, link)
        .with_context(|| format!("symlink {} -> {}", link.display(), target.display()))
}

/// `rename`, deliberately.
///
/// On upgrade a stale daemon from the *previous* binary is often still
/// running with `audit.log` open for append — detecting that is why
/// `build.rs` stamps `SECREQ_BUILD_ID` (the CLI restarts the daemon on
/// mismatch, see `daemon::client`). But migrations run at the top of
/// `cli::run`, *before* that restart. With `rename` the old daemon's fd
/// follows the inode and its writes keep landing in `~/.secreq/audit.log`, so
/// no audit rows are lost across the handoff. Copy-then-delete would silently
/// drop every row that daemon wrote between the copy and its restart.
fn migrate_audit_log(ctx: &Ctx) -> Result<()> {
    let Some(state_dir) = &ctx.legacy_state_dir else {
        return Ok(());
    };
    let old = state_dir.join("audit.log");
    let new = ctx.root.join("audit.log");

    if !old.is_file() || new.exists() {
        return Ok(());
    }
    std::fs::create_dir_all(&ctx.root).with_context(|| format!("create {}", ctx.root.display()))?;

    match std::fs::rename(&old, &new) {
        Ok(()) => Ok(()),
        // Separate mounts (`~/.local` on its own filesystem). Rename can't
        // cross them, and we can't safely delete the source because a live
        // daemon may still be writing to it — so copy and leave it, loudly.
        Err(e) if e.raw_os_error() == Some(libc::EXDEV) => {
            std::fs::copy(&old, &new)
                .with_context(|| format!("copy {} -> {}", old.display(), new.display()))?;
            eprintln!(
                "secreq: {} is on a different filesystem than {}, so it was \
                 copied rather than moved.\n\
                 The original was left in place; audit rows written by a \
                 still-running daemon may remain there.",
                old.display(),
                ctx.root.display(),
            );
            Ok(())
        }
        Err(e) => Err(e).with_context(|| format!("rename {} -> {}", old.display(), new.display())),
    }
}

/// `daemon.log` / `daemon.jsonl` are intentionally not migrated — transient
/// debug output, recreated at the new path on next daemon start.
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn ctx_in(tmp: &TempDir) -> Ctx {
        Ctx {
            root: tmp.path().join("secreq"),
            home: Some(tmp.path().join("home")),
            legacy_config_dir: Some(tmp.path().join("config/secreq")),
            legacy_state_dir: Some(tmp.path().join("state/secreq")),
            legacy_runtime_dir: Some(tmp.path().join("runtime/secreq")),
        }
    }

    #[test]
    fn no_home_means_nothing_to_migrate() {
        let tmp = TempDir::new().unwrap();
        let ctx = Ctx {
            root: tmp.path().join("secreq"),
            home: None,
            legacy_config_dir: None,
            legacy_state_dir: None,
            legacy_runtime_dir: None,
        };
        run(&ctx).unwrap();
    }

    #[test]
    fn refuses_to_replace_a_real_file_with_a_symlink() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("config/secreq")).unwrap();
        let link = tmp.path().join("config/secreq/wraps.json5");
        std::fs::write(&link, "real file").unwrap();
        let target = tmp.path().join("secreq/wraps.json5");
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(&target, "other").unwrap();

        let err = ensure_symlink(&link, &target).unwrap_err();
        assert!(format!("{err:#}").contains("refusing"));
    }

    #[test]
    fn repoints_a_stale_symlink() {
        let tmp = TempDir::new().unwrap();
        let link = tmp.path().join("link");
        let old_target = tmp.path().join("old");
        let new_target = tmp.path().join("new");
        std::fs::write(&old_target, "a").unwrap();
        std::fs::write(&new_target, "b").unwrap();
        std::os::unix::fs::symlink(&old_target, &link).unwrap();

        ensure_symlink(&link, &new_target).unwrap();
        assert_eq!(std::fs::read_link(&link).unwrap(), new_target);
    }

    #[test]
    fn existing_symlink_at_old_path_is_left_alone() {
        // Already migrated. Re-running must not treat the link as a source.
        let tmp = TempDir::new().unwrap();
        let ctx = ctx_in(&tmp);
        let legacy = ctx.legacy_config_dir.clone().unwrap();
        let new = ctx.root.join("wraps.json5");
        std::fs::create_dir_all(&ctx.root).unwrap();
        std::fs::create_dir_all(&legacy).unwrap();
        std::fs::write(&new, "{ gh: {} }").unwrap();
        std::os::unix::fs::symlink(&new, legacy.join("wraps.json5")).unwrap();

        run(&ctx).unwrap();

        assert_eq!(std::fs::read_to_string(&new).unwrap(), "{ gh: {} }");
        assert!(legacy
            .join("wraps.json5")
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink());
    }

    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// The move must not relax what the user chose. `copy_atomic` used to
    /// stage through `File::create` and rename, so every migrated config came
    /// out at the umask's 0644 — a `chmod 600 ~/.config/secreq/wraps.json5`
    /// silently undone by an automatic upgrade.
    #[test]
    fn moved_config_keeps_the_mode_the_user_chose() {
        use std::fs::Permissions;
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let ctx = ctx_in(&tmp);
        let legacy = ctx.legacy_config_dir.clone().unwrap();
        std::fs::create_dir_all(&legacy).unwrap();
        // One file the user narrowed, one they deliberately left wider — the
        // mode is carried across, not forced to a constant.
        for (name, mode) in [("wraps.json5", 0o600), ("auto-rules.json5", 0o640)] {
            std::fs::write(legacy.join(name), "{}").unwrap();
            std::fs::set_permissions(legacy.join(name), Permissions::from_mode(mode)).unwrap();
        }

        run(&ctx).unwrap();

        assert_eq!(
            mode_of(&ctx.root.join("wraps.json5")),
            0o600,
            "an upgrade must not undo a chmod"
        );
        assert_eq!(mode_of(&ctx.root.join("auto-rules.json5")), 0o640);
    }

    /// The staging file is a sibling of the destination and must not survive
    /// it — a `.wraps.json5.*.tmp` left in the root is a second copy of the
    /// config at whatever mode the crash left.
    #[test]
    fn the_migrated_root_holds_no_staging_leftovers() {
        let tmp = TempDir::new().unwrap();
        let ctx = ctx_in(&tmp);
        let legacy = ctx.legacy_config_dir.clone().unwrap();
        std::fs::create_dir_all(&legacy).unwrap();
        std::fs::write(legacy.join("wraps.json5"), "{}").unwrap();

        run(&ctx).unwrap();

        let mut names: Vec<String> = std::fs::read_dir(&ctx.root)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, vec!["wraps.json5".to_string()]);
    }

    #[test]
    fn audit_log_is_not_clobbered_if_one_already_exists_at_the_new_path() {
        let tmp = TempDir::new().unwrap();
        let ctx = ctx_in(&tmp);
        std::fs::create_dir_all(&ctx.root).unwrap();
        std::fs::create_dir_all(ctx.legacy_state_dir.clone().unwrap()).unwrap();
        std::fs::write(ctx.root.join("audit.log"), "new\n").unwrap();
        std::fs::write(
            ctx.legacy_state_dir.clone().unwrap().join("audit.log"),
            "old\n",
        )
        .unwrap();

        run(&ctx).unwrap();

        assert_eq!(
            std::fs::read_to_string(ctx.root.join("audit.log")).unwrap(),
            "new\n"
        );
    }
}
