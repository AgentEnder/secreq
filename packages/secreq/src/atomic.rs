//! Replace a file's contents without ever publishing a partial one — and
//! without publishing a *wider mode* than the file had.
//!
//! Both halves are one primitive because they are one bug. Staging through
//! `File::create` and renaming gets the atomicity right and the mode wrong:
//! `rename` publishes a **new inode**, so the destination ends up carrying
//! the staging file's `0666 & !umask` rather than the mode of whatever it
//! replaced. Migration 0001 shipped exactly that, republishing every
//! upgrader's `wraps.json5` at 0644 after they had deliberately chmod'd it
//! 0600. Every caller here therefore has to say what mode it means.
//!
//! Migrations may use this, unlike [`crate::paths`]: this module resolves no
//! locations at all, so there is no "where did this live?" answer here that a
//! later change could retroactively rewrite for a user who hasn't migrated
//! yet. It only ever writes to a path it is handed.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

/// Owner-only, for a destination whose mode source has vanished. Nothing
/// secreq writes is low-sensitivity enough to want the umask's answer.
const PRIVATE_FILE_MODE: u32 = 0o600;

/// The mode [`replace`] leaves on the destination.
pub(crate) enum Mode<'a> {
    /// Whatever mode this file carries — the file being rewritten in place, or
    /// the source being copied. A user who narrowed their config must not have
    /// it widened again by an upgrade they didn't ask for.
    Like(&'a Path),
    /// Exactly this, whatever the file had before. For a file whose *reader*
    /// dictates the mode: ssh refuses a group- or world-readable
    /// `~/.ssh/config`, so faithfully restoring a 0644 one would hand back a
    /// file ssh then ignores.
    Exactly(u32),
}

impl Mode<'_> {
    fn resolve(&self) -> u32 {
        match self {
            Mode::Exactly(mode) => *mode,
            Mode::Like(path) => std::fs::metadata(path)
                .map_or(PRIVATE_FILE_MODE, |md| md.permissions().mode() & 0o777),
        }
    }
}

/// Write `bytes` to `path` via a staging sibling, fsync, rename.
///
/// A reader of `path` sees either the old contents or the new ones, never a
/// truncated file — which is what a plain `fs::write` leaves behind if the
/// process dies mid-write. That matters most for the files this crate does
/// *not* own: a half-written `~/.zshrc` is a broken login shell.
pub(crate) fn replace(path: &Path, bytes: &[u8], mode: Mode<'_>) -> Result<()> {
    let parent = path.parent().context("path has no parent")?;
    // Resolve the mode before staging: `Mode::Like(path)` names the file we
    // are about to replace, and after the rename it describes the new inode.
    let mode = mode.resolve();
    std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;

    let (tmp, file) = create_staging(parent, path, mode)?;
    let res = finish(file, &tmp, path, bytes, mode);
    if res.is_err() {
        // The staging name is unique, so a failed attempt leaves litter rather
        // than something the next one would pick up. Sweep it.
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

fn finish(mut file: File, tmp: &Path, path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    file.write_all(bytes)
        .with_context(|| format!("write {}", tmp.display()))?;
    file.sync_all()
        .with_context(|| format!("fsync {}", tmp.display()))?;
    drop(file);
    // `OpenOptions::mode` is masked by the umask, so a 0644 source does not
    // survive a 022 umask on the creating open alone. Applying it again
    // unmasked is what actually preserves the mode; doing it in this order
    // means the staging file is never briefly *wider* than intended.
    std::fs::set_permissions(tmp, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("set mode {mode:o} on {}", tmp.display()))?;
    std::fs::rename(tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))
}

/// Create a staging file no other writer can already hold.
///
/// A fixed `.<name>.tmp` is a single inode shared by every writer of that
/// destination: two secreq processes there interleave their `write_all`s into
/// the one file and then both rename it, so what gets published *atomically*
/// can still be a splice of two payloads. `create_new` turns sharing into an
/// error instead of a silent stomp, the pid separates processes, and the
/// counter separates one process's own concurrent writes.
fn create_staging(parent: &Path, dst: &Path, mode: u32) -> Result<(PathBuf, File)> {
    let name = dst.file_name().unwrap_or_default().to_string_lossy();
    let mut last = None;
    // A collision here means a dead process with our pid left a file at the
    // name we drew, so a few draws is all it can take.
    for _ in 0..16 {
        let tmp = parent.join(format!(".{name}.{}.{}.tmp", std::process::id(), next_seq()));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)
        {
            Ok(file) => return Ok((tmp, file)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => last = Some(tmp),
            Err(e) => return Err(e).with_context(|| format!("create {}", tmp.display())),
        }
    }
    bail!(
        "could not find a free staging name beside {} (last tried {})",
        dst.display(),
        last.map(|p| p.display().to_string()).unwrap_or_default(),
    )
}

fn next_seq() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// The M2 shape: staging through `File::create` handed the destination the
    /// *temp file's* 0644, silently undoing a `chmod 600` on a config.
    #[test]
    fn like_carries_the_source_mode_across_the_rename() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        std::fs::write(&src, b"x").unwrap();
        std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o600)).unwrap();

        replace(&dst, b"x", Mode::Like(&src)).unwrap();

        assert_eq!(mode_of(&dst), 0o600);
    }

    /// Preserve means preserve in both directions: a file the user chose to
    /// leave group-readable is not quietly narrowed either.
    #[test]
    fn like_does_not_narrow_a_deliberately_wider_source() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        std::fs::write(&src, b"x").unwrap();
        std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o640)).unwrap();

        replace(&dst, b"x", Mode::Like(&src)).unwrap();

        assert_eq!(mode_of(&dst), 0o640);
    }

    #[test]
    fn a_missing_mode_source_falls_back_to_owner_only() {
        let tmp = tempfile::tempdir().unwrap();
        let dst = tmp.path().join("dst");

        replace(&dst, b"x", Mode::Like(&tmp.path().join("nope"))).unwrap();

        assert_eq!(mode_of(&dst), 0o600);
    }

    #[test]
    fn exactly_overrides_whatever_was_there() {
        let tmp = tempfile::tempdir().unwrap();
        let dst = tmp.path().join("dst");
        std::fs::write(&dst, b"old").unwrap();
        std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o644)).unwrap();

        replace(&dst, b"new", Mode::Exactly(0o600)).unwrap();

        assert_eq!(mode_of(&dst), 0o600);
        assert_eq!(std::fs::read_to_string(&dst).unwrap(), "new");
    }

    /// The M5 shape. A fixed `.<name>.tmp` is one inode every writer of this
    /// destination shares; whoever gets there second truncates the first
    /// writer's staging file out from under it and both then rename. Planting
    /// the old name is how a test can see that we no longer touch it.
    #[test]
    fn another_writers_staging_file_is_left_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let dst = tmp.path().join("state");
        let squatted = tmp.path().join(".state.tmp");
        std::fs::write(&squatted, b"another writer's half-written payload").unwrap();

        replace(&dst, b"mine", Mode::Exactly(0o600)).unwrap();

        assert_eq!(std::fs::read_to_string(&dst).unwrap(), "mine");
        assert_eq!(
            std::fs::read_to_string(&squatted).unwrap(),
            "another writer's half-written payload",
            "staging files must not be shared between writers"
        );
    }

    /// Replace-by-rename, not truncate-in-place: a reader mid-write sees the
    /// old inode's contents rather than an empty file.
    #[test]
    fn the_destination_is_a_new_inode_each_time() {
        use std::os::unix::fs::MetadataExt;
        let tmp = tempfile::tempdir().unwrap();
        let dst = tmp.path().join("dst");
        std::fs::write(&dst, b"old").unwrap();
        let before = std::fs::metadata(&dst).unwrap().ino();

        replace(&dst, b"new", Mode::Like(&dst)).unwrap();

        assert_ne!(std::fs::metadata(&dst).unwrap().ino(), before);
    }

    /// No litter on the happy path — the staging file is renamed, not copied.
    #[test]
    fn nothing_is_left_beside_the_destination() {
        let tmp = tempfile::tempdir().unwrap();
        replace(&tmp.path().join("dst"), b"x", Mode::Exactly(0o600)).unwrap();

        let names: Vec<String> = std::fs::read_dir(tmp.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["dst".to_string()]);
    }
}
