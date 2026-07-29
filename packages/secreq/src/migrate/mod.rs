//! Automatic, idempotent config migrations.
//!
//! Runs at the top of [`crate::cli::run`], before any subcommand dispatch —
//! the one chokepoint every entry point passes through, *including* the
//! daemon (it re-execs `current_exe()` and lands back in `cli::run`, see
//! `daemon::client`). Design:
//! `brain: areas/secreq/design/2026-07-16-secreq-root-and-migrations.md`.
//!
//! # Rules for writing a migration
//!
//! 1. **Idempotent.** A migration may re-run after a crash, or run against a
//!    fresh install where there is nothing to do. Both must be no-ops.
//! 2. **Atomic.** Failure must leave the *old* state intact so the next run
//!    retries cleanly. Copy → verify → swap, never mutate in place.
//! 3. **Legacy paths are frozen history.** A migration must never resolve an
//!    *old* location through [`crate::paths`]: that module tracks current
//!    behavior, and if it changed, the migration would retroactively mean
//!    something different for users who hadn't run it yet. Freeze the old
//!    logic here (see [`legacy_config_dir`]) and never touch it again. The
//!    *target* root is the exception — it should track current behavior, so
//!    it arrives via [`Ctx::root`].
//! 4. **Ids are dense, 1-based, append-only, never reused.** `run_pending`
//!    slices `MIGRATIONS[level..]`, so a gap would silently run the wrong
//!    migrations. Pinned by `migration_ids_are_dense_and_one_based`.
//! 5. **Say whether you finished.** A migration returns an [`Outcome`], not
//!    `()`, so "I found nothing to do" and "I could not find what I expected"
//!    are different answers. See [`Outcome`] for why that distinction is the
//!    difference between a migration that retries and one that is stamped
//!    over.

mod m0001_secreq_root;
mod m0002_ssh_agent_socket;
mod m0003_config_format;

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::atomic;
use crate::paths;

/// Everything a migration is allowed to know about the world. Injected
/// rather than resolved inside migrations, so tests can drive them against
/// tempdirs without touching the real home.
pub struct Ctx {
    /// Target root — tracks current behavior (`$SECREQ_HOME`, else `~/.secreq`).
    pub root: PathBuf,
    /// The user's home. `None` if it can't be resolved, which means any
    /// migration keyed on it has nothing to do.
    ///
    /// Injected rather than resolved in-migration for the reason the whole
    /// `Ctx` exists, but with more teeth than the fields below: migration
    /// 0002 rewrites files *outside* the secreq tree (`~/.ssh/config`, shell
    /// rc files). A migration that called `dirs::home_dir()` itself would
    /// edit the developer's real dotfiles on every `cargo test`, because
    /// `run_pending_in`'s tests drive the whole `MIGRATIONS` list.
    pub home: Option<PathBuf>,
    /// Frozen: where config lived before migration 0001. `None` if it can't
    /// be resolved (no `$HOME`), which simply means nothing to migrate.
    pub legacy_config_dir: Option<PathBuf>,
    /// Frozen: where logs lived before migration 0001.
    pub legacy_state_dir: Option<PathBuf>,
    /// Frozen: where the sockets lived before migration 0002. The value comes
    /// from [`m0002_ssh_agent_socket::legacy_runtime_dir`] — the frozen logic
    /// lives with the migration that needs it; only the resolved value is
    /// injected here so tests can substitute a tempdir.
    pub legacy_runtime_dir: Option<PathBuf>,
}

/// What a migration reports when it returns without erroring.
///
/// Deliberately not `()`. A migration works by looking for something — a file
/// at a legacy path, a managed block naming an old socket — and the absence of
/// that thing is ambiguous: on a fresh install it means "nothing to do", and on
/// an install whose dotfile we could not read it means "I could not find what I
/// expected". Returning `()` collapsed the two into success, and success is
/// what [`run_pending_in`] stamps the level on. A stamped level is permanent —
/// the migration never runs again — so a migration that silently did less than
/// it meant to had that written down as if it had done all of it. Migrations
/// 0002 (skipped a block it could not parse, then deleted the socket that block
/// named) and the truncated-dotfile case in `ssh_setup::rewrite_in_place` are
/// both that bug.
///
/// Erroring is not the same thing either: nothing failed. The migration read
/// the world, found it not as expected, and declined to pretend otherwise.
pub(crate) enum Outcome {
    /// Everything this migration set out to do is on disk. Includes the
    /// fresh-install case, where there was genuinely nothing to do.
    Done,
    /// The migration stopped short, for the reason carried here — written for
    /// a user, naming the file that stopped it. The level is not stamped, so
    /// the migration runs again (they are idempotent) once the obstacle clears.
    Incomplete(String),
}

struct Migration {
    id: u32,
    name: &'static str,
    /// Absolute paths to capture before running, at their **pre-migration**
    /// locations. Snapshots are keyed by pre-migration level, so
    /// `snapshots/K/` is the config as it stood at level K.
    snapshot: fn(&Ctx) -> Vec<PathBuf>,
    run: fn(&Ctx) -> Result<Outcome>,
}

/// Append-only. Never reorder, never reuse an id, never delete an entry.
const MIGRATIONS: &[Migration] = &[
    Migration {
        id: 1,
        name: "secreq-root",
        snapshot: m0001_secreq_root::snapshot_files,
        run: m0001_secreq_root::run,
    },
    Migration {
        id: 2,
        name: "ssh-agent-socket",
        snapshot: m0002_ssh_agent_socket::snapshot_files,
        run: m0002_ssh_agent_socket::run,
    },
    Migration {
        id: 3,
        name: "config-format",
        snapshot: m0003_config_format::snapshot_files,
        run: m0003_config_format::run,
    },
];

const STATE_FILE: &str = ".migration-state";
const LOCK_FILE: &str = ".migration.lock";
const SNAPSHOT_DIR: &str = "migration-snapshots";

/// Machine-local. Deliberately **not** stored in `config.toml`: that file is
/// dotfile-synced (chezmoi/stow/git), and a synced `migration_level` would
/// tell a fresh machine it was already migrated when it wasn't, so it would
/// skip the migration it actually needs.
#[derive(Serialize, Deserialize, Default, Debug)]
struct State {
    migration_level: u32,
    /// Display-only. `SECREQ_BUILD_ID` is `<sha>[-dirty] +<ts>` — built for
    /// equality ("same binary?"), not ordering, so this can never be
    /// *compared* to compute "install >= X". It only tells a human what
    /// wrote their config.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    migrated_by: Option<String>,
}

/// **FROZEN.** How secreq resolved its config dir before migration 0001
/// (mirrors the old `wraps::default_config_path`). Describes history — must
/// never change.
fn legacy_config_dir() -> Option<PathBuf> {
    std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|h| h.join(".config")))
        .map(|b| b.join("secreq"))
}

/// **FROZEN.** How secreq resolved its state dir before migration 0001
/// (mirrors the old `audit::state_dir`).
fn legacy_state_dir() -> Option<PathBuf> {
    std::env::var_os("XDG_STATE_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|h| h.join(".local").join("state")))
        .map(|b| b.join("secreq"))
}

fn build_stamp() -> String {
    format!("{} ({})", env!("CARGO_PKG_VERSION"), crate::BUILD_ID)
}

/// Run every migration the user hasn't yet. Called once per process from
/// `cli::run`.
pub fn run_pending() -> Result<()> {
    let ctx = Ctx {
        root: paths::secreq_root()?,
        home: dirs::home_dir(),
        legacy_config_dir: legacy_config_dir(),
        legacy_state_dir: legacy_state_dir(),
        legacy_runtime_dir: m0002_ssh_agent_socket::legacy_runtime_dir(),
    };
    run_pending_in(&ctx)
}

pub fn run_pending_in(ctx: &Ctx) -> Result<()> {
    let state = read_state(&ctx.root)?;
    let level = state.migration_level as usize;

    // Must precede the fast path. `level >= MIGRATIONS.len()` as a fast path
    // would swallow this case: an old binary would see `5 >= 3`, return Ok,
    // and silently run against a config a newer secreq migrated.
    if level > MIGRATIONS.len() {
        bail!(downgrade_message(ctx, &state));
    }
    // Fast path: no flock. `secreq x <bin>` is in the hot path of every
    // wrapped command and the consent-prompt child spawns per prompt, so the
    // steady-state cost must stay at one small read.
    if level == MIGRATIONS.len() {
        return Ok(());
    }

    // On a fresh install this is the *first* thing that creates the root — it
    // runs from `cli::run` before any command sees control, so whatever mode
    // it lands here is the mode `~/.secreq` has while `init` is still asking
    // questions. `create_dir_all` takes the umask's answer, which is 0755
    // under the common 022 and **0777** under the `umask 000` CI and container
    // images set, and the root goes on to hold `audit.log`, `auto-rules.toml`
    // and `config.toml`. Inlined at [`OWNER_ONLY_DIR`] rather than routed
    // through `paths::ensure_private_dir` for the same reason as the snapshot
    // dir below: migrations resolve nothing through `paths`, and the mode is a
    // constant rather than a location, so no frozen history is at stake.
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(OWNER_ONLY_DIR)
        .create(&ctx.root)
        .with_context(|| format!("create {}", ctx.root.display()))?;
    let _lock = acquire_lock(&ctx.root)?;

    // Re-read under the lock. On first upgrade a burst of wraps all observe
    // `level < len` at once; one migrates, the rest land here and no-op.
    let level = read_state(&ctx.root)?.migration_level as usize;
    if level >= MIGRATIONS.len() {
        return Ok(());
    }

    for m in MIGRATIONS.iter().skip(level) {
        let declared: Vec<PathBuf> = (m.snapshot)(ctx);
        // Declared but not yet on disk: the only paths this migration could
        // possibly be said to have created.
        let absent_before: Vec<PathBuf> =
            declared.iter().filter(|p| !p.exists()).cloned().collect();
        snapshot_if_absent(ctx, m)?;
        let outcome =
            (m.run)(ctx).with_context(|| format!("migration {:04} ({}) failed", m.id, m.name))?;
        // Refusing to stamp is the whole point: the level is what makes a
        // migration's result permanent, so it may only record a migration that
        // says it finished.
        if let Outcome::Incomplete(detail) = outcome {
            bail!(incomplete_message(m, &detail));
        }
        record_post_state(ctx, m, &declared, &absent_before);
        // Stamp after each, not at the end, so a failure at 3 keeps 1 and 2.
        write_state(&ctx.root, m.id)?;
    }
    Ok(())
}

/// Amend the migration's snapshot filemap with what actually happened: which
/// declared paths it brought into existence, and what every declared file it
/// touched looked like when it finished.
///
/// Written after the run rather than declared up front, so both are records
/// rather than statements of intent. A migration that only *edits* a file
/// (0002, rewriting a managed block in the user's `~/.ssh/config`) records
/// nothing in `created` no matter what it declares, and so can never
/// contribute a candidate to the restore cleanup.
///
/// Best-effort: a missing snapshot dir means there was nothing to roll back to
/// in the first place, and a filemap we cannot rewrite leaves both fields
/// empty. That is the conservative reading — an empty `created` removes less,
/// and an absent digest makes the restore warn rather than stay quiet.
fn record_post_state(ctx: &Ctx, m: &Migration, declared: &[PathBuf], absent_before: &[PathBuf]) {
    let created: Vec<PathBuf> = absent_before
        .iter()
        .filter(|p| p.is_file())
        .cloned()
        .collect();
    let post_sha256: BTreeMap<PathBuf, String> = declared
        .iter()
        .filter_map(|path| {
            let bytes = std::fs::read(path).ok()?;
            Some((path.clone(), crate::rules::sha256_hex(&bytes)))
        })
        .collect();
    if created.is_empty() && post_sha256.is_empty() {
        return;
    }

    let path = snapshot_dir(&ctx.root, m.id - 1).join("filemap.json");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return;
    };
    let Ok(mut map) = serde_json::from_str::<FileMap>(&text) else {
        return;
    };
    map.created = created;
    map.post_sha256 = post_sha256;
    if let Ok(encoded) = serde_json::to_string_pretty(&map) {
        let _ = atomic::replace(&path, encoded.as_bytes(), atomic::Mode::Exactly(OWNER_ONLY));
    }
}

/// A migration that stopped short is neither a crash nor a success, and the
/// message has to read as neither. It says what stopped it and that the level
/// stayed put — because the user's next move (fix the thing, run any secreq
/// command) only makes sense if they know the migration will come back.
fn incomplete_message(m: &Migration, detail: &str) -> String {
    format!(
        "migration {:04} ({}) could not finish:\n\
         \n  {detail}\n\
         \n\
         Migration level {} was not recorded, so secreq will run this migration\n\
         again — they are idempotent — once the above is resolved.\n",
        m.id, m.name, m.id,
    )
}

/// The read-only counterpart to [`run_pending`], for background/service roles
/// (the daemon, `agent open`, the consent/manager/badge window children, and
/// `resolve`). It reads the recorded level and refuses on a mismatch, but never
/// takes the lock, applies a migration, or stamps the state.
///
/// Why service roles must not apply: every role re-execs `current_exe()` back
/// through `cli::run`, so *any* build's background process used to be able to
/// bump the shared `.migration-state`. A worktree dev build's `agent open` did
/// exactly that — stamping a level the installed release daemon then read as a
/// downgrade and refused, bricking every command. Migrations are now applied
/// only by deliberate foreground commands (which also restart a stale daemon
/// via the `BUILD_ID` handshake); a service that finds itself out of step
/// refuses loudly instead of silently poisoning the level for other builds.
pub fn verify_current() -> Result<()> {
    let root = paths::secreq_root()?;
    verify_current_in(&root)
}

fn verify_current_in(root: &Path) -> Result<()> {
    let state = read_state(root)?;
    let level = state.migration_level as usize;

    if level > MIGRATIONS.len() {
        // Config migrated by a newer build than this one — the real downgrade.
        let ctx = Ctx {
            root: root.to_path_buf(),
            home: None,
            legacy_config_dir: None,
            legacy_state_dir: None,
            legacy_runtime_dir: None,
        };
        bail!(downgrade_message(&ctx, &state));
    }
    if level < MIGRATIONS.len() {
        // This binary ships migrations the config hasn't seen, but a service
        // role won't apply them (that's a foreground decision). In the normal
        // flow this never happens: the foreground command that spawns the
        // daemon migrates first, and it re-execs the same binary. It only
        // trips when a service is launched from a newer build than whatever
        // last ran a foreground command.
        bail!(pending_message(root, &state));
    }
    Ok(())
}

fn pending_message(root: &Path, state: &State) -> String {
    format!(
        "{} records migration level {}, but this secreq ships {}.\n\
         This is a background/service process, which never applies migrations.\n\
         Run any foreground secreq command (e.g. `secreq doctor`) or `secreq migrate`\n\
         to apply the pending migration(s), then retry.\n",
        state_path(root).display(),
        state.migration_level,
        MIGRATIONS.len(),
    )
}

fn downgrade_message(ctx: &Ctx, state: &State) -> String {
    let by = state
        .migrated_by
        .as_deref()
        .unwrap_or("an unknown secreq build");
    format!(
        "{} records migration level {}, but this secreq ships {}.\n\
         Your config was migrated by {}.\n\
         \n\
         This build is older than the one that migrated your config. Either\n\
         install that build (or newer), or restore the level-{} snapshot to\n\
         keep using this one:\n\
         \n    secreq migrate restore {}\n",
        state_path(&ctx.root).display(),
        state.migration_level,
        MIGRATIONS.len(),
        by,
        MIGRATIONS.len(),
        MIGRATIONS.len(),
    )
}

fn state_path(root: &Path) -> PathBuf {
    root.join(STATE_FILE)
}

/// Absent file means level 0 — so a fresh install runs every migration as a
/// no-op and stamps, with no special case.
fn read_state(root: &Path) -> Result<State> {
    let path = state_path(root);
    let raw = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(State::default()),
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    };
    serde_json::from_str(&raw).with_context(|| {
        format!(
            "{} is corrupt. Delete it to re-run migrations (they are idempotent).",
            path.display()
        )
    })
}

/// Written via [`atomic::replace`]: a torn `.migration-state` would either
/// re-run a migration (harmless, they're idempotent) or skip one (not
/// harmless), so it's worth the two extra syscalls.
fn write_state(root: &Path, level: u32) -> Result<()> {
    let state = State {
        migration_level: level,
        migrated_by: Some(build_stamp()),
    };
    let path = state_path(root);
    let body = serde_json::to_string_pretty(&state)?;
    atomic::replace(&path, body.as_bytes(), atomic::Mode::Exactly(OWNER_ONLY))
}

/// Mode for the bookkeeping files secreq owns outright — the state file and a
/// snapshot's `filemap.json`. They name every config path on the machine,
/// which is a map worth not publishing.
const OWNER_ONLY: u32 = 0o600;

/// The directory counterpart, for the snapshot dirs those files live in. A
/// directory's mode governs who can *list* it, and a listing of what a restore
/// touched is a map of the user's config paths.
const OWNER_ONLY_DIR: u32 = 0o700;

// ── restore ───────────────────────────────────────────────────────────────

/// Restore the config snapshot taken before migration `level`.
///
/// **Lossy, and says so.** Anything added since the snapshot — new wraps, new
/// auto-rules — is discarded. Saving the current state to a directory is not
/// sufficient on its own: the live config still silently reverts and the user
/// is left hand-reconciling two files they didn't know had diverged, and the
/// next `secreq x terraform` fails with nothing connecting it to the restore.
/// So we render the diff and require confirmation.
///
/// Callers must invoke this **without** running [`run_pending`] first — the
/// gate is exactly what's failing when a user needs this command.
pub fn restore(level: u32, assume_yes: bool) -> Result<i32> {
    let root = paths::secreq_root()?;
    restore_in(&root, level, assume_yes)
}

/// [`restore`] with the root injected, so tests can drive it against a
/// tempdir — same split as [`run_pending_in`] and [`verify_current_in`].
fn restore_in(root: &Path, level: u32, assume_yes: bool) -> Result<i32> {
    let root = root.to_path_buf();
    let dir = snapshot_dir(&root, level);
    if !dir.is_dir() {
        bail!(no_snapshot_message(&root, level));
    }

    let map: FileMap = serde_json::from_str(
        &std::fs::read_to_string(dir.join("filemap.json"))
            .with_context(|| format!("read {}", dir.join("filemap.json").display()))?,
    )
    .with_context(|| format!("parse {}", dir.join("filemap.json").display()))?;

    let mut plan = Vec::new();
    for entry in &map.files {
        let snapshot_body = std::fs::read_to_string(dir.join(&entry.snapshot))
            .with_context(|| format!("read snapshot {}", entry.snapshot))?;
        let live = live_path(&root, entry);
        let live_body = std::fs::read_to_string(&live).unwrap_or_default();
        plan.push((entry, live, live_body, snapshot_body));
    }

    // Only *diverged* content needs a warning — but an unchanged config still
    // needs the restore. Restoring is about the recorded **level** and the
    // on-disk **layout**, not just the bytes: a user whose config never
    // diverged is exactly the one for whom this must quietly work, and
    // returning early here would leave them as stuck as before with a message
    // claiming success.
    let changed: Vec<_> = plan.iter().filter(|(_, _, a, b)| a != b).collect();
    // Files a later migration created inside the root. The target level has no
    // snapshot for them, so the restore removes them — and therefore has to
    // name them here and rescue them below. Deleting a file the DISCARD block
    // never mentioned is the silent loss this warning exists to prevent.
    let stale: Vec<(PathBuf, String)> = stale_root_artifacts(&root, level, &plan)
        .into_iter()
        .filter_map(|path| {
            let body = std::fs::read_to_string(&path).ok()?;
            Some((path, body))
        })
        .collect();

    // Which of these carry the user's *own* edits, as opposed to the
    // migration's output. `changed` alone cannot tell them apart: the
    // migration is what made the file differ from its snapshot, so every file
    // it touched shows up as changed and the warning fires on the ordinary
    // case. Comparing against the recorded post-migration digest is what
    // separates "this reverts the upgrade" from "this drops work you did".
    let digests = recorded_post_digests(&root, level);
    let hand_edited: Vec<&Path> = changed
        .iter()
        .map(|(_, live, live_body, _)| (live.as_path(), live_body))
        .chain(stale.iter().map(|(path, body)| (path.as_path(), body)))
        .filter(|(path, body)| is_hand_edited(&digests, path, body))
        .map(|(path, _)| path)
        .collect();

    if changed.is_empty() && stale.is_empty() {
        println!("Config already matches the level-{level} snapshot; rolling back the level.");
    } else {
        println!("Restoring the level-{level} snapshot will DISCARD these changes:\n");
        for (entry, live, live_body, snapshot_body) in &changed {
            let diff = similar::TextDiff::from_lines(live_body.as_str(), snapshot_body.as_str());
            println!(
                "{}",
                diff.unified_diff()
                    .header(&format!("current {}", live.display()), &entry.snapshot)
            );
        }

        for (path, body) in &stale {
            let diff = similar::TextDiff::from_lines(body.as_str(), "");
            println!(
                "{}",
                diff.unified_diff()
                    .header(&format!("current {}", path.display()), "(removed)")
            );
        }

        if hand_edited.is_empty() {
            // Deliberately not naming a migration: rolling back to level N
            // undoes every migration above it, so the files above were written
            // by several, not by `level + 1`.
            println!(
                "Every file above matches what the migrations wrote, so this only\n\
                 reverts the upgrade — none of your own edits are at stake.\n"
            );
        } else {
            println!("You have edited these since the upgrade; a restore drops those edits:\n");
            for path in &hand_edited {
                println!(
                    "  {}",
                    crate::daemon::ui::abbreviate_home(&path.display().to_string())
                );
            }
            println!();
        }

        if !assume_yes {
            crate::term::soft_reset();
            // Two different questions, because they carry different weight. A
            // rollback that only undoes the migration is routine; one that
            // drops the user's own edits deserves to say so at the prompt,
            // not only in the wall of diff above it.
            let question = if hand_edited.is_empty() {
                "Roll back to this snapshot?".to_owned()
            } else if hand_edited.len() == 1 {
                "Discard your edits to 1 file and restore?".to_owned()
            } else {
                format!(
                    "Discard your edits to {} files and restore?",
                    hand_edited.len()
                )
            };
            let ok = cliclack::confirm(question).interact()?;
            if !ok {
                println!("Aborted; nothing changed.");
                return Ok(1);
            }
        }
    }

    // Everything below mutates: the dotfiles, and then the recorded level.
    // Under the lock, because `run_pending_in` writes the same level and a
    // restore that interleaves with a migration would stamp one migration's
    // level over another's files.
    //
    // Taken *after* the prompt on purpose — `acquire_lock` blocks, so holding
    // it across an interactive confirm would park every concurrent wrap on how
    // long the user takes to read the diff.
    let _lock = acquire_lock(&root)?;

    // Save the current state before overwriting it, so a mistaken restore is
    // itself recoverable.
    let saved = snapshot_root(&root).join(format!("current-{}", now_stamp()));
    // 0700, inlined rather than via `paths::ensure_private_dir` — migrations
    // resolve no locations through `paths`. What lands in here is a copy of
    // whatever the restore is about to overwrite, `~/.ssh/config` included, so
    // the directory has to be as private as the copies inside it: at the
    // umask's 0755 the listing alone maps every config path on the machine.
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(OWNER_ONLY_DIR)
        .create(&saved)
        .with_context(|| format!("create {}", saved.display()))?;
    for (entry, live, live_body, _) in &plan {
        if live.exists() {
            // Carry the live file's mode into the saved copy: this is the
            // rescue copy of a `~/.ssh/config`, and `fs::write` would have
            // parked it at 0644 inside the secreq root.
            atomic::replace(
                &saved.join(&entry.snapshot),
                live_body.as_bytes(),
                atomic::Mode::Like(live),
            )
            .with_context(|| format!("save current {}", live.display()))?;
        }
    }
    for (path, body) in &stale {
        let name = path.file_name().map_or_else(
            || "artifact".to_owned(),
            |n| n.to_string_lossy().into_owned(),
        );
        atomic::replace(&saved.join(name), body.as_bytes(), atomic::Mode::Like(path))
            .with_context(|| format!("save current {}", path.display()))?;
    }

    for (entry, live, _, snapshot_body) in &plan {
        // Drop whatever is at the destination first: after migration 0001 it's
        // a symlink, and writing through it would land in the new root rather
        // than restoring the old layout.
        let _ = std::fs::remove_file(&entry.restore_to);
        if let Some(parent) = entry.restore_to.parent() {
            // 0700, and this one lands *outside* `$SECREQ_HOME` — the restore
            // targets are the pre-migration paths, so this recreates
            // `~/.config/secreq` (and `~/.ssh` for 0002) when the forward
            // migration removed it. The 0700 root does not contain these, so
            // the umask's 0755 here published a directory holding the config
            // being restored into it. Only directories this actually creates
            // are affected: an existing `~/.ssh` or `~/.config` keeps its own
            // mode, so this narrows nothing the user chose.
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(OWNER_ONLY_DIR)
                .create(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
        atomic::replace(
            &entry.restore_to,
            snapshot_body.as_bytes(),
            restore_mode(&entry.restore_to, &dir.join(&entry.snapshot)),
        )?;

        // Remove the forward artifact so a later re-migration doesn't find two
        // real files that differ and refuse to guess.
        //
        // Heuristic, and only correct for migrations shaped like "this file
        // moved" — which is all of them today. It's guarded on the paths
        // actually differing, so an in-place content migration (where
        // `restore_to` *is* the live path) doesn't delete what we just wrote.
        // The day a migration needs different teardown is the day a `down`
        // hook earns its place.
        if live != &entry.restore_to {
            let _ = std::fs::remove_file(live);
        }
    }

    for (path, _) in &stale {
        std::fs::remove_file(path).with_context(|| format!("remove {}", path.display()))?;
    }

    write_state(&root, level)?;
    println!("\nRestored level {level}.");
    println!("Your previous config was saved to {}", saved.display());
    Ok(0)
}

/// Files a **later** migration created, that the target level therefore has no
/// snapshot for — so a restore cannot put them back, and leaving them strands
/// two real configs the next forward run has to choose between.
///
/// # This feeds a delete, so both bounds matter
///
/// 1. **Recorded, not predicted.** Candidates come from the `created` list each
///    filemap carries: paths a migration declared, that were absent when its
///    snapshot was taken, and existed once it finished. A migration that only
///    *edits* a file records nothing, so 0002's `~/.ssh/config` and shell rc
///    cannot appear here however they are declared.
/// 2. **Inside the root.** Belt to that braces. A recorded creation outside
///    `root` still would not be ours to delete.
///
/// The first bound is what makes this correct; the second is what makes a
/// future mistake in the first survivable. An earlier version had neither — it
/// re-ran `snapshot_files` against a `Ctx` built from the real
/// `dirs::home_dir()` — and deleted a user's SSH config and `.zshrc`.
fn stale_root_artifacts(
    root: &Path,
    level: u32,
    plan: &[(&FileEntry, PathBuf, String, String)],
) -> Vec<PathBuf> {
    let restored: Vec<&PathBuf> = plan.iter().map(|(e, _, _, _)| &e.restore_to).collect();
    let mut out: Vec<PathBuf> = Vec::new();

    for higher in level..MIGRATIONS.len() as u32 {
        let path = snapshot_dir(root, higher).join("filemap.json");
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(map) = serde_json::from_str::<FileMap>(&text) else {
            continue;
        };
        for created in map.created {
            if !created.starts_with(root) {
                continue;
            }
            if restored.iter().any(|kept| **kept == created) || out.contains(&created) {
                continue;
            }
            if created.exists() {
                out.push(created);
            }
        }
    }
    out
}

/// What mode a restored file must land with.
///
/// The **snapshot** is the mode source, not the live file and certainly not a
/// staging file: [`snapshot_if_absent`] captures with `fs::copy`, which carries
/// the mode across, so the copy under `migration-snapshots/` already records
/// what the user had before the migration. Restoring content while quietly
/// republishing it at the umask's mode is what made `migrate restore` hand back
/// a world-readable `~/.ssh/config`.
///
/// That file is then the one exception, forced rather than preserved. ssh
/// *refuses* a group- or world-readable config, so a snapshot that recorded
/// 0644 — a config the user's own editor had already loosened — would be
/// restored into a file ssh ignores, silently dropping the `IdentityAgent` the
/// restore existed to bring back. `ssh_setup::apply` forces 0600 when it writes
/// that file for the same reason; a restore has to reach the same place.
fn restore_mode<'a>(target: &Path, snapshot: &'a Path) -> atomic::Mode<'a> {
    if target.ends_with(".ssh/config") {
        return atomic::Mode::Exactly(0o600);
    }
    atomic::Mode::Like(snapshot)
}

/// Where the file described by `entry` lives *today*. Post-migration that's
/// the new root; pre-migration it's still the recorded origin.
fn live_path(root: &Path, entry: &FileEntry) -> PathBuf {
    let at_root = root.join(&entry.snapshot);
    if at_root.is_file() {
        at_root
    } else {
        entry.restore_to.clone()
    }
}

fn no_snapshot_message(root: &Path, level: u32) -> String {
    let mut available: Vec<String> = std::fs::read_dir(snapshot_root(root))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.parse::<u32>().is_ok())
        .collect();
    available.sort();
    if available.is_empty() {
        format!(
            "no snapshot for level {level} at {}.\n\
             Snapshots only exist for migrations this install actually ran; a \
             config that was already at the current level has nothing to go \
             back to.",
            snapshot_dir(root, level).display(),
        )
    } else {
        format!(
            "no snapshot for level {level}. Available: {}",
            available.join(", ")
        )
    }
}

/// `Date::now`-free timestamp for naming the pre-restore save.
fn now_stamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

struct LockGuard {
    _file: File,
}

/// Blocking exclusive flock. Blocking is the point: a concurrent wrap should
/// *wait* for the migration and then observe the new level, not fail. Unlike
/// the pidfile lock this file is never unlinked, so there's no inode race to
/// defend against.
fn acquire_lock(root: &Path) -> Result<LockGuard> {
    let path = root.join(LOCK_FILE);
    // 0600, because `create` alone takes `0666 & !umask` — 0644 ordinarily and
    // **0666** under `umask 000`. The file is empty, so there is nothing in it
    // to read; the mode is about who may *hold* it. `flock` needs only an open
    // descriptor, so a world-writable lock lets any local user take `LOCK_EX`
    // and park every `secreq x` on the machine behind a lock the user cannot
    // see. Applies on creation only, which is all this can do — an install
    // that already has one keeps its mode, and the 0700 root is what covers
    // that case.
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .mode(OWNER_ONLY)
        .open(&path)
        .with_context(|| format!("open migration lock {}", path.display()))?;
    let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("flock {}", path.display()));
    }
    Ok(LockGuard { _file: file })
}

#[derive(Serialize, Deserialize, Debug)]
struct FileMap {
    created_by: String,
    files: Vec<FileEntry>,
    /// Paths this migration **brought into existence** — declared in its
    /// `snapshot_files`, absent when the snapshot was taken, present once it
    /// finished. Recorded by [`record_created`] after the migration returns.
    ///
    /// This is the distinction `snapshot_files` alone cannot make. That list
    /// mixes files a migration *creates* (0003's `config.toml`) with files it
    /// *edits* (0002's `~/.ssh/config`, where it rewrites a managed block).
    /// A rollback must remove the first kind and must never remove the second,
    /// and deriving that from the declaration is how the restore cleanup once
    /// deleted a user's SSH config and shell rc.
    ///
    /// `#[serde(default)]` so a filemap written before this field existed
    /// deserializes as "recorded nothing" — the safe answer, since an older
    /// migration's creations are not knowable after the fact.
    #[serde(default)]
    created: Vec<PathBuf>,
    /// What each file this migration touched looked like **immediately after
    /// it ran**, as a hex SHA-256. Covers the files it edited and the ones it
    /// created alike.
    ///
    /// This is the one fact a restore cannot recompute. The *pre* state is
    /// already on disk — the snapshot copies are those bytes — so comparing
    /// live against snapshot only ever says "this file changed", which is
    /// unhelpful because the migration is what changed it. Comparing live
    /// against `post` says the thing that matters: whether the user has
    /// edited it *since*, and therefore whether a restore drops work.
    ///
    /// `#[serde(default)]` so an older filemap loads as "unknown". Unknown
    /// must degrade to warn-and-confirm, never to "unchanged" — an absent
    /// digest is not evidence of an untouched file.
    #[serde(default)]
    post_sha256: BTreeMap<PathBuf, String>,
}

/// Every post-migration digest recorded at or above `level`, merged.
///
/// One filemap is not enough: the digest for a file lives in the filemap of
/// the migration that *wrote* it, which for `config.toml` is level 2, while a
/// restore to level 0 reads level 0's. Ascending order, so a later migration's
/// record wins for a path more than one of them touched.
fn recorded_post_digests(root: &Path, level: u32) -> BTreeMap<PathBuf, String> {
    let mut out = BTreeMap::new();
    for at in level..MIGRATIONS.len() as u32 {
        let path = snapshot_dir(root, at).join("filemap.json");
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(map) = serde_json::from_str::<FileMap>(&text) else {
            continue;
        };
        out.extend(map.post_sha256);
    }
    out
}

/// Has the user edited `path` since the migration wrote it?
///
/// Compares the live bytes against the digest recorded when the migration
/// finished. A path that does not exist is never "edited" — there is nothing
/// of the user's there to drop, and this is the ordinary state of a moved
/// file's old location. Otherwise:
///
/// - digest recorded and it matches → **no**. The file is the migration's own
///   output; restoring reverts the upgrade and nothing else.
/// - digest recorded and it differs → **yes**. Real work is at stake.
/// - **no digest recorded** → **yes**, conservatively. A filemap written
///   before `post_sha256` existed knows nothing about this file, and "unknown"
///   must read as "might be yours" — treating it as untouched would quietly
///   downgrade the one warning standing between a user and their own edits.
fn is_hand_edited(digests: &BTreeMap<PathBuf, String>, path: &Path, live_body: &str) -> bool {
    if !path.exists() {
        return false;
    }
    let Some(recorded) = digests.get(path) else {
        return true;
    };
    crate::rules::sha256_hex(live_body.as_bytes()) != *recorded
}

#[derive(Serialize, Deserialize, Debug)]
struct FileEntry {
    /// Basename within the snapshot dir.
    snapshot: String,
    /// Absolute restore target. Safe to store absolute because snapshots are
    /// machine-local — same reasoning that keeps `.migration-state` out of
    /// `config.toml`.
    restore_to: PathBuf,
}

fn snapshot_root(root: &Path) -> PathBuf {
    root.join(SNAPSHOT_DIR)
}

pub fn snapshot_dir(root: &Path, level: u32) -> PathBuf {
    snapshot_root(root).join(level.to_string())
}

/// Capture the config as it stands *before* `m` runs, keyed by the level it
/// migrates away from.
///
/// **Never overwrites an existing snapshot.** If a migration failed partway
/// and re-runs, re-snapshotting would capture the half-migrated state and
/// destroy the real pre-state — turning the safety net into the thing that
/// loses the config. First write wins.
fn snapshot_if_absent(ctx: &Ctx, m: &Migration) -> Result<()> {
    let level = m.id - 1;
    let dir = snapshot_dir(&ctx.root, level);
    if dir.exists() {
        return Ok(());
    }

    let sources: Vec<PathBuf> = (m.snapshot)(ctx)
        .into_iter()
        .filter(|p| p.is_file())
        .collect();
    if sources.is_empty() {
        // Fresh install: nothing to snapshot. Don't create an empty dir —
        // its absence is what tells `restore` there's nothing to go back to.
        return Ok(());
    }

    // Stage in a sibling tmp dir and rename, so a crash can't leave a
    // half-written snapshot that `dir.exists()` would then treat as good.
    let staging = snapshot_root(&ctx.root).join(format!(".{level}.tmp"));
    let _ = std::fs::remove_dir_all(&staging);
    // Recursive at 0700, which is two directories: the staging dir *and*
    // `migration-snapshots/` itself on the first migration that captures
    // anything. A bare `create_dir_all` gave both the umask's 0755, and the
    // staging dir's mode is not transient — the `rename` below publishes this
    // inode as `migration-snapshots/<level>/`, so whatever it is created with
    // is the mode the committed snapshot keeps forever. What it holds is
    // `fs::copy` of every file the migration is about to move, which for 0002
    // reaches outside the secreq tree to `~/.ssh/config` and the shell rc
    // files; the copies carry their own modes, but the listing is a map of the
    // user's config paths. Inlined rather than routed through
    // `paths::ensure_private_dir` for the same reason as the root and the
    // pre-restore save: migrations resolve no locations through `paths`, and a
    // mode is a constant, not a location.
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(OWNER_ONLY_DIR)
        .create(&staging)
        .with_context(|| format!("create {}", staging.display()))?;

    let mut files = Vec::new();
    for src in &sources {
        let name = src
            .file_name()
            .context("snapshot source has no file name")?
            .to_string_lossy()
            .into_owned();
        if files.iter().any(|e: &FileEntry| e.snapshot == name) {
            bail!(
                "snapshot name collision on {name}; migration {:04} must not \
                 capture two files with the same basename",
                m.id
            );
        }
        std::fs::copy(src, staging.join(&name))
            .with_context(|| format!("snapshot {}", src.display()))?;
        files.push(FileEntry {
            snapshot: name,
            restore_to: src.clone(),
        });
    }

    let map = FileMap {
        created_by: build_stamp(),
        files,
        // Both filled in by `record_post_state` once the migration has
        // actually run; nothing has happened yet at snapshot time.
        created: Vec::new(),
        post_sha256: BTreeMap::new(),
    };
    atomic::replace(
        &staging.join("filemap.json"),
        serde_json::to_string_pretty(&map)?.as_bytes(),
        atomic::Mode::Exactly(OWNER_ONLY),
    )?;

    std::fs::rename(&staging, &dir)
        .with_context(|| format!("rename {} -> {}", staging.display(), dir.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Every path under `tmp`. These tests drive `run_pending_in`, which runs
    /// the *whole* `MIGRATIONS` list — including 0002, which edits dotfiles
    /// under `home`. A real `dirs::home_dir()` here would rewrite the
    /// developer's `~/.ssh/config` and `~/.zshrc` on `cargo test`.
    fn ctx_in(tmp: &TempDir) -> Ctx {
        Ctx {
            root: tmp.path().join("secreq"),
            home: Some(tmp.path().join("home")),
            legacy_config_dir: Some(tmp.path().join("config/secreq")),
            legacy_state_dir: Some(tmp.path().join("state/secreq")),
            legacy_runtime_dir: Some(tmp.path().join("runtime/secreq")),
        }
    }

    fn write(path: &Path, body: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    #[test]
    fn migration_ids_are_dense_and_one_based() {
        // run_pending slices MIGRATIONS[level..], which is only correct if
        // index == id - 1. A gap would silently run the wrong migrations.
        for (i, m) in MIGRATIONS.iter().enumerate() {
            assert_eq!(m.id as usize, i + 1, "migration {} out of order", m.name);
        }
    }

    #[test]
    fn fresh_install_stamps_latest_and_creates_no_legacy_dir() {
        let tmp = TempDir::new().unwrap();
        let ctx = ctx_in(&tmp);
        run_pending_in(&ctx).unwrap();

        assert_eq!(
            read_state(&ctx.root).unwrap().migration_level as usize,
            MIGRATIONS.len()
        );
        // Symlinks are a compatibility artifact for upgraders; a new user
        // has no legacy muscle memory to serve.
        assert!(!ctx.legacy_config_dir.unwrap().exists());
        // Nothing to snapshot, so no empty snapshot dir either.
        assert!(!snapshot_dir(&ctx.root, 0).exists());
    }

    #[test]
    fn verify_current_is_ok_and_inert_when_at_level() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("secreq");
        write_state(&root, MIGRATIONS.len() as u32).unwrap();

        verify_current_in(&root).unwrap();

        // Read-only: the recorded level is untouched, no lock/snapshot appears.
        assert_eq!(
            read_state(&root).unwrap().migration_level as usize,
            MIGRATIONS.len()
        );
        assert!(!root.join(".migration.lock").exists());
    }

    #[test]
    fn verify_current_below_level_refuses_and_applies_nothing() {
        // Regression: a service role (agent open / daemon) launched from a
        // build with pending migrations must NOT migrate — it used to, bumping
        // the shared level an older installed build then refused.
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("secreq");

        let err = verify_current_in(&root).unwrap_err().to_string();
        assert!(err.contains("background/service"), "got: {err}");

        // Nothing stamped, nothing created — the level stays untouched.
        assert!(!state_path(&root).exists());
        assert!(!root.exists());
    }

    #[test]
    fn verify_current_above_level_bails_downgrade() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("secreq");
        write_state(&root, MIGRATIONS.len() as u32 + 1).unwrap();

        let err = verify_current_in(&root).unwrap_err().to_string();
        // The same restore hint the foreground gate gives.
        assert!(err.contains("migrate restore"), "got: {err}");
    }

    #[test]
    fn moves_config_and_leaves_a_symlink_behind() {
        let tmp = TempDir::new().unwrap();
        let ctx = ctx_in(&tmp);
        let legacy = ctx.legacy_config_dir.clone().unwrap();
        write(&legacy.join("wraps.json5"), "{ gh: {} }");
        write(&legacy.join("auto-rules.json5"), "{ rules: [] }");

        run_pending_in(&ctx).unwrap();

        // 0001 moved the file and left a symlink; 0003 then converted it to
        // TOML and cleared that symlink, because an older secreq could not
        // read the new format wherever the link pointed.
        let config = ctx.root.join("config.toml");
        assert!(config.is_file(), "config landed in the root as TOML");
        assert!(
            !ctx.root.join("wraps.json5").exists(),
            "the JSON5 original is gone"
        );
        assert!(
            legacy.join("wraps.json5").symlink_metadata().is_err(),
            "the stale compat symlink is removed rather than left dangling"
        );
        let c = crate::wraps::WrapsConfig::parse(
            &std::fs::read_to_string(&config).unwrap(),
            "migrated",
        )
        .expect("the migrated config parses");
        assert!(c.wraps.contains_key("gh"), "the wrap survived both levels");
    }

    #[test]
    fn is_idempotent_across_repeated_runs() {
        let tmp = TempDir::new().unwrap();
        let ctx = ctx_in(&tmp);
        write(
            &ctx.legacy_config_dir.clone().unwrap().join("wraps.json5"),
            "{ gh: {} }",
        );

        run_pending_in(&ctx).unwrap();
        run_pending_in(&ctx).unwrap();
        run_pending_in(&ctx).unwrap();

        let c = crate::wraps::WrapsConfig::parse(
            &std::fs::read_to_string(ctx.root.join("config.toml")).unwrap(),
            "migrated",
        )
        .expect("the migrated config parses after repeated runs");
        assert!(c.wraps.contains_key("gh"));
    }

    #[test]
    fn resumes_when_both_files_exist_and_match() {
        // The state after a crash between copy and remove. Erroring here
        // would wedge the user on a retry that can never succeed.
        let tmp = TempDir::new().unwrap();
        let ctx = ctx_in(&tmp);
        let legacy = ctx.legacy_config_dir.clone().unwrap();
        write(&legacy.join("wraps.json5"), "{ gh: {} }");
        write(&ctx.root.join("wraps.json5"), "{ gh: {} }");

        run_pending_in(&ctx).unwrap();

        // 0001 leaves a symlink here; 0003 then clears it, because the
        // format it points at is one an older secreq cannot read anyway.
        assert!(
            legacy.join("wraps.json5").symlink_metadata().is_err(),
            "the compat symlink is cleared once the format changes under it"
        );
        assert!(ctx.root.join("config.toml").is_file());
    }

    #[test]
    fn refuses_when_both_files_exist_and_differ() {
        let tmp = TempDir::new().unwrap();
        let ctx = ctx_in(&tmp);
        let legacy = ctx.legacy_config_dir.clone().unwrap();
        write(&legacy.join("wraps.json5"), "{ gh: {} }");
        write(&ctx.root.join("wraps.json5"), "{ aws: {} }");

        let err = run_pending_in(&ctx).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("differ"), "unhelpful error: {msg}");
        // Refusing means refusing: neither file is touched.
        assert_eq!(
            std::fs::read_to_string(legacy.join("wraps.json5")).unwrap(),
            "{ gh: {} }"
        );
        assert_eq!(
            std::fs::read_to_string(ctx.root.join("wraps.json5")).unwrap(),
            "{ aws: {} }"
        );
    }

    /// `stale_root_artifacts` feeds a delete. It reads the `created` list a
    /// filemap records — paths a migration brought into existence — never the
    /// `snapshot_files` declaration, which mixes those with files a migration
    /// merely *edits*.
    ///
    /// That distinction is the whole fix. Migration 0002 manages a block inside
    /// the user's `~/.ssh/config` and shell rc, so it declares them and creates
    /// neither. An earlier version derived candidates from the declaration,
    /// against a `Ctx` holding the real `dirs::home_dir()`, and deleted both out
    /// of a live home.
    ///
    /// Pins both bounds: an edited file recorded in `files` is never a
    /// candidate, and nothing outside the root is either.
    #[test]
    fn stale_root_artifacts_only_removes_recorded_creations_inside_the_root() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("secreq");
        std::fs::create_dir_all(&root).unwrap();

        // A file a migration *edited* — captured in `files`, not `created`.
        // This is the `~/.ssh/config` shape.
        let edited = tmp.path().join("home/.ssh/config");
        std::fs::create_dir_all(edited.parent().unwrap()).unwrap();
        std::fs::write(&edited, "Host example\n").unwrap();

        // A creation outside the root. Recorded as created, still not ours.
        let outside_creation = tmp.path().join("home/somewhere.toml");
        std::fs::write(&outside_creation, "x = 1\n").unwrap();

        // The real artifact: created, inside the root.
        let artifact = root.join("config.toml");
        std::fs::write(&artifact, "[wraps.gh]\n").unwrap();

        let snap = snapshot_dir(&root, 1);
        std::fs::create_dir_all(&snap).unwrap();
        let map = FileMap {
            created_by: "test".to_owned(),
            post_sha256: BTreeMap::new(),
            files: vec![FileEntry {
                snapshot: "config".to_owned(),
                restore_to: edited.clone(),
            }],
            created: vec![artifact.clone(), outside_creation.clone()],
        };
        std::fs::write(
            snap.join("filemap.json"),
            serde_json::to_string(&map).unwrap(),
        )
        .unwrap();

        let found = stale_root_artifacts(&root, 0, &[]);

        assert_eq!(
            found,
            vec![artifact],
            "only the in-root creation is a candidate"
        );
        assert!(edited.exists(), "an edited file is never a candidate");
        assert!(
            outside_creation.exists(),
            "even a recorded creation outside the root is out of bounds"
        );
    }

    /// A file the migration wrote and nobody has touched since is not the
    /// user's work, and a restore that reverts it drops nothing of theirs.
    #[test]
    fn a_file_matching_its_post_migration_digest_is_not_hand_edited() {
        let body = "[wraps.gh]\n";
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("config.toml");
        std::fs::write(&path, body).unwrap();

        let mut digests = BTreeMap::new();
        digests.insert(path.clone(), crate::rules::sha256_hex(body.as_bytes()));

        assert!(!is_hand_edited(&digests, &path, body));
        assert!(
            is_hand_edited(&digests, &path, "[wraps.gh]\nreason = \"mine\"\n"),
            "an edit since the migration must be reported"
        );
    }

    /// The bound that keeps this from ever *weakening* the warning: a filemap
    /// written before `post_sha256` existed knows nothing, and unknown has to
    /// read as "might be the user's". Treating it as untouched would silence
    /// the one warning standing between them and their own edits.
    #[test]
    fn an_unrecorded_file_is_treated_as_hand_edited() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("config.toml");
        std::fs::write(&path, "anything").unwrap();
        assert!(is_hand_edited(&BTreeMap::new(), &path, "anything"));

        // ...but an absent file still is not, digest or no digest.
        assert!(!is_hand_edited(
            &BTreeMap::new(),
            &tmp.path().join("gone.toml"),
            ""
        ));
    }

    #[test]
    fn snapshots_the_pre_migration_state() {
        let tmp = TempDir::new().unwrap();
        let ctx = ctx_in(&tmp);
        let legacy = ctx.legacy_config_dir.clone().unwrap();
        write(&legacy.join("wraps.json5"), "{ gh: {} }");

        run_pending_in(&ctx).unwrap();

        let snap = snapshot_dir(&ctx.root, 0);
        assert_eq!(
            std::fs::read_to_string(snap.join("wraps.json5")).unwrap(),
            "{ gh: {} }"
        );
        let map: FileMap =
            serde_json::from_str(&std::fs::read_to_string(snap.join("filemap.json")).unwrap())
                .unwrap();
        assert_eq!(map.files.len(), 1);
        assert_eq!(map.files[0].restore_to, legacy.join("wraps.json5"));
    }

    #[test]
    fn snapshot_is_never_overwritten_on_retry() {
        // A retry must not capture the half-migrated state over the real
        // pre-state — that would make the safety net the thing that loses
        // the config.
        let tmp = TempDir::new().unwrap();
        let ctx = ctx_in(&tmp);
        write(
            &ctx.legacy_config_dir.clone().unwrap().join("wraps.json5"),
            "{ original: {} }",
        );

        run_pending_in(&ctx).unwrap();
        // Simulate a re-run from level 0 with the config already moved.
        write_state(&ctx.root, 0).unwrap();
        std::fs::write(ctx.root.join("config.toml"), "{ changed_after: {} }").unwrap();
        run_pending_in(&ctx).unwrap();

        assert_eq!(
            std::fs::read_to_string(snapshot_dir(&ctx.root, 0).join("wraps.json5")).unwrap(),
            "{ original: {} }"
        );
    }

    #[test]
    fn migrates_the_audit_log() {
        let tmp = TempDir::new().unwrap();
        let ctx = ctx_in(&tmp);
        write(
            &ctx.legacy_state_dir.clone().unwrap().join("audit.log"),
            "{\"decision\":\"approved\"}\n",
        );

        run_pending_in(&ctx).unwrap();

        assert_eq!(
            std::fs::read_to_string(ctx.root.join("audit.log")).unwrap(),
            "{\"decision\":\"approved\"}\n"
        );
        assert!(!ctx.legacy_state_dir.unwrap().join("audit.log").exists());
    }

    #[test]
    fn downgrade_bails_with_a_restore_hint() {
        let tmp = TempDir::new().unwrap();
        let ctx = ctx_in(&tmp);
        std::fs::create_dir_all(&ctx.root).unwrap();
        write_state(&ctx.root, MIGRATIONS.len() as u32 + 4).unwrap();

        let err = run_pending_in(&ctx).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("migrate restore"), "no restore hint: {msg}");
        assert!(msg.contains("older"), "doesn't explain the cause: {msg}");
    }

    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// A level-1 install whose `ssh setup` block names the pre-0002 socket,
    /// which is what gives migration 0002 something to snapshot and `restore`
    /// something to put back. Returns the `~/.ssh/config` path.
    fn wire_ssh_config(ctx: &Ctx) -> PathBuf {
        use crate::path_setup::Shell;
        use crate::ssh_setup::{self, Method};

        let home = ctx.home.clone().unwrap();
        let legacy_sock = ctx.legacy_runtime_dir.clone().unwrap().join("agent.sock");
        let plan = ssh_setup::plan(&home, Method::SshConfig, Shell::Zsh, &legacy_sock).unwrap();
        ssh_setup::apply(&plan).unwrap();
        plan.config_file
    }

    /// `restore` writes through an atomic replace, which publishes a **new
    /// inode** — so it used to hand `~/.ssh/config` back at the staging file's
    /// 0644, disclosing internal hostnames, bastion aliases and `IdentityFile`
    /// paths. ssh also refuses a config that laxer, so the restore broke the
    /// very `IdentityAgent` line it was restoring.
    #[test]
    fn restore_leaves_ssh_config_owner_only() {
        let tmp = TempDir::new().unwrap();
        let ctx = ctx_in(&tmp);
        let config = wire_ssh_config(&ctx);
        assert_eq!(mode_of(&config), 0o600, "ssh setup writes it 0600");

        run_pending_in(&ctx).unwrap();
        assert_eq!(restore_in(&ctx.root, 1, true).unwrap(), 0);

        assert_eq!(mode_of(&config), 0o600, "ssh refuses a laxer mode");
    }

    /// The forced half of [`restore_mode`]. Preserving the snapshot's mode is
    /// right for a shell rc, but `~/.ssh/config` has a mode its *reader*
    /// dictates: bringing back a 0644 one faithfully would restore a file ssh
    /// then ignores.
    #[test]
    fn restore_narrows_an_ssh_config_that_was_already_too_wide() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let ctx = ctx_in(&tmp);
        let config = wire_ssh_config(&ctx);
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o644)).unwrap();

        run_pending_in(&ctx).unwrap();
        restore_in(&ctx.root, 1, true).unwrap();

        assert_eq!(mode_of(&config), 0o600);
    }

    /// A shell rc is the user's file and its mode is the user's business, so
    /// the snapshot's mode is what comes back.
    #[test]
    fn restore_carries_a_shell_rc_mode_back_unchanged() {
        use crate::path_setup::Shell;
        use crate::ssh_setup::{self, Method};

        let tmp = TempDir::new().unwrap();
        let ctx = ctx_in(&tmp);
        let home = ctx.home.clone().unwrap();
        let legacy_sock = ctx.legacy_runtime_dir.clone().unwrap().join("agent.sock");
        let plan = ssh_setup::plan(&home, Method::ShellRc, Shell::Zsh, &legacy_sock).unwrap();
        ssh_setup::apply(&plan).unwrap();
        std::fs::set_permissions(
            &plan.config_file,
            std::os::unix::fs::PermissionsExt::from_mode(0o640),
        )
        .unwrap();

        run_pending_in(&ctx).unwrap();
        restore_in(&ctx.root, 1, true).unwrap();

        assert_eq!(mode_of(&plan.config_file), 0o640);
    }

    /// `restore` rewrites dotfiles and stamps the level, which is exactly what
    /// `run_pending_in` does — so it takes the same lock. The lock file is
    /// never unlinked, so its presence is the observable.
    #[test]
    fn restore_takes_the_migration_lock() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("secreq");
        let target = tmp.path().join("config/secreq/config.toml");
        write(&target, "live");

        // A hand-built level-0 snapshot, so nothing has taken the lock on this
        // root before `restore_in` does.
        let snap = snapshot_dir(&root, 0);
        std::fs::create_dir_all(&snap).unwrap();
        std::fs::write(snap.join("config.toml"), "snapshot").unwrap();
        let map = FileMap {
            created_by: "test".into(),
            created: Vec::new(),
            post_sha256: BTreeMap::new(),
            files: vec![FileEntry {
                snapshot: "config.toml".into(),
                restore_to: target.clone(),
            }],
        };
        write(
            &snap.join("filemap.json"),
            &serde_json::to_string(&map).unwrap(),
        );
        assert!(!root.join(LOCK_FILE).exists());

        restore_in(&root, 0, true).unwrap();

        assert_eq!(std::fs::read_to_string(&target).unwrap(), "snapshot");
        assert!(
            root.join(LOCK_FILE).exists(),
            "restore must serialise against run_pending_in"
        );
    }

    /// `.migration-state` names every config path on the machine, and the
    /// snapshot's `filemap.json` names them all again with their restore
    /// targets. Neither is a file to publish at the umask's 0644.
    #[test]
    fn the_bookkeeping_files_are_owner_only() {
        let tmp = TempDir::new().unwrap();
        let ctx = ctx_in(&tmp);
        write(
            &ctx.legacy_config_dir.clone().unwrap().join("wraps.json5"),
            "{ gh: {} }",
        );

        run_pending_in(&ctx).unwrap();

        assert_eq!(mode_of(&state_path(&ctx.root)), 0o600);
        assert_eq!(
            mode_of(&snapshot_dir(&ctx.root, 0).join("filemap.json")),
            0o600
        );
    }

    /// The framework used to read `Ok(())` from a migration as "done", with no
    /// way for one to say "I ran, and I could not finish". Migration 0002 hit
    /// that: a managed block it could not read was skipped, the level was
    /// stamped over the skip, and the stamp is what makes it permanent — a
    /// stamped level never retries, so a user who then fixed the block would
    /// never get the migration that fixing it was for.
    #[test]
    fn an_incomplete_migration_does_not_stamp_the_level() {
        use crate::ssh_setup::{BEGIN_SENTINEL, END_SENTINEL};

        let tmp = TempDir::new().unwrap();
        let ctx = ctx_in(&tmp);
        // A block whose socket path secreq cannot resolve — an unquoted `~`,
        // which is a hand-edit rather than anything `ssh setup` writes.
        write(
            &ctx.home.clone().unwrap().join(".ssh/config"),
            &format!(
                "{BEGIN_SENTINEL}\nHost *\n    IdentityAgent ~/Library/Caches/secreq/agent.sock\n{END_SENTINEL}\n"
            ),
        );

        let err = run_pending_in(&ctx).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("could not finish"),
            "an incomplete migration must say so: {msg}"
        );
        assert!(
            msg.contains(".ssh/config"),
            "and name what stopped it: {msg}"
        );

        // 0001 finished and stamped; 0002 did not, so the level stays at 1 and
        // the next foreground command runs 0002 again.
        assert_eq!(read_state(&ctx.root).unwrap().migration_level, 1);
    }

    // The pre-restore save directory's mode is pinned by
    // `the_pre_restore_save_dir_is_owner_only_under_a_hostile_umask` in
    // `tests/cli.rs`, not here. An in-process test takes the ambient umask,
    // so on a developer whose shell sets `umask 077` it passed against
    // unfixed code — and the shell that sets 077 is the shell most likely to
    // be running these tests. That test drives the real binary with
    // `umask 000` set in the child.

    #[test]
    fn corrupt_state_file_says_how_to_recover() {
        let tmp = TempDir::new().unwrap();
        let ctx = ctx_in(&tmp);
        write(&state_path(&ctx.root), "not json at all");

        let err = run_pending_in(&ctx).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("Delete it"), "unhelpful error: {msg}");
    }
}
