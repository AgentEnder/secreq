# `~/.secreq` as the single root, and a migration framework

Status: design agreed, not yet implemented
Date: 2026-07-16

## Problem

secreq scatters its files across four locations with no unifying idea:

| What | Where today | Resolved at |
|---|---|---|
| `wraps.json5` | `$XDG_CONFIG_HOME/secreq` | `wraps.rs:338` |
| `auto-rules.json5` | `$XDG_CONFIG_HOME/secreq` | `rules.rs:272` |
| `audit.log`, `daemon.log`, `daemon.jsonl` | `$XDG_STATE_HOME/secreq` | `audit.rs:195`, `daemon/log.rs:122` |
| `consent.sock`, `agent.sock`, `daemon.pid` | `$XDG_RUNTIME_DIR/secreq` or `cache_dir()` | `daemon/server.rs:1248` |
| shims | `$shim_dir` in config (default `~/.secreq/shims`) | `commands.rs:503` |

Four independent copies of near-identical XDG-resolution logic. `~/.secreq`
is not actually a concept in the code — it is a *suggested default* offered
once during `init` and thereafter read back from `$shim_dir`. A user who
typed a different path at init has no `~/.secreq` at all.

There is also no migration machinery, so changing any of this strands
existing users.

## Decisions

1. `~/.secreq` becomes the real root for config, logs, and shims.
2. Sockets keep preferring `$XDG_RUNTIME_DIR` when set; `~/.secreq/run` replaces
   `cache_dir()` as the fallback.
3. `$SECREQ_HOME` overrides the root. Replaces XDG vars as the relocation knob.
4. `~/.config/secreq/` keeps working via **file-level** symlinks to the two
   config files.
5. Migration state is machine-local, in a separate file — **not** in `wraps.json5`.
6. Migrations run automatically at the top of `cli::run()`.
7. Migration failure is fatal; each migration is atomic so the old state survives.
8. Downgrades are handled by **snapshot + restore**, not reverse migrations.

## Target layout

```
~/.secreq/
  wraps.json5              config
  auto-rules.json5         config
  audit.log                appended by daemon + wrap clients
  daemon.log
  daemon.jsonl
  shims/
  run/                     sockets, only when $XDG_RUNTIME_DIR is unset
  .migration-state         machine-local, never synced
  .migration.lock          flock target
  migration-snapshots/
    0/                     config as it stood at level 0
      filemap.json
      wraps.json5
      auto-rules.json5

~/.config/secreq/          real dir, upgraders only
  wraps.json5      -> ~/.secreq/wraps.json5
  auto-rules.json5 -> ~/.secreq/auto-rules.json5
```

Fresh installs get no `~/.config/secreq` — the symlinks are a compatibility
artifact for upgraders.

### Why file-level symlinks, not a directory symlink

`rm -rf ~/.config/secreq/` (trailing slash) against a **directory** symlink
deletes the *target tree*. Verified on macOS/BSD `rm`: it removed the entire
target directory, left a dangling symlink, and exited 0 silently. With
file-level symlinks, `rm -rf` unlinks the symlinks and the real files survive
— also verified. The danger only exists when the symlink *is* the directory
being named.

The symlinks turn out to double as downgrade compatibility for migration 0001:
an older secreq resolving `$XDG_CONFIG_HOME/secreq/wraps.json5` follows the
symlink and reads the correct file.

## `src/paths.rs`

Single source of truth. Deletes the duplicated resolution at `wraps.rs:338`,
`rules.rs:272`, `audit.rs:195`, and `server.rs:1248` (removed, not wrapped —
CLAUDE.md forbids keeping old and new side by side).

```rust
pub fn secreq_root() -> Result<PathBuf>      // $SECREQ_HOME, else ~/.secreq
pub fn wraps_path() -> Result<PathBuf>       // <root>/wraps.json5
pub fn rules_path() -> Result<PathBuf>       // <root>/auto-rules.json5
pub fn audit_log_path() -> Result<PathBuf>   // <root>/audit.log
pub fn daemon_log_path() -> Result<PathBuf>  // <root>/daemon.log
pub fn socket_dir() -> Result<PathBuf>       // $XDG_RUNTIME_DIR/secreq, else <root>/run
```

`socket_dir()` deliberately does **not** hang off `SECREQ_HOME` when
`XDG_RUNTIME_DIR` is set. `$XDG_RUNTIME_DIR` is spec-guaranteed mode 0700,
tmpfs, and never on NFS or a cloud-synced home — properties `~/.secreq/run`
cannot offer and that the pidfile flock does not substitute for. Test helpers
that need socket isolation must set both vars.

### Test impact — and the trap

The first draft of this design claimed `$SECREQ_HOME` would collapse the test
suite's env juggling down to one var. **That is wrong, and acting on it
corrupted a developer's real config during a `cargo test` run.**

`migrate` resolves the *pre-migration* locations through the frozen
`$XDG_CONFIG_HOME` / `$XDG_STATE_HOME` logic — that is the entire point of
freezing it. So a test pinning only `$SECREQ_HOME` leaves the legacy probe
aimed at the developer's **real** `~/.config/secreq`, and the migration
dutifully moves their live config into a tempdir that is deleted moments later.

Tests must pin in layers:

| Var | Why |
|---|---|
| `$SECREQ_HOME` | the new root |
| `$XDG_CONFIG_HOME`, `$XDG_STATE_HOME` | the migration's legacy probe |
| `$HOME` | backstop — every lookup above falls back to `dirs::home_dir()` |
| `$XDG_RUNTIME_DIR` | only where socket isolation is needed |

The XDG pins can go once migration 0001 is old enough to delete. `$HOME` should
stay: it is what makes a *forgotten* pin harmless rather than destructive.

### The pre-existing leak this uncovered

Unit tests never pinned anything, and production code reached transitively from
them (`daemon::log`, via `daemon::state` tests) writes files unconditionally.
That had been appending test output to the developer's real state dir for a long
time: `~/.local/state/secreq/daemon.log` was found at **473 MB**, `daemon.jsonl`
at 107 MB. This predates the migration work — moving to `~/.secreq` only
relocated the target.

Fixed by `paths::test_fallback_root`: under `#[cfg(test)]`, an unset
`$SECREQ_HOME` resolves to one `OnceLock<TempDir>` per test process instead of
the real home. This is test-only behavior in production code, normally worth
avoiding; the cleaner fix is injecting a sink into `daemon::log` and threading
it through the daemon, which is a much larger change. It is `#[cfg(test)]`, so
it compiles out of the shipped binary, and integration tests link the lib
without it and pin `$SECREQ_HOME` themselves (see
`tests/ssh_agent.rs::isolate_paths`).

Verified: two consecutive full-suite runs grow `~/.secreq/daemon.log` by
**0 bytes** and write **0** test-fixture lines.

## `src/migrate/`

### State file

`~/.secreq/.migration-state`:

```json
{ "migration_level": 1, "migrated_by": "0.1.0 (a1b2c3d4e5f6 +1750000000)" }
```

**Why not in `wraps.json5`**, as originally proposed:

- `wraps.json5` is dotfile-synced (chezmoi/stow/git). A synced
  `migration_level: 3` tells machine B it is already migrated when it is not,
  so machine B skips the migration it actually needs. Migration state is
  per-machine; config is portable.
- `wraps.rs:142-145` silently drops unknown `$`-prefixed keys and
  `write_config` (`commands.rs:2490`) regenerates from the parsed struct, so a
  `$migration_level` would be erased on the next write unless made a real
  field. A test at `wraps.rs:519` pins this drop behavior.
- Chicken-and-egg: migration 0001 *moves* `wraps.json5`.

`migrated_by` is `env!("CARGO_PKG_VERSION")` + `SECREQ_BUILD_ID` at **write**
time. It is display-only — see "Version ordering" below.

### Registry

Append-only, ids dense and 1-based, never reused.

```rust
struct Migration {
    id:   u32,
    name: &'static str,
    run:  fn(&Ctx) -> Result<()>,
}

const MIGRATIONS: &[Migration] = &[
    Migration { id: 1, name: "secreq-root", run: m0001::run },
];
```

There is no `LATEST` constant: it is `MIGRATIONS.len()`. Deriving it removes
the "appended a migration, forgot to bump LATEST" bug class, where the new
migration silently never runs.

### The gate

Called from `cli::run()` immediately after `Cli::parse()` — after, so `--help`
and `--version` exit inside `parse()` without touching disk.

```rust
pub fn run_pending() -> Result<()> {
    let level = read_level()? as usize;   // absent => 0

    if level > MIGRATIONS.len() {
        bail!(
            "{} records migration level {level}, but this secreq ships {}.\n\
             config was migrated by secreq {}.\n\
             a level-{} snapshot exists:\n    secreq migrate restore {}",
            state_path.display(), MIGRATIONS.len(), migrated_by,
            MIGRATIONS.len(), MIGRATIONS.len(),
        );
    }
    if level == MIGRATIONS.len() { return Ok(()); }   // fast path, no lock

    let _lock = acquire_migration_lock()?;            // flock <root>/.migration.lock
    let level = read_level()? as usize;               // re-read under lock
    if level >= MIGRATIONS.len() { return Ok(()); }

    for m in &MIGRATIONS[level..] {                   // ids dense & 1-based
        snapshot_if_absent(level)?;
        (m.run)(&ctx)
            .with_context(|| format!("migration {:04} ({}) failed", m.id, m.name))?;
        write_level(m.id)?;                           // stamp after EACH
    }
    Ok(())
}
```

Load-bearing details:

- **Downgrade check precedes the fast path.** `level >= MIGRATIONS.len()`
  as a fast path would swallow the downgrade case — an old binary would see
  `5 >= 3`, return `Ok(())`, and silently run against a config a newer secreq
  migrated. It is a `bail!` and not an `assert!` because a downgrade is a user
  action, not a programmer error.
- **The fast path skips the flock.** `secreq run` is in the hot path of every
  wrapped command, and the internal `Prompt` child (`cli.rs:134`) spawns per
  consent prompt. Once migrated the cost is one small read.
- **Double-check under the lock** prevents a thundering herd on first upgrade:
  many wraps see `level < len` at once, one migrates, the rest re-read and
  no-op. Mirrors the existing spawn-lock reasoning in `client.rs`.
- **Stamp after each migration**, so a failure at 3 keeps 1 and 2.
- **Missing state file = level 0**, so fresh installs run everything as no-ops
  and stamp. No fresh-install special case.

### Invariant test

The slice depends on density; pin it rather than assume it.

```rust
#[test]
fn migration_ids_are_dense_and_one_based() {
    for (i, m) in MIGRATIONS.iter().enumerate() {
        assert_eq!(m.id as usize, i + 1, "migration {} out of order", m.name);
    }
}
```

### Migrations are frozen history

**A migration must inline its own path logic and never call `paths::`.** If
`m0001` called `paths::secreq_root()` and that helper later changed, the
migration would retroactively mean something different for users who have not
run it yet. Same reason Django forbids importing live models into a migration.

## Migration 0001 — `secreq-root`

Legacy resolution is hardcoded inside `m0001` (`$XDG_CONFIG_HOME/secreq`, else
`~/.config/secreq`), as is the target.

Per config file (`wraps.json5`, `auto-rules.json5`):

```
new missing, old real file  -> copy(tmp+fsync+rename) -> remove old -> symlink old->new
new real,    old symlink    -> no-op (already migrated)
new real,    old missing    -> ensure symlink
new real,    old real       -> compare bytes:
                                 identical -> resume: remove old, symlink
                                 differ    -> ERROR, touch nothing
new missing, old missing    -> nothing (fresh install)
```

The both-real case is not a conflict by default — it is the expected state
after a crash between copy and remove, when both files exist and are
identical. Erroring there would wedge users on a retry that can never succeed.
Differing bytes means a real conflict (hand-created `~/.secreq/wraps.json5`)
and we refuse rather than pick a winner.

Crash-safety follows from the ordering: copy (old still truth) -> remove ->
symlink. A crash after remove leaves new-present/old-absent, recovered by row
three on the next run.

### `audit.log` uses `rename`, deliberately

On upgrade a **stale daemon from the previous binary is often still running**
with `audit.log` open for append — detecting exactly that is why `build.rs`
stamps `SECREQ_BUILD_ID` (`client.rs` restarts the daemon on mismatch). But
migration runs at the top of `cli::run()`, *before* that restart. With
`rename`, the old daemon's fd follows the inode and its writes continue landing
in `~/.secreq/audit.log`; no audit rows are lost across the handoff.
Copy-then-delete would silently drop every row that daemon wrote between the
copy and its restart.

`EXDEV` (if `~/.local` is a separate mount) is the rough edge: rename fails,
and the source cannot be safely deleted because that daemon may still be
writing to it. Fallback: copy, leave the old file, warn that entries may
remain at the old path.

`daemon.log`/`daemon.jsonl` are not migrated — transient, recreated at the new
path.

## Downgrades

### Version ordering is not available

`build.rs:35` emits `SECREQ_BUILD_ID` as `<git-short-sha>[-dirty] +<build-unix-seconds>`.
`CARGO_PKG_VERSION` is a separate string that only moves on release.

**Neither yields a reliable ordering.** The sha is unordered, `-dirty` is
unorderable by construction, and the timestamp is *build* time, not release
time — rebuilding an old tag produces a "newer" id. The id was designed for
equality ("same binary?"), which rarely doubles as comparison ("newer?").

Consequence: secreq can never honestly compute "install >= X". `migrated_by`
is displayed, never compared. This is what makes self-service restore the only
real answer rather than a convenience.

### Snapshots

Taken before each migration, keyed by pre-migration level: `snapshots/K/` *is*
the config at level K, so downgrading to K restores `snapshots/K/`.

```
~/.secreq/migration-snapshots/0/
  filemap.json
  wraps.json5
  auto-rules.json5
```

```json
{
  "created_by": "0.1.0 (a1b2c3d4e5f6 +1750000000)",
  "files": [
    { "snapshot": "wraps.json5",
      "restore_to": "/Users/x/.config/secreq/wraps.json5" }
  ]
}
```

- **`filemap.json`, not `.ini`** — the codebase is json5/serde throughout; an
  ini file adds a dependency and a second config format to maintain forever.
- **Absolute `restore_to` is safe** because snapshots are machine-local, by the
  same reasoning that keeps `.migration-state` out of `wraps.json5`.
- **Config files only, never `audit.log`** — it is append-only and unbounded;
  snapshotting it per migration would duplicate the whole audit history each
  time. Snapshots stay kilobytes.
- **Never overwrite an existing `snapshots/K/`.** If a migration fails partway
  and re-runs, re-snapshotting would capture the *partially migrated* state and
  destroy the true pre-state — turning the safety net into the thing that loses
  the config. First write wins.

### Why snapshots must be built now

A snapshot cannot be captured retroactively. Ship the format today and every
future binary understands it: a user on level 5 who installs a build shipping
only 3 migrations gets self-service restore from the *old* binary, with no
newer binary required — dissolving the chicken-and-egg of "run the downgrade
from the version you no longer have".

Gap: downgrading below the version that introduces snapshots is unsupported,
since 0.1.0 has never heard of them. One-time, unavoidable.

### `secreq migrate restore <level>`

Restore is **lossy and must say so**. If a user joins at level 3, migrates to
5, adds wraps and rules over weeks, then downgrades, a silent restore reverts
all of it — and the next `secreq run terraform` fails with nothing connecting
it to the restore. Saving the current state to a directory is not sufficient:
the live config still silently reverts and the user is left hand-reconciling
two files they did not know had diverged.

```
$ secreq migrate restore 3
warning: your current config has changed since the level-3 snapshot.
restoring will DISCARD these changes:

--- current wraps.json5
+++ snapshot level-3 wraps.json5
@@
-  terraform: { reason: "infra", env: [...] },
-  kubectl:   { reason: "k8s",   env: [...] },

  auto-rules.json5: 1 rule will be discarded (use --show-rules to view)

current config saved to ~/.secreq/migration-snapshots/current-2026-07-16T14:22:01/
continue? [y/N]
```

**Textual diff, not semantic.** A semantic diff (`+ wrap: terraform`) needs to
parse both the level-5 current file and the level-3 snapshot. The level-3
binary has never seen level-5's format — that is the premise of the downgrade —
and the level-5 binary does not retain level-3's parser. In the cross-format
case *neither* binary can produce one. It only works when the formats are
compatible, which is exactly the case that does not need the warning. A textual
unified diff (`similar`) always works and degrades gracefully.

### No reverse migrations

`Migration` has no `down` hook. Downgrade is snapshot-restore + diff + confirm.

Reverse functions would carry changes over losslessly in the compatible case,
but cost authoring burden on every migration and a second code path to test.
Snapshots are the part that cannot be retrofitted; a `down` hook can be added
per-migration later with zero rework to what is built here.

"Downgrade-compatible by construction" (additive fields over renames) is a good
norm where cheap, but is explicitly **not** relied upon: it is infeasible when
a field is structurally reshaped, and leaving dead config behind makes the file
hard to interpret when a field moves.

## Out of scope

- Reverse migration functions (`down`).
- Semantic (parsed) config diffing.
- A TUI diff viewer. The CLI diff + confirm covers the requirement; snapshots
  are on disk to build one from later.
- Rewriting `$shim_dir` in existing configs. If a user pointed it elsewhere,
  that is their choice; the default already resolves to `~/.secreq/shims`.
