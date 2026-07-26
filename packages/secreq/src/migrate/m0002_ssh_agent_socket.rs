//! Migration 0002 — `ssh-agent-socket`.
//!
//! Repoints the managed SSH-agent block at the socket's post-0001 home.
//!
//! Migration 0001 moved the socket dir out of `dirs::cache_dir()/secreq` and
//! under the `$SECREQ_HOME` root, but `secreq ssh setup` had already baked the
//! *old* absolute path into `~/.ssh/config` (`IdentityAgent`) and/or a shell rc
//! (`SSH_AUTH_SOCK`). Nothing rewrote those, so after 0001 every SSH client
//! pointed at a path no daemon listens on.
//!
//! It didn't fail at upgrade time, which is what makes it worth a migration
//! rather than a release note: the pre-upgrade daemon was usually still running
//! and still holding the old socket, so SSH kept working until that process
//! died. The breakage surfaced at the next reboot, disconnected from its cause.
//!
//! Only blocks naming the **legacy** socket are touched. A block pointing
//! anywhere else is either already correct or a deliberate choice, and this
//! migration is not the place to overrule it.
//!
//! Note this is a no-op wherever `$XDG_RUNTIME_DIR` is set: both the old and
//! new socket dirs prefer it, so the path never moved there. It is macOS (and
//! any bare login shell) that needs this.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::Ctx;
use crate::path_setup::{self, Shell};
use crate::paths;
use crate::ssh_setup::{self, Method};

/// Files a secreq SSH-agent block can live in. Frozen at the level-1 set:
/// `~/.ssh/config` plus one rc file per shell `ssh setup` knows how to write.
///
/// Every shell is probed rather than just `$SHELL`'s: migrations run from
/// whatever process happens to trigger them (including the daemon's re-exec of
/// `current_exe`), where `$SHELL` describes nobody in particular. Probing also
/// catches a block left in the rc of a shell the user has since moved off.
fn candidate_files(home: &Path) -> Vec<(Method, Shell, PathBuf)> {
    let mut out = vec![(Method::SshConfig, Shell::Zsh, home.join(".ssh/config"))];
    for shell in [Shell::Zsh, Shell::Bash, Shell::Fish, Shell::Posix] {
        if let Some(path) = path_setup::shell_config_path(home, &shell) {
            out.push((Method::ShellRc, shell, path));
        }
    }
    out
}

/// Only files that actually carry our block, so `migrate restore` can't revert
/// unrelated edits to a user's `.zshrc`. These are the user's own dotfiles, not
/// files secreq owns — capturing one we never intended to write would make a
/// later restore destructive well beyond this migration's blast radius.
pub fn snapshot_files(ctx: &Ctx) -> Vec<PathBuf> {
    let Some(home) = &ctx.home else {
        return Vec::new();
    };
    candidate_files(home)
        .into_iter()
        .map(|(_, _, path)| path)
        .filter(|path| ssh_setup::block_in_file(path).is_some())
        .collect()
}

/// **FROZEN.** How secreq resolved its socket dir before migration 0002
/// (mirrors the pre-0001 `daemon::server::socket_dir`). Describes history —
/// must never change, and must never be reached through [`crate::paths`],
/// which tracks *current* behavior.
///
/// Resolved by `run_pending` into [`Ctx::legacy_runtime_dir`] rather than
/// called from [`run`], so tests can substitute a tempdir.
pub(super) fn legacy_runtime_dir() -> Option<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_RUNTIME_DIR") {
        if !xdg.is_empty() {
            return Some(PathBuf::from(xdg).join("secreq"));
        }
    }
    dirs::cache_dir().map(|c| c.join("secreq"))
}

pub fn run(ctx: &Ctx) -> Result<()> {
    let (Some(home), Some(legacy_dir)) = (&ctx.home, &ctx.legacy_runtime_dir) else {
        return Ok(());
    };
    // Target tracks current behavior, but off the injected root — `paths`
    // would re-read `$SECREQ_HOME` and ignore the `Ctx` we were handed.
    let new_dir = paths::socket_dir_from(std::env::var_os("XDG_RUNTIME_DIR"), &ctx.root);
    run_in(home, legacy_dir, &new_dir)
}

/// The whole migration, with every location injected. [`run`] is a thin
/// resolver over this; **tests must call this**, never `run`, or they rewrite
/// the developer's real `~/.ssh/config`.
fn run_in(home: &Path, legacy_dir: &Path, new_dir: &Path) -> Result<()> {
    // Nothing moved (a set `$XDG_RUNTIME_DIR` resolves both the same way), so
    // there is no stale path to repoint and nothing safe to clean — the
    // "legacy" sockets are the live ones.
    if legacy_dir == new_dir {
        return Ok(());
    }

    let legacy_sock = legacy_dir.join("agent.sock");
    let new_sock = new_dir.join("agent.sock");
    let legacy_needle = legacy_sock.display().to_string();

    // Files carrying a block whose socket path we could not resolve. Deleting
    // the legacy socket dir while one of those is still on disk is the M4
    // failure: we skipped a block we could not read, then removed the very
    // socket it may name.
    let mut unresolved: Vec<PathBuf> = Vec::new();

    for (method, shell, path) in candidate_files(home) {
        let Some(existing) = ssh_setup::block_in_file(&path) else {
            continue;
        };
        // Compare by the path the block *means*, not the way it spells it.
        // `ssh setup` writes the socket as `~/…` (ssh config) or `$HOME/…`
        // (shell rc) whenever it sits under the user's home — which on macOS
        // is exactly where the legacy socket lives, `dirs::cache_dir()` being
        // `~/Library/Caches`. A raw substring match against the absolute path
        // therefore missed every block this migration was written for, on the
        // one platform that needs it. `ssh_setup::block_state` has always
        // compared this way; the migration was the odd one out.
        let expanded = ssh_setup::expand_home_tokens(&existing, home);
        // Someone else's socket, or already ours. Not our business.
        if !expanded.contains(&legacy_needle) {
            if carries_an_unexpanded_home_token(&expanded) {
                unresolved.push(path);
            }
            continue;
        }
        // Rebuild through `plan` so the block is byte-identical to what
        // `ssh setup` would write today — one block format, one source.
        let plan = ssh_setup::plan(home, method, shell, &new_sock)
            .with_context(|| format!("building the SSH-agent block for {}", path.display()))?;
        ssh_setup::rewrite_in_place(&plan.config_file, &plan.block)
            .with_context(|| format!("repointing the SSH-agent block in {}", path.display()))?;
        eprintln!(
            "secreq: repointed the SSH-agent block in {} at {}.",
            path.display(),
            new_sock.display(),
        );
    }

    if !unresolved.is_empty() {
        for path in &unresolved {
            eprintln!(
                "secreq: the SSH-agent block in {} names a socket path secreq \
                 could not resolve, so it was left alone — and the pre-upgrade \
                 socket directory {} was kept in case that block still names it.",
                path.display(),
                legacy_dir.display(),
            );
        }
        return Ok(());
    }

    clean_legacy_runtime_dir(legacy_dir);
    Ok(())
}

/// Did home-expansion leave a token behind? Then this block names a path we
/// cannot compare against anything — we do not know whether it is the legacy
/// socket, and "I do not know" is not "no".
///
/// `ssh setup` only ever writes the quoted forms [`ssh_setup::expand_home_tokens`]
/// understands, so this catches a hand-edit (an unquoted `~/…`, a `${HOME}/…`)
/// rather than anything secreq produced.
fn carries_an_unexpanded_home_token(expanded_block: &str) -> bool {
    expanded_block.contains("~/") || expanded_block.contains("$HOME")
}

/// The files the pre-0001 daemon left in its socket dir. Frozen: this is the
/// set as it existed at level 1.
const LEGACY_RUNTIME_FILES: &[&str] = &[
    "agent.sock",
    "consent.sock",
    "daemon.pid",
    "daemon.spawn.lock",
];

/// Remove the abandoned socket dir, by name and only the names we put there.
///
/// **Only reached once every managed block on the machine is accounted for** —
/// see the `unresolved` gate in [`run_in`]. Removing the socket a block still
/// names is strictly worse than leaving it: the block was skipped precisely
/// because we could not read it, so we would be deleting the one path we know
/// something might be pointing at.
///
/// A dead socket is worse than a missing one: `connect()` on it fails with
/// `ECONNREFUSED`, so anything still holding the old path gets "Connection
/// refused" — which reads as "the agent is broken" rather than "this path is
/// wrong". Deleting it turns a misleading error into an honest one.
///
/// Never `remove_dir_all`: this path is derived from `$XDG_RUNTIME_DIR` or
/// `dirs::cache_dir()`, and a recursive delete against a value someone else
/// controls is not a thing to write. Unlinking four known names can only ever
/// remove four known things, and the `rmdir` is allowed to fail — a dir with
/// anything else in it simply stays.
///
/// Best-effort throughout: this is tidy-up. Failing the migration (and with it
/// every secreq command, per the `cli::run` gate) over a leftover socket would
/// be a far worse outcome than the leftover.
fn clean_legacy_runtime_dir(dir: &Path) {
    if !dir.is_dir() {
        return;
    }
    for name in LEGACY_RUNTIME_FILES {
        let path = dir.join(name);
        if path.symlink_metadata().is_ok() {
            let _ = std::fs::remove_file(&path);
        }
    }
    // Fails while anything remains, which is the intent.
    let _ = std::fs::remove_dir(dir);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    struct Sandbox {
        _tmp: TempDir,
        home: PathBuf,
        legacy_dir: PathBuf,
        new_dir: PathBuf,
    }

    /// Every path lives under one tempdir. Nothing here reads `$HOME`,
    /// `$XDG_RUNTIME_DIR`, or `dirs::cache_dir()`.
    fn sandbox() -> Sandbox {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path().join("home");
        let legacy_dir = tmp.path().join("Caches/secreq");
        let new_dir = home.join(".secreq/run");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&legacy_dir).unwrap();
        Sandbox {
            _tmp: tmp,
            home,
            legacy_dir,
            new_dir,
        }
    }

    /// The shape a real macOS install has: `dirs::cache_dir()` is
    /// `~/Library/Caches`, so the legacy socket sits **under `$HOME`** — and
    /// `ssh setup` therefore spelled it with a `~` rather than absolutely.
    /// [`sandbox`] deliberately puts it outside home, which is the Linux
    /// (`$XDG_RUNTIME_DIR`-unset) shape and the one spelling a raw substring
    /// match happens to catch.
    fn sandbox_with_legacy_under_home() -> Sandbox {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path().join("home");
        let legacy_dir = home.join("Library/Caches/secreq");
        let new_dir = home.join(".secreq/run");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&legacy_dir).unwrap();
        Sandbox {
            _tmp: tmp,
            home,
            legacy_dir,
            new_dir,
        }
    }

    /// Wire up a block pointing at the legacy socket, the way a pre-0001
    /// `ssh setup` left it.
    fn wire_legacy(sb: &Sandbox, method: Method, shell: Shell) -> PathBuf {
        let legacy_sock = sb.legacy_dir.join("agent.sock");
        let plan = ssh_setup::plan(&sb.home, method, shell, &legacy_sock).unwrap();
        ssh_setup::apply(&plan).unwrap();
        plan.config_file
    }

    #[test]
    fn repoints_ssh_config_at_the_new_socket() {
        let sb = sandbox();
        let config = wire_legacy(&sb, Method::SshConfig, Shell::Zsh);

        run_in(&sb.home, &sb.legacy_dir, &sb.new_dir).unwrap();

        // The migration regenerates the block through `ssh_setup::plan`, so
        // it carries whatever spelling that writes today (`~`). Assert on the
        // socket it resolves to rather than the literal text.
        let content = std::fs::read_to_string(&config).unwrap();
        assert!(
            ssh_setup::expand_home_tokens(&content, &sb.home).contains(&format!(
                "IdentityAgent \"{}\"",
                sb.new_dir.join("agent.sock").display()
            ))
        );
        assert!(
            !content.contains(&sb.legacy_dir.join("agent.sock").display().to_string()),
            "stale path must be gone:\n{content}"
        );
    }

    /// The macOS case, which is the only platform this migration exists for.
    /// `ssh setup` wrote `IdentityAgent "~/Library/Caches/secreq/agent.sock"`;
    /// a raw substring match against the absolute path never sees it, so the
    /// block is skipped and the user's SSH stays pointed at a socket no daemon
    /// listens on.
    #[test]
    fn repoints_a_block_that_spells_the_legacy_socket_with_a_tilde() {
        let sb = sandbox_with_legacy_under_home();
        let config = wire_legacy(&sb, Method::SshConfig, Shell::Zsh);
        assert!(
            std::fs::read_to_string(&config)
                .unwrap()
                .contains("\"~/Library/Caches/secreq/agent.sock\""),
            "the fixture must reproduce the tilde spelling, or it proves nothing"
        );

        run_in(&sb.home, &sb.legacy_dir, &sb.new_dir).unwrap();

        let content = std::fs::read_to_string(&config).unwrap();
        assert!(
            ssh_setup::expand_home_tokens(&content, &sb.home).contains(&format!(
                "IdentityAgent \"{}\"",
                sb.new_dir.join("agent.sock").display()
            )),
            "block still names the legacy socket:\n{content}"
        );
    }

    /// Same spelling, the shell-rc half: `export SSH_AUTH_SOCK="$HOME/…"`.
    #[test]
    fn repoints_an_rc_block_that_spells_the_legacy_socket_with_a_home_var() {
        let sb = sandbox_with_legacy_under_home();
        let zshrc = wire_legacy(&sb, Method::ShellRc, Shell::Zsh);
        assert!(std::fs::read_to_string(&zshrc)
            .unwrap()
            .contains("\"$HOME/Library/Caches/secreq/agent.sock\""));

        run_in(&sb.home, &sb.legacy_dir, &sb.new_dir).unwrap();

        let content = std::fs::read_to_string(&zshrc).unwrap();
        assert!(
            ssh_setup::expand_home_tokens(&content, &sb.home).contains(&format!(
                r#"export SSH_AUTH_SOCK="{}""#,
                sb.new_dir.join("agent.sock").display()
            )),
            "rc still names the legacy socket:\n{content}"
        );
    }

    #[test]
    fn repoints_every_rc_that_carries_a_block() {
        let sb = sandbox();
        let zshrc = wire_legacy(&sb, Method::ShellRc, Shell::Zsh);
        let bashrc = wire_legacy(&sb, Method::ShellRc, Shell::Bash);

        run_in(&sb.home, &sb.legacy_dir, &sb.new_dir).unwrap();

        let want = sb.new_dir.join("agent.sock").display().to_string();
        for rc in [&zshrc, &bashrc] {
            let content = std::fs::read_to_string(rc).unwrap();
            assert!(
                ssh_setup::expand_home_tokens(&content, &sb.home).contains(&want),
                "{} not repointed:\n{content}",
                rc.display()
            );
        }
    }

    #[test]
    fn is_idempotent_across_repeated_runs() {
        let sb = sandbox();
        let config = wire_legacy(&sb, Method::SshConfig, Shell::Zsh);

        run_in(&sb.home, &sb.legacy_dir, &sb.new_dir).unwrap();
        let after_first = std::fs::read_to_string(&config).unwrap();
        run_in(&sb.home, &sb.legacy_dir, &sb.new_dir).unwrap();
        run_in(&sb.home, &sb.legacy_dir, &sb.new_dir).unwrap();
        let after_third = std::fs::read_to_string(&config).unwrap();

        assert_eq!(after_first, after_third);
        assert_eq!(after_third.matches(ssh_setup::BEGIN_SENTINEL).count(), 1);
    }

    #[test]
    fn leaves_a_block_pointing_somewhere_else_alone() {
        let sb = sandbox();
        let elsewhere = sb.home.join("custom/agent.sock");
        let plan = ssh_setup::plan(&sb.home, Method::SshConfig, Shell::Zsh, &elsewhere).unwrap();
        ssh_setup::apply(&plan).unwrap();
        let before = std::fs::read_to_string(&plan.config_file).unwrap();

        run_in(&sb.home, &sb.legacy_dir, &sb.new_dir).unwrap();

        assert_eq!(
            std::fs::read_to_string(&plan.config_file).unwrap(),
            before,
            "a non-legacy socket is a deliberate choice"
        );
    }

    #[test]
    fn fresh_install_with_no_blocks_is_a_no_op() {
        let sb = sandbox();
        std::fs::write(sb.home.join(".zshrc"), "# just my rc\n").unwrap();

        run_in(&sb.home, &sb.legacy_dir, &sb.new_dir).unwrap();

        assert_eq!(
            std::fs::read_to_string(sb.home.join(".zshrc")).unwrap(),
            "# just my rc\n"
        );
        assert!(
            !sb.home.join(".ssh/config").exists(),
            "must not create files"
        );
    }

    #[test]
    fn unrelated_rc_content_survives() {
        let sb = sandbox();
        let zshrc = sb.home.join(".zshrc");
        std::fs::write(&zshrc, "export EDITOR=vim\nalias ll='ls -la'\n").unwrap();
        wire_legacy(&sb, Method::ShellRc, Shell::Zsh);

        run_in(&sb.home, &sb.legacy_dir, &sb.new_dir).unwrap();

        let content = std::fs::read_to_string(&zshrc).unwrap();
        assert!(content.contains("export EDITOR=vim"));
        assert!(content.contains("alias ll='ls -la'"));
    }

    #[test]
    fn removes_the_stale_socket_dir() {
        let sb = sandbox();
        wire_legacy(&sb, Method::SshConfig, Shell::Zsh);
        std::fs::write(sb.legacy_dir.join("agent.sock"), "").unwrap();
        std::fs::write(sb.legacy_dir.join("daemon.pid"), "123").unwrap();

        run_in(&sb.home, &sb.legacy_dir, &sb.new_dir).unwrap();

        assert!(
            !sb.legacy_dir.exists(),
            "a dead socket answers connect() with ECONNREFUSED; it must go"
        );
    }

    /// Hand-write a managed block whose socket path we cannot resolve. An
    /// unquoted `~` is the realistic way to get one — ssh accepts it, `ssh
    /// setup` never writes it, and `expand_home_tokens` deliberately only
    /// expands the quoted form.
    fn wire_unresolvable_block(sb: &Sandbox) -> PathBuf {
        let ssh_dir = sb.home.join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        let config = ssh_dir.join("config");
        std::fs::write(
            &config,
            format!(
                "{}\nHost *\n    IdentityAgent ~/Library/Caches/secreq/agent.sock\n{}\n",
                ssh_setup::BEGIN_SENTINEL,
                ssh_setup::END_SENTINEL,
            ),
        )
        .unwrap();
        config
    }

    /// The M4 shape. A block we could not read as naming the legacy socket was
    /// skipped — and then the cleanup deleted the socket that block may well
    /// still name, turning "this path is wrong" into `ECONNREFUSED`, which
    /// reads as "the agent is broken". Cleanup has to be earned.
    #[test]
    fn a_block_we_cannot_resolve_spares_the_legacy_socket_dir() {
        let sb = sandbox_with_legacy_under_home();
        wire_unresolvable_block(&sb);
        std::fs::write(sb.legacy_dir.join("agent.sock"), "").unwrap();
        std::fs::write(sb.legacy_dir.join("daemon.pid"), "123").unwrap();

        run_in(&sb.home, &sb.legacy_dir, &sb.new_dir).unwrap();

        assert!(
            sb.legacy_dir.join("agent.sock").exists(),
            "a socket a surviving block may still name must not be removed"
        );
        assert!(sb.legacy_dir.exists());
    }

    /// The other side of that gate: a block naming a socket we *did* resolve,
    /// which simply is not ours, is accounted for. It stays untouched and it
    /// does not hold the stale directory hostage.
    #[test]
    fn a_resolvable_foreign_block_still_allows_cleanup() {
        let sb = sandbox_with_legacy_under_home();
        let elsewhere = sb.home.join("custom/agent.sock");
        let plan = ssh_setup::plan(&sb.home, Method::SshConfig, Shell::Zsh, &elsewhere).unwrap();
        ssh_setup::apply(&plan).unwrap();
        let before = std::fs::read_to_string(&plan.config_file).unwrap();
        std::fs::write(sb.legacy_dir.join("agent.sock"), "").unwrap();

        run_in(&sb.home, &sb.legacy_dir, &sb.new_dir).unwrap();

        assert_eq!(std::fs::read_to_string(&plan.config_file).unwrap(), before);
        assert!(
            !sb.legacy_dir.exists(),
            "nothing points at the legacy socket, so the dead socket goes"
        );
    }

    #[test]
    fn leaves_unknown_files_and_their_dir_in_place() {
        let sb = sandbox();
        std::fs::write(sb.legacy_dir.join("agent.sock"), "").unwrap();
        std::fs::write(sb.legacy_dir.join("something-else"), "not ours").unwrap();

        run_in(&sb.home, &sb.legacy_dir, &sb.new_dir).unwrap();

        assert!(!sb.legacy_dir.join("agent.sock").exists(), "ours goes");
        assert!(
            sb.legacy_dir.join("something-else").exists(),
            "we only ever remove names we wrote"
        );
        assert!(sb.legacy_dir.exists(), "dir stays while anything remains");
    }

    /// `$XDG_RUNTIME_DIR` is honoured by both the old and new socket_dir, so
    /// the path never moved — and the "legacy" sockets are the *live* ones.
    #[test]
    fn same_dir_means_no_op_and_no_cleanup() {
        let sb = sandbox();
        let config = wire_legacy(&sb, Method::SshConfig, Shell::Zsh);
        let before = std::fs::read_to_string(&config).unwrap();
        std::fs::write(sb.legacy_dir.join("agent.sock"), "").unwrap();

        run_in(&sb.home, &sb.legacy_dir, &sb.legacy_dir).unwrap();

        assert_eq!(std::fs::read_to_string(&config).unwrap(), before);
        assert!(
            sb.legacy_dir.join("agent.sock").exists(),
            "deleting the live socket would break the running agent"
        );
    }

    #[test]
    fn no_home_means_nothing_to_do() {
        let tmp = TempDir::new().unwrap();
        let ctx = Ctx {
            root: tmp.path().join("secreq"),
            home: None,
            legacy_config_dir: None,
            legacy_state_dir: None,
            legacy_runtime_dir: None,
        };
        run(&ctx).unwrap();
        assert!(snapshot_files(&ctx).is_empty());
    }

    #[test]
    fn snapshot_captures_only_files_carrying_our_block() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        // An rc with no secreq block — restoring it later would be collateral.
        std::fs::write(home.join(".bashrc"), "# untouched\n").unwrap();
        let sock = tmp.path().join("Caches/secreq/agent.sock");
        let plan = ssh_setup::plan(&home, Method::ShellRc, Shell::Zsh, &sock).unwrap();
        ssh_setup::apply(&plan).unwrap();

        let ctx = Ctx {
            root: tmp.path().join("secreq"),
            home: Some(home.clone()),
            legacy_config_dir: None,
            legacy_state_dir: None,
            legacy_runtime_dir: None,
        };

        let files = snapshot_files(&ctx);
        assert_eq!(files, vec![home.join(".zshrc")]);
    }
}
