//! SSH-agent wiring for `secreq ssh setup` (and `init`).
//!
//! Points SSH clients at secreq's agent socket by writing a
//! sentinel-bracketed managed block to a config file. Two methods, chosen
//! by the user:
//!
//! - **`Method::SshConfig`** → `~/.ssh/config`, a `Host * / IdentityAgent`
//!   stanza. ssh applies the **first** `IdentityAgent` it obtains for a
//!   host, so we **prepend** our block above any existing content. We also
//!   keep `~/.ssh` `0700` and `~/.ssh/config` `0600` — ssh refuses to use a
//!   group/world-writable config.
//! - **`Method::ShellRc`** → the shell rc file (reusing
//!   [`crate::path_setup`]'s per-shell file choice), exporting
//!   `SSH_AUTH_SOCK`. Appended like the PATH block.
//!
//! Mirrors [`crate::path_setup`]'s pure `plan()`/`apply()` +
//! sentinel-bracketed managed-block + `home`-injectable design, plus a
//! [`remove`] that strips the block for `--undo`.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::path_setup::{self, Shell};

/// Sentinel marking the start of our managed SSH-agent block. Distinct from
/// the PATH sentinels so the two managed blocks never collide in a file that
/// happens to host both.
pub const BEGIN_SENTINEL: &str = "# >>> secreq managed SSH agent (do not edit by hand) >>>";
/// Sentinel marking the end of our managed SSH-agent block.
pub const END_SENTINEL: &str = "# <<< secreq managed SSH agent <<<";

/// Which config file we wire the agent into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// `~/.ssh/config` with a `Host * / IdentityAgent` stanza (prepended).
    SshConfig,
    /// The shell rc file with an `SSH_AUTH_SOCK` export (appended).
    ShellRc,
}

/// What [`apply`] will do — handed back to the caller so the user gets to
/// see and approve it before any file is touched. Mirrors
/// [`crate::path_setup::Plan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshSetupPlan {
    /// Which method this plan wires.
    pub method: Method,
    /// Path to the config file we'll write (created if absent).
    pub config_file: PathBuf,
    /// Full block including sentinels. Show this to the user.
    pub block: String,
    /// True if the file already carries **exactly** this block — [`apply`]
    /// will be a no-op.
    ///
    /// Deliberately content equality, not sentinel presence. Presence-only
    /// would make the block write-once: the socket path is baked into it, so
    /// when that path moves (as it did in migration 0001) every existing
    /// install reports "already configured" and re-running setup silently
    /// changes nothing, leaving SSH pointed at a socket no daemon listens on.
    pub already_configured: bool,
    /// True if a block is present but differs from [`block`](Self::block) —
    /// [`apply`] will rewrite it in place rather than add a new one. Lets the
    /// caller say "updating" instead of "writing".
    pub updates_existing: bool,
    /// Optional one-liner caveat about this method/shell's behavior.
    pub caveat: Option<String>,
}

/// Build the plan: which config file, what block, and whether the file
/// already carries our sentinel. Pure (no filesystem writes); use [`apply`]
/// to write. `home` lets tests stand in a temp dir for `$HOME`.
///
/// `agent_sock` is the agent socket path the block should point at. The
/// pure module never derives it (production callers pass
/// [`crate::daemon::ssh_agent::default_agent_socket_path`]) so tests can
/// inject one.
pub fn plan(home: &Path, method: Method, shell: Shell, agent_sock: &Path) -> Result<SshSetupPlan> {
    match method {
        Method::SshConfig => {
            let config_file = home.join(".ssh/config");
            let block = ssh_config_block(agent_sock, home);
            let (already_configured, updates_existing) = block_state(&config_file, &block, home);
            Ok(SshSetupPlan {
                method,
                config_file,
                block,
                already_configured,
                updates_existing,
                // ssh applies the FIRST IdentityAgent it obtains for a host;
                // we prepend so ours wins over anything already in the file.
                caveat: Some(
                    "ssh uses the first IdentityAgent it finds for a host, which is why \
                     this block is prepended above your existing ~/.ssh/config."
                        .to_owned(),
                ),
            })
        }
        Method::ShellRc => {
            let config_file = path_setup::shell_config_path(home, &shell).with_context(|| {
                format!(
                    "unrecognized shell {shell:?}; please set SSH_AUTH_SOCK to {} manually",
                    agent_sock.display()
                )
            })?;
            let block = shell_rc_block(&shell, agent_sock, home);
            let (already_configured, updates_existing) = block_state(&config_file, &block, home);
            Ok(SshSetupPlan {
                method,
                config_file,
                block,
                already_configured,
                updates_existing,
                caveat: path_setup::caveat_for(&shell),
            })
        }
    }
}

/// Classify `config_file` against the block we want: `(already_configured,
/// updates_existing)`. A missing/unreadable file is neither.
fn block_state(config_file: &Path, want: &str, home: &Path) -> (bool, bool) {
    let Ok(content) = fs::read_to_string(config_file) else {
        return (false, false);
    };
    match existing_block(&content) {
        Some(found) if expand_home_tokens(&found, home) == expand_home_tokens(want, home) => {
            (true, false)
        }
        Some(_) => (false, true),
        None => (false, false),
    }
}

/// Compare blocks by the path they *mean*, not the way they spell it.
///
/// The block we write now uses `$HOME` / `~`, but a config written by an
/// earlier secreq spells the same socket absolutely. Comparing literally
/// would tell every one of those users their block "points at a different
/// socket than the agent now uses" and offer to rewrite something already
/// correct — a spurious prompt, and a false statement.
///
/// Expanding (rather than abbreviating) is the safer direction: it needs no
/// path-boundary rule and leaves a socket outside `$HOME` untouched.
pub(crate) fn expand_home_tokens(block: &str, home: &Path) -> String {
    let home = home.display().to_string();
    let home = home.trim_end_matches('/');
    block
        .replace("$HOME/", &format!("{home}/"))
        .replace("\"~/", &format!("\"{home}/"))
}

/// Apply the plan. Idempotent — if the file already carries exactly this
/// block, returns `Ok(false)` without touching it. Returns `Ok(true)` if we
/// wrote something.
///
/// Three cases: no block → add one (`SshConfig` **prepends**, since ssh uses
/// the first `IdentityAgent`; `ShellRc` **appends** like the PATH block); a
/// block that differs → rewrite it **in place**, preserving its position; an
/// identical block → no-op.
pub fn apply(plan: &SshSetupPlan) -> Result<bool> {
    if plan.already_configured {
        return Ok(false);
    }
    if plan.updates_existing {
        // `apply`'s own answer is "did a file change?", so both of
        // [`Rewrote`]'s outcomes map onto it honestly. The block going missing
        // between `plan` and here needs a live file racing an interactive
        // confirm; the migration, which has no user to re-run it, treats the
        // same answer as `Outcome::Incomplete`.
        let rewrote = rewrite_in_place(&plan.config_file, &plan.block)?;
        return Ok(rewrote == Rewrote::TheBlock);
    }
    match plan.method {
        Method::SshConfig => apply_ssh_config(plan),
        Method::ShellRc => apply_shell_rc(plan),
    }
}

/// What [`rewrite_in_place`] did — a type rather than a `bool`, so that not
/// looking at it is a compile error.
///
/// [`Rewrote::Nothing`] is a **real outcome a caller has to handle**, not a
/// nothing-happened. A caller reaches `rewrite_in_place` because it has
/// already read a managed block out of that file and decided it must change;
/// `Nothing` says the block was not there when the write came round, so the
/// file still carries whatever the caller wanted replaced. Migration 0002
/// discarded exactly this answer — `rewrite_in_place(..).with_context(..)?;` —
/// and stamped its migration level over a config still naming the
/// pre-upgrade socket. A stamped level is permanent, so the user never got
/// the migration again.
///
/// **`#[must_use]` on the function would not have caught that**, which is why
/// this is a type. `?` counts as a use of the call's `Result`, so the `bool`
/// that fell out the other side was an expression statement of an ordinary
/// type and the lint stayed quiet. On the type, the discard is the error.
#[must_use = "`Rewrote::Nothing` means the managed block was not there to \
              replace — that is an outcome to handle, not a success"]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rewrote {
    /// The block was found and `config_file` now carries `new_block`.
    TheBlock,
    /// Nothing was written: the file is absent or unreadable, it carries no
    /// managed block, or the block it carries is already byte-identical to
    /// `new_block`.
    Nothing,
}

/// Swap the managed block in `config_file` for `new_block`, leaving the rest
/// of the file byte-identical. See [`Rewrote`] for what the two answers mean
/// and why they are not a `bool`.
///
/// Shared by [`apply`] and migration 0002 — the migration repoints blocks on
/// installs whose owner will never re-run `ssh setup`, and must reach the
/// exact same result.
pub(crate) fn rewrite_in_place(config_file: &Path, new_block: &str) -> Result<Rewrote> {
    let Ok(content) = fs::read_to_string(config_file) else {
        return Ok(Rewrote::Nothing);
    };
    let Some(updated) = replace_block(&content, new_block) else {
        return Ok(Rewrote::Nothing);
    };
    if updated == content {
        return Ok(Rewrote::Nothing);
    }
    // Staged and renamed, not written in place. These are the user's own
    // dotfiles and we are rewriting them from a migration, where nobody asked
    // for the edit and nobody is watching it: a `fs::write` that dies after
    // truncating leaves a `~/.zshrc` that is a broken login shell, and — worse
    // for a migration — one the retry then reads as carrying no managed block,
    // so it reports success and stamps the level over the damage.
    //
    // `Mode::Like(config_file)` keeps the file's own mode across the new inode:
    // ~/.ssh/config must stay 0600 or ssh refuses it.
    crate::atomic::replace(
        config_file,
        updated.as_bytes(),
        crate::atomic::Mode::Like(config_file),
    )
    .with_context(|| format!("could not write {}", config_file.display()))?;
    Ok(Rewrote::TheBlock)
}

/// The managed block in `config_file`, sentinels included. `None` if the file
/// is absent, unreadable, or carries no block. Used by migration 0002 to ask
/// "does this block name the old socket?" before touching it.
pub(crate) fn block_in_file(config_file: &Path) -> Option<String> {
    existing_block(&fs::read_to_string(config_file).ok()?)
}

fn apply_ssh_config(plan: &SshSetupPlan) -> Result<bool> {
    // Ensure ~/.ssh exists with 0700 — ssh refuses a group/world-accessible
    // config dir. `create_dir_all` followed by a chmod left it at the umask's
    // answer (0777 under the `umask 000` CI images set) for the stretch in
    // between; `ensure_private_dir` asks for 0700 on the creating call and
    // narrows an existing directory, which is the pair this needs.
    if let Some(parent) = plan.config_file.parent() {
        crate::paths::ensure_private_dir(parent)
            .with_context(|| format!("could not make {} owner-only", parent.display()))?;
    }
    // Prepend the block above existing content: ssh applies the first
    // IdentityAgent it obtains for a host, so ours must come first.
    let existing = fs::read_to_string(&plan.config_file).unwrap_or_default();
    let to_write = if existing.is_empty() {
        format!("{}\n", plan.block)
    } else {
        format!("{}\n\n{existing}", plan.block)
    };
    // `Mode::Exactly`, the one place in this module that forces a mode: ssh
    // refuses a group- or world-readable config outright, so the *reader*
    // dictates it and a file the user left at 0644 is one ssh will ignore.
    // Writing at 0600 also retires the old write-then-chmod pair, which
    // published the file at `0666 & !umask` until the chmod landed.
    crate::atomic::replace(
        &plan.config_file,
        to_write.as_bytes(),
        crate::atomic::Mode::Exactly(0o600),
    )
    .with_context(|| format!("could not write {}", plan.config_file.display()))?;
    Ok(true)
}

fn apply_shell_rc(plan: &SshSetupPlan) -> Result<bool> {
    if let Some(parent) = plan.config_file.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("could not create {}", parent.display()))?;
    }
    // Append with a leading newline if the file exists and doesn't end with
    // one — keeps us from gluing onto a previous line (mirrors path_setup).
    let existing = fs::read_to_string(&plan.config_file).unwrap_or_default();
    let needs_leading_newline = !existing.is_empty() && !existing.ends_with('\n');
    let prefix = if needs_leading_newline { "\n" } else { "" };
    let to_write = format!("{existing}{prefix}{}\n", plan.block);
    // `Mode::Like`, not `Exactly`: this is the user's own `.zshrc`, and
    // `path_setup::apply` — which writes the *same file* — reached the same
    // answer. It preserves a mode they chose and falls back to 0600 for a file
    // we are creating, which is both halves in one expression.
    crate::atomic::replace(
        &plan.config_file,
        to_write.as_bytes(),
        crate::atomic::Mode::Like(&plan.config_file),
    )
    .with_context(|| format!("could not write {}", plan.config_file.display()))?;
    Ok(true)
}

/// Remove our sentinel-bracketed block from the method's target file. Strips
/// the begin..=end lines inclusive, plus a single blank line if one
/// immediately follows. Returns `Ok(false)` if the file is absent or has no
/// block; the rest of the file is preserved verbatim.
pub fn remove(home: &Path, method: Method, shell: Shell) -> Result<bool> {
    let config_file = match method {
        Method::SshConfig => home.join(".ssh/config"),
        Method::ShellRc => match path_setup::shell_config_path(home, &shell) {
            Some(path) => path,
            // No file to write to for an unknown shell — nothing to remove.
            None => return Ok(false),
        },
    };
    // File absent → nothing to remove.
    let Ok(existing) = fs::read_to_string(&config_file) else {
        return Ok(false);
    };
    let Some(stripped) = strip_block(&existing) else {
        return Ok(false);
    };
    // `Mode::Like`: `--undo` is putting the file back the way it was, so it is
    // the one write here that should decide nothing about the mode. The file
    // necessarily exists — we just read it — so the fallback never applies.
    crate::atomic::replace(
        &config_file,
        stripped.as_bytes(),
        crate::atomic::Mode::Like(&config_file),
    )
    .with_context(|| format!("could not write {}", config_file.display()))?;
    Ok(true)
}

/// Line indices of the begin/end sentinels in `content`, inclusive. `None` if
/// either is absent. The single source of truth for locating our block —
/// [`strip_block`], [`replace_block`], and [`existing_block`] all agree by
/// construction because they share it.
fn block_bounds(content: &str) -> Option<(usize, usize)> {
    let lines: Vec<&str> = content.lines().collect();
    let begin = lines.iter().position(|l| l.contains(BEGIN_SENTINEL))?;
    let end = lines
        .iter()
        .skip(begin)
        .position(|l| l.contains(END_SENTINEL))
        .map(|offset| begin + offset)?;
    Some((begin, end))
}

/// The managed block currently in `content`, sentinels included, or `None` if
/// there isn't one. Used to compare what's on disk against what we'd write —
/// see [`plan`]'s `already_configured`.
fn existing_block(content: &str) -> Option<String> {
    let (begin, end) = block_bounds(content)?;
    let lines: Vec<&str> = content.lines().collect();
    Some(lines[begin..=end].join("\n"))
}

/// Strip the sentinel-bracketed block from `content`. Returns `None` if no
/// block is present, else the remainder with the begin..=end lines removed
/// (plus one trailing blank line if it immediately follows the end line).
fn strip_block(content: &str) -> Option<String> {
    let (begin, end) = block_bounds(content)?;
    let lines: Vec<&str> = content.lines().collect();
    // Drop begin..=end, plus a single blank line right after the end line.
    let mut after = end + 1;
    if lines.get(after).is_some_and(|l| l.trim().is_empty()) {
        after += 1;
    }
    let kept: Vec<&str> = lines[..begin]
        .iter()
        .chain(lines[after..].iter())
        .copied()
        .collect();
    let mut result = kept.join("\n");
    // `str::lines` drops a trailing newline; restore one if there's content
    // and the original ended with a newline, so we don't strip the file's
    // final newline as a side effect.
    if !result.is_empty() && content.ends_with('\n') {
        result.push('\n');
    }
    Some(result)
}

/// Swap the managed block in `content` for `new_block`, **in place**. Returns
/// `None` if there's no block to replace.
///
/// In place, not strip-and-re-add: the block's position is the user's (or a
/// previous `apply`'s) and carries meaning we must not silently change. For
/// `~/.ssh/config` that position decides whether our `IdentityAgent` wins,
/// since ssh takes the first one it obtains for a host.
fn replace_block(content: &str, new_block: &str) -> Option<String> {
    let (begin, end) = block_bounds(content)?;
    let lines: Vec<&str> = content.lines().collect();
    let new_lines: Vec<&str> = new_block.lines().collect();
    let kept: Vec<&str> = lines[..begin]
        .iter()
        .chain(new_lines.iter())
        .chain(lines[end + 1..].iter())
        .copied()
        .collect();
    let mut result = kept.join("\n");
    if !result.is_empty() && content.ends_with('\n') {
        result.push('\n');
    }
    Some(result)
}

fn ssh_config_block(agent_sock: &Path, home: &Path) -> String {
    // `~`, not `$HOME`: OpenSSH tilde-expands `IdentityAgent` but performs
    // no shell-variable expansion, so this is the mirror image of the shell
    // block below. A socket outside `$HOME` (the usual `$XDG_RUNTIME_DIR`
    // case on Linux) stays absolute.
    let sock = crate::paths::under_home(agent_sock, home, "~");
    format!("{BEGIN_SENTINEL}\nHost *\n    IdentityAgent \"{sock}\"\n{END_SENTINEL}")
}

fn shell_rc_block(shell: &Shell, agent_sock: &Path, home: &Path) -> String {
    // Quoted in both forms, so `$HOME` — see `ssh_config_block` for why the
    // ssh-config sibling uses a tilde instead.
    let sock = crate::paths::under_home(agent_sock, home, "$HOME");
    let line = match shell {
        Shell::Fish => format!(r#"set -gx SSH_AUTH_SOCK "{sock}""#),
        _ => format!(r#"export SSH_AUTH_SOCK="{sock}""#),
    };
    format!("{BEGIN_SENTINEL}\n{line}\n{END_SENTINEL}")
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn mode_of(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn ssh_config_block_has_identityagent_and_prepends() {
        let home = tempfile::tempdir().unwrap();
        let sock = home.path().join("agent.sock");
        let ssh_dir = home.path().join(".ssh");
        fs::create_dir_all(&ssh_dir).unwrap();
        let config = ssh_dir.join("config");
        let preexisting = "Host example\n  User me\n";
        fs::write(&config, preexisting).unwrap();

        let p = plan(home.path(), Method::SshConfig, Shell::Zsh, &sock).unwrap();
        assert!(apply(&p).unwrap(), "first apply should write");

        let content = fs::read_to_string(&config).unwrap();
        // Managed block lands ABOVE the pre-existing content.
        let block_pos = content.find(BEGIN_SENTINEL).unwrap();
        let preexisting_pos = content.find("Host example").unwrap();
        assert!(
            block_pos < preexisting_pos,
            "managed block must be prepended above existing config:\n{content}"
        );
        assert!(content.contains("Host *"));
        assert!(expand_home_tokens(&content, home.path())
            .contains(&format!("IdentityAgent \"{}\"", sock.display())));
        // ssh refuses a group/world-readable config.
        assert_eq!(mode_of(&config), 0o600, "config file must be 0600");
    }

    #[test]
    fn ssh_config_creates_ssh_dir_0700_when_absent() {
        let home = tempfile::tempdir().unwrap();
        let sock = home.path().join("agent.sock");
        let ssh_dir = home.path().join(".ssh");
        assert!(!ssh_dir.exists());

        let p = plan(home.path(), Method::SshConfig, Shell::Zsh, &sock).unwrap();
        assert!(apply(&p).unwrap());

        assert!(ssh_dir.is_dir(), "~/.ssh should be created");
        assert_eq!(mode_of(&ssh_dir), 0o700, "~/.ssh must be 0700");
        assert_eq!(mode_of(&ssh_dir.join("config")), 0o600);
    }

    #[test]
    fn shell_rc_appends_ssh_auth_sock_for_zsh() {
        let home = tempfile::tempdir().unwrap();
        let sock = home.path().join("agent.sock");
        let zshrc = home.path().join(".zshrc");
        fs::write(&zshrc, "# my rc\n").unwrap();

        let p = plan(home.path(), Method::ShellRc, Shell::Zsh, &sock).unwrap();
        assert_eq!(p.config_file, zshrc);
        assert!(apply(&p).unwrap());

        let content = fs::read_to_string(&zshrc).unwrap();
        // Pre-existing content stays on top (append).
        assert!(content.starts_with("# my rc\n"));
        assert!(expand_home_tokens(&content, home.path())
            .contains(&format!(r#"export SSH_AUTH_SOCK="{}""#, sock.display())));
        assert!(content.contains(BEGIN_SENTINEL));
    }

    #[test]
    fn shell_rc_fish_uses_set_gx() {
        let home = tempfile::tempdir().unwrap();
        let sock = home.path().join("agent.sock");

        let p = plan(home.path(), Method::ShellRc, Shell::Fish, &sock).unwrap();
        assert!(apply(&p).unwrap());

        let content = fs::read_to_string(&p.config_file).unwrap();
        assert!(expand_home_tokens(&content, home.path())
            .contains(&format!(r#"set -gx SSH_AUTH_SOCK "{}""#, sock.display())));
        assert!(!content.contains("export SSH_AUTH_SOCK"));
    }

    #[test]
    fn apply_is_idempotent_ssh_config() {
        let home = tempfile::tempdir().unwrap();
        let sock = home.path().join("agent.sock");

        let p1 = plan(home.path(), Method::SshConfig, Shell::Zsh, &sock).unwrap();
        assert!(apply(&p1).unwrap());
        let after_first = fs::read_to_string(&p1.config_file).unwrap();

        let p2 = plan(home.path(), Method::SshConfig, Shell::Zsh, &sock).unwrap();
        assert!(p2.already_configured);
        assert!(!apply(&p2).unwrap(), "second apply must be a no-op");
        let after_second = fs::read_to_string(&p2.config_file).unwrap();
        assert_eq!(after_first, after_second);
    }

    #[test]
    fn a_block_written_before_the_tilde_switch_is_still_already_configured() {
        // Configs written by an earlier secreq spell the socket absolutely,
        // where we now write `~`. Both name the same socket, so a user who
        // already ran `ssh setup` must not be told their block "points at a
        // different socket" and offered a pointless rewrite.
        let home = tempfile::tempdir().unwrap();
        let sock = home.path().join(".secreq/run/agent.sock");
        let ssh_dir = home.path().join(".ssh");
        fs::create_dir_all(&ssh_dir).unwrap();
        let legacy = format!(
            "{BEGIN_SENTINEL}\nHost *\n    IdentityAgent \"{}\"\n{END_SENTINEL}\n",
            sock.display()
        );
        fs::write(ssh_dir.join("config"), &legacy).unwrap();

        let p = plan(home.path(), Method::SshConfig, Shell::Zsh, &sock).unwrap();
        assert!(p.already_configured, "absolute spelling must still match");
        assert!(!p.updates_existing);
        assert!(!apply(&p).unwrap(), "nothing to rewrite");
        // And the file is left exactly as the user had it.
        assert_eq!(fs::read_to_string(ssh_dir.join("config")).unwrap(), legacy);
    }

    #[test]
    fn a_genuinely_different_socket_still_reports_an_update() {
        // The normalization must not blunt the check the `already_configured`
        // doc calls out: a socket that actually moved has to be detected.
        let home = tempfile::tempdir().unwrap();
        let ssh_dir = home.path().join(".ssh");
        fs::create_dir_all(&ssh_dir).unwrap();
        fs::write(
            ssh_dir.join("config"),
            format!(
                "{BEGIN_SENTINEL}\nHost *\n    IdentityAgent \"{}\"\n{END_SENTINEL}\n",
                home.path().join("legacy/agent.sock").display()
            ),
        )
        .unwrap();

        let p = plan(
            home.path(),
            Method::SshConfig,
            Shell::Zsh,
            &home.path().join(".secreq/run/agent.sock"),
        )
        .unwrap();
        assert!(!p.already_configured);
        assert!(p.updates_existing, "a moved socket must still be rewritten");
    }

    #[test]
    fn apply_is_idempotent_shell_rc() {
        let home = tempfile::tempdir().unwrap();
        let sock = home.path().join("agent.sock");

        let p1 = plan(home.path(), Method::ShellRc, Shell::Bash, &sock).unwrap();
        assert!(apply(&p1).unwrap());
        let after_first = fs::read_to_string(&p1.config_file).unwrap();

        let p2 = plan(home.path(), Method::ShellRc, Shell::Bash, &sock).unwrap();
        assert!(p2.already_configured);
        assert!(!apply(&p2).unwrap(), "second apply must be a no-op");
        let after_second = fs::read_to_string(&p2.config_file).unwrap();
        assert_eq!(after_first, after_second);
    }

    /// The migration-0001 regression: the socket moved, so the block on disk
    /// names a path no daemon listens on. Sentinel-presence idempotency
    /// reported "already configured" and re-running setup fixed nothing.
    #[test]
    fn apply_rewrites_a_block_whose_socket_path_changed() {
        let home = tempfile::tempdir().unwrap();
        let old_sock = home.path().join("legacy/agent.sock");
        let new_sock = home.path().join("secreq/run/agent.sock");

        let p1 = plan(home.path(), Method::SshConfig, Shell::Zsh, &old_sock).unwrap();
        assert!(apply(&p1).unwrap());

        let p2 = plan(home.path(), Method::SshConfig, Shell::Zsh, &new_sock).unwrap();
        assert!(
            !p2.already_configured,
            "a block naming a stale socket is not 'already configured'"
        );
        assert!(
            p2.updates_existing,
            "should rewrite, not add a second block"
        );
        assert!(apply(&p2).unwrap(), "apply must rewrite the stale block");

        let content = fs::read_to_string(&p2.config_file).unwrap();
        assert!(expand_home_tokens(&content, home.path())
            .contains(&format!("IdentityAgent \"{}\"", new_sock.display())));
        assert!(
            !content.contains(&old_sock.display().to_string()),
            "stale path must be gone:\n{content}"
        );
        assert_eq!(
            content.matches(BEGIN_SENTINEL).count(),
            1,
            "must not accumulate blocks:\n{content}"
        );
    }

    #[test]
    fn rewrite_preserves_position_and_surrounding_content() {
        let home = tempfile::tempdir().unwrap();
        let old_sock = home.path().join("legacy/agent.sock");
        let new_sock = home.path().join("secreq/run/agent.sock");
        let ssh_dir = home.path().join(".ssh");
        fs::create_dir_all(&ssh_dir).unwrap();
        let config = ssh_dir.join("config");

        // Our block sandwiched between the user's own stanzas.
        let block = ssh_config_block(&old_sock, home.path());
        let before = "Host above\n  User me\n";
        let after = "\nHost below\n  User you\n";
        fs::write(&config, format!("{before}{block}\n{after}")).unwrap();

        let p = plan(home.path(), Method::SshConfig, Shell::Zsh, &new_sock).unwrap();
        assert!(p.updates_existing);
        assert!(apply(&p).unwrap());

        let content = fs::read_to_string(&config).unwrap();
        // Neighbours intact, and ours stayed between them.
        assert!(content.contains("Host above"));
        assert!(content.contains("Host below"));
        let above = content.find("Host above").unwrap();
        let ours = content.find(BEGIN_SENTINEL).unwrap();
        let below = content.find("Host below").unwrap();
        assert!(above < ours && ours < below, "block moved:\n{content}");
        assert!(expand_home_tokens(&content, home.path())
            .contains(&format!("IdentityAgent \"{}\"", new_sock.display())));
    }

    #[test]
    fn rewrite_keeps_ssh_config_0600() {
        let home = tempfile::tempdir().unwrap();
        let old_sock = home.path().join("legacy/agent.sock");
        let new_sock = home.path().join("secreq/run/agent.sock");

        let p1 = plan(home.path(), Method::SshConfig, Shell::Zsh, &old_sock).unwrap();
        apply(&p1).unwrap();
        let p2 = plan(home.path(), Method::SshConfig, Shell::Zsh, &new_sock).unwrap();
        apply(&p2).unwrap();

        assert_eq!(mode_of(&p2.config_file), 0o600, "ssh refuses a laxer mode");
    }

    /// `rewrite_in_place` edits files secreq does not own, and migration 0002
    /// calls it on installs whose owner never asked for the edit and isn't
    /// watching it happen. It must replace the inode, not truncate one: a
    /// `fs::write` that died mid-write left a truncated `~/.zshrc` — and the
    /// migration's retry then read that as carrying no managed block, reported
    /// success, and stamped the level over the damage.
    #[test]
    fn rewrite_replaces_the_inode_rather_than_truncating_it() {
        use std::os::unix::fs::MetadataExt;

        let home = tempfile::tempdir().unwrap();
        let zshrc = home.path().join(".zshrc");
        fs::write(&zshrc, "# my rc\n").unwrap();
        let p1 = plan(
            home.path(),
            Method::ShellRc,
            Shell::Zsh,
            &home.path().join("old.sock"),
        )
        .unwrap();
        apply(&p1).unwrap();
        let before = fs::metadata(&zshrc).unwrap().ino();

        let p2 = plan(
            home.path(),
            Method::ShellRc,
            Shell::Zsh,
            &home.path().join("new.sock"),
        )
        .unwrap();
        assert_eq!(
            rewrite_in_place(&zshrc, &p2.block).unwrap(),
            Rewrote::TheBlock
        );

        assert_ne!(
            fs::metadata(&zshrc).unwrap().ino(),
            before,
            "a truncate-in-place rewrite can publish a half-written rc"
        );
        // The whole point of the staging file: the rest of the rc is intact.
        assert!(fs::read_to_string(&zshrc).unwrap().starts_with("# my rc\n"));
        // And nothing is left beside it for the user to wonder about.
        assert!(!home.path().join(".zshrc.tmp").exists());
    }

    /// The answer that used to be thrown away. A file carrying no managed
    /// block is not a file that was successfully rewritten, and it is left
    /// exactly as it was — migration 0002 read `Ok(false)` here as "already
    /// fine" and recorded its level over an untouched config.
    #[test]
    fn rewrite_reports_nothing_when_there_is_no_managed_block() {
        let home = tempfile::tempdir().unwrap();
        let zshrc = home.path().join(".zshrc");
        fs::write(&zshrc, "# my rc\n").unwrap();
        let p = plan(
            home.path(),
            Method::ShellRc,
            Shell::Zsh,
            &home.path().join("agent.sock"),
        )
        .unwrap();

        assert_eq!(
            rewrite_in_place(&zshrc, &p.block).unwrap(),
            Rewrote::Nothing
        );
        assert_eq!(fs::read_to_string(&zshrc).unwrap(), "# my rc\n");
    }

    #[test]
    fn apply_rewrites_a_stale_shell_rc_block() {
        let home = tempfile::tempdir().unwrap();
        let old_sock = home.path().join("legacy/agent.sock");
        let new_sock = home.path().join("secreq/run/agent.sock");
        let zshrc = home.path().join(".zshrc");
        fs::write(&zshrc, "# my rc\n").unwrap();

        let p1 = plan(home.path(), Method::ShellRc, Shell::Zsh, &old_sock).unwrap();
        apply(&p1).unwrap();
        let p2 = plan(home.path(), Method::ShellRc, Shell::Zsh, &new_sock).unwrap();
        assert!(p2.updates_existing);
        assert!(apply(&p2).unwrap());

        let content = fs::read_to_string(&zshrc).unwrap();
        assert!(content.starts_with("# my rc\n"), "rc preamble survives");
        assert!(expand_home_tokens(&content, home.path())
            .contains(&format!(r#"export SSH_AUTH_SOCK="{}""#, new_sock.display())));
        assert!(!content.contains(&old_sock.display().to_string()));
        assert_eq!(content.matches(BEGIN_SENTINEL).count(), 1);
    }

    #[test]
    fn remove_round_trips_ssh_config() {
        let home = tempfile::tempdir().unwrap();
        let sock = home.path().join("agent.sock");
        let ssh_dir = home.path().join(".ssh");
        fs::create_dir_all(&ssh_dir).unwrap();
        let config = ssh_dir.join("config");
        let preexisting = "Host example\n  User me\n";
        fs::write(&config, preexisting).unwrap();

        let p = plan(home.path(), Method::SshConfig, Shell::Zsh, &sock).unwrap();
        apply(&p).unwrap();
        assert!(fs::read_to_string(&config)
            .unwrap()
            .contains(BEGIN_SENTINEL));

        assert!(remove(home.path(), Method::SshConfig, Shell::Zsh).unwrap());
        let after = fs::read_to_string(&config).unwrap();
        assert!(!after.contains(BEGIN_SENTINEL), "sentinels must be gone");
        assert!(!after.contains(END_SENTINEL));
        // Pre-existing lines intact, verbatim.
        assert_eq!(after, preexisting);
    }

    #[test]
    fn remove_round_trips_shell_rc() {
        let home = tempfile::tempdir().unwrap();
        let sock = home.path().join("agent.sock");
        let zshrc = home.path().join(".zshrc");
        let preexisting = "# my rc\nalias ll='ls -la'\n";
        fs::write(&zshrc, preexisting).unwrap();

        let p = plan(home.path(), Method::ShellRc, Shell::Zsh, &sock).unwrap();
        apply(&p).unwrap();
        assert!(fs::read_to_string(&zshrc).unwrap().contains(BEGIN_SENTINEL));

        assert!(remove(home.path(), Method::ShellRc, Shell::Zsh).unwrap());
        let after = fs::read_to_string(&zshrc).unwrap();
        assert!(!after.contains(BEGIN_SENTINEL));
        assert!(!after.contains(END_SENTINEL));
        assert_eq!(after, preexisting);
    }

    /// The three writers that are not `rewrite_in_place` edit the same
    /// dotfiles it does, and `path_setup::apply` writes two of them as well —
    /// so before this they disagreed about whether a crash could truncate a
    /// user's `~/.zshrc`. A `fs::write` that dies after truncating leaves a
    /// login shell that will not start, and an `~/.ssh/config` whose `Host`
    /// stanzas are gone. Replacing the inode is what makes a reader see either
    /// the old file or the new one.
    #[test]
    fn every_writer_replaces_the_inode_rather_than_truncating_it() {
        use std::os::unix::fs::MetadataExt;

        let home = tempfile::tempdir().unwrap();
        let sock = home.path().join("agent.sock");
        let ssh_dir = home.path().join(".ssh");
        fs::create_dir_all(&ssh_dir).unwrap();
        let config = ssh_dir.join("config");
        fs::write(&config, "Host example\n  User me\n").unwrap();
        let zshrc = home.path().join(".zshrc");
        fs::write(&zshrc, "# my rc\n").unwrap();

        // `apply_ssh_config` — prepending above the user's existing stanzas.
        let before = fs::metadata(&config).unwrap().ino();
        let p = plan(home.path(), Method::SshConfig, Shell::Zsh, &sock).unwrap();
        apply(&p).unwrap();
        assert_ne!(fs::metadata(&config).unwrap().ino(), before, "ssh config");

        // `apply_shell_rc` — appending below it.
        let before = fs::metadata(&zshrc).unwrap().ino();
        let p = plan(home.path(), Method::ShellRc, Shell::Zsh, &sock).unwrap();
        apply(&p).unwrap();
        assert_ne!(fs::metadata(&zshrc).unwrap().ino(), before, "shell rc");

        // `remove` — `ssh setup --undo`, which rewrites the whole file too.
        let before = fs::metadata(&zshrc).unwrap().ino();
        assert!(remove(home.path(), Method::ShellRc, Shell::Zsh).unwrap());
        assert_ne!(fs::metadata(&zshrc).unwrap().ino(), before, "remove");

        // And no staging file is left for the user to wonder about.
        for dir in [home.path(), ssh_dir.as_path()] {
            for entry in fs::read_dir(dir).unwrap() {
                let name = entry.unwrap().file_name();
                let name = name.to_string_lossy();
                assert!(!name.ends_with(".tmp"), "left {name} behind in {dir:?}");
            }
        }
    }

    /// A guard, not a repro: `fs::write` preserves an existing inode's mode,
    /// so this passed before the move to stage-and-rename and has to keep
    /// passing after it. Staging publishes a **new** inode, which is how
    /// migration 0001 republished everyone's `wraps.json5` at 0644 — and the
    /// naive reading of "secreq's files are owner-only" would narrow a
    /// `.zshrc` the user deliberately left group-readable. `Mode::Like` is
    /// what gets both halves; nobody should simplify it to `Exactly(0o600)`.
    #[test]
    fn apply_shell_rc_keeps_the_mode_of_an_rc_the_user_already_had() {
        let home = tempfile::tempdir().unwrap();
        let sock = home.path().join("agent.sock");
        let zshrc = home.path().join(".zshrc");
        fs::write(&zshrc, "# my rc\n").unwrap();
        fs::set_permissions(&zshrc, fs::Permissions::from_mode(0o644)).unwrap();

        let p = plan(home.path(), Method::ShellRc, Shell::Zsh, &sock).unwrap();
        apply(&p).unwrap();
        assert_eq!(mode_of(&zshrc), 0o644, "an rc the user owns keeps its mode");

        assert!(remove(home.path(), Method::ShellRc, Shell::Zsh).unwrap());
        assert_eq!(mode_of(&zshrc), 0o644, "and `--undo` does not narrow it");
    }

    /// An rc file secreq creates has no mode to preserve, and the umask's
    /// answer is 0644 under the common 022 and **0666** under the `umask 000`
    /// CI and container images set. `Mode::Like`'s missing-source fallback is
    /// what answers this half of the same expression.
    #[test]
    fn an_rc_file_ssh_setup_creates_is_owner_only() {
        let home = tempfile::tempdir().unwrap();
        let sock = home.path().join("agent.sock");

        let p = plan(home.path(), Method::ShellRc, Shell::Zsh, &sock).unwrap();
        apply(&p).unwrap();

        assert_eq!(mode_of(&home.path().join(".zshrc")), 0o600);
    }

    #[test]
    fn remove_returns_false_when_absent() {
        let home = tempfile::tempdir().unwrap();
        // No file at all.
        assert!(!remove(home.path(), Method::SshConfig, Shell::Zsh).unwrap());
        // File present but no managed block.
        fs::write(home.path().join(".zshrc"), "# just my rc\n").unwrap();
        assert!(!remove(home.path(), Method::ShellRc, Shell::Zsh).unwrap());
    }

    #[test]
    fn shell_rc_unknown_shell_errors() {
        let home = tempfile::tempdir().unwrap();
        let sock = home.path().join("agent.sock");
        let err = plan(
            home.path(),
            Method::ShellRc,
            Shell::Unknown("nu".into()),
            &sock,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unrecognized shell"));
    }
}
