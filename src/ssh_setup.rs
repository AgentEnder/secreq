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
use std::os::unix::fs::PermissionsExt;
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
            let block = ssh_config_block(agent_sock);
            let (already_configured, updates_existing) = block_state(&config_file, &block);
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
            let block = shell_rc_block(&shell, agent_sock);
            let (already_configured, updates_existing) = block_state(&config_file, &block);
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
fn block_state(config_file: &Path, want: &str) -> (bool, bool) {
    let Ok(content) = fs::read_to_string(config_file) else {
        return (false, false);
    };
    match existing_block(&content) {
        Some(found) if found == want => (true, false),
        Some(_) => (false, true),
        None => (false, false),
    }
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
        return rewrite_in_place(&plan.config_file, &plan.block);
    }
    match plan.method {
        Method::SshConfig => apply_ssh_config(plan),
        Method::ShellRc => apply_shell_rc(plan),
    }
}

/// Swap the managed block in `config_file` for `new_block`, leaving the rest
/// of the file byte-identical. `Ok(false)` if there was no block to replace.
///
/// Shared by [`apply`] and migration 0002 — the migration repoints blocks on
/// installs whose owner will never re-run `ssh setup`, and must reach the
/// exact same result.
pub(crate) fn rewrite_in_place(config_file: &Path, new_block: &str) -> Result<bool> {
    let content = match fs::read_to_string(config_file) {
        Ok(c) => c,
        Err(_) => return Ok(false),
    };
    let Some(updated) = replace_block(&content, new_block) else {
        return Ok(false);
    };
    if updated == content {
        return Ok(false);
    }
    // Preserve the file's mode: ~/.ssh/config must stay 0600 or ssh refuses
    // it, and `fs::write` on an existing file leaves the mode alone.
    fs::write(config_file, updated)
        .with_context(|| format!("could not write {}", config_file.display()))?;
    Ok(true)
}

/// The managed block in `config_file`, sentinels included. `None` if the file
/// is absent, unreadable, or carries no block. Used by migration 0002 to ask
/// "does this block name the old socket?" before touching it.
pub(crate) fn block_in_file(config_file: &Path) -> Option<String> {
    existing_block(&fs::read_to_string(config_file).ok()?)
}

fn apply_ssh_config(plan: &SshSetupPlan) -> Result<bool> {
    // Ensure ~/.ssh exists with 0700 — ssh refuses a group/world-accessible
    // config dir.
    if let Some(parent) = plan.config_file.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("could not create {}", parent.display()))?;
        let mut perms = fs::metadata(parent)
            .with_context(|| format!("could not stat {}", parent.display()))?
            .permissions();
        perms.set_mode(0o700);
        fs::set_permissions(parent, perms)
            .with_context(|| format!("could not set mode 0700 on {}", parent.display()))?;
    }
    // Prepend the block above existing content: ssh applies the first
    // IdentityAgent it obtains for a host, so ours must come first.
    let existing = fs::read_to_string(&plan.config_file).unwrap_or_default();
    let to_write = if existing.is_empty() {
        format!("{}\n", plan.block)
    } else {
        format!("{}\n\n{existing}", plan.block)
    };
    fs::write(&plan.config_file, to_write)
        .with_context(|| format!("could not write {}", plan.config_file.display()))?;
    // ssh refuses a group/world-readable config.
    let mut perms = fs::metadata(&plan.config_file)
        .with_context(|| format!("could not stat {}", plan.config_file.display()))?
        .permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&plan.config_file, perms)
        .with_context(|| format!("could not set mode 0600 on {}", plan.config_file.display()))?;
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
    fs::write(&plan.config_file, to_write)
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
    let existing = match fs::read_to_string(&config_file) {
        Ok(content) => content,
        Err(_) => return Ok(false), // file absent → nothing to remove
    };
    let Some(stripped) = strip_block(&existing) else {
        return Ok(false);
    };
    fs::write(&config_file, stripped)
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

fn ssh_config_block(agent_sock: &Path) -> String {
    let sock = agent_sock.display();
    format!("{BEGIN_SENTINEL}\nHost *\n    IdentityAgent \"{sock}\"\n{END_SENTINEL}")
}

fn shell_rc_block(shell: &Shell, agent_sock: &Path) -> String {
    let sock = agent_sock.display();
    let line = match shell {
        Shell::Fish => format!(r#"set -gx SSH_AUTH_SOCK "{sock}""#),
        _ => format!(r#"export SSH_AUTH_SOCK="{sock}""#),
    };
    format!("{BEGIN_SENTINEL}\n{line}\n{END_SENTINEL}")
}

#[cfg(test)]
mod tests {
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
        assert!(content.contains(&format!("IdentityAgent \"{}\"", sock.display())));
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
        assert!(content.contains(&format!(r#"export SSH_AUTH_SOCK="{}""#, sock.display())));
        assert!(content.contains(BEGIN_SENTINEL));
    }

    #[test]
    fn shell_rc_fish_uses_set_gx() {
        let home = tempfile::tempdir().unwrap();
        let sock = home.path().join("agent.sock");

        let p = plan(home.path(), Method::ShellRc, Shell::Fish, &sock).unwrap();
        assert!(apply(&p).unwrap());

        let content = fs::read_to_string(&p.config_file).unwrap();
        assert!(content.contains(&format!(r#"set -gx SSH_AUTH_SOCK "{}""#, sock.display())));
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
        assert!(content.contains(&format!("IdentityAgent \"{}\"", new_sock.display())));
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
        let block = ssh_config_block(&old_sock);
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
        assert!(content.contains(&format!("IdentityAgent \"{}\"", new_sock.display())));
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
        assert!(content.contains(&format!(r#"export SSH_AUTH_SOCK="{}""#, new_sock.display())));
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
