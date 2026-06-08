//! SSH-agent wiring for `secreq ssh-setup` (and `init`).
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
    /// True if the block is already present — [`apply`] will be a no-op.
    pub already_configured: bool,
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
            let already_configured = file_has_sentinel(&config_file);
            Ok(SshSetupPlan {
                method,
                config_file,
                block,
                already_configured,
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
            let already_configured = file_has_sentinel(&config_file);
            Ok(SshSetupPlan {
                method,
                config_file,
                block,
                already_configured,
                caveat: path_setup::caveat_for(&shell),
            })
        }
    }
}

/// Apply the plan. Idempotent — if the sentinel is already present, returns
/// `Ok(false)` without touching the file. Returns `Ok(true)` if we wrote
/// something.
///
/// `SshConfig` **prepends** the block (ssh uses the first `IdentityAgent`),
/// ensuring `~/.ssh` is `0700` and the config is `0600`. `ShellRc`
/// **appends** like the PATH block.
pub fn apply(plan: &SshSetupPlan) -> Result<bool> {
    if plan.already_configured {
        return Ok(false);
    }
    match plan.method {
        Method::SshConfig => apply_ssh_config(plan),
        Method::ShellRc => apply_shell_rc(plan),
    }
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

/// Strip the sentinel-bracketed block from `content`. Returns `None` if no
/// block is present, else the remainder with the begin..=end lines removed
/// (plus one trailing blank line if it immediately follows the end line).
fn strip_block(content: &str) -> Option<String> {
    let lines: Vec<&str> = content.lines().collect();
    let begin = lines.iter().position(|l| l.contains(BEGIN_SENTINEL))?;
    let end = lines
        .iter()
        .skip(begin)
        .position(|l| l.contains(END_SENTINEL))
        .map(|offset| begin + offset)?;
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

/// True if `path` exists and contains our begin sentinel.
fn file_has_sentinel(path: &Path) -> bool {
    fs::read_to_string(path)
        .map(|s| s.contains(BEGIN_SENTINEL))
        .unwrap_or(false)
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
