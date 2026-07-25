//! Shell detection and PATH-setup for `secreq init`.
//!
//! If the user's chosen shim dir isn't on `PATH`, we offer to append a
//! sentinel-bracketed block to the right shell config so future shells
//! pick it up. Children of those shells inherit `PATH`, which is how npm
//! postinstalls and other subprocesses find our shims.
//!
//! ## Per-shell file choice
//!
//! - **zsh** → `~/.zshrc`. Read by interactive shells *after* `.zprofile`,
//!   which is where `brew shellenv` typically lives. Writing to `.zshenv`
//!   (which runs first) means homebrew's later prepend wins; writing to
//!   `.zshrc` means our prepend runs last and our shim dir lands first on
//!   PATH. Tradeoff: non-interactive zsh launched *externally* (ssh
//!   non-login, cron) doesn't read `.zshrc`, but children of interactive
//!   shells inherit PATH at fork time so npm postinstalls and the like are
//!   still covered.
//! - **bash** → `~/.bashrc`. The honest gap: bash has no clean equivalent
//!   of `.zshenv`; non-interactive bash launched from outside the user's
//!   shell tree won't pick this up. Documented in [`plan`]'s returned `Plan`.
//! - **fish** → `~/.config/fish/conf.d/secreq.fish` (a self-contained
//!   snippet loaded by every fish; clean uninstall is `rm`).
//! - **sh / POSIX** → `~/.profile` (sourced by login `sh` and many others).
//!
//! ## Sentinel-bracketed block
//!
//! Every write is wrapped in `# >>> secreq managed PATH >>> … # <<< secreq
//! managed PATH <<<` so future `init` runs are idempotent (we detect the
//! block and skip) and a future `uninit` can cleanly remove it.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Sentinel marking the start of our managed block in shell configs.
pub const BEGIN_SENTINEL: &str = "# >>> secreq managed PATH (do not edit by hand) >>>";
/// Sentinel marking the end of our managed block.
pub const END_SENTINEL: &str = "# <<< secreq managed PATH <<<";

/// Which shell we detected. `Unknown` carries the executable name for the
/// error message we print when we can't figure out where to write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shell {
    Zsh,
    Bash,
    Fish,
    Posix,
    Unknown(String),
}

/// What [`add_to_path`] will do — handed back to the caller so the user
/// gets to see and approve it before any file is touched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// Detected shell.
    pub shell: Shell,
    /// Path to the config file we'll append to (will be created if absent).
    pub config_file: PathBuf,
    /// Full block we'll append, including sentinels. Show this to the user.
    pub block: String,
    /// True if the block is already present — `add_to_path` will be a no-op.
    pub already_configured: bool,
    /// Honesty note for the user: a one-liner caveat about this shell's
    /// coverage (e.g. bash + non-interactive subprocesses).
    pub caveat: Option<String>,
}

/// Detect the user's shell from `$SHELL`. Bare executable name only — we
/// don't care about login-shell-vs-not at this layer.
pub fn detect_shell() -> Shell {
    let raw = std::env::var("SHELL").unwrap_or_default();
    let basename = raw.rsplit('/').next().unwrap_or("");
    match basename {
        "zsh" => Shell::Zsh,
        "bash" => Shell::Bash,
        "fish" => Shell::Fish,
        "sh" | "dash" | "ash" => Shell::Posix,
        "" => Shell::Unknown(raw),
        other => Shell::Unknown(other.to_owned()),
    }
}

/// True if `dir` is currently on the process's `PATH`.
pub fn path_includes(dir: &Path) -> bool {
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path).any(|p| p == dir)
}

/// Scan the shell's *other* startup files for our sentinel — useful when
/// the canonical file (per [`plan`]) doesn't have our block but a previous
/// init may have written one elsewhere (e.g. before we moved zsh from
/// `.zshenv` to `.zshrc`). Returns the paths that still contain a managed
/// block, excluding `canonical`.
pub fn find_stale_blocks(home: &Path, shell: &Shell, canonical: &Path) -> Vec<PathBuf> {
    let candidates: &[&str] = match shell {
        // Every file zsh might read at startup; if a block is there, it's
        // ours from a prior init or the user's hand-copy.
        Shell::Zsh => &[".zshenv", ".zprofile", ".zshrc", ".zlogin"],
        Shell::Bash => &[".bashrc", ".bash_profile", ".profile"],
        Shell::Posix => &[".profile"],
        // Fish's conf.d snippet is unique per name; nothing to scan.
        Shell::Fish | Shell::Unknown(_) => &[],
    };
    candidates
        .iter()
        .map(|name| home.join(name))
        .filter(|p| p != canonical && p.is_file())
        .filter(|p| {
            std::fs::read_to_string(p)
                .map(|s| s.contains(BEGIN_SENTINEL))
                .unwrap_or(false)
        })
        .collect()
}

/// Build the plan: which config file, what block we'd append, whether it
/// already contains our sentinel. Pure (no filesystem writes); use
/// [`apply`] to actually write.
///
/// `home` lets tests stand in a temp dir for `$HOME`. Production callers
/// pass `dirs::home_dir()`.
pub fn plan(home: &Path, shell: Shell, shim_dir: &Path) -> Result<Plan> {
    let config_file = shell_config_path(home, &shell).with_context(|| {
        format!(
            "unrecognized shell {:?}; please add {} to PATH manually",
            shell,
            shim_dir.display()
        )
    })?;
    let block = format_block(&shell, shim_dir);
    let already_configured = match fs::read_to_string(&config_file) {
        Ok(existing) => existing.contains(BEGIN_SENTINEL),
        Err(_) => false, // file doesn't exist → not configured
    };
    Ok(Plan {
        caveat: caveat_for(&shell),
        shell,
        config_file,
        block,
        already_configured,
    })
}

/// Apply the plan: append the block to the config file. Idempotent — if
/// the sentinel is already present, returns `Ok(false)` without touching
/// the file. Returns `Ok(true)` if we wrote something.
pub fn apply(plan: &Plan) -> Result<bool> {
    if plan.already_configured {
        return Ok(false);
    }
    if let Some(parent) = plan.config_file.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("could not create {}", parent.display()))?;
    }
    // Append with a leading newline if the file exists and doesn't end with
    // one — keeps us from gluing onto a previous line.
    let existing = fs::read_to_string(&plan.config_file).unwrap_or_default();
    let needs_leading_newline = !existing.is_empty() && !existing.ends_with('\n');
    let prefix = if needs_leading_newline { "\n" } else { "" };
    let to_write = format!("{existing}{prefix}{}\n", plan.block);
    fs::write(&plan.config_file, to_write)
        .with_context(|| format!("could not write {}", plan.config_file.display()))?;
    Ok(true)
}

pub(crate) fn shell_config_path(home: &Path, shell: &Shell) -> Option<PathBuf> {
    match shell {
        // .zshrc runs AFTER .zprofile, where `brew shellenv` typically
        // prepends /opt/homebrew/bin. Our block needs to run last so our
        // shim dir wins on PATH; .zshrc is the right file for that.
        Shell::Zsh => Some(home.join(".zshrc")),
        // Best we can do on bash; non-interactive bash launched outside the
        // user's shell tree won't read this.
        Shell::Bash => Some(home.join(".bashrc")),
        // conf.d is the idiomatic place for plug-in style snippets in fish.
        Shell::Fish => Some(home.join(".config/fish/conf.d/secreq.fish")),
        Shell::Posix => Some(home.join(".profile")),
        Shell::Unknown(_) => None,
    }
}

pub(crate) fn caveat_for(shell: &Shell) -> Option<String> {
    match shell {
        Shell::Zsh => Some(
            "zsh note: writing to .zshrc (which runs after .zprofile, where homebrew lives) \
             so our prepend wins on PATH. Non-interactive zsh launched externally (ssh \
             non-login, cron) doesn't read .zshrc — children of your interactive shell \
             inherit PATH from it though, so npm postinstalls and the like still see the shim."
                .to_owned(),
        ),
        Shell::Bash => Some(
            "bash note: .bashrc is read by interactive bash and children inherit PATH from \
             there, but non-interactive bash launched from outside your shell tree (e.g. \
             launchd / systemd jobs) won't see this. For those, set PATH in the launcher \
             config instead."
                .to_owned(),
        ),
        Shell::Unknown(name) => Some(format!(
            "unrecognized shell `{name}`; add the shim dir to PATH in whatever config your \
             shell reads at startup."
        )),
        _ => None,
    }
}

fn format_block(shell: &Shell, shim_dir: &Path) -> String {
    let dir = shim_dir.display();
    let line = match shell {
        Shell::Fish => format!("fish_add_path --path --prepend {dir}"),
        _ => format!(r#"export PATH="{dir}:$PATH""#),
    };
    format!("{BEGIN_SENTINEL}\n{line}\n{END_SENTINEL}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_picks_zshrc_for_zsh_so_homebrew_doesnt_shadow_us() {
        // .zshrc runs after .zprofile (where `brew shellenv` typically
        // lives), so our prepend goes in last and our shim dir wins on
        // PATH. The .zshenv choice that used to be here let homebrew win.
        let home = tempfile::tempdir().unwrap();
        let shim = home.path().join(".local/bin");
        let p = plan(home.path(), Shell::Zsh, &shim).unwrap();
        assert_eq!(p.config_file, home.path().join(".zshrc"));
        assert!(p.block.contains(r#"export PATH=""#));
        assert!(p.block.contains(BEGIN_SENTINEL));
        assert!(p.block.contains(END_SENTINEL));
        assert!(!p.already_configured);
        // The caveat explicitly mentions the tradeoff so users aren't surprised.
        assert!(p.caveat.as_ref().unwrap().contains(".zshrc"));
    }

    #[test]
    fn plan_picks_fish_conf_d_with_fish_add_path() {
        let home = tempfile::tempdir().unwrap();
        let shim = home.path().join(".local/bin");
        let p = plan(home.path(), Shell::Fish, &shim).unwrap();
        assert_eq!(
            p.config_file,
            home.path().join(".config/fish/conf.d/secreq.fish")
        );
        assert!(p.block.contains("fish_add_path"));
    }

    #[test]
    fn plan_emits_bash_caveat() {
        let home = tempfile::tempdir().unwrap();
        let p = plan(home.path(), Shell::Bash, &home.path().join("bin")).unwrap();
        assert!(p.caveat.as_ref().unwrap().contains("bash"));
    }

    #[test]
    fn plan_errors_for_unknown_shell() {
        let home = tempfile::tempdir().unwrap();
        let err = plan(
            home.path(),
            Shell::Unknown("nu".into()),
            &home.path().join("b"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("unrecognized shell"));
    }

    #[test]
    fn apply_appends_block_and_is_idempotent() {
        let home = tempfile::tempdir().unwrap();
        let shim = home.path().join(".local/bin");
        let plan1 = plan(home.path(), Shell::Zsh, &shim).unwrap();
        assert!(apply(&plan1).unwrap(), "first apply should write");
        let after_first = fs::read_to_string(&plan1.config_file).unwrap();
        assert!(after_first.contains(BEGIN_SENTINEL));

        // Re-plan after writing — should now report already_configured.
        let plan2 = plan(home.path(), Shell::Zsh, &shim).unwrap();
        assert!(plan2.already_configured);
        assert!(!apply(&plan2).unwrap(), "second apply must be a no-op");
        let after_second = fs::read_to_string(&plan2.config_file).unwrap();
        assert_eq!(after_first, after_second);
    }

    #[test]
    fn find_stale_blocks_finds_managed_blocks_in_other_zsh_files() {
        let home = tempfile::tempdir().unwrap();
        let canonical = home.path().join(".zshrc");
        // Pretend the user ran an older init that wrote to .zshenv.
        std::fs::write(
            home.path().join(".zshenv"),
            format!("{BEGIN_SENTINEL}\nexport PATH=\"/foo:$PATH\"\n{END_SENTINEL}\n"),
        )
        .unwrap();
        let stale = find_stale_blocks(home.path(), &Shell::Zsh, &canonical);
        assert_eq!(stale, vec![home.path().join(".zshenv")]);
    }

    #[test]
    fn find_stale_blocks_ignores_canonical_file_and_unrelated_files() {
        let home = tempfile::tempdir().unwrap();
        let canonical = home.path().join(".zshrc");
        // Canonical with our block — must not be reported as stale.
        std::fs::write(
            &canonical,
            format!("{BEGIN_SENTINEL}\nexport PATH=\"/x:$PATH\"\n{END_SENTINEL}\n"),
        )
        .unwrap();
        // Unrelated content — must not be reported.
        std::fs::write(home.path().join(".zprofile"), "# nothing to do with us\n").unwrap();
        let stale = find_stale_blocks(home.path(), &Shell::Zsh, &canonical);
        assert!(stale.is_empty(), "got {stale:?}");
    }

    #[test]
    fn apply_appends_newline_when_existing_file_lacks_one() {
        let home = tempfile::tempdir().unwrap();
        let shim = home.path().join(".local/bin");
        let p = plan(home.path(), Shell::Zsh, &shim).unwrap();
        fs::write(&p.config_file, "# pre-existing rc, no trailing newline").unwrap();
        apply(&p).unwrap();
        let content = fs::read_to_string(&p.config_file).unwrap();
        assert!(content.contains("# pre-existing rc, no trailing newline\n"));
        assert!(content.contains(BEGIN_SENTINEL));
    }
}
