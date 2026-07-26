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
        .filter(|p| fs::read(p).is_ok_and(|s| contains_bytes(&s, BEGIN_SENTINEL.as_bytes())))
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
    let block = format_block(&shell, shim_dir, home);
    // Byte-wise, not `read_to_string`: an rc file is the user's, and one
    // latin-1 comment anywhere in it made the UTF-8 read fail, which read as
    // "no block here" and had `apply` append a second one.
    let already_configured = match fs::read(&config_file) {
        Ok(existing) => contains_bytes(&existing, BEGIN_SENTINEL.as_bytes()),
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
        ensure_config_dir(parent)?;
    }
    // Bytes, not a `String`. The rc file is the user's, nothing promises it is
    // UTF-8, and the old `read_to_string(..).unwrap_or_default()` turned a
    // single stray byte into an empty string — so the write below replaced
    // the whole file with our three-line block and reported success.
    let existing = match fs::read(&plan.config_file) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        // An unreadable file is not an empty one either.
        Err(err) => {
            return Err(err)
                .with_context(|| format!("could not read {}", plan.config_file.display()))
        }
    };

    // Append with a leading newline if the file exists and doesn't end with
    // one — keeps us from gluing onto a previous line.
    let mut to_write = existing;
    if !to_write.is_empty() && !to_write.ends_with(b"\n") {
        to_write.push(b'\n');
    }
    to_write.extend_from_slice(plan.block.as_bytes());
    to_write.push(b'\n');

    // Stage and rename rather than truncate in place: a crash or a full disk
    // partway through a `fs::write` leaves a `.zshrc` that is neither the old
    // one nor the new one, which is a login shell that no longer starts.
    // `Mode::Like` preserves the mode of a file the user already had and falls
    // back to owner-only for one we are creating — a shell rc written at the
    // umask's answer is 0666 under the `umask 000` CI images set, and a
    // world-writable file the login shell sources is arbitrary code execution.
    crate::atomic::replace(
        &plan.config_file,
        &to_write,
        crate::atomic::Mode::Like(&plan.config_file),
    )
    .with_context(|| format!("could not write {}", plan.config_file.display()))?;
    Ok(true)
}

/// Create the directory a shell config lives in, without letting the umask
/// choose its mode.
///
/// Only fish reaches this with anything to make — `~/.config/fish/conf.d`,
/// every file in which fish sources at startup, so a `umask 000` install would
/// hand fish a world-writable directory to read commands from. Directories the
/// user already had keep their mode: `~/.config` is shared with everything
/// else that follows the XDG layout, and narrowing it is not ours to do.
fn ensure_config_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("could not create {}", dir.display()))
}

/// `haystack.contains(needle)` for bytes — `[u8]` has no `contains` for a
/// subslice, and the sentinel search must not go through UTF-8.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len() && haystack.windows(needle.len()).any(|w| w == needle)
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

fn format_block(shell: &Shell, shim_dir: &Path, home: &Path) -> String {
    // `$HOME`, not `~`: the POSIX line quotes the path, and a tilde inside
    // double quotes is never expanded — `"~/.secreq/shims"` would put a
    // directory literally named `~` on PATH. `$HOME` expands in both the
    // POSIX form and fish's, and it keeps the block portable for anyone who
    // syncs their dotfiles between machines. A shim dir outside `$HOME`
    // stays absolute.
    //
    // The split is what lets both halves be true at once: the token is ours
    // and must expand, the remainder is the user's path and must not. So the
    // escaping is applied to the remainder only, never to the whole string.
    let (token, rest) = split_home_token(shim_dir, home);
    let dir = format!("{token}{}", escape_for_double_quotes(&rest, shell));
    let line = match shell {
        // Unquoted, fish split the argument on whitespace: a shim dir with a
        // space in its name added two directories, neither of them the one
        // the user chose.
        Shell::Fish => format!(r#"fish_add_path --path --prepend "{dir}""#),
        _ => format!(r#"export PATH="{dir}:$PATH""#),
    };
    format!("{BEGIN_SENTINEL}\n{line}\n{END_SENTINEL}")
}

/// The POSIX `export PATH=` line to hand a user whose shell we could not
/// place, for them to paste into whatever config it reads.
///
/// Spelled absolute rather than with `$HOME`: an unrecognized shell is
/// precisely the case where we cannot promise a variable expands. The path
/// still lands inside double quotes, so it gets the same escaping as the
/// block — a line the user is told to paste is not a safer place for a `$(…)`
/// than a line we write for them.
pub fn manual_export_line(shim_dir: &Path) -> String {
    let dir = escape_for_double_quotes(&shim_dir.display().to_string(), &Shell::Posix);
    format!(r#"export PATH="{dir}:$PATH""#)
}

/// Split the shim dir into the `$HOME` token we emit and the remainder, which
/// is the user's data. Mirrors [`crate::paths::under_home`]'s boundary rule —
/// `/Users/youthful/x` under a home of `/Users/you` keeps its full prefix —
/// but hands back the two pieces rather than one joined string, because only
/// one of them may be escaped.
fn split_home_token(shim_dir: &Path, home: &Path) -> (&'static str, String) {
    let dir = shim_dir.display().to_string();
    let home = home.display().to_string();
    let home = home.trim_end_matches('/');
    if !home.is_empty() {
        if let Some(rest) = dir.strip_prefix(home) {
            if rest.starts_with('/') {
                return ("$HOME", rest.to_owned());
            }
        }
    }
    ("", dir)
}

/// Escape `s` for the inside of a double-quoted word in `shell`.
///
/// Double quotes stop word splitting but not expansion, so a shim dir
/// containing `$(…)` (or, in sh, a backtick) is a command the login shell runs
/// at every start — from a line secreq wrote into their rc file.
///
/// The two shells do not have the same special set, and over-escaping is not
/// the safe direction: inside fish's double quotes a backslash escapes only
/// `\`, `"` and `$`, and before anything else it stays a literal backslash. A
/// backtick escaped fish-side would therefore corrupt the path rather than
/// protect it.
fn escape_for_double_quotes(s: &str, shell: &Shell) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' | '"' | '$' => {
                out.push('\\');
                out.push(ch);
            }
            '`' if !matches!(shell, Shell::Fish) => {
                out.push('\\');
                out.push(ch);
            }
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn mode_of(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

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

    // ── S9: the shim dir lands in a shell line the user then sources ──

    /// fish's `fish_add_path` argument was unquoted, so a shim dir with a
    /// space in it split into two arguments and fish put two wrong
    /// directories on PATH — while the shim dir the user asked for was on
    /// neither.
    #[test]
    fn the_fish_block_quotes_a_shim_dir_with_a_space_in_it() {
        let home = tempfile::tempdir().unwrap();
        let p = plan(home.path(), Shell::Fish, Path::new("/opt/my tools/shims")).unwrap();

        assert!(
            p.block
                .contains(r#"fish_add_path --path --prepend "/opt/my tools/shims""#),
            "got: {}",
            p.block
        );
    }

    /// Both blocks put the directory inside double quotes, where `$` and (in
    /// sh) a backtick still start an expansion — so a shim dir containing one
    /// becomes a command the login shell runs on every start.
    #[test]
    fn the_blocks_neutralise_an_expansion_inside_the_shim_dir() {
        let home = tempfile::tempdir().unwrap();
        let dir = Path::new("/opt/$(id -u)/`whoami`/shims");

        let posix = plan(home.path(), Shell::Zsh, dir).unwrap().block;
        assert!(posix.contains(r"\$(id -u)"), "got: {posix}");
        assert!(posix.contains(r"\`whoami\`"), "got: {posix}");

        // fish has no backtick substitution, and a backslash before a
        // non-special character inside its double quotes stays literal — so
        // escaping one there would corrupt the path rather than protect it.
        let fish = plan(home.path(), Shell::Fish, dir).unwrap().block;
        assert!(fish.contains(r"\$(id -u)"), "got: {fish}");
        assert!(fish.contains("`whoami`"), "got: {fish}");
        assert!(!fish.contains(r"\`"), "got: {fish}");
    }

    /// The escaping must not reach the `$HOME` we emit ourselves — that one
    /// has to expand, which is the whole reason the block says `$HOME` and
    /// not `~` (a tilde inside double quotes is never expanded).
    #[test]
    fn the_home_token_still_expands_after_escaping() {
        let home = tempfile::tempdir().unwrap();
        let shim = home.path().join(".secreq/shims");

        assert!(plan(home.path(), Shell::Zsh, &shim)
            .unwrap()
            .block
            .contains(r#"export PATH="$HOME/.secreq/shims:$PATH""#));
        assert!(plan(home.path(), Shell::Fish, &shim)
            .unwrap()
            .block
            .contains(r#"fish_add_path --path --prepend "$HOME/.secreq/shims""#));
    }

    /// The same line reaches the user as copy-paste text when we can't place
    /// their shell, which is not a safer place for an expansion.
    #[test]
    fn the_manual_export_line_is_escaped_too() {
        assert_eq!(
            manual_export_line(Path::new("/opt/$(id -u)/shims")),
            r#"export PATH="/opt/\$(id -u)/shims:$PATH""#
        );
    }

    // ── S4/S5: `apply` rewrites a file secreq does not own ──

    /// The rc file belongs to the user, and nothing says it is UTF-8: a
    /// latin-1 comment, a `\xff` in an alias, a stray byte from a pasted
    /// snippet. `read_to_string(..).unwrap_or_default()` turned any of those
    /// into an empty string, so the write that followed **replaced the entire
    /// file** with our three-line block — and returned `Ok(true)`, so `init`
    /// reported success over a destroyed `.zshrc`.
    #[test]
    fn apply_keeps_an_rc_file_that_is_not_valid_utf8() {
        let home = tempfile::tempdir().unwrap();
        let shim = home.path().join(".local/bin");
        let rc = home.path().join(".zshrc");
        let original: &[u8] = b"# caf\xe9\nalias ll='ls -l'\n";
        fs::write(&rc, original).unwrap();

        let p = plan(home.path(), Shell::Zsh, &shim).unwrap();
        assert!(apply(&p).unwrap());

        let after = fs::read(&rc).unwrap();
        assert!(
            after.starts_with(original),
            "the user's rc was replaced, not appended to: {after:?}"
        );
        assert!(String::from_utf8_lossy(&after).contains(BEGIN_SENTINEL));
    }

    /// The same lossy read in `plan`: a non-UTF-8 rc that already carries our
    /// block reported `already_configured == false`, so a second `init`
    /// appended a second block.
    #[test]
    fn plan_finds_an_existing_block_in_an_rc_file_that_is_not_valid_utf8() {
        let home = tempfile::tempdir().unwrap();
        let shim = home.path().join(".local/bin");
        let rc = home.path().join(".zshrc");
        let mut bytes = b"# caf\xe9\n".to_vec();
        bytes.extend_from_slice(
            format!("{BEGIN_SENTINEL}\nexport PATH=\"/x:$PATH\"\n{END_SENTINEL}\n").as_bytes(),
        );
        fs::write(&rc, &bytes).unwrap();

        let p = plan(home.path(), Shell::Zsh, &shim).unwrap();

        assert!(p.already_configured, "sentinel missed behind a stray byte");
        assert!(!apply(&p).unwrap());
    }

    /// A plain `fs::write` truncates in place, so a crash or a full disk
    /// halfway through leaves the user with a `.zshrc` that is neither the old
    /// one nor the new one — a broken login shell. Replacing by rename means a
    /// reader sees one or the other. The new inode is the signature of that.
    #[test]
    fn apply_replaces_the_rc_inode_rather_than_truncating_it() {
        use std::os::unix::fs::MetadataExt;
        let home = tempfile::tempdir().unwrap();
        let shim = home.path().join(".local/bin");
        let rc = home.path().join(".zshrc");
        fs::write(&rc, "# mine\n").unwrap();
        let before = fs::metadata(&rc).unwrap().ino();

        let p = plan(home.path(), Shell::Zsh, &shim).unwrap();
        apply(&p).unwrap();

        assert_ne!(fs::metadata(&rc).unwrap().ino(), before);
        let leftovers: Vec<String> = fs::read_dir(home.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "staging litter: {leftovers:?}");
    }

    /// An rc file secreq creates got the umask's answer — 0644 under the
    /// common 022, and **0666 under the `umask 000`** that CI and container
    /// images set. A world-writable file the login shell sources is arbitrary
    /// code execution as this user.
    #[test]
    fn an_rc_file_secreq_creates_is_owner_only() {
        let home = tempfile::tempdir().unwrap();
        let shim = home.path().join(".local/bin");

        let p = plan(home.path(), Shell::Zsh, &shim).unwrap();
        apply(&p).unwrap();

        assert_eq!(mode_of(&p.config_file), 0o600);
    }

    /// An rc file the user already had keeps the mode they chose — the
    /// stage-and-rename must not republish it at the staging file's mode, the
    /// way migration 0001 once did to `wraps.json5`.
    #[test]
    fn apply_keeps_the_mode_of_an_rc_file_the_user_already_had() {
        let home = tempfile::tempdir().unwrap();
        let shim = home.path().join(".local/bin");
        let rc = home.path().join(".zshrc");
        fs::write(&rc, "# mine\n").unwrap();
        fs::set_permissions(&rc, fs::Permissions::from_mode(0o640)).unwrap();

        let p = plan(home.path(), Shell::Zsh, &shim).unwrap();
        apply(&p).unwrap();

        assert_eq!(mode_of(&rc), 0o640);
    }

    /// fish's block goes in a directory we create. `create_dir_all` asks for
    /// 0777 and lets the umask decide, so under `umask 000` we hand fish a
    /// world-writable `conf.d` — and fish sources every file in it at startup.
    /// Asserting the exact mode is what makes that visible under the umask
    /// this test actually runs with.
    #[test]
    fn a_config_dir_secreq_creates_is_owner_only() {
        let home = tempfile::tempdir().unwrap();
        let shim = home.path().join(".local/bin");

        let p = plan(home.path(), Shell::Fish, &shim).unwrap();
        apply(&p).unwrap();

        let conf_d = home.path().join(".config/fish/conf.d");
        assert_eq!(mode_of(&conf_d), 0o700, "mode {:o}", mode_of(&conf_d));
        assert_eq!(
            mode_of(&home.path().join(".config")),
            0o700,
            "an intermediate dir we created is ours too"
        );
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
