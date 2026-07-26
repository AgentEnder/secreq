//! `secreq init` — the first-time setup wizard.
//!
//! One command, five steps: lock down `~/.secreq`, pick a shim dir, get it
//! onto `PATH` via the shell's canonical config file, write `wraps.json5`,
//! and offer the SSH-agent wiring. Every step after the config write is
//! optional and non-fatal — declining SSH setup must not fail `init`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::path_setup;
use crate::shim;
use crate::wraps::WrapsConfig;

use super::config::write_config;
use super::ssh::ssh_setup_core;
use super::{prompt, resolve_config_path};

/// `secreq init` — interactive first-time setup. Picks the shim dir,
/// optionally adds it to the shell's PATH config, and writes a minimal
/// `wraps.json5`.
pub fn init(config_path: Option<&Path>, default_shim_dir: Option<PathBuf>) -> Result<i32> {
    let config_path = resolve_config_path(config_path)?;

    // The root has to be owner-only from the moment it exists, and `init` is
    // the one command that can promise it: `paths::ensure_private_dir` is
    // otherwise reached only *lazily* — from the audit writer, the daemon's
    // log and the socket bind — so every install predating that lands here
    // with whatever mode its creator left, and a fresh `umask 000` install had
    // a world-writable `~/.secreq` from the end of `init` until the daemon
    // first started. `audit.log`, `auto-rules.json5` and `wraps.json5` all
    // live in there; a rule someone else can write is a rule that approves
    // their own command.
    //
    // Here rather than in `secreq_root()`, which nearly every code path calls
    // and which should stay a path resolver rather than doing I/O and a
    // possible chmod on each one.
    let root = crate::paths::secreq_root()?;
    crate::paths::ensure_private_dir(&root)
        .with_context(|| format!("could not make {} owner-only", root.display()))?;

    crate::term::soft_reset();
    cliclack::intro("secreq init — first-time setup")?;

    // 1. Pick the shim dir. Default to a dedicated `~/.secreq/shims` so
    // we don't share a directory with anything else — no risk of another
    // tool (asdf, pip user-installs, etc.) dropping a competing `gh`
    // shim into the same dir. The dir is also brand-new on first init,
    // so the "is it on PATH?" answer is unambiguous.
    let suggested = match default_shim_dir {
        Some(dir) => dir,
        None => crate::paths::default_shims_dir()?,
    };
    let shim_dir_input = prompt::read_with_default(
        "Where should secreq drop PATH shims?",
        // `~/…`, matching how the PATH note below renders the same
        // directory. `expand_tilde` on the answer makes this round-trip, so
        // accepting the default is identical to typing the full path.
        &crate::daemon::ui::abbreviate_home(&suggested.display().to_string()),
    )?;
    let shim_dir = expand_tilde(&shim_dir_input);

    // 2. Ensure the dir exists — and is not a directory anyone else can write
    // to, since step 3 puts it on PATH permanently.
    shim::ensure_shim_dir(&shim_dir)?;

    // 3. Plan the shell-PATH block. We always run this — being "on PATH"
    // somewhere is necessary but not sufficient. What actually matters is
    // whether our sentinel block lives in the *canonical* file for this
    // shell (e.g. `.zshrc` for zsh, where it'll prepend after homebrew).
    let shell = path_setup::detect_shell();
    let home = dirs::home_dir().context("could not determine $HOME")?;
    match path_setup::plan(&home, shell.clone(), &shim_dir) {
        Ok(plan) if plan.already_configured => {
            cliclack::log::success(crate::term::wrap_log_text(&format!(
                "PATH already configured via {}; nothing to add.",
                crate::daemon::ui::abbreviate_home(&plan.config_file.display().to_string())
            )))?;
            // Even when we're already-configured, hint about stale blocks
            // sitting in non-canonical files (e.g. a pre-pivot .zshenv).
            if let Some(list) = stale_block_list(&path_setup::find_stale_blocks(
                &home,
                &shell,
                &plan.config_file,
            )) {
                cliclack::log::warning(crate::term::wrap_log_text(&format!(
                    "Found leftover secreq PATH blocks in: {list}. They're harmless but you can remove them by hand for tidiness."
                )))?;
            }
        }
        Ok(plan) => {
            // Two cases land here: (a) we're not on PATH at all, (b) we
            // are on PATH but via a non-canonical file (e.g. .zshenv from
            // before the homebrew-shadowing fix). The diagnostic differs.
            let already_on_path = path_setup::path_includes(&shim_dir);
            // Display paths as `~/…`. A real `$HOME` is long enough on its own
            // to push these lines past a terminal, and the note body must stay
            // narrow enough that nothing has to wrap mid-path.
            let shim_display = crate::daemon::ui::abbreviate_home(&shim_dir.display().to_string());
            let config_display =
                crate::daemon::ui::abbreviate_home(&plan.config_file.display().to_string());
            let preamble = if already_on_path {
                format!(
                    "{shim_display} is on PATH already, but the secreq block isn't in \
                     {config_display}. That usually means it's in an earlier-loaded file \
                     (e.g. .zshenv) where later prepends like `brew shellenv` can shadow \
                     our shim. I can append a fresh block to {config_display} so we win \
                     on PATH:",
                )
            } else {
                format!(
                    "{shim_display} isn't on PATH. I can append this to \
                     {config_display} ({shell:?}):",
                )
            };
            // The preamble interpolates two paths and, in the `already_on_path`
            // branch, runs to ~250 characters — far past any terminal. It must
            // go in the *body* (wrapped) under a fixed-width title, never as
            // the title itself: cliclack sizes the box to its longest line, so
            // a title nobody bounded is a box nobody can read. See
            // `term::wrap_note_text`.
            cliclack::note(
                "Add secreq to your PATH",
                format!(
                    "{}\n\n{}",
                    crate::term::wrap_note_text(&preamble),
                    plan.block
                ),
            )?;
            if let Some(caveat) = &plan.caveat {
                cliclack::log::warning(crate::term::wrap_log_text(caveat))?;
            }
            if let Some(list) = stale_block_list(&path_setup::find_stale_blocks(
                &home,
                &shell,
                &plan.config_file,
            )) {
                cliclack::log::warning(crate::term::wrap_log_text(&format!(
                    "Found leftover secreq PATH blocks in: {list}. The new one in {config_display} will win on PATH, but you may want to remove the old blocks by hand for tidiness.",
                )))?;
            }
            if prompt::confirm_default_yes("Append it?")? {
                path_setup::apply(&plan)?;
                cliclack::log::success(crate::term::wrap_log_text(&format!(
                    "wrote {config_display}. Open a new terminal (or `source {config_display}`) to pick it up.",
                )))?;
            } else {
                cliclack::log::info(crate::term::wrap_log_text(&format!(
                    "skipped. Add {shim_display} to PATH yourself before running `secreq wrap`.",
                )))?;
            }
        }
        Err(err) => {
            // `plan` only fails on a shell we don't recognize, and its error
            // names the shim dir — so this line carries a path and has to be
            // wrapped like every other one here.
            cliclack::log::warning(crate::term::wrap_log_text(&format!(
                "couldn't auto-configure your shell: {err:#}"
            )))?;
            // Same shape as the branch above: a short constant title, the
            // prose wrapped into the body, and the line to paste verbatim
            // under it. The export line is the one thing here that must not
            // be reflowed — `wrap_note_text` breaks at spaces, and this
            // string has them, so wrapping it would split a shell command
            // the user is being told to copy. Nor can it be shortened with
            // `abbreviate_home`: it is spelled absolute on purpose (see
            // `path_setup::manual_export_line`), because a `~` inside the
            // double quotes is not expanded and would put a directory
            // literally named `~` on PATH.
            cliclack::note(
                "Add secreq to your PATH",
                format!(
                    "{}\n\n{}",
                    crate::term::wrap_note_text(
                        "I couldn't tell which file your shell reads at startup. Add this line to it by hand, then open a new terminal:"
                    ),
                    path_setup::manual_export_line(&shim_dir)
                ),
            )?;
        }
    }

    // 4. Write the wraps file (preserving anything already there).
    let mut config = if config_path.is_file() {
        WrapsConfig::load(&config_path)?
    } else {
        WrapsConfig::default()
    };
    config.shim_dir = Some(shim_dir.clone());
    write_config(&config_path, &config)?;

    // 4b. Repair/migrate managed shims. `install` rewrites the body of any
    // shim that carries our sentinel, so reinstalling every configured wrap's
    // shim migrates stale bodies (e.g. the old `exec secreq <wrap>` form) to
    // the current `exec secreq x <wrap>` form. Only touch shims we already
    // own — a foreign file at the same name must never abort init.
    let managed: Vec<String> = config
        .wraps
        .keys()
        .filter(|name| shim::is_managed(&shim_dir, name))
        .cloned()
        .collect();
    if !managed.is_empty() {
        let refreshed = shim::reinstall_all(&shim_dir, managed)?;
        cliclack::log::success(format!("Refreshed {} managed shims.", refreshed.len()))?;
    }

    // 5. Offer SSH-agent setup. secreq doubles as a provenance-aware SSH
    // agent when the config has an `ssh` block; wiring SSH clients at its
    // socket is the same plan/confirm/apply flow as `secreq ssh setup`, so
    // we share `ssh_setup_core`. Entirely optional and non-fatal: declining
    // (or any failure, including a non-terminal `interact`) must not fail
    // `init`.
    if prompt::confirm_default_yes("Also set up secreq as your SSH agent?").unwrap_or(false) {
        if let Err(err) = ssh_setup_core(None, false, false, Some(&config_path)) {
            cliclack::log::warning(crate::term::wrap_log_text(&format!(
                "skipped SSH-agent setup: {err:#}. Run `secreq ssh setup` later to wire it."
            )))?;
        }
    }

    cliclack::outro(crate::term::wrap_log_text(&format!(
        "Wrote {}. Next: `secreq wrap <binary>`, e.g. `secreq wrap gh`.",
        crate::daemon::ui::abbreviate_home(&config_path.display().to_string())
    )))?;
    Ok(0)
}

/// Render the leftover-PATH-block list for the warning, or `None` when there
/// is nothing to warn about.
///
/// Both branches of the `plan` match report the same finding about the same
/// files, so they render it the same way — one of them used to print
/// `/Users/you/.zshenv` where the other printed `~/.zshenv`, in one command,
/// for one thing. These are prose, not shell we're asking anyone to paste, so
/// `abbreviate_home` is safe here in a way it is not for
/// `path_setup::manual_export_line`.
fn stale_block_list(stale: &[PathBuf]) -> Option<String> {
    if stale.is_empty() {
        return None;
    }
    Some(
        stale
            .iter()
            .map(|p| crate::daemon::ui::abbreviate_home(&p.display().to_string()))
            .collect::<Vec<_>>()
            .join(", "),
    )
}

fn expand_tilde(raw: &str) -> PathBuf {
    if let Some(rest) = raw.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    if raw == "~" {
        if let Some(home) = dirs::home_dir() {
            return home;
        }
    }
    PathBuf::from(raw)
}
