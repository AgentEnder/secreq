//! Observer-aware wrapper around the existing SSH setup command.
//!
//! `ssh.rs` owns identity discovery and client wiring. This module adds the
//! optional PATH observer as a post-step without teaching that already-large
//! command about the SSH-agent protocol's progress limitation. The observer is
//! installed only when a Secreq-managed SSH wiring block actually exists after
//! setup, so declining a fresh setup does not silently create a shim.

use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::ssh_setup;

/// Run the existing setup flow, then reconcile the optional `ssh` PATH
/// observer with the wiring that remains on disk.
///
/// Observer failures are warnings, never setup failures: the observer only
/// explains a pending signature on stderr. `agent.sock` remains the security
/// boundary and must work identically when the shim cannot be installed.
pub fn ssh_setup(
    method: Option<ssh_setup::Method>,
    undo: bool,
    assume_yes: bool,
    config_path: Option<&Path>,
) -> Result<i32> {
    let code = super::ssh::ssh_setup(method, undo, assume_yes, config_path)?;
    if code != 0 {
        return Ok(code);
    }

    let config = match super::load_config_or_default(config_path) {
        Ok(config) => config,
        Err(err) => {
            cliclack::log::warning(crate::term::wrap_log_text(&format!(
                "SSH is configured, but the wait observer could not read the config to find its shim directory: {err:#}"
            )))?;
            return Ok(code);
        }
    };
    let Some(shim_dir) = config.shim_dir.as_deref() else {
        if !undo && managed_ssh_wiring_exists() {
            cliclack::log::warning(crate::term::wrap_log_text(
                "SSH is configured, but no shim_dir is set, so pending SSH approvals cannot be surfaced to the calling command. Run `secreq init` to configure PATH shims.",
            ))?;
        }
        return Ok(code);
    };

    let wiring_exists = managed_ssh_wiring_exists();
    if undo {
        // `ssh setup` supports both ssh-config and shell-rc wiring. If the
        // user configured both and undoes only one, keep the observer while
        // the other managed block still points clients at Secreq.
        if !wiring_exists {
            match crate::ssh_observer::remove_shim(shim_dir) {
                Ok(true) => cliclack::log::success(crate::term::wrap_log_text(
                    "Removed the Secreq SSH wait observer from PATH.",
                ))?,
                Ok(false) => {}
                Err(err) => cliclack::log::warning(crate::term::wrap_log_text(&format!(
                    "SSH agent wiring was removed, but the wait observer could not be removed: {err:#}"
                )))?,
            }
        }
        return Ok(code);
    }

    if !wiring_exists {
        // The interactive setup was declined (or no managed block survived),
        // so do not create a side-effect the user did not approve.
        return Ok(code);
    }

    match crate::ssh_observer::install_shim(shim_dir) {
        Ok(path) => {
            cliclack::log::success(crate::term::wrap_log_text(&format!(
                "Installed the SSH wait observer at {}.",
                crate::daemon::ui::abbreviate_home(&path.display().to_string())
            )))?;
            if !crate::path_setup::path_includes(shim_dir) {
                cliclack::log::warning(crate::term::wrap_log_text(&format!(
                    "{} is not on the current PATH, so SSH approval status will not be visible until a shell that includes the shim directory is started.",
                    crate::daemon::ui::abbreviate_home(&shim_dir.display().to_string())
                )))?;
            }
        }
        Err(err) => {
            cliclack::log::warning(crate::term::wrap_log_text(&format!(
                "SSH agent wiring is active, but the optional wait observer could not be installed: {err:#}. SSH signing still works; commands may remain silent while approval is pending."
            )))?;
        }
    }

    Ok(code)
}

/// True when either supported setup method currently has Secreq's managed
/// SSH-agent block. The observer belongs to the *wiring*, not to one method,
/// which is what lets undoing one of two configured methods leave it alone.
fn managed_ssh_wiring_exists() -> bool {
    let Some(home) = dirs::home_dir() else {
        return false;
    };
    if ssh_setup::block_in_file(&home.join(".ssh/config")).is_some() {
        return true;
    }

    shell_rc_path(&home).is_some_and(|path| ssh_setup::block_in_file(&path).is_some())
}

fn shell_rc_path(home: &Path) -> Option<PathBuf> {
    let shell = crate::path_setup::detect_shell();
    crate::path_setup::shell_config_path(home, &shell)
}
