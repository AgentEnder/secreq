//! Subcommand implementations for the per-binary wrap model.
//!
//! The center of gravity is [`wrap_run`] — the external-subcommand handler
//! invoked when the user runs `secreq <BINARY> [args…]`. Everything else is
//! admin verbs that read/write `~/.secreq/wraps.json5`.
//!
//! One module per concern, so the gating path can be read without the
//! 1Password item picker scrolling past:
//!
//! - [`run`]      — `secreq <BINARY>` and `secreq run`: consent, then exec.
//! - [`binaries`] — what `execvp` would pick, minus our own shims.
//! - [`secrets`]  — `read`, `agent open`, `resolve`: the value-returning verbs.
//! - [`ssh`]      — `ssh setup` / `add` / `validate`, and op discovery.
//! - [`rules`]    — the CLI face of the daemon's auto-rules store.
//! - [`daemon`]   — the daemon's lifecycle verbs and its log tail.
//! - [`config`]   — authoring `wraps.json5`, and the one writer for it.
//! - [`init`]     — the first-time setup wizard.
//! - [`prompt`]   — the cliclack prompts the interactive flows share.
//!
//! What stays here is what more than one of them needs: loading the config,
//! building a [`proto::Ask`], and the bare-`secreq` action picker that
//! dispatches into the rest.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::daemon::client as daemon_client;
use crate::daemon::proto;
use crate::provenance;
use crate::reference::Reference;
use crate::wraps::WrapsConfig;

mod binaries;
mod config;
mod daemon;
mod init;
mod prompt;
mod rules;
mod run;
mod secrets;
mod ssh;

pub use config::{check, doctor, edit_cmd, unwrap_cmd, wrap, wraps_list, WrapArgs};
pub use daemon::{daemon_install, daemon_log_path, daemon_status, daemon_stop, daemon_tail};
pub use init::init;
pub use rules::{rules_add_wasm, rules_list, rules_rm, rules_set_enabled, rules_show};
pub use run::{run, wrap_run, WrapRunOpts};
pub use secrets::{agent_open, read, resolve};
pub use ssh::{ssh_add, ssh_setup, ssh_test, SshAddArgs};

/// `secreq pending` — open the daemon's pending-requests window. Useful
/// when you want to inspect the queue without waiting for a fresh ask.
pub fn pending() -> Result<i32> {
    daemon_client::show_window().context("could not reach the consent daemon")?;
    Ok(0)
}

/// `secreq view` — open the daemon's window in viewer mode (pinned).
/// Lets the user browse the audit log without the empty-queue
/// auto-hide kicking in two seconds later. Closing the window with the
/// close button exits viewer mode (the daemon keeps running).
pub fn view() -> Result<i32> {
    daemon_client::show_viewer().context("could not reach the consent daemon")?;
    Ok(0)
}

/// The verbs offered by the bare-`secreq` action picker. Kept in dispatch
/// order — the first item is the default the cursor lands on, so a bare
/// `secreq` + Enter opens the viewer.
#[derive(Clone, PartialEq, Eq)]
enum MenuAction {
    View,
    Wraps,
    Rules,
    Pending,
    SshSetup,
    Init,
    Quit,
}

/// Bare `secreq` in an interactive terminal: present an action picker and
/// dispatch into the chosen verb. Non-TTY invocations never reach here —
/// `cli::run` keeps the exit-2 usage hint for shims, pipes, and CI.
pub fn interactive_menu(config_path: Option<&Path>, assume_yes: bool) -> Result<i32> {
    crate::term::soft_reset();
    cliclack::intro("secreq — what do you want to do?")?;
    let action = cliclack::select("Select an action")
        .item(MenuAction::View, "Open the viewer window", "view")
        .item(MenuAction::Wraps, "List configured wraps", "wraps")
        .item(MenuAction::Rules, "Manage auto-rules", "rules")
        .item(MenuAction::Pending, "Open pending requests", "pending")
        .item(MenuAction::SshSetup, "Set up the SSH agent", "ssh setup")
        .item(MenuAction::Init, "Run first-time setup", "init")
        .item(MenuAction::Quit, "Quit", "")
        .interact()
        .context("interactive selection failed (need a real terminal)")?;

    match action {
        MenuAction::View => view(),
        MenuAction::Wraps => wraps_list(config_path),
        MenuAction::Rules => rules_list(),
        MenuAction::Pending => pending(),
        MenuAction::SshSetup => ssh_setup(None, false, assume_yes, config_path),
        MenuAction::Init => init(config_path, None),
        MenuAction::Quit => {
            cliclack::outro("Nothing to do — bye.")?;
            Ok(0)
        }
    }
}

/// Load and merge built-in providers in. The caller can pass `None` to use
/// the default config path. We don't error if the file doesn't exist — the
/// wrap-run path treats "missing config" as "no wraps configured."
fn load_config_or_default(config_path: Option<&Path>) -> Result<WrapsConfig> {
    let path = resolve_config_path(config_path)?;
    let mut config = if path.is_file() {
        WrapsConfig::load(&path)?
    } else {
        WrapsConfig::default()
    };
    config.merge_builtin_providers();
    Ok(config)
}

fn resolve_config_path(config_path: Option<&Path>) -> Result<PathBuf> {
    match config_path {
        Some(p) => Ok(p.to_path_buf()),
        None => crate::paths::wraps_path(),
    }
}

/// Explicit inputs to [`build_ask`]. Lets the `x` consent path and the
/// `run` path share one Ask builder while supplying their own identity,
/// command, and remember policy.
pub(crate) struct AskSpec<'a> {
    /// `dedupe_key.wrap` — the wrap name for `x`, the fixed `"run"` for run.
    pub dedupe_wrap: String,
    /// Argv shown in the consent prompt (never values).
    pub command: Vec<String>,
    /// The `(env name, reference)` pairs to inject.
    pub refs: &'a [(String, Reference)],
    /// `$reason` carried onto each `SecretAsk`.
    pub reason: Option<String>,
    /// Whether `ApproveRemember` may persist an approval (`true` for `x`).
    pub allow_remember: bool,
    /// `--no-remember`: prompt even on a cache hit, and persist nothing.
    pub ignore_remembered: bool,
}

/// Build the daemon [`proto::Ask`] from explicit pieces. Pure — no I/O
/// beyond reading the providers snapshot already loaded into `config`.
///
/// Note the anchor's [`provenance::ProcessIdentity`] falls back to a zeroed
/// pair when the caller chain is empty. The `x` path guards against that case
/// *before* calling here (a meaningless dedupe key is a fail-closed condition
/// for `x`); a future `run` caller is the only one that would ever rely on the
/// fallback. Either way the daemon replaces it from its own walk of the socket
/// peer (`server::adopt_peer_provenance`).
pub(crate) fn build_ask(
    spec: AskSpec<'_>,
    callers: &[provenance::Caller],
    cwd: &Path,
    config: &WrapsConfig,
) -> proto::Ask {
    let mut providers = HashMap::new();
    let mut secrets: Vec<proto::SecretAsk> = Vec::new();
    for (name, reference) in spec.refs {
        // Include the provider definition the daemon will run. Built-ins
        // are overlaid by `load_config_or_default`, so they're in here too.
        if let Some(p) = config.providers.get(&reference.provider) {
            providers.insert(reference.provider.clone(), to_wire_provider(p));
        }
        secrets.push(proto::SecretAsk {
            name: name.clone(),
            provider: reference.provider.clone(),
            locator: reference.locator.clone(),
            default: None,
            description: None,
            reason: spec.reason.clone(),
            requested_by: vec![],
        });
    }

    let parent = callers.first();
    proto::Ask {
        command: spec.command,
        dedupe_key: proto::DedupeKey {
            wrap: spec.dedupe_wrap,
            anchor: proto::AskAnchor::Process(provenance::ProcessIdentity {
                pid: parent.map_or(0, |p| p.pid),
                start_time: parent.map_or(0, |p| p.start_time),
            }),
            subject_digest: None,
        },
        subject: proto::AskSubject::Wrap(proto::WrapSubject {
            cwd: cwd.display().to_string(),
            // The daemon re-walks from the socket peer and replaces both this
            // chain and this flag (`adopt_peer_provenance`), because a
            // client's account of its own ancestry is a claim. Nothing a
            // client writes here is ever what the prompt renders.
            callers_truncated: false,
            callers: callers
                .iter()
                .map(|c| proto::Caller {
                    pid: c.pid,
                    name: c.name.clone(),
                    command: c.command.clone(),
                    start_time: c.start_time,
                    exe: c.exe.clone(),
                })
                .collect(),
            secrets,
            providers,
            allow_remember: spec.allow_remember,
            ignore_remembered: spec.ignore_remembered,
            // Default to false (always-prompt). The `run` path sets it on the
            // returned ask when it detects it's nested under another run.
            nested_run: false,
        }),
    }
}

fn to_wire_provider(p: &crate::manifest::Provider) -> proto::WireProvider {
    proto::WireProvider {
        name: p.name.clone(),
        retrieve: p.retrieve.clone(),
        retrieve_batch: p.retrieve_batch.as_ref().map(|b| proto::WireBatchRetrieve {
            command: b.command.clone(),
            env_value_template: b.env_value_template.clone(),
        }),
    }
}

fn which_on_path(program: &str) -> bool {
    if program.contains('/') {
        return Path::new(program).exists();
    }
    let Some(paths) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&paths).any(|dir| dir.join(program).exists())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_ask_sets_identity_command_and_remember() {
        use crate::reference::Reference;
        let refs = vec![(
            "DATABASE_URL".to_owned(),
            Reference::parse("secret://op/Work/PG/url").unwrap(),
        )];
        let callers = vec![provenance::Caller {
            pid: 42,
            name: "zsh".to_owned(),
            command: "zsh".to_owned(),
            exe: None,
            start_time: 7,
        }];
        let config = WrapsConfig::default(); // providers map may be empty here
        let ask = build_ask(
            AskSpec {
                dedupe_wrap: "run".to_owned(),
                command: vec!["./deploy.sh".to_owned(), "--prod".to_owned()],
                refs: &refs,
                reason: None,
                allow_remember: false,
                ignore_remembered: false,
            },
            &callers,
            std::path::Path::new("/tmp/proj"),
            &config,
        );
        assert_eq!(ask.dedupe_key.wrap, "run");
        assert_eq!(ask.command, vec!["./deploy.sh", "--prod"]);
        assert!(!ask.allow_remember());
        assert_eq!(ask.secrets().len(), 1);
        assert_eq!(ask.secrets()[0].name, "DATABASE_URL");
        assert_eq!(ask.secrets()[0].provider, "op");
        assert_eq!(ask.secrets()[0].locator, "Work/PG/url");
        assert_eq!(
            ask.dedupe_key.anchor,
            proto::AskAnchor::Process(provenance::ProcessIdentity {
                pid: 42,
                start_time: 7,
            })
        );
    }
}
