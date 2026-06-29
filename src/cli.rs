//! Command-line surface for the per-binary wrap model.
//!
//! Admin verbs (`init`, `wrap`, `unwrap`, `wraps`, `check`, `doctor`,
//! `edit`) are parsed by clap. Wrap-and-run is the explicit `x` subcommand:
//! `secreq x <wrap> [args…]` (via [`commands::wrap_run`]) — that's what the
//! PATH shims `exec`.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use crate::commands::{self, SshAddArgs, WrapArgs, WrapRunOpts};
use crate::ssh_setup;

/// `op run`, but for every secret store you own — per-binary CLI wrapping
/// with provenance-aware consent.
#[derive(Parser)]
#[command(
    name = "secreq",
    version,
    about,
    long_about = None,
)]
struct Cli {
    /// Use a specific config file instead of `$XDG_CONFIG_HOME/secreq/wraps.json5`.
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Skip output masking. The wrapped binary still runs with secrets in
    /// its env; only redaction of its stdout/stderr is disabled.
    /// Applies only to wrap-and-run, not admin verbs.
    #[arg(long, global = true)]
    raw: bool,

    /// Auto-approve without prompting. Composes through nested runs.
    #[arg(long, short = 'y', global = true)]
    yes: bool,

    /// Don't read or write the remembered-approval cache.
    #[arg(long, global = true)]
    no_remember: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// First-time setup: pick the shim dir and (optionally) wire it into PATH.
    Init {
        /// Default shim dir to suggest (overrides `~/.secreq/shims`).
        #[arg(long)]
        shim_dir: Option<PathBuf>,
    },

    /// Add (or update) a wrap for a binary; installs the PATH shim.
    Wrap {
        /// The binary name to wrap, e.g. `gh`.
        binary: String,
        /// `--env NAME=secret://provider/locator`. Repeatable. If none given,
        /// runs the interactive flow.
        #[arg(long = "env", value_name = "NAME=REF")]
        envs: Vec<String>,
        /// Reason to show in the consent prompt.
        #[arg(long)]
        reason: Option<String>,
    },

    /// Remove a wrap (config entry + shim).
    Unwrap {
        /// The binary name.
        binary: String,
    },

    /// List configured wraps.
    Wraps,

    /// Manage secreq's SSH agent: configure identities, wire SSH clients to
    /// the agent socket, and verify that signing works.
    Ssh {
        #[command(subcommand)]
        action: SshAction,
    },

    /// Validate the config.
    Check,

    /// `check` plus confirm every used provider's CLI is installed.
    Doctor,

    /// Open the config in `$EDITOR`.
    Edit,

    /// Run or manage the consent daemon. Bare `secreq daemon` ensures a
    /// daemon is running in the background (spawning one if needed) and
    /// then tails its log until you Ctrl-C — handy for watching the
    /// consent flow live. Use `--fg` to run the daemon in the foreground
    /// in this process instead (the form auto-spawned by wraps).
    /// `secreq daemon stop` tells a running daemon to exit, which also
    /// clears every remembered approval (the cache is in-memory only by
    /// design). `secreq daemon status` reports whether one is running.
    /// `secreq daemon log-path` prints the log file path.
    Daemon {
        /// Run the daemon in the foreground in this process instead of
        /// starting a background daemon and tailing its log.
        #[arg(long)]
        fg: bool,
        #[command(subcommand)]
        action: Option<DaemonAction>,
    },

    /// Open the consent daemon's pending-requests window. Auto-spawns
    /// the daemon if it isn't running.
    Pending,

    /// Open the daemon's window in viewer mode — pinned so the
    /// auto-hide doesn't fire while you browse the audit log. Lands
    /// on the Audit tab; switch to Pending via the tab bar if you
    /// want to act on queued requests. Auto-spawns the daemon if it
    /// isn't running.
    View,

    /// Manage auto-approve / auto-deny rules. Rules are created from
    /// the consent window's Rules tab (or by hand-editing the rules
    /// file). The CLI surface here covers the headless management
    /// path: list, inspect, enable/disable, delete.
    Rules {
        #[command(subcommand)]
        action: Option<RulesAction>,
    },

    /// Internal: run the consent-window child process. The daemon
    /// spawns one of these whenever the user needs to see the
    /// consent UI. Not meant to be invoked by users directly — if
    /// the daemon isn't running, this will fail to connect.
    #[command(hide = true)]
    ConsentWindow {
        /// Open the window floating above other apps. The daemon sets
        /// this when the window is spawned to demand a decision (a wrap
        /// run or an SSH-agent sign), and omits it for `secreq view`.
        #[arg(long)]
        always_on_top: bool,
    },

    /// Internal: run the always-on-top pending-requests badge child.
    /// The daemon spawns one of these whenever requests are awaiting a
    /// decision, so a backgrounded consent window can't be forgotten.
    /// Not meant to be invoked by users directly.
    #[command(hide = true)]
    PendingBadge,

    /// Run a wrapped binary through secreq: consent → inject secrets → exec
    /// the real binary with output masking. This is what the PATH shims call
    /// (`exec secreq x <wrap> "$@"`). Run it directly to wrap a one-off.
    X {
        /// The wrap (binary) name, e.g. `gh`.
        wrap: String,
        /// Arguments forwarded to the wrapped binary.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

/// Subcommands under `secreq ssh …`: configure an identity, wire clients to
/// the agent socket, and prove the agent can sign.
#[derive(Subcommand)]
enum SshAction {
    /// Wire SSH clients at secreq's agent socket by writing a managed
    /// block to `~/.ssh/config` (`IdentityAgent`) or your shell rc
    /// (`SSH_AUTH_SOCK`). Pick the method with `--method`, or get an
    /// interactive prompt when it's omitted. `--undo` strips the block
    /// back out.
    Setup {
        /// Which file to wire: `ssh-config` (`~/.ssh/config`
        /// `IdentityAgent`) or `shell-rc` (`SSH_AUTH_SOCK` export).
        /// Omit to choose interactively.
        #[arg(long, value_enum)]
        method: Option<SshMethod>,
        /// Remove the managed block instead of adding it.
        #[arg(long)]
        undo: bool,
    },

    /// Add (or overwrite) an SSH identity in `wraps.json5`. The agent serves
    /// this identity once the daemon is running. The public key is stored
    /// inline; the private key is a `secret://provider/locator` reference
    /// resolved only at sign time. Omit `--public-key`/`--private-key` to
    /// resolve them interactively (with 1Password `op` discovery when on
    /// PATH). Pass both for a fully non-interactive run.
    Add {
        /// The identity name (the key under the `ssh` block), e.g. `github`.
        name: String,
        /// The OpenSSH public key: a path to a `.pub` file, or the literal
        /// `ssh-… / ecdsa-… / sk-…` line. Prompted for if omitted.
        #[arg(long, value_name = "PATH-OR-LITERAL")]
        public_key: Option<String>,
        /// The private key reference, `secret://provider/locator`. Prompted
        /// for (with `op` discovery) if omitted.
        #[arg(long, value_name = "secret://…")]
        private_key: Option<String>,
        /// Reason shown in the consent prompt when this identity signs.
        #[arg(long)]
        reason: Option<String>,
        /// Overwrite an existing identity of the same name.
        #[arg(long)]
        force: bool,
    },

    /// Prove the agent can sign with a configured SSH identity. Connects to
    /// the agent socket, lists identities, then asks the agent to sign a fixed
    /// test message with the key and verifies the returned signature against
    /// its public half — exercising the real consent → resolve → sign path.
    /// With no `<name>`, validates every configured identity. Signing is a
    /// real sign, so it may prompt for consent (and a biometric). Exits 0 only
    /// if every validated identity verifies.
    Validate {
        /// The identity name to validate (the key under the `ssh` block). Omit
        /// to validate every configured identity.
        name: Option<String>,
    },
}

/// Which config file `secreq ssh setup` should wire the agent into. Mirrors
/// [`ssh_setup::Method`] as a clap `ValueEnum` so it parses `--method`.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum SshMethod {
    /// `~/.ssh/config` with a `Host * / IdentityAgent` stanza.
    SshConfig,
    /// The shell rc file with an `SSH_AUTH_SOCK` export.
    ShellRc,
}

impl From<SshMethod> for ssh_setup::Method {
    fn from(m: SshMethod) -> Self {
        match m {
            SshMethod::SshConfig => ssh_setup::Method::SshConfig,
            SshMethod::ShellRc => ssh_setup::Method::ShellRc,
        }
    }
}

#[derive(Subcommand)]
enum RulesAction {
    /// One-line listing of every rule with its decide direction and
    /// enabled state. Default action for `secreq rules`.
    List,
    /// Show one rule in full (every match field, trained_secrets,
    /// deny_message, created_at). `target` matches by id, falling
    /// back to exact name.
    Show { target: String },
    /// Set `enabled = true` on a rule.
    Enable { target: String },
    /// Set `enabled = false` on a rule. The rule stays in the file;
    /// re-enable later without re-typing.
    Disable { target: String },
    /// Delete a rule by id or exact name.
    Rm { target: String },
}

#[derive(Subcommand)]
enum DaemonAction {
    /// Stop the running daemon. Clears the in-memory approvals cache —
    /// the next wrap invocation auto-spawns a fresh daemon.
    Stop {
        /// Skip the graceful protocol and SIGKILL the daemon outright.
        /// Use when the daemon is unresponsive (wedged UI, hung socket
        /// thread). Also removes the pidfile + socket, which the
        /// killed process can no longer clean up itself.
        #[arg(long, short = 'f')]
        force: bool,
    },
    /// Report whether a daemon is running, without spawning one. Prints the
    /// pid, the running build (flagging a stale daemon whose build differs
    /// from this CLI's), and the socket + log paths. Exits 0 when a daemon is
    /// running and 3 when none is, so scripts can branch on it.
    Status,
    /// Print the path of the daemon's persistent log file and exit.
    /// Does not start a daemon.
    LogPath,
    /// Install a per-user login service that runs the daemon at login and
    /// keeps it alive (launchd LaunchAgent on macOS, systemd `--user` unit
    /// on Linux). This is what keeps the SSH agent socket live for incoming
    /// connections. `--undo` unloads and removes the service.
    Install {
        /// Unload and remove the login service instead of installing it.
        #[arg(long)]
        undo: bool,
    },
}

/// Parse args, dispatch, return the process exit code.
pub fn run() -> i32 {
    let cli = Cli::parse();
    let config = cli.config.as_deref();

    let result = match cli.command {
        Some(Command::Init { shim_dir }) => commands::init(config, shim_dir),
        Some(Command::Wrap {
            binary,
            envs,
            reason,
        }) => commands::wrap(
            WrapArgs {
                binary,
                reason,
                envs,
            },
            config,
        ),
        Some(Command::Ssh {
            action: SshAction::Setup { method, undo },
        }) => commands::ssh_setup(method.map(ssh_setup::Method::from), undo, cli.yes, config),
        Some(Command::Ssh {
            action:
                SshAction::Add {
                    name,
                    public_key,
                    private_key,
                    reason,
                    force,
                },
        }) => commands::ssh_add(
            SshAddArgs {
                name,
                public_key,
                private_key,
                reason,
                force,
            },
            cli.yes,
            config,
        ),
        Some(Command::Ssh {
            action: SshAction::Validate { name },
        }) => commands::ssh_test(name, config),
        Some(Command::Unwrap { binary }) => commands::unwrap_cmd(&binary, config),
        Some(Command::Wraps) => commands::wraps_list(config),
        Some(Command::Check) => commands::check(config),
        Some(Command::Doctor) => commands::doctor(config),
        Some(Command::Edit) => commands::edit_cmd(config),
        Some(Command::Daemon { fg, action: None }) => {
            if fg {
                crate::daemon::run()
            } else {
                commands::daemon_tail()
            }
        }
        Some(Command::Daemon {
            action: Some(DaemonAction::Stop { force }),
            ..
        }) => commands::daemon_stop(force),
        Some(Command::Daemon {
            action: Some(DaemonAction::Status),
            ..
        }) => commands::daemon_status(),
        Some(Command::Daemon {
            action: Some(DaemonAction::LogPath),
            ..
        }) => commands::daemon_log_path(),
        Some(Command::Daemon {
            action: Some(DaemonAction::Install { undo }),
            ..
        }) => commands::daemon_install(undo, cli.yes),
        Some(Command::Pending) => commands::pending(),
        Some(Command::View) => commands::view(),
        Some(Command::Rules { action }) => match action {
            None | Some(RulesAction::List) => commands::rules_list(),
            Some(RulesAction::Show { target }) => commands::rules_show(&target),
            Some(RulesAction::Enable { target }) => commands::rules_set_enabled(&target, true),
            Some(RulesAction::Disable { target }) => commands::rules_set_enabled(&target, false),
            Some(RulesAction::Rm { target }) => commands::rules_rm(&target),
        },
        Some(Command::ConsentWindow { always_on_top }) => crate::daemon::child::run(always_on_top),
        Some(Command::PendingBadge) => crate::daemon::badge::run(),
        Some(Command::X { wrap, args }) => commands::wrap_run(
            &wrap,
            &args,
            WrapRunOpts {
                raw: cli.raw,
                no_remember: cli.no_remember,
                assume_yes: cli.yes,
            },
            config,
        ),
        None => {
            // `secreq` with no args: short usage hint.
            eprintln!("secreq: missing command. Try `secreq --help` or `secreq x <binary>`.");
            return 2;
        }
    };

    match result {
        Ok(code) => code,
        Err(err) => {
            eprintln!("secreq: error: {err:#}");
            1
        }
    }
}
