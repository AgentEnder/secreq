//! Command-line surface for the per-binary wrap model.
//!
//! Admin verbs (`init`, `wrap`, `unwrap`, `wraps`, `check`, `doctor`,
//! `edit`) are parsed by clap. Wrap-and-run is the explicit `x` subcommand:
//! `secreq x <wrap> [args…]` (via [`commands::wrap_run`]) — that's what the
//! PATH shims `exec`.

use std::io::IsTerminal;
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use crate::commands::{self, SshAddArgs, WrapArgs, WrapRunOpts};
use crate::ssh_setup;

/// Long `--version` output: the crate semver plus the compile-time
/// [`crate::BUILD_ID`], so a released binary self-reports exactly which
/// commit it was cut from (`secreq --version`). `-V` still prints the bare
/// semver. This is the load-bearing "stamp the build id into the artifact"
/// contract the release workflow verifies against the tagged commit.
const LONG_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (build ",
    env!("SECREQ_BUILD_ID"),
    ")"
);

/// `op run`, but for every secret store you own: per-binary CLI wrapping
/// with provenance-aware consent.
#[derive(Parser)]
#[command(
    name = "secreq",
    version,
    long_version = LONG_VERSION,
    about,
    long_about = None,
)]
struct Cli {
    /// Use a specific config file instead of `~/.secreq/wraps.json5`.
    /// For `x` use `--sq-config`.
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Skip output masking. The wrapped binary still runs with secrets in
    /// its env; only redaction of its stdout/stderr is disabled.
    /// Applies only to `run`, not admin verbs; for `x` use `--sq-raw`.
    #[arg(long, global = true)]
    raw: bool,

    /// Auto-approve without prompting. Composes through nested runs.
    /// For `x` use `--sq-yes`.
    #[arg(long, short = 'y', global = true)]
    yes: bool,

    /// Don't read or write the remembered-approval cache.
    /// For `x` use `--sq-no-remember`.
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
        #[arg(long, value_name = "PATH")]
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

    /// Manage scoped secret agent sockets: the host-side end of serving
    /// `secret://` refs to a guest VM instead of copying tokens into it.
    Agent {
        #[command(subcommand)]
        action: AgentAction,
    },

    /// Validate the config.
    Check,

    /// `check` plus confirm every used provider's CLI is installed.
    Doctor,

    /// Open the config in `$EDITOR`.
    Edit,

    /// Inspect and roll back config migrations.
    ///
    /// secreq migrates its own config on first run after an upgrade, taking a
    /// snapshot beforehand. This is how you get back to one.
    Migrate {
        #[command(subcommand)]
        action: MigrateAction,
    },

    /// Run or manage the consent daemon. Bare `secreq daemon` ensures a
    /// daemon is running in the background (spawning one if needed) and
    /// then tails its log until you Ctrl-C, which is handy for watching the
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

    /// Open the manager window: the persistent surface holding your
    /// auto-rules and the audit log. Lands on Audit; a segmented
    /// control switches to Rules. It never holds a pending decision
    /// (that is the prompt window's job, `secreq pending`), so
    /// browsing history never blocks a waiting request. Auto-spawns
    /// the daemon if it isn't running.
    #[command(visible_alias = "ui")]
    View,

    /// Manage auto-approve / auto-deny rules. Declarative rules are
    /// created from the manager window's Rules view (or by hand-editing
    /// the rules file); compiled wasm rule modules are registered here
    /// with `add-wasm`. The CLI surface covers the headless management
    /// path: list, inspect, enable/disable, delete, add-wasm.
    Rules {
        #[command(subcommand)]
        action: Option<RulesAction>,
    },

    /// Internal: run the consent-prompt child process. The daemon
    /// spawns one of these whenever a decision is demanded (a wrap run
    /// or an SSH-agent sign). Not meant to be invoked by users directly.
    /// If the daemon isn't running, this will fail to connect.
    #[command(hide = true)]
    ConsentWindow {
        /// Open the window floating above other apps. The daemon always
        /// sets this, because the prompt exists to demand a decision.
        #[arg(long)]
        always_on_top: bool,
    },

    /// Internal: run the manager-window child process (the persistent
    /// Rules + Audit surface). The daemon spawns one on `secreq view`
    /// or when the prompt's "Open Manager…" link is clicked. Not meant
    /// to be invoked by users directly.
    #[command(hide = true)]
    ManagerWindow {
        /// Which view to open on. Omitted → Rules, or Audit when the
        /// daemon's snapshot carries viewer mode.
        #[arg(long, value_parser = ["rules", "audit"])]
        view: Option<String>,
    },

    /// Internal: run the always-on-top pending-requests badge child.
    /// The daemon spawns one of these whenever requests are awaiting a
    /// decision, so a backgrounded consent window can't be forgotten.
    /// Not meant to be invoked by users directly.
    #[command(hide = true)]
    PendingBadge,

    /// Run a wrapped binary through secreq: consent → inject secrets → exec
    /// the real binary with output masking. This is what the PATH shims call
    /// (`exec '<path to secreq>' x '<wrap>' "$@"` — the shim names secreq by
    /// absolute path so it cannot be hijacked by a `secreq` earlier on the
    /// caller's PATH). `x` owns no ordinary flags: everything
    /// after the wrap name is forwarded to the binary verbatim (so
    /// `<wrap> --help` reaches the binary, not secreq), and secreq's own
    /// options use the reserved `--sq-` prefix; `secreq x --sq-help` lists
    /// them. Parsed by hand in `run_x`, never by clap; this variant exists so
    /// `secreq --help` documents the verb.
    // The args below are hidden so `secreq --help` doesn't advertise a
    // placeholder, which leaves clap with no usage line worth printing.
    // Spelling it out here keeps the correction beside the thing it
    // corrects — `gen_cli_reference` reads it back rather than special-casing
    // this one command.
    #[command(override_usage = "secreq x [--sq-OPTIONS] <WRAP> [ARGS...]")]
    X {
        /// Wrap name plus forwarded args; see `secreq x --sq-help`.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, hide = true)]
        _args: Vec<String>,
    },

    /// `op run`, but for every secret store: resolve every
    /// `secret://provider/locator` reference found in the environment (the
    /// inherited environment plus any `--env-file`) through the
    /// consent daemon, then run the command with the resolved values
    /// injected and its output masked. Plain `NAME=value` entries pass
    /// through unchanged. Unlike `x`, no wrap entry is required: the
    /// references describe the secrets inline.
    Run {
        /// Load `NAME=value` lines from this file, layered *under* the
        /// inherited environment (inherited wins on conflict). Values may
        /// be `secret://provider/locator` references or plaintext.
        /// Repeatable.
        #[arg(long = "env-file", value_name = "PATH")]
        env_file: Vec<PathBuf>,
        /// For each `secret://` reference whose locator resolves to nothing,
        /// prompt for the value (masked, no echo) and write it, via the
        /// provider's `store` capability, to exactly where the locator points,
        /// so this and every later run resolves it normally. A reference whose
        /// provider is read-only (no `store` capability) fails with a clear
        /// error instead of being silently skipped. Without this flag an
        /// unresolved reference fails as before.
        #[arg(long = "prompt-unresolved")]
        prompt_unresolved: bool,
        /// The command to run, followed by its arguments.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },

    /// `op read`, but for every secret store: resolve one or more secret
    /// references and print their values as a JSON object. Each reference is
    /// `secret://provider/locator` or the bare `provider/locator` shorthand.
    /// Output is always a JSON object keyed by each ref exactly as typed,
    /// even for a single ref, so it pipes cleanly into `jq`. Resolution
    /// always goes through the consent daemon (every read is prompted and
    /// audited); there is no `--yes` bypass, by design.
    Read {
        /// The references to resolve, e.g. `secret://op/Work/key` or
        /// `op/Work/key`. At least one is required.
        #[arg(value_name = "REF", required = true)]
        refs: Vec<String>,
    },

    /// Ask the host's secreq for one secret, from inside a sandbox.
    ///
    /// This is the guest end of a scoped agent socket (`secreq agent open`
    /// opens the host end). It dials the socket named by `$SECREQ_SOCK`,
    /// the same convention as `SSH_AUTH_SOCK`, so nothing is stored in the
    /// sandbox: each use is asked for, gated by consent on the host, and
    /// audited there. `$SECREQ_SOCK` is set for you inside a brain `--vm`
    /// sandbox.
    ///
    /// The value goes to stdout and everything else to stderr, so it
    /// composes:
    ///
    ///   export GH_TOKEN="$(secreq resolve secret://op/Dev/gh/token)"
    ///
    /// Exits 0 on a release, 3 when the host denies (reason on stderr,
    /// nothing on stdout), 1 on any error.
    // See `AgentAction::Open` — the shell line above has to survive as one.
    #[command(verbatim_doc_comment)]
    Resolve {
        /// The reference to resolve, e.g. `secret://op/Dev/gh/token` or the
        /// bare `op/Dev/gh/token`. It must be one the host declared with
        /// `--allow` when it opened this socket; anything else is denied
        /// without troubling the user for a decision.
        #[arg(value_name = "REF")]
        reference: Option<String>,
        /// Print the ref names this socket may resolve, one per line, and
        /// exit. Free: listing never prompts and never releases a value.
        #[arg(long, conflicts_with = "reference")]
        list: bool,
    },
}

/// Subcommands under `secreq agent …`.
#[derive(Subcommand)]
enum AgentAction {
    /// Open a scoped, ephemeral socket that resolves `secret://` refs for a
    /// guest, and serve it until interrupted.
    ///
    /// The scope name and the allowlist are declared **here, by you, at open
    /// time**, and are immutable for the socket's life. A ref outside the
    /// allowlist is denied without a prompt (and audited), so a compromised
    /// guest can neither train you to click through nor enumerate your vault
    /// one prompt at a time. Every allowed request prompts for consent,
    /// showing the scope as the principal: a guest has no host process tree,
    /// so there is no caller chain to show.
    ///
    /// The resolved socket path is printed to stdout on its own line, so the
    /// caller can read it back rather than reconstruct it.
    ///
    /// Forward the socket into a VM the way `ssh -A` forwards an agent:
    ///
    ///   secreq agent open --scope my-vm --allow secret://op/Dev/gh/token \
    ///     --sock "$HOME/.secreq/run/my-vm.sock" &
    ///   ssh -R /run/secreq.sock:"$HOME/.secreq/run/my-vm.sock" my-vm
    //
    // Without `verbatim_doc_comment` clap rewraps the whole comment as
    // prose, which folds the `\`-continued line onto its head and prints an
    // example that does not run — in `--help` as well as in the generated
    // reference, since both read the same string.
    #[command(verbatim_doc_comment)]
    Open {
        /// The scope name shown in the consent prompt as the principal,
        /// typically the sandbox / VM name.
        #[arg(long, value_name = "NAME")]
        scope: String,
        /// A `secret://provider/locator` ref this socket may resolve.
        /// Repeatable; at least one is required. Matched exactly: there is
        /// no prefix or wildcard form, by design.
        #[arg(long = "allow", value_name = "secret://…", required = true)]
        allow: Vec<String>,
        /// Where to bind the socket. Must not already exist.
        ///
        /// Defaults to `scope-<name>.sock` in secreq's socket dir
        /// (`$XDG_RUNTIME_DIR/secreq`, else `<$SECREQ_HOME>/run`), beside the
        /// consent and SSH-agent sockets. Pass this to bind elsewhere, e.g.
        /// at a path you are about to `ssh -R` into a guest.
        ///
        /// Pick a directory only you can write. The socket is owner-only from
        /// the moment it exists, but in a shared one like `/tmp` anyone can
        /// plant a file at the path first and break the bind.
        #[arg(long, value_name = "PATH")]
        sock: Option<PathBuf>,
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
    /// its public half, exercising the real consent → resolve → sign path.
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
    Show {
        /// The rule's id, or its exact name.
        target: String,
    },
    /// Set `enabled = true` on a rule.
    Enable {
        /// The rule's id, or its exact name.
        target: String,
    },
    /// Set `enabled = false` on a rule. The rule stays in the file;
    /// re-enable later without re-typing.
    Disable {
        /// The rule's id, or its exact name.
        target: String,
    },
    /// Delete a rule by id or exact name. A wasm rule's stored module
    /// file goes with it.
    Rm {
        /// The rule's id, or its exact name.
        target: String,
    },
    /// Register a compiled wasm rule module (built with the
    /// `secreq-rule` SDK). The daemon vets the module in its sandbox,
    /// copies it into the canonical store under the secreq root, pins
    /// it by sha256, and persists the rule. A failed vetting
    /// registers nothing. The module decides approve/pass/deny per
    /// ask at evaluation time.
    AddWasm {
        /// Path to the compiled `.wasm` module.
        file: std::path::PathBuf,
        /// Rule name shown in the UI and audit log. Defaults to the
        /// module's file stem.
        #[arg(long)]
        name: Option<String>,
        /// Env-var name the rule is allowed to decide (the
        /// trained-secrets guard). Repeatable. The rule never fires
        /// for an ask requesting any name outside this set.
        #[arg(long = "secret", value_name = "NAME")]
        secret: Vec<String>,
        /// Register with NO trained-secrets snapshot: the module will
        /// be consulted for every ask across every wrap. Dangerous;
        /// required explicitly when no --secret is given.
        #[arg(long, conflicts_with = "secret")]
        all_secrets: bool,
    },
}

#[derive(Subcommand)]
enum DaemonAction {
    /// Stop the running daemon. Clears the in-memory approvals cache;
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

#[derive(Subcommand)]
enum MigrateAction {
    /// Restore the config snapshot taken before migration <LEVEL>.
    ///
    /// Use this when a downgraded secreq refuses to run because your config
    /// was migrated by a newer build. Lossy: anything added since that
    /// snapshot is discarded. The diff is shown and confirmed first, and your
    /// current config is saved alongside the snapshots before anything is
    /// overwritten.
    Restore {
        /// Migration level to go back to (the snapshot is the config as it
        /// stood *before* migration LEVEL+1 ran).
        level: u32,
    },
}

/// Help text for `secreq x`, hand-written because `x` is hand-parsed.
const X_USAGE: &str = "\
Usage: secreq x [--sq-OPTIONS] <wrap> [args…]

Run a wrapped binary through secreq: consent → inject secrets → exec the
real binary with output masking. This is what the PATH shims call
(`exec secreq x <wrap> \"$@\"`). Run it directly to wrap a one-off.

`x` owns no ordinary flags: every argument except the wrap name is forwarded
to the wrapped binary untouched, so `<wrap> --help` reaches the binary. The
options secreq keeps for itself use the reserved `--sq-` prefix and are
recognized before or after the wrap name:

      --sq-config <PATH>  Use a specific config file instead of
                          `~/.secreq/wraps.json5`
      --sq-raw            Skip output masking. The binary still runs with
                          secrets in its env; only redaction is disabled
      --sq-yes            Auto-approve without prompting
      --sq-no-remember    Don't read or write the remembered-approval cache
      --sq-help           Print this help
      --                  Stop --sq- recognition: everything after a literal
                          `--` is forwarded as-is
";

/// A parsed `secreq x` invocation: the wrap name, the argv to forward, and
/// the `--sq-*` options secreq kept for itself.
struct XInvocation {
    wrap: String,
    args: Vec<String>,
    config: Option<PathBuf>,
    opts: WrapRunOpts,
}

enum XParse {
    Help,
    Run(XInvocation),
}

/// Hand parser for `secreq x` argv (everything after the `x` token).
///
/// The first token that isn't a recognized `--sq-*` option is the wrap name;
/// every other unrecognized token is forwarded verbatim — including tokens
/// that look like flags. `--sq-*` options are recognized before or after the
/// wrap name (the shim prepends `x <wrap>`, so a user's `gh --sq-raw …`
/// arrives with the option after the wrap name). An unrecognized `--sq-*`
/// token is an error, not a forward: the prefix is reserved so a typo can't
/// silently change which process receives the flag.
fn parse_x_argv(mut argv: impl Iterator<Item = String>) -> Result<XParse, String> {
    let mut wrap: Option<String> = None;
    let mut args: Vec<String> = Vec::new();
    let mut config: Option<PathBuf> = None;
    let (mut raw, mut yes, mut no_remember) = (false, false, false);
    let mut extracting = true;

    while let Some(tok) = argv.next() {
        if extracting {
            match tok.as_str() {
                "--sq-help" => return Ok(XParse::Help),
                "--sq-raw" => {
                    raw = true;
                    continue;
                }
                "--sq-yes" => {
                    yes = true;
                    continue;
                }
                "--sq-no-remember" => {
                    no_remember = true;
                    continue;
                }
                "--sq-config" => {
                    let value = argv
                        .next()
                        .ok_or_else(|| "--sq-config requires a value".to_owned())?;
                    config = Some(PathBuf::from(value));
                    continue;
                }
                "--" => {
                    extracting = false;
                    // Before the wrap name, `--` is the conventional
                    // options/command separator and isn't forwarded; after
                    // the wrap name it belongs to the binary's own grammar.
                    if wrap.is_some() {
                        args.push(tok);
                    }
                    continue;
                }
                t if t.starts_with("--sq-config=") => {
                    config = Some(PathBuf::from(&t["--sq-config=".len()..]));
                    continue;
                }
                t if t.starts_with("--sq-") => {
                    return Err(format!(
                        "unknown option `{t}` (--sq- is reserved for secreq)"
                    ));
                }
                _ => {}
            }
        }
        match wrap {
            None => wrap = Some(tok),
            Some(_) => args.push(tok),
        }
    }

    let Some(wrap) = wrap else {
        return Err("missing wrap name".to_owned());
    };
    Ok(XParse::Run(XInvocation {
        wrap,
        args,
        config,
        opts: WrapRunOpts {
            raw,
            no_remember,
            assume_yes: yes,
        },
    }))
}

/// Dispatch `secreq x` from raw argv, bypassing clap entirely.
fn run_x() -> i32 {
    match parse_x_argv(std::env::args().skip(2)) {
        Ok(XParse::Help) => {
            print!("{X_USAGE}");
            0
        }
        Ok(XParse::Run(inv)) => {
            // The migration gate for the clap-free path. `x` is a deliberate
            // foreground command — on a shim-only machine it is the only one
            // that ever runs, and service roles refuse to apply migrations —
            // so it must apply pending ones exactly like the clap-parsed
            // commands in `run` below. After parsing on purpose: `--sq-help`
            // and usage errors never touch disk.
            if let Err(e) = crate::migrate::run_pending() {
                eprintln!("secreq: {e:#}");
                return 1;
            }
            match commands::wrap_run(&inv.wrap, &inv.args, inv.opts, inv.config.as_deref()) {
                Ok(code) => code,
                Err(err) => {
                    eprintln!("secreq: error: {err:#}");
                    1
                }
            }
        }
        Err(msg) => {
            eprintln!("secreq: {msg}\n\n{X_USAGE}");
            2
        }
    }
}

/// The built clap command tree, for the reference generator and its drift
/// test.
///
/// `Cli` itself stays private: the only thing outside this module has any
/// business with is the *described* surface — names, flags and the doc
/// comments attached to them — not the parse types. `docs/cli-reference.md`
/// is rendered from exactly this, so a new subcommand or flag reaches the
/// docs by existing rather than by someone remembering to write it down.
///
/// See `examples/gen_cli_reference.rs` and `tests/cli_drift.rs`.
pub fn command() -> clap::Command {
    <Cli as clap::CommandFactory>::command()
}

/// Parse args, dispatch, return the process exit code.
pub fn run() -> i32 {
    // `secreq x` never reaches clap: everything after the wrap name belongs
    // to the wrapped binary, and clap can't express "parse nothing" — its
    // help/version flags and the global flags would eat leading tokens like
    // `<wrap> --help` (the shim path makes that the user's `--help`).
    if std::env::args().nth(1).as_deref() == Some("x") {
        return run_x();
    }

    let cli = Cli::parse();

    // The migration gate. Every entry point passes through here — including the
    // daemon and its window children, which re-exec `current_exe()` and land
    // back in this function (see `daemon::client`).
    //
    // After `Cli::parse()` on purpose: `--help` and `--version` exit inside
    // `parse()`, so they never touch disk. Failure is fatal because each
    // migration is atomic — the old state is intact and a half-migrated tree
    // that silently resolves the wrong secrets is never a thing we ship.
    //
    // Only DELIBERATE FOREGROUND commands apply migrations. Background/service
    // roles verify read-only (never apply, never stamp), so a mismatched-build
    // service can't silently bump the shared level and lock out other builds —
    // the bug this split fixes. `secreq migrate ...` bypasses the gate entirely:
    // the gate's own downgrade `bail!` is what a user runs `migrate restore` to
    // escape, so gating it would make that command unreachable.
    let gate = match &cli.command {
        Some(Command::Migrate { .. }) => Ok(()),
        // `resolve` also bypasses the gate, for the opposite reason: it runs
        // in a guest whose only secreq usage *is* `resolve` (dial
        // `$SECREQ_SOCK`, print). It reads no local config — the
        // host-declared scope is the principal — so the guest's migration
        // level protects nothing, no foreground command ever runs there to
        // stamp it, and verifying would brick every fresh guest. It must not
        // apply either: a guest has no business writing host-shaped state.
        //
        // Deliberately its own arm. It shares `Ok(())` with `migrate` by
        // coincidence, not by reason — merging the two patterns would leave
        // one body under two unrelated paragraphs, and the next time either
        // bypass grows a condition the arm has to be split back apart.
        #[allow(clippy::match_same_arms)]
        Some(Command::Resolve { .. }) => Ok(()),
        // Verify-only: the daemon, the host-side agent socket, and the three
        // daemon-spawned window children.
        Some(
            Command::Daemon { .. }
            | Command::Agent { .. }
            | Command::ConsentWindow { .. }
            | Command::ManagerWindow { .. }
            | Command::PendingBadge,
        ) => crate::migrate::verify_current(),
        // Everything else is a foreground command: apply pending migrations.
        _ => crate::migrate::run_pending(),
    };
    if let Err(e) = gate {
        eprintln!("secreq: {e:#}");
        return 1;
    }

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
        Some(Command::Agent {
            action: AgentAction::Open { scope, allow, sock },
        }) => commands::agent_open(&scope, &allow, sock.as_deref(), config),
        Some(Command::Unwrap { binary }) => commands::unwrap_cmd(&binary, config),
        Some(Command::Wraps) => commands::wraps_list(config),
        Some(Command::Check) => commands::check(config),
        Some(Command::Doctor) => commands::doctor(config),
        Some(Command::Edit) => commands::edit_cmd(config),
        Some(Command::Migrate {
            action: MigrateAction::Restore { level },
        }) => crate::migrate::restore(level, cli.yes),
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
            Some(RulesAction::AddWasm {
                file,
                name,
                secret,
                all_secrets,
            }) => commands::rules_add_wasm(&file, name.as_deref(), &secret, all_secrets),
        },
        Some(Command::ConsentWindow { always_on_top }) => {
            crate::daemon::child::run(crate::daemon::child::WindowKind::Prompt, always_on_top)
        }
        Some(Command::ManagerWindow { view }) => {
            let initial_view = view.as_deref().map(|v| match v {
                "audit" => crate::daemon::proto::ManagerFocus::Audit,
                _ => crate::daemon::proto::ManagerFocus::Rules,
            });
            crate::daemon::child::run(
                crate::daemon::child::WindowKind::Manager { initial_view },
                false,
            )
        }
        Some(Command::PendingBadge) => crate::daemon::badge::run(),
        // Plain `secreq x …` never gets here — `run` intercepts it before
        // clap. Reachable only as `secreq <global flags> x …`, and global
        // flags deliberately don't compose with `x`: a leading flag would be
        // indistinguishable from the wrapped binary's own argv — the exact
        // ambiguity the reserved `--sq-` prefix exists to prevent.
        Some(Command::X { .. }) => {
            eprintln!(
                "secreq: global flags don't apply to `x`; use the reserved --sq- forms after \
                 `x` instead (e.g. `secreq x --sq-yes <wrap> [args…]`; see `secreq x --sq-help`)"
            );
            return 2;
        }
        Some(Command::Run {
            env_file,
            prompt_unresolved,
            command,
        }) => commands::run(
            &command,
            &env_file,
            WrapRunOpts {
                raw: cli.raw,
                no_remember: cli.no_remember,
                assume_yes: cli.yes,
            },
            prompt_unresolved,
            config,
        ),
        // `read` is always daemon-gated: `cli.yes` is intentionally not
        // threaded through, so there is no client-side bypass for a raw
        // secret read.
        Some(Command::Read { refs }) => commands::read(&refs, config),
        // `resolve` reads no config and dials no local daemon: the host at
        // the other end of `$SECREQ_SOCK` owns every decision, so none of
        // the global flags (`--yes`, `--no-remember`, `--config`) has
        // anything to act on here.
        Some(Command::Resolve { reference, list }) => commands::resolve(reference.as_deref(), list),
        None => {
            // Bare `secreq` in a real terminal opens an action picker; a
            // non-TTY invocation (a shim, a pipe, CI) keeps the deterministic
            // usage hint so automation never blocks on stdin.
            if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
                commands::interactive_menu(config, cli.yes)
            } else {
                eprintln!("secreq: missing command. Try `secreq --help` or `secreq x <binary>`.");
                return 2;
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    /// The long `--version` string must carry both the crate semver and the
    /// compile-time build id. Released binaries are verified against this in
    /// the release workflow, so a regression here would silently ship
    /// unattributable artifacts.
    #[test]
    fn long_version_stamps_the_build_id() {
        let long = Cli::command().render_long_version();
        assert!(
            long.contains(env!("CARGO_PKG_VERSION")),
            "long --version must include the crate semver, got: {long}"
        );
        assert!(
            long.contains(crate::BUILD_ID),
            "long --version must include the build id, got: {long}"
        );
    }

    /// `-V` (short) stays the bare semver — scripts that parse it must not
    /// suddenly see the build-id suffix.
    #[test]
    fn short_version_is_the_bare_semver() {
        let short = Cli::command().render_version();
        assert!(short.contains(env!("CARGO_PKG_VERSION")));
        assert!(
            !short.contains(crate::BUILD_ID),
            "short -V must stay the bare semver, got: {short}"
        );
    }
}
