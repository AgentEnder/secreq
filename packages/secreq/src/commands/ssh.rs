//! `secreq ssh setup` / `ssh add` / `ssh validate` — declaring SSH
//! identities and wiring SSH clients at secreq's agent socket.
//!
//! [`ssh_setup_core`] is the guided flow (identity → auto-start → client
//! wiring → optional self-test); `secreq init` runs it as an optional final
//! step. The 1Password discovery helpers at the bottom are best-effort
//! conveniences for `ssh add` and never fail a run on their own.

use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::autostart;
use crate::path_setup;
use crate::reference::Reference;
use crate::ssh_setup;
use crate::wraps::{self, WrapsConfig};

use super::config::write_config;
use super::daemon::daemon_install_core;
use super::{load_config_or_default, prompt, resolve_config_path, which_on_path};

/// `secreq ssh setup` — wire SSH clients at secreq's agent socket (or, with
/// `--undo`, strip the managed block back out). Thin wrapper over
/// [`ssh_setup_core`], which `init` shares.
pub fn ssh_setup(
    method: Option<ssh_setup::Method>,
    undo: bool,
    assume_yes: bool,
    config_path: Option<&Path>,
) -> Result<i32> {
    ssh_setup_core(method, undo, assume_yes, config_path)?;
    Ok(0)
}

/// `secreq ssh setup` — a guided three-step onboarding flow:
///
/// 1. **Identity** — ensure the config declares at least one `ssh` identity
///    (offer `ssh add`'s interactive flow when there are none).
/// 2. **Auto-start** — offer to install the login service so the agent socket
///    is always live (the SSH agent is useless if the daemon isn't running).
/// 3. **Client wiring** — point SSH clients at the agent socket (the original
///    method-select + plan/confirm/apply block).
///
/// Used by both `secreq ssh setup` and the optional step inside `secreq init`.
///
/// ## Scripted vs. guided
///
/// When `assume_yes` is set AND an explicit `--method` was passed
/// (`method.is_some()`), the caller wants a non-interactive, scripted
/// client-wiring run: we do ONLY step 3 and never prompt for identity or
/// auto-start. This preserves `ssh setup --yes --method ssh-config` for
/// scripts and tests. Otherwise (no `--method`, or interactive), we run the
/// full guided flow.
///
/// `--undo` also strips only the client-wiring block — it never removes
/// identities or the login service. Run `secreq ssh add --force`/`secreq
/// daemon install --undo` to reverse those steps individually.
///
/// Steps 1 and 2 are best-effort: a failure or a decline there is surfaced as
/// a warning and does NOT abort step 3. A normal completion returns `Ok(())`.
pub(super) fn ssh_setup_core(
    method: Option<ssh_setup::Method>,
    undo: bool,
    assume_yes: bool,
    config_path: Option<&Path>,
) -> Result<()> {
    // Scripted path: `--yes` + explicit `--method` means "just wire the
    // client, don't prompt for identity/autostart". This is the deterministic
    // path scripts and tests rely on.
    let scripted = assume_yes && method.is_some();

    if !scripted {
        crate::term::soft_reset();
    }
    if !scripted && !undo {
        // Step 1: identity. Non-fatal — warn and continue on any error.
        if let Err(err) = ssh_setup_identity_step(config_path) {
            cliclack::log::warning(crate::term::wrap_log_text(&format!(
                "skipped the identity step: {err:#}. Add one later with `secreq ssh add`."
            )))?;
        }
        // Step 2: auto-start. Non-fatal — warn and continue on any error.
        if let Err(err) = ssh_setup_autostart_step(assume_yes) {
            cliclack::log::warning(crate::term::wrap_log_text(&format!(
                "skipped the auto-start step: {err:#}. Install it later with `secreq daemon install`."
            )))?;
        }
    }

    // Step 3: client wiring (the original flow). Always runs.
    ssh_setup_wiring_step(method, undo, assume_yes, config_path)?;

    // Optional post-step (guided, non-scripted, non-undo): offer to prove the
    // agent can actually sign. Non-fatal — a decline or failure never changes
    // the exit status.
    if !scripted && !undo {
        if let Err(err) = ssh_setup_self_test_step(config_path) {
            cliclack::log::warning(crate::term::wrap_log_text(&format!(
                "skipped the self-test: {err:#}. Run `secreq ssh validate` later to verify signing."
            )))?;
        }
    }

    Ok(())
}

/// Optional final step of the guided `ssh setup`: offer to self-test one
/// configured identity (prove the agent can sign). With one identity it tests
/// that one; with several it asks which. Skipped when no identities are
/// configured. Always non-fatal — `offer_self_test` swallows its own errors.
fn ssh_setup_self_test_step(config_path: Option<&Path>) -> Result<()> {
    let config = load_config_or_default(config_path)?;
    let names: Vec<String> = config.ssh.keys().cloned().collect();
    if names.is_empty() {
        return Ok(());
    }
    if !prompt::confirm_default_yes("Test that the agent can sign now?")? {
        return Ok(());
    }

    let chosen = if let [only] = names.as_slice() {
        only.clone()
    } else {
        let mut select = cliclack::select::<String>("Which identity should I test?");
        for name in &names {
            select = select.item(name.clone(), name.as_str(), "");
        }
        select
            .interact()
            .context("interactive selection failed (need a real terminal)")?
    };

    offer_self_test(&chosen, config_path);
    Ok(())
}

/// Step 1 of `ssh setup`: make sure an `ssh` identity is declared. With none
/// configured, offer the interactive `ssh add` flow; with some, list them and
/// offer to add another. Continues either way.
fn ssh_setup_identity_step(config_path: Option<&Path>) -> Result<()> {
    let config = load_config_or_default(config_path)?;
    if config.ssh.is_empty() {
        cliclack::log::warning(crate::term::wrap_log_text(
            "No SSH identities configured yet — the agent has nothing to serve until you add one.",
        ))?;
        if prompt::confirm_default_yes("Add an SSH identity now?")? {
            ssh_add_core(SshAddArgs::default(), false, config_path)?;
        }
    } else {
        let names = config.ssh.keys().cloned().collect::<Vec<_>>().join(", ");
        cliclack::log::info(crate::term::wrap_log_text(&format!(
            "Configured SSH identities: {names}."
        )))?;
        if cliclack::confirm("Add another identity?")
            .initial_value(false)
            .interact()
            .context("interactive confirm failed (need a real terminal)")?
        {
            ssh_add_core(SshAddArgs::default(), false, config_path)?;
        }
    }
    Ok(())
}

/// Step 2 of `ssh setup`: ensure the login service is installed so the agent
/// socket is always live. Already installed → just report it; otherwise offer
/// to install it (respecting `assume_yes` for the install confirm).
fn ssh_setup_autostart_step(assume_yes: bool) -> Result<()> {
    let platform = autostart::current_platform();
    let home = dirs::home_dir().context("could not determine $HOME")?;
    let service_file = autostart::service_file_path(&home, platform);
    if service_file.exists() {
        cliclack::log::success("Login service already installed.")?;
        return Ok(());
    }
    if prompt::confirm_default_yes("Install the login service so the agent is always running?")? {
        daemon_install_core(false, assume_yes)?;
    }
    Ok(())
}

/// Step 3 of `ssh setup`: the client-wiring block — resolve the agent socket,
/// pick the method, then plan/confirm/apply (or `--undo` strips it).
///
/// `assume_yes` skips the confirmation prompt so the command can run without
/// a terminal (and so tests can drive it deterministically).
fn ssh_setup_wiring_step(
    method: Option<ssh_setup::Method>,
    undo: bool,
    assume_yes: bool,
    config_path: Option<&Path>,
) -> Result<()> {
    let agent_sock = crate::daemon::ssh_agent::default_agent_socket_path()
        .context("could not determine the secreq SSH agent socket path")?;

    // Load the config best-effort: a missing/broken config shouldn't block
    // wiring the agent — but if it loads and has no `ssh` identities, warn
    // that there's nothing to serve yet.
    match load_config_or_default(config_path) {
        Ok(config) if config.ssh.is_empty() => {
            cliclack::log::warning(crate::term::wrap_log_text(
                "No SSH identities configured yet — setup will still wire the agent, but add an `ssh` block to wraps.json5 for it to serve keys.",
            ))?;
        }
        Ok(_) => {}
        Err(err) => {
            cliclack::log::warning(crate::term::wrap_log_text(&format!(
                "couldn't read your config ({err:#}); wiring the agent anyway."
            )))?;
        }
    }

    // Pick the method: explicit `--method`, else an interactive select.
    let method = if let Some(m) = method {
        m
    } else {
        let choice: String = cliclack::select("How should SSH find the secreq agent?")
            .item(
                "ssh-config".to_owned(),
                "Modify ~/.ssh/config (IdentityAgent)",
                "a Host * stanza pointing at the agent socket",
            )
            .item(
                "shell-rc".to_owned(),
                "Modify your shell rc (SSH_AUTH_SOCK)",
                "export SSH_AUTH_SOCK for new shells",
            )
            .interact()
            .context("interactive selection failed (need a real terminal)")?;
        if choice == "shell-rc" {
            ssh_setup::Method::ShellRc
        } else {
            ssh_setup::Method::SshConfig
        }
    };

    let home = dirs::home_dir().context("could not determine $HOME")?;
    let shell = path_setup::detect_shell();

    if undo {
        if ssh_setup::remove(&home, method, shell)? {
            cliclack::log::success("Removed the secreq SSH-agent block.")?;
        } else {
            cliclack::log::info("No secreq SSH-agent block found — nothing to remove.")?;
        }
        return Ok(());
    }

    let plan = ssh_setup::plan(&home, method, shell, &agent_sock)?;
    // Every message below names this file, so abbreviate `$HOME` once. A
    // note or log line sized by the reader's home directory is the bug
    // brain task #295 was about.
    let config_display =
        crate::daemon::ui::abbreviate_home(&plan.config_file.display().to_string());
    // One match over the plan's state decides both what we say and the verb
    // we say it with, so the two cannot disagree about which case we're in.
    let verb = match plan.block_state {
        ssh_setup::BlockState::UpToDate => {
            cliclack::log::success(crate::term::wrap_log_text(&format!(
                "{config_display} already wires the secreq SSH agent; nothing to do."
            )))?;
            return Ok(());
        }
        ssh_setup::BlockState::Stale => {
            cliclack::log::warning(crate::term::wrap_log_text(&format!(
                "{config_display} already has a secreq SSH-agent block, but it points at a \
                 different socket than the agent now uses. I'll update it in place."
            )))?;
            "update"
        }
        ssh_setup::BlockState::Absent => "write",
    };
    cliclack::note(
        format!("I'll {verb} your SSH config"),
        format!(
            "{}\n\n{}",
            crate::term::wrap_note_text(&format!("In {config_display}:")),
            plan.block
        ),
    )?;
    if let Some(caveat) = &plan.caveat {
        cliclack::log::warning(crate::term::wrap_log_text(caveat))?;
    }

    let proceed = assume_yes || prompt::confirm_default_yes(&format!("{verb} it?"))?;
    if !proceed {
        cliclack::log::info("Skipped — no files changed.")?;
        return Ok(());
    }

    ssh_setup::apply(&plan)?;
    cliclack::log::success(crate::term::wrap_log_text(&format!(
        "wrote {config_display}."
    )))?;
    cliclack::log::info(crate::term::wrap_log_text(
        "secreq's daemon must be running to serve keys — step 2 (or `secreq daemon install`) sets it to start at login. New shells / SSH sessions pick up the socket; restart your shell or run `exec $SHELL`.",
    ))?;
    cliclack::log::info(crate::term::wrap_log_text(
        "Each identity's `private_key` reference must resolve to an OpenSSH private key, e.g. `op read \"op://Vault/My Key/private key\"`.",
    ))?;
    Ok(())
}

/// Args for `secreq ssh add`.
#[derive(Debug, Clone, Default)]
pub struct SshAddArgs {
    /// The identity name (the key under the `ssh` block).
    pub name: String,
    /// The public key: a path to a `.pub` file or a literal OpenSSH line.
    pub public_key: Option<String>,
    /// The private key reference, `secret://provider/locator`.
    pub private_key: Option<String>,
    /// Reason shown in the consent prompt at sign time.
    pub reason: Option<String>,
    /// Overwrite an existing identity of the same name.
    pub force: bool,
}

/// `secreq ssh add <name>` — declare an SSH identity in `wraps.json5` so the
/// agent serves it. Mirrors [`wrap`]: load → build → insert → `write_config`.
///
/// The public key is stored inline (it isn't secret); the private key is a
/// `secret://provider/locator` reference resolved only at sign time. When
/// `--public-key` and `--private-key` are both supplied the command runs with
/// no prompts (so scripts/tests work); otherwise the missing pieces are
/// resolved interactively, with 1Password `op` discovery when it's on PATH.
pub fn ssh_add(args: SshAddArgs, assume_yes: bool, config_path: Option<&Path>) -> Result<i32> {
    ssh_add_core(args, assume_yes, config_path)?;
    Ok(0)
}

/// The reusable body of `secreq ssh add`, shared with the `ssh setup`
/// orchestrator's identity step. Returns `Ok(())` after writing the identity;
/// the standalone command wraps it to produce an exit code.
///
/// When `args.name` is empty the name is prompted for interactively — that's
/// the path the orchestrator takes (it has no name to preset).
fn ssh_add_core(args: SshAddArgs, assume_yes: bool, config_path: Option<&Path>) -> Result<()> {
    let config_path = resolve_config_path(config_path)?;
    let mut config = if config_path.is_file() {
        WrapsConfig::load(&config_path)?
    } else {
        WrapsConfig::default()
    };

    // The CLI supplies the name as a positional; the orchestrator leaves it
    // empty so we prompt for it here.
    let name = if args.name.is_empty() {
        prompt::ssh_identity_name()?
    } else {
        args.name.clone()
    };

    if config.ssh.contains_key(&name) && !args.force {
        bail!("identity `{name}` already exists; use --force to overwrite");
    }

    // Non-interactive iff both key pieces are on the command line. Tracked so
    // the op-discovery / manual prompts never fire on the scripted path.
    let non_interactive = args.public_key.is_some() && args.private_key.is_some();

    // Resolve the public key up front when supplied; otherwise leave it to be
    // filled by op discovery or a manual prompt below.
    let mut public_key: Option<String> = match &args.public_key {
        Some(raw) => Some(resolve_public_key(raw)?),
        None => None,
    };

    // Resolve the private-key reference.
    let private_key: Reference = match &args.private_key {
        Some(raw) => Reference::parse(raw).with_context(|| {
            format!("`{raw}` is not a valid `secret://provider/locator` reference")
        })?,
        None => {
            // Try op-assisted discovery (best-effort); on any failure fall
            // through to the manual prompt. When op supplies a public key and
            // none was given on the command line, capture it too.
            match op_assisted_identity(public_key.is_none())? {
                Some(found) => {
                    if public_key.is_none() {
                        public_key = found.public_key;
                    }
                    found.private_key
                }
                None => prompt::ssh_private_key_reference()?,
            }
        }
    };

    // Fill any still-missing public key via an interactive prompt.
    let public_key = if let Some(pk) = public_key {
        pk
    } else {
        if non_interactive {
            bail!("no public key supplied");
        }
        prompt::ssh_public_key()?
    };

    let identity = wraps::SshIdentity {
        reason: args.reason,
        public_key,
        private_key,
    };
    config.ssh.insert(name.clone(), identity);

    write_config(&config_path, &config)?;

    println!("Added SSH identity `{name}`.");
    println!(
        "  config: {}",
        crate::daemon::ui::abbreviate_home(&config_path.display().to_string())
    );
    println!(
        "  Ensure the private_key reference resolves to an OpenSSH private key, e.g. `op read \"op://Vault/My Key/private key\"`."
    );
    println!(
        "  secreq's daemon must be running to serve this key — run `secreq daemon install` to start it at login (or wire it via `secreq ssh setup`)."
    );

    // Optional post-step (interactive path only): offer to prove the agent can
    // actually sign with the key we just added. The fully non-interactive path
    // (`--public-key` + `--private-key`) never prompts or signs, so scripts
    // stay deterministic. A declined or failing self-test is non-fatal.
    //
    // `--yes` **skips** this rather than accepting it, which is the one place
    // in the crate where assume_yes does not mean "answer yes". Answering yes
    // here performs a *real* signature, and a real signature can park on a
    // consent prompt with nobody there to click it — so the automated answer
    // that keeps `--yes` unattended is "don't". The comment above is the
    // reason: scripted paths never sign, and `--yes` is a scripted path.
    if !non_interactive
        && !assume_yes
        && prompt::confirm_default_yes(&format!(
            "Test that the agent can sign with `{name}` now? (this performs a real signature and may prompt for approval)"
        ))
        .unwrap_or(false)
    {
        offer_self_test(&name, Some(&config_path));
    }

    Ok(())
}

/// `secreq ssh validate [<name>]` — prove the agent can sign with a configured
/// identity. Connects to the agent socket, lists identities, asks the agent to
/// sign a fixed test message with the key, and verifies the returned signature
/// against the key's public half. With no `<name>`, tests every configured
/// identity.
///
/// Signing is a *real* sign: if the daemon has no cached approval for this
/// caller it will prompt for consent (and may ask for a biometric), so running
/// the test can pop the consent window. Returns `Ok(0)` only if every tested
/// identity verified; any failure (or no identities) returns a non-zero code.
pub fn ssh_test(name: Option<String>, config_path: Option<&Path>) -> Result<i32> {
    let config = load_config_or_default(config_path)?;

    if config.ssh.is_empty() {
        bail!("no SSH identities configured; add one with `secreq ssh add <name>` first");
    }

    // Resolve the identities to test: the named one, or all of them.
    let to_test: Vec<(String, wraps::SshIdentity)> = match name {
        Some(name) => {
            let identity = config.ssh.get(&name).cloned().with_context(|| {
                format!("no SSH identity named `{name}` in the config; `secreq wraps` lists them")
            })?;
            vec![(name, identity)]
        }
        None => config
            .ssh
            .iter()
            .map(|(name, identity)| (name.clone(), identity.clone()))
            .collect(),
    };

    let agent_sock = crate::daemon::ssh_agent::default_agent_socket_path()
        .context("determining the agent socket path")?;

    println!("Signing may prompt for consent — answer the prompt if one appears.\n");

    let mut all_ok = true;
    for (name, identity) in to_test {
        let result = crate::ssh_selftest::run(&agent_sock, &identity, &name);
        all_ok &= print_self_test_result(&name, &result);
    }

    Ok(if all_ok { 0 } else { 1 })
}

/// Print a single identity's self-test outcome as a `✓`/`✗` line and report
/// whether it passed. Shared by `secreq ssh validate` and the optional
/// post-step after `ssh add`/`ssh setup` so both render the same per-identity
/// result.
fn print_self_test_result(name: &str, result: &Result<crate::ssh_selftest::SelfTest>) -> bool {
    match result {
        Ok(test) if test.listed && test.verified => {
            println!("✓ {name}: agent signed; signature verifies");
            true
        }
        Ok(test) if !test.listed => {
            println!(
                "✗ {name}: the agent didn't list this key — is the config the daemon loaded current? (restart with `secreq daemon stop`)"
            );
            false
        }
        Ok(_) => {
            println!("✗ {name}: the agent signed but the signature did not verify");
            false
        }
        Err(err) => {
            println!("✗ {name}: {err:#}");
            false
        }
    }
}

/// Offer the self-test as a NON-FATAL post-step after `ssh add`/`ssh setup`.
///
/// Resolves the agent socket, loads the identity by `key_id`, runs the
/// self-test, and prints the same `✓`/`✗` line as `secreq ssh validate`. Failure
/// is never fatal: an unreachable socket is reported as a friendly hint (the
/// daemon is probably not running yet), and a refused/unverified sign is a
/// warning. The caller's exit status is unaffected either way.
fn offer_self_test(key_id: &str, config_path: Option<&Path>) {
    let identity = match load_config_or_default(config_path) {
        Ok(config) => {
            if let Some(identity) = config.ssh.get(key_id).cloned() {
                identity
            } else {
                // The identity we just wrote is somehow gone — warn, don't fail.
                let _ = cliclack::log::warning(crate::term::wrap_log_text(&format!(
                    "couldn't find `{key_id}` in the config to self-test; skipping."
                )));
                return;
            }
        }
        Err(err) => {
            let _ = cliclack::log::warning(crate::term::wrap_log_text(&format!(
                "couldn't read the config to self-test: {err:#}"
            )));
            return;
        }
    };

    let agent_sock = match crate::daemon::ssh_agent::default_agent_socket_path() {
        Ok(path) => path,
        Err(err) => {
            let _ = cliclack::log::warning(crate::term::wrap_log_text(&format!(
                "couldn't determine the agent socket to self-test: {err:#}"
            )));
            return;
        }
    };

    println!("Signing may prompt for consent — answer the prompt if one appears.");
    let result = crate::ssh_selftest::run(&agent_sock, &identity, key_id);
    if result.is_err() && !agent_sock.exists() {
        // The socket isn't there at all: the daemon almost certainly isn't
        // running yet (the most common case right after onboarding). Give a
        // friendly hint rather than an alarming ✗.
        let _ = cliclack::log::info(crate::term::wrap_log_text(&format!(
            "couldn't reach the agent yet — make sure the daemon is running (`secreq daemon install`), then `secreq ssh validate {key_id}`."
        )));
        return;
    }
    print_self_test_result(key_id, &result);
}

/// Resolve a `--public-key` argument to a validated OpenSSH public-key line.
/// A path to an existing file is read (a `.pub` file is one line); otherwise
/// a value starting with a known OpenSSH key-type prefix is treated as a
/// literal. Anything else, or a value that doesn't parse, is an error.
pub(super) fn resolve_public_key(raw: &str) -> Result<String> {
    let candidate = Path::new(raw);
    let text = if candidate.is_file() {
        std::fs::read_to_string(candidate)
            .with_context(|| format!("could not read public key file {raw}"))?
    } else if is_openssh_public_key_literal(raw) {
        raw.to_owned()
    } else {
        bail!(
            "`{raw}` is neither an existing file nor an OpenSSH public key (expected an `ssh-…`/`ecdsa-…`/`sk-…` line)"
        );
    };
    validate_openssh_public_key(text.trim())
}

/// True if `s` looks like an inline OpenSSH public key (by key-type prefix).
fn is_openssh_public_key_literal(s: &str) -> bool {
    const PREFIXES: [&str; 4] = ["ssh-", "ecdsa-", "sk-ssh-", "sk-ecdsa-"];
    PREFIXES.iter().any(|p| s.starts_with(p))
}

/// Parse `line` as an OpenSSH public key to validate it, returning the
/// trimmed line on success.
fn validate_openssh_public_key(line: &str) -> Result<String> {
    ssh_key::PublicKey::from_openssh(line)
        .with_context(|| "not a valid OpenSSH public key (expected `ssh-… AAAA… [comment]`)")?;
    Ok(line.to_owned())
}

/// What op discovery yields: the private-key reference and, optionally, the
/// public key fetched alongside it.
struct OpIdentity {
    private_key: Reference,
    public_key: Option<String>,
}

/// Best-effort 1Password (`op`) discovery of an SSH-Key item. Returns `None`
/// (never an error) when op is missing, errors, returns no items, or the user
/// can't be prompted — the caller falls back to a manual prompt. When
/// `want_public_key` is set, also fetches the item's public key.
fn op_assisted_identity(want_public_key: bool) -> Result<Option<OpIdentity>> {
    if !which_on_path("op") {
        return Ok(None);
    }

    let items = match op_list_ssh_keys() {
        Some(items) if !items.is_empty() => items,
        _ => {
            cliclack::log::info(crate::term::wrap_log_text(
                "1Password `op` found no SSH-Key items (or couldn't list them); entering the reference manually.",
            ))
            .ok();
            return Ok(None);
        }
    };

    let mut select = cliclack::select::<usize>("Pick the 1Password SSH key to serve");
    for (idx, item) in items.iter().enumerate() {
        select = select.item(idx, item.title.as_str(), item.vault.as_str());
    }
    // The index comes back out of `select`, so it indexes `items` — but
    // resolving it with `get` keeps that between these two lines instead of
    // depending on what cliclack promises to return.
    let Some(chosen) = select.interact().ok().and_then(|idx| items.get(idx)) else {
        cliclack::log::info("No selection made; entering the reference manually.").ok();
        return Ok(None);
    };

    let Some(private_key) = Reference::parse(&format!(
        "secret://op/{}/{}/private key",
        chosen.vault, chosen.title
    )) else {
        return Ok(None);
    };

    let public_key = if want_public_key {
        match op_read(&format!(
            "op://{}/{}/public key",
            chosen.vault, chosen.title
        )) {
            Some(raw) => match validate_openssh_public_key(raw.trim()) {
                Ok(pk) => Some(pk),
                Err(err) => {
                    cliclack::log::warning(crate::term::wrap_log_text(&format!(
                        "op returned a public key that didn't parse ({err:#}); you'll be prompted for it."
                    )))
                    .ok();
                    None
                }
            },
            None => None,
        }
    } else {
        None
    };

    Ok(Some(OpIdentity {
        private_key,
        public_key,
    }))
}

/// One 1Password SSH-Key item, as surfaced by `op item list`.
struct OpItem {
    title: String,
    vault: String,
}

/// Run `op item list --categories "SSH Key" --format json` and parse out the
/// title + vault of each item. Returns `None` on any failure.
fn op_list_ssh_keys() -> Option<Vec<OpItem>> {
    let output = Command::new("op")
        .args([
            "item",
            "list",
            "--categories",
            "SSH Key",
            "--format",
            "json",
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
    let array = value.as_array()?;
    let mut items = Vec::with_capacity(array.len());
    for entry in array {
        let title = entry.get("title")?.as_str()?.to_owned();
        let vault = entry
            .get("vault")
            .and_then(|v| v.get("name"))
            .and_then(|n| n.as_str())?
            .to_owned();
        items.push(OpItem { title, vault });
    }
    Some(items)
}

/// Run `op read <uri>` and return its trimmed stdout, or `None` on failure.
fn op_read(uri: &str) -> Option<String> {
    let output = Command::new("op").args(["read", uri]).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8(output.stdout).ok()?.trim().to_owned())
}
