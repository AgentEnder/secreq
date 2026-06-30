//! Subcommand implementations for the per-binary wrap model.
//!
//! The center of gravity is [`wrap_run`] — the external-subcommand handler
//! invoked when the user runs `secreq <BINARY> [args…]`. Everything else is
//! admin verbs that read/write `~/.config/secreq/wraps.json5`.

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::{IsTerminal as _, Read as _, Seek as _, SeekFrom, Write as _};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread::sleep;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use crate::audit::{self, AuditEntry};
use crate::autostart;
use crate::consent::Decision;
use crate::daemon::client as daemon_client;
use crate::daemon::proto;
use crate::path_setup;
use crate::provenance;
use crate::provider;
use crate::reference::Reference;
use crate::resolve::{self, SecretRequest, Source};
use crate::secret::SecretValue;
use crate::shim;
use crate::ssh_setup;
use crate::wraps::{self, Wrap, WrapsConfig};

// ── Public entry points ───────────────────────────────────────────────────

/// Options for [`wrap_run`].
#[derive(Debug, Clone, Default)]
pub struct WrapRunOpts {
    /// `--raw`: disable output masking. The wrapped binary runs unchanged
    /// but its stdout/stderr pass through unredacted.
    pub raw: bool,
    /// `--no-remember`: ignore and don't update the approval cache.
    pub no_remember: bool,
    /// `--yes`: auto-approve without prompting.
    pub assume_yes: bool,
}

/// `secreq <BINARY> [args…]` — wrap-and-run. If `binary` has a wrap entry,
/// resolve its env, obtain consent, exec the real binary with masking. If
/// there's no wrap entry, **pass through** unchanged — lets users blanket-
/// shim binaries and add configs incrementally.
pub fn wrap_run(
    binary: &str,
    args: &[String],
    opts: WrapRunOpts,
    config_path: Option<&Path>,
) -> Result<i32> {
    let config = load_config_or_default(config_path)?;

    // Recursion guard: if we're already inside secreq's own secret
    // resolution (the daemon — or a `--yes` run — is invoking a provider's
    // retrieve command, and that provider's CLI happens to be wrapped),
    // don't gate. Without this, resolving a `secret://op/...` reference for
    // one wrap would PATH-resolve `op` to our shim and pop a *second*
    // consent prompt for `op`. We pass straight through to the real binary.
    // See `crate::RESOLVING_ENV`.
    if std::env::var_os(crate::RESOLVING_ENV).is_some() {
        return passthrough_unwrapped(binary, args, config.shim_dir.as_deref());
    }

    let Some(wrap) = config.wraps.get(binary).cloned() else {
        return passthrough_unwrapped(binary, args, config.shim_dir.as_deref());
    };

    // `caller_chain` already drops `secreq` self-frames during its walk
    // (see `provenance::caller_chain`), so the chain we get back is the
    // user-meaningful ancestry — what the consent UI shows and what the
    // approvals cache anchors on.
    let callers = provenance::caller_chain();

    // Consent: hand off to the daemon. The daemon owns the cache, the
    // coalescing queue, the UI, *and* the resolution — on approve it
    // ships back the resolved env values directly, so a parallel burst
    // of N invocations causes one provider call (and one biometric
    // prompt) instead of N.
    //
    // `--yes` bypasses the daemon entirely (no biometric coalescing
    // possible without it; --yes paths are scripted runs that need to
    // resolve client-side).
    let resolved: Vec<(String, SecretValue)> = if opts.assume_yes {
        let decision = Decision::Approve;
        let env_names: Vec<String> = wrap.env.keys().cloned().collect();
        let _ = audit::append(&AuditEntry::new(
            binary, args, &callers, &env_names, decision,
        ));
        resolve_wrap_env(&config, &wrap)?
    } else {
        let outcome = obtain_wrap_consent(&wrap, &callers, args)?;
        let env_names: Vec<String> = wrap.env.keys().cloned().collect();
        let _ = audit::append(
            &AuditEntry::new(binary, args, &callers, &env_names, outcome.decision)
                .with_rule_id(outcome.rule_id.clone()),
        );
        if !outcome.decision.approved() {
            // Auto-deny: surface the rule's configured message (or a
            // minimal "denied by rule X" fallback) before exiting 1.
            // Plain manual deny keeps the existing terse message.
            if outcome.decision == Decision::DenyAuto {
                let rule_name = outcome.rule_name.as_deref().unwrap_or("(unknown)");
                match outcome.deny_message.as_deref() {
                    Some(msg) => eprintln!("secreq: denied by rule '{rule_name}': {msg}"),
                    None => eprintln!("secreq: denied by rule '{rule_name}'"),
                }
            } else {
                eprintln!("secreq: denied — `{binary}` not run");
            }
            return Ok(1);
        }
        outcome
            .secrets
            .into_iter()
            .map(|(name, value)| (name, SecretValue::new(value)))
            .collect()
    };

    // Build the command: find the *real* binary on PATH excluding our shim
    // dir, then forward args. Without this, our shim would recurse.
    let real_binary =
        find_real_binary(binary, config.shim_dir.as_deref()).with_context(|| {
            format!(
                "could not locate the real `{binary}` on PATH; check that it's installed and that the wrap's shim dir is the one in your config"
            )
        })?;
    let mut command = vec![real_binary.display().to_string()];
    command.extend(args.iter().cloned());

    let env_overrides: Vec<(String, String)> = resolved
        .iter()
        .map(|(name, value)| (name.clone(), value.expose().to_owned()))
        .collect();

    // Mask the resolved values unless --raw was given. With --raw, we still
    // inject the env vars but pass output through verbatim.
    let secrets_for_masking: Vec<SecretValue> = if opts.raw {
        Vec::new()
    } else {
        resolved.into_iter().map(|(_, v)| v).collect()
    };

    let cwd = std::env::current_dir().context("could not determine current directory")?;

    crate::exec::run(&command, &env_overrides, &secrets_for_masking, &cwd)
}

/// Merge env-file pairs UNDER the inherited environment (inherited wins).
fn effective_env(
    inherited: &[(String, String)],
    envfile: &[(String, String)],
) -> BTreeMap<String, String> {
    let mut eff: BTreeMap<String, String> = BTreeMap::new();
    for (k, v) in envfile {
        eff.insert(k.clone(), v.clone());
    }
    for (k, v) in inherited {
        eff.insert(k.clone(), v.clone()); // inherited wins
    }
    eff
}

/// Compute the overrides for [`crate::exec::run`]. The child already
/// inherits the process env, so we only emit: (a) keys present in the
/// effective env but not inherited (file-only plain vars), and (b) every
/// resolved ref (replacing its `secret://…` placeholder with the real
/// value).
fn build_overrides(
    eff: &BTreeMap<String, String>,
    inherited: &[(String, String)],
    resolved: &[(String, String)],
) -> Vec<(String, String)> {
    use std::collections::HashSet;
    let inherited_keys: HashSet<&str> = inherited.iter().map(|(k, _)| k.as_str()).collect();
    let resolved_keys: HashSet<&str> = resolved.iter().map(|(k, _)| k.as_str()).collect();
    let mut out: Vec<(String, String)> = resolved.to_vec();
    for (k, v) in eff {
        if resolved_keys.contains(k.as_str()) {
            continue; // already carried by `resolved`
        }
        if !inherited_keys.contains(k.as_str()) {
            out.push((k.clone(), v.clone())); // file-only plain var
        }
    }
    out
}

/// `secreq run [--env-file PATH]… -- <cmd>` — the ambient mirror of `x`.
/// Resolve `secret://provider/locator` references found in the inherited
/// environment (and any `--env-file`) through the consent daemon, then exec
/// `<cmd>` with the resolved values injected and output masked.
///
/// Only wired into the CLI by Task 5; `pub fn` items in this lib aren't
/// dead-code-flagged (cf. `wrap_run`), so no `allow(dead_code)` is needed.
pub fn run(
    command: &[String],
    env_files: &[PathBuf],
    opts: WrapRunOpts,
    config_path: Option<&Path>,
) -> Result<i32> {
    if command.is_empty() {
        bail!(
            "secreq run: no command given (usage: secreq run [--env-file PATH]… -- <cmd> [args…])"
        );
    }
    let config = load_config_or_default(config_path)?;

    // Recursion guard: if we're already inside secreq's own resolution,
    // just exec the command without re-resolving (mirrors `wrap_run`). A
    // provider CLI invoked during resolution can't trigger a second consent.
    // This is a bare passthrough — `--env-file` entries (even plain ones)
    // are intentionally not applied in this pathological re-entry case.
    if std::env::var_os(crate::RESOLVING_ENV).is_some() {
        let cwd = std::env::current_dir().context("could not determine current directory")?;
        return crate::exec::run(command, &[], &[], &cwd);
    }

    // 1. Effective env = inherited, with --env-file layered underneath.
    // `dotenvy` does the real `.env` parsing (quoting, escapes, `export`,
    // `${VAR}` substitution against the process env), yielding processed
    // pairs *without* mutating our own environment — we layer them
    // explicitly so the inherited-wins precedence stays ours, not
    // dotenvy's. A malformed line is a hard error before any exec.
    let inherited: Vec<(String, String)> = std::env::vars().collect();
    let mut envfile_pairs = Vec::new();
    for path in env_files {
        let iter = dotenvy::from_path_iter(path)
            .with_context(|| format!("could not read env file {}", path.display()))?;
        for item in iter {
            let (key, value) =
                item.with_context(|| format!("malformed entry in env file {}", path.display()))?;
            envfile_pairs.push((key, value));
        }
    }
    let eff = effective_env(&inherited, &envfile_pairs);

    // 2. Scan for secret:// references. A value that looks like a ref but
    // doesn't parse is a hard error here, before any exec.
    let eff_pairs: Vec<(String, String)> =
        eff.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    let scanned = scan_env_refs(&eff_pairs)?;
    let refs: Vec<(String, Reference)> =
        scanned.into_iter().map(|r| (r.name, r.reference)).collect();

    let cwd = std::env::current_dir().context("could not determine current directory")?;

    // 3. Nothing to resolve → exec directly with the file-only plain vars.
    // No daemon contact, no consent (honest "nothing to resolve" fast path).
    if refs.is_empty() {
        let overrides = build_overrides(&eff, &inherited, &[]);
        return crate::exec::run(command, &overrides, &[], &cwd);
    }

    // 4 + 5. Consent + resolve (daemon, or client-side under --yes).
    let callers = provenance::caller_chain();
    let names: Vec<String> = refs.iter().map(|(n, _)| n.clone()).collect();
    let resolved: Vec<(String, SecretValue)> = if opts.assume_yes {
        let _ = audit::append(&AuditEntry::new(
            "run",
            command,
            &callers,
            &names,
            Decision::Approve,
        ));
        resolve_refs_client_side(&config, &refs, None)?
    } else {
        let ask = build_ask(
            AskSpec {
                dedupe_wrap: "run".to_owned(),
                command: command.to_vec(),
                refs: &refs,
                reason: None,
                allow_remember: false,
            },
            &callers,
            &cwd,
            &config,
        );
        let outcome = daemon_client::request_consent(ask, config.wait_indicator_enabled())
            .context("daemon consent request failed")?;
        let _ = audit::append(
            &AuditEntry::new("run", command, &callers, &names, outcome.decision)
                .with_rule_id(outcome.rule_id.clone()),
        );
        if !outcome.decision.approved() {
            // Mirror `wrap_run`'s deny messaging.
            if outcome.decision == Decision::DenyAuto {
                let rule_name = outcome.rule_name.as_deref().unwrap_or("(unknown)");
                match outcome.deny_message.as_deref() {
                    Some(msg) => eprintln!("secreq: denied by rule '{rule_name}': {msg}"),
                    None => eprintln!("secreq: denied by rule '{rule_name}'"),
                }
            } else {
                eprintln!("secreq: denied — command not run");
            }
            return Ok(1);
        }
        outcome
            .secrets
            .into_iter()
            .map(|(name, value)| (name, SecretValue::new(value)))
            .collect()
    };

    // 6. Substitute resolved values into the env; build the overrides.
    let resolved_plain: Vec<(String, String)> = resolved
        .iter()
        .map(|(name, value)| (name.clone(), value.expose().to_owned()))
        .collect();
    let env_overrides = build_overrides(&eff, &inherited, &resolved_plain);

    // 7. Exec with masking (unless --raw).
    let secrets_for_masking: Vec<SecretValue> = if opts.raw {
        Vec::new()
    } else {
        resolved.into_iter().map(|(_, v)| v).collect()
    };
    crate::exec::run(command, &env_overrides, &secrets_for_masking, &cwd)
}

/// `secreq init` — interactive first-time setup. Picks the shim dir,
/// optionally adds it to the shell's PATH config, and writes a minimal
/// `wraps.json5`.
pub fn init(config_path: Option<&Path>, default_shim_dir: Option<PathBuf>) -> Result<i32> {
    let config_path = config_path
        .map(PathBuf::from)
        .or_else(wraps::default_config_path)
        .context("could not determine config path")?;

    cliclack::intro("secreq init — first-time setup")?;

    // 1. Pick the shim dir. Default to a dedicated `~/.secreq/shims` so
    // we don't share a directory with anything else — no risk of another
    // tool (asdf, pip user-installs, etc.) dropping a competing `gh`
    // shim into the same dir. The dir is also brand-new on first init,
    // so the "is it on PATH?" answer is unambiguous.
    let suggested = default_shim_dir
        .or_else(|| dirs::home_dir().map(|h| h.join(".secreq").join("shims")))
        .context("could not determine a default shim dir")?;
    let shim_dir_input = prompt::read_with_default(
        "Where should secreq drop PATH shims?",
        &suggested.display().to_string(),
    )?;
    let shim_dir = expand_tilde(&shim_dir_input);

    // 2. Ensure the dir exists.
    std::fs::create_dir_all(&shim_dir)
        .with_context(|| format!("could not create {}", shim_dir.display()))?;

    // 3. Plan the shell-PATH block. We always run this — being "on PATH"
    // somewhere is necessary but not sufficient. What actually matters is
    // whether our sentinel block lives in the *canonical* file for this
    // shell (e.g. `.zshrc` for zsh, where it'll prepend after homebrew).
    let shell = path_setup::detect_shell();
    let home = dirs::home_dir().context("could not determine $HOME")?;
    match path_setup::plan(&home, shell.clone(), &shim_dir) {
        Ok(plan) if plan.already_configured => {
            cliclack::log::success(format!(
                "PATH already configured via {}; nothing to add.",
                plan.config_file.display()
            ))?;
            // Even when we're already-configured, hint about stale blocks
            // sitting in non-canonical files (e.g. a pre-pivot .zshenv).
            let stale = path_setup::find_stale_blocks(&home, &shell, &plan.config_file);
            if !stale.is_empty() {
                let list = stale
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                cliclack::log::warning(format!(
                    "Found leftover secreq PATH blocks in: {list}. They're harmless but you can remove them by hand for tidiness."
                ))?;
            }
        }
        Ok(plan) => {
            // Two cases land here: (a) we're not on PATH at all, (b) we
            // are on PATH but via a non-canonical file (e.g. .zshenv from
            // before the homebrew-shadowing fix). The diagnostic differs.
            let already_on_path = path_setup::path_includes(&shim_dir);
            let preamble = if already_on_path {
                format!(
                    "{} is on PATH already, but the secreq block isn't in {}. \
                     That usually means it's in an earlier-loaded file (e.g. .zshenv) \
                     where later prepends like `brew shellenv` can shadow our shim. \
                     I can append a fresh block to {} so we win on PATH:",
                    shim_dir.display(),
                    plan.config_file.display(),
                    plan.config_file.display(),
                )
            } else {
                format!(
                    "{} isn't on PATH. I can append this to {} ({:?}):",
                    shim_dir.display(),
                    plan.config_file.display(),
                    shell
                )
            };
            cliclack::note(preamble, &plan.block)?;
            if let Some(caveat) = &plan.caveat {
                cliclack::log::warning(caveat)?;
            }
            let stale = path_setup::find_stale_blocks(&home, &shell, &plan.config_file);
            if !stale.is_empty() {
                let list = stale
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                cliclack::log::warning(format!(
                    "Found leftover secreq PATH blocks in: {list}. The new one in {} will win on PATH, but you may want to remove the old blocks by hand for tidiness.",
                    plan.config_file.display()
                ))?;
            }
            if prompt::confirm_default_yes("Append it?")? {
                path_setup::apply(&plan)?;
                cliclack::log::success(format!(
                    "wrote {}. Open a new terminal (or `source {}`) to pick it up.",
                    plan.config_file.display(),
                    plan.config_file.display()
                ))?;
            } else {
                cliclack::log::info(format!(
                    "skipped. Add {} to PATH yourself before running `secreq wrap`.",
                    shim_dir.display()
                ))?;
            }
        }
        Err(err) => {
            cliclack::log::warning(format!("couldn't auto-configure your shell: {err:#}"))?;
            cliclack::note(
                "Add this to your shell config yourself:",
                format!(r#"export PATH="{}:$PATH""#, shim_dir.display()),
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
            cliclack::log::warning(format!(
                "skipped SSH-agent setup: {err:#}. Run `secreq ssh setup` later to wire it."
            ))?;
        }
    }

    cliclack::outro(format!(
        "Wrote {}.  Next: `secreq wrap <binary>`, e.g. `secreq wrap gh`.",
        config_path.display()
    ))?;
    Ok(0)
}

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
fn ssh_setup_core(
    method: Option<ssh_setup::Method>,
    undo: bool,
    assume_yes: bool,
    config_path: Option<&Path>,
) -> Result<()> {
    // Scripted path: `--yes` + explicit `--method` means "just wire the
    // client, don't prompt for identity/autostart". This is the deterministic
    // path scripts and tests rely on.
    let scripted = assume_yes && method.is_some();

    if !scripted && !undo {
        // Step 1: identity. Non-fatal — warn and continue on any error.
        if let Err(err) = ssh_setup_identity_step(config_path) {
            cliclack::log::warning(format!(
                "skipped the identity step: {err:#}. Add one later with `secreq ssh add`."
            ))?;
        }
        // Step 2: auto-start. Non-fatal — warn and continue on any error.
        if let Err(err) = ssh_setup_autostart_step(assume_yes) {
            cliclack::log::warning(format!(
                "skipped the auto-start step: {err:#}. Install it later with `secreq daemon install`."
            ))?;
        }
    }

    // Step 3: client wiring (the original flow). Always runs.
    ssh_setup_wiring_step(method, undo, assume_yes, config_path)?;

    // Optional post-step (guided, non-scripted, non-undo): offer to prove the
    // agent can actually sign. Non-fatal — a decline or failure never changes
    // the exit status.
    if !scripted && !undo {
        if let Err(err) = ssh_setup_self_test_step(config_path) {
            cliclack::log::warning(format!(
                "skipped the self-test: {err:#}. Run `secreq ssh validate` later to verify signing."
            ))?;
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

    let chosen = if names.len() == 1 {
        names[0].clone()
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
        cliclack::log::warning(
            "No SSH identities configured yet — the agent has nothing to serve until you add one.",
        )?;
        if prompt::confirm_default_yes("Add an SSH identity now?")? {
            ssh_add_core(SshAddArgs::default(), config_path)?;
        }
    } else {
        let names = config.ssh.keys().cloned().collect::<Vec<_>>().join(", ");
        cliclack::log::info(format!("Configured SSH identities: {names}."))?;
        if cliclack::confirm("Add another identity?")
            .initial_value(false)
            .interact()
            .context("interactive confirm failed (need a real terminal)")?
        {
            ssh_add_core(SshAddArgs::default(), config_path)?;
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
            cliclack::log::warning(
                "No SSH identities configured yet — setup will still wire the agent, but add an `ssh` block to wraps.json5 for it to serve keys.",
            )?;
        }
        Ok(_) => {}
        Err(err) => {
            cliclack::log::warning(format!(
                "couldn't read your config ({err:#}); wiring the agent anyway."
            ))?;
        }
    }

    // Pick the method: explicit `--method`, else an interactive select.
    let method = match method {
        Some(m) => m,
        None => {
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
    if plan.already_configured {
        cliclack::log::success(format!(
            "{} already wires the secreq SSH agent; nothing to do.",
            plan.config_file.display()
        ))?;
        return Ok(());
    }

    cliclack::note(
        format!("I'll write this to {}:", plan.config_file.display()),
        &plan.block,
    )?;
    if let Some(caveat) = &plan.caveat {
        cliclack::log::warning(caveat)?;
    }

    let proceed = assume_yes || prompt::confirm_default_yes("Write it?")?;
    if !proceed {
        cliclack::log::info("Skipped — no files changed.")?;
        return Ok(());
    }

    ssh_setup::apply(&plan)?;
    cliclack::log::success(format!("wrote {}.", plan.config_file.display()))?;
    cliclack::log::info(
        "secreq's daemon must be running to serve keys — step 2 (or `secreq daemon install`) sets it to start at login. New shells / SSH sessions pick up the socket; restart your shell or run `exec $SHELL`.",
    )?;
    cliclack::log::info(
        "Each identity's `private_key` reference must resolve to an OpenSSH private key, e.g. `op read \"op://Vault/My Key/private key\"`.",
    )?;
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
    let _ = assume_yes;
    ssh_add_core(args, config_path)?;
    Ok(0)
}

/// The reusable body of `secreq ssh add`, shared with the `ssh setup`
/// orchestrator's identity step. Returns `Ok(())` after writing the identity;
/// the standalone command wraps it to produce an exit code.
///
/// When `args.name` is empty the name is prompted for interactively — that's
/// the path the orchestrator takes (it has no name to preset).
fn ssh_add_core(args: SshAddArgs, config_path: Option<&Path>) -> Result<()> {
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
    let public_key = match public_key {
        Some(pk) => pk,
        None => {
            if non_interactive {
                bail!("no public key supplied");
            }
            prompt::ssh_public_key()?
        }
    };

    let identity = wraps::SshIdentity {
        reason: args.reason,
        public_key,
        private_key,
    };
    config.ssh.insert(name.clone(), identity);

    write_config(&config_path, &config)?;

    println!("Added SSH identity `{name}`.");
    println!("  config: {}", config_path.display());
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
    if !non_interactive
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
        Ok(config) => match config.ssh.get(key_id).cloned() {
            Some(identity) => identity,
            None => {
                // The identity we just wrote is somehow gone — warn, don't fail.
                let _ = cliclack::log::warning(format!(
                    "couldn't find `{key_id}` in the config to self-test; skipping."
                ));
                return;
            }
        },
        Err(err) => {
            let _ =
                cliclack::log::warning(format!("couldn't read the config to self-test: {err:#}"));
            return;
        }
    };

    let agent_sock = match crate::daemon::ssh_agent::default_agent_socket_path() {
        Ok(path) => path,
        Err(err) => {
            let _ = cliclack::log::warning(format!(
                "couldn't determine the agent socket to self-test: {err:#}"
            ));
            return;
        }
    };

    println!("Signing may prompt for consent — answer the prompt if one appears.");
    let result = crate::ssh_selftest::run(&agent_sock, &identity, key_id);
    if result.is_err() && !agent_sock.exists() {
        // The socket isn't there at all: the daemon almost certainly isn't
        // running yet (the most common case right after onboarding). Give a
        // friendly hint rather than an alarming ✗.
        let _ = cliclack::log::info(format!(
            "couldn't reach the agent yet — make sure the daemon is running (`secreq daemon install`), then `secreq ssh validate {key_id}`."
        ));
        return;
    }
    print_self_test_result(key_id, &result);
}

/// Resolve a `--public-key` argument to a validated OpenSSH public-key line.
/// A path to an existing file is read (a `.pub` file is one line); otherwise
/// a value starting with a known OpenSSH key-type prefix is treated as a
/// literal. Anything else, or a value that doesn't parse, is an error.
fn resolve_public_key(raw: &str) -> Result<String> {
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
            cliclack::log::info(
                "1Password `op` found no SSH-Key items (or couldn't list them); entering the reference manually.",
            )
            .ok();
            return Ok(None);
        }
    };

    let mut select = cliclack::select::<usize>("Pick the 1Password SSH key to serve");
    for (idx, item) in items.iter().enumerate() {
        select = select.item(idx, item.title.as_str(), item.vault.as_str());
    }
    let chosen = match select.interact() {
        Ok(idx) => &items[idx],
        Err(_) => {
            cliclack::log::info("No selection made; entering the reference manually.").ok();
            return Ok(None);
        }
    };

    let private_key = match Reference::parse(&format!(
        "secret://op/{}/{}/private key",
        chosen.vault, chosen.title
    )) {
        Some(reference) => reference,
        None => return Ok(None),
    };

    let public_key = if want_public_key {
        match op_read(&format!(
            "op://{}/{}/public key",
            chosen.vault, chosen.title
        )) {
            Some(raw) => match validate_openssh_public_key(raw.trim()) {
                Ok(pk) => Some(pk),
                Err(err) => {
                    cliclack::log::warning(format!(
                        "op returned a public key that didn't parse ({err:#}); you'll be prompted for it."
                    ))
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

/// Args for `secreq wrap`.
#[derive(Debug, Clone, Default)]
pub struct WrapArgs {
    pub binary: String,
    pub reason: Option<String>,
    pub envs: Vec<String>, // each: "ENV_NAME=secret://provider/locator"
}

/// `secreq wrap <BINARY>` — add (or update) a wrap entry and install the
/// shim. Interactive when `envs` is empty; non-interactive otherwise.
pub fn wrap(args: WrapArgs, config_path: Option<&Path>) -> Result<i32> {
    let config_path = resolve_config_path(config_path)?;
    let mut config = if config_path.is_file() {
        WrapsConfig::load(&config_path)?
    } else {
        WrapsConfig::default()
    };
    // Overlay the built-ins so the interactive picker can offer them even
    // when the user has no `providers` block. `write_config` filters
    // built-ins back out, so the file on disk doesn't get them baked in.
    config.merge_builtin_providers();

    if args.binary.starts_with('-') || args.binary.contains('/') {
        bail!(
            "`{}` is not a plain binary name; the wrap name is the executable filename only",
            args.binary
        );
    }

    let shim_dir = config
        .shim_dir
        .clone()
        .context("no $shim_dir configured; run `secreq init` first")?;

    // Interactive flow gets a banner; non-interactive (flags supplied, or
    // no terminal to prompt on) stays quiet so it composes cleanly with
    // scripts.
    let interactive = args.envs.is_empty() && std::io::stdin().is_terminal();
    if interactive {
        cliclack::intro(format!("Wrap `{}`", args.binary))?;
    }

    // Build the env map. Three paths:
    //  - `--env` flags supplied → parse them (non-interactive).
    //  - interactive terminal   → ask gate-only vs inject-secrets.
    //  - no flags, no terminal  → gate-only. There's nothing to inject and
    //    nothing to prompt on, so absence of `--env` means "just gate it".
    // An empty env map is a *gate-only* wrap: consent is still required,
    // but nothing is resolved or injected. Used to gate tools like `op`.
    let env: BTreeMap<String, String> = if !args.envs.is_empty() {
        parse_env_assignments(&args.envs)?
    } else if interactive {
        if prompt::wrap_is_gate_only()? {
            BTreeMap::new()
        } else {
            prompt::interactive_wrap_envs(&config.providers)?
        }
    } else {
        BTreeMap::new()
    };

    let reason = args.reason.or_else(|| {
        if interactive {
            prompt::optional_read("Reason (shown in consent prompt)")
                .ok()
                .flatten()
        } else {
            None
        }
    });
    let wrap = Wrap {
        name: args.binary.clone(),
        reason,
        env,
    };
    config.wraps.insert(args.binary.clone(), wrap);

    // Validate by round-tripping through the parser before writing.
    write_config(&config_path, &config)?;

    // Drop the shim.
    let shim_path = shim::install(&shim_dir, &args.binary)?;

    // `config.wraps[binary]` is the wrap we just inserted; an empty env
    // means we created a gate-only wrap.
    let kind = if config.wraps[&args.binary].env.is_empty() {
        " (gate-only — consent required, nothing injected)"
    } else {
        ""
    };
    let summary = format!(
        "config: {}\n  shim: {}",
        config_path.display(),
        shim_path.display()
    );
    if interactive {
        cliclack::outro(format!("Wrapped `{}`{kind}.\n  {summary}", args.binary))?;
    } else {
        println!("Wrapped `{}`{kind}.\n  {summary}", args.binary);
    }

    if !path_setup::path_includes(&shim_dir) {
        cliclack::log::warning(format!(
            "{} isn't on your current PATH. The shim is installed but new shells won't find it until you source your shell config (or open a new terminal). Run `secreq init` to wire up PATH.",
            shim_dir.display()
        ))?;
    }
    Ok(0)
}

/// `secreq unwrap <BINARY>` — remove the wrap entry and the shim.
pub fn unwrap_cmd(binary: &str, config_path: Option<&Path>) -> Result<i32> {
    let config_path = resolve_config_path(config_path)?;
    if !config_path.is_file() {
        bail!("no config at {}", config_path.display());
    }
    let mut config = WrapsConfig::load(&config_path)?;
    let removed = config.wraps.remove(binary).is_some();
    let shim_removed = if let Some(shim_dir) = &config.shim_dir {
        shim::remove(shim_dir, binary)?
    } else {
        false
    };
    write_config(&config_path, &config)?;
    // Drop the cache entry if any (best-effort across all parent pids).
    // We can't know which (ppid, start_time) tuples are in cache, so we
    // can't precisely target this wrap's entries — that's a known
    // limitation; entries will expire by TTL.
    match (removed, shim_removed) {
        (true, true) => println!("Unwrapped `{binary}` (config + shim removed)."),
        (true, false) => println!("Removed config entry for `{binary}` (no shim was present)."),
        (false, true) => println!("Removed shim for `{binary}` (no config entry was present)."),
        (false, false) => println!("Nothing to remove for `{binary}`."),
    }
    Ok(0)
}

/// `secreq wraps` — list configured wraps.
pub fn wraps_list(config_path: Option<&Path>) -> Result<i32> {
    let config_path = resolve_config_path(config_path)?;
    if !config_path.is_file() {
        println!("(no config at {})", config_path.display());
        return Ok(0);
    }
    let config = WrapsConfig::load(&config_path)?;
    if config.wraps.is_empty() {
        println!("(no wraps configured)");
        return Ok(0);
    }
    for wrap in config.wraps.values() {
        let reason = wrap.reason.as_deref().unwrap_or("");
        let reason_suffix = if reason.is_empty() {
            String::new()
        } else {
            format!(" — {reason}")
        };
        println!("{}{}", wrap.name, reason_suffix);
        for (name, ref_str) in &wrap.env {
            // Render the provider (and a short locator) but never the value.
            let summary = match Reference::parse(ref_str) {
                Some(r) => format!("{} ({})", name, r.provider),
                None => format!("{} (bare locator)", name),
            };
            println!("    {summary}");
        }
    }
    Ok(0)
}

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

/// `secreq rules` (with no subcommand or with `list`): one-line table
/// of every configured rule.
pub fn rules_list() -> Result<i32> {
    let rules = daemon_client::list_rules().context("could not reach the consent daemon")?;
    if rules.is_empty() {
        println!("no auto-rules configured");
        println!("(create one from the Rules tab in `secreq view`)");
        return Ok(0);
    }
    println!(
        "{:<24}  {:<8}  {:<8}  {:<16}  name",
        "id", "decide", "enabled", "wrap"
    );
    for r in &rules {
        let enabled = if r.enabled { "yes" } else { "no" };
        let decide = match r.decide {
            crate::rules::RuleDecision::Approve => "approve",
            crate::rules::RuleDecision::Deny => "deny",
        };
        println!(
            "{:<24}  {:<8}  {:<8}  {:<16}  {}",
            r.id, decide, enabled, r.r#match.wrap, r.name
        );
    }
    Ok(0)
}

/// `secreq rules show <target>` — verbose dump of one rule. `target`
/// matches by id first, then by exact name.
pub fn rules_show(target: &str) -> Result<i32> {
    let rules = daemon_client::list_rules().context("could not reach the consent daemon")?;
    let rule = find_rule(&rules, target)?;
    println!("id:             {}", rule.id);
    println!("name:           {}", rule.name);
    println!("enabled:        {}", rule.enabled);
    println!(
        "decide:         {}",
        match rule.decide {
            crate::rules::RuleDecision::Approve => "approve",
            crate::rules::RuleDecision::Deny => "deny",
        }
    );
    println!("wrap:           {}", rule.r#match.wrap);
    if let Some(p) = &rule.r#match.argv {
        println!("argv match:     {}", p.as_str());
    }
    if let Some(p) = &rule.r#match.ancestor {
        println!("ancestor match: {}", p.as_str());
    }
    if let Some(p) = &rule.r#match.cwd {
        println!("cwd match:      {}", p.as_str());
    }
    if !rule.trained_secrets.is_empty() {
        let names: Vec<_> = rule.trained_secrets.iter().cloned().collect();
        println!("trained on:     {}", names.join(", "));
    }
    if let Some(msg) = &rule.deny_message {
        println!("deny message:   {msg}");
    }
    if rule.created_at_unix > 0 {
        println!("created at:     {} (unix)", rule.created_at_unix);
    }
    Ok(0)
}

/// `secreq rules enable|disable <target>`. Idempotent — flipping a
/// bit that's already in the requested state succeeds silently.
pub fn rules_set_enabled(target: &str, enabled: bool) -> Result<i32> {
    let rules = daemon_client::list_rules().context("could not reach the consent daemon")?;
    let rule = find_rule(&rules, target)?;
    let id = rule.id.clone();
    daemon_client::set_rule_enabled(&id, enabled)
        .context("could not update the rule via the daemon")?;
    println!(
        "rule '{}' ({}) is now {}",
        rule.name,
        rule.id,
        if enabled { "enabled" } else { "disabled" }
    );
    Ok(0)
}

/// `secreq rules rm <target>`.
pub fn rules_rm(target: &str) -> Result<i32> {
    let rules = daemon_client::list_rules().context("could not reach the consent daemon")?;
    let rule = find_rule(&rules, target)?;
    let id = rule.id.clone();
    let name = rule.name.clone();
    daemon_client::delete_rule(&id).context("could not delete the rule via the daemon")?;
    println!("deleted rule '{name}' ({id})");
    Ok(0)
}

/// Resolve a user-supplied id-or-name to exactly one rule. Errors
/// with the candidate list on ambiguity so the user can disambiguate
/// by id.
fn find_rule<'a>(rules: &'a [crate::rules::Rule], target: &str) -> Result<&'a crate::rules::Rule> {
    if let Some(by_id) = rules.iter().find(|r| r.id == target) {
        return Ok(by_id);
    }
    let by_name: Vec<&crate::rules::Rule> = rules.iter().filter(|r| r.name == target).collect();
    match by_name.len() {
        0 => anyhow::bail!("no rule with id or name `{target}`"),
        1 => Ok(by_name[0]),
        _ => {
            let ids = by_name
                .iter()
                .map(|r| r.id.clone())
                .collect::<Vec<_>>()
                .join(", ");
            anyhow::bail!("multiple rules named `{target}`; disambiguate by id: {ids}")
        }
    }
}

/// `secreq daemon stop` — tell the running daemon to exit. The daemon's
/// approvals cache lives in memory only, so this is also how you clear
/// any "approve all" decisions you made earlier — the next wrap
/// invocation auto-spawns a fresh daemon with an empty cache.
///
/// With `force=true`, skips the graceful socket protocol and SIGKILLs
/// the daemon directly. The escape hatch for when the daemon is wedged.
pub fn daemon_stop(force: bool) -> Result<i32> {
    if force {
        match daemon_client::force_stop_daemon()
            .context("could not force-stop the consent daemon")?
        {
            daemon_client::ForceStopOutcome::Killed { pid } => {
                eprintln!("secreq: daemon (pid {pid}) killed (approvals cache cleared).");
            }
            daemon_client::ForceStopOutcome::NotRunning => {
                eprintln!("secreq: no daemon was running (approvals cache already clear).");
            }
        }
        return Ok(0);
    }
    match daemon_client::stop_daemon().context("could not stop the consent daemon")? {
        true => {
            eprintln!("secreq: daemon stopped (approvals cache cleared).");
            Ok(0)
        }
        false => {
            eprintln!("secreq: no daemon was running (approvals cache already clear).");
            Ok(0)
        }
    }
}

/// `secreq daemon status` — report whether a daemon is running, without
/// spawning one. Exit code follows the `systemctl status` convention so
/// scripts can branch on it: `0` when a daemon is running, [`STATUS_EXIT_NOT_RUNNING`]
/// when none is. The pid is decided by the pidfile flock, so it's always a
/// live process; the build id comes from the `Hello` handshake and is absent
/// when the daemon holds the lock but doesn't answer (wedged).
pub fn daemon_status() -> Result<i32> {
    let socket = crate::daemon::server::default_socket_path()?;
    let log = crate::daemon::log::log_path()?;
    match daemon_client::daemon_status().context("could not query the consent daemon")? {
        daemon_client::DaemonStatus::NotRunning => {
            println!("secreq daemon: not running");
            println!("  socket: {} (created on next spawn)", socket.display());
            println!("  log:    {}", log.display());
            Ok(STATUS_EXIT_NOT_RUNNING)
        }
        daemon_client::DaemonStatus::Running { pid, build_id } => {
            println!("secreq daemon: running");
            println!("  pid:    {pid}");
            match build_id {
                Some(id) if id == crate::BUILD_ID => {
                    println!("  build:  {id} (matches this CLI)");
                }
                Some(id) => {
                    println!("  build:  {id} (stale; this CLI is {})", crate::BUILD_ID);
                }
                None => {
                    println!("  build:  unknown (daemon holds the lock but isn't answering)");
                }
            }
            println!("  socket: {}", socket.display());
            println!("  log:    {}", log.display());
            Ok(0)
        }
    }
}

/// Exit code for `secreq daemon status` when no daemon is running. Mirrors
/// `systemctl status`'s "program is not running" code so shell scripts can
/// branch on `secreq daemon status` the same way.
const STATUS_EXIT_NOT_RUNNING: i32 = 3;

/// How many trailing lines of the existing log to print before
/// following, matching the familiar `tail -f` default feel (but a touch
/// larger — daemon lines are terse and a session's worth of context is
/// useful when you've just attached).
const TAIL_INITIAL_LINES: usize = 50;

/// Poll cadence for the log follower. The log is low-volume (a handful
/// of lines per consent flow, one resource sample per minute), so a
/// fifth-of-a-second poll feels live without busy-spinning.
const TAIL_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// How long to wait for the log file to appear after spawning a fresh
/// daemon before giving up. The daemon writes its first line within
/// milliseconds of starting.
const TAIL_OPEN_TIMEOUT: Duration = Duration::from_secs(5);

/// `secreq daemon` (the default action) — ensure a daemon is running in
/// the background (spawning a detached one if needed), then tail its
/// persistent log until interrupted. `secreq daemon --fg` runs the
/// daemon in the foreground instead (handled in the CLI dispatch).
pub fn daemon_tail() -> Result<i32> {
    daemon_client::ensure_daemon_running()
        .context("could not start or reach the consent daemon")?;
    let path = crate::daemon::log::log_path()?;
    eprintln!(
        "secreq: daemon running; tailing {} (Ctrl-C to stop)",
        path.display()
    );
    tail_follow(&path)
}

/// `secreq daemon log-path` — print the persistent daemon log path and
/// exit. Scripts use this to locate the log without knowing the XDG
/// layout; it never starts a daemon.
pub fn daemon_log_path() -> Result<i32> {
    println!("{}", crate::daemon::log::log_path()?.display());
    Ok(0)
}

/// `secreq daemon install` — install (or `--undo`) a per-user login service
/// that runs `secreq daemon --fg` at login and keeps it alive.
///
/// WHY: the SSH agent socket only exists while the daemon runs. Wraps
/// auto-spawn the daemon on demand, but an incoming SSH connection has nothing
/// to spawn it — so `SSH_AUTH_SOCK` points at a dead socket unless the daemon
/// already happens to be up. A login service keeps it live.
///
/// Writing the service file is pure ([`autostart::plan`]/[`autostart::apply`]);
/// loading it shells out to `launchctl`/`systemctl`
/// ([`autostart::load_service`]). If the load step fails (e.g. a headless
/// Linux box without a user bus), we still report the file was written and how
/// to load it by hand rather than hard-failing.
pub fn daemon_install(undo: bool, assume_yes: bool) -> Result<i32> {
    daemon_install_core(undo, assume_yes)?;
    Ok(0)
}

/// The reusable body of `secreq daemon install`, shared with the `ssh setup`
/// orchestrator's auto-start step. Returns `Ok(())` once the service file is
/// written (or undone); the standalone command wraps it for an exit code.
fn daemon_install_core(undo: bool, assume_yes: bool) -> Result<()> {
    let platform = autostart::current_platform();
    let home = dirs::home_dir().context("could not determine $HOME")?;
    let service_file = autostart::service_file_path(&home, platform);

    if undo {
        cliclack::intro("secreq daemon install --undo")?;
        // Best-effort unload first; an unloaded-already service isn't an error
        // we should stop on.
        if let Err(err) = autostart::unload_service(platform, &service_file) {
            cliclack::log::warning(format!(
                "couldn't unload the service (it may not have been loaded): {err:#}"
            ))?;
        }
        if autostart::remove(&home, platform)? {
            cliclack::log::success(format!("Removed {}.", service_file.display()))?;
        } else {
            cliclack::log::info("No secreq login service found — nothing to remove.")?;
        }
        cliclack::outro("Done.")?;
        return Ok(());
    }

    let exe = std::env::current_exe().context("could not determine the secreq executable path")?;
    // Canonicalize when we can so the service points at a stable path (resolves
    // symlinks like a homebrew shim); fall back to the raw path otherwise.
    let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
    let log_path = crate::daemon::log::log_path()?;

    let plan = autostart::plan(&home, platform, &exe, &log_path)?;

    cliclack::intro("secreq daemon install")?;
    cliclack::note(
        format!(
            "I'll write this login service to {}:",
            plan.service_file.display()
        ),
        &plan.contents,
    )?;
    if plan.already_installed {
        cliclack::log::info(
            "A service file already exists; it'll be rewritten (the exe path may have changed).",
        )?;
    }

    let proceed = assume_yes || prompt::confirm_default_yes("Write and load it?")?;
    if !proceed {
        cliclack::log::info("Skipped — no files changed.")?;
        cliclack::outro("Done.")?;
        return Ok(());
    }

    let changed = autostart::apply(&plan)?;
    if changed {
        cliclack::log::success(format!("wrote {}.", plan.service_file.display()))?;
    } else {
        cliclack::log::info(format!(
            "{} was already up to date.",
            plan.service_file.display()
        ))?;
    }

    match autostart::load_service(platform, &plan.service_file) {
        Ok(()) => {
            cliclack::log::success(
                "Loaded the login service — the daemon is running now and will start at login.",
            )?;
            let hint = match platform {
                autostart::Platform::Macos => "launchctl list | grep secreq",
                autostart::Platform::Linux => "systemctl --user status secreq",
            };
            cliclack::log::info(format!("Check status with: {hint}"))?;
        }
        Err(err) => {
            // Don't hard-fail after writing — the file is in place; tell the
            // user how to load it manually.
            cliclack::log::warning(format!("couldn't load the service automatically: {err:#}"))?;
            let manual = match platform {
                autostart::Platform::Macos => format!(
                    "launchctl bootstrap gui/$(id -u) {}",
                    plan.service_file.display()
                ),
                autostart::Platform::Linux => {
                    "systemctl --user daemon-reload && systemctl --user enable --now secreq.service"
                        .to_owned()
                }
            };
            cliclack::log::info(format!(
                "The file is written; load it by hand with:\n  {manual}"
            ))?;
        }
    }

    cliclack::outro("Done.")?;
    Ok(())
}

/// Print the tail of `path` then follow appended lines, `tail -f`-style.
/// Diverges until the process is interrupted (Ctrl-C); only an IO error
/// returns. Relies on the log sink writing whole lines atomically, so
/// every chunk we read ends on a line (and UTF-8) boundary.
fn tail_follow(path: &Path) -> Result<i32> {
    let mut file = open_log_with_retry(path)?;

    // Print the last `TAIL_INITIAL_LINES` lines of existing content.
    let mut existing = String::new();
    file.read_to_string(&mut existing)
        .with_context(|| format!("read daemon log {}", path.display()))?;
    let mut stdout = std::io::stdout();
    let lines: Vec<&str> = existing.lines().collect();
    let start = lines.len().saturating_sub(TAIL_INITIAL_LINES);
    for line in &lines[start..] {
        let _ = writeln!(stdout, "{line}");
    }
    let _ = stdout.flush();

    // Follow appends. `pos` tracks how far we've consumed; a shrink
    // means the file was truncated/replaced, so we restart from the top.
    let mut pos = file
        .stream_position()
        .with_context(|| format!("seek daemon log {}", path.display()))?;
    loop {
        sleep(TAIL_POLL_INTERVAL);
        let len = std::fs::metadata(path)
            .with_context(|| format!("stat daemon log {}", path.display()))?
            .len();
        if len < pos {
            pos = 0;
        }
        if len > pos {
            file.seek(SeekFrom::Start(pos))
                .with_context(|| format!("seek daemon log {}", path.display()))?;
            let mut chunk = String::new();
            let read = file
                .read_to_string(&mut chunk)
                .with_context(|| format!("read daemon log {}", path.display()))?;
            let _ = stdout.write_all(chunk.as_bytes());
            let _ = stdout.flush();
            pos += read as u64;
        }
    }
}

/// Open the log file, retrying briefly: a daemon we just spawned may not
/// have created it yet.
fn open_log_with_retry(path: &Path) -> Result<File> {
    let deadline = Instant::now() + TAIL_OPEN_TIMEOUT;
    loop {
        match File::open(path) {
            Ok(file) => return Ok(file),
            Err(_) if Instant::now() < deadline => sleep(Duration::from_millis(50)),
            Err(err) => {
                return Err(err).with_context(|| format!("open daemon log {}", path.display()));
            }
        }
    }
}

/// `secreq edit` — open the wraps config in `$EDITOR`.
pub fn edit_cmd(config_path: Option<&Path>) -> Result<i32> {
    let config_path = resolve_config_path(config_path)?;
    let editor = std::env::var("EDITOR")
        .or_else(|_| std::env::var("VISUAL"))
        .unwrap_or_else(|_| "vi".to_owned());

    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if !config_path.exists() {
        std::fs::write(&config_path, "{\n}\n")?;
    }
    let status = Command::new(&editor)
        .arg(&config_path)
        .status()
        .with_context(|| format!("failed to launch $EDITOR ({editor})"))?;
    Ok(status.code().unwrap_or(0))
}

/// `secreq check` — validate the config.
pub fn check(config_path: Option<&Path>) -> Result<i32> {
    let config_path = resolve_config_path(config_path)?;
    if !config_path.is_file() {
        println!(
            "✗ no config at {} (run `secreq init`)",
            config_path.display()
        );
        return Ok(1);
    }
    let mut config = WrapsConfig::load(&config_path)?;
    config.merge_builtin_providers();

    let mut problems = 0;
    println!("Config: {}", config_path.display());

    // Every env entry must reference a known provider.
    for wrap in config.wraps.values() {
        for (env_name, ref_str) in &wrap.env {
            let Some(reference) = Reference::parse(ref_str) else {
                println!(
                    "  ✗ {}.env.{}: not a valid `secret://provider/locator` reference",
                    wrap.name, env_name
                );
                problems += 1;
                continue;
            };
            if !config.providers.contains_key(&reference.provider) {
                println!(
                    "  ✗ {}.env.{}: unknown provider scheme `{}`",
                    wrap.name, env_name, reference.provider
                );
                problems += 1;
            }
        }
    }

    if problems == 0 {
        println!(
            "✓ config OK: {} wrap(s), {} provider(s)",
            config.wraps.len(),
            config.providers.len()
        );
        Ok(0)
    } else {
        println!("✗ {problems} problem(s) found");
        Ok(1)
    }
}

/// `secreq doctor` — `check` plus confirm used providers' CLIs are on PATH.
pub fn doctor(config_path: Option<&Path>) -> Result<i32> {
    let exit = check(config_path)?;
    let config_path = resolve_config_path(config_path)?;
    if !config_path.is_file() {
        return Ok(exit);
    }
    let mut config = WrapsConfig::load(&config_path)?;
    config.merge_builtin_providers();

    let mut problems = 0;

    // 1. Wrap shadowing: for every wrap, the first thing `execvp(<bin>, …)`
    // finds on PATH must be *our* shim. Detects the common failure where
    // homebrew (or any other path-prepending tool) shadows our shim dir.
    println!("\nWrap resolution (the first match on PATH):");
    if config.wraps.is_empty() {
        println!("  (no wraps configured)");
    } else if let Some(shim_dir) = config.shim_dir.as_ref() {
        for wrap_name in config.wraps.keys() {
            let expected = shim_dir.join(wrap_name);
            match first_on_path(wrap_name) {
                Some(found) if found == expected => {
                    println!("  ✓ {wrap_name} → {} (shim)", found.display());
                }
                Some(found) => {
                    println!(
                        "  ✗ {wrap_name} → {} (shadowed; expected the shim at {})",
                        found.display(),
                        expected.display()
                    );
                    problems += 1;
                }
                None => {
                    println!("  ✗ {wrap_name} → not on PATH at all");
                    problems += 1;
                }
            }
        }
        if problems > 0 {
            println!(
                "\n  Fix: make sure {} comes before other PATH entries (e.g. /opt/homebrew/bin) \
                in your shell's startup. zsh users: the secreq init block must be in .zshrc, \
                not .zshenv, because .zshrc runs after .zprofile (where `brew shellenv` lives).",
                shim_dir.display()
            );
        }
    } else {
        println!("  (no $shim_dir configured — run `secreq init`)");
        problems += 1;
    }

    // 2. Provider CLIs.
    let used: std::collections::BTreeSet<String> = config
        .wraps
        .values()
        .flat_map(|w| w.env.values())
        .filter_map(|v| Reference::parse(v).map(|r| r.provider))
        .collect();

    println!("\nProvider CLIs (used by a wrap):");
    if used.is_empty() {
        println!("  (no wraps reference any provider yet)");
    } else {
        for scheme in &used {
            let Some(provider) = config.providers.get(scheme) else {
                continue;
            };
            let Some(program) = provider::retrieve_program(provider) else {
                continue;
            };
            if which_on_path(program) {
                println!("  ✓ {scheme} → {program}");
            } else {
                println!("  ✗ {scheme} → {program} (not found on PATH)");
                problems += 1;
            }
        }
    }

    if problems > 0 {
        println!("\n✗ {problems} problem(s) found");
        return Ok(1);
    }
    Ok(exit)
}

/// What `execvp(name, …)` would resolve to: the first executable named
/// `name` on the current `PATH`, in order. Returns `None` if not found.
fn first_on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if is_executable(&candidate) {
            return Some(candidate);
        }
    }
    None
}

// ── Internal helpers ──────────────────────────────────────────────────────

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
    config_path
        .map(PathBuf::from)
        .or_else(wraps::default_config_path)
        .context("could not determine config path (no XDG_CONFIG_HOME / no $HOME?)")
}

/// A parsed env reference: the variable name and its `secret://` target.
#[derive(Debug)]
pub(crate) struct EnvRef {
    pub name: String,
    pub reference: Reference,
}

/// Scan `(name, value)` env pairs for `secret://provider/locator` values.
/// A value that *looks* like a reference (starts with the scheme) but does
/// not parse is a hard error, naming the variable — we never silently pass
/// a literal `secret://…` to the child. Values that don't look like a
/// reference at all pass through untouched (not returned here).
pub(crate) fn scan_env_refs(env: &[(String, String)]) -> Result<Vec<EnvRef>> {
    let mut refs = Vec::new();
    for (name, value) in env {
        if !Reference::looks_like_ref(value) {
            continue;
        }
        let reference = Reference::parse(value).with_context(|| {
            format!(
                "env var `{name}`: `{value}` is not a valid `secret://provider/locator` reference"
            )
        })?;
        refs.push(EnvRef {
            name: name.clone(),
            reference,
        });
    }
    Ok(refs)
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
}

/// Build the daemon [`proto::Ask`] from explicit pieces. Pure — no I/O
/// beyond reading the providers snapshot already loaded into `config`.
///
/// Note the `ppid`/`parent_start_time` fall back to `0` when the caller
/// chain is empty. The `x` path guards against that case *before* calling
/// here (a meaningless dedupe key is a fail-closed condition for `x`); a
/// future `run` caller is the only one that would ever rely on the fallback.
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
        });
    }

    let parent = callers.first();
    proto::Ask {
        command: spec.command,
        cwd: cwd.display().to_string(),
        callers: callers
            .iter()
            .map(|c| proto::Caller {
                pid: c.pid,
                name: c.name.clone(),
                command: c.command.clone(),
                start_time: c.start_time,
            })
            .collect(),
        secrets,
        providers,
        dedupe_key: proto::DedupeKey {
            wrap: spec.dedupe_wrap,
            ppid: parent.map(|p| p.pid).unwrap_or(0),
            parent_start_time: parent.map(|p| p.start_time).unwrap_or(0),
        },
        // Wrap / run asks are never SSH sign asks; only the in-process SSH
        // agent path sets this.
        ssh: None,
        allow_remember: spec.allow_remember,
    }
}

/// Build a consent ask, send it to the daemon, and return its decision +
/// daemon-resolved secret values. The daemon does the resolution itself so
/// a parallel burst of N asks triggers exactly one provider call per
/// secret — fixing the "50 Touch ID prompts from 50 `gh api` calls"
/// problem the file-lock approach couldn't.
fn obtain_wrap_consent(
    wrap: &Wrap,
    callers: &[provenance::Caller],
    args: &[String],
) -> Result<daemon_client::ConsentOutcome> {
    // No direct parent ⇒ the dedupe key would be meaningless. Synthetic
    // invocations (e.g. some test harnesses) land here. Fail closed before
    // building an ask with a zeroed-out parent. (`build_ask` tolerates an
    // empty chain for `run`; `x` must not.)
    if callers.is_empty() {
        bail!("could not determine direct parent process; refusing to request consent");
    }

    let cwd = std::env::current_dir().context("could not determine current directory")?;
    let mut command = vec![wrap.name.clone()];
    command.extend(args.iter().cloned());

    // Parse the wrap's env into references. Bare-locator wraps (no
    // `secret://...` prefix) never made it through `wraps::parse`, so we can
    // assume `Reference::parse` succeeds — but if it doesn't, surface the
    // malformed ref early instead of sending a junk ask the daemon would
    // reject at resolution time.
    let config = load_config_or_default(None)?;
    let refs = parse_wrap_refs(wrap)?;

    let ask = build_ask(
        AskSpec {
            dedupe_wrap: wrap.name.clone(),
            command,
            refs: &refs,
            reason: wrap.reason.clone(),
            // Wrap (`x`) asks may persist a remembered approval; only
            // `secreq run` disables this.
            allow_remember: true,
        },
        callers,
        &cwd,
        &config,
    );

    daemon_client::request_consent(ask, config.wait_indicator_enabled())
        .context("daemon consent request failed")
}

/// Parse a wrap's `env` map into `(name, Reference)` pairs, surfacing a
/// malformed `secret://` ref with the wrap-specific error message.
fn parse_wrap_refs(wrap: &Wrap) -> Result<Vec<(String, Reference)>> {
    let mut refs = Vec::with_capacity(wrap.env.len());
    for (env_name, ref_str) in &wrap.env {
        let reference = Reference::parse(ref_str).with_context(|| {
            format!(
                "wrap `{}`.env.{env_name}: `{ref_str}` is not a valid `secret://provider/locator` reference",
                wrap.name
            )
        })?;
        refs.push((env_name.clone(), reference));
    }
    Ok(refs)
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

/// Resolve every env entry for the wrap through its provider. Reuses the
/// resolve grouping/batching machinery by building a one-shot manifest with
/// the wrap's env as eager secrets.
fn resolve_wrap_env(config: &WrapsConfig, wrap: &Wrap) -> Result<Vec<(String, SecretValue)>> {
    let refs = parse_wrap_refs(wrap)?;
    resolve_refs_client_side(config, &refs, wrap.reason.as_deref())
}

/// Resolve a set of references client-side (the `--yes` path — no daemon, no
/// coalescing). Reuses [`resolve::resolve_all`] for batching/grouping by
/// adapting the providers into a one-shot manifest with each ref as an eager
/// secret.
pub(crate) fn resolve_refs_client_side(
    config: &WrapsConfig,
    refs: &[(String, Reference)],
    reason: Option<&str>,
) -> Result<Vec<(String, SecretValue)>> {
    // Adapt the WrapsConfig.providers into a Manifest so we can reuse
    // resolve::resolve_all (which already handles batching, defaults,
    // grouped invocations).
    let manifest = crate::manifest::Manifest {
        groups: std::collections::BTreeMap::new(),
        providers: config.providers.clone(),
    };

    let requests = refs
        .iter()
        .map(|(name, reference)| SecretRequest {
            name: name.clone(),
            provider: reference.provider.clone(),
            locator: reference.locator.clone(),
            group: None,
            reason: reason.map(|s| s.to_owned()),
            description: None,
            default: None,
            source: Source::Eager,
        })
        .collect();
    let plan = resolve::ResolutionPlan { requests };
    let resolved = resolve::resolve_all(&manifest, &plan)?;
    Ok(resolved.into_iter().map(|r| (r.name, r.value)).collect())
}

/// Locate the *real* binary on `$PATH`, skipping
/// - the configured shim dir, and
/// - any other secreq-managed shim found on PATH (identified by our
///   sentinel string in the file body).
///
/// The second exclusion is load-bearing: a user can end up with stray
/// shims in `~/.local/bin`, `/usr/local/bin`, or wherever an earlier
/// `secreq wrap` left one before they moved the shim dir. Those stray
/// shims are still functional (`exec secreq x <wrap> "$@"`) but secreq
/// doesn't know about them — and if the spawned-process PATH happens
/// to put one *before* the real binary's location, find_real_binary
/// would otherwise pick up the stray and spawn `secreq` recursively,
/// producing infinite-depth `secreq gh → secreq gh → secreq gh`
/// process chains. Checking the sentinel kills that loop dead.
fn find_real_binary(binary: &str, skip: Option<&Path>) -> Result<PathBuf> {
    let path = std::env::var_os("PATH").context("no PATH in environment")?;
    for dir in std::env::split_paths(&path) {
        if skip.is_some_and(|s| s == dir) {
            continue;
        }
        let candidate = dir.join(binary);
        if !is_executable(&candidate) {
            continue;
        }
        if is_secreq_shim(&candidate) {
            // Silently skip — duplicate shims are user-config drift, not
            // an error condition. We just don't want them in the lookup.
            continue;
        }
        return Ok(candidate);
    }
    bail!("could not find a non-shim `{binary}` on PATH. Is it installed?")
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    meta.is_file() && (meta.permissions().mode() & 0o111 != 0)
}

/// True iff the file at `path` is a secreq-managed shim — i.e. carries
/// the sentinel string our `shim::body` emits.
///
/// We read at most the first 256 bytes, which is plenty: the sentinel
/// sits on line 2 of a 5-line script. Larger files we read partially
/// and bail; native binaries we'd never bother loading.
fn is_secreq_shim(path: &Path) -> bool {
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut head = [0u8; 256];
    let n = f.read(&mut head).unwrap_or(0);
    let prefix = &head[..n];
    // Quick reject: a Mach-O / ELF binary won't start with `#!`. Saves a
    // substring search on the typical case.
    if !prefix.starts_with(b"#!") {
        return false;
    }
    prefix
        .windows(crate::shim::SENTINEL.len())
        .any(|w| w == crate::shim::SENTINEL.as_bytes())
}

/// Pass through an unwrapped binary unchanged. Used when `secreq <bin>` is
/// invoked for a binary with no configured wrap — keeps the alias-everything
/// workflow ergonomic.
fn passthrough_unwrapped(binary: &str, args: &[String], skip: Option<&Path>) -> Result<i32> {
    let real = find_real_binary(binary, skip)?;
    let err = Command::new(real).args(args).exec();
    // exec() only returns on failure.
    Err(anyhow::anyhow!("failed to exec `{binary}`: {err}"))
}

fn parse_env_assignments(envs: &[String]) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for raw in envs {
        let (k, v) = raw
            .split_once('=')
            .with_context(|| format!("--env `{raw}` is not in NAME=secret://… form"))?;
        if k.is_empty() {
            bail!("--env `{raw}` has an empty name");
        }
        if Reference::parse(v).is_none() {
            bail!("--env `{raw}`: value must be a `secret://provider/locator` reference");
        }
        out.insert(k.to_owned(), v.to_owned());
    }
    Ok(out)
}

/// Serialize a `WrapsConfig` to JSON-pretty (the parser accepts JSON5, so
/// this is a valid input). Same caveat as `store`: comments and exact
/// formatting from a hand-edited file aren't preserved through a write.
fn write_config(path: &Path, config: &WrapsConfig) -> Result<()> {
    let value = config_to_json_value(config)?;
    let text = serde_json::to_string_pretty(&value)?;
    // Validate by round-tripping before writing.
    WrapsConfig::parse(&text, &path.display().to_string())
        .context("internal: serialized config doesn't re-parse")?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, format!("{text}\n"))
        .with_context(|| format!("failed to write {}", path.display()))
}

fn config_to_json_value(config: &WrapsConfig) -> Result<serde_json::Value> {
    let mut root = serde_json::Map::new();
    if let Some(shim) = &config.shim_dir {
        root.insert(
            "$shim_dir".to_owned(),
            serde_json::Value::String(shim.display().to_string()),
        );
    }
    for (name, wrap) in &config.wraps {
        let mut obj = serde_json::Map::new();
        if let Some(reason) = &wrap.reason {
            obj.insert(
                "$reason".to_owned(),
                serde_json::Value::String(reason.clone()),
            );
        }
        let mut env_obj = serde_json::Map::new();
        for (k, v) in &wrap.env {
            env_obj.insert(k.clone(), serde_json::Value::String(v.clone()));
        }
        obj.insert("env".to_owned(), serde_json::Value::Object(env_obj));
        root.insert(name.clone(), serde_json::Value::Object(obj));
    }
    // Providers: only include user-declared schemes, not built-ins (avoid
    // baking them into the file; built-ins overlay at load time).
    let builtin_map = crate::manifest::builtin_providers();
    let builtin_names: std::collections::BTreeSet<&str> =
        builtin_map.keys().map(String::as_str).collect();
    let user_providers: std::collections::BTreeMap<&String, &crate::manifest::Provider> = config
        .providers
        .iter()
        .filter(|(name, _)| !builtin_names.contains(name.as_str()))
        .collect();
    if !user_providers.is_empty() {
        let mut providers_obj = serde_json::Map::new();
        for (name, p) in user_providers {
            providers_obj.insert(name.clone(), provider_to_json_value(p));
        }
        root.insert(
            "providers".to_owned(),
            serde_json::Value::Object(providers_obj),
        );
    }
    if !config.ssh.is_empty() {
        let mut ssh_obj = serde_json::Map::new();
        for (name, identity) in &config.ssh {
            let mut obj = serde_json::Map::new();
            if let Some(reason) = &identity.reason {
                obj.insert(
                    "$reason".to_owned(),
                    serde_json::Value::String(reason.clone()),
                );
            }
            obj.insert(
                "public_key".to_owned(),
                serde_json::Value::String(identity.public_key.clone()),
            );
            obj.insert(
                "private_key".to_owned(),
                serde_json::Value::String(identity.private_key.to_string()),
            );
            ssh_obj.insert(name.clone(), serde_json::Value::Object(obj));
        }
        root.insert(
            wraps::SSH_KEY.to_owned(),
            serde_json::Value::Object(ssh_obj),
        );
    }
    Ok(serde_json::Value::Object(root))
}

fn provider_to_json_value(p: &crate::manifest::Provider) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    obj.insert(
        "retrieve".to_owned(),
        serde_json::Value::Array(
            p.retrieve
                .iter()
                .map(|s| serde_json::Value::String(s.clone()))
                .collect(),
        ),
    );
    // We don't currently round-trip store/retrieve_batch from user-defined
    // providers when we re-emit the config; users who declare those should
    // edit the file by hand. `secreq edit` is the supported path.
    serde_json::Value::Object(obj)
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

// ── Interactive prompts (cliclack-backed) ─────────────────────────────────
//
// cliclack gives us value-typed select (no index lookup), real placeholders,
// per-prompt validation, and intro/outro/note framing so multi-step flows
// (init, wrap) look like one operation rather than a stream of bare lines.

mod prompt {
    use std::collections::BTreeMap;

    use anyhow::{Context, Result};

    use crate::manifest::Provider;
    use crate::reference::Reference;

    /// Prompt for a value with a default. cliclack's `default_input` pre-fills
    /// the line; an empty submission accepts the default unchanged.
    pub(super) fn read_with_default(label: &str, default: &str) -> Result<String> {
        cliclack::input(label)
            .default_input(default)
            .placeholder(default)
            .interact()
            .context("interactive input failed (need a real terminal)")
    }

    /// Prompt for an optional value. Empty submission returns `None`.
    pub(super) fn optional_read(label: &str) -> Result<Option<String>> {
        let value: String = cliclack::input(label)
            .required(false)
            .placeholder("(empty to skip)")
            .interact()
            .context("interactive input failed (need a real terminal)")?;
        if value.is_empty() {
            Ok(None)
        } else {
            Ok(Some(value))
        }
    }

    /// Prompt for the identity name (the key under the `ssh` block). Used by
    /// the `ssh setup` orchestrator's identity step, which has no preset name.
    pub(super) fn ssh_identity_name() -> Result<String> {
        cliclack::input("Identity name (the key under the `ssh` block)")
            .placeholder("e.g. github")
            .validate(|s: &String| {
                if s.trim().is_empty() {
                    Err("name can't be empty")
                } else {
                    Ok(())
                }
            })
            .interact()
            .context("interactive input failed (need a real terminal)")
            .map(|s: String| s.trim().to_owned())
    }

    /// Prompt for a `secret://provider/locator` reference (the manual
    /// fallback when op discovery is unavailable or declined). Validates the
    /// input parses before returning.
    pub(super) fn ssh_private_key_reference() -> Result<Reference> {
        let raw: String = cliclack::input("Private key reference (secret://provider/locator)")
            .placeholder("secret://op/Private/GitHub/private key")
            .validate(|s: &String| match Reference::parse(s) {
                Some(_) => Ok(()),
                None => Err("must be a `secret://provider/locator` reference"),
            })
            .interact()
            .context("interactive input failed (need a real terminal)")?;
        Reference::parse(&raw).context("internal: validated reference failed to re-parse")
    }

    /// Prompt for an inline OpenSSH public key (path or pasted line), then
    /// validate it parses.
    pub(super) fn ssh_public_key() -> Result<String> {
        let raw: String = cliclack::input("Public key (path to a .pub file, or the ssh-… line)")
            .placeholder("ssh-ed25519 AAAA… me@host")
            .interact()
            .context("interactive input failed (need a real terminal)")?;
        super::resolve_public_key(raw.trim())
    }

    pub(super) fn confirm_default_yes(prompt: &str) -> Result<bool> {
        cliclack::confirm(prompt)
            .initial_value(true)
            .interact()
            .context("interactive confirm failed (need a real terminal)")
    }

    /// Ask whether this wrap should inject secrets or just gate the
    /// command. A gate-only wrap (no env) still routes the binary through
    /// the consent daemon but injects nothing — the model for tools like
    /// `op` that have no secret to pass.
    pub(super) fn wrap_is_gate_only() -> Result<bool> {
        let choice: String = cliclack::select("What should this wrap do?")
            .item(
                "secrets".to_owned(),
                "Inject secrets",
                "resolve secret:// references into env vars",
            )
            .item(
                "gate".to_owned(),
                "Gate only (no secrets)",
                "just require consent before the command runs",
            )
            .interact()
            .context("interactive selection failed")?;
        Ok(choice == "gate")
    }

    /// Drive the interactive `secreq wrap` env-collection loop: pick a
    /// provider, name the env var, supply a locator; loop until the user
    /// signals they're done.
    pub(super) fn interactive_wrap_envs(
        providers: &BTreeMap<String, Provider>,
    ) -> Result<BTreeMap<String, String>> {
        if providers.is_empty() {
            anyhow::bail!("no providers available; declare some in your config first");
        }

        let mut env = BTreeMap::new();
        loop {
            // cliclack `select<T>` returns the value associated with the
            // chosen item (not an index) — passing the provider name as the
            // value means no lookup-by-position bug surface.
            let mut sel = cliclack::select::<String>("Provider for the next env var");
            for (name, provider) in providers {
                let hint = if provider.store.is_some() {
                    "supports store"
                } else {
                    "retrieve-only"
                };
                sel = sel.item(name.clone(), name.as_str(), hint);
            }
            let provider: String = sel
                .interact()
                .context("interactive provider selection failed")?;

            let env_name: String = cliclack::input("Environment variable name")
                .placeholder("e.g. GITHUB_TOKEN")
                .validate(|s: &String| {
                    if !s.is_empty()
                        && s.chars()
                            .next()
                            .is_some_and(|c| c == '_' || c.is_ascii_alphabetic())
                        && s.chars().all(|c| c == '_' || c.is_ascii_alphanumeric())
                    {
                        Ok(())
                    } else {
                        Err("env var names must match `[A-Za-z_][A-Za-z0-9_]*`")
                    }
                })
                .interact()
                .context("interactive input failed")?;

            let locator: String = cliclack::input("Locator")
                .placeholder("provider-specific address (e.g. Personal/GitHub Token/credential)")
                .interact()
                .context("interactive input failed")?;

            let ref_str = format!("secret://{provider}/{locator}");
            if Reference::parse(&ref_str).is_none() {
                cliclack::log::warning(format!("invalid ref `{ref_str}`; try again"))?;
                continue;
            }
            env.insert(env_name, ref_str);

            let again = cliclack::confirm("Add another env var?")
                .initial_value(false)
                .interact()
                .context("interactive confirm failed")?;
            if !again {
                return Ok(env);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

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
            },
            &callers,
            std::path::Path::new("/tmp/proj"),
            &config,
        );
        assert_eq!(ask.dedupe_key.wrap, "run");
        assert_eq!(ask.command, vec!["./deploy.sh", "--prod"]);
        assert!(!ask.allow_remember);
        assert_eq!(ask.secrets.len(), 1);
        assert_eq!(ask.secrets[0].name, "DATABASE_URL");
        assert_eq!(ask.secrets[0].provider, "op");
        assert_eq!(ask.secrets[0].locator, "Work/PG/url");
        assert_eq!(ask.dedupe_key.ppid, 42);
    }

    #[test]
    fn scan_env_refs_returns_only_well_formed_refs() {
        let env = vec![
            ("PLAIN".to_owned(), "hello".to_owned()),
            ("DB".to_owned(), "secret://op/Work/PG/url".to_owned()),
            ("PG".to_owned(), "postgres://host/db".to_owned()),
        ];
        let refs = scan_env_refs(&env).unwrap();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].name, "DB");
        assert_eq!(refs[0].reference.provider, "op");
        assert_eq!(refs[0].reference.locator, "Work/PG/url");
    }

    #[test]
    fn scan_env_refs_errors_on_a_malformed_ref_naming_the_var() {
        let env = vec![("BAD".to_owned(), "secret://noslash".to_owned())];
        let err = scan_env_refs(&env).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("BAD"), "error should name the var: {msg}");
    }

    #[test]
    fn effective_env_layers_envfile_under_inherited() {
        let inherited = vec![("A".to_owned(), "from_env".to_owned())];
        let envfile = vec![
            ("A".to_owned(), "from_file".to_owned()), // inherited wins
            ("B".to_owned(), "secret://op/x".to_owned()), // file-only
        ];
        let eff = effective_env(&inherited, &envfile);
        assert_eq!(eff.get("A").map(String::as_str), Some("from_env"));
        assert_eq!(eff.get("B").map(String::as_str), Some("secret://op/x"));
    }

    #[test]
    fn overrides_carry_filed_plain_vars_and_resolved_refs_only() {
        // Given the effective env + resolved values, the overrides passed to
        // exec::run must be: file-only plain vars + every resolved ref.
        // Inherited plain vars are NOT re-emitted (the child inherits them).
        let inherited = vec![("PATH".to_owned(), "/usr/bin".to_owned())];
        let envfile = vec![
            ("PLAIN".to_owned(), "hello".to_owned()),
            ("TOKEN".to_owned(), "secret://op/x".to_owned()),
        ];
        let eff = effective_env(&inherited, &envfile);
        let resolved = vec![("TOKEN".to_owned(), "real-token".to_owned())];
        let mut overrides = build_overrides(&eff, &inherited, &resolved);
        overrides.sort();
        assert_eq!(
            overrides,
            vec![
                ("PLAIN".to_owned(), "hello".to_owned()),
                ("TOKEN".to_owned(), "real-token".to_owned()),
            ]
        );
    }

    fn make_executable(path: &Path) {
        let mut perms = std::fs::metadata(path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(path, perms).unwrap();
    }

    #[test]
    fn is_secreq_shim_detects_a_managed_shim() {
        // Mirrors what `shim::body` writes: an sh script whose second
        // line carries the SENTINEL string.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gh");
        std::fs::write(
            &path,
            "#!/bin/sh\n# secreq-managed-shim: wrap=gh\nexec secreq x gh \"$@\"\n",
        )
        .unwrap();
        make_executable(&path);
        assert!(is_secreq_shim(&path));
    }

    #[test]
    fn is_secreq_shim_rejects_a_regular_script() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gh");
        std::fs::write(&path, "#!/bin/sh\necho hello\n").unwrap();
        make_executable(&path);
        assert!(!is_secreq_shim(&path));
    }

    #[test]
    fn is_secreq_shim_rejects_a_native_binary() {
        // Mach-O / ELF headers don't start with `#!`, so our cheap reject
        // path should kick in immediately. Use a tiny binary-like fixture:
        // 4 bytes that aren't a shebang.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gh");
        std::fs::write(&path, b"\x7fELF\0\0\0\0").unwrap();
        make_executable(&path);
        assert!(!is_secreq_shim(&path));
    }

    #[test]
    fn is_secreq_shim_returns_false_for_missing_files() {
        let path = std::path::PathBuf::from("/this/does/not/exist/gh");
        assert!(!is_secreq_shim(&path));
    }

    #[test]
    fn write_config_preserves_ssh_block() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wraps.json5");

        let mut config = WrapsConfig::default();
        config.wraps.insert(
            "gh".to_owned(),
            Wrap {
                name: "gh".to_owned(),
                reason: Some("GitHub API access".to_owned()),
                env: std::iter::once((
                    "GITHUB_TOKEN".to_owned(),
                    "secret://op/Private/gh/token".to_owned(),
                ))
                .collect(),
            },
        );
        config.ssh.insert(
            "github".to_owned(),
            wraps::SshIdentity {
                reason: Some("git pushes".to_owned()),
                public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1 me@mac".to_owned(),
                private_key: Reference::parse("secret://op/Private/GitHub/private key").unwrap(),
            },
        );

        write_config(&path, &config).unwrap();

        let reloaded = WrapsConfig::load(&path).unwrap();
        let id = reloaded
            .ssh
            .get("github")
            .expect("ssh identity must survive a write/reload round-trip");
        assert_eq!(id.reason.as_deref(), Some("git pushes"));
        assert_eq!(id.public_key, "ssh-ed25519 AAAAC3NzaC1lZDI1 me@mac");
        assert_eq!(id.private_key.provider, "op");
        assert_eq!(id.private_key.locator, "Private/GitHub/private key");
    }
}
