//! The gating path: `secreq <BINARY> [args…]` and `secreq run -- <cmd>`.
//!
//! This is the security-critical half of the CLI. Both entry points do the
//! same four things in the same order — work out what has to be resolved,
//! ask the daemon for consent, audit the answer, then exec the child with
//! the resolved values injected and its output masked — and differ only in
//! where the references come from: a wrap entry in `wraps.json5` for
//! [`wrap_run`], the ambient environment (plus `--env-file`) for [`run`].

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::audit::{self, AuditEntry};
use crate::consent::Decision;
use crate::daemon::client as daemon_client;
use crate::daemon::proto;
use crate::provenance;
use crate::provider;
use crate::reference::Reference;
use crate::resolve::{self, SecretRequest, Source};
use crate::secret::SecretValue;
use crate::wraps::{Wrap, WrapsConfig};

use super::binaries::{find_real_binary, passthrough_unwrapped};
use super::{build_ask, load_config_or_default, AskSpec};

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

    let Some(mut wrap) = config.wraps.get(binary).cloned() else {
        return passthrough_unwrapped(binary, args, config.shim_dir.as_deref());
    };

    // Parent-env satisfaction: an env entry whose variable already holds a
    // real value in OUR environment — non-empty and not a `secret://…`
    // marker — needs nothing injected; the child inherits the parent's
    // value as-is. Consent gates the release of secret material *by
    // secreq*, so a satisfied entry drops out of the ask entirely, and a
    // wrap whose entries are ALL satisfied runs without any consent (the
    // wrap-and-run mirror of `run`'s "nothing to resolve" fast path).
    // Deliberately not applied to gate-only wraps (empty `env`): those
    // exist to gate the binary itself, not to inject.
    let had_env_entries = !wrap.env.is_empty();
    wrap.env.retain(|name, _| !parent_env_satisfies(name));
    if had_env_entries && wrap.env.is_empty() {
        return passthrough_unwrapped(binary, args, config.shim_dir.as_deref());
    }

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
        let outcome = obtain_wrap_consent(&wrap, &callers, args, &opts)?;
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

/// Does the parent environment already satisfy a wrap env entry? True when
/// the variable is set to a non-empty value that isn't a `secret://…`
/// marker. A marker means "inject here" (the `run`-style convention), and
/// an empty value is treated as absent. A non-UTF-8 value can't be a
/// marker, so it counts as satisfied.
fn parent_env_satisfies(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|value| {
        !value.is_empty() && !value.to_str().is_some_and(Reference::looks_like_ref)
    })
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

/// Keep only the resolved entries whose name this run actually requested.
/// Defense-in-depth against a daemon bug: this filters by *name*, so it
/// catches a sibling's differently-named secret leaking in. It cannot
/// catch a same-name value swap (A's `FOO` populated with B's value) —
/// the daemon's `(provider, locator)` keying is the guarantor there.
fn filter_to_refs(
    resolved: HashMap<String, String>,
    refs: &[(String, Reference)],
) -> Vec<(String, SecretValue)> {
    use std::collections::HashSet;
    let requested: HashSet<&str> = refs.iter().map(|(name, _)| name.as_str()).collect();
    resolved
        .into_iter()
        .filter(|(name, _)| requested.contains(name.as_str()))
        .map(|(name, value)| (name, SecretValue::new(value)))
        .collect()
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
    prompt_unresolved: bool,
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

    // Nesting: this run is nested if an ancestor run already set the
    // session marker — detect that BEFORE we set it for our own children.
    // A nested run that turns out fully cached resolves without prompting
    // (the daemon gates on `nested_run`); a top-level run never sees the
    // marker, so it always prompts. We propagate the existing token (or
    // mint one from our pid) so a whole run tree shares a single session.
    let nested = std::env::var_os(crate::RUN_SESSION_ENV).is_some();
    let session = std::env::var(crate::RUN_SESSION_ENV).unwrap_or_else(|_| mint_session_token());

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

    // 2b. `--prompt-unresolved`: fill any reference whose locator resolves to
    // nothing by prompting for the value and writing it to where the locator
    // points, so the resolution below finds it normally. A read-only provider
    // surfaces a clear error here (never a silent skip).
    if prompt_unresolved && !refs.is_empty() {
        prompt_and_store_unresolved(&config, &refs, command)?;
    }

    // 3. Nothing to resolve → exec directly with the file-only plain vars.
    // No daemon contact, no consent (honest "nothing to resolve" fast path).
    if refs.is_empty() {
        let mut overrides = build_overrides(&eff, &inherited, &[]);
        overrides.push((crate::RUN_SESSION_ENV.to_owned(), session));
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
        let mut ask = build_ask(
            AskSpec {
                dedupe_wrap: "run".to_owned(),
                command: command.to_vec(),
                refs: &refs,
                reason: None,
                allow_remember: false,
                ignore_remembered: false,
            },
            &callers,
            &cwd,
            &config,
        );
        // A nested run may skip the prompt when fully cached; a top-level
        // run leaves this false, so the daemon always shows the window.
        if let Some(wrap) = ask.wrap_mut() {
            wrap.nested_run = nested;
        }
        if nested {
            if let Some(key) = session_dedupe_key(&session) {
                ask.dedupe_key = key;
            }
        }
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
        // Defense-in-depth: inject only secrets this run actually requested,
        // so a daemon bug can't leak a sibling's differently-named secret
        // here (the daemon's per-(provider,locator) slice guards same-name).
        filter_to_refs(outcome.secrets, &refs)
    };

    // 6. Substitute resolved values into the env; build the overrides.
    let resolved_plain: Vec<(String, String)> = resolved
        .iter()
        .map(|(name, value)| (name.clone(), value.expose().to_owned()))
        .collect();
    let mut env_overrides = build_overrides(&eff, &inherited, &resolved_plain);
    // Establish/propagate the run-session marker so a nested run can be
    // detected (and, when fully cached, skip its prompt).
    env_overrides.push((crate::RUN_SESSION_ENV.to_owned(), session));

    // 7. Exec with masking (unless --raw).
    let secrets_for_masking: Vec<SecretValue> = if opts.raw {
        Vec::new()
    } else {
        resolved.into_iter().map(|(_, v)| v).collect()
    };
    crate::exec::run(command, &env_overrides, &secrets_for_masking, &cwd)
}

/// The `--prompt-unresolved` pre-pass: for each reference whose locator
/// resolves to nothing, prompt for the value (masked) and persist it to
/// exactly where the locator points via the provider's `store` capability, so
/// the resolution that follows finds it. Values that already resolve are left
/// untouched (their probe value is dropped, unread).
///
/// **Consent / provenance.** Writing a secret is a write side-effect, so each
/// store is audited with an explicit `store` row (the reference address, never
/// the value; `decision = approve`). The value itself is read at the user's own
/// terminal and handed straight to the provider — the same deliberate carve-out
/// the `wrap` authoring flow already relies on (`prompt::locator_resolves`):
/// the consent daemon gates which *programs* receive secrets, and here the user
/// is interactively configuring their own secret at their own keyboard. The
/// provider's own auth still applies (1Password will biometric-prompt, etc.).
fn prompt_and_store_unresolved(
    config: &WrapsConfig,
    refs: &[(String, Reference)],
    command: &[String],
) -> Result<()> {
    let callers = provenance::caller_chain();
    for (env_name, reference) in refs {
        // Unknown provider: let the resolution step below produce its own
        // "unknown provider scheme" error rather than storing nowhere.
        let Some(provider) = config.providers.get(&reference.provider) else {
            continue;
        };

        match provider::retrieve(provider, &reference.locator) {
            // Already resolvable — the probe value is dropped here, unread.
            Ok(provider::RetrieveOutcome::Found(_)) => {}
            Ok(provider::RetrieveOutcome::NotFound { .. }) => {
                let ref_display = reference.to_string();
                cliclack::log::info(format!(
                    "`{env_name}` ({ref_display}) is not set yet — enter its value to store it."
                ))
                .ok();
                let entered = cliclack::password(format!("Value for {env_name}"))
                    .mask('•')
                    .interact()
                    .with_context(|| {
                        format!("could not read a value for `{env_name}` (need a real terminal)")
                    })?;
                let value = SecretValue::new(entered);
                // A read-only provider (or a locator the store template can't
                // round-trip) fails here with a clear error — never a silent
                // skip.
                provider::store_at_locator(provider, &reference.locator, &value).with_context(
                    || format!("could not store a value for `{env_name}` ({ref_display})"),
                )?;
                let _ = audit::append(&AuditEntry::new(
                    "store",
                    command,
                    &callers,
                    std::slice::from_ref(&ref_display),
                    Decision::Approve,
                ));
                cliclack::log::success(format!("Stored `{env_name}` at {ref_display}")).ok();
            }
            // The provider CLI couldn't run at all (not installed, etc.): that's
            // no evidence the locator is empty, so don't prompt. The resolution
            // step surfaces the real error.
            //
            // Empty like the `Found` arm above, but for the opposite reason —
            // one skips because the secret is already there, this one because
            // we learned nothing. Merging them would file two different
            // silences under one explanation.
            #[allow(clippy::match_same_arms)]
            Err(_) => {}
        }
    }
    Ok(())
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

/// Mint a run-session token for a root run: `"<pid>:<nonce>"`. The pid
/// aids debugging; the random nonce guarantees two trees never collide
/// (and one tree always coalesces, since descendants inherit it verbatim).
fn mint_session_token() -> String {
    use rand::RngCore;
    let nonce = rand::thread_rng().next_u64();
    format!("{}:{}", std::process::id(), nonce)
}

/// Parse a session token into the dedupe key every descendant run of the
/// tree shares. `parent_start_time` holds the nonce — opaque to the
/// daemon, used only to group same-session asks into one queue entry.
fn session_dedupe_key(token: &str) -> Option<proto::DedupeKey> {
    let (pid, nonce) = token.split_once(':')?;
    Some(proto::DedupeKey {
        wrap: "run".to_owned(),
        ppid: pid.parse().ok()?,
        parent_start_time: nonce.parse().ok()?,
        subject_digest: None,
    })
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
    opts: &WrapRunOpts,
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
            // `secreq run` and `--no-remember` disable it.
            allow_remember: !opts.no_remember,
            ignore_remembered: opts.no_remember,
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
            reason: reason.map(std::borrow::ToOwned::to_owned),
            description: None,
            default: None,
            source: Source::Eager,
        })
        .collect();
    let plan = resolve::ResolutionPlan { requests };
    let (resolved, _stats) = resolve::resolve_all(&manifest, &plan)?;
    Ok(resolved.into_iter().map(|r| (r.name, r.value)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn filter_to_refs_drops_unrequested_keys() {
        use crate::reference::Reference;
        let refs = vec![
            (
                "DATABASE_URL".to_owned(),
                Reference::parse("secret://op/Work/PG/url").unwrap(),
            ),
            (
                "API_KEY".to_owned(),
                Reference::parse("secret://op/Work/Stripe/key").unwrap(),
            ),
        ];
        let mut outcome: HashMap<String, String> = HashMap::new();
        outcome.insert("DATABASE_URL".to_owned(), "db-secret".to_owned());
        outcome.insert("API_KEY".to_owned(), "api-secret".to_owned());
        // A sibling's secret the daemon should never have sent, but might
        // due to a bug — the client filter must drop it.
        outcome.insert("SIBLING_TOKEN".to_owned(), "leaked".to_owned());

        let kept = filter_to_refs(outcome, &refs);
        let names: HashSet<&str> = kept.iter().map(|(n, _)| n.as_str()).collect();
        // Both requested names are kept…
        assert!(names.contains("DATABASE_URL"));
        assert!(names.contains("API_KEY"));
        // …and the unrequested sibling secret is dropped.
        assert!(!names.contains("SIBLING_TOKEN"));
        assert_eq!(kept.len(), 2);
        // Values survive intact for the kept entries.
        let db = kept
            .iter()
            .find(|(n, _)| n == "DATABASE_URL")
            .map(|(_, v)| v.expose());
        assert_eq!(db, Some("db-secret"));
    }

    #[test]
    fn session_token_round_trips_to_a_dedupe_key() {
        // "pid:nonce" → DedupeKey { wrap:"run", ppid:pid, parent_start_time:nonce }
        let key = session_dedupe_key("6042:12345678901234567890");
        assert_eq!(
            key,
            Some(proto::DedupeKey {
                wrap: "run".to_owned(),
                ppid: 6042,
                parent_start_time: 12345678901234567890,
                subject_digest: None,
            })
        );
        assert_eq!(session_dedupe_key("garbage"), None);
        assert_eq!(session_dedupe_key("6042"), None); // needs both halves
    }

    #[test]
    fn minted_session_token_parses_back() {
        let token = mint_session_token();
        let key = session_dedupe_key(&token).expect("minted token must parse");
        assert_eq!(key.wrap, "run");
        assert_eq!(key.ppid, std::process::id());
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
}
