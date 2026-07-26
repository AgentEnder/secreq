//! Interactive prompts (cliclack-backed).
//!
//! cliclack gives us value-typed select (no index lookup), real
//! placeholders, per-prompt validation, and intro/outro/note framing so
//! multi-step flows (init, wrap) look like one operation rather than a
//! stream of bare lines.

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
    super::ssh::resolve_public_key(raw.trim())
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

/// Check that `locator` actually resolves, so a typo or a mangled paste
/// fails here rather than at run time. Returns whether to accept it: `true`
/// when it resolved (or the user chose to keep it anyway), `false` to
/// re-prompt.
///
/// **This reads the real secret outside the consent daemon.** That's a
/// deliberate carve-out, narrower than it looks: the value is dropped
/// immediately, never printed, never audited, and never handed to another
/// process — only its *existence* reaches the user. The gate exists to
/// decide which programs receive secrets; here the user is at their own
/// terminal configuring this very wrap, and the store still applies its own
/// authentication (1Password biometric-prompts regardless). `commands::read`
/// stays daemon-gated with no bypass because it *prints* the value, which
/// is the exfiltration primitive this carve-out is not.
fn locator_resolves(provider: &crate::manifest::Provider, locator: &str) -> Result<bool> {
    let spinner = cliclack::spinner();
    spinner.start("Checking that the locator resolves…");
    let outcome = crate::provider::retrieve(provider, locator);

    match outcome {
        Ok(crate::provider::RetrieveOutcome::Found(_)) => {
            // The value is dropped right here, unread.
            spinner.stop("Locator resolves ✓");
            Ok(true)
        }
        Ok(crate::provider::RetrieveOutcome::NotFound { status, stderr }) => {
            spinner.stop("Locator did not resolve");
            let detail = if stderr.is_empty() { status } else { stderr };
            cliclack::log::warning(format!("provider `{}`: {detail}", provider.name))?;
            cliclack::confirm("Use this locator anyway?")
                .initial_value(false)
                .interact()
                .context("interactive confirm failed")
        }
        // The provider CLI isn't installed or couldn't run at all. That's
        // not evidence about the locator, so don't block on it.
        Err(err) => {
            spinner.stop("Skipped the resolvability check");
            cliclack::log::info(format!("couldn't check this locator ({err:#})"))?;
            Ok(true)
        }
    }
}

/// Prompt for an environment variable name, validating the shell-identifier
/// shape. Shared by the "reuse an existing secret" and "define a new one"
/// branches of [`interactive_wrap_envs`].
fn prompt_env_var_name() -> Result<String> {
    cliclack::input("Environment variable name")
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
        .context("interactive input failed")
}

/// The sentinel value returned by the reuse picker when the user wants to
/// define a brand-new secret rather than reuse an existing reference. It is
/// not a valid `secret://` reference, so it can never collide with a real
/// suggestion.
const DEFINE_NEW_REF: &str = "\0new";

/// Drive the interactive `secreq wrap` env-collection loop: for each env
/// var, either reuse a `secret://` reference already wired up elsewhere
/// (`known_refs`) or define a new one (pick a provider, supply a locator);
/// loop until the user signals they're done.
pub(super) fn interactive_wrap_envs(
    providers: &BTreeMap<String, Provider>,
    known_refs: &[String],
) -> Result<BTreeMap<String, String>> {
    if providers.is_empty() {
        anyhow::bail!("no providers available; declare some in your config first");
    }

    let mut env = BTreeMap::new();
    loop {
        // Offer reuse first: the same token often backs several wrapped
        // binaries, so surfacing what's already configured saves retyping
        // (and mistyping) a locator. Empty ⇒ straight to defining a new one.
        let reused = if known_refs.is_empty() {
            None
        } else {
            let mut sel =
                cliclack::select::<String>("Reuse a secret already used by another wrap?");
            for r in known_refs {
                sel = sel.item(r.clone(), r.as_str(), "");
            }
            sel = sel.item(
                DEFINE_NEW_REF.to_owned(),
                "Define a new secret…",
                "pick a provider and locator",
            );
            let choice: String = sel
                .interact()
                .context("interactive secret selection failed")?;
            (choice != DEFINE_NEW_REF).then_some(choice)
        };

        if let Some(ref_str) = reused {
            let env_name = prompt_env_var_name()?;
            env.insert(env_name, ref_str);
        } else {
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

            let env_name = prompt_env_var_name()?;

            // The provider was chosen from `providers`, so the lookup holds.
            let provider_def = &providers[&provider];
            let ref_str = loop {
                let raw: String = cliclack::input("Locator")
                    .placeholder(
                        "provider-specific address (e.g. Personal/GitHub Token/credential)",
                    )
                    .interact()
                    .context("interactive input failed")?;

                // Accept whatever the store handed the user — a quoted
                // `op://…` reference, our own `secret://…` form, or a bare
                // locator — and reduce it to the bare locator the template
                // wants. Without this, a pasted `"op://…"` gets re-prefixed
                // into `op://"op://…"` and fails only at run time.
                let locator = crate::provider::normalize_pasted_locator(provider_def, &raw);
                if locator != raw.trim() {
                    cliclack::log::info(format!("Reading that as locator `{locator}`"))?;
                }

                let ref_str = format!("secret://{provider}/{locator}");
                if Reference::parse(&ref_str).is_none() {
                    cliclack::log::warning(format!("invalid ref `{ref_str}`; try again"))?;
                    continue;
                }

                if locator_resolves(provider_def, &locator)? {
                    break ref_str;
                }
            };
            env.insert(env_name, ref_str);
        }

        let again = cliclack::confirm("Add another env var?")
            .initial_value(false)
            .interact()
            .context("interactive confirm failed")?;
        if !again {
            return Ok(env);
        }
    }
}
