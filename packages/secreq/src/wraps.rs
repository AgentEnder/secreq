//! The `config.toml` model: per-binary wraps, providers, SSH identities.
//!
//! `secreq` resolves secrets *for specific binaries you've wrapped*. The config
//! lives at `~/.secreq/config.toml` (`$SECREQ_HOME/config.toml`; user-scope
//! only — there's no project scope, that's varlock's territory).
//!
//! ```toml
//! shim_dir = "~/.secreq/shims"       # set by `secreq init`
//!
//! [wraps.gh]
//! reason = "GitHub API access"
//! env.GITHUB_TOKEN = "secret://op/Personal/GitHub Token/credential"
//!
//! [wraps.aws]
//! reason = "AWS deployments"
//! env.AWS_ACCESS_KEY_ID = "secret://op/Work/AWS/access_key_id"
//! env.AWS_SECRET_ACCESS_KEY = "secret://op/Work/AWS/secret_access_key"
//!
//! [providers.op]
//! retrieve = ["op", "read", "op://{locator}"]
//! ```
//!
//! **The top level is closed.** Wraps sit under `[wraps.<binary>]` rather than
//! at the root, so every root key is one this struct declares and an
//! unrecognised one is an error — where the root used to be an open namespace
//! in which a mistyped `providers` silently became a wrap.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::manifest::{builtin_providers, Provider};
use crate::reference::Reference;

/// Top-level configuration loaded from `config.toml`.
///
/// **Every top-level key is known.** Wraps live under `[wraps.<binary>]`
/// rather than at the root, which is what lets this be an ordinary
/// `deny_unknown_fields` struct: a mistyped `provdiers` is an error instead of
/// silently becoming a wrap for a binary of that name.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WrapsConfig {
    /// Where the PATH shims live. `None` until `secreq init` runs.
    #[serde(
        default,
        deserialize_with = "de_tilde_path",
        skip_serializing_if = "Option::is_none"
    )]
    pub shim_dir: Option<PathBuf>,
    /// Configured per-binary wraps, keyed by binary name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub wraps: BTreeMap<String, Wrap>,
    /// Provider scheme definitions (built-ins overlay these).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub providers: BTreeMap<String, Provider>,
    /// SSH identities served by the agent, keyed by identity name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub ssh: BTreeMap<String, SshIdentity>,
    /// Whether a blocked wrap prints the stderr "waiting for approval"
    /// indicator. `None` means unset (defaults to enabled); see
    /// [`WrapsConfig::wait_indicator_enabled`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait_indicator: Option<bool>,
    /// The rule editor's preferred "Open in editor" target (an editor id).
    /// `None` means the split-button falls back to the first detected editor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editor: Option<String>,
}

/// `shim_dir` is written with a leading `~/` by `secreq init` and read back as
/// an absolute path.
fn de_tilde_path<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<PathBuf>, D::Error> {
    let raw = Option::<String>::deserialize(d)?;
    Ok(raw.as_deref().map(expand_tilde))
}

/// One SSH identity served by the agent. `public_key` is the inline OpenSSH
/// public key (not secret); `private_key` is a `secret://provider/locator`
/// reference resolved only at SIGN time.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(deny_unknown_fields))]
pub struct SshIdentity {
    /// Rationale shown in the consent prompt when this identity is used to
    /// sign.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Inline OpenSSH public key (`ssh-ed25519 AAAA… comment`). Answered to
    /// REQUEST_IDENTITIES without a resolve.
    pub public_key: String,
    /// A `secret://provider/locator` reference to the private key, resolved
    /// only at SIGN time.
    pub private_key: Reference,
}

/// One per-binary wrap. `env` is optional: a wrap with no env entries is
/// *gate-only* — consent is required before the binary runs, but nothing is
/// injected (used to gate tools like `op` that have no secret to pass).
/// Everything else is metadata.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(deny_unknown_fields))]
pub struct Wrap {
    /// The binary name is the key this wrap is filed under, not a property of
    /// the object, so it is absent from the schema and the serialized form.
    #[serde(skip)]
    #[cfg_attr(feature = "schema", schemars(skip))]
    pub name: String,
    /// Rationale shown in the consent prompt when this wrap is invoked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Environment variables to inject. Each value is a
    /// `secret://provider/locator` reference; resolution happens at invocation
    /// time. Omit (or leave empty) for a gate-only wrap.
    //
    // Resolution is deferred to run-time so an unreachable provider doesn't
    // break config loading.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    #[cfg_attr(
        feature = "schema",
        schemars(default, with = "crate::schema::SecretRefMap")
    )]
    pub env: BTreeMap<String, String>,
}

impl WrapsConfig {
    /// Parse from a TOML string. `source_label` names the file in errors.
    ///
    /// The `toml` crate reports a line, a column and a caret at the offending
    /// value, so its message is the diagnostic — this only prefixes the file.
    pub fn parse(text: &str, source_label: &str) -> Result<WrapsConfig> {
        let mut config: WrapsConfig = toml::from_str(text)
            .with_context(|| format!("failed to parse config: {source_label}"))?;

        // `name` is the map key on both of these, skipped by serde and filled
        // in here so callers can keep reading `wrap.name` / `provider.name`.
        for (name, wrap) in &mut config.wraps {
            wrap.name = name.clone();
        }
        for (name, provider) in &mut config.providers {
            provider.name = name.clone();
            provider.validate(name, source_label)?;
        }
        Ok(config)
    }

    /// Load from `path`.
    pub fn load(path: &Path) -> Result<WrapsConfig> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read wraps config: {}", path.display()))?;
        WrapsConfig::parse(&text, &path.display().to_string())
    }

    /// A fresh config seeded with the built-in provider set (no wraps). New
    /// config files start from this so users can rely on built-in providers
    /// without a `providers` block.
    pub fn with_builtin_providers() -> WrapsConfig {
        WrapsConfig {
            shim_dir: None,
            wraps: BTreeMap::new(),
            providers: builtin_providers(),
            ssh: BTreeMap::new(),
            wait_indicator: None,
            editor: None,
        }
    }

    /// Whether a blocked wrap should print the stderr "waiting for approval"
    /// indicator. Defaults to enabled; only an explicit `$wait_indicator:
    /// false` silences it.
    pub fn wait_indicator_enabled(&self) -> bool {
        self.wait_indicator != Some(false)
    }

    /// Look up a wrap by binary name.
    pub fn wrap(&self, name: &str) -> Option<&Wrap> {
        self.wraps.get(name)
    }

    /// The distinct `secret://provider/locator` references already used across
    /// every wrap's `env` map, sorted. Reuse is common — the same token often
    /// backs several wrapped binaries — so the interactive `secreq wrap`
    /// authoring flow offers these as pickable suggestions instead of making
    /// the user retype (or misremember) a locator they've already wired up.
    ///
    /// Only values that actually look like a `secret://` reference are
    /// collected; a stray non-reference `env` value (there shouldn't be one,
    /// but the type doesn't forbid it) is skipped rather than suggested.
    pub fn known_secret_refs(&self) -> Vec<String> {
        let mut refs: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for wrap in self.wraps.values() {
            for value in wrap.env.values() {
                if Reference::looks_like_ref(value) {
                    refs.insert(value.clone());
                }
            }
        }
        refs.into_iter().collect()
    }

    /// Merge built-in providers in as a base layer (user `providers` entries
    /// override). Convenience for callers that load a raw file and want the
    /// built-ins available.
    pub fn merge_builtin_providers(&mut self) {
        let mut merged = builtin_providers();
        for (name, provider) in std::mem::take(&mut self.providers) {
            merged.insert(name, provider);
        }
        self.providers = merged;
    }
}

/// Expand a leading `~/` in a path string.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_minimal_wrap() {
        let c = WrapsConfig::parse(
            r#"
            [wraps.gh]
            reason = "GitHub API access"
            env.GITHUB_TOKEN = "secret://op/Personal/GitHub Token/credential"
            "#,
            "t",
        )
        .unwrap();
        let w = c.wrap("gh").unwrap();
        assert_eq!(w.name, "gh");
        assert_eq!(w.reason.as_deref(), Some("GitHub API access"));
        assert_eq!(
            w.env.get("GITHUB_TOKEN").map(String::as_str),
            Some("secret://op/Personal/GitHub Token/credential")
        );
    }

    #[test]
    fn known_secret_refs_dedupes_and_sorts_across_wraps() {
        let c = WrapsConfig::parse(
            r#"
            [wraps.gh]
            env.GITHUB_TOKEN = "secret://op/Personal/GitHub/token"

            [wraps.gh_alt]
            env.GH_TOKEN = "secret://op/Personal/GitHub/token"

            [wraps.aws]
            env.AWS_ACCESS_KEY_ID = "secret://op/Work/AWS/access_key_id"
            env.AWS_SECRET_ACCESS_KEY = "secret://op/Work/AWS/secret_access_key"
            "#,
            "t",
        )
        .unwrap();
        // The token shared by `gh` and `gh_alt` appears once; output is sorted.
        assert_eq!(
            c.known_secret_refs(),
            vec![
                "secret://op/Personal/GitHub/token".to_owned(),
                "secret://op/Work/AWS/access_key_id".to_owned(),
                "secret://op/Work/AWS/secret_access_key".to_owned(),
            ]
        );
    }

    #[test]
    fn known_secret_refs_is_empty_for_gate_only_wraps() {
        let c = WrapsConfig::parse("[wraps.op]\n", "t").unwrap();
        assert!(c.known_secret_refs().is_empty());
    }

    #[test]
    fn parses_shim_dir_with_tilde_expansion() {
        let c = WrapsConfig::parse(
            r#"
            shim_dir = "~/.local/bin"
            [wraps.gh]
            env.TOK = "secret://op/x"
            "#,
            "t",
        )
        .unwrap();
        let home = dirs::home_dir().unwrap();
        assert_eq!(
            c.shim_dir.as_deref(),
            Some(home.join(".local/bin").as_path())
        );
    }

    #[test]
    fn wait_indicator_defaults_on_and_parses_explicit_toggle() {
        // Absent → enabled (None).
        let c = WrapsConfig::parse("[wraps.gh]\nenv.T = \"secret://op/x\"\n", "t").unwrap();
        assert_eq!(c.wait_indicator, None);
        assert!(c.wait_indicator_enabled());

        // Explicit false → silenced.
        let off = WrapsConfig::parse("wait_indicator = false\n", "t").unwrap();
        assert_eq!(off.wait_indicator, Some(false));
        assert!(!off.wait_indicator_enabled());

        // Explicit true → enabled.
        let on = WrapsConfig::parse("wait_indicator = true\n", "t").unwrap();
        assert_eq!(on.wait_indicator, Some(true));
        assert!(on.wait_indicator_enabled());
    }

    #[test]
    fn wait_indicator_rejects_non_boolean() {
        let err = WrapsConfig::parse("wait_indicator = \"yes\"\n", "t").unwrap_err();
        assert!(
            format!("{err:#}").contains("wait_indicator"),
            "error should name the offending key: {err:#}"
        );
    }

    #[test]
    fn editor_preference_parses_and_defaults_none() {
        let none = WrapsConfig::parse("[wraps.gh]\n", "t").unwrap();
        assert_eq!(none.editor, None);

        let set = WrapsConfig::parse("editor = \"code\"\n[wraps.gh]\n", "t").unwrap();
        assert_eq!(set.editor.as_deref(), Some("code"));
        // The reserved key doesn't leak into the wrap map.
        assert!(set.wraps.contains_key("gh"));
        assert!(!set.wraps.contains_key("editor"));
    }

    #[test]
    fn editor_preference_rejects_non_string() {
        let err = WrapsConfig::parse("editor = 42\n", "t").unwrap_err();
        assert!(
            format!("{err:#}").contains("editor"),
            "error should name the offending key: {err:#}"
        );
    }

    #[test]
    fn parses_multiple_wraps_and_a_providers_block() {
        let c = WrapsConfig::parse(
            r#"
            [wraps.gh]
            env.GITHUB_TOKEN = "secret://op/x"

            [wraps.aws]
            env.AWS_KEY = "secret://op/y"
            env.AWS_SECRET = "secret://op/z"

            [providers.custom]
            retrieve = ["printf", "%s", "{locator}"]
            "#,
            "t",
        )
        .unwrap();
        assert_eq!(c.wraps.len(), 2);
        assert!(c.providers.contains_key("custom"));
    }

    #[test]
    fn remember_setting_is_rejected_now_that_caching_is_authorization_gated() {
        // Pre-pivot we had a `remember` field for per-wrap TTLs. The daemon
        // now drops TTLs entirely: the *approvals* cache lives for the daemon
        // process, and the *secret value* cache has no expiry. `remember` no
        // longer maps onto anything configurable per-wrap, so it is an unknown
        // key like any other.
        let err = WrapsConfig::parse(
            "[wraps.gh]\nremember = \"8h\"\nenv.X = \"secret://op/x\"\n",
            "t",
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("remember"));
    }

    #[test]
    fn rejects_an_unknown_key_inside_a_wrap() {
        let err = WrapsConfig::parse("[wraps.gh]\nbogus = 1\nenv.X = \"secret://op/x\"\n", "t")
            .unwrap_err();
        assert!(format!("{err:#}").contains("bogus"));
    }

    #[test]
    fn rejects_env_vars_declared_outside_the_env_table() {
        // Common mistake: putting GITHUB_TOKEN as a sibling of `env` rather
        // than inside it. `deny_unknown_fields` catches it and the message
        // lists the keys a wrap does accept.
        let err =
            WrapsConfig::parse("[wraps.gh]\nGITHUB_TOKEN = \"secret://op/x\"\n", "t").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("GITHUB_TOKEN"), "{msg}");
        assert!(
            msg.contains("env"),
            "the message should point at `env`: {msg}"
        );
    }

    /// A mistyped reserved key used to become a wrap for a binary of that
    /// name, silently. With wraps under `[wraps.*]` the top level is closed,
    /// so it is an error that names the key.
    #[test]
    fn rejects_a_mistyped_top_level_key() {
        let err = WrapsConfig::parse("[provdiers.op]\nretrieve = [\"true\"]\n", "t").unwrap_err();
        assert!(format!("{err:#}").contains("provdiers"));
    }

    #[test]
    fn parses_a_gate_only_wrap_with_no_env() {
        // A wrap with no `env` key is a *gate-only* wrap: consent is
        // required but nothing is injected. This is how you gate a tool
        // like `op` that has no secret to pass.
        let c =
            WrapsConfig::parse("[wraps.op]\nreason = \"1Password vault access\"\n", "t").unwrap();
        let w = c.wrap("op").unwrap();
        assert_eq!(w.name, "op");
        assert_eq!(w.reason.as_deref(), Some("1Password vault access"));
        assert!(w.env.is_empty(), "gate-only wrap has no env");
    }

    #[test]
    fn parses_a_gate_only_wrap_with_an_empty_env_table() {
        // An explicit empty `env` means the same thing as omitting it.
        let c = WrapsConfig::parse("[wraps.op]\nenv = {}\n", "t").unwrap();
        let w = c.wrap("op").unwrap();
        assert!(w.env.is_empty());
        assert_eq!(w.reason, None);
    }

    #[test]
    fn parses_ssh_identities() {
        let cfg = WrapsConfig::parse(
            r#"
            [ssh.github]
            reason = "git pushes"
            public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1 me@mac"
            private_key = "secret://op/Private/gh/private key"
            "#,
            "t",
        )
        .unwrap();

        let id = cfg.ssh.get("github").unwrap();
        assert_eq!(id.reason.as_deref(), Some("git pushes"));
        assert_eq!(id.public_key, "ssh-ed25519 AAAAC3NzaC1lZDI1 me@mac");
        assert_eq!(id.private_key.provider, "op");
        assert_eq!(id.private_key.locator, "Private/gh/private key");
    }

    #[test]
    fn ssh_identity_requires_public_and_private_key() {
        let err =
            WrapsConfig::parse("[ssh.x]\npublic_key = \"ssh-ed25519 AAAA x\"\n", "t").unwrap_err();
        assert!(format!("{err:#}").contains("private_key"));
    }

    /// A `private_key` that is not a `secret://` reference is caught at load,
    /// naming the value — not at sign time, when the user is waiting on a
    /// git push.
    #[test]
    fn ssh_identity_rejects_a_malformed_private_key_ref() {
        let err = WrapsConfig::parse(
            "[ssh.x]\npublic_key = \"ssh-ed25519 AAAA x\"\nprivate_key = \"op/no-scheme\"\n",
            "t",
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("op/no-scheme"));
    }
}
