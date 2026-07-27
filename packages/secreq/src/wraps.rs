//! The `wraps.json5` config model: per-binary wraps.
//!
//! `secreq` resolves secrets *for specific binaries you've wrapped*. The
//! config lives at `~/.secreq/wraps.json5` (`$SECREQ_HOME/wraps.json5`;
//! user-scope only — there's no project scope; that's varlock's
//! territory). Each top-level
//! key (other than reserved `providers` and `$`-prefixed metadata) names a
//! binary; its value is the wrap config for that binary.
//!
//! ```json5
//! {
//!   $shim_dir: "~/.secreq/shims",    // set by `secreq init`
//!
//!   gh: {
//!     $reason: "GitHub API access",
//!     env: {
//!       GITHUB_TOKEN: "secret://op/Personal/GitHub Token/credential",
//!     },
//!   },
//!
//!   aws: {
//!     $reason: "AWS deployments",
//!     env: {
//!       AWS_ACCESS_KEY_ID:     "secret://op/Work/AWS/access_key_id",
//!       AWS_SECRET_ACCESS_KEY: "secret://op/Work/AWS/secret_access_key",
//!     },
//!   },
//!
//!   providers: { /* … same shape as the old manifest's providers block … */ },
//! }
//! ```
//!
//! Provider definitions (`Provider`, `StoreCapability`, `BatchRetrieve`,
//! `FieldSpec`, `ValueMode`) are unchanged from the previous model — that
//! engine carries over wholesale. What changes is the *top-level shape*:
//! groups + secrets + eager-set/ambient-ref union → wraps + env maps.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde_json::Value;

// We reuse the provider model and the json-helpers from the existing
// `manifest` module. They aren't config-shape-specific.
use crate::manifest::{builtin_providers, parse_providers_value, present, Provider};
use crate::reference::Reference;

/// The reserved top-level key holding provider scheme definitions.
pub const PROVIDERS_KEY: &str = "providers";

/// `$shim_dir` — where `secreq wrap` drops PATH shims. Set by `secreq init`.
pub const SHIM_DIR_KEY: &str = "$shim_dir";

/// The reserved top-level key holding SSH identity definitions for the agent.
pub const SSH_KEY: &str = "ssh";

/// `$wait_indicator` — global toggle for the wrap's stderr "waiting for
/// approval" indicator. Absent / `true` = shown; `false` = silenced.
pub const WAIT_INDICATOR_KEY: &str = "$wait_indicator";

/// `$editor` — the editor the rule-editor's "Open in editor" split-button
/// defaults to (an id from [`crate::rule_scaffold`]'s catalog, e.g.
/// `"code"`). Machine-local like `$shim_dir`; written by the rule editor
/// when the user picks an editor.
pub const EDITOR_KEY: &str = "$editor";

/// Top-level configuration loaded from `wraps.json5`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct WrapsConfig {
    /// Where the PATH shims live. `None` until `secreq init` runs.
    pub shim_dir: Option<PathBuf>,
    /// Configured per-binary wraps.
    pub wraps: BTreeMap<String, Wrap>,
    /// Provider scheme definitions (built-ins overlay these).
    pub providers: BTreeMap<String, Provider>,
    /// SSH identities served by the agent, keyed by identity name.
    pub ssh: BTreeMap<String, SshIdentity>,
    /// `$wait_indicator` — whether a blocked wrap prints the stderr "waiting
    /// for approval" indicator. `None` means unset (defaults to enabled); see
    /// [`WrapsConfig::wait_indicator_enabled`].
    pub wait_indicator: Option<bool>,
    /// `$editor` — the rule editor's preferred "Open in editor" target
    /// (an editor id). `None` means the split-button falls back to the
    /// first detected editor.
    pub editor: Option<String>,
}

/// One SSH identity served by the agent. `public_key` is the inline OpenSSH
/// public key (not secret); `private_key` is a `secret://provider/locator`
/// reference resolved only at SIGN time.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(deny_unknown_fields))]
pub struct SshIdentity {
    /// Rationale shown in the consent prompt when this identity is used to
    /// sign.
    #[cfg_attr(feature = "schema", schemars(rename = "$reason"))]
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
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(deny_unknown_fields))]
pub struct Wrap {
    /// The binary name is the key this wrap is filed under, not a property of
    /// the object, so it is absent from the schema.
    #[cfg_attr(feature = "schema", schemars(skip))]
    pub name: String,
    /// Rationale shown in the consent prompt when this wrap is invoked.
    #[cfg_attr(feature = "schema", schemars(rename = "$reason"))]
    pub reason: Option<String>,
    /// Environment variables to inject. Each value is a
    /// `secret://provider/locator` reference; resolution happens at invocation
    /// time. Omit (or leave empty) for a gate-only wrap.
    //
    // Resolution is deferred to run-time so an unreachable provider doesn't
    // break config loading.
    #[cfg_attr(
        feature = "schema",
        schemars(default, with = "crate::schema::SecretRefMap")
    )]
    pub env: BTreeMap<String, String>,
}

impl WrapsConfig {
    /// Parse from a JSON5 string. `source_label` is used in error messages.
    pub fn parse(text: &str, source_label: &str) -> Result<WrapsConfig> {
        let root: Value = json5::from_str(text)
            .with_context(|| format!("failed to parse JSON5 config: {source_label}"))?;
        let obj = root
            .as_object()
            .with_context(|| format!("{source_label}: top level must be an object"))?;

        let mut config = WrapsConfig::default();

        for (key, value) in obj {
            match key.as_str() {
                PROVIDERS_KEY => {
                    config.providers = parse_providers_value(value, source_label)?;
                }
                SSH_KEY => {
                    config.ssh = parse_ssh_identities(value, source_label)?;
                }
                SHIM_DIR_KEY => {
                    let raw = value.as_str().with_context(|| {
                        format!("{source_label}: `{SHIM_DIR_KEY}` must be a string")
                    })?;
                    config.shim_dir = Some(expand_tilde(raw));
                }
                WAIT_INDICATOR_KEY => {
                    let on = value.as_bool().with_context(|| {
                        format!("{source_label}: `{WAIT_INDICATOR_KEY}` must be a boolean")
                    })?;
                    config.wait_indicator = Some(on);
                }
                EDITOR_KEY => {
                    let raw = value.as_str().with_context(|| {
                        format!("{source_label}: `{EDITOR_KEY}` must be a string")
                    })?;
                    config.editor = Some(raw.to_owned());
                }
                other if other.starts_with('$') => {
                    // `$schema`, `$version`, future metadata — silently ignored.
                    continue;
                }
                other => {
                    let wrap = parse_wrap(other, value, source_label)?;
                    config.wraps.insert(other.to_owned(), wrap);
                }
            }
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

fn parse_wrap(name: &str, value: &Value, source: &str) -> Result<Wrap> {
    let obj = value
        .as_object()
        .with_context(|| format!("{source}: wrap `{name}` must be an object (got {value})"))?;

    let mut wrap = Wrap {
        name: name.to_owned(),
        reason: None,
        env: BTreeMap::new(),
    };

    for (key, val) in obj {
        match key.as_str() {
            "$reason" => {
                wrap.reason = match present(Some(val)) {
                    None => None,
                    Some(val) => Some(
                        val.as_str()
                            .with_context(|| {
                                format!("{source}: `{name}.$reason` must be a string")
                            })?
                            .to_owned(),
                    ),
                };
            }
            "$description" => {
                // Future-proof: accept and ignore alongside $reason.
                continue;
            }
            "env" => {
                let env_obj = val
                    .as_object()
                    .with_context(|| format!("{source}: `{name}.env` must be an object"))?;
                for (env_name, env_val) in env_obj {
                    let s = env_val.as_str().with_context(|| {
                        format!("{source}: `{name}.env.{env_name}` must be a string")
                    })?;
                    wrap.env.insert(env_name.clone(), s.to_owned());
                }
            }
            other if other.starts_with('$') => {
                bail!("{source}: wrap `{name}` has unknown setting `{other}`");
            }
            other => {
                bail!("{source}: wrap `{name}` has unknown key `{other}` (env vars belong inside `env: {{ … }}`)");
            }
        }
    }

    // An empty `env` is legal: a wrap with no secrets is a *gate-only*
    // wrap — consent is still required before the binary runs, but
    // nothing is injected. This is how you gate a tool like `op` that has
    // no secret to pass through.
    Ok(wrap)
}

/// Parse the reserved `ssh` block: a map of identity name → identity.
fn parse_ssh_identities(value: &Value, source: &str) -> Result<BTreeMap<String, SshIdentity>> {
    let obj = value
        .as_object()
        .with_context(|| format!("{source}: `{SSH_KEY}` must be an object"))?;

    let mut identities = BTreeMap::new();
    for (name, val) in obj {
        identities.insert(name.clone(), parse_ssh_identity(name, val, source)?);
    }
    Ok(identities)
}

/// Parse one SSH identity. Requires `public_key` and `private_key`; accepts
/// an optional `$reason`; rejects any other key (mirrors `parse_wrap`).
fn parse_ssh_identity(name: &str, value: &Value, source: &str) -> Result<SshIdentity> {
    let obj = value.as_object().with_context(|| {
        format!("{source}: ssh identity `{name}` must be an object (got {value})")
    })?;

    let mut reason = None;
    let mut public_key = None;
    let mut private_key = None;

    for (key, val) in obj {
        match key.as_str() {
            "$reason" => {
                reason = match present(Some(val)) {
                    None => None,
                    Some(val) => Some(
                        val.as_str()
                            .with_context(|| {
                                format!("{source}: `ssh.{name}.$reason` must be a string")
                            })?
                            .to_owned(),
                    ),
                };
            }
            "public_key" => {
                public_key = Some(
                    val.as_str()
                        .with_context(|| {
                            format!("{source}: `ssh.{name}.public_key` must be a string")
                        })?
                        .to_owned(),
                );
            }
            "private_key" => {
                let raw = val.as_str().with_context(|| {
                    format!("{source}: `ssh.{name}.private_key` must be a string")
                })?;
                private_key = Some(Reference::parse(raw).with_context(|| {
                    format!(
                        "{source}: `ssh.{name}.private_key` is not a valid `secret://` reference"
                    )
                })?);
            }
            other => {
                bail!("{source}: ssh identity `{name}` has unknown key `{other}`");
            }
        }
    }

    let public_key = public_key
        .with_context(|| format!("{source}: ssh identity `{name}` is missing `public_key`"))?;
    let private_key = private_key
        .with_context(|| format!("{source}: ssh identity `{name}` is missing `private_key`"))?;

    Ok(SshIdentity {
        reason,
        public_key,
        private_key,
    })
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
            r#"{
                gh: {
                    $reason: "GitHub API access",
                    env: { GITHUB_TOKEN: "secret://op/Personal/GitHub Token/credential" },
                },
            }"#,
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
            r#"{
                gh: { env: { GITHUB_TOKEN: "secret://op/Personal/GitHub/token" } },
                gh_alt: { env: { GH_TOKEN: "secret://op/Personal/GitHub/token" } },
                aws: {
                    env: {
                        AWS_ACCESS_KEY_ID:     "secret://op/Work/AWS/access_key_id",
                        AWS_SECRET_ACCESS_KEY: "secret://op/Work/AWS/secret_access_key",
                    },
                },
            }"#,
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
        let c = WrapsConfig::parse(r#"{ op: { env: {} } }"#, "t").unwrap();
        assert!(c.known_secret_refs().is_empty());
    }

    #[test]
    fn parses_shim_dir_with_tilde_expansion() {
        let c = WrapsConfig::parse(
            r#"{ $shim_dir: "~/.local/bin", gh: { env: { TOK: "secret://op/x" } } }"#,
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
        let c = WrapsConfig::parse(r#"{ gh: { env: { T: "secret://op/x" } } }"#, "t").unwrap();
        assert_eq!(c.wait_indicator, None);
        assert!(c.wait_indicator_enabled());

        // Explicit false → silenced.
        let off = WrapsConfig::parse(r#"{ $wait_indicator: false }"#, "t").unwrap();
        assert_eq!(off.wait_indicator, Some(false));
        assert!(!off.wait_indicator_enabled());

        // Explicit true → enabled.
        let on = WrapsConfig::parse(r#"{ $wait_indicator: true }"#, "t").unwrap();
        assert_eq!(on.wait_indicator, Some(true));
        assert!(on.wait_indicator_enabled());
    }

    #[test]
    fn wait_indicator_rejects_non_boolean() {
        let err = WrapsConfig::parse(r#"{ $wait_indicator: "yes" }"#, "t").unwrap_err();
        assert!(
            format!("{err:#}").contains("$wait_indicator"),
            "error should name the offending key: {err:#}"
        );
    }

    #[test]
    fn editor_preference_parses_and_defaults_none() {
        let none = WrapsConfig::parse(r#"{ gh: { env: {} } }"#, "t").unwrap();
        assert_eq!(none.editor, None);

        let set = WrapsConfig::parse(r#"{ $editor: "code", gh: { env: {} } }"#, "t").unwrap();
        assert_eq!(set.editor.as_deref(), Some("code"));
        // The reserved key doesn't leak into the wrap map.
        assert!(set.wraps.contains_key("gh"));
        assert!(!set.wraps.contains_key("$editor"));
    }

    #[test]
    fn editor_preference_rejects_non_string() {
        let err = WrapsConfig::parse(r#"{ $editor: 42 }"#, "t").unwrap_err();
        assert!(
            format!("{err:#}").contains("$editor"),
            "error should name the offending key: {err:#}"
        );
    }

    #[test]
    fn parses_multiple_wraps_and_a_providers_block() {
        let c = WrapsConfig::parse(
            r#"{
                gh:  { env: { GITHUB_TOKEN: "secret://op/x" } },
                aws: { env: { AWS_KEY: "secret://op/y", AWS_SECRET: "secret://op/z" } },
                providers: {
                    custom: { retrieve: ["printf", "%s", "{locator}"] },
                },
            }"#,
            "t",
        )
        .unwrap();
        assert_eq!(c.wraps.len(), 2);
        assert!(c.providers.contains_key("custom"));
    }

    #[test]
    fn remember_setting_is_rejected_now_that_caching_is_authorization_gated() {
        // Pre-pivot we had a `$remember` field for per-wrap TTLs. The
        // daemon now drops TTLs entirely: the *approvals* cache lives
        // for the daemon process, and the *secret value* cache keys on
        // `(wrap, provider, locator)` with no expiry. `$remember` no
        // longer maps onto anything we can configure per-wrap.
        let err = WrapsConfig::parse(
            r#"{ gh: { $remember: "8h", env: { X: "secret://op/x" } } }"#,
            "t",
        )
        .unwrap_err();
        assert!(err.to_string().contains("$remember"));
    }

    #[test]
    fn rejects_unknown_dollar_keys_inside_a_wrap() {
        let err = WrapsConfig::parse(r#"{ gh: { $bogus: 1, env: { X: "secret://op/x" } } }"#, "t")
            .unwrap_err();
        assert!(err.to_string().contains("$bogus"));
    }

    #[test]
    fn rejects_top_level_env_vars_outside_env_block() {
        // Common mistake: putting GITHUB_TOKEN as a sibling of `env` rather than inside it.
        let err =
            WrapsConfig::parse(r#"{ gh: { GITHUB_TOKEN: "secret://op/x" } }"#, "t").unwrap_err();
        assert!(err.to_string().contains("env vars belong inside `env"));
    }

    #[test]
    fn parses_a_gate_only_wrap_with_no_env() {
        // A wrap with no `env` key is a *gate-only* wrap: consent is
        // required but nothing is injected. This is how you gate a tool
        // like `op` that has no secret to pass.
        let c =
            WrapsConfig::parse(r#"{ op: { $reason: "1Password vault access" } }"#, "t").unwrap();
        let w = c.wrap("op").unwrap();
        assert_eq!(w.name, "op");
        assert_eq!(w.reason.as_deref(), Some("1Password vault access"));
        assert!(w.env.is_empty(), "gate-only wrap has no env");
    }

    #[test]
    fn parses_a_gate_only_wrap_with_empty_env() {
        // An explicit `env: {}` means the same thing as omitting `env`.
        let c = WrapsConfig::parse(r#"{ op: { env: {} } }"#, "t").unwrap();
        let w = c.wrap("op").unwrap();
        assert!(w.env.is_empty());
        assert_eq!(w.reason, None);
    }

    #[test]
    fn parses_ssh_identities() {
        let cfg = WrapsConfig::parse(
            r#"{
                ssh: {
                    "github": {
                        $reason: "git pushes",
                        public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1 me@mac",
                        private_key: "secret://op/Private/gh/private key",
                    }
                }
            }"#,
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
        let err = WrapsConfig::parse(
            r#"{
                ssh: { "x": { public_key: "ssh-ed25519 AAAA x" } }
            }"#,
            "t",
        )
        .unwrap_err();
        assert!(err.to_string().contains("private_key"));
    }

    #[test]
    fn an_explicit_null_reason_means_no_reason() {
        // Same contract as the provider capabilities: the published schema
        // derives `$reason` from an `Option<String>`, which reads as "absent
        // or a string", so a null has to load rather than error.
        let c = WrapsConfig::parse(
            r#"{
                gh: { $reason: null, env: { X: "secret://op/x" } },
                ssh: {
                    k: {
                        $reason: null,
                        public_key: "ssh-ed25519 AAAA k",
                        private_key: "secret://op/k",
                    },
                },
            }"#,
            "t",
        )
        .expect("a null $reason loads as an absent one");
        assert_eq!(c.wrap("gh").expect("gh wrap").reason, None);
        assert_eq!(c.ssh["k"].reason, None);
    }

    #[test]
    fn ignores_top_level_dollar_metadata_keys() {
        let c = WrapsConfig::parse(
            r#"{ $schema: "x", $version: 2, gh: { env: { X: "secret://op/x" } } }"#,
            "t",
        )
        .unwrap();
        assert!(c.wrap("gh").is_some());
    }
}
