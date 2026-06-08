//! The `wraps.json5` config model: per-binary wraps.
//!
//! `secreq` resolves secrets *for specific binaries you've wrapped*. The
//! config lives at `$XDG_CONFIG_HOME/secreq/wraps.json5` (user-scope only —
//! there's no project scope; that's varlock's territory). Each top-level
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
use crate::manifest::{builtin_providers, parse_providers_value, Provider};
use crate::reference::Reference;

/// The reserved top-level key holding provider scheme definitions.
pub const PROVIDERS_KEY: &str = "providers";

/// `$shim_dir` — where `secreq wrap` drops PATH shims. Set by `secreq init`.
pub const SHIM_DIR_KEY: &str = "$shim_dir";

/// The reserved top-level key holding SSH identity definitions for the agent.
pub const SSH_KEY: &str = "ssh";

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
}

/// One SSH identity served by the agent. The public key is stored inline
/// (it isn't secret) so the agent can answer REQUEST_IDENTITIES without a
/// resolve. The private key is a `secret://` reference resolved only at
/// SIGN time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshIdentity {
    /// `$reason` — shown in the consent prompt for context.
    pub reason: Option<String>,
    /// The inline OpenSSH public key (`ssh-ed25519 AAAA… comment`).
    pub public_key: String,
    /// The private key, as a `secret://provider/locator` reference resolved
    /// only at SIGN time.
    pub private_key: Reference,
}

/// One per-binary wrap declaration.
#[derive(Debug, Clone, PartialEq)]
pub struct Wrap {
    /// The binary name this wrap applies to (the top-level key).
    pub name: String,
    /// `$reason` — shown in the consent prompt for context.
    pub reason: Option<String>,
    /// Environment variables this binary should be invoked with. Each value
    /// is a `secret://provider/locator` reference string; resolution is
    /// deferred to run-time (so an unreachable provider doesn't break
    /// config loading).
    ///
    /// **Empty means gate-only:** a wrap with no env entries still routes
    /// the binary through the consent daemon, but injects nothing. Used to
    /// gate tools (e.g. `op`) that have no secret to pass.
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
        }
    }

    /// Look up a wrap by binary name.
    pub fn wrap(&self, name: &str) -> Option<&Wrap> {
        self.wraps.get(name)
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
                wrap.reason = Some(
                    val.as_str()
                        .with_context(|| format!("{source}: `{name}.$reason` must be a string"))?
                        .to_owned(),
                );
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
                reason = Some(
                    val.as_str()
                        .with_context(|| {
                            format!("{source}: `ssh.{name}.$reason` must be a string")
                        })?
                        .to_owned(),
                );
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

/// Default location for the user's `wraps.json5`. Honors `XDG_CONFIG_HOME`.
pub fn default_config_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|h| h.join(".config")))?;
    Some(base.join("secreq").join("wraps.json5"))
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
    fn ignores_top_level_dollar_metadata_keys() {
        let c = WrapsConfig::parse(
            r#"{ $schema: "x", $version: 2, gh: { env: { X: "secret://op/x" } } }"#,
            "t",
        )
        .unwrap();
        assert!(c.wrap("gh").is_some());
    }
}
