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

/// The reserved top-level key holding provider scheme definitions.
pub const PROVIDERS_KEY: &str = "providers";

/// `$shim_dir` — where `secreq wrap` drops PATH shims. Set by `secreq init`.
pub const SHIM_DIR_KEY: &str = "$shim_dir";

/// Top-level configuration loaded from `wraps.json5`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct WrapsConfig {
    /// Where the PATH shims live. `None` until `secreq init` runs.
    pub shim_dir: Option<PathBuf>,
    /// Configured per-binary wraps.
    pub wraps: BTreeMap<String, Wrap>,
    /// Provider scheme definitions (built-ins overlay these).
    pub providers: BTreeMap<String, Provider>,
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

    if wrap.env.is_empty() {
        bail!("{source}: wrap `{name}` declares no env vars");
    }
    Ok(wrap)
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
    fn rejects_empty_env() {
        let err = WrapsConfig::parse(r#"{ gh: { env: {} } }"#, "t").unwrap_err();
        assert!(err.to_string().contains("declares no env vars"));
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
