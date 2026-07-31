//! The `config.toml` model: per-binary wraps, providers, SSH identities.
//!
//! `secreq` resolves secrets *for specific binaries you've wrapped*. The config
//! lives at `~/.secreq/config.toml` (`$SECREQ_HOME/config.toml`; user-scope
//! only — there's no project scope, that's varlock's territory).
//!
//! ```toml
//! shim_dir = "~/.secreq/shims"       # set by `secreq init`
//!
//! [secrets.github_token]             # declare once, reference by name
//! ref = "secret://op/Personal/GitHub Token/credential"
//! ttl = "15m"
//!
//! [wraps.gh]
//! reason = "GitHub API access"
//! env.GITHUB_TOKEN = "secret://github_token"
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
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::manifest::{builtin_providers, Provider};
use crate::reference::{undeclared_secret_message, RefForm, Reference};

/// Taplo schema directive written at the top of `config.toml`.
pub const CONFIG_SCHEMA_URL: &str = "https://craigory.dev/secreq/schemas/wraps.schema.json";

/// The reserved top-level key holding named secret declarations. The section
/// name in the file, and how errors spell a declaration's path.
pub const SECRETS_KEY: &str = "secrets";

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
    /// Secrets declared once under a name, referenced from any number of wraps
    /// as `secret://<name>`. Carries the per-secret cache TTL.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub secrets: BTreeMap<String, SecretDecl>,
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

/// How long the daemon may keep serving a resolved secret value from its
/// in-memory cache before the provider has to run again.
///
/// **The daemon's own lifetime is the default value, not a special case.** An
/// entry with no declared `ttl` is [`CacheTtl::DaemonLifetime`], which is
/// exactly the behaviour secreq has always had; every other value is a
/// *shortening* of it. Written this way on purpose — an `Option<Duration>`
/// would put "no TTL" on one branch and "a TTL" on another, and the expiry
/// check would have to say which it was at every call site.
///
/// A shortening is opt-in and per secret. A *global* cap was tried and is the
/// bug [`crate::daemon::cache`]'s module docs record: it re-triggered the
/// provider (and 1Password's biometric prompt) behind an approval the user had
/// already granted and been told would be remembered. Setting a TTL on one
/// high-sensitivity secret is the user saying "re-fetch this one, I accept the
/// re-prompt" — a local, informed choice rather than a default that surprises
/// everyone.
///
/// **Two serde representations, deliberately.** The derive below is the
/// daemon's wire form ([`crate::daemon::proto`]), where an enum shape is
/// exactly right and no human reads it. The *config* spelling is a count and a
/// unit (`15m`), which no derive produces — so [`SecretDecl::ttl`] names
/// [`de_ttl`] / [`ser_ttl`] instead, keeping the file's syntax next to the
/// field that has it. Don't collapse them: the wire form is not a spelling any
/// user should have to write, and `15m` is not a shape the IPC needs to parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheTtl {
    /// The default: the entry lives as long as the daemon process does.
    /// `secreq daemon stop` is the reset.
    #[default]
    DaemonLifetime,
    /// An explicit shortening, in whole seconds. Zero means the value is never
    /// served from cache — every ask re-runs the provider.
    Secs(u64),
}

impl CacheTtl {
    /// Has an entry stored `age` ago outlived this TTL?
    ///
    /// One expression rather than a branch per call site: the daemon-lifetime
    /// default simply never expires.
    pub fn expired_after(self, age: Duration) -> bool {
        match self {
            CacheTtl::DaemonLifetime => false,
            CacheTtl::Secs(secs) => age >= Duration::from_secs(secs),
        }
    }

    /// Render as the config spells it, for error messages and `secreq wraps`.
    pub fn label(self) -> String {
        match self {
            CacheTtl::DaemonLifetime => "daemon lifetime".to_owned(),
            CacheTtl::Secs(secs) => format!("{secs}s"),
        }
    }

    /// Is this the default? Drives `skip_serializing_if`, so an unset TTL stays
    /// absent from the file rather than being written back as an explicit one.
    fn is_daemon_lifetime(&self) -> bool {
        matches!(self, CacheTtl::DaemonLifetime)
    }

    /// The largest unit that divides this TTL exactly, so a `15m` the user
    /// wrote comes back out of a `wrap add` as `15m` and not `900s`.
    ///
    /// [`CacheTtl::label`] is deliberately not this: it is prose for an error
    /// message, where one unit for every duration is easier to compare.
    fn to_config_string(self) -> String {
        const MIN: u64 = 60;
        const HOUR: u64 = 60 * 60;
        const DAY: u64 = 24 * 60 * 60;
        match self {
            CacheTtl::DaemonLifetime => String::new(),
            CacheTtl::Secs(secs) if secs > 0 && secs % DAY == 0 => format!("{}d", secs / DAY),
            CacheTtl::Secs(secs) if secs > 0 && secs % HOUR == 0 => format!("{}h", secs / HOUR),
            CacheTtl::Secs(secs) if secs > 0 && secs % MIN == 0 => format!("{}m", secs / MIN),
            CacheTtl::Secs(secs) => format!("{secs}s"),
        }
    }
}

/// Parse a `ttl` value: a positive integer followed by a unit, e.g. `30s`,
/// `15m`, `2h`, `1d`.
///
/// A unit is required. `ttl = 900` would have to mean seconds by convention, and
/// a convention nobody can see in the file is how a 15-*minute* TTL gets
/// written as `15` and silently becomes fifteen seconds.
fn parse_ttl(raw: &str) -> Result<CacheTtl> {
    let trimmed = raw.trim();
    let (digits, unit) = trimmed.split_at(
        trimmed
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(trimmed.len()),
    );
    let multiplier = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        "" => bail!("`{raw}` needs a unit: `s`, `m`, `h`, or `d` (e.g. `15m`)"),
        other => bail!("`{raw}` has unknown unit `{other}`; use `s`, `m`, `h`, or `d`"),
    };
    let count: u64 = digits
        .parse()
        .with_context(|| format!("`{raw}` is not a duration like `15m`"))?;
    let secs = count
        .checked_mul(multiplier)
        .with_context(|| format!("`{raw}` is longer than any daemon will live"))?;
    Ok(CacheTtl::Secs(secs))
}

/// Read a `ttl` off the file. Only called when the key is present — an absent
/// one takes the field's `default`, which is the daemon lifetime.
fn de_ttl<'de, D: serde::Deserializer<'de>>(d: D) -> Result<CacheTtl, D::Error> {
    let raw = String::deserialize(d)?;
    parse_ttl(&raw).map_err(serde::de::Error::custom)
}

fn ser_ttl<S: serde::Serializer>(ttl: &CacheTtl, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&ttl.to_config_string())
}

/// One entry in the reserved `secrets` block: a provider reference declared
/// **once**, under a name any number of wraps can reference as
/// `secret://<name>`.
///
/// The name is what a TTL hangs on. Before this existed a secret had no
/// declaration — it was a string repeated in every wrap that needed it — so
/// there was nowhere for a per-secret setting to live.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(deny_unknown_fields))]
pub struct SecretDecl {
    /// The `secret://provider/locator` reference this name stands for. Always
    /// the direct form: a declaration naming another declaration would make
    /// resolution a graph walk with cycles to detect, for no reuse a second
    /// name buys.
    #[serde(rename = "ref")]
    #[cfg_attr(feature = "schema", schemars(rename = "ref"))]
    pub reference: Reference,
    /// How long the daemon may serve this secret from its in-memory cache
    /// before re-running the provider, as a count and a unit — `30s`, `15m`,
    /// `2h`, `1d`. Omit for the default, which is the daemon's own lifetime;
    /// any value here is a shortening, and shortening means the provider (and
    /// on 1Password, a biometric prompt) runs again once it elapses.
    #[serde(
        default,
        rename = "ttl",
        deserialize_with = "de_ttl",
        serialize_with = "ser_ttl",
        skip_serializing_if = "CacheTtl::is_daemon_lifetime"
    )]
    #[cfg_attr(feature = "schema", schemars(rename = "ttl", with = "Option<String>"))]
    pub ttl: CacheTtl,
}

/// A `secret://…` value from the config, resolved against the `secrets` block.
///
/// This is the "expand at load, but keep the name" shape. `reference` is what
/// resolution and the cache use, so nothing downstream learns a second kind of
/// reference; `declared_as` carries the friendly name alongside for the places
/// that show a human which secret is in play.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRef {
    /// Provider and locator, exactly as an inline reference would have given.
    pub reference: Reference,
    /// The declared name, when the raw value was `secret://<name>`. `None` for
    /// an inline `secret://provider/locator`, which names nothing.
    pub declared_as: Option<String>,
    /// The declaration's TTL, or the daemon-lifetime default for an inline
    /// reference (there is nowhere for an inline one to carry a TTL).
    pub ttl: CacheTtl,
}

impl ResolvedRef {
    /// How to name this secret to a human: the declared name when there is one,
    /// otherwise the reference itself.
    pub fn label(&self) -> String {
        match &self.declared_as {
            Some(name) => name.clone(),
            None => self.reference.to_string(),
        }
    }
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
        config.check_declarations(source_label)?;
        Ok(config)
    }

    /// Expand every named reference in the file, so a name that resolves to
    /// nothing fails **here** rather than at resolve time with a user waiting
    /// on a `git push`. Same principle `ssh.<id>.private_key` already applies
    /// to a malformed reference.
    ///
    /// Also refuses two declarations that point at the same
    /// `(provider, locator)` with different TTLs. The cache slot is keyed on
    /// the reference, so that config asks for one slot to have two lifetimes;
    /// silently picking the shorter is how a `ttl` stops meaning what the file
    /// says, which is the failure this whole feature exists to avoid.
    fn check_declarations(&self, source: &str) -> Result<()> {
        let mut claimed: BTreeMap<(&str, &str), (&String, CacheTtl)> = BTreeMap::new();
        for (name, decl) in &self.secrets {
            // The slash is what tells a name from a provider reference, so a
            // name holding one is a declaration nothing could ever reference.
            // Serde can't catch this — it's a map *key*, and any string is a
            // valid one.
            if name.contains('/') {
                bail!(
                    "{source}: `{SECRETS_KEY}.{name}` contains a `/`, so nothing could reference \
                     it — `secret://{name}` reads as a provider reference, not a name"
                );
            }
            let target = (
                decl.reference.provider.as_str(),
                decl.reference.locator.as_str(),
            );
            if let Some((other, other_ttl)) = claimed.insert(target, (name, decl.ttl)) {
                if other_ttl != decl.ttl {
                    bail!(
                        "{source}: `{SECRETS_KEY}.{other}` and `{SECRETS_KEY}.{name}` both point at \
                         `{}` but claim different TTLs ({} vs {}); the cache holds one value per \
                         reference, so it can only have one lifetime",
                        decl.reference,
                        other_ttl.label(),
                        decl.ttl.label(),
                    );
                }
            }
        }

        for wrap in self.wraps.values() {
            for (env_name, raw) in &wrap.env {
                self.resolve_ref(raw)
                    .with_context(|| format!("{source}: `wraps.{}.env.{env_name}`", wrap.name))?;
            }
        }
        Ok(())
    }

    /// The declared cache TTL for a reference, or the daemon-lifetime default
    /// when nothing declares it.
    ///
    /// Keyed on the **reference**, not on how it was written, because that is
    /// what a TTL is a property of: one `(provider, locator)` is one value and
    /// one cache slot, so it has exactly one lifetime whether a wrap reached it
    /// by name, wrote it inline, or an SSH identity used it as a private key.
    /// [`WrapsConfig::check_declarations`] refuses a file where two
    /// declarations claim different TTLs for one reference, which is what makes
    /// this lookup unambiguous rather than first-wins.
    pub fn ttl_for(&self, reference: &Reference) -> CacheTtl {
        self.secrets
            .values()
            .find(|decl| &decl.reference == reference)
            .map_or_else(CacheTtl::default, |decl| decl.ttl)
    }

    /// Expand one `secret://…` config value into the reference resolution uses,
    /// keeping the declared name and TTL alongside.
    ///
    /// This is the only door from the two written forms to the one resolved
    /// form. An inline `secret://provider/locator` passes straight through
    /// naming nothing; a `secret://<name>` is looked up in
    /// [`WrapsConfig::secrets`], and an undeclared name is an error stating both
    /// readings (see [`undeclared_secret_message`]). Both come back carrying the
    /// TTL, which [`WrapsConfig::ttl_for`] reads off the reference either way.
    pub fn resolve_ref(&self, raw: &str) -> Result<ResolvedRef> {
        let form = Reference::parse_form(raw)
            .with_context(|| format!("`{raw}` is not a valid `secret://` reference"))?;
        self.resolve_form(form)
    }

    /// [`WrapsConfig::resolve_ref`] for an argument position, where the
    /// `secret://` scheme is optional — `secreq read op/Work/x` and
    /// `secreq read github_token` both land here.
    pub fn resolve_arg(&self, raw: &str) -> Result<ResolvedRef> {
        let form = Reference::parse_arg_form(raw).with_context(|| {
            format!(
                "`{raw}` is not a valid reference (expected `secret://provider/locator`, \
                 `provider/locator`, or a declared secret's name)"
            )
        })?;
        self.resolve_form(form)
    }

    fn resolve_form(&self, form: RefForm) -> Result<ResolvedRef> {
        let (reference, declared_as) = match form {
            RefForm::Direct(reference) => (reference, None),
            RefForm::Named(name) => {
                let decl = self
                    .secrets
                    .get(&name)
                    .with_context(|| undeclared_secret_message(&name))?;
                (decl.reference.clone(), Some(name))
            }
        };
        let ttl = self.ttl_for(&reference);
        Ok(ResolvedRef {
            reference,
            declared_as,
            ttl,
        })
    }

    /// Every `(env name, resolved reference)` pair for one wrap, in `env` order.
    pub fn wrap_refs(&self, wrap: &Wrap) -> Result<Vec<(String, ResolvedRef)>> {
        let mut refs = Vec::with_capacity(wrap.env.len());
        for (env_name, raw) in &wrap.env {
            let resolved = self
                .resolve_ref(raw)
                .with_context(|| format!("wrap `{}`.env.{env_name}: `{raw}`", wrap.name))?;
            refs.push((env_name.clone(), resolved));
        }
        Ok(refs)
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
            secrets: BTreeMap::new(),
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

    #[test]
    fn a_declared_secret_expands_at_load_and_keeps_its_name() {
        let c = WrapsConfig::parse(
            r#"
            [secrets.github_token]
            ref = "secret://op/Personal/GitHub/token"
            ttl = "15m"

            [wraps.gh]
            env.GITHUB_TOKEN = "secret://github_token"
            "#,
            "t",
        )
        .expect("a `secrets` block and a `secret://<name>` reference must load");

        // The raw value is untouched, so a rewrite can't turn the user's
        // declaration back into an inline reference.
        assert_eq!(
            c.wrap("gh").unwrap().env.get("GITHUB_TOKEN").unwrap(),
            "secret://github_token"
        );

        let resolved = c.resolve_ref("secret://github_token").unwrap();
        assert_eq!(resolved.reference.provider, "op");
        assert_eq!(resolved.reference.locator, "Personal/GitHub/token");
        assert_eq!(resolved.declared_as.as_deref(), Some("github_token"));
        assert_eq!(resolved.ttl, CacheTtl::Secs(900));
        assert_eq!(resolved.label(), "github_token");
    }

    #[test]
    fn one_declaration_serves_many_wraps() {
        // The reuse half of the feature: declare once, reference from
        // several wraps, and every one of them gets the same reference and
        // the same TTL.
        let c = WrapsConfig::parse(
            r#"
            [secrets.tok]
            ref = "secret://op/Personal/GitHub/token"
            ttl = "5m"

            [wraps.gh]
            env.GITHUB_TOKEN = "secret://tok"

            [wraps.hub]
            env.GH_TOKEN = "secret://tok"
            "#,
            "t",
        )
        .unwrap();
        let a = c.wrap_refs(c.wrap("gh").unwrap()).unwrap();
        let b = c.wrap_refs(c.wrap("hub").unwrap()).unwrap();
        assert_eq!(a[0].1.reference, b[0].1.reference);
        assert_eq!(a[0].1.ttl, CacheTtl::Secs(300));
        assert_eq!(b[0].1.ttl, CacheTtl::Secs(300));
    }

    #[test]
    fn an_unset_ttl_is_the_daemon_lifetime() {
        let c = WrapsConfig::parse(
            r#"
            [secrets.tok]
            ref = "secret://op/x/y"

            [wraps.gh]
            env.T = "secret://tok"
            env.U = "secret://op/a/b"
            "#,
            "t",
        )
        .unwrap();
        assert_eq!(c.secrets["tok"].ttl, CacheTtl::DaemonLifetime);
        assert_eq!(
            c.resolve_ref("secret://tok").unwrap().ttl,
            CacheTtl::DaemonLifetime
        );
        // And so is an inline reference nothing declares.
        assert_eq!(
            c.resolve_ref("secret://op/a/b").unwrap().ttl,
            CacheTtl::DaemonLifetime
        );
    }

    #[test]
    fn the_ttl_follows_the_reference_however_it_was_written() {
        // A TTL is a property of the secret, and the cache holds one value
        // per reference — so an inline reference to a declared secret has to
        // get the declared lifetime, not the default. Otherwise one slot
        // would have two claimed lifetimes and last-writer would win.
        let c = WrapsConfig::parse(
            r#"
            [secrets.tok]
            ref = "secret://op/x/y"
            ttl = "30s"

            [wraps.gh]
            env.INLINE = "secret://op/x/y"
            env.NAMED = "secret://tok"
            "#,
            "t",
        )
        .unwrap();
        let inline = c.resolve_ref("secret://op/x/y").unwrap();
        assert_eq!(inline.ttl, CacheTtl::Secs(30));
        assert_eq!(inline.declared_as, None, "an inline ref names nothing");
        assert_eq!(
            c.resolve_ref("secret://tok").unwrap().ttl,
            CacheTtl::Secs(30)
        );
    }

    #[test]
    fn an_undeclared_name_fails_at_load_stating_both_readings() {
        // The typo case: someone who forgot the locator wrote `secret://op`,
        // which the slash rule now reads as a name. The message has to offer
        // that reading too, or it sends them off to write a declaration they
        // never wanted.
        let err = WrapsConfig::parse("[wraps.gh]\nenv.T = \"secret://op\"\n", "t").unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("not a declared secret"), "{text}");
        assert!(text.contains("secret://op/<locator>"), "{text}");
        // And it names where in the file the offending value is.
        assert!(text.contains("wraps.gh.env.T"), "{text}");
    }

    #[test]
    fn two_declarations_of_one_reference_with_different_ttls_are_a_load_error() {
        // One reference is one cache slot, so it has one lifetime. Silently
        // picking the shorter is how a `ttl` stops meaning what the file says.
        let err = WrapsConfig::parse(
            r#"
            [secrets.a]
            ref = "secret://op/x/y"
            ttl = "5m"

            [secrets.b]
            ref = "secret://op/x/y"
            ttl = "1h"
            "#,
            "t",
        )
        .unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("different TTLs"), "{text}");
        assert!(
            text.contains("secrets.a") && text.contains("secrets.b"),
            "{text}"
        );
    }

    #[test]
    fn two_declarations_of_one_reference_agreeing_on_the_ttl_are_fine() {
        // Aliasing is only a problem when the two claims disagree.
        WrapsConfig::parse(
            r#"
            [secrets.a]
            ref = "secret://op/x/y"
            ttl = "5m"

            [secrets.b]
            ref = "secret://op/x/y"
            ttl = "5m"
            "#,
            "t",
        )
        .expect("two names for one reference agreeing on its lifetime is not a conflict");
    }

    #[test]
    fn ttl_units_parse_and_a_bare_number_is_refused() {
        let cases = [("30s", 30), ("15m", 900), ("2h", 7200), ("1d", 86_400)];
        for (spelling, secs) in cases {
            let c = WrapsConfig::parse(
                &format!("[secrets.t]\nref = \"secret://op/x/y\"\nttl = \"{spelling}\"\n"),
                "t",
            )
            .unwrap_or_else(|err| panic!("`{spelling}` should parse: {err:#}"));
            assert_eq!(c.secrets["t"].ttl, CacheTtl::Secs(secs), "{spelling}");
        }

        // A unit is required: `15` would have to mean seconds by a convention
        // nobody can see in the file.
        let err = WrapsConfig::parse(
            "[secrets.t]\nref = \"secret://op/x/y\"\nttl = \"15\"\n",
            "t",
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("needs a unit"), "{err:#}");

        let err = WrapsConfig::parse(
            "[secrets.t]\nref = \"secret://op/x/y\"\nttl = \"15w\"\n",
            "t",
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("unknown unit"), "{err:#}");
    }

    /// A bare TOML integer is refused rather than read as seconds. Under the
    /// old walker this was a string-typed field; here it is serde's type
    /// error, so the guard is worth keeping either way.
    #[test]
    fn a_ttl_must_be_a_string_not_a_bare_integer() {
        let err = WrapsConfig::parse("[secrets.t]\nref = \"secret://op/x/y\"\nttl = 900\n", "t")
            .unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("string"), "{text}");
    }

    #[test]
    fn a_declaration_requires_a_ref_and_refuses_unknown_keys() {
        let err = WrapsConfig::parse("[secrets.t]\nttl = \"5m\"\n", "t").unwrap_err();
        assert!(format!("{err:#}").contains("ref"), "{err:#}");

        let err = WrapsConfig::parse("[secrets.t]\nref = \"secret://op/x/y\"\nnope = 1\n", "t")
            .unwrap_err();
        assert!(format!("{err:#}").contains("nope"), "{err:#}");
    }

    #[test]
    fn a_declarations_ref_must_be_the_direct_form() {
        // No alias chains: a declaration naming another declaration would
        // make resolution a graph walk with cycles to detect.
        let err = WrapsConfig::parse(
            "[secrets.a]\nref = \"secret://op/x/y\"\n\n[secrets.b]\nref = \"secret://a\"\n",
            "t",
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("secret://a"), "{err:#}");
    }

    #[test]
    fn a_secret_name_may_not_contain_a_slash() {
        // The slash is what tells a name from a provider reference, so a name
        // holding one is a declaration nothing could ever reference.
        let err =
            WrapsConfig::parse("[secrets.\"a/b\"]\nref = \"secret://op/x/y\"\n", "t").unwrap_err();
        assert!(format!("{err:#}").contains("contains a `/`"), "{err:#}");
    }

    #[test]
    fn known_secret_refs_offers_named_references_too() {
        // The interactive wrap picker suggests values already in use, and a
        // name is the value the user should be reusing.
        let c = WrapsConfig::parse(
            r#"
            [secrets.tok]
            ref = "secret://op/x/y"

            [wraps.gh]
            env.A = "secret://tok"

            [wraps.aws]
            env.B = "secret://op/other/thing"
            "#,
            "t",
        )
        .unwrap();
        assert_eq!(
            c.known_secret_refs(),
            vec![
                "secret://op/other/thing".to_owned(),
                "secret://tok".to_owned(),
            ]
        );
    }

    #[test]
    fn an_ssh_identitys_private_key_picks_up_a_declared_ttl() {
        // The highest-value use of the feature: bounding how long a private
        // key stays decryptable in the daemon. The identity still writes the
        // direct reference — the TTL is looked up by reference, not by name.
        let c = WrapsConfig::parse(
            r#"
            [secrets.deploy_key]
            ref = "secret://op/Private/gh/key"
            ttl = "10m"

            [ssh.github]
            public_key = "ssh-ed25519 AAAA me@mac"
            private_key = "secret://op/Private/gh/key"
            "#,
            "t",
        )
        .unwrap();
        assert_eq!(c.ttl_for(&c.ssh["github"].private_key), CacheTtl::Secs(600));
    }

    /// A `15m` the user wrote has to come back out of a `wrap add` as `15m`.
    /// `write_config` re-parses what it serialized, so a lossy rendering here
    /// would be a round-trip failure rather than a cosmetic one.
    #[test]
    fn a_ttl_round_trips_through_serialization_in_the_unit_it_was_written() {
        for spelling in ["30s", "15m", "2h", "1d", "90s"] {
            let c = WrapsConfig::parse(
                &format!("[secrets.t]\nref = \"secret://op/x/y\"\nttl = \"{spelling}\"\n"),
                "t",
            )
            .unwrap();
            let text = toml::to_string(&c).unwrap();
            assert!(
                text.contains(&format!("ttl = \"{spelling}\"")),
                "`{spelling}` should survive a round-trip, got:\n{text}"
            );
            let back = WrapsConfig::parse(&text, "t").unwrap();
            assert_eq!(back.secrets["t"].ttl, c.secrets["t"].ttl, "{spelling}");
        }
    }

    /// An unset TTL stays absent rather than being written back as an
    /// explicit one — otherwise the first `wrap add` would bake today's
    /// default into every declaration in the file.
    #[test]
    fn an_unset_ttl_is_not_written_back() {
        let c = WrapsConfig::parse("[secrets.t]\nref = \"secret://op/x/y\"\n", "t").unwrap();
        let text = toml::to_string(&c).unwrap();
        assert!(!text.contains("ttl"), "{text}");
    }
}
