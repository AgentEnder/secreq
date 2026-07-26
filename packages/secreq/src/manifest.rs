//! The `secrets.json5` config model and its loader (§6).
//!
//! Top-level keys are **groups**; the reserved `providers` key defines schemes.
//! Within a group, `$`-prefixed keys are inheritable settings and every other
//! key is a secret declaration (a shorthand string ref or an object form).
//!
//! We parse JSON5 into a dynamic [`serde_json::Value`] and then interpret it,
//! because a group's keys are arbitrary secret names plus one reserved key —
//! something a fixed deserialize target cannot express.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::reference::Reference;

/// The reserved top-level key that defines provider schemes.
pub const PROVIDERS_KEY: &str = "providers";

/// A fully-interpreted manifest: named groups plus provider schemes.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Manifest {
    pub groups: BTreeMap<String, Group>,
    pub providers: BTreeMap<String, Provider>,
}

/// A named, selectable subset of secrets with inheritable settings.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Group {
    pub name: String,
    /// `$provider` — group-default provider for secrets that omit one.
    pub provider: Option<String>,
    /// `$reason` — rationale shown in the consent prompt.
    pub reason: Option<String>,
    /// `$required` — group default for `required` (per-secret default is true).
    pub required: Option<bool>,
    /// `$description` — group-level description.
    pub description: Option<String>,
    pub secrets: BTreeMap<String, SecretDecl>,
}

/// One declared secret, with group defaults already folded in.
#[derive(Debug, Clone, PartialEq)]
pub struct SecretDecl {
    /// The env var name this secret is injected as.
    pub name: String,
    /// The owning group's name.
    pub group: String,
    /// The provider scheme that resolves it. `None` only if neither the entry,
    /// a full `secret://` ref, nor the group's `$provider` supplied one — that
    /// is reported as an error when the secret is actually needed.
    pub provider: Option<String>,
    /// The locator passed to the provider's read template.
    pub locator: String,
    /// `true` ⇒ eager set (collected by `run`, hard error if missing).
    pub required: bool,
    /// Fallback value if resolution returns nothing (satisfies `required`).
    pub default: Option<String>,
    /// Human description shown in the consent prompt, `list`, and `doctor`.
    pub description: Option<String>,
    /// Inherited group `$reason`, shown alongside the secret in the prompt.
    pub reason: Option<String>,
}

/// A provider scheme — its **retrieve** capability (required), plus optional
/// **store** (write) and **retrieve_batch** (single-invocation multi-read)
/// capabilities.
#[derive(Debug, Clone, PartialEq)]
pub struct Provider {
    pub name: String,
    /// The retrieve command template; contains `{locator}` placeholders. (This
    /// is the `retrieve` field in JSON5; named `read` in the design doc §6.)
    pub retrieve: Vec<String>,
    /// Optional write capability. Present ⇒ provider can persist new values (§6, §10).
    pub store: Option<StoreCapability>,
    /// Optional batched retrieve: one command invocation that resolves many
    /// secrets at once. The classic use case is `op run -- printenv`, which
    /// requires a single biometric prompt regardless of how many `op://` refs
    /// it resolves. When present and ≥2 secrets share this provider in one
    /// `run`, the resolver uses this path instead of per-secret reads.
    pub retrieve_batch: Option<BatchRetrieve>,
}

/// A provider's batched-retrieve descriptor.
///
/// The protocol is "synthetic env in, env-like output out":
/// 1. For each `(name, locator)` we want to resolve, set the env var `name`
///    to `env_value_template` with `{locator}` substituted (e.g.
///    `DATABASE_URL=op://Work/db/url`).
/// 2. Spawn `command` with that env layered onto the inherited environment.
/// 3. The command's stdout is parsed as `KEY=VALUE` lines; lines whose key
///    matches one of our requested names yield resolved values.
///
/// Limitation: line-based output can't carry multi-line values intact. If
/// any value contains a newline, the resolver falls back to per-secret
/// retrieve (this is detected when the parsed output is missing names we
/// asked for).
#[derive(Debug, Clone, PartialEq)]
pub struct BatchRetrieve {
    /// argv to execute. The synthetic env entries are added to the child's
    /// environment; no placeholder substitution happens on `command` itself.
    pub command: Vec<String>,
    /// Template for each synthetic env entry's *value*. `{locator}` is
    /// substituted per secret; the env-var *name* is the secret's name.
    pub env_value_template: String,
}

/// A provider's write capability descriptor (§6).
///
/// The `command` template is executed with `{field}` placeholders substituted
/// from the caller's `--field key=value` inputs. The secret value is supplied
/// according to `value_mode` (either as the `{value}` placeholder in argv, or
/// piped on the child's stdin). The `locator_template` then constructs the
/// retrieve-side locator from the same field inputs so a subsequent `retrieve`
/// finds the value just written.
#[derive(Debug, Clone, PartialEq)]
pub struct StoreCapability {
    pub command: Vec<String>,
    pub fields: BTreeMap<String, FieldSpec>,
    pub value_mode: ValueMode,
    pub locator_template: String,
}

/// Schema for one field of a [`StoreCapability`].
#[derive(Debug, Clone, PartialEq, Default)]
pub struct FieldSpec {
    pub required: bool,
    pub default: Option<String>,
}

/// How the secret value is delivered to the store command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueMode {
    /// Substitute the value into argv (any `{value}` placeholder is replaced).
    /// Convenient, but exposes the value to `ps eww` for the child's lifetime.
    Arg,
    /// Pipe the value on the child's stdin. Keeps the value out of argv —
    /// preferred for any built-in (§11).
    Stdin,
}

impl Manifest {
    /// Parse a manifest from a JSON5 source string. `source_label` is used in
    /// error messages (e.g. the file path).
    pub fn parse(text: &str, source_label: &str) -> Result<Manifest> {
        let root: Value = json5::from_str(text)
            .with_context(|| format!("failed to parse JSON5 manifest: {source_label}"))?;
        let obj = root
            .as_object()
            .with_context(|| format!("{source_label}: top level must be an object"))?;

        let mut manifest = Manifest::default();

        for (key, value) in obj {
            if key == PROVIDERS_KEY {
                manifest.providers = parse_providers(value, source_label)?;
            } else if key.starts_with('$') {
                // Top-level `$`-prefixed keys are reserved for metadata
                // (e.g. `$schema` for editor JSON-schema hints). Ignore them
                // here so `secrets.json5` files can include such pointers.
                continue;
            } else {
                let group = parse_group(key, value, source_label)?;
                manifest.groups.insert(key.clone(), group);
            }
        }
        Ok(manifest)
    }

    /// Load and parse a manifest file from disk.
    pub fn load(path: &Path) -> Result<Manifest> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read manifest: {}", path.display()))?;
        Manifest::parse(&text, &path.display().to_string())
    }

    /// A manifest seeded with the built-in Tier-1 providers (no groups). Loading
    /// starts from this and merges user/project manifests on top, so a manifest
    /// `providers` entry of the same name overrides the built-in (§6, §13.1).
    pub fn with_builtin_providers() -> Manifest {
        Manifest {
            groups: BTreeMap::new(),
            providers: builtin_providers(),
        }
    }

    /// Merge another manifest on top of this one. Secrets and groups union;
    /// `other` (the project scope) wins on key conflict. Providers merge, with
    /// `other` overriding a scheme of the same name (§6 scope & merge).
    pub fn merge(&mut self, other: Manifest) {
        for (name, group) in other.groups {
            match self.groups.get_mut(&name) {
                Some(existing) => existing.merge(group),
                None => {
                    self.groups.insert(name, group);
                }
            }
        }
        for (name, provider) in other.providers {
            self.providers.insert(name, provider);
        }
    }

    /// Every secret declaration across all groups.
    pub fn all_secrets(&self) -> impl Iterator<Item = &SecretDecl> {
        self.groups.values().flat_map(|g| g.secrets.values())
    }

    /// Find a declaration by env-var name (used to overlay metadata onto an
    /// ambient ref). The first match across groups wins.
    pub fn find_secret(&self, name: &str) -> Option<&SecretDecl> {
        self.all_secrets().find(|s| s.name == name)
    }
}

impl Group {
    /// Merge `other` into this group: settings from `other` override; secrets
    /// union with `other` winning on name conflict.
    fn merge(&mut self, other: Group) {
        if other.provider.is_some() {
            self.provider = other.provider;
        }
        if other.reason.is_some() {
            self.reason = other.reason;
        }
        if other.required.is_some() {
            self.required = other.required;
        }
        if other.description.is_some() {
            self.description = other.description;
        }
        for (name, secret) in other.secrets {
            self.secrets.insert(name, secret);
        }
    }
}

/// Public re-export so the new [`crate::wraps`] config module can reuse the
/// providers-block parser unchanged. (The provider model is shared across
/// both config shapes; only the top-level wrapper differs.)
pub fn parse_providers_value(value: &Value, source: &str) -> Result<BTreeMap<String, Provider>> {
    parse_providers(value, source)
}

fn parse_providers(value: &Value, source: &str) -> Result<BTreeMap<String, Provider>> {
    let obj = value
        .as_object()
        .with_context(|| format!("{source}: `providers` must be an object"))?;
    let mut out = BTreeMap::new();
    for (name, def) in obj {
        out.insert(name.clone(), parse_provider(name, def, source)?);
    }
    Ok(out)
}

fn parse_provider(name: &str, def: &Value, source: &str) -> Result<Provider> {
    let obj = def
        .as_object()
        .with_context(|| format!("{source}: provider `{name}` must be an object"))?;

    if obj.contains_key("wasm") {
        bail!("{source}: provider `{name}` uses a Wasm plugin, which is not supported in this MVP");
    }

    // Accept either the new name (`retrieve`) or the historical name (`read`,
    // used by the design doc) so older configs keep working.
    let retrieve_val = obj
        .get("retrieve")
        .or_else(|| obj.get("read"))
        .with_context(|| format!("{source}: provider `{name}` is missing a `retrieve` command"))?;
    let retrieve = parse_string_array(retrieve_val).with_context(|| {
        format!("{source}: provider `{name}`.retrieve must be an array of strings")
    })?;
    if retrieve.is_empty() {
        bail!("{source}: provider `{name}`.retrieve must not be empty");
    }

    let store = match obj.get("store").or_else(|| obj.get("write")) {
        Some(value) => Some(parse_store_capability(name, value, source)?),
        None => None,
    };

    let retrieve_batch = match obj
        .get("retrieve_batch")
        .or_else(|| obj.get("retrieveBatch"))
    {
        Some(value) => Some(parse_batch_retrieve(name, value, source)?),
        None => None,
    };

    Ok(Provider {
        name: name.to_owned(),
        retrieve,
        store,
        retrieve_batch,
    })
}

fn parse_batch_retrieve(provider_name: &str, value: &Value, source: &str) -> Result<BatchRetrieve> {
    let obj = value.as_object().with_context(|| {
        format!("{source}: provider `{provider_name}`.retrieve_batch must be an object")
    })?;

    let command_val = obj.get("command").with_context(|| {
        format!("{source}: provider `{provider_name}`.retrieve_batch is missing `command`")
    })?;
    let command = parse_string_array(command_val).with_context(|| {
        format!(
            "{source}: provider `{provider_name}`.retrieve_batch.command must be an array of strings"
        )
    })?;
    if command.is_empty() {
        bail!("{source}: provider `{provider_name}`.retrieve_batch.command must not be empty");
    }

    let env_value_template = obj
        .get("env_value")
        .or_else(|| obj.get("envValue"))
        .and_then(|v| v.as_str())
        .with_context(|| {
            format!("{source}: provider `{provider_name}`.retrieve_batch is missing `env_value`")
        })?
        .to_owned();

    Ok(BatchRetrieve {
        command,
        env_value_template,
    })
}

fn parse_store_capability(
    provider_name: &str,
    value: &Value,
    source: &str,
) -> Result<StoreCapability> {
    let obj = value
        .as_object()
        .with_context(|| format!("{source}: provider `{provider_name}`.store must be an object"))?;

    let command_val = obj.get("command").with_context(|| {
        format!("{source}: provider `{provider_name}`.store is missing a `command`")
    })?;
    let command = parse_string_array(command_val).with_context(|| {
        format!("{source}: provider `{provider_name}`.store.command must be an array of strings")
    })?;
    if command.is_empty() {
        bail!("{source}: provider `{provider_name}`.store.command must not be empty");
    }

    let mut fields = BTreeMap::new();
    if let Some(fields_val) = obj.get("fields") {
        let fields_obj = fields_val.as_object().with_context(|| {
            format!("{source}: provider `{provider_name}`.store.fields must be an object")
        })?;
        for (field_name, spec_val) in fields_obj {
            fields.insert(
                field_name.clone(),
                parse_field_spec(provider_name, field_name, spec_val, source)?,
            );
        }
    }

    // Omitting `value:` means stdin. Argv delivery is the explicit opt-in,
    // because it exposes the secret in `/proc/<pid>/cmdline` — world-readable
    // on Linux at the default `hidepid=0`, so a *cross-UID* leak, outside the
    // same-user carve-out. Every built-in uses stdin and `docs/providers.md`
    // says to prefer it; the silent default used to be the mode the docs warn
    // about, with no diagnostic.
    let value_mode = match obj.get("value").and_then(|v| v.as_str()) {
        Some("stdin") | None => ValueMode::Stdin,
        Some(_) => ValueMode::Arg,
    };

    let locator_template = obj
        .get("locator")
        .and_then(|v| v.as_str())
        .with_context(|| {
            format!(
                "{source}: provider `{provider_name}`.store is missing `locator` (template for the retrieve locator)"
            )
        })?
        .to_owned();

    Ok(StoreCapability {
        command,
        fields,
        value_mode,
        locator_template,
    })
}

fn parse_field_spec(
    provider_name: &str,
    field_name: &str,
    value: &Value,
    source: &str,
) -> Result<FieldSpec> {
    let obj = value.as_object().with_context(|| {
        format!("{source}: provider `{provider_name}`.store.fields.{field_name} must be an object")
    })?;
    let mut spec = FieldSpec::default();
    if let Some(req) = obj.get("required") {
        spec.required = as_bool(req, source, "required")?;
    }
    if let Some(opt) = obj.get("optional") {
        // Sugar from the design example: `optional: true` ⇔ `required: false`.
        spec.required = !as_bool(opt, source, "optional")?;
    }
    if let Some(def) = obj.get("default") {
        spec.default = match def {
            Value::Null => None,
            other => Some(as_str(other, source, "default")?.to_owned()),
        };
    }
    Ok(spec)
}

fn parse_string_array(value: &Value) -> Result<Vec<String>> {
    let arr = value.as_array().context("expected an array")?;
    arr.iter()
        .map(|v| {
            v.as_str()
                .map(std::borrow::ToOwned::to_owned)
                .context("expected a string array element")
        })
        .collect()
}

fn parse_group(name: &str, value: &Value, source: &str) -> Result<Group> {
    let obj = value
        .as_object()
        .with_context(|| format!("{source}: group `{name}` must be an object"))?;

    let mut group = Group {
        name: name.to_owned(),
        ..Group::default()
    };

    // First pass: collect group-level `$` settings so secrets can inherit them.
    for (key, val) in obj {
        match key.as_str() {
            "$provider" => group.provider = Some(as_str(val, source, key)?.to_owned()),
            "$reason" => group.reason = Some(as_str(val, source, key)?.to_owned()),
            "$description" => group.description = Some(as_str(val, source, key)?.to_owned()),
            "$required" => group.required = Some(as_bool(val, source, key)?),
            other if other.starts_with('$') => {
                bail!("{source}: group `{name}` has unknown setting `{other}`")
            }
            _ => {}
        }
    }

    // Second pass: secret declarations, folding in the group defaults.
    for (key, val) in obj {
        if key.starts_with('$') {
            continue;
        }
        let decl = parse_secret(name, key, val, &group, source)?;
        group.secrets.insert(key.clone(), decl);
    }

    Ok(group)
}

fn parse_secret(
    group_name: &str,
    secret_name: &str,
    value: &Value,
    group: &Group,
    source: &str,
) -> Result<SecretDecl> {
    // Defaults inherited from the group; per-secret values override below.
    let mut provider = group.provider.clone();
    let mut locator: Option<String> = None;
    let mut required = group.required.unwrap_or(true);
    let mut default: Option<String> = None;
    let mut description: Option<String> = None;

    match value {
        // Shorthand string: a full `secret://provider/locator` ref, or a bare
        // locator that uses the group's `$provider`.
        Value::String(s) => {
            apply_ref_string(s, &mut provider, &mut locator);
        }
        // Object form: explicit fields.
        Value::Object(map) => {
            if let Some(p) = map.get("provider") {
                provider = Some(as_str(p, source, "provider")?.to_owned());
            }
            if let Some(r) = map.get("ref") {
                apply_ref_string(as_str(r, source, "ref")?, &mut provider, &mut locator);
            }
            if let Some(req) = map.get("required") {
                required = as_bool(req, source, "required")?;
            }
            if let Some(d) = map.get("default") {
                default = match d {
                    Value::Null => None,
                    other => Some(as_str(other, source, "default")?.to_owned()),
                };
            }
            if let Some(desc) = map.get("description") {
                description = Some(as_str(desc, source, "description")?.to_owned());
            }
        }
        _ => {
            bail!("{source}: secret `{group_name}.{secret_name}` must be a string ref or an object")
        }
    }

    let locator = locator.with_context(|| {
        format!("{source}: secret `{group_name}.{secret_name}` has no `ref`/locator")
    })?;

    Ok(SecretDecl {
        name: secret_name.to_owned(),
        group: group_name.to_owned(),
        provider,
        locator,
        required,
        default,
        description,
        reason: group.reason.clone(),
    })
}

/// Interpret a ref string: a full `secret://provider/locator` overrides the
/// provider and sets the locator; otherwise the whole string is a bare locator.
fn apply_ref_string(s: &str, provider: &mut Option<String>, locator: &mut Option<String>) {
    if let Some(reference) = Reference::parse(s) {
        *provider = Some(reference.provider);
        *locator = Some(reference.locator);
    } else {
        *locator = Some(s.to_owned());
    }
}

fn as_str<'a>(value: &'a Value, source: &str, field: &str) -> Result<&'a str> {
    value
        .as_str()
        .with_context(|| format!("{source}: `{field}` must be a string"))
}

fn as_bool(value: &Value, source: &str, field: &str) -> Result<bool> {
    value
        .as_bool()
        .with_context(|| format!("{source}: `{field}` must be a boolean"))
}

/// The Tier-1 providers built into the binary (§13.1). These are available
/// without a manifest `providers` block; a manifest entry of the same name
/// overrides them. Entries are platform-gated to the store/CLI's reality.
///
/// Providers that have a robust, non-interactive write path also expose a
/// `store` capability — keychain (via `security add-generic-password`, stdin
/// value) and `pass` (via `pass insert -e`, stdin value). `op` and `lpass`
/// have rich, item-shaped writes that don't fit a one-size template; users
/// who want `store` for those define it in their manifest.
pub fn builtin_providers() -> BTreeMap<String, Provider> {
    fn retrieve_only(name: &str, retrieve: &[&str]) -> (String, Provider) {
        (
            name.to_owned(),
            Provider {
                name: name.to_owned(),
                retrieve: to_owned_vec(retrieve),
                store: None,
                retrieve_batch: None,
            },
        )
    }

    let mut out = BTreeMap::new();

    // 1Password CLI — cross-platform. Retrieve-only built-in.
    //
    // The batch capability uses `op run -- printenv`: we set N synthetic env
    // vars like `NAME=op://Work/db/url`; op resolves every `op://` it sees in
    // one biometric session and execs `printenv`, which echoes the env back as
    // KEY=VALUE lines we parse. `--no-masking` disables op's own redaction so
    // our parser sees the values (secreq's masker still scrubs them downstream).
    out.insert(
        "op".to_owned(),
        Provider {
            name: "op".to_owned(),
            retrieve: to_owned_vec(&["op", "read", "op://{locator}"]),
            store: None,
            retrieve_batch: Some(BatchRetrieve {
                command: to_owned_vec(&["op", "run", "--no-masking", "--", "printenv"]),
                env_value_template: "op://{locator}".to_owned(),
            }),
        },
    );

    #[cfg(target_os = "macos")]
    out.insert(
        "keychain".to_owned(),
        Provider {
            name: "keychain".to_owned(),
            retrieve: to_owned_vec(&["security", "find-generic-password", "-w", "-s", "{locator}"]),
            // `add-generic-password -U` updates an existing item if present.
            // The value is piped on stdin (no `-w` ⇒ stdin), keeping it out of
            // argv where `ps eww` could see it.
            store: Some(StoreCapability {
                command: to_owned_vec(&[
                    "security",
                    "add-generic-password",
                    "-U",
                    "-s",
                    "{service}",
                    "-a",
                    "{account}",
                ]),
                fields: BTreeMap::from([
                    ("service".to_owned(), required_field()),
                    ("account".to_owned(), required_field()),
                ]),
                value_mode: ValueMode::Stdin,
                locator_template: "{service}".to_owned(),
            }),
            // `security` has no batch mode; per-secret reads only.
            retrieve_batch: None,
        },
    );

    #[cfg(unix)]
    {
        out.extend([retrieve_only(
            "lastpass",
            &["lpass", "show", "--password", "{locator}"],
        )]);
        out.insert(
            "pass".to_owned(),
            Provider {
                name: "pass".to_owned(),
                retrieve: to_owned_vec(&["pass", "show", "{locator}"]),
                // `pass insert -e <name>` reads one line from stdin (no echo
                // prompt), so the value never appears in argv.
                store: Some(StoreCapability {
                    command: to_owned_vec(&["pass", "insert", "-f", "-e", "{name}"]),
                    fields: BTreeMap::from([("name".to_owned(), required_field())]),
                    value_mode: ValueMode::Stdin,
                    locator_template: "{name}".to_owned(),
                }),
                retrieve_batch: None,
            },
        );
    }

    out
}

fn to_owned_vec(slice: &[&str]) -> Vec<String> {
    slice.iter().map(|s| (*s).to_owned()).collect()
}

fn required_field() -> FieldSpec {
    FieldSpec {
        required: true,
        default: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
        database: {
            $provider: "op",
            $reason: "Database access",
            DATABASE_URL: "secret://keychain/myapp/db_url",
            DB_PASSWORD: {
                description: "Prod read-replica password",
                required: true,
                ref: "Work/Postgres/password",
            },
        },
        stripe: {
            STRIPE_KEY: "secret://op/Work/Stripe/api_key",
        },
        providers: {
            op: { read: ["op", "read", "op://{locator}"] },
            keychain: { read: ["security", "find-generic-password", "-w", "-s", "{locator}"] },
        },
    }"#;

    #[test]
    fn parses_groups_providers_and_secret_forms() {
        let m = Manifest::parse(SAMPLE, "sample").unwrap();
        assert_eq!(m.groups.len(), 2);
        assert_eq!(m.providers.len(), 2);

        // Full-ref shorthand overrides the group provider.
        let url = &m.groups["database"].secrets["DATABASE_URL"];
        assert_eq!(url.provider.as_deref(), Some("keychain"));
        assert_eq!(url.locator, "myapp/db_url");
        assert_eq!(url.reason.as_deref(), Some("Database access"));

        // Object form with a bare locator inherits the group `$provider`.
        let pw = &m.groups["database"].secrets["DB_PASSWORD"];
        assert_eq!(pw.provider.as_deref(), Some("op"));
        assert_eq!(pw.locator, "Work/Postgres/password");
        assert_eq!(
            pw.description.as_deref(),
            Some("Prod read-replica password")
        );
        assert!(pw.required);
    }

    #[test]
    fn required_defaults_to_true_then_group_then_secret() {
        let m = Manifest::parse(
            r#"{
                g: {
                    $required: false,
                    A: "secret://p/a",
                    B: { ref: "b", provider: "p", required: true },
                },
                providers: { p: { read: ["echo", "{locator}"] } },
            }"#,
            "t",
        )
        .unwrap();
        assert!(!m.groups["g"].secrets["A"].required); // inherits $required:false
        assert!(m.groups["g"].secrets["B"].required); // per-secret override
    }

    #[test]
    fn project_wins_on_merge() {
        let mut user = Manifest::parse(
            r#"{ db: { $provider: "op", PG: "secret://op/user/pg" },
                 providers: { op: { read: ["op","read","{locator}"] } } }"#,
            "user",
        )
        .unwrap();
        let project = Manifest::parse(
            r#"{ db: { PG: "secret://keychain/proj/pg" },
                 providers: { op: { read: ["op2","{locator}"] } } }"#,
            "project",
        )
        .unwrap();
        user.merge(project);
        // Project's secret wins.
        assert_eq!(
            user.groups["db"].secrets["PG"].provider.as_deref(),
            Some("keychain")
        );
        // Group `$provider` from user is preserved (project didn't set it).
        assert_eq!(user.groups["db"].provider.as_deref(), Some("op"));
        // Project overrode the provider scheme.
        assert_eq!(user.providers["op"].retrieve[0], "op2");
    }

    #[test]
    fn rejects_wasm_provider_in_mvp() {
        let err = Manifest::parse(r#"{ providers: { vault: { wasm: "./vault.wasm" } } }"#, "t")
            .unwrap_err();
        assert!(err.to_string().contains("Wasm"));
    }

    #[test]
    fn rejects_unknown_group_setting() {
        let err = Manifest::parse(r#"{ g: { $bogus: 1, A: "secret://p/a" } }"#, "t").unwrap_err();
        assert!(err.to_string().contains("$bogus"));
    }

    #[test]
    fn builtin_providers_include_op_and_platform_stores() {
        let p = builtin_providers();
        // 1Password is always built in (retrieve-only by default).
        assert_eq!(p["op"].retrieve, vec!["op", "read", "op://{locator}"]);
        assert!(p["op"].store.is_none(), "op built-in is retrieve-only");
        #[cfg(target_os = "macos")]
        {
            assert_eq!(p["keychain"].retrieve[0], "security");
            // The keychain built-in must be capable of persisting values.
            let cap = p["keychain"]
                .store
                .as_ref()
                .expect("keychain should expose a `store` capability");
            assert_eq!(cap.value_mode, ValueMode::Stdin, "value never via argv");
            assert!(cap.fields.contains_key("service"));
            assert!(cap.fields.contains_key("account"));
        }
        #[cfg(unix)]
        {
            assert!(p.contains_key("lastpass"));
            // `pass` built-in is also store-capable (stdin via `pass insert -e`).
            let pass_store = p["pass"]
                .store
                .as_ref()
                .expect("pass should expose a `store` capability");
            assert_eq!(pass_store.value_mode, ValueMode::Stdin);
        }
    }

    #[test]
    fn manifest_providers_override_builtins_on_merge() {
        let mut base = Manifest::with_builtin_providers();
        let user = Manifest::parse(
            r#"{ providers: { op: { retrieve: ["my-op", "{locator}"] } } }"#,
            "user",
        )
        .unwrap();
        base.merge(user);
        // The manifest's `op` wins over the built-in.
        assert_eq!(base.providers["op"].retrieve[0], "my-op");
    }

    #[test]
    fn parses_a_store_capability_block() {
        let m = Manifest::parse(
            r#"{
                providers: {
                    custom: {
                        retrieve: ["printf", "%s", "{locator}"],
                        store: {
                            command: ["sh", "-c", "echo '{name}={value}'"],
                            fields: {
                                name: { required: true },
                                tag:  { optional: true, default: "v1" },
                            },
                            value: "{value}",
                            locator: "{name}",
                        },
                    },
                },
            }"#,
            "t",
        )
        .unwrap();
        let cap = m.providers["custom"]
            .store
            .as_ref()
            .expect("store should parse");
        assert_eq!(cap.value_mode, ValueMode::Arg);
        assert_eq!(cap.locator_template, "{name}");
        assert!(cap.fields["name"].required);
        // `optional: true` is sugar for `required: false`.
        assert!(!cap.fields["tag"].required);
        assert_eq!(cap.fields["tag"].default.as_deref(), Some("v1"));
    }

    #[test]
    fn store_block_value_stdin_selects_stdin_mode() {
        let m = Manifest::parse(
            r#"{
                providers: {
                    p: {
                        retrieve: ["true"],
                        store: {
                            command: ["sh", "-c", "cat"],
                            fields: { name: { required: true } },
                            value: "stdin",
                            locator: "{name}",
                        },
                    },
                },
            }"#,
            "t",
        )
        .unwrap();
        assert_eq!(
            m.providers["p"].store.as_ref().unwrap().value_mode,
            ValueMode::Stdin
        );
    }

    #[test]
    fn historical_read_and_write_names_still_parse() {
        // The design doc uses `read`/`write`; manifests written against the
        // doc must keep loading after the rename.
        let m = Manifest::parse(
            r#"{
                providers: {
                    legacy: {
                        read: ["printf", "%s", "{locator}"],
                        write: {
                            command: ["sh", "-c", "cat > /tmp/x"],
                            fields: { name: { required: true } },
                            value: "stdin",
                            locator: "{name}",
                        },
                    },
                },
            }"#,
            "t",
        )
        .unwrap();
        assert_eq!(m.providers["legacy"].retrieve[0], "printf");
        assert!(m.providers["legacy"].store.is_some());
    }
}
