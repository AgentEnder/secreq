//! The provider model: schemes that know how to fetch (and sometimes store) a
//! secret.
//!
//! This began as the `secrets.json5` loader — groups of declared secrets, each
//! with inheritable settings. Wraps replaced that model, and what survived is
//! the half both shapes shared: [`Provider`] and the `providers` block parser
//! [`crate::wraps`] calls at load time.
//!
//! [`Manifest`] is now just the provider set handed to
//! [`crate::resolve::resolve_all`]. Every caller builds one in memory; nothing
//! reads a manifest file.

use std::collections::BTreeMap;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The reserved top-level key that defines provider schemes.
pub const PROVIDERS_KEY: &str = "providers";

/// The provider schemes available to a resolution.
///
/// Every caller builds one in memory from the loaded [`crate::wraps`] config
/// (or from the wire, in the daemon) and hands it to
/// [`crate::resolve::resolve_all`] — nothing reads a manifest file.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Manifest {
    pub providers: BTreeMap<String, Provider>,
}

/// A provider scheme. Required `retrieve`, optional `store`, optional
/// `retrieve_batch`.
//
// The published `providers` block in `docs/wraps.schema.json` is derived from
// this type (`schema.rs`), so every `///` below reaches secreq.dev as that
// property's `description`. The parser walks `serde_json::Value` by hand
// rather than deserializing, so the JSON key names are the `schemars(rename)`
// beside each field; `schema_covers_every_key_the_parser_accepts` in
// `tests/schema_drift.rs` is what holds the two together.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(deny_unknown_fields))]
#[cfg_attr(feature = "schema", schemars(extend("anyOf" = crate::schema::provider_any_of())))]
pub struct Provider {
    /// The provider's name is the key it is filed under, not a property of the
    /// object, so it is absent from the schema and from the serialized form.
    #[serde(skip)]
    #[cfg_attr(feature = "schema", schemars(skip))]
    pub name: String,
    /// Argv template for fetching a secret. `{locator}` is substituted with the
    /// secret's locator; stdout is the value (one trailing newline stripped).
    //
    // Required, but declared through the `anyOf` above rather than
    // `required: ["retrieve"]`, because `read` satisfies it too.
    #[serde(alias = "read")]
    #[cfg_attr(feature = "schema", schemars(default, length(min = 1)))]
    pub retrieve: Vec<String>,
    /// How this provider persists a new value. Optional — a provider without
    /// it is retrieve-only.
    #[serde(default, alias = "write", skip_serializing_if = "Option::is_none")]
    pub store: Option<StoreCapability>,
    /// Batched retrieve: one command invocation resolves many secrets at once
    /// (e.g. `op run -- printenv`). Used automatically when a wrap's `env`
    /// references the same provider for two or more entries, cutting biometric
    /// prompts from N to 1.
    #[serde(
        default,
        alias = "retrieveBatch",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(feature = "schema", schemars(rename = "retrieve_batch"))]
    pub retrieve_batch: Option<BatchRetrieve>,
}

/// Batched-retrieve: one command invocation resolves many secrets at once
/// (e.g. `op run -- printenv`). Used automatically when a wrap's `env`
/// references the same provider for two or more entries, cutting biometric
/// prompts from N to 1. Protocol: per requested (name, locator), set env var
/// `name` to `env_value` with `{locator}` substituted; spawn `command`; parse
/// stdout as `KEY=VALUE` lines.
//
// Limitation: line-based output can't carry multi-line values intact. If any
// value contains a newline, the resolver falls back to per-secret retrieve
// (this is detected when the parsed output is missing names we asked for).
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(deny_unknown_fields))]
pub struct BatchRetrieve {
    /// argv to execute. The synthetic env entries are added to the child's
    /// environment; no placeholder substitution happens on `command` itself.
    #[cfg_attr(feature = "schema", schemars(length(min = 1)))]
    pub command: Vec<String>,
    /// Template for each synthetic env entry's value. `{locator}` is
    /// substituted per secret; the env-var name is the secret's name. For
    /// 1Password: `"op://{locator}"`.
    #[serde(rename = "env_value", alias = "envValue")]
    #[cfg_attr(feature = "schema", schemars(rename = "env_value"))]
    pub env_value_template: String,
}

/// How this provider persists a new value (currently exposed via custom CLIs
/// the user may write that drive `secreq` programmatically — the public
/// `secreq` CLI no longer exposes a `store` verb).
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(deny_unknown_fields))]
pub struct StoreCapability {
    /// Argv template. `{field}` placeholders are filled from caller-supplied
    /// inputs; `{value}` (argv mode) is the secret. Prefer stdin mode.
    #[cfg_attr(feature = "schema", schemars(length(min = 1)))]
    pub command: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    #[cfg_attr(feature = "schema", schemars(default))]
    pub fields: BTreeMap<String, FieldSpec>,
    /// How the secret reaches `command`. Omitted or `"stdin"` pipes it in on
    /// stdin, which is the default. Any other string (typically `"{value}"`)
    /// opts into argv-substitution mode, where the secret appears in the
    /// process's command line and is readable by other users on Linux at the
    /// default `hidepid=0`. Prefer stdin.
    //
    // `ValueMode` is an enum in Rust and a free string on disk, because
    // `parse_store_capability` reads anything that isn't `"stdin"` as argv
    // mode. `default: "stdin"` below is that inversion; it was published as
    // `"{value}"` for a month after the parser changed.
    #[serde(rename = "value", default, with = "value_mode_as_str")]
    #[cfg_attr(
        feature = "schema",
        schemars(
            rename = "value",
            with = "String",
            default,
            extend("default" = "stdin")
        )
    )]
    pub value_mode: ValueMode,
    /// Template that builds the retrieve-side locator from the same field
    /// inputs.
    #[serde(rename = "locator")]
    #[cfg_attr(feature = "schema", schemars(rename = "locator"))]
    pub locator_template: String,
}

/// `value` is a free string on disk and an enum in Rust: `"stdin"` (or an
/// absent key) selects stdin delivery, and **any other string** opts into
/// argv substitution. That inversion is deliberate — argv delivery exposes the
/// secret in `/proc/<pid>/cmdline`, so it has to be the thing you ask for.
mod value_mode_as_str {
    use super::ValueMode;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(mode: &ValueMode, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(match mode {
            ValueMode::Stdin => "stdin",
            ValueMode::Arg => "{value}",
        })
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<ValueMode, D::Error> {
        // A non-string is an error now. The hand-written parser reached for
        // `as_str()` and silently fell back to stdin on, say, `value: 3`.
        let raw = String::deserialize(d)?;
        Ok(if raw == "stdin" {
            ValueMode::Stdin
        } else {
            ValueMode::Arg
        })
    }
}

/// Schema for one field in a provider's `store.fields`.
#[derive(Debug, Clone, PartialEq, Default, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(deny_unknown_fields))]
pub struct FieldSpec {
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(default))]
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
}

/// The on-disk form of a [`FieldSpec`], which accepts `optional: true` as
/// sugar for `required: false` (the spelling the design example used). Kept as
/// a separate wire type so `FieldSpec` itself stays a plain two-field struct —
/// `optional` is an input spelling, never a stored one.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FieldSpecWire {
    #[serde(default)]
    required: bool,
    #[serde(default)]
    optional: Option<bool>,
    #[serde(default)]
    default: Option<String>,
}

// Hand-written rather than `#[serde(from = "FieldSpecWire")]`, because
// `schemars` reads serde's container attributes: `from` would make the
// published schema describe the wire type, and `optional` is an accepted input
// spelling rather than part of the documented shape.
impl<'de> Deserialize<'de> for FieldSpec {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<FieldSpec, D::Error> {
        let wire = FieldSpecWire::deserialize(d)?;
        Ok(FieldSpec {
            // `optional` wins when both are present, matching the parser this
            // replaces.
            required: wire.optional.map_or(wire.required, |opt| !opt),
            default: wire.default,
        })
    }
}

/// How the secret value is delivered to the store command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ValueMode {
    /// Substitute the value into argv (any `{value}` placeholder is replaced).
    /// Convenient, but exposes the value to `ps eww` for the child's lifetime.
    Arg,
    /// Pipe the value on the child's stdin. Keeps the value out of argv —
    /// preferred for any built-in (§11).
    ///
    /// The default, and `parse_store_capability` says so too — omitting
    /// `value:` selects this. Argv delivery is the explicit opt-in.
    #[default]
    Stdin,
}

impl Manifest {
    /// A manifest seeded with the built-in Tier-1 providers. A user
    /// `providers` entry of the same name overlays the built-in (§6, §13.1).
    pub fn with_builtin_providers() -> Manifest {
        Manifest {
            providers: builtin_providers(),
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

    let store = match present(obj.get("store").or_else(|| obj.get("write"))) {
        Some(value) => Some(parse_store_capability(name, value, source)?),
        None => None,
    };

    let retrieve_batch = match present(
        obj.get("retrieve_batch")
            .or_else(|| obj.get("retrieveBatch")),
    ) {
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

/// Read an optional key: an explicit `null` means the same as an absent key.
///
/// The distinction is not one a config file can usefully draw — `store: null`
/// says "no store capability" as plainly as omitting it — and the published
/// schema derives these from `Option<T>`, which is exactly "absent or a T".
/// Without this the schema would have to declare a `null` the parser rejects.
pub(crate) fn present(value: Option<&Value>) -> Option<&Value> {
    value.filter(|v| !v.is_null())
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

    /// Build a [`Manifest`] from a fixture's `providers` block — exactly what
    /// `wraps.rs` does at load time, and all these tests ever needed. The
    /// group-shaped half of the old `secrets.json5` loader is gone; only the
    /// provider parser it shared with the wraps config survives.
    fn parse_manifest(text: &str, source: &str) -> Result<Manifest> {
        let root: Value =
            json5::from_str(text).with_context(|| format!("{source}: invalid JSON5 fixture"))?;
        let providers = match root.get(PROVIDERS_KEY) {
            Some(block) => parse_providers_value(block, source)?,
            None => BTreeMap::new(),
        };
        Ok(Manifest { providers })
    }

    #[test]
    fn rejects_wasm_provider_in_mvp() {
        let err = parse_manifest(r#"{ providers: { vault: { wasm: "./vault.wasm" } } }"#, "t")
            .unwrap_err();
        assert!(err.to_string().contains("Wasm"));
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
    fn parses_a_store_capability_block() {
        let m = parse_manifest(
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
        let m = parse_manifest(
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
    fn an_explicit_null_capability_means_the_provider_has_none() {
        // `Option<StoreCapability>` is what the published schema derives from,
        // and it says "absent or a store" — so `store: null` has to load as
        // "no store", not as "a store that isn't an object".
        let m = parse_manifest(
            r#"{
                providers: {
                    p: { retrieve: ["true"], store: null, retrieve_batch: null },
                },
            }"#,
            "t",
        )
        .expect("null capabilities load as absent ones");
        assert!(m.providers["p"].store.is_none());
        assert!(m.providers["p"].retrieve_batch.is_none());
    }

    #[test]
    fn historical_read_and_write_names_still_parse() {
        // The design doc uses `read`/`write`; manifests written against the
        // doc must keep loading after the rename.
        let m = parse_manifest(
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
