//! The two published JSON Schemas, derived from the types that read the files.
//!
//! ```sh
//! cargo run --example gen-schema             > docs/wraps.schema.json
//! cargo run --example gen-auto-rules-schema  > docs/auto-rules.schema.json
//! ```
//!
//! ## Where the schema comes from
//!
//! Everything under `definitions` is `schemars`, run over [`crate::rules`],
//! [`crate::wraps`] and [`crate::manifest`]: the property names, which of them
//! are required, their types, and — because `schemars` reads doc comments —
//! their prose. **A field's `description` is written at the field**, next to
//! the code the description is a claim about.
//!
//! That is the whole point of the arrangement. This module used to be a
//! hand-written `serde_json::json!` tree, and `tests/schema_drift.rs` compares
//! the committed JSON to *this generator*, never to `rules.rs` or
//! `manifest.rs` — so a description could contradict the parser indefinitely,
//! and three did: `cwd` documented as a plain prefix after
//! `Pattern::matches_path_prefix` made it segment-aware, `ancestor` claiming
//! the `exe` path was "NOT currently part of the match input" after it became
//! the *primary* input, and `store.value` advertising `{value}` as its default
//! after the parser inverted it to stdin — the mode that keeps a secret out of
//! `/proc/<pid>/cmdline`.
//!
//! ## What is still written by hand, and why
//!
//! Two things a Rust type cannot say, both of them here rather than scattered:
//!
//! - **The file envelope.** `wraps.json5` is keyed by names the user chooses —
//!   binary names — which is `patternProperties`, not a struct. `$schema` is
//!   in the same category: secreq ignores the key, so no type has a field for
//!   it, but an editor writes it and must not be told it is invalid.
//! - **Constraints that are not shapes.** Declarative-XOR-wasm is a `oneOf`
//!   ([`crate::rules::rule_one_of`], stated next to the `TryFrom` that
//!   enforces it), and a provider's `retrieve`/`read` pair is an `anyOf`
//!   ([`provider_any_of`]).
//!
//! ## The `wraps.json5` parser is hand-written, so its key names are too
//!
//! `manifest.rs` and `wraps.rs` walk a [`serde_json::Value`] rather than
//! deriving `Deserialize`, because a wraps file's top level is arbitrary binary
//! names beside a reserved `providers` key. So the JSON name of a field whose
//! Rust name differs (`env_value_template` → `env_value`, `locator_template` →
//! `locator`, `value_mode` → `value`) is a `schemars(rename)` beside that
//! field, not something the compiler derives.
//! `schema_covers_every_key_the_parser_accepts` in `tests/schema_drift.rs` is
//! what holds those two halves together: it feeds the parser a config using
//! every key the schema declares, and one key the schema does not.

use serde_json::{json, Value};

use crate::manifest::Provider;
use crate::rules::RulesFile;
use crate::wraps::{SshIdentity, Wrap};

// An `$id` is what a user's editor fetches when they put `$schema` at the top
// of their config, so it has to be the URL the file is actually served from.
// These were `secreq.dev/schema/…` and were wrong twice over: the domain was
// never registered, and the path was singular while `docs-site` publishes the
// files under `/schemas/`. Neither `$id` has ever resolved.

/// `$id` of the auto-rules schema. Read by [`RulesFile`]'s derive.
pub const AUTO_RULES_ID: &str = "https://craigory.dev/secreq/schemas/auto-rules.schema.json";

/// `$id` of the wraps schema.
pub const WRAPS_ID: &str = "https://craigory.dev/secreq/schemas/wraps.schema.json";

/// The reserved top-level `$schema` key, which both of these files may carry
/// and neither of them reads.
///
/// Not a field on any type: secreq's loaders skip `$`-prefixed metadata
/// wholesale, so there is nothing in Rust for it to be derived from. Declaring
/// it stops an editor from flagging the pointer it wrote itself.
pub fn schema_pointer_property() -> Value {
    json!({
        "$schema": {
            "type": "string",
            "description": "URL or path of this JSON Schema. Ignored by `secreq`."
        }
    })
}

/// `retrieve` is required, but `read` satisfies it — see `parse_provider`,
/// which accepts either. Stated as an `anyOf` because a plain
/// `required: ["retrieve"]` would invalidate every config written against the
/// design doc's name.
pub fn provider_any_of() -> Value {
    json!([
        { "required": ["retrieve"] },
        { "required": ["read"] }
    ])
}

/// The three legacy spellings `parse_provider` still accepts. They are not
/// fields on [`Provider`] — the parser folds each into its modern name on the
/// way in — so they cannot be derived, but a file using them is valid and the
/// schema has to say so.
pub fn provider_legacy_properties() -> Value {
    json!({
        "read": {
            "type": "array",
            "items": { "type": "string" },
            "minItems": 1,
            "description": "Legacy name for `retrieve` (the design doc §6 uses this name). Both are accepted; prefer `retrieve`."
        },
        "write": {
            "$ref": "#/definitions/StoreCapability",
            "description": "Legacy name for `store`. Both are accepted; prefer `store`."
        },
        "retrieveBatch": {
            "$ref": "#/definitions/BatchRetrieve",
            "description": "camelCase alias for `retrieve_batch`."
        }
    })
}

/// `optional: true` is sugar for `required: false` — `parse_field_spec` reads
/// it and inverts. Sugar has no field of its own to be derived from.
pub fn field_spec_optional_property() -> Value {
    json!({
        "optional": {
            "type": "boolean",
            "description": "Sugar for `required: false`."
        }
    })
}

/// A wrap's `env` map: env-var name to `secret://provider/locator` reference.
///
/// A named type so [`Wrap`]'s `env` values carry the reference pattern that
/// `BTreeMap<String, String>` alone would not. Never constructed — it exists
/// to be a `schemars(with = …)` target.
pub struct SecretRefMap;

impl schemars::JsonSchema for SecretRefMap {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        "SecretRefMap".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "object",
            "additionalProperties": {
                "type": "string",
                "pattern": r"^secret://[^/]+/.+$",
                "description": "A `secret://provider/locator` reference."
            }
        })
    }
}

/// A fresh draft-07 generator.
///
/// Draft-07 rather than schemars' 2020-12 default because that is what both
/// committed files declare and what the editors pointed at them support:
/// `definitions` rather than `$defs`, and no `$ref` siblings.
fn generator() -> schemars::SchemaGenerator {
    schemars::generate::SchemaSettings::draft07().into_generator()
}

/// Add properties to an already-generated object schema, keeping the derived
/// ones.
///
/// `schemars(extend("properties" = …))` would *replace* them, silently
/// emptying the definition it was meant to add one key to.
fn add_properties(schema: &mut Value, extra: &Value) {
    let (Some(properties), Some(extra)) = (
        schema.get_mut("properties").and_then(Value::as_object_mut),
        extra.as_object(),
    ) else {
        panic!("add_properties needs an object schema with properties, and an object to merge");
    };
    for (key, value) in extra {
        properties.insert(key.clone(), value.clone());
    }
}

/// Render every `description` as the prose it is: a doc comment's line breaks
/// are the author's wrapping, not the reader's.
///
/// Paragraph breaks (a blank line) survive; a lone newline becomes a space.
/// Without this, whether a description reads as one sentence or six on
/// secreq.dev would depend on where a `///` happened to wrap in the source.
fn flatten_descriptions(schema: &mut Value) {
    match schema {
        Value::Object(map) => {
            if let Some(Value::String(text)) = map.get_mut("description") {
                *text = text
                    .split("\n\n")
                    .map(|para| para.split('\n').collect::<Vec<_>>().join(" "))
                    .collect::<Vec<_>>()
                    .join("\n\n");
            }
            for value in map.values_mut() {
                flatten_descriptions(value);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(flatten_descriptions),
        _ => {}
    }
}

/// The complete JSON Schema for `auto-rules.json5`.
///
/// The root is [`RulesFile`] — `{ rules: [...] }` really is a struct — so
/// there is nothing to assemble beyond letting the derive run and declaring
/// the `$schema` pointer no type has a field for.
pub fn auto_rules_schema() -> Value {
    let mut schema = generator().into_root_schema_for::<RulesFile>().to_value();
    add_properties(&mut schema, &schema_pointer_property());
    flatten_descriptions(&mut schema);
    schema
}

/// The complete JSON Schema for `wraps.json5`.
///
/// Assembled rather than derived from [`crate::wraps::WrapsConfig`], because
/// the top level is *dynamic*: every key that isn't `providers`, `ssh`, or
/// `$`-prefixed metadata is a binary name the user chose, which no struct
/// field can stand for. Every definition it points at is derived.
pub fn wraps_schema() -> Value {
    let mut generator = generator();

    // Registering each definition yields the `$ref` that points at it.
    let wrap = generator.subschema_for::<Wrap>().to_value();
    let provider = generator.subschema_for::<Provider>().to_value();
    let ssh_identity = generator.subschema_for::<SshIdentity>().to_value();
    let mut definitions = Value::Object(generator.take_definitions(true));

    // The keys the parser accepts that are not fields on any type: legacy
    // spellings it folds away, sugar it inverts, and metadata it ignores.
    add_properties(
        definitions
            .get_mut("Provider")
            .expect("Provider was just registered"),
        &provider_legacy_properties(),
    );
    add_properties(
        definitions
            .get_mut("FieldSpec")
            .expect("FieldSpec is reachable from Provider"),
        &field_spec_optional_property(),
    );
    // Every root key is declared, because wraps moved into `[wraps.*]`. The
    // previous envelope could not do this: the root was an open namespace
    // where any unrecognised key was a binary name, so it needed a
    // `patternProperties` escape hatch and could never say `additionalProperties:
    // false`. It also could not tell a mistyped `provdiers` from a wrap — and
    // neither could the loader.
    let mut schema = json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "$id": WRAPS_ID,
        "title": "secreq config",
        "description": "Configuration for `secreq` (`~/.secreq/config.toml`, or \
            `$SECREQ_HOME/config.toml`). Wraps live under `wraps`, keyed by binary \
            name. See docs/wraps.md.",
        "type": "object",
        "properties": {
            "editor": {
                "type": "string",
                "description": "Editor the rule editor's 'Open in editor' split-button opens by default (an editor id such as `code`, `cursor`, `zed`, or `nvim`). Machine-local, like `shim_dir`; written when you pick an editor in the Rules view of `secreq view`."
            },
            "shim_dir": {
                "type": "string",
                "description": "Directory where `secreq wrap` drops PATH shims. Set by `secreq init`. Supports a leading `~/`."
            },
            "wait_indicator": {
                "type": "boolean",
                "description": "Whether a wrap prints a 'waiting for approval' indicator to stderr while blocked on the consent prompt (spinner on a TTY, a timestamped line on a pipe). Defaults to true; set false to silence. The SECREQ_NO_WAIT_INDICATOR env var overrides this per-invocation."
            },
            "wraps": {
                "type": "object",
                "description": "Per-binary wrap configuration, keyed by the binary name the shim is installed under. A wrap with no `env` is *gate-only*: consent is required before the binary runs, but nothing is injected.",
                "additionalProperties": wrap
            },
            "providers": {
                "type": "object",
                "description": "Provider scheme definitions. Built-in providers (`op`, `keychain` on macOS, `lastpass` / `pass` on Unix) are available without an explicit entry; entries here override or add new schemes.",
                "additionalProperties": provider
            },
            "ssh": {
                "type": "object",
                "description": "SSH identities served by the consent-gated SSH agent, keyed by identity name. Each identity stores its public key inline (not secret) so the agent can answer REQUEST_IDENTITIES without a resolve; the private key is a `secret://` reference resolved only at SIGN time.",
                "additionalProperties": ssh_identity
            }
        },
        "additionalProperties": false,
        "definitions": definitions
    });
    flatten_descriptions(&mut schema);
    schema
}
