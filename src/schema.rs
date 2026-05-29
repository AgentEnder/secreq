//! JSON Schema for `wraps.json5` — the source of truth.
//!
//! Hand-constructed as a [`serde_json::Value`] tree because the on-disk
//! format has dynamic keys (arbitrary binary names alongside reserved
//! `providers` / `$`-prefixed metadata) and a few Rust↔JSON shape
//! mismatches (`ValueMode::Stdin` vs `value: "stdin"`).
//!
//! ## Regenerating `docs/wraps.schema.json`
//!
//! ```sh
//! cargo run --example gen-schema > docs/wraps.schema.json
//! ```
//!
//! A test in `tests/schema_drift.rs` fails CI if the committed file falls
//! out of sync with [`wraps_schema`].

use serde_json::{json, Value};

/// The complete JSON Schema for `wraps.json5`.
pub fn wraps_schema() -> Value {
    json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "$id": "https://secreq.dev/schema/wraps.schema.json",
        "title": "secreq wraps config",
        "description": "Per-binary wrap configuration for `secreq` \
            (`$XDG_CONFIG_HOME/secreq/wraps.json5`). Top-level keys are \
            binary names; reserved keys are `providers` and any \
            `$`-prefixed metadata. See docs/wraps.md.",
        "type": "object",
        "properties": {
            "$schema": {
                "type": "string",
                "description": "URL or path of this JSON Schema. Ignored by `secreq`."
            },
            "$shim_dir": {
                "type": "string",
                "description": "Directory where `secreq wrap` drops PATH shims. Set by `secreq init`. Supports a leading `~/`."
            },
            "providers": {
                "type": "object",
                "description": "Provider scheme definitions. Built-in providers (`op`, `keychain` on macOS, `lastpass` / `pass` on Unix) are available without an explicit entry; entries here override or add new schemes.",
                "additionalProperties": { "$ref": "#/definitions/Provider" }
            }
        },
        "patternProperties": {
            "^[A-Za-z_][A-Za-z0-9_.+-]*$": { "$ref": "#/definitions/Wrap" }
        },
        "additionalProperties": false,
        "definitions": {
            "Wrap":            wrap_schema(),
            "Provider":        provider_schema(),
            "StoreCapability": store_capability_schema(),
            "FieldSpec":       field_spec_schema(),
            "BatchRetrieve":   batch_retrieve_schema()
        }
    })
}

/// Back-compat: kept under the old name for the drift test's stable import path.
pub fn manifest_schema() -> Value {
    wraps_schema()
}

fn wrap_schema() -> Value {
    json!({
        "type": "object",
        "description": "One per-binary wrap. `env` is required; everything else is metadata.",
        "required": ["env"],
        "properties": {
            "$reason": {
                "type": "string",
                "description": "Rationale shown in the consent prompt when this wrap is invoked."
            },
            "$description": {
                "type": "string",
                "description": "Optional free-form description (currently unused at runtime; kept for parity with future tooling)."
            },
            "env": {
                "type": "object",
                "description": "Environment variables to inject. Each value is a `secret://provider/locator` reference; resolution happens at invocation time.",
                "additionalProperties": {
                    "type": "string",
                    "pattern": "^secret://[^/]+/.+$",
                    "description": "A `secret://provider/locator` reference."
                },
                "minProperties": 1
            }
        },
        "additionalProperties": false
    })
}

fn provider_schema() -> Value {
    json!({
        "type": "object",
        "description": "A provider scheme. Required `retrieve`, optional `store`, optional `retrieve_batch`.",
        "anyOf": [
            { "required": ["retrieve"] },
            { "required": ["read"] }
        ],
        "properties": {
            "retrieve": {
                "type": "array",
                "items": { "type": "string" },
                "minItems": 1,
                "description": "Argv template for fetching a secret. `{locator}` is substituted with the secret's locator; stdout is the value (one trailing newline stripped)."
            },
            "read": {
                "type": "array",
                "items": { "type": "string" },
                "minItems": 1,
                "description": "Legacy name for `retrieve` (the design doc §6 uses this name). Both are accepted; prefer `retrieve`."
            },
            "store": { "$ref": "#/definitions/StoreCapability" },
            "write": {
                "$ref": "#/definitions/StoreCapability",
                "description": "Legacy name for `store`. Both are accepted; prefer `store`."
            },
            "retrieve_batch": { "$ref": "#/definitions/BatchRetrieve" },
            "retrieveBatch": {
                "$ref": "#/definitions/BatchRetrieve",
                "description": "camelCase alias for `retrieve_batch`."
            }
        },
        "additionalProperties": false
    })
}

fn store_capability_schema() -> Value {
    json!({
        "type": "object",
        "description": "How this provider persists a new value (currently exposed via custom CLIs the user may write that drive `secreq` programmatically — the public `secreq` CLI no longer exposes a `store` verb).",
        "required": ["command", "locator"],
        "properties": {
            "command": {
                "type": "array",
                "items": { "type": "string" },
                "minItems": 1,
                "description": "Argv template. `{field}` placeholders are filled from caller-supplied inputs; `{value}` (argv mode) is the secret. Prefer stdin mode."
            },
            "fields": {
                "type": "object",
                "additionalProperties": { "$ref": "#/definitions/FieldSpec" }
            },
            "value": {
                "type": "string",
                "default": "{value}",
                "description": "`\"stdin\"` (preferred) pipes via stdin; anything else (typically `\"{value}\"`) selects argv-substitution mode."
            },
            "locator": {
                "type": "string",
                "description": "Template that builds the retrieve-side locator from the same field inputs."
            }
        },
        "additionalProperties": false
    })
}

fn field_spec_schema() -> Value {
    json!({
        "type": "object",
        "description": "Schema for one field in a provider's `store.fields`.",
        "properties": {
            "required": { "type": "boolean", "default": false },
            "optional": { "type": "boolean", "description": "Sugar for `required: false`." },
            "default":  { "type": ["string", "null"] }
        },
        "additionalProperties": false
    })
}

fn batch_retrieve_schema() -> Value {
    json!({
        "type": "object",
        "description": "Batched-retrieve: one command invocation resolves many secrets at once (e.g. `op run -- printenv`). Used automatically when a wrap's `env` references the same provider for ≥2 entries, cutting biometric prompts from N to 1. Protocol: per requested (name, locator), set env var `name` to `env_value` with `{locator}` substituted; spawn `command`; parse stdout as `KEY=VALUE` lines.",
        "required": ["command", "env_value"],
        "properties": {
            "command": {
                "type": "array",
                "items": { "type": "string" },
                "minItems": 1
            },
            "env_value": {
                "type": "string",
                "description": "Template for each synthetic env entry's value. For 1Password: `\"op://{locator}\"`."
            }
        },
        "additionalProperties": false
    })
}
