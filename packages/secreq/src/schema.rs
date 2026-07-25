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
            (`~/.secreq/wraps.json5`, or `$SECREQ_HOME/wraps.json5`). Top-level keys are \
            binary names; reserved keys are `providers` and any \
            `$`-prefixed metadata. See docs/wraps.md.",
        "type": "object",
        "properties": {
            "$schema": {
                "type": "string",
                "description": "URL or path of this JSON Schema. Ignored by `secreq`."
            },
            "$editor": {
                "type": "string",
                "description": "Editor the rule editor's 'Open in editor' split-button opens by default (an editor id such as `code`, `cursor`, `zed`, or `nvim`). Machine-local, like `$shim_dir`; written when you pick an editor in the Rules view of `secreq view`."
            },
            "$shim_dir": {
                "type": "string",
                "description": "Directory where `secreq wrap` drops PATH shims. Set by `secreq init`. Supports a leading `~/`."
            },
            "$wait_indicator": {
                "type": "boolean",
                "description": "Whether a wrap prints a 'waiting for approval' indicator to stderr while blocked on the consent prompt (spinner on a TTY, a timestamped line on a pipe). Defaults to true; set false to silence. The SECREQ_NO_WAIT_INDICATOR env var overrides this per-invocation."
            },
            "providers": {
                "type": "object",
                "description": "Provider scheme definitions. Built-in providers (`op`, `keychain` on macOS, `lastpass` / `pass` on Unix) are available without an explicit entry; entries here override or add new schemes.",
                "additionalProperties": { "$ref": "#/definitions/Provider" }
            },
            "ssh": {
                "type": "object",
                "description": "SSH identities served by the consent-gated SSH agent, keyed by identity name. Each identity stores its public key inline (not secret) so the agent can answer REQUEST_IDENTITIES without a resolve; the private key is a `secret://` reference resolved only at SIGN time.",
                "additionalProperties": { "$ref": "#/definitions/SshIdentity" }
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
            "BatchRetrieve":   batch_retrieve_schema(),
            "SshIdentity":     ssh_identity_schema()
        }
    })
}

/// Back-compat: kept under the old name for the drift test's stable import path.
pub fn manifest_schema() -> Value {
    wraps_schema()
}

/// JSON Schema for `auto-rules.json5` — the persisted ruleset the
/// daemon evaluates before prompting the user. Source of truth in
/// `src/rules.rs`; see `dev-docs/plans/2026-06-02-auto-rules.md`.
///
/// Regenerate:
/// ```sh
/// cargo run --example gen-auto-rules-schema > docs/auto-rules.schema.json
/// ```
pub fn auto_rules_schema() -> Value {
    json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "$id": "https://secreq.dev/schema/auto-rules.schema.json",
        "title": "secreq auto-rules config",
        "description": "Persisted auto-approve / auto-deny rules for `secreq` \
            (`~/.secreq/auto-rules.json5`, or `$SECREQ_HOME/auto-rules.json5`). Owned by the consent \
            daemon; clients normally don't edit the file directly.",
        "type": "object",
        "properties": {
            "$schema": {
                "type": "string",
                "description": "URL or path of this JSON Schema. Ignored by `secreq`."
            },
            "rules": {
                "type": "array",
                "description": "Ordered list of rules. Order does not affect precedence (deny-wins, then most-specific approve), but is preserved on read/write so hand-edits stay stable.",
                "items": { "$ref": "#/definitions/Rule" }
            }
        },
        "additionalProperties": false,
        "definitions": {
            "Rule": rule_schema(),
            "RuleMatch": rule_match_schema(),
            "WasmRule": wasm_rule_schema()
        }
    })
}

fn rule_schema() -> Value {
    json!({
        "type": "object",
        "description": "One auto-decision rule. Exactly one of two shapes: declarative (`decide` + `match`, `wasm` absent) or wasm (`wasm` alone — the compiled module returns approve/pass/deny at evaluation time, so `decide` and `deny_message` must be absent).",
        "required": ["id", "name", "enabled"],
        "oneOf": [
            {
                "description": "Declarative rule: static decide + match clause.",
                "required": ["decide", "match"],
                "not": { "required": ["wasm"] }
            },
            {
                "description": "Wasm rule: the module decides. `decide`/`match`/`deny_message` are forbidden — the decision (and any deny reason) is the module's return value.",
                "required": ["wasm"],
                "allOf": [
                    { "not": { "required": ["decide"] } },
                    { "not": { "required": ["match"] } },
                    { "not": { "required": ["deny_message"] } }
                ]
            }
        ],
        "properties": {
            "id": {
                "type": "string",
                "description": "Stable identifier (12 random bytes as lowercase hex, generated by `secreq` when the rule is created). Never re-mint for an existing rule — surfaces in the audit log."
            },
            "name": {
                "type": "string",
                "description": "Human label shown in the UI and the audit pill."
            },
            "enabled": {
                "type": "boolean",
                "description": "`false` ⇒ rule is in the file but the evaluator skips it. Used for `pause this rule without losing the configuration`."
            },
            "decide": {
                "type": "string",
                "enum": ["approve", "deny"],
                "description": "Direction a declarative rule fires when it matches. Among matching rules, any deny wins; otherwise the most-specific approve wins (a wasm rule that returns a decision counts as maximally specific). Forbidden on wasm rules."
            },
            "match": { "$ref": "#/definitions/RuleMatch" },
            "wasm": { "$ref": "#/definitions/WasmRule" },
            "trained_secrets": {
                "type": "array",
                "items": { "type": "string" },
                "uniqueItems": true,
                "description": "Snapshot of env-var names the rule was created against. Rule will NOT fire if the ask requests anything outside this set — the trained-secrets guard, applied to declarative and wasm rules alike (a wasm module is never even run for an out-of-snapshot ask). Empty array disables the guard (legit for hand-edited rules)."
            },
            "deny_message": {
                "type": "string",
                "description": "Message printed to stderr on auto-deny and shown in the consent window's toast. Only meaningful when `decide == deny`; forbidden on wasm rules (the module returns its own reason)."
            },
            "created_at_unix": {
                "type": "integer",
                "minimum": 0,
                "description": "Seconds since the Unix epoch at creation. Informational only."
            }
        },
        "additionalProperties": false
    })
}

fn wasm_rule_schema() -> Value {
    json!({
        "type": "object",
        "description": "Reference to a compiled wasm rule module, evaluated in the secreq sandbox (no WASI, fuel-metered, memory-capped). The module exports `decide(ctx)` returning approve, pass (rule does not match), or deny with a reason. A runtime error makes the rule not match — the ask falls through to the interactive prompt, never to an auto-approve.",
        "required": ["path", "sha256"],
        "properties": {
            "path": {
                "type": "string",
                "description": "Path to the compiled `.wasm` module. Relative paths resolve against the directory containing `auto-rules.json5`; the canonical home is `rules/<id>.wasm` under the secreq root."
            },
            "sha256": {
                "type": "string",
                "pattern": "^[0-9a-fA-F]{64}$",
                "description": "Hex SHA-256 of the module bytes, recorded at registration and verified on every load. A mismatch refuses this rule (it can never fire) with a loud daemon-log error; other rules keep working."
            }
        },
        "additionalProperties": false
    })
}

fn rule_match_schema() -> Value {
    json!({
        "type": "object",
        "description": "The match clause. All present fields must match (logical AND). `wrap` is required and exact; the rest are patterns: glob if they contain `*`, `?`, or `[`, otherwise literal. Literal `argv`/`cwd` match as prefix; literal `ancestor` matches as substring (friendlier for `.app` bundle names).",
        "required": ["wrap"],
        "properties": {
            "wrap": {
                "type": "string",
                "description": "Wrap name (exact match)."
            },
            "argv": {
                "type": "string",
                "description": "Pattern against the joined argv of the wrapped command (`secreq` reconstructs this as `command.join(\" \")`)."
            },
            "ancestor": {
                "type": "string",
                "description": "Pattern matched against each caller in the process tree. For each caller, the pattern is checked against BOTH its short process name (sysinfo `name()`, typically the executable basename like `zsh` or `Cursor`) AND its full joined command line (sysinfo `cmd()` joined with spaces, e.g. `/Applications/Cursor.app/Contents/MacOS/Cursor --psn_0_12345`). Match if ANY caller's name or command satisfies the pattern. Substring match for literals, full-string glob for wildcards. The `exe` path is NOT currently part of the match input."
            },
            "cwd": {
                "type": "string",
                "description": "Pattern against the requesting process's current working directory."
            }
        },
        "additionalProperties": false
    })
}

fn wrap_schema() -> Value {
    json!({
        "type": "object",
        "description": "One per-binary wrap. `env` is optional: a wrap with no env entries is *gate-only* — consent is required before the binary runs, but nothing is injected (used to gate tools like `op` that have no secret to pass). Everything else is metadata.",
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
                "description": "Environment variables to inject. Each value is a `secret://provider/locator` reference; resolution happens at invocation time. Omit (or leave empty) for a gate-only wrap.",
                "additionalProperties": {
                    "type": "string",
                    "pattern": "^secret://[^/]+/.+$",
                    "description": "A `secret://provider/locator` reference."
                }
            }
        },
        "additionalProperties": false
    })
}

fn ssh_identity_schema() -> Value {
    json!({
        "type": "object",
        "description": "One SSH identity served by the agent. `public_key` is the inline OpenSSH public key (not secret); `private_key` is a `secret://provider/locator` reference resolved only at SIGN time.",
        "required": ["public_key", "private_key"],
        "properties": {
            "$reason": {
                "type": "string",
                "description": "Rationale shown in the consent prompt when this identity is used to sign."
            },
            "public_key": {
                "type": "string",
                "description": "Inline OpenSSH public key (`ssh-ed25519 AAAA… comment`). Answered to REQUEST_IDENTITIES without a resolve."
            },
            "private_key": {
                "type": "string",
                "pattern": "^secret://[^/]+/.+$",
                "description": "A `secret://provider/locator` reference to the private key, resolved only at SIGN time."
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
