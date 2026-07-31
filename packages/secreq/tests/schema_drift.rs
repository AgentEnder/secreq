//! What the two published JSON Schemas promise, checked against what `secreq`
//! actually reads and writes.
//!
//! The freshness half — committed file matches the generator — is the cheap
//! half, and on its own it never caught anything: `schema.rs` used to build
//! both documents as a hand-written `json!` tree, so the file and the generator
//! could agree with each other while both contradicted the parser, and three
//! descriptions did exactly that for a month or more.
//!
//! The generator now derives from the types (`schemars` over `rules.rs`,
//! `wraps.rs`, `manifest.rs`), which closes the shape half by construction.
//! The rest of this file closes what construction cannot reach:
//!
//! - **`auto-rules.json5`** — every rule shape `secreq` writes is validated
//!   against the committed schema, and a rule the loader refuses is checked to
//!   be one the schema refuses too. A published contract that rejects a file
//!   secreq itself wrote is the failure this catches; `"argv": null` was that
//!   failure, and the schema called it a type error.
//! - **`config.toml`** — the config is read with serde derives, but its JSON
//!   names are still `serde(rename)` / `schemars(rename)` attributes sitting
//!   side by side, and nothing makes the two agree. One config using every key
//!   the schema declares is fed to the parser, and one key the schema does not
//!   declare is fed to both.
//!
//! Regenerate after any change to those types:
//!
//! ```sh
//! cargo run --example gen-schema             > docs/wraps.schema.json
//! cargo run --example gen-auto-rules-schema  > docs/auto-rules.schema.json
//! ```

use serde_json::{json, Value};

use secreq::rules::{Pattern, Rule, RuleBody, RuleMatch, StaticDecision, WasmRule};
use secreq::wraps::WrapsConfig;

const WRAPS_PATH: &str = "../../docs/wraps.schema.json";
const AUTO_RULES_PATH: &str = "../../docs/auto-rules.schema.json";

// ── Freshness ─────────────────────────────────────────────────────────────

#[test]
fn committed_schema_matches_source_of_truth() {
    let generated = secreq::schema::wraps_schema();
    let expected = serde_json::to_string_pretty(&generated).expect("schema must serialize as JSON");
    let on_disk = std::fs::read_to_string(WRAPS_PATH)
        .expect("docs/wraps.schema.json must exist; run `cargo run --example gen-schema > docs/wraps.schema.json`");
    assert_eq!(
        expected.trim_end(),
        on_disk.trim_end(),
        "docs/wraps.schema.json is stale.\nRegenerate it:\n  cargo run --example gen-schema > docs/wraps.schema.json"
    );
}

#[test]
fn committed_auto_rules_schema_matches_source_of_truth() {
    let generated = secreq::schema::auto_rules_schema();
    let expected = serde_json::to_string_pretty(&generated).expect("schema must serialize as JSON");
    let on_disk = std::fs::read_to_string(AUTO_RULES_PATH)
        .expect("docs/auto-rules.schema.json must exist; run `cargo run --example gen-auto-rules-schema > docs/auto-rules.schema.json`");
    assert_eq!(
        expected.trim_end(),
        on_disk.trim_end(),
        "docs/auto-rules.schema.json is stale.\nRegenerate it:\n  cargo run --example gen-auto-rules-schema > docs/auto-rules.schema.json"
    );
}

// ── The committed schema, applied to real values ──────────────────────────

/// Compile a committed schema file so values can be validated against it.
///
/// Reads from disk rather than calling the generator: what these tests have to
/// hold is the document editors actually fetch.
fn compile(path: &str, id: &str) -> (boon::Schemas, boon::SchemaIndex) {
    let text = std::fs::read_to_string(path).expect("committed schema must exist");
    let document: Value = serde_json::from_str(&text).expect("committed schema must be JSON");
    let mut schemas = boon::Schemas::new();
    let mut compiler = boon::Compiler::new();
    compiler
        .add_resource(id, document)
        .expect("committed schema must be a valid JSON Schema");
    let index = compiler
        .compile(id, &mut schemas)
        .expect("committed schema must compile");
    (schemas, index)
}

fn auto_rules_schema() -> (boon::Schemas, boon::SchemaIndex) {
    compile(
        AUTO_RULES_PATH,
        "https://secreq.dev/schema/auto-rules.schema.json",
    )
}

fn wraps_schema() -> (boon::Schemas, boon::SchemaIndex) {
    compile(WRAPS_PATH, "https://secreq.dev/schema/wraps.schema.json")
}

fn declarative_rule(r#match: RuleMatch, decide: StaticDecision) -> Rule {
    Rule {
        id: "0a1b2c3d4e5f".to_owned(),
        name: "a rule".to_owned(),
        enabled: true,
        trained_secrets: ["GITHUB_TOKEN".to_owned()].into_iter().collect(),
        created_at_unix: 1_700_000_000,
        body: RuleBody::Declarative { r#match, decide },
    }
}

fn wrap_only(wrap: &str) -> RuleMatch {
    RuleMatch {
        wrap: wrap.to_owned(),
        argv: None,
        ancestor: None,
        cwd: None,
    }
}

/// Every rule shape `secreq` writes has to satisfy the schema it publishes.
///
/// The unconstrained clause is the load-bearing case: `RuleMatch`'s options
/// carry `default` but no `skip_serializing_if`, so a rule matching a wrap and
/// nothing else is written as `"argv": null, "ancestor": null, "cwd": null` —
/// which the published schema typed as `string`, and would have rejected.
#[test]
fn every_rule_secreq_writes_validates_against_the_published_schema() {
    let cases: Vec<(&str, Rule)> = vec![
        (
            "every clause set, deny with a message",
            declarative_rule(
                RuleMatch {
                    wrap: "gh".to_owned(),
                    argv: Some(Pattern::parse("gh repo delete *")),
                    ancestor: Some(Pattern::parse("Cursor.app")),
                    cwd: Some(Pattern::parse("/Users/me/oss")),
                },
                StaticDecision::Deny {
                    message: Some("Use the UI instead.".to_owned()),
                },
            ),
        ),
        (
            "no clause beyond the wrap, approve",
            declarative_rule(wrap_only("gh"), StaticDecision::Approve),
        ),
        (
            "deny with no message",
            declarative_rule(wrap_only("gh"), StaticDecision::Deny { message: None }),
        ),
        (
            "wasm",
            Rule {
                id: "0a1b2c3d4e5f".to_owned(),
                name: "npm publish guard".to_owned(),
                enabled: false,
                trained_secrets: ["NPM_TOKEN".to_owned()].into_iter().collect(),
                created_at_unix: 0,
                body: RuleBody::Wasm(WasmRule {
                    path: "rules/0a1b2c3d4e5f.wasm".to_owned(),
                    sha256: "b".repeat(64),
                }),
            },
        ),
    ];

    let (schemas, index) = auto_rules_schema();
    for (label, rule) in cases {
        let file = json!({ "rules": [rule] });
        if let Err(err) = schemas.validate(&file, index) {
            panic!("docs/auto-rules.schema.json rejects a rule secreq writes ({label}):\n{err}");
        }
    }
}

/// A rule the loader refuses must not be one the schema calls valid.
///
/// The declarative-XOR-wasm `oneOf` is the only part of that schema no field
/// implies, so it is the only part that can rot without the derive noticing.
#[test]
fn the_schema_refuses_the_rule_shapes_the_loader_refuses() {
    let cases = [
        (
            "both a match clause and a wasm module",
            json!({
                "id": "01", "name": "r", "enabled": true, "decide": "approve",
                "match": { "wrap": "gh" },
                "wasm": { "path": "r.wasm", "sha256": "c".repeat(64) }
            }),
        ),
        (
            "neither",
            json!({ "id": "01", "name": "r", "enabled": true }),
        ),
        (
            "a wasm rule that also sets decide",
            json!({
                "id": "01", "name": "r", "enabled": true, "decide": "deny",
                "wasm": { "path": "r.wasm", "sha256": "c".repeat(64) }
            }),
        ),
        (
            "a wasm rule that also sets deny_message",
            json!({
                "id": "01", "name": "r", "enabled": true, "deny_message": "no",
                "wasm": { "path": "r.wasm", "sha256": "c".repeat(64) }
            }),
        ),
        (
            "a match clause with no decide",
            json!({
                "id": "01", "name": "r", "enabled": true,
                "match": { "wrap": "gh" }
            }),
        ),
    ];

    let (schemas, index) = auto_rules_schema();
    for (label, rule) in cases {
        let file = json!({ "rules": [rule.clone()] });
        assert!(
            schemas.validate(&file, index).is_err(),
            "docs/auto-rules.schema.json accepts a rule the loader refuses ({label}): {file}"
        );
        assert!(
            serde_json::from_value::<Rule>(rule).is_err(),
            "the loader was expected to refuse this shape ({label})"
        );
    }
}

/// A config exercising every key `docs/wraps.schema.json` declares.
///
/// Deliberately maximal, legacy spellings included: `read` for `retrieve`,
/// `write` for `store`, `retrieveBatch` for `retrieve_batch`, and `optional`
/// for `required: false`.
const MAXIMAL_WRAPS_CONFIG: &str = r#"
editor = "code"
shim_dir = "~/.secreq/shims"
wait_indicator = false

[wraps.gh]
reason = "GitHub API access"
env_secrets = ["GITHUB_TOKEN"]
env.INLINE_TOKEN = "secret://op/Personal/GitHub/token"
env.GH_TOKEN = "secret://declared_with_ttl"
env.GH_ALT = "secret://declared_without_ttl"

# A gate-only wrap: consent required, nothing injected.
[wraps.op]

# Both spellings of a declaration: with an explicit `ttl` and without.
[secrets.GITHUB_TOKEN]
ref = "secret://op/Personal/GitHub/token"

[secrets.declared_with_ttl]
ref = "secret://op/Personal/GitHub/other"
ttl = "15m"

[secrets.declared_without_ttl]
ref = "secret://op/Personal/GitHub/third"

[ssh.github]
reason = "git pushes"
public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1 me@mac"
private_key = "secret://op/Private/gh/private key"

[providers.modern]
retrieve = ["printf", "%s", "{locator}"]
retrieve_batch = { command = ["op", "run", "--", "printenv"], env_value = "op://{locator}" }

[providers.modern.store]
command = ["sh", "-c", "cat"]
value = "stdin"
locator = "{service}"
fields.service = { required = true }
fields.tag = { optional = true, default = "v1" }

[providers.legacy]
read = ["printf", "%s", "{locator}"]
retrieveBatch = { command = ["op", "run", "--", "printenv"], env_value = "op://{locator}" }

[providers.legacy.write]
command = ["sh", "-c", "echo {value}"]
value = "{value}"
locator = "{name}"
fields.name = { required = true }

# TOML has no null, so "an explicit null means absent" is not expressible —
# and no longer needs to be. Omitting the key is the only spelling.
[providers.omitted_means_absent]
retrieve = ["true"]
"#;

/// The published schema and the hand-written parser must accept the same keys.
///
/// `manifest.rs` and `wraps.rs` walk a `serde_json::Value` rather than deriving
/// `Deserialize`, so the JSON name of every field whose Rust name differs is a
/// `schemars(rename)` beside it — a mapping the compiler does not check. This
/// is what checks it.
#[test]
fn schema_covers_every_key_the_parser_accepts() {
    let (schemas, index) = wraps_schema();
    // toml-lang/toml#1038: there is no TOML-native schema language, so a TOML
    // document is validated by loading it into the JSON data model and handing
    // that to an ordinary JSON Schema validator — the same thing Taplo does for
    // the `#:schema` directive an editor follows.
    let document: Value =
        toml::from_str(MAXIMAL_WRAPS_CONFIG).expect("the fixture must be valid TOML");

    if let Err(err) = schemas.validate(&document, index) {
        panic!("docs/wraps.schema.json rejects a config secreq accepts:\n{err}");
    }
    WrapsConfig::parse(MAXIMAL_WRAPS_CONFIG, "maximal")
        .expect("secreq must accept a config its own schema calls valid");
}

/// `additionalProperties: false` has to mean something. A key neither side
/// knows must be refused by both, or the schema documents a parser more
/// permissive than it looks.
#[test]
fn schema_and_parser_refuse_the_same_unknown_key() {
    let (schemas, index) = wraps_schema();
    let document = json!({ "gh": { "env": {}, "$bogus": "nope" } });

    assert!(
        schemas.validate(&document, index).is_err(),
        "docs/wraps.schema.json accepts a wrap key the parser refuses"
    );
    assert!(
        WrapsConfig::parse(&document.to_string(), "unknown-key").is_err(),
        "the parser was expected to refuse an unknown wrap key"
    );
}

#[test]
fn schema_and_parser_refuse_invalid_env_secrets_lists() {
    let (schemas, index) = wraps_schema();
    let cases = [
        (
            "a name that cannot be an env var",
            json!({
                "secrets": {
                    "github token": { "ref": "secret://op/Personal/GitHub/token" }
                },
                "wraps": {
                    "gh": { "env_secrets": ["github token"] }
                }
            }),
            r#"
            [secrets."github token"]
            ref = "secret://op/Personal/GitHub/token"

            [wraps.gh]
            env_secrets = ["github token"]
            "#,
        ),
        (
            "a duplicate declaration name",
            json!({
                "secrets": {
                    "GITHUB_TOKEN": { "ref": "secret://op/Personal/GitHub/token" }
                },
                "wraps": {
                    "gh": { "env_secrets": ["GITHUB_TOKEN", "GITHUB_TOKEN"] }
                }
            }),
            r#"
            [secrets.GITHUB_TOKEN]
            ref = "secret://op/Personal/GitHub/token"

            [wraps.gh]
            env_secrets = ["GITHUB_TOKEN", "GITHUB_TOKEN"]
            "#,
        ),
    ];

    for (label, document, config) in cases {
        assert!(
            schemas.validate(&document, index).is_err(),
            "docs/wraps.schema.json accepts {label}"
        );
        assert!(
            WrapsConfig::parse(config, label).is_err(),
            "the parser was expected to refuse {label}"
        );
    }
}
