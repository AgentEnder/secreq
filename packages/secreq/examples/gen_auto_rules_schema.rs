//! Emit the JSON Schema for `auto-rules.json5` to stdout.
//!
//! Regenerate the committed file with:
//!
//! ```sh
//! cargo run --example gen-auto-rules-schema > docs/auto-rules.schema.json
//! ```
//!
//! The schema is derived from `RuleWire` in `src/rules.rs` — the flat object a
//! user's file actually holds — so a field's doc comment is what a reader of
//! the published schema sees. `tests/schema_drift.rs` fails when the committed
//! file and this output disagree, and when either disagrees with the loader.
//!
//! Needs the `schema` feature, which the crate's self dev-dependency turns on
//! for any example or test build. Nothing else does, so a released binary
//! carries no `schemars`.
//!
//! See `brain: areas/secreq/design/2026-06-02-auto-rules.md` for the design.

fn main() {
    let schema = secreq::schema::auto_rules_schema();
    let pretty = serde_json::to_string_pretty(&schema)
        .expect("serializing serde_json::Value should never fail");
    println!("{pretty}");
}
