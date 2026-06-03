//! Emit the JSON Schema for `auto-rules.json5` to stdout.
//!
//! Regenerate the committed file with:
//!
//! ```sh
//! cargo run --example gen-auto-rules-schema > docs/auto-rules.schema.json
//! ```
//!
//! A drift test ensures the committed file matches what this example
//! produces. See `dev-docs/plans/2026-06-02-auto-rules.md` for the
//! design and `src/rules.rs` for the data model.

fn main() {
    let schema = secreq::schema::auto_rules_schema();
    let pretty = serde_json::to_string_pretty(&schema)
        .expect("serializing serde_json::Value should never fail");
    println!("{pretty}");
}
