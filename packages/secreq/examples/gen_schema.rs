//! Emit the JSON Schema for `config.toml` to stdout.
//!
//! Regenerate the committed file with:
//!
//! ```sh
//! cargo run --example gen-schema > docs/wraps.schema.json
//! ```
//!
//! The schema is derived from the types that read `config.toml` — `Wrap` and
//! `SshIdentity` in `src/wraps.rs`, `Provider` and friends in
//! `src/manifest.rs` — so a field's doc comment is what a reader of the
//! published schema sees. `tests/schema_drift.rs` fails when the committed
//! file and this output disagree, and when either disagrees with the parser.
//!
//! Needs the `schema` feature, which the crate's self dev-dependency turns on
//! for any example or test build. Nothing else does, so a released binary
//! carries no `schemars`.

fn main() {
    let schema = secreq::schema::wraps_schema();
    let pretty = serde_json::to_string_pretty(&schema)
        .expect("serializing serde_json::Value should never fail");
    println!("{pretty}");
}
