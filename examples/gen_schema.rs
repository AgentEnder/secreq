//! Emit the JSON Schema for `wraps.json5` to stdout.
//!
//! Regenerate the committed file with:
//!
//! ```sh
//! cargo run --example gen-schema > docs/wraps.schema.json
//! ```
//!
//! A drift test ensures the committed file matches what this example produces.

fn main() {
    let schema = secreq::schema::wraps_schema();
    let pretty = serde_json::to_string_pretty(&schema)
        .expect("serializing serde_json::Value should never fail");
    println!("{pretty}");
}
