//! Ensures `docs/wraps.schema.json` is kept in sync with the Rust source
//! of truth in `src/schema.rs`. If this test fails, regenerate the file:
//!
//! ```sh
//! cargo run --example gen-schema > docs/wraps.schema.json
//! ```

#[test]
fn committed_schema_matches_source_of_truth() {
    let generated = secreq::schema::wraps_schema();
    let expected = serde_json::to_string_pretty(&generated).expect("schema must serialize as JSON");
    let on_disk = std::fs::read_to_string("docs/wraps.schema.json")
        .expect("docs/wraps.schema.json must exist; run `cargo run --example gen-schema > docs/wraps.schema.json`");
    assert_eq!(
        expected.trim_end(),
        on_disk.trim_end(),
        "docs/wraps.schema.json is stale.\nRegenerate it:\n  cargo run --example gen-schema > docs/wraps.schema.json"
    );
}

#[test]
fn schema_is_valid_json() {
    let value = secreq::schema::wraps_schema();
    let text = serde_json::to_string(&value).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(value, parsed);
}
