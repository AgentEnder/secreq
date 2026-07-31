//! Guards that the `secreq-rule` SDK (`packages/secreq-rule/`) stays
//! publishable to npm. `cargo test` has no node/npm toolchain, so this
//! test can't run `npm pack` — instead it checks the manifest invariants
//! that make `npm install secreq-rule` yield a working
//! `secreq-rule-build`:
//!
//!   * the package is not `private` (npm refuses to publish those);
//!   * the `files` allowlist ships every source file the build wrapper
//!     needs at consume time — `bin/build.js`, the root `index.ts`, and
//!     the whole `assembly/` tree it compiles through `asc`.
//!
//! If this fails after adding a file the wrapper imports, extend the
//! `files` allowlist in `packages/secreq-rule/package.json` to cover it.

use std::path::Path;

// The SDK is a sibling workspace package; `cargo test` runs with the crate
// dir (`packages/secreq`) as CWD, so reach up one level to `packages/`.
const PKG_DIR: &str = "../secreq-rule";

fn manifest() -> serde_json::Value {
    let text = std::fs::read_to_string(format!("{PKG_DIR}/package.json"))
        .expect("packages/secreq-rule/package.json must exist");
    serde_json::from_str(&text).expect("package.json must be valid JSON")
}

/// The `files` allowlist, each entry normalized to a slash-free path
/// (npm treats a trailing-slash directory entry as the whole subtree).
fn files_allowlist(pkg: &serde_json::Value) -> Vec<String> {
    pkg["files"]
        .as_array()
        .expect("package.json must declare a `files` allowlist for publishing")
        .iter()
        .map(|v| {
            v.as_str()
                .expect("every `files` entry must be a string")
                .trim_end_matches('/')
                .to_string()
        })
        .collect()
}

/// True when `rel` (a repo-package-relative path) is shipped by the
/// allowlist: either listed verbatim, or under a listed directory.
fn covered(allowlist: &[String], rel: &str) -> bool {
    allowlist
        .iter()
        .any(|entry| entry == rel || rel.starts_with(&format!("{entry}/")))
}

#[test]
fn package_is_not_private() {
    let pkg = manifest();
    assert_ne!(
        pkg.get("private"),
        Some(&serde_json::Value::Bool(true)),
        "packages/secreq-rule/package.json is `private: true` — npm will refuse to \
         publish it. Drop the field to make the SDK publishable."
    );
}

#[test]
fn files_allowlist_ships_the_build_toolchain() {
    let pkg = manifest();
    let allowlist = files_allowlist(&pkg);

    // Everything `secreq-rule-build` reaches for at consume time: the bin
    // itself, the package-root re-export (bare `import "secreq-rule"`
    // resolves here), and every `.ts` under assembly/ that the generated
    // ABI entry compiles through.
    let mut required = vec![
        "bin/build.js".to_string(),
        "index.ts".to_string(),
        "testing/index.js".to_string(),
        "testing/assembly.ts".to_string(),
    ];
    for entry in std::fs::read_dir(format!("{PKG_DIR}/assembly"))
        .expect("assembly/ must exist")
        .flatten()
    {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(".ts") || name.ends_with(".json") {
            required.push(format!("assembly/{name}"));
        }
    }

    for rel in &required {
        assert!(
            Path::new(PKG_DIR).join(rel).exists(),
            "expected {PKG_DIR}/{rel} to exist"
        );
        assert!(
            covered(&allowlist, rel),
            "{rel} is needed by secreq-rule-build but is not covered by the \
             `files` allowlist {allowlist:?} in packages/secreq-rule/package.json — \
             `npm install secreq-rule` would ship an incomplete package"
        );
    }
}

#[test]
fn package_exports_both_testing_layers() {
    let pkg = manifest();
    assert_eq!(pkg["exports"]["./testing"], "./testing/index.js");
    assert_eq!(
        pkg["exports"]["./testing/assembly"],
        "./testing/assembly.ts"
    );
}

#[test]
fn declared_bin_exists_and_ships() {
    let pkg = manifest();
    let bin = pkg["bin"]["secreq-rule-build"]
        .as_str()
        .expect("package.json must declare the secreq-rule-build bin");
    assert!(
        Path::new(PKG_DIR).join(bin).exists(),
        "bin points at {bin}, which does not exist"
    );
    assert!(
        covered(&files_allowlist(&pkg), bin),
        "the secreq-rule-build bin ({bin}) is not covered by the `files` allowlist"
    );
}
