//! Guards the public distribution channels against drift from the release
//! build matrix and the crate version. These are hand-maintained text
//! artifacts that a reviewer can't easily eyeball for mutual consistency:
//!
//!   - `.github/workflows/release.yml` cross-compiles four target triples.
//!   - `dist/install.sh` maps `uname` output onto those same triples.
//!   - `dist/homebrew/secreq.rb` links the release tarball for each triple.
//!   - `Cargo.toml` carries the crates.io metadata, and `release-plz.toml`
//!     plus `release.yml` decide which of them publishes.
//!
//! When they fall out of lockstep the failure surfaces at a stranger's install
//! time — a 404 tarball, an "unsupported arch", or a `cargo publish`
//! rejection — long after the release shipped. These tests fail the build
//! instead. See brain: areas/secreq/releasing.md and docs/install.md.

use std::fs;

fn read(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// The release build matrix is the single source of truth for which platforms
/// secreq ships prebuilt binaries for; every other channel must cover exactly
/// these four target triples.
fn release_targets() -> Vec<String> {
    let yml = read("../../.github/workflows/release.yml");
    let mut targets: Vec<String> = yml
        .lines()
        .filter_map(|l| l.trim().strip_prefix("- target:"))
        .map(|t| t.trim().to_owned())
        .collect();
    targets.sort();
    targets.dedup();
    assert_eq!(
        targets.len(),
        4,
        "expected 4 release targets, got {targets:?}"
    );
    targets
}

/// `arch-rest` split of a target triple:
/// `x86_64-unknown-linux-gnu` -> ("x86_64", "unknown-linux-gnu").
fn split_target(triple: &str) -> (&str, &str) {
    match triple.split_once('-') {
        Some(parts) => parts,
        None => panic!("target triple {triple:?} must have an arch- prefix"),
    }
}

/// The installer builds each triple from an arch token and an OS token rather
/// than hard-coding the four full strings, so assert both halves of every
/// release target appear in the script. A target the build matrix gains but
/// the installer's `case` arms don't handle leaves those users with an
/// "unsupported" error against a binary that exists.
#[test]
fn installer_covers_every_release_target() {
    let sh = read("../../dist/install.sh");
    for triple in release_targets() {
        let (arch, rest) = split_target(&triple);
        assert!(sh.contains(arch), "install.sh omits arch token {arch:?}");
        assert!(sh.contains(rest), "install.sh omits OS token {rest:?}");
    }
}

/// The Homebrew formula links a concrete tarball per target; every release
/// target must have its download URL, or `brew install` 404s on that arch.
#[test]
fn homebrew_formula_links_every_release_target() {
    let version = env!("CARGO_PKG_VERSION");
    let formula = read("../../dist/homebrew/secreq.rb");
    for triple in release_targets() {
        let asset = format!("secreq-{version}-{triple}.tar.gz");
        assert!(
            formula.contains(&asset),
            "dist/homebrew/secreq.rb is missing the URL for {asset}; regenerate \
             with dist/homebrew/gen-formula.sh --version {version}"
        );
    }
}

/// A version bump that forgets the formula would point Homebrew at tarballs
/// from the previous release. The committed formula must name the crate's
/// current version.
#[test]
fn homebrew_formula_version_matches_crate() {
    let version = env!("CARGO_PKG_VERSION");
    let formula = read("../../dist/homebrew/secreq.rb");
    let needle = format!("version \"{version}\"");
    assert!(
        formula.contains(&needle),
        "dist/homebrew/secreq.rb must declare {needle:?}; regenerate with \
         dist/homebrew/gen-formula.sh --version {version}"
    );
}

/// Every `sha256 "…"` must be a 64-char hex digest (the committed template
/// uses an all-zero sentinel that the release workflow overwrites with the
/// real digests from the signed SHA256SUMS manifest). A malformed digest — a
/// truncated paste, a leftover placeholder word — makes `brew install` reject
/// the download.
#[test]
fn homebrew_formula_shas_are_wellformed() {
    let formula = read("../../dist/homebrew/secreq.rb");
    let mut seen = 0;
    for line in formula.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("sha256 \"") {
            let digest = rest.strip_suffix('"').unwrap_or(rest);
            assert_eq!(digest.len(), 64, "sha256 {digest:?} is not 64 chars");
            let all_hex = digest.chars().all(|c| c.is_ascii_hexdigit());
            assert!(all_hex, "sha256 digest is not hex: {digest:?}");
            seen += 1;
        }
    }
    assert_eq!(
        seen, 4,
        "expected 4 sha256 digests in the formula, got {seen}"
    );
}

/// Extract the quoted-string array assigned to `key` in Cargo.toml (the
/// values live on a single line).
fn cargo_string_array(key: &str) -> Vec<String> {
    let cargo = read("Cargo.toml");
    let prefix = format!("{key} = [");
    let line = cargo
        .lines()
        .find(|l| l.trim_start().starts_with(prefix.as_str()))
        .unwrap_or_else(|| panic!("Cargo.toml has no `{key} = [...]` array"));
    // Odd-indexed `split('"')` fields are the contents between quote pairs.
    let quoted = line.split('"').skip(1).step_by(2);
    quoted.map(str::to_owned).collect()
}

/// crates.io rejects a publish whose manifest breaks its metadata rules, and
/// the rejection only shows up when the maintainer runs the release. Assert
/// the constraints locally: keywords capped at 5 and 20 chars each, categories
/// present, and the descriptive fields `cargo install` users rely on set.
#[test]
fn crate_metadata_is_crates_io_publishable() {
    let cargo = read("Cargo.toml");

    let keywords = cargo_string_array("keywords");
    assert!(
        (1..=5).contains(&keywords.len()),
        "crates.io allows at most 5 keywords, found {}: {keywords:?}",
        keywords.len()
    );
    for kw in &keywords {
        assert!(
            !kw.is_empty() && kw.len() <= 20,
            "bad keyword length: {kw:?}"
        );
        let starts_alnum = kw.starts_with(|c: char| c.is_ascii_alphanumeric());
        assert!(starts_alnum, "keyword must start alphanumeric: {kw:?}");
    }

    let categories = cargo_string_array("categories");
    assert!(
        !categories.is_empty(),
        "declare at least one crates.io category"
    );

    for field in ["readme", "repository", "homepage", "license", "description"] {
        let decl = format!("{field} = ");
        let present = cargo.lines().any(|l| l.trim_start().starts_with(&decl));
        assert!(present, "Cargo.toml [package] is missing `{field}`");
    }
}

/// `cargo install secreq` only works if a release actually pushes the crate,
/// and exactly one thing must do it.
///
/// release-plz would publish from the runner that opens the release PR, using
/// a stored registry token. It is turned off so the crate ships from
/// `release.yml`'s `publish-crate` job instead, which mints a short-lived
/// crates.io token from GitHub's OIDC identity and runs only after the signed
/// binaries are out.
///
/// Both halves are asserted because either one alone fails quietly. Delete the
/// workflow job and nothing publishes; flip release-plz back on and the crate
/// ships from a commit CI never verified, before the tag exists.
#[test]
fn exactly_one_thing_publishes_to_crates_io() {
    let plz = read("../../release-plz.toml");
    assert!(
        plz.lines().any(|l| l.trim() == "publish = false"),
        "release-plz.toml must set `publish = false`; the crate is published \
         by release.yml's publish-crate job, over OIDC"
    );

    let yml = read("../../.github/workflows/release.yml");
    assert!(
        yml.contains("publish-crate:"),
        ".github/workflows/release.yml must keep the `publish-crate` job, or \
         nothing publishes the crate at all"
    );
    assert!(
        yml.contains("cargo publish"),
        "the publish-crate job must actually run `cargo publish`"
    );
    assert!(
        yml.contains("crates-io-auth-action"),
        "publish-crate must mint its token over OIDC rather than read a \
         stored CARGO_REGISTRY_TOKEN"
    );
}
