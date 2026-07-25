//! Guards the maintained CHANGELOG against version drift. Every released
//! version must have a matching `## [x.y.z]` section — the release workflow
//! (`.github/workflows/release.yml`) extracts the notes for the tagged
//! version straight from this file, so a missing section ships an empty
//! release body.
//!
//! Cut releases with cargo-release (`release.toml`), which rolls the
//! `## [Unreleased]` section into a dated one; see `dev-docs/RELEASING.md`.

/// The crate's current version must have a CHANGELOG section. Bumping
/// `Cargo.toml` without recording the release notes fails here.
#[test]
fn changelog_has_a_section_for_the_current_version() {
    let version = env!("CARGO_PKG_VERSION");
    let changelog = std::fs::read_to_string("../../CHANGELOG.md")
        .expect("CHANGELOG.md must exist at the repo root");
    let header = format!("## [{version}]");
    assert!(
        changelog.contains(&header),
        "CHANGELOG.md has no `{header}` section.\n\
         Add the release notes for {version} (cargo-release does this when \
         you cut a release; see dev-docs/RELEASING.md)."
    );
}

/// A standing `## [Unreleased]` section must remain on top so day-to-day
/// changes have a home and cargo-release has an anchor to roll forward.
#[test]
fn changelog_keeps_an_unreleased_section() {
    let changelog = std::fs::read_to_string("../../CHANGELOG.md")
        .expect("CHANGELOG.md must exist at the repo root");
    assert!(
        changelog.contains("## [Unreleased]"),
        "CHANGELOG.md must keep a `## [Unreleased]` section for in-flight changes."
    );
}
