//! Guards the internal-install scripts (`scripts/install.sh`,
//! `scripts/package-release.sh`).
//!
//! These aren't compiled by cargo, so nothing else would catch a syntax error
//! or a silently-dropped step. We shell out to `bash -n` to parse them, and
//! assert on a few load-bearing invariants so a refactor can't quietly remove
//! the build, the init handoff, or the tarball layout the two scripts share.

use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    let path = repo_root().join(rel);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("could not read {}: {e}", path.display()))
}

/// `bash -n` parses a script without executing it. Absent bash (shouldn't
/// happen in CI or on any dev box) we skip rather than fail.
fn bash_parses(rel: &str) {
    let path = repo_root().join(rel);
    assert!(path.is_file(), "{} must exist", path.display());
    match Command::new("bash").arg("-n").arg(&path).output() {
        Ok(out) => assert!(
            out.status.success(),
            "`bash -n {}` reported a syntax error:\n{}",
            path.display(),
            String::from_utf8_lossy(&out.stderr)
        ),
        Err(e) => eprintln!("skipping bash syntax check for {rel}: bash unavailable ({e})"),
    }
}

fn starts_with_bash_shebang(rel: &str) {
    let body = read(rel);
    let first = body.lines().next().unwrap_or_default();
    assert!(
        first.starts_with("#!") && first.contains("bash"),
        "{rel} must start with a bash shebang, got: {first:?}"
    );
}

#[test]
fn scripts_exist_and_parse() {
    for rel in ["scripts/install.sh", "scripts/package-release.sh"] {
        assert!(
            repo_root().join(rel).is_file(),
            "{rel} is missing — the internal-install path documented in \
             docs/getting-started.md depends on it"
        );
        starts_with_bash_shebang(rel);
        bash_parses(rel);
    }
}

#[test]
fn install_script_builds_installs_and_hands_off_to_init() {
    let body = read("scripts/install.sh");
    // Source mode compiles a release binary…
    assert!(
        body.contains("cargo build --release"),
        "install.sh must build a release binary in source mode"
    );
    // …and finishes by running first-time setup (the PATH-shim wiring).
    assert!(
        body.contains("init"),
        "install.sh must hand off to `secreq init` for shim/PATH setup"
    );
    // `secreq init` needs a TTY; the script must gate on one so a piped run
    // doesn't wedge on an interactive prompt.
    assert!(
        body.contains("-t 0"),
        "install.sh must gate the interactive init on a TTY check"
    );
    // The prebuilt/tarball fast path must exist so teammates can skip cargo.
    assert!(
        body.contains("--prebuilt") && body.contains("SCRIPT_DIR/secreq"),
        "install.sh must support installing a prebuilt/bundled binary"
    );
}

#[test]
fn package_layout_matches_install_expectations() {
    let pkg = read("scripts/package-release.sh");
    // The tarball drops the binary at `<pkg>/secreq`, next to install.sh —
    // exactly the sibling that install.sh's bundled-binary branch looks for.
    assert!(
        pkg.contains("cp \"$BIN\" \"$PKG/secreq\"") && pkg.contains("$PKG/install.sh"),
        "package-release.sh must place the binary beside install.sh so the \
         bundled-binary branch in install.sh finds it"
    );
    assert!(
        pkg.contains(".tar.gz"),
        "package-release.sh must produce a .tar.gz artifact"
    );
    // Cross-check the two halves of the contract literally: install.sh looks
    // for `$SCRIPT_DIR/secreq`, package-release.sh writes `$PKG/secreq`.
    let install = read("scripts/install.sh");
    assert!(
        install.contains("$SCRIPT_DIR/secreq"),
        "install.sh's bundled-binary branch must look for a sibling `secreq`"
    );
}

#[test]
fn dist_is_gitignored() {
    let ignore = read(".gitignore");
    let ignores_dist = ignore
        .lines()
        .map(|l| l.trim())
        .any(|l| l == "/dist" || l == "dist" || l == "/dist/" || l == "dist/");
    assert!(
        ignores_dist,
        "/dist (package-release.sh's output dir) must be gitignored so tarballs \
         aren't committed; .gitignore has:\n{ignore}"
    );
}

/// Keep the docs honest: getting-started must actually mention the script so a
/// coworker can find the one-command path.
#[test]
fn getting_started_documents_the_script() {
    let doc = read("docs/getting-started.md");
    assert!(
        doc.contains("scripts/install.sh"),
        "docs/getting-started.md must document the scripts/install.sh path"
    );
}
