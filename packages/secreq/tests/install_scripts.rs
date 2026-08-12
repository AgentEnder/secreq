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
    // The crate now lives at `packages/secreq`; the scripts/docs/dist it guards
    // stay at the workspace root, two levels up from the manifest dir.
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
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

/// `dist/` is shared: package-release.sh writes throwaway tarballs there, but
/// the Homebrew formula and the curl|sh installer are tracked files under the
/// same directory. Ignoring `/dist` wholesale would swallow them, so assert the
/// contract git actually enforces rather than a literal .gitignore line.
#[test]
fn dist_tarballs_are_ignored_but_tracked_dist_files_are_not() {
    let ignored = |rel: &str| {
        Command::new("git")
            .args(["check-ignore", "-q", rel])
            .current_dir(repo_root())
            .status()
            .expect("git check-ignore must run")
            .success()
    };

    assert!(
        ignored("dist/secreq-0.1.0-darwin-arm64.tar.gz"),
        "package-release.sh's tarballs must be gitignored so they aren't committed"
    );
    // The Homebrew formula is deliberately absent: `dist/homebrew/gen-formula.sh`
    // is its only copy, so a release-plz version bump has no checked-in `.rb` to
    // leave stale. See the section comment in `tests/dist_channels.rs`.
    for tracked in ["dist/install.sh", "dist/homebrew/gen-formula.sh"] {
        assert!(
            !ignored(tracked),
            "{tracked} is a tracked distribution file — .gitignore must not swallow it"
        );
    }
}

/// Keep the docs honest: a coworker starting cold has to be able to reach the
/// one-command checkout path.
///
/// The assertion is the *route*, not one page. `docs/install.md` owns the
/// install channels, and `getting-started` covers installation in a sentence
/// and links onward — so pinning this to whichever page happens to spell the
/// script out today would fail the next time the two are rebalanced, without
/// anything actually having become undiscoverable. Both halves are checked
/// because either one alone leaves the path broken: the script documented on a
/// page nothing links to, or a link to a page that no longer explains it.
#[test]
fn the_checkout_install_path_is_reachable_from_getting_started() {
    let install = read("docs/install.md");
    assert!(
        install.contains("scripts/install.sh"),
        "docs/install.md owns the install channels and must document the \
         scripts/install.sh path"
    );

    let start = read("docs/getting-started.md");
    assert!(
        start.contains("install.md"),
        "docs/getting-started.md must link to docs/install.md, or the checkout \
         path is documented where nobody starting out will find it"
    );
}
