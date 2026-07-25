//! Build script: stamp a `SECREQ_BUILD_ID` into the binary so the daemon
//! and the CLI can tell whether they were built from the same binary.
//!
//! The daemon is long-lived (it can run for hours, and never idle-exits
//! while the SSH agent is enabled). When the installed `secreq` binary is
//! updated underneath a running daemon, a newer CLI ends up talking to a
//! stale daemon. The build id lets the CLI detect that mismatch and
//! restart the daemon (see `daemon::client::connect_or_spawn`).
//!
//! Composition: `<git-short-sha>[-dirty] +<build-unix-seconds>`.
//!
//! - The git sha is the meaningful, human-readable part for release
//!   builds from a clean tree.
//! - `-dirty` flags a working tree with uncommitted changes.
//! - The build timestamp disambiguates *dev* rebuilds: two uncommitted
//!   iterations share a git sha (and the `-dirty` flag), so without a
//!   timestamp the daemon couldn't tell them apart and wouldn't restart
//!   between `cargo build`s. We emit no `rerun-if-changed`, so Cargo
//!   re-runs this script whenever a package source file changes — i.e.
//!   exactly when a rebuild produces a new binary.

use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let sha = git(&["rev-parse", "--short=12", "HEAD"]).unwrap_or_else(|| "nogit".to_owned());
    let dirty = git(&["status", "--porcelain"])
        .map(|s| !s.is_empty())
        .unwrap_or(false);
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let build_id = format!("{sha}{} +{ts}", if dirty { "-dirty" } else { "" });
    println!("cargo:rustc-env=SECREQ_BUILD_ID={build_id}");
}

/// Run `git <args>` and return trimmed stdout, or `None` if git is absent
/// or the command fails (e.g. building from a tarball with no `.git`).
fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}
