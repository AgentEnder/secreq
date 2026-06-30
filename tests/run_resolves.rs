//! End-to-end proof that `secreq run` resolves an ambient `secret://`
//! reference and the child process sees the resolved value: the full
//! scan → resolve → substitute → exec path.
//!
//! Drives the built `secreq` binary (the real CLI, exec + PTY path) rather
//! than calling `commands::run` in-process — this sidesteps the process-global
//! `std::env::set_var` hazard entirely and exercises the actual entry point.
//!
//! Resolution goes through the **client-side `--yes` path**
//! (`resolve_refs_client_side` → `resolve::resolve_all`), so there's no GUI
//! consent daemon and no biometric. A `sh -c` "fake provider" stands in for a
//! real store: its `retrieve` template prints `resolved-<locator>`, a value
//! deterministically derived from the locator.
//!
//! The child writes `$THEVAR` to a temp file rather than to stdout, because
//! `exec::run` masks resolved secrets in the child's output — reading the file
//! lets us assert the child genuinely received the *unmasked* resolved value.

use std::fs;
use std::path::Path;
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_secreq")
}

/// A config whose `fake` provider's retrieve prints `resolved-<locator>`.
/// `{locator}` is substituted by `provider::retrieve`; we pass it as a
/// positional (`$1`) after `--` so a locator with leading dashes can't be
/// misread as an `sh` flag.
fn fake_provider_config() -> &'static str {
    r#"{
        providers: {
            fake: { retrieve: ["sh", "-c", "printf 'resolved-%s' \"$1\"", "--", "{locator}"] },
        },
    }"#
}

fn write_config(config_path: &Path, body: &str) {
    fs::create_dir_all(config_path.parent().unwrap()).unwrap();
    fs::write(config_path, body).unwrap();
}

#[test]
fn run_resolves_ambient_secret_ref_for_the_child() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config/secreq/wraps.json5");
    write_config(&config, fake_provider_config());
    let outfile = dir.path().join("captured");

    // SECRET=secret://fake/thing in the child env; `run --yes` scans it,
    // resolves `fake`/`thing` → `resolved-thing`, then execs the command with
    // SECRET substituted. The child writes the value it actually saw to a file.
    let out = Command::new(bin())
        .args([
            "--yes",
            "--config",
            config.to_str().unwrap(),
            "run",
            "--",
            "sh",
            "-c",
            &format!("printf '%s' \"$SECRET\" > {}", outfile.display()),
        ])
        .env("SECRET", "secret://fake/thing")
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .env("XDG_STATE_HOME", dir.path().join("state"))
        .env_remove("SECREQ_CONSENT_SOCK")
        .env("SECREQ_NO_DAEMON", "1")
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "secreq run failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let captured = fs::read_to_string(&outfile).unwrap();
    assert_eq!(
        captured, "resolved-thing",
        "the child must see the resolved value, not the `secret://` placeholder",
    );
}

#[test]
fn run_passes_plain_env_vars_through_to_the_child() {
    // A non-reference env var must reach the child unchanged alongside any
    // resolved refs — `run` only rewrites `secret://` values.
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config/secreq/wraps.json5");
    write_config(&config, fake_provider_config());
    let outfile = dir.path().join("captured");

    let out = Command::new(bin())
        .args([
            "--yes",
            "--config",
            config.to_str().unwrap(),
            "run",
            "--",
            "sh",
            "-c",
            &format!(
                "printf '%s|%s' \"$SECRET\" \"$PLAIN\" > {}",
                outfile.display()
            ),
        ])
        .env("SECRET", "secret://fake/thing")
        .env("PLAIN", "just-a-literal")
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .env("XDG_STATE_HOME", dir.path().join("state"))
        .env_remove("SECREQ_CONSENT_SOCK")
        .env("SECREQ_NO_DAEMON", "1")
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "secreq run failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let captured = fs::read_to_string(&outfile).unwrap();
    assert_eq!(
        captured, "resolved-thing|just-a-literal",
        "the child must see both the resolved ref and the plain var",
    );
}

#[test]
fn run_resolves_ref_from_an_env_file() {
    // `--env-file` references resolve the same way ambient ones do. The file
    // holds a `secret://` ref (not plaintext); `run` layers it under the
    // inherited env, scans it, and substitutes the resolved value.
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config/secreq/wraps.json5");
    write_config(&config, fake_provider_config());
    let env_file = dir.path().join("the.env");
    fs::write(&env_file, "FROM_FILE=secret://fake/file-secret\n").unwrap();
    let outfile = dir.path().join("captured");

    let out = Command::new(bin())
        .args([
            "--yes",
            "--config",
            config.to_str().unwrap(),
            "run",
            "--env-file",
            env_file.to_str().unwrap(),
            "--",
            "sh",
            "-c",
            &format!("printf '%s' \"$FROM_FILE\" > {}", outfile.display()),
        ])
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .env("XDG_STATE_HOME", dir.path().join("state"))
        .env_remove("SECREQ_CONSENT_SOCK")
        .env("SECREQ_NO_DAEMON", "1")
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "secreq run failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let captured = fs::read_to_string(&outfile).unwrap();
    assert_eq!(
        captured, "resolved-file-secret",
        "the child must see the value resolved from the --env-file ref",
    );
}
