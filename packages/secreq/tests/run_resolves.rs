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

mod common;

use std::fs;

use common::Sandbox;

/// A config whose `fake` provider's retrieve prints `resolved-<locator>`.
/// `{locator}` is substituted by `provider::retrieve`; we pass it as a
/// positional (`$1`) after `--` so a locator with leading dashes can't be
/// misread as an `sh` flag.
fn fake_provider_config() -> &'static str {
    r#"
        [providers.fake]
        retrieve = ["sh", "-c", "printf 'resolved-%s' \"$1\"", "--", "{locator}"]
    "#
}

#[test]
fn run_resolves_ambient_secret_ref_for_the_child() {
    let sb = Sandbox::new();
    sb.write_config(fake_provider_config());
    let config = sb.config_path();
    let outfile = sb.path().join("captured");

    // SECRET=secret://fake/thing in the child env; `run --yes` scans it,
    // resolves `fake`/`thing` → `resolved-thing`, then execs the command with
    // SECRET substituted. The child writes the value it actually saw to a file.
    let out = sb
        .cmd(&[
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
    let sb = Sandbox::new();
    sb.write_config(fake_provider_config());
    let config = sb.config_path();
    let outfile = sb.path().join("captured");

    let out = sb
        .cmd(&[
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
    let sb = Sandbox::new();
    sb.write_config(fake_provider_config());
    let config = sb.config_path();
    let env_file = sb.path().join("the.env");
    fs::write(&env_file, "FROM_FILE=secret://fake/file-secret\n").unwrap();
    let outfile = sb.path().join("captured");

    let out = sb
        .cmd(&[
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

#[test]
fn run_uses_dotenvy_parsing_for_export_and_quotes() {
    // The env file is parsed by `dotenvy`, not a naive `KEY=value` splitter:
    // a leading `export ` prefix is stripped and surrounding double quotes
    // are honored. A line splitter would have produced a key of
    // `export FROM_FILE` and a quoted value, breaking resolution — so this
    // proves the real parser is in the path.
    let sb = Sandbox::new();
    sb.write_config(fake_provider_config());
    let config = sb.config_path();
    let env_file = sb.path().join("the.env");
    fs::write(
        &env_file,
        "# a comment\nexport FROM_FILE=\"secret://fake/file-secret\"\n",
    )
    .unwrap();
    let outfile = sb.path().join("captured");

    let out = sb
        .cmd(&[
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
        "dotenvy must strip `export` and quotes so the ref resolves",
    );
}

#[test]
fn run_stamps_and_propagates_the_session_marker() {
    // A run stamps SECREQ_RUN_SESSION on its child; a nested run inherits
    // the SAME token (it doesn't re-mint), so a whole run tree shares one
    // session id. That marker is how a nested run detects nesting. Drives
    // `outer run -> inner run -> sh` and captures what the innermost child
    // sees. No refs, so no daemon/GUI is touched.
    let sb = Sandbox::new();
    sb.write_config(fake_provider_config());
    let config = sb.config_path();
    let outfile = sb.path().join("captured");
    let bin = common::bin();

    let out = sb
        .cmd(&[
            "--config",
            config.to_str().unwrap(),
            "run",
            "--",
            bin,
            "--config",
            config.to_str().unwrap(),
            "run",
            "--",
            "sh",
            "-c",
            &format!(
                "printf '%s' \"$SECREQ_RUN_SESSION\" > {}",
                outfile.display()
            ),
        ])
        // Start clean: the test's own env must not pre-seed the marker.
        .env_remove("SECREQ_RUN_SESSION")
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "nested secreq run failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let captured = fs::read_to_string(&outfile).unwrap();
    // The innermost child sees the session token the OUTER run minted
    // (`"<pid>:<nonce>"`) — a digit-only pid and nonce joined by a single
    // colon, proving it was stamped and inherited unchanged rather than
    // re-minted at each level.
    let (pid, nonce) = captured
        .split_once(':')
        .unwrap_or_else(|| panic!("session token must be \"pid:nonce\", got {captured:?}"));
    assert!(
        !pid.is_empty() && pid.chars().all(|c| c.is_ascii_digit()),
        "session token pid half must be all digits, got {captured:?}",
    );
    assert!(
        !nonce.is_empty() && nonce.chars().all(|c| c.is_ascii_digit()),
        "session token nonce half must be all digits, got {captured:?}",
    );
}
