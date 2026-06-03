//! End-to-end tests driving the built `secreq` binary against the per-binary
//! wrap model. Each test sandboxes config + state into a tempdir so it can't
//! touch the developer's real `~/.config/secreq` or `~/.local/state/secreq`.
//!
//! A `printf`/`sh` "fake provider" stands in for real stores so the tests
//! never trigger Touch ID / `op` biometrics.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_secreq")
}

/// Sandbox: a tempdir with `XDG_CONFIG_HOME`, `XDG_STATE_HOME`, and a path
/// at which we drop the wraps file. Returns `(dir, config_path)`.
fn sandbox() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config/secreq/wraps.json5");
    fs::create_dir_all(config_path.parent().unwrap()).unwrap();
    (dir, config_path)
}

fn run_secreq(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(bin())
        .args(args)
        // Pin every state path into the sandbox.
        .env("XDG_CONFIG_HOME", dir.join("config"))
        .env("XDG_STATE_HOME", dir.join("state"))
        // Wipe SHELL so init's auto-PATH-setup goes through `Unknown` (no
        // file writes) — tests focus on behavior, not shell-rc mutation.
        .env_remove("SHELL")
        // Wipe any inherited consent socket from the test runner.
        .env_remove("SECREQ_CONSENT_SOCK")
        // Disable the consent daemon entirely; otherwise tests would pop
        // a native window on the developer's machine and hang waiting for
        // a click. Tests that need consent use `--yes` instead.
        .env("SECREQ_NO_DAEMON", "1")
        .output()
        .unwrap()
}

/// Write a config with a single wrap using a fake "echo" provider whose
/// retrieve template prints the locator back. Useful for non-biometric
/// integration testing of wrap-and-run.
fn write_config(config_path: &Path, body: &str) {
    fs::create_dir_all(config_path.parent().unwrap()).unwrap();
    fs::write(config_path, body).unwrap();
}

/// A config body whose `op` provider override echoes the locator. The
/// real-binary `gh` is stubbed by a script we drop into the sandbox bin dir.
fn echo_provider_config(shim_dir: &Path) -> String {
    format!(
        r#"{{
            $shim_dir: "{shim}",
            gh: {{
                $reason: "GitHub API access",
                env: {{
                    GITHUB_TOKEN: "secret://fake/the-token-value",
                }},
            }},
            providers: {{
                fake: {{ retrieve: ["printf", "%s", "{{locator}}"] }},
            }},
        }}"#,
        shim = shim_dir.display(),
    )
}

/// Drop a fake `gh` binary into `bin_dir` that echoes argv, env, and stdin
/// so the wrap-and-run test can assert what was injected.
fn install_fake_gh(bin_dir: &Path) {
    fs::create_dir_all(bin_dir).unwrap();
    let path = bin_dir.join("gh");
    fs::write(
        &path,
        "#!/bin/sh\necho \"argv=$*\"\necho \"GITHUB_TOKEN=$GITHUB_TOKEN\"\n",
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&path, perms).unwrap();
}

// ── wrap-and-run ──────────────────────────────────────────────────────────

#[test]
fn wrap_run_injects_env_and_masks_output_when_token_is_echoed() {
    let (dir, config) = sandbox();
    let bin_dir = dir.path().join("realbin");
    let shim_dir = dir.path().join("shims");
    install_fake_gh(&bin_dir);
    write_config(&config, &echo_provider_config(&shim_dir));

    // Put the fake gh on PATH so secreq's find_real_binary picks it up.
    let path = format!("{}:{}", bin_dir.display(), std::env::var("PATH").unwrap());
    let out = Command::new(bin())
        .args(["--yes", "gh", "auth", "status"])
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .env("XDG_STATE_HOME", dir.path().join("state"))
        .env("PATH", &path)
        .env_remove("SECREQ_CONSENT_SOCK")
        .env("SECREQ_NO_DAEMON", "1")
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Args forwarded.
    assert!(stdout.contains("argv=auth status"), "got: {stdout}");
    // GITHUB_TOKEN injected — and masked in output (8 stars).
    assert!(
        stdout.contains("GITHUB_TOKEN=********"),
        "expected masked token; got: {stdout}"
    );
    // The literal value must never appear.
    assert!(!stdout.contains("the-token-value"));
}

#[test]
fn raw_flag_disables_output_masking() {
    let (dir, config) = sandbox();
    let bin_dir = dir.path().join("realbin");
    let shim_dir = dir.path().join("shims");
    install_fake_gh(&bin_dir);
    write_config(&config, &echo_provider_config(&shim_dir));
    let path = format!("{}:{}", bin_dir.display(), std::env::var("PATH").unwrap());

    let out = Command::new(bin())
        .args(["--yes", "--raw", "gh"])
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .env("XDG_STATE_HOME", dir.path().join("state"))
        .env("PATH", &path)
        .env_remove("SECREQ_CONSENT_SOCK")
        .env("SECREQ_NO_DAEMON", "1")
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    // --raw means the real value passes through unredacted.
    assert!(
        stdout.contains("GITHUB_TOKEN=the-token-value"),
        "got: {stdout}"
    );
}

#[test]
fn unwrapped_binary_passes_through_unchanged() {
    let (dir, config) = sandbox();
    let bin_dir = dir.path().join("realbin");
    let shim_dir = dir.path().join("shims");
    install_fake_gh(&bin_dir);
    // Config has shim_dir but NO wrap for `gh`.
    write_config(
        &config,
        &format!(r#"{{ $shim_dir: "{}" }}"#, shim_dir.display()),
    );
    let path = format!("{}:{}", bin_dir.display(), std::env::var("PATH").unwrap());

    let out = Command::new(bin())
        .args(["gh", "passthrough-args"])
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .env("XDG_STATE_HOME", dir.path().join("state"))
        .env("PATH", &path)
        .env_remove("SECREQ_CONSENT_SOCK")
        .env("SECREQ_NO_DAEMON", "1")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("argv=passthrough-args"));
    // No injection happened — env var was empty in child.
    assert!(
        stdout.contains("GITHUB_TOKEN=")
            && !stdout.contains("GITHUB_TOKEN=the-token-value")
            && !stdout.contains("GITHUB_TOKEN=********"),
        "got: {stdout}"
    );
}

#[test]
fn denies_without_terminal_or_yes() {
    let (dir, config) = sandbox();
    let bin_dir = dir.path().join("realbin");
    let shim_dir = dir.path().join("shims");
    install_fake_gh(&bin_dir);
    write_config(&config, &echo_provider_config(&shim_dir));
    let path = format!("{}:{}", bin_dir.display(), std::env::var("PATH").unwrap());

    // No --yes; SECREQ_NO_DAEMON forces fail-closed without contacting the
    // daemon (which would otherwise pop a GUI window).
    let out = Command::new(bin())
        .args(["gh"])
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .env("XDG_STATE_HOME", dir.path().join("state"))
        .env("PATH", &path)
        .env("SECREQ_NO_DAEMON", "1")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Child must not have run.
    assert!(!stdout.contains("argv="));
}

// ── wrap / unwrap / wraps ─────────────────────────────────────────────────

#[test]
fn wrap_can_reference_a_builtin_provider_without_a_providers_block() {
    // Regression: `secreq wrap gh --env GITHUB_TOKEN=secret://op/...` against
    // a config that has *no* `providers` block must succeed (built-ins
    // overlay at load time). Before the fix, `commands::wrap` loaded the
    // file but didn't `merge_builtin_providers`, so the interactive picker
    // saw an empty map. Non-interactive runs reach a different code path,
    // but we still want the loaded config to see built-ins.
    let (dir, config) = sandbox();
    let shim_dir = dir.path().join("shims");
    fs::create_dir_all(&shim_dir).unwrap();
    write_config(
        &config,
        &format!(r#"{{ $shim_dir: "{}" }}"#, shim_dir.display()),
    );

    let out = run_secreq(
        dir.path(),
        &[
            "wrap",
            "--env",
            "GITHUB_TOKEN=secret://op/Personal/GitHub/credential",
            "gh",
        ],
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // And `check` against the resulting config — which uses the same overlay
    // path — must agree the `op` provider is known.
    let check = run_secreq(dir.path(), &["check"]);
    assert!(check.status.success());
    let stdout = String::from_utf8_lossy(&check.stdout);
    assert!(stdout.contains("config OK"), "got: {stdout}");
}

#[test]
fn wrap_records_config_and_drops_shim() {
    let (dir, config) = sandbox();
    let shim_dir = dir.path().join("shims");
    fs::create_dir_all(&shim_dir).unwrap();
    write_config(
        &config,
        &format!(r#"{{ $shim_dir: "{}" }}"#, shim_dir.display()),
    );

    let out = run_secreq(
        dir.path(),
        &[
            "wrap",
            "--env",
            "GITHUB_TOKEN=secret://op/Personal/GH/credential",
            "--reason",
            "GitHub",
            "gh",
        ],
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Config has the new wrap.
    let body = fs::read_to_string(&config).unwrap();
    assert!(body.contains(r#""gh""#));
    assert!(body.contains("secret://op/Personal/GH/credential"));
    // Shim exists with our sentinel.
    let shim = shim_dir.join("gh");
    assert!(shim.is_file());
    let shim_body = fs::read_to_string(&shim).unwrap();
    assert!(shim_body.contains("secreq-managed-shim"));
    assert!(shim_body.contains("exec secreq gh"));
}

#[test]
fn unwrap_removes_config_and_shim() {
    let (dir, config) = sandbox();
    let shim_dir = dir.path().join("shims");
    fs::create_dir_all(&shim_dir).unwrap();
    write_config(
        &config,
        &format!(r#"{{ $shim_dir: "{}" }}"#, shim_dir.display()),
    );
    run_secreq(dir.path(), &["wrap", "--env", "X=secret://op/x", "gh"]);
    assert!(shim_dir.join("gh").is_file());

    let out = run_secreq(dir.path(), &["unwrap", "gh"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!shim_dir.join("gh").exists());
    let body = fs::read_to_string(&config).unwrap();
    assert!(
        !body.contains(r#""gh""#),
        "gh should be gone from config: {body}"
    );
}

#[test]
fn wraps_list_shows_configured_wraps() {
    let (dir, config) = sandbox();
    let shim_dir = dir.path().join("shims");
    fs::create_dir_all(&shim_dir).unwrap();
    write_config(
        &config,
        &format!(
            r#"{{
                $shim_dir: "{}",
                gh: {{ $reason: "GitHub", env: {{ GITHUB_TOKEN: "secret://op/gh" }} }},
                aws: {{ env: {{ AWS_KEY: "secret://op/aws/k", AWS_SECRET: "secret://op/aws/s" }} }},
            }}"#,
            shim_dir.display()
        ),
    );
    let out = run_secreq(dir.path(), &["wraps"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("gh — GitHub"));
    assert!(stdout.contains("aws"));
    assert!(stdout.contains("GITHUB_TOKEN (op)"));
    assert!(stdout.contains("AWS_KEY (op)"));
    // Values never appear.
    assert!(!stdout.contains("secret://"));
}

#[test]
fn doctor_flags_when_a_shim_is_shadowed_by_an_earlier_path_entry() {
    // Reproduces the homebrew-shadows-our-shim case: shim_dir is on PATH
    // but a higher-priority dir (`realbin`, in this stand-in) contains
    // another `gh` that resolves first.
    let (dir, config) = sandbox();
    let bin_dir = dir.path().join("realbin");
    let shim_dir = dir.path().join("shims");
    install_fake_gh(&bin_dir);
    fs::create_dir_all(&shim_dir).unwrap();
    write_config(
        &config,
        &format!(
            r#"{{
                $shim_dir: "{}",
                gh: {{ env: {{ GITHUB_TOKEN: "secret://op/gh" }} }},
            }}"#,
            shim_dir.display(),
        ),
    );
    // Drop the shim manually (skip running `wrap` here — focused test).
    fs::write(
        shim_dir.join("gh"),
        "#!/bin/sh\n# secreq-managed-shim: wrap=gh\nexec secreq gh \"$@\"\n",
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(shim_dir.join("gh"), std::fs::Permissions::from_mode(0o755)).unwrap();

    // PATH order: realbin first → shim_dir second → system. Homebrew analogue.
    let path = format!(
        "{}:{}:{}",
        bin_dir.display(),
        shim_dir.display(),
        std::env::var("PATH").unwrap()
    );
    let out = Command::new(bin())
        .args(["doctor"])
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .env("XDG_STATE_HOME", dir.path().join("state"))
        .env("PATH", &path)
        .env_remove("SECREQ_CONSENT_SOCK")
        .env("SECREQ_NO_DAEMON", "1")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("shadowed"), "got: {stdout}");
    assert!(
        stdout.contains(".zshrc"),
        "doctor should hint at the .zshrc fix; got: {stdout}"
    );
}

#[test]
fn doctor_is_happy_when_the_shim_is_first_on_path() {
    let (dir, config) = sandbox();
    let shim_dir = dir.path().join("shims");
    fs::create_dir_all(&shim_dir).unwrap();
    write_config(
        &config,
        &format!(
            r#"{{
                $shim_dir: "{}",
                gh: {{ env: {{ GITHUB_TOKEN: "secret://op/gh" }} }},
            }}"#,
            shim_dir.display(),
        ),
    );
    fs::write(
        shim_dir.join("gh"),
        "#!/bin/sh\n# secreq-managed-shim: wrap=gh\nexec secreq gh \"$@\"\n",
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(shim_dir.join("gh"), std::fs::Permissions::from_mode(0o755)).unwrap();

    // PATH order: shim_dir first.
    let path = format!("{}:{}", shim_dir.display(), std::env::var("PATH").unwrap());
    let out = Command::new(bin())
        .args(["doctor"])
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .env("XDG_STATE_HOME", dir.path().join("state"))
        .env("PATH", &path)
        .env_remove("SECREQ_CONSENT_SOCK")
        .env("SECREQ_NO_DAEMON", "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("gh → "), "got: {stdout}");
    assert!(stdout.contains("(shim)"), "got: {stdout}");
}

#[test]
fn check_passes_on_a_well_formed_config() {
    let (dir, config) = sandbox();
    write_config(
        &config,
        r#"{ gh: { env: { GITHUB_TOKEN: "secret://op/gh" } } }"#,
    );
    let out = run_secreq(dir.path(), &["check"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("config OK"));
}

#[test]
fn check_flags_unknown_provider_in_a_wrap() {
    let (dir, config) = sandbox();
    write_config(
        &config,
        r#"{ gh: { env: { X: "secret://made-up-provider/loc" } } }"#,
    );
    let out = run_secreq(dir.path(), &["check"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stdout).contains("unknown provider scheme"));
}

// ── init (auto-PATH setup) ────────────────────────────────────────────────

#[test]
fn init_writes_config_with_shim_dir() {
    let (dir, config) = sandbox();
    let shim_dir = dir.path().join("local/bin");
    // SHELL=zsh + a fake HOME inside the sandbox would let us test the
    // PATH-update path; here we go through `Unknown` (no SHELL) which
    // means the auto-update is skipped (caveat printed instead).
    let out = Command::new(bin())
        .args(["init", "--shim-dir", shim_dir.to_str().unwrap()])
        // Pre-answer prompts: accept default shim dir.
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .env("XDG_STATE_HOME", dir.path().join("state"))
        .env_remove("SHELL")
        .env_remove("SECREQ_CONSENT_SOCK")
        // cliclack reads from the controlling terminal; closing stdin makes
        // its `interact` call error out, which the init command surfaces.
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    // cliclack with no terminal will error on `interact`; the init command
    // surfaces that. We tolerate either outcome but require the config file
    // to either be missing-but-the-error-was-clear OR exist with shim_dir
    // set.
    if out.status.success() {
        assert!(config.exists());
        let body = fs::read_to_string(&config).unwrap();
        assert!(body.contains("$shim_dir"));
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("terminal") || stderr.contains("interactive"),
            "stderr should mention the terminal requirement: {stderr}"
        );
    }
}

#[test]
fn daemon_log_path_prints_state_dir_path_without_spawning() {
    let (dir, _config) = sandbox();
    // `daemon log-path` is pure: it prints the path and never starts a
    // daemon (so it's safe even with the daemon disabled).
    let out = run_secreq(dir.path(), &["daemon", "log-path"]);
    assert!(
        out.status.success(),
        "log-path should exit 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let printed = String::from_utf8_lossy(&out.stdout);
    let expected = dir.path().join("state/secreq/daemon.log");
    assert_eq!(
        printed.trim(),
        expected.to_str().unwrap(),
        "log-path should print <XDG_STATE_HOME>/secreq/daemon.log"
    );
    // It must not have created the file or a daemon socket — pure print.
    assert!(
        !expected.exists(),
        "log-path must not create the log file"
    );
}
