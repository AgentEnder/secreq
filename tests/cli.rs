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
fn wrap_with_no_env_creates_a_gate_only_wrap() {
    // `secreq wrap op` with no `--env` and no terminal (the test harness
    // has no TTY) creates a gate-only wrap: consent is required, nothing
    // is injected. This is how you gate a tool like `op`.
    let (dir, config) = sandbox();
    let shim_dir = dir.path().join("shims");
    fs::create_dir_all(&shim_dir).unwrap();
    write_config(
        &config,
        &format!(r#"{{ $shim_dir: "{}" }}"#, shim_dir.display()),
    );

    let out = run_secreq(
        dir.path(),
        &["wrap", "--reason", "1Password vault access", "op"],
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("gate-only"), "got: {stdout}");

    // Config has the wrap with an empty env (gate-only) and the reason.
    let body = fs::read_to_string(&config).unwrap();
    assert!(body.contains(r#""op""#));
    assert!(body.contains("1Password vault access"));
    // No secret references made it in.
    assert!(!body.contains("secret://"), "got: {body}");

    // The config round-trips and `check` is happy with a gate-only wrap.
    let check = run_secreq(dir.path(), &["check"]);
    assert!(
        check.status.success(),
        "check stderr: {}",
        String::from_utf8_lossy(&check.stderr)
    );

    // Shim exists with our sentinel.
    let shim = shim_dir.join("op");
    assert!(shim.is_file());
    let shim_body = fs::read_to_string(&shim).unwrap();
    assert!(shim_body.contains("exec secreq op"));
}

#[test]
fn gate_only_wrap_denies_without_terminal_or_yes() {
    // Running a gated `op` with no consent path available (SECREQ_NO_DAEMON
    // + no --yes) must fail closed: exit 1, and `op` itself must not run.
    let (dir, config) = sandbox();
    let bin_dir = dir.path().join("realbin");
    let shim_dir = dir.path().join("shims");
    fs::create_dir_all(&bin_dir).unwrap();
    // A fake `op` that announces itself if it ever runs.
    let op_path = bin_dir.join("op");
    fs::write(&op_path, "#!/bin/sh\necho \"op-ran args=$*\"\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(&op_path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&op_path, perms).unwrap();

    write_config(
        &config,
        &format!(
            r#"{{ $shim_dir: "{}", op: {{ $reason: "1Password vault access" }} }}"#,
            shim_dir.display()
        ),
    );
    let path = format!("{}:{}", bin_dir.display(), std::env::var("PATH").unwrap());

    let out = Command::new(bin())
        .args(["op", "read", "op://Personal/AWS/credential"])
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .env("XDG_STATE_HOME", dir.path().join("state"))
        .env("PATH", &path)
        .env("SECREQ_NO_DAEMON", "1")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("op-ran"), "op must not have run: {stdout}");
}

#[test]
fn resolving_env_bypasses_the_gate_for_a_wrapped_provider() {
    // When secreq resolves a `secret://op/...` ref it spawns the provider
    // CLI with SECREQ_RESOLVING=1. If `op` is itself wrapped, that
    // invocation must pass through — NOT pop a consent prompt. We simulate
    // the inner call: set SECREQ_RESOLVING and run the gated `op`. Even with
    // no consent path (SECREQ_NO_DAEMON, no --yes), it should run the real
    // `op` and exit 0.
    let (dir, config) = sandbox();
    let bin_dir = dir.path().join("realbin");
    let shim_dir = dir.path().join("shims");
    fs::create_dir_all(&bin_dir).unwrap();
    let op_path = bin_dir.join("op");
    fs::write(&op_path, "#!/bin/sh\necho \"op-ran args=$*\"\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(&op_path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&op_path, perms).unwrap();

    write_config(
        &config,
        &format!(
            r#"{{ $shim_dir: "{}", op: {{ $reason: "1Password vault access" }} }}"#,
            shim_dir.display()
        ),
    );
    let path = format!("{}:{}", bin_dir.display(), std::env::var("PATH").unwrap());

    let out = Command::new(bin())
        .args(["op", "read", "op://Personal/AWS/credential"])
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .env("XDG_STATE_HOME", dir.path().join("state"))
        .env("PATH", &path)
        .env("SECREQ_NO_DAEMON", "1")
        // The marker secreq sets on a provider's retrieve subprocess.
        .env("SECREQ_RESOLVING", "1")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "expected pass-through exit 0; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("op-ran args=read op://Personal/AWS/credential"),
        "op should have run with forwarded args; got: {stdout}"
    );
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

// ── ssh-setup ─────────────────────────────────────────────────────────────

/// Run `secreq` with a sandboxed `$HOME` (and `$XDG_RUNTIME_DIR`) so
/// `ssh-setup` writes into the tempdir, never the developer's real home.
/// `shell` sets `$SHELL` (pass `""` to leave it unset, going through the
/// `Unknown` shell path).
fn run_ssh_setup(dir: &Path, home: &Path, shell: &str, args: &[&str]) -> std::process::Output {
    let mut cmd = Command::new(bin());
    cmd.args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", dir.join("config"))
        .env("XDG_STATE_HOME", dir.join("state"))
        .env("XDG_RUNTIME_DIR", dir.join("run"))
        .env_remove("SECREQ_CONSENT_SOCK")
        .env("SECREQ_NO_DAEMON", "1")
        .stdin(std::process::Stdio::null());
    if shell.is_empty() {
        cmd.env_remove("SHELL");
    } else {
        cmd.env("SHELL", shell);
    }
    cmd.output().unwrap()
}

#[test]
fn ssh_setup_ssh_config_writes_identityagent_block_0600() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, _config) = sandbox();
    let home = dir.path().join("home");
    fs::create_dir_all(&home).unwrap();

    // `--yes` skips the confirm prompt so the command runs without a TTY.
    let out = run_ssh_setup(
        dir.path(),
        &home,
        "",
        &["ssh-setup", "--method", "ssh-config", "--yes"],
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let ssh_config = home.join(".ssh/config");
    assert!(ssh_config.is_file(), "~/.ssh/config should exist");
    let body = fs::read_to_string(&ssh_config).unwrap();
    assert!(
        body.contains("IdentityAgent"),
        "should wire IdentityAgent: {body}"
    );
    assert!(
        body.contains("# >>> secreq managed SSH agent"),
        "should carry the begin sentinel: {body}"
    );
    let mode = fs::metadata(&ssh_config).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "~/.ssh/config must be 0600");
}

#[test]
fn ssh_setup_undo_removes_the_ssh_config_block() {
    let (dir, _config) = sandbox();
    let home = dir.path().join("home");
    fs::create_dir_all(&home).unwrap();

    // First write the block.
    let out = run_ssh_setup(
        dir.path(),
        &home,
        "",
        &["ssh-setup", "--method", "ssh-config", "--yes"],
    );
    assert!(out.status.success());
    let ssh_config = home.join(".ssh/config");
    assert!(fs::read_to_string(&ssh_config)
        .unwrap()
        .contains("# >>> secreq managed SSH agent"));

    // Then undo it.
    let out = run_ssh_setup(
        dir.path(),
        &home,
        "",
        &["ssh-setup", "--method", "ssh-config", "--undo"],
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let body = fs::read_to_string(&ssh_config).unwrap();
    assert!(
        !body.contains("# >>> secreq managed SSH agent"),
        "sentinel should be gone after --undo: {body}"
    );
    assert!(!body.contains("IdentityAgent"));
}

#[test]
fn ssh_setup_shell_rc_writes_ssh_auth_sock_block() {
    let (dir, _config) = sandbox();
    let home = dir.path().join("home");
    fs::create_dir_all(&home).unwrap();

    // SHELL=zsh → the block lands in ~/.zshrc.
    let out = run_ssh_setup(
        dir.path(),
        &home,
        "/bin/zsh",
        &["ssh-setup", "--method", "shell-rc", "--yes"],
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let zshrc = home.join(".zshrc");
    assert!(zshrc.is_file(), "~/.zshrc should be created");
    let body = fs::read_to_string(&zshrc).unwrap();
    assert!(
        body.contains("export SSH_AUTH_SOCK="),
        "should export SSH_AUTH_SOCK: {body}"
    );
    assert!(
        body.contains("# >>> secreq managed SSH agent"),
        "should carry the begin sentinel: {body}"
    );
}

#[test]
fn ssh_setup_scripted_does_only_client_wiring() {
    // `--yes --method ssh-config` is the scripted path: it must write ONLY the
    // client-wiring block, never prompting for (or creating) an identity or
    // the login service.
    let (dir, _config) = sandbox();
    let home = dir.path().join("home");
    fs::create_dir_all(&home).unwrap();

    let out = run_ssh_setup(
        dir.path(),
        &home,
        "",
        &["ssh-setup", "--method", "ssh-config", "--yes"],
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The client-wiring block was written.
    let ssh_config = home.join(".ssh/config");
    assert!(ssh_config.is_file(), "~/.ssh/config should exist");
    assert!(fs::read_to_string(&ssh_config)
        .unwrap()
        .contains("# >>> secreq managed SSH agent"));

    // No login service was installed (macOS LaunchAgents / Linux systemd user).
    let launchd = home.join("Library/LaunchAgents/com.secreq.daemon.plist");
    let systemd = home.join(".config/systemd/user/secreq.service");
    assert!(
        !launchd.exists() && !systemd.exists(),
        "scripted path must not install the login service"
    );

    // No ssh identity was written: the config either doesn't exist or has no
    // `ssh` block.
    let config_file = dir.path().join("config/secreq/wraps.json5");
    if config_file.exists() {
        let body = fs::read_to_string(&config_file).unwrap();
        assert!(
            !body.contains("\"ssh\""),
            "scripted path must not write an ssh identity: {body}"
        );
    }
}

// ── ssh-add ───────────────────────────────────────────────────────────────

/// A real (throwaway) ed25519 public key line for the ssh-add tests. Used as
/// both a literal and the contents of a `.pub` file.
const TEST_ED25519_PUB: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFxM1DmY0MNYQSHCQECYWC1Rqdom+nv5d1rCDKSm+nEn secreq-test@example";

#[test]
fn ssh_add_writes_identity_with_explicit_flags() {
    let (dir, config) = sandbox();
    let pub_path = dir.path().join("id_ed25519.pub");
    fs::write(&pub_path, format!("{TEST_ED25519_PUB}\n")).unwrap();

    let out = run_secreq(
        dir.path(),
        &[
            "ssh-add",
            "github",
            "--public-key",
            pub_path.to_str().unwrap(),
            "--private-key",
            "secret://op/Private/GitHub/private key",
            "--reason",
            "git",
        ],
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The written config must re-parse and carry the identity exactly.
    let body = fs::read_to_string(&config).unwrap();
    assert!(body.contains(r#""github""#), "got: {body}");
    assert!(
        body.contains(TEST_ED25519_PUB),
        "public_key missing: {body}"
    );
    assert!(
        body.contains("secret://op/Private/GitHub/private key"),
        "private_key ref missing: {body}"
    );
    assert!(body.contains(r#""git""#), "reason missing: {body}");

    // And `secreq check` is happy with the resulting config (it round-trips).
    let check = run_secreq(dir.path(), &["check"]);
    assert!(
        check.status.success(),
        "check stderr: {}",
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn ssh_add_rejects_duplicate_without_force() {
    let (dir, config) = sandbox();

    let add = |reason: &str| {
        run_secreq(
            dir.path(),
            &[
                "ssh-add",
                "github",
                "--public-key",
                TEST_ED25519_PUB,
                "--private-key",
                "secret://op/Private/GitHub/private key",
                "--reason",
                reason,
            ],
        )
    };

    // First add succeeds (literal public key).
    let first = add("first");
    assert!(
        first.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&first.stderr)
    );

    // Second add of the same name without --force errors.
    let dup = add("second");
    assert_eq!(dup.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&dup.stderr).contains("already exists"),
        "stderr: {}",
        String::from_utf8_lossy(&dup.stderr)
    );

    // --force overwrites (reason changes to the new value).
    let forced = run_secreq(
        dir.path(),
        &[
            "ssh-add",
            "github",
            "--public-key",
            TEST_ED25519_PUB,
            "--private-key",
            "secret://op/Private/GitHub/private key",
            "--reason",
            "overwritten",
            "--force",
        ],
    );
    assert!(
        forced.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&forced.stderr)
    );
    let body = fs::read_to_string(&config).unwrap();
    assert!(body.contains(r#""overwritten""#), "got: {body}");
    assert!(
        !body.contains(r#""first""#),
        "old reason should be gone: {body}"
    );
}

#[test]
fn ssh_add_rejects_invalid_public_key() {
    let (dir, _config) = sandbox();
    let out = run_secreq(
        dir.path(),
        &[
            "ssh-add",
            "github",
            "--public-key",
            "not a key",
            "--private-key",
            "secret://op/Private/GitHub/private key",
        ],
    );
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("neither an existing file") || stderr.contains("OpenSSH public key"),
        "stderr: {stderr}"
    );
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
    assert!(!expected.exists(), "log-path must not create the log file");
}
