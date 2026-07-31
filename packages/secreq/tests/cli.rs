//! End-to-end tests driving the built `secreq` binary against the per-binary
//! wrap model. Each test isolates config, state, and sockets through
//! [`common::Sandbox`] so it can't touch the developer's real
//! `~/.config/secreq` or `~/.local/state/secreq` — see `tests/common/mod.rs`
//! for why each environment variable is pinned or removed.
//!
//! A `printf`/`sh` "fake provider" stands in for real stores so the tests
//! never trigger Touch ID / `op` biometrics.

// Every line in this crate is test code, so an `unwrap` is an assertion —
// which is what `clippy.toml`'s `allow-unwrap-in-tests` already says. That key
// only reaches inside a `#[test]` fn, and an integration test has no
// `#[cfg(test)]` module for it to recognise, so the setup helpers the tests
// call fall outside it. Said once here rather than at each helper.
#![allow(clippy::unwrap_used)]

mod common;

use common::Sandbox;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

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
        r#"
            shim_dir = "{shim}"

            [wraps.gh]
            reason = "GitHub API access"
            env.GITHUB_TOKEN = "secret://fake/the-token-value"

            [providers.fake]
            retrieve = ["printf", "%s", "{{locator}}"]
        "#,
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
    let mut perms = fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&path, perms).unwrap();
}

fn install_survivor(bin_dir: &Path) -> PathBuf {
    fs::create_dir_all(bin_dir).unwrap();
    let path = bin_dir.join("secreq-test-survivor");
    fs::write(
        &path,
        "#!/bin/sh\n\
         trap 'printf hup > \"$2\"; exit 97' HUP\n\
         printf '%s' \"$$\" > \"$1\"\n\
         while :; do sleep 1; done\n",
    )
    .unwrap();
    let mut perms = fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&path, perms).unwrap();
    path
}

fn install_background_gh(bin_dir: &Path, survivor: &Path) {
    let path = bin_dir.join("gh");
    fs::write(
        &path,
        format!(
            "#!/bin/sh\n\
             \"{}\" \"$1\" \"$2\" \"$GITHUB_TOKEN\" </dev/null >/dev/null 2>&1 &\n\
             while [ ! -s \"$1\" ]; do sleep 0.01; done\n",
            survivor.display()
        ),
    )
    .unwrap();
    let mut perms = fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&path, perms).unwrap();
}

fn wait_for_survivor_pid(path: &Path) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(text) = fs::read_to_string(path) {
            if let Ok(pid) = text.parse() {
                return pid;
            }
        }
        assert!(
            Instant::now() < deadline,
            "survivor never wrote its pid to {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn process_is_alive(pid: u32) -> bool {
    let result = unsafe { libc::kill(pid.cast_signed(), 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

struct SurvivorGuard(u32);

impl Drop for SurvivorGuard {
    fn drop(&mut self) {
        let _ = unsafe { libc::kill(self.0.cast_signed(), libc::SIGTERM) };
    }
}

fn survivor_audit_record(sb: &Sandbox, pid: u32) -> serde_json::Value {
    let log = fs::read_to_string(sb.root().join("audit.log")).expect("read audit log");
    log.lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find(|row| {
            row.get("event").and_then(serde_json::Value::as_str) == Some("background_survivors")
                && row
                    .get("survivors")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|survivors| {
                        survivors.iter().any(|survivor| {
                            survivor.get("pid").and_then(serde_json::Value::as_u64)
                                == Some(u64::from(pid))
                        })
                    })
        })
        .unwrap_or_else(|| panic!("no survivor audit row for pid {pid}; log:\n{log}"))
}

// ── wrap-and-run ──────────────────────────────────────────────────────────

#[test]
fn wrap_run_injects_env_and_masks_output_when_token_is_echoed() {
    let sb = Sandbox::new();
    let bin_dir = sb.path().join("realbin");
    let shim_dir = sb.path().join("shims");
    install_fake_gh(&bin_dir);
    write_config(&sb.config_path(), &echo_provider_config(&shim_dir));

    // Put the fake gh on PATH so secreq's find_real_binary picks it up.
    let path = format!("{}:{}", bin_dir.display(), std::env::var("PATH").unwrap());
    let out = sb
        .cmd(&["x", "--sq-yes", "gh", "auth", "status"])
        .env("PATH", &path)
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
    let sb = Sandbox::new();
    let bin_dir = sb.path().join("realbin");
    let shim_dir = sb.path().join("shims");
    install_fake_gh(&bin_dir);
    write_config(&sb.config_path(), &echo_provider_config(&shim_dir));
    let path = format!("{}:{}", bin_dir.display(), std::env::var("PATH").unwrap());

    let out = sb
        .cmd(&["x", "--sq-yes", "--sq-raw", "gh"])
        .env("PATH", &path)
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
fn piped_run_reports_and_preserves_a_background_process() {
    let sb = Sandbox::new();
    let bin_dir = sb.path().join("realbin");
    let shim_dir = sb.path().join("shims");
    let survivor = install_survivor(&bin_dir);
    install_background_gh(&bin_dir, &survivor);
    write_config(&sb.config_path(), &echo_provider_config(&shim_dir));
    let pid_file = sb.path().join("piped-survivor.pid");
    let hup_file = sb.path().join("piped-survivor.hup");
    let path = format!("{}:{}", bin_dir.display(), std::env::var("PATH").unwrap());

    let out = sb
        .cmd(&[
            "x",
            "--sq-yes",
            "gh",
            pid_file.to_str().unwrap(),
            hup_file.to_str().unwrap(),
        ])
        .env("PATH", path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let pid = wait_for_survivor_pid(&pid_file);
    let _guard = SurvivorGuard(pid);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let survivor_lines: Vec<&str> = stderr
        .lines()
        .filter(|line| line.contains("background process"))
        .collect();
    assert_eq!(
        survivor_lines.len(),
        1,
        "expected one survivor line; stderr:\n{stderr}"
    );
    assert!(survivor_lines[0].contains(&pid.to_string()));
    assert!(survivor_lines[0].contains("secreq-test-survivor"));
    assert!(
        !stderr.contains("the-token-value"),
        "survivor report leaked the injected value: {stderr}"
    );

    std::thread::sleep(Duration::from_millis(200));
    assert!(process_is_alive(pid), "secreq killed piped survivor {pid}");
    assert!(
        !hup_file.exists(),
        "piped survivor received SIGHUP from secreq"
    );
    let audit = survivor_audit_record(&sb, pid);
    assert_eq!(
        audit.get("reach").and_then(serde_json::Value::as_str),
        Some("child_session_or_process_group")
    );
    assert!(
        !audit.to_string().contains("the-token-value"),
        "survivor audit leaked the injected value: {audit}"
    );
}

#[test]
fn pty_run_reports_and_preserves_a_background_process() {
    let sb = Sandbox::new();
    let bin_dir = sb.path().join("realbin");
    let shim_dir = sb.path().join("shims");
    let survivor = install_survivor(&bin_dir);
    install_background_gh(&bin_dir, &survivor);
    write_config(&sb.config_path(), &echo_provider_config(&shim_dir));
    let pid_file = sb.path().join("pty-survivor.pid");
    let hup_file = sb.path().join("pty-survivor.hup");
    let path = format!("{}:{}", bin_dir.display(), std::env::var("PATH").unwrap());
    let mut command = sb.cmd(&[
        "x",
        "--sq-yes",
        "gh",
        pid_file.to_str().unwrap(),
        hup_file.to_str().unwrap(),
    ]);
    command.env("PATH", path);
    let mut run = common::pty::PtyRun::spawn_with(command);

    let pid = wait_for_survivor_pid(&pid_file);
    let _guard = SurvivorGuard(pid);
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        !hup_file.exists(),
        "pty survivor received SIGHUP before secreq reported it"
    );
    // The harness drains the outer PTY on its own reader thread. Under a busy
    // suite the process can exit before that thread has copied the final line,
    // so wait on the report itself before inspecting the completed transcript.
    run.wait_for("background processes still running", Duration::from_secs(5));
    let status = run.wait_exit(Duration::from_secs(5));
    assert!(
        status.success(),
        "output:\n{}",
        String::from_utf8_lossy(&run.output_so_far())
    );
    let output_bytes = run.output_so_far();
    let output = String::from_utf8_lossy(&output_bytes);
    let survivor_lines: Vec<&str> = output
        .lines()
        .filter(|line| line.contains("background process"))
        .collect();
    assert_eq!(
        survivor_lines.len(),
        1,
        "expected one survivor line; output:\n{output}"
    );
    assert!(survivor_lines[0].contains(&pid.to_string()));
    assert!(survivor_lines[0].contains("secreq-test-survivor"));
    assert!(
        !output.contains("the-token-value"),
        "survivor report leaked the injected value: {output}"
    );

    std::thread::sleep(Duration::from_millis(200));
    assert!(process_is_alive(pid), "secreq killed pty survivor {pid}");
    assert!(
        !hup_file.exists(),
        "pty survivor received SIGHUP from secreq"
    );
    let audit = survivor_audit_record(&sb, pid);
    assert!(
        !audit.to_string().contains("the-token-value"),
        "survivor audit leaked the injected value: {audit}"
    );
}

#[test]
fn run_without_a_survivor_emits_no_survivor_line_or_audit_record() {
    let sb = Sandbox::new();
    let bin_dir = sb.path().join("realbin");
    let shim_dir = sb.path().join("shims");
    install_fake_gh(&bin_dir);
    write_config(&sb.config_path(), &echo_provider_config(&shim_dir));
    let path = format!("{}:{}", bin_dir.display(), std::env::var("PATH").unwrap());
    let out = sb
        .cmd(&["x", "--sq-yes", "gh"])
        .env("PATH", path)
        .output()
        .unwrap();
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("background process"), "stderr:\n{stderr}");

    let audit_path = sb.root().join("audit.log");
    if let Ok(log) = fs::read_to_string(audit_path) {
        assert!(!log.contains("\"event\":\"background_survivors\""));
    }
}

/// Run `secreq x` with the fake-`gh` sandbox wired up: fake binary on PATH,
/// echo provider config in place, daemon disabled.
fn run_x(sb: &Sandbox, bin_dir: &Path, args: &[&str]) -> std::process::Output {
    run_x_env(sb, bin_dir, args, &[])
}

/// [`run_x`], with extra env vars set on the secreq process — for the
/// parent-env-satisfaction tests, which hinge on what secreq inherits.
/// `Sandbox::cmd` removes `GITHUB_TOKEN` (the developer's real token must
/// never satisfy — or leak into — a test wrap), and the extras here win
/// because later `.env()` calls override.
fn run_x_env(
    sb: &Sandbox,
    bin_dir: &Path,
    args: &[&str],
    envs: &[(&str, &str)],
) -> std::process::Output {
    let path = format!("{}:{}", bin_dir.display(), std::env::var("PATH").unwrap());
    let mut cmd = sb.cmd(args);
    cmd.env("PATH", &path);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.output().unwrap()
}

/// Sandbox + fake gh + echo-provider config, for the `x` argv-contract tests.
/// Returns `(sandbox, bin_dir)`; the config lives at the sandbox default path.
fn x_fixture() -> (Sandbox, PathBuf) {
    let sb = Sandbox::new();
    let bin_dir = sb.path().join("realbin");
    let shim_dir = sb.path().join("shims");
    install_fake_gh(&bin_dir);
    write_config(&sb.config_path(), &echo_provider_config(&shim_dir));
    (sb, bin_dir)
}

// ── parent-env satisfaction: already-present secrets need no consent ──────

#[test]
fn x_skips_consent_when_parent_env_already_holds_real_values() {
    let (sb, bin_dir) = x_fixture();
    // No --sq-yes and no daemon: if secreq asked for consent, this would
    // fail. With GITHUB_TOKEN already carrying a real (non-marker) value,
    // there is nothing to inject, so the run must pass straight through.
    let out = run_x_env(
        &sb,
        &bin_dir,
        &["x", "gh", "auth", "status"],
        &[("GITHUB_TOKEN", "already-present-value")],
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("argv=auth status"), "got: {stdout}");
    // The parent's value flows through untouched — secreq released nothing,
    // so there is nothing of its own to mask.
    assert!(
        stdout.contains("GITHUB_TOKEN=already-present-value"),
        "got: {stdout}"
    );
}

#[test]
fn x_still_gates_when_parent_env_value_is_a_secret_marker() {
    let (sb, bin_dir) = x_fixture();
    // A `secret://…` marker is a request FOR injection, not a value —
    // consent is still required, and with the daemon disabled that fails.
    let out = run_x_env(
        &sb,
        &bin_dir,
        &["x", "gh"],
        &[("GITHUB_TOKEN", "secret://fake/the-token-value")],
    );
    assert!(!out.status.success());
}

#[test]
fn x_still_gates_when_parent_env_value_is_empty() {
    let (sb, bin_dir) = x_fixture();
    // An empty string is "not present" for satisfaction purposes.
    let out = run_x_env(&sb, &bin_dir, &["x", "gh"], &[("GITHUB_TOKEN", "")]);
    assert!(!out.status.success());
}

#[test]
fn x_resolves_only_the_env_vars_the_parent_is_missing() {
    let sb = Sandbox::new();
    let bin_dir = sb.path().join("realbin");
    let shim_dir = sb.path().join("shims");
    // A wrap with two secrets; the fake binary echoes both.
    write_config(
        &sb.config_path(),
        &format!(
            r#"
                shim_dir = "{shim}"

                [wraps.gh]
                env.GITHUB_TOKEN = "secret://fake/the-token-value"
                env.EXTRA_SECRET = "secret://fake/extra-value"

                [providers.fake]
                retrieve = ["printf", "%s", "{{locator}}"]
            "#,
            shim = shim_dir.display(),
        ),
    );
    fs::create_dir_all(&bin_dir).unwrap();
    let fake = bin_dir.join("gh");
    fs::write(
        &fake,
        "#!/bin/sh\necho \"GITHUB_TOKEN=$GITHUB_TOKEN\"\necho \"EXTRA_SECRET=$EXTRA_SECRET\"\n",
    )
    .unwrap();
    let mut perms = fs::metadata(&fake).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&fake, perms).unwrap();

    // GITHUB_TOKEN is satisfied by the parent; EXTRA_SECRET is not, so the
    // run still needs approval (--sq-yes here) and resolves ONLY the
    // missing var. The satisfied one keeps the parent's value, unmasked;
    // the resolved one is injected and masked.
    let out = run_x_env(
        &sb,
        &bin_dir,
        &["x", "--sq-yes", "gh"],
        &[("GITHUB_TOKEN", "parent-token-value")],
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("GITHUB_TOKEN=parent-token-value"),
        "got: {stdout}"
    );
    assert!(
        stdout.contains("EXTRA_SECRET=********"),
        "expected the missing var resolved and masked; got: {stdout}"
    );
    assert!(!stdout.contains("extra-value"), "got: {stdout}");
}

// ── `x` argv contract: everything after the wrap name belongs to the binary ──

#[test]
fn x_forwards_leading_help_flag_to_the_binary() {
    let (sb, bin_dir) = x_fixture();
    let out = run_x(&sb, &bin_dir, &["x", "--sq-yes", "gh", "--help"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("argv=--help"), "got: {stdout}");
}

#[test]
fn x_forwards_flags_secreq_used_to_intercept() {
    let (sb, bin_dir) = x_fixture();
    // Every one of these used to be eaten by clap (`--config` even swallowed
    // the following token). All must now reach the binary verbatim.
    let out = run_x(
        &sb,
        &bin_dir,
        &["x", "--sq-yes", "gh", "--raw", "-y", "--config", "somefile"],
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("argv=--raw -y --config somefile"),
        "got: {stdout}"
    );
    // `--raw` went to the binary, NOT to secreq: output is still masked.
    assert!(stdout.contains("GITHUB_TOKEN=********"), "got: {stdout}");
}

#[test]
fn x_recognizes_sq_flags_after_the_wrap_name() {
    let (sb, bin_dir) = x_fixture();
    // The shim prepends `x <wrap>`, so a user's `gh --sq-raw …` arrives with
    // the sq-flags after the wrap name. They must still apply to secreq.
    let out = run_x(&sb, &bin_dir, &["x", "gh", "--sq-yes", "--sq-raw", "auth"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("argv=auth"), "got: {stdout}");
    assert!(
        stdout.contains("GITHUB_TOKEN=the-token-value"),
        "got: {stdout}"
    );
}

#[test]
fn x_rejects_unknown_sq_flags() {
    let (sb, bin_dir) = x_fixture();
    let out = run_x(&sb, &bin_dir, &["x", "gh", "--sq-bogus"]);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--sq-bogus"), "got: {stderr}");
}

#[test]
fn x_double_dash_stops_sq_extraction() {
    let (sb, bin_dir) = x_fixture();
    let out = run_x(&sb, &bin_dir, &["x", "--sq-yes", "gh", "--", "--sq-raw"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // The `--` and everything after it forward verbatim; `--sq-raw` was NOT
    // applied to secreq, so output stays masked.
    assert!(stdout.contains("argv=-- --sq-raw"), "got: {stdout}");
    assert!(stdout.contains("GITHUB_TOKEN=********"), "got: {stdout}");
}

#[test]
fn x_sq_config_selects_the_config_file() {
    // Config lives ONLY at a non-default path; --sq-config must find it.
    let sb = Sandbox::new();
    let bin_dir = sb.path().join("realbin");
    let shim_dir = sb.path().join("shims");
    install_fake_gh(&bin_dir);
    let alt = sb.path().join("alt-wraps.json5");
    write_config(&alt, &echo_provider_config(&shim_dir));
    let out = run_x(
        &sb,
        &bin_dir,
        &["x", "--sq-yes", "--sq-config", alt.to_str().unwrap(), "gh"],
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("GITHUB_TOKEN=********"), "got: {stdout}");
}

#[test]
fn x_without_a_wrap_name_prints_usage() {
    let (sb, bin_dir) = x_fixture();
    let out = run_x(&sb, &bin_dir, &["x"]);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--sq-"), "got: {stderr}");
}

#[test]
fn x_sq_help_prints_help() {
    let (sb, bin_dir) = x_fixture();
    let out = run_x(&sb, &bin_dir, &["x", "--sq-help"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--sq-raw"), "got: {stdout}");
    assert!(stdout.contains("--sq-config"), "got: {stdout}");
}

#[test]
fn global_flags_before_x_point_at_the_sq_form() {
    let (sb, bin_dir) = x_fixture();
    // `secreq --yes x gh` reaches clap (argv[1] != "x"); the stub arm must
    // reject it with a pointer to the reserved-prefix form rather than
    // silently dropping flags or forwarding wrong args.
    let out = run_x(&sb, &bin_dir, &["--yes", "x", "gh"]);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--sq-"), "got: {stderr}");
}

#[test]
fn unwrapped_binary_passes_through_unchanged() {
    let sb = Sandbox::new();
    let bin_dir = sb.path().join("realbin");
    let shim_dir = sb.path().join("shims");
    install_fake_gh(&bin_dir);
    // Config has shim_dir but NO wrap for `gh`.
    write_config(
        &sb.config_path(),
        &format!("shim_dir = \"{}\"\n", shim_dir.display()),
    );
    let path = format!("{}:{}", bin_dir.display(), std::env::var("PATH").unwrap());

    let out = sb
        .cmd(&["x", "gh", "passthrough-args"])
        .env("PATH", &path)
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
    let sb = Sandbox::new();
    let bin_dir = sb.path().join("realbin");
    let shim_dir = sb.path().join("shims");
    install_fake_gh(&bin_dir);
    write_config(&sb.config_path(), &echo_provider_config(&shim_dir));
    let path = format!("{}:{}", bin_dir.display(), std::env::var("PATH").unwrap());

    // No --yes; the sandbox's SECREQ_NO_DAEMON default forces fail-closed
    // without contacting the daemon (which would otherwise pop a GUI window).
    let out = sb.cmd(&["x", "gh"]).env("PATH", &path).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Child must not have run.
    assert!(!stdout.contains("argv="));
}

#[test]
fn bare_unknown_command_is_not_a_wrap() {
    // With the external-subcommand catch-all gone, a bare `secreq gh` is no
    // longer wrap-and-run — clap rejects it as an unrecognized subcommand.
    // Wrap execution now lives behind the explicit `secreq x gh` form.
    let sb = Sandbox::new();
    let bin_dir = sb.path().join("realbin");
    let shim_dir = sb.path().join("shims");
    install_fake_gh(&bin_dir);
    write_config(&sb.config_path(), &echo_provider_config(&shim_dir));
    let path = format!("{}:{}", bin_dir.display(), std::env::var("PATH").unwrap());

    let out = sb
        .cmd(&["gh", "auth", "status"])
        .env("PATH", &path)
        .output()
        .unwrap();
    assert!(!out.status.success(), "bare `secreq gh` should not succeed");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unrecognized subcommand"),
        "expected a clap unrecognized-subcommand error; got: {stderr}"
    );
    // The wrapped binary must not have run.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("argv="), "child ran; got: {stdout}");
}

#[test]
fn bare_secreq_without_terminal_prints_usage_hint() {
    // `Sandbox::run` drives the binary with piped stdio, so stdin/stdout are
    // never a TTY. Bare `secreq` must then skip the interactive picker and
    // keep the deterministic usage hint + exit 2 that shims and CI rely on.
    let sb = Sandbox::new();
    let out = sb.run(&[]);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("missing command"),
        "expected the missing-command hint; got: {stderr}"
    );
}

#[test]
fn ui_alias_routes_identically_to_view() {
    // `secreq ui` is a clap alias of `secreq view`, so both must reach the
    // same viewer handler. With the daemon disabled the handler bails the
    // same way for both — identical exit code and stderr proves the routing.
    let sb = Sandbox::new();
    let ui = sb.run(&["ui"]);
    let view = sb.run(&["view"]);
    assert_eq!(
        ui.status.code(),
        view.status.code(),
        "ui and view should share an exit code"
    );
    assert_eq!(
        ui.stderr, view.stderr,
        "ui and view should produce identical output"
    );
    let stderr = String::from_utf8_lossy(&ui.stderr);
    assert!(
        stderr.contains("SECREQ_NO_DAEMON"),
        "expected the daemon-disabled error from the viewer handler; got: {stderr}"
    );
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
    let sb = Sandbox::new();
    let shim_dir = sb.path().join("shims");
    fs::create_dir_all(&shim_dir).unwrap();
    write_config(
        &sb.config_path(),
        &format!("shim_dir = \"{}\"\n", shim_dir.display()),
    );

    let out = sb.run(&[
        "wrap",
        "--env",
        "GITHUB_TOKEN=secret://op/Personal/GitHub/credential",
        "gh",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // And `check` against the resulting config — which uses the same overlay
    // path — must agree the `op` provider is known.
    let check = sb.run(&["check"]);
    assert!(check.status.success());
    let stdout = String::from_utf8_lossy(&check.stdout);
    assert!(stdout.contains("config OK"), "got: {stdout}");
}

#[test]
fn wrap_records_config_and_drops_shim() {
    let sb = Sandbox::new();
    let config = sb.config_path();
    let shim_dir = sb.path().join("shims");
    fs::create_dir_all(&shim_dir).unwrap();
    write_config(&config, &format!("shim_dir = \"{}\"\n", shim_dir.display()));

    let out = sb.run(&[
        "wrap",
        "--env",
        "GITHUB_TOKEN=secret://op/Personal/GH/credential",
        "--reason",
        "GitHub",
        "gh",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Config has the new wrap.
    let body = fs::read_to_string(&config).unwrap();
    assert!(body.contains("[wraps.gh]"), "got: {body}");
    assert!(body.contains("secret://op/Personal/GH/credential"));
    // Shim exists with our sentinel.
    let shim = shim_dir.join("gh");
    assert!(shim.is_file());
    let shim_body = fs::read_to_string(&shim).unwrap();
    assert!(shim_body.contains("secreq-managed-shim"));
    // Absolute path, not a bare `secreq`: a bare name would resolve
    // through whatever PATH the caller had.
    assert!(shim_body.contains("x 'gh' \"$@\""), "got: {shim_body}");
    assert!(
        !shim_body.contains("exec secreq "),
        "shim must not resolve secreq by bare name: {shim_body}"
    );
}

#[test]
fn wrap_with_no_env_creates_a_gate_only_wrap() {
    // `secreq wrap op` with no `--env` and no terminal (the test harness
    // has no TTY) creates a gate-only wrap: consent is required, nothing
    // is injected. This is how you gate a tool like `op`.
    let sb = Sandbox::new();
    let config = sb.config_path();
    let shim_dir = sb.path().join("shims");
    fs::create_dir_all(&shim_dir).unwrap();
    write_config(&config, &format!("shim_dir = \"{}\"\n", shim_dir.display()));

    let out = sb.run(&["wrap", "--reason", "1Password vault access", "op"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("gate-only"), "got: {stdout}");

    // Config has the wrap with an empty env (gate-only) and the reason.
    let body = fs::read_to_string(&config).unwrap();
    assert!(body.contains("[wraps.op]"), "got: {body}");
    assert!(body.contains("1Password vault access"));
    // No secret references made it in.
    assert!(!body.contains("secret://"), "got: {body}");

    // The config round-trips and `check` is happy with a gate-only wrap.
    let check = sb.run(&["check"]);
    assert!(
        check.status.success(),
        "check stderr: {}",
        String::from_utf8_lossy(&check.stderr)
    );

    // Shim exists with our sentinel.
    let shim = shim_dir.join("op");
    assert!(shim.is_file());
    let shim_body = fs::read_to_string(&shim).unwrap();
    // Absolute path, not a bare `secreq`: a bare name would resolve
    // through whatever PATH the caller had.
    assert!(shim_body.contains("x 'op' \"$@\""), "got: {shim_body}");
    assert!(
        !shim_body.contains("exec secreq "),
        "shim must not resolve secreq by bare name: {shim_body}"
    );
}

#[test]
fn gate_only_wrap_denies_without_terminal_or_yes() {
    // Running a gated `op` with no consent path available (SECREQ_NO_DAEMON
    // + no --yes) must fail closed: exit 1, and `op` itself must not run.
    let sb = Sandbox::new();
    let bin_dir = sb.path().join("realbin");
    let shim_dir = sb.path().join("shims");
    fs::create_dir_all(&bin_dir).unwrap();
    // A fake `op` that announces itself if it ever runs.
    let op_path = bin_dir.join("op");
    fs::write(&op_path, "#!/bin/sh\necho \"op-ran args=$*\"\n").unwrap();
    let mut perms = fs::metadata(&op_path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&op_path, perms).unwrap();

    write_config(
        &sb.config_path(),
        &format!(
            "shim_dir = \"{}\"\n\n[wraps.op]\nreason = \"1Password vault access\"\n",
            shim_dir.display()
        ),
    );
    let path = format!("{}:{}", bin_dir.display(), std::env::var("PATH").unwrap());

    let out = sb
        .cmd(&["x", "op", "read", "op://Personal/AWS/credential"])
        .env("PATH", &path)
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
    let sb = Sandbox::new();
    let bin_dir = sb.path().join("realbin");
    let shim_dir = sb.path().join("shims");
    fs::create_dir_all(&bin_dir).unwrap();
    let op_path = bin_dir.join("op");
    fs::write(&op_path, "#!/bin/sh\necho \"op-ran args=$*\"\n").unwrap();
    let mut perms = fs::metadata(&op_path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&op_path, perms).unwrap();

    write_config(
        &sb.config_path(),
        &format!(
            "shim_dir = \"{}\"\n\n[wraps.op]\nreason = \"1Password vault access\"\n",
            shim_dir.display()
        ),
    );
    let path = format!("{}:{}", bin_dir.display(), std::env::var("PATH").unwrap());

    let out = sb
        .cmd(&["x", "op", "read", "op://Personal/AWS/credential"])
        .env("PATH", &path)
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
    let sb = Sandbox::new();
    let config = sb.config_path();
    let shim_dir = sb.path().join("shims");
    fs::create_dir_all(&shim_dir).unwrap();
    write_config(&config, &format!("shim_dir = \"{}\"\n", shim_dir.display()));
    sb.run(&["wrap", "--env", "X=secret://op/x", "gh"]);
    assert!(shim_dir.join("gh").is_file());

    let out = sb.run(&["unwrap", "gh"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!shim_dir.join("gh").exists());
    let body = fs::read_to_string(&config).unwrap();
    assert!(
        !body.contains("[wraps.gh]"),
        "gh should be gone from config: {body}"
    );
}

#[test]
fn wraps_list_shows_configured_wraps() {
    let sb = Sandbox::new();
    let shim_dir = sb.path().join("shims");
    fs::create_dir_all(&shim_dir).unwrap();
    write_config(
        &sb.config_path(),
        &format!(
            r#"
                shim_dir = "{}"

                [wraps.gh]
                reason = "GitHub"
                env.GITHUB_TOKEN = "secret://op/gh"

                [wraps.aws]
                env.AWS_KEY = "secret://op/aws/k"
                env.AWS_SECRET = "secret://op/aws/s"
            "#,
            shim_dir.display()
        ),
    );
    let out = sb.run(&["wraps"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("gh — GitHub"));
    assert!(stdout.contains("aws"));
    // The provider, and the lifetime the value is cached for — the default
    // being the daemon's own, which is what an undeclared secret gets.
    assert!(stdout.contains("GITHUB_TOKEN (op, ttl daemon lifetime)"));
    assert!(stdout.contains("AWS_KEY (op, ttl daemon lifetime)"));
    // Values never appear.
    assert!(!stdout.contains("secret://"));
}

#[test]
fn doctor_flags_when_a_shim_is_shadowed_by_an_earlier_path_entry() {
    // Reproduces the homebrew-shadows-our-shim case: shim_dir is on PATH
    // but a higher-priority dir (`realbin`, in this stand-in) contains
    // another `gh` that resolves first.
    let sb = Sandbox::new();
    let bin_dir = sb.path().join("realbin");
    let shim_dir = sb.path().join("shims");
    install_fake_gh(&bin_dir);
    fs::create_dir_all(&shim_dir).unwrap();
    write_config(
        &sb.config_path(),
        &format!(
            r#"
                shim_dir = "{}"

                [wraps.gh]
                env.GITHUB_TOKEN = "secret://op/gh"
            "#,
            shim_dir.display(),
        ),
    );
    // Drop the shim manually (skip running `wrap` here — focused test).
    fs::write(
        shim_dir.join("gh"),
        "#!/bin/sh\n# secreq-managed-shim: wrap=gh\nexec secreq x gh \"$@\"\n",
    )
    .unwrap();
    fs::set_permissions(shim_dir.join("gh"), std::fs::Permissions::from_mode(0o755)).unwrap();

    // PATH order: realbin first → shim_dir second → system. Homebrew analogue.
    let path = format!(
        "{}:{}:{}",
        bin_dir.display(),
        shim_dir.display(),
        std::env::var("PATH").unwrap()
    );
    let out = sb.cmd(&["doctor"]).env("PATH", &path).output().unwrap();
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
    let sb = Sandbox::new();
    let shim_dir = sb.path().join("shims");
    fs::create_dir_all(&shim_dir).unwrap();
    write_config(
        &sb.config_path(),
        &format!(
            r#"
                shim_dir = "{}"

                [wraps.gh]
                env.GITHUB_TOKEN = "secret://op/gh"
            "#,
            shim_dir.display(),
        ),
    );
    fs::write(
        shim_dir.join("gh"),
        "#!/bin/sh\n# secreq-managed-shim: wrap=gh\nexec secreq x gh \"$@\"\n",
    )
    .unwrap();
    fs::set_permissions(shim_dir.join("gh"), std::fs::Permissions::from_mode(0o755)).unwrap();

    // PATH order: shim_dir first.
    let path = format!("{}:{}", shim_dir.display(), std::env::var("PATH").unwrap());
    let out = sb.cmd(&["doctor"]).env("PATH", &path).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("gh → "), "got: {stdout}");
    assert!(stdout.contains("(shim)"), "got: {stdout}");
}

#[test]
fn check_passes_on_a_well_formed_config() {
    let sb = Sandbox::new();
    write_config(
        &sb.config_path(),
        "[wraps.gh]\nenv.GITHUB_TOKEN = \"secret://op/gh\"\n",
    );
    let out = sb.run(&["check"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("config OK"));
}

#[test]
fn check_flags_unknown_provider_in_a_wrap() {
    let sb = Sandbox::new();
    write_config(
        &sb.config_path(),
        "[wraps.gh]\nenv.X = \"secret://made-up-provider/loc\"\n",
    );
    let out = sb.run(&["check"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stdout).contains("unknown provider scheme"));
}

// ── init (auto-PATH setup) ────────────────────────────────────────────────

#[test]
fn init_writes_config_with_shim_dir() {
    let sb = Sandbox::new();
    let config = sb.config_path();
    let shim_dir = sb.path().join("local/bin");
    // SHELL=zsh + a fake HOME inside the sandbox would let us test the
    // PATH-update path; here we go through `Unknown` (the sandbox removes
    // SHELL) which means the auto-update is skipped (caveat printed instead).
    let out = sb
        .cmd(&["init", "--shim-dir", shim_dir.to_str().unwrap()])
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

/// Every directory beneath `root`, including `root` itself, deepest last.
fn dirs_under(root: &Path) -> Vec<PathBuf> {
    let mut found = vec![root.to_path_buf()];
    let mut queue = vec![root.to_path_buf()];
    while let Some(dir) = queue.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            // `symlink_metadata`: a symlink into the tree is not a directory
            // we created and its target's mode is not ours to judge.
            if fs::symlink_metadata(&path).unwrap().is_dir() {
                found.push(path.clone());
                queue.push(path);
            }
        }
    }
    found
}

/// A fresh install must not leave a directory anyone else can write to under
/// `$SECREQ_HOME` — not for a moment, and least of all for the stretch
/// between `init` finishing and the daemon first starting.
///
/// `paths::ensure_private_dir` narrows the root, but it was only ever reached
/// from the audit writer, the daemon's log and the socket bind — so the
/// narrowing was *lazy*. Everything that ran before one of those (the
/// migration runner, `init` writing `wraps.json5`) created the root with a
/// bare `create_dir_all`, which takes the umask's answer: 0755 under the
/// common 022 and **0777** under the `umask 000` that CI and container images
/// routinely set. That directory holds the audit log, the auto-rules and the
/// wrap config, so anyone on the box could add a rule that approves their own
/// command.
///
/// Two deliberate choices, both of which an earlier version of this kind of
/// test got wrong:
///
/// - **The child runs under `umask 000`.** A developer whose shell sets 077
///   gets 0700 from `create_dir_all` for free, and the assertion would pass
///   while proving nothing.
/// - **The mode is asserted exactly.** `mode & 0o022 == 0` is satisfied by
///   the 0755 a umask-022 machine hands out, which is the bug wearing a
///   passing test.
#[test]
fn a_fresh_init_leaves_no_directory_others_can_write_under_the_root() {
    let sb = Sandbox::new();
    // A root that does not exist yet. `Sandbox` pre-creates its own, which
    // would hide the half of this that is about *creating* the directory.
    let root = sb.path().join("fresh-root");

    let mut cmd = sb.cmd(&["init"]);
    cmd.env("SECREQ_HOME", &root);
    // SAFETY: `umask` is async-signal-safe and touches only the child.
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            libc::umask(0);
            Ok(())
        });
    }

    let mut run = common::pty::PtyRun::spawn_with(cmd);
    // The sandbox strips `$SHELL`, so `init` takes its unrecognized-shell
    // branch and prints the export line instead of prompting to append it.
    // That leaves two prompts: the shim dir, and the SSH-agent offer.
    run.wait_for(
        "Where should secreq drop PATH shims?",
        Duration::from_secs(30),
    );
    run.press_enter();
    run.wait_for(
        "Also set up secreq as your SSH agent?",
        Duration::from_secs(30),
    );
    run.write_bytes(b"n"); // a cliclack confirm submits on y/n
    let status = run.wait_exit(Duration::from_secs(30));
    assert!(
        status.success(),
        "init exited with {status:?}; output:\n{}",
        String::from_utf8_lossy(&run.output_so_far())
    );

    assert!(root.is_dir(), "init should have created {}", root.display());
    let dirs = dirs_under(&root);
    // The default shim dir lives in the root, so a run that only made the
    // root means the flow did not get as far as this test believes.
    assert!(
        dirs.len() >= 2,
        "expected the root and at least the shim dir, got {dirs:?}"
    );
    for dir in dirs {
        let mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "{} is {mode:o}", dir.display());
    }
}

/// The window opens before `init` does. `cli::run` runs the pending
/// migrations first, and on a fresh install that is what creates the root —
/// so a user whose first command is `secreq wrap gh` never reaches `init`'s
/// hardening. The mode the migration runner leaves is the mode the root has.
#[test]
fn the_root_a_first_command_creates_is_owner_only() {
    let sb = Sandbox::new();
    let root = sb.path().join("fresh-root");

    let mut cmd = sb.cmd(&["check"]);
    cmd.env("SECREQ_HOME", &root);
    // SAFETY: `umask` is async-signal-safe and touches only the child.
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            libc::umask(0);
            Ok(())
        });
    }
    // Whether `check` itself succeeds without a config is beside the point:
    // the root is created before any command sees control.
    cmd.output().unwrap();

    assert!(
        root.is_dir(),
        "nothing created {} — the migration runner is no longer the first \
         thing to make the root, so this test no longer pins anything",
        root.display()
    );
    let mode = fs::metadata(&root).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700, "{} is {mode:o}", root.display());
}

/// The other half of the same finding: an install that predates any of this
/// already has a root at whatever its creator left, and nothing narrows it
/// until the first audit write or daemon start. `init` is the command a user
/// runs to fix their setup, so it is the one that has to repair the mode
/// rather than only get it right on a fresh directory.
#[test]
fn init_narrows_a_root_that_already_exists_too_permissively() {
    let sb = Sandbox::new();
    let root = sb.path().join("legacy-root");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();

    let mut cmd = sb.cmd(&["init"]);
    cmd.env("SECREQ_HOME", &root);
    let mut run = common::pty::PtyRun::spawn_with(cmd);
    run.wait_for(
        "Where should secreq drop PATH shims?",
        Duration::from_secs(30),
    );
    run.press_enter();
    run.wait_for(
        "Also set up secreq as your SSH agent?",
        Duration::from_secs(30),
    );
    run.write_bytes(b"n");
    let status = run.wait_exit(Duration::from_secs(30));
    assert!(
        status.success(),
        "init exited with {status:?}; output:\n{}",
        String::from_utf8_lossy(&run.output_so_far())
    );

    let mode = fs::metadata(&root).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700, "{} is {mode:o}", root.display());
}

/// Finding A8 covered `audit.log` **and** `auto-rules.toml`; only the first
/// was actually fixed. `rules::save_rules` still staged through `fs::write`,
/// so the rename published the staging file's `0666 & !umask` — and under the
/// `umask 000` that container and CI images routinely set, that is a
/// **world-writable** list of the commands which skip the consent prompt.
/// Anyone on the box could append a rule that auto-approves their own.
///
/// End-to-end rather than a unit test because the mode a unit test observes is
/// the mode the *test runner's* umask hands out: on a developer whose shell
/// sets 077 the old code produced 0600 by luck and the assertion proved
/// nothing. `pre_exec` sets the umask in the child only — never in the test
/// process, where it is global state two parallel tests would fight over.
///
/// `rules add-wasm` is the one CLI verb that reaches `save_rules`, so the
/// daemon it auto-spawns is doing the write. It never needs a window: no ask
/// is pending, so no consent child is spawned.
#[test]
fn a_rules_file_the_daemon_writes_under_a_lax_umask_is_owner_only() {
    let sb = Sandbox::new();
    // `daemon` is service-gated and refuses a fresh, unstamped root.
    sb.stamp_migrations();
    let module =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wasm_rules/always_pass.wasm");

    let mut cmd = sb.cmd_with_daemon(&[
        "rules",
        "add-wasm",
        module.to_str().unwrap(),
        "--secret",
        "GITHUB_TOKEN",
    ]);
    // SAFETY: `umask` is async-signal-safe and touches only the child.
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            libc::umask(0);
            Ok(())
        });
    }
    let out = cmd.output().unwrap();
    // Reap the daemon this test spawned before the sandbox tempdir goes.
    let _ = sb.cmd_with_daemon(&["daemon", "stop"]).output();
    assert!(
        out.status.success(),
        "rules add-wasm failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let rules_file = sb.root().join("auto-rules.toml");
    assert!(
        rules_file.is_file(),
        "the daemon should have written {}",
        rules_file.display()
    );
    // Exactly, not `mode & 0o022 == 0`: that passes on any 022 machine while
    // the file is still world-readable, which is the disclosure half of the
    // finding shipping under a green test.
    let mode = fs::metadata(&rules_file).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "{} is {mode:o}", rules_file.display());
}

/// The same defect on the config that is the bigger prize. `wraps.json5`
/// carries the `providers` block, and a provider is a **shell command secreq
/// runs** to fetch a secret — so a world-writable one is arbitrary code
/// execution as the user on the next resolve, not merely a disclosure of which
/// secrets exist.
///
/// It stayed hidden because every writer used `fs::write`, which preserves an
/// *existing* file's mode; only creation took the umask. Measured before the
/// fix, real binary, `umask 000`: `-rw-rw-rw-`.
///
/// `pre_exec` sets the umask in the child only — never in the test process,
/// where it is global state two parallel tests would fight over. The root is
/// one the sandbox has *not* pre-created, so the migration runner makes it and
/// the whole path, directory and file, is under test.
#[test]
fn a_wraps_file_ssh_add_creates_under_a_lax_umask_is_owner_only() {
    let sb = Sandbox::new();
    let root = sb.path().join("fresh-root");

    let mut cmd = sb.cmd(&[
        "ssh",
        "add",
        "work",
        "--public-key",
        TEST_ED25519_PUB,
        "--private-key",
        "secret://op/Private/GitHub/private key",
    ]);
    cmd.env("SECREQ_HOME", &root);
    // SAFETY: `umask` is async-signal-safe and touches only the child.
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            libc::umask(0);
            Ok(())
        });
    }
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "ssh add failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let config = root.join("config.toml");
    // Exactly, not `mode & 0o022 == 0`: that passes on any 022 machine while
    // the file is still world-readable, which is the disclosure half of the
    // finding shipping under a green test.
    let mode = fs::metadata(&config).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "{} is {mode:o}", config.display());
    // An owner-only file inside a directory anyone can write is still a file
    // anyone can replace by rename, so the root is half the claim.
    let dir_mode = fs::metadata(&root).unwrap().permissions().mode() & 0o777;
    assert_eq!(dir_mode, 0o700, "{} is {dir_mode:o}", root.display());
}

/// The third writer, and the one nothing else reaches: `secreq edit` seeds an
/// empty config when none exists before handing the path to `$EDITOR`. Same
/// `fs::write`, same 0666 under `umask 000` — and it is the writer a user hits
/// *first*, before any wrap or identity exists to write.
///
/// `$EDITOR=true` exits immediately, so the seed is all this exercises.
#[test]
fn the_config_secreq_edit_seeds_under_a_lax_umask_is_owner_only() {
    let sb = Sandbox::new();
    let root = sb.path().join("fresh-root");

    let mut cmd = sb.cmd(&["edit"]);
    cmd.env("SECREQ_HOME", &root);
    cmd.env("EDITOR", "true");
    // SAFETY: `umask` is async-signal-safe and touches only the child.
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            libc::umask(0);
            Ok(())
        });
    }
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "edit failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let config = root.join("config.toml");
    assert!(
        config.is_file(),
        "`secreq edit` should have seeded {}",
        config.display()
    );
    let mode = fs::metadata(&config).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "{} is {mode:o}", config.display());
}

/// The same registration writes a second thing the same way, one function
/// over: `State::add_wasm_rule` reached the module store with a bare
/// `create_dir_all` and an `fs::write` + `rename`, so `rules/` came out at
/// **0777** under `umask 000` and the `.wasm` inside it at 0666.
///
/// A world-writable store does not get a stranger's module *executed* — the
/// sha256 in `auto-rules.toml` pins the bytes, so a swap surfaces as a
/// visible REFUSED rule. It gets the rule silenced, which for a `deny` rule
/// is the whole of what that rule was for.
///
/// End-to-end for the reason the sibling test above is: a unit test observes
/// whatever mode the *test runner's* umask hands out, so on a developer whose
/// shell sets 077 the old code produced 0600 by luck and proved nothing.
/// `pre_exec` sets the umask in the child only.
#[test]
fn a_wasm_module_the_daemon_stores_under_a_lax_umask_is_owner_only() {
    let sb = Sandbox::new();
    // `daemon` is service-gated and refuses a fresh, unstamped root.
    sb.stamp_migrations();
    let module =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wasm_rules/always_pass.wasm");

    let mut cmd = sb.cmd_with_daemon(&[
        "rules",
        "add-wasm",
        module.to_str().unwrap(),
        "--secret",
        "GITHUB_TOKEN",
    ]);
    // SAFETY: `umask` is async-signal-safe and touches only the child.
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            libc::umask(0);
            Ok(())
        });
    }
    let out = cmd.output().unwrap();
    // Reap the daemon this test spawned before the sandbox tempdir goes.
    let _ = sb.cmd_with_daemon(&["daemon", "stop"]).output();
    assert!(
        out.status.success(),
        "rules add-wasm failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let store_dir = sb.root().join("rules");
    let mode = fs::metadata(&store_dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700, "{} is {mode:o}", store_dir.display());

    let modules: Vec<_> = fs::read_dir(&store_dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(
        modules.len(),
        1,
        "one module, no staging litter: {modules:?}"
    );
    let stored = &modules[0];
    let mode = fs::metadata(stored).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "{} is {mode:o}", stored.display());
}

// ── ssh setup ─────────────────────────────────────────────────────────────

/// Run `secreq ssh setup` in the sandbox, so it writes into the sandboxed
/// `$HOME`, never the developer's real home. `shell` sets `$SHELL` (pass `""`
/// to leave it unset — `Sandbox::cmd` removes it — going through the
/// `Unknown` shell path).
fn run_ssh_setup(sb: &Sandbox, shell: &str, args: &[&str]) -> std::process::Output {
    let mut cmd = sb.cmd(args);
    cmd.stdin(std::process::Stdio::null());
    if !shell.is_empty() {
        cmd.env("SHELL", shell);
    }
    cmd.output().unwrap()
}

#[test]
fn ssh_setup_ssh_config_writes_identityagent_block_0600() {
    let sb = Sandbox::new();
    let home = sb.path().join("home");

    // `--yes` skips the confirm prompt so the command runs without a TTY.
    let out = run_ssh_setup(
        &sb,
        "",
        &["ssh", "setup", "--method", "ssh-config", "--yes"],
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
    let sb = Sandbox::new();
    let home = sb.path().join("home");

    // First write the block.
    let out = run_ssh_setup(
        &sb,
        "",
        &["ssh", "setup", "--method", "ssh-config", "--yes"],
    );
    assert!(out.status.success());
    let ssh_config = home.join(".ssh/config");
    assert!(fs::read_to_string(&ssh_config)
        .unwrap()
        .contains("# >>> secreq managed SSH agent"));

    // Then undo it.
    let out = run_ssh_setup(
        &sb,
        "",
        &["ssh", "setup", "--method", "ssh-config", "--undo"],
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
    let sb = Sandbox::new();
    let home = sb.path().join("home");

    // SHELL=zsh → the block lands in ~/.zshrc.
    let out = run_ssh_setup(
        &sb,
        "/bin/zsh",
        &["ssh", "setup", "--method", "shell-rc", "--yes"],
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
    let sb = Sandbox::new();
    let home = sb.path().join("home");

    let out = run_ssh_setup(
        &sb,
        "",
        &["ssh", "setup", "--method", "ssh-config", "--yes"],
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

    // The scripted path must not offer or perform the self-test (no prompt, no
    // real sign) — it stays deterministic and returns promptly.
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !combined.contains("Test that the agent can sign")
            && !combined.contains("Signing may prompt"),
        "scripted ssh setup must not offer the self-test: {combined}"
    );

    // No login service was installed (macOS LaunchAgents / Linux systemd user).
    let launchd = home.join("Library/LaunchAgents/com.secreq.daemon.plist");
    let systemd = home.join(".config/systemd/user/secreq.service");
    assert!(
        !launchd.exists() && !systemd.exists(),
        "scripted path must not install the login service"
    );

    // No ssh identity was written: the config either doesn't exist or has no
    // `ssh` block.
    let config_file = sb.config_path();
    if config_file.exists() {
        let body = fs::read_to_string(&config_file).unwrap();
        assert!(
            !body.contains("\"ssh\""),
            "scripted path must not write an ssh identity: {body}"
        );
    }
}

// ── ssh add ───────────────────────────────────────────────────────────────

/// A real (throwaway) ed25519 public key line for the ssh add tests. Used as
/// both a literal and the contents of a `.pub` file.
const TEST_ED25519_PUB: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFxM1DmY0MNYQSHCQECYWC1Rqdom+nv5d1rCDKSm+nEn secreq-test@example";

#[test]
fn ssh_add_writes_identity_with_explicit_flags() {
    let sb = Sandbox::new();
    let config = sb.config_path();
    let pub_path = sb.path().join("id_ed25519.pub");
    fs::write(&pub_path, format!("{TEST_ED25519_PUB}\n")).unwrap();

    let out = sb.run(&[
        "ssh",
        "add",
        "github",
        "--public-key",
        pub_path.to_str().unwrap(),
        "--private-key",
        "secret://op/Private/GitHub/private key",
        "--reason",
        "git",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The written config must re-parse and carry the identity exactly.
    let body = fs::read_to_string(&config).unwrap();
    assert!(body.contains("[ssh.github]"), "got: {body}");
    assert!(
        body.contains(TEST_ED25519_PUB),
        "public_key missing: {body}"
    );
    assert!(
        body.contains("secret://op/Private/GitHub/private key"),
        "private_key ref missing: {body}"
    );
    assert!(body.contains(r#"reason = "git""#), "reason missing: {body}");

    // And `secreq check` is happy with the resulting config (it round-trips).
    let check = sb.run(&["check"]);
    assert!(
        check.status.success(),
        "check stderr: {}",
        String::from_utf8_lossy(&check.stderr)
    );

    // The fully non-interactive path (both key flags supplied) must NOT offer
    // the self-test — it never prompts and never performs a real sign, so it
    // returns promptly and can't hang against a (non-existent) live socket.
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !combined.contains("Test that the agent can sign")
            && !combined.contains("real signature")
            && !combined.contains("Signing may prompt"),
        "scripted ssh add must not offer the self-test: {combined}"
    );
}

#[test]
fn ssh_add_rejects_duplicate_without_force() {
    let sb = Sandbox::new();
    let config = sb.config_path();

    let add = |reason: &str| {
        sb.run(&[
            "ssh",
            "add",
            "github",
            "--public-key",
            TEST_ED25519_PUB,
            "--private-key",
            "secret://op/Private/GitHub/private key",
            "--reason",
            reason,
        ])
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
    let forced = sb.run(&[
        "ssh",
        "add",
        "github",
        "--public-key",
        TEST_ED25519_PUB,
        "--private-key",
        "secret://op/Private/GitHub/private key",
        "--reason",
        "overwritten",
        "--force",
    ]);
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
    let sb = Sandbox::new();
    let out = sb.run(&[
        "ssh",
        "add",
        "github",
        "--public-key",
        "not a key",
        "--private-key",
        "secret://op/Private/GitHub/private key",
    ]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("neither an existing file") || stderr.contains("OpenSSH public key"),
        "stderr: {stderr}"
    );
}

#[test]
fn ssh_help_lists_subcommands() {
    // `secreq ssh --help` should advertise the nested subcommands so the flat
    // names didn't silently survive the migration.
    let sb = Sandbox::new();
    let out = sb.run(&["ssh", "--help"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    for sub in ["setup", "add", "validate"] {
        assert!(
            stdout.contains(sub),
            "`ssh --help` should list `{sub}`: {stdout}"
        );
    }
}

#[test]
fn daemon_log_path_prints_root_log_path_without_spawning() {
    let sb = Sandbox::new();
    // Stamp the migration level first: `daemon` is a service-gated command
    // and refuses a fresh, unstamped root (services verify, never apply).
    sb.stamp_migrations();
    // `daemon log-path` is pure: it prints the path and never starts a
    // daemon (so it's safe even with the daemon disabled).
    let out = sb.run(&["daemon", "log-path"]);
    assert!(
        out.status.success(),
        "log-path should exit 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let printed = String::from_utf8_lossy(&out.stdout);
    let expected = sb.root().join("daemon.log");
    assert_eq!(
        printed.trim(),
        expected.to_str().unwrap(),
        "log-path should print <SECREQ_HOME>/daemon.log"
    );
    // It must not have created the file or a daemon socket — pure print.
    assert!(!expected.exists(), "log-path must not create the log file");
}

#[test]
fn read_with_no_refs_is_a_usage_error() {
    let sb = Sandbox::new();
    // clap enforces `required = true` on the refs, so this exits 2 with a
    // usage message — before any daemon contact.
    let out = sb.run(&["read"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "missing refs should be usage err"
    );
}

#[test]
fn read_refuses_re_entrant_call_during_resolution() {
    let sb = Sandbox::new();
    write_config(
        &sb.config_path(),
        "[providers.op]\nretrieve = [\"printf\", \"%s\", \"{locator}\"]\n",
    );
    // Simulate being spawned by the daemon mid-resolution: SECREQ_RESOLVING is
    // set. `read` must refuse rather than deadlock on a second daemon round.
    let out = sb
        .cmd(&["read", "op/Work/key"])
        .env("SECREQ_RESOLVING", "1")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "re-entrant read should exit 1");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("re-entrant"), "stderr: {stderr}");
}

#[test]
fn read_rejects_an_undeclared_no_slash_reference_naming_both_readings() {
    let sb = Sandbox::new();
    // A provider that would echo the locator — proves we never reach it.
    write_config(
        &sb.config_path(),
        "[providers.op]\nretrieve = [\"printf\", \"%s\", \"{locator}\"]\n",
    );
    // `noslash` has no `/`, so it is a declared secret's name — and nothing
    // declares it. The message has to offer the other reading too, because
    // the common mistake is forgetting the locator, not misspelling a name.
    let out = sb.run(&["read", "noslash"]);
    assert_eq!(out.status.code(), Some(1), "unknown name should exit 1");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not a declared secret"), "stderr: {stderr}");
    assert!(
        stderr.contains("secret://noslash/<locator>"),
        "stderr: {stderr}"
    );
}

#[test]
fn read_resolves_a_declared_secret_by_name() {
    let sb = Sandbox::new();
    write_config(
        &sb.config_path(),
        r#"{
            providers: { op: { retrieve: ["printf", "%s", "{locator}"] } },
            secrets: { github_token: { ref: "secret://op/Personal/GitHub/token" } },
        }"#,
    );
    // The config is in hand on this path, so a bare name resolves through
    // the `secrets` block on the same slash rule a wrap's `env` uses. The
    // daemon is not running in the sandbox, so this gets as far as consent
    // and stops — which is enough to prove the name resolved rather than
    // failing as a malformed reference.
    let out = sb.run(&["read", "github_token"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("not a declared secret") && !stderr.contains("not a valid reference"),
        "a declared name must resolve, not fail parsing: {stderr}"
    );
}

#[test]
fn read_is_denied_when_the_daemon_is_disabled() {
    let sb = Sandbox::new();
    write_config(
        &sb.config_path(),
        "[providers.op]\nretrieve = [\"printf\", \"%s\", \"{locator}\"]\n",
    );
    // `Sandbox::cmd` sets SECREQ_NO_DAEMON=1, so consent fails closed: a well
    // formed ref parses and reaches the consent boundary, which denies. This
    // proves `read` has no client-side bypass — there is no `--yes` to add.
    let out = sb.run(&["read", "op/Work/key"]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "no-daemon read should be denied"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("denied"), "stderr: {stderr}");
    // Nothing leaked to stdout.
    assert!(
        String::from_utf8_lossy(&out.stdout).trim().is_empty(),
        "denied read must print no value to stdout"
    );
}

// ── migrations ────────────────────────────────────────────────────────────

/// Seed the sandbox's *legacy* config location, so the next `secreq` run
/// performs migration 0001 for real. The `legacy-config` layout matches the
/// sandbox's `$XDG_CONFIG_HOME` pin.
fn seed_legacy_config(dir: &Path, body: &str) -> PathBuf {
    let legacy = dir.join("legacy-config/secreq/wraps.json5");
    fs::create_dir_all(legacy.parent().unwrap()).unwrap();
    fs::write(&legacy, body).unwrap();
    legacy
}

#[test]
fn first_run_migrates_legacy_config_and_leaves_a_working_symlink() {
    let sb = Sandbox::new();
    let legacy = seed_legacy_config(sb.path(), r#"{ gh: { $reason: "x", env: {} } }"#);

    // Any command triggers the gate; `wraps` just lists.
    let out = sb.run(&["wraps"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Config moved to the new root (0001) and was converted to TOML (0003).
    let moved = sb.config_path();
    let body = fs::read_to_string(&moved).unwrap();
    assert!(body.contains("[wraps.gh]"), "got: {body}");
    assert!(body.contains(r#"reason = "x""#), "got: {body}");

    // 0001 left a symlink at the old path so an older secreq kept working;
    // 0003 cleared it, because that older secreq cannot read TOML wherever it
    // points. A dangling link would be worse than none.
    assert!(
        legacy.symlink_metadata().is_err(),
        "the stale compat symlink should be gone, not dangling"
    );
}

#[test]
fn migration_is_idempotent_across_runs() {
    let sb = Sandbox::new();
    seed_legacy_config(sb.path(), r#"{ gh: { $reason: "x", env: {} } }"#);

    for _ in 0..3 {
        let out = sb.run(&["wraps"]);
        assert!(
            out.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let body = fs::read_to_string(sb.config_path()).unwrap();
    assert!(body.contains("[wraps.gh]"), "got: {body}");
    assert!(body.contains(r#"reason = "x""#), "got: {body}");
}

#[test]
fn migrate_restore_reverts_to_the_snapshot_and_reports_what_it_discarded() {
    let sb = Sandbox::new();
    let legacy = seed_legacy_config(sb.path(), r#"{ gh: { $reason: "original", env: {} } }"#);
    sb.run(&["wraps"]);

    // Diverge from the snapshot, as a user would by adding a wrap. The legacy
    // path is what level 0 holds, so that is what the diff is about.
    let moved = sb.config_path();
    fs::write(&moved, "[wraps.terraform]\nreason = \"added later\"\n").unwrap();
    fs::write(&legacy, r#"{ gh: { $reason: "edited since", env: {} } }"#).unwrap();

    let out = sb.run(&["--yes", "migrate", "restore", "0"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);

    // The loss must be itemized, not merely announced.
    assert!(stdout.contains("DISCARD"), "no discard warning: {stdout}");
    assert!(
        stdout.contains("edited since"),
        "diff should name what's lost: {stdout}"
    );

    // `config.toml` is an artifact of 0003 that level 0 has no snapshot for,
    // so the restore removes it — and had to say so above, which it did.
    assert!(
        stdout.contains("added later"),
        "a file about to be removed must be itemized too: {stdout}"
    );
    assert!(!moved.exists(), "the forward artifact is cleared");

    // Removed, but not lost: the rescue copy makes a mistaken restore
    // recoverable, which is the whole promise of the pre-restore save.
    let saved: Vec<_> = fs::read_dir(sb.root().join("migration-snapshots"))
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("current-"))
        .collect();
    assert_eq!(saved.len(), 1, "exactly one pre-restore save");
    assert_eq!(
        fs::read_to_string(saved[0].path().join("config.toml")).unwrap(),
        "[wraps.terraform]\nreason = \"added later\"\n",
        "the removed artifact is recoverable from the rescue copy"
    );

    // The level-0 layout is back: a real file at the legacy path.
    assert!(!legacy.symlink_metadata().unwrap().file_type().is_symlink());
    assert_eq!(
        fs::read_to_string(&legacy).unwrap(),
        r#"{ gh: { $reason: "original", env: {} } }"#
    );
}

#[test]
fn migrate_restore_saves_the_current_config_before_overwriting_it() {
    let sb = Sandbox::new();
    seed_legacy_config(sb.path(), r#"{ gh: { $reason: "original", env: {} } }"#);
    sb.run(&["wraps"]);
    fs::write(
        sb.config_path(),
        "[wraps.terraform]\nreason = \"precious\"\n",
    )
    .unwrap();

    sb.run(&["--yes", "migrate", "restore", "0"]);

    // A mistaken restore must itself be recoverable.
    let saved: Vec<_> = fs::read_dir(sb.root().join("migration-snapshots"))
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("current-"))
        .collect();
    assert_eq!(saved.len(), 1, "exactly one pre-restore save");
    // The rescue copy covers what the restore removes as well as what it
    // overwrites — a `config.toml` dropped on the floor would be recoverable
    // only for the files that happened to survive.
    assert_eq!(
        fs::read_to_string(saved[0].path().join("config.toml")).unwrap(),
        "[wraps.terraform]\nreason = \"precious\"\n",
        "the rescue copy holds the artifact the restore is about to remove"
    );
}

/// The pre-restore save directory holds copies of everything the restore is
/// about to overwrite, and on migration 0002 that includes the user's
/// `~/.ssh/config`. The copies carry the live file's own mode, but the
/// directory around them was created at the umask's 0755 — so the *listing*,
/// which is a map of every config path on the machine, was readable by anyone
/// on the box.
///
/// This lives out here rather than beside `restore_in` for the reason
/// `a_fresh_init_leaves_no_directory_others_can_write_under_the_root` does,
/// and it is the same two choices that make it evidence rather than
/// decoration:
///
/// - **The child runs under `umask 000`**, set in `pre_exec` so it touches
///   only the child. The in-process version of this test took the ambient
///   umask and so passed against unfixed code on any developer whose shell
///   sets 077 — which is the shell most likely to be running it. Setting the
///   umask in the *test* process instead would be global state that parallel
///   tests fight over.
/// - **The mode is asserted exactly.** `mode & 0o022 == 0` is satisfied by
///   the 0755 that a umask-022 machine hands out, which is the bug wearing a
///   passing test. That weakness is exactly what the old test had.
#[test]
fn the_pre_restore_save_dir_is_owner_only_under_a_hostile_umask() {
    let sb = Sandbox::new();
    seed_legacy_config(sb.path(), r#"{ gh: { $reason: "original", env: {} } }"#);
    // The forward migration, which creates the snapshot the restore rolls back
    // to. Its own umask does not matter here: the directory under test is made
    // by the restore below.
    sb.run(&["wraps"]);

    let mut cmd = sb.cmd(&["--yes", "migrate", "restore", "0"]);
    // SAFETY: `umask` is async-signal-safe and touches only the child.
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            libc::umask(0);
            Ok(())
        });
    }
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "restore exited with {:?}; stderr:\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );

    let saved: Vec<_> = fs::read_dir(sb.root().join("migration-snapshots"))
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("current-"))
        .map(|e| e.path())
        .collect();
    assert_eq!(
        saved.len(),
        1,
        "the restore should have saved the config it overwrote; without that \
         directory this test pins nothing"
    );
    let mode = fs::metadata(&saved[0]).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700, "{} is {mode:o}", saved[0].display());
}

#[test]
fn migrate_restore_is_reachable_even_when_the_gate_refuses_to_run() {
    // The deadlock this guards: the downgrade error tells the user to run
    // `secreq migrate restore`, but the gate is what emits that error. If
    // `migrate` went through the gate, the remedy would be unreachable.
    let sb = Sandbox::new();
    seed_legacy_config(sb.path(), r#"{ gh: { $reason: "original", env: {} } }"#);
    sb.run(&["wraps"]);

    // Simulate a config migrated by a much newer secreq.
    fs::write(
        sb.root().join(".migration-state"),
        r#"{ "migration_level": 99, "migrated_by": "9.9.9 (deadbeef +1)" }"#,
    )
    .unwrap();

    // A normal command is refused...
    let blocked = sb.run(&["wraps"]);
    assert!(!blocked.status.success(), "gate should refuse a downgrade");
    let stderr = String::from_utf8_lossy(&blocked.stderr);
    assert!(stderr.contains("migrate restore"), "no remedy: {stderr}");

    // ...but the remedy it names still runs.
    let out = sb.run(&["--yes", "migrate", "restore", "0"]);
    assert!(
        out.status.success(),
        "restore must bypass the gate; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // And the user is unblocked afterwards.
    let after = sb.run(&["wraps"]);
    assert!(
        after.status.success(),
        "should work after restore; stderr: {}",
        String::from_utf8_lossy(&after.stderr)
    );
}

#[test]
fn migrate_restore_names_available_levels_when_the_snapshot_is_missing() {
    let sb = Sandbox::new();
    let out = sb.run(&["--yes", "migrate", "restore", "7"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("no snapshot"), "unhelpful: {stderr}");
}

/// The migration runner's own bookkeeping is the last corner of the tree that
/// still took its mode from the umask. `run_pending_in` creates the root at
/// 0700 and `restore_in` creates the pre-restore save at 0700, but the lock it
/// opens and the snapshot tree it stages named no mode at all — so they landed
/// at `0666 & !umask` and `0777 & !umask`, which is 0644 and 0755 on an
/// ordinary box and **0666 and 0777** under the `umask 000` that CI and
/// container images routinely set.
///
/// What the snapshot tree holds is the point: `migration-snapshots/<level>/`
/// is `fs::copy` of every file a migration is about to move, and migration
/// 0002's list reaches outside the secreq tree to `~/.ssh/config` and the
/// shell rc files. The copies carry their source modes, but the directory
/// listing is a map of the user's config paths, and at 0777 it is a map
/// anyone can also write to. The lock is the quieter one: it is empty, so
/// there is nothing to read, but at 0666 any local user can take `LOCK_EX`
/// on it and park every `secreq x` on the machine for as long as they like.
///
/// Two deliberate choices, the same two the other umask tests here make:
///
/// - **The child runs under `umask 000`**, set from `pre_exec` so it never
///   touches the test process every other test in this binary shares. A
///   developer whose shell sets 077 gets 0700 out of a bare `create_dir_all`
///   for free, and the assertion would pass while proving nothing.
/// - **The modes are asserted exactly.** `mode & 0o022 == 0` is satisfied by
///   the 0755 a umask-022 machine hands out, which is the bug wearing a
///   passing test.
#[test]
fn the_migration_lock_and_snapshot_tree_a_lax_umask_creates_are_owner_only() {
    let sb = Sandbox::new();
    seed_legacy_config(sb.path(), r#"{ gh: { $reason: "x", env: {} } }"#);
    // A root that does not exist yet: `Sandbox` pre-creates its own at the
    // test runner's umask, which would seed the tree from the wrong mode.
    let root = sb.path().join("fresh-root");

    let mut cmd = sb.cmd(&["wraps"]);
    cmd.env("SECREQ_HOME", &root);
    // SAFETY: `umask` is async-signal-safe and touches only the child.
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            libc::umask(0);
            Ok(())
        });
    }
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let lock = root.join(".migration.lock");
    let snapshots = root.join("migration-snapshots");
    // The level-0 snapshot is what migration 0001 captured on the way past.
    // Assert it exists rather than letting a missing directory surface as an
    // unwrap panic on `metadata` — an absent snapshot means the run did not
    // migrate anything and this test proved nothing.
    let level_0 = snapshots.join("0");
    assert!(lock.is_file(), "no migration lock at {}", lock.display());
    assert!(
        level_0.is_dir(),
        "no level-0 snapshot at {}; did the run migrate?",
        level_0.display()
    );

    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode(&lock),
        0o600,
        "{} is {:o}",
        lock.display(),
        mode(&lock)
    );
    for dir in [&snapshots, &level_0] {
        assert_eq!(mode(dir), 0o700, "{} is {:o}", dir.display(), mode(dir));
    }
}

/// Migration 0001 leaves a symlink behind at the legacy path so an older
/// secreq keeps resolving its config, and in the "new real, old missing" case
/// it has to create the directory to put that symlink in. That
/// `create_dir_all` named no mode either — and unlike everything else in this
/// module it writes **outside** `$SECREQ_HOME`, so the 0700 root is not
/// quietly containing it.
///
/// Under `umask 000` the compat directory lands at 0777, and a directory
/// anyone can write to is a directory in which anyone can swap the symlink
/// and point an older secreq's `wraps.json5` at a config of their choosing —
/// which is a config that names the wraps and the reasons the user will be
/// asked to approve.
#[test]
fn the_legacy_compat_dir_migration_0001_creates_is_owner_only() {
    let sb = Sandbox::new();
    // "new real, old missing": the config is already at the new root and the
    // legacy directory is absent, so 0001 has only the symlink left to plant.
    // `Sandbox` leaves the `legacy-*` subdirectories uncreated for exactly
    // this kind of seeding.
    let root = sb.path().join("fresh-root");
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join("wraps.json5"),
        r#"{ gh: { $reason: "x", env: {} } }"#,
    )
    .unwrap();

    let mut cmd = sb.cmd(&["wraps"]);
    cmd.env("SECREQ_HOME", &root);
    // SAFETY: `umask` is async-signal-safe and touches only the child.
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            libc::umask(0);
            Ok(())
        });
    }
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // 0001 creates this directory (and plants a compat symlink in it, which
    // 0003 then clears once the format changes). The directory outlives the
    // link, and its mode is what this test is about.
    let compat_dir = sb.path().join("legacy-config/secreq");
    assert!(compat_dir.is_dir(), "{} should exist", compat_dir.display());
    let mode = fs::metadata(&compat_dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700, "{} is {mode:o}", compat_dir.display());
}

/// The same directory, reached from the other direction. `restore` writes
/// each file back to the path it came from, and it has to recreate that
/// path's parent when it is gone — which the module's own docs describe as a
/// thing users do: `rm -rf ~/.config/secreq/` against the directory of
/// compatibility symlinks unlinks the links and leaves the real files alone,
/// so it is a reasonable thing to run after migrating, and it takes the
/// directory with it.
///
/// A restore then rebuilds it at the umask and puts the restored `wraps.json5`
/// inside. Like the compat directory above this is outside `$SECREQ_HOME`, so
/// nothing else narrows it.
#[test]
fn the_legacy_dir_a_restore_rebuilds_is_owner_only() {
    let sb = Sandbox::new();
    seed_legacy_config(sb.path(), r#"{ gh: { $reason: "original", env: {} } }"#);
    sb.run(&["wraps"]); // migrate forward

    // The user cleans up what now looks like a leftover directory of links.
    let legacy_dir = sb.path().join("legacy-config/secreq");
    fs::remove_dir_all(&legacy_dir).unwrap();

    let mut cmd = sb.cmd(&["--yes", "migrate", "restore", "0"]);
    // SAFETY: `umask` is async-signal-safe and touches only the child.
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            libc::umask(0);
            Ok(())
        });
    }
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The restore has to have rebuilt the directory, or this proves nothing.
    assert_eq!(
        fs::read_to_string(legacy_dir.join("wraps.json5")).unwrap(),
        r#"{ gh: { $reason: "original", env: {} } }"#
    );
    let mode = fs::metadata(&legacy_dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700, "{} is {mode:o}", legacy_dir.display());
}

/// `secreq x` bypasses clap, but it must NOT bypass the migration gate: on a
/// shim-only machine (hooks, wraps) `x` is the only foreground command that
/// ever runs, and services (the daemon) refuse to apply migrations. If `x`
/// doesn't heal a pending level, nothing does — every daemon spawn dies
/// before binding its socket.
#[test]
fn x_applies_pending_migrations_so_the_daemon_can_start() {
    let sb = Sandbox::new();
    let bin_dir = sb.path().join("realbin");
    let shim_dir = sb.path().join("shims");
    install_fake_gh(&bin_dir);
    write_config(&sb.config_path(), &echo_provider_config(&shim_dir));

    // A root stuck mid-history (e.g. after `migrate restore 1`).
    fs::write(
        sb.root().join(".migration-state"),
        r#"{ "migration_level": 1 }"#,
    )
    .unwrap();

    // Prove the seed bites: a service-gated command refuses to run.
    // (`daemon log-path` exits 0 whenever the gate lets it through, unlike
    // `daemon status`, whose exit code reports whether a daemon is running.)
    let blocked = sb.run(&["daemon", "log-path"]);
    assert!(
        !blocked.status.success(),
        "seed should leave service roles refusing; stdout: {}",
        String::from_utf8_lossy(&blocked.stdout)
    );

    // `x` is a deliberate foreground command: it must apply the pending
    // migration(s) before running the wrap. (Sandbox default: no daemon.)
    let path = format!("{}:{}", bin_dir.display(), std::env::var("PATH").unwrap());
    let out = sb
        .cmd(&["x", "--sq-yes", "gh", "version"])
        .env("PATH", &path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "x should run; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The gate stamped the level, so service roles start again.
    let after = sb.run(&["daemon", "log-path"]);
    assert!(
        after.status.success(),
        "service gate should pass after x healed the level; stderr: {}",
        String::from_utf8_lossy(&after.stderr)
    );
}

/// When the auto-spawned daemon dies before binding its socket, the client's
/// error must carry the daemon's actual stderr — not just the canned
/// "is a display available?" guess. In a hook/headless context that death
/// note is the only clue the user gets.
#[test]
fn x_reports_the_daemons_stderr_when_it_dies_before_binding() {
    let sb = Sandbox::new();
    // A SECREQ_HOME deep enough that `<root>/run/consent.sock` exceeds the
    // unix-socket path limit (SUN_LEN: 104 bytes on macOS, 108 on Linux).
    // The client's optimistic connect fails (no daemon), the spawn itself
    // succeeds, and the child dies at bind — a pre-bind death with no
    // dependence on migration state.
    let root = sb.path().join("x".repeat(120)).join("secreq");
    fs::create_dir_all(&root).unwrap();
    let bin_dir = sb.path().join("realbin");
    let shim_dir = sb.path().join("shims");
    install_fake_gh(&bin_dir);
    write_config(&root.join("config.toml"), &echo_provider_config(&shim_dir));

    let path = format!("{}:{}", bin_dir.display(), std::env::var("PATH").unwrap());
    // No --sq-yes: resolving the wrap's secret needs consent, which needs
    // the daemon. `cmd_with_daemon`: the spawn path is the test subject.
    // Deliberate overrides after the sandbox defaults (later env calls win):
    // SECREQ_HOME moves to the long root, and XDG_RUNTIME_DIR is unpinned so
    // `socket_dir()` falls back to `<root>/run` — the sandbox's short runtime
    // dir would otherwise let the bind succeed.
    let out = sb
        .cmd_with_daemon(&["x", "gh", "version"])
        .env("SECREQ_HOME", &root)
        .env("PATH", &path)
        .env_remove("XDG_RUNTIME_DIR")
        .env_remove("SECREQ_NO_DAEMON")
        // The client refuses to spawn a daemon it knows cannot render, and on
        // Linux that means `$DISPLAY` or `$WAYLAND_DISPLAY` — neither of which
        // a CI runner has. Without one it fails closed before reaching the
        // spawn, so the death note this test exists for is never written and
        // the assertion below sees a plain denial instead. macOS always
        // reports a display, which is why this only ever failed on Linux.
        //
        // The value need not name a real server: the daemon binds its socket
        // before it touches the UI, so it dies at bind either way, which is
        // the failure being asserted.
        .env("DISPLAY", ":0")
        .output()
        .unwrap();
    assert!(!out.status.success(), "consent has no daemon; x must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("exited before binding"),
        "expected the early-exit error; stderr: {stderr}"
    );
    assert!(
        stderr.contains("bind daemon socket"),
        "the daemon's own stderr (its bind failure) must be surfaced; stderr: {stderr}"
    );
}

/// `agent open` with no `--sock` binds into `paths::socket_dir()` beside the
/// other sockets, and prints the resolved path on stdout so a caller (brain,
/// which must `ssh -R` it into a guest) reads it back rather than guessing.
///
/// The sandbox pins `$XDG_RUNTIME_DIR` — `socket_dir()` prefers it, so
/// without the pin this test would bind beside the developer's live daemon
/// sockets.
#[test]
fn agent_open_defaults_its_socket_into_the_socket_dir_and_prints_it() {
    use std::io::BufRead;

    let sb = Sandbox::new();
    // Stamp the migration level first: `agent` is a service-gated command
    // and refuses a fresh, unstamped root (services verify, never apply).
    sb.stamp_migrations();

    let mut cmd = sb.cmd(&[
        "agent",
        "open",
        "--scope",
        "test-vm",
        "--allow",
        "secret://fake/thing",
    ]);
    cmd.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());

    // `agent open` serves until killed — the socket's lifetime *is* the
    // process's — so read the one line it promises and then stop it, rather
    // than waiting for an exit that never comes.
    let mut child = cmd.spawn().expect("spawn agent open");
    let mut line = String::new();
    std::io::BufReader::new(child.stdout.take().expect("piped stdout"))
        .read_line(&mut line)
        .expect("read the resolved socket path");
    let printed = PathBuf::from(line.trim());

    let expected = sb.runtime_dir().join("secreq/scope-test-vm.sock");
    assert_eq!(
        printed, expected,
        "the printed path must be the scope's socket in the socket dir"
    );
    assert!(
        printed.exists(),
        "the printed path must be a socket that actually got bound: {}",
        printed.display()
    );

    child.kill().expect("kill agent open");
    child.wait().expect("reap agent open");
}

/// `--sock` still wins: brain picks the path so it can `ssh -R` it into a
/// guest, and the printed path must report where it actually bound.
#[test]
fn agent_open_honours_an_explicit_sock_override() {
    use std::io::BufRead;

    let sb = Sandbox::new();
    let chosen = sb.path().join("chosen.sock");
    // Stamp the migration level first: `agent` is a service-gated command
    // and refuses a fresh, unstamped root (services verify, never apply).
    sb.stamp_migrations();

    let mut cmd = sb.cmd(&[
        "agent",
        "open",
        "--scope",
        "test-vm",
        "--allow",
        "secret://fake/thing",
        "--sock",
    ]);
    cmd.arg(&chosen);
    cmd.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());

    let mut child = cmd.spawn().expect("spawn agent open");
    let mut line = String::new();
    std::io::BufReader::new(child.stdout.take().expect("piped stdout"))
        .read_line(&mut line)
        .expect("read the resolved socket path");

    assert_eq!(
        PathBuf::from(line.trim()),
        chosen,
        "an explicit --sock must be honoured and reported"
    );
    assert!(chosen.exists(), "--sock must be where it actually bound");
    assert!(
        !sb.runtime_dir().join("secreq/scope-test-vm.sock").exists(),
        "an explicit --sock must not also bind the default path"
    );

    child.kill().expect("kill agent open");
    child.wait().expect("reap agent open");
}

// ── rules new-wasm ────────────────────────────────────────────────────────

/// The mode arguments to `mkdir(2)` and `open(2)` are *requests*: the
/// kernel masks both with the process umask, and a umask clears owner bits
/// as readily as group and world ones. Under `umask 700` that lands on the
/// scaffold twice over — the 0700 directory becomes 0000 and cannot be
/// written into at all, and a file written at the umask's answer becomes
/// `----rw-rw-`, which its own owner cannot read.
///
/// Both failures are silent in the shape a scaffold test naturally takes:
/// the command still exits 0 for the second one, and `Path::exists` is
/// satisfied by a file nobody can open. So this reads the project back
/// the way `npm install` would, and pins both modes.
///
/// The two other places this codebase creates a private directory
/// (`paths::ensure_private_dir`, `scoped_agent::create_staging_dir`) and
/// the one that writes a private file (`atomic::replace`) all follow the
/// create with an explicit `set_permissions` for exactly this reason.
///
/// Driven through the real binary because the umask is process-global: a
/// unit test that set one would hand the same hostile mask to every other
/// test running beside it in the same binary. `pre_exec` scopes it to the
/// child, which is also how `init`'s umask test does it.
#[test]
fn a_scaffolded_project_is_readable_whatever_the_umask() {
    let sb = Sandbox::new();
    sb.stamp_migrations();
    let project = sb.path().join("my-rule");

    let mut cmd = sb.cmd(&["rules", "new-wasm"]);
    cmd.arg(&project);
    // SAFETY: `umask` is async-signal-safe and touches only the child.
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            // Clears every owner bit — the case a `& 0o022` style
            // assertion, or one that only checks a file *exists*, calls
            // clean.
            libc::umask(0o700);
            Ok(())
        });
    }
    let out = cmd.output().expect("run rules new-wasm");

    assert!(
        out.status.success(),
        "scaffold failed under a hostile umask:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    for dir in [project.clone(), project.join("assembly")] {
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700,
            "{} must be owner-only whatever the umask cleared",
            dir.display()
        );
    }

    // Reading it back is the assertion `exists()` was not: a scaffold the
    // owner cannot open is one `npm install` cannot install.
    for rel in ["package.json", "assembly/rule.ts"] {
        let path = project.join(rel);
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{} must be readable by its owner: {e}", path.display()));
        assert!(!text.is_empty(), "{rel} is empty");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600,
            "{rel} must carry the mode secreq chose, not the umask's answer"
        );
    }
    assert!(
        fs::read_to_string(project.join("package.json"))
            .unwrap()
            .contains("secreq-rule"),
        "the manifest must name the SDK dependency"
    );
}
