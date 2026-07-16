//! End-to-end tests for the **guest** client — the real `secreq resolve`
//! binary, against a real scoped agent socket.
//!
//! No VM and no daemon. The test process plays the host: it binds a socket in
//! a tempdir and serves it with `scoped_agent::serve_on` and a synthetic
//! [`Gate`] (the same instrument `tests/scoped_agent.rs` uses), then runs the
//! built binary with `$SECREQ_SOCK` pointed at it. What's exercised is the
//! production path a guest takes: env → dial → framed protocol → stdout.
//!
//! **These tests are mostly about stdout.** `secreq resolve` exists to be
//! substituted into a shell — `export GH_TOKEN="$(secreq resolve …)"` — so
//! "the value and nothing but the value on stdout" is not a nicety, it is the
//! interface. A stray diagnostic line would silently end up *inside* someone's
//! token, and a denial that printed to stdout would export the word "denied"
//! as a credential. Every assertion below that looks pedantic about a stream
//! is guarding that.

use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use secreq::consent::Decision;
use secreq::reference::Reference;
use secreq::scoped_agent::{serve_on, Gate, GuestChain, Scope, ScopeApprovals};
use secreq::secret::SecretValue;

/// Distinctive so "never on stdout / never in stderr" assertions can search
/// for it verbatim.
const SECRET_VALUE: &str = "ghp_liveTokenValue_DEADBEEF_do_not_log_me";

const ALLOWED_REF: &str = "secret://op/Dev/gh/token";
const OTHER_ALLOWED_REF: &str = "secret://op/Dev/linear/token";
const OUT_OF_SCOPE_REF: &str = "secret://op/Prod/aws/root_key";

/// The denied exit code, mirroring `commands::RESOLVE_DENIED_EXIT`. Pinned
/// here rather than imported because it is a *published* part of the guest
/// contract — a script branches on it — so a change should have to break a
/// test that says so out loud.
const DENIED_EXIT: i32 = 3;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_secreq")
}

/// Run `f` with `$XDG_STATE_HOME` pointed at a fresh tempdir.
///
/// The **host** half of these tests runs in this process, so its audit rows
/// land wherever this process's env says — i.e. in the developer's real
/// `~/.local/state/secreq/audit.log` unless we move it. (The `secreq resolve`
/// child writes no rows: auditing is the host's job. It gets its own pinned
/// dir anyway, in `run_resolve`.)
///
/// The lock serializes callers, since `$XDG_STATE_HOME` is process-global and
/// two of these at once would clobber each other's target — the same reasoning
/// as `tests/scoped_agent.rs`'s copy of this helper.
fn with_temp_audit_log<R>(f: impl FnOnce() -> R) -> R {
    static ENV_LOCK: Mutex<()> = Mutex::new(());
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().expect("tempdir");
    let prev = std::env::var_os("XDG_STATE_HOME");
    std::env::set_var("XDG_STATE_HOME", dir.path());
    let out = f();
    match prev {
        Some(v) => std::env::set_var("XDG_STATE_HOME", v),
        None => std::env::remove_var("XDG_STATE_HOME"),
    }
    out
}

fn reference(s: &str) -> Reference {
    Reference::parse(s).expect("valid reference")
}

/// A gate that answers with a canned decision and hands back a fixed value.
struct FakeGate {
    decision: Decision,
}

impl Gate for FakeGate {
    fn consent(&self, _: &Scope, _: &Reference, _: &GuestChain) -> Result<Decision> {
        Ok(self.decision)
    }

    fn resolve(&self, _: &Scope, _: &Reference) -> Result<SecretValue> {
        Ok(SecretValue::new(SECRET_VALUE.to_owned()))
    }
}

/// A scoped agent listening on a tempdir socket, plus a tempdir for the
/// binary's state. The `TempDir`s are held so the paths outlive the test; the
/// serving thread exits with the process.
struct Host {
    _dir: tempfile::TempDir,
    socket: PathBuf,
}

impl Host {
    fn serving(decision: Decision) -> Host {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("scoped.sock");
        let listener = UnixListener::bind(&socket).expect("bind scoped agent socket");
        let scope = Scope::new(
            "brain-nx-t5",
            vec![reference(ALLOWED_REF), reference(OTHER_ALLOWED_REF)],
        )
        .expect("valid scope");
        let gate: Arc<dyn Gate> = Arc::new(FakeGate { decision });
        std::thread::spawn(move || {
            serve_on(
                listener,
                Arc::new(scope),
                Arc::new(ScopeApprovals::new()),
                gate,
            )
        });
        Host { _dir: dir, socket }
    }

    /// Run `secreq resolve …` as a guest would: `$SECREQ_SOCK` set, and
    /// nothing else configured.
    fn run(&self, args: &[&str]) -> Output {
        run_resolve(Some(&self.socket), args)
    }
}

/// Run the real binary with `$SECREQ_SOCK` set to `socket` (or explicitly
/// unset), with every state path pinned into a throwaway dir.
///
/// `SECREQ_NO_DAEMON` is set for the same reason the other CLI tests set it:
/// nothing on this path should ever dial the local daemon, and if a
/// regression made it try, we want a failure rather than a window on the
/// developer's screen.
fn run_resolve(socket: Option<&Path>, args: &[&str]) -> Output {
    let state = tempfile::tempdir().expect("tempdir");
    let mut command = Command::new(bin());
    command
        .arg("resolve")
        .args(args)
        .env("XDG_CONFIG_HOME", state.path().join("config"))
        .env("XDG_STATE_HOME", state.path().join("state"))
        .env("SECREQ_NO_DAEMON", "1")
        .env_remove("SECREQ_CONSENT_SOCK");
    match socket {
        Some(path) => command.env("SECREQ_SOCK", path),
        None => command.env_remove("SECREQ_SOCK"),
    };
    command.output().expect("run secreq resolve")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout is utf-8")
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr is utf-8")
}

fn code(output: &Output) -> i32 {
    output.status.code().expect("the process exited normally")
}

/// A process that died on a signal never "exited with a code" — and a panic
/// prints its own unmistakable line. Both are checked explicitly wherever an
/// error path is asserted, because "clear error" and "clean crash" are
/// indistinguishable from an exit code alone.
fn assert_no_panic(output: &Output) {
    let stderr = stderr(output);
    assert!(
        !stderr.contains("panicked"),
        "the client must never panic:\n{stderr}"
    );
}

/// **The load-bearing test.** stdout carries the value and *only* the value.
#[test]
fn a_resolve_prints_the_value_on_stdout_and_nothing_else() {
    with_temp_audit_log(|| {
        let host = Host::serving(Decision::Approve);

        let output = host.run(&[ALLOWED_REF]);

        assert_eq!(code(&output), 0, "stderr: {}", stderr(&output));
        assert_eq!(
            stdout(&output),
            format!("{SECRET_VALUE}\n"),
            "stdout must be exactly the value plus the trailing newline `$(…)` strips"
        );
        assert_eq!(
            stderr(&output),
            "",
            "a successful resolve has nothing to say"
        );
    });
}

/// The shell contract itself: what `$(…)` actually binds is the value, with
/// no newline and no extra. Asserted through a real shell rather than by
/// reasoning about the bytes above, because that substitution is the entire
/// reason for the stdout rule.
#[test]
fn the_value_substitutes_cleanly_into_a_shell_variable() {
    with_temp_audit_log(|| {
        let host = Host::serving(Decision::Approve);

        let output = Command::new("sh")
            .arg("-c")
            .arg(format!(
                r#"GH_TOKEN="$({} resolve {ALLOWED_REF})"; printf '[%s]' "$GH_TOKEN""#,
                bin(),
            ))
            .env("SECREQ_SOCK", &host.socket)
            .env("SECREQ_NO_DAEMON", "1")
            .output()
            .expect("run the shell");

        assert_eq!(
            stdout(&output),
            format!("[{SECRET_VALUE}]"),
            "the substituted variable must be the value exactly"
        );
    });
}

/// The bare shorthand resolves too, matching `read` and `agent open --allow`.
#[test]
fn the_bare_provider_locator_shorthand_resolves() {
    with_temp_audit_log(|| {
        let host = Host::serving(Decision::Approve);

        let output = host.run(&["op/Dev/gh/token"]);

        assert_eq!(code(&output), 0, "stderr: {}", stderr(&output));
        assert_eq!(stdout(&output), format!("{SECRET_VALUE}\n"));
    });
}

/// `--list` answers the scope's allowed names, one per line, and never a
/// value.
#[test]
fn list_prints_the_allowed_ref_names_one_per_line() {
    with_temp_audit_log(|| {
        let host = Host::serving(Decision::Approve);

        let output = host.run(&["--list"]);

        assert_eq!(code(&output), 0, "stderr: {}", stderr(&output));
        assert_eq!(
            stdout(&output),
            format!("{ALLOWED_REF}\n{OTHER_ALLOWED_REF}\n"),
            "listing must be exactly the declared allowlist, line per ref"
        );
        assert!(
            !stdout(&output).contains(SECRET_VALUE),
            "listing must never carry material"
        );
        assert_eq!(stderr(&output), "");
    });
}

/// `$SECREQ_SOCK` unset is the most likely mistake (running it on the host,
/// or in a tier with no forward). It must say so, exit non-zero, print
/// nothing on stdout, and not panic.
#[test]
fn an_unset_secreq_sock_is_a_clear_error_and_not_a_panic() {
    let output = run_resolve(None, &[ALLOWED_REF]);

    assert_no_panic(&output);
    assert_ne!(code(&output), 0, "an unset socket cannot succeed");
    assert_eq!(
        stdout(&output),
        "",
        "nothing may reach stdout when there is no value"
    );
    let stderr = stderr(&output);
    assert!(
        stderr.contains("SECREQ_SOCK"),
        "the error must name the variable: {stderr}"
    );
    assert!(
        stderr.contains("--vm"),
        "the error must say where it is normally set: {stderr}"
    );
}

/// A socket path with nothing behind it — the agent stopped, or the forward
/// is down. Both are named, because from inside a guest you cannot tell which
/// and the path you see isn't the host's.
#[test]
fn a_dead_socket_is_a_clear_error_and_not_a_panic() {
    let dir = tempfile::tempdir().expect("tempdir");

    let output = run_resolve(Some(&dir.path().join("not-a-socket.sock")), &[ALLOWED_REF]);

    assert_no_panic(&output);
    assert_ne!(code(&output), 0);
    assert_eq!(stdout(&output), "");
    let stderr = stderr(&output);
    assert!(
        stderr.contains("agent open") && stderr.contains("forward"),
        "the error must name both things that can be broken: {stderr}"
    );
}

/// A socket file whose listener is gone (a SIGKILLed agent leaves one behind)
/// is the same story as no file at all — and must not hang or panic.
#[test]
fn a_stale_socket_file_with_no_listener_errors_clearly() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("stale.sock");
    drop(UnixListener::bind(&path).expect("bind"));

    let output = run_resolve(Some(&path), &[ALLOWED_REF]);

    assert_no_panic(&output);
    assert_ne!(code(&output), 0);
    assert_eq!(stdout(&output), "");
    assert!(stderr(&output).contains("cannot reach"));
}

/// **A denial exits non-zero with the reason on stderr and stdout empty.**
///
/// The stdout half is the one that matters: `export
/// GH_TOKEN="$(secreq resolve …)"` ignores the exit code, so anything printed
/// here becomes the token. An empty variable fails loudly at first use; a
/// variable containing "denied" fails mysteriously somewhere else.
#[test]
fn a_denied_ref_exits_nonzero_with_the_reason_on_stderr_and_nothing_on_stdout() {
    with_temp_audit_log(|| {
        let host = Host::serving(Decision::Deny);

        let output = host.run(&[ALLOWED_REF]);

        assert_no_panic(&output);
        assert_eq!(
            code(&output),
            DENIED_EXIT,
            "a denial is a policy answer with its own code, not a generic error"
        );
        assert_eq!(stdout(&output), "", "a denial must release nothing");
        let stderr = stderr(&output);
        assert!(
            stderr.contains("denied"),
            "the reason must reach stderr: {stderr}"
        );
        assert!(
            !stderr.contains(SECRET_VALUE),
            "no value may leak: {stderr}"
        );
    });
}

/// An out-of-scope ref surfaces #41's silent denial intelligibly: the guest
/// is told the ref is outside the socket's scope — and the host never raised
/// a prompt to tell it.
#[test]
fn an_out_of_scope_ref_surfaces_the_hosts_denial() {
    with_temp_audit_log(|| {
        // The gate would approve anything it was asked about, so a denial
        // here can only have come from the allowlist, upstream of any prompt.
        let host = Host::serving(Decision::Approve);

        let output = host.run(&[OUT_OF_SCOPE_REF]);

        assert_no_panic(&output);
        assert_eq!(code(&output), DENIED_EXIT);
        assert_eq!(stdout(&output), "");
        let stderr = stderr(&output);
        assert!(
            stderr.contains("outside this socket's declared scope"),
            "the host's reason must reach the user intelligibly: {stderr}"
        );
        assert!(
            stderr.contains(OUT_OF_SCOPE_REF),
            "and must say which ref was refused: {stderr}"
        );
        assert!(
            !stderr.contains(ALLOWED_REF),
            "but must not enumerate what else the scope holds: {stderr}"
        );
    });
}

/// A malformed ref fails locally, before a socket is even dialled — a typo
/// should read as a typo, not as a broken host.
#[test]
fn a_malformed_reference_is_rejected_locally_with_the_shape_it_should_have() {
    let output = run_resolve(None, &["definitely-not-a-ref"]);

    assert_no_panic(&output);
    assert_ne!(code(&output), 0);
    assert_eq!(stdout(&output), "");
    // Reported without ever needing $SECREQ_SOCK, which isn't set here.
    assert!(
        stderr(&output).contains("secret://provider/locator"),
        "stderr: {}",
        stderr(&output)
    );
}

/// Neither a ref nor `--list` is a usage error, not a crash.
#[test]
fn no_arguments_is_a_usage_error() {
    let output = run_resolve(None, &[]);

    assert_no_panic(&output);
    assert_ne!(code(&output), 0);
    assert_eq!(stdout(&output), "");
}

/// A ref *and* `--list` is refused by the parser rather than silently
/// preferring one.
#[test]
fn a_ref_and_list_together_are_refused() {
    let output = run_resolve(None, &[ALLOWED_REF, "--list"]);

    assert_no_panic(&output);
    assert_ne!(code(&output), 0);
    assert_eq!(stdout(&output), "");
}

/// The guest's self-reported chain rides the resolve — display-only on the
/// host, but it has to actually arrive to be displayed.
///
/// Asserted through a gate that captures what `consent` was handed, and
/// deliberately weakly: the chain is whatever the test runner's own process
/// tree happens to be (cargo, a shell, an IDE), so the only stable facts are
/// that *something* was claimed and that it isn't us. `provenance` excludes
/// secreq's own frames — a guest reporting "secreq" as its caller would be
/// noise at best.
#[test]
fn the_client_sends_its_own_process_chain_as_a_claim() {
    struct CapturingGate(Mutex<Vec<Option<String>>>);

    impl Gate for CapturingGate {
        fn consent(&self, _: &Scope, _: &Reference, chain: &GuestChain) -> Result<Decision> {
            self.0
                .lock()
                .expect("chains mutex")
                .push(chain.display().map(str::to_owned));
            Ok(Decision::Approve)
        }
        fn resolve(&self, _: &Scope, _: &Reference) -> Result<SecretValue> {
            Ok(SecretValue::new(SECRET_VALUE.to_owned()))
        }
    }

    with_temp_audit_log(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("scoped.sock");
        let listener = UnixListener::bind(&socket).expect("bind");
        let gate = Arc::new(CapturingGate(Mutex::new(Vec::new())));
        let serve_gate: Arc<dyn Gate> = gate.clone();
        let scope = Scope::new("brain-nx-t5", vec![reference(ALLOWED_REF)]).expect("valid scope");
        std::thread::spawn(move || {
            serve_on(
                listener,
                Arc::new(scope),
                Arc::new(ScopeApprovals::new()),
                serve_gate,
            )
        });

        let output = run_resolve(Some(&socket), &[ALLOWED_REF]);
        assert_eq!(code(&output), 0, "stderr: {}", stderr(&output));

        let chains = gate.0.lock().expect("chains mutex").clone();
        assert_eq!(chains.len(), 1, "the resolve must have raised one prompt");
        if let Some(chain) = &chains[0] {
            assert!(
                !chain.contains("secreq"),
                "our own frames are not the caller: {chain}"
            );
        }
    });
}
