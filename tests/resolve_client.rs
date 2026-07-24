//! End-to-end tests for the **guest** client — the real `secreq resolve`
//! binary, against a real scoped agent socket.
//!
//! No VM and no daemon. The test process plays the host: it binds a socket in
//! the test's sandbox and serves it with `scoped_agent::serve_on` and a
//! synthetic [`Gate`] (the same instrument `tests/scoped_agent.rs` uses), then
//! runs the built binary with `$SECREQ_SOCK` pointed at it. What's exercised
//! is the production path a guest takes: env → dial → framed protocol →
//! stdout.
//!
//! **These tests are mostly about stdout.** `secreq resolve` exists to be
//! substituted into a shell — `export GH_TOKEN="$(secreq resolve …)"` — so
//! "the value and nothing but the value on stdout" is not a nicety, it is the
//! interface. A stray diagnostic line would silently end up *inside* someone's
//! token, and a denial that printed to stdout would export the word "denied"
//! as a credential. Every assertion below that looks pedantic about a stream
//! is guarding that.
//!
//! Isolation comes from [`common::Sandbox`]: the host half of a test (the
//! in-process `serve_on`, and the audit rows it writes) runs under
//! [`common::Sandbox::enter`], and the spawned binary is built by
//! [`common::Sandbox::cmd`], which applies the same complete pin set.

mod common;

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

/// A scoped agent listening on a socket inside the sandbox's runtime dir.
/// The sandbox owns the path's lifetime; the serving thread exits with the
/// process.
struct Host {
    socket: PathBuf,
}

impl Host {
    fn serving(sb: &common::Sandbox, decision: Decision) -> Host {
        let socket = sb.runtime_dir().join("scoped.sock");
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
        Host { socket }
    }

    /// Run `secreq resolve …` as a guest would: `$SECREQ_SOCK` set, and
    /// nothing else configured.
    fn run(&self, sb: &common::Sandbox, args: &[&str]) -> Output {
        run_resolve(sb, Some(&self.socket), args)
    }
}

/// Run the real binary with `$SECREQ_SOCK` set to `socket` (or explicitly
/// unset), fully sandboxed via [`common::Sandbox::cmd`] — the complete pin
/// set, `SECREQ_NO_DAEMON=1` (nothing on this path should ever dial the local
/// daemon; if a regression made it try, we want a failure rather than a
/// window on the developer's screen), and the live socket vars removed.
///
/// The socket is applied *after* `cmd`'s defaults, so it wins over the
/// sandbox's removal of `SECREQ_SOCK`; `None` simply keeps that removal.
fn run_resolve(sb: &common::Sandbox, socket: Option<&Path>, args: &[&str]) -> Output {
    let mut full_args = vec!["resolve"];
    full_args.extend_from_slice(args);
    let mut command = sb.cmd(&full_args);
    if let Some(path) = socket {
        command.env("SECREQ_SOCK", path);
    }
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
    let sb = common::Sandbox::new();
    let _env = sb.enter();
    let host = Host::serving(&sb, Decision::Approve);

    let output = host.run(&sb, &[ALLOWED_REF]);

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
}

/// The shell contract itself: what `$(…)` actually binds is the value, with
/// no newline and no extra. Asserted through a real shell rather than by
/// reasoning about the bytes above, because that substitution is the entire
/// reason for the stdout rule.
#[test]
fn the_value_substitutes_cleanly_into_a_shell_variable() {
    let sb = common::Sandbox::new();
    let _env = sb.enter();
    let host = Host::serving(&sb, Decision::Approve);

    let mut command = Command::new("sh");
    command.arg("-c").arg(format!(
        r#"GH_TOKEN="$({} resolve {ALLOWED_REF})"; printf '[%s]' "$GH_TOKEN""#,
        common::bin(),
    ));
    // The `secreq` under this shell is a real binary running the real
    // `cli::run`, migration and all. Its isolation is the environment the
    // shell inherits — which `sb.enter()` above has pinned to the *complete*
    // sandbox set (and holds locked for the duration), so the inheritance is
    // the full pin, not a lucky subset. Only the socket is layered on top.
    let output = command
        .env("SECREQ_SOCK", &host.socket)
        .output()
        .expect("run the shell");

    assert_eq!(
        stdout(&output),
        format!("[{SECRET_VALUE}]"),
        "the substituted variable must be the value exactly"
    );
}

/// The bare shorthand resolves too, matching `read` and `agent open --allow`.
#[test]
fn the_bare_provider_locator_shorthand_resolves() {
    let sb = common::Sandbox::new();
    let _env = sb.enter();
    let host = Host::serving(&sb, Decision::Approve);

    let output = host.run(&sb, &["op/Dev/gh/token"]);

    assert_eq!(code(&output), 0, "stderr: {}", stderr(&output));
    assert_eq!(stdout(&output), format!("{SECRET_VALUE}\n"));
}

/// `--list` answers the scope's allowed names, one per line, and never a
/// value.
#[test]
fn list_prints_the_allowed_ref_names_one_per_line() {
    let sb = common::Sandbox::new();
    let _env = sb.enter();
    let host = Host::serving(&sb, Decision::Approve);

    let output = host.run(&sb, &["--list"]);

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
}

/// `$SECREQ_SOCK` unset is the most likely mistake (running it on the host,
/// or in a tier with no forward). It must say so, exit non-zero, print
/// nothing on stdout, and not panic.
#[test]
fn an_unset_secreq_sock_is_a_clear_error_and_not_a_panic() {
    let sb = common::Sandbox::new();

    let output = run_resolve(&sb, None, &[ALLOWED_REF]);

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
    let sb = common::Sandbox::new();

    let output = run_resolve(
        &sb,
        Some(&sb.runtime_dir().join("not-a-socket.sock")),
        &[ALLOWED_REF],
    );

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
    let sb = common::Sandbox::new();
    let path = sb.runtime_dir().join("stale.sock");
    drop(UnixListener::bind(&path).expect("bind"));

    let output = run_resolve(&sb, Some(&path), &[ALLOWED_REF]);

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
    let sb = common::Sandbox::new();
    let _env = sb.enter();
    let host = Host::serving(&sb, Decision::Deny);

    let output = host.run(&sb, &[ALLOWED_REF]);

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
}

/// An out-of-scope ref surfaces #41's silent denial intelligibly: the guest
/// is told the ref is outside the socket's scope — and the host never raised
/// a prompt to tell it.
#[test]
fn an_out_of_scope_ref_surfaces_the_hosts_denial() {
    let sb = common::Sandbox::new();
    let _env = sb.enter();
    // The gate would approve anything it was asked about, so a denial
    // here can only have come from the allowlist, upstream of any prompt.
    let host = Host::serving(&sb, Decision::Approve);

    let output = host.run(&sb, &[OUT_OF_SCOPE_REF]);

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
}

/// A malformed ref fails locally, before a socket is even dialled — a typo
/// should read as a typo, not as a broken host.
#[test]
fn a_malformed_reference_is_rejected_locally_with_the_shape_it_should_have() {
    let sb = common::Sandbox::new();

    let output = run_resolve(&sb, None, &["definitely-not-a-ref"]);

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
    let sb = common::Sandbox::new();

    let output = run_resolve(&sb, None, &[]);

    assert_no_panic(&output);
    assert_ne!(code(&output), 0);
    assert_eq!(stdout(&output), "");
}

/// A ref *and* `--list` is refused by the parser rather than silently
/// preferring one.
#[test]
fn a_ref_and_list_together_are_refused() {
    let sb = common::Sandbox::new();

    let output = run_resolve(&sb, None, &[ALLOWED_REF, "--list"]);

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

    let sb = common::Sandbox::new();
    let _env = sb.enter();
    let socket = sb.runtime_dir().join("scoped.sock");
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

    let output = run_resolve(&sb, Some(&socket), &[ALLOWED_REF]);
    assert_eq!(code(&output), 0, "stderr: {}", stderr(&output));

    let chains = gate.0.lock().expect("chains mutex").clone();
    assert_eq!(chains.len(), 1, "the resolve must have raised one prompt");
    if let Some(chain) = &chains[0] {
        assert!(
            !chain.contains("secreq"),
            "our own frames are not the caller: {chain}"
        );
    }
}
