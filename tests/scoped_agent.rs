//! End-to-end tests for the scoped secret agent over a **real unix socket**.
//!
//! No VM and no daemon: `serve_on` is driven directly with a synthetic
//! [`Gate`] (mirroring how `tests/ssh_agent.rs` drives the SSH agent's
//! `serve_on` with a synthetic `SignContext`), and a client dials the socket
//! and speaks the real framed protocol. What's exercised is the production
//! path from bytes on a socket through allowlist enforcement to a response —
//! the same code a guest's `ssh -R`-forwarded connection lands on.
//!
//! The [`RecordingGate`] is the instrument for the load-bearing assertion.
//! The gate is the *only* door to the consent machinery, so "the gate was
//! never called" is exactly "no prompt was raised" — an observable fact, not
//! a proxy for one.

use std::io::Write;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex};

use secreq::audit;
use secreq::consent::Decision;
use secreq::reference::Reference;
use secreq::scoped_agent::proto::{read_message, write_message, Request, Response};
use secreq::scoped_agent::{serve_on, Gate, GateOutcome, Scope};
use secreq::secret::SecretValue;

/// The value the fake gate hands back on approve. Deliberately distinctive
/// so the "never in the audit log" assertions can search for it verbatim.
const SECRET_VALUE: &str = "ghp_liveTokenValue_DEADBEEF_do_not_log_me";

const ALLOWED_REF: &str = "secret://op/Dev/gh/token";
const OTHER_ALLOWED_REF: &str = "secret://op/Dev/linear/token";
const OUT_OF_SCOPE_REF: &str = "secret://op/Prod/aws/root_key";

fn reference(s: &str) -> Reference {
    Reference::parse(s).expect("valid reference")
}

fn test_scope() -> Scope {
    Scope::new(
        "brain-nx-t5",
        vec![reference(ALLOWED_REF), reference(OTHER_ALLOWED_REF)],
    )
    .expect("valid scope")
}

/// A [`Gate`] that records the refs it was asked to gate. Approves
/// everything it *is* asked about — so any denial a test observes must have
/// come from the allowlist, upstream of here, which is the point.
struct RecordingGate {
    calls: Mutex<Vec<String>>,
}

impl RecordingGate {
    fn new() -> Arc<RecordingGate> {
        Arc::new(RecordingGate {
            calls: Mutex::new(Vec::new()),
        })
    }
    fn calls(&self) -> Vec<String> {
        self.calls.lock().expect("calls mutex").clone()
    }
}

impl Gate for RecordingGate {
    fn resolve(&self, _scope: &Scope, reference: &Reference) -> GateOutcome {
        self.calls
            .lock()
            .expect("calls mutex")
            .push(reference.to_string());
        GateOutcome::Approved {
            decision: Decision::Approve,
            value: SecretValue::new(SECRET_VALUE.to_owned()),
        }
    }
}

/// Bind a socket in a tempdir, serve it on a background thread, and hand
/// back everything the test needs to talk to it.
///
/// The `TempDir` is returned (not dropped) so the socket path outlives the
/// call; the listener thread exits when the process does.
struct Harness {
    _dir: tempfile::TempDir,
    socket: std::path::PathBuf,
    gate: Arc<RecordingGate>,
}

impl Harness {
    fn start() -> Harness {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("scoped.sock");
        let listener = UnixListener::bind(&socket).expect("bind scoped agent socket");
        let gate = RecordingGate::new();
        let serve_gate: Arc<dyn Gate> = gate.clone();
        std::thread::spawn(move || serve_on(listener, Arc::new(test_scope()), serve_gate));
        Harness {
            _dir: dir,
            socket,
            gate,
        }
    }

    fn connect(&self) -> UnixStream {
        UnixStream::connect(&self.socket).expect("connect to scoped agent socket")
    }

    /// Send one request and read one response over a fresh connection.
    fn round_trip(&self, request: &Request) -> Response {
        let mut stream = self.connect();
        write_message(&mut stream, request).expect("write request");
        read_message::<Response, _>(&mut stream)
            .expect("read response")
            .expect("a response frame")
    }
}

/// Run `f` with `$XDG_STATE_HOME` pointed at a fresh tempdir so audit
/// appends land there instead of the developer's real state dir, and
/// `read_history` inside `f` reads them back.
///
/// A process-wide lock serializes callers: `$XDG_STATE_HOME` is
/// process-global, so two of these running concurrently in this test binary
/// would clobber each other's target dir. (The same reasoning as
/// `audit::with_temp_log`, which is `cfg(test)`-internal to the crate and so
/// isn't reachable from an integration test.)
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

/// An allowed ref resolves: the gate is consulted and the value crosses.
#[test]
fn allowed_ref_resolves_over_the_socket() {
    with_temp_audit_log(|| {
        let harness = Harness::start();

        let response = harness.round_trip(&Request::Resolve {
            reference: ALLOWED_REF.to_owned(),
        });

        assert_eq!(
            response,
            Response::Value {
                value: SECRET_VALUE.to_owned()
            },
            "an allowed ref must resolve to its value"
        );
        assert_eq!(
            harness.gate.calls(),
            vec![ALLOWED_REF],
            "an allowed ref must reach the gate (i.e. must be gated by consent)"
        );

        let history = audit::read_history(None).expect("read audit history");
        assert_eq!(history.len(), 1, "the release must be audited");
        assert_eq!(history[0].wrap, "agent:brain-nx-t5");
        assert_eq!(history[0].secrets, vec![ALLOWED_REF]);
        assert_eq!(history[0].decision, "approve");
    });
}

/// **The load-bearing test.** A ref outside the declared scope is denied,
/// the gate (and therefore the prompt) is never reached, and the attempt is
/// audited.
#[test]
fn out_of_scope_ref_is_denied_with_no_prompt_and_an_audit_row() {
    with_temp_audit_log(|| {
        let harness = Harness::start();

        let response = harness.round_trip(&Request::Resolve {
            reference: OUT_OF_SCOPE_REF.to_owned(),
        });

        match response {
            Response::Denied { .. } => {}
            other => panic!("out-of-scope ref must be denied, got {other:?}"),
        }

        // NO PROMPT: the gate is the only route to the consent machinery,
        // and it was never called. This is what stops a compromised guest
        // from enumerating the vault one prompt at a time, and what stops
        // the user being trained to click through.
        assert!(
            harness.gate.calls().is_empty(),
            "an out-of-scope ref must never reach the gate — no prompt may be raised"
        );

        // ...but it IS audited, so a probing guest is visible.
        let history = audit::read_history(None).expect("read audit history");
        assert_eq!(history.len(), 1, "the denial must be audited");
        assert_eq!(history[0].wrap, "agent:brain-nx-t5");
        assert_eq!(history[0].secrets, vec![OUT_OF_SCOPE_REF]);
        assert_eq!(
            history[0].decision, "deny+out-of-scope",
            "the row must record that the user was never asked, not a plain deny"
        );
        assert!(
            history[0].callers.is_empty(),
            "a guest has no host caller chain; the row must not invent one"
        );
    });
}

/// `list` returns the allowed names only, never prompts, and never leaks a
/// value.
#[test]
fn list_returns_allowed_names_only_and_never_prompts() {
    with_temp_audit_log(|| {
        let harness = Harness::start();

        let response = harness.round_trip(&Request::List);

        assert_eq!(
            response,
            Response::Refs {
                refs: vec![ALLOWED_REF.to_owned(), OTHER_ALLOWED_REF.to_owned()],
            },
            "list must answer exactly the declared allowlist"
        );
        assert!(
            harness.gate.calls().is_empty(),
            "listing is free — it must never prompt"
        );
        assert!(
            audit::read_history(None)
                .expect("read audit history")
                .is_empty(),
            "list releases nothing, so it writes no audit row"
        );
    });
}

/// An unknown verb errors — and the error says nothing that would help a
/// guest enumerate anything.
#[test]
fn unknown_verb_errors() {
    with_temp_audit_log(|| {
        let harness = Harness::start();
        let mut stream = harness.connect();

        // Hand-rolled frame: an unknown verb can't be built from the
        // `Request` enum, which is the point — the protocol is closed.
        let payload = br#"{"op":"enumerate_everything"}"#;
        let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(payload);
        stream.write_all(&frame).expect("write unknown verb frame");
        stream.flush().expect("flush");

        let response = read_message::<Response, _>(&mut stream)
            .expect("read response")
            .expect("a response frame");

        match &response {
            Response::Error { message } => {
                assert!(
                    !message.contains("secret://"),
                    "an error must not name any ref: {message}"
                );
            }
            other => panic!("an unknown verb must error, got {other:?}"),
        }
        assert!(
            harness.gate.calls().is_empty(),
            "an unknown verb must never reach the gate"
        );
    });
}

/// A malformed ref is an error, not a denial — nothing was refused because
/// nothing coherent was asked.
#[test]
fn malformed_reference_errors_without_gating() {
    with_temp_audit_log(|| {
        let harness = Harness::start();

        let response = harness.round_trip(&Request::Resolve {
            reference: "definitely-not-a-ref".to_owned(),
        });

        assert!(matches!(response, Response::Error { .. }));
        assert!(harness.gate.calls().is_empty());
    });
}

/// One connection carries several requests: a guest lists, then resolves,
/// without redialing. Also proves the framing doesn't desynchronize across
/// pipelined messages.
#[test]
fn one_connection_serves_list_then_resolve() {
    with_temp_audit_log(|| {
        let harness = Harness::start();
        let mut stream = harness.connect();

        write_message(&mut stream, &Request::List).expect("write list");
        let listed = read_message::<Response, _>(&mut stream)
            .expect("read list response")
            .expect("a response");
        assert!(matches!(listed, Response::Refs { .. }));

        write_message(
            &mut stream,
            &Request::Resolve {
                reference: ALLOWED_REF.to_owned(),
            },
        )
        .expect("write resolve");
        let resolved = read_message::<Response, _>(&mut stream)
            .expect("read resolve response")
            .expect("a response");
        assert_eq!(
            resolved,
            Response::Value {
                value: SECRET_VALUE.to_owned()
            }
        );
    });
}

/// **The secret value must never appear in the audit log** — not on the
/// approve row, not anywhere in the file. Asserted against the raw file
/// bytes rather than the parsed rows, so a value smuggled into any field
/// (or a future field) still trips this.
#[test]
fn the_secret_value_never_appears_in_the_audit_log() {
    with_temp_audit_log(|| {
        let harness = Harness::start();

        // Exercise every path that writes a row: an approve and a denial.
        harness.round_trip(&Request::Resolve {
            reference: ALLOWED_REF.to_owned(),
        });
        harness.round_trip(&Request::Resolve {
            reference: OUT_OF_SCOPE_REF.to_owned(),
        });
        harness.round_trip(&Request::List);

        let path = audit::audit_log_path().expect("audit log path");
        let raw = std::fs::read_to_string(&path).expect("read raw audit log");

        assert!(
            !raw.contains(SECRET_VALUE),
            "the secret value leaked into the audit log:\n{raw}"
        );
        // Sanity: the rows we expect really are there, so the assertion
        // above isn't passing vacuously against an empty file.
        assert!(
            raw.contains("agent:brain-nx-t5"),
            "expected the scope's rows in the log:\n{raw}"
        );
        assert!(raw.contains(ALLOWED_REF), "expected the approve row");
        assert!(raw.contains("deny+out-of-scope"), "expected the deny row");
    });
}

/// The refs a scope was never opened with are invisible: neither `list` nor
/// a denial names them. A guest cannot use this socket to learn what else
/// the host holds.
#[test]
fn a_denial_never_names_another_ref() {
    with_temp_audit_log(|| {
        let harness = Harness::start();

        let response = harness.round_trip(&Request::Resolve {
            reference: OUT_OF_SCOPE_REF.to_owned(),
        });

        let Response::Denied { message } = response else {
            panic!("expected a denial");
        };
        assert!(
            !message.contains(ALLOWED_REF) && !message.contains(OTHER_ALLOWED_REF),
            "a denial must not enumerate the scope's other refs: {message}"
        );
    });
}
