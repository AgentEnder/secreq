//! End-to-end tests for the scoped secret agent over a **real unix socket**.
//!
//! No VM and no daemon: `serve_on` is driven directly with a synthetic
//! [`Gate`] (mirroring how `tests/ssh_agent.rs` drives the SSH agent's
//! `serve_on` with a synthetic `SignContext`), and a client dials the socket
//! and speaks the real framed protocol. What's exercised is the production
//! path from bytes on a socket through allowlist enforcement to a response —
//! the same code a guest's `ssh -R`-forwarded connection lands on.
//!
//! The [`RecordingGate`] is the instrument for the load-bearing assertions.
//! `Gate::consent` is the *only* door to the consent machinery, so "consent
//! was never called" is exactly "no prompt was raised" — an observable fact,
//! not a proxy for one. It counts `resolve` separately, because the two are
//! *meant* to diverge: a cached release prompts zero times and resolves once,
//! which is the design's "only the decision caches, never the material"
//! invariant made countable.

use std::io::Write;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use secreq::audit;
use secreq::audit::{AuditLocalPeer, ScopeDeclarant};
use secreq::consent::Decision;
use secreq::reference::Reference;
use secreq::scoped_agent::proto::{read_message, write_message, Request, Response};
use secreq::scoped_agent::{serve_on, Clock, Consented, Gate, GuestChain, Scope, ScopeApprovals};
use secreq::secret::SecretValue;

mod common;

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

/// A [`Gate`] that records every prompt it was asked to raise and every
/// resolve it performed, and answers `consent` with a canned decision.
///
/// It approves whatever it *is* asked about by default — so any denial a
/// test observes must have come from the allowlist, upstream of here, which
/// is the point.
struct RecordingGate {
    prompts: Mutex<Vec<String>>,
    resolves: Mutex<Vec<String>>,
    /// The guest's claim as `consent` saw it. Asserted on to prove the chain
    /// *does* reach the prompt — display is the one thing it's for, and a
    /// test that only proved it was ignored everywhere would be equally
    /// satisfied by dropping it on the floor.
    seen_chains: Mutex<Vec<Option<String>>>,
    decision: Decision,
    reason: Option<String>,
}

impl RecordingGate {
    fn new() -> Arc<RecordingGate> {
        RecordingGate::deciding(Decision::Approve)
    }

    fn deciding(decision: Decision) -> Arc<RecordingGate> {
        Arc::new(RecordingGate {
            prompts: Mutex::new(Vec::new()),
            resolves: Mutex::new(Vec::new()),
            seen_chains: Mutex::new(Vec::new()),
            decision,
            reason: None,
        })
    }

    fn denying_with_reason(reason: &str) -> Arc<RecordingGate> {
        let mut gate = Arc::try_unwrap(RecordingGate::deciding(Decision::Deny))
            .ok()
            .expect("new gate has one owner");
        gate.reason = Some(reason.to_owned());
        Arc::new(gate)
    }

    fn prompts(&self) -> Vec<String> {
        self.prompts.lock().expect("prompts mutex").clone()
    }

    fn resolves(&self) -> Vec<String> {
        self.resolves.lock().expect("resolves mutex").clone()
    }

    fn seen_chains(&self) -> Vec<Option<String>> {
        self.seen_chains.lock().expect("chains mutex").clone()
    }
}

impl Gate for RecordingGate {
    fn consent(
        &self,
        _scope: &Scope,
        reference: &Reference,
        guest_chain: &GuestChain,
    ) -> Result<Consented> {
        self.prompts
            .lock()
            .expect("prompts mutex")
            .push(reference.to_string());
        self.seen_chains
            .lock()
            .expect("chains mutex")
            .push(guest_chain.display().map(str::to_owned));
        Ok(Consented {
            decision: self.decision,
            reason: self.reason.clone(),
            declared_by: ScopeDeclarant::Peer(AuditLocalPeer {
                pid: 4711,
                name: "secreq".to_owned(),
                command: "secreq agent open brain-nx-t5".to_owned(),
                exe: Some("/usr/local/bin/secreq".to_owned()),
            }),
        })
    }

    fn resolve(&self, _scope: &Scope, reference: &Reference) -> Result<SecretValue> {
        self.resolves
            .lock()
            .expect("resolves mutex")
            .push(reference.to_string());
        Ok(SecretValue::new(SECRET_VALUE.to_owned()))
    }
}

/// A clock the test winds by hand.
///
/// The TTL is five minutes, and a test that proved expiry by sleeping for
/// five minutes would be deleted by the first person who ran the suite —
/// so the clock is injected and expiry is asserted as a property rather
/// than assumed.
struct FakeClock(Mutex<u64>);

impl FakeClock {
    fn at(now: u64) -> Arc<FakeClock> {
        Arc::new(FakeClock(Mutex::new(now)))
    }
    fn advance(&self, secs: u64) {
        *self.0.lock().expect("clock mutex") += secs;
    }
}

impl Clock for FakeClock {
    fn now_unix(&self) -> u64 {
        *self.0.lock().expect("clock mutex")
    }
}

/// The TTL the harness's approvals run with. Deliberately not
/// `SCOPE_GRANT_TTL_SECS`: the tests assert the *mechanism* (a grant lives
/// exactly as long as its stamp says), and pinning them to the production
/// constant would make retuning it a test-editing exercise.
const TEST_TTL_SECS: u64 = 300;

/// Bind a socket in a tempdir, serve it on a background thread, and hand
/// back everything the test needs to talk to it.
///
/// The `TempDir` is returned (not dropped) so the socket path outlives the
/// call; the listener thread exits when the process does.
struct Harness {
    _dir: tempfile::TempDir,
    socket: std::path::PathBuf,
    gate: Arc<RecordingGate>,
    clock: Arc<FakeClock>,
}

impl Harness {
    fn start() -> Harness {
        Harness::with_gate(RecordingGate::new())
    }

    fn with_gate(gate: Arc<RecordingGate>) -> Harness {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("scoped.sock");
        let listener = UnixListener::bind(&socket).expect("bind scoped agent socket");
        let clock = FakeClock::at(1_000_000);
        let approvals = Arc::new(ScopeApprovals::with_clock(clock.clone(), TEST_TTL_SECS));
        let serve_gate: Arc<dyn Gate> = gate.clone();
        std::thread::spawn(move || {
            serve_on(listener, Arc::new(test_scope()), approvals, serve_gate);
        });
        Harness {
            _dir: dir,
            socket,
            gate,
            clock,
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

/// An allowed ref resolves: the gate is consulted and the value crosses.
#[test]
fn allowed_ref_resolves_over_the_socket() {
    let sb = common::Sandbox::new();
    let _env = sb.enter();

    let harness = Harness::start();

    let response = harness.round_trip(&Request::resolve(ALLOWED_REF));

    assert_eq!(
        response,
        Response::Value {
            value: SECRET_VALUE.to_owned()
        },
        "an allowed ref must resolve to its value"
    );
    assert_eq!(
        harness.gate.prompts(),
        vec![ALLOWED_REF],
        "an allowed ref must reach the gate (i.e. must be gated by consent)"
    );
    assert_eq!(
        harness.gate.resolves(),
        vec![ALLOWED_REF],
        "and must be resolved fresh, not served from anything"
    );

    let history = audit::read_history(None).expect("read audit history");
    assert_eq!(history.len(), 1, "the release must be audited");
    assert_eq!(history[0].wrap, "agent:brain-nx-t5");
    assert_eq!(history[0].secrets, vec![ALLOWED_REF]);
    assert_eq!(history[0].decision, "approve");
}

/// **The load-bearing test.** A ref outside the declared scope is denied,
/// the gate (and therefore the prompt) is never reached, and the attempt is
/// audited.
#[test]
fn out_of_scope_ref_is_denied_with_no_prompt_and_an_audit_row() {
    let sb = common::Sandbox::new();
    let _env = sb.enter();

    let harness = Harness::start();

    let response = harness.round_trip(&Request::resolve(OUT_OF_SCOPE_REF));

    match response {
        Response::Denied { .. } => {}
        other => panic!("out-of-scope ref must be denied, got {other:?}"),
    }

    // NO PROMPT: the gate is the only route to the consent machinery,
    // and it was never called. This is what stops a compromised guest
    // from enumerating the vault one prompt at a time, and what stops
    // the user being trained to click through.
    assert!(
        harness.gate.prompts().is_empty(),
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
}

/// `list` returns the allowed names only, never prompts, and never leaks a
/// value.
#[test]
fn list_returns_allowed_names_only_and_never_prompts() {
    let sb = common::Sandbox::new();
    let _env = sb.enter();

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
        harness.gate.prompts().is_empty(),
        "listing is free — it must never prompt"
    );
    assert!(
        audit::read_history(None)
            .expect("read audit history")
            .is_empty(),
        "list releases nothing, so it writes no audit row"
    );
}

/// An unknown verb errors — and the error says nothing that would help a
/// guest enumerate anything.
#[test]
fn unknown_verb_errors() {
    let sb = common::Sandbox::new();
    let _env = sb.enter();

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
        harness.gate.prompts().is_empty(),
        "an unknown verb must never reach the gate"
    );
}

/// A malformed ref is an error, not a denial — nothing was refused because
/// nothing coherent was asked.
#[test]
fn malformed_reference_errors_without_gating() {
    let sb = common::Sandbox::new();
    let _env = sb.enter();

    let harness = Harness::start();

    let response = harness.round_trip(&Request::resolve("definitely-not-a-ref"));

    assert!(matches!(response, Response::Error { .. }));
    assert!(harness.gate.prompts().is_empty());
}

/// One connection carries several requests: a guest lists, then resolves,
/// without redialing. Also proves the framing doesn't desynchronize across
/// pipelined messages.
#[test]
fn one_connection_serves_list_then_resolve() {
    let sb = common::Sandbox::new();
    let _env = sb.enter();

    let harness = Harness::start();
    let mut stream = harness.connect();

    write_message(&mut stream, &Request::List).expect("write list");
    let listed = read_message::<Response, _>(&mut stream)
        .expect("read list response")
        .expect("a response");
    assert!(matches!(listed, Response::Refs { .. }));

    write_message(&mut stream, &Request::resolve(ALLOWED_REF)).expect("write resolve");
    let resolved = read_message::<Response, _>(&mut stream)
        .expect("read resolve response")
        .expect("a response");
    assert_eq!(
        resolved,
        Response::Value {
            value: SECRET_VALUE.to_owned()
        }
    );
}

/// **The secret value must never appear in the audit log** — not on the
/// approve row, not anywhere in the file. Asserted against the raw file
/// bytes rather than the parsed rows, so a value smuggled into any field
/// (or a future field) still trips this.
#[test]
fn the_secret_value_never_appears_in_the_audit_log() {
    let sb = common::Sandbox::new();
    let _env = sb.enter();

    let harness = Harness::start();

    // Exercise every path that writes a row: an approve and a denial.
    harness.round_trip(&Request::resolve(ALLOWED_REF));
    harness.round_trip(&Request::resolve(OUT_OF_SCOPE_REF));
    harness.round_trip(&Request::List);

    let path = secreq::paths::audit_log_path().expect("audit log path");
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
}

// ── Scope anchoring: TTL-cached decisions ────────────────────────────────

/// The baseline: the **first** request for a ref prompts, and a **second**
/// within the TTL does not — the user anchored the approval to the scope.
///
/// The `resolves` count is the other half of the invariant and matters just
/// as much: two releases, two fresh resolutions. The *decision* is what was
/// cached; the material was fetched again and zeroized again, exactly as if
/// the user had been asked twice.
#[test]
fn a_second_request_within_the_ttl_is_served_without_a_prompt() {
    let sb = common::Sandbox::new();
    let _env = sb.enter();

    let harness = Harness::with_gate(RecordingGate::deciding(Decision::ApproveAgentSession));

    let first = harness.round_trip(&Request::resolve(ALLOWED_REF));
    let second = harness.round_trip(&Request::resolve(ALLOWED_REF));

    for response in [&first, &second] {
        assert_eq!(
            response,
            &Response::Value {
                value: SECRET_VALUE.to_owned()
            },
            "both requests must release the secret"
        );
    }
    assert_eq!(
        harness.gate.prompts(),
        vec![ALLOWED_REF],
        "the second request must ride the scope's grant — exactly one prompt"
    );
    assert_eq!(
        harness.gate.resolves(),
        vec![ALLOWED_REF, ALLOWED_REF],
        "the decision caches; the MATERIAL must be resolved fresh every time"
    );

    // Both releases are audited, and the cached one says so — a reader
    // must be able to tell "the user said yes" from "the user wasn't
    // asked".
    let history = audit::read_history(None).expect("read audit history");
    assert_eq!(history.len(), 2, "every release is audited, cached or not");
    assert_eq!(history[0].decision, "approve+agent-session");
    assert_eq!(
        history[1].decision, "approve+cached",
        "a silent release must record that the user was never asked"
    );
}

/// A plain `Approve` is "this request only": it anchors nothing, so the next
/// request prompts again. Only the explicit TTL action grants a session.
#[test]
fn a_plain_approve_anchors_nothing_and_the_next_request_prompts_again() {
    let sb = common::Sandbox::new();
    let _env = sb.enter();

    let harness = Harness::with_gate(RecordingGate::deciding(Decision::Approve));

    harness.round_trip(&Request::resolve(ALLOWED_REF));
    harness.round_trip(&Request::resolve(ALLOWED_REF));

    assert_eq!(
        harness.gate.prompts(),
        vec![ALLOWED_REF, ALLOWED_REF],
        "`Approve` means once; only `ApproveAgentSession` may skip a later prompt"
    );
}

/// The grant is per-`(scope, ref)`. Approving `GH_TOKEN` for a sandbox must
/// not silently release `LINEAR_TOKEN` to it — the user was shown one ref
/// and consented to that one.
#[test]
fn a_grant_for_one_ref_does_not_cover_another_in_the_same_scope() {
    let sb = common::Sandbox::new();
    let _env = sb.enter();

    let harness = Harness::with_gate(RecordingGate::deciding(Decision::ApproveAgentSession));

    harness.round_trip(&Request::resolve(ALLOWED_REF));
    harness.round_trip(&Request::resolve(OTHER_ALLOWED_REF));

    assert_eq!(
        harness.gate.prompts(),
        vec![ALLOWED_REF, OTHER_ALLOWED_REF],
        "a second, different ref must raise its own prompt"
    );
}

/// **Expiry.** Once the TTL lapses, the same scope asking for the same ref
/// prompts again — the anchor is still alive (the socket is still up), and
/// that is exactly why the timer exists.
#[test]
fn a_request_after_the_ttl_expires_prompts_again() {
    let sb = common::Sandbox::new();
    let _env = sb.enter();

    let harness = Harness::with_gate(RecordingGate::deciding(Decision::ApproveAgentSession));

    harness.round_trip(&Request::resolve(ALLOWED_REF));
    // One second short of expiry: still silent.
    harness.clock.advance(TEST_TTL_SECS - 1);
    harness.round_trip(&Request::resolve(ALLOWED_REF));
    assert_eq!(
        harness.gate.prompts(),
        vec![ALLOWED_REF],
        "a grant must cover the full TTL"
    );

    // ...and one second later, it's dead.
    harness.clock.advance(1);
    harness.round_trip(&Request::resolve(ALLOWED_REF));
    assert_eq!(
        harness.gate.prompts(),
        vec![ALLOWED_REF, ALLOWED_REF],
        "an expired grant must re-prompt even though the scope is unchanged"
    );
}

/// **A denial is never cached as an approval.** The obvious catastrophe if
/// the cache stored "the decision" too literally: a refusal that later reads
/// back as a hit would turn "no" into a silent "yes" for five minutes.
#[test]
fn a_denial_is_not_cached_and_never_becomes_a_silent_approval() {
    let sb = common::Sandbox::new();
    let _env = sb.enter();

    let harness = Harness::with_gate(RecordingGate::deciding(Decision::Deny));

    let first = harness.round_trip(&Request::resolve(ALLOWED_REF));
    let second = harness.round_trip(&Request::resolve(ALLOWED_REF));

    for response in [&first, &second] {
        assert!(
            matches!(response, Response::Denied { .. }),
            "a denied ref must stay denied, got {response:?}"
        );
    }
    // Re-prompted rather than served from a cached "no" — and, more to
    // the point, never served from a cached "yes".
    assert_eq!(
        harness.gate.prompts(),
        vec![ALLOWED_REF, ALLOWED_REF],
        "a denial must not populate the cache in either direction"
    );
    assert!(
        harness.gate.resolves().is_empty(),
        "a denied ref must never be resolved at all"
    );

    let history = audit::read_history(None).expect("read audit history");
    assert_eq!(history.len(), 2);
    for row in &history {
        assert_eq!(row.decision, "deny");
    }
}

#[test]
fn a_host_denial_reason_is_audited_but_never_forwarded_to_the_guest() {
    let sb = common::Sandbox::new();
    let _env = sb.enter();
    let host_reason = "wrong production repository";
    let harness = Harness::with_gate(RecordingGate::denying_with_reason(host_reason));

    let response = harness.round_trip(&Request::resolve(ALLOWED_REF));
    assert_eq!(
        response,
        Response::Denied {
            message: "denied".to_owned()
        },
        "the scoped-agent wire must remain deliberately uninformative"
    );

    let history = audit::read_history(None).expect("read audit history");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].reason.as_deref(), Some(host_reason));
}

// ── The guest-reported chain: display-only ───────────────────────────────

/// **The load-bearing test for #42.** Two requests, the **same scope and
/// ref**, but wildly different guest-reported chains — the second must ride
/// the first's grant.
///
/// This is what proves the chain is not in the cache key, and it proves it
/// the only way that counts: by observation, not by inspection. If the chain
/// keyed the cache in any way, the second request's fabricated chain would
/// miss and re-prompt.
///
/// The attack this forecloses runs the other way round. A compromised guest
/// that could *steer* the key would replay a chain the user approved earlier
/// and be handed a **silent** release — no prompt, no chance to notice. Here
/// the guest changes its story completely and it changes nothing: the gate
/// rests on the scope, which the host declared and the guest cannot touch.
#[test]
fn a_different_guest_chain_hits_the_same_cache_entry_and_does_not_reprompt() {
    let sb = common::Sandbox::new();
    let _env = sb.enter();

    let harness = Harness::with_gate(RecordingGate::deciding(Decision::ApproveAgentSession));

    // The user sees this chain and approves the scope for 5 minutes.
    harness.round_trip(&Request::resolve_claiming(
        ALLOWED_REF,
        vec!["node".to_owned(), "pnpm".to_owned(), "build".to_owned()],
    ));

    // A totally different claim, same scope, same ref, well within TTL.
    let second = harness.round_trip(&Request::resolve_claiming(
        ALLOWED_REF,
        vec!["curl".to_owned(), "exfiltrate.sh".to_owned()],
    ));

    assert_eq!(
        second,
        Response::Value {
            value: SECRET_VALUE.to_owned()
        }
    );
    assert_eq!(
        harness.gate.prompts(),
        vec![ALLOWED_REF],
        "a differing guest chain must NOT create a new cache entry or re-prompt — \
         proof the chain is not part of the key"
    );
    assert_eq!(
        harness.gate.resolves(),
        vec![ALLOWED_REF, ALLOWED_REF],
        "both releases resolve fresh"
    );

    // The chain reached the prompt exactly once — on the request that
    // actually raised one. It is display, so it has nothing to say on a
    // request nobody was shown.
    assert_eq!(
        harness.gate.seen_chains(),
        vec![Some("node → pnpm → build".to_owned())]
    );
}

/// The converse: a guest that claims *nothing* rides a grant earned while
/// claiming *something*, and vice versa. Absence of a chain is not a
/// distinguishing feature either, because the chain is not a feature of the
/// key at all.
#[test]
fn dropping_the_guest_chain_entirely_still_hits_the_same_cache_entry() {
    let sb = common::Sandbox::new();
    let _env = sb.enter();

    let harness = Harness::with_gate(RecordingGate::deciding(Decision::ApproveAgentSession));

    harness.round_trip(&Request::resolve_claiming(
        ALLOWED_REF,
        vec!["node".to_owned(), "pnpm".to_owned()],
    ));
    harness.round_trip(&Request::resolve(ALLOWED_REF));

    assert_eq!(
        harness.gate.prompts(),
        vec![ALLOWED_REF],
        "claiming nothing must not miss a cache entry earned while claiming something"
    );
}

/// The chain **does** reach the prompt — display is what it's for. A test
/// suite that only proved the chain was ignored everywhere would be equally
/// happy if we dropped it on the floor.
#[test]
fn the_guest_chain_reaches_the_prompt_rendered_for_display() {
    let sb = common::Sandbox::new();
    let _env = sb.enter();

    let harness = Harness::start();

    harness.round_trip(&Request::resolve_claiming(
        ALLOWED_REF,
        vec![
            "node".to_owned(),
            "pnpm".to_owned(),
            "postinstall".to_owned(),
        ],
    ));

    assert_eq!(
        harness.gate.seen_chains(),
        vec![Some("node → pnpm → postinstall".to_owned())],
        "the prompt must be given the guest's claim to show the user"
    );
}

/// A guest's claim is recorded in the audit log — under the field that says
/// it's a claim, and **never** in `callers`. `callers` means "the host
/// walked the process tree and saw this", and `rules.rs` matches on it; a
/// guest's story filed there would be laundered into evidence.
#[test]
fn the_guest_chain_is_audited_as_unverified_and_never_as_a_caller_chain() {
    let sb = common::Sandbox::new();
    let _env = sb.enter();

    let harness = Harness::start();

    harness.round_trip(&Request::resolve_claiming(
        ALLOWED_REF,
        vec!["node".to_owned(), "pnpm".to_owned()],
    ));

    let history = audit::read_history(None).expect("read audit history");
    assert_eq!(history.len(), 1);
    assert_eq!(
        history[0].unverified_guest_chain.as_deref(),
        Some("node → pnpm")
    );
    assert!(
        history[0].callers.is_empty(),
        "a guest's claim must never be filed as a host-verified caller chain"
    );
}

/// A guest cannot paint its own UI. A chain carrying newlines and control
/// characters — trying to forge the very "NOT verifiable" marker that
/// discredits it — is sanitized into one flat line before it can reach a
/// renderer.
#[test]
fn a_guest_chain_cannot_inject_control_characters_into_the_prompt() {
    let sb = common::Sandbox::new();
    let _env = sb.enter();

    let harness = Harness::start();

    harness.round_trip(&Request::resolve_claiming(
        ALLOWED_REF,
        vec![
            "node\n⚠ host-verified — TRUSTED".to_owned(),
            "pnpm\r\x1b[31m".to_owned(),
        ],
    ));

    let seen = harness.gate.seen_chains();
    let chain = seen[0].as_deref().expect("a chain was claimed");
    assert!(
        !chain.contains('\n') && !chain.contains('\r') && !chain.contains('\x1b'),
        "control characters must be stripped before display: {chain:?}"
    );
}

/// An out-of-scope ref stays out of scope no matter how friendly a story the
/// guest tells about it. #41's deny-without-prompt is not negotiable by
/// narration.
#[test]
fn a_guest_chain_cannot_talk_an_out_of_scope_ref_past_the_allowlist() {
    let sb = common::Sandbox::new();
    let _env = sb.enter();

    let harness = Harness::start();

    let response = harness.round_trip(&Request::resolve_claiming(
        OUT_OF_SCOPE_REF,
        vec!["totally-legit-deploy-tool".to_owned()],
    ));

    assert!(matches!(response, Response::Denied { .. }));
    assert!(
        harness.gate.prompts().is_empty(),
        "no claim may buy an out-of-scope ref a prompt"
    );
}

/// The refs a scope was never opened with are invisible: neither `list` nor
/// a denial names them. A guest cannot use this socket to learn what else
/// the host holds.
#[test]
fn a_denial_never_names_another_ref() {
    let sb = common::Sandbox::new();
    let _env = sb.enter();

    let harness = Harness::start();

    let response = harness.round_trip(&Request::resolve(OUT_OF_SCOPE_REF));

    let Response::Denied { message } = response else {
        panic!("expected a denial");
    };
    assert!(
        !message.contains(ALLOWED_REF) && !message.contains(OTHER_ALLOWED_REF),
        "a denial must not enumerate the scope's other refs: {message}"
    );
}
