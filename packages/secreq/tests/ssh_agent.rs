//! Integration tests for the SSH agent listener.
//!
//! Listing: bind a socket and answer `REQUEST_IDENTITIES` with the
//! configured public keys, WITHOUT resolving any private key (no provider
//! call, no consent).
//!
//! Gated SIGN: with the SSH approval cache pre-seeded (so the
//! consent prompt is skipped), drive a `SIGN_REQUEST` over the socket and
//! assert the returned signature verifies against the public key. Also
//! assert an unknown key blob answers `SSH_AGENT_FAILURE`.
//!
//! The tests drive the agent purely over its Unix socket — the
//! `ssh-add -l` / sign exchange, hand-rolled so they don't depend on a real
//! `ssh` binary. They exercise the testable entry point
//! `ssh_agent::serve_on(listener, ctx)` directly rather than spawning the
//! whole daemon.

mod common;

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex};
use std::thread;

use secreq::consent::{SshGrant, SshGrantScope};
use secreq::daemon::ssh_agent::{self, SignContext};
use secreq::daemon::ssh_proto::{self, SSH_AGENT_FAILURE, SSH_AGENT_IDENTITIES_ANSWER};
use secreq::daemon::state::State;
use secreq::manifest::Provider;
use secreq::reference::Reference;
use secreq::wraps::SshIdentity;

use rsa::signature::Verifier;
use ssh_encoding::{Decode, Encode};
use ssh_key::{LineEnding, PrivateKey, PublicKey, Signature};

// These tests drive `ssh_agent::serve_on` **in-process**, and it logs
// through `daemon::log`, which resolves its sink from `$SECREQ_HOME`. Each
// test therefore pins this process's environment with
// `common::Sandbox::enter` — the guard applies the full isolation set under
// a global lock and restores it on drop, so a plain `cargo test` can never
// append this suite's `SIGN_REQUEST` chatter to the developer's real
// `~/.secreq` daemon log. (The lib's own unit tests get an automatic
// fallback in `paths::secreq_root`, but integration tests link the lib
// without `cfg(test)` and must pin it themselves.)

/// A real OpenSSH ed25519 public key (generated once for this test). The
/// private half is irrelevant: listing never resolves a private key.
const TEST_PUBLIC_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIKFjuAiAa6imLCL+qSIopFbqkxLiCGLODCDIAKnYEsU secreq-test@example";

/// Read one complete `[u32 length][payload]` agent frame off `stream`.
fn read_frame(stream: &mut UnixStream) -> Vec<u8> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).expect("read length prefix");
    let payload_len = u32::from_be_bytes(len_buf) as usize;
    let mut payload = vec![0u8; payload_len];
    stream.read_exact(&mut payload).expect("read payload");
    let mut frame = Vec::with_capacity(4 + payload_len);
    frame.extend_from_slice(&len_buf);
    frame.extend_from_slice(&payload);
    frame
}

/// Encode a `SSH_AGENTC_SIGN_REQUEST` frame:
/// `[u32 len][type=13][string key_blob][string data][u32 flags]`.
fn encode_sign_request(key_blob: &[u8], data: &[u8], flags: u32) -> Vec<u8> {
    let mut payload = vec![ssh_proto::SSH_AGENTC_SIGN_REQUEST];
    key_blob.encode(&mut payload).unwrap();
    data.encode(&mut payload).unwrap();
    flags.encode(&mut payload).unwrap();
    let len = payload.len() as u32;
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&payload);
    out
}

#[test]
fn lists_configured_identities_without_resolving() {
    let sb = common::Sandbox::new();
    let _env = sb.enter();
    // One identity whose private_key reference is deliberately bogus: if
    // listing tried to resolve it, the provider call would be observable.
    // It succeeds regardless, which proves listing never resolves.
    let mut ssh: BTreeMap<String, SshIdentity> = BTreeMap::new();
    ssh.insert(
        "github".to_owned(),
        SshIdentity {
            reason: Some("git pushes".to_owned()),
            public_key: TEST_PUBLIC_KEY.to_owned(),
            private_key: Reference::parse("secret://nonexistent-provider/this/never/resolves")
                .expect("parse bogus reference"),
        },
    );

    // Prepare the identities once, exactly as the daemon does.
    let identities = ssh_agent::prepare_identities(&ssh);
    assert_eq!(identities.len(), 1, "one identity prepared");

    // The expected wire blob + comment, derived independently from the
    // same public-key string.
    let expected_key = PublicKey::from_openssh(TEST_PUBLIC_KEY).unwrap();
    let expected_blob = expected_key.to_bytes().unwrap();
    let expected_comment = expected_key.comment().to_owned();
    assert_eq!(expected_comment, "secreq-test@example");

    let ctx = SignContext {
        identities: Arc::new(identities),
        providers: Arc::new(BTreeMap::new()),
        state: None,
    };

    // Bind the agent on a tempdir path and serve on a background thread.
    // The serve thread owns the listener; it blocks in `accept()` between
    // connections. We don't join it — it's a daemon-style loop that the
    // test process reaps on exit. The tempdir drop removes the socket file.
    let dir = tempfile::tempdir().expect("tempdir");
    let sock_path = dir.path().join("agent.sock");
    let listener = UnixListener::bind(&sock_path).expect("bind agent socket");
    thread::spawn(move || ssh_agent::serve_on(listener, ctx));

    // Connect and send REQUEST_IDENTITIES: [u32 len=1][type=11].
    let mut client = UnixStream::connect(&sock_path).expect("connect");
    client
        .write_all(&[0, 0, 0, 1, ssh_proto::SSH_AGENTC_REQUEST_IDENTITIES])
        .expect("send request");

    let frame = read_frame(&mut client);

    // Decode the IDENTITIES_ANSWER and assert it lists our key.
    let payload = &frame[4..];
    assert_eq!(
        payload[0], SSH_AGENT_IDENTITIES_ANSWER,
        "reply is IDENTITIES_ANSWER"
    );
    let mut reader = &payload[1..];
    let nkeys = u32::decode(&mut reader).expect("decode nkeys");
    assert_eq!(nkeys, 1, "one key listed");
    let blob = Vec::<u8>::decode(&mut reader).expect("decode key blob");
    let comment = String::decode(&mut reader).expect("decode comment");
    assert!(reader.is_empty(), "no trailing bytes");

    assert_eq!(blob, expected_blob, "listed blob matches configured key");
    assert_eq!(comment, "secreq-test@example", "comment matches");

    // Drop the client; the per-connection handler sees EOF and exits.
    drop(client);
}

/// Build a `SignContext` wired to real `State` whose SSH approval cache is
/// pre-seeded for the anchor the SIGN handler will compute. The peer of the
/// test's connection is the test process itself, so the anchor is whatever
/// `select_anchor(caller_chain_from_pid(our_pid))` yields — we compute it
/// the same way and seed an approval that never expires within the test.
///
/// Returns the context plus the configured public key (for verification)
/// and the raw wire blob (for the SIGN_REQUEST key_blob). A file-based fake
/// provider (`cat <path>`) returns the exact OpenSSH PEM written to a temp
/// file, so resolve is real but deterministic and offline.
fn signing_context_with_seeded_approval(
    key_dir: &std::path::Path,
) -> (SignContext, PublicKey, Vec<u8>, SshIdentity) {
    // Generate a real ed25519 key; write its PEM where the fake provider can
    // `cat` it, and use its public half as the configured identity.
    let private = PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519)
        .expect("generate test key");
    let pem = private
        .to_openssh(LineEnding::LF)
        .expect("encode openssh pem")
        .to_string();
    let pem_path = key_dir.join("github.key");
    std::fs::write(&pem_path, &pem).expect("write key pem");
    let public_key = private.public_key().clone();
    let public_openssh = public_key.to_openssh().expect("encode public openssh");

    // Provider whose `retrieve` is `cat <locator>` — the locator is the PEM
    // file path, so the resolved value is the exact PEM bytes.
    let mut providers: BTreeMap<String, Provider> = BTreeMap::new();
    providers.insert(
        "file".to_owned(),
        Provider {
            name: "file".to_owned(),
            retrieve: vec!["cat".to_owned(), "{locator}".to_owned()],
            store: None,
            retrieve_batch: None,
        },
    );

    let identity = SshIdentity {
        reason: Some("git pushes".to_owned()),
        public_key: public_openssh,
        private_key: Reference::parse(&format!("secret://file/{}", pem_path.to_string_lossy()))
            .expect("parse reference"),
    };
    let mut ssh: BTreeMap<String, SshIdentity> = BTreeMap::new();
    ssh.insert("github".to_owned(), identity.clone());

    let identities = ssh_agent::prepare_identities(&ssh);
    let [identity_blob] = identities.as_slice() else {
        panic!("one declared identity should prepare exactly one blob");
    };
    let blob = identity_blob.blob.clone();

    // Compute the anchor exactly as the SIGN handler will, then seed a
    // session grant for it that won't expire during the test.
    let chain = secreq::provenance::caller_chain_from_pid(std::process::id());
    let anchor =
        secreq::provenance::select_anchor(&chain.frames).expect("an anchor in the test's chain");
    let far_future = u64::MAX;
    let state = Arc::new(Mutex::new(State::new()));
    state.lock().unwrap().remember_ssh_grant(SshGrant {
        scope: SshGrantScope::OneKey("github".to_owned()),
        anchor: anchor.identity(),
        expires_at: far_future,
    });

    let ctx = SignContext {
        identities: Arc::new(identities),
        providers: Arc::new(providers),
        state: Some(state),
    };
    (ctx, public_key, blob, identity)
}

#[test]
fn signs_for_seeded_approval_and_signature_verifies() {
    let sb = common::Sandbox::new();
    let _env = sb.enter();
    let dir = tempfile::tempdir().expect("tempdir");
    let (ctx, public_key, blob, _identity) = signing_context_with_seeded_approval(dir.path());

    let sock_dir = tempfile::tempdir().expect("sock tempdir");
    let sock_path = sock_dir.path().join("agent.sock");
    let listener = UnixListener::bind(&sock_path).expect("bind agent socket");
    thread::spawn(move || ssh_agent::serve_on(listener, ctx));

    let mut client = UnixStream::connect(&sock_path).expect("connect");
    let data = b"challenge bytes from the remote peer";
    client
        .write_all(&encode_sign_request(&blob, data, 0))
        .expect("send sign request");

    let frame = read_frame(&mut client);
    let payload = &frame[4..];
    assert_eq!(
        payload[0],
        ssh_proto::SSH_AGENT_SIGN_RESPONSE,
        "reply is SIGN_RESPONSE (got type {})",
        payload[0]
    );

    // Body is a single `string signature`; the signature is itself the
    // `string algorithm` + `string blob` wire encoding.
    let mut reader = &payload[1..];
    let sig_blob = Vec::<u8>::decode(&mut reader).expect("decode signature string");
    assert!(reader.is_empty(), "no trailing bytes after signature");

    // The returned signature must verify against the configured public key.
    let mut sig_reader: &[u8] = &sig_blob;
    let signature = Signature::decode(&mut sig_reader).expect("decode signature");
    Verifier::verify(&public_key, data, &signature)
        .expect("signature verifies against the public key");

    drop(client);
}

#[test]
fn unknown_key_blob_answers_failure() {
    let sb = common::Sandbox::new();
    let _env = sb.enter();
    let dir = tempfile::tempdir().expect("tempdir");
    let (ctx, _public_key, _blob, _identity) = signing_context_with_seeded_approval(dir.path());

    let sock_dir = tempfile::tempdir().expect("sock tempdir");
    let sock_path = sock_dir.path().join("agent.sock");
    let listener = UnixListener::bind(&sock_path).expect("bind agent socket");
    thread::spawn(move || ssh_agent::serve_on(listener, ctx));

    let mut client = UnixStream::connect(&sock_path).expect("connect");
    // A key blob we don't hold.
    client
        .write_all(&encode_sign_request(b"not-a-configured-key", b"data", 0))
        .expect("send sign request");

    let frame = read_frame(&mut client);
    assert_eq!(
        frame[4], SSH_AGENT_FAILURE,
        "unknown key blob must answer SSH_AGENT_FAILURE"
    );

    drop(client);
}

/// The library self-test against an in-process agent with a correctly-seeded
/// approval: `listed` and `verified` are both true and `run` returns promptly.
///
/// The seeded anchor is computed from THIS test process's own caller chain
/// (the agent reads the peer pid off the socket, which is us), so the SIGN is
/// a guaranteed approval-cache HIT — no consent prompt, no blocking wait, no
/// hang. The `set_read_timeout` inside `run` is a belt-and-suspenders backstop;
/// a correct cache hit never reaches it.
#[test]
fn ssh_selftest_run_lists_and_verifies_on_cache_hit() {
    let sb = common::Sandbox::new();
    let _env = sb.enter();
    let dir = tempfile::tempdir().expect("tempdir");
    let (ctx, _public_key, _blob, identity) = signing_context_with_seeded_approval(dir.path());

    let sock_dir = tempfile::tempdir().expect("sock tempdir");
    let sock_path = sock_dir.path().join("agent.sock");
    let listener = UnixListener::bind(&sock_path).expect("bind agent socket");
    thread::spawn(move || ssh_agent::serve_on(listener, ctx));

    let result = secreq::ssh_selftest::run(&sock_path, &identity, "github")
        .expect("self-test runs against the in-process agent");

    assert!(result.listed, "the agent should list the seeded identity");
    assert!(
        result.verified,
        "the agent's signature should verify against the public key"
    );
    assert_eq!(result.key_id, "github");
}

/// A self-test whose identity carries a public key the agent doesn't hold:
/// the agent answers SSH_AGENT_FAILURE on the SIGN_REQUEST, and `run`
/// surfaces that as an error (never a hang). Listing also won't include the
/// unknown key, but the SIGN failure is the load-bearing assertion.
#[test]
fn ssh_selftest_run_errors_when_agent_does_not_hold_the_key() {
    let sb = common::Sandbox::new();
    let _env = sb.enter();
    let dir = tempfile::tempdir().expect("tempdir");
    let (ctx, _public_key, _blob, _identity) = signing_context_with_seeded_approval(dir.path());

    let sock_dir = tempfile::tempdir().expect("sock tempdir");
    let sock_path = sock_dir.path().join("agent.sock");
    let listener = UnixListener::bind(&sock_path).expect("bind agent socket");
    thread::spawn(move || ssh_agent::serve_on(listener, ctx));

    // A real, well-formed ed25519 key the agent was never configured with.
    let stranger = PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519)
        .expect("generate stranger key");
    let unknown = SshIdentity {
        reason: None,
        public_key: stranger
            .public_key()
            .to_openssh()
            .expect("encode public openssh"),
        private_key: Reference::parse("secret://file/does-not-matter").expect("parse reference"),
    };

    let err = secreq::ssh_selftest::run(&sock_path, &unknown, "stranger")
        .expect_err("agent must refuse to sign with a key it doesn't hold");
    assert!(
        err.to_string().contains("refused to sign"),
        "error should explain the agent refused, got: {err}"
    );
}

/// The agent socket spawned one unbounded OS thread per accept, with no read
/// timeout. A peer that connects and says nothing therefore parked a thread —
/// and its stack reservation — for the daemon's lifetime, as many times as it
/// liked. This socket is not local-only: `ssh -A` forwards a *remote* host's
/// agent connections here, so the party opening them need not be on this
/// machine.
///
/// Concurrency is what the cap bounds, so the observable is not a refusal —
/// past the cap a client waits. Sixteen silent connections fill every slot;
/// the seventeenth then gets no answer to a request the agent would otherwise
/// serve without consent and without resolving anything. Closing the silent
/// ones frees a slot and that same request is answered, which is what
/// separates "capped" from "wedged".
///
/// The idle timeout that stops a silent connection holding its slot *forever*
/// is 120s and is not exercised here — what it triggers is unit-tested in
/// `ssh_agent::tests` against a 50ms timeout instead.
#[test]
fn a_flood_of_silent_connections_cannot_starve_the_agent_forever() {
    // Must match `ssh_agent::MAX_CONCURRENT_CONNECTIONS`, which is private.
    // Filling every slot is the whole setup, so a raised cap has to be
    // reflected here; this test going red on a bump is the intended cost.
    const CAP: usize = 16;

    let sb = common::Sandbox::new();
    let _env = sb.enter();

    let mut ssh: BTreeMap<String, SshIdentity> = BTreeMap::new();
    ssh.insert(
        "github".to_owned(),
        SshIdentity {
            reason: None,
            public_key: TEST_PUBLIC_KEY.to_owned(),
            private_key: Reference::parse("secret://nonexistent-provider/never/resolves")
                .expect("parse bogus reference"),
        },
    );
    let ctx = SignContext {
        identities: Arc::new(ssh_agent::prepare_identities(&ssh)),
        providers: Arc::new(BTreeMap::new()),
        state: None,
    };

    let dir = tempfile::tempdir().expect("tempdir");
    let sock_path = dir.path().join("agent.sock");
    let listener = UnixListener::bind(&sock_path).expect("bind agent socket");
    thread::spawn(move || ssh_agent::serve_on(listener, ctx));

    // Connect and say nothing, `CAP` times over. Each is accepted and handed
    // to a handler that then blocks on its first read.
    let silent: Vec<UnixStream> = (0..CAP)
        .map(|_| UnixStream::connect(&sock_path).expect("connect a silent peer"))
        .collect();

    // Let the accept loop take all of them. Without this the assertion below
    // could pass because the flood had not landed yet rather than because the
    // cap held.
    thread::sleep(std::time::Duration::from_millis(500));

    // A request needing no consent and no provider call: if anything is going
    // to be answered, this is it.
    let mut starved = UnixStream::connect(&sock_path).expect("connect past the cap");
    starved
        .set_read_timeout(Some(std::time::Duration::from_millis(750)))
        .expect("set read timeout");
    starved
        .write_all(&[0, 0, 0, 1, ssh_proto::SSH_AGENTC_REQUEST_IDENTITIES])
        .expect("send request");

    let mut len_buf = [0u8; 4];
    assert!(
        starved.read_exact(&mut len_buf).is_err(),
        "a 17th connection must wait behind the cap, not be served"
    );

    // Free the slots: each handler sees EOF, returns, and drops its permit.
    drop(silent);

    // …and the connection that was waiting gets served, so the cap delays
    // rather than refuses.
    starved
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .expect("set read timeout");
    let frame = read_frame(&mut starved);
    assert_eq!(
        frame[4], SSH_AGENT_IDENTITIES_ANSWER,
        "the waiting connection is served once a slot frees"
    );
}
