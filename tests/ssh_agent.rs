//! Integration test for the SSH agent listener (Task 9): bind a socket and
//! answer `REQUEST_IDENTITIES` with the configured public keys, WITHOUT
//! resolving any private key (no provider call, no consent).
//!
//! The test drives the agent purely over its Unix socket — the
//! `ssh-add -l` exchange, but hand-rolled so it doesn't depend on a real
//! `ssh` binary. It exercises the testable entry point
//! `ssh_agent::serve_on(listener, identities)` directly rather than
//! spawning the whole daemon.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::thread;

use secreq::daemon::ssh_agent;
use secreq::daemon::ssh_proto::{self, SSH_AGENT_IDENTITIES_ANSWER};
use secreq::reference::Reference;
use secreq::wraps::SshIdentity;

use ssh_encoding::Decode;

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

#[test]
fn lists_configured_identities_without_resolving() {
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

    // Prepare the (blob, comment) list once, exactly as the daemon does.
    let identities = ssh_agent::prepare_identities(&ssh);
    assert_eq!(identities.len(), 1, "one identity prepared");

    // The expected wire blob + comment, derived independently from the
    // same public-key string.
    let expected_key = ssh_key::PublicKey::from_openssh(TEST_PUBLIC_KEY).unwrap();
    let expected_blob = expected_key.to_bytes().unwrap();
    let expected_comment = expected_key.comment().to_owned();
    assert_eq!(expected_comment, "secreq-test@example");

    // Bind the agent on a tempdir path and serve on a background thread.
    // The serve thread owns the listener; it blocks in `accept()` between
    // connections. We don't join it (there's no clean cross-thread way to
    // unblock a blocking `accept`) — it's a daemon-style loop that the test
    // process reaps on exit. The tempdir drop removes the socket file.
    let dir = tempfile::tempdir().expect("tempdir");
    let sock_path = dir.path().join("agent.sock");
    let listener = UnixListener::bind(&sock_path).expect("bind agent socket");
    thread::spawn(move || ssh_agent::serve_on(listener, identities));

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
