//! SSH agent listener — a second daemon socket speaking the SSH agent
//! protocol (PROTOCOL.agent) at `~/.secreq/agent.sock`.
//!
//! This is separate from the control socket (`consent.sock`): SSH clients
//! (`ssh`, `git`, `ssh-add`) connect here when `SSH_AUTH_SOCK` points at
//! it. The wire format is the SSH agent protocol (see
//! [`super::ssh_proto`]), NOT the daemon's JSON control protocol.
//!
//! **This task (9) implements listing only.** `REQUEST_IDENTITIES` answers
//! with the configured public keys, parsed once from the inline
//! `public_key` strings in `wraps.json5` — **no provider resolve, no
//! consent**. A `SIGN_REQUEST` currently answers `SSH_AGENT_FAILURE`; the
//! gated sign flow lands in Task 10 and will extend [`handle_request`].

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::thread;

use anyhow::{Context, Result};

use super::ssh_proto::{self, AgentRequest};
use crate::wraps::SshIdentity;

/// Upper bound on a single agent frame's payload length. Mirrors OpenSSH's
/// `AGENT_MAX_MSGLEN` (256 KiB) from `authfd.h`: the agent protocol never
/// carries a legitimate message this large, so a bigger length prefix is a
/// buggy/hostile client. We reject it before allocating so an untrusted
/// wire value can't drive an arbitrary allocation in the long-lived daemon.
const MAX_AGENT_MSG_LEN: usize = 256 * 1024;

/// One configured identity prepared for `REQUEST_IDENTITIES`: the raw SSH
/// wire key blob plus the comment. Derived once from the inline
/// `public_key` string so listing never parses keys per-connection and
/// never touches a provider.
pub type PreparedIdentity = (Vec<u8>, String);

/// Stable per-user agent socket path. Lives alongside the control socket
/// (`consent.sock`) in [`super::server::socket_dir`] so both sockets share
/// the same per-user runtime dir; SSH clients point `SSH_AUTH_SOCK` here.
pub fn default_agent_socket_path() -> Result<PathBuf> {
    Ok(super::server::socket_dir()?.join("agent.sock"))
}

/// Parse each identity's inline `public_key` string into its raw SSH wire
/// blob + comment, **once**, up front. The blob is what
/// `SSH_AGENT_IDENTITIES_ANSWER` carries; deriving it here means the
/// per-connection listing path never parses keys and never resolves the
/// private key reference.
///
/// An unparseable `public_key` is skipped with a daemon-log warning rather
/// than failing the whole agent — one malformed entry shouldn't hide every
/// other key from `ssh-add -l`.
pub fn prepare_identities(ssh: &BTreeMap<String, SshIdentity>) -> Vec<PreparedIdentity> {
    let mut prepared = Vec::with_capacity(ssh.len());
    for (name, identity) in ssh {
        match ssh_key::PublicKey::from_openssh(&identity.public_key) {
            Ok(public_key) => match public_key.to_bytes() {
                Ok(blob) => prepared.push((blob, public_key.comment().to_owned())),
                Err(err) => super::log::log_at(
                    "ssh-agent",
                    format_args!("identity {name:?}: cannot serialize public key blob: {err}"),
                ),
            },
            Err(err) => super::log::log_at(
                "ssh-agent",
                format_args!("identity {name:?}: malformed public_key, skipping: {err}"),
            ),
        }
    }
    prepared
}

/// Bind the agent socket (unlinking any stale file first), set `0600`
/// perms, and spawn the accept loop. Returns the bound listener so the
/// caller keeps it alive; the accept thread exits when the listener is
/// dropped. Returns `Ok(None)` when there are no configured identities —
/// no agent socket is created in that case.
pub fn start(
    socket_path: PathBuf,
    ssh: &BTreeMap<String, SshIdentity>,
) -> Result<Option<UnixListener>> {
    if ssh.is_empty() {
        return Ok(None);
    }
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    // Clear a stale socket from a previously-crashed daemon. The pidfile
    // flock taken in `daemon::run` guarantees we're the only live daemon,
    // so this can't race a running one.
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("bind agent socket {}", socket_path.display()))?;
    let mut perms = std::fs::metadata(&socket_path)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(&socket_path, perms)?;

    let identities = prepare_identities(ssh);
    super::log::log_at(
        "ssh-agent",
        format_args!(
            "listener bound at {} serving {} identit{}",
            socket_path.display(),
            identities.len(),
            if identities.len() == 1 { "y" } else { "ies" }
        ),
    );

    let listener_clone = listener.try_clone().context("clone agent listener")?;
    thread::Builder::new()
        .name("secreqd-ssh-agent".to_owned())
        .spawn(move || serve_on(listener_clone, identities))
        .context("spawn ssh-agent accept thread")?;

    Ok(Some(listener))
}

/// Accept loop for the agent socket: one thread per connection.
///
/// This is the testable entry point — a test can bind a `UnixListener` on
/// a tempdir path and call `serve_on` directly with a synthetic identity
/// list, without spawning the whole daemon. Task 10 will extend the
/// per-connection [`handle_connection`] / [`handle_request`] with the SIGN
/// path; its signature already carries the identities the SIGN handler
/// needs to map a key blob back to a config entry.
pub fn serve_on(listener: UnixListener, identities: Vec<PreparedIdentity>) {
    let identities = std::sync::Arc::new(identities);
    for incoming in listener.incoming() {
        let stream = match incoming {
            Ok(s) => s,
            Err(_) => break, // Listener closed or unrecoverable accept error.
        };
        let identities = identities.clone();
        thread::Builder::new()
            .name("secreqd-ssh-conn".to_owned())
            .spawn(move || {
                if let Err(err) = handle_connection(stream, &identities) {
                    super::log::log_at("ssh-agent", format_args!("connection error: {err:#}"));
                }
            })
            .ok();
    }
}

/// Read framed agent requests off `stream` until the peer hangs up,
/// answering each in turn. SSH clients keep the socket open and pipeline
/// requests (e.g. `ssh-add -l` then a sign), so we loop rather than
/// handling a single message.
fn handle_connection(mut stream: UnixStream, identities: &[PreparedIdentity]) -> Result<()> {
    while let Some(frame) = read_frame(&mut stream)? {
        let reply = match ssh_proto::parse_request(&frame) {
            Ok(request) => handle_request(request, identities),
            // A malformed frame is the client's fault, not ours. Answer
            // FAILURE so a confused client gets a defined response rather
            // than a dropped connection.
            Err(err) => {
                super::log::log_at(
                    "ssh-agent",
                    format_args!("malformed request frame: {err:#}"),
                );
                ssh_proto::encode_failure()
            }
        };
        stream.write_all(&reply).context("write agent reply")?;
    }
    Ok(())
}

/// Map one parsed request to its reply bytes.
///
/// `REQUEST_IDENTITIES` lists the prepared public keys with no resolve and
/// no consent. `SIGN_REQUEST` and unsupported types answer
/// `SSH_AGENT_FAILURE` for now.
fn handle_request(request: AgentRequest, identities: &[PreparedIdentity]) -> Vec<u8> {
    match request {
        AgentRequest::RequestIdentities => {
            super::log::log_at(
                "ssh-agent",
                format_args!(
                    "← REQUEST_IDENTITIES; answering {} key(s)",
                    identities.len()
                ),
            );
            ssh_proto::encode_identities_answer(identities)
        }
        // Task 10: gated sign — peer pid → provenance → consent → resolve
        // → sign. Until then a sign request gets a defined failure so
        // clients fall back gracefully rather than hang.
        AgentRequest::Sign { .. } => {
            super::log::log_at(
                "ssh-agent",
                format_args!("← SIGN_REQUEST (not yet implemented); answering FAILURE"),
            );
            ssh_proto::encode_failure()
        }
        AgentRequest::Unsupported(msg_type) => {
            super::log::log_at(
                "ssh-agent",
                format_args!("← unsupported message type {msg_type}; answering FAILURE"),
            );
            ssh_proto::encode_failure()
        }
    }
}

/// Read one complete `[u32 length][payload]` agent frame off `stream`,
/// returning the **full** frame (length prefix included) so it can be
/// handed straight to [`ssh_proto::parse_request`]. Returns `Ok(None)` on
/// a clean EOF before any bytes of a new frame — the normal "client hung
/// up" signal.
fn read_frame(stream: &mut UnixStream) -> Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match read_exact_or_eof(stream, &mut len_buf)? {
        ReadOutcome::Eof => return Ok(None),
        ReadOutcome::Filled => {}
    }
    let payload_len = u32::from_be_bytes(len_buf) as usize;
    // `payload_len` is untrusted wire input. Reject an over-cap length
    // before sizing or reading any body bytes so a buggy/hostile client
    // can't drive a huge allocation in the long-lived daemon.
    if payload_len > MAX_AGENT_MSG_LEN {
        return Err(anyhow::anyhow!(
            "agent frame payload length {payload_len} exceeds cap of {MAX_AGENT_MSG_LEN} bytes"
        ));
    }
    let mut frame = Vec::with_capacity(4 + payload_len);
    frame.extend_from_slice(&len_buf);
    frame.resize(4 + payload_len, 0);
    stream
        .read_exact(&mut frame[4..])
        .context("read agent frame payload")?;
    Ok(Some(frame))
}

enum ReadOutcome {
    Filled,
    Eof,
}

/// Like `read_exact`, but a clean EOF *before the first byte* is reported
/// as `Eof` rather than an error — that's the peer closing the socket
/// between frames, which is expected. An EOF *partway* through the buffer
/// is a truncated frame and still errors.
fn read_exact_or_eof(stream: &mut UnixStream, buf: &mut [u8]) -> Result<ReadOutcome> {
    let mut filled = 0;
    while filled < buf.len() {
        match stream.read(&mut buf[filled..]) {
            Ok(0) => {
                if filled == 0 {
                    return Ok(ReadOutcome::Eof);
                }
                return Err(anyhow::anyhow!(
                    "truncated agent frame: got {filled} of {} length-prefix bytes before EOF",
                    buf.len()
                ));
            }
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e).context("read agent frame length prefix"),
        }
    }
    Ok(ReadOutcome::Filled)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An oversized length prefix must be rejected by the guard *before*
    /// `read_frame` tries to allocate or read a body that large. Writing
    /// just the 4-byte prefix is enough: without the guard, `read_frame`
    /// would size a buffer for the bogus length and then block in
    /// `read_exact` waiting for body bytes that never come.
    #[test]
    fn read_frame_rejects_oversized_length() {
        let (mut client, mut server) = UnixStream::pair().expect("create UnixStream pair");
        let oversized = (MAX_AGENT_MSG_LEN + 1) as u32;
        client
            .write_all(&oversized.to_be_bytes())
            .expect("write oversized length prefix");
        // Drop the client so any (incorrect) attempt to read a body sees EOF
        // rather than blocking forever; the guard should fire first anyway.
        drop(client);

        let result = read_frame(&mut server);
        let err = result.expect_err("expected Err for over-cap length");
        // The error must come from the size guard (which cites the cap),
        // not from an incidental truncated-body read after EOF — that
        // proves the guard fires before any body read/allocation.
        let msg = format!("{err:#}");
        assert!(
            msg.contains(&MAX_AGENT_MSG_LEN.to_string()),
            "error should cite the cap, got: {msg}"
        );
    }

    /// A normal small frame still round-trips: the returned bytes are the
    /// full frame (length prefix included), byte-for-byte.
    #[test]
    fn read_frame_reads_small_frame() {
        let (mut client, mut server) = UnixStream::pair().expect("create UnixStream pair");
        let input = [0u8, 0, 0, 1, 11];
        client.write_all(&input).expect("write small frame");
        drop(client);

        let frame = read_frame(&mut server)
            .expect("read_frame ok")
            .expect("frame present");
        assert_eq!(frame, input);
    }
}
