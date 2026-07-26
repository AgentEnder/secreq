//! SSH agent self-test: prove the agent can actually sign.
//!
//! [`run`] connects to the agent socket as a plain SSH client would, asks it
//! to list its identities (so we know the key is being served), then asks it
//! to sign a fixed test message with that key and verifies the returned
//! signature against the key's public half. This exercises the real
//! consent → resolve → sign path end-to-end — the only way to know the wiring
//! actually works short of pushing to a remote.
//!
//! # Why this can never hang
//!
//! A SIGN request that misses the consent cache parks the agent on the user's
//! decision; a self-test that runs against a daemon with no one at the
//! keyboard would otherwise block forever. As a safety net, [`run`] sets a
//! socket read timeout after connecting (see [`READ_TIMEOUT`]). A read that
//! times out is reported as a clear error rather than hanging — in production
//! it means the consent prompt went unanswered; in tests it means the seeding
//! was wrong (it should be a cache hit). Either way `run` returns.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};

use crate::daemon::ssh_proto::{self, AgentResponse};
use crate::ssh_sign::SSH_AGENT_RSA_SHA2_256;

/// The fixed message the self-test asks the agent to sign. Arbitrary bytes;
/// the only thing that matters is that the signature over them verifies.
pub const TEST_DATA: &[u8] = b"secreq ssh agent self-test";

/// Upper bound on a single agent reply frame, mirroring the daemon's
/// `MAX_AGENT_MSG_LEN` (OpenSSH `AGENT_MAX_MSGLEN`, 256 KiB). A reply whose
/// length prefix exceeds this is a buggy/hostile agent; reject before
/// allocating.
const MAX_AGENT_MSG_LEN: usize = 256 * 1024;

/// Safety-net read timeout. Long enough that a human answering a genuine
/// consent prompt comfortably beats it, short enough that an unanswered
/// prompt (or a misconfigured test) surfaces as an error instead of a hang.
const READ_TIMEOUT: Duration = Duration::from_secs(60);

/// The outcome of one identity's self-test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfTest {
    /// The config identity name that was tested.
    pub key_id: String,
    /// Whether the agent listed this key in its `REQUEST_IDENTITIES` answer.
    pub listed: bool,
    /// Whether the signature the agent returned verified against the key's
    /// public half.
    pub verified: bool,
}

/// Run the self-test for one identity against the agent at `agent_sock`.
///
/// Connects, lists identities (sets `listed`), then sends a SIGN_REQUEST for
/// the identity's key over [`TEST_DATA`] and verifies the returned signature
/// (sets `verified`). Signing is a *real* sign: if the daemon has no cached
/// approval for the caller it will prompt for consent, so this may pop the
/// consent window.
pub fn run(
    agent_sock: &Path,
    identity: &crate::wraps::SshIdentity,
    key_id: &str,
) -> Result<SelfTest> {
    let mut stream = UnixStream::connect(agent_sock).with_context(|| {
        format!(
            "couldn't reach the agent socket at {}; is the daemon running? try `secreq daemon install`",
            agent_sock.display()
        )
    })?;
    // Safety net: never block indefinitely on a read. A missed-cache SIGN
    // parks the agent on the user's consent decision; without this a
    // self-test against an unattended daemon would hang forever.
    stream
        .set_read_timeout(Some(READ_TIMEOUT))
        .context("setting agent socket read timeout")?;

    // The wire blob identifying this key — what the agent lists and what a
    // SIGN_REQUEST is keyed on.
    let public_key = ssh_key::PublicKey::from_openssh(&identity.public_key)
        .with_context(|| format!("parsing the public key for identity {key_id:?}"))?;
    let blob = public_key
        .to_bytes()
        .with_context(|| format!("serializing the public-key blob for identity {key_id:?}"))?;

    // 1. List identities; `listed` = our blob is in the answer.
    stream
        .write_all(&ssh_proto::encode_request_identities())
        .context("sending REQUEST_IDENTITIES to the agent")?;
    let listed = match read_response(&mut stream)? {
        AgentResponse::Identities(keys) => keys.iter().any(|(b, _)| *b == blob),
        other => bail!("agent answered REQUEST_IDENTITIES with an unexpected reply: {other:?}"),
    };

    // 2. Sign TEST_DATA. RSA keys need a SHA2 flag; everything else ignores it.
    let flags = if matches!(public_key.algorithm(), ssh_key::Algorithm::Rsa { .. }) {
        SSH_AGENT_RSA_SHA2_256
    } else {
        0
    };
    stream
        .write_all(&ssh_proto::encode_sign_request(&blob, TEST_DATA, flags))
        .context("sending SIGN_REQUEST to the agent")?;
    let verified = match read_response(&mut stream)? {
        AgentResponse::SignResponse(sig) => {
            crate::ssh_sign::verify(&identity.public_key, TEST_DATA, &sig)
                .context("verifying the agent's signature against the public key")?
        }
        AgentResponse::Failure => bail!(
            "the agent refused to sign with {key_id:?} — the request was denied, or the private key didn't resolve"
        ),
        other => bail!("agent answered SIGN_REQUEST with an unexpected reply: {other:?}"),
    };

    Ok(SelfTest {
        key_id: key_id.to_owned(),
        listed,
        verified,
    })
}

/// Read exactly one framed agent reply (`[u32 len][payload]`) and parse it.
///
/// Bounded by [`MAX_AGENT_MSG_LEN`] so a bogus length prefix can't drive a
/// huge allocation. A read that times out (the safety net from [`run`]) is
/// reported as a distinct, actionable error rather than a generic I/O failure.
fn read_response(stream: &mut UnixStream) -> Result<AgentResponse> {
    let mut len_buf = [0u8; 4];
    read_exact_or_timeout(stream, &mut len_buf)?;
    let payload_len = u32::from_be_bytes(len_buf) as usize;
    if payload_len > MAX_AGENT_MSG_LEN {
        bail!("agent reply length {payload_len} exceeds cap of {MAX_AGENT_MSG_LEN} bytes");
    }
    // Fill the payload in its own buffer and append it, rather than
    // over-sizing `frame` and reading into the tail past the prefix.
    let mut payload = vec![0u8; payload_len];
    read_exact_or_timeout(stream, &mut payload)?;
    let mut frame = Vec::with_capacity(4 + payload_len);
    frame.extend_from_slice(&len_buf);
    frame.append(&mut payload);
    ssh_proto::parse_response(&frame)
}

/// `read_exact`, but a `WouldBlock`/`TimedOut` (the socket read-timeout
/// firing) maps to the actionable "timed out waiting to sign" error instead
/// of a generic read failure. Any other error propagates with context.
fn read_exact_or_timeout(stream: &mut UnixStream, buf: &mut [u8]) -> Result<()> {
    match stream.read_exact(buf) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
            bail!("timed out waiting for the agent to sign — was the consent prompt answered?")
        }
        Err(e) => Err(e).context("reading the agent's reply"),
    }
}
