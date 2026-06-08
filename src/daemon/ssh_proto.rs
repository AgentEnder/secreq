//! SSH agent protocol framing (PROTOCOL.agent / draft-miller-ssh-agent).
//!
//! Every agent message is framed as `[u32 length][payload]`, where the
//! big-endian `length` counts the payload bytes (the message-type byte
//! plus everything after it). The first payload byte is the message
//! type; the rest is type-specific.
//!
//! SSH `string` encoding is `[u32 length][bytes]` (big-endian length).
//! We reuse `ssh-encoding`'s `Decode`/`Encode` impls for the SSH-string
//! and `u32` bodies (`Vec<u8>` decodes/encodes the `[u32 len][bytes]`
//! string form; `u32` is big-endian). The **outer** message frame is
//! hand-rolled here: it's a trivial 4-byte length prefix and writing it
//! explicitly keeps the framing legible at the call site.

use anyhow::{bail, Context, Result};
use ssh_encoding::{Decode, Encode};

/// Client → agent: "list the identities you hold."
pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
/// Agent → client: the identity list.
pub const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
/// Client → agent: "sign this data with this key."
pub const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
/// Agent → client: the signature.
pub const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
/// Agent → client: generic failure.
pub const SSH_AGENT_FAILURE: u8 = 5;
/// Agent → client: generic success.
pub const SSH_AGENT_SUCCESS: u8 = 6;

/// A parsed, fully-framed request from an SSH client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentRequest {
    /// `SSH_AGENTC_REQUEST_IDENTITIES` — list identities.
    RequestIdentities,
    /// `SSH_AGENTC_SIGN_REQUEST` — sign `data` with the key identified
    /// by `key_blob`. `flags` carries the signature-algorithm request
    /// bits (e.g. `SSH_AGENT_RSA_SHA2_256`).
    Sign {
        key_blob: Vec<u8>,
        data: Vec<u8>,
        flags: u32,
    },
    /// A well-formed frame whose message type we don't implement. The
    /// caller answers these with `SSH_AGENT_FAILURE`.
    Unsupported(u8),
}

/// Parse exactly one complete framed message: `[u32 len][u8 type][payload]`.
///
/// Validates that the declared length matches the bytes available
/// (rejecting both truncated frames and trailing-garbage frames) and
/// returns a clear error rather than panicking on malformed input.
/// Known message types map to their variant; anything else maps to
/// [`AgentRequest::Unsupported`].
pub fn parse_request(frame: &[u8]) -> Result<AgentRequest> {
    if frame.len() < 4 {
        bail!(
            "agent frame too short for length prefix: {} bytes",
            frame.len()
        );
    }
    let declared_len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    let payload = &frame[4..];
    if payload.len() != declared_len {
        bail!(
            "agent frame length mismatch: prefix declares {declared_len} payload bytes, {} present",
            payload.len()
        );
    }
    if declared_len == 0 {
        bail!("agent frame has empty payload (no message type byte)");
    }

    let msg_type = payload[0];
    let body = &payload[1..];

    match msg_type {
        SSH_AGENTC_REQUEST_IDENTITIES => Ok(AgentRequest::RequestIdentities),
        SSH_AGENTC_SIGN_REQUEST => parse_sign_request(body),
        other => Ok(AgentRequest::Unsupported(other)),
    }
}

/// Parse a SIGN_REQUEST body (everything after the type byte):
/// `string key_blob`, `string data`, `u32 flags`.
fn parse_sign_request(body: &[u8]) -> Result<AgentRequest> {
    let mut reader = body;
    let key_blob = Vec::<u8>::decode(&mut reader)
        .map_err(|e| anyhow::anyhow!(e))
        .context("read SIGN_REQUEST key_blob")?;
    let data = Vec::<u8>::decode(&mut reader)
        .map_err(|e| anyhow::anyhow!(e))
        .context("read SIGN_REQUEST data")?;
    let flags = u32::decode(&mut reader)
        .map_err(|e| anyhow::anyhow!(e))
        .context("read SIGN_REQUEST flags")?;
    if !reader.is_empty() {
        bail!(
            "SIGN_REQUEST has {} trailing bytes after flags",
            reader.len()
        );
    }
    Ok(AgentRequest::Sign {
        key_blob,
        data,
        flags,
    })
}

/// Wrap a payload (type byte + body) in the outer `[u32 len][payload]`
/// frame. `length` counts the whole payload, including the type byte.
fn frame(payload: Vec<u8>) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&payload);
    out
}

/// Encode a `SSH_AGENT_IDENTITIES_ANSWER`: `u32 nkeys`, then per key a
/// `string key_blob` followed by a `string comment`.
///
/// Keys are supplied as `(key_blob, comment)` pairs. The blob is raw
/// SSH wire bytes (`Vec<u8>` / `&[u8]`), not text — an ed25519 or RSA
/// public-key blob is binary — so the blob is `[u8]` and the comment is
/// `&str`. (The plan sketched `&[(String, String)]`; using `[u8]` for
/// the blob is the correct, non-lossy type.)
pub fn encode_identities_answer<B, C>(keys: &[(B, C)]) -> Vec<u8>
where
    B: AsRef<[u8]>,
    C: AsRef<str>,
{
    let mut payload = vec![SSH_AGENT_IDENTITIES_ANSWER];
    let nkeys = keys.len() as u32;
    nkeys
        .encode(&mut payload)
        .expect("encoding into a Vec is infallible");
    for (key_blob, comment) in keys {
        key_blob
            .as_ref()
            .encode(&mut payload)
            .expect("encoding into a Vec is infallible");
        comment
            .as_ref()
            .encode(&mut payload)
            .expect("encoding into a Vec is infallible");
    }
    frame(payload)
}

/// Encode a `SSH_AGENT_SIGN_RESPONSE`: a single `string signature`.
///
/// `signature_blob` is the in-process SSH signature wire blob (itself the
/// `string algorithm` + `string blob` structure); here it is wrapped as
/// one SSH string in the response payload.
pub fn encode_sign_response(signature_blob: &[u8]) -> Vec<u8> {
    let mut payload = vec![SSH_AGENT_SIGN_RESPONSE];
    signature_blob
        .encode(&mut payload)
        .expect("encoding into a Vec is infallible");
    frame(payload)
}

/// Encode a bare `SSH_AGENT_FAILURE`.
pub fn encode_failure() -> Vec<u8> {
    frame(vec![SSH_AGENT_FAILURE])
}

/// Encode a bare `SSH_AGENT_SUCCESS`.
pub fn encode_success() -> Vec<u8> {
    frame(vec![SSH_AGENT_SUCCESS])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `SSH_AGENTC_SIGN_REQUEST` frame for round-trip tests:
    /// `[u32 len][type=13][string key_blob][string data][u32 flags]`.
    fn encode_sign_request(key_blob: &[u8], data: &[u8], flags: u32) -> Vec<u8> {
        let mut payload = vec![SSH_AGENTC_SIGN_REQUEST];
        key_blob.encode(&mut payload).unwrap();
        data.encode(&mut payload).unwrap();
        flags.encode(&mut payload).unwrap();
        frame(payload)
    }

    #[test]
    fn parses_request_identities() {
        // length-prefixed: [u32 len=1][u8 type=11]
        let bytes = [0, 0, 0, 1, 11];
        assert!(matches!(
            parse_request(&bytes).unwrap(),
            AgentRequest::RequestIdentities
        ));
    }

    #[test]
    fn parses_sign_request() {
        let req = encode_sign_request(b"KEYBLOB", b"DATA", 0);
        match parse_request(&req).unwrap() {
            AgentRequest::Sign {
                key_blob,
                data,
                flags,
            } => {
                assert_eq!(key_blob, b"KEYBLOB");
                assert_eq!(data, b"DATA");
                assert_eq!(flags, 0);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn parses_sign_request_with_nonzero_flags() {
        let req = encode_sign_request(b"k", b"payload-bytes", 0x0000_0002);
        match parse_request(&req).unwrap() {
            AgentRequest::Sign { flags, .. } => assert_eq!(flags, 2),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn encodes_identities_answer_and_failure() {
        let ans = encode_identities_answer(&[(b"ssh-ed25519 AAAA".to_vec(), "blob".to_owned())]);
        assert_eq!(ans[4], SSH_AGENT_IDENTITIES_ANSWER);
        assert_eq!(encode_failure()[4], SSH_AGENT_FAILURE);
    }

    #[test]
    fn identities_answer_round_trips() {
        let ans = encode_identities_answer(&[
            (b"blob-one".to_vec(), "comment one".to_owned()),
            (b"blob-two".to_vec(), "comment two".to_owned()),
        ]);
        // Strip the 4-byte frame and the type byte, then re-read.
        let payload = &ans[4..];
        assert_eq!(payload[0], SSH_AGENT_IDENTITIES_ANSWER);
        let mut reader = &payload[1..];
        let nkeys = u32::decode(&mut reader).unwrap();
        assert_eq!(nkeys, 2);
        let blob1 = Vec::<u8>::decode(&mut reader).unwrap();
        let comment1 = String::decode(&mut reader).unwrap();
        let blob2 = Vec::<u8>::decode(&mut reader).unwrap();
        let comment2 = String::decode(&mut reader).unwrap();
        assert_eq!(blob1, b"blob-one");
        assert_eq!(comment1, "comment one");
        assert_eq!(blob2, b"blob-two");
        assert_eq!(comment2, "comment two");
        assert!(reader.is_empty());
    }

    #[test]
    fn parse_request_rejects_truncated_frame() {
        // Prefix claims 10 payload bytes but only 1 is present.
        let bytes = [0, 0, 0, 10, 11];
        let err = parse_request(&bytes).unwrap_err();
        assert!(err.to_string().contains("length mismatch"), "{err}");
    }

    #[test]
    fn parse_request_rejects_short_prefix() {
        let bytes = [0, 0, 1];
        assert!(parse_request(&bytes).is_err());
    }

    #[test]
    fn parse_request_rejects_empty_payload() {
        let bytes = [0, 0, 0, 0];
        assert!(parse_request(&bytes).is_err());
    }

    #[test]
    fn parse_request_maps_unknown_type_to_unsupported() {
        // [u32 len=1][type=99]
        let bytes = [0, 0, 0, 1, 99];
        assert!(matches!(
            parse_request(&bytes).unwrap(),
            AgentRequest::Unsupported(99)
        ));
    }

    #[test]
    fn sign_response_wraps_signature_as_string() {
        let sig = b"\x00\x00\x00\x0bssh-ed25519signature-bytes";
        let resp = encode_sign_response(sig);
        // Frame: [u32 len][type=14][string signature].
        assert_eq!(resp[4], SSH_AGENT_SIGN_RESPONSE);
        let mut reader = &resp[5..];
        let inner = Vec::<u8>::decode(&mut reader).unwrap();
        assert_eq!(inner, sig);
        assert!(reader.is_empty());
    }
}
