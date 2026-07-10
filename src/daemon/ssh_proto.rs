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

/// Client → agent: `SSH_AGENTC_REQUEST_IDENTITIES`. The payload is just the
/// message-type byte; there is no body.
pub fn encode_request_identities() -> Vec<u8> {
    frame(vec![SSH_AGENTC_REQUEST_IDENTITIES])
}

/// Client → agent: `SSH_AGENTC_SIGN_REQUEST`. Frame is
/// `[u32 len][type=13][string key_blob][string data][u32 flags]`. `flags`
/// carries the signature-algorithm request bits (e.g.
/// `crate::ssh_sign::SSH_AGENT_RSA_SHA2_256`).
pub fn encode_sign_request(key_blob: &[u8], data: &[u8], flags: u32) -> Vec<u8> {
    let mut payload = vec![SSH_AGENTC_SIGN_REQUEST];
    key_blob
        .encode(&mut payload)
        .expect("encoding into a Vec is infallible");
    data.encode(&mut payload)
        .expect("encoding into a Vec is infallible");
    flags
        .encode(&mut payload)
        .expect("encoding into a Vec is infallible");
    frame(payload)
}

/// A parsed, fully-framed reply from the agent (the client's view).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentResponse {
    /// `SSH_AGENT_IDENTITIES_ANSWER` — each held key as `(key_blob, comment)`.
    Identities(Vec<(Vec<u8>, String)>),
    /// `SSH_AGENT_SIGN_RESPONSE` — the inner signature `string` (itself the
    /// `string algorithm` + `string blob` wire encoding).
    SignResponse(Vec<u8>),
    /// `SSH_AGENT_FAILURE` — the agent refused or errored.
    Failure,
    /// `SSH_AGENT_SUCCESS`.
    Success,
    /// A well-formed frame whose message type we don't decode.
    Unsupported(u8),
}

/// Parse exactly one complete framed agent reply: `[u32 len][u8 type][payload]`.
///
/// Mirrors [`parse_request`]'s framing discipline: the declared length must
/// match the bytes present (rejecting truncated and trailing-garbage frames)
/// and malformed bodies return an error rather than panicking.
pub fn parse_response(frame: &[u8]) -> Result<AgentResponse> {
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
        SSH_AGENT_IDENTITIES_ANSWER => parse_identities_answer(body),
        SSH_AGENT_SIGN_RESPONSE => parse_sign_response(body),
        SSH_AGENT_FAILURE => Ok(AgentResponse::Failure),
        SSH_AGENT_SUCCESS => Ok(AgentResponse::Success),
        other => Ok(AgentResponse::Unsupported(other)),
    }
}

/// Parse an IDENTITIES_ANSWER body: `u32 nkeys`, then per key a
/// `string key_blob` followed by a `string comment`.
fn parse_identities_answer(body: &[u8]) -> Result<AgentResponse> {
    let mut reader = body;
    let nkeys = u32::decode(&mut reader)
        .map_err(|e| anyhow::anyhow!(e))
        .context("read IDENTITIES_ANSWER nkeys")?;
    let mut keys = Vec::with_capacity(nkeys as usize);
    for i in 0..nkeys {
        let blob = Vec::<u8>::decode(&mut reader)
            .map_err(|e| anyhow::anyhow!(e))
            .with_context(|| format!("read IDENTITIES_ANSWER key blob #{i}"))?;
        let comment = String::decode(&mut reader)
            .map_err(|e| anyhow::anyhow!(e))
            .with_context(|| format!("read IDENTITIES_ANSWER comment #{i}"))?;
        keys.push((blob, comment));
    }
    if !reader.is_empty() {
        bail!(
            "IDENTITIES_ANSWER has {} trailing bytes after {nkeys} key(s)",
            reader.len()
        );
    }
    Ok(AgentResponse::Identities(keys))
}

/// Parse a SIGN_RESPONSE body: a single `string signature`.
fn parse_sign_response(body: &[u8]) -> Result<AgentResponse> {
    let mut reader = body;
    let signature = Vec::<u8>::decode(&mut reader)
        .map_err(|e| anyhow::anyhow!(e))
        .context("read SIGN_RESPONSE signature")?;
    if !reader.is_empty() {
        bail!(
            "SIGN_RESPONSE has {} trailing bytes after signature",
            reader.len()
        );
    }
    Ok(AgentResponse::SignResponse(signature))
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn encode_request_identities_is_a_single_type_byte_frame() {
        let bytes = encode_request_identities();
        assert_eq!(bytes, [0, 0, 0, 1, SSH_AGENTC_REQUEST_IDENTITIES]);
        // And the server-side parser accepts what the client encodes.
        assert!(matches!(
            parse_request(&bytes).unwrap(),
            AgentRequest::RequestIdentities
        ));
    }

    #[test]
    fn encode_sign_request_round_trips_through_parse_request() {
        let req = encode_sign_request(b"KEYBLOB", b"DATA", 2);
        match parse_request(&req).unwrap() {
            AgentRequest::Sign {
                key_blob,
                data,
                flags,
            } => {
                assert_eq!(key_blob, b"KEYBLOB");
                assert_eq!(data, b"DATA");
                assert_eq!(flags, 2);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn parse_response_decodes_identities_answer() {
        let ans = encode_identities_answer(&[
            (b"blob-one".to_vec(), "comment one".to_owned()),
            (b"blob-two".to_vec(), "comment two".to_owned()),
        ]);
        match parse_response(&ans).unwrap() {
            AgentResponse::Identities(keys) => {
                assert_eq!(keys.len(), 2);
                assert_eq!(keys[0], (b"blob-one".to_vec(), "comment one".to_owned()));
                assert_eq!(keys[1], (b"blob-two".to_vec(), "comment two".to_owned()));
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn parse_response_decodes_sign_response() {
        let sig = b"\x00\x00\x00\x0bssh-ed25519signature-bytes";
        let resp = encode_sign_response(sig);
        match parse_response(&resp).unwrap() {
            AgentResponse::SignResponse(inner) => assert_eq!(inner, sig),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn parse_response_decodes_failure_and_success() {
        assert_eq!(
            parse_response(&encode_failure()).unwrap(),
            AgentResponse::Failure
        );
        assert_eq!(
            parse_response(&encode_success()).unwrap(),
            AgentResponse::Success
        );
    }

    #[test]
    fn parse_response_maps_unknown_type_to_unsupported() {
        let bytes = [0, 0, 0, 1, 99];
        assert!(matches!(
            parse_response(&bytes).unwrap(),
            AgentResponse::Unsupported(99)
        ));
    }

    #[test]
    fn parse_response_rejects_truncated_frame() {
        // Prefix claims 10 payload bytes but only 1 is present.
        let bytes = [0, 0, 0, 10, SSH_AGENT_SIGN_RESPONSE];
        let err = parse_response(&bytes).unwrap_err();
        assert!(err.to_string().contains("length mismatch"), "{err}");
    }

    #[test]
    fn parse_response_rejects_short_prefix() {
        assert!(parse_response(&[0, 0, 1]).is_err());
    }
}
