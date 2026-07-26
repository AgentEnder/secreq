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
//!
//! # Every byte in here was chosen by a peer
//!
//! `parse_request` reads the agent socket and `parse_response` reads
//! whatever answers on `$SSH_AUTH_SOCK`, so a panic in this module is a
//! panic in the long-lived daemon, reachable by anyone who can write a
//! frame to it. Nothing here may index or slice at an offset it has not
//! proven: [`split_frame`] is the one place the outer framing is taken
//! apart, and it returns a message type and a body or an error. A parser
//! added later gets the framing checks by calling it, which is why the
//! lint below is a `deny` rather than a comment asking nicely.
#![deny(clippy::indexing_slicing)]

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
    let (msg_type, body) = split_frame(frame)?;
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

/// Take one complete `[u32 len][u8 type][body]` frame apart, returning the
/// message type and the body behind it. The inverse of [`frame`].
///
/// This is the only code in the module that works with byte offsets, and
/// it reaches every one of them through a checked `split_*` that yields
/// `None` rather than panicking. The three ways a frame can be malformed
/// each become an error:
///
/// - **shorter than the length prefix** — fewer than 4 bytes to read;
/// - **length mismatch** — the prefix's count disagrees with the bytes
///   actually present, which covers both a truncated frame and one with
///   trailing garbage. Note this is checked against the *declared* number
///   alone: nothing is ever sized or allocated from it, so a prefix of
///   `0xFFFF_FFFF` costs a comparison rather than 4 GiB;
/// - **empty payload** — a frame that declares zero bytes has no message
///   type byte, so there is nothing to dispatch on.
fn split_frame(frame: &[u8]) -> Result<(u8, &[u8])> {
    let Some((len_bytes, payload)) = frame.split_first_chunk::<4>() else {
        bail!(
            "agent frame too short for length prefix: {} bytes",
            frame.len()
        );
    };
    let declared_len = u32::from_be_bytes(*len_bytes) as usize;
    if payload.len() != declared_len {
        bail!(
            "agent frame length mismatch: prefix declares {declared_len} payload bytes, {} present",
            payload.len()
        );
    }
    let Some((&msg_type, body)) = payload.split_first() else {
        bail!("agent frame has empty payload (no message type byte)");
    };
    Ok((msg_type, body))
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
    let (msg_type, body) = split_frame(frame)?;
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
    // Not `with_capacity(nkeys)`: `nkeys` is an unvalidated wire `u32`, and
    // `Vec::<(Vec<u8>, String)>::with_capacity(0xFFFF_FFFF)` asks for ~190 GB
    // in one call — a failed allocation aborts the process rather than
    // erroring. The enclosing frame is capped well below what a real count
    // could need, so let the vec grow into whatever the body actually holds
    // and let the per-key decode hit the short read.
    let mut keys = Vec::new();
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

    // ── Malformed input ──
    //
    // Both parsers are fed bytes a peer chose: `parse_request` reads the
    // agent socket, `parse_response` reads whatever answers on
    // `$SSH_AUTH_SOCK`. A panic here is a panic in the long-lived daemon,
    // so every one of these asserts an `Err` rather than a specific error.

    /// Build a frame whose length prefix is written by hand, so a test can
    /// declare a length the payload does not have.
    fn framed_with_declared_len(declared_len: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = declared_len.to_be_bytes().to_vec();
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn parsers_reject_empty_input() {
        assert!(parse_request(&[]).is_err());
        assert!(parse_response(&[]).is_err());
    }

    #[test]
    fn parsers_reject_a_lone_length_prefix_declaring_a_body() {
        // Four bytes exactly, so the prefix reads cleanly and there is
        // nothing behind it.
        let bytes = framed_with_declared_len(1, &[]);
        assert!(parse_request(&bytes).is_err());
        assert!(parse_response(&bytes).is_err());
    }

    #[test]
    fn parsers_reject_an_overlong_frame() {
        // Prefix declares 1 payload byte; 4 are present. Trailing garbage
        // must not be silently accepted — the frame is not what it says.
        let bytes = framed_with_declared_len(1, &[11, 0xAA, 0xBB, 0xCC]);
        assert!(parse_request(&bytes).is_err());
        assert!(parse_response(&bytes).is_err());
    }

    #[test]
    fn parsers_reject_a_saturated_length_prefix_without_allocating() {
        // 0xFFFF_FFFF payload bytes declared, one present. The mismatch has
        // to be caught off the declared number alone: nothing may size a
        // buffer from it.
        let bytes = framed_with_declared_len(u32::MAX, &[11]);
        assert!(parse_request(&bytes).is_err());
        assert!(parse_response(&bytes).is_err());
    }

    #[test]
    fn parse_response_rejects_empty_payload() {
        assert!(parse_response(&[0, 0, 0, 0]).is_err());
    }

    /// Every prefix of a well-formed frame is malformed input, and there is
    /// no clever way to be wrong about a truncation — so assert the whole
    /// family at once rather than picking three offsets by hand.
    #[test]
    fn no_truncation_of_a_valid_frame_panics() {
        let request = encode_sign_request(b"KEYBLOB", b"DATA", 2);
        for cut in 0..request.len() {
            assert!(
                parse_request(&request[..cut]).is_err(),
                "truncation to {cut} bytes was accepted"
            );
        }
        assert!(parse_request(&request).is_ok());

        let response = encode_identities_answer(&[
            (b"blob-one".to_vec(), "comment one".to_owned()),
            (b"blob-two".to_vec(), "comment two".to_owned()),
        ]);
        for cut in 0..response.len() {
            assert!(
                parse_response(&response[..cut]).is_err(),
                "truncation to {cut} bytes was accepted"
            );
        }
        assert!(parse_response(&response).is_ok());
    }

    /// Same family, but keeping the length prefix honest as the body
    /// shrinks — so the framing check passes and the *body* decoders are
    /// the ones that have to reject the short read.
    #[test]
    fn no_correctly_framed_truncated_body_panics() {
        for body in [
            encode_sign_request(b"KEYBLOB", b"DATA", 2),
            encode_identities_answer(&[(b"blob".to_vec(), "comment".to_owned())]),
            encode_sign_response(b"signature-bytes"),
        ] {
            let payload = &body[4..];
            for cut in 1..payload.len() {
                let short = &payload[..cut];
                let frame = framed_with_declared_len(cut as u32, short);
                // Truncating the body can only ever produce an error or a
                // valid shorter message; it must never panic.
                let _ = parse_request(&frame);
                let _ = parse_response(&frame);
            }
        }
    }

    #[test]
    fn sign_request_rejects_a_string_length_longer_than_the_body() {
        // type=13, then a key_blob string claiming 0xFFFF bytes with 2 present.
        let payload = vec![SSH_AGENTC_SIGN_REQUEST, 0, 0, 0xFF, 0xFF, 0xAA, 0xBB];
        let frame = framed_with_declared_len(payload.len() as u32, &payload);
        assert!(parse_request(&frame).is_err());
    }

    #[test]
    fn sign_request_rejects_a_missing_flags_word() {
        // key_blob and data both present and well-formed; flags absent.
        let mut payload = vec![SSH_AGENTC_SIGN_REQUEST];
        b"k".encode(&mut payload).unwrap();
        b"d".encode(&mut payload).unwrap();
        let frame = framed_with_declared_len(payload.len() as u32, &payload);
        assert!(parse_request(&frame).is_err());
    }

    #[test]
    fn sign_request_rejects_trailing_bytes_after_flags() {
        let mut req = encode_sign_request(b"k", b"d", 0);
        req.push(0xAA);
        // Fix the prefix so the framing check passes and the body decoder
        // is the one that has to notice.
        let payload_len = (req.len() - 4) as u32;
        req.splice(0..4, payload_len.to_be_bytes());
        let err = parse_request(&req).unwrap_err();
        assert!(err.to_string().contains("trailing"), "{err}");
    }

    #[test]
    fn sign_request_rejects_an_empty_body() {
        let frame = framed_with_declared_len(1, &[SSH_AGENTC_SIGN_REQUEST]);
        assert!(parse_request(&frame).is_err());
    }

    #[test]
    fn identities_answer_rejects_a_saturated_key_count() {
        // nkeys = 0xFFFF_FFFF with no keys behind it. The per-key decode has
        // to fail on the first pass rather than the loop running four
        // billion times or a vec being sized from the count.
        let mut payload = vec![SSH_AGENT_IDENTITIES_ANSWER];
        u32::MAX.encode(&mut payload).unwrap();
        let frame = framed_with_declared_len(payload.len() as u32, &payload);
        assert!(parse_response(&frame).is_err());
    }

    #[test]
    fn identities_answer_rejects_a_key_count_larger_than_the_keys_present() {
        let mut payload = vec![SSH_AGENT_IDENTITIES_ANSWER];
        2u32.encode(&mut payload).unwrap();
        b"only-one-blob".as_slice().encode(&mut payload).unwrap();
        "only-one-comment".encode(&mut payload).unwrap();
        let frame = framed_with_declared_len(payload.len() as u32, &payload);
        assert!(parse_response(&frame).is_err());
    }

    #[test]
    fn identities_answer_rejects_a_non_utf8_comment() {
        let mut payload = vec![SSH_AGENT_IDENTITIES_ANSWER];
        1u32.encode(&mut payload).unwrap();
        b"blob".as_slice().encode(&mut payload).unwrap();
        // A comment string whose bytes are not valid UTF-8.
        b"\xFF\xFE".as_slice().encode(&mut payload).unwrap();
        let frame = framed_with_declared_len(payload.len() as u32, &payload);
        assert!(parse_response(&frame).is_err());
    }

    #[test]
    fn identities_answer_rejects_trailing_bytes_after_the_last_key() {
        let mut payload = vec![SSH_AGENT_IDENTITIES_ANSWER];
        0u32.encode(&mut payload).unwrap();
        payload.push(0xAA);
        let frame = framed_with_declared_len(payload.len() as u32, &payload);
        let err = parse_response(&frame).unwrap_err();
        assert!(err.to_string().contains("trailing"), "{err}");
    }

    #[test]
    fn identities_answer_rejects_an_empty_body() {
        let frame = framed_with_declared_len(1, &[SSH_AGENT_IDENTITIES_ANSWER]);
        assert!(parse_response(&frame).is_err());
    }

    #[test]
    fn sign_response_rejects_an_empty_body_and_trailing_bytes() {
        let empty = framed_with_declared_len(1, &[SSH_AGENT_SIGN_RESPONSE]);
        assert!(parse_response(&empty).is_err());

        let mut payload = vec![SSH_AGENT_SIGN_RESPONSE];
        b"sig".as_slice().encode(&mut payload).unwrap();
        payload.push(0xAA);
        let frame = framed_with_declared_len(payload.len() as u32, &payload);
        let err = parse_response(&frame).unwrap_err();
        assert!(err.to_string().contains("trailing"), "{err}");
    }
}
