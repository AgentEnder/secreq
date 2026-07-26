//! Wire protocol for the scoped secret agent — `[u32 length][JSON]` frames.
//!
//! ## Carrier-agnostic by construction
//!
//! The scoped agent's first carrier is an SSH-forwarded unix socket, but
//! brain's container tier has no sshd to forward through (`incus exec`
//! only), so a future carrier is an exec-pump relaying bytes over a
//! child's stdin/stdout. This codec is therefore written against the
//! *least* a carrier can offer: **a reliable, in-order byte stream**.
//!
//! Concretely, that rules out:
//!
//! - **`SO_PEERCRED` / fd passing / any socket-only syscall.** Nothing
//!   here reads the peer's credentials — see the provenance note in
//!   `brain: areas/secreq/design/2026-07-16-remote-secret-agent.md`; over a forwarded
//!   socket the peer is the tunnel, not the asker.
//! - **Line-orientation.** A pump is free to chunk or coalesce writes, so
//!   a `\n`-delimited codec (what `daemon/proto.rs` uses on its own local
//!   socket) could desynchronize. An explicit length prefix cannot.
//!
//! The length prefix is capped ([`MAX_FRAME_LEN`]) for the same reason
//! `daemon/ssh_agent.rs` caps `MAX_AGENT_MSG_LEN`: the length is untrusted
//! wire input from a guest, and it must not be able to drive an arbitrary
//! allocation in a long-lived host process.
//!
//! Payloads are JSON, matching `daemon/proto.rs`'s idiom. They're
//! self-describing, so a version skew between guest and host degrades to a
//! defined [`Response::Error`] rather than a misparse.

use std::io::{self, Read, Write};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Upper bound on one frame's JSON payload. Requests are a verb plus a
/// `secret://` ref and responses are one secret value or a short list of
/// refs, so 64 KiB is orders of magnitude more than any legitimate frame —
/// a larger prefix is a buggy or hostile peer. Rejected *before* the body
/// is sized or read.
pub const MAX_FRAME_LEN: usize = 64 * 1024;

/// One request, guest → host.
///
/// `#[serde(deny_unknown_fields)]` is deliberately *absent* on the
/// variants but the tag itself is closed: any verb that isn't `resolve` or
/// `list` fails to deserialize, and [`super::handle_request`] turns that
/// into [`Response::Error`]. That is the "everything else → error, no
/// enumeration surface" rule from the design — an unknown verb learns
/// nothing beyond "unsupported".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// "Resolve this `secret://provider/locator` for me." Gated: allowed
    /// refs prompt for consent, refs outside the socket's declared scope
    /// are denied without one.
    Resolve {
        reference: String,
        /// What the guest **claims** is asking, nearest-first
        /// (`["node", "pnpm", "postinstall"]`). Untrusted, optional, and
        /// **display-only**: the host cannot check a word of it (see the
        /// provenance section of
        /// `brain: areas/secreq/design/2026-07-16-remote-secret-agent.md`), so it is
        /// shown to the user marked as a guest claim and is never allowed to
        /// influence the decision or the cache key.
        ///
        /// It stays a raw `Vec<String>` for exactly as long as it is *wire
        /// input*. [`super::handle_request`] converts it into a
        /// [`super::GuestChain`] before any policy code can see it, and that
        /// type — which implements neither `Hash` nor `Eq` — is the only
        /// form that travels any further.
        ///
        /// `#[serde(default)]` keeps a guest that predates this field (a #41
        /// client) decoding cleanly as "claimed nothing".
        #[serde(default)]
        guest_chain: Vec<String>,
    },
    /// "What may I ask for?" Answers the scope's allowed ref **names**.
    /// Free — no prompt, no consent, mirroring the SSH agent's
    /// `REQUEST_IDENTITIES`.
    List,
}

impl Request {
    /// A resolve that claims nothing about its caller.
    pub fn resolve(reference: impl Into<String>) -> Request {
        Request::Resolve {
            reference: reference.into(),
            guest_chain: Vec::new(),
        }
    }

    /// A resolve carrying the guest's self-reported caller chain. See
    /// [`Request::Resolve::guest_chain`]: display-only, never load-bearing.
    pub fn resolve_claiming(reference: impl Into<String>, guest_chain: Vec<String>) -> Request {
        Request::Resolve {
            reference: reference.into(),
            guest_chain,
        }
    }
}

/// One response, host → guest.
///
/// [`Response::Denied`] and [`Response::Error`] are distinct on purpose:
/// a denial is a *policy* outcome (out of scope, or the user said no) and
/// is a normal, expected answer; an error means the request was malformed
/// or resolution failed after approval. A guest that conflates them would
/// retry a denial, which is exactly the click-training the design forbids.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Response {
    /// The resolved secret. The **only** message that carries material.
    Value { value: String },
    /// The request was understood and refused. `message` explains the
    /// refusal to a human reading guest-side logs; it never names another
    /// ref, so a denial can't be used to probe what else exists.
    Denied { message: String },
    /// The scope's allowed refs, as typed by the host at open time. Names
    /// (addresses) only — never values.
    Refs { refs: Vec<String> },
    /// The request was malformed, unsupported, or failed after approval.
    Error { message: String },
}

impl Response {
    /// Build a denial with the standard out-of-scope wording.
    pub fn out_of_scope() -> Response {
        Response::Denied {
            message: "reference is outside this socket's declared scope".to_owned(),
        }
    }
}

/// Encode one message as a framed `[u32 length][JSON]` buffer.
///
/// Generic over the payload so both directions share one framing
/// implementation — there is no request-only or response-only framing
/// quirk for a carrier to have to know about.
pub fn encode<T: Serialize>(message: &T) -> Result<Vec<u8>> {
    // Zeroizing, because for a `Response::Value` this buffer is a complete
    // plaintext copy of the secret as JSON. `write_response` scrubs the
    // `Response`'s own `String` and the frame it writes; this was the third
    // copy, freed intact on return. (serde_json's growth reallocations leave
    // further partial copies behind, which is harder to reach — but the final
    // buffer is ours and is the one that lives longest.)
    let payload =
        Zeroizing::new(serde_json::to_vec(message).context("serialize scoped-agent frame")?);
    if payload.len() > MAX_FRAME_LEN {
        anyhow::bail!(
            "scoped-agent frame payload of {} bytes exceeds the cap of {MAX_FRAME_LEN}",
            payload.len()
        );
    }
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Write one framed message to `w`.
pub fn write_message<T: Serialize, W: Write>(w: &mut W, message: &T) -> Result<()> {
    let frame = encode(message)?;
    w.write_all(&frame).context("write scoped-agent frame")?;
    w.flush().context("flush scoped-agent frame")
}

/// Read one frame's **payload bytes** off `r`, or `Ok(None)` on a clean
/// EOF before any bytes of a new frame — the normal "peer hung up" signal.
///
/// An over-cap length prefix errors *before* the body is sized or read, so
/// an untrusted length can't drive the allocation.
pub fn read_payload<R: Read>(r: &mut R) -> Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    if !read_exact_or_eof(r, &mut len_buf)? {
        return Ok(None);
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_LEN {
        anyhow::bail!(
            "scoped-agent frame payload length {len} exceeds the cap of {MAX_FRAME_LEN} bytes"
        );
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload)
        .context("read scoped-agent frame payload")?;
    Ok(Some(payload))
}

/// Read and decode one framed message, or `Ok(None)` on clean EOF.
///
/// A payload that doesn't decode as `T` is an `Err` — the caller decides
/// whether that's fatal (a client reading a garbled reply) or answerable
/// (the server, which replies [`Response::Error`] and keeps serving).
pub fn read_message<T: for<'de> Deserialize<'de>, R: Read>(r: &mut R) -> Result<Option<T>> {
    let Some(payload) = read_payload(r)? else {
        return Ok(None);
    };
    let message =
        serde_json::from_slice(&payload).context("decode scoped-agent frame payload as JSON")?;
    Ok(Some(message))
}

/// Fill `buf` completely. Returns `false` for a clean EOF *before the
/// first byte* (the peer closed between frames — expected); an EOF partway
/// through is a truncated frame and errors.
fn read_exact_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => {
                if filled == 0 {
                    return Ok(false);
                }
                anyhow::bail!(
                    "truncated scoped-agent frame: got {filled} of {} length-prefix bytes before EOF",
                    buf.len()
                );
            }
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e).context("read scoped-agent frame length prefix"),
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_round_trip_through_a_frame() {
        for request in [
            Request::resolve("secret://op/Dev/gh/token"),
            Request::resolve_claiming(
                "secret://op/Dev/gh/token",
                vec!["node".to_owned(), "pnpm".to_owned()],
            ),
            Request::List,
        ] {
            let frame = encode(&request).expect("encode");
            let mut cursor = std::io::Cursor::new(frame);
            let decoded: Request = read_message(&mut cursor).expect("read").expect("present");
            assert_eq!(decoded, request);
        }
    }

    #[test]
    fn responses_round_trip_through_a_frame() {
        let response = Response::Refs {
            refs: vec!["secret://op/Dev/gh/token".to_owned()],
        };
        let frame = encode(&response).expect("encode");
        let mut cursor = std::io::Cursor::new(frame);
        let decoded: Response = read_message(&mut cursor).expect("read").expect("present");
        assert_eq!(decoded, response);
    }

    /// Two frames written back-to-back into one buffer must decode as two
    /// distinct messages. This is the property a line-delimited codec
    /// couldn't promise over a carrier that coalesces writes, and it's why
    /// the frame is length-prefixed.
    #[test]
    fn pipelined_frames_decode_independently() {
        let mut stream = Vec::new();
        write_message(&mut stream, &Request::List).expect("write list");
        write_message(&mut stream, &Request::resolve("secret://op/Dev/gh/token"))
            .expect("write resolve");

        let mut cursor = std::io::Cursor::new(stream);
        let first: Request = read_message(&mut cursor).expect("read").expect("present");
        let second: Request = read_message(&mut cursor).expect("read").expect("present");
        assert_eq!(first, Request::List);
        assert_eq!(second, Request::resolve("secret://op/Dev/gh/token"));
        // Third read hits a clean EOF between frames, not an error.
        let third: Option<Request> = read_message(&mut cursor).expect("read");
        assert!(third.is_none());
    }

    /// An oversized length prefix must be rejected by the cap check
    /// *before* a body that large is allocated or read. Writing only the
    /// 4-byte prefix is enough: without the guard we'd size a buffer for
    /// the bogus length and then block in `read_exact` for body bytes that
    /// never come.
    #[test]
    fn oversized_length_prefix_is_rejected_before_allocating() {
        let oversized = (MAX_FRAME_LEN + 1) as u32;
        let mut cursor = std::io::Cursor::new(oversized.to_be_bytes().to_vec());
        let err = read_payload(&mut cursor).expect_err("expected Err for over-cap length");
        let msg = format!("{err:#}");
        assert!(
            msg.contains(&MAX_FRAME_LEN.to_string()),
            "error should cite the cap, got: {msg}"
        );
    }

    /// An unknown verb must not deserialize — that's what makes
    /// "everything else → error" structural rather than a hand-written
    /// match arm someone can forget to update.
    #[test]
    fn unknown_verb_fails_to_decode() {
        let payload = br#"{"op":"enumerate"}"#;
        let decoded: Result<Request, _> = serde_json::from_slice::<Request>(payload);
        assert!(decoded.is_err(), "unknown verbs must not decode");
    }

    /// A resolve frame from a guest that predates `guest_chain` must still
    /// decode — as "claimed nothing", not as an error. The field is an
    /// optional embellishment on an existing verb; a #41 client that never
    /// heard of it must keep working unchanged.
    #[test]
    fn resolve_without_a_guest_chain_decodes_as_claiming_nothing() {
        let payload = br#"{"op":"resolve","reference":"secret://op/Dev/gh/token"}"#;
        let decoded: Request = serde_json::from_slice(payload).expect("old frames must decode");
        assert_eq!(decoded, Request::resolve("secret://op/Dev/gh/token"));
    }

    /// A clean EOF before any frame is `Ok(None)`, not an error.
    #[test]
    fn clean_eof_between_frames_is_not_an_error() {
        let mut cursor = std::io::Cursor::new(Vec::new());
        let decoded: Option<Request> = read_message(&mut cursor).expect("clean EOF is Ok");
        assert!(decoded.is_none());
    }

    /// A truncated length prefix *is* an error — distinct from the clean
    /// EOF above.
    #[test]
    fn truncated_length_prefix_errors() {
        let mut cursor = std::io::Cursor::new(vec![0u8, 0]);
        let err = read_payload(&mut cursor).expect_err("expected Err for truncated prefix");
        assert!(format!("{err:#}").contains("truncated"));
    }
}
