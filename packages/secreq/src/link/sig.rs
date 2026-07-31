//! Verification of decisions signed by linked devices.

use anyhow::{anyhow, Result};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use ssh_encoding::base64::{Base64, Encoding};

use super::canonical::canonical_parts;
use super::devices::Device;

const INVALID_SIGNATURE: &str = "invalid decision signature";

/// A linked device's signed response to one pending ask.
///
/// The signature is WebCrypto's 64-byte IEEE P1363 (`r || s`) ECDSA output,
/// encoded as standard padded Base64. `Device::public_key_b64` likewise holds
/// the standard Base64 encoding of an uncompressed SEC1 P-256 public point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedDecision {
    pub request_id: String,
    pub ask_hash_hex: String,
    pub decision: String,
    pub nonce: String,
    pub signature_b64: String,
}

/// Verify a signed decision against one enrolled device.
///
/// Every failure deliberately returns the same opaque error. The caller has
/// no legitimate use for knowing whether key decoding, signature decoding, or
/// verification failed, and distinguishing those cases would make this LAN
/// endpoint an oracle.
pub fn verify(device: &Device, payload: &SignedDecision) -> Result<()> {
    verify_inner(device, payload).map_err(|()| anyhow!(INVALID_SIGNATURE))
}

fn verify_inner(device: &Device, payload: &SignedDecision) -> Result<(), ()> {
    let public_key = Base64::decode_vec(&device.public_key_b64).map_err(|_| ())?;
    let verifying_key = VerifyingKey::from_sec1_bytes(&public_key).map_err(|_| ())?;
    let signature = Base64::decode_vec(&payload.signature_b64).map_err(|_| ())?;
    let signature = Signature::from_slice(&signature).map_err(|_| ())?;
    let signed_bytes = canonical_parts(&[
        &payload.request_id,
        &payload.ask_hash_hex,
        &payload.decision,
        &payload.nonce,
    ]);

    verifying_key
        .verify(&signed_bytes, &signature)
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};
    use ssh_encoding::base64::{Base64, Encoding};

    use super::*;

    fn signing_key() -> SigningKey {
        SigningKey::random(&mut rand::thread_rng())
    }

    fn device_for(signing_key: &SigningKey) -> Device {
        Device {
            nickname: "Craig's iPhone".into(),
            public_key_b64: Base64::encode_string(
                signing_key
                    .verifying_key()
                    .to_encoded_point(false)
                    .as_bytes(),
            ),
            enrolled_at: 1_753_000_000,
            last_seen: None,
        }
    }

    fn signed_decision(signing_key: &SigningKey) -> SignedDecision {
        let mut payload = SignedDecision {
            request_id: "request-123".into(),
            ask_hash_hex: "0123456789abcdef".repeat(4),
            decision: "approve".into(),
            nonce: "nonce-456".into(),
            signature_b64: String::new(),
        };
        let bytes = canonical_parts(&[
            &payload.request_id,
            &payload.ask_hash_hex,
            &payload.decision,
            &payload.nonce,
        ]);
        let signature: Signature = signing_key.sign(&bytes);
        payload.signature_b64 = Base64::encode_string(&signature.to_bytes());
        payload
    }

    #[test]
    fn a_good_signature_verifies() {
        let signing_key = signing_key();

        verify(&device_for(&signing_key), &signed_decision(&signing_key))
            .expect("a signature from the enrolled device");
    }

    #[test]
    fn a_signature_from_an_unenrolled_key_is_refused() {
        let enrolled = signing_key();
        let stranger = signing_key();

        verify(&device_for(&enrolled), &signed_decision(&stranger))
            .expect_err("a signature from another key must fail");
    }

    #[test]
    fn a_signature_over_a_different_decision_is_refused() {
        let signing_key = signing_key();
        let device = device_for(&signing_key);
        let mut payload = signed_decision(&signing_key);
        payload.decision = "deny".into();

        verify(&device, &payload).expect_err("the decision is signed, not adjacent metadata");
    }

    #[test]
    fn a_signature_over_a_different_ask_hash_is_refused() {
        let signing_key = signing_key();
        let device = device_for(&signing_key);
        let mut payload = signed_decision(&signing_key);
        payload.ask_hash_hex = "f".repeat(64);

        verify(&device, &payload).expect_err("the displayed ask hash is signed");
    }

    #[test]
    fn every_failure_is_the_same_opaque_error() {
        let signing_key = signing_key();
        let mut bad_key = device_for(&signing_key);
        bad_key.public_key_b64 = "not base64".into();
        let mut bad_signature = signed_decision(&signing_key);
        bad_signature.signature_b64 = "not base64".into();

        let key_error = verify(&bad_key, &signed_decision(&signing_key)).unwrap_err();
        let signature_error = verify(&device_for(&signing_key), &bad_signature).unwrap_err();

        assert_eq!(key_error.to_string(), signature_error.to_string());
    }
}
