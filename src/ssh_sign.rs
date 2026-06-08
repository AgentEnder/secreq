//! In-process SSH signing. The private key arrives as an OpenSSH PEM
//! string resolved from a provider; we sign the agent's challenge and
//! return the wire-encoded signature blob (SSH `string algorithm` +
//! `string blob`, i.e. the body of an `SSH_AGENT_SIGN_RESPONSE`). This is
//! the SSH *agent/protocol* signature, NOT the namespaced `ssh-keygen -Y`
//! `SshSig` format.
//!
//! The PEM is owned and zeroized by the caller after we return; `sign`
//! does not copy or log key material.

use anyhow::{bail, Context, Result};
use rsa::signature::Signer;
use ssh_encoding::Encode;
use ssh_key::private::KeypairData;
use ssh_key::{Algorithm, HashAlg, PrivateKey, Signature};

/// `SSH_AGENT_RSA_SHA2_256` SIGN_REQUEST flag (PROTOCOL.agent): request an
/// `rsa-sha2-256` signature instead of the legacy `ssh-rsa` (SHA-1).
pub const SSH_AGENT_RSA_SHA2_256: u32 = 0x02;
/// `SSH_AGENT_RSA_SHA2_512` SIGN_REQUEST flag (PROTOCOL.agent): request an
/// `rsa-sha2-512` signature.
pub const SSH_AGENT_RSA_SHA2_512: u32 = 0x04;

/// Sign `data` with the OpenSSH private key in `private_key_pem`, honoring
/// the RSA SHA2 SIGN_REQUEST `flags`. Returns the SSH wire encoding of the
/// signature (`string algorithm` + `string blob`) suitable for an
/// `SSH_AGENT_SIGN_RESPONSE`.
///
/// For ed25519 and ecdsa keys the RSA flags are ignored. For RSA keys the
/// flags select the hash: `SSH_AGENT_RSA_SHA2_512` -> `rsa-sha2-512`,
/// otherwise `rsa-sha2-256` (we never emit the deprecated SHA-1 `ssh-rsa`).
pub fn sign(private_key_pem: &str, data: &[u8], flags: u32) -> Result<Vec<u8>> {
    let key = PrivateKey::from_openssh(private_key_pem)
        .context("parsing the resolved private key (is the field an OpenSSH private key?)")?;

    let signature = match key.key_data() {
        KeypairData::Rsa(keypair) => {
            let hash = rsa_hash_from_flags(flags);
            sign_rsa(keypair, data, hash).context("signing challenge with RSA key")?
        }
        _ => Signer::try_sign(&key, data).context("signing challenge")?,
    };

    let mut blob = Vec::new();
    signature
        .encode(&mut blob)
        .context("encoding signature to SSH wire format")?;
    Ok(blob)
}

/// Map the SIGN_REQUEST flags to an RSA hash algorithm. `ssh` always sets
/// one of the SHA2 flags for RSA keys; if neither is set we default to
/// SHA-256 rather than the deprecated SHA-1 `ssh-rsa`.
fn rsa_hash_from_flags(flags: u32) -> HashAlg {
    if flags & SSH_AGENT_RSA_SHA2_512 != 0 {
        HashAlg::Sha512
    } else {
        HashAlg::Sha256
    }
}

/// Sign with an RSA keypair at a specific hash. ssh-key 0.6's public
/// `Signer` impl for RSA hardcodes SHA-512, so we drop to the
/// `rsa::pkcs1v15` path to honor the requested hash. We also rebuild the
/// `rsa::RsaPrivateKey` ourselves rather than via ssh-key's
/// `TryFrom<&RsaKeypair>`: that conversion in 0.6.7 passes the prime `p`
/// twice instead of `(p, q)` to `from_components`, so the consistency
/// check fails and *all* RSA signing through ssh-key errors. Reconstructing
/// from the correct `(n, e, d, p, q)` components sidesteps the bug.
fn sign_rsa(
    keypair: &ssh_key::private::RsaKeypair,
    data: &[u8],
    hash: HashAlg,
) -> Result<Signature> {
    use rsa::pkcs1v15::SigningKey;
    use rsa::sha2::{Sha256, Sha512};
    use rsa::signature::{SignatureEncoding, Signer};

    let private = rsa_private_key_from(keypair)?;

    let (algorithm, raw) = match hash {
        HashAlg::Sha256 => {
            let signing_key = SigningKey::<Sha256>::new(private);
            let sig = Signer::try_sign(&signing_key, data)
                .map_err(|e| anyhow::anyhow!("RSA SHA-256 sign: {e}"))?;
            (
                Algorithm::Rsa {
                    hash: Some(HashAlg::Sha256),
                },
                sig.to_vec(),
            )
        }
        HashAlg::Sha512 => {
            let signing_key = SigningKey::<Sha512>::new(private);
            let sig = Signer::try_sign(&signing_key, data)
                .map_err(|e| anyhow::anyhow!("RSA SHA-512 sign: {e}"))?;
            (
                Algorithm::Rsa {
                    hash: Some(HashAlg::Sha512),
                },
                sig.to_vec(),
            )
        }
        other => bail!("unsupported RSA hash algorithm: {other:?}"),
    };

    Signature::new(algorithm, raw).context("assembling RSA signature")
}

/// Reconstruct an `rsa::RsaPrivateKey` from an ssh-key `RsaKeypair`'s
/// public/private components, using the correct primes `(p, q)`. See
/// `sign_rsa` for why ssh-key's own conversion can't be used.
fn rsa_private_key_from(keypair: &ssh_key::private::RsaKeypair) -> Result<rsa::RsaPrivateKey> {
    let n = mpint_to_biguint(&keypair.public.n).context("RSA modulus n")?;
    let e = mpint_to_biguint(&keypair.public.e).context("RSA public exponent e")?;
    let d = mpint_to_biguint(&keypair.private.d).context("RSA private exponent d")?;
    let p = mpint_to_biguint(&keypair.private.p).context("RSA prime p")?;
    let q = mpint_to_biguint(&keypair.private.q).context("RSA prime q")?;

    rsa::RsaPrivateKey::from_components(n, e, d, vec![p, q])
        .context("reconstructing RSA private key from components")
}

/// Convert an ssh-key `Mpint` to an `rsa::BigUint` via its positive
/// big-endian byte representation.
fn mpint_to_biguint(m: &ssh_key::Mpint) -> Result<rsa::BigUint> {
    let bytes = m
        .as_positive_bytes()
        .context("multi-precision integer is not a positive value")?;
    Ok(rsa::BigUint::from_bytes_be(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::signature::Verifier;
    use ssh_key::{Algorithm, EcdsaCurve, LineEnding, PublicKey};

    /// A static 2048-bit RSA private key (OpenSSH format) used by the RSA
    /// signing tests. In debug builds `PrivateKey::random(.., Rsa)` takes
    /// ~30-40s per call, which dominated the entire test suite. The key is a
    /// throwaway generated once with `ssh-keygen -t rsa -b 2048`; embedding it
    /// keeps these tests in the millisecond range. Do NOT switch this back to
    /// `PrivateKey::random` — that reintroduces the slow keygen.
    const RSA_TEST_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEA9ydPEFgcRVKRXdYvGS1+qHliLtDXB798bW5nsvdrtijnep9LvaeD
SeH/2tFPbfYltz2QV2rvzAmC+tOwfH2X6tOvLJtNCHQmqtrzq0D9mPy6cAAcPJIeozHTnB
T2OsLXtChU8t9z0wh1N2d1586slgEO99CrHm+WqMWeguIJitu6MdaQH6R62k5bvUmTDi+/
kxtZBO43Ozy01QvnYqO+o77YigpiKp7JSdmESSfrg4WgExiZ1fF6JXU1GTrZ8VrRZ9WKvB
eYpqFDO3LB/1W4s7vBLNkMHY0VGGqwJC7GLY7Jkx1UdMBJtip+J+fcoqL2euCJsenUYwKL
IXxIXdhlRQAAA8ihJqnSoSap0gAAAAdzc2gtcnNhAAABAQD3J08QWBxFUpFd1i8ZLX6oeW
Iu0NcHv3xtbmey92u2KOd6n0u9p4NJ4f/a0U9t9iW3PZBXau/MCYL607B8fZfq068sm00I
dCaq2vOrQP2Y/LpwABw8kh6jMdOcFPY6wte0KFTy33PTCHU3Z3XnzqyWAQ730Kseb5aoxZ
6C4gmK27ox1pAfpHraTlu9SZMOL7+TG1kE7jc7PLTVC+dio76jvtiKCmIqnslJ2YRJJ+uD
haATGJnV8XoldTUZOtnxWtFn1Yq8F5imoUM7csH/Vbizu8Es2QwdjRUYarAkLsYtjsmTHV
R0wEm2Kn4n59yiovZ64Imx6dRjAoshfEhd2GVFAAAAAwEAAQAAAQEAmhKYODElVpXVZzD5
ZXG2DqK08UhhdEQL9lAoNyoErKctPoUFe3Js5ucLT8bCBGO5OVUYoVZZrNGVJHZJBCJrTQ
mvn1glGosF++bIlk7KiM+sDdwTvjK9BLEwIJH0ucbzHy0xX8Kq+rjAEczedKajclOwmA4u
TqfzvLyNRzxQBI4iE40PYKOOZjzxTaVdfJKZTfGnbtvPP4vBfge4F5LWXHRpz7b9SrScqs
8XYbxK795ZvA1QWAIzb/52pRAcdgsK21/jicvUKs6MDVrATdFIGotVX0Q2dQG6ROmfXfht
yYd+WNj4y+SRY5tGn5FOO2hG4SHGhrGheTGmhICqMez/AQAAAIAxuqjlWYPC3T2ZyV3jmq
XsVSo0nLFgybECb1GNhVTxO6xspKSRebfCGsl4NsrXkXun3ER1ZmtL+gXpQAFvmc81vqNp
WFEXCIY8HO1RCSUd8Rf13sOEYNwLwUz2iwJYHxc8/0pz4rx+HVgG7Dy55Qgi0bt5A0i5gP
J9FPk0XQnCnwAAAIEA/D1RrJQdU7TNYlF/KkmT9duBXXKPU/BtaFfh8xIw3vFtkEiaCllW
N3INDs9gTNp/bgyDJ3/1vkgy5qgFPVJ4N0H3Cmekf6BYqRL3b3UuCdUTmW5vY+tbjbN4cR
J1pcoAEvHB/6gi1QQYXG6pCrKcuoku7ib/4lvmWZ5Mom56dgUAAACBAPrWlDjsCcs357P4
eNyj8wTCR3TPg2yy0FhQd3vMF1O5MVrgp4wI1sgsYSa//jfQeTlZJSZocJMG8p+HLgUzRM
XuvFOkbWVXWXVyJZRq4J7Cw40OVsXYf/jUw8zxFAehxxihH3eu7JaTOaAS0BzOapCG8oHh
UmZO5k6cb+1m7BZBAAAAD3NlY3JlcS1yc2EtdGVzdAECAw==
-----END OPENSSH PRIVATE KEY-----
";

    fn pem_for(algorithm: Algorithm) -> String {
        PrivateKey::random(&mut rand::rngs::OsRng, algorithm)
            .expect("generate test key")
            .to_openssh(LineEnding::LF)
            .expect("encode openssh pem")
            .to_string()
    }

    /// Decode our wire blob back into a `Signature` and verify it against
    /// the public key, mirroring what a remote peer / ssh-keygen does.
    fn verify_blob(public_key: &PublicKey, data: &[u8], blob: &[u8]) -> Signature {
        use ssh_encoding::Decode;
        let mut reader: &[u8] = blob;
        let sig = Signature::decode(&mut reader).expect("decode signature blob");
        // `PublicKey` has an inherent `verify(namespace, msg, &SshSig)` for
        // the ssh-keygen format; we want the `signature::Verifier` impl for
        // the agent-protocol `Signature`, so call the trait method directly.
        Verifier::verify(public_key, data, &sig).expect("signature verifies against public key");
        sig
    }

    #[test]
    fn signs_and_verifies_ed25519() {
        let pem = pem_for(Algorithm::Ed25519);
        let key = PrivateKey::from_openssh(&pem).unwrap();
        let data = b"challenge bytes";
        let blob = sign(&pem, data, 0).unwrap();
        let sig = verify_blob(key.public_key(), data, &blob);
        assert_eq!(sig.algorithm(), Algorithm::Ed25519);
    }

    #[test]
    fn signs_and_verifies_rsa_sha256() {
        let pem = RSA_TEST_KEY;
        let key = PrivateKey::from_openssh(pem).unwrap();
        let data = b"challenge bytes";
        let blob = sign(pem, data, SSH_AGENT_RSA_SHA2_256).unwrap();
        let sig = verify_blob(key.public_key(), data, &blob);
        assert_eq!(
            sig.algorithm(),
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha256)
            }
        );
        assert_eq!(sig.algorithm().as_str(), "rsa-sha2-256");
    }

    #[test]
    fn signs_and_verifies_rsa_sha512() {
        let pem = RSA_TEST_KEY;
        let key = PrivateKey::from_openssh(pem).unwrap();
        let data = b"challenge bytes";
        let blob = sign(pem, data, SSH_AGENT_RSA_SHA2_512).unwrap();
        let sig = verify_blob(key.public_key(), data, &blob);
        assert_eq!(
            sig.algorithm(),
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha512)
            }
        );
        assert_eq!(sig.algorithm().as_str(), "rsa-sha2-512");
    }

    #[test]
    fn signs_and_verifies_ecdsa_p256() {
        let pem = pem_for(Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        });
        let key = PrivateKey::from_openssh(&pem).unwrap();
        let data = b"challenge bytes";
        let blob = sign(&pem, data, 0).unwrap();
        let sig = verify_blob(key.public_key(), data, &blob);
        assert_eq!(
            sig.algorithm(),
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256
            }
        );
    }

    #[test]
    fn rejects_non_openssh_pem() {
        let err = sign("not a key", b"data", 0).unwrap_err();
        assert!(
            err.to_string().contains("resolved private key"),
            "error should mention the resolved private key, got: {err}"
        );
    }
}
