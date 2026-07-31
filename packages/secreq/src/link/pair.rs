//! Short-lived, single-use enrollment for linked approval devices.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use p256::ecdsa::VerifyingKey;
use rand::RngCore;
use serde::Deserialize;
use ssh_encoding::base64::{Base64, Encoding};

use super::devices::Device;

/// How long an in-person enrollment token remains valid.
pub const ENROLLMENT_TTL: Duration = Duration::from_secs(60);

/// The JSON body accepted by `POST /pair`.
#[derive(Debug, Deserialize)]
pub struct PairRequest {
    pub token: String,
    pub public_key_b64: String,
    pub nickname: String,
}

/// Pairing state shared by the CLI and LAN request handlers.
pub struct Pairing {
    registry_path: PathBuf,
    window: Mutex<Option<Window>>,
}

struct Window {
    token: String,
    expires_at: Instant,
}

/// A pairing request that is safe to report to the enrolling user.
#[derive(Debug, thiserror::Error)]
pub enum PairError {
    #[error("no enrollment window is open; run `secreq link` to open one")]
    NoOpenWindow,
    #[error("the enrollment window expired; run `secreq link` to open another")]
    Expired,
    #[error("the enrollment token is not valid")]
    InvalidToken,
    #[error("the public key is not a valid uncompressed P-256 key")]
    InvalidPublicKey,
    #[error("a device nickname cannot be empty")]
    EmptyNickname,
    #[error("a device named `{nickname}` is already paired; choose another nickname")]
    NicknameCollision { nickname: String },
    #[error("pairing state is unavailable")]
    Unavailable,
    #[error("read the system clock")]
    Clock(#[source] std::time::SystemTimeError),
    #[error("update paired-device registry")]
    Registry(#[source] anyhow::Error),
}

impl Pairing {
    /// Create pairing state backed by the device registry at `registry_path`.
    pub fn new(registry_path: impl Into<PathBuf>) -> Self {
        Self {
            registry_path: registry_path.into(),
            window: Mutex::new(None),
        }
    }

    pub(crate) fn registry_path(&self) -> &std::path::Path {
        &self.registry_path
    }

    /// Open a fresh 60-second enrollment window and return its one-time token.
    pub fn open(&self) -> Result<String, PairError> {
        let token = mint_token();
        self.open_at(token.clone(), Instant::now())?;
        Ok(token)
    }

    /// Validate and persist one device, consuming the enrollment token.
    pub fn pair(&self, request: PairRequest) -> Result<Device, PairError> {
        let enrolled_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(PairError::Clock)?
            .as_secs();
        self.pair_at(request, Instant::now(), enrolled_at)
    }

    fn open_at(&self, token: String, now: Instant) -> Result<(), PairError> {
        *self.window.lock().map_err(|_| PairError::Unavailable)? = Some(Window {
            token,
            expires_at: now + ENROLLMENT_TTL,
        });
        Ok(())
    }

    fn pair_at(
        &self,
        request: PairRequest,
        now: Instant,
        enrolled_at: u64,
    ) -> Result<Device, PairError> {
        let mut window = self.window.lock().map_err(|_| PairError::Unavailable)?;
        let Some(open) = window.as_ref() else {
            return Err(PairError::NoOpenWindow);
        };
        if now >= open.expires_at {
            *window = None;
            return Err(PairError::Expired);
        }
        if request.token != open.token {
            return Err(PairError::InvalidToken);
        }
        if request.nickname.trim().is_empty() {
            return Err(PairError::EmptyNickname);
        }
        validate_public_key(&request.public_key_b64)?;

        let mut devices = super::devices::load(&self.registry_path).map_err(PairError::Registry)?;
        if devices
            .iter()
            .any(|device| device.nickname == request.nickname)
        {
            return Err(PairError::NicknameCollision {
                nickname: request.nickname,
            });
        }

        let device = Device {
            nickname: request.nickname,
            public_key_b64: request.public_key_b64,
            enrolled_at,
            last_seen: None,
        };
        devices.push(device.clone());
        super::devices::save(&self.registry_path, &devices).map_err(PairError::Registry)?;
        *window = None;
        Ok(device)
    }
}

fn mint_token() -> String {
    use std::fmt::Write as _;

    let mut bytes = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let mut token = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut token, "{byte:02x}").expect("writing to a String cannot fail");
    }
    token
}

fn validate_public_key(public_key_b64: &str) -> Result<(), PairError> {
    let bytes = Base64::decode_vec(public_key_b64).map_err(|_| PairError::InvalidPublicKey)?;
    if bytes.len() != 65 || bytes.first() != Some(&0x04) {
        return Err(PairError::InvalidPublicKey);
    }
    VerifyingKey::from_sec1_bytes(&bytes)
        .map(|_| ())
        .map_err(|_| PairError::InvalidPublicKey)
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::SigningKey;
    use ssh_encoding::base64::{Base64, Encoding};

    use super::*;
    use crate::link::devices;

    fn public_key_b64() -> String {
        let key = SigningKey::random(&mut rand::thread_rng());
        Base64::encode_string(key.verifying_key().to_encoded_point(false).as_bytes())
    }

    fn request(token: &str, nickname: &str) -> PairRequest {
        PairRequest {
            token: token.into(),
            public_key_b64: public_key_b64(),
            nickname: nickname.into(),
        }
    }

    #[test]
    fn a_token_pairs_once_and_is_then_dead() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("devices.json");
        let pairing = Pairing::new(&path);
        let now = Instant::now();
        pairing.open_at("one-use".into(), now).unwrap();

        pairing
            .pair_at(request("one-use", "phone"), now, 1_753_000_000)
            .expect("first use pairs");
        let err = pairing
            .pair_at(request("one-use", "tablet"), now, 1_753_000_001)
            .expect_err("second use must fail");

        assert!(matches!(err, PairError::NoOpenWindow));
        assert_eq!(devices::load(&path).unwrap().len(), 1);
    }

    #[test]
    fn a_token_past_its_ttl_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("devices.json");
        let pairing = Pairing::new(&path);
        let opened_at = Instant::now();
        pairing.open_at("too-old".into(), opened_at).unwrap();

        let err = pairing
            .pair_at(
                request("too-old", "phone"),
                opened_at + ENROLLMENT_TTL,
                1_753_000_000,
            )
            .expect_err("expired token must fail");

        assert!(matches!(err, PairError::Expired));
        assert!(devices::load(&path).unwrap().is_empty());
    }

    #[test]
    fn pairing_with_no_open_window_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("devices.json");
        let pairing = Pairing::new(&path);

        let err = pairing
            .pair_at(request("not-open", "phone"), Instant::now(), 1_753_000_000)
            .expect_err("pairing requires an open window");

        assert!(matches!(err, PairError::NoOpenWindow));
        assert!(devices::load(&path).unwrap().is_empty());
    }

    #[test]
    fn a_nickname_collision_has_a_usable_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("devices.json");
        devices::save(
            &path,
            &[Device {
                nickname: "Craig's iPhone".into(),
                public_key_b64: public_key_b64(),
                enrolled_at: 1_753_000_000,
                last_seen: None,
            }],
        )
        .unwrap();
        let pairing = Pairing::new(&path);
        let now = Instant::now();
        pairing.open_at("collision".into(), now).unwrap();

        let err = pairing
            .pair_at(request("collision", "Craig's iPhone"), now, 1_753_000_001)
            .expect_err("duplicate nickname must fail");

        let message = err.to_string();
        assert!(message.contains("Craig's iPhone"), "{message}");
        assert!(message.contains("already paired"), "{message}");
        assert_eq!(devices::load(&path).unwrap().len(), 1);
    }
}
