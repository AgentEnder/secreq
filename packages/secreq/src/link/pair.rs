//! Short-lived, single-use enrollment for linked approval devices.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use p256::ecdsa::VerifyingKey;
use rand::RngCore;
use serde::Deserialize;
use ssh_encoding::base64::{Base64, Encoding};
use subtle::ConstantTimeEq;

use super::devices::Device;

/// How long an in-person enrollment token remains valid.
pub const ENROLLMENT_TTL: Duration = Duration::from_secs(60);

const MAX_FAILED_TOKEN_ATTEMPTS: u8 = 5;
const MAX_NICKNAME_CHARS: usize = 64;

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
    failed_token_attempts: u8,
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
    #[error("too many invalid enrollment tokens; run `secreq link` to open another window")]
    TooManyTokenAttempts,
    #[error("the public key is not a valid uncompressed P-256 key")]
    InvalidPublicKey,
    #[error("a device nickname cannot be empty")]
    EmptyNickname,
    #[error("a device nickname cannot exceed 64 characters")]
    NicknameTooLong,
    #[error("a device nickname cannot contain a control character")]
    NicknameControlCharacter,
    #[error("a device named `{nickname}` is already paired; choose another nickname")]
    NicknameCollision { nickname: String },
    #[error("that public key is already paired as `{nickname}`; one key cannot name two devices")]
    PublicKeyCollision { nickname: String },
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
            failed_token_attempts: 0,
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
        let Some(open) = window.as_mut() else {
            return Err(PairError::NoOpenWindow);
        };
        if now >= open.expires_at {
            *window = None;
            return Err(PairError::Expired);
        }
        if !token_matches(&open.token, &request.token) {
            open.failed_token_attempts = open.failed_token_attempts.saturating_add(1);
            if open.failed_token_attempts >= MAX_FAILED_TOKEN_ATTEMPTS {
                *window = None;
                return Err(PairError::TooManyTokenAttempts);
            }
            return Err(PairError::InvalidToken);
        }
        let nickname = normalize_nickname(&request.nickname)?;
        let public_key = validate_public_key(&request.public_key_b64)?;
        let public_key_b64 = Base64::encode_string(&public_key);

        let mut devices = super::devices::load(&self.registry_path).map_err(PairError::Registry)?;
        if devices.iter().any(|device| device.nickname == nickname) {
            return Err(PairError::NicknameCollision { nickname });
        }
        if let Some(existing) = devices.iter().find(|device| {
            Base64::decode_vec(&device.public_key_b64)
                .is_ok_and(|existing_key| existing_key == public_key)
        }) {
            return Err(PairError::PublicKeyCollision {
                nickname: existing.nickname.clone(),
            });
        }

        let device = Device {
            nickname,
            public_key_b64,
            enrolled_at,
            last_seen: None,
        };
        devices.push(device.clone());
        super::devices::save(&self.registry_path, &devices).map_err(PairError::Registry)?;
        *window = None;
        Ok(device)
    }
}

fn token_matches(expected: &str, candidate: &str) -> bool {
    bool::from(expected.as_bytes().ct_eq(candidate.as_bytes()))
}

fn normalize_nickname(raw: &str) -> Result<String, PairError> {
    if raw.chars().any(char::is_control) {
        return Err(PairError::NicknameControlCharacter);
    }
    let nickname = raw.trim();
    if nickname.is_empty() {
        return Err(PairError::EmptyNickname);
    }
    if nickname.chars().count() > MAX_NICKNAME_CHARS {
        return Err(PairError::NicknameTooLong);
    }
    Ok(nickname.to_owned())
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

fn validate_public_key(public_key_b64: &str) -> Result<Vec<u8>, PairError> {
    let bytes = Base64::decode_vec(public_key_b64).map_err(|_| PairError::InvalidPublicKey)?;
    if bytes.len() != 65 || bytes.first() != Some(&0x04) {
        return Err(PairError::InvalidPublicKey);
    }
    VerifyingKey::from_sec1_bytes(&bytes).map_err(|_| PairError::InvalidPublicKey)?;
    Ok(bytes)
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
        request_with_key(token, nickname, public_key_b64())
    }

    fn request_with_key(token: &str, nickname: &str, public_key_b64: String) -> PairRequest {
        PairRequest {
            token: token.into(),
            public_key_b64,
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
            .pair_at(
                request("collision", "  Craig's iPhone  "),
                now,
                1_753_000_001,
            )
            .expect_err("duplicate nickname must fail");

        let message = err.to_string();
        assert!(message.contains("Craig's iPhone"), "{message}");
        assert!(message.contains("already paired"), "{message}");
        assert_eq!(devices::load(&path).unwrap().len(), 1);
    }

    #[test]
    fn a_nickname_is_trimmed_once_before_it_is_stored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("devices.json");
        let pairing = Pairing::new(&path);
        let now = Instant::now();
        pairing.open_at("trimmed".into(), now).unwrap();

        pairing
            .pair_at(request("trimmed", "  Craig's iPhone  "), now, 1_753_000_000)
            .expect("trimmed nickname pairs");

        assert_eq!(devices::load(&path).unwrap()[0].nickname, "Craig's iPhone");
    }

    #[test]
    fn nicknames_reject_terminal_controls_and_overlong_input() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("devices.json");
        let pairing = Pairing::new(&path);
        let now = Instant::now();
        pairing.open_at("nickname".into(), now).unwrap();

        for nickname in ["phone\nforged row".to_owned(), "phone\u{1b}[31m".to_owned()] {
            let err = pairing
                .pair_at(request("nickname", &nickname), now, 1_753_000_000)
                .expect_err("terminal controls must be refused");
            assert!(err.to_string().contains("control character"), "{err}");
        }
        let err = pairing
            .pair_at(request("nickname", "   "), now, 1_753_000_000)
            .expect_err("a nickname empty after trimming must fail");
        assert!(matches!(err, PairError::EmptyNickname));
        let err = pairing
            .pair_at(request("nickname", &"a".repeat(65)), now, 1_753_000_000)
            .expect_err("nicknames are capped at 64 characters");
        assert!(err.to_string().contains("64"), "{err}");
        assert!(devices::load(&path).unwrap().is_empty());
    }

    #[test]
    fn five_bad_token_guesses_close_the_window() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("devices.json");
        let pairing = Pairing::new(&path);
        let now = Instant::now();
        pairing.open_at("right-token".into(), now).unwrap();

        for attempt in 1..=5 {
            let err = pairing
                .pair_at(request("wrong-token", "phone"), now, 1_753_000_000)
                .expect_err("a wrong token must fail");
            if attempt == 5 {
                assert!(err.to_string().contains("too many"), "{err}");
            } else {
                assert!(matches!(err, PairError::InvalidToken));
            }
        }
        let err = pairing
            .pair_at(request("right-token", "phone"), now, 1_753_000_000)
            .expect_err("the locked window must be closed");

        assert!(matches!(err, PairError::NoOpenWindow));
        assert!(devices::load(&path).unwrap().is_empty());
    }

    #[test]
    fn four_bad_token_guesses_still_allow_the_in_person_token() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("devices.json");
        let pairing = Pairing::new(&path);
        let now = Instant::now();
        pairing.open_at("right-token".into(), now).unwrap();

        for _ in 0..4 {
            pairing
                .pair_at(request("wrong-token", "phone"), now, 1_753_000_000)
                .expect_err("a wrong token must fail");
        }
        pairing
            .pair_at(request("right-token", "phone"), now, 1_753_000_000)
            .expect("the fifth attempt may use the real token");

        assert_eq!(devices::load(&path).unwrap().len(), 1);
    }

    #[test]
    fn one_public_key_cannot_claim_a_second_nickname() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("devices.json");
        let key = public_key_b64();
        devices::save(
            &path,
            &[Device {
                nickname: "phone".into(),
                public_key_b64: key.clone(),
                enrolled_at: 1_753_000_000,
                last_seen: None,
            }],
        )
        .unwrap();
        let pairing = Pairing::new(&path);
        let now = Instant::now();
        pairing.open_at("same-key".into(), now).unwrap();

        let err = pairing
            .pair_at(
                request_with_key("same-key", "tablet", key),
                now,
                1_753_000_001,
            )
            .expect_err("one key must have one audit identity");

        assert!(err.to_string().contains("phone"), "{err}");
        assert!(err.to_string().contains("public key"), "{err}");
        assert_eq!(devices::load(&path).unwrap().len(), 1);
    }
}
