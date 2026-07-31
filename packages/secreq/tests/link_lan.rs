use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use serde_json::json;
use ssh_encoding::base64::{Base64, Encoding};

use secreq::link::pair::Pairing;
use secreq::link::sig::SignedDecision;

fn start_listener(registry_path: &std::path::Path) -> (secreq::link::lan::Listener, Arc<Pairing>) {
    let pairing = Arc::new(Pairing::new(registry_path));
    let listener = secreq::link::lan::start(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        Arc::clone(&pairing),
    )
    .expect("start LAN listener");
    (listener, pairing)
}

fn start_synced_listener(
    registry_path: &std::path::Path,
    state: secreq::daemon::state::SharedState,
) -> (secreq::link::lan::Listener, Arc<Pairing>) {
    let pairing = Arc::new(Pairing::new(registry_path));
    let listener = secreq::link::lan::start_synced(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        Arc::clone(&pairing),
        state,
    )
    .expect("start synced LAN listener");
    (listener, pairing)
}

fn send(addr: SocketAddr, request: &[u8]) -> String {
    let mut client = TcpStream::connect(addr).expect("connect to LAN listener");
    client.write_all(request).expect("write HTTP request");
    let mut response = String::new();
    client
        .read_to_string(&mut response)
        .expect("read HTTP response");
    response
}

fn post_pair(addr: SocketAddr, body: &serde_json::Value) -> String {
    let body = serde_json::to_vec(body).expect("serialize pair request");
    let request = format!(
        "POST /pair HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut bytes = request.into_bytes();
    bytes.extend_from_slice(&body);
    send(addr, &bytes)
}

fn post_decision(addr: SocketAddr, payload: &SignedDecision) -> String {
    let body = serde_json::to_vec(payload).expect("serialize decision request");
    let request = format!(
        "POST /decision HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut bytes = request.into_bytes();
    bytes.extend_from_slice(&body);
    send(addr, &bytes)
}

fn signing_bytes(payload: &SignedDecision) -> Vec<u8> {
    let mut bytes = Vec::new();
    for part in [
        payload.request_id.as_str(),
        payload.ask_hash_hex.as_str(),
        payload.decision.as_str(),
        payload.nonce.as_str(),
    ] {
        bytes.extend_from_slice(&(part.len() as u32).to_be_bytes());
        bytes.extend_from_slice(part.as_bytes());
    }
    bytes
}

fn signed_decision(
    signing_key: &SigningKey,
    request_id: &str,
    ask_hash_hex: &str,
    decision: &str,
    nonce: &str,
) -> SignedDecision {
    let mut payload = SignedDecision {
        request_id: request_id.to_owned(),
        ask_hash_hex: ask_hash_hex.to_owned(),
        decision: decision.to_owned(),
        nonce: nonce.to_owned(),
        signature_b64: String::new(),
    };
    let signature: Signature = signing_key.sign(&signing_bytes(&payload));
    payload.signature_b64 = Base64::encode_string(&signature.to_bytes());
    payload
}

fn device(signing_key: &SigningKey, nickname: &str) -> secreq::link::devices::Device {
    secreq::link::devices::Device {
        nickname: nickname.to_owned(),
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

fn queued_ask() -> secreq::daemon::proto::Ask {
    use secreq::daemon::proto::{
        Ask, AskAnchor, AskSubject, DedupeKey, SecretAsk, WireProvider, WrapSubject,
    };
    use secreq::provenance::ProcessIdentity;

    Ask {
        command: vec!["deploy".to_owned(), "--production".to_owned()],
        dedupe_key: DedupeKey {
            wrap: "deploy".to_owned(),
            anchor: AskAnchor::Process(ProcessIdentity {
                pid: 42,
                start_time: 1_753_000_000,
            }),
            subject_digest: None,
        },
        subject: AskSubject::Wrap(WrapSubject {
            cwd: "/srv/app".to_owned(),
            callers: Vec::new(),
            callers_truncated: false,
            secrets: vec![SecretAsk {
                name: "DEPLOY_TOKEN".to_owned(),
                provider: "fake".to_owned(),
                locator: "production".to_owned(),
                default: None,
                description: None,
                reason: Some("publish the release".to_owned()),
                requested_by: Vec::new(),
                declared_as: None,
                ttl: Default::default(),
            }],
            providers: [(
                "fake".to_owned(),
                WireProvider {
                    name: "fake".to_owned(),
                    retrieve: vec![
                        "sh".to_owned(),
                        "-c".to_owned(),
                        "echo resolved-{locator}".to_owned(),
                    ],
                    retrieve_batch: None,
                },
            )]
            .into_iter()
            .collect(),
            allow_remember: true,
            nested_run: false,
            ignore_remembered: false,
        }),
    }
}

fn queued_state() -> (
    secreq::daemon::state::SharedState,
    mpsc::Receiver<secreq::daemon::state::WaiterReply>,
    String,
    String,
) {
    let state = Arc::new(Mutex::new(secreq::daemon::state::State::new()));
    let (tx, rx) = mpsc::channel();
    state
        .lock()
        .expect("state mutex")
        .submit_ask(queued_ask(), tx);
    let snapshot = state.lock().expect("state mutex").snapshot_for_wire();
    let row = snapshot.queue.first().expect("queued row");
    (state, rx, row.request_id.clone(), row.ask_hash_hex.clone())
}

#[test]
fn listener_serves_healthz_on_an_ephemeral_port() {
    let dir = tempfile::tempdir().unwrap();
    let (listener, _pairing) = start_listener(&dir.path().join("devices.json"));
    let response = send(
        listener.local_addr(),
        b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );

    assert!(
        response.starts_with("HTTP/1.1 200 "),
        "unexpected response: {response:?}"
    );
}

#[test]
fn post_pair_enrolls_a_valid_p256_key_and_returns_no_content() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("devices.json");
    let (listener, pairing) = start_listener(&path);
    let token = pairing.open().expect("open enrollment window");
    let key = SigningKey::random(&mut rand::thread_rng());
    let public_key_b64 =
        Base64::encode_string(key.verifying_key().to_encoded_point(false).as_bytes());

    let response = post_pair(
        listener.local_addr(),
        &json!({
            "token": token,
            "public_key_b64": public_key_b64,
            "nickname": "Craig's iPhone"
        }),
    );

    assert!(
        response.starts_with("HTTP/1.1 204 "),
        "unexpected response: {response:?}"
    );
    let devices = secreq::link::devices::load(&path).expect("load registry");
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].nickname, "Craig's iPhone");
}

#[test]
fn a_malformed_public_key_never_reaches_disk() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("devices.json");
    let (listener, pairing) = start_listener(&path);
    let token = pairing.open().expect("open enrollment window");

    let response = post_pair(
        listener.local_addr(),
        &json!({
            "token": token,
            "public_key_b64": "not base64",
            "nickname": "Mallory's phone"
        }),
    );

    assert!(
        response.starts_with("HTTP/1.1 400 "),
        "unexpected response: {response:?}"
    );
    assert!(
        secreq::link::devices::load(&path)
            .expect("load registry")
            .is_empty(),
        "an invalid key must not be persisted"
    );
}

#[test]
fn post_pair_without_an_open_window_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("devices.json");
    let (listener, _pairing) = start_listener(&path);

    let response = post_pair(
        listener.local_addr(),
        &json!({
            "token": "not-open",
            "public_key_b64": "not relevant",
            "nickname": "phone"
        }),
    );

    assert!(
        response.starts_with("HTTP/1.1 403 "),
        "unexpected response: {response:?}"
    );
    assert!(secreq::link::devices::load(&path).unwrap().is_empty());
}

#[test]
fn a_valid_signed_approval_resolves_the_live_ask_and_names_the_device() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("devices.json");
    let signing_key = SigningKey::random(&mut rand::thread_rng());
    secreq::link::devices::save(&path, &[device(&signing_key, "Craig's iPhone")]).unwrap();
    let (state, rx, request_id, ask_hash) = queued_state();
    let (listener, _pairing) = start_synced_listener(&path, state);
    let payload = signed_decision(
        &signing_key,
        &request_id,
        &ask_hash,
        "approve",
        "fresh-nonce",
    );

    let response = post_decision(listener.local_addr(), &payload);
    assert!(response.starts_with("HTTP/1.1 204 "), "{response:?}");
    match rx
        .recv_timeout(Duration::from_secs(2))
        .expect("resolved reply")
    {
        secreq::daemon::state::WaiterReply::Decision {
            decision,
            secrets,
            deciding_device,
            ..
        } => {
            assert!(decision.approved());
            assert_eq!(
                secrets.get("DEPLOY_TOKEN").map(String::as_str),
                Some("resolved-production")
            );
            assert_eq!(deciding_device.as_deref(), Some("Craig's iPhone"));
        }
        other => panic!("expected resolved decision, got {other:?}"),
    }
}

#[test]
fn an_unenrolled_signer_is_refused_and_the_ask_stays_pending() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("devices.json");
    let enrolled = SigningKey::random(&mut rand::thread_rng());
    let stranger = SigningKey::random(&mut rand::thread_rng());
    secreq::link::devices::save(&path, &[device(&enrolled, "phone")]).unwrap();
    let (state, _rx, request_id, ask_hash) = queued_state();
    let (listener, _pairing) = start_synced_listener(&path, Arc::clone(&state));

    let response = post_decision(
        listener.local_addr(),
        &signed_decision(&stranger, &request_id, &ask_hash, "deny", "nonce"),
    );

    assert!(response.starts_with("HTTP/1.1 403 "), "{response:?}");
    assert_eq!(state.lock().unwrap().snapshot().entries.len(), 1);
}

#[test]
fn a_burned_nonce_cannot_be_replayed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("devices.json");
    let key = SigningKey::random(&mut rand::thread_rng());
    secreq::link::devices::save(&path, &[device(&key, "phone")]).unwrap();
    let (state, _rx, request_id, ask_hash) = queued_state();
    let (listener, _pairing) = start_synced_listener(&path, Arc::clone(&state));

    let stale = signed_decision(&key, &request_id, &"0".repeat(64), "deny", "same");
    let first = post_decision(listener.local_addr(), &stale);
    assert!(first.starts_with("HTTP/1.1 409 "), "{first:?}");
    let replay = signed_decision(&key, &request_id, &ask_hash, "deny", "same");
    let second = post_decision(listener.local_addr(), &replay);
    assert!(second.starts_with("HTTP/1.1 409 "), "{second:?}");
    assert_eq!(state.lock().unwrap().snapshot().entries.len(), 1);
}

#[test]
fn a_stale_ask_hash_is_refused_without_resolving() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("devices.json");
    let key = SigningKey::random(&mut rand::thread_rng());
    secreq::link::devices::save(&path, &[device(&key, "phone")]).unwrap();
    let (state, _rx, request_id, _ask_hash) = queued_state();
    let (listener, _pairing) = start_synced_listener(&path, Arc::clone(&state));
    let stale = signed_decision(&key, &request_id, &"f".repeat(64), "approve", "nonce");

    let response = post_decision(listener.local_addr(), &stale);

    assert!(response.starts_with("HTTP/1.1 409 "), "{response:?}");
    assert_eq!(state.lock().unwrap().snapshot().entries.len(), 1);
}

#[test]
fn a_revoked_devices_already_signed_decision_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("devices.json");
    let key = SigningKey::random(&mut rand::thread_rng());
    secreq::link::devices::save(&path, &[device(&key, "lost phone")]).unwrap();
    let (state, _rx, request_id, ask_hash) = queued_state();
    let payload = signed_decision(&key, &request_id, &ask_hash, "approve", "in-flight");
    secreq::link::devices::save(&path, &[]).unwrap();
    let (listener, _pairing) = start_synced_listener(&path, Arc::clone(&state));

    let response = post_decision(listener.local_addr(), &payload);

    assert!(response.starts_with("HTTP/1.1 403 "), "{response:?}");
    assert_eq!(state.lock().unwrap().snapshot().entries.len(), 1);
}

#[test]
fn events_streams_a_snapshot_and_drops_the_subscriber_after_disconnect() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("devices.json");
    let (state, _rx, request_id, _ask_hash) = queued_state();
    let (listener, _pairing) = start_synced_listener(&path, Arc::clone(&state));
    let mut client = TcpStream::connect(listener.local_addr()).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    client
        .write_all(b"GET /events HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();

    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 4096];
    for _ in 0..8 {
        let count = client.read(&mut chunk).expect("initial SSE response");
        bytes.extend_from_slice(&chunk[..count]);
        if String::from_utf8_lossy(&bytes).contains(&request_id) {
            break;
        }
    }
    let response = String::from_utf8_lossy(&bytes);
    assert!(response.starts_with("HTTP/1.1 200 "), "{response:?}");
    assert!(response.contains("text/event-stream"), "{response:?}");
    assert!(response.contains(&request_id), "{response:?}");
    assert!(!response.contains("resolving_since"), "{response:?}");
    assert_eq!(state.lock().unwrap().link_subscriber_count(), 1);

    drop(client);
    state.lock().unwrap().show_window();
    for _ in 0..50 {
        if state.lock().unwrap().link_subscriber_count() == 0 {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("dropped SSE connection remained subscribed after a write");
}
