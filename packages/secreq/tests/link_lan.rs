use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::Arc;

use p256::ecdsa::SigningKey;
use serde_json::json;
use ssh_encoding::base64::{Base64, Encoding};

use secreq::link::pair::Pairing;

fn start_listener(registry_path: &std::path::Path) -> (secreq::link::lan::Listener, Arc<Pairing>) {
    let pairing = Arc::new(Pairing::new(registry_path));
    let listener = secreq::link::lan::start(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        Arc::clone(&pairing),
    )
    .expect("start LAN listener");
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
