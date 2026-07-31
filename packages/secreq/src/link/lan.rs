//! Plain-HTTP listener for devices linked over the local network.

use std::io::{Cursor, Read};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{mpsc, Arc};
use std::thread::{self, JoinHandle};

use anyhow::{bail, Context, Result};
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

use super::nonce::NonceStore;
use super::pair::{PairError, PairRequest, Pairing};
use super::sig::SignedDecision;

const MAX_PAIR_BODY_BYTES: u64 = 16 * 1024;
const MAX_DECISION_BODY_BYTES: u64 = 16 * 1024;
const SSE_CHUNK_FLUSH_BYTES: usize = 8 * 1024 + 1;

struct Runtime {
    pairing: Arc<Pairing>,
    state: Option<crate::daemon::state::SharedState>,
    registry_path: PathBuf,
    nonces: Arc<NonceStore>,
}

/// Returns whether an address is local to the host or its private LAN.
///
/// IPv4 RFC 1918 and IPv6 unique-local addresses are accepted, as are
/// loopback addresses used by host-local probes. IPv4-mapped IPv6 addresses
/// are classified by their embedded IPv4 address. In particular,
/// `100.64.0.0/10` is refused: carrier-grade NAT is shared address space, not a
/// private household network.
///
/// **This guard is a backstop, not the control.** The linked device's
/// signature is the security control. Callers must not treat a source address
/// accepted here as authenticated or grant it approval authority.
pub fn is_lan(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_loopback(),
        IpAddr::V6(ip) => {
            ip.to_ipv4_mapped()
                .is_some_and(|ip| ip.is_private() || ip.is_loopback())
                || ip.is_unique_local()
                || ip.is_loopback()
        }
    }
}

/// A running LAN HTTP listener.
///
/// Dropping the handle stops its accept loop and releases the bound socket.
pub struct Listener {
    server: Arc<Server>,
    accept_thread: Option<JoinHandle<()>>,
    local_addr: SocketAddr,
}

impl Listener {
    /// The interface and port selected by the operating system.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.server.unblock();
        if let Some(accept_thread) = self.accept_thread.take() {
            let _ = accept_thread.join();
        }
    }
}

/// Bind an HTTP listener to a private LAN interface and start serving it.
///
/// A port of zero asks the operating system to choose an unused port. Each
/// parsed HTTP request is handled on its own thread, matching the daemon's
/// existing thread-per-connection model.
pub fn start(bind_addr: SocketAddr, pairing: Arc<Pairing>) -> Result<Listener> {
    let registry_path = pairing.registry_path().to_owned();
    start_runtime(
        bind_addr,
        Arc::new(Runtime {
            pairing,
            state: None,
            registry_path,
            nonces: Arc::new(NonceStore::default()),
        }),
    )
}

/// Start the listener with live daemon state, enabling `/events` and
/// `/decision` in addition to pairing.
pub fn start_synced(
    bind_addr: SocketAddr,
    pairing: Arc<Pairing>,
    state: crate::daemon::state::SharedState,
) -> Result<Listener> {
    let registry_path = pairing.registry_path().to_owned();
    start_runtime(
        bind_addr,
        Arc::new(Runtime {
            pairing,
            state: Some(state),
            registry_path,
            nonces: Arc::new(NonceStore::default()),
        }),
    )
}

fn start_runtime(bind_addr: SocketAddr, runtime: Arc<Runtime>) -> Result<Listener> {
    if !is_lan(&bind_addr.ip()) {
        bail!("refuse to bind LAN listener to non-LAN address {bind_addr}");
    }

    let server = Server::http(bind_addr)
        .map_err(|err| anyhow::anyhow!("bind LAN listener at {bind_addr}: {err}"))?;
    let local_addr = server
        .server_addr()
        .to_ip()
        .context("LAN listener did not bind a TCP address")?;
    let server = Arc::new(server);
    let accept_server = Arc::clone(&server);
    let accept_thread = thread::Builder::new()
        .name("secreqd-link-accept".to_owned())
        .spawn(move || accept_loop(accept_server, runtime))
        .context("spawn LAN listener accept thread")?;

    Ok(Listener {
        server,
        accept_thread: Some(accept_thread),
        local_addr,
    })
}

fn accept_loop(server: Arc<Server>, runtime: Arc<Runtime>) {
    for request in server.incoming_requests() {
        let runtime = Arc::clone(&runtime);
        thread::Builder::new()
            .name("secreqd-link-conn".to_owned())
            .spawn(move || {
                if let Err(err) = handle_request(request, &runtime) {
                    eprintln!("secreqd: link connection error: {err}");
                }
            })
            .ok();
    }
}

fn handle_request(request: Request, runtime: &Runtime) -> std::io::Result<()> {
    if !request.remote_addr().is_some_and(|addr| is_lan(&addr.ip())) {
        return request.respond(Response::empty(StatusCode(403)));
    }

    if request.method() == &Method::Get && request.url() == "/healthz" {
        return request.respond(Response::empty(StatusCode(200)));
    }
    if request.method() == &Method::Post && request.url() == "/pair" {
        return handle_pair(request, &runtime.pairing);
    }
    if request.method() == &Method::Get && request.url() == "/events" {
        return match &runtime.state {
            Some(state) => handle_events(request, Arc::clone(state)),
            None => request.respond(Response::empty(StatusCode(404))),
        };
    }
    if request.method() == &Method::Post && request.url() == "/decision" {
        return match &runtime.state {
            Some(state) => handle_decision(request, runtime, state),
            None => request.respond(Response::empty(StatusCode(404))),
        };
    }

    request.respond(Response::empty(StatusCode(404)))
}

fn handle_events(
    request: Request,
    state: crate::daemon::state::SharedState,
) -> std::io::Result<()> {
    let (tx, rx) = mpsc::channel();
    let (subscriber_id, initial) = state
        .lock()
        .map_err(|_| std::io::Error::other("daemon state unavailable"))?
        .attach_link_events(tx);
    let reader = SseReader::new(state, subscriber_id, rx, initial)?;
    let headers = vec![
        Header::from_bytes("Content-Type", "text/event-stream; charset=utf-8")
            .expect("static SSE content-type header"),
        Header::from_bytes("Cache-Control", "no-cache").expect("static cache header"),
        Header::from_bytes("X-Accel-Buffering", "no").expect("static buffering header"),
    ];
    request.respond(Response::new(StatusCode(200), headers, reader, None, None))
}

struct SseReader {
    state: crate::daemon::state::SharedState,
    subscriber_id: u64,
    rx: mpsc::Receiver<crate::daemon::proto::DaemonMsg>,
    frame: Cursor<Vec<u8>>,
}

impl SseReader {
    fn new(
        state: crate::daemon::state::SharedState,
        subscriber_id: u64,
        rx: mpsc::Receiver<crate::daemon::proto::DaemonMsg>,
        initial: crate::daemon::proto::WireSnapshot,
    ) -> std::io::Result<SseReader> {
        Ok(SseReader {
            state,
            subscriber_id,
            rx,
            frame: Cursor::new(sse_frame(&initial)?),
        })
    }
}

impl Read for SseReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let read = self.frame.read(buf)?;
            if read != 0 {
                return Ok(read);
            }
            match self.rx.recv() {
                Ok(crate::daemon::proto::DaemonMsg::ConsentUpdate { snapshot }) => {
                    self.frame = Cursor::new(sse_frame(&snapshot)?);
                }
                Ok(crate::daemon::proto::DaemonMsg::ConsentExitPlease) | Err(_) => return Ok(0),
                Ok(_) => {}
            }
        }
    }
}

impl Drop for SseReader {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            state.detach_link_events(self.subscriber_id);
        }
    }
}

fn sse_frame(snapshot: &crate::daemon::proto::WireSnapshot) -> std::io::Result<Vec<u8>> {
    let json = serde_json::to_string(snapshot).map_err(std::io::Error::other)?;
    let mut frame = format!("data: {json}\n\n").into_bytes();
    // `tiny_http`'s chunked encoder buffers 8 KiB and exposes no flush hook.
    // A smaller long-lived body would therefore leave both headers and the
    // first event buffered until the connection ended. An SSE comment is
    // semantically inert, so pad each state frame just past that boundary:
    // every update forces the prior encoder buffer onto the socket and the
    // browser dispatches the `data` event at the blank line before padding.
    if frame.len() < SSE_CHUNK_FLUSH_BYTES {
        frame.extend_from_slice(b":");
        let padding = SSE_CHUNK_FLUSH_BYTES.saturating_sub(frame.len() + 2);
        frame.resize(frame.len() + padding, b' ');
        frame.extend_from_slice(b"\n\n");
    }
    Ok(frame)
}

fn handle_decision(
    mut request: Request,
    runtime: &Runtime,
    state: &crate::daemon::state::SharedState,
) -> std::io::Result<()> {
    let mut body = Vec::new();
    request
        .as_reader()
        .take(MAX_DECISION_BODY_BYTES + 1)
        .read_to_end(&mut body)?;
    if body.len() as u64 > MAX_DECISION_BODY_BYTES {
        return request.respond(Response::empty(StatusCode(413)));
    }
    let Ok(payload) = serde_json::from_slice::<SignedDecision>(&body) else {
        return request.respond(Response::empty(StatusCode(400)));
    };

    // Find the signer only among the registry as it exists for this request.
    // Iterating avoids a caller-supplied device id becoming an identity oracle.
    let Ok(devices) = super::devices::load(&runtime.registry_path) else {
        return request.respond(Response::empty(StatusCode(503)));
    };
    let Some(device) = devices
        .into_iter()
        .find(|device| super::sig::verify(device, &payload).is_ok())
    else {
        return request.respond(Response::empty(StatusCode(403)));
    };

    if runtime
        .nonces
        .accept(&payload.request_id, &payload.nonce)
        .is_err()
    {
        return request.respond(Response::empty(StatusCode(409)));
    }

    let resolved = state
        .lock()
        .map_err(|_| std::io::Error::other("daemon state unavailable"))?
        .resolve_remote(
            &payload.request_id,
            &payload.ask_hash_hex,
            &payload.decision,
            device.nickname,
            state,
        );
    match resolved {
        Ok(()) => {
            let _ = runtime.nonces.retire(&payload.request_id);
            request.respond(Response::empty(StatusCode(204)))
        }
        Err(_) => request.respond(Response::empty(StatusCode(409))),
    }
}

fn handle_pair(mut request: Request, pairing: &Pairing) -> std::io::Result<()> {
    let mut body = Vec::new();
    request
        .as_reader()
        .take(MAX_PAIR_BODY_BYTES + 1)
        .read_to_end(&mut body)?;
    if body.len() as u64 > MAX_PAIR_BODY_BYTES {
        return request.respond(
            Response::from_string("pairing request is too large").with_status_code(StatusCode(413)),
        );
    }

    let Ok(pair_request) = serde_json::from_slice::<PairRequest>(&body) else {
        return request.respond(
            Response::from_string("invalid pairing request").with_status_code(StatusCode(400)),
        );
    };

    match pairing.pair(pair_request) {
        Ok(_) => request.respond(Response::empty(StatusCode(204))),
        Err(err) => {
            let status = pair_error_status(&err);
            request.respond(Response::from_string(err.to_string()).with_status_code(status))
        }
    }
}

fn pair_error_status(error: &PairError) -> StatusCode {
    match error {
        PairError::NoOpenWindow | PairError::Expired | PairError::InvalidToken => StatusCode(403),
        PairError::InvalidPublicKey | PairError::EmptyNickname => StatusCode(400),
        PairError::NicknameCollision { .. } => StatusCode(409),
        PairError::Unavailable | PairError::Clock(_) | PairError::Registry(_) => StatusCode(500),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tiny_http::{Method, TestRequest};

    #[test]
    fn rfc1918_sources_are_allowed() {
        for ip in ["10.0.0.5", "172.16.4.1", "192.168.1.20"] {
            assert!(is_lan(&ip.parse().unwrap()), "{ip} should be allowed");
        }
    }

    #[test]
    fn public_sources_are_refused() {
        for ip in ["8.8.8.8", "203.0.113.7"] {
            assert!(!is_lan(&ip.parse().unwrap()), "{ip} should be refused");
        }
    }

    #[test]
    fn carrier_grade_nat_is_not_lan() {
        // 100.64.0.0/10 is shared address space, not your house.
        assert!(!is_lan(&"100.64.0.1".parse().unwrap()));
    }

    #[test]
    fn ipv6_unique_local_is_allowed_and_global_is_not() {
        assert!(is_lan(&"fd00::1".parse().unwrap()));
        assert!(!is_lan(&"2606:4700::1".parse().unwrap()));
    }

    #[test]
    fn non_lan_sources_are_refused_before_routing() {
        let request: Request = TestRequest::new()
            .with_method(Method::Get)
            .with_path("/healthz")
            .with_remote_addr("203.0.113.7:1234".parse().unwrap())
            .into();

        assert!(!request.remote_addr().is_some_and(|addr| is_lan(&addr.ip())));
    }
}
