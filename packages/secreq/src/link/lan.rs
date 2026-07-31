//! Plain-HTTP listener for devices linked over the local network.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{mpsc, Arc};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tiny_http::{Method, Request, Response, Server, StatusCode};

use super::nonce::NonceStore;
use super::pair::{PairError, PairRequest, Pairing};
use super::sig::SignedDecision;

const MAX_PAIR_BODY_BYTES: u64 = 16 * 1024;
const MAX_DECISION_BODY_BYTES: u64 = 16 * 1024;
const MAX_PENDING_SNAPSHOTS: usize = 8;
/// Hard cap on unauthenticated long-lived SSE connections from the LAN.
pub const MAX_LINK_SUBSCRIBERS: usize = 8;
const SSE_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);

struct Runtime {
    pairing: Arc<Pairing>,
    state: crate::daemon::state::SharedState,
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
pub fn start(
    bind_addr: SocketAddr,
    pairing: Arc<Pairing>,
    state: crate::daemon::state::SharedState,
) -> Result<Listener> {
    let registry_path = pairing.registry_path().to_owned();
    let nonces = state
        .lock()
        .map_err(|_| anyhow::anyhow!("daemon state unavailable"))?
        .link_nonce_store();
    start_runtime(
        bind_addr,
        Arc::new(Runtime {
            pairing,
            state,
            registry_path,
            nonces,
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
    match route_decision(&request) {
        RouteDecision::Forbidden => request.respond(Response::empty(StatusCode(403))),
        RouteDecision::Health => request.respond(Response::empty(StatusCode(200))),
        RouteDecision::Pair => handle_pair(request, &runtime.pairing),
        RouteDecision::Events => handle_events(request, Arc::clone(&runtime.state)),
        RouteDecision::Decision => handle_decision(request, runtime, &runtime.state),
        RouteDecision::NotFound => request.respond(Response::empty(StatusCode(404))),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteDecision {
    Forbidden,
    Health,
    Pair,
    Events,
    Decision,
    NotFound,
}

fn route_decision(request: &Request) -> RouteDecision {
    if !request.remote_addr().is_some_and(|addr| is_lan(&addr.ip())) {
        return RouteDecision::Forbidden;
    }
    if request.method() == &Method::Get && request.url() == "/healthz" {
        return RouteDecision::Health;
    }
    if request.method() == &Method::Post && request.url() == "/pair" {
        return RouteDecision::Pair;
    }
    if request.method() == &Method::Get && request.url() == "/events" {
        return RouteDecision::Events;
    }
    if request.method() == &Method::Post && request.url() == "/decision" {
        return RouteDecision::Decision;
    }
    RouteDecision::NotFound
}

fn handle_events(
    request: Request,
    state: crate::daemon::state::SharedState,
) -> std::io::Result<()> {
    let (tx, rx) = mpsc::sync_channel(MAX_PENDING_SNAPSHOTS);
    let (subscriber_id, initial) = {
        let mut state = state
            .lock()
            .map_err(|_| std::io::Error::other("daemon state unavailable"))?;
        if state.link_subscriber_count() >= MAX_LINK_SUBSCRIBERS {
            drop(state);
            return request.respond(Response::empty(StatusCode(503)));
        }
        state.attach_link_events(tx)
    };
    let _subscription = LinkSubscription {
        state,
        subscriber_id,
    };

    // `tiny_http`'s response body buffers small chunked writes without a
    // flush hook, which is hostile to both SSE latency and heartbeat-based
    // liveness. Its raw writer lets us own the HTTP framing and flush every
    // snapshot or comment immediately.
    let mut writer = request.into_writer();
    writer.write_all(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\nCache-Control: no-cache\r\nX-Accel-Buffering: no\r\nConnection: close\r\n\r\n",
    )?;
    write_sse_snapshot(&mut writer, &initial)?;

    loop {
        match rx.recv_timeout(SSE_HEARTBEAT_INTERVAL) {
            Ok(crate::daemon::proto::DaemonMsg::ConsentUpdate { snapshot }) => {
                write_sse_snapshot(&mut writer, &snapshot)?;
            }
            Ok(crate::daemon::proto::DaemonMsg::ConsentExitPlease)
            | Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                writer.write_all(b": keep-alive\n\n")?;
                writer.flush()?;
            }
            Ok(_) => {}
        }
    }
}

struct LinkSubscription {
    state: crate::daemon::state::SharedState,
    subscriber_id: u64,
}

impl Drop for LinkSubscription {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            state.detach_link_events(self.subscriber_id);
        }
    }
}

fn write_sse_snapshot(
    writer: &mut dyn Write,
    snapshot: &crate::daemon::proto::WireSnapshot,
) -> std::io::Result<()> {
    let json = serde_json::to_string(snapshot).map_err(std::io::Error::other)?;
    writeln!(writer, "data: {json}\n")?;
    writer.flush()
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

    let live = state
        .lock()
        .map_err(|_| std::io::Error::other("daemon state unavailable"))?
        .link_request_matches(&payload.request_id, &payload.ask_hash_hex);
    if !live {
        return request.respond(Response::empty(StatusCode(409)));
    }

    // Burn only after proving the signed request still names a live ask.
    // `resolve_remote` repeats that proof under its own lock acquisition;
    // if a local decision wins between the two, the error path below retires
    // the just-created bucket.
    if runtime
        .nonces
        .accept(&payload.request_id, &payload.nonce)
        .is_err()
    {
        return request.respond(Response::empty(StatusCode(409)));
    }

    let resolved = if let Ok(mut guard) = state.lock() {
        guard.resolve_remote(
            &payload.request_id,
            &payload.ask_hash_hex,
            &payload.decision,
            device.nickname,
            state,
        )
    } else {
        let _ = runtime.nonces.retire(&payload.request_id);
        return Err(std::io::Error::other("daemon state unavailable"));
    };
    // Success is terminal too; State also retires while removing the queue
    // entry so local decisions and withdrawals share the same guarantee.
    let _ = runtime.nonces.retire(&payload.request_id);
    match resolved {
        Ok(()) => request.respond(Response::empty(StatusCode(204))),
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
        PairError::NoOpenWindow
        | PairError::Expired
        | PairError::InvalidToken
        | PairError::TooManyTokenAttempts => StatusCode(403),
        PairError::InvalidPublicKey
        | PairError::EmptyNickname
        | PairError::NicknameTooLong
        | PairError::NicknameControlCharacter => StatusCode(400),
        PairError::NicknameCollision { .. } | PairError::PublicKeyCollision { .. } => {
            StatusCode(409)
        }
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
        let public_health: Request = TestRequest::new()
            .with_method(Method::Get)
            .with_path("/healthz")
            .with_remote_addr("203.0.113.7:1234".parse().unwrap())
            .into();
        let public_unknown: Request = TestRequest::new()
            .with_method(Method::Get)
            .with_path("/missing")
            .with_remote_addr("203.0.113.7:1234".parse().unwrap())
            .into();
        let local_health: Request = TestRequest::new()
            .with_method(Method::Get)
            .with_path("/healthz")
            .with_remote_addr("127.0.0.1:1234".parse().unwrap())
            .into();
        let local_unknown: Request = TestRequest::new()
            .with_method(Method::Get)
            .with_path("/missing")
            .with_remote_addr("127.0.0.1:1234".parse().unwrap())
            .into();

        assert_eq!(route_decision(&public_health), RouteDecision::Forbidden);
        assert_eq!(route_decision(&public_unknown), RouteDecision::Forbidden);
        assert_eq!(route_decision(&local_health), RouteDecision::Health);
        assert_eq!(route_decision(&local_unknown), RouteDecision::NotFound);
    }
}
