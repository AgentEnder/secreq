//! Plain-HTTP listener for devices linked over the local network.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use anyhow::{bail, Context, Result};
use tiny_http::{Method, Request, Response, Server, StatusCode};

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
pub fn start(bind_addr: SocketAddr) -> Result<Listener> {
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
        .spawn(move || accept_loop(accept_server))
        .context("spawn LAN listener accept thread")?;

    Ok(Listener {
        server,
        accept_thread: Some(accept_thread),
        local_addr,
    })
}

fn accept_loop(server: Arc<Server>) {
    for request in server.incoming_requests() {
        thread::Builder::new()
            .name("secreqd-link-conn".to_owned())
            .spawn(move || {
                if let Err(err) = handle_request(request) {
                    eprintln!("secreqd: link connection error: {err}");
                }
            })
            .ok();
    }
}

fn handle_request(request: Request) -> std::io::Result<()> {
    let status = response_status(&request);
    request.respond(Response::empty(status))
}

fn response_status(request: &Request) -> StatusCode {
    if !request.remote_addr().is_some_and(|addr| is_lan(&addr.ip())) {
        return StatusCode(403);
    }

    if request.method() == &Method::Get && request.url() == "/healthz" {
        StatusCode(200)
    } else {
        StatusCode(404)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tiny_http::{Method, StatusCode, TestRequest};

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
        let request = TestRequest::new()
            .with_method(Method::Get)
            .with_path("/healthz")
            .with_remote_addr("203.0.113.7:1234".parse().unwrap())
            .into();

        assert_eq!(response_status(&request), StatusCode(403));
    }
}
