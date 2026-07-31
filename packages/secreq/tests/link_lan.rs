use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};

#[test]
fn listener_serves_healthz_on_an_ephemeral_port() {
    let listener = secreq::link::lan::start(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .expect("start LAN listener");
    let mut client = TcpStream::connect(listener.local_addr()).expect("connect to LAN listener");
    client
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .expect("write health request");

    let mut response = String::new();
    client
        .read_to_string(&mut response)
        .expect("read health response");

    assert!(
        response.starts_with("HTTP/1.1 200 "),
        "unexpected response: {response:?}"
    );
}
