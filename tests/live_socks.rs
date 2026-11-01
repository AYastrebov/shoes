//! A live check of one outbound through a real server, driven through a
//! SOCKS listener in front of it: TCP by name and by address, UDP, and a
//! burst of connections. Opt-in, because it needs a server and a credential
//! that must never enter this repository; without `SHOES_LIVE_CONFIG` it
//! passes doing nothing and says so.
//!
//! ```bash
//! SHOES_LIVE_CONFIG=/outside/the/tree/client.yaml \
//! SHOES_LIVE_SOCKS=127.0.0.1:11080 \
//! SHOES_LIVE_EXIT_IP=203.0.113.7 \
//! cargo test --locked --test live_socks -- --nocapture
//! ```
//!
//! The config is any shoes config whose first server is a `socks` listener
//! at `SHOES_LIVE_SOCKS` with the outbound under test in its chain; the
//! `examples/*_client.yaml` files are that shape. `SHOES_LIVE_EXIT_IP` is
//! optional: when set, the address a public echo service sees must equal
//! it, which is the one check that proves the traffic left through the
//! server rather than around it. See `.agent/skills/live-interop-check/`.
//!
//! What it checks, and why each: a request by hostname, since that is how
//! every real client speaks to a SOCKS proxy; a request by IPv4 literal,
//! which takes the proxy's other address path; a DNS query over UDP
//! ASSOCIATE, since every outbound here carries UDP one way or another and
//! a TCP-only run would pass over a broken one; and eight connections at
//! once, because a tunnel that multiplexes (mieru, OpenConnect, SSTP) can
//! serialise them or lose one under contention where single requests pass.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "a test; the lint is allowed in test code by clippy.toml for unit tests only"
)]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

const IO_TIMEOUT: Duration = Duration::from_secs(20);
const START_TIMEOUT: Duration = Duration::from_secs(15);
/// A public echo of the client's address, over plain HTTP so no TLS stack
/// is needed here; the proxy carries it as any other TCP connection.
const ECHO_HOST: &str = "api.ipify.org";
/// A name that resolves and answers HTTP, for the burst.
const BURST_HOST: &str = "example.com";
/// An address that answers HTTP, for the connect-by-literal path.
const LITERAL: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
/// A public resolver, for UDP.
const RESOLVER: Ipv4Addr = Ipv4Addr::new(9, 9, 9, 9);

/// A child that dies with the test, whichever way the test ends.
struct Child(std::process::Child);

impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Live {
    socks: SocketAddr,
    exit_ip: Option<String>,
}

fn live() -> Option<Live> {
    std::env::var_os("SHOES_LIVE_CONFIG")?;
    let socks: SocketAddr = std::env::var("SHOES_LIVE_SOCKS")
        .expect("SHOES_LIVE_SOCKS names the config's socks listener")
        .parse()
        .expect("SHOES_LIVE_SOCKS is host:port");
    let exit_ip = std::env::var("SHOES_LIVE_EXIT_IP").ok();
    Some(Live { socks, exit_ip })
}

fn spawn(socks: SocketAddr) -> Child {
    let config = std::env::var_os("SHOES_LIVE_CONFIG").unwrap();
    let child = std::process::Command::new(env!("CARGO_BIN_EXE_shoes"))
        .arg("--no-reload")
        .arg(config)
        .stdin(std::process::Stdio::null())
        .spawn()
        .expect("shoes starts");
    let child = Child(child);
    let deadline = Instant::now() + START_TIMEOUT;
    while TcpStream::connect_timeout(&socks, Duration::from_millis(200)).is_err() {
        assert!(
            Instant::now() < deadline,
            "shoes did not listen on {socks} within {START_TIMEOUT:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    child
}

/// Open a SOCKS5 connection and CONNECT to `target`, given as the ATYP and
/// address bytes (name or IPv4) plus the port.
fn socks_connect(socks: SocketAddr, atyp_and_addr: &[u8], port: u16) -> TcpStream {
    let mut stream = TcpStream::connect_timeout(&socks, IO_TIMEOUT).unwrap();
    stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
    stream.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
    stream.write_all(&[5, 1, 0]).unwrap();
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).unwrap();
    assert_eq!(reply, [5, 0], "no-auth SOCKS5");
    let mut request = vec![5, 1, 0];
    request.extend_from_slice(atyp_and_addr);
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).unwrap();
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).unwrap();
    assert_eq!(head[1], 0, "CONNECT refused with reply {}", head[1]);
    let bound = match head[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).unwrap();
            usize::from(len[0]) + 2
        }
        other => panic!("bound address type {other}"),
    };
    let mut skip = vec![0u8; bound];
    stream.read_exact(&mut skip).unwrap();
    stream
}

fn name(host: &str) -> Vec<u8> {
    let mut out = vec![3, host.len() as u8];
    out.extend_from_slice(host.as_bytes());
    out
}

fn ipv4(addr: Ipv4Addr) -> Vec<u8> {
    let mut out = vec![1];
    out.extend_from_slice(&addr.octets());
    out
}

/// One HTTP/1.0 GET through an open stream; the whole response as text.
fn http_get(stream: &mut TcpStream, host: &str, path: &str) -> String {
    write!(
        stream,
        "GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: shoes-live-check\r\n\r\n"
    )
    .unwrap();
    let mut body = Vec::new();
    stream.read_to_end(&mut body).unwrap();
    String::from_utf8_lossy(&body).into_owned()
}

fn status_of(response: &str) -> u16 {
    response
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("no status line in {response:.80?}"))
}

fn body_of(response: &str) -> &str {
    response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.trim())
        .unwrap_or("")
}

/// The address the echo service saw, requested by hostname.
fn exit_address(socks: SocketAddr) -> String {
    let mut stream = socks_connect(socks, &name(ECHO_HOST), 80);
    let response = http_get(&mut stream, ECHO_HOST, "/");
    assert_eq!(status_of(&response), 200, "{response:.200}");
    let ip = body_of(&response).to_string();
    assert!(
        ip.parse::<std::net::IpAddr>().is_ok(),
        "the echo body is an address, got {ip:?}"
    );
    ip
}

#[test]
fn a_request_by_hostname_exits_through_the_server() {
    let Some(live) = live() else {
        eprintln!("SHOES_LIVE_CONFIG unset: live check skipped");
        return;
    };
    let _shoes = spawn(live.socks);
    let ip = exit_address(live.socks);
    eprintln!("exit address: {ip}");
    if let Some(expected) = &live.exit_ip {
        assert_eq!(&ip, expected, "the traffic left through the server");
    }
}

#[test]
fn a_request_by_ipv4_literal_is_carried() {
    let Some(live) = live() else {
        eprintln!("SHOES_LIVE_CONFIG unset: live check skipped");
        return;
    };
    let _shoes = spawn(live.socks);
    let mut stream = socks_connect(live.socks, &ipv4(LITERAL), 80);
    let response = http_get(&mut stream, &LITERAL.to_string(), "/");
    let status = status_of(&response);
    assert!(
        (200..500).contains(&status),
        "an HTTP answer from the literal address, got {status}"
    );
}

#[test]
fn a_dns_query_over_udp_associate_is_answered() {
    let Some(live) = live() else {
        eprintln!("SHOES_LIVE_CONFIG unset: live check skipped");
        return;
    };
    let _shoes = spawn(live.socks);

    let mut control = TcpStream::connect_timeout(&live.socks, IO_TIMEOUT).unwrap();
    control.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
    control.write_all(&[5, 1, 0]).unwrap();
    let mut reply = [0u8; 2];
    control.read_exact(&mut reply).unwrap();
    assert_eq!(reply, [5, 0]);
    control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
    let mut head = [0u8; 10];
    control.read_exact(&mut head).unwrap();
    assert_eq!(head[1], 0, "UDP ASSOCIATE refused with reply {}", head[1]);
    assert_eq!(head[3], 1, "the relay is given as IPv4");
    let mut relay_ip = Ipv4Addr::new(head[4], head[5], head[6], head[7]);
    if relay_ip.is_unspecified() {
        relay_ip = Ipv4Addr::LOCALHOST;
    }
    let relay = SocketAddr::from((relay_ip, u16::from_be_bytes([head[8], head[9]])));

    // An A query for example.com, id 0x4242.
    let mut query = vec![0x42, 0x42, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in BURST_HOST.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 1, 0, 1]);
    let mut datagram = vec![0, 0, 0, 1];
    datagram.extend_from_slice(&RESOLVER.octets());
    datagram.extend_from_slice(&53u16.to_be_bytes());
    datagram.extend_from_slice(&query);

    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    udp.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
    udp.send_to(&datagram, relay).unwrap();
    let mut answer = [0u8; 1500];
    let (len, _) = udp
        .recv_from(&mut answer)
        .expect("an answer within the timeout");
    let answer = &answer[..len];
    assert!(len > 10 + 12, "a SOCKS UDP header and a DNS header");
    assert_eq!(&answer[..3], &[0, 0, 0], "a SOCKS UDP header");
    let dns = &answer[10..];
    assert_eq!(&dns[..2], &[0x42, 0x42], "our query id");
    let answers = u16::from_be_bytes([dns[6], dns[7]]);
    assert!(answers > 0, "at least one A record for {BURST_HOST}");
    eprintln!("udp: {answers} answer(s) from {RESOLVER}");
}

#[test]
fn eight_connections_at_once_all_complete() {
    let Some(live) = live() else {
        eprintln!("SHOES_LIVE_CONFIG unset: live check skipped");
        return;
    };
    let _shoes = spawn(live.socks);
    let socks = live.socks;
    let handles: Vec<_> = (0..8)
        .map(|_| {
            std::thread::spawn(move || {
                let mut stream = socks_connect(socks, &name(BURST_HOST), 80);
                status_of(&http_get(&mut stream, BURST_HOST, "/"))
            })
        })
        .collect();
    let statuses: Vec<u16> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert!(
        statuses.iter().all(|s| *s == 200),
        "every connection answered 200, got {statuses:?}"
    );
}
