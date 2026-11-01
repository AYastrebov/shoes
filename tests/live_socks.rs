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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, TcpStream, UdpSocket};
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

/// Start shoes on the config and wait for its listener. Something already
/// accepting at the address is refused first, else a stale client would
/// be the one tested while the new one failed to bind; and a child that
/// exits while we wait is reported with its status, not as a timeout.
fn spawn(socks: SocketAddr) -> Child {
    assert!(
        TcpStream::connect_timeout(&socks, Duration::from_millis(200)).is_err(),
        "something already accepts at {socks}; stop it, or point SHOES_LIVE_SOCKS elsewhere"
    );
    let config = std::env::var_os("SHOES_LIVE_CONFIG").unwrap();
    let child = std::process::Command::new(env!("CARGO_BIN_EXE_shoes"))
        .arg("--no-reload")
        .arg(config)
        .stdin(std::process::Stdio::null())
        .spawn()
        .expect("shoes starts");
    let mut child = Child(child);
    let deadline = Instant::now() + START_TIMEOUT;
    while TcpStream::connect_timeout(&socks, Duration::from_millis(200)).is_err() {
        if let Some(status) = child.0.try_wait().expect("the child can be polled") {
            panic!("shoes exited with {status} before listening on {socks}");
        }
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

/// The four checks in sequence, through one child, because every check
/// needs the same listener: parallel tests each spawning a child on the
/// one port would probe each other's, and a finishing test's guard would
/// kill the proxy another was still using.
#[test]
fn the_outbound_carries_tcp_by_name_and_literal_udp_and_a_burst() {
    let Some(live) = live() else {
        eprintln!("SHOES_LIVE_CONFIG unset: live check skipped");
        return;
    };
    let _shoes = spawn(live.socks);
    // Every check runs and is reported before the verdict, so a run with a
    // wrong password shows that each path refused it, not only the first:
    // a UDP or literal-address route around the outbound would otherwise
    // hide behind the first check's panic.
    type Check = fn(&Live);
    let checks: [(&str, Check); 4] = [
        (
            "a request by hostname exits through the server",
            a_request_by_hostname_exits_through_the_server,
        ),
        (
            "a request by IPv4 literal is carried",
            a_request_by_ipv4_literal_is_carried,
        ),
        (
            "a DNS query over UDP ASSOCIATE is answered",
            a_dns_query_over_udp_associate_is_answered,
        ),
        (
            "eight connections at once all complete",
            eight_connections_at_once_all_complete,
        ),
    ];
    let mut failed = Vec::new();
    for (name, check) in checks {
        let outcome = std::panic::catch_unwind(|| check(&live));
        match outcome {
            Ok(()) => eprintln!("pass: {name}"),
            Err(_) => {
                eprintln!("FAIL: {name}");
                failed.push(name);
            }
        }
    }
    assert!(failed.is_empty(), "failed checks: {failed:?}");
}

fn a_request_by_hostname_exits_through_the_server(live: &Live) {
    let ip = exit_address(live.socks);
    eprintln!("exit address: {ip}");
    if let Some(expected) = &live.exit_ip {
        assert_eq!(&ip, expected, "the traffic left through the server");
    }
}

fn a_request_by_ipv4_literal_is_carried(live: &Live) {
    let mut stream = socks_connect(live.socks, &ipv4(LITERAL), 80);
    let response = http_get(&mut stream, &LITERAL.to_string(), "/");
    let status = status_of(&response);
    assert!(
        (200..500).contains(&status),
        "an HTTP answer from the literal address, got {status}"
    );
}

fn a_dns_query_over_udp_associate_is_answered(live: &Live) {
    let mut control = TcpStream::connect_timeout(&live.socks, IO_TIMEOUT).unwrap();
    control.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
    control.write_all(&[5, 1, 0]).unwrap();
    let mut reply = [0u8; 2];
    control.read_exact(&mut reply).unwrap();
    assert_eq!(reply, [5, 0]);
    control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
    let mut head = [0u8; 4];
    control.read_exact(&mut head).unwrap();
    assert_eq!(head[1], 0, "UDP ASSOCIATE refused with reply {}", head[1]);
    // The relay is given in the listener's family; an unspecified address
    // means the listener's own.
    let relay_ip: IpAddr = match head[3] {
        1 => {
            let mut a = [0u8; 4];
            control.read_exact(&mut a).unwrap();
            let ip = Ipv4Addr::from(a);
            if ip.is_unspecified() {
                live.socks.ip()
            } else {
                IpAddr::V4(ip)
            }
        }
        4 => {
            let mut a = [0u8; 16];
            control.read_exact(&mut a).unwrap();
            let ip = Ipv6Addr::from(a);
            if ip.is_unspecified() {
                live.socks.ip()
            } else {
                IpAddr::V6(ip)
            }
        }
        other => panic!("relay address type {other}"),
    };
    let mut port = [0u8; 2];
    control.read_exact(&mut port).unwrap();
    let port = u16::from_be_bytes(port);
    // A link-local listener's scope does not travel in the reply; the relay
    // was bound with the listener's (`handle_udp_associate`), so it is the
    // listener's here too.
    let relay = match (relay_ip, live.socks) {
        (IpAddr::V6(ip), SocketAddr::V6(listener)) => {
            SocketAddr::V6(SocketAddrV6::new(ip, port, 0, listener.scope_id()))
        }
        (ip, _) => SocketAddr::from((ip, port)),
    };

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

    let udp = UdpSocket::bind(SocketAddr::from((
        match relay {
            SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        },
        0,
    )))
    .unwrap();
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

fn eight_connections_at_once_all_complete(live: &Live) {
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
