//! A VLESS Vision client and server over real TLS, built from config the way
//! the binary builds them.

use std::future::poll_fn;
use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};

use crate::address::NetLocation;
use crate::config::{ClientProxyConfig, RuleConfig, ServerProxyConfig};
use crate::resolver::{NativeResolver, Resolver};
use crate::tcp::tcp_client_handler_factory::{
    HopContext, create_tcp_client_handler, create_tcp_client_proxy_selector,
};
use crate::tcp::tcp_handler::{TcpClientHandler, TcpServerHandler, TcpServerSetupResult};
use crate::tcp::tcp_server_handler_factory::create_tcp_server_handler;

/// Long enough that only a hang trips it, on the slowest CI runner.
const HANG: Duration = Duration::from_secs(30);

const USER_ID: &str = "b0e80a62-8a51-47f0-91f1-f0f7faf8d9d4";

fn indent(pem: &str) -> String {
    pem.lines()
        .map(|l| format!("        {l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn handlers() -> (Box<dyn TcpServerHandler>, Box<dyn TcpClientHandler>) {
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let certified = rcgen::generate_simple_self_signed(vec!["vision.test".to_string()]).unwrap();
    let server_yaml = format!(
        "type: tls\ndefault_tls_target:\n    cert: |\n{}\n    key: |\n{}\n    vision: true\n    protocol:\n        type: vless\n        user_id: {USER_ID}\n",
        indent(&certified.cert.pem()),
        indent(&certified.signing_key.serialize_pem()),
    );
    let server_config: ServerProxyConfig = serde_yaml::from_str(&server_yaml).unwrap();
    let client_config: ClientProxyConfig = serde_yaml::from_str(&format!(
        "type: tls\nverify: false\nsni_hostname: vision.test\nvision: true\nprotocol:\n    type: vless\n    user_id: {USER_ID}\n"
    ))
    .unwrap();
    let rules: Vec<RuleConfig> =
        serde_yaml::from_str("- masks: 0.0.0.0/0\n  action: allow\n").unwrap();
    let selector = Arc::new(create_tcp_client_proxy_selector(rules, resolver.clone()));
    let server = create_tcp_server_handler(server_config, &selector, &resolver, None);
    let proxy = NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
    let client = create_tcp_client_handler(client_config, None, &HopContext::new(&proxy), resolver);
    (server, client)
}

async fn tcp_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (connected, accepted) =
        tokio::join!(tokio::net::TcpStream::connect(addr), listener.accept());
    (connected.unwrap(), accepted.unwrap().0)
}

/// A client-side and a server-side end, joined by a relay that keeps a copy
/// of everything the client sends.
async fn recorded_pair() -> (
    tokio::net::TcpStream,
    tokio::net::TcpStream,
    Arc<std::sync::Mutex<Vec<u8>>>,
) {
    let (client_end, mut relay_client) = tcp_pair().await;
    let (mut relay_server, server_end) = tcp_pair().await;
    let recorded = Arc::new(std::sync::Mutex::new(Vec::new()));
    let copy = recorded.clone();
    tokio::spawn(async move {
        let (mut from_client, mut to_client) = relay_client.split();
        let (mut from_server, mut to_server) = relay_server.split();
        let upstream = async {
            let mut buf = [0u8; 16 * 1024];
            loop {
                let n = from_client.read(&mut buf).await?;
                if n == 0 {
                    return to_server.shutdown().await;
                }
                copy.lock().unwrap().extend_from_slice(&buf[..n]);
                to_server.write_all(&buf[..n]).await?;
            }
        };
        let downstream = tokio::io::copy(&mut from_server, &mut to_client);
        let _: (std::io::Result<()>, std::io::Result<u64>) = tokio::join!(upstream, downstream);
    });
    (client_end, server_end, recorded)
}

/// The (content type, length) of each TLS record in `wire`.
fn records(mut wire: &[u8]) -> Vec<(u8, usize)> {
    let mut out = Vec::new();
    while wire.len() >= 5 {
        let len = u16::from_be_bytes([wire[3], wire[4]]) as usize;
        out.push((wire[0], len));
        wire = &wire[(5 + len).min(wire.len())..];
    }
    out
}

fn target() -> NetLocation {
    NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)), 443)
}

/// An inner TLS ClientHello, the first thing a browser sends through the
/// proxy to an HTTPS site -- what Vision long-pads.
fn inner_client_hello() -> Vec<u8> {
    let config = Arc::new(crate::rustls_config_util::create_client_config(
        false,
        &[],
        &[],
        true,
        None,
        false,
    ));
    let mut conn = rustls::ClientConnection::new(
        config,
        rustls::pki_types::ServerName::try_from("inner.test").unwrap(),
    )
    .unwrap();
    let mut hello = Vec::new();
    conn.write_tls(&mut std::io::Cursor::new(&mut hello))
        .unwrap();
    hello
}

/// VL-V3: the request reaches the server inside the client's first padded
/// frame -- one record, long-padded, as Xray sends it -- and data flows both
/// ways.
#[tokio::test]
async fn the_request_rides_in_the_first_padded_frame() {
    let hello = inner_client_hello();
    let (server, client) = handlers();
    let (client_end, server_end, recorded) = recorded_pair().await;
    let accepted =
        tokio::spawn(async move { server.setup_server_stream(Box::new(server_end)).await });

    let mut stream = client
        .setup_client_tcp_stream(Box::new(client_end), target().into())
        .await
        .unwrap()
        .client_stream;
    stream.write_all(&hello).await.unwrap();
    stream.flush().await.unwrap();

    let TcpServerSetupResult::TcpForward {
        remote_location,
        stream: mut server_stream,
        initial_remote_data,
        ..
    } = tokio::time::timeout(HANG, accepted)
        .await
        .expect("the server read the request")
        .unwrap()
        .unwrap()
    else {
        panic!("not a TCP forward");
    };
    assert_eq!(remote_location, target());

    // After the handshake's own encrypted record (the client Finished), one
    // record carries the header and the padded frame together. Before, the
    // header went first as a record of its own, some 60 bytes on the wire.
    let sent = records(&recorded.lock().unwrap());
    let encrypted: Vec<usize> = sent
        .iter()
        .filter(|(content_type, _)| *content_type == 0x17)
        .map(|(_, len)| *len)
        .collect();
    assert_eq!(
        encrypted.len(),
        2,
        "the Finished, then one record with header and frame: {sent:?}"
    );
    assert!(
        encrypted[1] >= 900,
        "the inner ClientHello is long-padded: {sent:?}"
    );

    let mut received = initial_remote_data.map(Vec::from).unwrap_or_default();
    while received.len() < hello.len() {
        let mut buf = [0u8; 64];
        let n = server_stream.read(&mut buf).await.unwrap();
        assert!(n > 0, "EOF before the payload");
        received.extend_from_slice(&buf[..n]);
    }
    assert_eq!(received, hello);

    server_stream.write_all(b"HTTP/1.1 200 OK").await.unwrap();
    server_stream.flush().await.unwrap();
    let mut reply = [0u8; 15];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"HTTP/1.1 200 OK");
}

/// A server-first protocol: the client only reads, so the request goes out
/// with an empty frame after the wait, and the server's greeting comes back.
#[tokio::test]
async fn a_client_that_only_reads_sends_the_request_after_the_wait() {
    let (server, client) = handlers();
    let (client_end, server_end) = tcp_pair().await;
    let accepted =
        tokio::spawn(async move { server.setup_server_stream(Box::new(server_end)).await });

    let mut stream = client
        .setup_client_tcp_stream(Box::new(client_end), target().into())
        .await
        .unwrap()
        .client_stream;
    let started = std::time::Instant::now();
    let reader = tokio::spawn(async move {
        let mut greeting = [0u8; 7];
        stream.read_exact(&mut greeting).await.map(|_| greeting)
    });

    let TcpServerSetupResult::TcpForward {
        remote_location,
        stream: mut server_stream,
        ..
    } = tokio::time::timeout(HANG, accepted)
        .await
        .expect("the request arrived without a client write")
        .unwrap()
        .unwrap()
    else {
        panic!("not a TCP forward");
    };
    assert_eq!(remote_location, target());
    assert!(
        started.elapsed() >= super::vision_stream::FIRST_FRAME_AFTER,
        "the request waited for a first write"
    );

    server_stream.write_all(b"SSH-2.0").await.unwrap();
    server_stream.flush().await.unwrap();
    let greeting = tokio::time::timeout(HANG, reader)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(&greeting, b"SSH-2.0");
}

/// A write and then a shutdown with no flush between still delivers the
/// write: the shutdown pushes out what the TLS session holds.
#[tokio::test]
async fn a_shutdown_delivers_what_was_written_before_it() {
    let (server, client) = handlers();
    let (client_end, server_end) = tcp_pair().await;
    let accepted =
        tokio::spawn(async move { server.setup_server_stream(Box::new(server_end)).await });

    let mut stream = client
        .setup_client_tcp_stream(Box::new(client_end), target().into())
        .await
        .unwrap()
        .client_stream;
    stream.write_all(b"last words").await.unwrap();
    stream.shutdown().await.unwrap();

    let TcpServerSetupResult::TcpForward {
        stream: mut server_stream,
        initial_remote_data,
        ..
    } = tokio::time::timeout(HANG, accepted)
        .await
        .expect("the server read the request")
        .unwrap()
        .unwrap()
    else {
        panic!("not a TCP forward");
    };
    let mut received = initial_remote_data.map(Vec::from).unwrap_or_default();
    let mut rest = Vec::new();
    tokio::time::timeout(HANG, server_stream.read_to_end(&mut rest))
        .await
        .expect("EOF after the payload")
        .unwrap();
    received.extend_from_slice(&rest);
    assert_eq!(received, b"last words");
}

/// UDP over Vision asks for the Mux command under the Vision flow, with no
/// address: sing-box refuses a Vision user's request that names no flow, and
/// both reference servers refuse the plain UDP command under it.
#[test]
fn udp_asks_for_mux_under_the_vision_flow() {
    let user_id = crate::uuid_util::parse_uuid(USER_ID).unwrap();
    let addon = super::vless_util::vision_flow_addon_data();
    let header = super::vless_client_handler::vless_mux_header(&user_id, addon);

    let mut expected = vec![0];
    expected.extend_from_slice(&user_id);
    expected.push(addon.len() as u8);
    expected.extend_from_slice(addon);
    expected.push(super::vless_util::COMMAND_MUX);
    assert_eq!(header, expected);
}

/// A packet goes out over the Vision flow as XUDP and the server reads it as
/// a Vision XUDP session, under its target; the reply comes back through it.
#[tokio::test]
async fn udp_rides_the_vision_flow_as_xudp() {
    udp_round_trip(b"query").await;
}

/// A datagram ending in a byte that could begin a TLS record is still sent
/// whole: the client pads each XUDP write as one unit, as Xray's VisionWriter
/// does, rather than holding the tail back for a record that never comes.
#[tokio::test]
async fn a_datagram_ending_in_a_tls_prefix_is_sent_whole() {
    udp_round_trip(b"query\x16").await;
    udp_round_trip(b"query\x16\x03\x03").await;
}

/// One datagram to the server and one back, with nothing else written in
/// between: the server must see it on its own.
async fn udp_round_trip(payload: &[u8]) {
    let (server, client) = handlers();
    let (client_end, server_end) = tcp_pair().await;
    let accepted =
        tokio::spawn(async move { server.setup_server_stream(Box::new(server_end)).await });

    let dns = NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)), 53);
    let mut packets = client
        .setup_client_udp_bidirectional(Box::new(client_end), dns.clone().into())
        .await
        .unwrap();
    poll_fn(|cx| Pin::new(&mut *packets).poll_write_message(cx, payload))
        .await
        .unwrap();
    poll_fn(|cx| Pin::new(&mut *packets).poll_flush_message(cx))
        .await
        .unwrap();

    let TcpServerSetupResult::SessionBasedUdp {
        stream: mut sessions,
        ..
    } = tokio::time::timeout(HANG, accepted)
        .await
        .expect("the server read the request")
        .unwrap()
        .unwrap()
    else {
        panic!("not an XUDP session stream");
    };

    let mut storage = vec![0u8; 65535];
    let mut buf = ReadBuf::new(&mut storage);
    let (session, source) = tokio::time::timeout(
        HANG,
        poll_fn(|cx| Pin::new(&mut *sessions).poll_read_session_message(cx, &mut buf)),
    )
    .await
    .expect("the server read the packet")
    .unwrap();
    assert_eq!(source, "192.0.2.53:53".parse().unwrap());
    assert_eq!(buf.filled(), payload);

    poll_fn(|cx| {
        Pin::new(&mut *sessions).poll_write_session_message(cx, session, b"answer", &source)
    })
    .await
    .unwrap();
    poll_fn(|cx| Pin::new(&mut *sessions).poll_flush_message(cx))
        .await
        .unwrap();

    let mut storage = vec![0u8; 65535];
    let mut buf = ReadBuf::new(&mut storage);
    tokio::time::timeout(
        HANG,
        poll_fn(|cx| Pin::new(&mut *packets).poll_read_message(cx, &mut buf)),
    )
    .await
    .expect("the reply came back")
    .unwrap();
    assert_eq!(buf.filled(), b"answer");
}
