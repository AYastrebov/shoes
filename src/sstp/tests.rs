//! End to end: the SSTP connector against the server double in
//! `testing.rs`, TCP and UDP echoed through the whole path.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests: a panic is the failure report"
)]

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::SstpConnector;
use super::testing::{self, ECHO_PORT, Options, SERVER_IP, ServerAuth, TestServer};
use crate::address::{NetLocation, ResolvedLocation};
use crate::config::{SstpAuthMethod, SstpClientConfig, SstpTlsConfig};
use crate::option_util::{NoneOrOne, NoneOrSome};
use crate::resolver::Resolver;
use crate::tcp::terminal_connector::TerminalConnector;

/// The server's certificate is self-signed and pinned, the way a user with
/// an RRAS box and no public CA would configure it.
fn connector(server: &TestServer, auth: Vec<SstpAuthMethod>, password: &str) -> SstpConnector {
    SstpConnector::new(
        NetLocation::from(server.address),
        config_for(server, auth, password),
        None,
        true,
    )
    .unwrap()
}

fn config_for(server: &TestServer, auth: Vec<SstpAuthMethod>, password: &str) -> SstpClientConfig {
    SstpClientConfig {
        username: "alice".into(),
        password: password.to_string().into(),
        auth,
        mtu: 1500,
        tls: SstpTlsConfig {
            verify: false,
            server_fingerprints: NoneOrSome::One(server.fingerprint.clone()),
            sni_hostname: NoneOrOne::Unspecified,
        },
        camouflage_secret: None,
    }
}

fn resolver() -> Arc<dyn Resolver> {
    crate::quic_outbound::testing::test_resolver()
}

fn echo() -> ResolvedLocation {
    ResolvedLocation::new(NetLocation::from(SocketAddr::new(
        IpAddr::V4(SERVER_IP),
        ECHO_PORT,
    )))
}

/// Write `payload` through the tunnel to the echo service and read it back.
async fn tcp_echo(connector: &SstpConnector, payload: &[u8]) -> std::io::Result<()> {
    let mut stream = connector
        .connect_tcp(&resolver(), echo())
        .await?
        .client_stream;
    let (mut read, mut write) = tokio::io::split(&mut stream);
    let writing = async {
        write.write_all(payload).await?;
        write.flush().await
    };
    let mut back = vec![0u8; payload.len()];
    let reading = read.read_exact(&mut back);
    let (written, read) = tokio::time::timeout(Duration::from_secs(20), async {
        tokio::join!(writing, reading)
    })
    .await
    .expect("the echo did not come back in time");
    written?;
    read?;
    assert!(back == payload, "the echo came back altered");
    Ok(())
}

fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 + i / 251) as u8).collect()
}

const PASSWORD: &str = "correct horse";

#[tokio::test]
async fn tcp_crosses_the_tunnel_with_ms_chap_v2_and_sha256_binding() {
    let server = testing::start(Options::default()).await;
    let connector = connector(&server, vec![SstpAuthMethod::Mschapv2], PASSWORD);
    tcp_echo(&connector, &payload(256 * 1024)).await.unwrap();
    assert_eq!(server.stats.bindings_verified.load(Ordering::SeqCst), 1);
    assert_eq!(server.stats.early_packets.load(Ordering::SeqCst), 0);
}

/// A server offering SHA-1 only gets a SHA-1 binding it can verify.
#[tokio::test]
async fn a_sha1_server_gets_a_sha1_binding() {
    let server = testing::start(Options {
        hash_bitmask: 0x01,
        ..Options::default()
    })
    .await;
    let connector = connector(&server, vec![SstpAuthMethod::Mschapv2], PASSWORD);
    tcp_echo(&connector, b"sha-1").await.unwrap();
    assert_eq!(server.stats.bindings_verified.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn udp_crosses_the_tunnel() {
    let server = testing::start(Options::default()).await;
    let connector = connector(&server, vec![SstpAuthMethod::Mschapv2], PASSWORD);
    let mut stream = connector
        .connect_udp_bidirectional(&resolver(), echo())
        .await
        .unwrap();
    let reply = crate::quic_outbound::testing::udp_echo_exchange(&mut stream, b"a datagram")
        .await
        .unwrap();
    assert_eq!(reply, b"a datagram");
}

#[tokio::test]
async fn pap_works_when_listed() {
    let server = testing::start(Options {
        auth: ServerAuth::Pap,
        ..Options::default()
    })
    .await;
    let connector = connector(&server, vec![SstpAuthMethod::Pap], PASSWORD);
    tcp_echo(&connector, b"pap").await.unwrap();
    assert_eq!(
        server.stats.bindings_verified.load(Ordering::SeqCst),
        1,
        "PAP binds with a zero HLAK"
    );
}

#[tokio::test]
async fn a_server_that_insists_on_pap_is_refused_unless_pap_is_listed() {
    let server = testing::start(Options {
        auth: ServerAuth::Pap,
        ..Options::default()
    })
    .await;
    let connector = connector(&server, vec![SstpAuthMethod::Mschapv2], PASSWORD);
    let err = tcp_echo(&connector, b"x").await.unwrap_err();
    assert!(err.to_string().contains("requires PAP"), "{err}");
}

/// SoftEther's order: EAP first, MS-CHAPv2 once the client refuses it.
#[tokio::test]
async fn an_eap_proposal_is_refused_and_ms_chap_v2_follows() {
    let server = testing::start(Options {
        auth: ServerAuth::EapThenMsChapV2,
        ..Options::default()
    })
    .await;
    let connector = connector(&server, vec![SstpAuthMethod::Mschapv2], PASSWORD);
    tcp_echo(&connector, b"eap").await.unwrap();
}

#[tokio::test]
async fn a_server_that_insists_on_eap_is_refused_by_name() {
    let server = testing::start(Options {
        auth: ServerAuth::EapOnly,
        ..Options::default()
    })
    .await;
    let connector = connector(&server, vec![SstpAuthMethod::Mschapv2], PASSWORD);
    let err = tcp_echo(&connector, b"x").await.unwrap_err();
    assert!(err.to_string().contains("requires EAP"), "{err}");
}

#[tokio::test]
async fn a_wrong_password_fails_with_the_servers_code_and_not_the_password() {
    let server = testing::start(Options::default()).await;
    let wrong = "not the password";
    let connector = connector(&server, vec![SstpAuthMethod::Mschapv2], wrong);
    let err = tcp_echo(&connector, b"x").await.unwrap_err();
    let text = err.to_string();
    assert!(text.contains("691"), "{text}");
    assert!(!text.contains(wrong) && !text.contains("alice"), "{text}");
    // The cooldown answers the next connection without redialling.
    let again = tcp_echo(&connector, b"x").await.unwrap_err();
    assert!(again.to_string().contains("cooldown"), "{again}");
    assert_eq!(server.stats.sessions.load(Ordering::SeqCst), 1);
}

/// A certificate that does not match the pin is refused before any
/// credential is sent.
#[tokio::test]
async fn a_certificate_that_does_not_match_the_pin_is_refused() {
    let pinned = testing::start(Options::default()).await;
    let other = testing::start(Options::default()).await;
    let mut connector = connector(&pinned, vec![SstpAuthMethod::Mschapv2], PASSWORD);
    connector.point_at(NetLocation::from(other.address));
    let err = tcp_echo(&connector, b"x").await.unwrap_err();
    assert!(err.to_string().contains("fingerprint"), "{err}");
    assert_eq!(other.stats.sessions.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn connections_share_one_session() {
    let server = testing::start(Options::default()).await;
    let connector = Arc::new(connector(&server, vec![SstpAuthMethod::Mschapv2], PASSWORD));
    let tasks: Vec<_> = (0..8)
        .map(|i| {
            let connector = connector.clone();
            tokio::spawn(async move { tcp_echo(&connector, &payload(32 * 1024 + i)).await })
        })
        .collect();
    for task in tasks {
        task.await.unwrap().unwrap();
    }
    assert_eq!(server.stats.sessions.load(Ordering::SeqCst), 1);
}

/// The server's Call Disconnect ends the session; the next connection
/// builds a new one.
#[tokio::test]
async fn a_server_disconnect_is_followed_by_a_new_session() {
    let server = testing::start(Options::default()).await;
    let connector = connector(&server, vec![SstpAuthMethod::Mschapv2], PASSWORD);
    tcp_echo(&connector, b"first").await.unwrap();
    server.stats.disconnect.notify_waiters();
    wait_until_dead(&connector).await;
    // The Ack is queued by the reader as it ends; the writer flushes it
    // before the connection closes ([MS-SSTP] §3.1.2.2).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while server.stats.disconnect_acks.load(Ordering::SeqCst) == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the server never got its Disconnect Ack"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tcp_echo(&connector, b"second").await.unwrap();
    assert_eq!(server.stats.sessions.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_network_change_ends_the_session() {
    let server = testing::start(Options::default()).await;
    let connector = connector(&server, vec![SstpAuthMethod::Mschapv2], PASSWORD);
    tcp_echo(&connector, b"first").await.unwrap();
    connector.network_changed().await;
    wait_until_dead(&connector).await;
    tcp_echo(&connector, b"second").await.unwrap();
    assert_eq!(server.stats.sessions.load(Ordering::SeqCst), 2);
}

/// Three malformed PPP frames from the server are discarded, as RFC 1661
/// §5 says, and the session and the connection through it carry on.
#[tokio::test]
async fn malformed_ppp_frames_are_discarded_not_fatal() {
    let server = testing::start(Options::default()).await;
    let connector = connector(&server, vec![SstpAuthMethod::Mschapv2], PASSWORD);
    let mut stream = connector
        .connect_tcp(&resolver(), echo())
        .await
        .unwrap()
        .client_stream;
    stream.write_all(b"before").await.unwrap();
    let mut back = [0u8; 6];
    stream.read_exact(&mut back).await.unwrap();

    server.stats.garbage.notify_waiters();
    // The frames go out ahead of the next echo on the same connection.
    tokio::time::sleep(Duration::from_millis(100)).await;
    stream.write_all(b"after").await.unwrap();
    let mut back = [0u8; 5];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut back))
        .await
        .expect("the session died on garbage")
        .unwrap();
    assert_eq!(&back, b"after");
    assert!(connector.session_alive().await);
    assert_eq!(server.stats.sessions.load(Ordering::SeqCst), 1);
}

/// A stream open when its session dies ends, rather than waiting on a
/// netstack that is gone: the netstack closes every control it drops.
#[tokio::test]
async fn a_stream_open_across_the_sessions_death_ends() {
    let server = testing::start(Options::default()).await;
    let connector = connector(&server, vec![SstpAuthMethod::Mschapv2], PASSWORD);
    let mut stream = connector
        .connect_tcp(&resolver(), echo())
        .await
        .unwrap()
        .client_stream;
    stream.write_all(b"alive").await.unwrap();
    let mut back = [0u8; 5];
    stream.read_exact(&mut back).await.unwrap();

    connector.network_changed().await;
    wait_until_dead(&connector).await;

    let mut buf = [0u8; 16];
    let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("the read parked on a dead session");
    assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
    let write = tokio::time::timeout(Duration::from_secs(5), async {
        stream.write_all(&[0u8; 65536]).await?;
        stream.flush().await
    })
    .await
    .expect("the write parked on a dead session");
    assert!(write.is_err(), "a write on a dead session fails");
}

async fn wait_until_dead(connector: &SstpConnector) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while connector.session_alive().await {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the session did not end"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// A burst shares TLS records: the writer drains what is queued into one
/// write. One record per packet is what sstp-client does.
#[tokio::test]
async fn a_burst_of_packets_shares_tls_records() {
    let server = testing::start(Options::default()).await;
    let connector = connector(&server, vec![SstpAuthMethod::Mschapv2], PASSWORD);
    tcp_echo(&connector, b"warm up").await.unwrap();
    let records = server.stats.client_records.load(Ordering::SeqCst);
    let packets = server.stats.client_packets.load(Ordering::SeqCst);
    tcp_echo(&connector, &payload(1024 * 1024)).await.unwrap();
    let records = server.stats.client_records.load(Ordering::SeqCst) - records;
    let packets = server.stats.client_packets.load(Ordering::SeqCst) - packets;
    assert!(
        records * 2 < packets,
        "{packets} packets took {records} records"
    );
}

/// Answers every name with an IPv6 address first, as a dual-stack host's
/// resolver often does.
#[derive(Debug)]
struct SixFirst;

impl Resolver for SixFirst {
    fn resolve_location(
        &self,
        location: &NetLocation,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>>
    {
        let port = location.port();
        let v4 = location.address().hostname() == Some("dual.test");
        Box::pin(async move {
            let mut out = vec![SocketAddr::from(([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1], port))];
            if v4 {
                out.push(SocketAddr::new(IpAddr::V4(SERVER_IP), port));
            }
            Ok(out)
        })
    }
}

/// The tunnel is IPv4 only, so a name is reached at its IPv4 address even
/// when the resolver lists an IPv6 one first, and a name with none is
/// refused by saying so. The first live run failed on exactly the first.
#[tokio::test]
async fn a_name_is_reached_at_its_ipv4_address() {
    let server = testing::start(Options::default()).await;
    let connector = connector(&server, vec![SstpAuthMethod::Mschapv2], PASSWORD);
    let resolver: Arc<dyn Resolver> = Arc::new(SixFirst);
    let dual = ResolvedLocation::new(NetLocation::from_str("dual.test", Some(ECHO_PORT)).unwrap());
    let mut stream = connector
        .connect_tcp(&resolver, dual)
        .await
        .unwrap()
        .client_stream;
    stream.write_all(b"v4").await.unwrap();
    let mut back = [0u8; 2];
    stream.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"v4");

    // The rule engine resolves a name to match it against an IP mask and
    // keeps the first address: an IPv6 one here, as on a dual-stack host.
    // The name still has an IPv4 address, and that is the one to use.
    let mut pre_resolved =
        ResolvedLocation::new(NetLocation::from_str("dual.test", Some(ECHO_PORT)).unwrap());
    pre_resolved.set_resolved(SocketAddr::from((
        [0x2001, 0xdb8, 0, 0, 0, 0, 0, 1],
        ECHO_PORT,
    )));
    let mut stream = connector
        .connect_tcp(&resolver, pre_resolved)
        .await
        .unwrap()
        .client_stream;
    stream.write_all(b"pre").await.unwrap();
    let mut back = [0u8; 3];
    stream.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"pre");

    let six_only =
        ResolvedLocation::new(NetLocation::from_str("six.test", Some(ECHO_PORT)).unwrap());
    let err = connector
        .connect_tcp(&resolver, six_only)
        .await
        .err()
        .expect("an IPv6-only name cannot be reached");
    assert!(err.to_string().contains("IPv4 only"), "{err}");
}

/// The production path, end to end: the config text through the loader
/// (validation, the single-hop rule for a transport owner), the selector
/// `create_tcp_client_proxy_selector` builds (the chain builder's terminal
/// arm), the chain's dial, the tunnel. The tests above construct the
/// connector directly to reach its internals; this one proves the wiring.
#[tokio::test]
async fn the_configured_chain_reaches_the_tunnel_through_the_selector() {
    use crate::client_proxy_selector::ConnectDecision;
    use crate::config::{Config, ConfigSelection};
    use crate::tcp::tcp_client_handler_factory::create_tcp_client_proxy_selector;

    let server = testing::start(Options::default()).await;
    let yaml = format!(
        r#"
- address: "127.0.0.1:0"
  protocol:
    type: socks
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        - address: "{}"
          protocol:
            type: sstp
            username: alice
            password: "{PASSWORD}"
            tls:
              verify: false
              server_fingerprints: ["{}"]
"#,
        server.address, server.fingerprint
    );
    let configs = crate::config::load_config_str(&yaml).unwrap();
    let validated = crate::config::create_server_configs(configs).unwrap();
    let rules: Vec<_> = validated
        .configs
        .into_iter()
        .filter_map(|config| match config {
            Config::Server(server) => Some(server.rules),
            _ => None,
        })
        .flat_map(|rules| rules.into_vec())
        .filter_map(|rule| match rule {
            ConfigSelection::Config(rule) => Some(rule),
            ConfigSelection::GroupName(_) => None,
        })
        .collect();
    assert_eq!(rules.len(), 1);
    let resolver = resolver();
    let selector = Arc::new(create_tcp_client_proxy_selector(rules, resolver.clone()));

    let ConnectDecision::Allow {
        chain_group,
        remote_location,
    } = selector.judge(echo(), &resolver).await.unwrap()
    else {
        panic!("the rule allows everything");
    };
    let mut stream = chain_group
        .connect_tcp(remote_location.clone(), &resolver)
        .await
        .unwrap()
        .client_stream;
    stream.write_all(b"via the selector").await.unwrap();
    let mut back = [0u8; 16];
    tokio::time::timeout(Duration::from_secs(20), stream.read_exact(&mut back))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&back, b"via the selector");

    let mut udp = chain_group
        .connect_udp_bidirectional(&resolver, remote_location)
        .await
        .unwrap();
    let reply = crate::quic_outbound::testing::udp_echo_exchange(&mut udp, b"udp via the selector")
        .await
        .unwrap();
    assert_eq!(reply, b"udp via the selector");
    assert_eq!(server.stats.sessions.load(Ordering::SeqCst), 1);
}

/// Keenetic's camouflage mode: the request must carry the secret as the
/// URI's query string. Without it, or with the wrong one, the server is a
/// web server answering 404, and the error says what that means without
/// repeating the secret.
#[tokio::test]
async fn a_camouflaged_server_needs_its_secret_on_the_request() {
    const SECRET: &str = "0123abcd";
    let server = testing::start(Options {
        camouflage_secret: Some(SECRET),
        ..Options::default()
    })
    .await;

    let plain = connector(&server, vec![SstpAuthMethod::Mschapv2], PASSWORD);
    let err = tcp_echo(&plain, b"x").await.unwrap_err();
    assert!(
        err.to_string().contains("404") && err.to_string().contains("set camouflage_secret"),
        "{err}"
    );

    let mut wrong = config_for(&server, vec![SstpAuthMethod::Mschapv2], PASSWORD);
    wrong.camouflage_secret = Some("not-it".to_string().into());
    let wrong = SstpConnector::new(NetLocation::from(server.address), wrong, None, true).unwrap();
    let err = tcp_echo(&wrong, b"x").await.unwrap_err();
    let text = err.to_string();
    assert!(text.contains("secret may be wrong"), "{text}");
    assert!(!text.contains("not-it"), "{text}");

    let mut right = config_for(&server, vec![SstpAuthMethod::Mschapv2], PASSWORD);
    right.camouflage_secret = Some(SECRET.to_string().into());
    let right = SstpConnector::new(NetLocation::from(server.address), right, None, true).unwrap();
    tcp_echo(&right, b"camouflaged").await.unwrap();
    assert_eq!(server.stats.sessions.load(Ordering::SeqCst), 1);
}

/// A name whose first address refuses: the next is tried, within the one
/// negotiation deadline, as the other outbounds do.
#[derive(Debug)]
struct DeadThenLive {
    dead: SocketAddr,
    live: SocketAddr,
}

impl Resolver for DeadThenLive {
    fn resolve_location(
        &self,
        _location: &NetLocation,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>>
    {
        let (dead, live) = (self.dead, self.live);
        Box::pin(async move { Ok(vec![dead, live]) })
    }
}

#[tokio::test]
async fn the_next_resolved_address_is_tried_when_the_first_refuses() {
    let server = testing::start(Options::default()).await;
    let dead = crate::quic_outbound::testing::reserve_tcp_port();
    let resolver: Arc<dyn Resolver> = Arc::new(DeadThenLive {
        dead,
        live: server.address,
    });
    let config = config_for(&server, vec![SstpAuthMethod::Mschapv2], PASSWORD);
    let connector = SstpConnector::new(
        NetLocation::from_str("sstp.test:443", None).unwrap(),
        config,
        None,
        true,
    )
    .unwrap();
    let mut stream = connector
        .connect_tcp(&resolver, echo())
        .await
        .unwrap()
        .client_stream;
    stream.write_all(b"second address").await.unwrap();
    let mut back = [0u8; 14];
    tokio::time::timeout(Duration::from_secs(20), stream.read_exact(&mut back))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&back, b"second address");
}

/// The server's LCP Terminate-Request is answered with a Terminate-Ack
/// before the session ends, and the next connection opens a new one.
#[tokio::test]
async fn a_terminate_request_is_acked_before_the_session_ends() {
    let server = testing::start(Options::default()).await;
    let connector = connector(&server, vec![SstpAuthMethod::Mschapv2], PASSWORD);
    tcp_echo(&connector, b"first").await.unwrap();
    server.stats.terminate.notify_waiters();
    wait_until_dead(&connector).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while server.stats.terminate_acks.load(Ordering::SeqCst) == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the server never got its Terminate-Ack"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tcp_echo(&connector, b"second").await.unwrap();
    assert_eq!(server.stats.sessions.load(Ordering::SeqCst), 2);
}

/// A first address that drops SYNs, rather than refusing: the attempt is
/// bounded, so the next address is tried with most of the negotiation
/// deadline left. The stall is a listener whose backlog is full, after
/// which the kernel drops further SYNs instead of answering them.
#[tokio::test]
async fn a_stalled_first_address_is_abandoned_for_the_next() {
    let server = testing::start(Options::default()).await;
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let blackhole = socket.listen(1).unwrap();
    let stalled = blackhole.local_addr().unwrap();
    // Fill the backlog and never accept; these stay open for the test.
    let mut fillers = Vec::new();
    for _ in 0..8 {
        if let Ok(Ok(c)) = tokio::time::timeout(
            Duration::from_millis(200),
            tokio::net::TcpStream::connect(stalled),
        )
        .await
        {
            fillers.push(c);
        }
    }
    let resolver: Arc<dyn Resolver> = Arc::new(DeadThenLive {
        dead: stalled,
        live: server.address,
    });
    let config = config_for(&server, vec![SstpAuthMethod::Mschapv2], PASSWORD);
    let mut connector = SstpConnector::new(
        NetLocation::from_str("sstp.test:443", None).unwrap(),
        config,
        None,
        true,
    )
    .unwrap();
    connector.connect_attempt_timeout(Duration::from_millis(500));

    let started = tokio::time::Instant::now();
    let mut stream = tokio::time::timeout(
        Duration::from_secs(20),
        connector.connect_tcp(&resolver, echo()),
    )
    .await
    .expect("the stalled address held the whole connect")
    .unwrap()
    .client_stream;
    stream.write_all(b"past the stall").await.unwrap();
    let mut back = [0u8; 14];
    tokio::time::timeout(Duration::from_secs(20), stream.read_exact(&mut back))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&back, b"past the stall");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the fallback took {:?}",
        started.elapsed()
    );
    drop(fillers);
    drop(blackhole);
}
