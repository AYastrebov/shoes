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
    let config = SstpClientConfig {
        username: "alice".into(),
        password: password.to_string().into(),
        auth,
        mtu: 1500,
        tls: SstpTlsConfig {
            verify: false,
            server_fingerprints: NoneOrSome::One(server.fingerprint.clone()),
            sni_hostname: NoneOrOne::Unspecified,
        },
    };
    SstpConnector::new(NetLocation::from(server.address), config, None, true).unwrap()
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
