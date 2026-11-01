//! End to end: the OpenConnect connector against the server double in
//! `testing.rs`, TCP and UDP echoed through the whole path.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests: a panic is the failure report"
)]

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::OpenConnectConnector;
use super::testing::{self, ECHO_PORT, Options, SERVER_IP, SERVER_IP6, TestServer};
use crate::address::{NetLocation, ResolvedLocation};
use crate::config::{OpenConnectClientConfig, SstpTlsConfig};
use crate::option_util::{NoneOrOne, NoneOrSome};
use crate::resolver::Resolver;
use crate::tcp::terminal_connector::TerminalConnector;

const PASSWORD: &str = "correct horse";

fn config_for(server: &TestServer, password: &str) -> OpenConnectClientConfig {
    OpenConnectClientConfig {
        username: "alice".into(),
        password: password.to_string().into(),
        group: None,
        path: "/".into(),
        mtu: 1500,
        tls: SstpTlsConfig {
            verify: false,
            server_fingerprints: NoneOrSome::One(server.fingerprint.clone()),
            sni_hostname: NoneOrOne::Unspecified,
        },
        camouflage_secret: None,
    }
}

fn connector_with(server: &TestServer, config: OpenConnectClientConfig) -> OpenConnectConnector {
    OpenConnectConnector::new(NetLocation::from(server.address), config, None, true).unwrap()
}

fn connector(server: &TestServer) -> OpenConnectConnector {
    connector_with(server, config_for(server, PASSWORD))
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

fn echo6() -> ResolvedLocation {
    ResolvedLocation::new(NetLocation::from(SocketAddr::new(
        IpAddr::V6(SERVER_IP6),
        ECHO_PORT,
    )))
}

async fn tcp_echo_to(
    connector: &OpenConnectConnector,
    target: ResolvedLocation,
    payload: &[u8],
) -> std::io::Result<()> {
    let mut stream = connector
        .connect_tcp(&resolver(), target)
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

async fn tcp_echo(connector: &OpenConnectConnector, payload: &[u8]) -> std::io::Result<()> {
    tcp_echo_to(connector, echo(), payload).await
}

fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 + i / 251) as u8).collect()
}

async fn wait_until_dead(connector: &OpenConnectConnector) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while connector.session_alive().await {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the session did not end"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn wait_for(counter: &AtomicUsize, at_least: usize, what: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while counter.load(Ordering::SeqCst) < at_least {
        assert!(tokio::time::Instant::now() < deadline, "{what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn tcp_crosses_the_tunnel() {
    let server = testing::start(Options::default()).await;
    let connector = connector(&server);
    tcp_echo(&connector, &payload(256 * 1024)).await.unwrap();
    assert_eq!(server.stats.logins.load(Ordering::SeqCst), 1);
    assert_eq!(server.stats.sessions.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn udp_crosses_the_tunnel() {
    let server = testing::start(Options::default()).await;
    let connector = connector(&server);
    let mut stream = connector
        .connect_udp_bidirectional(&resolver(), echo())
        .await
        .unwrap();
    let reply = crate::quic_outbound::testing::udp_echo_exchange(&mut stream, b"a datagram")
        .await
        .unwrap();
    assert_eq!(reply, b"a datagram");
}

/// ocserv assigns an IPv6 address beside the IPv4 one when configured to;
/// a destination of either family is then carried. Without one, an IPv6
/// destination is refused by saying what the session carries.
#[tokio::test]
async fn ipv6_destinations_cross_when_the_server_assigns_an_address() {
    let server = testing::start(Options {
        ipv6: true,
        ..Options::default()
    })
    .await;
    let dual = connector(&server);
    tcp_echo_to(&dual, echo6(), b"six").await.unwrap();
    tcp_echo(&dual, b"four").await.unwrap();
    assert_eq!(server.stats.sessions.load(Ordering::SeqCst), 1);

    let four_only = testing::start(Options::default()).await;
    let four = connector(&four_only);
    let err = tcp_echo_to(&four, echo6(), b"six").await.unwrap_err();
    assert!(err.to_string().contains("IPv4 only"), "{err}");
}

/// Even when the server echoes what was sent, as a careless gateway
/// might, the error does not.
#[tokio::test]
async fn a_wrong_password_fails_without_the_password_in_the_error() {
    let server = testing::start(Options {
        echo_credentials: true,
        ..Options::default()
    })
    .await;
    let wrong = "not the password";
    let connector = connector_with(&server, config_for(&server, wrong));
    let err = tcp_echo(&connector, b"x").await.unwrap_err();
    let text = err.to_string();
    assert!(text.contains("authentication failed"), "{text}");
    assert!(!text.contains(wrong) && !text.contains("alice"), "{text}");
    let again = tcp_echo(&connector, b"x").await.unwrap_err();
    assert!(again.to_string().contains("cooldown"), "{again}");
    assert_eq!(server.stats.logins.load(Ordering::SeqCst), 0);
}

/// A server that asks for a second password gets a refusal naming the
/// field, not a guess.
#[tokio::test]
async fn a_second_factor_is_named_and_refused() {
    let server = testing::start(Options {
        second_password: true,
        echo_credentials: true,
        ..Options::default()
    })
    .await;
    let connector = connector(&server);
    let err = tcp_echo(&connector, b"x").await.unwrap_err();
    let text = err.to_string();
    assert!(text.contains("secondary_password"), "{text}");
    assert!(text.contains("Password2"), "{text}");
    // The form's label echoed the password; the error does not.
    assert!(!text.contains(PASSWORD), "{text}");
}

/// A server that asks for the password again after taking one wants a
/// challenge answer or a one-time code, not the same password: refused by
/// saying so, with the server's own prompt, and the password is not sent
/// twice.
#[tokio::test]
async fn a_repeated_password_prompt_is_refused() {
    let server = testing::start(Options {
        ask_password_again: true,
        ..Options::default()
    })
    .await;
    let err = tcp_echo(&connector(&server), b"x").await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(err.to_string().contains("password again"), "{err}");
    assert!(err.to_string().contains("Enter the next token"), "{err}");
    assert_eq!(server.stats.logins.load(Ordering::SeqCst), 0);
}

/// The server's message is redacted before its line breaks are flattened:
/// a password that spans a line, echoed back, must not survive as two
/// words with a space between.
#[tokio::test]
async fn a_password_with_a_line_break_echoed_in_the_retry_form_is_redacted() {
    const TWO_LINES: &str = "first\nsecond";
    let server = testing::start(Options {
        password: TWO_LINES,
        ask_password_again: true,
        password_again_message: "Login failed for first\nsecond. Please enter your password.",
        ..Options::default()
    })
    .await;
    let config = config_for(&server, TWO_LINES);
    let err = tcp_echo(&connector_with(&server, config), b"x")
        .await
        .unwrap_err();
    let text = err.to_string();
    assert!(text.contains("[redacted]"), "{text}");
    assert!(
        !text.contains("first second") && !text.contains(TWO_LINES),
        "{text}"
    );
}

/// ocserv answers a wrong password with the same password-only form, no
/// `<error>`, and "Login failed." in the message (seen live, 2026-11-02):
/// the error carries that text, so the user reads a refused login rather
/// than an unsupported second factor, and never the password.
#[tokio::test]
async fn ocservs_login_failed_form_is_reported_as_the_refusal_it_is() {
    let server = testing::start(Options {
        ask_password_again: true,
        password_again_message: "Login failed.\nPlease enter your password.",
        ..Options::default()
    })
    .await;
    let err = tcp_echo(&connector(&server), b"x").await.unwrap_err();
    let text = err.to_string();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(text.contains("did not accept the login"), "{text}");
    assert!(text.contains("Login failed."), "{text}");
    assert!(!text.contains(PASSWORD), "{text}");
    assert_eq!(server.stats.logins.load(Ordering::SeqCst), 0);
}

/// A DPD request whose echo would not fit one TLS record gets a bare
/// response: still an answer, still one record.
#[tokio::test]
async fn a_big_dpd_request_gets_a_bare_answer() {
    let server = testing::start(Options::default()).await;
    let connector = connector(&server);
    tcp_echo(&connector, b"x").await.unwrap();
    let records = server.stats.client_records.load(Ordering::SeqCst);
    let frames = server.stats.client_frames.load(Ordering::SeqCst);
    server.stats.big_dpd.notify_waiters();
    wait_for(&server.stats.client_dpd_responses, 1, "no DPD response").await;
    assert!(connector.session_alive().await);
    let records = server.stats.client_records.load(Ordering::SeqCst) - records;
    let frames = server.stats.client_frames.load(Ordering::SeqCst) - frames;
    assert_eq!((frames, records), (1, 1), "one bare response in one record");
}

#[tokio::test]
async fn the_group_is_selected_or_the_first_offered() {
    let server = testing::start(Options {
        groups: vec!["Route", "All"],
        ..Options::default()
    })
    .await;
    let mut config = config_for(&server, PASSWORD);
    config.group = Some("All".into());
    tcp_echo(&connector_with(&server, config), b"all")
        .await
        .unwrap();
    tcp_echo(&connector(&server), b"first").await.unwrap();
    assert_eq!(
        *server.stats.groups_selected.lock().unwrap(),
        ["All", "Route"]
    );

    let mut config = config_for(&server, PASSWORD);
    config.group = Some("Nope".into());
    let err = tcp_echo(&connector_with(&server, config), b"x")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("\"Route\", \"All\""), "{err}");
}

/// The cookie survives the session: a tunnel that dropped comes back with
/// `CONNECT` alone, as `cstp_reconnect` does (`cstp.c:785-800`).
#[tokio::test]
async fn the_cookie_is_reused_after_a_server_disconnect() {
    let server = testing::start(Options::default()).await;
    let connector = connector(&server);
    tcp_echo(&connector, b"first").await.unwrap();
    server.stats.disconnect.notify_waiters();
    wait_until_dead(&connector).await;
    tcp_echo(&connector, b"second").await.unwrap();
    assert_eq!(server.stats.sessions.load(Ordering::SeqCst), 2);
    assert_eq!(
        server.stats.logins.load(Ordering::SeqCst),
        1,
        "no second login"
    );
}

/// A cookie the server no longer accepts gets a 401 to `CONNECT`
/// (`cstp.c:379-380`); the client authenticates again, once.
#[tokio::test]
async fn a_refused_cookie_is_followed_by_a_fresh_login() {
    let server = testing::start(Options::default()).await;
    let connector = connector(&server);
    tcp_echo(&connector, b"first").await.unwrap();
    connector.network_changed().await;
    wait_until_dead(&connector).await;
    server
        .stats
        .refuse_next_cookie
        .store(true, Ordering::SeqCst);
    tcp_echo(&connector, b"second").await.unwrap();
    assert_eq!(server.stats.logins.load(Ordering::SeqCst), 2);
    assert_eq!(server.stats.sessions.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_terminate_ends_the_session_and_the_next_connection_reconnects() {
    let server = testing::start(Options::default()).await;
    let connector = connector(&server);
    tcp_echo(&connector, b"first").await.unwrap();
    server.stats.terminate.notify_waiters();
    wait_until_dead(&connector).await;
    tcp_echo(&connector, b"second").await.unwrap();
    assert_eq!(server.stats.sessions.load(Ordering::SeqCst), 2);
}

/// Camouflage: the request must carry the secret as the URI's query.
/// Without it, or with the wrong one, the server is a web server
/// answering 404, and the error says what that means without repeating
/// the secret.
#[tokio::test]
async fn a_camouflaged_server_needs_its_secret_on_the_first_request() {
    const SECRET: &str = "0123abcd";
    let server = testing::start(Options {
        camouflage_secret: Some(SECRET),
        ..Options::default()
    })
    .await;

    let err = tcp_echo(&connector(&server), b"x").await.unwrap_err();
    assert!(
        err.to_string().contains("404") && err.to_string().contains("set camouflage_secret"),
        "{err}"
    );

    let mut wrong = config_for(&server, PASSWORD);
    wrong.camouflage_secret = Some("not-it".to_string().into());
    let err = tcp_echo(&connector_with(&server, wrong), b"x")
        .await
        .unwrap_err();
    let text = err.to_string();
    assert!(text.contains("secret may be wrong"), "{text}");
    assert!(!text.contains("not-it"), "{text}");

    let mut right = config_for(&server, PASSWORD);
    right.camouflage_secret = Some(SECRET.to_string().into());
    let connector = connector_with(&server, right);
    tcp_echo(&connector, b"camouflaged").await.unwrap();
    // ocserv under camouflage answers a refused cookie on CONNECT with 405
    // (`worker-auth.c:1300-1304`); that is a refused cookie, not a wrong
    // secret, and the client logs in again.
    server.stats.disconnect.notify_waiters();
    wait_until_dead(&connector).await;
    server
        .stats
        .refuse_next_cookie
        .store(true, Ordering::SeqCst);
    tcp_echo(&connector, b"relogin").await.unwrap();
    assert_eq!(server.stats.logins.load(Ordering::SeqCst), 2);
    // The reconnect with the cookie makes no POST, so it carries no secret:
    // ocserv gates CONNECT on the cookie and would 404 a query on it.
    server.stats.disconnect.notify_waiters();
    wait_until_dead(&connector).await;
    tcp_echo(&connector, b"again").await.unwrap();
    assert_eq!(server.stats.sessions.load(Ordering::SeqCst), 3);
    assert_eq!(server.stats.logins.load(Ordering::SeqCst), 2);

    // With `camouflage_realm` set, ocserv's refusal is a 401 with a realm
    // before any credential went out: the hint, not "wrong password".
    let realm = testing::start(Options {
        camouflage_secret: Some(SECRET),
        camouflage_realm: true,
        ..Options::default()
    })
    .await;
    let unaware = connector_with(&realm, config_for(&realm, PASSWORD));
    let err = tcp_echo(&unaware, b"x").await.unwrap_err();
    assert!(
        err.to_string().contains("401") && err.to_string().contains("set camouflage_secret"),
        "{err}"
    );
}

#[tokio::test]
async fn a_certificate_that_does_not_match_the_pin_is_refused() {
    let pinned = testing::start(Options::default()).await;
    let other = testing::start(Options::default()).await;
    let mut connector = connector(&pinned);
    connector.point_at(NetLocation::from(other.address));
    let err = tcp_echo(&connector, b"x").await.unwrap_err();
    assert!(err.to_string().contains("fingerprint"), "{err}");
    assert_eq!(other.stats.logins.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn connections_share_one_session() {
    let server = testing::start(Options::default()).await;
    let connector = Arc::new(connector(&server));
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

/// The server's DPD request is answered with its contents.
#[tokio::test]
async fn a_dpd_request_is_answered() {
    let server = testing::start(Options::default()).await;
    let connector = connector(&server);
    tcp_echo(&connector, b"x").await.unwrap();
    server.stats.dpd.notify_waiters();
    wait_for(&server.stats.client_dpd_responses, 1, "no DPD response").await;
    assert!(connector.session_alive().await);
}

/// With nothing received for the DPD interval the client probes, and with
/// nothing for twice it the session is dead (`mainloop.c:454-492`).
#[tokio::test]
async fn a_silent_server_is_probed_and_then_given_up() {
    let server = testing::start(Options {
        dpd: 1,
        ..Options::default()
    })
    .await;
    let connector = connector(&server);
    tcp_echo(&connector, b"x").await.unwrap();
    server.stats.mute.store(true, Ordering::SeqCst);
    let started = tokio::time::Instant::now();
    wait_until_dead(&connector).await;
    assert!(
        server.stats.client_dpd_requests.load(Ordering::SeqCst) >= 1,
        "the client probed before giving up"
    );
    assert!(
        started.elapsed() >= Duration::from_millis(1500),
        "{:?}",
        started.elapsed()
    );
}

/// With nothing sent for the keepalive interval the client sends one.
#[tokio::test]
async fn an_idle_client_sends_keepalives() {
    let server = testing::start(Options {
        keepalive: 1,
        dpd: 0,
        ..Options::default()
    })
    .await;
    let connector = connector(&server);
    tcp_echo(&connector, b"x").await.unwrap();
    wait_for(&server.stats.client_keepalives, 1, "no keepalive").await;
    assert!(connector.session_alive().await);
}

/// ocserv ends a session whose TLS record holds other than one frame, so
/// every frame is its own record: as many records as frames.
#[tokio::test]
async fn every_frame_is_its_own_tls_record() {
    let server = testing::start(Options::default()).await;
    let connector = connector(&server);
    tcp_echo(&connector, b"warm up").await.unwrap();
    let records = server.stats.client_records.load(Ordering::SeqCst);
    let frames = server.stats.client_frames.load(Ordering::SeqCst);
    tcp_echo(&connector, &payload(1024 * 1024)).await.unwrap();
    // Everything the client wrote is in: one more frame, one more record.
    tcp_echo(&connector, b"flush").await.unwrap();
    let records = server.stats.client_records.load(Ordering::SeqCst) - records;
    let frames = server.stats.client_frames.load(Ordering::SeqCst) - frames;
    assert!(frames > 100, "{frames} frames");
    assert_eq!(records, frames, "{frames} frames in {records} records");
}

/// The same rule under backpressure: the server stops reading, the
/// client's socket fills, and a frame must still go out whole. (The TLS
/// stream drains each record before the next write, so rustls's buffer
/// limit never truncates a frame here; this guards the rule, not that
/// mechanism, and fails on the batching defect as the test above does.)
#[tokio::test]
async fn every_frame_is_its_own_tls_record_under_backpressure() {
    let server = testing::start(Options {
        receive_buffer: Some(64 * 1024),
        ..Options::default()
    })
    .await;
    let connector = connector(&server);
    tcp_echo(&connector, b"warm up").await.unwrap();
    let records = server.stats.client_records.load(Ordering::SeqCst);
    let frames = server.stats.client_frames.load(Ordering::SeqCst);
    server.stats.stall_ms.store(1500, Ordering::SeqCst);
    tcp_echo(&connector, &payload(4 * 1024 * 1024))
        .await
        .unwrap();
    tcp_echo(&connector, b"flush").await.unwrap();
    let records = server.stats.client_records.load(Ordering::SeqCst) - records;
    let frames = server.stats.client_frames.load(Ordering::SeqCst) - frames;
    assert!(frames > 100, "{frames} frames");
    assert_eq!(records, frames, "{frames} frames in {records} records");
}

/// A server that kept its own larger MTU sends packets past the
/// configured one; openconnect accepts them (`cstp.c:961-964`), and so
/// does this: the configured MTU caps what goes out, not what comes in.
#[tokio::test]
async fn an_inbound_packet_past_the_configured_mtu_is_delivered() {
    let server = testing::start(Options {
        link_mtu: 1500,
        ..Options::default()
    })
    .await;
    let mut config = config_for(&server, PASSWORD);
    config.mtu = 1280;
    let connector = connector_with(&server, config);
    let mut stream = connector
        .connect_udp_bidirectional(&resolver(), echo())
        .await
        .unwrap();
    let reply = crate::quic_outbound::testing::udp_echo_exchange(&mut stream, b"small")
        .await
        .unwrap();
    assert_eq!(reply, b"small");
    server.stats.big_packet.notify_waiters();
    let mut buf = vec![0u8; 65535];
    let mut read_buf = tokio::io::ReadBuf::new(&mut buf);
    let read = std::future::poll_fn(|cx| {
        std::pin::Pin::new(&mut *stream).poll_read_message(cx, &mut read_buf)
    });
    tokio::time::timeout(Duration::from_secs(5), read)
        .await
        .expect("the large datagram was dropped")
        .unwrap();
    assert_eq!(read_buf.filled().len(), 1400);
}

/// A frame of a type neither side knows is ignored, as ocserv ignores it.
#[tokio::test]
async fn an_unknown_frame_type_is_ignored() {
    let server = testing::start(Options::default()).await;
    let connector = connector(&server);
    let mut stream = connector
        .connect_tcp(&resolver(), echo())
        .await
        .unwrap()
        .client_stream;
    stream.write_all(b"before").await.unwrap();
    let mut back = [0u8; 6];
    stream.read_exact(&mut back).await.unwrap();
    server.stats.unknown_frame.notify_waiters();
    tokio::time::sleep(Duration::from_millis(100)).await;
    stream.write_all(b"after").await.unwrap();
    let mut back = [0u8; 5];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut back))
        .await
        .expect("the session died on an unknown frame")
        .unwrap();
    assert_eq!(&back, b"after");
    assert!(connector.session_alive().await);
}

#[tokio::test]
async fn a_network_change_ends_the_session() {
    let server = testing::start(Options::default()).await;
    let connector = connector(&server);
    tcp_echo(&connector, b"first").await.unwrap();
    connector.network_changed().await;
    wait_until_dead(&connector).await;
    tcp_echo(&connector, b"second").await.unwrap();
    assert_eq!(server.stats.sessions.load(Ordering::SeqCst), 2);
}

/// The outbound going away says goodbye: a DISCONNECT with the user
/// reason, so the server frees the session.
#[tokio::test]
async fn dropping_the_outbound_sends_a_goodbye() {
    let server = testing::start(Options::default()).await;
    let connector = connector(&server);
    tcp_echo(&connector, b"x").await.unwrap();
    drop(connector);
    wait_for(&server.stats.byes, 1, "no goodbye").await;
}

/// The production path, end to end: the config text through the loader,
/// the selector `create_tcp_client_proxy_selector` builds, the chain's
/// dial, the tunnel.
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
            type: openconnect
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
