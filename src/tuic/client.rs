//! The TUIC v5 client outbound.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use log::debug;

use crate::address::{NetLocation, ResolvedLocation};
use crate::async_stream::{AsyncMessageStream, AsyncStream};
use crate::config::{ClientQuicConfig, TuicUdpRelayMode};
use crate::quic_outbound::QuicOutboundSettings;
use crate::quic_outbound::connection::{ConnectionAuthenticator, LiveConnection};
use crate::quic_outbound::datagram_router::DatagramRouting;
use crate::quic_stream::QuicStream;
use crate::quic_transport::CongestionControl;
use crate::resolver::Resolver;
use crate::tcp::tcp_handler::TcpClientSetupResult;
use crate::tcp::terminal_connector::TerminalConnector;

use super::frame::{encode_authenticate, encode_connect, encode_heartbeat};

/// One relaying task -- a TCP stream or a UDP association -- counted while
/// it lives, so the connection's heartbeat knows when it is owed.
pub(crate) struct LiveTask(Arc<AtomicUsize>);

impl LiveTask {
    pub(crate) fn new(count: &Arc<AtomicUsize>) -> Self {
        count.fetch_add(1, Ordering::Relaxed);
        Self(count.clone())
    }
}

impl Drop for LiveTask {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Each connection's count of live relaying tasks, by quinn's stable id.
///
/// Per connection, not per outbound: the authenticator outlives reconnects,
/// so one shared count would keep a replacement connection heartbeating for
/// tasks still held on the one it replaced. A task counts against the
/// connection it was opened on, and the entry goes when that connection does.
#[derive(Debug, Default)]
pub(crate) struct LiveCounts(
    parking_lot::Mutex<std::collections::HashMap<usize, Arc<AtomicUsize>>>,
);

impl LiveCounts {
    pub(crate) fn of(&self, connection: &quinn::Connection) -> Arc<AtomicUsize> {
        self.0
            .lock()
            .entry(connection.stable_id())
            .or_default()
            .clone()
    }

    fn forget(&self, connection: &quinn::Connection) {
        self.0.lock().remove(&connection.stable_id());
    }
}

/// The connection's heartbeat, as the reference client sends it: one task per
/// connection, a Heartbeat every interval while any relaying task on it is
/// live, none while it is idle (TU-D10). One per UDP association, as before,
/// sent N for N associations and none at all for TCP streams.
async fn heartbeat(connection: quinn::Connection, counts: Arc<LiveCounts>, interval: Duration) {
    let live = counts.of(&connection);
    let mut ticker = tokio::time::interval(interval);
    ticker.tick().await; // the first tick fires immediately
    loop {
        tokio::select! {
            _ = connection.closed() => {
                counts.forget(&connection);
                return;
            }
            _ = ticker.tick() => {}
        }
        if live.load(Ordering::Relaxed) == 0 {
            continue;
        }
        if connection
            .send_datagram(Bytes::from(encode_heartbeat()))
            .is_err()
        {
            return;
        }
    }
}

/// Derives the authentication token and sends the Authenticate command, then
/// starts the connection's heartbeat.
#[derive(Debug)]
struct TuicAuthenticator {
    uuid: [u8; 16],
    password: String,
    live: Arc<LiveCounts>,
    heartbeat_interval: Duration,
}

#[async_trait]
impl ConnectionAuthenticator for TuicAuthenticator {
    async fn authenticate(&self, connection: &quinn::Connection) -> std::io::Result<()> {
        // The token is exported from the live TLS session with the UUID as the
        // label and the raw password as the context, which is exactly what the
        // server computes to compare against.
        let mut token = [0u8; 32];
        connection
            .export_keying_material(&mut token, &self.uuid, self.password.as_bytes())
            .map_err(|e| {
                std::io::Error::other(format!("failed to export TUIC keying material: {e:?}"))
            })?;

        let mut stream = connection.open_uni().await.map_err(|e| {
            std::io::Error::other(format!("failed to open the TUIC auth stream: {e}"))
        })?;
        stream
            .write_all(&encode_authenticate(&self.uuid, &token))
            .await
            .map_err(|e| std::io::Error::other(format!("failed to send Authenticate: {e}")))?;
        stream
            .finish()
            .map_err(|e| std::io::Error::other(format!("failed to finish the auth stream: {e}")))?;

        // There is no response: the specification defines none. A wrong UUID or
        // token shows up later, as the server closing the connection.
        debug!("TUIC Authenticate sent");
        tokio::spawn(heartbeat(
            connection.clone(),
            self.live.clone(),
            self.heartbeat_interval,
        ));
        Ok(())
    }
}

pub struct TuicConnector {
    connection: LiveConnection,
    udp_enabled: bool,
    udp_relay_mode: TuicUdpRelayMode,
    /// The authenticator's copy is the one the heartbeat reads; this one is
    /// for the tests that check the configured value arrived.
    #[cfg(test)]
    heartbeat_interval: Duration,
    live: Arc<LiveCounts>,
}

impl std::fmt::Debug for TuicConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TuicConnector")
            .field("server", &self.connection.settings().server)
            .field("udp_relay_mode", &self.udp_relay_mode)
            .field("congestion", &self.connection.settings().congestion)
            .finish()
    }
}

impl TuicConnector {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        server: NetLocation,
        uuid: [u8; 16],
        password: String,
        udp_enabled: bool,
        udp_relay_mode: TuicUdpRelayMode,
        heartbeat_interval: Duration,
        quic: ClientQuicConfig,
        bind_interface: Option<String>,
        congestion: CongestionControl,
    ) -> std::io::Result<Self> {
        let live = Arc::new(LiveCounts::default());
        let authenticator = Arc::new(TuicAuthenticator {
            uuid,
            password,
            live: live.clone(),
            heartbeat_interval,
        });

        let settings = QuicOutboundSettings {
            server,
            quic,
            bind_interface,
            // TUIC has no obfuscation layer of its own.
            obfs: None,
            // TUIC has no port hopping in its protocol; offering the
            // setting would offer something no real server understands.
            port_hopping: None,
            default_alpn: "h3",
            // The operator's choice, Cubic unless they made one.
            congestion,
        };

        Ok(Self {
            // One router per connection for both relay modes' replies:
            // datagrams in native mode, a uni stream per packet in quic mode,
            // keyed on the 16-bit association id (TU-D6).
            connection: LiveConnection::new(
                settings,
                authenticator,
                Some(DatagramRouting {
                    key_of: super::udp::assoc_key,
                    max_id: u32::from(u16::MAX),
                    uni_stream_limit: Some(super::udp::MAX_COMMAND_BYTES),
                }),
            ),
            udp_enabled,
            udp_relay_mode,
            #[cfg(test)]
            heartbeat_interval,
            live,
        })
    }

    /// Open a stream and send Connect.
    ///
    /// Reported as `ConnectionAborted` when the connection itself failed, so
    /// the caller can tell that apart and retry once.
    async fn open_tcp_stream_once(
        &self,
        resolver: &Arc<dyn Resolver>,
        location: &NetLocation,
    ) -> std::io::Result<QuicStream> {
        let connection = self.connection.get(resolver).await?;

        let (mut send, recv) = connection.open_bi().await.map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                format!("failed to open a QUIC stream: {e}"),
            )
        })?;

        send.write_all(&encode_connect(location))
            .await
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    format!("failed to send Connect: {e}"),
                )
            })?;

        Ok(QuicStream::from(send, recv).with_guard(LiveTask::new(&self.live.of(&connection))))
    }

    #[cfg(test)]
    fn connection_count(&self) -> usize {
        self.connection.connections_raised()
    }

    #[cfg(test)]
    pub(crate) fn heartbeat_interval(&self) -> Duration {
        self.heartbeat_interval
    }

    #[cfg(test)]
    pub(crate) fn udp_relay_mode(&self) -> TuicUdpRelayMode {
        self.udp_relay_mode
    }
}

#[async_trait]
impl TerminalConnector for TuicConnector {
    async fn connect_tcp(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        let location = target.into_location();
        debug!("TUIC: TCP connect to {location}");

        // One retry, for the window between the connection being handed out
        // and being used, in which the server can have gone away.
        let stream = match self.open_tcp_stream_once(resolver, &location).await {
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionAborted => {
                debug!("TUIC: connection died while opening a stream; retrying once");
                self.open_tcp_stream_once(resolver, &location).await?
            }
            other => other?,
        };

        // The server never answers a Connect. Payload follows the header
        // immediately, and a failure shows up as the stream being closed.
        Ok(TcpClientSetupResult {
            client_stream: Box::new(stream) as Box<dyn AsyncStream>,
            early_data: None,
        })
    }

    async fn connect_udp_bidirectional(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        if !self.udp_enabled {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "UDP is disabled for this TUIC outbound (udp_enabled: false)",
            ));
        }
        let (connection, router) = self.connection.get_with_datagrams(resolver).await?;
        let location = target.into_location();
        // The router allocates the id: only it knows which are in use.
        let (assoc_id, incoming) = router.register()?;
        let assoc_id = u16::try_from(assoc_id)
            .map_err(|_| std::io::Error::other("TUIC association id past 16 bits"))?;
        debug!("TUIC: UDP association {assoc_id} to {location}");

        let task = LiveTask::new(&self.live.of(&connection));
        Ok(Box::new(super::udp::TuicUdpSession::new(
            connection,
            router,
            assoc_id,
            incoming,
            location,
            self.udp_relay_mode,
            task,
        )))
    }

    fn supports_udp(&self) -> bool {
        self.udp_enabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic_outbound::testing::*;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const TEST_UUID: &str = "b0e80a62-8a51-47f0-91f1-f0f7faf8d9d4";

    fn uuid_bytes(uuid: &str) -> [u8; 16] {
        *uuid.parse::<crate::config::Uuid>().unwrap().as_bytes()
    }
    const SERVER_PASSWORD: &str = "test password";

    async fn spawn_server() -> SocketAddr {
        spawn_server_with(test_resolver()).await
    }

    async fn spawn_server_with(resolver: Arc<dyn Resolver>) -> SocketAddr {
        let cert = generate_certificate();
        let bind_address = reserve_udp_port();

        let uuid: &'static [u8] = Box::leak(
            crate::uuid_util::parse_uuid(TEST_UUID)
                .unwrap()
                .into_boxed_slice(),
        );

        crate::tuic::start_tuic_server(
            crate::quic_transport::QuicListenerSettings {
                bind_address,
                quic_server_config: quic_server_config(&cert, &["h3".to_string()]),
                num_endpoints: 1,
                obfs: None,
            },
            uuid,
            Box::leak(SERVER_PASSWORD.to_string().into_boxed_str()),
            direct_selector(resolver.clone()),
            resolver,
            false,
            CongestionControl::Cubic,
            Duration::from_secs(300),
            Default::default(),
        )
        .await
        .unwrap();

        bind_address
    }

    /// The connector dials with the controller its config chose.
    #[test]
    fn test_the_connector_asks_for_the_configured_controller() {
        for congestion in [
            CongestionControl::Cubic,
            CongestionControl::NewReno,
            CongestionControl::Bbr,
        ] {
            let connector = TuicConnector::new(
                NetLocation::from_str("127.0.0.1:1", None).unwrap(),
                uuid_bytes(TEST_UUID),
                "pw".to_string(),
                true,
                TuicUdpRelayMode::Native,
                Duration::from_millis(10_000),
                client_quic_config(),
                None,
                congestion,
            )
            .unwrap();
            assert_eq!(connector.connection.settings().congestion, congestion);
        }
    }

    fn connector(server: SocketAddr, uuid: &str, password: &str) -> TuicConnector {
        connector_with_mode(server, uuid, password, TuicUdpRelayMode::Native)
    }

    fn connector_with_mode(
        server: SocketAddr,
        uuid: &str,
        password: &str,
        mode: TuicUdpRelayMode,
    ) -> TuicConnector {
        TuicConnector::new(
            NetLocation::from_str(&server.to_string(), None).unwrap(),
            uuid_bytes(uuid),
            password.to_string(),
            true,
            mode,
            Duration::from_millis(10_000),
            client_quic_config(),
            None,
            CongestionControl::Cubic,
        )
        .unwrap()
    }

    fn target(addr: SocketAddr) -> ResolvedLocation {
        NetLocation::from_str(&addr.to_string(), None)
            .unwrap()
            .into()
    }

    #[test]
    fn test_keeps_its_configured_settings() {
        let connector = TuicConnector::new(
            NetLocation::from_str("127.0.0.1:1", None).unwrap(),
            uuid_bytes(TEST_UUID),
            "password".to_string(),
            true,
            TuicUdpRelayMode::Quic,
            Duration::from_millis(3000),
            client_quic_config(),
            None,
            CongestionControl::Cubic,
        )
        .unwrap();
        assert_eq!(connector.udp_relay_mode(), TuicUdpRelayMode::Quic);
        assert_eq!(connector.heartbeat_interval(), Duration::from_millis(3000));
    }

    #[tokio::test]
    async fn test_tcp_round_trip() {
        let server = spawn_server().await;
        let echo = spawn_tcp_echo().await;
        let resolver = test_resolver();
        let connector = connector(server, TEST_UUID, SERVER_PASSWORD);

        let result = connector
            .connect_tcp(&resolver, target(echo))
            .await
            .unwrap();

        assert!(
            result.early_data.is_none(),
            "TUIC servers never answer Connect, so there is no early data"
        );

        let mut stream = result.client_stream;
        stream.write_all(b"hello through tuic").await.unwrap();
        stream.flush().await.unwrap();
        let mut buf = [0u8; 18];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello through tuic");
    }

    #[tokio::test]
    async fn test_streams_share_one_authenticated_connection() {
        let server = spawn_server().await;
        let echo = spawn_tcp_echo().await;
        let resolver = test_resolver();
        let connector = connector(server, TEST_UUID, SERVER_PASSWORD);

        for i in 0..3 {
            let mut stream = connector
                .connect_tcp(&resolver, target(echo))
                .await
                .unwrap()
                .client_stream;
            let payload = format!("stream {i}");
            stream.write_all(payload.as_bytes()).await.unwrap();
            stream.flush().await.unwrap();
            let mut buf = vec![0u8; payload.len()];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf, payload.as_bytes());
        }
        assert_eq!(connector.connection_count(), 1);
    }

    /// The protocol defines no response to Connect and no rejection for bad
    /// credentials, so a wrong password surfaces as the server closing the
    /// stream rather than as an error from connect_tcp.
    #[tokio::test]
    async fn test_wrong_password_cannot_relay() {
        let server = spawn_server().await;
        let echo = spawn_tcp_echo().await;
        let resolver = test_resolver();
        let connector = connector(server, TEST_UUID, "the wrong password");

        let outcome = tokio::time::timeout(Duration::from_secs(10), async {
            let mut stream = connector
                .connect_tcp(&resolver, target(echo))
                .await?
                .client_stream;
            stream.write_all(b"ping").await?;
            stream.flush().await?;
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await
        })
        .await;

        match outcome {
            Ok(Err(_)) => {}
            Ok(Ok(_)) => panic!("a wrong password must not relay traffic"),
            Err(_) => panic!("must fail rather than hang"),
        }
    }

    #[tokio::test]
    async fn test_udp_round_trip_in_native_mode() {
        let server = spawn_server().await;
        let echo = spawn_udp_echo().await;
        let resolver = test_resolver();
        let connector = connector(server, TEST_UUID, SERVER_PASSWORD);

        let mut stream = connector
            .connect_udp_bidirectional(&resolver, target(echo))
            .await
            .unwrap();

        let reply = udp_echo_exchange(&mut stream, b"tuic udp").await.unwrap();
        assert_eq!(reply, b"tuic udp");
    }

    /// TU-D6: two associations on one connection do not take each other's
    /// replies. Each used to run its own reader on the shared connection and
    /// drop what was not its own, so while only the first was reading, every
    /// reply for the second was taken and thrown away. A reply lost on
    /// loopback is sent again; a stolen one never arrives however often, and
    /// the deadline reports it. Mirrors Hysteria2's test of the same router.
    async fn associations_do_not_steal(mode: TuicUdpRelayMode) {
        let server = spawn_server().await;
        let echo = spawn_udp_echo().await;
        let resolver = test_resolver();
        let connector = connector_with_mode(server, TEST_UUID, SERVER_PASSWORD, mode);

        let mut first = connector
            .connect_udp_bidirectional(&resolver, target(echo))
            .await
            .unwrap();
        let mut second = connector
            .connect_udp_bidirectional(&resolver, target(echo))
            .await
            .unwrap();
        assert_eq!(connector.connection_count(), 1, "one shared connection");

        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            std::future::poll_fn(|cx| {
                std::pin::Pin::new(&mut *second).poll_write_message(cx, &[2u8, 0xff])
            })
            .await
            .unwrap();
            let mut buf = [0u8; 64];
            let mut read = tokio::io::ReadBuf::new(&mut buf);
            let on_first = tokio::time::timeout(
                Duration::from_millis(250),
                std::future::poll_fn(|cx| {
                    std::pin::Pin::new(&mut *first).poll_read_message(cx, &mut read)
                }),
            )
            .await;
            assert!(
                on_first.is_err(),
                "{mode:?}: association 1 was handed a reply while only 2 had sent: {:?}",
                read.filled()
            );
            let mut buf = [0u8; 64];
            let mut read = tokio::io::ReadBuf::new(&mut buf);
            let on_second = tokio::time::timeout(
                Duration::from_millis(250),
                std::future::poll_fn(|cx| {
                    std::pin::Pin::new(&mut *second).poll_read_message(cx, &mut read)
                }),
            )
            .await;
            if on_second.is_ok() {
                assert_eq!(read.filled(), [2u8, 0xff]);
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "{mode:?}: association 2 never received its reply while 1 was reading"
            );
        }
    }

    #[tokio::test]
    async fn test_two_associations_do_not_steal_in_native_mode() {
        associations_do_not_steal(TuicUdpRelayMode::Native).await;
    }

    #[tokio::test]
    async fn test_two_associations_do_not_steal_in_quic_mode() {
        associations_do_not_steal(TuicUdpRelayMode::Quic).await;
    }

    /// TU-D10: the connection counts its live relaying tasks, TCP streams and
    /// UDP associations alike, which is what gates its one heartbeat.
    #[tokio::test]
    async fn test_live_tasks_count_streams_and_associations() {
        let server = spawn_server().await;
        let echo = spawn_udp_echo().await;
        let resolver = test_resolver();
        let connector = connector(server, TEST_UUID, SERVER_PASSWORD);
        let connection = connector.connection.get(&resolver).await.unwrap();
        let count = connector.live.of(&connection);
        let live = || count.load(Ordering::Relaxed);
        assert_eq!(live(), 0);

        let tcp = connector
            .connect_tcp(&resolver, target(echo))
            .await
            .unwrap();
        let udp = connector
            .connect_udp_bidirectional(&resolver, target(echo))
            .await
            .unwrap();
        assert_eq!(live(), 2);
        drop(tcp);
        assert_eq!(live(), 1);
        drop(udp);
        assert_eq!(live(), 0, "an idle connection owes no heartbeat");
    }

    /// A task counts against the connection it was opened on: one still held
    /// on a connection that was replaced does not keep the replacement
    /// heartbeating once the replacement's own tasks are gone.
    #[tokio::test]
    async fn test_a_replaced_connections_tasks_do_not_count_on_the_new_one() {
        let server = spawn_server().await;
        let echo = spawn_udp_echo().await;
        let resolver = test_resolver();
        let connector = connector(server, TEST_UUID, SERVER_PASSWORD);

        let old_connection = connector.connection.get(&resolver).await.unwrap();
        let held = connector
            .connect_udp_bidirectional(&resolver, target(echo))
            .await
            .unwrap();
        old_connection.close(0u32.into(), b"replaced");

        let tcp = connector
            .connect_tcp(&resolver, target(echo))
            .await
            .unwrap();
        let new_connection = connector.connection.get(&resolver).await.unwrap();
        assert_ne!(new_connection.stable_id(), old_connection.stable_id());
        assert_eq!(connector.connection_count(), 2);
        let new_count = connector.live.of(&new_connection);
        assert_eq!(new_count.load(Ordering::Relaxed), 1);
        drop(tcp);
        assert_eq!(
            new_count.load(Ordering::Relaxed),
            0,
            "the old connection's association must not count on the new one"
        );
        drop(held);
    }

    /// HY-D2, TUIC's half: an association's packets each go to the target
    /// they name ("Full Cone"), and every reply is labelled with its real
    /// source. The server used to pin an association to its first target's
    /// address and label replies with the name the client used.
    #[tokio::test]
    async fn test_one_association_reaches_two_targets_and_replies_carry_their_source() {
        let server = spawn_server_with(loopback_resolver()).await;
        let first = spawn_udp_echo().await;
        let second = spawn_udp_echo().await;
        let resolver = test_resolver();
        let connector = connector(server, TEST_UUID, SERVER_PASSWORD);
        let (connection, router) = connector
            .connection
            .get_with_datagrams(&resolver)
            .await
            .unwrap();
        let (assoc_id, incoming) = router.register().unwrap();
        let task = LiveTask::new(&connector.live.of(&connection));
        let mut session = crate::tuic::udp::TuicUdpSession::new(
            connection,
            router,
            u16::try_from(assoc_id).unwrap(),
            incoming,
            NetLocation::from_str(&first.to_string(), None).unwrap(),
            TuicUdpRelayMode::Native,
            task,
        );

        let reply = udp_echo_exchange_on(&mut session, b"to the first")
            .await
            .unwrap();
        assert_eq!(reply, b"to the first");
        assert_eq!(
            session.last_reply_address(),
            Some(&NetLocation::from_str(&first.to_string(), None).unwrap())
        );

        // Named, not addressed: the server resolves it (to loopback, by the
        // resolver it was given) and must label the reply with the address
        // the reply came from, not with the name.
        session.retarget(
            NetLocation::from_str(&format!("echo.test:{}", second.port()), None).unwrap(),
        );
        let reply = udp_echo_exchange_on(&mut session, b"to the second")
            .await
            .unwrap();
        assert_eq!(reply, b"to the second");
        assert_eq!(
            session.last_reply_address(),
            Some(&NetLocation::from_str(&second.to_string(), None).unwrap()),
            "the reply is labelled with its real source"
        );
    }

    #[tokio::test]
    async fn test_udp_carries_several_packets_over_one_association() {
        let server = spawn_server().await;
        let echo = spawn_udp_echo().await;
        let resolver = test_resolver();
        let connector = connector(server, TEST_UUID, SERVER_PASSWORD);

        let mut stream = connector
            .connect_udp_bidirectional(&resolver, target(echo))
            .await
            .unwrap();

        for i in 0..4u8 {
            let payload = vec![i; 48];
            let reply = udp_echo_exchange(&mut stream, &payload).await.unwrap();
            assert_eq!(reply, payload, "packet {i}");
        }
    }

    #[tokio::test]
    async fn test_large_udp_payload_is_fragmented_and_reassembled() {
        let server = spawn_server().await;
        let echo = spawn_udp_echo().await;
        let resolver = test_resolver();
        let connector = connector(server, TEST_UUID, SERVER_PASSWORD);

        let mut stream = connector
            .connect_udp_bidirectional(&resolver, target(echo))
            .await
            .unwrap();

        let payload: Vec<u8> = (0..4000u32).map(|i| i as u8).collect();
        let reply = udp_echo_exchange(&mut stream, &payload).await.unwrap();
        assert_eq!(reply, payload);
    }

    /// Sends a `quic`-mode Packet to `target` before Authenticate, the order
    /// a client may use when its first packet races the auth stream.
    #[derive(Debug)]
    struct PacketBeforeAuth {
        inner: TuicAuthenticator,
        target: NetLocation,
        payload: &'static [u8],
    }

    #[async_trait]
    impl ConnectionAuthenticator for PacketBeforeAuth {
        async fn authenticate(&self, connection: &quinn::Connection) -> std::io::Result<()> {
            let mut stream = connection.open_uni().await.map_err(std::io::Error::other)?;
            let mut packet = super::super::frame::encode_packet_header(
                7,
                0,
                1,
                0,
                self.payload.len() as u16,
                Some(&self.target),
            );
            packet.extend_from_slice(self.payload);
            stream
                .write_all(&packet)
                .await
                .map_err(std::io::Error::other)?;
            stream.finish().map_err(std::io::Error::other)?;
            // Let the Packet stream reach the server ahead of the auth stream.
            tokio::time::sleep(Duration::from_millis(100)).await;
            self.inner.authenticate(connection).await
        }
    }

    /// A Packet stream sent before Authenticate is held and relayed once the
    /// client authenticates. It used to be read and thrown away, which lost
    /// the first packet of a `quic`-mode association - often a DNS query.
    #[tokio::test]
    async fn test_a_packet_sent_before_auth_is_relayed_after_it() {
        let server = spawn_server().await;
        let echo = spawn_udp_echo().await;
        let resolver = test_resolver();

        let authenticator = Arc::new(PacketBeforeAuth {
            inner: TuicAuthenticator {
                uuid: crate::uuid_util::parse_uuid(TEST_UUID)
                    .unwrap()
                    .try_into()
                    .unwrap(),
                password: SERVER_PASSWORD.to_string(),
                live: Arc::new(LiveCounts::default()),
                heartbeat_interval: Duration::from_secs(10),
            },
            target: NetLocation::from_str(&echo.to_string(), None).unwrap(),
            payload: b"before auth",
        });
        let connection = LiveConnection::new(
            QuicOutboundSettings {
                server: NetLocation::from_str(&server.to_string(), None).unwrap(),
                quic: client_quic_config(),
                bind_interface: None,
                obfs: None,
                port_hopping: None,
                default_alpn: "h3",
                congestion: CongestionControl::Cubic,
            },
            authenticator,
            None,
        );
        let connection = connection.get(&resolver).await.unwrap();

        // The echo comes back as a Packet on a server uni stream; its payload
        // is the tail.
        let mut reply = tokio::time::timeout(Duration::from_secs(5), async {
            let mut stream = connection.accept_uni().await.unwrap();
            stream.read_to_end(65535).await.unwrap()
        })
        .await
        .expect("the packet sent before auth was never relayed");
        let payload = reply.split_off(reply.len() - b"before auth".len());
        assert_eq!(payload, b"before auth");
        let header = &reply[..4];
        assert_eq!(header[1], super::super::frame::COMMAND_TYPE_PACKET);
        assert_eq!(u16::from_be_bytes([header[2], header[3]]), 7);
    }

    #[tokio::test]
    async fn test_udp_round_trip_in_quic_mode() {
        let server = spawn_server().await;
        let echo = spawn_udp_echo().await;
        let resolver = test_resolver();
        let connector =
            connector_with_mode(server, TEST_UUID, SERVER_PASSWORD, TuicUdpRelayMode::Quic);

        let mut stream = connector
            .connect_udp_bidirectional(&resolver, target(echo))
            .await
            .unwrap();

        let reply = udp_echo_exchange(&mut stream, b"tuic over streams")
            .await
            .unwrap();
        assert_eq!(reply, b"tuic over streams");
    }

    #[tokio::test]
    async fn test_quic_mode_carries_several_packets_over_one_association() {
        let server = spawn_server().await;
        let echo = spawn_udp_echo().await;
        let resolver = test_resolver();
        let connector =
            connector_with_mode(server, TEST_UUID, SERVER_PASSWORD, TuicUdpRelayMode::Quic);

        let mut stream = connector
            .connect_udp_bidirectional(&resolver, target(echo))
            .await
            .unwrap();

        for i in 0..4u8 {
            let payload = vec![i; 48];
            let reply = udp_echo_exchange(&mut stream, &payload).await.unwrap();
            assert_eq!(reply, payload, "packet {i}");
        }
    }

    /// Larger than a QUIC datagram would carry. In this mode the packet still
    /// travels whole, because a stream has no datagram limit to fragment for.
    #[tokio::test]
    async fn test_quic_mode_carries_a_payload_past_the_datagram_limit() {
        let server = spawn_server().await;
        let echo = spawn_udp_echo().await;
        let resolver = test_resolver();
        let connector =
            connector_with_mode(server, TEST_UUID, SERVER_PASSWORD, TuicUdpRelayMode::Quic);

        let mut stream = connector
            .connect_udp_bidirectional(&resolver, target(echo))
            .await
            .unwrap();

        let payload: Vec<u8> = (0..8000u32).map(|i| i as u8).collect();
        let reply = udp_echo_exchange(&mut stream, &payload).await.unwrap();
        assert_eq!(reply, payload);
    }

    #[tokio::test]
    async fn test_udp_is_refused_when_the_client_disabled_it() {
        let server = spawn_server().await;
        let resolver = test_resolver();
        let connector = TuicConnector::new(
            NetLocation::from_str(&server.to_string(), None).unwrap(),
            uuid_bytes(TEST_UUID),
            SERVER_PASSWORD.to_string(),
            false,
            TuicUdpRelayMode::Native,
            Duration::from_millis(10_000),
            client_quic_config(),
            None,
            CongestionControl::Cubic,
        )
        .unwrap();

        assert!(!connector.supports_udp());
        let err = connector
            .connect_udp_bidirectional(&resolver, target(server))
            .await
            .err()
            .expect("UDP must be refused when the client disabled it")
            .to_string();
        assert!(err.contains("udp_enabled"), "{err}");
    }
}
