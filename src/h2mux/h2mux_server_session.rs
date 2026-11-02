//! H2MUX Server Session
//!
//! Accepts incoming HTTP/2 streams and demultiplexes them into individual proxy streams.
//! Includes idle timeout support matching sing-mux behavior.

use std::io;
use std::sync::Arc;

use bytes::Bytes;
use http::Response;
use log::{debug, info};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::interval;

use crate::client_proxy_selector::{ClientProxySelector, ConnectDecision};
use crate::copy_bidirectional::copy_bidirectional;
use crate::resolver::Resolver;
use crate::routing::{ServerStream, run_udp_routing};
use crate::tcp::tcp_server::run_udp_copy;
use crate::uot::SocksPacketAddrStream;
use crate::vless::VlessMessageStream;

use super::MuxProtocol;
use super::activity_tracked_stream::ActivityTrackedStream;
use super::activity_tracker::{ActivityTracker, IDLE_TIMEOUT, SHUTDOWN_DRAIN_TIMEOUT};
use super::h2mux_padding::H2MuxPaddingStream;
use super::h2mux_protocol::{SessionRequest, StreamRequest};
use super::h2mux_server_stream::H2MuxServerStream;
use super::h2mux_stream::H2MuxStream;
use crate::prepend_stream::PrependStream;

/// HTTP/2 window and frame size configuration
const STREAM_WINDOW_SIZE: u32 = 256 * 1024; // 256 KB per stream
const CONNECTION_WINDOW_SIZE: u32 = 1 << 20; // 1 MB (matches Go's http2 default)
const MAX_FRAME_SIZE: u32 = (1 << 24) - 1; // ~16 MB (max allowed by HTTP/2)

/// Channel buffer size for inbound streams
const INBOUND_BUFFER: usize = 128;

/// An incoming stream with its destination
pub struct InboundStream {
    /// The multiplexed stream (wrapped with deferred status response)
    pub stream: H2MuxServerStream,
    /// Stream request with destination info
    pub request: StreamRequest,
}

/// Server session that accepts multiplexed streams.
pub struct H2MuxServerSession {
    /// Receiver for incoming streams
    inbound_rx: mpsc::Receiver<InboundStream>,
    /// Session protocol
    protocol: MuxProtocol,
    /// Padding enabled
    padding_enabled: bool,
}

impl H2MuxServerSession {
    /// Create a new server session from a raw connection.
    ///
    /// This performs:
    /// 1. Read session request header on RAW stream (unpadded)
    /// 2. Apply padding layer if client requested it
    /// 3. Perform HTTP/2 server handshake over (potentially padded) stream
    /// 4. Start accepting streams with idle timeout monitoring
    pub async fn new<IO>(mut conn: IO) -> io::Result<Self>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // Read session request header on RAW stream (before padding)
        let session_req = SessionRequest::decode(&mut conn).await?;

        if session_req.protocol != MuxProtocol::H2Mux {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported mux protocol: {:?}", session_req.protocol),
            ));
        }

        debug!(
            "H2MuxServerSession: received session request (version={}, protocol={:?}, padding={})",
            session_req.version, session_req.protocol, session_req.padding
        );

        // Apply padding layer and perform handshake
        if session_req.padding {
            let padded = H2MuxPaddingStream::new(conn);
            Self::handshake_and_spawn(padded, session_req.protocol, session_req.padding).await
        } else {
            Self::handshake_and_spawn(conn, session_req.protocol, session_req.padding).await
        }
    }

    /// Perform HTTP/2 handshake and spawn acceptor task.
    async fn handshake_and_spawn<IO>(
        conn: IO,
        protocol: MuxProtocol,
        padding_enabled: bool,
    ) -> io::Result<Self>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // Create channel for inbound streams
        let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_BUFFER);

        // Create activity tracker for idle timeout.
        // Wrap the connection with ActivityTrackedStream so that ALL HTTP/2 frames
        // (including PING, SETTINGS, WINDOW_UPDATE) count as activity,
        // matching Go's http2.Server.IdleTimeout behavior.
        let activity = ActivityTracker::new();
        let conn = ActivityTrackedStream::new(conn, activity.clone());

        // Perform H2 server handshake
        let connection = h2::server::Builder::new()
            .initial_window_size(STREAM_WINDOW_SIZE)
            .initial_connection_window_size(CONNECTION_WINDOW_SIZE)
            .max_frame_size(MAX_FRAME_SIZE)
            .max_concurrent_streams(1024)
            .handshake(conn)
            .await
            .map_err(|e| io::Error::other(format!("H2 server handshake failed: {}", e)))?;

        debug!("H2MuxServerSession: H2 handshake complete");

        // Spawn acceptor task with idle timeout monitoring
        crate::connections::spawn(async move {
            Self::accept_loop(connection, inbound_tx, activity).await;
        });

        Ok(Self {
            inbound_rx,
            protocol,
            padding_enabled,
        })
    }

    /// Accept loop - handles incoming H2 streams with idle timeout.
    ///
    /// Activity tracking is handled at the IO level by ActivityTrackedStream,
    /// so we don't need to manually record activity on stream accept/read/write.
    async fn accept_loop(
        mut connection: h2::server::Connection<impl AsyncRead + AsyncWrite + Unpin, Bytes>,
        inbound_tx: mpsc::Sender<InboundStream>,
        activity: ActivityTracker,
    ) {
        // Check idle timeout periodically (6 times per timeout period)
        let check_interval = IDLE_TIMEOUT / 6;
        let mut idle_timer = interval(check_interval);
        idle_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Skip the first tick which returns immediately
        idle_timer.tick().await;

        loop {
            tokio::select! {
                // Accept new streams
                result = connection.accept() => {
                    match result {
                        Some(Ok((request, respond))) => {
                            let inbound_tx = inbound_tx.clone();
                            crate::connections::spawn(async move {
                                if let Err(e) = Self::handle_stream(request, respond, inbound_tx).await {
                                    debug!("H2MuxServerSession: stream error: {}", e);
                                }
                            });
                        }
                        Some(Err(e)) => {
                            debug!("H2MuxServerSession: accept error: {}", e);
                            break;
                        }
                        None => break,
                    }
                }

                // Check for idle timeout
                _ = idle_timer.tick() => {
                    if activity.is_idle(IDLE_TIMEOUT) {
                        debug!("H2MuxServerSession: idle timeout, initiating graceful shutdown");
                        // Send GOAWAY and allow existing streams to complete
                        connection.graceful_shutdown();

                        // Drain remaining accepts with a timeout to prevent indefinite hangs.
                        // Without this timeout, if the client keeps the TCP connection open
                        // (e.g., with keepalive PINGs), accept().await can block forever.
                        let drain_result = tokio::time::timeout(SHUTDOWN_DRAIN_TIMEOUT, async {
                            while let Some(result) = connection.accept().await {
                                match result {
                                    Ok((request, respond)) => {
                                        let inbound_tx = inbound_tx.clone();
                                        crate::connections::spawn(async move {
                                            if let Err(e) = Self::handle_stream(request, respond, inbound_tx).await {
                                                debug!("H2MuxServerSession: stream error during drain: {}", e);
                                            }
                                        });
                                    }
                                    Err(e) => {
                                        debug!("H2MuxServerSession: error during drain, stopping: {}", e);
                                        break;
                                    }
                                }
                            }
                        }).await;

                        if drain_result.is_err() {
                            debug!("H2MuxServerSession: drain timeout, forcing close");
                        }
                        break;
                    }
                }
            }
        }

        debug!("H2MuxServerSession: accept loop ended");
    }

    /// Handle a single incoming H2 stream
    async fn handle_stream(
        request: http::Request<h2::RecvStream>,
        mut respond: h2::server::SendResponse<Bytes>,
        inbound_tx: mpsc::Sender<InboundStream>,
    ) -> io::Result<()> {
        // Send 200 OK response
        let response = Response::builder()
            .status(http::StatusCode::OK)
            .body(())
            .map_err(|e| io::Error::other(format!("failed to build H2 response: {e}")))?;

        let send_stream = respond
            .send_response(response, false)
            .map_err(|e| io::Error::other(format!("failed to send H2 response: {e}")))?;

        let recv_stream = request.into_body();

        // Create H2MuxStream
        let mut stream = H2MuxStream::new(send_stream, recv_stream);

        // Read stream request (destination)
        let stream_request = StreamRequest::decode_async(&mut stream).await?;

        debug!(
            "H2MuxServerSession: new stream to {} ({})",
            stream_request.destination, stream_request.network
        );

        // Wrap with server stream that sends status on first write
        let server_stream = H2MuxServerStream::new(stream);

        // Send to inbound channel
        let inbound = InboundStream {
            stream: server_stream,
            request: stream_request,
        };

        inbound_tx
            .send(inbound)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "inbound channel closed"))?;

        Ok(())
    }

    /// Accept the next incoming stream.
    ///
    /// Returns None when the session is closed.
    pub async fn accept(&mut self) -> Option<InboundStream> {
        self.inbound_rx.recv().await
    }

    /// Get the protocol being used
    pub fn protocol(&self) -> MuxProtocol {
        self.protocol
    }

    /// Check if padding is enabled
    pub fn padding_enabled(&self) -> bool {
        self.padding_enabled
    }
}

/// Handle an H2MUX session on a stream.
///
/// This function is called when a protocol handler detects the h2mux magic address.
/// It reads the session header, sets up HTTP/2, and handles each multiplexed stream.
pub async fn handle_h2mux_session<S>(
    stream: S,
    initial_data: Option<Box<[u8]>>,
    udp_enabled: bool,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    info!("H2MUX: Starting server session");

    // Wrap with PrependStream if there's initial data from protocol parsing
    let stream = PrependStream::new(stream, initial_data);
    let mut session = H2MuxServerSession::new(stream).await?;

    info!(
        "H2MUX: Session established (protocol={:?}, padding={})",
        session.protocol(),
        session.padding_enabled()
    );

    while let Some(inbound) = session.accept().await {
        let proxy_selector = proxy_selector.clone();
        let resolver = resolver.clone();

        crate::connections::spawn(async move {
            if let Err(e) =
                handle_h2mux_stream(inbound, udp_enabled, proxy_selector, resolver).await
            {
                debug!("H2MUX stream error: {}", e);
            }
        });
    }

    debug!("H2MUX: Session ended");
    Ok(())
}

/// Handle a single h2mux stream
async fn handle_h2mux_stream(
    inbound: InboundStream,
    udp_enabled: bool,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
) -> io::Result<()> {
    let InboundStream {
        mut stream,
        request,
    } = inbound;
    let is_udp = request.is_udp();
    let packet_addr = request.packet_addr;
    let destination = request.destination;

    if !is_udp && is_brutal_exchange(&destination) {
        return answer_brutal_exchange(&mut stream).await;
    }

    info!(
        "H2MUX stream: {} -> {} (udp={}, packet_addr={})",
        if is_udp { "UDP" } else { "TCP" },
        destination,
        is_udp,
        packet_addr
    );

    if is_udp {
        if !udp_enabled {
            let _ = stream.write_error_response("UDP not enabled").await;
            let _ = stream.shutdown().await;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "UDP not enabled",
            ));
        }

        // UDP stream - wrap in message stream
        if packet_addr {
            // Per-packet addressing (like UoT V1)
            handle_h2mux_udp_packet_addr(stream, proxy_selector, resolver).await
        } else {
            // Fixed destination
            handle_h2mux_udp(stream, destination, proxy_selector, resolver).await
        }
    } else {
        // TCP stream - regular forwarding
        handle_h2mux_tcp(stream, destination, proxy_selector, resolver).await
    }
}

/// The destination a sing-mux client opens to negotiate TCP Brutal
/// (sing-mux brutal.go, `BrutalExchangeDomain`).
const BRUTAL_EXCHANGE_DOMAIN: &str = "_BrutalBwExchange";

fn is_brutal_exchange(destination: &crate::address::NetLocation) -> bool {
    matches!(destination.address(), crate::address::Address::Hostname(host) if host == BRUTAL_EXCHANGE_DOMAIN)
}

/// Decline TCP Brutal, as a sing-mux server with brutal disabled does
/// (sing-mux server.go, newSession): read the client's u64 receive rate and
/// answer `bool(false)` and a varbin message. A brutal-enabled client then
/// carries on without it. Dialled as a hostname instead, the exchange failed
/// and the client tore the whole session down.
///
/// On an `H2MuxServerStream` the write is preceded by the success status
/// byte, as sing-mux's serverConn writes it.
async fn answer_brutal_exchange<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
) -> io::Result<()> {
    const MESSAGE: &[u8] = b"brutal is not enabled by the server";

    let mut client_receive_bps = [0u8; 8];
    stream.read_exact(&mut client_receive_bps).await?;
    debug!(
        "H2MUX: declining TCP Brutal (client receives {} B/s)",
        u64::from_be_bytes(client_receive_bps)
    );

    // bool(false), then the message as varbin: a uvarint length and the bytes.
    let mut response = vec![0u8];
    let mut len = MESSAGE.len();
    while len >= 0x80 {
        response.push((len as u8) | 0x80);
        len >>= 7;
    }
    response.push(len as u8);
    response.extend_from_slice(MESSAGE);

    stream.write_all(&response).await?;
    stream.flush().await?;
    let _ = stream.shutdown().await;
    Ok(())
}

/// Handle TCP stream from h2mux
async fn handle_h2mux_tcp(
    mut stream: H2MuxServerStream,
    destination: crate::address::NetLocation,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
) -> io::Result<()> {
    // Fake IP: DNS to port 53 is answered from the pool, as the TCP forward
    // answers it, whatever server the client addressed; a query to a fake
    // address standing for nothing is refused like any connection to one.
    if let Some(responder) = resolver.fake_ip().cloned()
        && destination.port() == crate::dns::fake_ip::DNS_PORT
    {
        if crate::dns::fake_ip::refuse_or_mark_used(&destination, responder.pool()) {
            let _ = stream
                .write_error_response("Connection blocked by rules")
                .await;
            let _ = stream.shutdown().await;
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("Connection to {destination} blocked: the fake address stands for nothing"),
            ));
        }
        let result = crate::dns::fake_ip::handle_dns_over_tcp(
            &mut stream,
            destination,
            responder,
            proxy_selector,
            resolver,
        )
        .await;
        let _ = stream.shutdown().await;
        return result;
    }

    // A fake address is restored to its name by `judge`; one standing for
    // nothing is blocked there.
    let action = proxy_selector
        .judge(destination.clone().into(), &resolver)
        .await?;

    match action {
        ConnectDecision::Allow {
            chain_group,
            remote_location,
        } => {
            debug!("H2MUX TCP: connecting to {} via chain", remote_location);

            let client_result = chain_group.connect_tcp(remote_location, &resolver).await?;
            let mut client_stream = client_result.client_stream;

            // Bidirectional copy
            let result = copy_bidirectional(&mut stream, &mut *client_stream, false, false).await;

            let _ = stream.shutdown().await;
            let _ = client_stream.shutdown().await;

            result
        }
        ConnectDecision::Block => {
            debug!("H2MUX TCP: blocked by rules: {}", destination);
            let _ = stream
                .write_error_response("Connection blocked by rules")
                .await;
            let _ = stream.shutdown().await;
            Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("Connection to {} blocked", destination),
            ))
        }
    }
}

/// Handle UDP stream with fixed destination
async fn handle_h2mux_udp(
    mut stream: H2MuxServerStream,
    destination: crate::address::NetLocation,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
) -> io::Result<()> {
    debug!("H2MUX UDP fixed: {}", destination);

    if resolver.fake_ip().is_some() {
        // Through the router, which answers DNS before any rule and ends
        // this one-destination stream when the rules block its destination.
        let server_stream = VlessMessageStream::new(Box::new(stream));
        return crate::tcp::tcp_server::run_one_destination_udp_with_fake_ip(
            Box::new(server_stream),
            destination,
            proxy_selector,
            resolver,
            false,
        )
        .await;
    }

    let action = proxy_selector.judge(destination.into(), &resolver).await?;

    match action {
        ConnectDecision::Allow {
            chain_group,
            remote_location,
        } => {
            // Connect to destination
            let client_stream = chain_group
                .connect_udp_bidirectional(&resolver, remote_location)
                .await?;

            // Wrap in VlessMessageStream for length-prefixed packets
            let server_stream = VlessMessageStream::new(Box::new(stream));

            run_udp_copy(Box::new(server_stream), client_stream, false, false).await
        }
        ConnectDecision::Block => {
            let _ = stream
                .write_error_response("Connection blocked by rules")
                .await;
            let _ = stream.shutdown().await;
            Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "UDP connection blocked by rules",
            ))
        }
    }
}

/// Handle UDP stream with per-packet addressing (packet_addr mode)
async fn handle_h2mux_udp_packet_addr(
    stream: H2MuxServerStream,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
) -> io::Result<()> {
    debug!("H2MUX UDP packet_addr mode - entering");

    // Uses the sing-mux SOCKS packet serializer for h2mux `packet_addr`.
    let packet_stream = SocksPacketAddrStream::new_socks(Box::new(stream));

    debug!("H2MUX UDP packet_addr mode - starting routing");
    let result = run_udp_routing(
        ServerStream::Targeted(Box::new(packet_stream)),
        proxy_selector,
        resolver,
        false,
    )
    .await;

    debug!("H2MUX UDP packet_addr mode - routing ended: {:?}", result);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::{Address, NetLocation};
    use tokio::io::duplex;

    #[test]
    fn only_the_exchange_hostname_is_the_brutal_exchange() {
        let exchange = NetLocation::new(Address::Hostname(BRUTAL_EXCHANGE_DOMAIN.into()), 444);
        let other = NetLocation::new(Address::Hostname("example.com".into()), 443);
        assert!(is_brutal_exchange(&exchange));
        assert!(!is_brutal_exchange(&other));
    }

    /// The decline is the bytes sing-mux's WriteBrutalResponse writes for
    /// `ok = false`: a zero bool, a uvarint length, the message.
    #[tokio::test]
    async fn the_brutal_exchange_is_declined_with_the_exact_bytes() {
        let (mut server, mut client) = duplex(1024);
        client
            .write_all(&100_000_000u64.to_be_bytes())
            .await
            .unwrap();

        answer_brutal_exchange(&mut server).await.unwrap();
        drop(server);

        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        let mut expected = vec![0x00, 35];
        expected.extend_from_slice(b"brutal is not enabled by the server");
        assert_eq!(response, expected);
    }

    /// A resolver with fake IP on, over a pool of 198.18.0.0/16.
    fn fake_ip_resolver() -> Arc<dyn Resolver> {
        use crate::dns::fake_ip::{
            BypassList, FakeIpNetwork, FakeIpPool, FakeIpResolver, FakeIpResponder,
        };
        let pool =
            Arc::new(FakeIpPool::new(FakeIpNetwork::parse("198.18.0.0/16").unwrap(), 64).unwrap());
        Arc::new(FakeIpResolver::new(
            Arc::new(crate::quic_outbound::testing::LoopbackResolver),
            Arc::new(FakeIpResponder::new(
                pool,
                BypassList::new(std::iter::empty::<&str>(), false),
            )),
        ))
    }

    /// Rules that block everything: what reaches them is not answered.
    fn block_all() -> Arc<ClientProxySelector> {
        use crate::address::NetLocationMask;
        use crate::client_proxy_selector::{ConnectAction, ConnectRule};
        Arc::new(ClientProxySelector::new(vec![ConnectRule::new(
            vec![NetLocationMask::ANY],
            vec![],
            ConnectAction::new_block(),
        )]))
    }

    /// One h2mux TCP stream to `destination`, the client sending `sent` and
    /// closing; what the client reads back, status byte first.
    async fn h2mux_tcp_exchange(destination: &str, sent: Vec<u8>) -> (io::Result<()>, Vec<u8>) {
        use super::super::h2mux_server_stream::tests::{read_response_body, stream_pair};
        use tokio::task::JoinSet;
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut drivers = JoinSet::new();
            let (stream, mut response, mut request) = stream_pair(65535, &mut drivers).await;
            let resolver = fake_ip_resolver();
            let handler = tokio::spawn(handle_h2mux_tcp(
                stream,
                NetLocation::from(destination.parse::<std::net::SocketAddr>().unwrap()),
                block_all(),
                resolver,
            ));
            request.send_data(sent.into(), true).unwrap();
            let body = read_response_body(&mut response).await;
            (handler.await.unwrap(), body)
        })
        .await
        .expect("the exchange ends")
    }

    fn framed_a_query(name: &str) -> Vec<u8> {
        use hickory_resolver::proto::op::{Message, MessageType, OpCode, Query};
        use hickory_resolver::proto::rr::{Name, RecordType};
        use std::str::FromStr;
        let mut message = Message::new(7, MessageType::Query, OpCode::Query);
        message.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
        let query = message.to_vec().unwrap();
        let mut framed = (query.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&query);
        framed
    }

    /// DNS over an h2mux TCP stream is answered from the pool, as the TCP
    /// forward answers it, ahead of the rules (which block everything here).
    #[tokio::test]
    async fn dns_over_h2mux_tcp_is_answered_from_the_pool() {
        use hickory_resolver::proto::op::Message;
        use hickory_resolver::proto::rr::RData;
        let (result, body) = h2mux_tcp_exchange("8.8.8.8:53", framed_a_query("echo.test.")).await;
        result.unwrap();
        assert_eq!(body[0], crate::h2mux::h2mux_protocol::STATUS_SUCCESS);
        let length = u16::from_be_bytes([body[1], body[2]]) as usize;
        let answer = Message::from_vec(&body[3..3 + length]).unwrap();
        let fake = answer
            .answers
            .iter()
            .find_map(|record| match &record.data {
                RData::A(a) => Some(a.0),
                _ => None,
            })
            .expect("an A record");
        assert_eq!(fake.octets()[..2], [198, 18], "{fake} is from the pool");
    }

    /// DNS to a fake address standing for nothing is refused, not answered.
    #[tokio::test]
    async fn dns_over_h2mux_tcp_to_an_unmapped_fake_address_is_refused() {
        let (result, body) =
            h2mux_tcp_exchange("198.18.250.250:53", framed_a_query("echo.test.")).await;
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::ConnectionRefused);
        assert_eq!(body[0], crate::h2mux::h2mux_protocol::STATUS_ERROR);
    }
}
