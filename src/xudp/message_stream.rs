#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "predates the lint; see the [lints] note in Cargo.toml"
)]

// XUDP message stream - protocol-agnostic UDP session multiplexing
// Wraps any AsyncStream and provides XUDP frame encoding/decoding with session management
// Used by both VLESS and VMess protocols
//
// This is the server side of mux.cool as Xray runs it (common/mux/server.go):
// session ids belong to the client (common/mux/client.go allocates them), so
// every packet is reported under the id it arrived with and every response
// echoes that id in a Keep frame (NewResponseWriter, common/mux/writer.go).

use bytes::{Buf, BufMut, BytesMut};
use futures::ready;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::address::{Address, NetLocation};
use crate::async_stream::{
    AsyncFlushMessage, AsyncPing, AsyncReadSessionMessage, AsyncSessionMessageStream,
    AsyncShutdownMessage, AsyncStream, AsyncWriteSessionMessage, MessageSessionId,
};
use crate::resolver::{Resolver, ResolverCache};

use super::frame::{FrameMetadata, FrameOption, SessionStatus, TargetNetwork, decode_frame};

/// The largest response payload sent. Xray reads a frame into one 8192-byte
/// buffer and its own XUDP writer skips anything over 8192 - 666
/// (common/xudp/xudp.go, PacketWriter.WriteMultiBuffer).
const MAX_RESPONSE_LEN: usize = 8192 - 666;

/// Routes open at once across every wire session of one stream: a client
/// sending to a new destination past this has its packet dropped, since
/// each route is a remote socket (upstream cfal/shoes, "bound XUDP
/// destination routes").
pub(crate) const MAX_XUDP_ROUTES: usize = 1024;

/// One of the client's sessions, as the wire names it, and the routes it
/// has been given: one per destination it sends to.
///
/// A session id belongs to the client, and one session may carry packets to
/// several destinations (a Keep frame names one). The router keeps one
/// remote per id it is told, rule-checked for that remote's destination,
/// so reporting every destination under the one wire id sent the second
/// destination's packets to the first destination's remote, and a reused
/// wire id landed on the old remote (upstream cfal/shoes, "isolate XUDP
/// routing sessions"). Each (wire session, destination) pair is its own
/// route id to the router; the wire id is put back on the response.
struct WireSession {
    /// The target of the last frame that named one, for Keep frames that
    /// carry no address.
    target: NetLocation,
    routes: HashMap<NetLocation, MessageSessionId>,
}

/// A decoded payload frame: the client's session id, the payload, and the
/// target as the client named it (may be a hostname).
struct InboundFrame {
    session_id: u16,
    data: Vec<u8>,
    target: NetLocation,
}

pub struct XudpMessageStream {
    /// Underlying byte stream (VLESS VisionStream, VMess stream, or any TLS stream) that reads/writes raw XUDP frame bytes
    inner_stream: Box<dyn AsyncStream>,

    /// Read buffer for incoming XUDP frames
    read_buffer: BytesMut,

    /// Write buffer for outgoing XUDP frames
    write_buffer: BytesMut,

    /// Open wire sessions by the client's session id.
    wire_sessions: HashMap<u16, WireSession>,

    /// Every open route, back to its wire session.
    routes: HashMap<MessageSessionId, u16>,

    /// Routes whose wire session the client ended, for the router to drop.
    closed_routes: VecDeque<MessageSessionId>,

    next_route_id: MessageSessionId,

    /// Set when the route limit first drops a packet and cleared by the
    /// next admission, so a client spraying new destinations logs once per
    /// episode rather than once per packet.
    route_cap_reported: bool,

    /// Resolver cache for hostname targets
    resolver_cache: ResolverCache,

    /// A decoded frame whose target is still resolving
    incoming_frame: Option<InboundFrame>,

    /// EOF flag
    is_eof: bool,
}

impl XudpMessageStream {
    /// `resolver` is the server's own, so a hostname target resolves through
    /// the configured DNS (routing, fake IP) like any other connection.
    pub fn new(inner_stream: Box<dyn AsyncStream>, resolver: Arc<dyn Resolver>) -> Self {
        Self {
            inner_stream,
            read_buffer: BytesMut::with_capacity(65536),
            write_buffer: BytesMut::with_capacity(65536),
            wire_sessions: HashMap::new(),
            routes: HashMap::new(),
            closed_routes: VecDeque::new(),
            next_route_id: 1,
            route_cap_reported: false,
            resolver_cache: ResolverCache::new(resolver),
            incoming_frame: None,
            is_eof: false,
        }
    }

    /// Feed initial unparsed data into the read buffer
    /// Used when protocol header parsing (VLESS/VMess) consumed data that belongs to XUDP frames
    pub fn feed_initial_read_data(&mut self, data: &[u8]) -> std::io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        log::debug!(
            "[XUDP] Feeding {} bytes of initial data to read buffer",
            data.len()
        );
        self.read_buffer.extend_from_slice(data);
        Ok(())
    }

    /// The client ended a session: its routes are closed and handed to the
    /// router, so no response and no reuse of the id reaches them.
    fn close_wire_session(&mut self, wire_session_id: u16) {
        let Some(session) = self.wire_sessions.remove(&wire_session_id) else {
            return;
        };
        for route in session.routes.into_values() {
            self.routes.remove(&route);
            self.closed_routes.push_back(route);
        }
    }

    fn start_wire_session(&mut self, wire_session_id: u16, target: NetLocation) {
        self.close_wire_session(wire_session_id);
        self.wire_sessions.insert(
            wire_session_id,
            WireSession {
                target,
                routes: HashMap::new(),
            },
        );
    }

    /// The route for a packet of `wire_session_id` to `target`, made on
    /// first use. `None` when the session is not open or the stream is at
    /// its route limit: the packet is dropped, and said so.
    fn admit_route(
        &mut self,
        wire_session_id: u16,
        target: &NetLocation,
    ) -> Option<MessageSessionId> {
        let session = self.wire_sessions.get_mut(&wire_session_id)?;
        if let Some(route) = session.routes.get(target) {
            return Some(*route);
        }
        if self.routes.len() >= MAX_XUDP_ROUTES {
            if self.route_cap_reported {
                log::debug!(
                    "[XUDP READ] Dropping a packet for new destination {target} at the \
                     {MAX_XUDP_ROUTES}-route limit"
                );
            } else {
                self.route_cap_reported = true;
                log::warn!(
                    "[XUDP READ] Dropping a packet for new destination {target} at the \
                     {MAX_XUDP_ROUTES}-route limit; further drops are logged at debug \
                     until one is admitted again"
                );
            }
            return None;
        }
        self.route_cap_reported = false;
        let route = self.next_route_id;
        self.next_route_id = self.next_route_id.checked_add(1)?;
        session.routes.insert(target.clone(), route);
        self.routes.insert(route, wire_session_id);
        Some(route)
    }

    /// Queue an End for a session the client keeps using but this side does
    /// not know, as Xray's handleStatusKeep does. It goes out ahead of the
    /// next response, or on the next flush.
    fn queue_end(&mut self, session_id: u16) -> std::io::Result<()> {
        FrameMetadata {
            session_id,
            status: SessionStatus::End,
            option: FrameOption::new(),
            target: None,
            network: None,
        }
        .encode(&mut self.write_buffer)
    }

    /// Try to decode one complete XUDP payload frame from the read buffer.
    ///
    /// This function must NOT consume any bytes from the buffer unless
    /// it successfully decodes a complete frame. Otherwise, partial frames would
    /// be lost when the function is called again with more data.
    ///
    /// Returns:
    ///   Ok(Some(frame)) - Successfully decoded a complete payload frame
    ///   Ok(None) - Buffer doesn't contain a complete frame yet (need more data)
    ///   Err(e) - Error during decoding
    fn try_decode_one_frame(&mut self) -> std::io::Result<Option<InboundFrame>> {
        // Iteratively skip control/empty frames (End, KeepAlive, no-data) instead of
        // recursing: a peer can pack thousands of tiny such frames into one read buffer,
        // and tail-recursion there would exhaust the stack. Each iteration consumes bytes,
        // so the loop always makes progress toward a payload frame or an empty buffer.
        loop {
            let Some((metadata, data)) = decode_frame(&mut self.read_buffer)? else {
                return Ok(None);
            };

            log::debug!(
                "[XUDP READ] Decoded frame: session_id={}, status={:?}, has_data={}, target={:?}, network={:?}",
                metadata.session_id,
                metadata.status,
                metadata.option.has_data(),
                metadata.target,
                metadata.network
            );

            match metadata.status {
                SessionStatus::End => {
                    self.close_wire_session(metadata.session_id);
                    continue;
                }
                SessionStatus::KeepAlive => continue,
                SessionStatus::New => {
                    // Check for TCP destination - we don't support TCP over XUDP
                    if let Some(TargetNetwork::Tcp) = metadata.network {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Unsupported,
                            "XUDP with TCP destinations is not supported. Only UDP destinations are supported.",
                        ));
                    }
                    let target = metadata.target.ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "New frame without a target",
                        )
                    })?;
                    self.start_wire_session(metadata.session_id, target);
                }
                SessionStatus::Keep => {
                    if data.is_none() {
                        continue;
                    }
                    let Some(session) = self.wire_sessions.get_mut(&metadata.session_id) else {
                        log::debug!(
                            "[XUDP READ] Keep for unknown session {}, answering End",
                            metadata.session_id
                        );
                        self.queue_end(metadata.session_id)?;
                        continue;
                    };
                    if let Some(target) = metadata.target {
                        session.target = target;
                    }
                }
            }

            // Check for ERROR option bit - remote side is signaling an error
            if metadata.option.has_error() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "XUDP session closed by remote with error",
                ));
            }

            let Some(data) = data.filter(|data| !data.is_empty()) else {
                continue;
            };

            let target = self.wire_sessions[&metadata.session_id].target.clone();
            return Ok(Some(InboundFrame {
                session_id: metadata.session_id,
                data: data.to_vec(),
                target,
            }));
        }
    }

    /// Start writing what is buffered without waiting for it, so a queued
    /// End reaches the client even while no response is being written.
    fn poll_write_buffered(&mut self, cx: &mut Context<'_>) -> std::io::Result<()> {
        while !self.write_buffer.is_empty() {
            match Pin::new(&mut self.inner_stream).poll_write(cx, &self.write_buffer) {
                Poll::Ready(Ok(0)) | Poll::Pending => break,
                Poll::Ready(Ok(n)) => self.write_buffer.advance(n),
                Poll::Ready(Err(e)) => return Err(e),
            }
        }
        Ok(())
    }
}

impl AsyncFlushMessage for XudpMessageStream {
    fn poll_flush_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        while !this.write_buffer.is_empty() {
            let n = ready!(Pin::new(&mut this.inner_stream).poll_write(cx, &this.write_buffer))?;
            this.write_buffer.advance(n);
        }

        Pin::new(&mut this.inner_stream).poll_flush(cx)
    }
}

impl AsyncShutdownMessage for XudpMessageStream {
    fn poll_shutdown_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        ready!(self.as_mut().poll_flush_message(cx))?;
        Pin::new(&mut self.get_mut().inner_stream).poll_shutdown(cx)
    }
}

impl AsyncPing for XudpMessageStream {
    fn supports_ping(&self) -> bool {
        self.inner_stream.supports_ping()
    }

    fn poll_write_ping(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Pin::new(&mut self.get_mut().inner_stream).poll_write_ping(cx)
    }
}

impl AsyncReadSessionMessage for XudpMessageStream {
    fn poll_read_session_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<(MessageSessionId, SocketAddr)>> {
        let this = self.get_mut();

        loop {
            let frame = match this.incoming_frame.take() {
                Some(frame) => frame,
                None => {
                    if this.is_eof {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "EOF reached",
                        )));
                    }
                    let decoded = this.try_decode_one_frame()?;
                    this.poll_write_buffered(cx)?;
                    match decoded {
                        Some(frame) => frame,
                        None => {
                            ready!(this.poll_fill_read_buffer(cx))?;
                            continue;
                        }
                    }
                }
            };

            // The route is admitted before the name resolves, so a packet
            // the stream cannot carry is dropped without a lookup.
            let Some(route) = this.admit_route(frame.session_id, &frame.target) else {
                continue;
            };

            let socket_addr = match this.resolver_cache.poll_resolve_location(cx, &frame.target) {
                Poll::Ready(Ok(addr)) => addr,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    // DNS resolution pending - keep the frame and wait
                    this.incoming_frame = Some(frame);
                    return Poll::Pending;
                }
            };

            if frame.data.len() > buf.remaining() {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "buffer too small for incoming message",
                )));
            }

            buf.put_slice(&frame.data);
            return Poll::Ready(Ok((route, socket_addr)));
        }
    }

    fn take_closed_session(&mut self) -> Option<MessageSessionId> {
        self.closed_routes.pop_front()
    }

    /// The router expired, refused or failed this route: it stops counting
    /// against MAX_XUDP_ROUTES, and the wire session's next packet to that
    /// destination gets a new route. Without this, only a client's End
    /// freed a route, and a long-lived session reaching many destinations
    /// hit the limit for good.
    fn release_session(&mut self, route: MessageSessionId) {
        let Some(wire_session_id) = self.routes.remove(&route) else {
            return;
        };
        if let Some(session) = self.wire_sessions.get_mut(&wire_session_id) {
            session.routes.retain(|_, r| *r != route);
        }
    }
}

impl XudpMessageStream {
    /// Read more bytes from the inner stream into the read buffer.
    fn poll_fill_read_buffer(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // Read into reserved but still uninitialized capacity. Using
        // ReadBuf::uninit avoids zero-filling 8 KiB on every poll, which is
        // pure waste since poll_read overwrites it and any unwritten tail is
        // dropped.
        let original_filled = self.read_buffer.len();
        self.read_buffer.reserve(8192);
        let mut temp_buf = ReadBuf::uninit(&mut self.read_buffer.spare_capacity_mut()[..8192]);
        let poll_result = Pin::new(&mut self.inner_stream).poll_read(cx, &mut temp_buf);

        let n = temp_buf.filled().len();
        // SAFETY: poll_read reported `n` bytes written through `temp_buf` into
        // the reserved spare capacity, so bytes [0, original_filled + n) are
        // now initialized. `reserve(8192)` guaranteed the capacity exists.
        unsafe {
            self.read_buffer.set_len(original_filled + n);
        }

        ready!(poll_result)?;
        if n == 0 {
            self.is_eof = true;
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "EOF reached",
            )));
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWriteSessionMessage for XudpMessageStream {
    fn poll_write_session_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        session_id: MessageSessionId,
        buf: &[u8],
        target: &SocketAddr,
    ) -> Poll<std::io::Result<()>> {
        // The reverse direction: a UDP response to the client, under the
        // client's own session id and labelled with its real source.

        // Flush any pending write buffer first
        if !self.write_buffer.is_empty() {
            ready!(self.as_mut().poll_flush_message(cx))?;
        }

        // A route the client has ended gets no response.
        let Some(&wire_session_id) = self.routes.get(&session_id) else {
            log::debug!("[XUDP SESSION WRITE] Dropping a response for closed route {session_id}");
            return Poll::Ready(Ok(()));
        };

        if buf.len() > MAX_RESPONSE_LEN {
            log::debug!(
                "[XUDP SESSION WRITE] Dropping a {}-byte response for session {}: over {MAX_RESPONSE_LEN}",
                buf.len(),
                wire_session_id
            );
            return Poll::Ready(Ok(()));
        }

        let address = match target.ip() {
            std::net::IpAddr::V4(v4) => Address::Ipv4(v4),
            std::net::IpAddr::V6(v6) => Address::Ipv6(v6),
        };
        let metadata = FrameMetadata {
            session_id: wire_session_id,
            status: SessionStatus::Keep,
            option: FrameOption::new().with_data(),
            target: Some(NetLocation::new(address, target.port())),
            network: Some(TargetNetwork::Udp),
        };

        metadata.encode(&mut self.write_buffer)?;
        self.write_buffer.put_u16(buf.len() as u16);
        self.write_buffer.extend_from_slice(buf);

        self.poll_flush_message(cx)
    }
}

impl AsyncSessionMessageStream for XudpMessageStream {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::async_stream::testing::TestStream;
    use crate::quic_outbound::testing::test_resolver;
    use std::future::poll_fn;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn frame_for(
        session_id: u16,
        status: SessionStatus,
        target: Option<NetLocation>,
        data: &[u8],
    ) -> BytesMut {
        let mut buf = BytesMut::new();
        FrameMetadata {
            session_id,
            status,
            option: FrameOption::new().with_data(),
            network: target.as_ref().map(|_| TargetNetwork::Udp),
            target,
        }
        .encode(&mut buf)
        .unwrap();
        buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
        buf.extend_from_slice(data);
        buf
    }

    fn frame(status: SessionStatus, target: Option<NetLocation>, data: &[u8]) -> BytesMut {
        frame_for(1, status, target, data)
    }

    fn dns_server() -> NetLocation {
        NetLocation::new(Address::Ipv4("1.1.1.1".parse().unwrap()), 53)
    }

    async fn read(stream: &mut XudpMessageStream) -> (MessageSessionId, SocketAddr, Vec<u8>) {
        let mut storage = vec![0u8; 65535];
        let mut buf = ReadBuf::new(&mut storage);
        let (id, addr) =
            poll_fn(|cx| Pin::new(&mut *stream).poll_read_session_message(cx, &mut buf))
                .await
                .unwrap();
        (id, addr, buf.filled().to_vec())
    }

    /// A KeepAlive carrying OptionData, then a New frame: both are consumed and
    /// the New frame's payload is what comes out.
    #[tokio::test]
    async fn data_on_a_keepalive_is_skipped_with_its_frame() {
        let (near, _far) = tokio::io::duplex(1024);
        let mut stream = XudpMessageStream::new(Box::new(TestStream(near)), test_resolver());
        let target = dns_server();

        stream
            .read_buffer
            .extend_from_slice(&frame(SessionStatus::KeepAlive, None, &[0xAA; 10]));
        stream.read_buffer.extend_from_slice(&frame(
            SessionStatus::New,
            Some(target.clone()),
            b"hi",
        ));

        let frame = stream.try_decode_one_frame().unwrap().unwrap();
        assert_eq!(frame.data, b"hi");
        assert_eq!(frame.target, target);
        assert!(stream.read_buffer.is_empty());
    }

    /// A KeepAlive whose data has not fully arrived waits rather than
    /// consuming its metadata alone.
    #[tokio::test]
    async fn a_partial_keepalive_waits_for_its_data() {
        let (near, _far) = tokio::io::duplex(1024);
        let mut stream = XudpMessageStream::new(Box::new(TestStream(near)), test_resolver());
        let whole = frame(SessionStatus::KeepAlive, None, &[0xAA; 10]);
        stream
            .read_buffer
            .extend_from_slice(&whole[..whole.len() - 3]);

        assert!(stream.try_decode_one_frame().unwrap().is_none());
        assert_eq!(stream.read_buffer.len(), whole.len() - 3);
    }

    /// Two client sessions to one destination stay two routes, and a
    /// response written under a route comes back as a Keep under the
    /// client's own id for it. Before, ids were invented per destination
    /// and mux.cool clients dropped every response.
    #[tokio::test]
    async fn the_clients_session_ids_are_reported_and_echoed() {
        let (near, mut far) = tokio::io::duplex(1 << 16);
        let mut stream = XudpMessageStream::new(Box::new(TestStream(near)), test_resolver());

        far.write_all(&frame_for(7, SessionStatus::New, Some(dns_server()), b"a"))
            .await
            .unwrap();
        far.write_all(&frame_for(9, SessionStatus::New, Some(dns_server()), b"b"))
            .await
            .unwrap();
        far.write_all(&frame_for(7, SessionStatus::Keep, None, b"c"))
            .await
            .unwrap();

        let source: SocketAddr = "1.1.1.1:53".parse().unwrap();
        let (route_7, got_source, data) = read(&mut stream).await;
        assert_eq!((got_source, data), (source, b"a".to_vec()));
        let (route_9, _, data) = read(&mut stream).await;
        assert_eq!(data, b"b");
        assert_ne!(route_7, route_9, "two client sessions are two routes");
        assert_eq!(read(&mut stream).await, (route_7, source, b"c".to_vec()));

        poll_fn(|cx| {
            Pin::new(&mut stream).poll_write_session_message(cx, route_9, b"reply", &source)
        })
        .await
        .unwrap();

        let mut written = BytesMut::new();
        written.resize(64, 0);
        let n = far.read(&mut written).await.unwrap();
        written.truncate(n);
        let metadata = FrameMetadata::decode(&mut written).unwrap().unwrap();
        assert_eq!(metadata.session_id, 9);
        assert_eq!(metadata.status, SessionStatus::Keep);
        assert_eq!(metadata.target, Some(dns_server()));
        assert_eq!(&written[..], b"\x00\x05reply");
    }

    /// A Keep for a session this side never saw draws an End for that id and
    /// the connection carries on, as Xray's handleStatusKeep does.
    #[tokio::test]
    async fn a_keep_for_an_unknown_session_is_answered_with_end() {
        let (near, mut far) = tokio::io::duplex(1 << 16);
        let mut stream = XudpMessageStream::new(Box::new(TestStream(near)), test_resolver());

        far.write_all(&frame_for(5, SessionStatus::Keep, None, b"lost"))
            .await
            .unwrap();
        far.write_all(&frame_for(6, SessionStatus::New, Some(dns_server()), b"ok"))
            .await
            .unwrap();

        let (_, _, data) = read(&mut stream).await;
        assert_eq!(data, b"ok");

        let mut written = BytesMut::new();
        written.resize(64, 0);
        let n = far.read(&mut written).await.unwrap();
        written.truncate(n);
        let metadata = FrameMetadata::decode(&mut written).unwrap().unwrap();
        assert_eq!(metadata.session_id, 5);
        assert_eq!(metadata.status, SessionStatus::End);
        assert!(written.is_empty());
    }

    #[tokio::test]
    async fn metadata_over_512_bytes_is_refused() {
        let (near, _far) = tokio::io::duplex(1024);
        let mut stream = XudpMessageStream::new(Box::new(TestStream(near)), test_resolver());
        stream.read_buffer.extend_from_slice(&513u16.to_be_bytes());
        stream.read_buffer.extend_from_slice(&[0u8; 513]);

        let err = stream.try_decode_one_frame().err().unwrap();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    /// A response the client could not read into its 8 KiB frame buffer is
    /// dropped, as Xray's own XUDP writer drops it; one at the limit is sent.
    #[tokio::test]
    async fn a_response_over_the_client_frame_limit_is_dropped() {
        let (near, mut far) = tokio::io::duplex(1 << 16);
        let mut stream = XudpMessageStream::new(Box::new(TestStream(near)), test_resolver());
        let source: SocketAddr = "1.1.1.1:53".parse().unwrap();
        far.write_all(&frame_for(1, SessionStatus::New, Some(dns_server()), b"q"))
            .await
            .unwrap();
        let (route, _, _) = read(&mut stream).await;

        let too_big = vec![0u8; MAX_RESPONSE_LEN + 1];
        poll_fn(|cx| {
            Pin::new(&mut stream).poll_write_session_message(cx, route, &too_big, &source)
        })
        .await
        .unwrap();
        let fits = vec![0u8; MAX_RESPONSE_LEN];
        poll_fn(|cx| Pin::new(&mut stream).poll_write_session_message(cx, route, &fits, &source))
            .await
            .unwrap();
        drop(stream);

        let mut written = Vec::new();
        far.read_to_end(&mut written).await.unwrap();
        let mut written = BytesMut::from(&written[..]);
        FrameMetadata::decode(&mut written).unwrap().unwrap();
        assert_eq!(written.get_u16() as usize, MAX_RESPONSE_LEN);
        assert_eq!(written.len(), MAX_RESPONSE_LEN);
    }

    /// One client session sending to two destinations is two routes, each
    /// rule-checked and connected for its own destination by the router;
    /// a response under either goes out under the one wire id. Before, the
    /// second destination's packets went to the first destination's remote
    /// (upstream cfal/shoes, "isolate XUDP routing sessions").
    #[tokio::test]
    async fn two_destinations_on_one_wire_session_are_two_routes() {
        let (near, mut far) = tokio::io::duplex(1 << 16);
        let mut stream = XudpMessageStream::new(Box::new(TestStream(near)), test_resolver());
        let other = NetLocation::new(Address::Ipv4("9.9.9.9".parse().unwrap()), 53);

        far.write_all(&frame_for(3, SessionStatus::New, Some(dns_server()), b"a"))
            .await
            .unwrap();
        far.write_all(&frame_for(
            3,
            SessionStatus::Keep,
            Some(other.clone()),
            b"b",
        ))
        .await
        .unwrap();
        far.write_all(&frame_for(3, SessionStatus::Keep, Some(dns_server()), b"c"))
            .await
            .unwrap();

        let (route_a, source_a, _) = read(&mut stream).await;
        let (route_b, source_b, _) = read(&mut stream).await;
        let (route_c, _, _) = read(&mut stream).await;
        assert_eq!(source_a, "1.1.1.1:53".parse().unwrap());
        assert_eq!(source_b, "9.9.9.9:53".parse().unwrap());
        assert_ne!(route_a, route_b, "a second destination is a second route");
        assert_eq!(route_a, route_c, "the same destination is the same route");

        poll_fn(|cx| {
            Pin::new(&mut stream).poll_write_session_message(cx, route_b, b"reply", &source_b)
        })
        .await
        .unwrap();
        let mut written = BytesMut::new();
        written.resize(64, 0);
        let n = far.read(&mut written).await.unwrap();
        written.truncate(n);
        let metadata = FrameMetadata::decode(&mut written).unwrap().unwrap();
        assert_eq!(metadata.session_id, 3, "the response carries the wire id");
        assert_eq!(metadata.target, Some(other));
    }

    /// An End closes every route of the session: the router is told, and a
    /// response under a closed route is dropped, so a reused id cannot
    /// reach the old remote (upstream cfal/shoes, "cancel closed XUDP
    /// routes").
    #[tokio::test]
    async fn an_end_closes_the_sessions_routes() {
        let (near, mut far) = tokio::io::duplex(1 << 16);
        let mut stream = XudpMessageStream::new(Box::new(TestStream(near)), test_resolver());
        let other = NetLocation::new(Address::Ipv4("9.9.9.9".parse().unwrap()), 53);

        far.write_all(&frame_for(4, SessionStatus::New, Some(dns_server()), b"a"))
            .await
            .unwrap();
        far.write_all(&frame_for(4, SessionStatus::Keep, Some(other), b"b"))
            .await
            .unwrap();
        let (route_a, source, _) = read(&mut stream).await;
        let (route_b, _, _) = read(&mut stream).await;
        assert!(stream.take_closed_session().is_none());

        far.write_all(&frame_for(4, SessionStatus::End, None, b""))
            .await
            .unwrap();
        far.write_all(&frame_for(
            4,
            SessionStatus::New,
            Some(dns_server()),
            b"again",
        ))
        .await
        .unwrap();
        let (route_again, _, data) = read(&mut stream).await;
        assert_eq!(data, b"again");
        let mut closed = [
            stream.take_closed_session().unwrap(),
            stream.take_closed_session().unwrap(),
        ];
        closed.sort();
        let mut expected = [route_a, route_b];
        expected.sort();
        assert_eq!(closed, expected, "both routes of the ended session");
        assert!(stream.take_closed_session().is_none());
        assert!(
            !expected.contains(&route_again),
            "the reused id is a new route"
        );

        poll_fn(|cx| {
            Pin::new(&mut stream).poll_write_session_message(cx, route_a, b"late", &source)
        })
        .await
        .unwrap();
        poll_fn(|cx| {
            Pin::new(&mut stream).poll_write_session_message(cx, route_again, b"ok", &source)
        })
        .await
        .unwrap();
        drop(stream);
        let mut written = Vec::new();
        far.read_to_end(&mut written).await.unwrap();
        let mut written = BytesMut::from(&written[..]);
        let metadata = FrameMetadata::decode(&mut written).unwrap().unwrap();
        assert_eq!(metadata.session_id, 4);
        assert_eq!(
            &written[..],
            b"\x00\x02ok",
            "only the live route's response went out"
        );
    }

    /// Past the route limit a packet for a new destination is dropped and
    /// the stream carries on; one for a known destination still arrives.
    #[tokio::test]
    async fn a_new_destination_past_the_route_limit_is_dropped() {
        let (near, mut far) = tokio::io::duplex(1 << 20);
        let mut stream = XudpMessageStream::new(Box::new(TestStream(near)), test_resolver());
        far.write_all(&frame_for(
            1,
            SessionStatus::New,
            Some(dns_server()),
            b"first",
        ))
        .await
        .unwrap();
        let mut frames = BytesMut::new();
        for i in 1..=MAX_XUDP_ROUTES as u32 {
            let ip = std::net::Ipv4Addr::from(0x0a00_0000 + i);
            frames.extend_from_slice(&frame_for(
                1,
                SessionStatus::Keep,
                Some(NetLocation::new(Address::Ipv4(ip), 53)),
                b"x",
            ));
        }
        frames.extend_from_slice(&frame_for(
            1,
            SessionStatus::Keep,
            Some(dns_server()),
            b"known",
        ));
        far.write_all(&frames).await.unwrap();

        let (_, _, data) = read(&mut stream).await;
        assert_eq!(data, b"first");
        // The limit admits 1024 routes in all; the first destination holds one.
        for _ in 1..MAX_XUDP_ROUTES {
            let (_, _, data) = read(&mut stream).await;
            assert_eq!(data, b"x");
        }
        let (_, _, data) = read(&mut stream).await;
        assert_eq!(data, b"known", "the one past the limit was dropped");
    }

    /// A route the router releases (expired, refused) stops counting against
    /// the limit, and the next packet to its destination gets a new route.
    /// Before, only an End freed a route, so a long-lived session reaching
    /// many destinations was refused every new one for good.
    #[tokio::test]
    async fn a_released_route_frees_room_under_the_limit() {
        let (near, mut far) = tokio::io::duplex(1 << 20);
        let mut stream = XudpMessageStream::new(Box::new(TestStream(near)), test_resolver());
        far.write_all(&frame_for(
            1,
            SessionStatus::New,
            Some(dns_server()),
            b"first",
        ))
        .await
        .unwrap();
        let mut frames = BytesMut::new();
        for i in 1..MAX_XUDP_ROUTES as u32 {
            let ip = std::net::Ipv4Addr::from(0x0a00_0000 + i);
            frames.extend_from_slice(&frame_for(
                1,
                SessionStatus::Keep,
                Some(NetLocation::new(Address::Ipv4(ip), 53)),
                b"x",
            ));
        }
        far.write_all(&frames).await.unwrap();

        let (first_route, _, data) = read(&mut stream).await;
        assert_eq!(data, b"first");
        for _ in 1..MAX_XUDP_ROUTES {
            read(&mut stream).await;
        }
        assert_eq!(stream.routes.len(), MAX_XUDP_ROUTES);

        stream.release_session(first_route);
        let fresh = NetLocation::new(Address::Ipv4(std::net::Ipv4Addr::new(10, 9, 9, 9)), 53);
        let mut frames = BytesMut::new();
        frames.extend_from_slice(&frame_for(1, SessionStatus::Keep, Some(fresh), b"fresh"));
        frames.extend_from_slice(&frame_for(
            1,
            SessionStatus::Keep,
            Some(dns_server()),
            b"back",
        ));
        far.write_all(&frames).await.unwrap();

        let (_, _, data) = read(&mut stream).await;
        assert_eq!(data, b"fresh", "the released route made room");
        stream.release_session(first_route + 1);
        let (route, _, data) = read(&mut stream).await;
        assert_eq!(data, b"back");
        assert_ne!(
            route, first_route,
            "the released destination got a new route"
        );
    }
}
