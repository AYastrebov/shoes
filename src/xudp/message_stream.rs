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
use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::address::{Address, NetLocation};
use crate::async_stream::{
    AsyncFlushMessage, AsyncPing, AsyncReadSessionMessage, AsyncSessionMessageStream,
    AsyncShutdownMessage, AsyncStream, AsyncWriteSessionMessage,
};
use crate::resolver::{Resolver, ResolverCache};

use super::frame::{FrameMetadata, FrameOption, SessionStatus, TargetNetwork};

/// Xray refuses frame metadata longer than this (common/mux/frame.go, Unmarshal).
const MAX_METADATA_LEN: usize = 512;

/// The largest response payload sent. Xray reads a frame into one 8192-byte
/// buffer and its own XUDP writer skips anything over 8192 - 666
/// (common/xudp/xudp.go, PacketWriter.WriteMultiBuffer).
const MAX_RESPONSE_LEN: usize = 8192 - 666;

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

    /// Open sessions: the client's session id -> the target of its last
    /// frame, used by Keep frames that carry no address.
    sessions: HashMap<u16, NetLocation>,

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
            sessions: HashMap::new(),
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
            // First, peek at the buffer to determine total frame size WITHOUT consuming anything.
            // We need to check: metadata_len (2 bytes) + metadata + data_len (2 bytes) + data

            // Need at least 2 bytes for metadata length
            if self.read_buffer.len() < 2 {
                return Ok(None);
            }

            let metadata_len =
                u16::from_be_bytes([self.read_buffer[0], self.read_buffer[1]]) as usize;

            if metadata_len > MAX_METADATA_LEN {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("metadata too long: {metadata_len}"),
                ));
            }

            // Check if we have complete metadata
            if self.read_buffer.len() < 2 + metadata_len {
                return Ok(None);
            }

            if metadata_len < 4 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("metadata too short: {}", metadata_len),
                ));
            }

            // Peek at the option byte: skip metadata_len(2) + session_id(2) + status(1)
            let has_data = (self.read_buffer[2 + 3] & 0x01) != 0; // FrameOption::DATA

            // The whole frame, data included, must be buffered before any of it
            // is consumed. Every status may carry OptionData: an End or KeepAlive
            // carries it too, and Xray reads and discards it (common/mux/server.go,
            // handleStatusKeepAlive and handleStatusEnd).
            let data_len_offset = 2 + metadata_len;
            let data_len = if has_data {
                if self.read_buffer.len() < data_len_offset + 2 {
                    return Ok(None);
                }
                let data_len = u16::from_be_bytes([
                    self.read_buffer[data_len_offset],
                    self.read_buffer[data_len_offset + 1],
                ]) as usize;
                if self.read_buffer.len() < data_len_offset + 2 + data_len {
                    return Ok(None);
                }
                Some(data_len)
            } else {
                None
            };

            let metadata = FrameMetadata::decode(&mut self.read_buffer)?
                .expect("metadata decode should succeed after length check");
            let data = data_len.map(|len| {
                self.read_buffer.advance(2);
                self.read_buffer.split_to(len)
            });

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
                    self.sessions.remove(&metadata.session_id);
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
                    self.sessions.insert(metadata.session_id, target);
                }
                SessionStatus::Keep => {
                    if data.is_none() {
                        continue;
                    }
                    if !self.sessions.contains_key(&metadata.session_id) {
                        log::debug!(
                            "[XUDP READ] Keep for unknown session {}, answering End",
                            metadata.session_id
                        );
                        self.queue_end(metadata.session_id)?;
                        continue;
                    }
                    if let Some(target) = metadata.target {
                        self.sessions.insert(metadata.session_id, target);
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

            let target = self.sessions[&metadata.session_id].clone();
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
    ) -> Poll<std::io::Result<(u16, SocketAddr)>> {
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
            return Poll::Ready(Ok((frame.session_id, socket_addr)));
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
        session_id: u16,
        buf: &[u8],
        target: &SocketAddr,
    ) -> Poll<std::io::Result<()>> {
        // The reverse direction: a UDP response to the client, under the
        // client's own session id and labelled with its real source.

        // Flush any pending write buffer first
        if !self.write_buffer.is_empty() {
            ready!(self.as_mut().poll_flush_message(cx))?;
        }

        if buf.len() > MAX_RESPONSE_LEN {
            log::debug!(
                "[XUDP SESSION WRITE] Dropping a {}-byte response for session {}: over {MAX_RESPONSE_LEN}",
                buf.len(),
                session_id
            );
            return Poll::Ready(Ok(()));
        }

        let address = match target.ip() {
            std::net::IpAddr::V4(v4) => Address::Ipv4(v4),
            std::net::IpAddr::V6(v6) => Address::Ipv6(v6),
        };
        let metadata = FrameMetadata {
            session_id,
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

    async fn read(stream: &mut XudpMessageStream) -> (u16, SocketAddr, Vec<u8>) {
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

    /// Two client sessions to one destination stay two sessions, each under
    /// the client's id, and a response comes back as a Keep under that id.
    /// Before, ids were invented per destination and mux.cool clients dropped
    /// every response.
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
        assert_eq!(read(&mut stream).await, (7, source, b"a".to_vec()));
        assert_eq!(read(&mut stream).await, (9, source, b"b".to_vec()));
        assert_eq!(read(&mut stream).await, (7, source, b"c".to_vec()));

        poll_fn(|cx| Pin::new(&mut stream).poll_write_session_message(cx, 9, b"reply", &source))
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

        let (id, _, data) = read(&mut stream).await;
        assert_eq!((id, data.as_slice()), (6, &b"ok"[..]));

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

        let too_big = vec![0u8; MAX_RESPONSE_LEN + 1];
        poll_fn(|cx| Pin::new(&mut stream).poll_write_session_message(cx, 1, &too_big, &source))
            .await
            .unwrap();
        let fits = vec![0u8; MAX_RESPONSE_LEN];
        poll_fn(|cx| Pin::new(&mut stream).poll_write_session_message(cx, 1, &fits, &source))
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
}
