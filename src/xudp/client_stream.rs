// XUDP client stream - one UDP target carried as mux.cool frames
//
// The client side of XUDP as sing-box writes it (sing-vmess, vless
// DialEarlyXUDPPacketConn) and Xray's own client does (common/xudp/xudp.go,
// PacketWriter): session 0, a New frame with the first packet, then a Keep
// frame naming the target with every packet after it. A VLESS Vision flow
// carries UDP only this way: sing-box refuses a Vision user's plain UDP
// command ("flow mismatch"), and Xray refuses UDP under the Vision flow.

use bytes::{BufMut, BytesMut};
use std::io::{Error, ErrorKind, Result};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::ReadBuf;

use crate::address::NetLocation;
use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncShutdownMessage,
    AsyncStream, AsyncWriteMessage,
};
use crate::util::allocate_vec;

use super::frame::{FrameMetadata, FrameOption, SessionStatus, TargetNetwork, decode_frame};

/// The only session on the connection; both reference clients use 0.
const SESSION_ID: u16 = 0;

/// The largest packet sent. Xray reads a frame into one 8192-byte buffer and
/// its own client skips anything over 8192 - 666
/// (common/xudp/xudp.go, PacketWriter.WriteMultiBuffer).
const MAX_PACKET_LEN: usize = 8192 - 666;

pub struct XudpClientStream<S> {
    stream: S,
    target: NetLocation,
    /// The New frame has gone out; every later packet is a Keep.
    session_open: bool,
    read_buffer: BytesMut,
    read_chunk: Box<[u8]>,
    pending_write: BytesMut,
    is_eof: bool,
}

impl<S: AsyncStream> XudpClientStream<S> {
    pub fn new(stream: S, target: NetLocation) -> Self {
        Self {
            stream,
            target,
            session_open: false,
            read_buffer: BytesMut::with_capacity(65536),
            read_chunk: allocate_vec(16384).into_boxed_slice(),
            pending_write: BytesMut::with_capacity(65536),
            is_eof: false,
        }
    }

    /// The next packet of this session, skipping control frames and frames
    /// that carry nothing.
    fn try_decode_packet(&mut self) -> Result<Option<BytesMut>> {
        // A loop rather than recursion: a peer can pack thousands of empty
        // frames into one read.
        loop {
            let Some((metadata, data)) = decode_frame(&mut self.read_buffer)? else {
                return Ok(None);
            };
            if metadata.session_id != SESSION_ID {
                log::debug!(
                    "[XUDP CLIENT] Skipping a frame for session {}",
                    metadata.session_id
                );
                continue;
            }
            match metadata.status {
                SessionStatus::End => {
                    self.is_eof = true;
                    if metadata.option.has_error() {
                        return Err(Error::new(
                            ErrorKind::ConnectionReset,
                            "XUDP session closed by the server with an error",
                        ));
                    }
                    return Ok(None);
                }
                SessionStatus::KeepAlive => continue,
                SessionStatus::New | SessionStatus::Keep => {}
            }
            if metadata.option.has_error() {
                return Err(Error::new(
                    ErrorKind::ConnectionReset,
                    "XUDP session closed by the server with an error",
                ));
            }
            match data {
                Some(data) if !data.is_empty() => return Ok(Some(data)),
                _ => continue,
            }
        }
    }

    fn encode_packet(&mut self, buf: &[u8]) -> Result<()> {
        let status = if self.session_open {
            SessionStatus::Keep
        } else {
            SessionStatus::New
        };
        FrameMetadata {
            session_id: SESSION_ID,
            status,
            option: FrameOption::new().with_data(),
            target: Some(self.target.clone()),
            network: Some(TargetNetwork::Udp),
        }
        .encode(&mut self.pending_write)?;
        self.pending_write.put_u16(buf.len() as u16);
        self.pending_write.extend_from_slice(buf);
        self.session_open = true;
        Ok(())
    }
}

impl<S: AsyncStream> AsyncReadMessage for XudpClientStream<S> {
    fn poll_read_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out_buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        let this = self.get_mut();

        loop {
            if this.is_eof {
                return Poll::Ready(Ok(()));
            }

            if let Some(packet) = this.try_decode_packet()? {
                if out_buf.remaining() < packet.len() {
                    return Poll::Ready(Err(Error::other(
                        "out_buf is too small to hold the message",
                    )));
                }
                out_buf.put_slice(&packet);
                return Poll::Ready(Ok(()));
            }
            if this.is_eof {
                // an End frame
                return Poll::Ready(Ok(()));
            }

            let mut tmp = ReadBuf::new(&mut this.read_chunk);
            match Pin::new(&mut this.stream).poll_read(cx, &mut tmp) {
                Poll::Ready(Ok(())) => {
                    let n = tmp.filled().len();
                    if n == 0 {
                        this.is_eof = true;
                        if this.read_buffer.is_empty() {
                            return Poll::Ready(Ok(()));
                        }
                        return Poll::Ready(Err(Error::new(
                            ErrorKind::UnexpectedEof,
                            "EOF reached in the middle of an XUDP frame",
                        )));
                    }
                    this.read_buffer.extend_from_slice(&this.read_chunk[..n]);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncStream> AsyncWriteMessage for XudpClientStream<S> {
    fn poll_write_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<()>> {
        if !self.pending_write.is_empty() {
            if let Poll::Ready(Err(e)) = self.as_mut().poll_flush_message(cx) {
                return Poll::Ready(Err(e));
            }
            if !self.pending_write.is_empty() {
                return Poll::Pending;
            }
        }

        if buf.len() > MAX_PACKET_LEN {
            // Dropped, as a UDP packet too large for the path would be.
            log::debug!(
                "[XUDP CLIENT] Dropping a {}-byte packet: over {MAX_PACKET_LEN}",
                buf.len()
            );
            return Poll::Ready(Ok(()));
        }

        self.encode_packet(buf)?;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncStream> AsyncFlushMessage for XudpClientStream<S> {
    fn poll_flush_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let this = self.get_mut();
        while !this.pending_write.is_empty() {
            match Pin::new(&mut this.stream).poll_write(cx, &this.pending_write) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::WriteZero,
                        "failed to write message",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    let _ = this.pending_write.split_to(n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut this.stream).poll_flush(cx)
    }
}

impl<S: AsyncStream> AsyncShutdownMessage for XudpClientStream<S> {
    fn poll_shutdown_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let this = self.get_mut();
        // Close the session first, as Xray's client does (common/mux/writer.go,
        // Writer.Close), so the server drops it now rather than on its timeout.
        if this.session_open {
            FrameMetadata {
                session_id: SESSION_ID,
                status: SessionStatus::End,
                option: FrameOption::new(),
                target: None,
                network: None,
            }
            .encode(&mut this.pending_write)?;
            this.session_open = false;
        }
        match Pin::new(&mut *this).poll_flush_message(cx) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }
        Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}

impl<S: AsyncStream> AsyncPing for XudpClientStream<S> {
    fn supports_ping(&self) -> bool {
        self.stream.supports_ping()
    }

    fn poll_write_ping(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<bool>> {
        Pin::new(&mut self.stream).poll_write_ping(cx)
    }
}

impl<S: AsyncStream> AsyncMessageStream for XudpClientStream<S> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Address;
    use crate::async_stream::testing::TestStream;
    use crate::kat::{hex, text, vectors};
    use std::future::poll_fn;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn dns_server() -> NetLocation {
        NetLocation::new(Address::Ipv4("192.0.2.7".parse().unwrap()), 53)
    }

    async fn write(stream: &mut XudpClientStream<TestStream>, packet: &[u8]) {
        poll_fn(|cx| Pin::new(&mut *stream).poll_write_message(cx, packet))
            .await
            .unwrap();
        poll_fn(|cx| Pin::new(&mut *stream).poll_flush_message(cx))
            .await
            .unwrap();
    }

    async fn read(stream: &mut XudpClientStream<TestStream>) -> Vec<u8> {
        let mut storage = vec![0u8; 65535];
        let mut buf = ReadBuf::new(&mut storage);
        poll_fn(|cx| Pin::new(&mut *stream).poll_read_message(cx, &mut buf))
            .await
            .unwrap();
        buf.filled().to_vec()
    }

    fn response(status: SessionStatus, option: FrameOption, data: &[u8]) -> BytesMut {
        let mut buf = BytesMut::new();
        FrameMetadata {
            session_id: SESSION_ID,
            status,
            option,
            target: Some(dns_server()),
            network: Some(TargetNetwork::Udp),
        }
        .encode(&mut buf)
        .unwrap();
        if option.has_data() {
            buf.put_u16(data.len() as u16);
            buf.extend_from_slice(data);
        }
        buf
    }

    /// Two packets come out byte for byte as sing-box's client writes them:
    /// the frames that follow the VLESS request header in its captured flight.
    #[tokio::test]
    async fn packets_are_framed_as_sing_box_frames_them() {
        let v = vectors("frames-sing");
        let case = &v["xudp"];
        let wire = hex(&case["wire"]);
        // version, user id, an empty addon block, the Mux command, no address
        let frames = &wire[1 + 16 + 1 + 1..];
        let target = NetLocation::from_str(text(&case["target"]), None).unwrap();

        let (near, mut far) = tokio::io::duplex(1 << 16);
        let mut stream = XudpClientStream::new(TestStream(near), target);
        for packet in case["packets"].as_array().unwrap() {
            write(&mut stream, &hex(packet)).await;
        }

        let mut written = vec![0u8; frames.len()];
        far.read_exact(&mut written).await.unwrap();
        assert_eq!(written, frames);
    }

    /// Responses come back as Keep frames under the session, labelled with
    /// their source; a KeepAlive and an empty frame between them are skipped.
    #[tokio::test]
    async fn responses_are_read_past_control_frames() {
        let (near, mut far) = tokio::io::duplex(1 << 16);
        let mut stream = XudpClientStream::new(TestStream(near), dns_server());

        let mut wire = response(SessionStatus::Keep, FrameOption::new().with_data(), b"one");
        wire.extend_from_slice(&response(SessionStatus::KeepAlive, FrameOption::new(), b""));
        wire.extend_from_slice(&response(SessionStatus::Keep, FrameOption::new(), b""));
        wire.extend_from_slice(&response(
            SessionStatus::Keep,
            FrameOption::new().with_data(),
            b"two",
        ));
        // split mid-frame, so the second packet waits for the rest of it
        let (first, rest) = wire.split_at(wire.len() - 2);
        far.write_all(first).await.unwrap();
        assert_eq!(read(&mut stream).await, b"one");
        far.write_all(rest).await.unwrap();
        assert_eq!(read(&mut stream).await, b"two");
    }

    /// The server's End closes the stream: the read after it is EOF.
    #[tokio::test]
    async fn an_end_frame_is_eof() {
        let (near, mut far) = tokio::io::duplex(1 << 16);
        let mut stream = XudpClientStream::new(TestStream(near), dns_server());
        let mut end = BytesMut::new();
        FrameMetadata {
            session_id: SESSION_ID,
            status: SessionStatus::End,
            option: FrameOption::new(),
            target: None,
            network: None,
        }
        .encode(&mut end)
        .unwrap();
        far.write_all(&end).await.unwrap();
        assert!(read(&mut stream).await.is_empty());
    }

    /// Shutting down after a packet closes the session with an End frame.
    #[tokio::test]
    async fn shutdown_ends_the_session() {
        let (near, mut far) = tokio::io::duplex(1 << 16);
        let mut stream = XudpClientStream::new(TestStream(near), dns_server());
        write(&mut stream, b"query").await;
        poll_fn(|cx| Pin::new(&mut stream).poll_shutdown_message(cx))
            .await
            .unwrap();

        let mut written = Vec::new();
        far.read_to_end(&mut written).await.unwrap();
        let mut written = BytesMut::from(&written[..]);
        let (new, data) = decode_frame(&mut written).unwrap().unwrap();
        assert_eq!(new.status, SessionStatus::New);
        assert_eq!(data.unwrap().as_ref(), b"query");
        let (end, _) = decode_frame(&mut written).unwrap().unwrap();
        assert_eq!(end.status, SessionStatus::End);
        assert_eq!(end.session_id, SESSION_ID);
    }
}
