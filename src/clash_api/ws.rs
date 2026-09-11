//! A server-side WebSocket for one-way text frames.
//!
//! Built on the handshake and frame packer the transport module already
//! has, rather than a WebSocket crate: every frame here goes server to
//! client and carries text, and the client sends nothing after the
//! handshake but a ping or a close. See the spec, "Transport".

use std::future::Future;

use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{ApiBody, body, error};

const OPCODE_TEXT: u8 = 0x1;
const OPCODE_CLOSE: u8 = 0x8;
const OPCODE_PING: u8 = 0x9;
const OPCODE_PONG: u8 = 0xA;

/// RFC 6455 close codes: the server is going away; the peer broke the
/// protocol.
const CLOSE_GOING_AWAY: u16 = 1001;
const CLOSE_PROTOCOL_ERROR: u16 = 1002;

/// A frame's header is at most 14 bytes before the payload.
const MAX_FRAME_OVERHEAD: usize = 14;

/// Nothing a client sends here is longer than a close reason, and a frame
/// claiming more is a client that has lost the plot.
const MAX_CLIENT_FRAME: usize = 64 * 1024;

pub fn is_upgrade(req: &Request<Incoming>) -> bool {
    req.headers()
        .get(hyper::header::UPGRADE)
        .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"websocket"))
}

/// Somewhere a stream's frames go, and a way to learn the reader left.
///
/// One trait for both transports, so a producer is written once and served
/// either as a WebSocket or as chunked JSON lines.
pub trait Sink: Send {
    fn send(&mut self, text: &str) -> impl Future<Output = std::io::Result<()>> + Send;
    /// Resolves when the client has gone. Used as the other arm of a
    /// select, so a producer stops rather than writing into a dead socket
    /// -- and cancellation-safe for the same reason: the select drops it on
    /// every tick.
    fn closed(&mut self) -> impl Future<Output = ()> + Send;
    /// Tell the client the server is going, where the transport has a way
    /// to say so. Called when the controller stops under a live stream.
    fn close(&mut self) -> impl Future<Output = ()> + Send;
}

pub struct TextSink {
    io: TokioIo<hyper::upgrade::Upgraded>,
    scratch: Vec<u8>,
    /// Bytes read from the client and not yet a whole frame.
    inbox: Vec<u8>,
    /// Frames owed to the client -- pongs, a close -- and how much of them
    /// is already on the wire.
    outbox: Vec<u8>,
    written: usize,
    /// A close has been queued: it goes out, and nothing after it.
    closing: bool,
}

/// One whole frame out of the client's bytes: `Ok(None)` until it is all
/// there, `Err` for a frame a client must not send, which fails the
/// connection.
///
/// A function over the buffer rather than a method, so it is testable
/// without a socket.
fn take_frame(inbox: &mut Vec<u8>) -> Result<Option<(u8, Vec<u8>)>, ()> {
    if inbox.len() < 2 {
        return Ok(None);
    }
    let opcode = inbox[0] & 0x0f;
    // RFC 6455 5.1: a client masks every frame, and a server that receives
    // one unmasked fails the connection. Checked before the length, so a
    // sender that is not a browser is refused on its first two bytes.
    if inbox[1] & 0x80 == 0 {
        return Err(());
    }
    let (len, header) = match inbox[1] & 0x7f {
        126 => {
            if inbox.len() < 4 {
                return Ok(None);
            }
            (u16::from_be_bytes([inbox[2], inbox[3]]) as u64, 4)
        }
        127 => {
            if inbox.len() < 10 {
                return Ok(None);
            }
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&inbox[2..10]);
            (u64::from_be_bytes(raw), 10)
        }
        n => (n as u64, 2),
    };
    // Compared before the narrowing: on a 32-bit target a length past
    // `usize` would otherwise wrap to a small one.
    if len > MAX_CLIENT_FRAME as u64 {
        return Err(());
    }
    let len = len as usize;
    let total = header + 4 + len;
    if inbox.len() < total {
        return Ok(None);
    }
    let mut mask = [0u8; 4];
    mask.copy_from_slice(&inbox[header..header + 4]);
    let mut payload = inbox[header + 4..total].to_vec();
    for (i, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[i % 4];
    }
    inbox.drain(..total);
    Ok(Some((opcode, payload)))
}

impl TextSink {
    /// Queue a control frame for the client.
    fn owe(&mut self, opcode: u8, payload: &[u8]) {
        let start = self.outbox.len();
        self.outbox
            .resize(start + payload.len() + MAX_FRAME_OVERHEAD, 0);
        let n = crate::websocket::websocket_stream::pack_frame(
            opcode,
            false,
            payload,
            &mut self.outbox[start..],
        );
        self.outbox.truncate(start + n);
    }

    /// Put what is owed on the wire.
    ///
    /// Cancellation-safe, which `write_all` is not: one `write` either lands
    /// whole or not at all, and the offset moves only after it lands, so a
    /// frame cut off by a select resumes where it stopped rather than
    /// starting over or being followed by another frame mid-way.
    async fn flush_owed(&mut self) -> std::io::Result<()> {
        while self.written < self.outbox.len() {
            let n = self.io.write(&self.outbox[self.written..]).await?;
            if n == 0 {
                return Err(std::io::ErrorKind::WriteZero.into());
            }
            self.written += n;
        }
        self.outbox.clear();
        self.written = 0;
        Ok(())
    }
}

impl Sink for TextSink {
    async fn send(&mut self, text: &str) -> std::io::Result<()> {
        // Anything owed goes first, so a pong or a close that a select cut
        // off mid-frame is finished before a text frame follows it.
        self.flush_owed().await?;
        if self.closing {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "the client is closing",
            ));
        }
        self.scratch.clear();
        self.scratch.resize(text.len() + MAX_FRAME_OVERHEAD, 0);
        // Unmasked: a server must not mask, and a client must.
        let n = crate::websocket::websocket_stream::pack_frame(
            OPCODE_TEXT,
            false,
            text.as_bytes(),
            &mut self.scratch,
        );
        self.io.write_all(&self.scratch[..n]).await
    }

    /// Reads the client's frames until one says the conversation is over.
    ///
    /// A close or an EOF ends it; a ping is answered with a pong, because a
    /// dashboard that pings and hears nothing hangs up; an unmasked or
    /// oversized frame is a protocol error, answered with a close; anything
    /// else is read and discarded.
    ///
    /// Every await here is one read or one write with the parse state kept
    /// on `self`, so the select that drops this future each tick loses no
    /// bytes and splits no frame.
    async fn closed(&mut self) {
        loop {
            if self.flush_owed().await.is_err() {
                return;
            }
            if self.closing {
                return;
            }
            match take_frame(&mut self.inbox) {
                Ok(Some((OPCODE_CLOSE, payload))) => {
                    // Echo the close, then stop: a client waits for it
                    // before releasing the socket.
                    self.owe(OPCODE_CLOSE, &payload);
                    self.closing = true;
                }
                Ok(Some((OPCODE_PING, payload))) => self.owe(OPCODE_PONG, &payload),
                Ok(Some(_)) => {}
                Ok(None) => match self.io.read_buf(&mut self.inbox).await {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {}
                },
                Err(()) => {
                    self.owe(OPCODE_CLOSE, &CLOSE_PROTOCOL_ERROR.to_be_bytes());
                    self.closing = true;
                }
            }
        }
    }

    async fn close(&mut self) {
        if !self.closing {
            self.owe(OPCODE_CLOSE, &CLOSE_GOING_AWAY.to_be_bytes());
            self.closing = true;
        }
        let _ = self.flush_owed().await;
    }
}

/// Answer the handshake, then run `on_socket` on the upgraded connection.
///
/// The upgrade completes after this response is sent, so the work happens
/// in a spawned task rather than here.
pub fn upgrade<F, Fut>(mut req: Request<Incoming>, on_socket: F) -> Response<ApiBody>
where
    F: FnOnce(TextSink) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let Some(key) = req
        .headers()
        .get("sec-websocket-key")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
    else {
        return error(StatusCode::BAD_REQUEST, "missing Sec-WebSocket-Key");
    };
    let accept = crate::websocket::websocket_handler::create_websocket_key_response(key);

    let on_upgrade = hyper::upgrade::on(&mut req);
    tokio::spawn(async move {
        match on_upgrade.await {
            Ok(upgraded) => {
                on_socket(TextSink {
                    io: TokioIo::new(upgraded),
                    scratch: Vec::new(),
                    inbox: Vec::new(),
                    outbox: Vec::new(),
                    written: 0,
                    closing: false,
                })
                .await
            }
            Err(e) => log::debug!("Clash API upgrade failed: {e}"),
        }
    });

    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header("upgrade", "websocket")
        .header("connection", "Upgrade")
        .header("sec-websocket-accept", accept)
        .body(body(String::new()))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The accept key is RFC 6455's example, so a wrong hash or a wrong
    /// GUID fails here rather than at a dashboard's handshake.
    #[test]
    fn the_accept_key_is_the_rfc_example() {
        let accept = crate::websocket::websocket_handler::create_websocket_key_response(
            "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
        );
        assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    /// A frame arrives in whatever pieces the network makes of it, and a
    /// tick may cut the read between them: nothing is taken until the
    /// whole frame is there, and exactly that frame is taken then.
    #[test]
    fn a_frame_is_taken_whole_or_not_at_all() {
        // A masked ping "hi", split after the first mask byte.
        let mut inbox = vec![0x89, 0x82, 1];
        assert_eq!(take_frame(&mut inbox), Ok(None));
        assert_eq!(inbox.len(), 3, "nothing consumed while incomplete");
        inbox.extend_from_slice(&[2, 3, 4, b'h' ^ 1, b'i' ^ 2]);
        assert_eq!(
            take_frame(&mut inbox),
            Ok(Some((OPCODE_PING, b"hi".to_vec())))
        );
        assert!(inbox.is_empty(), "exactly one frame consumed");
    }

    /// RFC 6455 has a client mask every frame; one that does not is refused
    /// on its header, and so is one claiming more than a client may send,
    /// before any payload is read for either.
    #[test]
    fn an_unmasked_or_oversized_frame_is_a_protocol_error() {
        let mut unmasked = vec![0x89, 0x00];
        assert_eq!(take_frame(&mut unmasked), Err(()));

        let mut oversized = vec![0x82, 0xff];
        oversized.extend_from_slice(&(MAX_CLIENT_FRAME as u64 + 1).to_be_bytes());
        assert_eq!(take_frame(&mut oversized), Err(()));
    }
}
