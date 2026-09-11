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
    /// select, so a producer stops rather than writing into a dead socket.
    fn closed(&mut self) -> impl Future<Output = ()> + Send;
}

pub struct TextSink {
    io: TokioIo<hyper::upgrade::Upgraded>,
    scratch: Vec<u8>,
}

impl Sink for TextSink {
    async fn send(&mut self, text: &str) -> std::io::Result<()> {
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
    /// dashboard that pings and hears nothing hangs up; anything else is
    /// read and discarded.
    async fn closed(&mut self) {
        loop {
            let mut header = [0u8; 2];
            if self.io.read_exact(&mut header).await.is_err() {
                return;
            }
            let opcode = header[0] & 0x0f;
            let masked = header[1] & 0x80 != 0;

            let mut len = (header[1] & 0x7f) as usize;
            if len == 126 {
                let mut extended = [0u8; 2];
                if self.io.read_exact(&mut extended).await.is_err() {
                    return;
                }
                len = u16::from_be_bytes(extended) as usize;
            } else if len == 127 {
                let mut extended = [0u8; 8];
                if self.io.read_exact(&mut extended).await.is_err() {
                    return;
                }
                len = u64::from_be_bytes(extended) as usize;
            }
            if len > MAX_CLIENT_FRAME {
                return;
            }

            let mut mask = [0u8; 4];
            if masked && self.io.read_exact(&mut mask).await.is_err() {
                return;
            }

            let mut payload = vec![0u8; len];
            if self.io.read_exact(&mut payload).await.is_err() {
                return;
            }
            if masked {
                for (i, byte) in payload.iter_mut().enumerate() {
                    *byte ^= mask[i % 4];
                }
            }

            match opcode {
                OPCODE_CLOSE => {
                    // Echo the close, then stop: a client waits for it
                    // before releasing the socket.
                    let _ = self.write_control(OPCODE_CLOSE, &payload).await;
                    return;
                }
                OPCODE_PING => {
                    if self.write_control(OPCODE_PONG, &payload).await.is_err() {
                        return;
                    }
                }
                _ => {}
            }
        }
    }
}

impl TextSink {
    async fn write_control(&mut self, opcode: u8, payload: &[u8]) -> std::io::Result<()> {
        let mut frame = vec![0u8; payload.len() + MAX_FRAME_OVERHEAD];
        let n = crate::websocket::websocket_stream::pack_frame(opcode, false, payload, &mut frame);
        self.io.write_all(&frame[..n]).await
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
    /// The accept key is RFC 6455's example, so a wrong hash or a wrong
    /// GUID fails here rather than at a dashboard's handshake.
    #[test]
    fn the_accept_key_is_the_rfc_example() {
        let accept = crate::websocket::websocket_handler::create_websocket_key_response(
            "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
        );
        assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }
}
