//! WebSocket early data: the first bytes of a connection carried in its
//! upgrade request, base64url-encoded, saving the round trip before the
//! proxy request can be read (TR-3). The names and the wire format follow
//! sing-box (`transport/v2raywebsocket`): with `early_data_header_name` set,
//! the data rides in that header (Xray sends and expects
//! `Sec-WebSocket-Protocol`); without it, it is appended to the path.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::websocket_handler::{ClientRequest, client_handshake};
use super::websocket_stream::WebsocketStream;
use crate::async_stream::{AsyncPing, AsyncStream, SocketPassthrough};
use crate::config::WebsocketPingType;

#[derive(Debug, Clone)]
pub struct EarlyData {
    /// The most bytes of the first write the request carries.
    pub max: usize,
    /// The header that carries them, or `None` for the path.
    pub header_name: Option<String>,
}

pub fn encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Decode early data as Xray's server does: base64url without padding, also
/// taking the standard alphabet and padding.
pub fn decode(encoded: &str) -> io::Result<Vec<u8>> {
    let normalized: String = encoded
        .chars()
        .filter(|c| *c != '=')
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            c => c,
        })
        .collect();
    URL_SAFE_NO_PAD.decode(normalized).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid websocket early data: {e}"),
        )
    })
}

type Handshake = Pin<Box<dyn Future<Output = io::Result<WebsocketStream>> + Send + Sync>>;

enum State {
    /// Nothing written yet: the upgrade request waits for the first write.
    Waiting(Box<dyn AsyncStream>),
    Handshaking(Handshake),
    Open(WebsocketStream),
    Failed(io::ErrorKind, String),
}

/// The client's WebSocket stream when early data is on. As sing-box's
/// `EarlyWebsocketConn`, the upgrade is sent with the first write, carrying
/// up to `max` of its bytes; reads wait until then.
pub struct EarlyDataStream {
    state: State,
    request: Arc<ClientRequest>,
    header_name: Option<String>,
    max: usize,
    /// Whichever half waits while the handshake has not started, or while
    /// the other half drives it, is woken when it starts and when it ends.
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
}

impl EarlyDataStream {
    pub fn new(
        stream: Box<dyn AsyncStream>,
        request: Arc<ClientRequest>,
        early_data: &EarlyData,
    ) -> Self {
        // A larger first write sends the rest as frames.
        let max = early_data
            .max
            .min(request.early_data_room(early_data.header_name.as_deref()));
        Self {
            state: State::Waiting(stream),
            request,
            header_name: early_data.header_name.clone(),
            max,
            read_waker: None,
            write_waker: None,
        }
    }

    fn wake_both(&mut self) {
        for waker in [self.read_waker.take(), self.write_waker.take()]
            .into_iter()
            .flatten()
        {
            waker.wake();
        }
    }

    /// Send the upgrade request, carrying `early`.
    fn start(&mut self, early: &[u8]) {
        let not_started = State::Failed(
            io::ErrorKind::NotConnected,
            "websocket handshake did not start".to_string(),
        );
        match std::mem::replace(&mut self.state, not_started) {
            State::Waiting(stream) => {
                let encoded = (!early.is_empty()).then(|| encode(early));
                self.state = State::Handshaking(Box::pin(client_handshake(
                    Arc::clone(&self.request),
                    stream,
                    self.header_name.clone(),
                    encoded,
                )));
                self.wake_both();
            }
            state => self.state = state,
        }
    }

    /// Ready once the handshake is done; a waiting half is woken then.
    fn poll_open(&mut self, cx: &mut Context<'_>, reading: bool) -> Poll<io::Result<()>> {
        let result = match &mut self.state {
            State::Waiting(_) => None,
            State::Handshaking(handshake) => match handshake.as_mut().poll(cx) {
                Poll::Pending => None,
                Poll::Ready(Ok(stream)) => {
                    self.state = State::Open(stream);
                    self.wake_both();
                    Some(Ok(()))
                }
                Poll::Ready(Err(e)) => {
                    self.state = State::Failed(e.kind(), e.to_string());
                    self.wake_both();
                    Some(Err(e))
                }
            },
            State::Open(_) => Some(Ok(())),
            State::Failed(kind, message) => Some(Err(io::Error::new(*kind, message.clone()))),
        };
        match result {
            Some(result) => Poll::Ready(result),
            None => {
                let waker = Some(cx.waker().clone());
                if reading {
                    self.read_waker = waker;
                } else {
                    self.write_waker = waker;
                }
                Poll::Pending
            }
        }
    }

    fn open(&mut self) -> io::Result<Pin<&mut WebsocketStream>> {
        match &mut self.state {
            State::Open(stream) => Ok(Pin::new(stream)),
            _ => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "websocket handshake not done",
            )),
        }
    }
}

impl AsyncRead for EarlyDataStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        std::task::ready!(this.poll_open(cx, true))?;
        this.open()?.poll_read(cx, buf)
    }
}

impl AsyncWrite for EarlyDataStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let State::Waiting(_) = this.state {
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            // These bytes are in the request; a failed handshake is reported
            // by the next write, flush or read.
            let n = buf.len().min(this.max);
            this.start(&buf[..n]);
            return Poll::Ready(Ok(n));
        }
        std::task::ready!(this.poll_open(cx, false))?;
        this.open()?.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let State::Waiting(_) = this.state {
            return Poll::Ready(Ok(()));
        }
        std::task::ready!(this.poll_open(cx, false))?;
        this.open()?.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // Nothing was written: the upgrade still has to happen, for the
        // server to see the close.
        this.start(&[]);
        std::task::ready!(this.poll_open(cx, false))?;
        this.open()?.poll_shutdown(cx)
    }
}

impl AsyncPing for EarlyDataStream {
    fn supports_ping(&self) -> bool {
        self.request.ping_type != WebsocketPingType::Disabled
    }

    fn poll_write_ping(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        match &mut self.get_mut().state {
            State::Open(stream) => Pin::new(stream).poll_write_ping(cx),
            _ => Poll::Ready(Ok(false)),
        }
    }
}

impl SocketPassthrough for EarlyDataStream {}

impl AsyncStream for EarlyDataStream {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::ResolvedLocation;
    use crate::async_stream::testing::TestStream;
    use crate::tcp::tcp_handler::{
        TcpClientHandler, TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult,
    };
    use crate::websocket::{
        WebsocketServerTarget, WebsocketTcpClientHandler, WebsocketTcpServerHandler,
    };
    use async_trait::async_trait;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
    use tokio::sync::mpsc;

    const PAYLOAD: &[u8] = b"hello early data";

    /// Hands the upgraded stream back as the setup result.
    #[derive(Debug)]
    struct Bare;

    #[async_trait]
    impl TcpClientHandler for Bare {
        async fn setup_client_tcp_stream(
            &self,
            client_stream: Box<dyn AsyncStream>,
            _remote_location: ResolvedLocation,
        ) -> io::Result<TcpClientSetupResult> {
            Ok(TcpClientSetupResult {
                client_stream,
                early_data: None,
            })
        }
    }

    /// Reads the payload, reports it, and answers "ok".
    #[derive(Debug)]
    struct Captures(mpsc::UnboundedSender<Vec<u8>>, usize);

    #[async_trait]
    impl TcpServerHandler for Captures {
        async fn setup_server_stream(
            &self,
            mut server_stream: Box<dyn AsyncStream>,
        ) -> io::Result<TcpServerSetupResult> {
            let mut got = vec![0u8; self.1];
            server_stream.read_exact(&mut got).await?;
            let _ = self.0.send(got);
            server_stream.write_all(b"ok").await?;
            server_stream.flush().await?;
            std::future::pending().await
        }
    }

    fn early(max: usize, header_name: Option<&str>) -> Option<EarlyData> {
        Some(EarlyData {
            max,
            header_name: header_name.map(str::to_string),
        })
    }

    /// A client and a server over a pipe; returns the client's stream and
    /// what the server's inner handler read.
    async fn pair(
        client_early: Option<EarlyData>,
        server_early: Option<EarlyData>,
        path: &str,
    ) -> (Box<dyn AsyncStream>, mpsc::UnboundedReceiver<Vec<u8>>) {
        pair_at(client_early, server_early, path, "/ws", PAYLOAD.len()).await
    }

    async fn pair_at(
        client_early: Option<EarlyData>,
        server_early: Option<EarlyData>,
        path: &str,
        server_path: &str,
        payload_len: usize,
    ) -> (Box<dyn AsyncStream>, mpsc::UnboundedReceiver<Vec<u8>>) {
        let (near, far) = duplex(65536);
        let (tx, rx) = mpsc::unbounded_channel();
        let server = WebsocketTcpServerHandler::new(vec![WebsocketServerTarget {
            matching_path: Some(server_path.to_string()),
            matching_headers: None,
            ping_type: WebsocketPingType::Disabled,
            early_data: server_early,
            handler: Box::new(Captures(tx, payload_len)),
        }]);
        tokio::spawn(async move {
            let _ = server.setup_server_stream(Box::new(TestStream(far))).await;
        });
        let client = WebsocketTcpClientHandler::new(
            "proxy.example.com:443".to_string(),
            Some(path.to_string()),
            None,
            WebsocketPingType::Disabled,
            client_early,
            Box::new(Bare),
        );
        let destination: ResolvedLocation =
            crate::address::NetLocation::from(std::net::SocketAddr::from(([1, 2, 3, 4], 80)))
                .into();
        let stream = client
            .setup_client_tcp_stream(Box::new(TestStream(near)), destination)
            .await
            .unwrap()
            .client_stream;
        (stream, rx)
    }

    async fn round_trip(stream: Box<dyn AsyncStream>, rx: mpsc::UnboundedReceiver<Vec<u8>>) {
        round_trip_with(stream, rx, PAYLOAD).await;
    }

    async fn round_trip_with(
        mut stream: Box<dyn AsyncStream>,
        mut rx: mpsc::UnboundedReceiver<Vec<u8>>,
        payload: &[u8],
    ) {
        stream.write_all(payload).await.unwrap();
        stream.flush().await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("the server read the payload")
            .unwrap();
        assert_eq!(got, payload);
        let mut ok = [0u8; 2];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut ok))
            .await
            .expect("the answer")
            .unwrap();
        assert_eq!(&ok, b"ok");
    }

    /// TR-3: early data in the path, split across the request and a frame.
    #[tokio::test]
    async fn early_data_in_the_path_reaches_the_server() {
        let (stream, rx) = pair(early(5, None), early(2048, None), "/ws").await;
        round_trip(stream, rx).await;
    }

    /// The whole first write fits in the request.
    #[tokio::test]
    async fn a_first_write_within_the_maximum_rides_whole() {
        let (stream, rx) = pair(early(2048, None), early(2048, None), "/ws").await;
        round_trip(stream, rx).await;
    }

    /// TR-3: early data in `Sec-WebSocket-Protocol`, as Xray sends it; the
    /// server echoes the protocol back.
    #[tokio::test]
    async fn early_data_in_a_header_reaches_the_server() {
        let header = Some("Sec-WebSocket-Protocol");
        let (stream, rx) = pair(
            early(2048, header),
            early(2048, Some("sec-websocket-protocol")),
            "/ws",
        )
        .await;
        round_trip(stream, rx).await;
    }

    /// A query in the configured path stays after the data.
    #[tokio::test]
    async fn a_query_follows_the_data_in_the_path() {
        let (stream, rx) = pair(early(5, None), early(2048, None), "/ws?ed=2048").await;
        round_trip(stream, rx).await;
    }

    /// A query configured on both ends still matches: the data goes before
    /// it, and the server takes it from before it.
    #[tokio::test]
    async fn a_query_configured_on_both_ends_matches() {
        let (stream, rx) = pair_at(
            early(5, None),
            early(2048, None),
            "/ws?token=abc",
            "/ws?token=abc",
            PAYLOAD.len(),
        )
        .await;
        round_trip(stream, rx).await;
    }

    /// A maximum past what one HTTP line carries sends what fits in the
    /// request and the rest as frames, in either mode, between two shoes
    /// ends; the echoed protocol header fits the client's parser too.
    #[tokio::test]
    async fn a_large_maximum_fits_the_line_limit() {
        let payload: Vec<u8> = (0..10_000u32).map(|i| i as u8).collect();
        for header in [None, Some("Sec-WebSocket-Protocol")] {
            let (stream, rx) = pair_at(
                early(8192, header),
                early(8192, header.map(|_| "sec-websocket-protocol")),
                "/ws",
                "/ws",
                payload.len(),
            )
            .await;
            round_trip_with(stream, rx, &payload).await;
        }
    }

    /// The client's reads wait for its first write, which sends the upgrade.
    #[tokio::test]
    async fn reads_wait_for_the_first_write() {
        let (mut stream, rx) = pair(early(2048, None), early(2048, None), "/ws").await;
        let mut byte = [0u8; 1];
        assert!(
            tokio::time::timeout(Duration::from_millis(100), stream.read(&mut byte))
                .await
                .is_err(),
            "nothing to read before the upgrade"
        );
        round_trip(stream, rx).await;
    }

    #[test]
    fn decoding_takes_both_alphabets_and_padding() {
        let data = [0xfbu8, 0xff, 0xfe];
        assert_eq!(decode(&encode(&data)).unwrap(), data);
        assert_eq!(decode("+//+").unwrap(), [0xfb, 0xff, 0xfe]);
        assert_eq!(decode("aGk=").unwrap(), b"hi");
        assert!(decode("not base64!").is_err());
    }

    /// Undecodable early data is refused with 400, before the upgrade.
    #[tokio::test]
    async fn undecodable_early_data_is_refused() {
        let server = WebsocketTcpServerHandler::new(vec![WebsocketServerTarget {
            matching_path: Some("/ws".to_string()),
            matching_headers: None,
            ping_type: WebsocketPingType::Disabled,
            early_data: early(2048, None),
            handler: Box::new(Captures(mpsc::unbounded_channel().0, PAYLOAD.len())),
        }]);
        let (near, mut far) = duplex(8192);
        far.write_all(
            b"GET /ws!!! HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        )
        .await
        .unwrap();
        assert!(
            server
                .setup_server_stream(Box::new(TestStream(near)))
                .await
                .is_err()
        );
        let mut response = vec![0u8; 256];
        let n = far.read(&mut response).await.unwrap();
        assert!(response[..n].starts_with(b"HTTP/1.1 400 "));
    }
}
