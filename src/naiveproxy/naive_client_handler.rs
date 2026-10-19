//! NaiveProxy client handler with HTTP/2 multiplexing support.
//!
//! This handler maintains a persistent H2 session and multiplexes all outgoing
//! connections over the same underlying TLS connection, matching the behavior
//! of the reference NaiveProxy client.
//!
//! ## Multiplexing Design
//!
//! Following the h2 crate's pattern (see their benchmarks), `NaiveClientSession`
//! is cheaply cloneable because h2's `SendRequest` internally uses `Arc<Mutex<...>>`.
//!
//! The handler maintains `Arc<Mutex<Option<NaiveClientSession>>>` only for:
//! - Lazy initialization (session created on first request)
//! - Reconnection (recreate session if connection dies)
//!
//! Once obtained, the session is cloned and used directly without holding locks,
//! enabling concurrent stream creation.

use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use base64::engine::{Engine as _, general_purpose::STANDARD as BASE64};
use log::debug;
use tokio::sync::Mutex;

use crate::address::ResolvedLocation;
use crate::async_stream::AsyncStream;
use crate::tcp::tcp_handler::{TcpClientHandler, TcpClientSetupResult};

use super::naive_client_session::NaiveClientSession;

/// NaiveProxy client handler with HTTP/2 multiplexing.
///
/// Establishes HTTP/2 CONNECT tunnels with padding support, reusing H2 sessions
/// across multiple connections for efficient multiplexing.
pub struct NaiveProxyTcpClientHandler {
    /// Base64-encoded credentials for Basic Auth
    auth_header: String,
    /// Enable padding
    padding_enabled: bool,
    /// Session slot for lazy init and reconnection (session itself is cheap to clone)
    session: Arc<Mutex<Option<NaiveClientSession>>>,
}

impl std::fmt::Debug for NaiveProxyTcpClientHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NaiveProxyTcpClientHandler")
            .field("padding_enabled", &self.padding_enabled)
            .finish()
    }
}

impl Clone for NaiveProxyTcpClientHandler {
    fn clone(&self) -> Self {
        Self {
            auth_header: self.auth_header.clone(),
            padding_enabled: self.padding_enabled,
            // Share the same session slot across clones for multiplexing
            session: Arc::clone(&self.session),
        }
    }
}

impl NaiveProxyTcpClientHandler {
    pub fn new(username: &str, password: &str, padding_enabled: bool) -> Self {
        let credentials = format!("{}:{}", username, password);
        let auth_header = format!("Basic {}", BASE64.encode(&credentials));

        Self {
            auth_header,
            padding_enabled,
            session: Arc::new(Mutex::new(None)),
        }
    }
}

#[async_trait]
impl TcpClientHandler for NaiveProxyTcpClientHandler {
    /// A CONNECT stream on the live H2 session, if there is one: no new TCP
    /// connection, no new TLS handshake. Every proxied connection used to
    /// dial and handshake a fresh TLS connection only to drop it unused when
    /// a session already existed (NA-N1).
    ///
    /// A session that turns out to be dead is cleared and `None` returned,
    /// so the chain dials a new one; a target the proxy refuses is an error,
    /// since a new connection would be refused too.
    async fn try_reuse_tcp_stream(
        &self,
        remote_location: &ResolvedLocation,
    ) -> Option<io::Result<TcpClientSetupResult>> {
        let mut session = {
            let guard = self.session.lock().await;
            guard.as_ref().filter(|s| s.is_ready()).cloned()
        }?;
        match session
            .open_stream(
                remote_location.location(),
                &self.auth_header,
                self.padding_enabled,
            )
            .await
        {
            Ok(stream) => {
                debug!("NaiveProxy: stream opened on the existing session");
                Some(Ok(TcpClientSetupResult {
                    client_stream: stream,
                    early_data: None,
                }))
            }
            Err(e) if !session.is_ready() => {
                debug!("NaiveProxy: the session is gone ({e}); dialling a new one");
                self.forget(&session).await;
                None
            }
            Err(e) => Some(Err(e)),
        }
    }

    /// A fresh transport: a new H2 session on it, which becomes the one
    /// later connections reuse.
    async fn setup_client_tcp_stream(
        &self,
        client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> io::Result<TcpClientSetupResult> {
        debug!("NaiveProxy: creating new H2 session for multiplexing");
        let mut session = NaiveClientSession::new(client_stream).await?;
        *self.session.lock().await = Some(session.clone());

        let stream = session
            .open_stream(
                remote_location.location(),
                &self.auth_header,
                self.padding_enabled,
            )
            .await?;

        Ok(TcpClientSetupResult {
            client_stream: stream,
            early_data: None,
        })
    }
}

impl NaiveProxyTcpClientHandler {
    /// Clear the slot if it still holds `dead`; a session another connection
    /// stored in the meantime stays.
    async fn forget(&self, dead: &NaiveClientSession) {
        let mut guard = self.session.lock().await;
        if guard.as_ref().is_some_and(|s| s.is_same_session(dead)) {
            *guard = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handler_new_encodes_credentials() {
        let handler = NaiveProxyTcpClientHandler::new("user", "pass", true);
        // Base64 of "user:pass" is "dXNlcjpwYXNz"
        assert_eq!(handler.auth_header, "Basic dXNlcjpwYXNz");
    }

    #[test]
    fn test_handler_new_special_chars_in_credentials() {
        let handler = NaiveProxyTcpClientHandler::new("user@domain", "p@ss:word!", false);
        // Verify it encodes without panicking
        assert!(handler.auth_header.starts_with("Basic "));
    }

    #[test]
    fn test_handler_clone_shares_session_slot() {
        let handler1 = NaiveProxyTcpClientHandler::new("user", "pass", true);
        let handler2 = handler1.clone();

        // Both handlers should share the same session slot
        assert!(Arc::ptr_eq(&handler1.session, &handler2.session));
    }

    #[test]
    fn test_handler_is_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<NaiveProxyTcpClientHandler>();
        assert_sync::<NaiveProxyTcpClientHandler>();
    }

    use std::sync::Arc as StdArc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// An H2 CONNECT server on loopback that answers 200 and echoes each
    /// stream. `connections` counts TCP connections; `stop` makes it drop
    /// every connection it holds.
    struct EchoServer {
        addr: std::net::SocketAddr,
        connections: StdArc<AtomicUsize>,
        stop: tokio::sync::watch::Sender<bool>,
    }

    async fn echo_server() -> EchoServer {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connections = StdArc::new(AtomicUsize::new(0));
        let (stop, stop_rx) = tokio::sync::watch::channel(false);
        let counted = connections.clone();
        tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                counted.fetch_add(1, Ordering::SeqCst);
                let mut stop_rx = stop_rx.clone();
                tokio::spawn(async move {
                    let mut conn = h2::server::handshake(tcp).await.unwrap();
                    loop {
                        tokio::select! {
                            _ = stop_rx.changed() => return,
                            accepted = conn.accept() => {
                                let Some(Ok((request, mut respond))) = accepted else { return };
                                let response = http::Response::builder().status(200).body(()).unwrap();
                                let mut send = respond.send_response(response, false).unwrap();
                                let mut body = request.into_body();
                                tokio::spawn(async move {
                                    while let Some(Ok(data)) = body.data().await {
                                        let _ = body.flow_control().release_capacity(data.len());
                                        if send.send_data(data, false).is_err() {
                                            return;
                                        }
                                    }
                                });
                            }
                        }
                    }
                });
            }
        });
        EchoServer {
            addr,
            connections,
            stop,
        }
    }

    fn target() -> ResolvedLocation {
        crate::address::NetLocation::from_ip_addr(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)),
            443,
        )
        .into()
    }

    async fn dial(server: &EchoServer) -> Box<dyn AsyncStream> {
        Box::new(tokio::net::TcpStream::connect(server.addr).await.unwrap())
    }

    async fn round_trip(stream: &mut Box<dyn AsyncStream>, payload: &[u8]) {
        stream.write_all(payload).await.unwrap();
        stream.flush().await.unwrap();
        let mut echoed = vec![0u8; payload.len()];
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read_exact(&mut echoed),
        )
        .await
        .expect("echo")
        .unwrap();
        assert_eq!(echoed, payload);
    }

    /// NA-N1: the second connection rides the first one's H2 session -- no
    /// new TCP connection -- where it used to dial and drop one each time.
    #[tokio::test]
    async fn a_live_session_is_reused_without_a_new_connection() {
        let server = echo_server().await;
        let handler = NaiveProxyTcpClientHandler::new("user", "pass", false);

        assert!(
            handler.try_reuse_tcp_stream(&target()).await.is_none(),
            "no session yet"
        );
        let mut first = handler
            .setup_client_tcp_stream(dial(&server).await, target())
            .await
            .unwrap()
            .client_stream;
        round_trip(&mut first, b"first").await;

        let mut second = handler
            .try_reuse_tcp_stream(&target())
            .await
            .expect("the session is live")
            .unwrap()
            .client_stream;
        round_trip(&mut second, b"second").await;
        assert_eq!(server.connections.load(Ordering::SeqCst), 1);
    }

    /// NA-N1: once the server drops the connection the session is not
    /// handed out again; the handler asks for a dial, and the next session
    /// works. It used to fail every connection until a restart.
    #[tokio::test]
    async fn a_dead_session_is_replaced_not_reused() {
        let server = echo_server().await;
        let handler = NaiveProxyTcpClientHandler::new("user", "pass", false);
        let mut first = handler
            .setup_client_tcp_stream(dial(&server).await, target())
            .await
            .unwrap()
            .client_stream;
        round_trip(&mut first, b"before").await;

        server.stop.send(true).unwrap();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match handler.try_reuse_tcp_stream(&target()).await {
                None => break,
                Some(_) => {
                    assert!(
                        tokio::time::Instant::now() < deadline,
                        "the dead session was still offered"
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            }
        }
        assert!(
            handler.session.lock().await.is_none(),
            "the slot was cleared"
        );

        let _ = server.stop.send(false);
        let server = echo_server().await;
        let mut fresh = handler
            .setup_client_tcp_stream(dial(&server).await, target())
            .await
            .unwrap()
            .client_stream;
        round_trip(&mut fresh, b"after").await;
    }

    /// A stream keeps its connection running after the session that opened
    /// it is replaced in the handler's slot.
    #[tokio::test]
    async fn a_stream_outlives_its_session_being_replaced() {
        let server = echo_server().await;
        let handler = NaiveProxyTcpClientHandler::new("user", "pass", false);
        let mut old = handler
            .setup_client_tcp_stream(dial(&server).await, target())
            .await
            .unwrap()
            .client_stream;
        // A second fresh dial replaces the session in the slot.
        let _new = handler
            .setup_client_tcp_stream(dial(&server).await, target())
            .await
            .unwrap()
            .client_stream;
        round_trip(&mut old, b"still here").await;
    }

    /// A stream the server has already reset -- as Go's HTTP/2 server does
    /// with RST_STREAM(NO_ERROR) once its handler returns -- shuts down
    /// cleanly instead of failing with "inactive stream".
    #[tokio::test]
    async fn shutdown_after_the_server_reset_the_stream_is_clean() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // The client says when it holds its stream; the server then ends and
        // resets it, and says when it has.
        let (opened_tx, opened_rx) = tokio::sync::oneshot::channel::<()>();
        let (reset_tx, reset_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut conn = h2::server::handshake(tcp).await.unwrap();
            let (_request, mut respond) = conn.accept().await.unwrap().unwrap();
            let response = http::Response::builder().status(200).body(()).unwrap();
            let mut send = respond.send_response(response, false).unwrap();
            tokio::spawn(async move {
                opened_rx.await.unwrap();
                send.send_data(bytes::Bytes::from_static(b"bye"), true)
                    .unwrap();
                send.send_reset(h2::Reason::NO_ERROR);
                let _ = reset_tx.send(());
            });
            // Keep driving the connection so the frames go out.
            while conn.accept().await.is_some() {}
        });
        let handler = NaiveProxyTcpClientHandler::new("user", "pass", false);
        let mut stream = handler
            .setup_client_tcp_stream(
                Box::new(tokio::net::TcpStream::connect(addr).await.unwrap()),
                target(),
            )
            .await
            .unwrap()
            .client_stream;
        opened_tx.send(()).unwrap();
        reset_rx.await.unwrap();
        let mut all = Vec::new();
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read_to_end(&mut all),
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        stream
            .shutdown()
            .await
            .expect("a closed stream shuts down cleanly");
    }
}
