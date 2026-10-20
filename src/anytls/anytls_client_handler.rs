//! AnyTLS Client Handler
//!
//! Implements TcpClientHandler for AnyTLS protocol outbound connections.
//!
//! Sessions are pooled as the reference client pools them (`ClientPool`): a
//! connection reuses the newest idle session through `try_reuse_tcp_stream`,
//! without a new TLS connection, and a session returns to the pool when its
//! stream ends.

use async_trait::async_trait;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

use crate::address::{Address, NetLocation, ResolvedLocation};
use crate::anytls::anytls_client_pool::ClientPool;
use crate::anytls::anytls_client_session::AnyTlsClientSession;
use crate::anytls::anytls_padding::{PaddingFactory, SharedPadding};
use crate::async_stream::AsyncMessageStream;
use crate::async_stream::AsyncStream;
use crate::tcp::tcp_handler::{TcpClientHandler, TcpClientSetupResult};
use crate::uot::UOT_V2_MAGIC_ADDRESS;
use crate::vless::VlessMessageStream;

/// AnyTLS client handler implementing TcpClientHandler.
///
/// Creates an AnyTLS session on the provided transport (expected to be TLS-wrapped),
/// opens multiplexed streams to destinations, and supports UDP-over-TCP via UoT magic addresses.
#[derive(Clone)]
pub struct AnyTlsClientHandler {
    /// Authentication password
    password: String,
    /// Padding factory for traffic obfuscation, shared with every session
    /// so a server's UpdatePaddingScheme reaches them all.
    padding: SharedPadding,
    /// UDP enabled
    udp_enabled: bool,
    /// Idle sessions, newest first.
    pool: Arc<ClientPool>,
}

impl std::fmt::Debug for AnyTlsClientHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnyTlsClientHandler")
            .field("udp_enabled", &self.udp_enabled)
            .finish()
    }
}

impl AnyTlsClientHandler {
    /// Create a new AnyTLS client handler. `min_idle_session` idle sessions
    /// are kept past the idle timeout, as sing-box's option of that name.
    pub fn new(
        password: String,
        padding: Arc<PaddingFactory>,
        udp_enabled: bool,
        min_idle_session: usize,
    ) -> Self {
        Self {
            password,
            padding: Arc::new(parking_lot::RwLock::new(padding)),
            udp_enabled,
            pool: ClientPool::new(min_idle_session),
        }
    }

    /// A new session on `client_stream`, which comes back to the pool when
    /// its stream ends.
    async fn new_session(
        &self,
        client_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<Arc<AnyTlsClientSession>> {
        let session =
            AnyTlsClientSession::new(client_stream, &self.password, Arc::clone(&self.padding))
                .await?;
        self.pool.attach(&session);
        Ok(session)
    }
}

#[async_trait]
impl TcpClientHandler for AnyTlsClientHandler {
    /// A stream on the newest idle session: no new TCP connection, no new
    /// TLS handshake. A session that fails to open one is closed and `None`
    /// returned, so the chain dials a new session, as the reference client
    /// does.
    async fn try_reuse_tcp_stream(
        &self,
        remote_location: &ResolvedLocation,
    ) -> Option<std::io::Result<TcpClientSetupResult>> {
        let session = self.pool.take()?;
        match session
            .open_stream(remote_location.clone().into_location())
            .await
        {
            Ok(stream) if !session.is_closed() => Some(Ok(TcpClientSetupResult {
                client_stream: Box::new(stream),
                early_data: None,
            })),
            Ok(_) | Err(_) => {
                session.shut().await;
                None
            }
        }
    }

    async fn setup_client_tcp_stream(
        &self,
        client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        let session = self.new_session(client_stream).await?;

        // The pool holds the session from the start, so a failed first open
        // has to close it: no stream exists to finish it.
        let stream = match session.open_stream(remote_location.into_location()).await {
            Ok(stream) => stream,
            Err(e) => {
                session.shut().await;
                return Err(e);
            }
        };

        Ok(TcpClientSetupResult {
            client_stream: Box::new(stream),
            early_data: None,
        })
    }

    fn supports_udp_over_tcp(&self) -> bool {
        self.udp_enabled
    }

    async fn setup_client_udp_bidirectional(
        &self,
        client_stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        if !self.udp_enabled {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "UDP not enabled for AnyTLS client",
            ));
        }

        let session = self.new_session(client_stream).await?;

        // UoT V2 Connect Mode: single destination via magic address
        let uot_dest = NetLocation::new(Address::Hostname(UOT_V2_MAGIC_ADDRESS.to_string()), 0);
        let mut stream = match session.open_stream(uot_dest).await {
            Ok(stream) => stream,
            Err(e) => {
                session.shut().await;
                return Err(e);
            }
        };

        // UoT V2 header: isConnect(1) + destination
        stream.write_u8(1).await?;
        stream
            .write_all(&encode_socks_address(target.location()))
            .await?;
        stream.flush().await?;

        let message_stream = VlessMessageStream::new(stream);

        Ok(Box::new(message_stream))
    }
}

/// Encode a NetLocation to SOCKS address format
fn encode_socks_address(location: &NetLocation) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32);

    match location.address() {
        Address::Ipv4(ip) => {
            buf.push(0x01); // IPv4
            buf.extend_from_slice(&ip.octets());
        }
        Address::Ipv6(ip) => {
            buf.push(0x04); // IPv6
            buf.extend_from_slice(&ip.octets());
        }
        Address::Hostname(host) => {
            buf.push(0x03); // Domain
            buf.push(host.len() as u8);
            buf.extend_from_slice(host.as_bytes());
        }
    }

    buf.extend_from_slice(&location.port().to_be_bytes());
    buf
}

#[cfg(test)]
mod pool_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::config::{RuleConfig, ServerProxyConfig};
    use crate::resolver::{NativeResolver, Resolver};
    use crate::tcp::tcp_client_handler_factory::create_tcp_client_proxy_selector;
    use crate::tcp::tcp_server_handler_factory::create_tcp_server_handler;

    const PASSWORD: &str = "anytls-pool-test";
    const SERVER_SCHEME: &str = "stop=3\n0=30-30\n1=100-400\n2=400-500";

    /// A loopback echo server, the destination.
    async fn echo() -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut tcp, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let (mut r, mut w) = tcp.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        addr
    }

    /// shoes's own AnyTLS server, built from config, on loopback; counts the
    /// TCP connections it accepts.
    async fn server() -> (std::net::SocketAddr, Arc<AtomicUsize>) {
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let config: ServerProxyConfig = serde_yaml::from_str(&format!(
            "type: anytls\nusers:\n  - password: {PASSWORD}\npadding_scheme:\n{}",
            SERVER_SCHEME
                .lines()
                .map(|l| format!("  - \"{l}\"\n"))
                .collect::<String>()
        ))
        .unwrap();
        let rules: Vec<RuleConfig> =
            serde_yaml::from_str("- masks: 0.0.0.0/0\n  action: allow\n").unwrap();
        let selector = Arc::new(create_tcp_client_proxy_selector(rules, resolver.clone()));
        let handler: Arc<dyn crate::tcp::tcp_handler::TcpServerHandler> =
            create_tcp_server_handler(config, &selector, &resolver, None).into();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let counter = accepted.clone();
        tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                counter.fetch_add(1, Ordering::SeqCst);
                let handler = handler.clone();
                tokio::spawn(async move {
                    let _ = handler.setup_server_stream(Box::new(tcp)).await;
                });
            }
        });
        (addr, accepted)
    }

    async fn dial(addr: std::net::SocketAddr) -> Box<dyn AsyncStream> {
        Box::new(tokio::net::TcpStream::connect(addr).await.unwrap())
    }

    /// Echo a payload, then close the stream, which returns its session.
    async fn use_and_close(mut stream: Box<dyn AsyncStream>, payload: &[u8]) {
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
        stream.shutdown().await.unwrap();
    }

    async fn wait_for_idle(handler: &AnyTlsClientHandler, n: usize) {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        while handler.pool.idle_len() != n {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the pool never held {n}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    fn handler(min_idle: usize) -> AnyTlsClientHandler {
        AnyTlsClientHandler::new(
            PASSWORD.to_string(),
            PaddingFactory::default_factory(),
            true,
            min_idle,
        )
    }

    /// AT-A1/A2: the second connection takes the first one's session from the
    /// pool -- one TCP connection to the server for both -- where every
    /// connection used to be a new session on a new connection.
    #[tokio::test]
    async fn a_finished_session_is_reused_for_the_next_connection() {
        let destination: ResolvedLocation = crate::address::NetLocation::from(echo().await).into();
        let (addr, accepted) = server().await;
        let handler = handler(0);

        assert!(
            handler.try_reuse_tcp_stream(&destination).await.is_none(),
            "empty pool"
        );
        let first = handler
            .setup_client_tcp_stream(dial(addr).await, destination.clone())
            .await
            .unwrap()
            .client_stream;
        use_and_close(first, b"first").await;
        wait_for_idle(&handler, 1).await;

        let second = handler
            .try_reuse_tcp_stream(&destination)
            .await
            .expect("an idle session")
            .unwrap()
            .client_stream;
        assert_eq!(handler.pool.idle_len(), 0, "in use, out of the pool");
        use_and_close(second, b"second").await;
        wait_for_idle(&handler, 1).await;
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            1,
            "one TCP connection for both"
        );
    }

    /// A destination that says goodbye and closes, so the server's FIN comes
    /// before the client's.
    async fn closer() -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut tcp, _) = listener.accept().await.unwrap();
                let _ = tcp.write_all(b"bye").await;
            }
        });
        addr
    }

    /// The server's FIN returns the session; the client's own FIN, coming
    /// after the session took a newer stream, must not return it again,
    /// which would offer an active session as idle.
    #[tokio::test]
    async fn a_late_fin_does_not_release_a_reused_session() {
        let echo: ResolvedLocation = crate::address::NetLocation::from(echo().await).into();
        let closing: ResolvedLocation = crate::address::NetLocation::from(closer().await).into();
        let (addr, _) = server().await;
        let handler = handler(0);

        let mut first = handler
            .setup_client_tcp_stream(dial(addr).await, closing)
            .await
            .unwrap()
            .client_stream;
        let mut bye = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            first.read_to_end(&mut bye),
        )
        .await
        .expect("the server's FIN")
        .unwrap();
        assert_eq!(bye, b"bye");
        wait_for_idle(&handler, 1).await;

        let second = handler
            .try_reuse_tcp_stream(&echo)
            .await
            .expect("an idle session")
            .unwrap()
            .client_stream;
        first.shutdown().await.unwrap();
        drop(first);
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert_eq!(handler.pool.idle_len(), 0, "the session is in use");

        use_and_close(second, b"second").await;
        wait_for_idle(&handler, 1).await;
    }

    /// AT-A1: the server's UpdatePaddingScheme replaces the client's scheme,
    /// for every session after it.
    #[tokio::test]
    async fn the_servers_padding_scheme_is_adopted() {
        let destination: ResolvedLocation = crate::address::NetLocation::from(echo().await).into();
        let (addr, _) = server().await;
        let handler = handler(0);
        let expected = PaddingFactory::new(SERVER_SCHEME.as_bytes()).unwrap();
        assert_ne!(handler.padding.read().md5(), expected.md5());

        let stream = handler
            .setup_client_tcp_stream(dial(addr).await, destination)
            .await
            .unwrap()
            .client_stream;
        use_and_close(stream, b"hello").await;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        while handler.padding.read().md5() != expected.md5() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the scheme was never adopted"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    /// The reaper closes sessions idle past the timeout, oldest first,
    /// keeping `min_idle_session` of them; a fresh one is left alone.
    #[tokio::test]
    async fn idle_sessions_expire_keeping_the_minimum() {
        let destination: ResolvedLocation = crate::address::NetLocation::from(echo().await).into();
        let (addr, _) = server().await;
        let handler = handler(1);
        // Three sessions at once, then all idle.
        let mut streams = Vec::new();
        for _ in 0..3 {
            streams.push(
                handler
                    .setup_client_tcp_stream(dial(addr).await, destination.clone())
                    .await
                    .unwrap()
                    .client_stream,
            );
        }
        for stream in streams {
            use_and_close(stream, b"x").await;
        }
        wait_for_idle(&handler, 3).await;

        let now = tokio::time::Instant::now();
        assert_eq!(
            handler.pool.expire_at(now).await,
            0,
            "none idle long enough"
        );
        let later = now + std::time::Duration::from_secs(31);
        assert_eq!(handler.pool.expire_at(later).await, 2);
        assert_eq!(handler.pool.idle_len(), 1, "min_idle_session kept");
    }
}
