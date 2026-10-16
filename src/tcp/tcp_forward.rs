//! The `TcpForward` half of connection handling, shared by the TCP and QUIC
//! servers. Both transports reach the same place once the inbound protocol has
//! been parsed: a destination, a stream carrying application data, and a proxy
//! selector to route it with.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::time::timeout;

use crate::address::{NetLocation, ResolvedLocation};
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::{ClientProxySelector, ConnectDecision};
use crate::copy_bidirectional::copy_bidirectional;
use crate::resolver::Resolver;
use crate::sniff::peek::{DEFAULT_MAX_BYTES, peek_stream};
use crate::sniff::{self, SniffSettings};
use crate::tcp::tcp_handler::TcpClientSetupResult;
use crate::util::write_all;

/// Why the connection to the remote location was not made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectFailure {
    /// The rules blocked it.
    Blocked,
    Refused,
    NetworkUnreachable,
    HostUnreachable,
    /// Anything else, a timeout included.
    Other,
}

impl ConnectFailure {
    fn from_error(e: &std::io::Error) -> Self {
        match e.kind() {
            std::io::ErrorKind::ConnectionRefused => Self::Refused,
            std::io::ErrorKind::NetworkUnreachable => Self::NetworkUnreachable,
            std::io::ErrorKind::HostUnreachable => Self::HostUnreachable,
            _ => Self::Other,
        }
    }
}

/// The reply an inbound protocol owes its client when the connection fails,
/// such as SOCKS5's non-zero REP (RFC 1928 section 6).
pub type ConnectFailureReply = fn(ConnectFailure) -> Box<[u8]>;

/// Everything `TcpServerSetupResult::TcpForward` carries, plus the resolver
/// and this listener's sniffing settings.
pub struct ForwardRequest {
    pub remote_location: NetLocation,
    pub server_stream: Box<dyn AsyncStream>,
    pub server_need_initial_flush: bool,
    pub connection_success_response: Option<Box<[u8]>>,
    pub connection_failure_response: Option<ConnectFailureReply>,
    pub initial_remote_data: Option<Box<[u8]>>,
    pub proxy_selector: Arc<ClientProxySelector>,
    pub resolver: Arc<dyn Resolver>,
    pub sniff: Option<SniffSettings>,
}

pub async fn forward_tcp(request: ForwardRequest) -> std::io::Result<()> {
    let ForwardRequest {
        remote_location,
        mut server_stream,
        server_need_initial_flush,
        mut connection_success_response,
        mut connection_failure_response,
        initial_remote_data,
        proxy_selector,
        resolver,
        sniff,
    } = request;

    let mut initial_data: Vec<u8> = initial_remote_data
        .map(|d| d.into_vec())
        .unwrap_or_default();
    let mut judged: ResolvedLocation = remote_location.clone().into();

    if let Some(settings) = sniff.as_ref()
        && let Some(addr) = sniff::sniff_target(&remote_location)
    {
        // The success response has to go first here. A SOCKS5 client sends
        // nothing until it sees one, so sniffing before it would time out on
        // an empty buffer. The cost is telling the client the connection
        // succeeded before we know it can, which is the same trade sing-box
        // and Xray make, and it only applies to listeners that opted in.
        if let Some(data) = connection_success_response.take() {
            write_all(&mut server_stream, &data).await?;
            server_stream.flush().await?;
            // Too late to say otherwise.
            connection_failure_response = None;
        }

        let result = peek_stream(
            &mut server_stream,
            &initial_data,
            &settings.protocols,
            settings.timeout,
            DEFAULT_MAX_BYTES,
        )
        .await;

        initial_data = result.buffered;

        if let Some(name) = result.sniffed.as_ref().and_then(|s| s.domain.as_deref()) {
            log::debug!("sniffed {name} for {remote_location}");
            judged = sniff::judged_location(name, addr);
        }
    }

    let setup_client_stream_future = timeout(
        Duration::from_secs(60),
        setup_client_tcp_stream(&mut server_stream, proxy_selector, resolver, judged),
    );

    let (failure, result) = match setup_client_stream_future.await {
        Ok(Ok(Some(s))) => (None, Ok(s)),
        // Must have been blocked.
        Ok(Ok(None)) => (Some(ConnectFailure::Blocked), Err(None)),
        Ok(Err(e)) => (
            Some(ConnectFailure::from_error(&e)),
            Err(Some(std::io::Error::new(
                e.kind(),
                format!("failed to setup client stream to {remote_location}: {e}"),
            ))),
        ),
        Err(elapsed) => (
            Some(ConnectFailure::Other),
            Err(Some(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("client setup to {remote_location} timed out: {elapsed}"),
            ))),
        ),
    };
    let mut client_stream = match result {
        Ok(s) => s,
        Err(e) => {
            if let (Some(reply), Some(failure)) = (connection_failure_response, failure) {
                let _ = write_all(&mut server_stream, &reply(failure)).await;
                let _ = server_stream.flush().await;
            }
            let _ = server_stream.shutdown().await;
            return e.map_or(Ok(()), Err);
        }
    };

    if let Some(data) = connection_success_response {
        // Already written above when sniffing ran.
        write_all(&mut server_stream, &data).await?;
        // server_need_initial_flush should be set to true by the handler if
        // it's needed.
    }

    let client_need_initial_flush = if initial_data.is_empty() {
        false
    } else {
        write_all(&mut client_stream, &initial_data).await?;
        true
    };

    let copy_result = relay(
        &mut server_stream,
        &mut client_stream,
        server_need_initial_flush,
        client_need_initial_flush,
    )
    .await;

    let (_, _) = futures::join!(server_stream.shutdown(), client_stream.shutdown());

    copy_result?;
    Ok(())
}

/// Carry bytes between the two sides until both directions have finished.
///
/// On Linux, two streams that are each nothing more than a TCP socket are
/// spliced inside the kernel; see `crate::splice`. Everything else is copied
/// through a buffer.
async fn relay(
    server_stream: &mut Box<dyn AsyncStream>,
    client_stream: &mut Box<dyn AsyncStream>,
    server_need_initial_flush: bool,
    client_need_initial_flush: bool,
) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    if let (Some(server), Some(client)) = (server_stream.plain_tcp(), client_stream.plain_tcp()) {
        // Nothing to flush first: a socket has no buffer of its own to hold
        // what was written to it.
        return crate::splice::splice_bidirectional(server, client).await;
    }
    copy_bidirectional(
        server_stream,
        client_stream,
        server_need_initial_flush,
        client_need_initial_flush,
    )
    .await
}

/// Judge the destination and open the client side of the connection.
///
/// Takes a `ResolvedLocation` rather than a `NetLocation` so that a caller
/// which already knows the address — after sniffing, for instance — can keep
/// it attached to the name.
pub async fn setup_client_tcp_stream(
    server_stream: &mut Box<dyn AsyncStream>,
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    remote_location: ResolvedLocation,
) -> std::io::Result<Option<Box<dyn AsyncStream>>> {
    let Some((client_stream, early_data)) =
        connect_client_tcp_stream(client_proxy_selector, resolver, remote_location).await?
    else {
        return Ok(None);
    };

    if let Some(data) = early_data {
        write_all(server_stream, &data).await?;
        server_stream.flush().await?;
    }

    Ok(Some(client_stream))
}

/// Dial the target, handing back anything the chain read past its own
/// handshake instead of writing it.
///
/// The early data belongs to the requester and has to reach it, but *when* it
/// may be written is the protocol's business: one that answers its own request
/// only after the dial has to put that answer in front of these bytes, or the
/// requester parses the target's greeting as the response. `Ok(None)` is the
/// rules blocking the request.
pub async fn connect_client_tcp_stream(
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    remote_location: ResolvedLocation,
) -> std::io::Result<Option<(Box<dyn AsyncStream>, Option<Vec<u8>>)>> {
    let action = client_proxy_selector
        .judge(remote_location, &resolver)
        .await?;

    match action {
        ConnectDecision::Allow {
            chain_group,
            remote_location,
        } => {
            let TcpClientSetupResult {
                client_stream,
                early_data,
            } = chain_group.connect_tcp(remote_location, &resolver).await?;

            Ok(Some((client_stream, early_data)))
        }
        ConnectDecision::Block => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use crate::address::{Address, NetLocationMask};
    use crate::client_proxy_chain::ClientChainGroup;
    use crate::client_proxy_selector::{ConnectAction, ConnectRule};
    use crate::config::{ClientChain, ClientChainHop, ClientConfig, ConfigSelection};
    use crate::option_util::{NoneOrSome, OneOrSome};
    use crate::resolver::NativeResolver;
    use crate::sniff::SniffedProtocol;
    use crate::tcp::chain_builder::build_client_chain_group;

    use super::*;

    /// Accepts one connection, reads it to EOF and reports everything it got.
    async fn spawn_recorder() -> (SocketAddr, tokio::sync::oneshot::Receiver<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut received = Vec::new();
            let _ = stream.read_to_end(&mut received).await;
            let _ = tx.send(received);
        });

        (addr, rx)
    }

    fn direct_group(resolver: Arc<dyn Resolver>) -> ClientChainGroup {
        let chain = ClientChain {
            hops: OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(
                ClientConfig::default(),
            ))),
        };
        build_client_chain_group(NoneOrSome::One(chain), resolver)
    }

    fn allow_everything(resolver: Arc<dyn Resolver>) -> Arc<ClientProxySelector> {
        let rule = ConnectRule::new(
            vec![NetLocationMask::ANY],
            vec![],
            ConnectAction::new_allow(None, direct_group(resolver)),
        );
        Arc::new(ClientProxySelector::new(vec![rule]))
    }

    struct Outcome {
        upstream_received: Vec<u8>,
        client_received: Vec<u8>,
    }

    /// Runs one connection through `forward_tcp` and returns what each side
    /// saw.
    ///
    /// The client writes `payload` only after reading the success response, if
    /// there is one, which is how a SOCKS5 client behaves: it says nothing
    /// until it has one.
    async fn drive(
        payload: &[u8],
        connection_success_response: Option<Box<[u8]>>,
        sniff: Option<SniffSettings>,
        selector: Option<Arc<ClientProxySelector>>,
        upstream: Option<SocketAddr>,
    ) -> Outcome {
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());

        let (upstream_addr, received) = match upstream {
            Some(addr) => (addr, None),
            None => {
                let (addr, rx) = spawn_recorder().await;
                (addr, Some(rx))
            }
        };

        let selector = selector.unwrap_or_else(|| allow_everything(resolver.clone()));

        let inbound = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let inbound_addr = inbound.local_addr().unwrap();

        let expect_before_payload = connection_success_response
            .as_ref()
            .map(|r| r.len())
            .unwrap_or(0);

        let server_resolver = resolver.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = inbound.accept().await.unwrap();
            forward_tcp(ForwardRequest {
                remote_location: NetLocation::new(
                    Address::Ipv4(Ipv4Addr::LOCALHOST),
                    upstream_addr.port(),
                ),
                server_stream: Box::new(stream),
                server_need_initial_flush: false,
                connection_success_response,
                connection_failure_response: None,
                initial_remote_data: None,
                proxy_selector: selector,
                resolver: server_resolver,
                sniff,
            })
            .await
        });

        let mut client = TcpStream::connect(inbound_addr).await.unwrap();

        let mut client_received = vec![0u8; expect_before_payload];
        if expect_before_payload > 0 {
            client.read_exact(&mut client_received).await.unwrap();
        }

        client.write_all(payload).await.unwrap();
        client.flush().await.unwrap();
        client.shutdown().await.unwrap();

        let _ = server.await.unwrap();

        let upstream_received = match received {
            Some(rx) => rx.await.unwrap(),
            None => Vec::new(),
        };

        Outcome {
            upstream_received,
            client_received,
        }
    }

    fn tls_and_http() -> Option<SniffSettings> {
        Some(SniffSettings {
            protocols: vec![SniffedProtocol::Tls, SniffedProtocol::Http],
            timeout: Duration::from_millis(300),
        })
    }

    #[tokio::test]
    async fn a_sniffed_client_hello_reaches_the_remote_unchanged() {
        let hello = crate::sniff::test_client_hello("ex.com");
        let outcome = drive(&hello, None, tls_and_http(), None, None).await;
        assert_eq!(outcome.upstream_received, hello);
    }

    #[tokio::test]
    async fn an_http_request_reaches_the_remote_unchanged() {
        let request = b"GET / HTTP/1.1\r\nHost: ex.com\r\n\r\nbody";
        let outcome = drive(request, None, tls_and_http(), None, None).await;
        assert_eq!(outcome.upstream_received, request);
    }

    #[tokio::test]
    async fn unrecognised_traffic_reaches_the_remote_unchanged() {
        let payload = b"SSH-2.0-OpenSSH_9.6\r\nand then some more bytes";
        let outcome = drive(payload, None, tls_and_http(), None, None).await;
        assert_eq!(outcome.upstream_received, payload);
    }

    #[tokio::test]
    async fn traffic_that_stalls_mid_handshake_reaches_the_remote_unchanged() {
        // A prefix that keeps the TLS sniffer asking for more until the
        // deadline, so the whole timeout path is exercised.
        let hello = crate::sniff::test_client_hello("ex.com");
        let partial = &hello[..9];
        let outcome = drive(partial, None, tls_and_http(), None, None).await;
        assert_eq!(outcome.upstream_received, partial);
    }

    #[tokio::test]
    async fn the_stream_is_unchanged_with_sniffing_off() {
        let hello = crate::sniff::test_client_hello("ex.com");
        let outcome = drive(&hello, None, None, None, None).await;
        assert_eq!(outcome.upstream_received, hello);
    }

    #[tokio::test]
    async fn the_success_response_goes_out_before_sniffing_starts() {
        // The client here writes nothing until it has read the response, so
        // this only completes if the response was written first. With the old
        // ordering it would stall until the sniff deadline.
        let hello = crate::sniff::test_client_hello("ex.com");
        let response: Box<[u8]> = b"READY".to_vec().into_boxed_slice();
        let outcome = drive(&hello, Some(response), tls_and_http(), None, None).await;

        assert_eq!(outcome.client_received, b"READY");
        assert_eq!(outcome.upstream_received, hello);
    }

    #[tokio::test]
    async fn routing_matches_the_sniffed_name_not_the_address() {
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let (upstream_addr, received) = spawn_recorder().await;

        // Only a rule naming the sniffed host allows the connection.
        // `matches_domain` matches a suffix at a label boundary, so the mask
        // is the bare parent domain. Without sniffing the destination is
        // 127.0.0.1 and the block rule wins.
        let selector = Arc::new(ClientProxySelector::new(vec![
            ConnectRule::new(
                vec![NetLocationMask::from("com").unwrap()],
                vec![],
                ConnectAction::new_allow(None, direct_group(resolver.clone())),
            ),
            ConnectRule::new(
                vec![NetLocationMask::ANY],
                vec![],
                ConnectAction::new_block(),
            ),
        ]));

        let hello = crate::sniff::test_client_hello("ex.com");
        drive(
            &hello,
            None,
            tls_and_http(),
            Some(selector),
            Some(upstream_addr),
        )
        .await;

        let upstream_received = tokio::time::timeout(Duration::from_secs(5), received)
            .await
            .expect("the domain rule should have allowed the connection")
            .unwrap();

        assert_eq!(upstream_received, hello);
    }

    fn name_the_failure(failure: ConnectFailure) -> Box<[u8]> {
        format!("{failure:?}").into_bytes().into_boxed_slice()
    }

    /// Forward to `port` on loopback and return what the client was told.
    async fn failure_reply(selector: Arc<ClientProxySelector>, port: u16) -> Vec<u8> {
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let inbound = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let inbound_addr = inbound.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = inbound.accept().await.unwrap();
            forward_tcp(ForwardRequest {
                remote_location: NetLocation::new(Address::Ipv4(Ipv4Addr::LOCALHOST), port),
                server_stream: Box::new(stream),
                server_need_initial_flush: false,
                connection_success_response: Some(b"OK".to_vec().into_boxed_slice()),
                connection_failure_response: Some(name_the_failure),
                initial_remote_data: None,
                proxy_selector: selector,
                resolver,
                sniff: None,
            })
            .await
        });
        let mut client = TcpStream::connect(inbound_addr).await.unwrap();
        let mut received = Vec::new();
        client.read_to_end(&mut received).await.unwrap();
        let _ = server.await.unwrap();
        received
    }

    /// RFC 1928 section 6 has the server reply before closing; the reply is
    /// the inbound's, chosen by what went wrong.
    #[tokio::test]
    async fn a_refused_connection_is_answered_with_the_failure_reply() {
        let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = closed.local_addr().unwrap().port();
        drop(closed);

        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let reply = failure_reply(allow_everything(resolver), port).await;
        assert_eq!(reply, b"Refused");
    }

    #[tokio::test]
    async fn a_blocked_connection_is_answered_with_the_failure_reply() {
        let block_all = Arc::new(ClientProxySelector::new(vec![ConnectRule::new(
            vec![NetLocationMask::ANY],
            vec![],
            ConnectAction::new_block(),
        )]));
        let reply = failure_reply(block_all, 9).await;
        assert_eq!(reply, b"Blocked");
    }
}
