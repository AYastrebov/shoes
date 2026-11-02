#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "predates the lint; see the [lints] note in Cargo.toml"
)]

use std::collections::HashMap;
use std::net::IpAddr;
// Only the unix-socket server takes a filesystem path.
#[cfg(unix)]
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use log::{debug, error};
use tokio::task::JoinHandle;

use crate::connections::ConnectionSet;
use tokio::time::timeout;

use super::tcp_client_handler_factory::create_tcp_client_proxy_selector;
use super::tcp_server_handler_factory::create_tcp_server_handler;

use crate::async_stream::AsyncMessageStream;
use crate::async_stream::{
    AsyncReadMessage, AsyncShutdownMessageExt, AsyncStream, AsyncWriteMessage,
};
use crate::client_proxy_selector::ConnectDecision;
use crate::config::{BindLocation, Config, ConfigSelection, ServerConfig, TcpConfig, Transport};
use crate::copy_bidirectional_message::copy_bidirectional_message;
use crate::quic_server::start_quic_servers;
use crate::resolver::Resolver;
use crate::routing::{ServerStream, run_udp_routing};
use crate::sniff::SniffSettings;
use crate::socket_util::{new_tcp_listener, set_tcp_keepalive};
use crate::tcp::tcp_forward::{ForwardRequest, forward_tcp};
use crate::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};
#[cfg(any(unix, windows))]
use crate::tun::start_tun_server;

/// How long an accept loop sleeps after an error that means the process is
/// out of a resource. Long enough to stop the spin, short enough that the
/// first connection after recovery waits imperceptibly.
const ACCEPT_EXHAUSTION_BACKOFF: std::time::Duration = std::time::Duration::from_millis(100);

/// Whether an accept error means a process- or system-wide resource ran out.
///
/// These do not consume the pending connection: `accept` fails and the
/// backlog entry stays, so the same error returns immediately and a bare
/// `continue` spins the loop at CPU speed, logging each turn -- fd
/// exhaustion elsewhere in the process turned into a hot loop and a log
/// flood here. Per-connection errors (`ECONNABORTED`) do consume their
/// entry and are safe to retry at once.
fn accept_exhausted_a_resource(e: &std::io::Error) -> bool {
    #[cfg(unix)]
    {
        matches!(
            e.raw_os_error(),
            Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM)
        )
    }
    #[cfg(windows)]
    {
        // WSAEMFILE, WSAENOBUFS: WinSock's numbers for the same facts.
        matches!(e.raw_os_error(), Some(10024 | 10055))
    }
}

/// The accept loop. The listener is bound by the caller, before the task
/// spawns: a bind failure must surface from `start_servers` as an error
/// the launch path can act on, not panic silently inside a task nobody
/// joins while the port goes unserved.
async fn run_tcp_server(
    listener: tokio::net::TcpListener,
    tcp_config: TcpConfig,
    resolver: Arc<dyn Resolver>,
    server_handler: Arc<dyn TcpServerHandler>,
    sniff: Option<SniffSettings>,
    connections: ConnectionSet,
) {
    let TcpConfig { no_delay } = tcp_config;
    let limiter = Arc::new(tokio::sync::Semaphore::new(
        crate::util::MAX_INFLIGHT_PER_LISTENER,
    ));

    loop {
        let permit = limiter
            .clone()
            .acquire_owned()
            .await
            .expect("the limiter is never closed");
        let (stream, addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!("Accept failed: {e}");
                if accept_exhausted_a_resource(&e) {
                    tokio::time::sleep(ACCEPT_EXHAUSTION_BACKOFF).await;
                }
                continue;
            }
        };

        if let Err(e) = set_tcp_keepalive(
            &stream,
            std::time::Duration::from_secs(300),
            std::time::Duration::from_secs(60),
        ) {
            error!("Failed to set TCP keepalive: {e}");
        }

        if no_delay && let Err(e) = stream.set_nodelay(true) {
            error!("Failed to set TCP nodelay: {e}");
        }

        // The permit rides inside the stream: handlers that answer
        // AlreadyHandled hand the connection to a detached task and
        // return, and a permit scoped to this task freed while their
        // sockets lived on -- the cap was a no-op for exactly those
        // paths. See PermitStream.
        let stream = crate::async_stream::PermitStream::new(stream, permit);

        let cloned_resolver = resolver.clone();
        let cloned_handler = server_handler.clone();
        let cloned_sniff = sniff.clone();
        connections.spawn(async move {
            match process_stream(stream, cloned_handler, cloned_resolver, cloned_sniff).await {
                Ok(()) => debug!("{}:{} finished successfully", addr.ip(), addr.port()),
                Err(e) => log::log!(
                    crate::util::connection_end_level(&e),
                    "{}:{} finished with error: {:?}",
                    addr.ip(),
                    addr.port(),
                    e
                ),
            }
        });
    }
}

/// Clear anything squatting on the socket path and bind. Runs before the
/// accept task spawns, for the same reason as the TCP listener above.
#[cfg(target_family = "unix")]
async fn bind_unix_listener(path_buf: PathBuf) -> std::io::Result<tokio::net::UnixListener> {
    if tokio::fs::symlink_metadata(&path_buf).await.is_ok() {
        println!(
            "WARNING: replacing file at socket path {}",
            path_buf.display()
        );
        let _ = tokio::fs::remove_file(&path_buf).await;
    }

    crate::socket_util::new_unix_listener(path_buf, 4096)
}

#[cfg(target_family = "unix")]
async fn run_unix_server(
    listener: tokio::net::UnixListener,
    resolver: Arc<dyn Resolver>,
    server_handler: Arc<dyn TcpServerHandler>,
    sniff: Option<SniffSettings>,
    connections: ConnectionSet,
) {
    let limiter = Arc::new(tokio::sync::Semaphore::new(
        crate::util::MAX_INFLIGHT_PER_LISTENER,
    ));
    loop {
        let permit = limiter
            .clone()
            .acquire_owned()
            .await
            .expect("the limiter is never closed");
        let (stream, addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!("Accept failed: {e:?}");
                if accept_exhausted_a_resource(&e) {
                    tokio::time::sleep(ACCEPT_EXHAUSTION_BACKOFF).await;
                }
                continue;
            }
        };

        // Same permit-in-stream reasoning as the TCP loop above.
        let stream = crate::async_stream::PermitStream::new(stream, permit);
        let cloned_resolver = resolver.clone();
        let cloned_handler = server_handler.clone();
        let cloned_sniff = sniff.clone();
        connections.spawn(async move {
            match process_stream(stream, cloned_handler, cloned_resolver, cloned_sniff).await {
                Ok(()) => debug!("{addr:?} finished successfully"),
                Err(e) => log::log!(
                    crate::util::connection_end_level(&e),
                    "{addr:?} finished with error: {e:?}"
                ),
            }
        });
    }
}

async fn setup_server_stream<AS>(
    stream: AS,
    server_handler: Arc<dyn TcpServerHandler>,
) -> std::io::Result<TcpServerSetupResult>
where
    AS: AsyncStream + 'static,
{
    let server_stream = Box::new(stream);
    server_handler.setup_server_stream(server_stream).await
}

pub async fn process_stream<AS>(
    stream: AS,
    server_handler: Arc<dyn TcpServerHandler>,
    resolver: Arc<dyn Resolver>,
    sniff: Option<SniffSettings>,
) -> std::io::Result<()>
where
    AS: AsyncStream + 'static,
{
    let setup_server_stream_future = timeout(
        Duration::from_secs(60),
        setup_server_stream(stream, server_handler),
    );

    let setup_result = match setup_server_stream_future.await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            return Err(std::io::Error::new(
                e.kind(),
                format!("failed to setup server stream: {e}"),
            ));
        }
        Err(elapsed) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("server setup timed out: {elapsed}"),
            ));
        }
    };

    match setup_result {
        TcpServerSetupResult::TcpForward {
            remote_location,
            stream: server_stream,
            need_initial_flush: server_need_initial_flush,
            proxy_selector,
            connection_success_response,
            connection_failure_response,
            initial_remote_data,
        } => {
            forward_tcp(ForwardRequest {
                remote_location,
                server_stream,
                server_need_initial_flush,
                connection_success_response,
                connection_failure_response,
                initial_remote_data,
                proxy_selector,
                resolver,
                sniff,
            })
            .await
        }
        TcpServerSetupResult::BidirectionalUdp {
            remote_location,
            stream: server_stream,
            need_initial_flush: server_need_initial_flush,
            proxy_selector,
        } if resolver.fake_ip().is_some() => {
            run_one_destination_udp_with_fake_ip(
                server_stream,
                remote_location,
                proxy_selector,
                resolver,
                server_need_initial_flush,
            )
            .await
        }
        TcpServerSetupResult::BidirectionalUdp {
            remote_location,
            stream: server_stream,
            need_initial_flush: server_need_initial_flush,
            proxy_selector,
        } => {
            let action = proxy_selector
                .judge(remote_location.into(), &resolver)
                .await?;
            match action {
                ConnectDecision::Allow {
                    chain_group,
                    remote_location,
                } => {
                    let client_stream = chain_group
                        .connect_udp_bidirectional(&resolver, remote_location)
                        .await?;

                    run_udp_copy(
                        server_stream,
                        client_stream,
                        server_need_initial_flush,
                        false,
                    )
                    .await
                }
                ConnectDecision::Block => Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "Blocked bidirectional udp forward",
                )),
            }
        }
        TcpServerSetupResult::MultiDirectionalUdp {
            stream: server_stream,
            need_initial_flush,
            proxy_selector,
        } => {
            // Per-destination routing: each packet is routed based on its destination
            run_udp_routing(
                ServerStream::Targeted(server_stream),
                proxy_selector,
                resolver,
                need_initial_flush,
            )
            .await
        }
        TcpServerSetupResult::SessionBasedUdp {
            stream: server_stream,
            need_initial_flush,
            proxy_selector,
        } => {
            // Per-destination routing: each session is routed based on its destination
            run_udp_routing(
                ServerStream::Session(server_stream),
                proxy_selector,
                resolver,
                need_initial_flush,
            )
            .await
        }
        TcpServerSetupResult::AlreadyHandled => {
            // Connection is being handled by a spawned task (e.g., Reality fallback).
            // Nothing more to do here.
            Ok(())
        }
    }
}

/// A UDP stream to one destination, with fake IP on: the destination may be
/// port 53 (answered from the pool), a fake address (routed by its name) or
/// an unmapped one (dropped). The router does all three for SOCKS UDP; a
/// stream with one fixed destination is that with the destination filled
/// in, so it goes through the router too.
pub(crate) async fn run_one_destination_udp_with_fake_ip(
    stream: Box<dyn AsyncMessageStream>,
    destination: crate::address::NetLocation,
    proxy_selector: Arc<crate::client_proxy_selector::ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    need_initial_flush: bool,
) -> std::io::Result<()> {
    // The router ends this stream with its one session, and that session
    // with the router's idle timeout, the direct copy's 200 seconds.
    run_udp_routing(
        ServerStream::Targeted(Box::new(OneDestination {
            inner: stream,
            destination,
        })),
        proxy_selector,
        resolver,
        need_initial_flush,
    )
    .await
}

/// A UDP stream to one destination, read as a stream whose every datagram
/// names that destination, so the router can serve it. Replies carry no
/// source on such a stream; the address the router gives is dropped.
struct OneDestination {
    inner: Box<dyn crate::async_stream::AsyncMessageStream>,
    destination: crate::address::NetLocation,
}

impl crate::async_stream::AsyncReadTargetedMessage for OneDestination {
    fn poll_read_targeted_message(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<crate::address::NetLocation>> {
        let this = &mut *self;
        std::task::ready!(std::pin::Pin::new(&mut this.inner).poll_read_message(cx, buf))?;
        std::task::Poll::Ready(Ok(this.destination.clone()))
    }
}

impl crate::async_stream::AsyncWriteSourcedMessage for OneDestination {
    fn poll_write_sourced_message(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
        _source: &std::net::SocketAddr,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_write_message(cx, buf)
    }

    fn replies_need_source(&self) -> bool {
        false
    }
}

impl crate::async_stream::AsyncFlushMessage for OneDestination {
    fn poll_flush_message(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush_message(cx)
    }
}

impl crate::async_stream::AsyncShutdownMessage for OneDestination {
    fn poll_shutdown_message(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown_message(cx)
    }
}

impl crate::async_stream::AsyncPing for OneDestination {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }

    fn poll_write_ping(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<bool>> {
        std::pin::Pin::new(&mut self.inner).poll_write_ping(cx)
    }
}

impl crate::async_stream::AsyncTargetedMessageStream for OneDestination {}

/// Unified function to run the appropriate UDP copy based on the setup result.
/// Copy messages bidirectionally between server and client message streams.
///
/// After the copy completes (whether successfully or with an error), both streams
/// are shut down to ensure proper cleanup and FIN frames are sent.
#[inline]
pub async fn run_udp_copy(
    mut server_stream: Box<dyn AsyncMessageStream>,
    mut client_stream: Box<dyn AsyncMessageStream>,
    server_need_initial_flush: bool,
    client_need_initial_flush: bool,
) -> std::io::Result<()> {
    let copy_result = copy_bidirectional_message(
        &mut server_stream,
        &mut client_stream,
        server_need_initial_flush,
        client_need_initial_flush,
    )
    .await;

    let (_, _) = futures::join!(
        server_stream.shutdown_message(),
        client_stream.shutdown_message()
    );

    copy_result
}

/// Start `config`'s listeners. The connections they accept run in
/// `connections`, which the caller owns: stopping the returned accept loops
/// stops new connections, and draining or aborting the set is what ends the
/// live ones.
pub async fn start_servers(
    config: Config,
    resolver: Arc<dyn Resolver>,
    connections: &ConnectionSet,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    match config {
        #[cfg(any(unix, windows))]
        Config::TunServer(tun_config) => start_tun_server(tun_config, resolver)
            .await
            .map(|t| vec![t]),
        #[cfg(not(any(unix, windows)))]
        Config::TunServer(_) => Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "TUN server is not supported on this platform",
        )),
        Config::Server(server_config) => {
            start_tcp_or_quic_servers(server_config, resolver, connections).await
        }
        _ => unreachable!("create_server_configs only returns Server and TunServer"),
    }
}

async fn start_tcp_or_quic_servers(
    config: ServerConfig,
    resolver: Arc<dyn Resolver>,
    connections: &ConnectionSet,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    let mut join_handles = Vec::with_capacity(3);

    match config.transport {
        Transport::Tcp => match start_tcp_servers(config.clone(), resolver, connections).await {
            Ok(handles) => {
                join_handles.extend(handles);
            }
            Err(e) => {
                for join_handle in join_handles {
                    join_handle.abort();
                }
                return Err(e);
            }
        },
        Transport::Quic => match start_quic_servers(config.clone(), resolver, connections).await {
            Ok(handles) => {
                join_handles.extend(handles);
            }
            Err(e) => {
                for join_handle in join_handles {
                    join_handle.abort();
                }
                return Err(e);
            }
        },
        // Validation admits `transport: udp` only for `tproxy`, and only on
        // Linux.
        #[cfg(target_os = "linux")]
        Transport::Udp => {
            match crate::tproxy::start_tproxy_udp_server(config.clone(), resolver, connections)
                .await
            {
                Ok(handles) => join_handles.extend(handles),
                Err(e) => return Err(e),
            }
        }
        #[cfg(not(target_os = "linux"))]
        Transport::Udp => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "transport: udp is the tproxy inbound's, which needs Linux",
            ));
        }
    }

    if join_handles.is_empty() {
        return Err(std::io::Error::other(format!(
            "failed to start servers at {}",
            config.bind_location
        )));
    }

    Ok(join_handles)
}

async fn start_tcp_servers(
    config: ServerConfig,
    resolver: Arc<dyn Resolver>,
    connections: &ConnectionSet,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    let ServerConfig {
        bind_location,
        tcp_settings,
        protocol,
        rules,
        sniff,
        ..
    } = config;

    println!("Starting {} TCP server at {}", protocol, bind_location);

    // Resolved once per listener rather than per connection: the protocol list
    // and the timeout do not change while the server runs.
    let sniff = sniff.as_ref().and_then(|s| s.to_settings());

    let rules = rules.map(ConfigSelection::unwrap_config).into_vec();
    // We should always have a direct entry.
    assert!(!rules.is_empty());

    let tcp_config = tcp_settings.unwrap_or_else(TcpConfig::default);

    let client_proxy_selector = Arc::new(create_tcp_client_proxy_selector(
        rules.clone(),
        resolver.clone(),
    ));

    let mut handles = vec![];

    match bind_location {
        BindLocation::Address(addresses) => {
            // Shares protocol state across ports without reusing an interface-specific UDP bind IP.
            let mut handlers: HashMap<IpAddr, Arc<dyn TcpServerHandler>> = HashMap::new();
            for address in addresses.into_vec() {
                for socket_addr in address.to_socket_addrs()? {
                    let tcp_handler = handlers
                        .entry(socket_addr.ip())
                        .or_insert_with(|| {
                            create_tcp_server_handler(
                                protocol.clone(),
                                &client_proxy_selector,
                                &resolver,
                                Some(socket_addr.ip()),
                            )
                            .into()
                        })
                        .clone();
                    debug!("TCP handler for {}: {tcp_handler:?}", socket_addr.ip());

                    let tcp_config = tcp_config.clone();
                    let resolver = resolver.clone();
                    let sniff = sniff.clone();
                    let listener = new_tcp_listener(socket_addr, 4096, None)?;
                    let handle = tokio::spawn(run_tcp_server(
                        listener,
                        tcp_config,
                        resolver,
                        tcp_handler,
                        sniff,
                        connections.clone(),
                    ));
                    handles.push(handle);
                }
            }
        }
        // Underscore-prefixed for the same reason as `_b` in socket_util:
        // consumed only by the unix arm.
        BindLocation::Path(_path_buf) => {
            #[cfg(target_family = "unix")]
            {
                let tcp_handler: Arc<dyn TcpServerHandler> =
                    create_tcp_server_handler(protocol, &client_proxy_selector, &resolver, None)
                        .into();
                debug!("TCP handler: {tcp_handler:?}");
                let listener = bind_unix_listener(_path_buf).await?;
                let handle = tokio::spawn(run_unix_server(
                    listener,
                    resolver,
                    tcp_handler,
                    sniff,
                    connections.clone(),
                ));
                handles.push(handle);
            }
            #[cfg(not(target_family = "unix"))]
            {
                return Err(std::io::Error::other(
                    "Unix sockets are not supported on this platform",
                ));
            }
        }
    }

    Ok(handles)
}

// Unix only: the errnos the one test names are libc's.
#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// EMFILE does not consume the backlog entry, so retrying instantly
    /// spins; ECONNABORTED does consume it, so backing off would only
    /// slow real clients behind it.
    #[test]
    fn only_resource_exhaustion_backs_the_accept_loop_off() {
        for errno in [libc::EMFILE, libc::ENFILE, libc::ENOBUFS, libc::ENOMEM] {
            assert!(accept_exhausted_a_resource(
                &std::io::Error::from_raw_os_error(errno)
            ));
        }
        for errno in [libc::ECONNABORTED, libc::EAGAIN, libc::EINTR] {
            assert!(!accept_exhausted_a_resource(
                &std::io::Error::from_raw_os_error(errno)
            ));
        }
    }

    /// A UDP stream to one destination (plain VLESS UDP, say) goes through
    /// the router when fake IP is on: a DNS query to port 53 on it is
    /// answered from the pool rather than carried to the server unanswered.
    #[tokio::test]
    async fn one_destination_udp_gets_fake_ip_through_the_router() {
        use crate::async_stream::{
            AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncShutdownMessage,
        };
        use crate::dns::fake_ip::{
            BypassList, FakeIpNetwork, FakeIpPool, FakeIpResolver, FakeIpResponder,
        };
        use hickory_resolver::proto::op::{Message, MessageType, OpCode, Query};
        use hickory_resolver::proto::rr::{Name, RData, RecordType};
        use std::collections::VecDeque;
        use std::pin::Pin;
        use std::str::FromStr;
        use std::sync::{Arc, Mutex};
        use std::task::{Context, Poll};
        use tokio::io::ReadBuf;

        struct Scripted {
            incoming: VecDeque<Vec<u8>>,
            written: Arc<Mutex<Vec<Vec<u8>>>>,
        }
        impl AsyncReadMessage for Scripted {
            fn poll_read_message(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<std::io::Result<()>> {
                match self.incoming.pop_front() {
                    Some(message) => {
                        buf.put_slice(&message);
                        Poll::Ready(Ok(()))
                    }
                    None => Poll::Pending,
                }
            }
        }
        impl AsyncWriteMessage for Scripted {
            fn poll_write_message(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<std::io::Result<()>> {
                self.written.lock().unwrap().push(buf.to_vec());
                Poll::Ready(Ok(()))
            }
        }
        impl AsyncFlushMessage for Scripted {
            fn poll_flush_message(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        impl AsyncShutdownMessage for Scripted {
            fn poll_shutdown_message(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        impl AsyncPing for Scripted {
            fn supports_ping(&self) -> bool {
                false
            }
            fn poll_write_ping(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<bool>> {
                Poll::Ready(Ok(false))
            }
        }
        impl AsyncMessageStream for Scripted {}

        let pool =
            Arc::new(FakeIpPool::new(FakeIpNetwork::parse("198.18.0.0/16").unwrap(), 64).unwrap());
        let responder = Arc::new(FakeIpResponder::new(
            pool.clone(),
            BypassList::new(std::iter::empty::<&str>(), false),
        ));
        let resolver: Arc<dyn Resolver> = Arc::new(FakeIpResolver::new(
            Arc::new(crate::quic_outbound::testing::LoopbackResolver),
            responder,
        ));
        let mut query = Message::new(3, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(
            Name::from_str("echo.test.").unwrap(),
            RecordType::A,
        ));
        let written = Arc::new(Mutex::new(Vec::new()));
        let stream = OneDestination {
            inner: Box::new(Scripted {
                incoming: VecDeque::from([query.to_vec().unwrap()]),
                written: written.clone(),
            }),
            destination: crate::address::NetLocation::from_str("8.8.8.8:53", None).unwrap(),
        };
        let selector = crate::quic_outbound::testing::direct_selector(resolver.clone());
        let routing = tokio::spawn(run_udp_routing(
            ServerStream::Targeted(Box::new(stream)),
            selector,
            resolver,
            false,
        ));
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        while written.lock().unwrap().is_empty() {
            assert!(tokio::time::Instant::now() < deadline, "no answer");
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let answer = Message::from_vec(&written.lock().unwrap()[0]).unwrap();
        let address = answer.answers.iter().find_map(|record| match &record.data {
            RData::A(a) => Some(a.0),
            _ => None,
        });
        assert!(address.is_some_and(|ip| pool.is_fake_ip(ip)), "{address:?}");
        routing.abort();
    }
}
