//! Resolver implementation using hickory-dns.
//!
//! Uses ProxyRuntimeProvider for all connections, which handles both direct
//! and proxied connections through ClientChainGroup.

use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::Resolver;
use hickory_resolver::config::{
    ConnectionConfig, NameServerConfig, ProtocolConfig, ResolverConfig,
};

use crate::address::NetLocation;
use crate::client_proxy_chain::ClientChainGroup;
use crate::dns::parsed::IpStrategy;
use crate::dns::proxy_runtime::ProxyRuntimeProvider;
use crate::resolver::Resolver as ShoesResolver;

/// Tuning options for hickory-backed resolvers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HickoryResolverOptions {
    pub ip_strategy: IpStrategy,
    /// Per-request timeout passed to hickory's ResolverOpts.timeout.
    /// None means use hickory's default.
    pub request_timeout: Option<Duration>,
    /// Timeout for establishing TCP/TLS connections to DNS upstreams.
    pub connect_timeout: Duration,
    /// Number of retry attempts for failed queries.
    pub attempts: usize,
}

impl Default for HickoryResolverOptions {
    fn default() -> Self {
        Self {
            ip_strategy: IpStrategy::default(),
            request_timeout: Some(Duration::from_secs(5)),
            connect_timeout: Duration::from_secs(5),
            attempts: 2,
        }
    }
}

/// Resolver implementation using hickory-dns.
/// Uses ProxyRuntimeProvider for all connections (both direct and proxied).
pub struct HickoryResolver {
    inner: Resolver<ProxyRuntimeProvider>,
    description: String,
}

impl Debug for HickoryResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HickoryResolver")
            .field("description", &self.description)
            .finish()
    }
}

impl HickoryResolver {
    /// Create a UDP DNS resolver.
    /// Note: UDP uses the chain_group but only works with direct chains.
    pub fn udp(
        addr: SocketAddr,
        chain_group: Arc<ClientChainGroup>,
        bootstrap: Arc<dyn ShoesResolver>,
        options: HickoryResolverOptions,
    ) -> std::io::Result<Self> {
        let mut conn_config = ConnectionConfig::udp();
        conn_config.port = addr.port();
        Self::build(
            addr.ip(),
            conn_config,
            chain_group,
            bootstrap,
            options,
            format!("udp://{}", addr),
        )
    }

    /// Create a TCP DNS resolver.
    pub fn tcp(
        addr: SocketAddr,
        chain_group: Arc<ClientChainGroup>,
        bootstrap: Arc<dyn ShoesResolver>,
        options: HickoryResolverOptions,
    ) -> std::io::Result<Self> {
        let mut conn_config = ConnectionConfig::tcp();
        conn_config.port = addr.port();
        Self::build(
            addr.ip(),
            conn_config,
            chain_group,
            bootstrap,
            options,
            format!("tcp://{}", addr),
        )
    }

    /// Create a DNS-over-TLS resolver.
    pub fn tls(
        addr: SocketAddr,
        server_name: Arc<str>,
        chain_group: Arc<ClientChainGroup>,
        bootstrap: Arc<dyn ShoesResolver>,
        options: HickoryResolverOptions,
    ) -> std::io::Result<Self> {
        let description = format!("tls://{}#{}", addr, server_name);
        let mut conn_config = ConnectionConfig::tls(server_name);
        conn_config.port = addr.port();
        Self::build(
            addr.ip(),
            conn_config,
            chain_group,
            bootstrap,
            options,
            description,
        )
    }

    /// Create a DNS-over-HTTPS resolver.
    pub fn https(
        addr: SocketAddr,
        server_name: Arc<str>,
        path: Arc<str>,
        chain_group: Arc<ClientChainGroup>,
        bootstrap: Arc<dyn ShoesResolver>,
        options: HickoryResolverOptions,
    ) -> std::io::Result<Self> {
        let description = format!("https://{}", server_name);
        let mut conn_config = ConnectionConfig::https(server_name, Some(path));
        conn_config.port = addr.port();
        Self::build(
            addr.ip(),
            conn_config,
            chain_group,
            bootstrap,
            options,
            description,
        )
    }

    /// Create a DNS-over-HTTP/3 resolver.
    pub fn h3(
        addr: SocketAddr,
        server_name: Arc<str>,
        path: Arc<str>,
        chain_group: Arc<ClientChainGroup>,
        bootstrap: Arc<dyn ShoesResolver>,
        options: HickoryResolverOptions,
    ) -> std::io::Result<Self> {
        // Cloudflare has a broken GREASE implementation.
        // See: https://github.com/hyperium/h3/issues/206
        let description = format!("h3://{}", server_name);
        let protocol = ProtocolConfig::H3 {
            server_name,
            path,
            disable_grease: true,
        };
        let mut conn_config = ConnectionConfig::new(protocol);
        conn_config.port = addr.port();
        Self::build(
            addr.ip(),
            conn_config,
            chain_group,
            bootstrap,
            options,
            description,
        )
    }

    /// Create a resolver with multiple nameservers in a single hickory pool.
    /// Hickory's NameServerPool handles ordering and parallelism internally,
    /// avoiding the sequential fallback behavior of CompositeResolver.
    pub fn build_pooled(
        servers: Vec<(std::net::IpAddr, ConnectionConfig)>,
        chain_group: Arc<ClientChainGroup>,
        bootstrap: Arc<dyn ShoesResolver>,
        options: HickoryResolverOptions,
        description: String,
    ) -> std::io::Result<Self> {
        let ns_configs: Vec<NameServerConfig> = servers
            .into_iter()
            .map(|(ip, conn_config)| NameServerConfig::new(ip, true, vec![conn_config]))
            .collect();

        Self::build_with_ns_configs(ns_configs, chain_group, bootstrap, options, description)
    }

    fn build(
        ip: std::net::IpAddr,
        conn_config: ConnectionConfig,
        chain_group: Arc<ClientChainGroup>,
        bootstrap: Arc<dyn ShoesResolver>,
        options: HickoryResolverOptions,
        description: String,
    ) -> std::io::Result<Self> {
        let ns_config = NameServerConfig::new(ip, true, vec![conn_config]);
        Self::build_with_ns_configs(
            vec![ns_config],
            chain_group,
            bootstrap,
            options,
            description,
        )
    }

    fn build_with_ns_configs(
        ns_configs: Vec<NameServerConfig>,
        chain_group: Arc<ClientChainGroup>,
        bootstrap: Arc<dyn ShoesResolver>,
        options: HickoryResolverOptions,
        description: String,
    ) -> std::io::Result<Self> {
        let config = ResolverConfig::from_parts(None, vec![], ns_configs);
        let provider =
            ProxyRuntimeProvider::with_bootstrap(chain_group, bootstrap, options.connect_timeout);

        let mut builder = Resolver::builder_with_config(config, provider);
        let resolver_opts = builder.options_mut();
        resolver_opts.ip_strategy = options.ip_strategy.to_hickory();
        if let Some(timeout) = options.request_timeout {
            resolver_opts.timeout = timeout;
        }
        resolver_opts.attempts = options.attempts;
        // DNS 0x20 (DN-D1): hickory randomises the query name's case over UDP
        // and drops an answer that does not echo it, which an off-path
        // spoofer cannot do without guessing the case too.
        resolver_opts.case_randomization = true;
        let builder =
            builder.with_tls_config(crate::rustls_config_util::create_dns_client_config());
        let resolver = builder
            .build()
            .map_err(|e| std::io::Error::other(format!("failed to build resolver: {e}")))?;

        Ok(Self {
            inner: resolver,
            description,
        })
    }
}

impl ShoesResolver for HickoryResolver {
    fn resolve_location(
        &self,
        location: &NetLocation,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>>
    {
        // Fast path: if already an IP address, return immediately without DNS lookup
        if let Some(socket_addr) = location.to_socket_addr_nonblocking() {
            return Box::pin(std::future::ready(Ok(vec![socket_addr])));
        }

        let name = location.address().to_string();
        let port = location.port();
        let description = self.description.clone();
        let resolver = self.inner.clone();

        Box::pin(async move {
            let started = std::time::Instant::now();

            let response = resolver.lookup_ip(&name).await.map_err(|e| {
                let elapsed = started.elapsed();
                log::warn!(
                    "DNS lookup failed via {}: {}:{} in {:?}: {}",
                    description,
                    name,
                    port,
                    elapsed,
                    e
                );
                net_error(e)
            })?;

            let addrs: Vec<SocketAddr> = response
                .iter()
                .filter(|ip| !ip.is_unspecified())
                .map(|ip| SocketAddr::new(ip, port))
                .collect();

            if addrs.is_empty() {
                return Err(std::io::Error::other(format!(
                    "DNS lookup returned no addresses for {name}"
                )));
            }

            let elapsed = started.elapsed();
            if elapsed > Duration::from_millis(500) {
                log::info!(
                    "slow DNS lookup via {}: {}:{} -> {:?} in {:?}",
                    description,
                    name,
                    port,
                    addrs,
                    elapsed
                );
            } else {
                log::debug!(
                    "DNS lookup via {}: {}:{} -> {:?} in {:?}",
                    description,
                    name,
                    port,
                    addrs,
                    elapsed
                );
            }
            Ok(addrs)
        })
    }
}

/// A hickory transport failure as an `io::Error` whose kind says what
/// happened. Every failure was `Other` before, so `RefreshingResolver`'s
/// refresh-and-retry, which reads the kind, never saw a timeout or a lost
/// connection, and a DoT or DoH resolver whose connection had died stayed
/// dead until it idled out (upstream cfal/shoes#242). A refusal from the
/// server (NXDOMAIN and the like) stays `Other`: nothing to refresh for.
fn net_error(error: hickory_resolver::net::NetError) -> std::io::Error {
    use hickory_resolver::net::NetError;
    let kind = match &error {
        NetError::Timeout => std::io::ErrorKind::TimedOut,
        NetError::Io(error) => error.kind(),
        NetError::Busy => std::io::ErrorKind::WouldBlock,
        NetError::NoConnections => std::io::ErrorKind::NotConnected,
        _ if error.is_connection_closed() => std::io::ErrorKind::ConnectionAborted,
        _ => std::io::ErrorKind::Other,
    };
    std::io::Error::new(kind, error)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A lookup that times out, finds no connection, or loses its connection
    /// mid-request makes the refreshing resolver rebuild and retry once; a
    /// server's NXDOMAIN does not. The kinds are what the refresh policy
    /// reads (upstream cfal/shoes#242).
    #[tokio::test]
    async fn hostname_lookup_refreshes_only_transport_failures() {
        use crate::resolver::{RefreshPolicy, RefreshingResolver, ResolverFactory};
        use hickory_resolver::proto::{
            op::{Message, ResponseCode},
            rr::{RData, Record, rdata},
        };
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        #[derive(Clone, Copy)]
        enum Failure {
            Timeout,
            NoConnections,
            ConnectionClosed,
            NxDomain,
        }

        let location = NetLocation::from_str("recovery.example.:443", None).unwrap();
        let expected_addresses: [SocketAddr; 1] = ["198.51.100.7:443".parse().unwrap()];

        for failure in [
            Failure::Timeout,
            Failure::NoConnections,
            Failure::ConnectionClosed,
            Failure::NxDomain,
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
                // Keeps the unanswered connection open so the lookup fails by
                // timeout, not EOF.
                let _unanswered_connection = if matches!(failure, Failure::Timeout) {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let length = stream.read_u16().await.unwrap();
                    let mut bytes = vec![0; length as usize];
                    stream.read_exact(&mut bytes).await.unwrap();
                    Some(stream)
                } else {
                    None
                };
                // Reads the query and hangs up without answering, so the
                // request is in flight when its connection dies.
                if matches!(failure, Failure::ConnectionClosed) {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let length = stream.read_u16().await.unwrap();
                    let mut bytes = vec![0; length as usize];
                    stream.read_exact(&mut bytes).await.unwrap();
                    drop(stream);
                }
                let (mut stream, _) = listener.accept().await.unwrap();
                let length = stream.read_u16().await.unwrap();
                let mut bytes = vec![0; length as usize];
                stream.read_exact(&mut bytes).await.unwrap();
                let mut reply = Message::from_vec(&bytes).unwrap().into_response();
                if matches!(failure, Failure::NxDomain) {
                    reply.metadata.response_code = ResponseCode::NXDomain;
                } else {
                    reply.add_answer(Record::from_rdata(
                        reply.queries[0].name.clone(),
                        60,
                        RData::A(rdata::A("198.51.100.7".parse().unwrap())),
                    ));
                }
                let bytes = reply.to_vec().unwrap();
                stream.write_u16(bytes.len() as u16).await.unwrap();
                stream.write_all(&bytes).await.unwrap();
            }));
            let builds = Arc::new(AtomicUsize::new(0));
            let factory_builds = builds.clone();
            let factory: ResolverFactory = Arc::new(move || {
                let generation = factory_builds.fetch_add(1, Ordering::Relaxed);
                Box::pin(async move {
                    let bootstrap: Arc<dyn ShoesResolver> =
                        Arc::new(crate::resolver::NativeResolver::new());
                    let chain = Arc::new(crate::tcp::chain_builder::build_direct_chain_group(
                        bootstrap.clone(),
                    ));
                    let options = HickoryResolverOptions {
                        ip_strategy: IpStrategy::Ipv4Only,
                        request_timeout: Some(Duration::from_millis(250)),
                        attempts: 0,
                        ..Default::default()
                    };
                    let resolver = if matches!(failure, Failure::NoConnections) && generation == 0 {
                        HickoryResolver::build_pooled(
                            vec![],
                            chain,
                            bootstrap,
                            options,
                            "empty test pool".into(),
                        )?
                    } else {
                        HickoryResolver::tcp(address, chain, bootstrap, options)?
                    };
                    Ok(Arc::new(resolver) as Arc<dyn ShoesResolver>)
                })
            });
            let resolver = RefreshingResolver::new(
                factory,
                RefreshPolicy {
                    max_idle: Duration::from_secs(3600),
                    max_age: Duration::from_secs(3600),
                    retry_after_failure: Duration::from_secs(1),
                    retry_once_after_refresh: true,
                },
                "hostname refresh regression".into(),
            )
            .await
            .unwrap();
            let result =
                tokio::time::timeout(Duration::from_secs(3), resolver.resolve_location(&location))
                    .await
                    .unwrap();
            match failure {
                Failure::NxDomain => {
                    let error = result.unwrap_err();
                    assert_eq!(error.kind(), std::io::ErrorKind::Other);
                    assert_eq!(builds.load(Ordering::Relaxed), 1);
                }
                Failure::Timeout | Failure::NoConnections | Failure::ConnectionClosed => {
                    assert_eq!(result.unwrap(), expected_addresses);
                    assert_eq!(builds.load(Ordering::Relaxed), 2);
                    assert_eq!(
                        resolver.resolve_location(&location).await.unwrap(),
                        expected_addresses
                    );
                    assert_eq!(builds.load(Ordering::Relaxed), 2);
                }
            }
            server.await.unwrap();
        }
    }

    /// A lookup after the server closed an idle connection gets an answer,
    /// as when a network change kills an encrypted resolver's idle
    /// connection. Hickory notices this close and reconnects with or without
    /// the fork pinned in Cargo.toml; the fork's fix is for a close racing a
    /// request into the exchange, which its own tests cover and
    /// `a_closed_connection_is_a_kind_the_refresh_policy_reads` maps.
    #[tokio::test]
    async fn a_lookup_after_the_server_closed_an_idle_connection_is_answered() {
        use crate::resolver::{RefreshPolicy, RefreshingResolver, ResolverFactory};
        use hickory_resolver::proto::{
            op::Message,
            rr::{RData, Record, rdata},
        };
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        async fn answer_one(stream: &mut tokio::net::TcpStream) {
            let length = stream.read_u16().await.unwrap();
            let mut bytes = vec![0; length as usize];
            stream.read_exact(&mut bytes).await.unwrap();
            let mut reply = Message::from_vec(&bytes).unwrap().into_response();
            reply.add_answer(Record::from_rdata(
                reply.queries[0].name.clone(),
                60,
                RData::A(rdata::A("198.51.100.7".parse().unwrap())),
            ));
            let bytes = reply.to_vec().unwrap();
            stream.write_u16(bytes.len() as u16).await.unwrap();
            stream.write_all(&bytes).await.unwrap();
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
        let server = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
            // The first connection answers once, then the server closes it
            // while it is idle.
            let (mut first, _) = listener.accept().await.unwrap();
            answer_one(&mut first).await;
            drop(first);
            let _ = closed_tx.send(());
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                tokio::spawn(async move { answer_one(&mut stream).await });
            }
        }));

        let factory: ResolverFactory = Arc::new(move || {
            Box::pin(async move {
                let bootstrap: Arc<dyn ShoesResolver> =
                    Arc::new(crate::resolver::NativeResolver::new());
                let chain = Arc::new(crate::tcp::chain_builder::build_direct_chain_group(
                    bootstrap.clone(),
                ));
                let options = HickoryResolverOptions {
                    ip_strategy: IpStrategy::Ipv4Only,
                    request_timeout: Some(Duration::from_millis(500)),
                    attempts: 0,
                    ..Default::default()
                };
                let resolver = HickoryResolver::tcp(address, chain, bootstrap, options)?;
                Ok(Arc::new(resolver) as Arc<dyn ShoesResolver>)
            })
        });
        let resolver = RefreshingResolver::new(
            factory,
            RefreshPolicy {
                max_idle: Duration::from_secs(3600),
                max_age: Duration::from_secs(3600),
                retry_after_failure: Duration::from_secs(1),
                retry_once_after_refresh: true,
            },
            "closed idle connection regression".into(),
        )
        .await
        .unwrap();

        let first = NetLocation::from_str("first.example.:443", None).unwrap();
        resolver.resolve_location(&first).await.unwrap();
        closed_rx.await.unwrap();
        // Let the client side see the close before the next request.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let second = NetLocation::from_str("second.example.:443", None).unwrap();
        let answer =
            tokio::time::timeout(Duration::from_secs(3), resolver.resolve_location(&second))
                .await
                .expect("the second lookup finished")
                .expect("the second lookup was answered");
        assert_eq!(answer, ["198.51.100.7:443".parse::<SocketAddr>().unwrap()]);
        drop(server);
    }

    /// DN-D1: every hickory-backed resolver randomises the query name's case.
    #[tokio::test]
    async fn resolvers_randomise_the_query_case() {
        let resolver = HickoryResolver::udp(
            "127.0.0.1:53".parse().unwrap(),
            Arc::new(crate::tcp::chain_builder::build_direct_chain_group(
                Arc::new(crate::resolver::NativeResolver::new()),
            )),
            Arc::new(crate::resolver::NativeResolver::new()),
            HickoryResolverOptions::default(),
        )
        .unwrap();
        assert!(resolver.inner.options().case_randomization);
    }

    /// A connection that dies under a request is `NetError::ConnectionClosed`
    /// with the hickory fork pinned in Cargo.toml (hickory-dns/hickory-dns
    /// #3861, upstream cfal/shoes#222), where stock 0.26.3 said `Busy` or a
    /// string cancellation that nothing retried. It must reach the refresh
    /// policy as a kind it reads, and `Busy` must stay one it does not.
    #[test]
    fn a_closed_connection_is_a_kind_the_refresh_policy_reads() {
        use hickory_resolver::net::NetError;
        assert_eq!(
            net_error(NetError::ConnectionClosed).kind(),
            std::io::ErrorKind::ConnectionAborted
        );
        assert_eq!(
            net_error(NetError::Busy).kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn test_hickory_resolver_options_default() {
        let opts = HickoryResolverOptions::default();
        assert_eq!(opts.ip_strategy, IpStrategy::default());
        assert_eq!(opts.request_timeout, Some(Duration::from_secs(5)));
        assert_eq!(opts.connect_timeout, Duration::from_secs(5));
        assert_eq!(opts.attempts, 2);
    }

    #[test]
    fn test_hickory_resolver_options_zero_timeout() {
        let opts = HickoryResolverOptions {
            request_timeout: None,
            ..Default::default()
        };
        assert!(opts.request_timeout.is_none());
    }

    #[test]
    fn test_hickory_resolver_options_custom() {
        let opts = HickoryResolverOptions {
            ip_strategy: IpStrategy::Ipv4Only,
            request_timeout: Some(Duration::from_secs(3)),
            connect_timeout: Duration::from_secs(1),
            attempts: 1,
        };
        assert_eq!(opts.ip_strategy, IpStrategy::Ipv4Only);
        assert_eq!(opts.request_timeout, Some(Duration::from_secs(3)));
        assert_eq!(opts.connect_timeout, Duration::from_secs(1));
        assert_eq!(opts.attempts, 1);
    }
}
