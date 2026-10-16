//! Where the datagrams of one proxied UDP session go.
//!
//! Hysteria2 and TUIC carry a target in every datagram, and a session may
//! talk to many targets. Upstream sends each datagram to its own target
//! (hysteria core/server/udp.go, `write`; TUIC is "Full Cone",
//! tuic-server handle_task.rs) and labels each reply with its real source.
//! What is kept here is the routing decision and address of the last target,
//! so a session that talks to one peer is judged and resolved once.

use std::net::SocketAddr;
use std::sync::Arc;

use crate::address::NetLocation;
use crate::client_proxy_selector::{ClientProxySelector, ConnectDecision};
use crate::resolver::{Resolver, resolve_single_address};

#[derive(Debug)]
pub struct UdpRouteCache {
    /// The target as the client named it, which is what the next datagram
    /// is compared against.
    location: NetLocation,
    socket_addr: SocketAddr,
}

impl UdpRouteCache {
    pub fn new(location: NetLocation, socket_addr: SocketAddr) -> Self {
        Self {
            location,
            socket_addr,
        }
    }

    /// The address for `location` if it is the cached target.
    pub fn cached(&self, location: &NetLocation) -> Option<SocketAddr> {
        (&self.location == location).then_some(self.socket_addr)
    }

    pub fn remember(&mut self, location: NetLocation, socket_addr: SocketAddr) {
        self.location = location;
        self.socket_addr = socket_addr;
    }

    /// The address for `location`, judging and resolving it when it is not
    /// the cached target, and caching the result.
    pub async fn route(
        &mut self,
        location: &NetLocation,
        selector: &ClientProxySelector,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<SocketAddr> {
        if let Some(socket_addr) = self.cached(location) {
            return Ok(socket_addr);
        }
        let socket_addr = judge_and_resolve(location, selector, resolver).await?;
        self.remember(location.clone(), socket_addr);
        Ok(socket_addr)
    }
}

/// Run `location` through the rules and resolve where they send it.
pub async fn judge_and_resolve(
    location: &NetLocation,
    selector: &ClientProxySelector,
    resolver: &Arc<dyn Resolver>,
) -> std::io::Result<SocketAddr> {
    let routed = match selector.judge(location.clone().into(), resolver).await? {
        ConnectDecision::Allow {
            remote_location, ..
        } => remote_location,
        ConnectDecision::Block => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("Blocked UDP forward to {location}"),
            ));
        }
    };
    resolve_single_address(resolver, routed.location()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Address;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Resolves `a.test` and `b.test` to two loopback addresses, and counts.
    #[derive(Debug, Default)]
    struct TwoHosts {
        calls: AtomicUsize,
    }

    impl Resolver for TwoHosts {
        fn resolve_location(
            &self,
            location: &NetLocation,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>,
        > {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let ip = match location.address() {
                Address::Hostname(h) if h == "a.test" => "127.0.0.1",
                Address::Hostname(h) if h == "b.test" => "127.0.0.2",
                _ => "0.0.0.0",
            };
            let addr = SocketAddr::new(ip.parse().unwrap(), location.port());
            Box::pin(async move { Ok(vec![addr]) })
        }
    }

    fn host(name: &str) -> NetLocation {
        NetLocation::new(Address::Hostname(name.to_string()), 53)
    }

    fn allow_all() -> ClientProxySelector {
        use crate::address::NetLocationMask;
        use crate::client_proxy_selector::{ConnectAction, ConnectRule};
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let chain_group = crate::tcp::chain_builder::build_client_chain_group(
            crate::option_util::NoneOrSome::None,
            resolver,
        );
        ClientProxySelector::new(vec![ConnectRule::new(
            vec![NetLocationMask::ANY],
            vec![],
            ConnectAction::new_allow(None, chain_group),
        )])
    }

    /// One session, two hostnames: each datagram goes to its own target.
    /// Before, a session opened with a hostname was pinned to that
    /// hostname's address for its whole life.
    #[tokio::test]
    async fn each_target_in_a_session_gets_its_own_address() {
        let two_hosts = Arc::new(TwoHosts::default());
        let resolver: Arc<dyn Resolver> = two_hosts.clone();
        let selector = allow_all();
        let mut cache = UdpRouteCache::new(host("a.test"), "127.0.0.1:53".parse().unwrap());

        let a = cache
            .route(&host("a.test"), &selector, &resolver)
            .await
            .unwrap();
        let b = cache
            .route(&host("b.test"), &selector, &resolver)
            .await
            .unwrap();
        let a_again = cache
            .route(&host("a.test"), &selector, &resolver)
            .await
            .unwrap();

        assert_eq!(a, "127.0.0.1:53".parse().unwrap());
        assert_eq!(b, "127.0.0.2:53".parse().unwrap());
        assert_eq!(a_again, a);
        // The first lookup was served by the cache the session opened with.
        assert_eq!(two_hosts.calls.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn a_repeated_target_is_judged_once() {
        let two_hosts = Arc::new(TwoHosts::default());
        let resolver: Arc<dyn Resolver> = two_hosts.clone();
        let selector = allow_all();
        let mut cache = UdpRouteCache::new(host("a.test"), "127.0.0.1:53".parse().unwrap());

        for _ in 0..3 {
            cache
                .route(&host("b.test"), &selector, &resolver)
                .await
                .unwrap();
        }
        assert_eq!(two_hosts.calls.load(Ordering::Relaxed), 1);
    }
}
