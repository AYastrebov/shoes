//! Fake IP DNS.
//!
//! A DNS query for `example.com` is answered immediately with an address from a
//! private pool instead of a real one. The client connects to that address, and
//! the TUN turns it back into `example.com` before the connection is routed, so
//! the name reaches the proxy and is resolved at the far end.
//!
//! Two things come out of that:
//!
//! * **No DNS leak.** Nothing is resolved on the device, so no query reaches a
//!   local resolver. Queries this module does not answer — everything that is
//!   not an A record — are forwarded through the tunnel rather than answered
//!   locally.
//! * **One less round trip.** The client skips waiting for a real resolution
//!   before it can connect.
//!
//! It also means routing rules see the domain rather than an address, so
//! hostname-based rules work for traffic that arrived over the TUN.
//!
//! # Shape
//!
//! [`FakeIpPool`] owns the mapping. [`FakeIpResponder`] decides what to do with
//! a query and is pure — no sockets, no runtime — so the policy is testable on
//! its own. The TUN wires them in: interception in the UDP path, restoration
//! where a packet's destination becomes a routable location.
//!
//! The pool is passed explicitly rather than held in a global. A VPN service is
//! started and stopped repeatedly in one process, and a process-lifetime
//! singleton would carry one session's mappings into the next.

mod bypass;
mod pool;
mod responder;
mod tcp;

pub(crate) use tcp::handle_dns_over_tcp;

pub use bypass::BypassList;
pub use pool::{
    DEFAULT_MAX_ENTRIES, FakeIpNetwork, FakeIpPool, MAPPING_REFRESH_INTERVAL, MAX_SESSION_IDLE,
    MIN_REUSE_AGE,
};
pub use responder::{AnswerableQuery, DnsDecision, FakeIpResponder};

/// What a listener's destination turns into with fake IP on.
#[derive(Debug, PartialEq, Eq)]
pub enum Restored {
    /// Not a fake address: route it as it is.
    Unchanged,
    /// A fake address standing for this name, at the same port.
    Hostname(NetLocation),
    /// A fake address standing for nothing (handed out before a restart, or
    /// recycled since): refuse it, as the TUN does, so the client resolves
    /// again instead of stalling on an address that goes nowhere.
    Unmapped,
}

/// Turn a listener's destination back into the name its fake address stands
/// for. An IPv4-mapped IPv6 literal is read as the IPv4 address it carries,
/// so a client that writes addresses that way cannot step around the pool.
pub fn restore_location(location: &NetLocation, pool: &FakeIpPool) -> Restored {
    let Some(ip) = fake_address(location, pool) else {
        return Restored::Unchanged;
    };
    match pool.lookup(ip) {
        Some(domain) => Restored::Hostname(NetLocation::new(
            Address::Hostname(domain.to_string()),
            location.port(),
        )),
        None => {
            note_unmapped(SocketAddr::new(ip.into(), location.port()));
            Restored::Unmapped
        }
    }
}

/// The pool address `location` names, read through an IPv4-mapped IPv6
/// literal as [`restore_location`] reads it; `None` for a name or an
/// address outside the pool.
pub fn fake_address(location: &NetLocation, pool: &FakeIpPool) -> Option<std::net::Ipv4Addr> {
    let ip = match location.address() {
        Address::Ipv4(v4) => *v4,
        Address::Ipv6(v6) => v6.to_ipv4_mapped()?,
        Address::Hostname(_) => return None,
    };
    pool.is_fake_ip(ip).then_some(ip)
}

/// Whether `location` is a pool address standing for nothing. Port 53 is
/// answered before anything is restored, so the interception paths ask
/// this first: a query sent to an unmapped fake address is refused like
/// any other connection to one, not answered. Leaves recency alone.
pub fn is_unmapped_fake(location: &NetLocation, pool: &FakeIpPool) -> bool {
    match fake_address(location, pool) {
        Some(ip) if pool.is_unmapped(ip) => {
            note_unmapped(SocketAddr::new(ip.into(), location.port()));
            true
        }
        _ => false,
    }
}

/// For a destination used as it is, without restoration (port 53, which is
/// answered here or forwarded to the address the client gave): whether it
/// is a pool address standing for nothing, to be refused. A mapped one is
/// marked used, so a DNS server's fake address keeps its name while queries
/// to it are answered here, and a session forwarding to it never outlives
/// that name.
pub fn refuse_or_mark_used(location: &NetLocation, pool: &FakeIpPool) -> bool {
    match fake_address(location, pool) {
        Some(ip) if !pool.touch(ip) => {
            note_unmapped(SocketAddr::new(ip.into(), location.port()));
            true
        }
        _ => false,
    }
}

/// The responder, and the pool behind it, that `config` describes. `owner`
/// names where it is configured, for the log line.
pub fn responder_from_config(
    config: &crate::config::FakeIpConfig,
    owner: &str,
) -> std::io::Result<Arc<FakeIpResponder>> {
    let network = FakeIpNetwork::parse(&config.network)?;
    let pool = Arc::new(FakeIpPool::new(network, config.max_entries)?);
    let bypass = BypassList::new(config.bypass_domains.iter(), config.bypass_defaults);

    log::info!(
        "Fake IP enabled for {owner}: network={}, capacity={}, bypass_patterns={}, local names bypassed={}",
        network,
        pool.capacity(),
        config.bypass_domains.len(),
        config.bypass_defaults
    );

    Ok(Arc::new(FakeIpResponder::new(pool, bypass)))
}

/// A resolver for inbounds that have fake IP on: the real resolver, plus the
/// responder those inbounds answer DNS with and restore addresses through.
///
/// A real answer inside the fake network is dropped. It would be taken for
/// one of the pool's own addresses when the client connected to it, and
/// restored to whatever name holds it, or refused.
pub struct FakeIpResolver {
    inner: Arc<dyn crate::resolver::Resolver>,
    responder: Arc<FakeIpResponder>,
}

impl FakeIpResolver {
    pub fn new(inner: Arc<dyn crate::resolver::Resolver>, responder: Arc<FakeIpResponder>) -> Self {
        Self { inner, responder }
    }
}

impl std::fmt::Debug for FakeIpResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeIpResolver")
            .field("inner", &self.inner)
            .field("capacity", &self.responder.pool().capacity())
            .finish()
    }
}

impl crate::resolver::Resolver for FakeIpResolver {
    fn resolve_location(&self, location: &NetLocation) -> crate::resolver::ResolveFuture {
        let pool = self.responder.pool().clone();
        let lookup = self.inner.resolve_location(location);
        let location = location.clone();
        Box::pin(async move {
            let mut addrs = lookup.await?;
            // An IPv4-mapped answer is the IPv4 address it carries, as
            // restore_location reads it.
            addrs.retain(|addr| {
                !matches!(addr.ip().to_canonical(), std::net::IpAddr::V4(v4) if pool.is_fake_ip(v4))
            });
            if addrs.is_empty() {
                return Err(std::io::Error::other(format!(
                    "every address for {location} is inside the fake IP network"
                )));
            }
            Ok(addrs)
        })
    }

    fn fake_ip(&self) -> Option<&Arc<FakeIpResponder>> {
        Some(&self.responder)
    }
}

/// The port a DNS query arrives on. Traffic to this port is offered to the
/// responder no matter which server address the client chose, so an app that
/// hardcodes a public resolver is intercepted the same as one that follows the
/// system settings.
pub const DNS_PORT: u16 = 53;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use log::debug;
use parking_lot::Mutex;

use crate::address::{Address, NetLocation};

/// Turn a packet's destination into a routable location, restoring the original
/// domain if the address came from `pool`.
///
/// This is the counterpart to the DNS side, and it runs *before* routing rules
/// are applied, so hostname rules match traffic that arrived over the TUN. With
/// no pool configured it is the plain address conversion.
///
/// `None` is an address inside the pool that stands for no domain: one handed
/// out before a restart, or recycled since. Dialled as itself it would go
/// nowhere and stall until the app gave up, so the caller refuses it at once
/// (SF-2), and the app resolves again. The refusal is counted here.
pub fn destination_to_net_location(
    addr: SocketAddr,
    pool: Option<&Arc<FakeIpPool>>,
) -> Option<NetLocation> {
    if let std::net::IpAddr::V4(v4) = addr.ip()
        && let Some(pool) = pool
        && pool.is_fake_ip(v4)
    {
        let Some(domain) = pool.lookup(v4) else {
            note_unmapped(addr);
            return None;
        };
        return Some(NetLocation::new(
            Address::Hostname(domain.to_string()),
            addr.port(),
        ));
    }

    let address = match addr.ip() {
        std::net::IpAddr::V4(v4) => Address::Ipv4(v4),
        std::net::IpAddr::V6(v6) => Address::Ipv6(v6),
    };
    Some(NetLocation::new(address, addr.port()))
}

/// Connections and datagrams refused for an unmapped pool address.
static UNMAPPED_REFUSED: AtomicU64 = AtomicU64::new(0);

/// When a refusal was last logged; a page of stale addresses after a restart
/// is one line a second, not one per packet.
static UNMAPPED_LOGGED: Mutex<Option<Instant>> = Mutex::new(None);

pub fn unmapped_refused() -> u64 {
    UNMAPPED_REFUSED.load(Ordering::Relaxed)
}

/// Count, and now and then log, a refusal of `addr`.
pub fn note_unmapped(addr: SocketAddr) {
    let total = UNMAPPED_REFUSED.fetch_add(1, Ordering::Relaxed) + 1;
    let now = Instant::now();
    let mut logged = UNMAPPED_LOGGED.lock();
    if logged.is_none_or(|at| now.duration_since(at) >= Duration::from_secs(1)) {
        *logged = Some(now);
        debug!("Refused {addr}: a fake IP with no mapping ({total} refused so far)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool() -> Arc<FakeIpPool> {
        Arc::new(FakeIpPool::new(FakeIpNetwork::parse("198.18.0.0/16").unwrap(), 64).unwrap())
    }

    /// A listener's destination: a fake address becomes its name, an
    /// IPv4-mapped one too, an unmapped one is refused, anything else stays.
    #[test]
    fn restore_location_covers_every_shape() {
        let pool = pool();
        let fake = pool.assign("example.com").unwrap();
        let at = |address: Address| NetLocation::new(address, 443);
        assert_eq!(
            restore_location(&at(Address::Ipv4(fake)), &pool),
            Restored::Hostname(at(Address::Hostname("example.com".into())))
        );
        assert_eq!(
            restore_location(&at(Address::Ipv6(fake.to_ipv6_mapped())), &pool),
            Restored::Hostname(at(Address::Hostname("example.com".into()))),
            "an IPv4-mapped literal cannot step around the pool"
        );
        assert_eq!(
            restore_location(&at(Address::Ipv4("198.18.250.250".parse().unwrap())), &pool),
            Restored::Unmapped
        );
        for unchanged in [
            Address::Ipv4("192.0.2.1".parse().unwrap()),
            Address::Ipv6("2001:db8::1".parse().unwrap()),
            Address::Hostname("example.org".into()),
        ] {
            assert_eq!(restore_location(&at(unchanged), &pool), Restored::Unchanged);
        }
    }

    /// A real answer inside the fake network is dropped by the resolver:
    /// connecting to it would be read as one of the pool's own addresses.
    #[tokio::test]
    async fn a_real_answer_inside_the_fake_network_is_dropped() {
        use crate::resolver::Resolver;
        #[derive(Debug)]
        struct Answers(Vec<SocketAddr>);
        impl crate::resolver::Resolver for Answers {
            fn resolve_location(&self, _: &NetLocation) -> crate::resolver::ResolveFuture {
                let answers = self.0.clone();
                Box::pin(async move { Ok(answers) })
            }
        }
        let responder = Arc::new(FakeIpResponder::new(
            pool(),
            BypassList::new(std::iter::empty::<&str>(), false),
        ));
        let target = NetLocation::new(Address::Hostname("example.com".into()), 443);
        let inside: SocketAddr = "198.18.0.9:443".parse().unwrap();
        let outside: SocketAddr = "192.0.2.1:443".parse().unwrap();

        let mapped: SocketAddr = "[::ffff:198.18.0.9]:443".parse().unwrap();
        let mixed = FakeIpResolver::new(
            Arc::new(Answers(vec![inside, mapped, outside])),
            responder.clone(),
        );
        assert_eq!(mixed.resolve_location(&target).await.unwrap(), [outside]);
        let only_inside = FakeIpResolver::new(Arc::new(Answers(vec![inside])), responder);
        assert!(only_inside.resolve_location(&target).await.is_err());
    }

    #[test]
    fn restores_the_domain_behind_a_fake_address() {
        let pool = pool();
        let ip = pool.assign("example.com").unwrap();
        let addr = SocketAddr::from((ip, 443));

        let location = destination_to_net_location(addr, Some(&pool)).unwrap();
        assert_eq!(
            location.address(),
            &Address::Hostname("example.com".to_string())
        );
        assert_eq!(location.port(), 443);
    }

    #[test]
    fn leaves_real_addresses_alone() {
        let pool = pool();
        let addr: SocketAddr = "1.1.1.1:443".parse().unwrap();
        let location = destination_to_net_location(addr, Some(&pool)).unwrap();
        assert_eq!(
            location.address(),
            &Address::Ipv4("1.1.1.1".parse().unwrap())
        );
    }

    /// SF-2: an address inside the pool range that was never handed out, or
    /// whose mapping has been recycled, is refused: dialled as itself it goes
    /// nowhere, and as some other domain it would be misrouted.
    #[test]
    fn refuses_unmapped_pool_addresses() {
        let pool = pool();
        let addr: SocketAddr = "198.18.9.9:443".parse().unwrap();
        let before = unmapped_refused();
        assert_eq!(destination_to_net_location(addr, Some(&pool)), None);
        assert!(unmapped_refused() > before);
    }

    /// Without fake IP the pool's range is an ordinary range.
    #[test]
    fn without_a_pool_a_pool_range_address_is_dialled() {
        let addr: SocketAddr = "198.18.9.9:443".parse().unwrap();
        assert!(destination_to_net_location(addr, None).is_some());
    }

    #[test]
    fn without_a_pool_it_is_the_plain_conversion() {
        let addr: SocketAddr = "1.1.1.1:443".parse().unwrap();
        let location = destination_to_net_location(addr, None).unwrap();
        assert_eq!(
            location.address(),
            &Address::Ipv4("1.1.1.1".parse().unwrap())
        );

        let v6: SocketAddr = "[2606:4700::1111]:443".parse().unwrap();
        let location = destination_to_net_location(v6, None).unwrap();
        assert_eq!(
            location.address(),
            &Address::Ipv6("2606:4700::1111".parse().unwrap())
        );
    }
}
