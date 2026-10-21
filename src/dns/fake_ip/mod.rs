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

pub use bypass::BypassList;
pub use pool::{DEFAULT_MAX_ENTRIES, FakeIpNetwork, FakeIpPool, MIN_REUSE_AGE};
pub use responder::{DnsDecision, FakeIpResponder};

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
