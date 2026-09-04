//! Host network configuration: what the daemon does to the machine.
//!
//! shoes moves packets and the host owns the network -- that rule is why
//! nothing under `src/` touches routes or resolvers, and it is not relaxed
//! here. This module is the host half, and it lives in the daemon binary.
//!
//! Everything privileged goes through [`HostNetwork`], with a real macOS
//! implementation and a recording double. That is not a testing convenience
//! bolted on afterwards: the ordering is the part with the damage in it. A
//! daemon that applies routes, fails at DNS and returns without undoing them
//! leaves a Mac that cannot reach the network, and the machine it happens on
//! is the user's. Putting the sequence behind a trait means the sequence is
//! tested on every platform, in CI, with no root and no device.

mod plan;
mod state;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(test)]
pub mod double;

pub use plan::{Plan, Session};
pub use state::AppliedState;

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// Where a route sends what matches it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Via {
    /// Out of an interface, with no next hop. How a tunnel route is pinned:
    /// the utun is point-to-point, so naming the interface says everything a
    /// gateway address would and survives the peer address changing.
    Interface(String),
    /// Through a next-hop router. How an excluded address stays outside the
    /// tunnel, using the gateway that was there before it came up.
    Gateway(IpAddr),
    /// Dropped, silently. For an excluded address when there is no gateway to
    /// send it through -- mid-transition between Wi-Fi and Ethernet, say.
    /// Without it the address matches nothing but the tunnel's own half-default
    /// and the proxy's packets enter the tunnel they are carrying. Failing the
    /// connection is recoverable; that loop is not. wg-quick does the same
    /// thing, under a comment reading "Prevent routing loop".
    Blackhole,
    /// Refused, audibly: the sender gets an unreachable error at once.
    ///
    /// For IPv6, which v1 does not carry. A blackhole would make every v6
    /// connection wait out its timeout before Happy Eyeballs fell back to v4;
    /// a reject makes the fallback immediate. Leaking v6 to the physical
    /// interface is not an option, so those are the two choices.
    Reject,
}

/// What a route matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Destination {
    /// A prefix. `0.0.0.0/1` and `128.0.0.0/1` are the pair that captures the
    /// default without deleting it -- more specific than the physical
    /// interface's `default`, so they win while it stays in the table to hang
    /// exclusions off, and a crash leaves it untouched.
    Net { addr: IpAddr, prefix: u8 },
    /// One address.
    Host(IpAddr),
}

impl Destination {
    /// Which address family this belongs to, which decides `-inet` against
    /// `-inet6` and which loopback a blackhole names.
    pub fn is_ipv6(&self) -> bool {
        match self {
            Destination::Net { addr, .. } | Destination::Host(addr) => addr.is_ipv6(),
        }
    }
}

/// One route the daemon installs and must be able to remove again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Route {
    pub destination: Destination,
    pub via: Via,
}

impl Route {
    pub fn net(addr: IpAddr, prefix: u8, via: Via) -> Self {
        Self {
            destination: Destination::Net { addr, prefix },
            via,
        }
    }

    pub fn host(addr: IpAddr, via: Via) -> Self {
        Self {
            destination: Destination::Host(addr),
            via,
        }
    }
}

/// The privileged operations, and nothing else.
///
/// Deliberately small and free of policy: each method does one thing to the
/// machine and reports whether it worked. Which routes to install, in what
/// order, and what to undo when one fails is [`Session`]'s job, and that is
/// the part worth testing.
pub trait HostNetwork {
    /// The default gateway in the routing table right now.
    ///
    /// Read fresh every time rather than cached at start: the Mac moving from
    /// Wi-Fi to Ethernet is the ordinary case, not an edge one. `None` when
    /// there is no default route, which is a state to handle rather than an
    /// error -- see [`Via::Blackhole`].
    fn default_gateway(&self) -> std::io::Result<Option<IpAddr>>;

    fn add_route(&self, route: &Route) -> std::io::Result<()>;

    /// Remove a route.
    ///
    /// Must treat a route that is not in the table as success. Revert runs
    /// after a partial apply and after a crash, so it is asked to remove
    /// routes that were never added -- and one that refuses there would abort
    /// the revert partway and leave the rest installed.
    fn delete_route(&self, route: &Route) -> std::io::Result<()>;

    /// The id of the network service DNS should be set on.
    fn primary_dns_service(&self) -> std::io::Result<String>;

    /// The resolvers currently configured on a service, for restoring later.
    fn read_dns(&self, service: &str) -> std::io::Result<Vec<IpAddr>>;

    /// Set the resolvers on a service. An empty list restores the default,
    /// which is what reverting to a service that had none means.
    fn write_dns(&self, service: &str, servers: &[IpAddr]) -> std::io::Result<()>;

    /// Drop cached answers, so the change takes effect for things that already
    /// resolved.
    fn flush_dns_cache(&self) -> std::io::Result<()>;
}

/// A `Net` route from a string address, for tests in sibling modules.
#[cfg(test)]
pub fn route_for_test(addr: &str, prefix: u8, via: Via) -> Route {
    Route::net(addr.parse().unwrap(), prefix, via)
}
