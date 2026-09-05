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

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(test)]
pub mod double;

pub use plan::{Plan, Session};
pub use state::AppliedState;
// Only tests construct a backup directly; the apply path builds it from what
// it read.
#[cfg(test)]
pub use state::DnsBackup;

use std::net::IpAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Everything restoring a service's DNS needs, beyond the service's name.
///
/// A resolver list alone is enough on macOS, and was enough when this trait
/// had one implementation. The direct `/etc/resolv.conf` backend needs one
/// thing more: whether the path was a **symlink**, and to what. On a
/// resolved host it points at `stub-resolv.conf`; elsewhere it may point into
/// `/run`. Restoring a flattened regular file where a symlink was is how this
/// class of tool breaks a host permanently -- the real manager keeps rewriting
/// a target nothing follows any more -- so the target travels with the backup
/// rather than being re-derived at revert time, when the answer would already
/// be wrong.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsState {
    /// The resolvers. Empty means the service had none configured, and
    /// restoring empty is how it gets back to that.
    #[serde(default)]
    pub servers: Vec<IpAddr>,
    /// Where the path pointed, when it was a symlink. `None` for a regular
    /// file and for every backend that is not a file at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symlink_target: Option<PathBuf>,
    /// The bytes the path held, when the backend replaces a regular file.
    ///
    /// `servers` is the *parsed* view -- what the resolvers were -- and it is
    /// what logs and diagnostics read. It is not enough to restore from.
    /// `/etc/resolv.conf` also carries `search`, `options` and `sortlist`
    /// lines, and a revert that wrote back only `nameserver` lines would
    /// silently drop the host's search domain until whatever manages the file
    /// happened to rewrite it -- which on a `netconfig` host is its own
    /// schedule, not ours. So the restore replays these bytes and ignores
    /// `servers` entirely.
    ///
    /// `None` for a symlinked original, where the link is restored instead and
    /// its target was never ours to rewrite; `None` for every backend that is
    /// not a file; and `None` in the apply direction, which has nothing to
    /// restore.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verbatim: Option<String>,
}

impl DnsState {
    /// The resolvers a session wants advertised, with no restore information --
    /// which is what applying, as opposed to reverting, always is.
    pub fn servers(servers: &[IpAddr]) -> Self {
        Self {
            servers: servers.to_vec(),
            symlink_target: None,
            verbatim: None,
        }
    }
}

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
    ///
    /// macOS only, because only `route` needs telling. `ip` infers the family
    /// from the destination literal and has native `blackhole`/`unreachable`
    /// route types, so the Linux arm has nothing to ask.
    #[cfg(target_os = "macos")]
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

    /// The id of the network service DNS should be set on, for a session on
    /// `interface`.
    ///
    /// The argument exists because the two platforms answer with different
    /// things. macOS wants the primary *physical* service -- you override its
    /// resolvers and restore them later -- and ignores it. Linux wants the
    /// tunnel's own link, because putting our resolvers on the physical one
    /// means NetworkManager clobbers them on the next DHCP renew, which is the
    /// contention the macOS arm needed a watchdog for.
    fn primary_dns_service(&self, interface: &str) -> std::io::Result<String>;

    /// What the service looks like now, so it can be put back later.
    fn read_dns(&self, service: &str) -> std::io::Result<DnsState>;

    /// Set the resolvers on a service. An empty list restores the default,
    /// which is what reverting to a service that had none means.
    ///
    /// `state.symlink_target` is meaningful only on a revert, and only for the
    /// direct file backend; applying passes [`DnsState::servers`], which
    /// carries none.
    ///
    /// Must treat a service that is not there as success, for the reason
    /// [`HostNetwork::delete_route`] gives about routes. Revert runs after the
    /// tunnel link is gone, and on Linux the resolvers were configured *on*
    /// that link -- so the restore is routinely asked to write to something
    /// that has already disappeared. One that returned an error there would
    /// abort the revert partway and leave the exclusion routes installed.
    ///
    /// Only that. A refusal, a missing tool or a permission error has to
    /// propagate: swallowing one would report a clean revert, delete the
    /// record, and leave the host's DNS pointed into a tunnel that is gone.
    fn write_dns(&self, service: &str, state: &DnsState) -> std::io::Result<()>;

    /// Drop cached answers, so the change takes effect for things that already
    /// resolved.
    fn flush_dns_cache(&self) -> std::io::Result<()>;
}

/// A `Net` route from a string address, for tests in sibling modules.
#[cfg(test)]
pub fn route_for_test(addr: &str, prefix: u8, via: Via) -> Route {
    Route::net(addr.parse().unwrap(), prefix, via)
}
