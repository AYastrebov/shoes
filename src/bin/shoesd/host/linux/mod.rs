//! The Linux [`HostNetwork`](super::HostNetwork).
//!
//! The same two halves the macOS arm is split into, and for the same reason:
//! everything that decides *what* to run -- the argv for a route, which row of
//! the routing table is the default gateway, which DNS backend this host wants
//! -- is a pure function with tests, and everything that actually runs it is a
//! thin wrapper exercised by the live run.
//!
//! Nothing here interpolates into a shell. Every command is
//! `std::process::Command` with an argv array, and every address in one is a
//! parsed `IpAddr` re-serialised rather than a string forwarded from the
//! request. OpenVPN Connect shipped CVE-2026-9560 by doing otherwise, and the
//! addresses in these arrays arrive over the control socket.
//!
//! Design: `docs/specs/2026-09-04-linux-privileged-daemon.md`.

pub mod dns;
pub mod monitor;
pub mod routes;

use super::{DnsState, HostNetwork, Route};

/// The real thing.
pub struct LinuxHost {
    routes: routes::Routes,
    dns: dns::Dns,
}

impl LinuxHost {
    /// Locate the tools, with the DNS backend already chosen.
    ///
    /// `ip` is resolved here rather than per call so that a machine without
    /// iproute2 fails the daemon's startup with a sentence, rather than failing
    /// the first `Start` with an error that reads like a bad config.
    ///
    /// The backend is passed in rather than probed here because `main.rs`
    /// probes before the supervisor exists -- the answer is wanted in three
    /// places, and probing again would be a second subprocess and a second
    /// chance to disagree with the first.
    pub fn with_dns(dns: dns::Dns) -> std::io::Result<Self> {
        let routes = routes::Routes::locate()?;
        log::info!(
            "host network: ip at {}, DNS through {}",
            routes.program().display(),
            dns.backend_name()
        );
        Ok(Self { routes, dns })
    }
}

impl HostNetwork for LinuxHost {
    fn default_gateway(&self) -> std::io::Result<Option<std::net::IpAddr>> {
        self.routes.default_gateway()
    }

    fn add_route(&self, route: &Route) -> std::io::Result<()> {
        self.routes.add(route)
    }

    fn delete_route(&self, route: &Route) -> std::io::Result<()> {
        self.routes.delete(route)
    }

    fn primary_dns_service(&self, interface: &str) -> std::io::Result<String> {
        // The tunnel's own link, not the physical one -- which is what the
        // argument exists for. Our resolvers on `eno1` would be clobbered by
        // NetworkManager on the next DHCP renew.
        self.dns.primary_service(interface)
    }

    fn read_dns(&self, service: &str) -> std::io::Result<DnsState> {
        self.dns.read(service)
    }

    fn write_dns(&self, service: &str, state: &DnsState) -> std::io::Result<()> {
        self.dns.write(service, state)
    }

    fn flush_dns_cache(&self) -> std::io::Result<()> {
        self.dns.flush()
    }
}
