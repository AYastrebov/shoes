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
            "host network: ip at {}, DNS through {}, IPv6 {}",
            routes.program().display(),
            dns.backend_name(),
            if super::carries_ipv6() {
                "carried"
            } else {
                "rejected (disable_ipv6 is set)"
            }
        );
        Ok(Self { routes, dns })
    }
}

/// The sysctls that decide whether a device created later can take an IPv6
/// address. `default` is what a new device inherits; `all` is what a
/// hardening guide sets, and the kernel copies a write to it into `default`
/// and every existing device. Read separately because they can be set apart.
const DISABLE_IPV6_ALL: &str = "/proc/sys/net/ipv6/conf/all/disable_ipv6";
const DISABLE_IPV6_DEFAULT: &str = "/proc/sys/net/ipv6/conf/default/disable_ipv6";

/// Whether this host will accept an IPv6 address on the tunnel device.
///
/// The kernel's own check is per device (`addrconf_add_dev` answers `EACCES`
/// when `disable_ipv6` is set on it), and the device does not exist yet when
/// `Hello` has to answer -- so the two files a new device is configured from
/// are read instead. Called once, from [`crate::host::carries_ipv6`], which
/// keeps the answer.
pub fn ipv6_enabled() -> bool {
    let read = |path: &str| std::fs::read_to_string(path).ok();
    ipv6_enabled_from(
        read(DISABLE_IPV6_ALL).as_deref(),
        read(DISABLE_IPV6_DEFAULT).as_deref(),
    )
}

/// The decision, from the two files' contents. `None` is a file that is not
/// there, which is a kernel without IPv6 (`ipv6.disable=1`, or not built in)
/// and so a host that cannot carry it either.
fn ipv6_enabled_from(all: Option<&str>, default: Option<&str>) -> bool {
    let enabled = |contents: Option<&str>| contents.is_some_and(|c| c.trim() == "0");
    enabled(all) && enabled(default)
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

    fn add_address(&self, address: &super::InterfaceAddress) -> std::io::Result<()> {
        self.routes.add_address(address)
    }

    fn delete_address(&self, address: &super::InterfaceAddress) -> std::io::Result<()> {
        self.routes.delete_address(address)
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

#[cfg(test)]
mod ipv6_tests {
    use super::ipv6_enabled_from;

    /// The ordinary host, and the three ways it stops being one. `all` and
    /// `default` are checked separately rather than `all` alone because an
    /// operator can set `default` back to 1 after a write to `all` reset
    /// it; the device that matters is created later and inherits `default`.
    #[test]
    fn ipv6_is_carried_only_where_both_sysctls_allow_a_device_to_take_an_address() {
        assert!(ipv6_enabled_from(Some("0\n"), Some("0\n")));
        assert!(
            !ipv6_enabled_from(Some("1\n"), Some("1\n")),
            "net.ipv6.conf.all.disable_ipv6 = 1, as a hardening guide sets it"
        );
        assert!(
            !ipv6_enabled_from(Some("0\n"), Some("1\n")),
            "a device created later inherits default, which refuses the address"
        );
        assert!(
            !ipv6_enabled_from(Some("1\n"), Some("0\n")),
            "all = 1 is the operator saying no IPv6, whatever default says"
        );
    }

    /// A kernel booted with `ipv6.disable=1` has no `/proc/sys/net/ipv6` at
    /// all; an unreadable file is the same answer.
    #[test]
    fn a_kernel_without_ipv6_does_not_carry_it() {
        assert!(!ipv6_enabled_from(None, None));
        assert!(!ipv6_enabled_from(Some("0\n"), None));
        assert!(!ipv6_enabled_from(None, Some("0\n")));
    }
}
