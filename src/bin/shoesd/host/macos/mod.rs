//! The macOS [`HostNetwork`](super::HostNetwork).
//!
//! Two halves, split by what can be tested. Everything that decides *what* to
//! run -- the argv for a route, which line of a routing table is the default
//! gateway -- is a pure function with tests. Everything that actually runs it
//! is a thin wrapper, exercised by the live run.
//!
//! Nothing here interpolates into a shell. Every command is
//! `std::process::Command` with an argv array, and every address in one is a
//! parsed `IpAddr` re-serialised rather than a string forwarded from the
//! request. OpenVPN Connect shipped CVE-2026-9560 by doing otherwise, and the
//! addresses in these arrays arrive over the control socket.

mod dns;

use std::net::IpAddr;
use std::process::Command;

use super::{Destination, HostNetwork, Route, Via};

/// The real thing.
pub struct MacosHost {
    dns: dns::DnsStore,
}

impl MacosHost {
    pub fn new() -> std::io::Result<Self> {
        Ok(Self {
            dns: dns::DnsStore::open()?,
        })
    }
}

impl HostNetwork for MacosHost {
    fn default_gateway(&self) -> std::io::Result<Option<IpAddr>> {
        // `netstat -rn` rather than `route -n get default`, and the difference
        // is not cosmetic. `route get` does a longest-prefix lookup for the
        // address 0.0.0.0, so once this daemon has installed `0.0.0.0/1` it
        // answers with the tunnel -- the very interface the exclusion exists
        // to avoid. Reading the table and matching the literal `default`
        // destination cannot be fooled that way, and it is what wg-quick's
        // darwin.bash does.
        let output = run_capturing("netstat", &["-rn", "-f", "inet"])?;
        Ok(parse_default_gateway(&output))
    }

    fn add_route(&self, route: &Route) -> std::io::Result<()> {
        run("route", &route_args("add", route))
    }

    fn delete_route(&self, route: &Route) -> std::io::Result<()> {
        // A route that is not in the table is success. Revert runs after a
        // partial apply and after a crash, so it is routinely asked to remove
        // routes that were never added; failing there would abort the revert
        // and leave the rest installed. The trait says so, and this is where
        // it has to be true.
        match run("route", &route_args("delete", route)) {
            Ok(()) => Ok(()),
            Err(e) => {
                log::debug!("removing {route:?} reported: {e}");
                Ok(())
            }
        }
    }

    fn primary_dns_service(&self) -> std::io::Result<String> {
        self.dns.primary_service()
    }

    fn read_dns(&self, service: &str) -> std::io::Result<Vec<IpAddr>> {
        self.dns.read(service)
    }

    fn write_dns(&self, service: &str, servers: &[IpAddr]) -> std::io::Result<()> {
        self.dns.write(service, servers)
    }

    fn flush_dns_cache(&self) -> std::io::Result<()> {
        // Both, in this order, which is what Apple's own guidance and every
        // other client does: the cache lives in mDNSResponder, and
        // dscacheutil is the older half that some releases still need.
        let _ = run("dscacheutil", &["-flushcache".to_string()]);
        run(
            "killall",
            &["-HUP".to_string(), "mDNSResponder".to_string()],
        )
    }
}

/// The argv for `route add`/`route delete`.
///
/// Pure, so the shape of every command this daemon runs as root is asserted in
/// a test rather than discovered on a live machine. `-q` keeps `route` quiet
/// on success and `-n` stops it resolving names -- a reverse lookup here would
/// block the supervisor thread on DNS that the tunnel may be about to break.
fn route_args(verb: &str, route: &Route) -> Vec<String> {
    let mut args = vec!["-q".to_string(), "-n".to_string(), verb.to_string()];

    let (family, destination) = match &route.destination {
        Destination::Net { addr, prefix } => (
            if addr.is_ipv6() { "-inet6" } else { "-inet" },
            format!("{addr}/{prefix}"),
        ),
        Destination::Host(addr) => (
            if addr.is_ipv6() { "-inet6" } else { "-inet" },
            addr.to_string(),
        ),
    };
    args.push(family.to_string());

    // `-net` for a prefix and nothing for a host address: `route` infers the
    // wrong one often enough that saying it is worth the argument.
    if matches!(route.destination, Destination::Net { .. }) {
        args.push("-net".to_string());
    }
    args.push(destination);

    // `delete` matches on the destination, so the next hop is only meaningful
    // when adding. Passing it to a delete makes an otherwise-fine removal fail
    // when the route in the table has drifted.
    if verb == "add" {
        match &route.via {
            Via::Interface(name) => {
                args.push("-interface".to_string());
                args.push(name.clone());
            }
            Via::Gateway(gateway) => {
                args.push("-gateway".to_string());
                args.push(gateway.to_string());
            }
            Via::Blackhole => {
                // A next hop is required even though nothing is delivered;
                // loopback is what wg-quick uses.
                args.push(if route.destination.is_ipv6() {
                    "::1".to_string()
                } else {
                    "127.0.0.1".to_string()
                });
                args.push("-blackhole".to_string());
            }
            Via::Reject => {
                args.push(if route.destination.is_ipv6() {
                    "::1".to_string()
                } else {
                    "127.0.0.1".to_string()
                });
                args.push("-reject".to_string());
            }
        }
    }

    args
}

/// The default gateway from `netstat -rn` output.
///
/// The first `default` row whose gateway is a real address. A `link#N` gateway
/// is a pseudo-entry for a point-to-point interface -- which is exactly what
/// this daemon's own tunnel installs -- so taking it would send an excluded
/// address into the tunnel it is excluded from. wg-quick skips these for the
/// same reason.
fn parse_default_gateway(table: &str) -> Option<IpAddr> {
    table
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let destination = fields.next()?;
            let gateway = fields.next()?;
            (destination == "default").then_some(gateway)
        })
        .find(|gateway| !gateway.starts_with("link#"))
        .and_then(|gateway| gateway.parse().ok())
}

/// Run a command, failing if it does.
fn run(program: &str, args: &[String]) -> std::io::Result<()> {
    let output = Command::new(program).args(args).output().map_err(|e| {
        std::io::Error::new(e.kind(), format!("could not run {program} {args:?}: {e}"))
    })?;

    if output.status.success() {
        return Ok(());
    }
    Err(std::io::Error::other(format!(
        "{program} {args:?} failed ({}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}

/// Run a command and return its stdout.
fn run_capturing(program: &str, args: &[&str]) -> std::io::Result<String> {
    let output = Command::new(program).args(args).output().map_err(|e| {
        std::io::Error::new(e.kind(), format!("could not run {program} {args:?}: {e}"))
    })?;

    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "{program} {args:?} failed ({})",
            output.status
        )));
    }
    String::from_utf8(output.stdout)
        .map_err(|e| std::io::Error::other(format!("{program} produced non-UTF-8 output: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// The shape of `netstat -rn` output on a Mac with a VPN up, which is the
    /// case that matters: two `default` rows, the second being the tunnel's
    /// `link#` pseudo-gateway. Taking that one would send the proxy's own
    /// connection into the tunnel carrying it.
    ///
    /// Column layout, flags and the `link#N` form follow real output; the
    /// addresses are documentation-range, because a fixture has no business
    /// carrying the topology of whichever machine it was written on.
    const TABLE_WITH_A_TUNNEL_UP: &str = "\
Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            198.51.100.1       UGScg                 en0
default            link#23            UCSIg               utun4
10.99.0/24         link#23            UCS                 utun4
100.64/10          link#23            UCS                 utun4
127                127.0.0.1          UCS                   lo0
";

    #[test]
    fn the_gateway_is_the_real_one_not_the_tunnels() {
        assert_eq!(
            parse_default_gateway(TABLE_WITH_A_TUNNEL_UP),
            Some(ip("198.51.100.1"))
        );
    }

    /// The same table with the tunnel's row first, which is the order the
    /// `link#` filter actually exists for.
    ///
    /// The captured fixture above happens to list the real gateway first, so
    /// it passes with or without the filter -- removing the filter did not
    /// fail it. Whichever order a given machine reports, the answer must be
    /// the same, and this is the half that pins it.
    #[test]
    fn the_tunnels_row_is_skipped_wherever_it_appears() {
        let tunnel_first = "\
Destination        Gateway            Flags               Netif Expire
default            link#23            UCSIg               utun4
default            198.51.100.1       UGScg                 en0
127                127.0.0.1          UCS                   lo0
";
        assert_eq!(
            parse_default_gateway(tunnel_first),
            Some(ip("198.51.100.1")),
            "a link# pseudo-gateway must be skipped even when it is listed first"
        );
    }

    /// A `link#` row on its own means the only default route is a
    /// point-to-point interface with no next hop, so there is no gateway to
    /// send an excluded address through -- and the caller blackholes it.
    #[test]
    fn a_link_only_default_yields_no_gateway() {
        let table = "\
Destination        Gateway            Flags               Netif Expire
default            link#23            UCSIg               utun4
127                127.0.0.1          UCS                   lo0
";
        assert_eq!(parse_default_gateway(table), None);
    }

    /// A machine with no default route at all -- between Wi-Fi and Ethernet,
    /// or on a link that never had one.
    #[test]
    fn no_default_row_yields_no_gateway() {
        let table = "\
Destination        Gateway            Flags               Netif Expire
127                127.0.0.1          UCS                   lo0
";
        assert_eq!(parse_default_gateway(table), None);
        assert_eq!(parse_default_gateway(""), None);
    }

    /// The header lines are not rows, and neither is a blank one.
    #[test]
    fn headers_are_not_mistaken_for_routes() {
        assert_eq!(parse_default_gateway("Routing tables\n\nInternet:\n"), None);
    }

    #[test]
    fn the_tunnel_halves_are_pinned_to_the_interface() {
        let route = Route::net(ip("0.0.0.0"), 1, Via::Interface("utun4".into()));
        assert_eq!(
            route_args("add", &route),
            vec![
                "-q",
                "-n",
                "add",
                "-inet",
                "-net",
                "0.0.0.0/1",
                "-interface",
                "utun4"
            ]
        );
    }

    #[test]
    fn an_exclusion_is_a_host_route_through_the_gateway() {
        let route = Route::host(ip("203.0.113.7"), Via::Gateway(ip("192.168.1.1")));
        assert_eq!(
            route_args("add", &route),
            vec![
                "-q",
                "-n",
                "add",
                "-inet",
                "203.0.113.7",
                "-gateway",
                "192.168.1.1"
            ]
        );
    }

    #[test]
    fn a_blackholed_exclusion_names_loopback_and_the_flag() {
        let route = Route::host(ip("203.0.113.7"), Via::Blackhole);
        assert_eq!(
            route_args("add", &route),
            vec![
                "-q",
                "-n",
                "add",
                "-inet",
                "203.0.113.7",
                "127.0.0.1",
                "-blackhole"
            ]
        );
    }

    /// v6 gets `-inet6` and a v6 loopback, not the v4 ones. Mixing them is
    /// rejected by `route` with a message about the address family that says
    /// nothing about which argument was wrong.
    #[test]
    fn the_v6_rejects_use_the_v6_family_and_loopback() {
        let route = Route::net(ip("8000::"), 1, Via::Reject);
        assert_eq!(
            route_args("add", &route),
            vec![
                "-q", "-n", "add", "-inet6", "-net", "8000::/1", "::1", "-reject"
            ]
        );
    }

    /// `route delete` matches on the destination. Passing the next hop as
    /// well makes an otherwise-fine removal fail when what is in the table has
    /// drifted -- and a revert that fails leaves routes installed.
    #[test]
    fn delete_names_only_the_destination() {
        let route = Route::net(ip("0.0.0.0"), 1, Via::Interface("utun4".into()));
        assert_eq!(
            route_args("delete", &route),
            vec!["-q", "-n", "delete", "-inet", "-net", "0.0.0.0/1"]
        );
    }

    /// Every argument is a separate element, so nothing a caller sent can
    /// become a second argument or a shell token. The addresses in these
    /// arrays arrive over the control socket.
    #[test]
    fn no_argument_carries_a_separator() {
        let routes = [
            Route::net(ip("0.0.0.0"), 1, Via::Interface("utun4".into())),
            Route::host(ip("203.0.113.7"), Via::Gateway(ip("192.168.1.1"))),
            Route::host(ip("203.0.113.7"), Via::Blackhole),
            Route::net(ip("::"), 1, Via::Reject),
        ];
        for route in &routes {
            for verb in ["add", "delete"] {
                for arg in route_args(verb, route) {
                    assert!(
                        !arg.contains(char::is_whitespace) && !arg.contains(';'),
                        "{arg:?} in {verb} {route:?}"
                    );
                }
            }
        }
    }
}
