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
pub mod monitor;

use std::net::IpAddr;
use std::process::Command;

use super::{Destination, DnsState, HostNetwork, Route, Via};

/// The tools, by absolute path.
///
/// A root process that resolves a program through `PATH` runs whatever the
/// first writable directory on it happens to hold. launchd gives the daemon a
/// sane `PATH`, but `shoesd install` and `shoesd run` under `sudo` inherit the
/// invoker's environment -- and these are the same argv arrays the no-shell
/// rule already protects. Naming the paths costs nothing and removes the
/// question.
const ROUTE: &str = "/sbin/route";
const IFCONFIG: &str = "/sbin/ifconfig";
const NETSTAT: &str = "/usr/sbin/netstat";
const DSCACHEUTIL: &str = "/usr/bin/dscacheutil";
const KILLALL: &str = "/usr/bin/killall";

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
        let output = run_capturing(NETSTAT, &["-rn", "-f", "inet"])?;
        Ok(parse_default_gateway(&output))
    }

    fn add_route(&self, route: &Route) -> std::io::Result<()> {
        run(ROUTE, &route_args("add", route))
    }

    fn delete_route(&self, route: &Route) -> std::io::Result<()> {
        // A route that is not in the table is success -- and *only* that.
        // Revert runs after a partial apply and after a crash, so it is
        // routinely asked to remove routes that were never added; failing
        // there would abort the revert and leave the rest installed.
        //
        // Every other failure has to propagate. `Session::revert` reports what
        // failed, and the supervisor keeps the on-disk record when it does;
        // swallowing an EPERM or a missing `route` here would report a clean
        // revert, delete the record, and leave the Mac with its default routed
        // into a utun that no longer exists -- the exact failure the record
        // exists to prevent.
        match run(ROUTE, &route_args("delete", route)) {
            Ok(()) => Ok(()),
            Err(e) if is_absent_route(&e.to_string()) => {
                log::debug!("{route:?} was already gone");
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    fn add_address(&self, address: &super::InterfaceAddress) -> std::io::Result<()> {
        // Looked up before it is added, because `ifconfig … alias` of an
        // address the interface already has exits 0: `SIOCAIFADDR_IN6` updates
        // the existing entry in place and prints nothing. Linux's `ip` says
        // "File exists" and the arm turns that into `AlreadyExists`; here
        // there is no such text to turn, and without this read an address
        // someone else put on the utun would be recorded as ours and removed
        // on revert -- the exact thing `AlreadyExists` exists to prevent.
        let family = if address.address.is_ipv6() {
            "inet6"
        } else {
            "inet"
        };
        let listing = run_capturing(IFCONFIG, &[address.interface.as_str(), family])?;
        if lists_address(&listing, address.address) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "{} already has {}/{}",
                    address.interface, address.address, address.prefix
                ),
            ));
        }
        run(IFCONFIG, &address_args("alias", address))
    }

    fn delete_address(&self, address: &super::InterfaceAddress) -> std::io::Result<()> {
        // Not there is success -- and only that -- as for a route; the usual
        // way it is not there is that the utun it was on is gone.
        match run(IFCONFIG, &address_args("-alias", address)) {
            Ok(()) => Ok(()),
            Err(e) if is_absent_address(&e.to_string()) => {
                log::debug!("{address:?} was already gone");
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    fn primary_dns_service(&self, _interface: &str) -> std::io::Result<String> {
        // Ignored: macOS sets resolvers on the primary *physical* service, not
        // on the tunnel. Linux is the arm the argument exists for.
        self.dns.primary_service()
    }

    fn read_dns(&self, service: &str) -> std::io::Result<DnsState> {
        // No symlink to remember: SCDynamicStore is a store, not a file.
        self.dns
            .read(service)
            .map(|servers| DnsState::servers(&servers))
    }

    fn write_dns(&self, service: &str, state: &DnsState) -> std::io::Result<()> {
        self.dns.write(service, &state.servers)
    }

    fn flush_dns_cache(&self) -> std::io::Result<()> {
        // Both, in this order, which is what Apple's own guidance and every
        // other client does: the cache lives in mDNSResponder, and
        // dscacheutil is the older half that some releases still need.
        let _ = run(DSCACHEUTIL, &["-flushcache".to_string()]);
        run(KILLALL, &["-HUP".to_string(), "mDNSResponder".to_string()])
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

/// The argv for `ifconfig <utun> inet6 <addr> prefixlen <n> alias|-alias`.
///
/// Pure, for the same reason [`route_args`] is: what runs as root is asserted
/// in a test rather than discovered on a live machine.
fn address_args(verb: &str, address: &super::InterfaceAddress) -> Vec<String> {
    vec![
        address.interface.clone(),
        if address.address.is_ipv6() {
            "inet6"
        } else {
            "inet"
        }
        .to_string(),
        address.address.to_string(),
        "prefixlen".to_string(),
        address.prefix.to_string(),
        verb.to_string(),
    ]
}

/// Whether `ifconfig <interface> <family>` output lists `address`.
///
/// An address row is `inet6 <addr>[%scope] prefixlen <n> …`, and the link-local
/// row carries a `%utunN` scope suffix that the parse has to drop. Everything
/// else -- the flags line, `nd6 options`, `inet` rows when asked for `inet6` --
/// fails the parse and is skipped.
fn lists_address(listing: &str, address: IpAddr) -> bool {
    listing.lines().any(|line| {
        let mut fields = line.split_whitespace();
        let family = fields.next();
        let candidate = fields.next();
        matches!(family, Some("inet" | "inet6"))
            && candidate
                .and_then(|c| c.split('%').next())
                .and_then(|c| c.parse::<IpAddr>().ok())
                .is_some_and(|c| c == address)
    })
}

/// What `ifconfig` says when the address, or the interface, is not there.
fn is_absent_address(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("can't assign requested address")
        || message.contains("does not exist")
        || message.contains("no such interface")
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

/// Whether a `route delete` failure means the route was simply not there.
///
/// macOS answers a delete for an absent route with `not in table`, and for an
/// absent *interface* route with `bad address`. Both mean the same thing to a
/// revert: nothing to remove. Matched on the message rather than the exit
/// status, because `route` returns 1 for every failure alike.
fn is_absent_route(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("not in table") || message.contains("bad address")
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
    /// Column layout, flags and the `link#N` form are copied from real output;
    /// the addresses are documentation-range, because a fixture has no business
    /// carrying the topology of whichever machine it was captured on.
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

    /// Only "it was not there" is success. Anything else -- no permission,
    /// no `route` binary, a kernel refusal -- has to reach `Session::revert`,
    /// which is what keeps the on-disk record instead of deleting it and
    /// leaving routes installed that nothing remembers.
    #[test]
    fn only_an_absent_route_counts_as_already_removed() {
        for absent in [
            "route [-q, -n, delete, -inet, -net, 0.0.0.0/1] failed (exit status: 1): \
             route: writing to routing socket: not in table",
            "delete net 0.0.0.0: bad address",
            "route: writing to routing socket: Not in table",
        ] {
            assert!(is_absent_route(absent), "{absent}");
        }

        for real in [
            "route [...] failed (exit status: 1): route: writing to routing socket: \
             Operation not permitted",
            "could not run route [...]: No such file or directory (os error 2)",
            "route: must be root to alter routing table",
        ] {
            assert!(!is_absent_route(real), "{real} must not be swallowed");
        }
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

#[cfg(test)]
mod address_tests {
    use super::*;

    fn ula() -> crate::host::InterfaceAddress {
        crate::host::InterfaceAddress {
            interface: "utun4".into(),
            address: "fd00:6b76:6e00::2".parse().unwrap(),
            prefix: 64,
        }
    }

    #[test]
    fn the_v6_address_is_an_inet6_alias_on_the_utun() {
        assert_eq!(
            address_args("alias", &ula()),
            [
                "utun4",
                "inet6",
                "fd00:6b76:6e00::2",
                "prefixlen",
                "64",
                "alias"
            ]
        );
        assert_eq!(
            address_args("-alias", &ula()),
            [
                "utun4",
                "inet6",
                "fd00:6b76:6e00::2",
                "prefixlen",
                "64",
                "-alias"
            ]
        );
    }

    #[test]
    fn only_ifconfigs_own_words_count_as_absent() {
        assert!(is_absent_address(
            "ifconfig: ioctl (SIOCDIFADDR): Can't assign requested address"
        ));
        assert!(is_absent_address(
            "ifconfig: interface utun4 does not exist"
        ));
        assert!(!is_absent_address(
            "ifconfig: ioctl (SIOCAIFADDR): Operation not permitted"
        ));
    }

    /// The shape of `ifconfig utun4 inet6` on a utun that already carries the
    /// ULA: a flags line, a scoped link-local, the ULA, and the `nd6` line.
    /// `alias` on this interface would exit 0 and say nothing, so this listing
    /// is the only way to learn the address was there before the session.
    const UTUN_WITH_THE_ULA: &str = "\
utun4: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500
\tinet6 fe80::ce81:b1c:bd2c:69e%utun4 prefixlen 64 scopeid 0x17
\tinet6 fd00:6b76:6e00::2 prefixlen 64
\tnd6 options=201<PERFORMNUD,DAD>
";

    #[test]
    fn an_address_already_on_the_utun_is_found_in_the_listing() {
        assert!(lists_address(UTUN_WITH_THE_ULA, ula().address));
    }

    /// A fresh utun lists only its link-local, whose `%utun4` scope must not
    /// make the row unparseable -- or every listing would read as "absent"
    /// and the check would never fire.
    #[test]
    fn a_fresh_utun_does_not_list_it() {
        let fresh = "\
utun4: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500
\tinet6 fe80::ce81:b1c:bd2c:69e%utun4 prefixlen 64 scopeid 0x17
\tnd6 options=201<PERFORMNUD,DAD>
";
        assert!(!lists_address(fresh, ula().address));
        assert!(
            lists_address(fresh, "fe80::ce81:b1c:bd2c:69e".parse().unwrap()),
            "the scoped link-local row parses, scope dropped"
        );
        assert!(!lists_address("", ula().address));
    }
}
