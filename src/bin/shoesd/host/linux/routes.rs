//! Routes through `ip`.
//!
//! The Linux counterpart of `host/macos/mod.rs`'s route half, split the same
//! way: [`route_args`], [`parse_default_gateway`] and [`is_absent_route`]
//! decide *what* to run and what an answer means, and are pure and tested;
//! [`run`] and [`run_capturing`] are the thin wrappers that do it, exercised by
//! the live run.
//!
//! Nothing here interpolates into a shell -- every command is a
//! `std::process::Command` with an argv array, and every address in one is a
//! parsed `IpAddr` re-serialised rather than a string forwarded from the
//! request.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;

use crate::host::{Destination, Route, Via};

/// Where `ip` may be, in the order the candidates are tried.
///
/// Never searched on `PATH`. A root process that resolves a program through
/// `PATH` runs whatever the first writable directory on it happens to hold, and
/// `shoesd run` under `sudo` inherits the invoker's environment -- the same
/// reason the macOS arm names `/sbin/route` outright.
///
/// Three entries rather than two because merged-`/usr` layouts differ: on
/// Fedora 44 `/sbin` and `/usr/sbin` both lead to `/usr/bin/ip`, while on
/// Debian `/usr/sbin/ip` is the real file. Whichever is found first is used for
/// the life of the process.
const IP_CANDIDATES: [&str; 3] = ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip"];

/// `ip`, located once.
pub struct Routes {
    program: PathBuf,
}

impl Routes {
    pub fn locate() -> std::io::Result<Self> {
        Ok(Self {
            program: locate_among(&IP_CANDIDATES)?,
        })
    }

    pub fn program(&self) -> &Path {
        &self.program
    }

    pub fn default_gateway(&self) -> std::io::Result<Option<IpAddr>> {
        // `route show default` matches the literal `default` destination, so --
        // unlike `ip route get 0.0.0.0`, the direct analogue of the `route get
        // default` trap the macOS arm documents -- it cannot be answered with
        // this daemon's own `0.0.0.0/1`. That is a half-default, not `default`.
        //
        // No `-6`, so this is the IPv4 table, matching macOS's `netstat -rn -f
        // inet`. `exclusion_routes` already blackholes an exclusion whose
        // family does not match the gateway's, so a v6 answer here would be
        // discarded by the only caller.
        let output = run_capturing(&self.program, &["-j", "route", "show", "default"])?;
        parse_default_gateway(&output)
    }

    pub fn add(&self, route: &Route) -> std::io::Result<()> {
        run(&self.program, &route_args("add", route))
    }

    pub fn delete(&self, route: &Route) -> std::io::Result<()> {
        // A route that is not in the table is success -- and *only* that.
        // Revert runs after a partial apply and after a crash, so it is
        // routinely asked to remove routes that were never added, or ones the
        // kernel already dropped along with the tunnel device; failing there
        // would abort the revert and leave the rest installed.
        //
        // Every other failure has to propagate. `Session::revert` reports what
        // failed and the supervisor keeps the on-disk record when it does, so
        // swallowing an EPERM or a missing `ip` here would report a clean
        // revert, delete the record, and leave the host with its default routed
        // into a tun device that no longer exists -- the exact failure the
        // record exists to prevent.
        match run(&self.program, &route_args("del", route)) {
            Ok(()) => Ok(()),
            Err(e) if is_absent_route(&e.to_string()) => {
                log::debug!("{route:?} was already gone");
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}

/// The first candidate that exists.
///
/// Separate from [`Routes::locate`] so the ordering is asserted against a
/// temporary directory rather than against whatever the machine running the
/// tests happens to have in `/sbin`.
fn locate_among<P: AsRef<Path>>(candidates: &[P]) -> std::io::Result<PathBuf> {
    candidates
        .iter()
        .map(|candidate| candidate.as_ref())
        .find(|candidate| candidate.exists())
        .map(Path::to_path_buf)
        .ok_or_else(missing_ip)
}

/// The failure a host without iproute2 gets, at daemon startup.
///
/// Names every candidate: "ip not found" leaves the reader to guess whether
/// the daemon wanted a package installed or looked somewhere their
/// distribution does not use, and this message is the whole of what they get.
fn missing_ip() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!(
            "no `ip` found -- looked for {} and nothing else, because a root \
             daemon must not resolve a program through PATH. Install iproute2",
            IP_CANDIDATES.join(", ")
        ),
    )
}

/// The argv for `ip route add`/`ip route del`.
///
/// Pure, so the shape of every command this daemon runs as root is asserted in
/// a test rather than discovered on a live machine. There is no family flag:
/// `ip` infers `inet` or `inet6` from the destination literal, which is the one
/// place this is simpler than macOS's `-inet`/`-inet6`.
fn route_args(verb: &str, route: &Route) -> Vec<String> {
    let mut args = vec!["route".to_string(), verb.to_string()];

    // `del` matches on the destination, so the next hop is only meaningful when
    // adding. Passing it to a delete makes an otherwise-fine removal fail when
    // the route in the table has drifted. The route type below is part of the
    // next hop for this purpose and is dropped with it.
    let via = (verb == "add").then_some(&route.via);

    // `blackhole` and `unreachable` are native route *types* here, so they come
    // before the destination -- macOS spells the same two as trailing flags on
    // a loopback next hop, and that shape put in this position is a command
    // `ip` rejects outright. There is no "a next hop is required even though
    // nothing is delivered" workaround to carry over.
    match via {
        Some(Via::Blackhole) => args.push("blackhole".to_string()),
        Some(Via::Reject) => args.push("unreachable".to_string()),
        _ => {}
    }

    args.push(match &route.destination {
        Destination::Net { addr, prefix } => format!("{addr}/{prefix}"),
        // Bare, with no `/32`: `ip` reads an address without a prefix as a host
        // route already, and both spellings land in the table identically.
        Destination::Host(addr) => addr.to_string(),
    });

    match via {
        Some(Via::Interface(name)) => {
            args.push("dev".to_string());
            args.push(name.clone());
        }
        Some(Via::Gateway(gateway)) => {
            args.push("via".to_string());
            args.push(gateway.to_string());
        }
        _ => {}
    }

    args
}

/// One entry of `ip -j route show default`.
///
/// Only the two fields this decision needs. Every other key `ip` emits --
/// `dst`, `dev`, `protocol`, `prefsrc`, `flags`, `type` -- is ignored rather
/// than denied, because the set varies by route type and by iproute2 release,
/// and a daemon that refused to start on an unexpected key would be broken by
/// an upgrade of a package it only reads from.
#[derive(Deserialize)]
struct DefaultRoute {
    /// Absent for a default through a point-to-point interface, and for a
    /// non-unicast one such as `{"type":"blackhole",...}`.
    gateway: Option<IpAddr>,
    /// **Absent means zero.** `ip -j` omits the key entirely at metric 0
    /// (measured), so treating absence as "unknown, therefore last" would
    /// invert the ordering for exactly the route most likely to be the real
    /// default.
    #[serde(default)]
    metric: u32,
}

/// The default gateway from `ip -j route show default`.
///
/// Entries with no `gateway` are skipped, which is the exact analogue of the
/// macOS arm's `link#N` filter and exists for the same reason: a gateway-less
/// default belongs to a point-to-point interface -- typically this daemon's own
/// tunnel -- so taking it would send an excluded address into the tunnel it is
/// excluded from.
///
/// The lowest metric wins, ties broken by table order, because a laptop with
/// Ethernet and Wi-Fi both up has two live defaults and the kernel uses the
/// lower. macOS needs no such rule only because `netstat` reports one row.
fn parse_default_gateway(table: &str) -> std::io::Result<Option<IpAddr>> {
    // Nothing at all is an empty table, not a parse failure: there is no
    // gateway in either, and stdout that is empty rather than `[]` says only
    // that something printed nothing.
    if table.trim().is_empty() {
        return Ok(None);
    }

    let routes: Vec<DefaultRoute> = serde_json::from_str(table).map_err(|e| {
        // An `ip` too old for `-j` exits non-zero and never reaches here, so
        // unparseable output at exit 0 means the output is not understood.
        // Answering `None` there would silently blackhole every exclusion on a
        // host that has a perfectly good gateway, which looks to the user like
        // the proxy being unreachable.
        std::io::Error::other(format!("could not parse `ip -j route show default`: {e}"))
    })?;

    // `min_by_key` keeps the first of an equal run, which is the tie-break.
    Ok(routes
        .iter()
        .filter(|route| route.gateway.is_some())
        .min_by_key(|route| route.metric)
        .and_then(|route| route.gateway))
}

/// Whether an `ip route del` failure means the route was simply not there.
///
/// Deleting an absent route exits **2** with `RTNETLINK answers: No such
/// process` -- ESRCH, surfaced as a message rather than an errno (measured).
/// Matched on the message rather than the exit status, because `ip` also exits
/// 2 for EPERM and for an unreachable next hop, which are not this.
fn is_absent_route(message: &str) -> bool {
    message
        .to_ascii_lowercase()
        .contains("rtnetlink answers: no such process")
}

/// Run a command, failing if it does.
fn run(program: &Path, args: &[String]) -> std::io::Result<()> {
    let output = Command::new(program).args(args).output().map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!("could not run {} {args:?}: {e}", program.display()),
        )
    })?;

    if output.status.success() {
        return Ok(());
    }
    Err(std::io::Error::other(format!(
        "{} {args:?} failed ({}): {}",
        program.display(),
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}

/// Run a command and return its stdout.
fn run_capturing(program: &Path, args: &[&str]) -> std::io::Result<String> {
    let output = Command::new(program).args(args).output().map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!("could not run {} {args:?}: {e}", program.display()),
        )
    })?;

    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "{} {args:?} failed ({}): {}",
            program.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    String::from_utf8(output.stdout).map_err(|e| {
        std::io::Error::other(format!(
            "{} produced non-UTF-8 output: {e}",
            program.display()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// The tunnel halves are pinned to the interface rather than to a next
    /// hop, and `ip` infers the address family from the destination -- there
    /// is no `-inet`/`-inet6` to get wrong, unlike macOS.
    #[test]
    fn a_tunnel_half_is_pinned_to_the_interface() {
        assert_eq!(
            route_args(
                "add",
                &Route::net(ip("0.0.0.0"), 1, Via::Interface("tun0".into()))
            ),
            vec!["route", "add", "0.0.0.0/1", "dev", "tun0"]
        );
        assert_eq!(
            route_args(
                "add",
                &Route::net(ip("8000::"), 1, Via::Interface("tun0".into()))
            ),
            vec!["route", "add", "8000::/1", "dev", "tun0"]
        );
    }

    /// An exclusion is a host route -- a bare address, with no `/32` -- out
    /// through the gateway that was in the table before the tunnel came up.
    #[test]
    fn an_exclusion_is_a_host_route_through_the_gateway() {
        assert_eq!(
            route_args(
                "add",
                &Route::host(ip("203.0.113.7"), Via::Gateway(ip("192.0.2.1")))
            ),
            vec!["route", "add", "203.0.113.7", "via", "192.0.2.1"]
        );
        assert_eq!(
            route_args(
                "add",
                &Route::host(ip("2001:db8::7"), Via::Gateway(ip("2001:db8::1")))
            ),
            vec!["route", "add", "2001:db8::7", "via", "2001:db8::1"]
        );
    }

    /// `blackhole` is a route *type* and comes before the destination. macOS
    /// spells the same thing as a trailing flag on a loopback next hop, so
    /// carrying that shape over would put the word in the wrong place and
    /// `ip` would reject the whole command.
    #[test]
    fn a_blackhole_is_a_route_type_before_the_destination() {
        assert_eq!(
            route_args("add", &Route::host(ip("203.0.113.7"), Via::Blackhole)),
            vec!["route", "add", "blackhole", "203.0.113.7"]
        );
        assert_eq!(
            route_args("add", &Route::host(ip("2001:db8::7"), Via::Blackhole)),
            vec!["route", "add", "blackhole", "2001:db8::7"]
        );
    }

    /// `Via::Reject` is `unreachable`, not `reject` -- `reject` is macOS's
    /// spelling and is not a route type `ip` knows.
    #[test]
    fn a_reject_is_an_unreachable_route() {
        assert_eq!(
            route_args("add", &Route::net(ip("0.0.0.0"), 1, Via::Reject)),
            vec!["route", "add", "unreachable", "0.0.0.0/1"]
        );
        assert_eq!(
            route_args("add", &Route::net(ip("::"), 1, Via::Reject)),
            vec!["route", "add", "unreachable", "::/1"]
        );
    }

    /// `ip route del` matches on the destination. Naming the next hop as well
    /// makes an otherwise-fine removal fail when what is in the table has
    /// drifted -- and a revert that fails leaves routes installed. The route
    /// type is part of the next hop for this purpose: a session that added a
    /// `blackhole` deletes the destination, nothing more.
    #[test]
    fn delete_names_only_the_destination() {
        assert_eq!(
            route_args(
                "del",
                &Route::net(ip("0.0.0.0"), 1, Via::Interface("tun0".into()))
            ),
            vec!["route", "del", "0.0.0.0/1"]
        );
        assert_eq!(
            route_args("del", &Route::host(ip("203.0.113.7"), Via::Blackhole)),
            vec!["route", "del", "203.0.113.7"]
        );
        assert_eq!(
            route_args("del", &Route::net(ip("::"), 1, Via::Reject)),
            vec!["route", "del", "::/1"]
        );
    }

    /// Every argument is a separate element, so nothing a caller sent can
    /// become a second argument or a shell token. The addresses in these
    /// arrays arrive over the control socket, and OpenVPN Connect shipped
    /// CVE-2026-9560 by interpolating one into a shell.
    #[test]
    fn no_argument_carries_a_separator() {
        let routes = [
            Route::net(ip("0.0.0.0"), 1, Via::Interface("tun0".into())),
            Route::net(ip("8000::"), 1, Via::Interface("tun0".into())),
            Route::host(ip("203.0.113.7"), Via::Gateway(ip("192.0.2.1"))),
            Route::host(ip("2001:db8::7"), Via::Gateway(ip("2001:db8::1"))),
            Route::host(ip("203.0.113.7"), Via::Blackhole),
            Route::net(ip("::"), 1, Via::Reject),
        ];
        for route in &routes {
            for verb in ["add", "del"] {
                for arg in route_args(verb, route) {
                    assert!(
                        !arg.contains(char::is_whitespace) && !arg.contains(';'),
                        "{arg:?} in {verb} {route:?}"
                    );
                }
            }
        }
    }

    /// The shape of a real `ip -j route show default`, kept whole rather than
    /// trimmed to the two keys this parse reads: the point of it is that it
    /// carries every key `ip` actually emits, so a parse that refused an
    /// unknown one would fail here rather than on a user's machine.
    ///
    /// The key set, their order and the empty `flags` array are copied from a
    /// capture on the development host; the addresses are documentation-range,
    /// because a fixture has no business carrying the topology of whichever
    /// machine it was captured on. The macOS `netstat` fixture says the same.
    const REAL_CAPTURE: &str = r#"[{"dst":"default","gateway":"198.51.100.1","dev":"eno1","protocol":"dhcp","prefsrc":"198.51.100.23","metric":100,"flags":[]}]"#;

    #[test]
    fn the_real_capture_yields_its_gateway() {
        assert_eq!(
            parse_default_gateway(REAL_CAPTURE).unwrap(),
            Some(ip("198.51.100.1"))
        );
    }

    /// A host with no default route at all -- between Wi-Fi and Ethernet, or
    /// on a link that never had one. `ip -j` prints `[]`; empty stdout is
    /// treated the same way rather than as a parse failure, because there is
    /// no gateway in it either way.
    #[test]
    fn no_default_route_yields_no_gateway() {
        assert_eq!(parse_default_gateway("[]").unwrap(), None);
        assert_eq!(parse_default_gateway("").unwrap(), None);
        assert_eq!(parse_default_gateway("  \n").unwrap(), None);
    }

    /// A default through a point-to-point interface has no `gateway` key.
    /// This is the analogue of macOS's `link#N` filter and exists for the same
    /// reason: that interface is typically this daemon's own tunnel, so taking
    /// it would send an excluded address into the tunnel it is excluded from.
    #[test]
    fn a_gateway_less_default_is_skipped() {
        let table =
            r#"[{"dst":"default","dev":"tun0","protocol":"static","metric":50,"flags":[]}]"#;
        assert_eq!(parse_default_gateway(table).unwrap(), None);
    }

    /// The tunnel's gateway-less default listed *first*, with the real one
    /// behind it. A parse that merely took the first entry would pass the
    /// fixture above and fail here, which is the case the filter exists for.
    #[test]
    fn a_gateway_less_default_is_skipped_wherever_it_appears() {
        let table = r#"[
            {"dst":"default","dev":"tun0","protocol":"static","flags":[]},
            {"dst":"default","gateway":"192.0.2.1","dev":"eno1","metric":100,"flags":[]}
        ]"#;
        assert_eq!(parse_default_gateway(table).unwrap(), Some(ip("192.0.2.1")));
    }

    /// A non-unicast default has neither `dev` nor `gateway`, and the same
    /// rule covers it for free -- but only if the absent keys are tolerated
    /// rather than refused, which is what this pins.
    #[test]
    fn a_blackhole_default_is_skipped() {
        let table = r#"[{"type":"blackhole","dst":"default","flags":[]}]"#;
        assert_eq!(parse_default_gateway(table).unwrap(), None);
    }

    /// A laptop with Ethernet and Wi-Fi both up has two defaults at different
    /// metrics, and the kernel uses the lower one. Taking the first entry
    /// would be a coin flip between two live gateways, so both orders are
    /// asserted.
    #[test]
    fn the_lowest_metric_wins() {
        let ethernet_first = r#"[
            {"dst":"default","gateway":"192.0.2.1","dev":"eno1","metric":100,"flags":[]},
            {"dst":"default","gateway":"198.51.100.1","dev":"wlp3s0","metric":600,"flags":[]}
        ]"#;
        let wifi_first = r#"[
            {"dst":"default","gateway":"198.51.100.1","dev":"wlp3s0","metric":600,"flags":[]},
            {"dst":"default","gateway":"192.0.2.1","dev":"eno1","metric":100,"flags":[]}
        ]"#;
        assert_eq!(
            parse_default_gateway(ethernet_first).unwrap(),
            Some(ip("192.0.2.1"))
        );
        assert_eq!(
            parse_default_gateway(wifi_first).unwrap(),
            Some(ip("192.0.2.1")),
            "the lower metric wins wherever it is listed"
        );
    }

    /// `ip -j` omits `metric` entirely when it is zero, so absence has to sort
    /// as 0 and not as "unknown, therefore last". Treating it as a large
    /// number inverts the ordering for exactly the route most likely to be the
    /// real default.
    #[test]
    fn an_absent_metric_sorts_as_zero() {
        let table = r#"[
            {"dst":"default","gateway":"198.51.100.1","dev":"eno1","metric":100,"flags":[]},
            {"dst":"default","gateway":"192.0.2.1","dev":"eno2","flags":[]}
        ]"#;
        assert_eq!(parse_default_gateway(table).unwrap(), Some(ip("192.0.2.1")));
    }

    /// Output that is not the JSON array this asks for is an error, not "no
    /// gateway". An `ip` too old for `-j` exits non-zero and never reaches
    /// here, so anything unparseable at exit 0 means the output is not
    /// understood -- and answering `None` there would silently blackhole every
    /// exclusion on a host that has a perfectly good gateway.
    #[test]
    fn unparseable_output_is_an_error_not_an_empty_table() {
        let err = parse_default_gateway("default via 192.0.2.1 dev eno1\n").expect_err("not JSON");
        assert!(
            err.to_string().contains("ip -j route show default"),
            "{err}"
        );
    }

    /// Only "it was not there" is success. Anything else -- no permission, no
    /// `ip` binary, a kernel refusal -- has to reach `Session::revert`, which
    /// is what keeps the on-disk record instead of deleting it and leaving
    /// routes installed that nothing remembers.
    #[test]
    fn only_an_absent_route_counts_as_already_removed() {
        let absent = "/usr/sbin/ip [\"route\", \"del\", \"0.0.0.0/1\"] failed (exit status: 2): \
                      RTNETLINK answers: No such process";
        assert!(is_absent_route(absent));

        for real in [
            "/usr/sbin/ip [\"route\", \"del\", \"0.0.0.0/1\"] failed (exit status: 2): \
             RTNETLINK answers: Operation not permitted",
            "could not run /usr/sbin/ip [\"route\", \"del\"]: No such file or directory (os error 2)",
            "/usr/sbin/ip [...] failed (exit status: 1): ip: must be root to alter routing table",
            "/usr/sbin/ip [...] failed (exit status: 2): RTNETLINK answers: Network is unreachable",
            "/usr/sbin/ip [...] failed (exit status: 1): Cannot find device \"tun0\"",
        ] {
            assert!(!is_absent_route(real), "{real} must not be swallowed");
        }
    }

    /// The failure a host without iproute2 gets. It names all three candidates
    /// because the answer -- which package to install, or which of the three
    /// the distribution was expected to have -- is not derivable from "not
    /// found", and this error is what aborts daemon startup.
    #[test]
    fn the_missing_ip_error_names_every_candidate() {
        let message = missing_ip().to_string();
        for candidate in IP_CANDIDATES {
            assert!(message.contains(candidate), "{message}");
        }
        assert_eq!(missing_ip().kind(), std::io::ErrorKind::NotFound);
    }

    /// First candidate that exists wins, in list order rather than in
    /// whichever order the filesystem answers. Debian has the real file at
    /// `/usr/sbin/ip`; on a merged-`/usr` Fedora all three names resolve to
    /// one file, so the order only ever shows itself on the distributions
    /// where it matters.
    #[test]
    fn the_first_candidate_that_exists_is_the_one_used() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first");
        let second = dir.path().join("second");
        std::fs::write(&second, "").unwrap();

        assert_eq!(
            locate_among(&[first.clone(), second.clone()]).unwrap(),
            second,
            "a missing candidate is skipped"
        );

        std::fs::write(&first, "").unwrap();
        assert_eq!(
            locate_among(&[first.clone(), second]).unwrap(),
            first,
            "an earlier candidate wins over a later one"
        );

        let missing = dir.path().join("nothing");
        assert!(locate_among(&[missing]).is_err());
    }
}
