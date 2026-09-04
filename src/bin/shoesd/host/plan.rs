//! What to apply, in what order, and what to undo when a step fails.
//!
//! This is the part of the daemon with the damage in it, which is why it is
//! separated from the calls that do the work: it runs in CI on every platform,
//! against a recording double, with no root and no device.
//!
//! Two rules shape everything here.
//!
//! **Undo in reverse.** A failure part-way through leaves the machine
//! half-configured, and the only state a user can act from is the one they
//! started in. So `apply` reverts what it managed before returning its error,
//! and `revert` walks the record backwards.
//!
//! **Never stop reverting early.** A revert step that fails must not abort the
//! ones after it. Undoing three routes out of five and returning leaves two
//! installed, pointing at an interface that is about to disappear -- which is
//! a Mac with no network and no record of why. Every failure is collected and
//! reported together, after everything has been attempted.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use super::state::{AppliedState, DnsBackup};
use super::{HostNetwork, Route, Via};

/// What a session wants done to the host.
#[derive(Debug, Clone)]
pub struct Plan {
    /// The tunnel interface, as the kernel named it.
    pub interface: String,
    /// Literal addresses that must stay outside the tunnel -- the proxy
    /// server. Resolved by the client before it asks, so no name lookup
    /// happens here.
    pub exclude: Vec<IpAddr>,
    /// Resolvers to advertise. Empty leaves the host's DNS alone.
    pub dns: Vec<IpAddr>,
}

/// Applies a [`Plan`] and can undo it.
pub struct Session<'a, N: HostNetwork> {
    net: &'a N,
    state_path: PathBuf,
}

impl<'a, N: HostNetwork> Session<'a, N> {
    pub fn new(net: &'a N, state_path: impl Into<PathBuf>) -> Self {
        Self {
            net,
            state_path: state_path.into(),
        }
    }

    /// Undo anything a previous run left behind, then forget it.
    ///
    /// Called before the first change of every start, not only after a crash:
    /// a start that finds a record has one either because the last process
    /// died holding it, or because its own revert could not finish. Both mean
    /// the machine is not in the state this session is about to assume.
    pub fn recover(&self) -> std::io::Result<()> {
        let Some(state) = AppliedState::load(&self.state_path)? else {
            return Ok(());
        };

        if state.is_empty() {
            return AppliedState::clear(&self.state_path);
        }

        log::warn!(
            "a previous session left {} route(s){} applied; undoing them",
            state.routes.len(),
            if state.dns.is_some() {
                " and a DNS override"
            } else {
                ""
            }
        );

        self.revert(&state)?;
        AppliedState::clear(&self.state_path)
    }

    /// Apply the plan, or leave the machine as it was found.
    pub fn apply(&self, plan: &Plan) -> std::io::Result<AppliedState> {
        let mut state = AppliedState {
            interface: Some(plan.interface.clone()),
            ..Default::default()
        };

        match self.apply_steps(plan, &mut state) {
            Ok(()) => Ok(state),
            Err(e) => {
                // The machine is half-configured and the caller is about to
                // hear about a failure, so put it back first. A revert that
                // itself fails is logged rather than returned: the original
                // error is the one that explains what went wrong, and losing
                // it behind a secondary failure would be the worse trade.
                if let Err(revert_error) = self.revert(&state) {
                    log::error!(
                        "could not fully undo a failed start ({revert_error}); \
                         the record at {} still describes what is applied",
                        self.state_path.display()
                    );
                } else {
                    let _ = AppliedState::clear(&self.state_path);
                }
                Err(e)
            }
        }
    }

    fn apply_steps(&self, plan: &Plan, state: &mut AppliedState) -> std::io::Result<()> {
        for route in tunnel_routes(&plan.interface) {
            self.add_recorded(route, state)?;
        }

        // The gateway is read once here and again on every routing change
        // while the session is up; the caller re-applies exclusions rather
        // than this function caching an answer that expires.
        let gateway = self.net.default_gateway()?;
        for address in &plan.exclude {
            let via = match gateway {
                Some(gateway) if gateway.is_ipv4() == address.is_ipv4() => Via::Gateway(gateway),
                // No usable gateway. Dropping the address is the only choice
                // that is not a routing loop -- see `Via::Blackhole`.
                _ => Via::Blackhole,
            };
            self.add_recorded(Route::host(*address, via), state)?;
        }

        if !plan.dns.is_empty() {
            self.apply_dns(&plan.dns, state)?;
        }

        Ok(())
    }

    /// Record the route, then install it.
    ///
    /// That order is the whole point of the record: a crash between the two
    /// leaves a route described but not applied, and reverting it is a no-op.
    /// The other order leaves a route applied and undescribed, which is a Mac
    /// with no network.
    fn add_recorded(&self, route: Route, state: &mut AppliedState) -> std::io::Result<()> {
        state.routes.push(route.clone());
        state.save(&self.state_path)?;
        self.net.add_route(&route)
    }

    fn apply_dns(&self, servers: &[IpAddr], state: &mut AppliedState) -> std::io::Result<()> {
        let service = self.net.primary_dns_service()?;
        let previous = self.net.read_dns(&service)?;

        // Recorded before the write, and only after the read: a backup written
        // any earlier would not know what to restore.
        state.dns = Some(DnsBackup {
            service: service.clone(),
            servers: previous,
        });
        state.save(&self.state_path)?;

        self.net.write_dns(&service, servers)?;
        self.net.flush_dns_cache()
    }

    /// Put everything in `state` back, in reverse order.
    ///
    /// Every step is attempted even after one fails; the failures are reported
    /// together at the end.
    pub fn revert(&self, state: &AppliedState) -> std::io::Result<()> {
        let mut failures: Vec<String> = Vec::new();

        // DNS first, because it went on last.
        if let Some(backup) = &state.dns {
            if let Err(e) = self.net.write_dns(&backup.service, &backup.servers) {
                failures.push(format!("restoring DNS on {}: {e}", backup.service));
            }
            if let Err(e) = self.net.flush_dns_cache() {
                failures.push(format!("flushing the DNS cache: {e}"));
            }
        }

        for route in state.routes.iter().rev() {
            if let Err(e) = self.net.delete_route(route) {
                failures.push(format!("removing {route:?}: {e}"));
            }
        }

        if failures.is_empty() {
            return Ok(());
        }
        Err(std::io::Error::other(format!(
            "could not fully revert: {}",
            failures.join("; ")
        )))
    }
}

/// The routes that put traffic into the tunnel.
///
/// The v4 default arrives as two halves rather than a replaced `default`:
/// each is more specific than the physical interface's default route, so they
/// win without deleting it. That matters twice over -- the pre-tunnel default
/// is still in the table for exclusions to point at, and a crash leaves it
/// exactly as it was.
///
/// The v6 halves are rejects. v1 does not carry IPv6, and the alternatives are
/// worse: leaving it alone leaks every v6 connection to the physical
/// interface, and blackholing makes each one wait out a timeout before Happy
/// Eyeballs falls back to v4. A reject fails immediately, so the fallback is
/// immediate too.
fn tunnel_routes(interface: &str) -> Vec<Route> {
    let via = Via::Interface(interface.to_string());
    vec![
        Route::net(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 1, via.clone()),
        Route::net(IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)), 1, via),
        Route::net(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 1, Via::Reject),
        Route::net(
            IpAddr::V6(Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0)),
            1,
            Via::Reject,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::Destination;
    use crate::host::double::{Recorder, Step};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn plan() -> Plan {
        Plan {
            interface: "utun4".to_string(),
            exclude: vec![ip("203.0.113.7")],
            dns: vec![ip("10.0.0.1")],
        }
    }

    fn session_path(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("applied.json")
    }

    /// The order is the contract: traffic must not be able to reach the
    /// tunnel before the exclusion for the proxy exists, or the proxy's own
    /// connection is captured by the tunnel it carries.
    ///
    /// It is asserted as a whole sequence rather than as "contains", because
    /// a reordering is exactly the kind of change that looks harmless.
    #[test]
    fn apply_installs_routes_then_dns_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let net = Recorder::new().with_gateway(Some(ip("192.168.1.1")));
        let session = Session::new(&net, session_path(&dir));

        session.apply(&plan()).expect("every step succeeds");

        let steps = net.steps();
        assert_eq!(
            steps,
            vec![
                Step::AddRoute(Route::net(ip("0.0.0.0"), 1, Via::Interface("utun4".into()))),
                Step::AddRoute(Route::net(
                    ip("128.0.0.0"),
                    1,
                    Via::Interface("utun4".into())
                )),
                Step::AddRoute(Route::net(ip("::"), 1, Via::Reject)),
                Step::AddRoute(Route::net(ip("8000::"), 1, Via::Reject)),
                Step::Gateway,
                Step::AddRoute(Route::host(
                    ip("203.0.113.7"),
                    Via::Gateway(ip("192.168.1.1"))
                )),
                Step::PrimaryService,
                Step::ReadDns("primary".into()),
                Step::WriteDns("primary".into(), vec![ip("10.0.0.1")]),
                Step::FlushDns,
            ],
            "got {steps:#?}"
        );
    }

    /// Without a gateway the excluded address matches nothing but the
    /// tunnel's own half-default, so the proxy's packets would enter the
    /// tunnel that is carrying them. Blackholing fails the connection
    /// instead, which is recoverable; the loop is not.
    #[test]
    fn an_excluded_address_is_blackholed_when_there_is_no_gateway() {
        let dir = tempfile::tempdir().unwrap();
        let net = Recorder::new().with_gateway(None);
        let session = Session::new(&net, session_path(&dir));

        session.apply(&plan()).unwrap();

        assert!(
            net.steps().contains(&Step::AddRoute(Route::host(
                ip("203.0.113.7"),
                Via::Blackhole
            ))),
            "got {:#?}",
            net.steps()
        );
    }

    /// A v4 exclusion must not be sent through a v6 gateway. The families are
    /// checked rather than assumed to match, because a machine with only a v6
    /// default route is a real configuration and the resulting route would be
    /// rejected by the kernel with an error that says nothing useful.
    #[test]
    fn an_exclusion_is_not_sent_through_a_gateway_of_the_wrong_family() {
        let dir = tempfile::tempdir().unwrap();
        let net = Recorder::new().with_gateway(Some(ip("fe80::1")));
        let session = Session::new(&net, session_path(&dir));

        session.apply(&plan()).unwrap();

        assert!(
            net.steps().contains(&Step::AddRoute(Route::host(
                ip("203.0.113.7"),
                Via::Blackhole
            ))),
            "a v4 address must not take a v6 gateway: {:#?}",
            net.steps()
        );
    }

    /// The case the whole design exists for: DNS fails, and the routes that
    /// were already installed have to come back off. Otherwise the user is
    /// left with a default route into an interface that is about to go away.
    #[test]
    fn a_dns_failure_undoes_the_routes() {
        let dir = tempfile::tempdir().unwrap();
        let net = Recorder::new()
            .with_gateway(Some(ip("192.168.1.1")))
            .failing_write_dns();
        let session = Session::new(&net, session_path(&dir));

        session
            .apply(&plan())
            .expect_err("a DNS failure must fail the start");

        let deleted: Vec<&Route> = net
            .steps()
            .iter()
            .filter_map(|step| match step {
                Step::DeleteRoute(route) => Some(route),
                _ => None,
            })
            .cloned()
            .collect::<Vec<_>>()
            .leak()
            .iter()
            .collect();
        assert_eq!(deleted.len(), 5, "every added route comes back off");

        // Reverse order, so the exclusion goes before the halves it depended
        // on being more specific than.
        assert_eq!(
            deleted[0].destination,
            Destination::Host(ip("203.0.113.7")),
            "the last route added is the first removed"
        );
    }

    /// A route failing part-way undoes what came before it, and stops.
    ///
    /// The failed route is undone too, and that is the record-before-apply
    /// rule showing through rather than a bug: it was written down before it
    /// was attempted, precisely so that a crash *between* those two moments
    /// leaves it described. Removing a route that was never installed is
    /// required to be a no-op -- see `HostNetwork::delete_route` -- so the
    /// cost of the safe order is one harmless call, and the cost of the other
    /// order is a route nothing knows about.
    #[test]
    fn a_route_failure_undoes_what_it_recorded_and_stops() {
        let dir = tempfile::tempdir().unwrap();
        let net = Recorder::new()
            .with_gateway(Some(ip("192.168.1.1")))
            .failing_add_route_after(2);
        let session = Session::new(&net, session_path(&dir));

        session.apply(&plan()).expect_err("the third route fails");

        let added = net.count_added();
        let deleted = net.count_deleted();
        assert_eq!(added, 2, "two succeeded before the failure");
        assert_eq!(
            deleted, 3,
            "those two plus the one that was recorded before it failed"
        );
        assert!(
            !net.steps().iter().any(|s| matches!(s, Step::WriteDns(..))),
            "DNS is never reached"
        );
    }

    /// Undoing three routes out of five and giving up leaves two installed,
    /// pointing at an interface that is about to disappear. Every step is
    /// attempted; the failures are reported together.
    #[test]
    fn revert_continues_past_a_failure_and_reports_them_all() {
        let dir = tempfile::tempdir().unwrap();
        let net = Recorder::new().failing_delete_route();
        let session = Session::new(&net, session_path(&dir));

        let state = AppliedState {
            interface: Some("utun4".into()),
            routes: vec![
                Route::net(ip("0.0.0.0"), 1, Via::Interface("utun4".into())),
                Route::net(ip("128.0.0.0"), 1, Via::Interface("utun4".into())),
                Route::host(ip("203.0.113.7"), Via::Blackhole),
            ],
            dns: None,
        };

        let err = session
            .revert(&state)
            .expect_err("failures must be reported");

        assert_eq!(
            net.count_deleted(),
            3,
            "all three were attempted despite the first failing"
        );
        assert_eq!(
            err.to_string().matches("removing").count(),
            3,
            "each failure is named: {err}"
        );
    }

    /// After a crash the record is on disk and the machine is still
    /// configured. Recovery is what runs before anything else on the next
    /// start, and `launchd`'s KeepAlive is what makes "the next start" happen
    /// within seconds rather than when someone logs in -- which they cannot,
    /// because the network is down.
    #[test]
    fn recover_undoes_what_a_crash_left_behind() {
        let dir = tempfile::tempdir().unwrap();
        let path = session_path(&dir);

        let left_behind = AppliedState {
            interface: Some("utun4".into()),
            routes: vec![Route::net(ip("0.0.0.0"), 1, Via::Interface("utun4".into()))],
            dns: Some(DnsBackup {
                service: "primary".into(),
                servers: vec![ip("192.168.1.1")],
            }),
        };
        left_behind.save(&path).unwrap();

        let net = Recorder::new();
        Session::new(&net, &path).recover().expect("recovery works");

        assert_eq!(
            net.steps(),
            vec![
                Step::WriteDns("primary".into(), vec![ip("192.168.1.1")]),
                Step::FlushDns,
                Step::DeleteRoute(Route::net(ip("0.0.0.0"), 1, Via::Interface("utun4".into()))),
            ]
        );
        assert!(!path.exists(), "the record is gone once it is undone");
    }

    /// The ordinary start on a machine that has never crashed.
    #[test]
    fn recover_does_nothing_without_a_record() {
        let dir = tempfile::tempdir().unwrap();
        let net = Recorder::new();
        Session::new(&net, session_path(&dir)).recover().unwrap();
        assert!(net.steps().is_empty());
    }

    /// A successful apply leaves the record in place: it describes what is
    /// applied *now*, and it is what a crash a minute later will be undone
    /// from.
    #[test]
    fn a_successful_apply_leaves_the_record_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = session_path(&dir);
        let net = Recorder::new().with_gateway(Some(ip("192.168.1.1")));

        let state = Session::new(&net, &path).apply(&plan()).unwrap();

        let on_disk = AppliedState::load(&path).unwrap().expect("still there");
        assert_eq!(on_disk, state);
        assert_eq!(on_disk.routes.len(), 5);
        assert_eq!(
            on_disk.dns.as_ref().map(|d| d.service.as_str()),
            Some("primary")
        );
    }

    /// Revert restores what was there, not an empty list. A machine whose
    /// resolvers were cleared rather than restored resolves nothing, and the
    /// user has no way to look up how to fix it.
    #[test]
    fn revert_restores_the_resolvers_the_host_had() {
        let dir = tempfile::tempdir().unwrap();
        let existing = vec![ip("192.168.1.1"), ip("1.1.1.1")];
        let net = Recorder::new()
            .with_gateway(Some(ip("192.168.1.1")))
            .with_existing_dns(existing.clone());
        let session = Session::new(&net, session_path(&dir));

        let state = session.apply(&plan()).unwrap();
        assert_eq!(
            state.dns.as_ref().map(|d| d.servers.clone()),
            Some(existing.clone()),
            "the backup holds what the host had before"
        );

        session.revert(&state).unwrap();

        let writes: Vec<Vec<IpAddr>> = net
            .steps()
            .into_iter()
            .filter_map(|step| match step {
                Step::WriteDns(_, servers) => Some(servers),
                _ => None,
            })
            .collect();
        assert_eq!(
            writes,
            vec![vec![ip("10.0.0.1")], existing],
            "the tunnel's resolvers go on, then the host's come back"
        );
    }

    /// Empty `dns` means the client did not ask for resolvers, and the host's
    /// own must then be left alone -- not overwritten with an empty list,
    /// which is a machine that resolves nothing.
    #[test]
    fn an_empty_dns_list_leaves_the_host_resolvers_alone() {
        let dir = tempfile::tempdir().unwrap();
        let net = Recorder::new().with_gateway(Some(ip("192.168.1.1")));
        let session = Session::new(&net, session_path(&dir));

        let state = session
            .apply(&Plan {
                dns: Vec::new(),
                ..plan()
            })
            .unwrap();

        assert!(state.dns.is_none());
        assert!(
            !net.steps()
                .iter()
                .any(|s| matches!(s, Step::WriteDns(..) | Step::ReadDns(..))),
            "DNS is not touched at all: {:#?}",
            net.steps()
        );
    }
}
