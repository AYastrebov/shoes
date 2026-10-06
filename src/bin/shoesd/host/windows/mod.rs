//! The Windows host: routes through the IP Helper API, DNS on the tunnel
//! adapter plus an NRPT rule.
//!
//! The plan this carries out is the shared one (`host/plan.rs`); this file is
//! only the privileged operations, and like the other two arms it is free of
//! policy. Two choices differ from them, both for the same reason: the Unix
//! arms run `ip`/`route` and match their error text, and Windows' equivalents
//! (`route.exe`, `netsh`) print localised text with no stable message to
//! match. So routes go through the API, whose errors are numbers.
//!
//! Design: docs/specs/2026-10-06-windows-privileged-daemon.md.

mod dns;
pub mod monitor;
mod routes;

use std::net::IpAddr;

use super::{DnsState, HostNetwork, Route};

pub struct WindowsHost;

impl WindowsHost {
    pub fn new() -> std::io::Result<Self> {
        Ok(Self)
    }
}

impl HostNetwork for WindowsHost {
    fn default_gateway(&self) -> std::io::Result<Option<IpAddr>> {
        routes::default_gateway()
    }

    fn add_route(&self, route: &Route) -> std::io::Result<()> {
        routes::add(route)
    }

    fn delete_route(&self, route: &Route) -> std::io::Result<()> {
        routes::delete(route)
    }

    /// The tunnel adapter itself, as on Linux: resolvers go on the tunnel's
    /// own interface, which nothing else on the host writes. The NRPT rule
    /// [`dns::write`] adds alongside is what stops the other interfaces from
    /// answering anyway.
    fn primary_dns_service(&self, interface: &str) -> std::io::Result<String> {
        Ok(interface.to_owned())
    }

    /// Nothing to restore: the adapter is created per session with no
    /// resolvers of its own, and revert's job is to remove the NRPT rule,
    /// which restoring "no servers" does.
    fn read_dns(&self, _service: &str) -> std::io::Result<DnsState> {
        Ok(DnsState::default())
    }

    fn write_dns(&self, service: &str, state: &DnsState) -> std::io::Result<()> {
        dns::write(service, &state.servers)
    }

    fn flush_dns_cache(&self) -> std::io::Result<()> {
        dns::flush()
    }
}
