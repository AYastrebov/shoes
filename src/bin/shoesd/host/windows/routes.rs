//! Routes through the IP Helper API.
//!
//! Every route is created in the active store only (`CreateIpForwardEntry2`
//! does not persist), so a reboot can never leave one behind -- the property
//! the revert record exists to provide for a crash short of that.
//!
//! Deletion matches rows in the live table by destination and next hop rather
//! than rebuilding the row it added. Revert runs after the adapter is gone and
//! after the network moved, and a row rebuilt then would name an interface
//! that no longer resolves; finding what is actually installed cannot drift.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::windows::ffi::OsStrExt;

use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, ERROR_SUCCESS, WIN32_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceAliasToLuid, CreateIpForwardEntry2, DeleteIpForwardEntry2, FreeMibTable,
    GetBestRoute2, GetIfTable2, GetIpForwardTable2, GetIpInterfaceEntry, IF_TYPE_SOFTWARE_LOOPBACK,
    InitializeIpForwardEntry, InitializeIpInterfaceEntry, MIB_IF_TABLE2, MIB_IPFORWARD_ROW2,
    MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{
    ADDRESS_FAMILY, AF_INET, AF_INET6, MIB_IPPROTO_NETMGMT, SOCKADDR_INET,
};

use super::super::{Destination, Route, Via};

pub fn default_gateway() -> std::io::Result<Option<IpAddr>> {
    let mut candidates = Vec::new();
    for row in forward_table(AF_INET)? {
        let Some((IpAddr::V4(prefix), 0)) = prefix_of(&row) else {
            continue;
        };
        let Some(IpAddr::V4(next_hop)) = ip_of(&row.NextHop) else {
            continue;
        };
        if !prefix.is_unspecified() || next_hop.is_unspecified() {
            continue;
        }
        // What Windows itself ranks by: the route's metric plus its
        // interface's. An interface that cannot be read is skipped rather
        // than ranked as zero, which would make it win.
        if let Ok(interface_metric) = interface_metric(row.InterfaceLuid, AF_INET) {
            candidates.push((next_hop, row.Metric.saturating_add(interface_metric)));
        }
    }
    Ok(pick_gateway(candidates).map(IpAddr::V4))
}

/// The lowest combined metric wins; on a tie, the first seen.
fn pick_gateway(candidates: Vec<(Ipv4Addr, u32)>) -> Option<Ipv4Addr> {
    candidates
        .into_iter()
        .min_by_key(|&(_, metric)| metric)
        .map(|(gateway, _)| gateway)
}

pub fn add(route: &Route) -> std::io::Result<()> {
    let (destination, prefix_length) = destination_of(route);
    let mut row = new_row();
    row.DestinationPrefix.Prefix = sockaddr(destination);
    row.DestinationPrefix.PrefixLength = prefix_length;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row.Metric = 0;
    match &route.via {
        Via::Interface(alias) => {
            row.InterfaceLuid = luid_of_alias(alias)?;
            row.NextHop = sockaddr(unspecified_like(destination));
        }
        Via::Gateway(gateway) => {
            row.InterfaceLuid = luid_reaching(*gateway)?;
            row.NextHop = sockaddr(*gateway);
        }
        // Windows has neither route type. A route into the loopback interface
        // drops whatever is not addressed to the machine itself, which is
        // what both ask for; `Reject` thereby becomes a blackhole. Whether
        // that makes IPv6 fail fast is measured in the spec.
        Via::Blackhole | Via::Reject => {
            row.InterfaceLuid = loopback_luid()?;
            row.NextHop = sockaddr(unspecified_like(destination));
        }
    }

    // SAFETY: a fully initialised row.
    let rc = unsafe { CreateIpForwardEntry2(&row) };
    check(rc, || {
        format!("could not add a route to {destination}/{prefix_length}")
    })
}

pub fn delete(route: &Route) -> std::io::Result<()> {
    let (destination, prefix_length) = destination_of(route);
    // The interface this route was pinned to, where it names one. `None` for a
    // gateway route, which is identified by its next hop alone.
    let pinned = match &route.via {
        // A tunnel adapter that no longer exists took its routes with it:
        // nothing to delete, which the trait counts as success.
        Via::Interface(alias) => match luid_of_alias(alias) {
            Ok(luid) => Some(luid),
            Err(_) => return Ok(()),
        },
        Via::Blackhole | Via::Reject => Some(loopback_luid()?),
        Via::Gateway(_) => None,
    };
    let next_hop = match &route.via {
        Via::Gateway(gateway) => *gateway,
        _ => unspecified_like(destination),
    };

    for row in forward_table(family_of(destination))? {
        if !matches(&row, destination, prefix_length, next_hop, pinned) {
            continue;
        }
        // SAFETY: a row read back from the table.
        let rc = unsafe { DeleteIpForwardEntry2(&row) };
        if rc != ERROR_NOT_FOUND {
            check(rc, || {
                format!("could not delete the route to {destination}/{prefix_length}")
            })?;
        }
    }
    Ok(())
}

/// Whether `row` is the route described. The LUID is compared only when the
/// route was pinned to an interface.
fn matches(
    row: &MIB_IPFORWARD_ROW2,
    destination: IpAddr,
    prefix_length: u8,
    next_hop: IpAddr,
    pinned: Option<NET_LUID_LH>,
) -> bool {
    prefix_of(row) == Some((destination, prefix_length))
        && ip_of(&row.NextHop) == Some(next_hop)
        // SAFETY: `Value` is the whole 64-bit LUID; every bit pattern is valid.
        && pinned.is_none_or(|luid| unsafe { luid.Value == row.InterfaceLuid.Value })
}

fn destination_of(route: &Route) -> (IpAddr, u8) {
    match route.destination {
        Destination::Net { addr, prefix } => (addr, prefix),
        Destination::Host(addr) => (addr, if addr.is_ipv4() { 32 } else { 128 }),
    }
}

fn family_of(ip: IpAddr) -> ADDRESS_FAMILY {
    if ip.is_ipv4() { AF_INET } else { AF_INET6 }
}

fn unspecified_like(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    }
}

fn sockaddr(ip: IpAddr) -> SOCKADDR_INET {
    // SAFETY: all-zero is a valid SOCKADDR_INET; the active member is then
    // written whole.
    let mut address: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    match ip {
        IpAddr::V4(v4) => {
            address.Ipv4.sin_family = AF_INET;
            address.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(v4.octets());
        }
        IpAddr::V6(v6) => {
            address.Ipv6.sin6_family = AF_INET6;
            address.Ipv6.sin6_addr.u.Byte = v6.octets();
        }
    }
    address
}

fn ip_of(address: &SOCKADDR_INET) -> Option<IpAddr> {
    // SAFETY: `si_family` overlays the family field of both members, and the
    // member read is the one it names.
    unsafe {
        match address.si_family {
            AF_INET => Some(IpAddr::V4(Ipv4Addr::from(
                address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes(),
            ))),
            AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(address.Ipv6.sin6_addr.u.Byte))),
            _ => None,
        }
    }
}

fn prefix_of(row: &MIB_IPFORWARD_ROW2) -> Option<(IpAddr, u8)> {
    ip_of(&row.DestinationPrefix.Prefix).map(|ip| (ip, row.DestinationPrefix.PrefixLength))
}

fn new_row() -> MIB_IPFORWARD_ROW2 {
    // SAFETY: zeroed, then initialised to the API's defaults as documented.
    unsafe {
        let mut row: MIB_IPFORWARD_ROW2 = std::mem::zeroed();
        InitializeIpForwardEntry(&mut row);
        row
    }
}

/// The routing table for one family, copied out so the API's allocation is
/// freed before anything is done with it.
fn forward_table(family: ADDRESS_FAMILY) -> std::io::Result<Vec<MIB_IPFORWARD_ROW2>> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    // SAFETY: `table` is written on success and freed below.
    let rc = unsafe { GetIpForwardTable2(family, &mut table) };
    check(rc, || "could not read the routing table".to_owned())?;
    // SAFETY: `Table` is a variable-length array of `NumEntries` rows.
    let rows = unsafe {
        std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize).to_vec()
    };
    // SAFETY: allocated by GetIpForwardTable2.
    unsafe { FreeMibTable(table.cast()) };
    Ok(rows)
}

fn interface_metric(luid: NET_LUID_LH, family: ADDRESS_FAMILY) -> std::io::Result<u32> {
    // SAFETY: zeroed, initialised, then keyed by LUID and family as documented.
    let mut row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
    unsafe { InitializeIpInterfaceEntry(&mut row) };
    row.Family = family;
    row.InterfaceLuid = luid;
    // SAFETY: a keyed row.
    let rc = unsafe { GetIpInterfaceEntry(&mut row) };
    check(rc, || "could not read an interface's metric".to_owned())?;
    Ok(row.Metric)
}

fn luid_of_alias(alias: &str) -> std::io::Result<NET_LUID_LH> {
    let wide: Vec<u16> = std::ffi::OsStr::new(alias)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: a NUL-terminated alias; the LUID is written on success.
    let mut luid: NET_LUID_LH = unsafe { std::mem::zeroed() };
    let rc = unsafe { ConvertInterfaceAliasToLuid(wide.as_ptr(), &mut luid) };
    check(rc, || format!("no interface named {alias:?}"))?;
    Ok(luid)
}

/// The interface the host would use to reach `gateway` -- which is where an
/// excluded address's route has to leave from.
fn luid_reaching(gateway: IpAddr) -> std::io::Result<NET_LUID_LH> {
    let destination = sockaddr(gateway);
    // SAFETY: zeroed out-parameters, written on success.
    let mut best: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    let mut source: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        GetBestRoute2(
            std::ptr::null(),
            0,
            std::ptr::null(),
            &destination,
            0,
            &mut best,
            &mut source,
        )
    };
    check(rc, || format!("no route to the gateway {gateway}"))?;
    Ok(best.InterfaceLuid)
}

/// The software loopback interface, found by type rather than by its alias,
/// which is localised on some editions.
fn loopback_luid() -> std::io::Result<NET_LUID_LH> {
    let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
    // SAFETY: `table` is written on success and freed below.
    let rc = unsafe { GetIfTable2(&mut table) };
    check(rc, || "could not list interfaces".to_owned())?;
    // SAFETY: `Table` is a variable-length array of `NumEntries` rows.
    let found = unsafe {
        std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
            .iter()
            .find(|row| row.Type == IF_TYPE_SOFTWARE_LOOPBACK)
            .map(|row| row.InterfaceLuid)
    };
    // SAFETY: allocated by GetIfTable2.
    unsafe { FreeMibTable(table.cast()) };
    found.ok_or_else(|| std::io::Error::other("no loopback interface"))
}

fn check(rc: WIN32_ERROR, what: impl FnOnce() -> String) -> std::io::Result<()> {
    if rc == ERROR_SUCCESS {
        return Ok(());
    }
    let e = std::io::Error::from_raw_os_error(rc as i32);
    Err(std::io::Error::new(e.kind(), format!("{}: {e}", what())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_survive_the_round_trip_through_sockaddr() {
        for ip in [
            "0.0.0.0",
            "128.0.0.0",
            "192.0.2.7",
            "::",
            "8000::",
            "2001:db8::1",
        ] {
            let ip: IpAddr = ip.parse().unwrap();
            assert_eq!(ip_of(&sockaddr(ip)), Some(ip), "{ip}");
        }
    }

    #[test]
    fn a_host_route_is_a_full_length_prefix() {
        let v4 = Route::host("192.0.2.1".parse().unwrap(), Via::Blackhole);
        let v6 = Route::host("2001:db8::1".parse().unwrap(), Via::Blackhole);
        assert_eq!(destination_of(&v4).1, 32);
        assert_eq!(destination_of(&v6).1, 128);
    }

    #[test]
    fn the_lowest_combined_metric_is_the_gateway() {
        let wifi = Ipv4Addr::new(192, 168, 1, 1);
        let ethernet = Ipv4Addr::new(10, 0, 0, 1);
        assert_eq!(
            pick_gateway(vec![(wifi, 55), (ethernet, 25)]),
            Some(ethernet)
        );
        assert_eq!(pick_gateway(Vec::new()), None);
    }

    fn row(destination: &str, prefix_length: u8, next_hop: &str, luid: u64) -> MIB_IPFORWARD_ROW2 {
        let mut row = new_row();
        row.DestinationPrefix.Prefix = sockaddr(destination.parse().unwrap());
        row.DestinationPrefix.PrefixLength = prefix_length;
        row.NextHop = sockaddr(next_hop.parse().unwrap());
        row.InterfaceLuid.Value = luid;
        row
    }

    fn luid(value: u64) -> NET_LUID_LH {
        NET_LUID_LH { Value: value }
    }

    #[test]
    fn a_pinned_route_matches_only_on_its_interface() {
        let ours = row("0.0.0.0", 1, "0.0.0.0", 7);
        let any = "0.0.0.0".parse().unwrap();
        assert!(matches(&ours, any, 1, any, Some(luid(7))));
        assert!(!matches(&ours, any, 1, any, Some(luid(8))));
        assert!(
            !matches(&ours, any, 0, any, Some(luid(7))),
            "a /0 is not a /1"
        );
    }

    /// An exclusion is found by its next hop wherever it now lives: the
    /// interface it left from may have gone.
    #[test]
    fn a_gateway_route_matches_on_any_interface() {
        let exclusion = row("203.0.113.9", 32, "192.168.1.1", 3);
        let destination = "203.0.113.9".parse().unwrap();
        assert!(matches(
            &exclusion,
            destination,
            32,
            "192.168.1.1".parse().unwrap(),
            None
        ));
        assert!(!matches(
            &exclusion,
            destination,
            32,
            "192.168.1.254".parse().unwrap(),
            None
        ));
    }

    /// The table can be read unprivileged; on any machine with a network
    /// there is at least the loopback's own routes.
    #[test]
    fn the_routing_table_reads() {
        assert!(!forward_table(AF_INET).expect("readable").is_empty());
        loopback_luid().expect("every Windows has a loopback interface");
    }
}
