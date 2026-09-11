//! The JSON shapes mihomo serves, rendered from shoes' registries.
//!
//! Every key here is one a dashboard reads; the tests deserialise these into
//! structs written from mihomo's schema, so a renamed key fails a build
//! rather than a panel in production. See the spec, "The proxy model",
//! "Rules" and "The endpoint table".

use serde_json::{Value, json};

use crate::connection_registry as conns;
use crate::outbound_stats;

pub fn hello() -> Value {
    json!({ "hello": "shoes" })
}

/// `meta: true` is what a dashboard tests to enable the richer UI, and
/// what awg-manager's health probe reads the version out of.
pub fn version() -> Value {
    json!({ "version": env!("CARGO_PKG_VERSION"), "meta": true })
}

pub fn configs(state: &super::ApiState) -> Value {
    let level = match log::max_level() {
        log::LevelFilter::Off => "silent",
        log::LevelFilter::Error => "error",
        log::LevelFilter::Warn => "warning",
        log::LevelFilter::Info => "info",
        log::LevelFilter::Debug | log::LevelFilter::Trace => "debug",
    };
    json!({
        "port": state.ports.http,
        "socks-port": state.ports.socks,
        "mixed-port": state.ports.mixed,
        "redir-port": 0,
        "tproxy-port": 0,
        "allow-lan": true,
        "bind-address": "*",
        "mode": "rule",
        "log-level": level,
        "ipv6": true,
        "tun": { "enable": state.ports.tun },
    })
}

/// mihomo's spelling for a shoes protocol name.
///
/// A dashboard displays this verbatim and switches only on the group types,
/// so an unmapped protocol passes through under its own name rather than
/// being forced into a wrong one.
fn clash_type(protocol: &str) -> &str {
    match protocol {
        "HTTP" => "Http",
        "SOCKS5" => "Socks5",
        // Reality carries VLESS; a dashboard has no Reality type.
        "VLESS" | "Reality" => "Vless",
        "VMess" => "Vmess",
        "TUIC" => "Tuic",
        "mieru" => "Mieru",
        other => other,
    }
}

fn leaf(
    detail: &outbound_stats::OutboundDetail,
    stats: Option<&outbound_stats::OutboundStats>,
) -> Value {
    json!({
        "name": detail.name,
        "type": clash_type(&detail.protocol),
        "udp": detail.udp,
        // True until something measures: a dashboard greys out a dead proxy,
        // and the pessimistic lie would hide working servers.
        "alive": true,
        "history": [],
        "extra": {},
        "upload": stats.map(|s| s.upload_bytes).unwrap_or(0),
        "download": stats.map(|s| s.download_bytes).unwrap_or(0),
    })
}

fn group(name: &str, group_type: &str, now: &str, members: &[String], udp: bool) -> Value {
    json!({
        "name": name,
        "type": group_type,
        "now": now,
        "all": members,
        "udp": udp,
        "history": [],
        "alive": true,
    })
}

/// `GET /proxies` (leaves and groups) or `GET /group` (groups only).
pub fn proxies(groups_only: bool) -> Value {
    let details = outbound_stats::details();
    let stats = outbound_stats::snapshot_all();

    let mut map = serde_json::Map::new();
    if !groups_only {
        for detail in &details {
            let s = stats.iter().find(|s| s.name == detail.name);
            map.insert(detail.name.clone(), leaf(detail, s));
        }
    }

    for g in outbound_stats::groups() {
        // A round-robin group is a LoadBalance in Clash terms, and has no
        // chosen member to report.
        let udp = g.members.iter().all(|m| {
            details
                .iter()
                .find(|d| d.name == *m)
                .map(|d| d.udp)
                .unwrap_or(true)
        });
        map.insert(
            g.name.clone(),
            group(&g.name, "LoadBalance", "", &g.members, udp),
        );
    }

    // Synthetic: every dashboard assumes GLOBAL exists and uses it as the
    // picker in Global mode. Writing to it is refused until selection means
    // something.
    let leaves: Vec<String> = details.iter().map(|d| d.name.clone()).collect();
    let now = leaves.first().cloned().unwrap_or_default();
    map.insert(
        "GLOBAL".to_string(),
        group("GLOBAL", "Selector", &now, &leaves, true),
    );

    json!({ "proxies": map })
}

pub fn proxy(name: &str) -> Option<Value> {
    proxies(false)["proxies"].get(name).cloned()
}

/// Every listener's rules, in the order the listeners were started.
///
/// mihomo has one list because it has one router; shoes has one per
/// listener, and a controller that showed only the first would hide the
/// rules half the traffic is matched against.
pub fn rules() -> Value {
    let lists = conns::rule_lists();
    let rules: Vec<Value> = lists
        .iter()
        .flat_map(|list| list.iter())
        .map(|r| {
            json!({
                "type": r.rule_type,
                "payload": r.payload,
                "proxy": r.proxy,
                // mihomo reports a rule-set's size here; -1 is its "not a
                // counted set".
                "size": -1,
            })
        })
        .collect();
    json!({ "rules": rules })
}

/// RFC 3339 in UTC, which is what a dashboard puts through `new Date()`.
///
/// Hand-rolled rather than a date crate: this is the only place in the tree
/// that formats a calendar date, and the civil-from-days arithmetic is
/// Howard Hinnant's, which is exact for every day this will ever see.
fn rfc3339(t: std::time::SystemTime) -> String {
    let secs = t
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let (hour, minute, second) = ((secs % 86_400) / 3600, (secs % 3600) / 60, secs % 60);

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

pub fn connection(c: &conns::ConnectionSnapshot) -> Value {
    // The exit first, then the group it came from: awg-manager credits every
    // tag in this list, and a dashboard shows the first.
    let chains: Vec<&str> = c
        .chain
        .iter()
        .chain(c.group.iter())
        .map(String::as_str)
        .collect();

    let (rule, payload) = match &c.rule_summary {
        Some(s) => (s.rule_type.to_string(), s.payload.clone()),
        None => ("Match".to_string(), String::new()),
    };

    // A hostname when one is known, sniffed or requested; the address field
    // stays empty unless the destination really was an address.
    let host = c
        .sniffed_host
        .clone()
        .or_else(|| {
            c.destination_host
                .clone()
                .filter(|h| h.parse::<std::net::IpAddr>().is_err())
        })
        .unwrap_or_default();
    let destination_ip = c
        .destination_host
        .clone()
        .filter(|h| h.parse::<std::net::IpAddr>().is_ok())
        .unwrap_or_default();

    json!({
        "id": c.id.to_string(),
        "metadata": {
            "network": c.network.as_str(),
            // The protocol half of the label; the whole label is beside it.
            "type": c.inbound.split('@').next().unwrap_or(c.inbound),
            "sourceIP": c.source.ip().to_string(),
            "sourcePort": c.source.port().to_string(),
            "destinationIP": destination_ip,
            "destinationPort": c.destination_port.to_string(),
            "host": host,
            "dnsMode": "normal",
            "processPath": "",
            "specialProxy": "",
            "inboundName": c.inbound,
        },
        "upload": c.up,
        "download": c.down,
        "start": rfc3339(c.started),
        "chains": chains,
        "rule": rule,
        "rulePayload": payload,
    })
}

pub fn connections() -> Value {
    let totals = conns::totals();
    json!({
        "downloadTotal": totals.down,
        "uploadTotal": totals.up,
        "connections": conns::snapshot().iter().map(connection).collect::<Vec<_>>(),
        "memory": super::memory::rss(),
        // Not a Clash field: connections served past the tracking cap, so
        // the omission is visible rather than silent.
        "untracked": totals.untracked,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_epoch_and_a_known_date_render_as_rfc3339() {
        assert_eq!(rfc3339(std::time::UNIX_EPOCH), "1970-01-01T00:00:00Z");
        // 2026-09-11T12:00:00Z
        let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_789_128_000);
        assert_eq!(rfc3339(t), "2026-09-11T12:00:00Z");
        // A leap day, which the month arithmetic is the easiest to get wrong on.
        let leap = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_709_208_000);
        assert_eq!(leap, leap);
        assert!(rfc3339(leap).starts_with("2024-02-29"), "{}", rfc3339(leap));
    }

    #[test]
    fn protocol_names_map_onto_the_spellings_a_dashboard_knows() {
        assert_eq!(clash_type("SOCKS5"), "Socks5");
        assert_eq!(clash_type("Reality"), "Vless", "Reality carries VLESS");
        assert_eq!(
            clash_type("Hysteria2"),
            "Hysteria2",
            "unmapped passes through"
        );
    }
}
