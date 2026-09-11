//! Prometheus text exposition.
//!
//! Not a Clash route: a VPS operator wants bytes per listener over time, and
//! Prometheus is what they already scrape everything else with. Every family
//! here reads a counter that is O(1) or O(configured items); nothing scans
//! the connection table. See the spec, "Metrics".

use std::fmt::Write as _;

use crate::connection_registry as conns;

/// Escape a label value per the exposition format: backslash, quote and
/// newline. Labels here are config values -- a bind address, an outbound's
/// name -- never anything a client sends, but a config can hold a quote.
fn escape(label: &str) -> String {
    label
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

pub fn render() -> String {
    let mut out = String::with_capacity(2048);
    let totals = conns::totals();

    let _ = writeln!(
        out,
        "# HELP shoes_build_info Build metadata.\n\
         # TYPE shoes_build_info gauge\n\
         shoes_build_info{{version=\"{}\"}} 1",
        env!("CARGO_PKG_VERSION")
    );
    let _ = writeln!(
        out,
        "# HELP shoes_connections_active Tracked connections open now.\n\
         # TYPE shoes_connections_active gauge\n\
         shoes_connections_active {}",
        totals.active
    );
    let _ = writeln!(
        out,
        "# HELP shoes_connections_total Connections tracked since start.\n\
         # TYPE shoes_connections_total counter\n\
         shoes_connections_total {}",
        totals.total
    );
    let _ = writeln!(
        out,
        "# HELP shoes_connections_untracked_total Connections served past the tracking cap.\n\
         # TYPE shoes_connections_untracked_total counter\n\
         shoes_connections_untracked_total {}",
        totals.untracked
    );
    let _ = writeln!(
        out,
        "# HELP shoes_bytes_total Bytes at the client edge. A connection's bytes are folded in when it closes; bytes of live connections are included.\n\
         # TYPE shoes_bytes_total counter\n\
         shoes_bytes_total{{direction=\"up\"}} {}\n\
         shoes_bytes_total{{direction=\"down\"}} {}",
        totals.up, totals.down
    );

    let inbounds = conns::inbound_stats();
    let _ = writeln!(
        out,
        "# HELP shoes_inbound_connections_active Connections open now, per listener.\n\
         # TYPE shoes_inbound_connections_active gauge"
    );
    for i in &inbounds {
        let _ = writeln!(
            out,
            "shoes_inbound_connections_active{{inbound=\"{}\"}} {}",
            escape(i.inbound),
            i.active
        );
    }
    let _ = writeln!(
        out,
        "# HELP shoes_inbound_connections_total Connections accepted since start, per listener.\n\
         # TYPE shoes_inbound_connections_total counter"
    );
    for i in &inbounds {
        let _ = writeln!(
            out,
            "shoes_inbound_connections_total{{inbound=\"{}\"}} {}",
            escape(i.inbound),
            i.total
        );
    }
    let _ = writeln!(
        out,
        "# HELP shoes_inbound_bytes_total Bytes per listener, folded in when a connection closes.\n\
         # TYPE shoes_inbound_bytes_total counter"
    );
    for i in &inbounds {
        let _ = writeln!(
            out,
            "shoes_inbound_bytes_total{{inbound=\"{}\",direction=\"up\"}} {}\n\
             shoes_inbound_bytes_total{{inbound=\"{}\",direction=\"down\"}} {}",
            escape(i.inbound),
            i.up,
            escape(i.inbound),
            i.down
        );
    }

    let outbounds = crate::outbound_stats::snapshot_all();
    let _ = writeln!(
        out,
        "# HELP shoes_outbound_connections_active Streams open now, per outbound.\n\
         # TYPE shoes_outbound_connections_active gauge"
    );
    for o in &outbounds {
        let _ = writeln!(
            out,
            "shoes_outbound_connections_active{{outbound=\"{}\"}} {}",
            escape(&o.name),
            o.active_connections
        );
    }
    let _ = writeln!(
        out,
        "# HELP shoes_outbound_bytes_total Bytes measured at the outbound, which differs from the client edge by the handshake.\n\
         # TYPE shoes_outbound_bytes_total counter"
    );
    for o in &outbounds {
        let _ = writeln!(
            out,
            "shoes_outbound_bytes_total{{outbound=\"{}\",direction=\"up\"}} {}\n\
             shoes_outbound_bytes_total{{outbound=\"{}\",direction=\"down\"}} {}",
            escape(&o.name),
            o.upload_bytes,
            escape(&o.name),
            o.download_bytes
        );
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_values_are_escaped() {
        assert_eq!(escape("a\"b\\c"), "a\\\"b\\\\c");
        assert_eq!(escape("one\ntwo"), "one\\ntwo");
    }

    /// Every line is either a comment or a sample with a value: a scrape
    /// that hits a malformed line drops the whole body.
    #[test]
    fn the_exposition_parses_as_samples_and_comments() {
        let body = render();
        for line in body.lines().filter(|l| !l.is_empty()) {
            if line.starts_with('#') {
                continue;
            }
            let (name, value) = line.rsplit_once(' ').unwrap_or_else(|| panic!("{line}"));
            assert!(name.starts_with("shoes_"), "{line}");
            assert!(
                value.parse::<f64>().is_ok(),
                "a sample needs a numeric value: {line}"
            );
        }
    }
}
