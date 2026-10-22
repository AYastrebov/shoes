//! Domain patterns that must resolve for real.
//!
//! A fake address is useless to anything that needs to reach the host outside
//! the tunnel, or that compares the answer against something: captive-portal
//! probes, NTP, STUN, and `.local`/`.lan` names the tunnel does not carry.

/// Suffixes of names that only mean something on the local network, matched
/// as the name itself or any name under it (SF-3). Built in, ahead of the
/// user's patterns, unless `bypass_defaults: false`.
///
/// `local` is mDNS (RFC 6762), `home.arpa` the home-network zone (RFC 8375),
/// `internal` ICANN's 2024 private-use reservation, and the reverse zones are
/// what a local resolver answers PTR-style questions from. `lan`, `home` and
/// `localdomain` are unregistered but what home routers and DHCP hand out.
///
/// Bypassing only stops a fake address being made up: the query is forwarded
/// like any other, along the rules for the resolver it was sent to. Reaching
/// the LAN takes a direct rule for its ranges, which carries the query to
/// the router and the connection after it alike.
const LOCAL_SUFFIXES: &[&str] = &[
    "local",
    "lan",
    "home.arpa",
    "internal",
    "localhost",
    "localdomain",
    "home",
    "in-addr.arpa",
    "ip6.arpa",
];

/// A compiled list of glob patterns matched against query names.
///
/// Patterns are lowercased at construction and matched case-insensitively, as
/// DNS names are. `*` matches any run of characters, including dots, so
/// `*.local` matches `printer.local` and `time.*.apple.com` matches
/// `time.euro.apple.com`.
#[derive(Debug, Default, Clone)]
pub struct BypassList {
    patterns: Vec<Pattern>,
    /// Whether single-label names and [`LOCAL_SUFFIXES`] match too.
    local_names: bool,
}

#[derive(Debug, Clone)]
enum Pattern {
    /// No wildcard: compare the whole name.
    Exact(String),
    /// Wildcard: the literal runs between `*`s, in order.
    Glob {
        /// Text before the first `*`, empty if the pattern starts with one.
        prefix: String,
        /// Literals between wildcards, in order.
        middles: Vec<String>,
        /// Text after the last `*`, empty if the pattern ends with one.
        suffix: String,
    },
}

impl BypassList {
    /// `patterns` are the user's; `local_names` adds the built-in local
    /// names in front of them.
    pub fn new<I, S>(patterns: I, local_names: bool) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let patterns = patterns
            .into_iter()
            .filter_map(|p| Pattern::compile(p.as_ref()))
            .collect();
        Self {
            patterns,
            local_names,
        }
    }

    /// True if `domain` should skip fake IP and be resolved for real.
    ///
    /// `domain` is expected already normalized: lowercase, no trailing dot.
    pub fn matches(&self, domain: &str) -> bool {
        (self.local_names && is_local_name(domain))
            || self.patterns.iter().any(|p| p.matches(domain))
    }
}

/// A single-label name, or one at or under a [`LOCAL_SUFFIXES`] entry.
fn is_local_name(domain: &str) -> bool {
    !domain.contains('.')
        || LOCAL_SUFFIXES.iter().any(|suffix| {
            domain == *suffix
                || domain
                    .strip_suffix(suffix)
                    .is_some_and(|rest| rest.ends_with('.'))
        })
}

impl Pattern {
    fn compile(raw: &str) -> Option<Self> {
        let raw = raw.trim().trim_end_matches('.').to_ascii_lowercase();
        if raw.is_empty() {
            return None;
        }

        if !raw.contains('*') {
            return Some(Pattern::Exact(raw));
        }

        // "a*b*c" -> prefix "a", middles ["b"], suffix "c".
        // A leading or trailing `*` yields an empty prefix or suffix, which
        // matches anything, so no special case is needed for them.
        let mut parts = raw.split('*');
        let prefix = parts.next().unwrap_or_default().to_string();
        let mut rest: Vec<String> = parts.map(str::to_string).collect();
        let suffix = rest.pop().unwrap_or_default();
        let middles = rest.into_iter().filter(|m| !m.is_empty()).collect();

        Some(Pattern::Glob {
            prefix,
            middles,
            suffix,
        })
    }

    fn matches(&self, domain: &str) -> bool {
        match self {
            Pattern::Exact(pattern) => pattern == domain,
            Pattern::Glob {
                prefix,
                middles,
                suffix,
            } => {
                let Some(mut rest) = domain.strip_prefix(prefix.as_str()) else {
                    return false;
                };

                // Each middle must appear after the previous one. Leftmost
                // match is sufficient: the literals cannot overlap, so an
                // earlier match never rules out a later one.
                for middle in middles {
                    match rest.find(middle.as_str()) {
                        Some(idx) => rest = &rest[idx + middle.len()..],
                        None => return false,
                    }
                }

                rest.len() >= suffix.len() && rest.ends_with(suffix.as_str())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_list_matches_nothing() {
        let list = BypassList::new(Vec::<String>::new(), false);
        assert!(!list.matches("example.com"));
    }

    #[test]
    fn exact_pattern_matches_only_itself() {
        let list = BypassList::new(["captive.apple.com"], false);
        assert!(list.matches("captive.apple.com"));
        assert!(!list.matches("apple.com"));
        assert!(!list.matches("evil-captive.apple.com"));
        assert!(!list.matches("captive.apple.com.evil.test"));
    }

    #[test]
    fn leading_wildcard_matches_any_subdomain() {
        let list = BypassList::new(["*.local"], false);
        assert!(list.matches("printer.local"));
        assert!(list.matches("a.b.c.local"));
        assert!(!list.matches("local"));
        assert!(!list.matches("notlocal"));
        assert!(!list.matches("printer.local.example.com"));
    }

    #[test]
    fn middle_wildcard_matches_between_literals() {
        let list = BypassList::new(["time.*.apple.com"], false);
        assert!(list.matches("time.euro.apple.com"));
        assert!(list.matches("time.a.b.apple.com"));
        assert!(!list.matches("time.apple.com.evil.test"));
        assert!(!list.matches("nottime.euro.apple.com"));
    }

    #[test]
    fn trailing_wildcard_matches_any_suffix() {
        let list = BypassList::new(["internal.*"], false);
        assert!(list.matches("internal.example.com"));
        assert!(list.matches("internal."));
        assert!(!list.matches("an.internal.example.com"));
    }

    #[test]
    fn matching_is_case_insensitive_and_dot_insensitive() {
        let list = BypassList::new(["*.LOCAL.", "Captive.Apple.Com"], false);
        assert!(list.matches("printer.local"));
        assert!(list.matches("captive.apple.com"));
    }

    #[test]
    fn blank_patterns_are_dropped() {
        let list = BypassList::new(["", "   ", "."], false);
        assert!(!list.matches(""));
        assert!(!list.matches("example.com"));
    }

    #[test]
    fn bare_wildcard_matches_everything() {
        let list = BypassList::new(["*"], false);
        assert!(list.matches("example.com"));
        assert!(list.matches("a"));
    }

    #[test]
    fn local_names_match_with_the_defaults_on() {
        let list = BypassList::new(Vec::<String>::new(), true);
        for name in [
            "printer",
            "nas.lan",
            "_ipp._tcp.local",
            "router.home.arpa",
            "db.internal",
            "app.localhost",
            "host.localdomain",
            "box.home",
            "1.0.168.192.in-addr.arpa",
            "b.a.9.8.ip6.arpa",
            "lan",
        ] {
            assert!(list.matches(name), "{name}");
        }
        // A suffix matches on a label boundary only.
        for name in [
            "example.com",
            "notlocal.com",
            "local.example.com",
            "evillan.com",
        ] {
            assert!(!list.matches(name), "{name}");
        }
    }

    #[test]
    fn local_names_do_not_match_with_the_defaults_off() {
        let list = BypassList::new(Vec::<String>::new(), false);
        for name in ["printer", "nas.lan", "_ipp._tcp.local", "router.home.arpa"] {
            assert!(!list.matches(name), "{name}");
        }
    }

    #[test]
    fn user_patterns_still_match_with_the_defaults_on() {
        let list = BypassList::new(["captive.apple.com"], true);
        assert!(list.matches("captive.apple.com"));
        assert!(list.matches("nas.lan"));
        assert!(!list.matches("example.com"));
    }

    #[test]
    fn any_matching_pattern_wins() {
        let list = BypassList::new(["*.local", "captive.apple.com", "*.pool.ntp.org"], false);
        assert!(list.matches("0.pool.ntp.org"));
        assert!(list.matches("printer.local"));
        assert!(!list.matches("example.com"));
    }
}
