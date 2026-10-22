//! Decoding assertions against rule-sets published by sing-box.
//!
//! These files are the format's specification in practice. A decoder for a
//! reverse-engineered binary format without real inputs is not meaningfully
//! tested, so about 255 KB of fixtures is a deliberate trade.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "predates the lint; see the [lints] note in Cargo.toml"
)]

use std::net::Ipv4Addr;
use std::path::PathBuf;

use shoes::rule_set::{MatchTarget, RuleSet, normalize_domain};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/rule_sets")
        .join(name)
}

fn load(name: &str) -> std::sync::Arc<RuleSet> {
    RuleSet::load(name, &fixture(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn domain_target(domain: &str) -> MatchTarget<'_> {
    MatchTarget {
        domain: Some(domain),
        ip: None,
    }
}

fn ip_target(a: u8, b: u8, c: u8, d: u8) -> MatchTarget<'static> {
    MatchTarget {
        domain: None,
        ip: Some(u128::from(Ipv4Addr::new(a, b, c, d).to_ipv6_mapped())),
    }
}

#[test]
fn every_published_fixture_decodes() {
    for name in [
        "geosite-google.srs",
        "geosite-telegram.srs",
        "geosite-cloudflare.srs",
        "geosite-category-ads-all.srs",
        "geoip-ru.srs",
        "geoip-us.srs",
    ] {
        load(name);
    }
}

#[test]
fn geosite_google_matches_google_domains() {
    // This set carries a domain trie and two domain_regex patterns. If the two
    // were ANDed instead of ORed, almost none of this would match.
    let set = load("geosite-google.srs");
    assert!(set.matches(&domain_target("google.com")));
    assert!(set.matches(&domain_target("www.google.com")));
    assert!(!set.matches(&domain_target("example.invalid")));
}

#[test]
fn geosite_telegram_matches_telegram_domains() {
    let set = load("geosite-telegram.srs");
    assert!(set.matches(&domain_target("telegram.org")));
    assert!(set.matches(&domain_target("api.telegram.org")));
    assert!(!set.matches(&domain_target("telegram.org.example.invalid")));
}

#[test]
fn matching_is_case_insensitive_after_normalisation() {
    let set = load("geosite-cloudflare.srs");
    let normalised = normalize_domain("CLOUDFLARE.COM.");
    assert!(set.matches(&domain_target(normalised.as_ref())));
}

#[test]
fn geoip_ru_matches_a_russian_address_and_not_a_us_one() {
    let set = load("geoip-ru.srs");
    // Yandex, allocated in RU.
    assert!(set.matches(&ip_target(77, 88, 8, 8)));
    // Google Public DNS, allocated in US.
    assert!(!set.matches(&ip_target(8, 8, 8, 8)));
}

#[test]
fn geoip_us_matches_a_us_address() {
    let set = load("geoip-us.srs");
    assert!(set.matches(&ip_target(8, 8, 8, 8)));
    assert!(!set.matches(&ip_target(77, 88, 8, 8)));
}

#[test]
fn a_domain_set_does_not_match_on_ip_alone() {
    let set = load("geosite-google.srs");
    assert!(!set.matches(&ip_target(8, 8, 8, 8)));
}

#[test]
fn an_ip_set_does_not_match_on_domain_alone() {
    let set = load("geoip-ru.srs");
    assert!(!set.matches(&domain_target("yandex.ru")));
}

/// sing-box writes IPv4 ranges as 4-byte addresses ahead of IPv6 ones, while
/// shoes maps IPv4 into `::ffff:0:0/96`, above `::1` and `64:ff9b::/96`. A set
/// mixing the two must still load, and match on both sides.
/// Source: `mixed-v4-v6.json`, compiled by `regenerate-mixed-v4-v6.sh`.
#[test]
fn a_set_mixing_ipv4_with_low_ipv6_ranges_loads_and_matches() {
    let set = load("mixed-v4-v6.srs");
    assert!(set.matches(&ip_target(10, 1, 2, 3)));
    assert!(set.matches(&ip_target(192, 168, 7, 7)));
    assert!(!set.matches(&ip_target(8, 8, 8, 8)));

    let v6 = |ip: &str| MatchTarget {
        domain: None,
        ip: Some(u128::from(ip.parse::<std::net::Ipv6Addr>().unwrap())),
    };
    assert!(set.matches(&v6("::1")));
    assert!(set.matches(&v6("64:ff9b::808:808")));
    assert!(!set.matches(&v6("::2")));
}

/// sing-box's own verdicts (`tests/data/rule_sets/oracle.json`, written by
/// `record-oracle.py` from `sing-box rule-set match`). A matcher checked only
/// against expectations written by hand shares its author's misreadings.
fn oracle() -> serde_json::Value {
    let text = std::fs::read_to_string(fixture("oracle.json")).unwrap();
    serde_json::from_str(&text).unwrap()
}

fn oracle_target(text: &str) -> MatchTarget<'_> {
    match text.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => MatchTarget {
            domain: None,
            ip: Some(u128::from(v4.to_ipv6_mapped())),
        },
        Ok(std::net::IpAddr::V6(v6)) => MatchTarget {
            domain: None,
            ip: Some(u128::from(v6)),
        },
        Err(_) => domain_target(text),
    }
}

#[test]
fn every_match_agrees_with_sing_box() {
    let oracle = oracle();
    let cases = oracle["cases"].as_array().unwrap();
    assert!(cases.len() >= 30, "the oracle lost its cases");
    let mut disagreements = Vec::new();
    for case in cases {
        let file = case["file"].as_str().unwrap();
        let target = case["target"].as_str().unwrap();
        let expected = case["matched"].as_bool().unwrap();
        if load(file).matches(&oracle_target(target)) != expected {
            disagreements.push(format!("{file} {target}: sing-box says {expected}"));
        }
    }
    assert!(disagreements.is_empty(), "{disagreements:#?}");
}

/// Every file sing-box refuses, shoes refuses, with an error rather than a
/// panic. One difference is deliberate: sing-box does not check the zlib
/// trailer, so it loads a file whose Adler-32 is wrong or missing. shoes
/// refuses those, since a short payload would be a quietly wrong matcher
/// (`rule_set/srs.rs`, `inflate`).
#[test]
fn every_corrupt_file_sing_box_refuses_is_refused() {
    let oracle = oracle();
    let corrupt = oracle["corrupt"].as_array().unwrap();
    assert!(corrupt.len() >= 9, "the oracle lost its corruption cases");
    for case in corrupt {
        let file = case["file"].as_str().unwrap();
        let sing_box_loads = case["loads"].as_bool().unwrap();
        let shoes_loads = RuleSet::load(file, &fixture(file)).is_ok();
        let checksum = file.contains("checksum");
        if checksum {
            assert!(sing_box_loads, "{file}: sing-box now checks the trailer");
            assert!(!shoes_loads, "{file}: shoes must refuse a bad trailer");
        } else {
            assert_eq!(shoes_loads, sing_box_loads, "{file}");
        }
    }
}
