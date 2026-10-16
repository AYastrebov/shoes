//! A config survives being written back out (plan PR 1.4).
//!
//! Generated documents are parsed, serialized, and parsed again; the two
//! parses must agree. They are compared through `Debug`, which every config
//! type derives, rather than `PartialEq`, which most do not: a field the
//! serializer drops, renames, or writes in a form the parser reads
//! differently shows up as a difference either way.
//!
//! The generators cover the shapes most configs use -- the common inbounds,
//! rules with every action shape, and inline outbound chains through the
//! common outbounds -- with the newtypes this PR series introduced.

use base64::Engine;
use proptest::prelude::*;

use super::Config;

/// Quoted: a bare `0` or `true` would be a YAML number or boolean.
fn password() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9]{1,16}".prop_map(|p| format!("\"{p}\""))
}

fn port() -> impl Strategy<Value = u16> {
    1u16..=65535
}

fn ipv4() -> impl Strategy<Value = String> {
    (1u8..=223, any::<u8>(), any::<u8>(), 1u8..=254)
        .prop_map(|(a, b, c, d)| format!("{a}.{b}.{c}.{d}"))
}

fn uuid() -> impl Strategy<Value = String> {
    any::<[u8; 16]>().prop_map(|mut b| {
        b[6] = (b[6] & 0x0f) | 0x40;
        b[8] = (b[8] & 0x3f) | 0x80;
        let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
        format!(
            "{}-{}-{}-{}-{}",
            &hex[0..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..32]
        )
    })
}

fn key(len: usize) -> impl Strategy<Value = String> {
    proptest::collection::vec(any::<u8>(), len)
        .prop_map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes))
}

/// `cipher: ...` and `password: ...` lines for a Shadowsocks block.
fn shadowsocks_fields() -> impl Strategy<Value = String> {
    prop_oneof![
        (
            prop_oneof![
                Just("aes-128-gcm"),
                Just("aes-256-gcm"),
                Just("chacha20-ietf-poly1305")
            ],
            password()
        )
            .prop_map(|(c, p)| format!("cipher: {c}\npassword: {p}\n")),
        key(16).prop_map(|k| format!("cipher: 2022-blake3-aes-128-gcm\npassword: \"{k}\"\n")),
        key(32).prop_map(|k| format!("cipher: 2022-blake3-aes-256-gcm\npassword: \"{k}\"\n")),
    ]
}

/// An outbound `protocol:` block's body.
fn client_protocol() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("type: direct\n".to_string()),
        proptest::option::of((password(), password())).prop_map(|creds| match creds {
            Some((u, p)) => format!("type: socks\nusername: {u}\npassword: {p}\n"),
            None => "type: socks\n".to_string(),
        }),
        shadowsocks_fields().prop_map(|f| format!("type: shadowsocks\n{f}")),
        (uuid(), any::<bool>())
            .prop_map(|(id, udp)| format!("type: vless\nuser_id: {id}\nudp_enabled: {udp}\n")),
        (
            prop_oneof![Just("aes-128-gcm"), Just("chacha20-poly1305")],
            uuid()
        )
            .prop_map(|(c, id)| format!("type: vmess\ncipher: {c}\nuser_id: {id}\n")),
        password().prop_map(|p| format!("type: trojan\npassword: {p}\n")),
        (
            key(32),
            key(32),
            proptest::option::of(key(32)),
            ipv4(),
            0u8..=32
        )
            .prop_map(|(private, public, psk, local, len)| {
                let psk = psk.map(|k| format!("preshared_key: \"{k}\"\n")).unwrap_or_default();
                format!(
                    "type: wireguard\nprivate_key: \"{private}\"\npeer_public_key: \"{public}\"\n\
                     {psk}local_addresses: {local}/{len}\nallowed_ips: 0.0.0.0/0\n"
                )
            }),
        (password(), 20000u16..30000, 1u16..100, proptest::option::of(5_000u64..60_000))
            .prop_map(|(p, start, span, interval)| {
                let interval = interval
                    .map(|ms| format!("  interval_ms: {ms}\n"))
                    .unwrap_or_default();
                format!(
                    "type: hysteria2\npassword: {p}\nport_hopping:\n  ports: {start}-{}\n{interval}",
                    start + span
                )
            }),
    ]
}

fn indent(text: &str, spaces: usize) -> String {
    let pad = " ".repeat(spaces);
    text.lines().map(|line| format!("{pad}{line}\n")).collect()
}

/// One rule: block, allow, or allow through an inline outbound.
fn rule() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("- masks: 10.0.0.0/8\n  action: block\n".to_string()),
        Just("- masks: 0.0.0.0/0\n  action: allow\n".to_string()),
        (ipv4(), port()).prop_map(|(ip, p)| format!(
            "- masks: 0.0.0.0/0\n  action: allow\n  override_address: {ip}:{p}\n"
        )),
        (ipv4(), port(), client_protocol()).prop_map(|(ip, p, proto)| format!(
            "- masks: 0.0.0.0/0\n  action: allow\n  client_chain:\n    address: {ip}:{p}\n    \
             protocol:\n{}",
            indent(&proto, 6)
        )),
    ]
}

/// An inbound `protocol:` block's body.
fn server_protocol() -> impl Strategy<Value = String> {
    prop_oneof![
        any::<bool>().prop_map(|udp| format!("type: socks\nudp_enabled: {udp}\n")),
        (password(), password())
            .prop_map(|(u, p)| format!("type: http\nusername: {u}\npassword: {p}\n")),
        Just("type: mixed\n".to_string()),
        shadowsocks_fields().prop_map(|f| format!("type: shadowsocks\n{f}")),
        uuid().prop_map(|id| format!("type: vless\nuser_id: {id}\n")),
        uuid().prop_map(|id| format!("type: vmess\ncipher: aes-128-gcm\nuser_id: {id}\n")),
        password().prop_map(|p| format!("type: trojan\npassword: {p}\n")),
    ]
}

fn server_entry() -> impl Strategy<Value = String> {
    (
        port(),
        server_protocol(),
        proptest::collection::vec(rule(), 0..3),
    )
        .prop_map(|(p, proto, rules)| {
            let rules = if rules.is_empty() {
                String::new()
            } else {
                format!("  rules:\n{}", indent(&rules.concat(), 4))
            };
            format!(
                "- address: 127.0.0.1:{p}\n  protocol:\n{}{rules}",
                indent(&proto, 4)
            )
        })
}

fn client_group() -> impl Strategy<Value = String> {
    (ipv4(), port(), client_protocol()).prop_map(|(ip, p, proto)| {
        format!(
            "- client_group: out\n  client_proxies:\n    - address: {ip}:{p}\n      protocol:\n{}",
            indent(&proto, 8)
        )
    })
}

fn document() -> impl Strategy<Value = String> {
    (
        proptest::collection::vec(server_entry(), 1..3),
        proptest::option::of(client_group()),
    )
        .prop_map(|(servers, group)| format!("{}{}", group.unwrap_or_default(), servers.concat()))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn a_config_survives_being_written_back(yaml in document()) {
        let first: Vec<Config> = serde_yaml::from_str(&yaml)
            .map_err(|e| TestCaseError::fail(format!("generated YAML did not parse: {e}\n{yaml}")))?;
        let written = serde_yaml::to_string(&first).unwrap();
        let second: Vec<Config> = serde_yaml::from_str(&written)
            .map_err(|e| TestCaseError::fail(format!("written YAML did not parse: {e}\n{written}")))?;
        prop_assert_eq!(format!("{first:?}"), format!("{second:?}"), "\n{}\n---\n{}", yaml, written);
        // And writing is stable: the second write is the first.
        prop_assert_eq!(serde_yaml::to_string(&second).unwrap(), written);
    }
}
