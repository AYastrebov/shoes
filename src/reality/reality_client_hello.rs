//! The Reality client's ClientHello, shaped as Chrome 133 sends it.
//!
//! uTLS `HelloChrome_133` (`metacubex/utls@v1.8.7/u_parrots.go:884-955`) is
//! what sing-box and Xray clients send by default, and so what a Reality
//! connection is expected to look like. The spec is
//! `docs/specs/2026-10-19-reality-chrome-client-hello.md`.

use rand::{Rng, RngExt};

/// X25519MLKEM768 (draft-ietf-tls-ecdhe-mlkem).
pub const GROUP_X25519_MLKEM768: u16 = 0x11ec;
pub const GROUP_X25519: u16 = 0x001d;
const GROUP_SECP256R1: u16 = 0x0017;
const GROUP_SECP384R1: u16 = 0x0018;

/// ML-KEM-768 sizes, FIPS 203.
pub const MLKEM768_ENCAPSULATION_KEY_LEN: usize = 1184;
pub const MLKEM768_CIPHERTEXT_LEN: usize = 1088;

/// The TLS 1.2 suites Chrome offers after the three TLS 1.3 ones. Never
/// negotiated here -- the client speaks TLS 1.3 only -- but a list without
/// them is a signature of its own.
const CHROME_TLS12_SUITES: [u16; 12] = [
    0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
];

const EXT_SERVER_NAME: u16 = 0;
const EXT_STATUS_REQUEST: u16 = 5;
const EXT_SUPPORTED_GROUPS: u16 = 10;
const EXT_EC_POINT_FORMATS: u16 = 11;
const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
const EXT_ALPN: u16 = 16;
const EXT_SCT: u16 = 18;
const EXT_EXTENDED_MASTER_SECRET: u16 = 23;
const EXT_COMPRESS_CERTIFICATE: u16 = 27;
const EXT_SESSION_TICKET: u16 = 35;
const EXT_SUPPORTED_VERSIONS: u16 = 43;
const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 45;
const EXT_KEY_SHARE: u16 = 51;
/// application_settings, the codepoint Chrome moved to in 2024.
pub const EXT_APPLICATION_SETTINGS: u16 = 17613;
/// The codepoint before it, which a server could still answer with.
pub const EXT_APPLICATION_SETTINGS_OLD: u16 = 17513;
const EXT_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;
const EXT_RENEGOTIATION_INFO: u16 = 0xff01;

/// The signature schemes the client has always sent, Chrome's eight.
const SIGNATURE_SCHEMES: [u16; 8] = [
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];

/// The GREASE values of one ClientHello (RFC 8701), one per position as
/// BoringSSL draws them: the cipher, the group (supported_groups and
/// key_share share it), the two extensions, and the version.
#[derive(Debug, Clone, Copy)]
struct Grease {
    cipher: u16,
    group: u16,
    extension1: u16,
    extension2: u16,
    version: u16,
}

impl Grease {
    fn draw(rng: &mut impl Rng) -> Self {
        let mut value = || 0x0a0a_u16 | (u16::from(rng.random_range(0..16_u8)) * 0x1010);
        let extension1 = value();
        let mut extension2 = value();
        // BoringSSL keeps the two GREASE extensions distinct; a ClientHello
        // with one extension type twice is malformed.
        if extension2 == extension1 {
            extension2 ^= 0x1010;
        }
        Self {
            cipher: value(),
            group: value(),
            extension1,
            extension2,
            version: value(),
        }
    }
}

/// Whether `value` is one of RFC 8701's sixteen GREASE values.
#[cfg(test)]
fn is_grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a && (value >> 8) == (value & 0xff)
}

/// The key shares one ClientHello carries. The X25519 key is the same in the
/// hybrid share and the standalone one, as in Go's crypto/tls, so whichever
/// the server reads the Reality auth key from, it gets the same one.
pub struct ClientKeyShares<'a> {
    pub x25519_public: &'a [u8; 32],
    pub mlkem768_encapsulation_key: &'a [u8],
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_u16_prefixed(out: &mut Vec<u8>, body: &[u8]) {
    push_u16(out, body.len() as u16);
    out.extend_from_slice(body);
}

fn extension(ext_type: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    push_u16(&mut out, ext_type);
    push_u16_prefixed(&mut out, body);
    out
}

/// A GREASE encrypted_client_hello, as BoringSSL sends when it has no ECH
/// config: outer type, HKDF-SHA256 / AES-128-GCM, random config id and
/// `enc`, and a random payload of a Chrome length plus the AEAD tag.
fn grease_ech(rng: &mut impl Rng) -> Vec<u8> {
    const PAYLOAD_LENS: [usize; 4] = [128, 160, 192, 224];
    const AEAD_TAG_LEN: usize = 16;
    let payload_len = PAYLOAD_LENS[rng.random_range(0..PAYLOAD_LENS.len())] + AEAD_TAG_LEN;

    let mut body = Vec::with_capacity(1 + 4 + 1 + 2 + 32 + 2 + payload_len);
    body.push(0x00); // ClientHelloOuter
    push_u16(&mut body, 0x0001); // HKDF-SHA256
    push_u16(&mut body, 0x0001); // AES-128-GCM
    body.push(rng.random());
    let mut enc = [0u8; 32];
    rng.fill_bytes(&mut enc);
    push_u16_prefixed(&mut body, &enc);
    let mut payload = vec![0u8; payload_len];
    rng.fill_bytes(&mut payload);
    push_u16_prefixed(&mut body, &payload);
    extension(EXT_ENCRYPTED_CLIENT_HELLO, &body)
}

/// Build the ClientHello handshake message (no record header).
///
/// `tls13_suites` replaces Chrome's three TLS 1.3 suites when the config
/// names its own; the TLS 1.2 tail stays, since a short list is itself a
/// signature. The session id sits at offset 39, where Reality expects it.
pub fn construct_chrome_client_hello(
    client_random: &[u8; 32],
    session_id: &[u8; 32],
    keys: &ClientKeyShares<'_>,
    server_name: &str,
    tls13_suites: &[u16],
    alpn_protocols: &[&str],
) -> std::io::Result<Vec<u8>> {
    if keys.mlkem768_encapsulation_key.len() != MLKEM768_ENCAPSULATION_KEY_LEN {
        return Err(std::io::Error::other(
            "ML-KEM-768 encapsulation key has the wrong length",
        ));
    }
    let mut rng = rand::rng();
    let grease = Grease::draw(&mut rng);

    // The extensions between the two GREASE ones, which Chrome shuffles per
    // connection (ShuffleChromeTLSExtensions).
    let mut middle: Vec<Vec<u8>> = Vec::with_capacity(16);
    {
        let name = server_name.as_bytes();
        let mut body = Vec::with_capacity(5 + name.len());
        push_u16(&mut body, (3 + name.len()) as u16);
        body.push(0x00); // host_name
        push_u16_prefixed(&mut body, name);
        middle.push(extension(EXT_SERVER_NAME, &body));
    }
    middle.push(extension(EXT_EXTENDED_MASTER_SECRET, &[]));
    middle.push(extension(EXT_RENEGOTIATION_INFO, &[0x00]));
    {
        let mut groups = Vec::with_capacity(10);
        for group in [
            grease.group,
            GROUP_X25519_MLKEM768,
            GROUP_X25519,
            GROUP_SECP256R1,
            GROUP_SECP384R1,
        ] {
            push_u16(&mut groups, group);
        }
        let mut body = Vec::with_capacity(12);
        push_u16_prefixed(&mut body, &groups);
        middle.push(extension(EXT_SUPPORTED_GROUPS, &body));
    }
    middle.push(extension(EXT_EC_POINT_FORMATS, &[0x01, 0x00]));
    middle.push(extension(EXT_SESSION_TICKET, &[]));
    if !alpn_protocols.is_empty() {
        let mut list = Vec::new();
        for protocol in alpn_protocols {
            list.push(protocol.len() as u8);
            list.extend_from_slice(protocol.as_bytes());
        }
        let mut body = Vec::with_capacity(2 + list.len());
        push_u16_prefixed(&mut body, &list);
        middle.push(extension(EXT_ALPN, &body));
    }
    // OCSP, no responder ids, no request extensions.
    middle.push(extension(EXT_STATUS_REQUEST, &[0x01, 0, 0, 0, 0]));
    {
        let mut schemes = Vec::with_capacity(16);
        for scheme in SIGNATURE_SCHEMES {
            push_u16(&mut schemes, scheme);
        }
        let mut body = Vec::with_capacity(18);
        push_u16_prefixed(&mut body, &schemes);
        middle.push(extension(EXT_SIGNATURE_ALGORITHMS, &body));
    }
    middle.push(extension(EXT_SCT, &[]));
    {
        let mut shares = Vec::with_capacity(5 + 4 + 1216 + 4 + 32);
        push_u16(&mut shares, grease.group);
        push_u16_prefixed(&mut shares, &[0x00]);
        push_u16(&mut shares, GROUP_X25519_MLKEM768);
        push_u16(&mut shares, (MLKEM768_ENCAPSULATION_KEY_LEN + 32) as u16);
        shares.extend_from_slice(keys.mlkem768_encapsulation_key);
        shares.extend_from_slice(keys.x25519_public);
        push_u16(&mut shares, GROUP_X25519);
        push_u16_prefixed(&mut shares, keys.x25519_public);
        let mut body = Vec::with_capacity(2 + shares.len());
        push_u16_prefixed(&mut body, &shares);
        middle.push(extension(EXT_KEY_SHARE, &body));
    }
    middle.push(extension(EXT_PSK_KEY_EXCHANGE_MODES, &[0x01, 0x01])); // psk_dhe_ke
    {
        let mut body = vec![0x06];
        push_u16(&mut body, grease.version);
        body.extend_from_slice(&[0x03, 0x04, 0x03, 0x03]);
        middle.push(extension(EXT_SUPPORTED_VERSIONS, &body));
    }
    middle.push(extension(EXT_COMPRESS_CERTIFICATE, &[0x02, 0x00, 0x02])); // brotli
    {
        // ALPS for h2: the protocol list, as Chrome sends it.
        let mut body = Vec::with_capacity(5);
        push_u16_prefixed(&mut body, b"\x02h2");
        middle.push(extension(EXT_APPLICATION_SETTINGS, &body));
    }
    middle.push(grease_ech(&mut rng));
    shuffle(&mut middle, &mut rng);

    let mut extensions = extension(grease.extension1, &[]);
    for ext in &middle {
        extensions.extend_from_slice(ext);
    }
    extensions.extend_from_slice(&extension(grease.extension2, &[0x00]));

    let mut suites = Vec::with_capacity(2 * (1 + tls13_suites.len() + CHROME_TLS12_SUITES.len()));
    push_u16(&mut suites, grease.cipher);
    for &suite in tls13_suites.iter().chain(CHROME_TLS12_SUITES.iter()) {
        push_u16(&mut suites, suite);
    }

    let mut hello =
        Vec::with_capacity(4 + 2 + 32 + 33 + 2 + suites.len() + 2 + 2 + extensions.len());
    hello.push(0x01); // ClientHello
    hello.extend_from_slice(&[0, 0, 0]); // length, below
    hello.extend_from_slice(&[0x03, 0x03]);
    hello.extend_from_slice(client_random);
    hello.push(32);
    hello.extend_from_slice(session_id);
    push_u16_prefixed(&mut hello, &suites);
    hello.extend_from_slice(&[0x01, 0x00]); // null compression
    push_u16_prefixed(&mut hello, &extensions);

    let body_len = hello.len() - 4;
    hello[1..4].copy_from_slice(&(body_len as u32).to_be_bytes()[1..]);
    Ok(hello)
}

fn shuffle<T>(items: &mut [T], rng: &mut impl Rng) {
    for i in (1..items.len()).rev() {
        let j = rng.random_range(0..=i);
        items.swap(i, j);
    }
}

/// The record that carries it. Chrome, like crypto/tls and uTLS, labels the
/// first ClientHello record TLS 1.0 for middlebox compatibility.
pub fn client_hello_record(hello: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(5 + hello.len());
    record.push(0x16);
    record.extend_from_slice(&[0x03, 0x01]);
    push_u16_prefixed(&mut record, hello);
    record
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Parsed {
        suites: Vec<u16>,
        session_id_offset_ok: bool,
        extensions: Vec<(u16, Vec<u8>)>,
    }

    fn parse(hello: &[u8]) -> Parsed {
        let mut at = 4 + 2 + 32;
        assert_eq!(hello[at], 32);
        let session_id_offset_ok = at + 1 == 39;
        at += 1 + 32;
        let suites_len = u16::from_be_bytes([hello[at], hello[at + 1]]) as usize;
        at += 2;
        let suites = hello[at..at + suites_len]
            .chunks(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        at += suites_len;
        assert_eq!(&hello[at..at + 2], &[0x01, 0x00]);
        at += 2;
        let ext_len = u16::from_be_bytes([hello[at], hello[at + 1]]) as usize;
        at += 2;
        assert_eq!(at + ext_len, hello.len());
        let mut extensions = Vec::new();
        while at < hello.len() {
            let ty = u16::from_be_bytes([hello[at], hello[at + 1]]);
            let len = u16::from_be_bytes([hello[at + 2], hello[at + 3]]) as usize;
            extensions.push((ty, hello[at + 4..at + 4 + len].to_vec()));
            at += 4 + len;
        }
        Parsed {
            suites,
            session_id_offset_ok,
            extensions,
        }
    }

    fn hello() -> Vec<u8> {
        let ek = vec![0x5a; MLKEM768_ENCAPSULATION_KEY_LEN];
        let x25519 = [0x42; 32];
        construct_chrome_client_hello(
            &[1; 32],
            &[2; 32],
            &ClientKeyShares {
                x25519_public: &x25519,
                mlkem768_encapsulation_key: &ek,
            },
            "www.example.com",
            &[0x1301, 0x1302, 0x1303],
            &["h2", "http/1.1"],
        )
        .unwrap()
    }

    #[test]
    fn the_hello_carries_chromes_suites_and_extensions() {
        let parsed = parse(&hello());
        assert!(parsed.session_id_offset_ok);
        assert!(is_grease(parsed.suites[0]));
        assert_eq!(
            &parsed.suites[1..],
            &[
                0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
                0xc014, 0x009c, 0x009d, 0x002f, 0x0035
            ]
        );

        let types: Vec<u16> = parsed.extensions.iter().map(|(t, _)| *t).collect();
        assert!(is_grease(types[0]), "GREASE first");
        assert!(is_grease(*types.last().unwrap()), "GREASE last");
        assert_ne!(types[0], *types.last().unwrap());
        assert_eq!(parsed.extensions.last().unwrap().1, vec![0x00]);
        let mut middle = types[1..types.len() - 1].to_vec();
        middle.sort_unstable();
        let mut expected = vec![
            EXT_SERVER_NAME,
            EXT_STATUS_REQUEST,
            EXT_SUPPORTED_GROUPS,
            EXT_EC_POINT_FORMATS,
            EXT_SIGNATURE_ALGORITHMS,
            EXT_ALPN,
            EXT_SCT,
            EXT_EXTENDED_MASTER_SECRET,
            EXT_COMPRESS_CERTIFICATE,
            EXT_SESSION_TICKET,
            EXT_SUPPORTED_VERSIONS,
            EXT_PSK_KEY_EXCHANGE_MODES,
            EXT_KEY_SHARE,
            EXT_APPLICATION_SETTINGS,
            EXT_ENCRYPTED_CLIENT_HELLO,
            EXT_RENEGOTIATION_INFO,
        ];
        expected.sort_unstable();
        assert_eq!(middle, expected, "Chrome 133's set, no padding");
    }

    #[test]
    fn the_key_shares_are_grease_the_hybrid_and_x25519() {
        let parsed = parse(&hello());
        let body = &parsed
            .extensions
            .iter()
            .find(|(t, _)| *t == EXT_KEY_SHARE)
            .unwrap()
            .1;
        let mut at = 2;
        let mut shares = Vec::new();
        while at < body.len() {
            let group = u16::from_be_bytes([body[at], body[at + 1]]);
            let len = u16::from_be_bytes([body[at + 2], body[at + 3]]) as usize;
            shares.push((group, body[at + 4..at + 4 + len].to_vec()));
            at += 4 + len;
        }
        assert_eq!(shares.len(), 3);
        assert!(is_grease(shares[0].0));
        assert_eq!(shares[0].1, vec![0x00]);
        assert_eq!(shares[1].0, GROUP_X25519_MLKEM768);
        assert_eq!(shares[1].1.len(), 1216);
        assert_eq!(shares[2].0, GROUP_X25519);
        assert_eq!(&shares[2].1[..], &[0x42; 32]);
        assert_eq!(
            &shares[1].1[1184..],
            &shares[2].1[..],
            "one X25519 key in both"
        );

        let groups = &parsed
            .extensions
            .iter()
            .find(|(t, _)| *t == EXT_SUPPORTED_GROUPS)
            .unwrap()
            .1;
        assert_eq!(
            u16::from_be_bytes([groups[2], groups[3]]),
            shares[0].0,
            "the group GREASE is the key share GREASE"
        );
        assert_eq!(
            &groups[4..],
            &[0x11, 0xec, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18]
        );
    }

    #[test]
    fn the_extension_order_changes_between_connections() {
        let order = |h: &[u8]| -> Vec<u16> {
            parse(h)
                .extensions
                .iter()
                .map(|(t, _)| *t)
                .filter(|t| !is_grease(*t))
                .collect()
        };
        let first = order(&hello());
        assert!(
            (0..20).any(|_| order(&hello()) != first),
            "shuffled per connection"
        );
    }

    #[test]
    fn grease_values_are_rfc_8701s() {
        let mut rng = rand::rng();
        for _ in 0..200 {
            let g = Grease::draw(&mut rng);
            for v in [g.cipher, g.group, g.extension1, g.extension2, g.version] {
                assert!(is_grease(v), "{v:#06x}");
            }
            assert_ne!(g.extension1, g.extension2);
        }
        assert!(!is_grease(0x1301));
        assert!(!is_grease(0x0a1a));
    }

    /// Chrome 133's signature schemes, as the uTLS parrot lists them
    /// (`u_parrots.go:925-934`).
    #[test]
    fn the_signature_algorithms_are_chromes() {
        let parsed = parse(&hello());
        let body = &parsed
            .extensions
            .iter()
            .find(|(t, _)| *t == EXT_SIGNATURE_ALGORITHMS)
            .unwrap()
            .1;
        assert_eq!(
            &body[..],
            &[
                0x00, 0x10, // list length
                0x04, 0x03, // ecdsa_secp256r1_sha256
                0x08, 0x04, // rsa_pss_rsae_sha256
                0x04, 0x01, // rsa_pkcs1_sha256
                0x05, 0x03, // ecdsa_secp384r1_sha384
                0x08, 0x05, // rsa_pss_rsae_sha384
                0x05, 0x01, // rsa_pkcs1_sha384
                0x08, 0x06, // rsa_pss_rsae_sha512
                0x06, 0x01, // rsa_pkcs1_sha512
            ]
        );
    }

    /// A shoes Reality server reads the client's X25519 key out of this
    /// hello, past the GREASE and hybrid shares in front of it.
    #[test]
    fn the_shoes_server_finds_the_x25519_share() {
        let record = client_hello_record(&hello());
        assert_eq!(
            crate::reality::reality_util::extract_client_public_key(&record).unwrap(),
            [0x42; 32]
        );
    }

    #[test]
    fn the_record_is_labelled_tls_1_0() {
        let record = client_hello_record(&hello());
        assert_eq!(&record[..3], &[0x16, 0x03, 0x01]);
    }
}
