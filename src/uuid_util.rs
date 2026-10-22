#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "predates the lint; see the [lints] note in Cargo.toml"
)]

use std::fmt::Write;

use aws_lc_rs::digest::{SHA1_FOR_LEGACY_USE_ONLY, digest};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};

/// The hex groups of a UUID, each optionally preceded by a dash (Xray
/// `common/uuid` `byteGroups`).
const HEX_GROUPS: [usize; 5] = [8, 4, 4, 4, 12];

fn invalid(reason: &str) -> std::io::Error {
    // The id is a credential, so the error does not repeat it.
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("Invalid uuid: {reason}"),
    )
}

/// Parse a UUID's 32 hex digits, with or without the four dashes, into 16
/// bytes. Any version and variant: UUIDv7 ids are in use, and neither Xray
/// nor sing-box checks either field.
pub fn parse_uuid(uuid_str: &str) -> std::io::Result<Vec<u8>> {
    let mut text = uuid_str.as_bytes();
    let mut bytes = Vec::with_capacity(16);
    for group in HEX_GROUPS {
        if let [b'-', rest @ ..] = text {
            text = rest;
        }
        if text.len() < group {
            return Err(invalid("expected 32 hex digits"));
        }
        let (digits, rest) = text.split_at(group);
        for pair in digits.chunks_exact(2) {
            let (Some(high), Some(low)) = (hex_value(pair[0]), hex_value(pair[1])) else {
                return Err(invalid("expected 32 hex digits"));
            };
            bytes.push((high << 4) | low);
        }
        text = rest;
    }
    if !text.is_empty() {
        return Err(invalid("expected 32 hex digits"));
    }
    Ok(bytes)
}

fn hex_value(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Parse a VLESS or VMess user id the way Xray does (`common/uuid`
/// `ParseString`): 32 to 36 characters are a UUID's hex form, and 1 to 30
/// characters of anything are a name, mapped to its version-5 UUID in the nil
/// namespace. Panels hand out such names (`TMG_74317ba5f91`). sing-vmess
/// computes the same id (`uuid.NewV5(uuid.Nil, ...)`) for whatever its UUID
/// parser refuses, with no length limit; the limits here are Xray's.
pub fn parse_user_id(user_id: &str) -> std::io::Result<[u8; 16]> {
    let len = user_id.len();
    if (32..=36).contains(&len) {
        let bytes = parse_uuid(user_id)?;
        return bytes
            .try_into()
            .map_err(|_| invalid("expected 32 hex digits"));
    }
    if len == 0 || len > 30 {
        return Err(invalid("expected a UUID, or a name of 1 to 30 characters"));
    }
    Ok(name_based_uuid(user_id.as_bytes()))
}

/// RFC 4122 version 5: SHA-1 over the nil namespace (16 zero bytes) and the
/// name, with the version and variant bits set.
fn name_based_uuid(name: &[u8]) -> [u8; 16] {
    let mut input = Vec::with_capacity(16 + name.len());
    input.extend_from_slice(&[0u8; 16]);
    input.extend_from_slice(name);
    let hash = digest(&SHA1_FOR_LEGACY_USE_ONLY, &input);
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&hash.as_ref()[..16]);
    uuid[6] = (uuid[6] & 0x0f) | 0x50;
    uuid[8] = (uuid[8] & 0x3f) | 0x80;
    uuid
}

/// Generate a random UUID v4 and return it as a formatted string.
#[inline]
pub fn generate_uuid() -> String {
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 16];
    rng.fill(&mut bytes).expect("RNG failed");

    // Set version (4) in bits 12-15 of byte 6
    bytes[6] = (bytes[6] & 0x0f) | 0x40;

    // Set variant (RFC 4122) in bits 6-7 of byte 8
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    let mut s = String::with_capacity(36);
    for (i, &b) in bytes.iter().enumerate() {
        if i == 4 || i == 6 || i == 8 || i == 10 {
            s.push('-');
        }
        write!(s, "{:02x}", b).unwrap();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_uuid_format() {
        let uuid = generate_uuid();
        // Check format: 8-4-4-4-12
        assert_eq!(uuid.len(), 36);
        assert_eq!(uuid.chars().nth(8), Some('-'));
        assert_eq!(uuid.chars().nth(13), Some('-'));
        assert_eq!(uuid.chars().nth(18), Some('-'));
        assert_eq!(uuid.chars().nth(23), Some('-'));

        // Check version (4) at position 14
        assert_eq!(uuid.chars().nth(14), Some('4'));

        // Check variant at position 19 (must be 8, 9, a, or b)
        let variant_char = uuid.chars().nth(19).unwrap();
        assert!(
            variant_char == '8'
                || variant_char == '9'
                || variant_char == 'a'
                || variant_char == 'b'
        );
    }

    #[test]
    fn test_generate_uuid_roundtrip() {
        let uuid = generate_uuid();
        let bytes = parse_uuid(&uuid).unwrap();
        assert_eq!(bytes.len(), 16);

        // Verify version nibble
        assert_eq!(bytes[6] >> 4, 4);

        // Verify variant bits
        assert_eq!(bytes[8] >> 6, 2);
    }

    #[test]
    fn test_parse_uuid_with_dashes() {
        // Valid v4 UUID (version=4, variant=10xx)
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        let bytes = parse_uuid(uuid).unwrap();
        assert_eq!(bytes.len(), 16);
        assert_eq!(bytes[0], 0x55);
        assert_eq!(bytes[1], 0x0e);
    }

    #[test]
    fn test_parse_uuid_without_dashes() {
        // Valid v4 UUID (version=4, variant=10xx)
        let uuid = "550e8400e29b41d4a716446655440000";
        let bytes = parse_uuid(uuid).unwrap();
        assert_eq!(bytes.len(), 16);
        assert_eq!(bytes[0], 0x55);
        assert_eq!(bytes[1], 0x0e);
    }

    #[test]
    fn any_version_and_variant_is_accepted() {
        // A UUIDv7, a version 1, and a variant outside RFC 4122.
        for uuid in [
            "01890a5d-ac96-774b-bcce-b302099a8057",
            "550e8400-e29b-11d4-a716-446655440000",
            "550e8400-e29b-41d4-c716-446655440000",
        ] {
            assert_eq!(parse_uuid(uuid).unwrap().len(), 16, "{uuid}");
            assert!(parse_user_id(uuid).is_ok(), "{uuid}");
        }
    }

    #[test]
    fn dashes_go_only_between_groups() {
        assert!(parse_uuid("550e8400-e29b41d4a716446655440000").is_ok());
        assert!(parse_uuid("550e-8400e29b41d4a716446655440000").is_err());
        assert!(parse_uuid("550e8400-e29b-41d4-a716-4466554400001").is_err());
        assert!(parse_uuid("550e8400-e29b-41d4-a716-44665544000").is_err());
    }

    #[test]
    fn a_short_name_is_a_name_based_uuid() {
        let id = parse_user_id("TMG_74317ba5f91").unwrap();
        assert_eq!(id[6] >> 4, 5);
        assert_eq!(id[8] >> 6, 2);
        assert_eq!(parse_user_id("TMG_74317ba5f91").unwrap(), id);
        assert_ne!(parse_user_id("TMG_74317ba5f92").unwrap(), id);
        assert!(parse_user_id(&"x".repeat(30)).is_ok());
    }

    #[test]
    fn lengths_outside_the_two_forms_are_refused() {
        for id in [
            String::new(),
            "x".repeat(31),
            "x".repeat(37),
            "x".repeat(32),
        ] {
            let err = parse_user_id(&id).unwrap_err().to_string();
            assert!(err.starts_with("Invalid uuid"), "{err}");
            if !id.is_empty() {
                assert!(!err.contains(&id), "the error repeats the id: {err}");
            }
        }
    }

    #[test]
    fn names_match_the_reference_vectors() {
        use crate::kat::{cases, text, vectors};
        let vectors = vectors("user-id");
        for case in cases(&vectors, "cases") {
            let name = text(&case["name"]);
            let expected = parse_uuid(text(&case["uuid"])).unwrap();
            assert_eq!(parse_user_id(name).unwrap().to_vec(), expected, "{name}");
        }
    }
}
