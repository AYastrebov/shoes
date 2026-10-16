//! A UUID as configs carry it, parsed once when the config is read.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A version 4, RFC 4122 UUID: what VLESS, VMess and TUIC name a user by.
///
/// Parsed when the config is deserialized, so a malformed one is a config
/// error at load and every consumer gets the bytes, rather than each handler
/// parsing the string again and unwrapping on the assumption that validation
/// already did.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Uuid([u8; 16]);

impl Uuid {
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl FromStr for Uuid {
    type Err = std::io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = crate::uuid_util::parse_uuid(s)?;
        let bytes: [u8; 16] = bytes
            .try_into()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid uuid"))?;
        Ok(Self(bytes))
    }
}

/// The canonical form: lowercase, hyphenated.
impl fmt::Display for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, b) in self.0.iter().enumerate() {
            if matches!(i, 4 | 6 | 8 | 10) {
                f.write_str("-")?;
            }
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl Serialize for Uuid {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Uuid {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_uuid_round_trips_in_canonical_form() {
        let uuid: Uuid = "B0E80A62-8A51-47F0-91F1-F0F7FAF8D9D4".parse().unwrap();
        assert_eq!(uuid.to_string(), "b0e80a62-8a51-47f0-91f1-f0f7faf8d9d4");
        let yaml = serde_yaml::to_string(&uuid).unwrap();
        assert_eq!(serde_yaml::from_str::<Uuid>(&yaml).unwrap(), uuid);
    }

    #[test]
    fn a_malformed_uuid_is_a_parse_error_naming_it() {
        let err = serde_yaml::from_str::<Uuid>("\"test-uuid\"").unwrap_err();
        assert!(err.to_string().contains("Invalid uuid: test-uuid"), "{err}");
        let err =
            serde_yaml::from_str::<Uuid>("\"123e4567-e89b-12d3-a456-426614174000\"").unwrap_err();
        assert!(err.to_string().contains("not version 4"), "{err}");
    }
}
