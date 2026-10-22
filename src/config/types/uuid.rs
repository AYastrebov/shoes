//! A UUID as configs carry it, parsed once when the config is read.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The 16-byte id VLESS, VMess and TUIC name a user by.
///
/// Parsed when the config is deserialized, so a malformed one is a config
/// error at load and every consumer gets the bytes, rather than each handler
/// parsing the string again and unwrapping on the assumption that validation
/// already did.
///
/// It parses as a VLESS or VMess user id: a UUID of any version, or a name of
/// up to 30 characters (`uuid_util::parse_user_id`). TUIC's fields take only
/// the UUID form, through [`Uuid::deserialize_hex`], as sing-box's TUIC does.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Uuid([u8; 16]);

impl Uuid {
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// A UUID's hex form only, any version: `#[serde(deserialize_with)]` for
    /// TUIC, whose references parse strictly.
    pub fn deserialize_hex<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = crate::uuid_util::parse_uuid(&s).map_err(serde::de::Error::custom)?;
        let bytes: [u8; 16] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("Invalid uuid"))?;
        Ok(Self(bytes))
    }
}

impl FromStr for Uuid {
    type Err = std::io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        crate::uuid_util::parse_user_id(s).map(Self)
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
    fn a_malformed_id_is_a_parse_error_that_does_not_repeat_it() {
        let id = "not-a-uuid-and-longer-than-thirty";
        let err = serde_yaml::from_str::<Uuid>(&format!("\"{id}\"")).unwrap_err();
        assert!(err.to_string().contains("Invalid uuid"), "{err}");
        assert!(!err.to_string().contains(id), "{err}");
    }

    #[test]
    fn a_uuidv7_and_a_name_load() {
        let v7: Uuid = serde_yaml::from_str("\"01890a5d-ac96-774b-bcce-b302099a8057\"").unwrap();
        assert_eq!(v7.to_string(), "01890a5d-ac96-774b-bcce-b302099a8057");
        let name: Uuid = serde_yaml::from_str("\"TMG_74317ba5f91\"").unwrap();
        assert_eq!(name.as_bytes()[6] >> 4, 5);
    }

    #[test]
    fn the_hex_form_refuses_a_name() {
        #[derive(Debug, Deserialize)]
        struct Tuic {
            #[serde(deserialize_with = "Uuid::deserialize_hex")]
            #[allow(dead_code, reason = "only the parse is under test")]
            uuid: Uuid,
        }
        assert!(serde_yaml::from_str::<Tuic>("uuid: TMG_74317ba5f91").is_err());
        assert!(serde_yaml::from_str::<Tuic>("uuid: 01890a5d-ac96-774b-bcce-b302099a8057").is_ok());
    }
}
