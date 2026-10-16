//! WireGuard keys and address prefixes as configs carry them, parsed once
//! when the config is read.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use base64::Engine;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

fn invalid(message: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message)
}

/// A WireGuard key: 32 bytes, standard base64 in the config.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct WgKey([u8; 32]);

impl WgKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl FromStr for WgKey {
    type Err = std::io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(|e| invalid(format!("invalid base64: {e}")))?;
        let len = bytes.len();
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| invalid(format!("key must be 32 bytes, got {len}")))?;
        Ok(Self(bytes))
    }
}

impl fmt::Display for WgKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&base64::engine::general_purpose::STANDARD.encode(self.0))
    }
}

impl fmt::Debug for WgKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// An address and prefix length, `10.0.0.2/32` or a bare address meaning
/// the whole host (`/32`, `/128`).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpPrefix {
    pub addr: IpAddr,
    pub len: u8,
}

impl FromStr for IpPrefix {
    type Err = std::io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let max_len = |addr: &IpAddr| if addr.is_ipv4() { 32 } else { 128 };
        let Some((addr_str, len_str)) = s.split_once('/') else {
            let addr: IpAddr = s
                .parse()
                .map_err(|e| invalid(format!("invalid IP address or CIDR '{s}': {e}")))?;
            return Ok(Self {
                addr,
                len: max_len(&addr),
            });
        };
        let addr: IpAddr = addr_str
            .parse()
            .map_err(|e| invalid(format!("invalid IP address '{addr_str}': {e}")))?;
        let len: u8 = len_str
            .parse()
            .map_err(|e| invalid(format!("invalid prefix length '{len_str}': {e}")))?;
        // smoltcp's IpCidr::new panics on an out-of-range prefix, so this has
        // to be refused here rather than reach the netstack.
        if len > max_len(&addr) {
            return Err(invalid(format!(
                "prefix length {len} exceeds maximum {} for {}",
                max_len(&addr),
                if addr.is_ipv4() { "IPv4" } else { "IPv6" }
            )));
        }
        Ok(Self { addr, len })
    }
}

impl fmt::Display for IpPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

impl fmt::Debug for IpPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

macro_rules! string_serde {
    ($ty:ty) => {
        impl Serialize for $ty {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let s = String::deserialize(deserializer)?;
                s.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

string_serde!(WgKey);
string_serde!(IpPrefix);

/// `deserialize_with` helpers that name the field in the error: serde does
/// not, and "key must be 32 bytes" without the field leaves the reader
/// guessing which of three keys it means.
pub(crate) mod named {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer};

    fn named<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
        deserializer: D,
        field: &str,
    ) -> Result<T, D::Error> {
        T::deserialize(deserializer).map_err(|e| D::Error::custom(format!("{field}: {e}")))
    }

    macro_rules! field {
        ($name:ident) => {
            pub fn $name<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
                deserializer: D,
            ) -> Result<T, D::Error> {
                named(deserializer, stringify!($name))
            }
        };
    }

    field!(private_key);
    field!(peer_public_key);
    field!(preshared_key);
    field!(local_addresses);
    field!(allowed_ips);
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0A=";

    #[test]
    fn a_key_round_trips() {
        let key: WgKey = KEY.parse().unwrap();
        assert_eq!(key.to_string(), KEY);
        assert_eq!(
            serde_yaml::from_str::<WgKey>(&serde_yaml::to_string(&key).unwrap()).unwrap(),
            key
        );
    }

    #[test]
    fn a_short_or_malformed_key_says_why() {
        let err = "AAAA".parse::<WgKey>().unwrap_err().to_string();
        assert_eq!(err, "key must be 32 bytes, got 3");
        let err = "not base64!".parse::<WgKey>().unwrap_err().to_string();
        assert!(err.starts_with("invalid base64"), "{err}");
    }

    #[test]
    fn prefixes_parse_and_print() {
        let p: IpPrefix = "10.0.0.1/24".parse().unwrap();
        assert_eq!((p.addr.to_string().as_str(), p.len), ("10.0.0.1", 24));
        let p: IpPrefix = "fd00::1".parse().unwrap();
        assert_eq!(p.len, 128);
        assert_eq!(p.to_string(), "fd00::1/128");
        assert_eq!("192.168.1.1".parse::<IpPrefix>().unwrap().len, 32);
    }

    #[test]
    fn a_bad_prefix_is_refused() {
        assert!("not-an-ip/24".parse::<IpPrefix>().is_err());
        assert!("10.0.0.1/abc".parse::<IpPrefix>().is_err());
        let err = "10.0.0.1/33".parse::<IpPrefix>().unwrap_err().to_string();
        assert!(err.contains("exceeds maximum 32"), "{err}");
        assert!("::1/129".parse::<IpPrefix>().is_err());
    }

    /// Which of the three keys is wrong is in the message.
    #[test]
    fn a_bad_key_names_its_field() {
        let yaml = format!(
            "private_key: {KEY}\npeer_public_key: {KEY}\npreshared_key: AAAA\n\
             local_addresses: 10.0.0.2/32\nallowed_ips: 0.0.0.0/0\n"
        );
        let err = serde_yaml::from_str::<crate::config::WireGuardClientConfig>(&yaml)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("preshared_key: key must be 32 bytes, got 3"),
            "{err}"
        );

        let yaml = format!(
            "private_key: {KEY}\npeer_public_key: {KEY}\n\
             local_addresses: 10.0.0.2/33\nallowed_ips: 0.0.0.0/0\n"
        );
        let err = serde_yaml::from_str::<crate::config::WireGuardClientConfig>(&yaml)
            .unwrap_err()
            .to_string();
        assert!(err.contains("local_addresses: prefix length 33"), "{err}");
    }
}
