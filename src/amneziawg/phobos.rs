//! Phobos obfuscation around the tunnel's datagrams.
//!
//! A Phobos server is plain kernel WireGuard behind an obfuscating UDP proxy.
//! The wire format and the codec are awgtun's (`awgtun::phobos`,
//! `docs/phobos.md` there). This module converts the shoes config into the
//! codec's and shares one codec between the tunnel's tasks. Where it is
//! applied, and why the rebind sends a handshake, is
//! `docs/specs/2026-11-02-phobos-obfuscation.md`.

use std::net::SocketAddr;
use std::time::Duration;

use awgtun::phobos::{BINDING_REQUEST_LEN, PhobosCodec, PhobosConfig, Unwrapped, WrapError};
use parking_lot::Mutex;

use crate::config::PhobosClientConfig;

/// Build the codec's configuration from the `phobos:` block.
///
/// Every value goes through `PhobosConfig::set`, which applies the
/// reference's ranges (`config.c` in Ground-Zerro/Phobos), so the two cannot
/// drift. An error names the field and never repeats the value: the key is
/// a deployment's secret.
pub fn convert_phobos_config(config: &PhobosClientConfig) -> std::io::Result<PhobosConfig> {
    let invalid = |e: awgtun::amnezia::ConfigError| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid phobos config: {e}"),
        )
    };
    // Trimmed as the reference trims every configuration value.
    let mut converted =
        PhobosConfig::new(config.key.expose().trim().as_bytes().to_vec()).map_err(invalid)?;
    let numeric = [
        ("max-dummy", config.max_dummy.map(u64::from)),
        ("obfuscate-bytes", config.obfuscate_bytes.map(u64::from)),
        ("media-pt", config.media_pt.map(u64::from)),
        ("media-ssrc", config.media_ssrc.map(u64::from)),
        ("media-clock", config.media_clock.map(u64::from)),
    ];
    if let Some(masking) = &config.masking {
        converted.set("masking", masking).map_err(invalid)?;
    }
    for (name, value) in numeric {
        if let Some(value) = value {
            converted.set(name, &value.to_string()).map_err(invalid)?;
        }
    }
    Ok(converted)
}

/// One Phobos codec, shared by the tunnel's tasks.
///
/// The lock is held for one wrap or unwrap and never across an `await`.
/// Two tasks may therefore send in the other order from the one they wrapped
/// in, which under `media` reorders RTP sequence numbers. That is what RTP
/// over UDP sees anyway, and the server reads neither the sequence number
/// nor the timestamp (`media_on_data_unwrap`).
pub struct PhobosLayer {
    codec: Mutex<PhobosCodec>,
    control_interval: Option<Duration>,
}

impl PhobosLayer {
    pub fn new(config: PhobosConfig) -> std::io::Result<Self> {
        let codec = PhobosCodec::new(config).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid phobos config: {e}"),
            )
        })?;
        Ok(Self {
            control_interval: codec.control_interval(),
            codec: Mutex::new(codec),
        })
    }

    /// Wrap one outgoing datagram into `wire`. A returned Binding Request
    /// goes out before `wire`.
    pub fn wrap(
        &self,
        datagram: &[u8],
        wire: &mut Vec<u8>,
    ) -> Result<Option<[u8; BINDING_REQUEST_LEN]>, WrapError> {
        self.codec.lock().wrap(datagram, wire)
    }

    /// Unwrap one incoming datagram in place.
    pub fn unwrap<'a>(&self, datagram: &'a mut [u8], source: SocketAddr) -> Unwrapped<'a> {
        self.codec.lock().unwrap(datagram, source)
    }

    /// A Binding Request for the periodic control traffic.
    pub fn binding_request(&self) -> [u8; BINDING_REQUEST_LEN] {
        self.codec.lock().binding_request()
    }

    /// How often the masking sends a Binding Request, if it does.
    pub fn control_interval(&self) -> Option<Duration> {
        self.control_interval
    }
}

impl std::fmt::Debug for PhobosLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The codec's own Debug redacts the key.
        f.debug_struct("PhobosLayer")
            .field("codec", &*self.codec.lock())
            .finish()
    }
}

/// The Phobos frame's share of a full-size datagram: what `mtu` must leave
/// room for. The random tail is never added at that size (`encode` in the
/// reference stops below 1024 bytes).
pub fn frame_overhead(config: &PhobosConfig) -> usize {
    config.masking.overhead()
}

#[cfg(test)]
mod tests {
    use super::*;
    use awgtun::phobos::Masking;

    fn block(yaml: &str) -> PhobosClientConfig {
        serde_yaml::from_str(yaml).unwrap()
    }

    #[test]
    fn every_key_reaches_the_codec() {
        let config = convert_phobos_config(&block(
            "key: synthetic-key\nmasking: MEDIA\nmax_dummy: 16\nobfuscate_bytes: 32\n\
             media_pt: 100\nmedia_ssrc: 42\nmedia_clock: 30\n",
        ))
        .unwrap();
        assert_eq!(config.key(), b"synthetic-key");
        assert_eq!(config.masking, Masking::Media);
        assert_eq!(config.max_dummy, 16);
        assert_eq!(config.obfuscate_bytes, 32);
        assert_eq!(config.media.payload_type, 100);
        assert_eq!(config.media.ssrc, 42);
        assert_eq!(config.media.timestamp_step, 3000);
    }

    #[test]
    fn unset_keys_take_the_reference_defaults() {
        let config = convert_phobos_config(&block("key: k\n")).unwrap();
        // The reference defaults `masking` to AUTO, which frames nothing on
        // a client.
        assert_eq!(config.masking, Masking::None);
        assert_eq!(config.max_dummy, 4);
        assert_eq!(config.effective_obfuscate_bytes(), 0);

        let media = convert_phobos_config(&block("key: k\nmasking: media\n")).unwrap();
        assert_eq!(media.effective_obfuscate_bytes(), 16);
    }

    #[test]
    fn out_of_range_values_name_the_field() {
        for (yaml, field) in [
            ("key: k\nmax_dummy: 1025\n", "max-dummy"),
            ("key: k\nmedia_pt: 128\n", "media-pt"),
            ("key: k\nmedia_clock: 1001\n", "media-clock"),
            ("key: k\nobfuscate_bytes: 2147483648\n", "obfuscate-bytes"),
            ("key: k\nmasking: quic\n", "masking"),
        ] {
            let err = convert_phobos_config(&block(yaml)).unwrap_err().to_string();
            assert!(err.contains(field), "{yaml}: {err}");
        }
    }

    #[test]
    fn a_refusal_never_repeats_the_key() {
        let secret = "x".repeat(300);
        let err = convert_phobos_config(&block(&format!("key: {secret}\n")))
            .unwrap_err()
            .to_string();
        assert!(err.contains("key"), "{err}");
        assert!(!err.contains(&secret), "{err}");

        let empty = convert_phobos_config(&block("key: \"  \"\n")).unwrap_err();
        assert!(empty.to_string().contains("empty"), "{empty}");
    }

    #[test]
    fn debug_never_prints_the_key() {
        let secret = "very-secret-preset-key";
        let parsed = block(&format!("key: {secret}\nmasking: stun\n"));
        let layer = PhobosLayer::new(convert_phobos_config(&parsed).unwrap()).unwrap();
        let shown = format!("{parsed:?} {layer:?}");
        assert!(!shown.contains(secret), "{shown}");
    }

    #[test]
    fn unknown_fields_are_refused() {
        // `target` and `source-lport` from a Phobos client file have no
        // place here: the first is the chain's address, the second a
        // loopback port shoes doesn't use.
        assert!(serde_yaml::from_str::<PhobosClientConfig>("key: k\ntarget: x\n").is_err());
    }
}
