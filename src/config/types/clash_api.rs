//! The `clash_api:` block: a Clash-compatible controller and a Prometheus
//! `/metrics`, served by the CLI when a config asks for one.
//!
//! See docs/specs/2026-09-09-clash-api.md, "Configuration".

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Live connections a controller tracks before it starts serving without
/// tracking. The cost is memory -- about 250 bytes an entry -- and this is
/// the number that bounds it on a router.
fn default_max_tracked_connections() -> usize {
    4096
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClashApiConfig {
    /// Where the controller listens. Loopback may go without a secret;
    /// anything else may not -- see [`ClashApiConfig::validate`].
    pub listen: SocketAddr,

    /// The bearer secret every request must carry, and the `?token=` a
    /// WebSocket handshake may carry instead because a browser cannot set a
    /// header on one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,

    /// Origins allowed to read a response from a browser. Empty means `*`,
    /// which is what a dashboard served from elsewhere needs and what mihomo
    /// does; the secret is the access control either way.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_origins: Vec<String>,

    /// Live connections the registry holds. Past it a connection is served
    /// and not tracked, and the omission is reported: a limit on memory must
    /// not become a limit on service.
    #[serde(default = "default_max_tracked_connections")]
    pub max_tracked_connections: usize,

    /// Where a proxy selection survives a restart. Its own setting rather
    /// than a path beside the config, because a router's config directory is
    /// often read-only. Unused until selection exists (spec, slice 2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_file: Option<PathBuf>,
}

impl ClashApiConfig {
    /// The bind rule, and the two settings that cannot be zero.
    ///
    /// A controller is a control plane: it closes connections, and from the
    /// selection slice it redirects every connection on the machine. The
    /// secret is the whole of the access control, so a listener reachable
    /// from another host refuses to start without one rather than warning
    /// about it. Loopback is exempt because the common server case is a
    /// dashboard tunnelled over SSH, where the user already has the machine.
    pub fn validate(&self) -> std::io::Result<()> {
        if let Some(secret) = &self.secret
            && secret.is_empty()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "clash_api.secret is empty; remove the field or give it a value",
            ));
        }

        if !self.listen.ip().is_loopback() && self.secret.is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "clash_api.listen is {}, which is reachable from other hosts, \
                     so clash_api.secret is required",
                    self.listen
                ),
            ));
        }

        if self.max_tracked_connections == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "clash_api.max_tracked_connections must be at least 1",
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(yaml: &str) -> ClashApiConfig {
        serde_yaml::from_str(yaml).unwrap()
    }

    #[test]
    fn loopback_without_a_secret_is_allowed() {
        cfg("listen: 127.0.0.1:9090").validate().unwrap();
        cfg("listen: '[::1]:9090'").validate().unwrap();
    }

    #[test]
    fn a_non_loopback_bind_needs_a_secret() {
        let err = cfg("listen: 0.0.0.0:9090").validate().unwrap_err();
        assert!(
            err.to_string().contains("secret is required"),
            "the message should say what is missing: {err}"
        );
        cfg("listen: 0.0.0.0:9090\nsecret: s").validate().unwrap();
    }

    #[test]
    fn an_empty_secret_is_refused() {
        let err = cfg("listen: 127.0.0.1:9090\nsecret: \"\"")
            .validate()
            .unwrap_err();
        assert!(err.to_string().contains("empty"), "{err}");
    }

    #[test]
    fn the_cap_defaults_and_cannot_be_zero() {
        assert_eq!(cfg("listen: 127.0.0.1:9090").max_tracked_connections, 4096);
        assert!(
            cfg("listen: 127.0.0.1:9090\nmax_tracked_connections: 0")
                .validate()
                .is_err()
        );
    }

    /// An unknown key is a typo, and a controller that silently ignores one
    /// is a controller listening somewhere the config did not say.
    #[test]
    fn an_unknown_field_is_refused() {
        let err = serde_yaml::from_str::<ClashApiConfig>("listen: 127.0.0.1:9090\nsecrte: s")
            .unwrap_err()
            .to_string();
        assert!(err.contains("secrte"), "{err}");
    }

    #[test]
    fn a_block_round_trips() {
        let original = cfg(
            "listen: 127.0.0.1:9090\nsecret: s\nallow_origins: [http://a.example]\n\
             max_tracked_connections: 16\nstate_file: /var/lib/shoes/clash.json",
        );
        let dumped = serde_yaml::to_string(&original).unwrap();
        assert_eq!(
            serde_yaml::from_str::<ClashApiConfig>(&dumped).unwrap(),
            original
        );
    }
}
