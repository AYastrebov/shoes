use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct TlsPaths {
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ControlApiConfig {
    #[serde(default = "default_bind")]
    pub bind: SocketAddr,
    pub token: String,
    pub config_path: PathBuf,
    #[serde(default)]
    pub tls: Option<TlsPaths>,
}

fn default_bind() -> SocketAddr {
    "127.0.0.1:9000".parse().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_minimal_section() {
        let yaml = "token: secret\nconfig_path: /etc/shoes/config.yaml\n";
        let cfg: ControlApiConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.token, "secret");
        assert_eq!(cfg.bind, "127.0.0.1:9000".parse().unwrap());
        assert!(cfg.tls.is_none());
    }
}
