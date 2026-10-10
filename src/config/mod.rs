//! Configuration module for the proxy server.
//!
//! This module provides:
//! - [`types`]: All configuration types (server, client, rules, etc.)
//! - [`pem`]: PEM file handling and certificate loading
//! - [`validate`]: Configuration validation and server config creation
//! - [`singbox`]: Sing-box JSON configuration conversion
//! - [`convert_util`]: Utilities for preprocessing JSON-like configs
//!
//! The main entry points are:
//! - [`load_configs`]: Load config files from disk
//! - [`convert_cert_paths`]: Convert PEM file paths to inline data
//! - [`create_server_configs`]: Validate and create final server configs
//! - [`singbox::convert_singbox_config`]: Convert sing-box configs to shoes format

mod pem;
mod types;
mod validate;

pub use pem::convert_cert_paths;
pub use types::*;
pub use validate::{ValidatedConfigs, create_server_configs};

/// Rewrite relative rule-set paths so they resolve against the config file that
/// declared them, letting a config directory be relocated intact.
///
/// This has to happen here: `load_configs` is the last point that still knows
/// which file an entry came from, since the configs are flattened into one list
/// immediately afterwards.
fn resolve_rule_set_paths(configs: &mut [Config], config_filename: &str) {
    let Some(base) = std::path::Path::new(config_filename).parent() else {
        return;
    };
    if base.as_os_str().is_empty() {
        return;
    }
    for config in configs.iter_mut() {
        if let Config::RuleSet(rule_set) = config {
            let path = std::path::Path::new(&rule_set.path);
            if path.is_relative() {
                rule_set.path = base.join(path).to_string_lossy().into_owned();
            }
        }
    }
}

/// Loads configuration files from the provided paths.
///
/// Reads each file, parses it as YAML, and returns the combined list of configs.
pub async fn load_configs(args: &Vec<String>) -> std::io::Result<Vec<Config>> {
    let mut all_configs = vec![];
    for config_filename in args {
        let config_bytes = match tokio::fs::read(config_filename).await {
            Ok(b) => b,
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Could not read config file {config_filename}: {e}"),
                ));
            }
        };

        let config_str = match String::from_utf8(config_bytes) {
            Ok(s) => s,
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Could not parse config file {config_filename} as UTF8: {e}"),
                ));
            }
        };

        let mut configs = match serde_yaml::from_str::<Vec<Config>>(&config_str) {
            Ok(c) => c,
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Could not parse config file {config_filename} as config YAML: {e}"),
                ));
            }
        };
        resolve_rule_set_paths(&mut configs, config_filename);
        all_configs.append(&mut configs)
    }

    Ok(all_configs)
}

/// Load config from a string, rather than from a path.
///
/// Ungated, because `crate::control` calls it on every platform: an embedding
/// host — a Network Extension, a Windows service, a desktop GUI validating
/// what the user typed — has the config as a string and no file to point at.
/// It was previously gated to the FFI targets, which made the library unable
/// to parse a config on a desktop build at all.
///
/// Still `allow(dead_code)`: the binary declares its modules in main.rs, which
/// has no `control`, so a binary build compiles this with nothing to use it.
/// That is a property of the build rather than something a later change fixes.
#[allow(dead_code)]
pub fn load_config_str(config_str: &str) -> std::io::Result<Vec<Config>> {
    serde_yaml::from_str::<Vec<Config>>(config_str).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Could not parse config string as config YAML: {e}"),
        )
    })
}

#[cfg(test)]
mod redaction_tests {
    use super::*;

    /// A config touching every kind of secret the parser accepts. Each value is
    /// distinctive so a leak is unambiguous rather than a coincidental substring.
    const CONFIG_WITH_SECRETS: &str = r#"
- address: "127.0.0.1:1080"
  protocol:
    type: socks
    username: alice
    password: LEAK-socks-inbound-password
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        address: "wg.example.com:51820"
        protocol:
          type: amneziawg
          private_key: "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="
          peer_public_key: "ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0A="
          preshared_key: "ERERERERERERERERERERERERERERERERERERERERERE="
          local_addresses: "10.8.0.2/32"
          allowed_ips: "0.0.0.0/0"
          awg:
            s1: 20
            s2: 20
            s3: 20
            s4: 20
            header_protection_key: "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI="
- address: "127.0.0.1:8388"
  protocol:
    type: shadowsocks
    cipher: chacha20-ietf-poly1305
    password: LEAK-shadowsocks-password
- address: "127.0.0.1:1443"
  protocol:
    type: trojan
    password: LEAK-trojan-password
- address: "127.0.0.1:2443"
  protocol:
    type: vless
    user_id: 11111111-2222-3333-4444-555555555555
"#;

    /// Every secret above, as it appears in the YAML.
    const SECRET_VALUES: &[&str] = &[
        "LEAK-socks-inbound-password",
        "LEAK-shadowsocks-password",
        "LEAK-trojan-password",
        "11111111-2222-3333-4444-555555555555",
        "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=", // private key
        "ERERERERERERERERERERERERERERERERERERERERERE=", // preshared key
        "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=", // header protection key
    ];

    /// `load_config_str` is gated to the FFI targets; this is the same parse.
    fn parse(yaml: &str) -> Vec<Config> {
        serde_yaml::from_str::<Vec<Config>>(yaml).expect("config must parse")
    }

    /// The CLI dumps every parsed config at debug level. That dump must not
    /// carry credentials: with `--log-file` it lands on disk in cleartext, and
    /// logs get pasted into bug reports.
    #[test]
    fn the_config_debug_dump_contains_no_secrets() {
        let configs = parse(CONFIG_WITH_SECRETS);
        assert!(!configs.is_empty());

        // Exactly what main.rs writes for each config.
        let dump = configs
            .iter()
            .map(|config| format!("{config:#?}"))
            .collect::<Vec<_>>()
            .join("\n");

        for secret in SECRET_VALUES {
            assert!(
                !dump.contains(secret),
                "the debug dump leaked a secret: {secret}\n\ndump:\n{dump}"
            );
        }

        // The dump is still worth having: non-secret fields survive.
        assert!(dump.contains("alice"), "usernames should remain visible");
        assert!(
            dump.contains("wg.example.com"),
            "endpoints should remain visible"
        );
        assert!(
            dump.contains("<redacted>"),
            "secrets should be marked, not dropped"
        );
    }

    /// Redaction must not corrupt the config. Re-serializing has to reproduce
    /// the real values, or a round-trip would silently destroy credentials.
    #[test]
    fn secrets_survive_a_serde_round_trip() {
        let configs = parse(CONFIG_WITH_SECRETS);
        let yaml = serde_yaml::to_string(&configs).expect("config must re-serialize");

        for secret in SECRET_VALUES {
            assert!(
                yaml.contains(secret),
                "re-serializing lost a secret: {secret}"
            );
        }
    }
}

#[cfg(test)]
mod rule_set_path_tests {
    use super::*;

    fn rule_set(path: &str) -> Config {
        Config::RuleSet(RuleSetConfig {
            rule_set: "geo".to_string(),
            path: path.to_string(),
        })
    }

    fn path_of(config: &Config) -> &str {
        match config {
            Config::RuleSet(c) => &c.path,
            other => panic!("expected a rule-set config, got {other:?}"),
        }
    }

    #[test]
    fn relative_rule_set_paths_resolve_against_the_config_file() {
        let mut configs = vec![rule_set("lists/geo.srs")];
        resolve_rule_set_paths(&mut configs, "/etc/shoes/main.yaml");
        // Built with join rather than written out, because the separator the
        // resolver inserts is the platform's: "/" on Unix, "\" on Windows.
        let expected = std::path::Path::new("/etc/shoes").join("lists/geo.srs");
        assert_eq!(path_of(&configs[0]), expected.to_str().unwrap());
    }

    #[test]
    fn absolute_rule_set_paths_are_left_alone() {
        let mut configs = vec![rule_set("/opt/geo.srs")];
        resolve_rule_set_paths(&mut configs, "/etc/shoes/main.yaml");
        assert_eq!(path_of(&configs[0]), "/opt/geo.srs");
    }

    #[test]
    fn a_config_in_the_working_directory_leaves_paths_untouched() {
        let mut configs = vec![rule_set("geo.srs")];
        resolve_rule_set_paths(&mut configs, "config.yaml");
        assert_eq!(path_of(&configs[0]), "geo.srs");
    }
}

/// What a mistake deep inside a config file reports.
///
/// `NoneOrSome`, `OneOrSome` and `NoneOrOne` sit between almost every
/// nested option and the file. Derived as `#[serde(untagged)]`, each failed
/// variant's error was thrown away and the file reported only "data did not
/// match any variant of untagged enum NoneOrSome", for a misspelled value
/// three levels down as much as for a malformed top level.
#[cfg(test)]
mod nested_error_tests {
    use super::load_config_str;

    fn server_with_hop(hop: &str) -> String {
        format!(
            r#"
- address: "127.0.0.1:1080"
  protocol:
    type: socks
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        - address: "example.com:443"
          protocol:
{hop}
"#
        )
    }

    fn tuic_hop(extra: &str) -> String {
        format!(
            "            type: tuic\n            uuid: \"b0e80a62-8a51-47f0-91f1-f0f7faf8d9d4\"\n            password: secret\n{extra}"
        )
    }

    fn error_of(yaml: &str) -> String {
        load_config_str(yaml)
            .expect_err("the config must be refused")
            .to_string()
    }

    #[test]
    fn an_unknown_value_in_a_rules_outbound_is_named() {
        let err = error_of(&server_with_hop(&tuic_hop(
            "            congestion_control: vegas\n",
        )));
        assert!(err.contains("vegas"), "{err}");
        assert!(err.contains("new_reno"), "{err}");
        assert!(!err.contains("did not match any variant"), "{err}");
    }

    #[test]
    fn an_unknown_relay_mode_in_a_rules_outbound_is_named() {
        let err = error_of(&server_with_hop(&tuic_hop(
            "            udp_relay_mode: sideways\n",
        )));
        assert!(err.contains("sideways"), "{err}");
    }

    #[test]
    fn a_misspelled_field_in_a_rules_outbound_is_named() {
        let err = error_of(&server_with_hop(&tuic_hop("            heartbeat: 5\n")));
        assert!(err.contains("heartbeat"), "{err}");
        assert!(!err.contains("did not match any variant"), "{err}");
    }

    #[test]
    fn an_empty_mask_list_says_it_is_empty() {
        let err = error_of(
            r#"
- address: "127.0.0.1:1080"
  protocol:
    type: socks
  rules:
    - masks: []
      action: allow
"#,
        );
        assert!(err.contains("at least one"), "{err}");
    }

    #[test]
    fn a_misspelled_field_in_a_dns_server_is_named() {
        let err = error_of(
            r#"
- dns_group: proxied
  dns_servers:
    - url: "udp://8.8.8.8"
      client_chian: direct
"#,
        );
        assert!(err.contains("client_chian"), "{err}");
    }

    #[test]
    fn a_misspelled_field_in_a_server_is_still_named() {
        let err = error_of(
            r#"
- address: "127.0.0.1:1080"
  protocol:
    type: socks
  rulez: []
"#,
        );
        assert!(err.contains("rulez"), "{err}");
    }
}
