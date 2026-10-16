//! Factory functions for creating TCP client handlers from config.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "predates the lint; see the [lints] note in Cargo.toml"
)]

use std::sync::Arc;

use log::debug;

use crate::anytls::{AnyTlsClientHandler, PaddingFactory};
use crate::client_proxy_selector::{ClientProxySelector, ConnectAction, ConnectRule};
use crate::config::Redacted;
use crate::config::{
    ClientProxyConfig, HttpUpgradeClientConfig, RuleActionConfig, RuleConfig, ShadowsocksConfig,
    TlsClientConfig, WebsocketClientConfig,
};
use crate::h2mux::H2MuxClientHandler;
use crate::http_handler::HttpTcpClientHandler;
use crate::httpupgrade::HttpUpgradeTcpClientHandler;
use crate::naiveproxy::NaiveProxyTcpClientHandler;
use crate::port_forward_handler::PortForwardClientHandler;
use crate::resolver::Resolver;
use crate::rustls_config_util::create_client_config;
use crate::shadow_tls::ShadowTlsClientHandler;
use crate::shadowsocks::ShadowsocksTcpHandler;
use crate::snell::snell_handler::SnellClientHandler;
use crate::socks_handler::SocksTcpClientHandler;
use crate::tcp::chain_builder::build_client_chain_group;
use crate::tcp::tcp_handler::TcpClientHandler;
use crate::tls_client_handler::TlsClientHandler;
use crate::trojan_handler::TrojanTcpHandler;
use crate::uuid_util::parse_uuid;
use crate::vless::vless_client_handler::VlessTcpClientHandler;
use crate::vmess::VmessTcpClientHandler;
use crate::websocket::WebsocketTcpClientHandler;

fn create_auth_credentials(
    username: Option<String>,
    password: Option<String>,
) -> Option<(String, String)> {
    match (&username, &password) {
        (None, None) => None,
        _ => Some((username.unwrap_or_default(), password.unwrap_or_default())),
    }
}

/// What a layer of a client chain may need to know about the hop it runs on.
#[derive(Debug, Clone)]
pub struct HopContext {
    /// The proxy server's address as dialled, `host:port` with an IPv6 host
    /// bracketed: the `Host` a WebSocket or HTTPUpgrade request falls back to.
    pub dialled_address: String,
    /// The TLS server name of the layer below, which HTTPUpgrade prefers over
    /// the dialled address (sing-box transport/v2rayhttpupgrade/client.go).
    pub tls_server_name: Option<String>,
}

impl HopContext {
    pub fn new(server: &crate::address::NetLocation) -> Self {
        let dialled_address = match server.address() {
            crate::address::Address::Ipv6(ip) => format!("[{ip}]:{}", server.port()),
            _ => server.to_string(),
        };
        Self {
            dialled_address,
            tls_server_name: None,
        }
    }

    fn under_tls(&self, server_name: Option<String>) -> Self {
        Self {
            dialled_address: self.dialled_address.clone(),
            tls_server_name: server_name,
        }
    }
}

pub fn create_tcp_client_handler(
    client_proxy_config: ClientProxyConfig,
    default_sni_hostname: Option<String>,
    hop: &HopContext,
    resolver: Arc<dyn Resolver>,
) -> Box<dyn TcpClientHandler> {
    match client_proxy_config {
        ClientProxyConfig::Direct => {
            panic!("Tried to create a direct tcp client handler");
        }
        ClientProxyConfig::Http {
            username,
            password,
            resolve_hostname,
        } => {
            let http_resolver = if resolve_hostname {
                Some(resolver.clone())
            } else {
                None
            };
            Box::new(HttpTcpClientHandler::new(
                create_auth_credentials(username, password.map(Redacted::into_inner)),
                http_resolver,
            ))
        }
        ClientProxyConfig::Socks { username, password } => Box::new(SocksTcpClientHandler::new(
            create_auth_credentials(username, password.map(Redacted::into_inner)).as_ref(),
        )),
        ClientProxyConfig::Shadowsocks {
            config,
            udp_enabled,
        } => match config {
            ShadowsocksConfig::Legacy { cipher, password } => Box::new(
                ShadowsocksTcpHandler::new_client(cipher, &password, udp_enabled),
            ),
            ShadowsocksConfig::Aead2022 { cipher, key_bytes } => Box::new(
                ShadowsocksTcpHandler::new_aead2022_client(cipher, &key_bytes, udp_enabled),
            ),
        },
        ClientProxyConfig::Snell {
            config: ShadowsocksConfig::Legacy { cipher, password },
            udp_enabled,
        } => Box::new(SnellClientHandler::new(cipher, &password, udp_enabled)),
        ClientProxyConfig::Snell {
            config: ShadowsocksConfig::Aead2022 { .. },
            ..
        } => {
            panic!(
                "Snell does not support shadowsocks 2022 ciphers (checked during config validation)"
            )
        }
        ClientProxyConfig::Vless {
            user_id,
            udp_enabled,
            h2mux,
        } => {
            let handler: Box<dyn TcpClientHandler> =
                Box::new(VlessTcpClientHandler::new(&user_id, udp_enabled));
            if let Some(h2mux_config) = h2mux {
                Box::new(H2MuxClientHandler::new(
                    Arc::from(handler),
                    h2mux_config.to_options(),
                ))
            } else {
                handler
            }
        }
        ClientProxyConfig::Mieru(mieru) => Box::new(crate::mieru::client::MieruTcpHandler::new(
            &mieru.username,
            mieru.password.expose(),
        )),
        ClientProxyConfig::Trojan {
            password,
            shadowsocks,
            h2mux,
        } => {
            let handler: Box<dyn TcpClientHandler> =
                Box::new(TrojanTcpHandler::new_client(&password, &shadowsocks));
            if let Some(h2mux_config) = h2mux {
                Box::new(H2MuxClientHandler::new(
                    Arc::from(handler),
                    h2mux_config.to_options(),
                ))
            } else {
                handler
            }
        }
        ClientProxyConfig::Tls(tls_client_config) => {
            let TlsClientConfig {
                verify,
                server_fingerprints,
                sni_hostname,
                alpn_protocols,
                tls_buffer_size,
                protocol,
                key,
                cert,
                vision,
            } = tls_client_config;

            let sni_hostname = if sni_hostname.is_unspecified() {
                if let Some(ref hostname) = default_sni_hostname {
                    debug!(
                        "Using default sni hostname for TLS client connection: {}",
                        hostname
                    );
                }
                default_sni_hostname
            } else {
                sni_hostname.into_option()
            };
            let inner_hop = hop.under_tls(sni_hostname.clone());

            let key_and_cert_bytes = key.zip(cert).map(|(key, cert)| {
                // Certificates are already embedded as PEM data during config validation
                let cert_bytes = cert.as_bytes().to_vec();
                let key_bytes = key.as_bytes().to_vec();

                (key_bytes, cert_bytes)
            });

            let client_config = Arc::new(create_client_config(
                verify,
                &server_fingerprints.into_vec(),
                &alpn_protocols.into_vec(),
                sni_hostname.is_some(),
                key_and_cert_bytes,
                false, // tls13_only
            ));

            let server_name = match sni_hostname {
                Some(s) => rustls::pki_types::ServerName::try_from(s).unwrap(),
                // This is unused, since enable_sni is false, but connect_with still requires a
                // parameter.
                None => "example.com".try_into().unwrap(),
            };

            if vision {
                let ClientProxyConfig::Vless {
                    user_id,
                    udp_enabled,
                    h2mux: _, // h2mux not supported with vision
                } = protocol.as_ref()
                else {
                    // Validated when loading config
                    unreachable!();
                };
                let user_id_bytes = parse_uuid(user_id)
                    .expect("Invalid user_id UUID")
                    .into_boxed_slice();
                Box::new(TlsClientHandler::new_vision_vless(
                    client_config,
                    tls_buffer_size,
                    server_name,
                    user_id_bytes,
                    *udp_enabled,
                ))
            } else {
                let handler =
                    create_tcp_client_handler(*protocol, None, &inner_hop, resolver.clone());

                Box::new(TlsClientHandler::new(
                    client_config,
                    tls_buffer_size,
                    server_name,
                    handler,
                ))
            }
        }
        ClientProxyConfig::Reality {
            public_key,
            short_id,
            sni_hostname,
            cipher_suites,
            vision,
            protocol,
        } => {
            // Decode public key from base64url
            let public_key_bytes =
                crate::reality::decode_public_key(&public_key).expect("Invalid REALITY public key");

            // Decode short ID from hex string
            let short_id_bytes =
                crate::reality::decode_short_id(&short_id).expect("Invalid REALITY short_id");

            // Determine SNI hostname
            let sni_hostname = sni_hostname.or(default_sni_hostname.clone());
            let inner_hop = hop.under_tls(sni_hostname.clone());
            let server_name = match sni_hostname {
                Some(s) => rustls::pki_types::ServerName::try_from(s)
                    .unwrap()
                    .to_owned(),
                None => {
                    panic!("REALITY client requires sni_hostname to be specified");
                }
            };

            let cipher_suites = cipher_suites.into_vec();

            if vision {
                let ClientProxyConfig::Vless {
                    user_id,
                    udp_enabled,
                    h2mux: _, // h2mux not supported with vision
                } = protocol.as_ref()
                else {
                    unreachable!("Vision requires VLESS (should be validated during config load)")
                };
                let user_id_bytes = parse_uuid(user_id)
                    .expect("Invalid user_id UUID")
                    .into_boxed_slice();
                Box::new(
                    crate::reality_client_handler::RealityClientHandler::new_vision_vless(
                        public_key_bytes,
                        short_id_bytes,
                        server_name,
                        cipher_suites,
                        user_id_bytes,
                        *udp_enabled,
                    ),
                )
            } else {
                let inner_handler =
                    create_tcp_client_handler(*protocol, None, &inner_hop, resolver.clone());
                Box::new(crate::reality_client_handler::RealityClientHandler::new(
                    public_key_bytes,
                    short_id_bytes,
                    server_name,
                    cipher_suites,
                    inner_handler,
                ))
            }
        }
        ClientProxyConfig::ShadowTls {
            password,
            sni_hostname,
            protocol,
        } => {
            let sni_hostname = sni_hostname.or(default_sni_hostname);
            let enable_sni = sni_hostname.is_some();

            let server_name = match sni_hostname {
                Some(s) => rustls::pki_types::ServerName::try_from(s).unwrap(),
                None => "example.com".try_into().unwrap(), // Fallback
            };

            // Create TLS config for ShadowTLS - must be TLS 1.3 only.
            // ShadowTLS v3 requires TLS 1.3: we modify the ClientHello session_id to embed
            // an HMAC tag, and rustls doesn't validate session_id echo for TLS 1.3 ServerHello.
            // TLS 1.2 would fail anyway (no supported_versions extension), but restricting
            // here provides defense in depth and fails fast at the TLS level.
            let client_config = Arc::new(create_client_config(
                false,      // No WebPKI verification needed for ShadowTLS
                &[],        // No fingerprints
                &[],        // No ALPN
                enable_sni, // Enable SNI if hostname provided
                None,       // No client cert
                true,       // tls13_only - required for ShadowTLS v3
            ));

            let handler = create_tcp_client_handler(*protocol, None, hop, resolver.clone());

            Box::new(ShadowTlsClientHandler::new(
                password.into_inner(),
                client_config,
                server_name,
                handler,
            ))
        }
        ClientProxyConfig::Vmess {
            cipher,
            user_id,
            udp_enabled,
            h2mux,
        } => {
            let handler: Box<dyn TcpClientHandler> =
                Box::new(VmessTcpClientHandler::new(&cipher, &user_id, udp_enabled));
            if let Some(h2mux_config) = h2mux {
                Box::new(H2MuxClientHandler::new(
                    Arc::from(handler),
                    h2mux_config.to_options(),
                ))
            } else {
                handler
            }
        }
        ClientProxyConfig::Websocket(websocket_client_config) => {
            let WebsocketClientConfig {
                matching_path,
                matching_headers,
                ping_type,
                protocol,
            } = websocket_client_config;

            let handler = create_tcp_client_handler(*protocol, None, hop, resolver.clone());

            Box::new(WebsocketTcpClientHandler::new(
                hop.dialled_address.clone(),
                matching_path,
                matching_headers.map(|h| h.into_iter().collect()),
                ping_type,
                handler,
            ))
        }
        ClientProxyConfig::HttpUpgrade(httpupgrade_client_config) => {
            let HttpUpgradeClientConfig {
                host,
                matching_path,
                matching_headers,
                protocol,
            } = httpupgrade_client_config;

            let handler = create_tcp_client_handler(*protocol, None, hop, resolver.clone());

            Box::new(HttpUpgradeTcpClientHandler::new(
                host.or_else(|| hop.tls_server_name.clone())
                    .unwrap_or_else(|| hop.dialled_address.clone()),
                matching_path,
                matching_headers.map(|h| h.into_iter().collect()),
                handler,
            ))
        }
        ClientProxyConfig::PortForward => Box::new(PortForwardClientHandler),
        ClientProxyConfig::Anytls {
            password,
            udp_enabled,
            padding_scheme,
        } => {
            let padding = match padding_scheme {
                Some(lines) => {
                    let scheme = lines.join("\n");
                    Arc::new(
                        PaddingFactory::new(scheme.as_bytes())
                            .expect("Invalid padding scheme in AnyTLS config"),
                    )
                }
                None => PaddingFactory::default_factory(),
            };
            Box::new(AnyTlsClientHandler::new(
                password.into_inner(),
                padding,
                udp_enabled,
            ))
        }
        ClientProxyConfig::Naiveproxy {
            username,
            password,
            padding,
        } => Box::new(NaiveProxyTcpClientHandler::new(
            &username, &password, padding,
        )),
        other @ (ClientProxyConfig::Wireguard(..)
        | ClientProxyConfig::AmneziaWg(..)
        | ClientProxyConfig::Hysteria2(..)
        | ClientProxyConfig::Tuic(..)) => {
            panic!(
                "{} owns its transport and should not use TcpClientHandler. \
                    It must be handled as a TerminalConnector in the chain builder.",
                other.protocol_name()
            )
        }
    }
}

pub fn create_tcp_client_proxy_selector(
    rules: Vec<RuleConfig>,
    resolver: Arc<dyn Resolver>,
) -> ClientProxySelector {
    let rules = rules
        .into_iter()
        .map(|rule_config| {
            let RuleConfig {
                masks,
                loaded_rule_sets,
                action,
                ..
            } = rule_config;
            let connect_action = match action {
                RuleActionConfig::Allow {
                    override_address,
                    client_chains,
                } => {
                    let chain_group = build_client_chain_group(client_chains, resolver.clone());
                    ConnectAction::new_allow(override_address, chain_group)
                }
                RuleActionConfig::Block => ConnectAction::new_block(),
            };
            ConnectRule::new(masks.into_vec(), loaded_rule_sets, connect_action)
        })
        .collect::<Vec<_>>();
    ClientProxySelector::new(rules)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::NetLocation;

    #[test]
    fn the_dialled_address_brackets_an_ipv6_host() {
        let v6 = NetLocation::from_str("[2001:db8::1]:443", None).unwrap();
        assert_eq!(HopContext::new(&v6).dialled_address, "[2001:db8::1]:443");
        let name = NetLocation::from_str("proxy.example.com:8443", None).unwrap();
        assert_eq!(
            HopContext::new(&name).dialled_address,
            "proxy.example.com:8443"
        );
    }

    #[test]
    fn under_tls_keeps_the_dialled_address() {
        let hop = HopContext::new(&NetLocation::from_str("1.2.3.4:443", None).unwrap())
            .under_tls(Some("cdn.example.com".to_string()));
        assert_eq!(hop.dialled_address, "1.2.3.4:443");
        assert_eq!(hop.tls_server_name.as_deref(), Some("cdn.example.com"));
    }
}
