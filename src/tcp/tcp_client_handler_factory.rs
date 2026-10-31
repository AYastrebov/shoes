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

    /// An empty server name (REALITY's `sni_hostname: ""`, which sends none)
    /// is no name for the layers above either, so HTTPUpgrade falls back to
    /// the dialled address rather than sending an empty `Host`.
    fn under_tls(&self, server_name: Option<String>) -> Self {
        Self {
            dialled_address: self.dialled_address.clone(),
            tls_server_name: server_name.filter(|name| !name.is_empty()),
        }
    }

    /// The identity a server certificate is checked against when no server
    /// name is sent: the hop as dialled. `sni_hostname: ""` turns the SNI
    /// extension off, and so does dialling by address with no name
    /// configured, but neither turns WebPKI's name check off, so rustls has
    /// to be handed the name the certificate is expected to carry rather
    /// than a placeholder. For a dialled address that is an IP, that is the
    /// IP, which a certificate carries as an IP SAN.
    fn verification_identity(&self) -> rustls::pki_types::ServerName<'static> {
        use crate::address::Address;
        let dialled = crate::address::NetLocation::from_str(&self.dialled_address, None).ok();
        match dialled.as_ref().map(|location| location.address()) {
            Some(Address::Ipv4(ip)) => Some(rustls::pki_types::ServerName::IpAddress((*ip).into())),
            Some(Address::Ipv6(ip)) => Some(rustls::pki_types::ServerName::IpAddress((*ip).into())),
            Some(Address::Hostname(name)) => {
                rustls::pki_types::ServerName::try_from(name.clone()).ok()
            }
            None => None,
        }
        // Unreachable for a hop built by `HopContext::new`; rustls still
        // needs some name.
        .unwrap_or_else(|| "example.com".try_into().expect("a literal name"))
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
                Box::new(VlessTcpClientHandler::new(user_id.as_bytes(), udp_enabled));
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
                // `""` sends no server name, as it does for REALITY (SF-4);
                // rustls has no ServerName for it.
                sni_hostname.into_option().filter(|s| !s.is_empty())
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
                // Checked by `validate_tls_server_name` when the config loads.
                Some(s) => rustls::pki_types::ServerName::try_from(s)
                    .expect("validated when loading config"),
                // No SNI goes out, but the certificate is still checked
                // against a name when `verify` is on.
                None => hop.verification_identity(),
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
                let user_id_bytes: Box<[u8]> = Box::new(*user_id.as_bytes());
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
            client_version,
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
            // `""` and an IP address send no server_name (SF-4). A missing
            // one is refused by config validation (`validate_reality_sni`).
            let server_name =
                sni_hostname.expect("REALITY sni_hostname is checked by config validation");

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
                let user_id_bytes: Box<[u8]> = Box::new(*user_id.as_bytes());
                Box::new(
                    crate::reality_client_handler::RealityClientHandler::new_vision_vless(
                        public_key_bytes,
                        short_id_bytes,
                        server_name,
                        cipher_suites,
                        client_version,
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
                    client_version,
                    inner_handler,
                ))
            }
        }
        ClientProxyConfig::ShadowTls {
            password,
            sni_hostname,
            protocol,
        } => {
            // `""` sends no server name, as for TLS and REALITY.
            let sni_hostname = sni_hostname
                .or(default_sni_hostname)
                .filter(|s| !s.is_empty());
            let enable_sni = sni_hostname.is_some();

            let server_name = match sni_hostname {
                // Checked by `validate_tls_server_name` when the config loads.
                Some(s) => rustls::pki_types::ServerName::try_from(s)
                    .expect("validated when loading config"),
                // ShadowTLS never verifies the certificate, so this name is
                // only what rustls insists on being given.
                None => hop.verification_identity(),
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
            let handler: Box<dyn TcpClientHandler> = Box::new(VmessTcpClientHandler::new(
                &cipher,
                user_id.as_bytes(),
                udp_enabled,
            ));
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
                max_early_data,
                early_data_header_name,
                protocol,
            } = websocket_client_config;

            let handler = create_tcp_client_handler(*protocol, None, hop, resolver.clone());
            let early_data = (max_early_data > 0).then_some(crate::websocket::EarlyData {
                max: max_early_data,
                header_name: early_data_header_name,
            });

            Box::new(WebsocketTcpClientHandler::new(
                hop.dialled_address.clone(),
                matching_path,
                matching_headers.map(|h| h.into_iter().collect()),
                ping_type,
                early_data,
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
            min_idle_session,
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
                min_idle_session,
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
        | ClientProxyConfig::Tuic(..)
        | ClientProxyConfig::Sstp(..)
        | ClientProxyConfig::OpenConnect(..)) => {
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

    /// When no server name goes out, the certificate is checked against the
    /// hop as dialled, not against a placeholder that no certificate has.
    #[test]
    fn the_verification_identity_is_the_dialled_hop() {
        use rustls::pki_types::ServerName;
        let hop = |s: &str| HopContext::new(&NetLocation::from_str(s, None).unwrap());
        assert_eq!(
            hop("proxy.example.com:8443").verification_identity(),
            ServerName::try_from("proxy.example.com").unwrap()
        );
        assert_eq!(
            hop("1.2.3.4:443").verification_identity(),
            ServerName::IpAddress(std::net::Ipv4Addr::new(1, 2, 3, 4).into())
        );
        assert_eq!(
            hop("[2001:db8::1]:443").verification_identity(),
            ServerName::IpAddress("2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap().into())
        );
    }

    /// A TLS client built from config, handshaking with a rustls server that
    /// reports the name it was sent. `sni_hostname: ""` sends none and the
    /// handshake still completes; a name is sent as given.
    async fn sni_seen_by_the_server(sni_line: &str) -> Option<String> {
        use crate::crypto::{CryptoConnection, perform_crypto_handshake};
        use crate::rustls_config_util::create_server_config;

        let certified = rcgen::generate_simple_self_signed(vec!["tls.test".to_string()]).unwrap();
        let server_config = Arc::new(create_server_config(
            certified.cert.pem().as_bytes(),
            certified.signing_key.serialize_pem().as_bytes(),
            vec![],
            &[],
            &[],
        ));
        let client_config: ClientProxyConfig = serde_yaml::from_str(&format!(
            "type: tls\nverify: false\n{sni_line}protocol:\n    type: portforward\n"
        ))
        .unwrap();
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let hop = HopContext::new(&NetLocation::from_str("tls.test:443", None).unwrap());
        let client = create_tcp_client_handler(client_config, None, &hop, resolver);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (accepted, _) = listener.accept().await.unwrap();
            let mut stream: Box<dyn crate::async_stream::AsyncStream> = Box::new(accepted);
            let mut connection = CryptoConnection::new_rustls_server(
                rustls::ServerConnection::new(server_config).unwrap(),
            );
            perform_crypto_handshake(&mut connection, &mut stream, 16384)
                .await
                .unwrap();
            match connection {
                CryptoConnection::RustlsServer(conn) => conn.server_name().map(str::to_string),
                _ => unreachable!("a rustls server was built"),
            }
        });
        let connected = tokio::net::TcpStream::connect(addr).await.unwrap();
        let target = NetLocation::from_str("example.org:80", None).unwrap();
        client
            .setup_client_tcp_stream(Box::new(connected), target.into())
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(30), server)
            .await
            .expect("the server finished its handshake")
            .unwrap()
    }

    #[tokio::test]
    async fn an_empty_sni_hostname_sends_no_server_name() {
        assert_eq!(sni_seen_by_the_server("sni_hostname: \"\"\n").await, None);
    }

    #[tokio::test]
    async fn a_configured_sni_hostname_is_sent() {
        assert_eq!(
            sni_seen_by_the_server("sni_hostname: tls.test\n").await,
            Some("tls.test".to_string())
        );
    }

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

    #[test]
    fn an_empty_server_name_is_no_name_for_the_layers_above() {
        let hop = HopContext::new(&NetLocation::from_str("1.2.3.4:443", None).unwrap())
            .under_tls(Some(String::new()));
        assert_eq!(hop.tls_server_name, None);
    }
}
