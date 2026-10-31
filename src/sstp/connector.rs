//! The SSTP outbound as a `TerminalConnector`: one session per hop, shared
//! by every connection through it, carried by the same smoltcp stack
//! AmneziaWG uses.
//!
//! The lifecycle is AmneziaWG's (`src/amneziawg/connector.rs`): the session
//! is built on the first connection, rebuilt when it has died, and a failed
//! build fails new connections fast for a cooldown instead of redialling and
//! re-authenticating once per inbound connection.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use async_trait::async_trait;
use log::{debug, info};
use tokio::sync::{Mutex, mpsc, oneshot};

use super::handshake::{self, Settings};
use super::ppp::AuthMethod;
use super::session::{self, Channels, SessionState};
use crate::address::{NetLocation, ResolvedLocation};
use crate::async_stream::AsyncMessageStream;
use crate::config::{SstpAuthMethod, SstpClientConfig};
use crate::netstack::{NetStackRequest, VirtualNetStack};
use crate::resolver::{self, Resolver};
use crate::tcp::tcp_handler::TcpClientSetupResult;
use crate::tcp::terminal_connector::TerminalConnector;

/// How long after a failed build the next connection fails fast. As for
/// AmneziaWG: long enough to stop per-connection churn against a server that
/// is down or refusing the credentials, short enough to notice it is back.
const REBUILD_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(3);

struct Live {
    state: Arc<SessionState>,
    request_tx: mpsc::Sender<NetStackRequest>,
    netstack_abort: tokio::task::AbortHandle,
}

impl Live {
    fn usable(&self) -> bool {
        !self.state.is_dead() && !self.request_tx.is_closed()
    }
}

impl Drop for Live {
    /// The outbound is going away, or the session is being replaced: say
    /// goodbye to the server if the connection is still up, and stop the
    /// netstack, whose streams end with the session.
    fn drop(&mut self) {
        self.state.stop();
        self.netstack_abort.abort();
    }
}

#[derive(Default)]
struct ConnectorState {
    live: Option<Live>,
    last_attempt_failed_at: Option<std::time::Instant>,
}

pub struct SstpConnector {
    template: Settings,
    state: Mutex<ConnectorState>,
}

impl std::fmt::Debug for SstpConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SstpConnector")
            .field("address", &self.template.address)
            .finish()
    }
}

impl SstpConnector {
    pub fn new(
        address: NetLocation,
        config: SstpClientConfig,
        bind_interface: Option<String>,
        no_delay: bool,
    ) -> std::io::Result<Self> {
        // The name the certificate is checked against: `sni_hostname` when
        // set, else the bare hostname or literal (rustls takes an IPv6
        // literal without brackets).
        let bare = address.address().to_string();
        let (tls, server_name) = handshake::tls_settings(&config.tls, Some(&bare))?;
        // The `Host` header names the same server, as a browser's does: a
        // client that resolves the name itself and dials the literal keeps
        // the name in `sni_hostname`, and a `Host` built from the literal
        // 404s at a server that routes on it, which here reads as
        // camouflage. An IPv6 literal keeps its brackets, and the port
        // follows unless it is the scheme's default (RFC 7230 §5.4).
        let host = match &server_name {
            rustls::pki_types::ServerName::IpAddress(ip)
                if std::net::IpAddr::from(*ip).is_ipv6() =>
            {
                format!("[{}]", server_name.to_str())
            }
            _ => server_name.to_str().into_owned(),
        };
        let host = match address.port() {
            443 => host,
            port => format!("{host}:{port}"),
        };
        let methods = config
            .auth
            .iter()
            .map(|method| match method {
                SstpAuthMethod::Mschapv2 => AuthMethod::MsChapV2,
                SstpAuthMethod::Pap => AuthMethod::Pap,
            })
            .collect();
        Ok(SstpConnector {
            template: Settings {
                address,
                host,
                tls,
                server_name,
                bind_interface,
                no_delay,
                username: config.username,
                password: config.password,
                methods,
                mtu: config.mtu,
                camouflage_secret: config.camouflage_secret,
                connect_attempt_timeout: handshake::CONNECT_ATTEMPT_TIMEOUT,
            },
            state: Mutex::new(ConnectorState::default()),
        })
    }

    /// Whether a usable session is up, for tests that wait on its end.
    #[cfg(test)]
    pub async fn session_alive(&self) -> bool {
        self.state
            .lock()
            .await
            .live
            .as_ref()
            .is_some_and(Live::usable)
    }

    /// Ring this session's network-change listener, as
    /// `network_change::notify` would. Not the global call: tests run as
    /// threads of one process, and it would end every other test's session.
    #[cfg(test)]
    pub async fn network_changed(&self) {
        use crate::network_change::NetworkChangeListener;
        if let Some(live) = &self.state.lock().await.live {
            let listener: Arc<dyn NetworkChangeListener> = live.state.clone();
            assert!(
                crate::network_change::is_registered(&listener),
                "the session registered for network changes"
            );
            live.state.network_changed();
        }
    }

    /// Shorten the per-address connect attempt, for the test that stalls
    /// one; the default is ten seconds.
    #[cfg(test)]
    pub fn connect_attempt_timeout(&mut self, timeout: std::time::Duration) {
        self.template.connect_attempt_timeout = timeout;
    }

    /// Dial a different server with the same settings, for the test that
    /// checks a pin refuses the wrong certificate.
    #[cfg(test)]
    pub fn point_at(&mut self, address: NetLocation) {
        self.template.address = address;
    }

    async fn ensure_session(
        &self,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<mpsc::Sender<NetStackRequest>> {
        let mut state = self.state.lock().await;
        if let Some(live) = &state.live {
            if live.usable() {
                return Ok(live.request_tx.clone());
            }
            info!(
                "SSTP: the session to {} ended; reconnecting",
                self.template.address
            );
            state.live = None;
        }
        if let Some(failed_at) = state.last_attempt_failed_at
            && failed_at.elapsed() < REBUILD_COOLDOWN
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "SSTP session setup failed moments ago; next attempt after the cooldown",
            ));
        }
        match self.build(resolver).await {
            Ok(live) => {
                let request_tx = live.request_tx.clone();
                state.last_attempt_failed_at = None;
                state.live = Some(live);
                Ok(request_tx)
            }
            Err(e) => {
                state.last_attempt_failed_at = Some(std::time::Instant::now());
                Err(e)
            }
        }
    }

    async fn build(&self, resolver: &Arc<dyn Resolver>) -> std::io::Result<Live> {
        let t = &self.template;
        let servers = resolver::resolve_addresses(resolver, &t.address).await?;
        let established = handshake::establish(t, &servers).await?;
        // What this side may send (the server's MRU), what it may receive
        // (its own MRU as acknowledged), and what was configured.
        let mtu = established
            .link
            .peer_mru
            .min(established.link.local_mru)
            .min(t.mtu);

        let (ip_to_tunnel_tx, ip_to_tunnel_rx) =
            mpsc::channel(crate::buffer_sizing::default_outbound_queue_depth());
        // A full inbound channel makes the reader wait rather than drop; see
        // `session.rs`.
        let (ip_from_tunnel_tx, ip_from_tunnel_rx) =
            mpsc::channel(crate::buffer_sizing::default_inbound_queue_depth());
        let netstack = VirtualNetStack::new(
            &[(IpAddr::V4(established.link.address), 32)],
            mtu,
            ip_to_tunnel_tx,
            ip_from_tunnel_rx,
            // AmneziaWG's liveness watchdog reads this; SSTP's liveness is
            // the hello timer.
            Arc::new(AtomicUsize::new(0)),
        );
        let (request_tx, request_rx) = mpsc::channel::<NetStackRequest>(64);
        let netstack_task = tokio::spawn(async move {
            netstack.run(request_rx).await;
        });

        let state = session::spawn(
            established,
            Channels {
                ip_to_tunnel: ip_to_tunnel_rx,
                ip_from_tunnel: ip_from_tunnel_tx,
            },
            mtu,
        );
        let listener: Arc<dyn crate::network_change::NetworkChangeListener> = state.clone();
        crate::network_change::register(Arc::downgrade(&listener));

        Ok(Live {
            state,
            request_tx,
            netstack_abort: netstack_task.abort_handle(),
        })
    }
}

/// The destination's IPv4 address. The session negotiated IPv4 only, so a
/// name is answered with its first IPv4 address, not its first address: a
/// live run's first request resolved to an IPv6 address the tunnel could
/// not carry, though the name had IPv4 ones too.
async fn resolve_target(
    resolver: &Arc<dyn Resolver>,
    target: &ResolvedLocation,
) -> std::io::Result<SocketAddr> {
    let addresses = match target.resolved_addr() {
        // The rule engine resolves a name to match it against an IP mask and
        // keeps the first address, which on a dual-stack host is an IPv6
        // one; the name may have IPv4 addresses too. A literal has only
        // itself.
        Some(addr) if addr.is_ipv4() || target.location().address().hostname().is_none() => {
            vec![addr]
        }
        _ => resolver::resolve_addresses(resolver, target.location()).await?,
    };
    addresses
        .iter()
        .copied()
        .find(SocketAddr::is_ipv4)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                format!(
                    "SSTP carries IPv4 only, and {} has no IPv4 address",
                    target.location()
                ),
            )
        })
}

fn stopped() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::BrokenPipe, "SSTP session stopped")
}

#[async_trait]
impl TerminalConnector for SstpConnector {
    async fn connect_tcp(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        let request_tx = self.ensure_session(resolver).await?;
        let target = resolve_target(resolver, &target).await?;
        debug!("SSTP: TCP connect to {target}");
        let (reply, reply_rx) = oneshot::channel();
        request_tx
            .send(NetStackRequest::ConnectTcp { target, reply })
            .await
            .map_err(|_| stopped())?;
        let stream = reply_rx.await.map_err(|_| stopped())??;
        Ok(TcpClientSetupResult {
            client_stream: Box::new(stream),
            early_data: None,
        })
    }

    async fn connect_udp_bidirectional(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        let request_tx = self.ensure_session(resolver).await?;
        let target = resolve_target(resolver, &target).await?;
        debug!("SSTP: UDP connect to {target}");
        let (reply, reply_rx) = oneshot::channel();
        request_tx
            .send(NetStackRequest::ConnectUdp { target, reply })
            .await
            .map_err(|_| stopped())?;
        let stream = reply_rx.await.map_err(|_| stopped())??;
        Ok(Box::new(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> SstpClientConfig {
        SstpClientConfig {
            username: "alice".into(),
            password: "pw".to_string().into(),
            auth: vec![SstpAuthMethod::Mschapv2],
            mtu: 1280,
            tls: crate::config::SstpTlsConfig::default(),
            camouflage_secret: None,
        }
    }

    /// RFC 7230 §5.4: an IPv6 literal in `Host` keeps its brackets. A
    /// hostname and an IPv4 literal are themselves.
    #[test]
    fn the_host_header_brackets_an_ipv6_literal() {
        for (address, host) in [
            ("vpn.example.com:443", "vpn.example.com"),
            ("192.0.2.1:443", "192.0.2.1"),
            ("[2001:db8::1]:443", "[2001:db8::1]"),
            ("vpn.example.com:8443", "vpn.example.com:8443"),
            ("[2001:db8::1]:8443", "[2001:db8::1]:8443"),
        ] {
            let location = NetLocation::from_str(address, None).unwrap();
            let connector = SstpConnector::new(location, config(), None, true).unwrap();
            assert_eq!(connector.template.host, host, "{address}");
            let literal = !host.starts_with('v');
            assert_eq!(
                matches!(
                    connector.template.server_name,
                    rustls::pki_types::ServerName::IpAddress(_)
                ),
                literal,
                "{address}: a literal is verified as an IP address, a name as a DNS name"
            );
        }
    }

    /// A client that resolves the name itself dials the literal and keeps
    /// the name in `sni_hostname`; `Host` follows the name, so a server that
    /// routes on it still finds its site. `""` sends no SNI, and then the
    /// address is all there is to name.
    #[test]
    fn the_host_header_follows_the_sni_hostname() {
        for (address, sni, host) in [
            ("192.0.2.1:443", Some("vpn.example.com"), "vpn.example.com"),
            (
                "192.0.2.1:8443",
                Some("vpn.example.com"),
                "vpn.example.com:8443",
            ),
            (
                "[2001:db8::1]:443",
                Some("vpn.example.com"),
                "vpn.example.com",
            ),
            ("vpn.example.com:443", Some("2001:db8::1"), "[2001:db8::1]"),
            ("192.0.2.1:443", Some(""), "192.0.2.1"),
            ("192.0.2.1:443", None, "192.0.2.1"),
        ] {
            let mut config = config();
            if let Some(sni) = sni {
                config.tls.sni_hostname = crate::option_util::NoneOrOne::One(sni.to_string());
            }
            let location = NetLocation::from_str(address, None).unwrap();
            let connector = SstpConnector::new(location, config, None, true).unwrap();
            assert_eq!(connector.template.host, host, "{address} with {sni:?}");
        }
    }
}
