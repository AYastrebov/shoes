//! The OpenConnect outbound as a `TerminalConnector`: one session per hop,
//! shared by every connection through it, carried by the shared smoltcp
//! stack. The lifecycle is SSTP's (`src/sstp/connector.rs`), plus the
//! session cookie, kept across rebuilds so a tunnel that dropped comes
//! back without a second authentication.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use async_trait::async_trait;
use log::{debug, info};
use tokio::sync::{Mutex, mpsc, oneshot};

use super::handshake::{self, Settings};
use super::session::{self, Channels, SessionState};
use crate::address::{NetLocation, ResolvedLocation};
use crate::async_stream::AsyncMessageStream;
use crate::config::{OpenConnectClientConfig, Redacted};
use crate::netstack::{NetStackRequest, VirtualNetStack};
use crate::resolver::{self, Resolver};
use crate::tcp::tcp_handler::TcpClientSetupResult;
use crate::tcp::terminal_connector::TerminalConnector;

/// How long after a failed build the next connection fails fast.
const REBUILD_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(3);

struct Live {
    state: Arc<SessionState>,
    request_tx: mpsc::Sender<NetStackRequest>,
    netstack_abort: tokio::task::AbortHandle,
    /// Which families the session carries, for the target's address.
    has_ipv4: bool,
    has_ipv6: bool,
}

impl Live {
    fn usable(&self) -> bool {
        !self.state.is_dead() && !self.request_tx.is_closed()
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        self.state.stop();
        self.netstack_abort.abort();
    }
}

#[derive(Default)]
struct ConnectorState {
    live: Option<Live>,
    last_attempt_failed_at: Option<std::time::Instant>,
    /// The cookies the last authentication earned, presented on a rebuild.
    cookies: Option<Vec<(String, Redacted<String>)>>,
}

pub struct OpenConnectConnector {
    template: Settings,
    state: Mutex<ConnectorState>,
}

impl std::fmt::Debug for OpenConnectConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenConnectConnector")
            .field("address", &self.template.address)
            .finish()
    }
}

impl OpenConnectConnector {
    pub fn new(
        address: NetLocation,
        config: OpenConnectClientConfig,
        bind_interface: Option<String>,
        no_delay: bool,
    ) -> std::io::Result<Self> {
        // As for SSTP: the certificate is checked against `sni_hostname` or
        // the address, and `Host` names the same server, with the port when
        // it is not 443 (`http.c:1426-1429`).
        let bare = address.address().to_string();
        let (tls, server_name) =
            crate::sstp::tls_settings(&config.tls, Some(&bare), "OpenConnect")?;
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
        Ok(OpenConnectConnector {
            template: Settings {
                address,
                host,
                tls,
                server_name,
                bind_interface,
                no_delay,
                username: config.username,
                password: config.password,
                group: config.group,
                path: config.path,
                mtu: config.mtu,
                camouflage_secret: config.camouflage_secret,
                connect_attempt_timeout: handshake::CONNECT_ATTEMPT_TIMEOUT,
            },
            state: Mutex::new(ConnectorState::default()),
        })
    }

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
    /// `network_change::notify` would, without ending every other test's
    /// session in the process.
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

    #[cfg(test)]
    pub fn point_at(&mut self, address: NetLocation) {
        self.template.address = address;
    }

    async fn ensure_session(&self, resolver: &Arc<dyn Resolver>) -> std::io::Result<Target> {
        let mut state = self.state.lock().await;
        if let Some(live) = &state.live {
            if live.usable() {
                return Ok(Target::of(live));
            }
            info!(
                "OpenConnect: the session to {} ended; reconnecting",
                self.template.address
            );
            state.live = None;
        }
        if let Some(failed_at) = state.last_attempt_failed_at
            && failed_at.elapsed() < REBUILD_COOLDOWN
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "OpenConnect session setup failed moments ago; next attempt after the cooldown",
            ));
        }
        let servers = resolver::resolve_addresses(resolver, &self.template.address).await?;
        let mut established =
            handshake::establish(&self.template, &servers, state.cookies.as_deref()).await;
        // `cstp.c:379-380`: a 401 to CONNECT is the cookie refused; the
        // credentials are still good, so authenticate again, once.
        if state.cookies.is_some()
            && established
                .as_ref()
                .is_err_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied)
        {
            info!(
                "OpenConnect: {} refused the session cookie; authenticating again",
                self.template.address
            );
            state.cookies = None;
            established = handshake::establish(&self.template, &servers, None).await;
        }
        match established {
            Ok(established) => {
                state.cookies = Some(established.cookies.clone());
                let live = build(established);
                let target = Target::of(&live);
                state.last_attempt_failed_at = None;
                state.live = Some(live);
                Ok(target)
            }
            Err(e) => {
                state.last_attempt_failed_at = Some(std::time::Instant::now());
                Err(e)
            }
        }
    }
}

/// What a connection needs from the session: the netstack and the families.
struct Target {
    request_tx: mpsc::Sender<NetStackRequest>,
    has_ipv4: bool,
    has_ipv6: bool,
}

impl Target {
    fn of(live: &Live) -> Self {
        Target {
            request_tx: live.request_tx.clone(),
            has_ipv4: live.has_ipv4,
            has_ipv6: live.has_ipv6,
        }
    }

    /// The destination's address in a family the session carries. IPv4
    /// first when both are: the rule engine resolves a name to its first
    /// address, an IPv6 one on a dual-stack host, and the name may have
    /// IPv4 ones too.
    async fn resolve(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: &ResolvedLocation,
    ) -> std::io::Result<SocketAddr> {
        let fits = |addr: &SocketAddr| {
            (addr.is_ipv4() && self.has_ipv4) || (addr.is_ipv6() && self.has_ipv6)
        };
        let addresses = match target.resolved_addr() {
            Some(addr) if fits(&addr) && (addr.is_ipv4() || !self.has_ipv4) => vec![addr],
            Some(addr) if target.location().address().hostname().is_none() => vec![addr],
            _ => resolver::resolve_addresses(resolver, target.location()).await?,
        };
        addresses
            .iter()
            .copied()
            .filter(fits)
            .max_by_key(|a| a.is_ipv4() == self.has_ipv4)
            .ok_or_else(|| {
                let families = match (self.has_ipv4, self.has_ipv6) {
                    (true, false) => "IPv4 only",
                    (false, true) => "IPv6 only",
                    _ => "IPv4 and IPv6",
                };
                std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    format!(
                        "OpenConnect: the session carries {families}, and {} has no such address",
                        target.location()
                    ),
                )
            })
    }
}

fn build(established: handshake::Established) -> Live {
    let link = &established.link;
    let mut addresses: Vec<(IpAddr, u8)> = Vec::new();
    if let Some((a, p)) = link.ipv4 {
        addresses.push((IpAddr::V4(a), p));
    }
    if let Some((a, p)) = link.ipv6 {
        addresses.push((IpAddr::V6(a), p));
    }
    let (ip_to_tunnel_tx, ip_to_tunnel_rx) =
        mpsc::channel(crate::buffer_sizing::default_outbound_queue_depth());
    let (ip_from_tunnel_tx, ip_from_tunnel_rx) =
        mpsc::channel(crate::buffer_sizing::default_inbound_queue_depth());
    let netstack = VirtualNetStack::new(
        &addresses,
        link.mtu,
        ip_to_tunnel_tx,
        ip_from_tunnel_rx,
        // AmneziaWG's liveness watchdog reads this; here DPD is the
        // liveness.
        Arc::new(AtomicUsize::new(0)),
    );
    let (request_tx, request_rx) = mpsc::channel::<NetStackRequest>(64);
    let netstack_task = tokio::spawn(async move {
        netstack.run(request_rx).await;
    });
    let has_ipv4 = link.ipv4.is_some();
    let has_ipv6 = link.ipv6.is_some();
    let state = session::spawn(
        established,
        Channels {
            ip_to_tunnel: ip_to_tunnel_rx,
            ip_from_tunnel: ip_from_tunnel_tx,
        },
    );
    let listener: Arc<dyn crate::network_change::NetworkChangeListener> = state.clone();
    crate::network_change::register(Arc::downgrade(&listener));
    Live {
        state,
        request_tx,
        netstack_abort: netstack_task.abort_handle(),
        has_ipv4,
        has_ipv6,
    }
}

fn stopped() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::BrokenPipe,
        "OpenConnect session stopped",
    )
}

#[async_trait]
impl TerminalConnector for OpenConnectConnector {
    async fn connect_tcp(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        let session = self.ensure_session(resolver).await?;
        let target = session.resolve(resolver, &target).await?;
        debug!("OpenConnect: TCP connect to {target}");
        let (reply, reply_rx) = oneshot::channel();
        session
            .request_tx
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
        let session = self.ensure_session(resolver).await?;
        let target = session.resolve(resolver, &target).await?;
        debug!("OpenConnect: UDP connect to {target}");
        let (reply, reply_rx) = oneshot::channel();
        session
            .request_tx
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

    fn config() -> OpenConnectClientConfig {
        OpenConnectClientConfig {
            username: "alice".into(),
            password: "pw".to_string().into(),
            group: None,
            path: "/".into(),
            mtu: 1280,
            tls: crate::config::SstpTlsConfig::default(),
            camouflage_secret: None,
        }
    }

    /// `Host` as for SSTP: the verified name, brackets for an IPv6 literal,
    /// the port when not 443, `sni_hostname` when set.
    #[test]
    fn the_host_header_names_the_verified_server() {
        for (address, sni, host) in [
            ("vpn.example.com:443", None, "vpn.example.com"),
            ("[2001:db8::1]:8443", None, "[2001:db8::1]:8443"),
            ("192.0.2.1:443", Some("vpn.example.com"), "vpn.example.com"),
            ("192.0.2.1:443", Some(""), "192.0.2.1"),
        ] {
            let mut config = config();
            if let Some(sni) = sni {
                config.tls.sni_hostname = crate::option_util::NoneOrOne::One(sni.to_string());
            }
            let location = NetLocation::from_str(address, None).expect("a location");
            let connector =
                OpenConnectConnector::new(location, config, None, true).expect("a connector");
            assert_eq!(connector.template.host, host, "{address} with {sni:?}");
        }
    }
}
