//! The pipeline every host runs a configuration through: load the
//! certificates it names, validate it, build its DNS resolvers, then start
//! its servers. The `shoes` binary runs it directly; the TUN hosts run it
//! through [`super::prepare_from_config`] and friends, which add the device.

use log::{debug, info};
use tokio::task::JoinHandle;

use crate::config::{Config, ValidatedConfigs, convert_cert_paths, create_server_configs};
use crate::connections::ConnectionSet;
use crate::dns::{DnsRegistry, build_dns_registry};
use crate::outbound_stats::OutboundSet;
use crate::tcp::tcp_server::start_servers;

/// A configuration that has loaded, validated and built its resolvers, and
/// has not started anything.
pub struct PreparedServers {
    pub(super) configs: Vec<Config>,
    pub(super) dns_registry: DnsRegistry,
    pub(super) outbounds: OutboundSet,
}

impl PreparedServers {
    /// How many servers [`launch_servers`] will start.
    pub fn len(&self) -> usize {
        self.configs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.configs.is_empty()
    }
}

/// Which step of [`prepare_servers`] failed. `Display` names the step, for a
/// host that prints the error; converting to `io::Error` keeps the step's
/// own error as it was, which is what the FFI and gRPC hosts report.
#[derive(Debug)]
pub enum PrepareError {
    Certificates(std::io::Error),
    Validation(std::io::Error),
    Dns(std::io::Error),
}

impl std::fmt::Display for PrepareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Certificates(e) => write!(f, "Failed to load cert files: {e}"),
            Self::Validation(e) => write!(f, "Failed to create server configs: {e}"),
            Self::Dns(e) => write!(f, "Failed to build DNS registry: {e}"),
        }
    }
}

impl std::error::Error for PrepareError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Certificates(e) | Self::Validation(e) | Self::Dns(e) => Some(e),
        }
    }
}

impl From<PrepareError> for std::io::Error {
    fn from(e: PrepareError) -> Self {
        match e {
            PrepareError::Certificates(e) | PrepareError::Validation(e) | PrepareError::Dns(e) => e,
        }
    }
}

/// Load the certificates `configs` name, validate them, and build their
/// resolvers. Nothing is installed or started.
pub async fn prepare_servers(configs: Vec<Config>) -> Result<PreparedServers, PrepareError> {
    let (configs, pem_count) = convert_cert_paths(configs)
        .await
        .map_err(PrepareError::Certificates)?;
    if pem_count > 0 {
        info!("Loaded {pem_count} certs/keys from files");
    }

    for config in configs.iter() {
        debug!("{config:#?}");
    }

    let ValidatedConfigs {
        configs,
        dns_groups,
        outbounds,
    } = create_server_configs(configs).map_err(PrepareError::Validation)?;

    let dns_registry = build_dns_registry(dns_groups)
        .await
        .map_err(PrepareError::Dns)?;

    Ok(PreparedServers {
        configs,
        dns_registry,
        outbounds,
    })
}

/// Publish the outbounds a configuration runs, replacing the previous
/// configuration's: a reload must not carry its servers into the new list.
pub(super) fn install_outbounds(outbounds: &OutboundSet) {
    crate::outbound_stats::install(outbounds);
}

/// Start every server in `configs`, each with the resolver its `dns:` block
/// names. If one fails to start, the ones already started are stopped and
/// awaited before the error returns.
pub(super) async fn start_configs(
    configs: Vec<Config>,
    dns_registry: &mut DnsRegistry,
    connections: &ConnectionSet,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    let mut join_handles: Vec<JoinHandle<()>> = vec![];
    for config in configs {
        let resolver = match &config {
            Config::Server(s) => dns_registry.get_for_server(s.dns.as_ref()),
            Config::TunServer(t) => dns_registry.get_for_tun(t.dns.as_ref()),
            _ => dns_registry.get_for_server(None),
        };
        match start_servers(config, resolver, connections).await {
            Ok(handles) => join_handles.extend(handles),
            Err(e) => {
                for handle in &join_handles {
                    handle.abort();
                }
                for handle in join_handles {
                    let _ = handle.await;
                }
                connections.abort().await;
                return Err(e);
            }
        }
    }
    Ok(join_handles)
}

/// How a running configuration's live connections end when it is replaced
/// or stopped.
#[derive(Debug, Clone, Copy)]
pub enum Ending {
    /// Let them finish for up to this long, then cancel the rest.
    Drain(std::time::Duration),
    /// Cancel them now.
    Abort,
}

/// A launched configuration: its accept loops, and the connections they
/// accepted.
pub struct Launched {
    accept_loops: Vec<JoinHandle<()>>,
    connections: ConnectionSet,
}

impl Launched {
    /// The connections this launch accepted.
    pub fn connections(&self) -> &ConnectionSet {
        &self.connections
    }

    /// Stop accepting, and wait until the listening sockets are released --
    /// a replacement binds the same addresses next. Live connections are not
    /// touched.
    pub async fn stop_accepting(&mut self) {
        for handle in &self.accept_loops {
            handle.abort();
        }
        for handle in self.accept_loops.drain(..) {
            let _ = handle.await;
        }
    }

    /// Stop accepting, then end the live connections as `ending` says.
    /// Returns how many were cancelled.
    pub async fn end(mut self, ending: Ending) -> usize {
        self.stop_accepting().await;
        match ending {
            Ending::Drain(grace) => self.connections.drain(grace).await,
            Ending::Abort => {
                let live = self.connections.len();
                self.connections.abort().await;
                live
            }
        }
    }
}

/// Publish the outbounds and start every server, TUN entries included./// Publish the outbounds and start every server, TUN entries included.
pub async fn launch_servers(prepared: PreparedServers) -> std::io::Result<Launched> {
    let PreparedServers {
        configs,
        mut dns_registry,
        outbounds,
    } = prepared;
    install_outbounds(&outbounds);
    let connections = ConnectionSet::new();
    let accept_loops = start_configs(configs, &mut dns_registry, &connections).await?;
    Ok(Launched {
        accept_loops,
        connections,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    // The registry lock is held across the launch's awaits on purpose: the
    // launch installs this config's outbounds into the process-global
    // registry, and a registry test running meanwhile would read them. A
    // `#[tokio::test]` runtime is current-thread, so nothing here is starved.
    #[allow(clippy::await_holding_lock)]
    async fn launch_socks_on_a_free_port() -> (Launched, std::net::SocketAddr) {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);
        let yaml = format!("- address: {addr}\n  protocol:\n    type: socks\n");
        let configs = crate::config::load_config_str(&yaml).unwrap();
        let _registry = crate::outbound_stats::REGISTRY_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prepared = prepare_servers(configs).await.unwrap();
        (launch_servers(prepared).await.unwrap(), addr)
    }

    async fn wait_for(launched: &Launched, live: usize) {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        while launched.connections().len() != live {
            assert!(
                tokio::time::Instant::now() < deadline,
                "never reached {live} live"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    /// A reload used to stop the accept loops and leave live connections
    /// running on the old configuration with nothing owning them. They are
    /// in the launch's set now: they survive the listener closing, and a
    /// drain past its grace cancels them.
    #[tokio::test]
    async fn a_launchs_connections_outlive_its_listener_until_drained() {
        let (mut launched, addr) = launch_socks_on_a_free_port().await;
        // Silent after connecting: the SOCKS handshake waits for the
        // greeting, so the connection stays live until it is cancelled.
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        wait_for(&launched, 1).await;

        launched.stop_accepting().await;
        assert_eq!(
            launched.connections().len(),
            1,
            "closing the listener kept it"
        );
        assert!(
            tokio::net::TcpStream::connect(addr).await.is_err(),
            "the port no longer accepts"
        );

        let cancelled = launched
            .end(Ending::Drain(std::time::Duration::from_millis(50)))
            .await;
        assert_eq!(cancelled, 1);
        let mut byte = [0u8; 1];
        let read = tokio::time::timeout(std::time::Duration::from_secs(2), client.read(&mut byte))
            .await
            .expect("the cancelled connection is closed, not left hanging");
        assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
    }

    #[tokio::test]
    async fn an_abort_ends_live_connections_at_once() {
        let (launched, addr) = launch_socks_on_a_free_port().await;
        let _client = tokio::net::TcpStream::connect(addr).await.unwrap();
        wait_for(&launched, 1).await;
        let started = tokio::time::Instant::now();
        assert_eq!(launched.end(Ending::Abort).await, 1);
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }
}
