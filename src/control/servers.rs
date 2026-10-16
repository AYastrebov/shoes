//! The pipeline every host runs a configuration through: load the
//! certificates it names, validate it, build its DNS resolvers, then start
//! its servers. The `shoes` binary runs it directly; the TUN hosts run it
//! through [`super::prepare_from_config`] and friends, which add the device.

use log::{debug, info};
use tokio::task::JoinHandle;

use crate::config::{Config, ValidatedConfigs, convert_cert_paths, create_server_configs};
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
    #[cfg(feature = "control-stats")]
    crate::outbound_stats::install(outbounds);
    #[cfg(not(feature = "control-stats"))]
    let _ = outbounds;
}

/// Start every server in `configs`, each with the resolver its `dns:` block
/// names. If one fails to start, the ones already started are stopped and
/// awaited before the error returns.
pub(super) async fn start_configs(
    configs: Vec<Config>,
    dns_registry: &mut DnsRegistry,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    let mut join_handles: Vec<JoinHandle<()>> = vec![];
    for config in configs {
        let resolver = match &config {
            Config::Server(s) => dns_registry.get_for_server(s.dns.as_ref()),
            Config::TunServer(t) => dns_registry.get_for_tun(t.dns.as_ref()),
            _ => dns_registry.get_for_server(None),
        };
        match start_servers(config, resolver).await {
            Ok(handles) => join_handles.extend(handles),
            Err(e) => {
                for handle in &join_handles {
                    handle.abort();
                }
                for handle in join_handles {
                    let _ = handle.await;
                }
                return Err(e);
            }
        }
    }
    Ok(join_handles)
}

/// Publish the outbounds and start every server, TUN entries included.
pub async fn launch_servers(prepared: PreparedServers) -> std::io::Result<Vec<JoinHandle<()>>> {
    let PreparedServers {
        configs,
        mut dns_registry,
        outbounds,
    } = prepared;
    install_outbounds(&outbounds);
    start_configs(configs, &mut dns_registry).await
}
