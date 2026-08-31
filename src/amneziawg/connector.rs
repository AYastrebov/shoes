//! AmneziaWG virtual network connector implementation.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use log::{debug, info};
use tokio::sync::{Mutex, mpsc, oneshot};

use crate::address::{NetLocation, ResolvedLocation};
use crate::async_stream::AsyncMessageStream;
use crate::config::{AmneziaWgClientConfig, ClientProxyConfig, WireGuardClientConfig};
use crate::resolver::{self, Resolver};
use crate::tcp::tcp_handler::TcpClientSetupResult;
use crate::tcp::terminal_connector::TerminalConnector;

use super::config::AwgRuntimeConfig;
use super::netstack::{NetStackRequest, VirtualNetStack};
use super::tunnel::TunnelRuntime;

struct TunnelState {
    runtime: Arc<TunnelRuntime>,
    request_tx: mpsc::Sender<NetStackRequest>,
    /// The netstack task, so a rebuild can kill it. Aborting drops its
    /// `request_rx` and every pending reply sender with it, which is what
    /// unblocks callers parked on a reply from a stack nobody feeds --
    /// their own `request_tx` clones would otherwise keep it alive.
    netstack_abort: tokio::task::AbortHandle,
}

/// Tunnel protocol variant for display purposes.
#[derive(Debug, Clone, Copy)]
enum TunnelProtocol {
    WireGuard,
    AmneziaWg,
}

pub struct AmneziaWgConnector {
    config: AmneziaWgClientConfig,
    protocol: TunnelProtocol,
    endpoint: NetLocation,
    state: Mutex<ConnectorState>,
}

/// The connector's tunnel, plus the memory of a build that failed.
#[derive(Default)]
struct ConnectorState {
    tunnel: Option<TunnelState>,
    /// When the last build attempt failed. A busy proxy with an
    /// unreachable peer otherwise repeats DNS resolution and a socket
    /// bind for every inbound connection, serialized behind this mutex
    /// with every other connection queued on it.
    last_attempt_failed_at: Option<std::time::Instant>,
}

/// How long after a failed build the next inbound connection fails fast
/// instead of retrying the build. Long enough to stop the per-connection
/// churn, short enough that a recovered peer is noticed promptly.
const REBUILD_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(3);

impl std::fmt::Debug for AmneziaWgConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AmneziaWgConnector")
            .field("protocol", &self.protocol)
            .field("endpoint", &self.endpoint)
            .finish()
    }
}

impl AmneziaWgConnector {
    /// Create from a `ClientProxyConfig::Wireguard` or `ClientProxyConfig::AmneziaWg`.
    pub fn from_client_config(
        proxy_config: ClientProxyConfig,
        endpoint: NetLocation,
    ) -> std::io::Result<Self> {
        match proxy_config {
            ClientProxyConfig::Wireguard(wg) => Ok(Self::from_wireguard(*wg, endpoint)),
            ClientProxyConfig::AmneziaWg(awg) => Ok(Self::from_amneziawg(*awg, endpoint)),
            other => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "AmneziaWgConnector: expected Wireguard or AmneziaWg config, got {:?}",
                    std::mem::discriminant(&other)
                ),
            )),
        }
    }

    fn from_amneziawg(config: AmneziaWgClientConfig, endpoint: NetLocation) -> Self {
        Self {
            config,
            protocol: TunnelProtocol::AmneziaWg,
            endpoint,
            state: Mutex::new(ConnectorState::default()),
        }
    }

    fn from_wireguard(wg: WireGuardClientConfig, endpoint: NetLocation) -> Self {
        // Convert WireGuard config to AmneziaWG config with default (no-op) obfuscation
        let config = AmneziaWgClientConfig {
            private_key: wg.private_key,
            peer_public_key: wg.peer_public_key,
            preshared_key: wg.preshared_key,
            local_addresses: wg.local_addresses,
            allowed_ips: wg.allowed_ips,
            persistent_keepalive: wg.persistent_keepalive,
            mtu: wg.mtu,
            awg: crate::config::AmneziaWgParams {
                jc: 0,
                jmin: 0,
                jmax: 0,
                s1: 0,
                s2: 0,
                s3: 0,
                s4: 0,
                h1: None,
                h2: None,
                h3: None,
                h4: None,
                i1: None,
                i2: None,
                i3: None,
                i4: None,
                i5: None,
                header_protection_key: None,
                content_padding_addition: None,
                rekey_after_time: None,
                rekey_timeout: None,
                reject_after_time: None,
                keepalive_timeout: None,
                max_handshake_attempts: None,
                persistent_keepalive_interval: None,
                random_trailers: false,
                disable_cookies: false,
            },
        };
        Self {
            config,
            protocol: TunnelProtocol::WireGuard,
            endpoint,
            state: Mutex::new(ConnectorState::default()),
        }
    }

    async fn ensure_initialized(
        &self,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<mpsc::Sender<NetStackRequest>> {
        let mut state = self.state.lock().await;
        if let Some(ref s) = state.tunnel {
            // is_dead covers the receive path; is_closed covers a netstack
            // task that ended on its own (its request_rx is gone). A
            // request that slipped through after the death -- the is_dead
            // check races the caller's DNS resolution -- parks its caller
            // until this rebuild aborts the old stack and fails it.
            if s.runtime.is_dead() || s.request_tx.is_closed() {
                // The receive path died and reported fatal. Under the
                // mobile engine that has already stopped the service; in
                // the standalone binary nobody listens, so recovery is
                // here -- drop the dead runtime and rebuild on this
                // connection. Streams on the old netstack are lost, which
                // they already were.
                info!("AmneziaWG: tunnel receive path died; rebuilding the tunnel");
                s.netstack_abort.abort();
                state.tunnel = None;
            } else {
                return Ok(s.request_tx.clone());
            }
        }

        if let Some(failed_at) = state.last_attempt_failed_at
            && failed_at.elapsed() < REBUILD_COOLDOWN
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "AmneziaWG tunnel build failed moments ago; next attempt after the cooldown",
            ));
        }

        // The bookkeeping happens in one match on the helper's result, so
        // failure is stamped when it HAPPENS -- a stamp at attempt start
        // was already expired by the time a 10-second DNS timeout failed,
        // which is the motivating slow-failure case -- and a caller future
        // dropped mid-build stamps nothing: a cancellation is not evidence
        // the peer is down, and there is no Drop guard to clean a
        // pessimistic stamp up.
        match self.build_tunnel(resolver).await {
            Ok((tunnel, request_tx)) => {
                state.last_attempt_failed_at = None;
                state.tunnel = Some(tunnel);
                Ok(request_tx)
            }
            Err(e) => {
                state.last_attempt_failed_at = Some(std::time::Instant::now());
                Err(e)
            }
        }
    }

    /// Resolve, start the tunnel runtime, and spawn its netstack. Pure
    /// build: no connector state is touched, so `ensure_initialized` owns
    /// the outcome bookkeeping in one place.
    async fn build_tunnel(
        &self,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<(TunnelState, mpsc::Sender<NetStackRequest>)> {
        let variant = match self.protocol {
            TunnelProtocol::WireGuard => "WireGuard",
            TunnelProtocol::AmneziaWg if self.config.awg.uses_awg31() => "AmneziaWG 3.1",
            TunnelProtocol::AmneziaWg if self.config.awg.uses_awg3() => "AmneziaWG 3.0",
            TunnelProtocol::AmneziaWg => "AmneziaWG 2.0",
        };
        info!("{}: initializing tunnel to {}", variant, self.endpoint);

        let runtime_config = AwgRuntimeConfig::from_client_config(&self.config)?;
        let endpoint_addr = resolver::resolve_single_address(resolver, &self.endpoint).await?;

        let tunnel_runtime = TunnelRuntime::start(
            runtime_config.private_key,
            runtime_config.peer_public_key,
            runtime_config.preshared_key,
            runtime_config.persistent_keepalive,
            runtime_config.amnezia,
            endpoint_addr,
        )
        .await?;

        let ip_from_tunnel_rx = tunnel_runtime
            .ip_from_tunnel_rx
            .lock()
            .take()
            .ok_or_else(|| std::io::Error::other("AmneziaWG tunnel already initialized"))?;

        let netstack = VirtualNetStack::new(
            &runtime_config.local_addresses,
            runtime_config.mtu,
            tunnel_runtime.ip_to_tunnel_tx.clone(),
            ip_from_tunnel_rx,
        );

        let (request_tx, request_rx) = mpsc::channel::<NetStackRequest>(64);

        let netstack_task = tokio::spawn(async move {
            netstack.run(request_rx).await;
        });

        Ok((
            TunnelState {
                runtime: tunnel_runtime,
                request_tx: request_tx.clone(),
                netstack_abort: netstack_task.abort_handle(),
            },
            request_tx,
        ))
    }
}

#[async_trait]
impl TerminalConnector for AmneziaWgConnector {
    async fn connect_tcp(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        let request_tx = self.ensure_initialized(resolver).await?;
        let target_addr = resolve_target(resolver, &target).await?;

        debug!("AmneziaWG: TCP connect to {}", target_addr);

        let (reply_tx, reply_rx) = oneshot::channel();
        request_tx
            .send(NetStackRequest::ConnectTcp {
                target: target_addr,
                reply: reply_tx,
            })
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "AmneziaWG netstack stopped")
            })?;

        let stream = reply_rx.await.map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "AmneziaWG netstack did not reply",
            )
        })??;

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
        let request_tx = self.ensure_initialized(resolver).await?;
        let target_addr = resolve_target(resolver, &target).await?;

        debug!("AmneziaWG: UDP connect to {}", target_addr);

        let (reply_tx, reply_rx) = oneshot::channel();
        request_tx
            .send(NetStackRequest::ConnectUdp {
                target: target_addr,
                reply: reply_tx,
            })
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "AmneziaWG netstack stopped")
            })?;

        let stream = reply_rx.await.map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "AmneziaWG netstack did not reply",
            )
        })??;

        Ok(Box::new(stream))
    }
}

async fn resolve_target(
    resolver: &Arc<dyn Resolver>,
    target: &ResolvedLocation,
) -> std::io::Result<SocketAddr> {
    if let Some(addr) = target.resolved_addr() {
        return Ok(addr);
    }
    resolver::resolve_single_address(resolver, target.location()).await
}
