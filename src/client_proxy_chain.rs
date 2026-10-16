//! Client proxy chain implementation for multi-hop proxy connections.
//!
//! A `ClientProxyChain` represents either:
//! - An ordered sequence of proxy hops (stream chain), where each hop
//!   can be a pool of connectors (for round-robin selection)
//! - A virtual network tunnel connector (e.g., AmneziaWG) that owns its own transport
//!
//! ## Design: InitialHopEntry for Hop 0
//!
//! Hop 0 is fundamentally different from subsequent hops:
//! - **Hop 0**: Creates socket AND optionally sets up protocol (if not direct)
//! - **Hops 1+**: Only set up protocol on existing stream
//!
//! To handle mixed pools at hop 0 (e.g., direct + various proxy types), we use
//! `InitialHopEntry` which pairs socket and proxy together, ensuring they are
//! always selected atomically during round-robin.
//!
//! ## Structure
//!
//! For stream chains:
//! - `initial_hop`: Pool of `InitialHopEntry` (Direct or Proxy) for hop 0
//! - `subsequent_hops`: Protocol connectors for hops 1+ (no socket creation)
//!
//! For virtual network chains:
//! - A pool of `TerminalConnector`s, each of which handles all connections
//!   internally

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "predates the lint; see the [lints] note in Cargo.toml"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use log::debug;

use crate::address::ResolvedLocation;
use crate::async_stream::AsyncMessageStream;
#[cfg(feature = "control-stats")]
use crate::outbound_stats::OutboundCounters;
use crate::resolver::Resolver;
use crate::tcp::proxy_connector::ProxyConnector;
use crate::tcp::socket_connector::SocketConnector;
use crate::tcp::tcp_handler::TcpClientSetupResult;
use crate::tcp::terminal_connector::TerminalConnector;

/// Entry in the initial hop (hop 0) pool.
///
/// Each entry pairs socket creation with optional protocol setup,
/// ensuring they are always selected together during round-robin.
pub enum InitialHopEntry {
    /// Direct connection - socket only, no protocol setup.
    /// Connects directly to the next hop's proxy or final destination.
    Direct(Box<dyn SocketConnector>),

    /// Proxy connection - socket + protocol setup paired together.
    /// Socket connects to proxy_location, then protocol wraps the stream.
    Proxy {
        socket: Box<dyn SocketConnector>,
        proxy: Box<dyn ProxyConnector>,
    },
}

impl std::fmt::Debug for InitialHopEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InitialHopEntry::Direct(socket) => f.debug_tuple("Direct").field(socket).finish(),
            InitialHopEntry::Proxy { socket, proxy } => f
                .debug_struct("Proxy")
                .field("socket", socket)
                .field("proxy_location", &proxy.proxy_location())
                .finish(),
        }
    }
}

impl InitialHopEntry {
    /// Returns true if this entry supports UDP.
    pub fn supports_udp(&self) -> bool {
        match self {
            InitialHopEntry::Direct(_) => true, // Direct always supports UDP
            InitialHopEntry::Proxy { proxy, .. } => proxy.supports_udp_over_tcp(),
        }
    }
}

/// Internal kind of a proxy chain.
enum ClientProxyChainKind {
    /// Standard stream-based chain with socket connectors and proxy wrappers.
    StreamChain {
        initial_hop: Vec<InitialHopEntry>,
        initial_hop_next_index: AtomicU32,
        subsequent_hops: Vec<Vec<Box<dyn ProxyConnector>>>,
        subsequent_next_indices: Vec<AtomicU32>,
        /// One handle per member of `initial_hop`, same order.
        #[cfg(feature = "control-stats")]
        initial_hop_counters: Vec<Arc<OutboundCounters>>,
        /// One handle per member of each pool in `subsequent_hops`, same order.
        #[cfg(feature = "control-stats")]
        subsequent_hop_counters: Vec<Vec<Arc<OutboundCounters>>>,
        udp_final_hop_indices: Vec<usize>,
        udp_final_hop_next_index: AtomicU32,
        udp_uses_initial_hop: bool,
    },
    /// Connectors that own their own transport (AmneziaWG today, Hysteria2 and
    /// TUIC once they land). A pool is selected round-robin, exactly like a
    /// pool of proxy hops.
    Terminal {
        connectors: Vec<Arc<dyn TerminalConnector>>,
        next_index: AtomicU32,
        #[cfg(feature = "control-stats")]
        connector_counters: Vec<Arc<OutboundCounters>>,
    },
}

/// A chain of proxy hops with paired initial hop entries,
/// or a virtual network tunnel connector.
pub struct ClientProxyChain {
    kind: ClientProxyChainKind,
}

impl std::fmt::Debug for ClientProxyChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            ClientProxyChainKind::StreamChain {
                initial_hop,
                subsequent_hops,
                udp_final_hop_indices,
                udp_uses_initial_hop,
                ..
            } => f
                .debug_struct("ClientProxyChain::StreamChain")
                .field("initial_hop_count", &initial_hop.len())
                .field(
                    "subsequent_hops",
                    &subsequent_hops.iter().map(|h| h.len()).collect::<Vec<_>>(),
                )
                .field("udp_final_hop_indices", udp_final_hop_indices)
                .field("udp_uses_initial_hop", udp_uses_initial_hop)
                .finish(),
            ClientProxyChainKind::Terminal { connectors, .. } => f
                .debug_struct("ClientProxyChain::Terminal")
                .field("connector_count", &connectors.len())
                .finish(),
        }
    }
}

/// Everything `as_stream_chain` hands a test, in the order the variant
/// declares its fields.
#[cfg(test)]
type StreamChainParts<'a> = (
    &'a Vec<InitialHopEntry>,
    &'a AtomicU32,
    &'a Vec<Vec<Box<dyn ProxyConnector>>>,
    &'a Vec<usize>,
    &'a AtomicU32,
    bool,
);

impl ClientProxyChain {
    /// Create a new stream-based chain from initial hop entries and subsequent hop pools.
    ///
    /// # Arguments
    /// * `initial_hop` - Pool of InitialHopEntry for hop 0
    /// * `subsequent_hops` - Protocol connectors for hops 1+
    ///
    /// # Panics
    /// Panics if initial_hop is empty.
    pub fn new(
        initial_hop: Vec<InitialHopEntry>,
        subsequent_hops: Vec<Vec<Box<dyn ProxyConnector>>>,
    ) -> Self {
        assert!(
            !initial_hop.is_empty(),
            "ClientProxyChain must have at least one initial hop entry"
        );

        // Compute UDP-capable indices in the FINAL hop pool.
        let (udp_final_hop_indices, udp_uses_initial_hop) = if subsequent_hops.is_empty() {
            let indices = initial_hop
                .iter()
                .enumerate()
                .filter(|(_, entry)| entry.supports_udp())
                .map(|(i, _)| i)
                .collect();
            (indices, true)
        } else {
            let final_hop = subsequent_hops.last().unwrap();
            let indices = final_hop
                .iter()
                .enumerate()
                .filter(|(_, p)| p.supports_udp_over_tcp())
                .map(|(i, _)| i)
                .collect();
            (indices, false)
        };

        let subsequent_next_indices = subsequent_hops.iter().map(|_| AtomicU32::new(0)).collect();

        // One handle per pool member, so an index chosen by selection is
        // always in bounds. `unattributed` until chain_builder replaces them:
        // a chain built with no config behind it counts into a void rather
        // than crediting an arbitrary server.
        #[cfg(feature = "control-stats")]
        let initial_hop_counters = vec![crate::outbound_stats::unattributed(); initial_hop.len()];
        #[cfg(feature = "control-stats")]
        let subsequent_hop_counters: Vec<Vec<Arc<OutboundCounters>>> = subsequent_hops
            .iter()
            .map(|hop| vec![crate::outbound_stats::unattributed(); hop.len()])
            .collect();

        Self {
            kind: ClientProxyChainKind::StreamChain {
                initial_hop,
                initial_hop_next_index: AtomicU32::new(0),
                subsequent_hops,
                subsequent_next_indices,
                #[cfg(feature = "control-stats")]
                initial_hop_counters,
                #[cfg(feature = "control-stats")]
                subsequent_hop_counters,
                udp_final_hop_indices,
                udp_final_hop_next_index: AtomicU32::new(0),
                udp_uses_initial_hop,
            },
        }
    }

    /// Create a new terminal chain from one or more connectors that own their
    /// transport.
    ///
    /// # Panics
    /// Panics if `connectors` is empty.
    pub fn new_terminal(connectors: Vec<Arc<dyn TerminalConnector>>) -> Self {
        assert!(
            !connectors.is_empty(),
            "ClientProxyChain must have at least one terminal connector"
        );
        #[cfg(feature = "control-stats")]
        let connector_counters = vec![crate::outbound_stats::unattributed(); connectors.len()];

        Self {
            kind: ClientProxyChainKind::Terminal {
                connectors,
                next_index: AtomicU32::new(0),
                #[cfg(feature = "control-stats")]
                connector_counters,
            },
        }
    }

    /// Attach the counters for each pool member, in the order the pools were
    /// built. Panics on a length mismatch: that is a construction bug in
    /// `chain_builder`, and silently mis-attributing traffic would be worse
    /// than a loud failure at startup.
    #[cfg(feature = "control-stats")]
    pub fn with_counters(
        mut self,
        initial: Vec<Arc<OutboundCounters>>,
        subsequent: Vec<Vec<Arc<OutboundCounters>>>,
    ) -> Self {
        match &mut self.kind {
            ClientProxyChainKind::StreamChain {
                initial_hop,
                subsequent_hops,
                initial_hop_counters,
                subsequent_hop_counters,
                ..
            } => {
                assert_eq!(initial.len(), initial_hop.len(), "initial counter count");
                assert_eq!(subsequent.len(), subsequent_hops.len(), "hop count");
                for (given, hop) in subsequent.iter().zip(subsequent_hops.iter()) {
                    assert_eq!(given.len(), hop.len(), "pool counter count");
                }
                *initial_hop_counters = initial;
                *subsequent_hop_counters = subsequent;
            }
            ClientProxyChainKind::Terminal { .. } => {
                panic!("with_counters on a terminal chain; use with_terminal_counters")
            }
        }
        self
    }

    #[cfg(feature = "control-stats")]
    pub fn with_terminal_counters(mut self, counters: Vec<Arc<OutboundCounters>>) -> Self {
        match &mut self.kind {
            ClientProxyChainKind::Terminal {
                connectors,
                connector_counters,
                ..
            } => {
                assert_eq!(counters.len(), connectors.len(), "terminal counter count");
                *connector_counters = counters;
            }
            ClientProxyChainKind::StreamChain { .. } => {
                panic!("with_terminal_counters on a stream chain; use with_counters")
            }
        }
        self
    }

    /// The counters this connection's bytes belong to: the exit hop's, which
    /// is the last subsequent hop when there is one and the initial hop
    /// otherwise.
    #[cfg(feature = "control-stats")]
    ///
    /// Takes only the exit hop's index rather than every hop's, so the caller
    /// has nothing to collect: the selection it already holds answers this.
    fn exit_counters(
        initial_hop_counters: &[Arc<OutboundCounters>],
        subsequent_hop_counters: &[Vec<Arc<OutboundCounters>>],
        initial_idx: usize,
        subsequent_exit_idx: Option<usize>,
    ) -> Arc<OutboundCounters> {
        match (subsequent_hop_counters.last(), subsequent_exit_idx) {
            (Some(pool), Some(idx)) => pool[idx].clone(),
            _ => initial_hop_counters[initial_idx].clone(),
        }
    }

    #[cfg(all(test, feature = "control-stats"))]
    fn initial_counter_len(&self) -> usize {
        match &self.kind {
            ClientProxyChainKind::StreamChain {
                initial_hop_counters,
                ..
            } => initial_hop_counters.len(),
            ClientProxyChainKind::Terminal { .. } => 0,
        }
    }

    #[cfg(all(test, feature = "control-stats"))]
    fn initial_counter(&self, i: usize) -> Arc<OutboundCounters> {
        match &self.kind {
            ClientProxyChainKind::StreamChain {
                initial_hop_counters,
                ..
            } => initial_hop_counters[i].clone(),
            ClientProxyChainKind::Terminal { .. } => panic!("not a stream chain"),
        }
    }

    /// Returns the total number of hops (only meaningful for stream chains).
    #[cfg(test)]
    pub fn num_hops(&self) -> usize {
        match &self.kind {
            ClientProxyChainKind::StreamChain {
                subsequent_hops, ..
            } => 1 + subsequent_hops.len(),
            ClientProxyChainKind::Terminal { .. } => 1,
        }
    }

    /// Returns true if this chain supports UDP connections.
    pub fn supports_udp(&self) -> bool {
        match &self.kind {
            ClientProxyChainKind::StreamChain {
                udp_final_hop_indices,
                ..
            } => !udp_final_hop_indices.is_empty(),
            ClientProxyChainKind::Terminal { connectors, .. } => {
                connectors.iter().any(|c| c.supports_udp())
            }
        }
    }

    /// Returns true if this chain is "direct-only": all initial hops are Direct
    /// and there are no subsequent hops.
    pub fn is_direct_only(&self) -> bool {
        match &self.kind {
            ClientProxyChainKind::StreamChain {
                initial_hop,
                subsequent_hops,
                ..
            } => {
                if !subsequent_hops.is_empty() {
                    return false;
                }
                initial_hop
                    .iter()
                    .all(|entry| matches!(entry, InitialHopEntry::Direct(_)))
            }
            ClientProxyChainKind::Terminal { .. } => false,
        }
    }

    /// Returns the bind_interface from a direct-only chain.
    pub fn get_bind_interface(&self) -> Option<&str> {
        if !self.is_direct_only() {
            return None;
        }
        match &self.kind {
            ClientProxyChainKind::StreamChain { initial_hop, .. } => {
                initial_hop.first().and_then(|entry| match entry {
                    InitialHopEntry::Direct(socket) => socket.bind_interface(),
                    InitialHopEntry::Proxy { .. } => None,
                })
            }
            ClientProxyChainKind::Terminal { .. } => None,
        }
    }

    /// Connect through the chain to the remote location for TCP traffic.
    pub async fn connect_tcp(
        &self,
        remote_location: ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<TcpClientSetupResult> {
        match &self.kind {
            ClientProxyChainKind::StreamChain {
                initial_hop,
                initial_hop_next_index,
                subsequent_hops,
                subsequent_next_indices,
                #[cfg(feature = "control-stats")]
                initial_hop_counters,
                #[cfg(feature = "control-stats")]
                subsequent_hop_counters,
                ..
            } => {
                let (entry, _initial_idx) = select_from_pool(initial_hop, initial_hop_next_index);
                // One allocation per connection, the same one this path always
                // made. The indices ride along in it rather than in a second
                // vector, so a build without counters carries them without
                // paying for them.
                let selected = select_subsequent(subsequent_hops, subsequent_next_indices);
                #[cfg(feature = "control-stats")]
                let subsequent_exit_idx = selected.last().map(|(_, i)| *i);

                debug!(
                    "Chain TCP connect: 1 initial + {} subsequent hop(s) -> {}",
                    selected.len(),
                    remote_location.location()
                );

                let first_subsequent_target: ResolvedLocation = selected
                    .first()
                    .map(|(p, _)| p.proxy_location().into())
                    .unwrap_or_else(|| remote_location.clone());

                let mut result = match entry {
                    InitialHopEntry::Direct(socket) => {
                        debug!(
                            "Initial hop: Direct -> {}",
                            first_subsequent_target.location()
                        );
                        let stream = socket.connect(resolver, &first_subsequent_target).await?;
                        TcpClientSetupResult {
                            client_stream: stream,
                            early_data: None,
                        }
                    }
                    InitialHopEntry::Proxy { socket, proxy } => {
                        debug!(
                            "Initial hop: Proxy {} -> {}",
                            proxy.proxy_location(),
                            first_subsequent_target.location()
                        );
                        let proxy_loc = proxy.proxy_location().into();
                        let stream = socket.connect(resolver, &proxy_loc).await?;
                        proxy
                            .setup_tcp_stream(stream, &first_subsequent_target)
                            .await?
                    }
                };

                for (i, (proxy, _)) in selected.iter().enumerate() {
                    let target: ResolvedLocation = selected
                        .get(i + 1)
                        .map(|(p, _)| p.proxy_location().into())
                        .unwrap_or_else(|| remote_location.clone());

                    debug!(
                        "Subsequent hop {}/{}: {} -> {}",
                        i + 1,
                        selected.len(),
                        proxy.proxy_location(),
                        target.location()
                    );

                    result = proxy
                        .setup_tcp_stream(result.client_stream, &target)
                        .await?;

                    if let Some(data) = &result.early_data
                        && i < selected.len() - 1
                    {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!(
                                "Unexpected early data ({} bytes) from intermediate hop {}",
                                data.len(),
                                i + 1
                            ),
                        ));
                    }
                }

                debug!(
                    "Chain TCP complete: {} total hop(s) to {}",
                    1 + selected.len(),
                    remote_location.location()
                );

                #[cfg(feature = "control-stats")]
                let result = {
                    let counters = Self::exit_counters(
                        initial_hop_counters,
                        subsequent_hop_counters,
                        _initial_idx,
                        subsequent_exit_idx,
                    );
                    let counting = crate::outbound_counting_stream::OutboundCountingStream::new(
                        result.client_stream,
                        counters,
                    );
                    // early_data never travels through the stream and would
                    // otherwise be lost from the count entirely.
                    if let Some(data) = &result.early_data {
                        counting.count_early_data(data.len());
                    }
                    TcpClientSetupResult {
                        client_stream: Box::new(counting),
                        early_data: result.early_data,
                    }
                };

                Ok(result)
            }
            ClientProxyChainKind::Terminal {
                connectors,
                next_index,
                #[cfg(feature = "control-stats")]
                connector_counters,
            } => {
                let (connector, _idx) = select_terminal(connectors, next_index);
                debug!("Terminal TCP connect -> {}", remote_location.location());
                let result = connector.connect_tcp(resolver, remote_location).await?;

                #[cfg(feature = "control-stats")]
                let result = {
                    let counting = crate::outbound_counting_stream::OutboundCountingStream::new(
                        result.client_stream,
                        connector_counters[_idx].clone(),
                    );
                    if let Some(data) = &result.early_data {
                        counting.count_early_data(data.len());
                    }
                    TcpClientSetupResult {
                        client_stream: Box::new(counting),
                        early_data: result.early_data,
                    }
                };

                Ok(result)
            }
        }
    }

    /// Connect for bidirectional UDP traffic through the chain.
    pub async fn connect_udp_bidirectional(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        match &self.kind {
            ClientProxyChainKind::StreamChain {
                initial_hop,
                initial_hop_next_index,
                subsequent_hops,
                subsequent_next_indices,
                udp_final_hop_indices,
                udp_final_hop_next_index,
                udp_uses_initial_hop,
                #[cfg(feature = "control-stats")]
                initial_hop_counters,
                #[cfg(feature = "control-stats")]
                subsequent_hop_counters,
            } => {
                if udp_final_hop_indices.is_empty() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "Chain does not support UDP",
                    ));
                }

                if *udp_uses_initial_hop {
                    let idx = udp_final_hop_next_index.fetch_add(1, Ordering::Relaxed) as usize;
                    let pool_idx = udp_final_hop_indices[idx % udp_final_hop_indices.len()];
                    let entry = &initial_hop[pool_idx];

                    debug!(
                        "Chain UDP connect: 1 hop (initial IS final), target={}",
                        target.location()
                    );

                    let stream = match entry {
                        InitialHopEntry::Direct(socket) => {
                            debug!("Chain UDP: Direct connection (native UDP)");
                            socket.connect_udp_bidirectional(resolver, target).await?
                        }
                        InitialHopEntry::Proxy { socket, proxy } => {
                            debug!(
                                "Chain UDP: Proxy {} (UDP, no subsequent)",
                                proxy.proxy_location()
                            );
                            let proxy_loc = proxy.proxy_location().into();
                            let stream = socket.connect(resolver, &proxy_loc).await?;
                            proxy.setup_udp_bidirectional(stream, target).await?
                        }
                    };

                    // pool_idx indexes initial_hop here: this branch is the
                    // one where the initial hop IS the final hop.
                    #[cfg(feature = "control-stats")]
                    let stream: Box<dyn AsyncMessageStream> = Box::new(
                        crate::outbound_counting_stream::OutboundCountingMessageStream::new(
                            stream,
                            initial_hop_counters[pool_idx].clone(),
                        ),
                    );

                    Ok(stream)
                } else {
                    let (entry, _initial_idx) =
                        select_from_pool(initial_hop, initial_hop_next_index);

                    let intermediate_proxies: Vec<&dyn ProxyConnector> = subsequent_hops
                        .iter()
                        .enumerate()
                        .take(subsequent_hops.len() - 1)
                        .map(|(i, hop)| {
                            if hop.len() == 1 {
                                hop[0].as_ref()
                            } else {
                                let idx = subsequent_next_indices[i].fetch_add(1, Ordering::Relaxed)
                                    as usize;
                                hop[idx % hop.len()].as_ref()
                            }
                        })
                        .collect();

                    let final_hop_pool = subsequent_hops.last().unwrap();
                    let idx = udp_final_hop_next_index.fetch_add(1, Ordering::Relaxed) as usize;
                    let pool_idx = udp_final_hop_indices[idx % udp_final_hop_indices.len()];
                    let final_proxy = final_hop_pool[pool_idx].as_ref();

                    debug!(
                        "Chain UDP connect: 1 initial + {} intermediate + 1 final (UDP) hop(s), target={}",
                        intermediate_proxies.len(),
                        target.location()
                    );

                    let mut stream = match entry {
                        InitialHopEntry::Direct(socket) => {
                            let first_target: ResolvedLocation =
                                if let Some(first) = intermediate_proxies.first() {
                                    first.proxy_location().into()
                                } else {
                                    final_proxy.proxy_location().into()
                                };
                            debug!("Chain UDP: Direct -> {} (TCP)", first_target.location());
                            socket.connect(resolver, &first_target).await?
                        }
                        InitialHopEntry::Proxy { socket, proxy } => {
                            let first_target: ResolvedLocation =
                                if let Some(first) = intermediate_proxies.first() {
                                    first.proxy_location().into()
                                } else {
                                    final_proxy.proxy_location().into()
                                };
                            debug!(
                                "Chain UDP: Proxy {} -> {} (TCP)",
                                proxy.proxy_location(),
                                first_target.location()
                            );
                            let proxy_loc = proxy.proxy_location().into();
                            let raw_stream = socket.connect(resolver, &proxy_loc).await?;
                            let result = proxy.setup_tcp_stream(raw_stream, &first_target).await?;
                            result.client_stream
                        }
                    };

                    for (i, proxy) in intermediate_proxies.iter().enumerate() {
                        let next_target: ResolvedLocation = intermediate_proxies
                            .get(i + 1)
                            .map(|p| p.proxy_location().into())
                            .unwrap_or_else(|| final_proxy.proxy_location().into());
                        debug!(
                            "Chain UDP intermediate hop {}/{}: {} -> {} (TCP)",
                            i + 1,
                            intermediate_proxies.len(),
                            proxy.proxy_location(),
                            next_target.location()
                        );
                        let result = proxy.setup_tcp_stream(stream, &next_target).await?;
                        stream = result.client_stream;
                    }

                    debug!(
                        "Chain UDP final hop: {} (UDP)",
                        final_proxy.proxy_location()
                    );
                    let stream = final_proxy.setup_udp_bidirectional(stream, target).await?;

                    // pool_idx indexes the final hop pool in this branch.
                    #[cfg(feature = "control-stats")]
                    let stream: Box<dyn AsyncMessageStream> = Box::new(
                        crate::outbound_counting_stream::OutboundCountingMessageStream::new(
                            stream,
                            subsequent_hop_counters
                                .last()
                                .expect("multi-hop branch has a final pool")[pool_idx]
                                .clone(),
                        ),
                    );

                    Ok(stream)
                }
            }
            ClientProxyChainKind::Terminal {
                connectors,
                next_index,
                #[cfg(feature = "control-stats")]
                connector_counters,
            } => {
                let (connector, _idx) = select_terminal(connectors, next_index);
                debug!("Terminal UDP connect -> {}", target.location());
                let stream = connector
                    .connect_udp_bidirectional(resolver, target)
                    .await?;

                #[cfg(feature = "control-stats")]
                let stream: Box<dyn AsyncMessageStream> = Box::new(
                    crate::outbound_counting_stream::OutboundCountingMessageStream::new(
                        stream,
                        connector_counters[_idx].clone(),
                    ),
                );

                Ok(stream)
            }
        }
    }

    // Test helpers to access internal state for stream chains
    #[cfg(test)]
    fn as_stream_chain(&self) -> StreamChainParts<'_> {
        match &self.kind {
            ClientProxyChainKind::StreamChain {
                initial_hop,
                initial_hop_next_index,
                subsequent_hops,
                udp_final_hop_indices,
                udp_final_hop_next_index,
                udp_uses_initial_hop,
                ..
            } => (
                initial_hop,
                initial_hop_next_index,
                subsequent_hops,
                udp_final_hop_indices,
                udp_final_hop_next_index,
                *udp_uses_initial_hop,
            ),
            _ => panic!("Expected StreamChain"),
        }
    }
}

fn select_from_pool<'a>(
    pool: &'a [InitialHopEntry],
    index: &AtomicU32,
) -> (&'a InitialHopEntry, usize) {
    if pool.len() == 1 {
        (&pool[0], 0)
    } else {
        let idx = index.fetch_add(1, Ordering::Relaxed) as usize % pool.len();
        (&pool[idx], idx)
    }
}

fn select_terminal<'a>(
    pool: &'a [Arc<dyn TerminalConnector>],
    index: &AtomicU32,
) -> (&'a Arc<dyn TerminalConnector>, usize) {
    if pool.len() == 1 {
        (&pool[0], 0)
    } else {
        let idx = index.fetch_add(1, Ordering::Relaxed) as usize % pool.len();
        (&pool[idx], idx)
    }
}

fn select_subsequent<'a>(
    hops: &'a [Vec<Box<dyn ProxyConnector>>],
    indices: &[AtomicU32],
) -> Vec<(&'a dyn ProxyConnector, usize)> {
    hops.iter()
        .enumerate()
        .map(|(i, hop)| {
            if hop.len() == 1 {
                (hop[0].as_ref(), 0)
            } else {
                let idx = indices[i].fetch_add(1, Ordering::Relaxed) as usize % hop.len();
                (hop[idx].as_ref(), idx)
            }
        })
        .collect()
}

/// A group of proxy chains for round-robin selection.
pub struct ClientChainGroup {
    chains: Vec<ClientProxyChain>,
    next_tcp_index: AtomicU32,
    pub(crate) udp_chain_indices: Vec<usize>,
    next_udp_index: AtomicU32,
}

impl std::fmt::Debug for ClientChainGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientChainGroup")
            .field("chains_count", &self.chains.len())
            .field("udp_chain_indices", &self.udp_chain_indices)
            .finish()
    }
}

impl ClientChainGroup {
    pub fn new(chains: Vec<ClientProxyChain>) -> Self {
        assert!(
            !chains.is_empty(),
            "ClientChainGroup must have at least one chain"
        );

        let udp_chain_indices: Vec<usize> = chains
            .iter()
            .enumerate()
            .filter(|(_, chain)| chain.supports_udp())
            .map(|(i, _)| i)
            .collect();

        Self {
            chains,
            next_tcp_index: AtomicU32::new(0),
            udp_chain_indices,
            next_udp_index: AtomicU32::new(0),
        }
    }

    pub async fn connect_tcp(
        &self,
        remote_location: ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<TcpClientSetupResult> {
        let idx = self.next_tcp_index.fetch_add(1, Ordering::Relaxed) as usize;
        let chain = &self.chains[idx % self.chains.len()];
        chain.connect_tcp(remote_location, resolver).await
    }

    pub async fn connect_udp_bidirectional(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        if self.udp_chain_indices.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "No chains in group support UDP",
            ));
        }

        let idx = self.next_udp_index.fetch_add(1, Ordering::Relaxed) as usize;
        let chain_idx = self.udp_chain_indices[idx % self.udp_chain_indices.len()];
        let chain = &self.chains[chain_idx];
        chain.connect_udp_bidirectional(resolver, target).await
    }

    #[cfg(test)]
    pub fn supports_udp(&self) -> bool {
        !self.udp_chain_indices.is_empty()
    }

    /// Returns true if all chains are direct-only.
    pub fn is_direct_only(&self) -> bool {
        self.chains.iter().all(|chain| chain.is_direct_only())
    }

    /// Returns the bind_interface if all chains are direct-only and share
    /// the same bind_interface (or all have None).
    pub fn get_bind_interface(&self) -> Option<&str> {
        if !self.is_direct_only() {
            return None;
        }
        self.chains
            .first()
            .and_then(|chain| chain.get_bind_interface())
    }
}

#[cfg(test)]
mod tests;
