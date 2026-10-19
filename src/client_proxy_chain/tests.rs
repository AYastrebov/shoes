use super::*;
use async_trait::async_trait;
use std::net::{IpAddr, Ipv4Addr};

use crate::address::NetLocation;
use crate::async_stream::AsyncStream;
use crate::tcp::proxy_connector::ProxyConnector;
use crate::tcp::socket_connector::SocketConnector;

/// Mock SocketConnector that fails on connect (for unit testing structure).
///
/// The id is carried only so a chain's connectors are distinguishable in a
/// Debug dump when a test fails.
#[derive(Debug)]
struct MockSocketConnector {
    #[allow(dead_code)]
    id: usize,
}

#[async_trait]
impl SocketConnector for MockSocketConnector {
    async fn connect(
        &self,
        _resolver: &Arc<dyn Resolver>,
        _address: &ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        Err(std::io::Error::other(
            "MockSocketConnector::connect not implemented",
        ))
    }

    async fn connect_udp_bidirectional(
        &self,
        _resolver: &Arc<dyn Resolver>,
        _target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        Err(std::io::Error::other(
            "MockSocketConnector::connect_udp_bidirectional not implemented",
        ))
    }

    fn bind_interface(&self) -> Option<&str> {
        None
    }
}

/// Mock ProxyConnector for testing.
#[derive(Debug)]
struct MockProxyConnector {
    location: NetLocation,
    supports_udp: bool,
}

impl MockProxyConnector {
    fn new(port: u16, supports_udp: bool) -> Self {
        Self {
            location: NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port),
            supports_udp,
        }
    }
}

#[async_trait]
impl ProxyConnector for MockProxyConnector {
    fn proxy_location(&self) -> &NetLocation {
        &self.location
    }

    fn supports_udp_over_tcp(&self) -> bool {
        self.supports_udp
    }

    async fn setup_tcp_stream(
        &self,
        _stream: Box<dyn AsyncStream>,
        _target: &ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        Err(std::io::Error::other(
            "MockProxyConnector::setup_tcp_stream not implemented",
        ))
    }

    async fn setup_udp_bidirectional(
        &self,
        _stream: Box<dyn AsyncStream>,
        _target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        Err(std::io::Error::other(
            "MockProxyConnector::setup_udp_bidirectional not implemented",
        ))
    }
}

fn mock_socket(id: usize) -> Box<dyn SocketConnector> {
    Box::new(MockSocketConnector { id })
}

fn mock_proxy(port: u16, supports_udp: bool) -> Box<dyn ProxyConnector> {
    Box::new(MockProxyConnector::new(port, supports_udp))
}

fn direct_entry(id: usize) -> InitialHopEntry {
    InitialHopEntry::Direct(mock_socket(id))
}

fn proxy_entry(id: usize, port: u16, supports_udp: bool) -> InitialHopEntry {
    InitialHopEntry::Proxy {
        socket: mock_socket(id),
        proxy: mock_proxy(port, supports_udp),
    }
}

#[test]
fn test_initial_hop_entry_direct_supports_udp() {
    let entry = direct_entry(0);
    assert!(entry.supports_udp());
}

#[test]
fn test_initial_hop_entry_proxy_supports_udp() {
    let entry = proxy_entry(0, 1080, true);
    assert!(entry.supports_udp());
}

#[test]
fn test_initial_hop_entry_proxy_no_udp() {
    let entry = proxy_entry(0, 1080, false);
    assert!(!entry.supports_udp());
}

#[test]
fn test_chain_single_direct() {
    let chain = ClientProxyChain::new(vec![direct_entry(0)], vec![]);
    assert_eq!(chain.num_hops(), 1);
    assert!(chain.supports_udp());
}

#[test]
fn test_chain_single_proxy() {
    let chain = ClientProxyChain::new(vec![proxy_entry(0, 1080, true)], vec![]);
    assert_eq!(chain.num_hops(), 1);
    assert!(chain.supports_udp());
}

#[test]
fn test_chain_single_proxy_no_udp() {
    let chain = ClientProxyChain::new(vec![proxy_entry(0, 1080, false)], vec![]);
    assert_eq!(chain.num_hops(), 1);
    assert!(!chain.supports_udp());
}

#[test]
fn test_chain_direct_with_subsequent() {
    let chain = ClientProxyChain::new(vec![direct_entry(0)], vec![vec![mock_proxy(1080, true)]]);
    assert_eq!(chain.num_hops(), 2);
    assert!(chain.supports_udp());
}

#[test]
fn test_chain_direct_with_subsequent_no_udp() {
    let chain = ClientProxyChain::new(vec![direct_entry(0)], vec![vec![mock_proxy(1080, false)]]);
    assert_eq!(chain.num_hops(), 2);
    assert!(!chain.supports_udp());
}

#[test]
fn test_chain_proxy_with_subsequent() {
    let chain = ClientProxyChain::new(
        vec![proxy_entry(0, 1080, true)],
        vec![vec![mock_proxy(1081, true)]],
    );
    assert_eq!(chain.num_hops(), 2);
    assert!(chain.supports_udp());
}

#[test]
fn test_chain_mixed_initial_pool() {
    let chain = ClientProxyChain::new(
        vec![
            proxy_entry(0, 1080, true),
            proxy_entry(1, 1081, true),
            direct_entry(2),
        ],
        vec![],
    );
    assert_eq!(chain.num_hops(), 1);
    assert!(chain.supports_udp());
    let (_, _, _, udp_indices, _, udp_uses_initial) = chain.as_stream_chain();
    assert!(udp_uses_initial);
    assert_eq!(*udp_indices, vec![0, 1, 2]);
}

#[test]
fn test_chain_mixed_initial_pool_partial_udp() {
    let chain = ClientProxyChain::new(
        vec![
            proxy_entry(0, 1080, false),
            proxy_entry(1, 1081, true),
            direct_entry(2),
        ],
        vec![],
    );
    assert!(chain.supports_udp());
    let (_, _, _, udp_indices, _, udp_uses_initial) = chain.as_stream_chain();
    assert!(udp_uses_initial);
    assert_eq!(*udp_indices, vec![1, 2]);
}

#[test]
fn test_chain_two_subsequent_hops() {
    let chain = ClientProxyChain::new(
        vec![direct_entry(0)],
        vec![vec![mock_proxy(1080, true)], vec![mock_proxy(1081, true)]],
    );
    assert_eq!(chain.num_hops(), 3);
    assert!(chain.supports_udp());
}

#[test]
fn test_chain_pool_at_subsequent_hop() {
    let chain = ClientProxyChain::new(
        vec![direct_entry(0)],
        vec![vec![
            mock_proxy(1080, true),
            mock_proxy(1081, false),
            mock_proxy(1082, true),
        ]],
    );
    assert_eq!(chain.num_hops(), 2);
    assert!(chain.supports_udp());
}

#[test]
#[should_panic(expected = "must have at least one initial hop entry")]
fn test_chain_empty_initial_hop_panics() {
    ClientProxyChain::new(vec![], vec![]);
}

#[test]
fn test_group_single_chain() {
    let chain = ClientProxyChain::new(vec![direct_entry(0)], vec![]);
    let group = ClientChainGroup::new(vec![chain]);
    assert!(group.supports_udp());
}

#[test]
#[should_panic(expected = "must have at least one chain")]
fn test_group_empty_chains_panics() {
    ClientChainGroup::new(vec![]);
}

#[test]
fn test_group_mixed_udp_support() {
    let chain1 = ClientProxyChain::new(vec![proxy_entry(0, 1080, true)], vec![]);
    let chain2 = ClientProxyChain::new(vec![proxy_entry(1, 1081, false)], vec![]);
    let group = ClientChainGroup::new(vec![chain1, chain2]);
    assert!(group.supports_udp());
    assert_eq!(group.udp_chain_indices, vec![0]);
}

#[test]
fn test_group_all_support_udp() {
    let chain1 = ClientProxyChain::new(vec![proxy_entry(0, 1080, true)], vec![]);
    let chain2 = ClientProxyChain::new(vec![direct_entry(1)], vec![]);
    let group = ClientChainGroup::new(vec![chain1, chain2]);
    assert!(group.supports_udp());
    assert_eq!(group.udp_chain_indices, vec![0, 1]);
}

#[test]
fn test_group_none_support_udp() {
    let chain1 = ClientProxyChain::new(vec![proxy_entry(0, 1080, false)], vec![]);
    let chain2 = ClientProxyChain::new(vec![proxy_entry(1, 1081, false)], vec![]);
    let group = ClientChainGroup::new(vec![chain1, chain2]);
    assert!(!group.supports_udp());
    assert!(group.udp_chain_indices.is_empty());
}

#[test]
fn test_pool_pairing_fix_socket_proxy_always_paired() {
    let chain = ClientProxyChain::new(
        vec![
            proxy_entry(0, 1080, true),
            proxy_entry(1, 1081, true),
            direct_entry(2),
        ],
        vec![],
    );

    let (initial_hop, initial_hop_next_index, _, _, _, _) = chain.as_stream_chain();

    for iteration in 0..6 {
        let (entry, _) = select_from_pool(initial_hop, initial_hop_next_index);
        let expected_idx = iteration % 3;

        match (expected_idx, entry) {
            (0, InitialHopEntry::Proxy { proxy, .. }) => {
                assert_eq!(proxy.proxy_location().port(), 1080);
            }
            (1, InitialHopEntry::Proxy { proxy, .. }) => {
                assert_eq!(proxy.proxy_location().port(), 1081);
            }
            (2, InitialHopEntry::Direct(_)) => {}
            (idx, entry) => {
                panic!(
                    "Iteration {}: unexpected entry type at index {}. Entry: {:?}",
                    iteration, idx, entry
                );
            }
        }
    }
}

#[test]
fn test_pool_pairing_fix_udp_selection_also_paired() {
    let chain = ClientProxyChain::new(
        vec![
            proxy_entry(0, 1080, false),
            proxy_entry(1, 1081, true),
            direct_entry(2),
        ],
        vec![],
    );

    let (initial_hop, _, _, udp_indices, udp_next, udp_uses_initial) = chain.as_stream_chain();
    assert!(udp_uses_initial);
    assert_eq!(*udp_indices, vec![1, 2]);

    for iteration in 0..4 {
        let idx = udp_next.fetch_add(1, Ordering::Relaxed) as usize;
        let pool_idx = udp_indices[idx % udp_indices.len()];
        let entry = &initial_hop[pool_idx];
        let expected_udp_idx = iteration % 2;

        match (expected_udp_idx, entry) {
            (0, InitialHopEntry::Proxy { proxy, .. }) => {
                assert_eq!(proxy.proxy_location().port(), 1081);
            }
            (1, InitialHopEntry::Direct(_)) => {}
            (idx, entry) => {
                panic!(
                    "UDP iteration {}: unexpected at udp_idx {}. Entry: {:?}",
                    iteration, idx, entry
                );
            }
        }
    }
}

#[test]
fn test_udp_selection_with_subsequent_hops() {
    let chain = ClientProxyChain::new(
        vec![proxy_entry(0, 1080, false), proxy_entry(1, 1081, false)],
        vec![vec![
            mock_proxy(8080, false),
            mock_proxy(443, true),
            mock_proxy(444, true),
        ]],
    );

    let (initial_hop, initial_hop_next, subsequent_hops, udp_indices, udp_next, udp_uses_initial) =
        chain.as_stream_chain();
    assert!(!udp_uses_initial);
    assert_eq!(*udp_indices, vec![1, 2]);

    for i in 0..4 {
        let (entry, _) = select_from_pool(initial_hop, initial_hop_next);
        let expected_idx = i % 2;
        match (expected_idx, entry) {
            (0, InitialHopEntry::Proxy { proxy, .. }) => {
                assert_eq!(proxy.proxy_location().port(), 1080);
            }
            (1, InitialHopEntry::Proxy { proxy, .. }) => {
                assert_eq!(proxy.proxy_location().port(), 1081);
            }
            _ => panic!("Unexpected entry"),
        }
    }

    let final_hop = subsequent_hops.last().unwrap();
    for iteration in 0..6 {
        let idx = udp_next.fetch_add(1, Ordering::Relaxed) as usize;
        let pool_idx = udp_indices[idx % udp_indices.len()];
        let proxy = &final_hop[pool_idx];

        let expected_udp_idx = iteration % 2;
        match expected_udp_idx {
            0 => assert_eq!(proxy.proxy_location().port(), 443),
            1 => assert_eq!(proxy.proxy_location().port(), 444),
            _ => panic!("Unexpected index"),
        }
    }
}

#[test]
fn test_chain_with_subsequent_hops_uses_final_hop_indices() {
    let chain = ClientProxyChain::new(
        vec![proxy_entry(0, 1080, false), proxy_entry(1, 1081, true)],
        vec![vec![
            mock_proxy(8080, false),
            mock_proxy(443, true),
            mock_proxy(444, true),
        ]],
    );

    assert_eq!(chain.num_hops(), 2);
    assert!(chain.supports_udp());

    let (_, _, _, udp_indices, _, udp_uses_initial) = chain.as_stream_chain();
    assert!(!udp_uses_initial);
    assert_eq!(*udp_indices, vec![1, 2]);
}

#[test]
fn test_chain_intermediate_hop_no_udp_final_hop_has_udp() {
    let chain = ClientProxyChain::new(
        vec![direct_entry(0)],
        vec![vec![mock_proxy(8080, false)], vec![mock_proxy(443, true)]],
    );
    assert_eq!(chain.num_hops(), 3);
    assert!(chain.supports_udp());
}

#[test]
fn test_chain_all_intermediate_no_udp_final_has_udp() {
    let chain = ClientProxyChain::new(
        vec![direct_entry(0)],
        vec![
            vec![mock_proxy(8080, false)],
            vec![mock_proxy(1080, false)],
            vec![mock_proxy(443, true)],
        ],
    );
    assert_eq!(chain.num_hops(), 4);
    assert!(chain.supports_udp());
}

#[test]
fn test_chain_intermediate_has_udp_final_no_udp() {
    let chain = ClientProxyChain::new(
        vec![direct_entry(0)],
        vec![vec![mock_proxy(443, true)], vec![mock_proxy(8080, false)]],
    );
    assert_eq!(chain.num_hops(), 3);
    assert!(!chain.supports_udp());
}

#[test]
fn test_chain_pooled_final_hop_partial_udp() {
    let chain = ClientProxyChain::new(
        vec![direct_entry(0)],
        vec![vec![
            mock_proxy(8080, false),
            mock_proxy(443, true),
            mock_proxy(444, true),
        ]],
    );
    assert_eq!(chain.num_hops(), 2);
    assert!(chain.supports_udp());
}

#[test]
fn test_chain_pooled_final_hop_no_udp() {
    let chain = ClientProxyChain::new(
        vec![direct_entry(0)],
        vec![vec![mock_proxy(8080, false), mock_proxy(1080, false)]],
    );
    assert_eq!(chain.num_hops(), 2);
    assert!(!chain.supports_udp());
}

#[test]
fn test_chain_complex_multi_hop_mixed_udp() {
    let chain = ClientProxyChain::new(
        vec![direct_entry(0)],
        vec![
            vec![mock_proxy(8080, false)],
            vec![mock_proxy(1080, false)],
            vec![mock_proxy(8081, false), mock_proxy(443, true)],
        ],
    );
    assert_eq!(chain.num_hops(), 4);
    assert!(chain.supports_udp());
}

#[test]
fn a_chain_without_counters_is_unattributed_not_empty() {
    let chain = ClientProxyChain::new(vec![direct_entry(0)], vec![]);
    // One handle per pool member, so indexing after selection is always
    // in bounds rather than needing a bounds check on the hot path.
    assert_eq!(chain.initial_counter_len(), 1);
}

// --- Session reuse ----------------------------------------------------
//
// A hop holding a live session answers before the chain dials. The sockets
// here are MockSocketConnector, whose connect fails, so a chain that dials
// when it should reuse fails the test.

/// A stream that reads EOF and accepts every write.
#[derive(Debug)]
struct NullStream;

impl tokio::io::AsyncRead for NullStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl tokio::io::AsyncWrite for NullStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::task::Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl crate::async_stream::AsyncPing for NullStream {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<bool>> {
        std::task::Poll::Ready(Ok(false))
    }
}
impl crate::async_stream::SocketPassthrough for NullStream {}
impl AsyncStream for NullStream {}

/// A hop holding a live session: it answers the reuse question, and records
/// the target it was asked for. Its setup path is never meant to run.
#[derive(Debug)]
struct SessionProxy {
    location: NetLocation,
    asked_for: std::sync::Mutex<Vec<NetLocation>>,
}

impl SessionProxy {
    fn new(port: u16) -> Self {
        Self {
            location: NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port),
            asked_for: std::sync::Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl ProxyConnector for SessionProxy {
    fn proxy_location(&self) -> &NetLocation {
        &self.location
    }
    fn supports_udp_over_tcp(&self) -> bool {
        false
    }
    async fn try_reuse_tcp_stream(
        &self,
        target: &ResolvedLocation,
    ) -> Option<std::io::Result<TcpClientSetupResult>> {
        self.asked_for
            .lock()
            .unwrap()
            .push(target.location().clone());
        Some(Ok(TcpClientSetupResult {
            client_stream: Box::new(NullStream),
            early_data: None,
        }))
    }
    async fn setup_tcp_stream(
        &self,
        _stream: Box<dyn AsyncStream>,
        _target: &ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        panic!("a hop with a live session was handed a fresh transport")
    }
    async fn setup_udp_bidirectional(
        &self,
        _stream: Box<dyn AsyncStream>,
        _target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        unreachable!()
    }
}

/// A hop that passes the stream through and counts its setups.
#[derive(Debug)]
struct CountingProxy {
    location: NetLocation,
    setups: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

#[async_trait]
impl ProxyConnector for CountingProxy {
    fn proxy_location(&self) -> &NetLocation {
        &self.location
    }
    fn supports_udp_over_tcp(&self) -> bool {
        false
    }
    async fn setup_tcp_stream(
        &self,
        stream: Box<dyn AsyncStream>,
        _target: &ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        self.setups
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(TcpClientSetupResult {
            client_stream: stream,
            early_data: None,
        })
    }
    async fn setup_udp_bidirectional(
        &self,
        _stream: Box<dyn AsyncStream>,
        _target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        unreachable!()
    }
}

fn destination() -> ResolvedLocation {
    NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 443).into()
}

fn resolver() -> Arc<dyn Resolver> {
    Arc::new(crate::resolver::NativeResolver::new())
}

/// The first hop holds a session: the connection is made without its socket.
#[tokio::test]
async fn a_live_session_at_the_first_hop_means_no_dial() {
    let chain = ClientProxyChain::new(
        vec![InitialHopEntry::Proxy {
            socket: mock_socket(0),
            proxy: Box::new(SessionProxy::new(8443)),
        }],
        vec![],
    );
    chain
        .connect_tcp(destination(), &resolver())
        .await
        .expect("the session was reused; the failing socket was not dialled");
}

/// A session at a middle hop carries the hops below it; the hop after it
/// still runs, on the reused stream, and the session is asked for that
/// hop's address.
#[tokio::test]
async fn a_live_session_at_a_middle_hop_skips_the_hops_below_it() {
    let setups = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let exit = NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9001);
    let chain = ClientProxyChain::new(
        vec![direct_entry(0)],
        vec![
            vec![Box::new(SessionProxy::new(8443)) as Box<dyn ProxyConnector>],
            vec![Box::new(CountingProxy {
                location: exit.clone(),
                setups: setups.clone(),
            })],
        ],
    );
    chain
        .connect_tcp(destination(), &resolver())
        .await
        .expect("reused at hop 1, hop 2 run on top");
    assert_eq!(setups.load(std::sync::atomic::Ordering::SeqCst), 1);
}

/// With no live session anywhere, the chain dials as before -- here into
/// the mock socket, which fails, proving the dial happened.
#[tokio::test]
async fn without_a_session_the_chain_dials() {
    let chain = ClientProxyChain::new(vec![proxy_entry(0, 8443, false)], vec![]);
    let err = chain
        .connect_tcp(destination(), &resolver())
        .await
        .map(|_| ())
        .unwrap_err();
    assert!(err.to_string().contains("not implemented"), "{err}");
}

/// The tests that read what was counted, which only exists with the feature.
#[cfg(feature = "control-stats")]
mod counting {
    use super::*;

    #[test]
    fn with_counters_replaces_the_unattributed_handles() {
        let _guard = crate::outbound_stats::REGISTRY_TEST_LOCK.lock().unwrap();
        let counters = installed(&[("Frankfurt", "fra1.example:443")])[0].clone();
        let chain = ClientProxyChain::new(vec![direct_entry(0)], vec![])
            .with_counters(vec![counters.clone()], vec![]);
        assert!(Arc::ptr_eq(&chain.initial_counter(0), &counters));
    }

    /// The exit is the last subsequent hop when there is one, else the
    /// initial hop.
    #[test]
    fn exit_counters_picks_the_last_hop() {
        use crate::outbound_stats::unattributed;
        let a = Arc::new(crate::outbound_stats::OutboundCounters::default());
        let b = Arc::new(crate::outbound_stats::OutboundCounters::default());
        let c = Arc::new(crate::outbound_stats::OutboundCounters::default());

        // Two subsequent hops, the exit being index 1 of the second pool.
        let two_hop = ClientProxyChain::exit_counters(
            std::slice::from_ref(&a),
            &[vec![b.clone()], vec![unattributed(), c.clone()]],
            0,
            Some(1),
        );
        assert!(Arc::ptr_eq(&two_hop, &c));

        // No subsequent hop at all: the initial hop is the exit.
        let single = ClientProxyChain::exit_counters(&[unattributed(), a.clone()], &[], 1, None);
        assert!(Arc::ptr_eq(&single, &a));
    }

    /// Install these outbounds and hand back their counters, in order.
    /// install is the only writer, so a test that wants real counters has to
    /// declare them the way a running config would.
    ///
    /// This WRITES process-global state: the caller must already hold
    /// `REGISTRY_TEST_LOCK`, or it will race every other test that reads the
    /// registry.
    fn installed(entries: &[(&str, &str)]) -> Vec<Arc<crate::outbound_stats::OutboundCounters>> {
        let mut set = crate::outbound_stats::OutboundSet::default();
        for (name, address) in entries {
            set.insert(name, address).unwrap();
        }
        crate::outbound_stats::install(&set);
        entries
            .iter()
            .map(|(name, _)| crate::outbound_stats::lookup(name))
            .collect()
    }

    // --- Connecting mocks -------------------------------------------------
    //
    // The mocks above return Err from every connect method: they test
    // structure, not connections. Counting can only be tested through a
    // connection that completes, so these carry real bytes.

    /// A socket that actually connects: hands out one half of a duplex pipe
    /// and lets the test keep the other, so bytes can be driven through.
    #[derive(Debug)]
    struct PipeSocket {
        half: std::sync::Mutex<Option<tokio::io::DuplexStream>>,
    }

    impl PipeSocket {
        /// Not `new`: this returns the connector paired with the peer half,
        /// not a bare Self.
        fn pair() -> (Box<dyn SocketConnector>, tokio::io::DuplexStream) {
            let (ours, theirs) = tokio::io::duplex(4096);
            let socket = Self {
                half: std::sync::Mutex::new(Some(ours)),
            };
            (Box::new(socket), theirs)
        }
    }

    #[async_trait]
    impl SocketConnector for PipeSocket {
        async fn connect(
            &self,
            _resolver: &Arc<dyn Resolver>,
            _address: &ResolvedLocation,
        ) -> std::io::Result<Box<dyn AsyncStream>> {
            let half = self
                .half
                .lock()
                .unwrap()
                .take()
                .expect("PipeSocket connects once");
            Ok(Box::new(crate::async_stream::testing::TestStream(half)))
        }

        async fn connect_udp_bidirectional(
            &self,
            _resolver: &Arc<dyn Resolver>,
            _target: ResolvedLocation,
        ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
            Err(std::io::Error::other("PipeSocket has no native UDP"))
        }

        fn bind_interface(&self) -> Option<&str> {
            None
        }
    }

    /// A proxy hop that performs no handshake: the stream goes out as it came
    /// in. Enough to prove which hop's counter a chain credits.
    #[derive(Debug)]
    struct PassthroughProxy {
        location: NetLocation,
    }

    #[async_trait]
    impl ProxyConnector for PassthroughProxy {
        fn proxy_location(&self) -> &NetLocation {
            &self.location
        }

        fn supports_udp_over_tcp(&self) -> bool {
            true
        }

        async fn setup_tcp_stream(
            &self,
            stream: Box<dyn AsyncStream>,
            _target: &ResolvedLocation,
        ) -> std::io::Result<TcpClientSetupResult> {
            Ok(TcpClientSetupResult {
                client_stream: stream,
                early_data: None,
            })
        }

        async fn setup_udp_bidirectional(
            &self,
            _stream: Box<dyn AsyncStream>,
            _target: ResolvedLocation,
        ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
            Ok(Box::new(SinkMessageStream))
        }
    }

    fn passthrough(port: u16) -> Box<dyn ProxyConnector> {
        Box::new(PassthroughProxy {
            location: NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port),
        })
    }

    /// A message stream that accepts every write and never yields a read.
    #[derive(Debug, Default)]
    struct SinkMessageStream;

    impl crate::async_stream::AsyncReadMessage for SinkMessageStream {
        fn poll_read_message(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Pending
        }
    }

    impl crate::async_stream::AsyncWriteMessage for SinkMessageStream {
        fn poll_write_message(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &[u8],
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    impl crate::async_stream::AsyncFlushMessage for SinkMessageStream {
        fn poll_flush_message(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    impl crate::async_stream::AsyncShutdownMessage for SinkMessageStream {
        fn poll_shutdown_message(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    impl crate::async_stream::AsyncPing for SinkMessageStream {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<bool>> {
            std::task::Poll::Ready(Ok(false))
        }
    }

    impl AsyncMessageStream for SinkMessageStream {}

    fn test_location() -> ResolvedLocation {
        ResolvedLocation::new(NetLocation::from_ip_addr(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            443,
        ))
    }

    fn test_resolver() -> Arc<dyn Resolver> {
        Arc::new(crate::resolver::NativeResolver::new())
    }

    /// The relay is where the bytes physically flow; the exit is the server a
    /// person means. Only the exit may be credited.
    // The guard is held across awaits on purpose. `#[tokio::test]` runs a
    // current-thread runtime, so there is no other task on this thread to
    // starve, and no test takes this lock twice -- it exists precisely to stop
    // these tests interleaving on the process-global registry.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn a_two_hop_chain_credits_the_exit_not_the_relay() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let _guard = crate::outbound_stats::REGISTRY_TEST_LOCK.lock().unwrap();
        crate::outbound_stats::reset_for_test();

        let handles = installed(&[
            ("direct", "0.0.0.0:0"),
            ("relay", "relay:1080"),
            ("exit", "exit:1081"),
        ]);
        let (direct, relay, exit) = (handles[0].clone(), handles[1].clone(), handles[2].clone());

        let (socket, mut peer) = PipeSocket::pair();
        let chain = ClientProxyChain::new(
            vec![InitialHopEntry::Direct(socket)],
            vec![vec![passthrough(1080)], vec![passthrough(1081)]],
        )
        .with_counters(vec![direct], vec![vec![relay], vec![exit]]);

        let mut result = chain
            .connect_tcp(test_location(), &test_resolver())
            .await
            .unwrap();

        // Deliberately asymmetric, so a transposition cannot pass.
        result.client_stream.write_all(&[1u8; 5]).await.unwrap();
        peer.write_all(&[2u8; 13]).await.unwrap();
        let mut buf = [0u8; 13];
        result.client_stream.read_exact(&mut buf).await.unwrap();

        let by_name = |n: &str| {
            crate::outbound_stats::snapshot_all()
                .into_iter()
                .find(|o| o.name == n)
                .unwrap()
        };
        assert_eq!(by_name("exit").upload_bytes, 5);
        assert_eq!(by_name("exit").download_bytes, 13);
        assert_eq!(by_name("exit").active_connections, 1);
        assert_eq!(by_name("relay").upload_bytes, 0);
        assert_eq!(by_name("relay").download_bytes, 0);
        assert_eq!(by_name("relay").active_connections, 0);
        assert_eq!(by_name("direct").active_connections, 0);

        drop(result);
        assert_eq!(by_name("exit").active_connections, 0);
    }

    /// A single-hop chain has no subsequent hop, so the initial hop IS the
    /// exit -- and a pool credits the member actually selected.
    // The guard is held across awaits on purpose. `#[tokio::test]` runs a
    // current-thread runtime, so there is no other task on this thread to
    // starve, and no test takes this lock twice -- it exists precisely to stop
    // these tests interleaving on the process-global registry.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn a_pool_credits_the_member_selected() {
        let _guard = crate::outbound_stats::REGISTRY_TEST_LOCK.lock().unwrap();
        crate::outbound_stats::reset_for_test();

        let handles = installed(&[("first", "first:1"), ("second", "second:2")]);
        let (first, second) = (handles[0].clone(), handles[1].clone());

        let (socket_a, _peer_a) = PipeSocket::pair();
        let (socket_b, _peer_b) = PipeSocket::pair();
        let chain = ClientProxyChain::new(
            vec![
                InitialHopEntry::Direct(socket_a),
                InitialHopEntry::Direct(socket_b),
            ],
            vec![],
        )
        .with_counters(vec![first, second], vec![]);

        // Round-robin: the first connection takes member 0, the second member 1.
        let a = chain
            .connect_tcp(test_location(), &test_resolver())
            .await
            .unwrap();
        let b = chain
            .connect_tcp(test_location(), &test_resolver())
            .await
            .unwrap();

        let all = crate::outbound_stats::snapshot_all();
        assert_eq!(
            all.iter()
                .find(|o| o.name == "first")
                .unwrap()
                .active_connections,
            1
        );
        assert_eq!(
            all.iter()
                .find(|o| o.name == "second")
                .unwrap()
                .active_connections,
            1
        );

        drop(a);
        drop(b);
        let all = crate::outbound_stats::snapshot_all();
        assert!(all.iter().all(|o| o.active_connections == 0));
    }

    // The guard is held across awaits on purpose. `#[tokio::test]` runs a
    // current-thread runtime, so there is no other task on this thread to
    // starve, and no test takes this lock twice -- it exists precisely to stop
    // these tests interleaving on the process-global registry.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn udp_payload_is_credited_to_the_final_hop_without_a_connection_slot() {
        let _guard = crate::outbound_stats::REGISTRY_TEST_LOCK.lock().unwrap();
        crate::outbound_stats::reset_for_test();

        let only = installed(&[("only", "only:1080")])[0].clone();
        let (socket, _peer) = PipeSocket::pair();
        let chain = ClientProxyChain::new(
            vec![InitialHopEntry::Proxy {
                socket,
                proxy: passthrough(1080),
            }],
            vec![],
        )
        .with_counters(vec![only], vec![]);

        let mut stream = chain
            .connect_udp_bidirectional(&test_resolver(), test_location())
            .await
            .unwrap();

        std::future::poll_fn(|cx| {
            std::pin::Pin::new(&mut *stream).poll_write_message(cx, &[0u8; 11])
        })
        .await
        .unwrap();

        let all = crate::outbound_stats::snapshot_all();
        let only = all
            .iter()
            .find(|o| o.name == "only")
            .unwrap_or_else(|| panic!("registry held {all:?}"));
        assert_eq!(only.upload_bytes, 11, "registry held {all:?}");
        // A datagram session is not a connection.
        assert_eq!(only.active_connections, 0);
    }
}
