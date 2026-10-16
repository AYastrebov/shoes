use super::*;
use crate::config::{RuleActionConfig, RuleConfig};
use crate::option_util::OneOrSome;
use crate::quic_outbound::testing::{direct_selector, spawn_udp_echo, test_resolver};
use crate::routing::buffers::SparePool;
use crate::tcp::tcp_client_handler_factory::create_tcp_client_proxy_selector;
use std::sync::Mutex;
use std::task::Waker;

/// A scripted server-side stream: hands the router a fixed list of
/// packets, records everything the router writes back, and can close
/// itself once a given number of replies have been recorded.
///
/// Closing means what a dead client connection means: reads return EOF and
/// writes fail. That pairing exists because the router only finishes when
/// both directions are down - a read EOF alone leaves it waiting for
/// replies it may still have to deliver.
struct ScriptedInner {
    script: VecDeque<(NetLocation, Vec<u8>)>,
    replies: Vec<(SocketAddr, Vec<u8>)>,
    /// Replies to accept before the stream acts closed. usize::MAX keeps
    /// it open forever.
    close_after_replies: usize,
    /// Registered when a read returns Pending; recording a reply wakes it
    /// so the router notices the stream has since closed.
    read_waker: Option<Waker>,
}

impl ScriptedInner {
    fn closed(&self) -> bool {
        self.replies.len() >= self.close_after_replies
    }
}

struct ScriptedServer {
    inner: Arc<Mutex<ScriptedInner>>,
}

fn scripted(
    script: Vec<(NetLocation, Vec<u8>)>,
    close_after_replies: usize,
) -> (ScriptedServer, Arc<Mutex<ScriptedInner>>) {
    let inner = Arc::new(Mutex::new(ScriptedInner {
        script: script.into(),
        replies: Vec::new(),
        close_after_replies,
        read_waker: None,
    }));
    (
        ScriptedServer {
            inner: inner.clone(),
        },
        inner,
    )
}

impl AsyncReadTargetedMessage for ScriptedServer {
    fn poll_read_targeted_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<NetLocation>> {
        let mut inner = self.inner.lock().unwrap();
        if let Some((destination, payload)) = inner.script.pop_front() {
            buf.put_slice(&payload);
            return Poll::Ready(Ok(destination));
        }
        if inner.closed() {
            // A zero-length read is how the router learns of EOF.
            return Poll::Ready(Ok(NetLocation::UNSPECIFIED));
        }
        inner.read_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWriteSourcedMessage for ScriptedServer {
    fn poll_write_sourced_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
        source: &SocketAddr,
    ) -> Poll<io::Result<()>> {
        let mut inner = self.inner.lock().unwrap();
        if inner.closed() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "scripted stream closed",
            )));
        }
        inner.replies.push((*source, buf.to_vec()));
        if inner.closed()
            && let Some(waker) = inner.read_waker.take()
        {
            waker.wake();
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncFlushMessage for ScriptedServer {
    fn poll_flush_message(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncShutdownMessage for ScriptedServer {
    fn poll_shutdown_message(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncPing for ScriptedServer {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncTargetedMessageStream for ScriptedServer {}

fn location(addr: SocketAddr) -> NetLocation {
    let address = match addr.ip() {
        std::net::IpAddr::V4(v4) => Address::Ipv4(v4),
        std::net::IpAddr::V6(v6) => Address::Ipv6(v6),
    };
    NetLocation::new(address, addr.port())
}

/// Poll the recorded replies until there are `count`, or fail loudly.
/// Sleeping rather than a notification keeps the double simple, and the
/// suite spends the wait only when something is actually in flight.
async fn wait_for_replies(inner: &Arc<Mutex<ScriptedInner>>, count: usize) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if inner.lock().unwrap().replies.len() >= count {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {count} replies, have {}",
            inner.lock().unwrap().replies.len()
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Hand the router one more packet after it has started, which a fixed
/// script cannot do: the cap tests need "and then, later, another".
fn push_packet(inner: &Arc<Mutex<ScriptedInner>>, destination: SocketAddr, payload: &[u8]) {
    let mut inner = inner.lock().unwrap();
    inner
        .script
        .push_back((location(destination), payload.to_vec()));
    if let Some(waker) = inner.read_waker.take() {
        waker.wake();
    }
}

/// "This must not arrive": long enough for a loopback echo to have come
/// back many times over, short enough not to be felt in the suite.
async fn assert_no_further_reply(inner: &Arc<Mutex<ScriptedInner>>, have: usize) {
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(
        inner.lock().unwrap().replies.len(),
        have,
        "a datagram over the cap must be dropped, not answered"
    );
}

/// Holds the router's only slot with a session to `first`, shows that a
/// second destination is refused while it lives, and that the slot comes
/// back once it has idled past the listener's timeout.
async fn cap_then_expiry(first: SocketAddr, first_replies: usize) {
    let second = spawn_udp_echo().await;
    // `second` is scripted straight after `first`, so it is judged while
    // the first session exists or is being created, whichever it is.
    let (stream, inner) = scripted(
        vec![
            (location(first), b"one".to_vec()),
            (location(second), b"over the cap".to_vec()),
        ],
        usize::MAX,
    );
    let resolver = test_resolver();
    // 400 ms against a 150 ms "no reply" window: on a loaded runner the
    // window may end late, and a first session that had expired by then
    // would make this test pass for the wrong reason further down.
    let timeout = Duration::from_millis(400);
    let limits = RouterLimits {
        session_timeout: timeout,
        max_sessions: 1,
        shared_budget: None,
    };

    let router = tokio::spawn(run_udp_routing_with_limits(
        ServerStream::Targeted(Box::new(stream)),
        direct_selector(resolver.clone()),
        resolver,
        false,
        limits,
    ));

    wait_for_replies(&inner, first_replies).await;
    assert_no_further_reply(&inner, first_replies).await;

    // Let the first session sit idle past its timeout.
    tokio::time::sleep(timeout).await;
    push_packet(&inner, second, b"after expiry");
    wait_for_replies(&inner, first_replies + 1).await;
    {
        let inner = inner.lock().unwrap();
        let last = inner.replies.last().unwrap();
        assert_eq!(last.0, second);
        assert_eq!(last.1, b"after expiry");
    }
    router.abort();
}

/// A full table drops the new flow and keeps the old one, which is what a
/// full conntrack table does; and the slot comes back when the session
/// that held it expires, so the cap is a ceiling rather than a latch.
///
/// The destination answers, so the session's timer is the one its last
/// activity reset.
#[tokio::test]
async fn test_the_session_cap_refuses_a_new_destination_and_expiry_frees_it() {
    cap_then_expiry(spawn_udp_echo().await, 1).await;
}

/// The same, against a destination that never answers, which is what most
/// of a full table looks like under a scan or a flood: sessions nobody
/// replies to. Only the client's own write ever touches this session's
/// timer, so it is the write path's use of the listener's timeout that
/// frees the slot here, where the test above leans on the read path's.
///
/// Neither this test nor the one above can see the timeout a session is
/// *created* with: a real socket accepts its first write at once, which
/// resets the timer. `..._first_write_stalls_...` below covers that one,
/// with a remote that does not.
#[tokio::test]
async fn test_a_session_that_never_hears_back_expires_on_the_listeners_timeout() {
    let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    cap_then_expiry(silent.local_addr().unwrap(), 0).await;
}

/// What a test can see of a `FakeRemote`, and the one thing it can do to it.
#[derive(Default)]
struct FakeRemoteState {
    writes_stay_pending: bool,
    shutdown_may_finish: bool,
    shutdown_polled: bool,
    dropped: bool,
    shutdown_waker: Option<Waker>,
}

/// A session remote that never hears back, whose writes and shutdown can
/// be held pending. The real connect path cannot produce either, and they
/// are exactly where two of the limits' promises are kept or broken.
struct FakeRemote(Arc<Mutex<FakeRemoteState>>);

impl Drop for FakeRemote {
    fn drop(&mut self) {
        self.0.lock().unwrap().dropped = true;
    }
}

impl AsyncReadMessage for FakeRemote {
    fn poll_read_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWriteMessage for FakeRemote {
    fn poll_write_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<()>> {
        if self.0.lock().unwrap().writes_stay_pending {
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }
}

impl AsyncFlushMessage for FakeRemote {
    fn poll_flush_message(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncShutdownMessage for FakeRemote {
    fn poll_shutdown_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.0.lock().unwrap();
        state.shutdown_polled = true;
        if state.shutdown_may_finish {
            return Poll::Ready(Ok(()));
        }
        state.shutdown_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncPing for FakeRemote {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncMessageStream for FakeRemote {}

/// Run a router whose every session gets a `FakeRemote` sharing `state`.
/// Owns the server stream so the whole thing can be spawned.
async fn run_with_fake_remotes(
    mut server: ServerStream,
    limits: RouterLimits,
    state: Arc<Mutex<FakeRemoteState>>,
) -> io::Result<()> {
    let resolver = test_resolver();
    let mut router = UdpRouter::new(
        &mut server,
        direct_selector(resolver.clone()),
        resolver,
        false,
        limits,
    );
    router.remote_factory = Some(Box::new(move |_destination| {
        let remote: Box<dyn AsyncMessageStream> = Box::new(FakeRemote(state.clone()));
        Box::pin(async move {
            Ok(CreateOutcome::Remote(SessionCreateResult {
                remote,
                resolved_addr: "192.0.2.1:9".parse().unwrap(),
            }))
        })
    }));
    router.await
}

async fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting until {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// A session whose first write never completes is never touched again, so
/// the only deadline it ever has is the one it was created with. That one
/// has to be the listener's timeout too: with the 200-second default left
/// there, a destination that accepts nothing holds its slot, and its share
/// of the listener's budget, for over three minutes.
#[tokio::test]
async fn test_a_session_whose_first_write_stalls_expires_on_the_listeners_timeout() {
    let state = Arc::new(Mutex::new(FakeRemoteState {
        writes_stay_pending: true,
        shutdown_may_finish: true,
        ..Default::default()
    }));
    let (stream, _inner) = scripted(
        vec![(location("192.0.2.1:9".parse().unwrap()), b"one".to_vec())],
        usize::MAX,
    );
    let limits = RouterLimits {
        session_timeout: Duration::from_millis(100),
        ..RouterLimits::default()
    };

    let router = tokio::spawn(run_with_fake_remotes(
        ServerStream::Targeted(Box::new(stream)),
        limits,
        state.clone(),
    ));

    wait_until(
        "the stalled session expires and its remote is dropped",
        || state.lock().unwrap().dropped,
    )
    .await;
    router.abort();
}

/// The budget counts descriptors, and a removed session's remote keeps its
/// descriptor until its shutdown completes. Its share must stay taken for
/// exactly that long: returned at removal, it admits a new session on top
/// of a socket that is still open, and under churn that is over the cap.
#[tokio::test]
async fn test_a_remote_still_shutting_down_keeps_its_share_of_the_budget() {
    let state = Arc::new(Mutex::new(FakeRemoteState::default()));
    let (stream, _inner) = scripted(
        vec![(location("192.0.2.1:9".parse().unwrap()), b"one".to_vec())],
        usize::MAX,
    );
    let budget = Arc::new(tokio::sync::Semaphore::new(1));
    let limits = RouterLimits {
        session_timeout: Duration::from_millis(100),
        shared_budget: Some(budget.clone()),
        ..RouterLimits::default()
    };

    let router = tokio::spawn(run_with_fake_remotes(
        ServerStream::Targeted(Box::new(stream)),
        limits,
        state.clone(),
    ));

    // Expiry removes the session, and the router starts shutting its
    // remote down; the fake keeps that pending.
    wait_until("the expired session's remote is being shut down", || {
        state.lock().unwrap().shutdown_polled
    })
    .await;
    assert_eq!(
        budget.available_permits(),
        0,
        "the socket is still open, so its share is still taken"
    );

    let waker = {
        let mut state = state.lock().unwrap();
        state.shutdown_may_finish = true;
        state.shutdown_waker.take()
    };
    waker
        .expect("a pending shutdown registers its waker")
        .wake();

    wait_until("the remote is dropped", || state.lock().unwrap().dropped).await;
    assert_eq!(budget.available_permits(), 1, "and now it is back");
    router.abort();
}

/// A `tproxy` listener runs one router per LAN client and promises one
/// `udp_nat_max` for all of them. The budget is what makes that true, and
/// a router that goes away, however it goes, has to give its share back.
#[tokio::test]
async fn test_routers_sharing_a_budget_are_capped_together() {
    let first = spawn_udp_echo().await;
    let second = spawn_udp_echo().await;
    let resolver = test_resolver();
    let budget = Arc::new(tokio::sync::Semaphore::new(1));
    let limits = RouterLimits {
        shared_budget: Some(budget.clone()),
        ..RouterLimits::default()
    };

    let (stream_a, inner_a) = scripted(vec![(location(first), b"a".to_vec())], usize::MAX);
    let router_a = tokio::spawn(run_udp_routing_with_limits(
        ServerStream::Targeted(Box::new(stream_a)),
        direct_selector(resolver.clone()),
        resolver.clone(),
        false,
        limits.clone(),
    ));
    wait_for_replies(&inner_a, 1).await;
    assert_eq!(
        budget.available_permits(),
        0,
        "the session holds the permit"
    );

    let (stream_b, inner_b) = scripted(vec![(location(second), b"b".to_vec())], usize::MAX);
    let router_b = tokio::spawn(run_udp_routing_with_limits(
        ServerStream::Targeted(Box::new(stream_b)),
        direct_selector(resolver.clone()),
        resolver,
        false,
        limits,
    ));
    assert_no_further_reply(&inner_b, 0).await;

    // The first client goes away mid-session: no expiry, no clean close.
    router_a.abort();
    let _ = router_a.await;
    assert_eq!(budget.available_permits(), 1, "a dropped router returns it");

    push_packet(&inner_b, second, b"b again");
    wait_for_replies(&inner_b, 1).await;
    assert_eq!(inner_b.lock().unwrap().replies[0].1, b"b again");
    router_b.abort();
}

#[tokio::test]
async fn test_a_packet_round_trips_to_its_destination() {
    let echo = spawn_udp_echo().await;
    let (stream, inner) = scripted(vec![(location(echo), b"ping".to_vec())], usize::MAX);
    let resolver = test_resolver();

    let router = tokio::spawn(run_udp_routing(
        ServerStream::Targeted(Box::new(stream)),
        direct_selector(resolver.clone()),
        resolver,
        false,
    ));

    wait_for_replies(&inner, 1).await;
    {
        let inner = inner.lock().unwrap();
        assert_eq!(inner.replies[0].0, echo, "the reply must name its source");
        assert_eq!(inner.replies[0].1, b"ping", "the echo must round-trip");
    }
    router.abort();
}

/// A router between datagrams holds no packet buffers: a tproxy
/// listener runs one router per client socket, mostly idle, and two
/// 64 KiB buffers kept by each were the bulk of a client's cost.
#[tokio::test]
async fn test_an_idle_router_holds_no_buffers() {
    let echo = spawn_udp_echo().await;
    let (stream, inner) = scripted(vec![(location(echo), b"ping".to_vec())], usize::MAX);
    let mut server = ServerStream::Targeted(Box::new(stream));
    let resolver = test_resolver();
    let mut router = UdpRouter::new(
        &mut server,
        direct_selector(resolver.clone()),
        resolver,
        false,
        RouterLimits::default(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while inner.lock().unwrap().replies.is_empty() {
        assert!(Instant::now() < deadline, "the echo never came back");
        let poll = std::future::poll_fn(|cx| Poll::Ready(Pin::new(&mut router).poll(cx))).await;
        assert!(poll.is_pending(), "the router must still be running");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        std::future::poll_fn(|cx| Poll::Ready(Pin::new(&mut router).poll(cx)))
            .await
            .is_pending()
    );
    assert_eq!(
        (router.remote_write_pool.held, router.server_write_pool.held),
        (0, 0),
        "buffers held by an idle router"
    );
}

/// Parked buffers are reused by the next router rather than allocated
/// again, so going idle costs the busy path nothing; and the spares are
/// bounded, so many routers parking at once free the rest. Each test has
/// spares of its own: the process's are shared by every router in the
/// suite.
#[test]
fn test_parked_buffers_are_reused_and_bounded() {
    static SPARES: SparePool = SparePool::new(4);
    let mut first = BufferPool::with_spares(1, &SPARES);
    let buf = first.acquire().unwrap();
    let address = buf.as_ptr();
    first.release(buf);
    first.park();
    assert_eq!(first.held, 0);

    let mut second = BufferPool::with_spares(1, &SPARES);
    let reused = second.acquire().unwrap();
    assert_eq!(reused.as_ptr(), address, "a parked buffer is reused");

    let mut many = BufferPool::with_spares(6, &SPARES);
    let bufs: Vec<_> = (0..6).map(|_| many.acquire().unwrap()).collect();
    for buf in bufs {
        many.release(buf);
    }
    many.park();
    assert_eq!(many.held, 0);
    assert_eq!(SPARES.buffers.lock().unwrap().len(), 4);

    SPARES.clear();
    assert!(SPARES.buffers.lock().unwrap().is_empty());
}

/// A parked buffer goes to whichever router wakes next, which may serve
/// another client or another user: what a read left in it is zeroed
/// first, including in a buffer that was still queued at the last park.
#[test]
fn test_a_parked_buffer_carries_no_datagram_to_its_next_router() {
    static SPARES: SparePool = SparePool::new(4);
    let mut pool = BufferPool::with_spares(2, &SPARES);
    let mut free = pool.acquire().unwrap();
    let mut queued = pool.acquire().unwrap();
    free[..100].fill(0xAA);
    pool.mark_used(100);
    queued[..1400].fill(0xBB);
    pool.mark_used(1400);

    pool.release(free);
    pool.park(); // `queued` is still out, waiting on a write
    pool.release(queued);
    pool.park();

    let mut spares = SPARES.buffers.lock().unwrap();
    assert_eq!(spares.len(), 2);
    for buf in spares.drain(..) {
        assert!(
            buf[..1400].iter().all(|&b| b == 0),
            "a datagram's bytes survived parking"
        );
    }
}

#[tokio::test]
async fn test_two_destinations_get_separate_sessions() {
    let first = spawn_udp_echo().await;
    let second = spawn_udp_echo().await;
    let (stream, inner) = scripted(
        vec![
            (location(first), b"to the first".to_vec()),
            (location(second), b"to the second".to_vec()),
        ],
        usize::MAX,
    );
    let resolver = test_resolver();

    let router = tokio::spawn(run_udp_routing(
        ServerStream::Targeted(Box::new(stream)),
        direct_selector(resolver.clone()),
        resolver,
        false,
    ));

    wait_for_replies(&inner, 2).await;
    {
        let inner = inner.lock().unwrap();
        let by_source = |addr: SocketAddr| {
            inner
                .replies
                .iter()
                .find(|(source, _)| *source == addr)
                .map(|(_, payload)| payload.clone())
        };
        assert_eq!(
            by_source(first).as_deref(),
            Some(b"to the first".as_slice()),
            "each reply must come back attributed to its own destination"
        );
        assert_eq!(
            by_source(second).as_deref(),
            Some(b"to the second".as_slice())
        );
    }
    router.abort();
}

/// A destination the rules block must not take the router down, and must
/// not stop traffic to destinations that are allowed.
/// Run a router for one packet to `destination`, its session created by
/// `outcome`, and report whether the destination was remembered as blocked.
async fn remembered_as_blocked(outcome: fn() -> io::Result<CreateOutcome>) -> bool {
    let destination: SocketAddr = "192.0.2.7:9".parse().unwrap();
    let (stream, _inner) = scripted(vec![(location(destination), b"one".to_vec())], usize::MAX);
    let mut server = ServerStream::Targeted(Box::new(stream));
    let resolver = test_resolver();
    let mut router = UdpRouter::new(
        &mut server,
        direct_selector(resolver.clone()),
        resolver,
        false,
        RouterLimits::default(),
    );
    router.remote_factory = Some(Box::new(move |_| Box::pin(async move { outcome() })));
    let _ = tokio::time::timeout(Duration::from_millis(200), &mut router).await;
    router.blocked.contains(&location(destination))
}

/// A socket's own `EACCES` is a failure to retry, not a rule: it used to
/// share `PermissionDenied` with "blocked by rules" and was cached as one,
/// so the destination stayed unreachable for as long as the LRU kept it.
#[tokio::test]
async fn test_a_failed_connect_is_not_remembered_as_a_block() {
    assert!(
        !remembered_as_blocked(|| Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Permission denied (os error 13)"
        )))
        .await
    );
}

#[tokio::test]
async fn test_a_rules_block_is_remembered() {
    assert!(remembered_as_blocked(|| Ok(CreateOutcome::Blocked)).await);
}

#[tokio::test]
async fn test_a_blocked_destination_does_not_stall_the_rest() {
    let echo = spawn_udp_echo().await;
    let resolver = test_resolver();

    let block_rule = RuleConfig {
        masks: OneOrSome::One(crate::address::NetLocationMask::from("10.0.0.0/8:0").unwrap()),
        action: RuleActionConfig::Block,
        ..Default::default()
    };
    let selector = Arc::new(create_tcp_client_proxy_selector(
        vec![block_rule, RuleConfig::default()],
        resolver.clone(),
    ));

    let (stream, inner) = scripted(
        vec![
            // TEST-NET-style address inside the blocked range; blocking
            // must happen before any socket is opened toward it.
            (
                location("10.1.2.3:9".parse().unwrap()),
                b"must be dropped".to_vec(),
            ),
            (location(echo), b"must flow".to_vec()),
        ],
        usize::MAX,
    );

    let router = tokio::spawn(run_udp_routing(
        ServerStream::Targeted(Box::new(stream)),
        selector,
        resolver,
        false,
    ));

    wait_for_replies(&inner, 1).await;
    {
        let inner = inner.lock().unwrap();
        assert_eq!(
            inner.replies.len(),
            1,
            "the blocked packet must get no reply"
        );
        assert_eq!(inner.replies[0].0, echo);
        assert_eq!(inner.replies[0].1, b"must flow");
    }
    router.abort();
}

/// The router finishes only when the server stream is dead in both
/// directions: reads at EOF and a write having failed. The double closes
/// itself after the first reply, so the second echo reply is the write
/// that fails - after which run_udp_routing must return rather than hang.
#[tokio::test]
async fn test_the_router_exits_once_the_server_stream_dies() {
    let echo = spawn_udp_echo().await;
    let (stream, _inner) = scripted(
        vec![
            (location(echo), b"first".to_vec()),
            (location(echo), b"second".to_vec()),
        ],
        1,
    );
    let resolver = test_resolver();

    let result = tokio::time::timeout(
        Duration::from_secs(5),
        run_udp_routing(
            ServerStream::Targeted(Box::new(stream)),
            direct_selector(resolver.clone()),
            resolver,
            false,
        ),
    )
    .await;

    assert!(
        result.is_ok(),
        "the router must terminate when the server stream is dead both ways"
    );
}
