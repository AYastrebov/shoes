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
    /// Acts as a stream with one fixed destination, which drops reply
    /// sources.
    drops_sources: bool,
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
        drops_sources: false,
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

    fn replies_need_source(&self) -> bool {
        !self.inner.lock().unwrap().drops_sources
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
    /// Writes fail, as a connected UDP socket's do after an ICMP refusal.
    writes_fail: bool,
    /// Datagrams the remote sends, read in order; `read_waker` is woken
    /// when a test adds one.
    inbound: VecDeque<Vec<u8>>,
    read_waker: Option<Waker>,
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
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut state = self.0.lock().unwrap();
        if let Some(datagram) = state.inbound.pop_front() {
            buf.put_slice(&datagram);
            return Poll::Ready(Ok(()));
        }
        state.read_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

/// Have a `FakeRemote` send one datagram.
fn remote_sends(state: &Arc<Mutex<FakeRemoteState>>, datagram: &[u8]) {
    let mut state = state.lock().unwrap();
    state.inbound.push_back(datagram.to_vec());
    if let Some(waker) = state.read_waker.take() {
        waker.wake();
    }
}

impl AsyncWriteMessage for FakeRemote {
    fn poll_write_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<()>> {
        if self.0.lock().unwrap().writes_fail {
            Poll::Ready(Err(io::Error::from(io::ErrorKind::ConnectionRefused)))
        } else if self.0.lock().unwrap().writes_stay_pending {
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

/// A scripted session-based server stream (XUDP's shape): hands the router
/// packets under route ids, and reports routes the client has ended
/// through `take_closed_session`.
/// What the scripted session stream does on a poll: hand over a packet,
/// or learn of an End (close the route and keep polling, as the XUDP
/// stream does inside one read).
enum SessionScript {
    Packet(MessageSessionId, SocketAddr, Vec<u8>),
    End(MessageSessionId),
}

struct ScriptedSessionInner {
    script: VecDeque<SessionScript>,
    closed: VecDeque<MessageSessionId>,
    released: Vec<MessageSessionId>,
    replies: Vec<(MessageSessionId, SocketAddr, Vec<u8>)>,
    read_waker: Option<Waker>,
}

struct ScriptedSessionServer {
    inner: Arc<Mutex<ScriptedSessionInner>>,
}

fn scripted_sessions(
    script: Vec<SessionScript>,
) -> (ScriptedSessionServer, Arc<Mutex<ScriptedSessionInner>>) {
    let inner = Arc::new(Mutex::new(ScriptedSessionInner {
        script: script.into(),
        closed: VecDeque::new(),
        released: Vec::new(),
        replies: Vec::new(),
        read_waker: None,
    }));
    (
        ScriptedSessionServer {
            inner: inner.clone(),
        },
        inner,
    )
}

impl AsyncReadSessionMessage for ScriptedSessionServer {
    fn poll_read_session_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<(MessageSessionId, SocketAddr)>> {
        let mut inner = self.inner.lock().unwrap();
        while let Some(step) = inner.script.pop_front() {
            match step {
                SessionScript::Packet(route, destination, payload) => {
                    buf.put_slice(&payload);
                    return Poll::Ready(Ok((route, destination)));
                }
                SessionScript::End(route) => inner.closed.push_back(route),
            }
        }
        inner.read_waker = Some(cx.waker().clone());
        Poll::Pending
    }

    fn take_closed_session(&mut self) -> Option<MessageSessionId> {
        self.inner.lock().unwrap().closed.pop_front()
    }

    fn release_session(&mut self, session_id: MessageSessionId) {
        self.inner.lock().unwrap().released.push(session_id);
    }
}

impl AsyncWriteSessionMessage for ScriptedSessionServer {
    fn poll_write_session_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        session_id: MessageSessionId,
        buf: &[u8],
        target: &SocketAddr,
    ) -> Poll<io::Result<()>> {
        let mut inner = self.inner.lock().unwrap();
        // XUDP drops a write under a route it has released, silently.
        if !inner.released.contains(&session_id) {
            inner.replies.push((session_id, *target, buf.to_vec()));
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncFlushMessage for ScriptedSessionServer {
    fn poll_flush_message(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncShutdownMessage for ScriptedSessionServer {
    fn poll_shutdown_message(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncPing for ScriptedSessionServer {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncSessionMessageStream for ScriptedSessionServer {}

/// A route the client ended is dropped at once, remote and all: not on the
/// session timeout, and not through the graceful shutdown an expired
/// session gets. Before, the router never heard of the End, and a reused
/// session id landed on the old remote (upstream cfal/shoes, "cancel
/// closed XUDP routes").
#[tokio::test]
async fn test_a_closed_route_drops_its_remote_at_once() {
    let state = Arc::new(Mutex::new(FakeRemoteState {
        shutdown_may_finish: false,
        ..Default::default()
    }));
    let destination: SocketAddr = "192.0.2.1:9".parse().unwrap();
    let (stream, inner) =
        scripted_sessions(vec![SessionScript::Packet(1, destination, b"one".to_vec())]);
    let limits = RouterLimits {
        session_timeout: Duration::from_secs(600),
        ..RouterLimits::default()
    };
    let router = tokio::spawn(run_with_fake_remotes(
        ServerStream::Session(Box::new(stream)),
        limits,
        state.clone(),
    ));

    // The session exists once the router has handed the packet to its remote.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!state.lock().unwrap().dropped, "the session is live");

    {
        let mut inner = inner.lock().unwrap();
        inner.closed.push_back(1);
        if let Some(waker) = inner.read_waker.take() {
            waker.wake();
        }
    }
    wait_until("the closed route's remote is dropped", || {
        state.lock().unwrap().dropped
    })
    .await;
    assert!(
        !state.lock().unwrap().shutdown_polled,
        "dropped outright, not through the graceful shutdown"
    );
    router.abort();
}

/// A route the router refuses, or whose session expires, is handed back to
/// the stream. Before, only a client's End freed an XUDP route, so a
/// long-lived wire session reaching many destinations filled the stream's
/// route limit for good although the router held none of them.
#[tokio::test]
async fn test_a_refused_or_expired_route_is_released_to_the_stream() {
    let state = Arc::new(Mutex::new(FakeRemoteState::default()));
    let (stream, inner) = scripted_sessions(vec![
        SessionScript::Packet(1, "192.0.2.1:9".parse().unwrap(), b"one".to_vec()),
        SessionScript::Packet(2, "192.0.2.2:9".parse().unwrap(), b"two".to_vec()),
    ]);
    let limits = RouterLimits {
        max_sessions: 1,
        session_timeout: Duration::from_millis(200),
        ..RouterLimits::default()
    };
    let router = tokio::spawn(run_with_fake_remotes(
        ServerStream::Session(Box::new(stream)),
        limits,
        state.clone(),
    ));

    wait_until("the route over the cap is released", || {
        inner.lock().unwrap().released == [2]
    })
    .await;
    wait_until("the expired route is released", || {
        inner.lock().unwrap().released == [2, 1]
    })
    .await;
    router.abort();
}

/// An End the stream meets inside a read that then returns Pending (the
/// XUDP stream consumes control frames within one read) drops the route on
/// that same wakeup. Nothing else wakes this router, so a drain done only
/// before the poll would leave the remote and its budget held.
#[tokio::test]
async fn test_an_end_only_read_drops_the_route_on_the_same_wakeup() {
    let state = Arc::new(Mutex::new(FakeRemoteState {
        shutdown_may_finish: false,
        ..Default::default()
    }));
    let destination: SocketAddr = "192.0.2.1:9".parse().unwrap();
    let (stream, inner) =
        scripted_sessions(vec![SessionScript::Packet(1, destination, b"one".to_vec())]);
    let limits = RouterLimits {
        session_timeout: Duration::from_secs(600),
        ..RouterLimits::default()
    };
    let router = tokio::spawn(run_with_fake_remotes(
        ServerStream::Session(Box::new(stream)),
        limits,
        state.clone(),
    ));

    // The session is up and the router is idle; the End arrives as the one
    // thing the next read finds.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!state.lock().unwrap().dropped, "the session is live");
    {
        let mut inner = inner.lock().unwrap();
        inner.script.push_back(SessionScript::End(1));
        if let Some(waker) = inner.read_waker.take() {
            waker.wake();
        }
    }
    wait_until("the route ended within the read is dropped", || {
        state.lock().unwrap().dropped
    })
    .await;
    assert!(!state.lock().unwrap().shutdown_polled);
    router.abort();
}

/// A stream with one fixed destination that the rules block ends, as the
/// direct path refused it, instead of dropping every datagram in silence
/// while the client waits.
#[tokio::test]
async fn test_a_blocked_one_destination_stream_ends() {
    use crate::address::NetLocationMask;
    use crate::client_proxy_selector::{ConnectAction, ConnectRule};
    let block_all = Arc::new(ClientProxySelector::new(vec![ConnectRule::new(
        vec![NetLocationMask::ANY],
        vec![],
        ConnectAction::new_block(),
    )]));
    let destination = location("192.0.2.9:4000".parse().unwrap());
    let (stream, inner) = scripted(vec![(destination, b"x".to_vec())], usize::MAX);
    inner.lock().unwrap().drops_sources = true;
    let mut server = ServerStream::Targeted(Box::new(stream));
    let router = async move {
        UdpRouter::new(
            &mut server,
            block_all,
            test_resolver(),
            false,
            RouterLimits::default(),
        )
        .await
    };
    tokio::time::timeout(Duration::from_secs(5), router)
        .await
        .expect("the router ends with the blocked stream")
        .unwrap();
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

/// A resolver for a listener with fake IP on, as `DnsRegistry` hands out:
/// names resolve to loopback, and the responder answers DNS from a pool.
fn fake_ip_resolver() -> Arc<dyn Resolver> {
    use crate::dns::fake_ip::{
        BypassList, FakeIpNetwork, FakeIpPool, FakeIpResolver, FakeIpResponder,
    };
    let pool =
        Arc::new(FakeIpPool::new(FakeIpNetwork::parse("198.18.0.0/16").unwrap(), 64).unwrap());
    let responder = Arc::new(FakeIpResponder::new(
        pool,
        BypassList::new(std::iter::empty::<&str>(), false),
    ));
    Arc::new(FakeIpResolver::new(
        Arc::new(crate::quic_outbound::testing::LoopbackResolver),
        responder,
    ))
}

fn dns_a_query(name: &str) -> Vec<u8> {
    use hickory_resolver::proto::op::{Message, MessageType, OpCode, Query};
    use hickory_resolver::proto::rr::{Name, RecordType};
    use std::str::FromStr;
    let mut message = Message::new(0x4242, MessageType::Query, OpCode::Query);
    message.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
    message.to_vec().unwrap()
}

fn answered_ipv4(reply: &[u8]) -> std::net::Ipv4Addr {
    use hickory_resolver::proto::op::Message;
    use hickory_resolver::proto::rr::RData;
    let message = Message::from_vec(reply).unwrap();
    message
        .answers
        .iter()
        .find_map(|record| match &record.data {
            RData::A(a) => Some(a.0),
            _ => None,
        })
        .expect("an A record")
}

/// A SOCKS-style listener with fake IP on: a query to port 53 is answered
/// from the pool, from the server the client addressed; a datagram to the
/// fake address reaches the name it stands for and its reply comes back
/// from the fake address, not the real one; a datagram to an unmapped fake
/// address goes nowhere.
#[tokio::test]
async fn test_fake_ip_answers_dns_and_routes_the_fake_address_by_name() {
    let echo = spawn_udp_echo().await;
    let resolver = fake_ip_resolver();
    let dns_server: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let (stream, inner) = scripted(
        vec![(location(dns_server), dns_a_query("echo.test."))],
        usize::MAX,
    );
    let mut server = ServerStream::Targeted(Box::new(stream));
    let router_resolver = resolver.clone();
    let router = tokio::spawn(async move {
        let selector = direct_selector(router_resolver.clone());
        UdpRouter::new(
            &mut server,
            selector,
            router_resolver,
            false,
            RouterLimits::default(),
        )
        .await
    });

    wait_for_replies(&inner, 1).await;
    let (from, answer) = inner.lock().unwrap().replies[0].clone();
    assert_eq!(
        from, dns_server,
        "the answer comes from the server addressed"
    );
    let fake = answered_ipv4(&answer);
    assert!(
        resolver.fake_ip().unwrap().pool().is_fake_ip(fake),
        "{fake}"
    );

    let fake_addr = SocketAddr::new(fake.into(), echo.port());
    push_packet(&inner, fake_addr, b"by name");
    wait_for_replies(&inner, 2).await;
    let (from, echoed) = inner.lock().unwrap().replies[1].clone();
    assert_eq!(echoed, b"by name");
    assert_eq!(from, fake_addr, "the reply comes from the fake address");

    let unmapped: SocketAddr = "198.18.200.200:9".parse().unwrap();
    push_packet(&inner, unmapped, b"nowhere");
    assert_no_further_reply(&inner, 2).await;
    router.abort();
}

/// A DNS query addressed to a server by name is answered too, from that
/// name's own fake address: a SOCKS reply needs an address, and resolving
/// the server's name for real is what fake IP avoids.
#[tokio::test]
async fn test_fake_ip_answers_a_query_addressed_to_a_server_by_name() {
    let resolver = fake_ip_resolver();
    let by_name = NetLocation::new(Address::Hostname("dns.google".into()), 53);
    let (stream, inner) = scripted(vec![(by_name, dns_a_query("echo.test."))], usize::MAX);
    let mut server = ServerStream::Targeted(Box::new(stream));
    let router_resolver = resolver.clone();
    let router = tokio::spawn(async move {
        let selector = direct_selector(router_resolver.clone());
        UdpRouter::new(
            &mut server,
            selector,
            router_resolver,
            false,
            RouterLimits::default(),
        )
        .await
    });
    wait_for_replies(&inner, 1).await;
    let (from, answer) = inner.lock().unwrap().replies[0].clone();
    let pool = resolver.fake_ip().unwrap().pool().clone();
    let std::net::IpAddr::V4(from_ip) = from.ip() else {
        panic!("{from}")
    };
    assert_eq!(pool.lookup(from_ip).as_deref(), Some("dns.google"));
    assert_eq!(from.port(), 53);
    assert!(pool.is_fake_ip(answered_ipv4(&answer)));
    router.abort();
}

/// A fake-addressed flow and one the client addressed to the same name are
/// two sessions: the fake one's replies come from the fake address even when
/// the name's own flow was there first.
#[tokio::test]
async fn test_fake_ip_flow_does_not_merge_with_the_named_flow() {
    let echo = spawn_udp_echo().await;
    let resolver = fake_ip_resolver();
    let fake = resolver
        .fake_ip()
        .unwrap()
        .pool()
        .assign("echo.test")
        .unwrap();
    let by_name = NetLocation::new(Address::Hostname("echo.test".into()), echo.port());
    let (stream, inner) = scripted(vec![(by_name, b"named".to_vec())], usize::MAX);
    let mut server = ServerStream::Targeted(Box::new(stream));
    let router_resolver = resolver.clone();
    let router = tokio::spawn(async move {
        let selector = direct_selector(router_resolver.clone());
        UdpRouter::new(
            &mut server,
            selector,
            router_resolver,
            false,
            RouterLimits::default(),
        )
        .await
    });
    wait_for_replies(&inner, 1).await;
    let fake_addr = SocketAddr::new(fake.into(), echo.port());
    push_packet(&inner, fake_addr, b"faked");
    wait_for_replies(&inner, 2).await;
    let (from, echoed) = inner.lock().unwrap().replies[1].clone();
    assert_eq!(echoed, b"faked");
    assert_eq!(from, fake_addr, "the fake flow's own source");
    router.abort();
}

/// A query the pool does not answer, sent to a DNS server whose own address
/// is fake, is routed to the server's name, not to the fake literal.
#[tokio::test]
async fn test_fake_ip_forwards_to_a_fake_dns_server_by_name() {
    use hickory_resolver::proto::op::{Message, MessageType, OpCode, Query};
    use hickory_resolver::proto::rr::{Name, RecordType};
    use std::str::FromStr;
    let resolver = fake_ip_resolver();
    let server_ip = resolver
        .fake_ip()
        .unwrap()
        .pool()
        .assign("dns.test")
        .unwrap();
    let mut txt = Message::new(1, MessageType::Query, OpCode::Query);
    txt.add_query(Query::query(
        Name::from_str("echo.test.").unwrap(),
        RecordType::TXT,
    ));
    let (stream, _inner) = scripted(
        vec![(
            location(SocketAddr::new(server_ip.into(), 53)),
            txt.to_vec().unwrap(),
        )],
        usize::MAX,
    );
    let targets = Arc::new(Mutex::new(Vec::new()));
    let seen = targets.clone();
    let mut server = ServerStream::Targeted(Box::new(stream));
    let router = tokio::spawn(async move {
        let mut router = UdpRouter::new(
            &mut server,
            direct_selector(resolver.clone()),
            resolver,
            false,
            RouterLimits::default(),
        );
        router.remote_factory = Some(Box::new(move |target| {
            seen.lock().unwrap().push(target.clone());
            Box::pin(async { Err(io::Error::other("test: not connecting")) })
        }));
        router.await
    });
    wait_until("the forward was attempted", || {
        !targets.lock().unwrap().is_empty()
    })
    .await;
    assert_eq!(
        targets.lock().unwrap()[0],
        NetLocation::new(Address::Hostname("dns.test".into()), 53)
    );
    router.abort();
}

/// On an XUDP stream a route that only carried a DNS query answered here,
/// or a datagram to an unmapped fake address, is handed back: no session
/// holds it, and kept it would count against the stream's route limit.
#[tokio::test]
async fn test_fake_ip_releases_routes_it_answered_or_dropped() {
    let resolver = fake_ip_resolver();
    let (stream, inner) = scripted_sessions(vec![
        SessionScript::Packet(1, "8.8.8.8:53".parse().unwrap(), dns_a_query("echo.test.")),
        SessionScript::Packet(2, "198.18.200.200:9".parse().unwrap(), b"nowhere".to_vec()),
    ]);
    let mut server = ServerStream::Session(Box::new(stream));
    let router = tokio::spawn(async move {
        UdpRouter::new(
            &mut server,
            direct_selector(resolver.clone()),
            resolver,
            false,
            RouterLimits::default(),
        )
        .await
    });
    wait_until("both routes are released", || {
        let mut released = inner.lock().unwrap().released.clone();
        released.sort();
        released == [1, 2]
    })
    .await;
    assert_eq!(
        inner.lock().unwrap().replies.len(),
        1,
        "the query was answered"
    );
    router.abort();
}

/// A query to a server named by hostname is answered only if that name can
/// be given a fake address to reply from. With one slot, the name takes it,
/// the answer then cannot, and the query goes on to the server: never an
/// answer from a made-up 0.0.0.0 source, which the old order (answer first)
/// produced.
#[tokio::test]
async fn test_fake_ip_forwards_a_named_server_query_when_the_pool_is_full() {
    use crate::dns::fake_ip::{
        BypassList, FakeIpNetwork, FakeIpPool, FakeIpResolver, FakeIpResponder,
    };
    let pool =
        Arc::new(FakeIpPool::new(FakeIpNetwork::parse("198.18.0.0/16").unwrap(), 1).unwrap());
    // One slot, empty: the server's name must take it before the answer
    // can, or the answer would take it and leave no source to reply from.
    let resolver: Arc<dyn Resolver> = Arc::new(FakeIpResolver::new(
        Arc::new(crate::quic_outbound::testing::LoopbackResolver),
        Arc::new(FakeIpResponder::new(
            pool,
            BypassList::new(std::iter::empty::<&str>(), false),
        )),
    ));
    let by_name = NetLocation::new(Address::Hostname("dns.google".into()), 53);
    let (stream, inner) = scripted(
        vec![(by_name.clone(), dns_a_query("echo.test."))],
        usize::MAX,
    );
    let targets = Arc::new(Mutex::new(Vec::new()));
    let seen = targets.clone();
    let mut server = ServerStream::Targeted(Box::new(stream));
    let router = tokio::spawn(async move {
        let mut router = UdpRouter::new(
            &mut server,
            direct_selector(resolver.clone()),
            resolver,
            false,
            RouterLimits::default(),
        );
        router.remote_factory = Some(Box::new(move |target| {
            seen.lock().unwrap().push(target.clone());
            Box::pin(async { Err(io::Error::other("test: not connecting")) })
        }));
        router.await
    });
    wait_until("the query was forwarded", || {
        !targets.lock().unwrap().is_empty()
    })
    .await;
    assert_eq!(targets.lock().unwrap()[0], by_name);
    assert!(
        inner.lock().unwrap().replies.is_empty(),
        "nothing answered from 0.0.0.0"
    );
    router.abort();
}

/// Two queries answered here on one XUDP route are both delivered: the
/// route is released after the last answer, not after the first.
#[tokio::test]
async fn test_fake_ip_keeps_a_route_until_its_last_answer() {
    let resolver = fake_ip_resolver();
    let (stream, inner) = scripted_sessions(vec![
        SessionScript::Packet(1, "8.8.8.8:53".parse().unwrap(), dns_a_query("one.test.")),
        SessionScript::Packet(1, "8.8.8.8:53".parse().unwrap(), dns_a_query("two.test.")),
    ]);
    let mut server = ServerStream::Session(Box::new(stream));
    let router = tokio::spawn(async move {
        UdpRouter::new(
            &mut server,
            direct_selector(resolver.clone()),
            resolver,
            false,
            RouterLimits::default(),
        )
        .await
    });
    wait_until("the route is released", || {
        !inner.lock().unwrap().released.is_empty()
    })
    .await;
    let inner = inner.lock().unwrap();
    assert_eq!(inner.replies.len(), 2, "both answers delivered");
    assert_eq!(inner.released, [1], "released once, after the last");
    drop(inner);
    router.abort();
}

/// A stream that drops reply sources (one fixed destination: plain VLESS
/// UDP, h2mux) has its hostname judged as a name, with no local lookup to
/// make a reply address it would throw away. Routed through the router for
/// fake IP, it used to be resolved first: a local DNS lookup, and a name
/// only the proxy can resolve failed.
#[tokio::test]
async fn test_a_stream_without_reply_sources_judges_names_without_a_lookup() {
    use crate::address::NetLocationMask;
    use crate::client_proxy_selector::{ConnectAction, ConnectRule};
    use crate::dns::fake_ip::{
        BypassList, FakeIpNetwork, FakeIpPool, FakeIpResolver, FakeIpResponder,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug, Default)]
    struct Counting(AtomicUsize);
    impl Resolver for Counting {
        fn resolve_location(&self, _: &NetLocation) -> crate::resolver::ResolveFuture {
            self.0.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(vec!["192.0.2.1:53".parse().unwrap()]) })
        }
    }
    let counting = Arc::new(Counting::default());
    let pool =
        Arc::new(FakeIpPool::new(FakeIpNetwork::parse("198.18.0.0/16").unwrap(), 8).unwrap());
    let resolver: Arc<dyn Resolver> = Arc::new(FakeIpResolver::new(
        counting.clone(),
        Arc::new(FakeIpResponder::new(
            pool,
            BypassList::new(std::iter::empty::<&str>(), false),
        )),
    ));
    let block_all = Arc::new(ClientProxySelector::new(vec![ConnectRule::new(
        vec![NetLocationMask::ANY],
        vec![],
        ConnectAction::new_block(),
    )]));
    let only_far = NetLocation::new(Address::Hostname("only.far".into()), 4000);
    let (stream, inner) = scripted(vec![(only_far, b"x".to_vec())], usize::MAX);
    inner.lock().unwrap().drops_sources = true;
    let mut server = ServerStream::Targeted(Box::new(stream));
    let router = tokio::spawn(async move {
        UdpRouter::new(
            &mut server,
            block_all,
            resolver,
            false,
            RouterLimits::default(),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(counting.0.load(Ordering::SeqCst), 0, "no local lookup");
    router.abort();
}

/// A pool of `max_entries` and a resolver over it, as `DnsRegistry` hands
/// out for a listener with fake IP on.
fn small_fake_ip_resolver(
    max_entries: usize,
) -> (Arc<dyn Resolver>, Arc<crate::dns::fake_ip::FakeIpPool>) {
    use crate::dns::fake_ip::{
        BypassList, FakeIpNetwork, FakeIpPool, FakeIpResolver, FakeIpResponder,
    };
    let pool = Arc::new(
        FakeIpPool::new(FakeIpNetwork::parse("198.18.0.0/16").unwrap(), max_entries).unwrap(),
    );
    let responder = Arc::new(FakeIpResponder::new(
        pool.clone(),
        BypassList::new(std::iter::empty::<&str>(), false),
    ));
    let resolver = Arc::new(FakeIpResolver::new(
        Arc::new(crate::quic_outbound::testing::LoopbackResolver),
        responder,
    ));
    (resolver, pool)
}

/// What a session's create comes to in `spawn_router_making`.
#[derive(Clone, Copy)]
enum Made {
    /// A remote that takes every write and answers only when told to.
    Remote,
    /// A remote whose writes fail.
    RefusingWrites,
    /// The rules refused the target.
    Blocked,
    /// Resolving or connecting failed.
    Failed,
}

/// A router over `server` whose sessions are made by `made(target)` instead
/// of the connect path, each target recorded: the outcomes a test needs
/// without sockets, so paused time can drive expiry and the reuse guard.
/// What `spawn_router_making` hands back: the router's task, every target
/// a session was asked for, and every remote made, in order.
struct MadeRouter {
    router: tokio::task::JoinHandle<io::Result<()>>,
    targets: Arc<Mutex<Vec<NetLocation>>>,
    remotes: Arc<Mutex<Vec<Arc<Mutex<FakeRemoteState>>>>>,
}

fn spawn_router_making(
    server: ServerStream,
    resolver: Arc<dyn Resolver>,
    made: fn(&NetLocation) -> Made,
) -> MadeRouter {
    let targets = Arc::new(Mutex::new(Vec::new()));
    let recorded = targets.clone();
    let remotes = Arc::new(Mutex::new(Vec::new()));
    let made_remotes = remotes.clone();
    let router = tokio::spawn(async move {
        let mut server = server;
        let mut router = UdpRouter::new(
            &mut server,
            direct_selector(resolver.clone()),
            resolver,
            false,
            RouterLimits::default(),
        );
        router.remote_factory = Some(Box::new(move |target| {
            recorded.lock().unwrap().push(target.clone());
            let outcome = match made(target) {
                kind @ (Made::Remote | Made::RefusingWrites) => {
                    let state = Arc::new(Mutex::new(FakeRemoteState {
                        shutdown_may_finish: true,
                        writes_fail: matches!(kind, Made::RefusingWrites),
                        ..FakeRemoteState::default()
                    }));
                    made_remotes.lock().unwrap().push(state.clone());
                    let remote: Box<dyn AsyncMessageStream> = Box::new(FakeRemote(state));
                    Ok(CreateOutcome::Remote(SessionCreateResult {
                        remote,
                        resolved_addr: "192.0.2.1:9".parse().unwrap(),
                    }))
                }
                Made::Blocked => Ok(CreateOutcome::Blocked),
                Made::Failed => Err(io::Error::other("no route to the target")),
            };
            Box::pin(async move { outcome })
        }));
        router.await
    });
    MadeRouter {
        router,
        targets,
        remotes,
    }
}

/// Let the spawned router run until it has nothing left to do now.
async fn settle() {
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
}

fn dns_query(name: &str, record_type: hickory_resolver::proto::rr::RecordType) -> Vec<u8> {
    use hickory_resolver::proto::op::{Message, MessageType, OpCode, Query};
    use hickory_resolver::proto::rr::Name;
    use std::str::FromStr;
    let mut message = Message::new(0x4343, MessageType::Query, OpCode::Query);
    message.add_query(Query::query(Name::from_str(name).unwrap(), record_type));
    message.to_vec().unwrap()
}

/// A query sent to a fake address that stands for nothing is dropped like
/// any datagram to one, not answered from the pool.
#[tokio::test]
async fn test_fake_ip_drops_dns_to_an_unmapped_fake_address() {
    let (resolver, _pool) = small_fake_ip_resolver(64);
    let unmapped: SocketAddr = "198.18.250.250:53".parse().unwrap();
    let (stream, inner) = scripted(
        vec![(location(unmapped), dns_a_query("echo.test."))],
        usize::MAX,
    );
    let MadeRouter {
        router,
        targets,
        remotes: _,
    } = spawn_router_making(ServerStream::Targeted(Box::new(stream)), resolver, |_| {
        Made::Remote
    });
    assert_no_further_reply(&inner, 0).await;
    assert!(targets.lock().unwrap().is_empty(), "nothing dialled");
    router.abort();
}

/// A flow to a fake address in steady use keeps its mapping in use, so the
/// pool's reuse guard does not hand the address to another name while the
/// client still sends to it, though restoration ran once, at the start.
#[tokio::test(start_paused = true)]
async fn test_a_live_fake_ip_flow_keeps_its_address_from_being_recycled() {
    let (resolver, pool) = small_fake_ip_resolver(1);
    let fake = pool.assign("live.test").unwrap();
    let flow = SocketAddr::new(fake.into(), 443);
    let (stream, inner) = scripted(vec![(location(flow), b"first".to_vec())], usize::MAX);
    let MadeRouter {
        router,
        targets,
        remotes: _,
    } = spawn_router_making(ServerStream::Targeted(Box::new(stream)), resolver, |_| {
        Made::Remote
    });
    settle().await;
    for _ in 0..11 {
        tokio::time::sleep(Duration::from_secs(61)).await;
        push_packet(&inner, flow, b"again");
        settle().await;
    }
    assert_eq!(targets.lock().unwrap().len(), 1, "one session throughout");
    assert_eq!(
        pool.assign("other.test"),
        None,
        "{fake} is in use and must not be recycled"
    );
    router.abort();
}

/// A blocked fake address is cached by the name it stood for: once the
/// pool gives the address to another name, the flow goes to that name.
#[tokio::test(start_paused = true)]
async fn test_a_blocked_fake_address_is_cached_by_its_name() {
    let (resolver, pool) = small_fake_ip_resolver(1);
    let fake = pool.assign("blocked.test").unwrap();
    let flow = SocketAddr::new(fake.into(), 443);
    let (stream, inner) = scripted(vec![(location(flow), b"refused".to_vec())], usize::MAX);
    let MadeRouter {
        router,
        targets,
        remotes: _,
    } = spawn_router_making(
        ServerStream::Targeted(Box::new(stream)),
        resolver,
        |target| match target.address() {
            Address::Hostname(name) if name == "blocked.test" => Made::Blocked,
            _ => Made::Remote,
        },
    );
    settle().await;
    tokio::time::sleep(crate::dns::fake_ip::MIN_REUSE_AGE + Duration::from_secs(1)).await;
    assert_eq!(pool.assign("allowed.test"), Some(fake), "recycled");
    push_packet(&inner, flow, b"allowed now");
    settle().await;
    let targets: Vec<String> = targets
        .lock()
        .unwrap()
        .iter()
        .map(|t| t.to_string())
        .collect();
    assert_eq!(targets, ["blocked.test:443", "allowed.test:443"]);
    router.abort();
}

/// A one-destination stream whose session cannot be made (resolving or
/// connecting failed) ends, as the direct path does, rather than leave the
/// client waiting on no remote.
#[tokio::test]
async fn test_a_one_destination_stream_ends_when_its_session_fails() {
    let destination = location("192.0.2.9:4000".parse().unwrap());
    let (stream, inner) = scripted(vec![(destination, b"x".to_vec())], usize::MAX);
    inner.lock().unwrap().drops_sources = true;
    let MadeRouter {
        router,
        targets: _,
        remotes: _,
    } = spawn_router_making(
        ServerStream::Targeted(Box::new(stream)),
        test_resolver(),
        |_| Made::Failed,
    );
    tokio::time::timeout(Duration::from_secs(5), router)
        .await
        .expect("the router ends with the failed stream")
        .unwrap()
        .unwrap();
}

/// A one-destination stream ends when the client closes it, as the direct
/// copy does, rather than hold its remote until the session expires.
#[tokio::test]
async fn test_a_one_destination_stream_ends_when_the_client_closes() {
    let destination = location("192.0.2.9:4000".parse().unwrap());
    let (stream, inner) = scripted(vec![(destination, b"x".to_vec())], 0);
    inner.lock().unwrap().drops_sources = true;
    let MadeRouter {
        router,
        targets,
        remotes: _,
    } = spawn_router_making(
        ServerStream::Targeted(Box::new(stream)),
        test_resolver(),
        |_| Made::Remote,
    );
    tokio::time::timeout(Duration::from_secs(5), router)
        .await
        .expect("the router ends with the client")
        .unwrap()
        .unwrap();
    assert_eq!(targets.lock().unwrap().len(), 1, "the datagram was sent on");
}

/// A one-destination stream ends with its session's idle expiry, as the
/// direct copy ends after the same idle time, rather than re-create the
/// remote from a new source port when the client speaks again.
#[tokio::test(start_paused = true)]
async fn test_a_one_destination_stream_ends_when_its_session_expires() {
    let destination = location("192.0.2.9:4000".parse().unwrap());
    let (stream, inner) = scripted(vec![(destination, b"x".to_vec())], usize::MAX);
    inner.lock().unwrap().drops_sources = true;
    let MadeRouter {
        router,
        targets: _,
        remotes: _,
    } = spawn_router_making(
        ServerStream::Targeted(Box::new(stream)),
        test_resolver(),
        |_| Made::Remote,
    );
    settle().await;
    tokio::time::sleep(Duration::from_secs(SESSION_TIMEOUT_SECS - 1)).await;
    settle().await;
    assert!(!router.is_finished(), "still inside the idle timeout");
    tokio::time::sleep(Duration::from_secs(2)).await;
    settle().await;
    assert!(router.is_finished(), "ended with its session");
    router.await.unwrap().unwrap();
}

/// On a one-destination stream to a DNS server, queries answered from the
/// pool keep the session a forwarded query made alive: the stream is in
/// use, and it ends with that session.
#[tokio::test(start_paused = true)]
async fn test_answered_queries_keep_a_one_destination_session_alive() {
    use hickory_resolver::proto::rr::RecordType;
    let (resolver, _pool) = small_fake_ip_resolver(64);
    let server: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let (stream, inner) = scripted(
        vec![(location(server), dns_query("echo.test.", RecordType::TXT))],
        usize::MAX,
    );
    inner.lock().unwrap().drops_sources = true;
    let MadeRouter {
        router,
        targets,
        remotes: _,
    } = spawn_router_making(ServerStream::Targeted(Box::new(stream)), resolver, |_| {
        Made::Remote
    });
    settle().await;
    assert_eq!(targets.lock().unwrap().len(), 1, "the TXT query went on");
    for _ in 0..5 {
        tokio::time::sleep(Duration::from_secs(60)).await;
        push_packet(&inner, server, &dns_query("echo.test.", RecordType::A));
        settle().await;
    }
    assert_eq!(
        inner.lock().unwrap().replies.len(),
        5,
        "each A answered here"
    );
    assert!(
        !router.is_finished(),
        "in use for 300 s, past the session's idle timeout"
    );
    router.abort();
}

/// A one-destination stream that carries nothing ends after the session
/// timeout, as the direct copy does, though it never made a session.
#[tokio::test(start_paused = true)]
async fn test_an_idle_one_destination_stream_ends_without_a_session() {
    let (stream, inner) = scripted(vec![], usize::MAX);
    inner.lock().unwrap().drops_sources = true;
    let MadeRouter {
        router,
        targets,
        remotes: _,
    } = spawn_router_making(
        ServerStream::Targeted(Box::new(stream)),
        test_resolver(),
        |_| Made::Remote,
    );
    settle().await;
    tokio::time::sleep(Duration::from_secs(SESSION_TIMEOUT_SECS - 20)).await;
    settle().await;
    assert!(!router.is_finished(), "still inside the idle timeout");
    tokio::time::sleep(Duration::from_secs(40)).await;
    settle().await;
    assert!(router.is_finished(), "ended after the idle timeout");
    assert!(targets.lock().unwrap().is_empty());
    router.await.unwrap().unwrap();
}

/// A one-destination stream whose every datagram is a DNS query answered
/// here is in use, though it has no session: it lasts while they come and
/// ends the session timeout after the last.
#[tokio::test(start_paused = true)]
async fn test_answered_queries_alone_keep_a_one_destination_stream_open() {
    use hickory_resolver::proto::rr::RecordType;
    let (resolver, _pool) = small_fake_ip_resolver(64);
    let server: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let (stream, inner) = scripted(vec![], usize::MAX);
    inner.lock().unwrap().drops_sources = true;
    let MadeRouter {
        router,
        targets,
        remotes: _,
    } = spawn_router_making(ServerStream::Targeted(Box::new(stream)), resolver, |_| {
        Made::Remote
    });
    for _ in 0..5 {
        tokio::time::sleep(Duration::from_secs(60)).await;
        push_packet(&inner, server, &dns_query("echo.test.", RecordType::A));
        settle().await;
    }
    assert_eq!(inner.lock().unwrap().replies.len(), 5, "each answered here");
    assert!(targets.lock().unwrap().is_empty(), "nothing forwarded");
    assert!(!router.is_finished(), "in use for 300 s");
    // Idleness is measured on the 15 s ping tick: the end comes up to two
    // ticks after the timeout.
    tokio::time::sleep(Duration::from_secs(SESSION_TIMEOUT_SECS + 30)).await;
    settle().await;
    assert!(router.is_finished(), "ended after the last query went idle");
}

/// A one-destination stream drops reply sources, so a query to a server
/// named by hostname is answered without spending a pool slot on that
/// server's name: with one slot, the query's own name gets it.
#[tokio::test]
async fn test_a_one_destination_stream_spends_no_slot_on_the_servers_name() {
    use hickory_resolver::proto::rr::RecordType;
    let (resolver, pool) = small_fake_ip_resolver(1);
    let server = NetLocation::new(Address::Hostname("dns.google".into()), 53);
    let (stream, inner) = scripted(
        vec![(server, dns_query("echo.test.", RecordType::A))],
        usize::MAX,
    );
    inner.lock().unwrap().drops_sources = true;
    let MadeRouter {
        router,
        targets,
        remotes: _,
    } = spawn_router_making(ServerStream::Targeted(Box::new(stream)), resolver, |_| {
        Made::Remote
    });
    wait_for_replies(&inner, 1).await;
    let answer = inner.lock().unwrap().replies[0].1.clone();
    let fake = answered_ipv4(&answer);
    assert_eq!(pool.lookup(fake).as_deref(), Some("echo.test"));
    assert!(
        targets.lock().unwrap().is_empty(),
        "answered, not forwarded"
    );
    router.abort();
}

/// A one-destination stream ends when its remote fails one way, as the
/// direct copy does, rather than waiting for the other way to end too.
#[tokio::test]
async fn test_a_one_destination_stream_ends_when_its_remote_fails_one_way() {
    let destination = location("192.0.2.9:4000".parse().unwrap());
    let (stream, inner) = scripted(vec![(destination, b"x".to_vec())], usize::MAX);
    inner.lock().unwrap().drops_sources = true;
    let MadeRouter {
        router,
        targets: _,
        remotes: _,
    } = spawn_router_making(
        ServerStream::Targeted(Box::new(stream)),
        test_resolver(),
        |_| Made::RefusingWrites,
    );
    tokio::time::timeout(Duration::from_secs(5), router)
        .await
        .expect("the router ends with its remote's failure")
        .unwrap()
        .unwrap();
}

/// A flow to a fake address that only hears from its remote (the client
/// sent once, the remote keeps sending) still keeps the address in use.
#[tokio::test(start_paused = true)]
async fn test_replies_alone_keep_a_fake_address_from_being_recycled() {
    let (resolver, pool) = small_fake_ip_resolver(1);
    let fake = pool.assign("live.test").unwrap();
    let flow = SocketAddr::new(fake.into(), 443);
    let (stream, inner) = scripted(vec![(location(flow), b"hello".to_vec())], usize::MAX);
    let MadeRouter {
        router,
        targets: _,
        remotes,
    } = spawn_router_making(ServerStream::Targeted(Box::new(stream)), resolver, |_| {
        Made::Remote
    });
    settle().await;
    let remote = remotes.lock().unwrap()[0].clone();
    for _ in 0..11 {
        tokio::time::sleep(Duration::from_secs(61)).await;
        remote_sends(&remote, b"update");
        settle().await;
    }
    assert_eq!(
        inner.lock().unwrap().replies.len(),
        11,
        "every reply delivered"
    );
    assert_eq!(
        pool.assign("other.test"),
        None,
        "{fake} is in use and must not be recycled"
    );
    router.abort();
}

/// An A query answered here and a TXT query blocked on the same XUDP route:
/// the block must not release the route while the answer is still queued
/// under it, or XUDP drops the answer.
#[tokio::test]
async fn test_a_blocked_query_keeps_the_route_for_an_answer_still_queued() {
    use hickory_resolver::proto::rr::RecordType;
    let (resolver, _pool) = small_fake_ip_resolver(64);
    let server: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let (stream, inner) = scripted_sessions(vec![
        SessionScript::Packet(1, server, dns_query("one.test.", RecordType::A)),
        SessionScript::Packet(1, server, dns_query("one.test.", RecordType::TXT)),
    ]);
    let MadeRouter { router, .. } =
        spawn_router_making(ServerStream::Session(Box::new(stream)), resolver, |_| {
            Made::Blocked
        });
    wait_until("the route is released", || {
        !inner.lock().unwrap().released.is_empty()
    })
    .await;
    let inner = inner.lock().unwrap();
    assert_eq!(inner.replies.len(), 1, "the A answer was delivered");
    assert_eq!(inner.released, [1], "released once, after the answer");
    drop(inner);
    router.abort();
}

/// Queries answered here for a DNS server whose own address is fake keep
/// that address in use: it is not recycled while queries keep coming, so a
/// later forwarded query still reaches the server's name.
#[tokio::test(start_paused = true)]
async fn test_answered_queries_keep_a_fake_dns_server_address() {
    use hickory_resolver::proto::rr::RecordType;
    let (resolver, pool) = small_fake_ip_resolver(2);
    let fake = pool.assign("dns.test").unwrap();
    let server = SocketAddr::new(fake.into(), 53);
    let (stream, inner) = scripted(vec![], usize::MAX);
    let MadeRouter { router, .. } =
        spawn_router_making(ServerStream::Targeted(Box::new(stream)), resolver, |_| {
            Made::Remote
        });
    for _ in 0..11 {
        tokio::time::sleep(Duration::from_secs(61)).await;
        push_packet(&inner, server, &dns_query("x.test.", RecordType::A));
        settle().await;
    }
    assert_eq!(
        inner.lock().unwrap().replies.len(),
        11,
        "each answered here"
    );
    assert_eq!(
        pool.assign("other.test"),
        None,
        "the server's address {fake} is in use and must not be recycled"
    );
    router.abort();
}

/// A one-destination DNS stream with fake IP on is served partly here: a
/// forwarded query the rules block is dropped like any other, and the
/// stream lives on, its queued answer delivered, rather than ending as a
/// stream whose only destination was refused does.
#[tokio::test]
async fn test_a_blocked_forwarded_query_does_not_end_a_one_destination_dns_stream() {
    use hickory_resolver::proto::rr::RecordType;
    let (resolver, _pool) = small_fake_ip_resolver(64);
    let server: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let (stream, inner) = scripted(
        vec![
            (location(server), dns_query("one.test.", RecordType::A)),
            (location(server), dns_query("one.test.", RecordType::TXT)),
        ],
        usize::MAX,
    );
    inner.lock().unwrap().drops_sources = true;
    let MadeRouter {
        router, targets, ..
    } = spawn_router_making(ServerStream::Targeted(Box::new(stream)), resolver, |_| {
        Made::Blocked
    });
    wait_for_replies(&inner, 1).await;
    assert_eq!(targets.lock().unwrap().len(), 1, "the TXT query was judged");
    push_packet(&inner, server, &dns_query("two.test.", RecordType::A));
    wait_for_replies(&inner, 2).await;
    assert!(!router.is_finished(), "the stream carries on");
    router.abort();
}

/// A one-destination stream to a fake address standing for nothing ends at
/// once, as a TCP connection to one is refused at once, rather than
/// dropping every datagram until the idle timeout.
#[tokio::test]
async fn test_a_one_destination_stream_to_an_unmapped_fake_address_ends() {
    let (resolver, _pool) = small_fake_ip_resolver(64);
    let unmapped: SocketAddr = "198.18.250.250:443".parse().unwrap();
    let (stream, inner) = scripted(vec![(location(unmapped), b"x".to_vec())], usize::MAX);
    inner.lock().unwrap().drops_sources = true;
    let MadeRouter {
        router, targets, ..
    } = spawn_router_making(ServerStream::Targeted(Box::new(stream)), resolver, |_| {
        Made::Remote
    });
    tokio::time::timeout(Duration::from_secs(5), router)
        .await
        .expect("the stream ends at once")
        .unwrap()
        .unwrap();
    assert!(targets.lock().unwrap().is_empty(), "nothing dialled");
}

/// A one-destination stream to an unmapped fake address on port 53 ends at
/// once too: DNS takes its own path through the router, and it must not
/// keep the stream open while the client keeps querying nowhere.
#[tokio::test]
async fn test_a_one_destination_dns_stream_to_an_unmapped_fake_address_ends() {
    use hickory_resolver::proto::rr::RecordType;
    let (resolver, _pool) = small_fake_ip_resolver(64);
    let unmapped: SocketAddr = "198.18.250.250:53".parse().unwrap();
    let (stream, inner) = scripted(
        vec![(location(unmapped), dns_query("one.test.", RecordType::A))],
        usize::MAX,
    );
    inner.lock().unwrap().drops_sources = true;
    let MadeRouter {
        router, targets, ..
    } = spawn_router_making(ServerStream::Targeted(Box::new(stream)), resolver, |_| {
        Made::Remote
    });
    tokio::time::timeout(Duration::from_secs(5), router)
        .await
        .expect("the stream ends at once")
        .unwrap()
        .unwrap();
    assert!(inner.lock().unwrap().replies.is_empty(), "not answered");
    assert!(targets.lock().unwrap().is_empty(), "nothing dialled");
}

/// On a one-destination DNS stream, a forwarding session whose remote
/// fails is replaced by the next forwarded query, rather than kept alive
/// by the answered ones and dropping every forwarded query after it.
#[tokio::test]
async fn test_a_one_destination_dns_stream_replaces_a_failed_upstream() {
    use hickory_resolver::proto::rr::RecordType;
    let (resolver, _pool) = small_fake_ip_resolver(64);
    let server: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let (stream, inner) = scripted(
        vec![(location(server), dns_query("one.test.", RecordType::TXT))],
        usize::MAX,
    );
    inner.lock().unwrap().drops_sources = true;
    let MadeRouter {
        router, targets, ..
    } = spawn_router_making(ServerStream::Targeted(Box::new(stream)), resolver, |_| {
        Made::RefusingWrites
    });
    wait_until("the first forwarding session is made", || {
        targets.lock().unwrap().len() == 1
    })
    .await;
    push_packet(&inner, server, &dns_query("two.test.", RecordType::A));
    wait_for_replies(&inner, 1).await;
    push_packet(&inner, server, &dns_query("two.test.", RecordType::TXT));
    wait_until(
        "a fresh session is made for the next forwarded query",
        || targets.lock().unwrap().len() == 2,
    )
    .await;
    assert!(!router.is_finished(), "the DNS stream carries on");
    router.abort();
}
