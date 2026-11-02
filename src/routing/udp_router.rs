//! UDP Router - Per-destination routing for multi-destination UDP streams.
//!
//! This implementation uses:
//! - IndexMap with FxHasher for fast session storage with stable iteration order
//! - Separate buffer pools for outbound/inbound to prevent starvation
//! - Zero-copy queuing: read directly into pool buffer, queue if write pending
//! - DelayQueue for O(1) session expiry (no iteration)
//! - Work queues for pending writes/flushes/responses (no iteration over all sessions)

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "predates the lint; see the [lints] note in Cargo.toml"
)]

use std::collections::{HashSet, VecDeque};
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use indexmap::IndexMap;
use log::{debug, warn};
use lru::LruCache;
use rustc_hash::{FxBuildHasher, FxHashMap};
use tokio::io::ReadBuf;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;
use tokio_util::time::DelayQueue;

use super::buffers::BufferPool;
use super::session::{KeyState, LookupKey, RoutingSession, SessionKey, SessionLookup};
use crate::address::{Address, NetLocation, ResolvedLocation};
use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncReadSessionMessage,
    AsyncReadTargetedMessage, AsyncSessionMessageStream, AsyncShutdownMessage,
    AsyncShutdownMessageExt, AsyncTargetedMessageStream, AsyncWriteMessage,
    AsyncWriteSessionMessage, AsyncWriteSourcedMessage, MessageSessionId,
};
use crate::client_proxy_selector::{ClientProxySelector, ConnectDecision};
use crate::resolver::{Resolver, resolve_single_address};

/// Timeout for inactive sessions, unless the listener sets its own
const SESSION_TIMEOUT_SECS: u64 = 200;

/// Per-listener session policy. The defaults are what every UDP inbound had
/// before one of them made these configurable.
#[derive(Debug, Clone)]
pub struct RouterLimits {
    /// How long a session may sit idle before it is removed.
    pub session_timeout: Duration,
    /// Sessions this one router may hold, counting those still being created.
    pub max_sessions: usize,
    /// Sessions every router holding this budget may hold between them.
    ///
    /// A `tproxy` listener runs one router per LAN client, and its
    /// `udp_nat_max` is a promise about the listener's descriptors, not about
    /// each client's. A semaphore rather than a counter because the share has
    /// to come back on every way a session can end, including the router
    /// being dropped with its client, and a permit held by the session does
    /// that without any bookkeeping to forget.
    pub shared_budget: Option<Arc<Semaphore>>,
}

impl Default for RouterLimits {
    fn default() -> Self {
        Self {
            session_timeout: Duration::from_secs(SESSION_TIMEOUT_SECS),
            max_sessions: usize::MAX,
            shared_budget: None,
        }
    }
}

/// Maximum UDP packet size
pub(super) const MAX_UDP_PACKET_SIZE: usize = 65535;

/// Maximum number of blocked destinations to remember (LRU eviction)
const MAX_BLOCKED_ENTRIES: usize = 80;

/// Buffer pool size for outbound (server → remote) - one per concurrent session
const REMOTE_WRITE_POOL_SIZE: usize = 8;

/// Buffer pool size for inbound (remote → server) - all go to same writer
const SERVER_WRITE_POOL_SIZE: usize = 8;

/// Max pending remote writes per session (prevents one slow session from starving others)
const MAX_PENDING_REMOTE_WRITES_PER_SESSION: usize = 4;

/// Max pending server writes per session (prevents one chatty session from starving others)
const MAX_PENDING_SERVER_WRITES_PER_SESSION: usize = 4;

/// Max concurrent session creation attempts (limits resource usage under burst)
const MAX_PENDING_CREATES: usize = 16;

/// The address a locally made DNS answer comes from: the server the client
/// addressed. A server named by hostname has no address to reply from
/// without resolving it, which is what fake IP avoids, so the reply comes
/// from that name's own fake address.
/// `None` when that name cannot be given a fake address (the pool is
/// exhausted): there is then no honest source to answer from.
fn local_answer_source(
    packet: &InboundPacket,
    pool: &crate::dns::fake_ip::FakeIpPool,
) -> Option<SocketAddr> {
    if let Some(addr) = packet.destination.to_socket_addr_nonblocking() {
        return Some(addr);
    }
    match packet.destination.address() {
        Address::Hostname(name) => pool
            .assign(name)
            .map(|fake| SocketAddr::new(fake.into(), packet.destination.port())),
        _ => None,
    }
}

/// See [`MAPPING_REFRESH_INTERVAL`](crate::dns::fake_ip::MAPPING_REFRESH_INTERVAL).
const FAKE_IP_TOUCH_INTERVAL: Duration = crate::dns::fake_ip::MAPPING_REFRESH_INTERVAL;

/// Keep a live flow's fake address in use, so the pool does not hand it to
/// another name while the client still sends to or hears from it: at most
/// once per [`FAKE_IP_TOUCH_INTERVAL`], rather than a pool lock per datagram.
/// Every path that keeps a session alive calls it (an immediate write, a
/// queued write's completion, a reply from the remote); `now` is read only
/// for a session keyed by a fake address.
#[inline]
fn touch_fake_ip(
    fake_ip: Option<&crate::dns::fake_ip::FakeIpResponder>,
    session: &mut RoutingSession,
    now: impl FnOnce() -> Instant,
) {
    let Some(responder) = fake_ip else {
        return;
    };
    let Some(ip) = crate::dns::fake_ip::fake_address(&session.destination, responder.pool()) else {
        return;
    };
    let now = now();
    if now.duration_since(session.fake_ip_touched) >= FAKE_IP_TOUCH_INTERVAL {
        responder.pool().touch(ip);
        session.fake_ip_touched = now;
    }
}

/// DNS answers made locally (fake IP) that may wait for the client to read.
/// Past this a new answer is dropped and the client's retry asks again.
const MAX_LOCAL_ANSWERS: usize = 64;

/// What fake IP makes of one inbound datagram.
enum FakeIpVerdict {
    /// Route it (restored, if it was a fake address).
    Route,
    /// A DNS query answered here, to be written back from `from`.
    Answer(Vec<u8>, SocketAddr),
}

/// How often to check if pings are needed
const PING_CHECK_INTERVAL: Duration = Duration::from_secs(15);

/// Ping streams that haven't had writes for this long
const PING_IDLE_THRESHOLD: Duration = Duration::from_secs(30);

/// A pending write waiting to be sent to remote
struct PendingWrite {
    id: SessionKey,
    buf: Box<[u8]>,
    len: usize,
}

/// Server stream variants - unified via enum
pub enum ServerStream {
    /// SOCKS5 UDP, Shadowsocks UoT, etc.
    Targeted(Box<dyn AsyncTargetedMessageStream>),
    /// XUDP (VLESS/VMess)
    Session(Box<dyn AsyncSessionMessageStream>),
}

impl ServerStream {
    fn poll_read_message(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<InboundPacket>> {
        match self {
            ServerStream::Targeted(stream) => {
                match Pin::new(stream).poll_read_targeted_message(cx, buf) {
                    Poll::Ready(Ok(dest)) => Poll::Ready(Ok(InboundPacket {
                        destination: dest,
                        session_id: 0,
                        route_to: None,
                        reply_as: None,
                    })),
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Pending => Poll::Pending,
                }
            }
            ServerStream::Session(stream) => {
                match Pin::new(stream).poll_read_session_message(cx, buf) {
                    Poll::Ready(Ok((session_id, addr))) => {
                        let address = match addr.ip() {
                            std::net::IpAddr::V4(v4) => Address::Ipv4(v4),
                            std::net::IpAddr::V6(v6) => Address::Ipv6(v6),
                        };
                        Poll::Ready(Ok(InboundPacket {
                            destination: NetLocation::new(address, addr.port()),
                            session_id,
                            route_to: None,
                            reply_as: None,
                        }))
                    }
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }

    /// A route the client has ended, for the router to drop.
    fn take_closed_session(&mut self) -> Option<MessageSessionId> {
        match self {
            ServerStream::Targeted(_) => None,
            ServerStream::Session(stream) => stream.take_closed_session(),
        }
    }

    /// Tell a session stream its route is gone; nothing to do for a
    /// targeted stream, whose packets carry no route.
    fn release_session(&mut self, session_id: MessageSessionId) {
        if let ServerStream::Session(stream) = self {
            stream.release_session(session_id);
        }
    }

    fn poll_write_message(
        &mut self,
        cx: &mut Context<'_>,
        data: &[u8],
        source: &SocketAddr,
        session_id: MessageSessionId,
    ) -> Poll<io::Result<()>> {
        match self {
            ServerStream::Targeted(stream) => {
                Pin::new(stream).poll_write_sourced_message(cx, data, source)
            }
            ServerStream::Session(stream) => {
                Pin::new(stream).poll_write_session_message(cx, session_id, data, source)
            }
        }
    }

    fn supports_ping(&self) -> bool {
        match self {
            ServerStream::Targeted(stream) => stream.supports_ping(),
            ServerStream::Session(stream) => stream.supports_ping(),
        }
    }

    fn poll_write_ping(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        match self {
            ServerStream::Targeted(stream) => Pin::new(stream).poll_write_ping(cx),
            ServerStream::Session(stream) => Pin::new(stream).poll_write_ping(cx),
        }
    }

    fn poll_flush_message(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self {
            ServerStream::Targeted(stream) => Pin::new(stream).poll_flush_message(cx),
            ServerStream::Session(stream) => Pin::new(stream).poll_flush_message(cx),
        }
    }

    async fn shutdown_message(&mut self) -> io::Result<()> {
        match self {
            ServerStream::Targeted(stream) => stream.shutdown_message().await,
            ServerStream::Session(stream) => stream.shutdown_message().await,
        }
    }
}

impl std::fmt::Debug for ServerStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerStream::Targeted(_) => f.debug_struct("Targeted").finish_non_exhaustive(),
            ServerStream::Session(_) => f.debug_struct("Session").finish_non_exhaustive(),
        }
    }
}

/// Packet info extracted from server stream
struct InboundPacket {
    destination: NetLocation,
    session_id: MessageSessionId,
    /// With fake IP, the name `destination` (a fake address) stands for:
    /// the session is routed to it, judged as a name with no local lookup.
    /// `destination` stays the session's key, so a fake-addressed flow never
    /// merges with one the client addressed to the name itself.
    route_to: Option<NetLocation>,
    /// The fake address replies to a restored flow come from, as the client
    /// expects.
    reply_as: Option<SocketAddr>,
}

/// Result of session creation
struct SessionCreateResult {
    remote: Box<dyn AsyncMessageStream>,
    resolved_addr: SocketAddr,
}

/// What creating a session came to. A block is an outcome of its own rather
/// than an error kind: `PermissionDenied` used to carry it, so a real `EACCES`
/// from a socket was remembered as a routing block.
enum CreateOutcome {
    Blocked,
    Remote(SessionCreateResult),
}

/// Type alias for the session creation future
type SessionCreateFuture = Pin<Box<dyn Future<Output = io::Result<CreateOutcome>> + Send>>;

/// See `UdpRouter::remote_factory`.
#[cfg(test)]
type RemoteFactory = Box<dyn Fn(&NetLocation) -> SessionCreateFuture + Send + Sync>;

/// Pending session creation state
struct PendingSessionCreate {
    lookup_key: LookupKey,
    destination: NetLocation,
    /// What the rules judge: the restored name of a fake address, else
    /// `destination`. A block is cached under it.
    judged: NetLocation,
    session_id: MessageSessionId,
    initial_data: Vec<u8>,
    future: SessionCreateFuture,
    /// Taken before the create starts, so a burst cannot overshoot the budget
    /// while its sessions are still connecting. Handed to the session on
    /// success, returned by the drop on failure.
    budget_permit: Option<OwnedSemaphorePermit>,
}

/// The unified UDP router
pub struct UdpRouter<'a> {
    server: &'a mut ServerStream,
    /// Lookup: maps flow key -> session state
    session_lookup: SessionLookup,

    sessions: IndexMap<SessionKey, RoutingSession, FxBuildHasher>,
    next_session_id: SessionKey,
    /// Round-robin position for fair session polling
    session_poll_position: usize,
    /// Blocked destinations (LRU-bounded)
    blocked: LruCache<NetLocation, ()>,

    pending_creates: Vec<PendingSessionCreate>,

    remote_write_queue: VecDeque<PendingWrite>,
    remote_flush_queue: VecDeque<SessionKey>,
    server_write_queue: VecDeque<PendingWrite>,

    /// The server stream drops reply sources (one fixed destination): a name
    /// is then judged as a name, with no local lookup first, and the stream
    /// ends with its one session (blocked, failed, expired or closed) or
    /// with the client, as such a stream's direct copy always did.
    one_destination: bool,

    /// The fake IP responder of this listener, when its `dns:` turns it on.
    fake_ip: Option<Arc<crate::dns::fake_ip::FakeIpResponder>>,
    /// DNS answers made here for the client, with the server address each
    /// came "from" and its session: written ahead of the remotes' replies.
    local_answers: VecDeque<(Vec<u8>, SocketAddr, MessageSessionId)>,

    needs_server_flush: bool,

    server_read_eof: bool,
    server_write_eof: bool,

    sessions_to_remove: HashSet<SessionKey>,
    /// Remotes of removed sessions, each with the budget share it still
    /// occupies until its shutdown completes and it is dropped.
    pending_shutdowns: VecDeque<(Box<dyn AsyncMessageStream>, Option<OwnedSemaphorePermit>)>,

    remote_write_pool: BufferPool,
    server_write_pool: BufferPool,

    expiry_queue: DelayQueue<SessionKey>,
    ping_timer: tokio::time::Interval,
    expiry_iteration: usize,

    last_server_write: Instant,
    /// Datagrams seen either way, and when that count last moved: a
    /// one-destination stream ends after the session timeout with neither
    /// (no session to expire before the first datagram, or while every
    /// datagram is a DNS query answered here). Compared on the ping tick,
    /// so no clock is read per datagram.
    activity: u64,
    activity_seen: (u64, Instant),

    selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,

    /// Tests only: replaces the real connect path, so a test can hand the
    /// router a remote whose writes or shutdown stay pending. Two parts of
    /// the limits are visible no other way: the deadline a session is created
    /// with, and the budget share a remote keeps while it shuts down.
    #[cfg(test)]
    remote_factory: Option<RemoteFactory>,

    limits: RouterLimits,
    /// Set when a cap first turns a datagram away and cleared by the next
    /// admission, so a flood over a full table logs once per episode rather
    /// than once per packet. Cleared on admission rather than when a session
    /// leaves because room can appear without one leaving here (a failed
    /// create, another router returning its share of the budget) and a
    /// session leaving here does not mean the shared budget has room.
    cap_reported: bool,
}

impl<'a> UdpRouter<'a> {
    /// Create a new UDP router.
    pub fn new(
        server: &'a mut ServerStream,
        selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
        need_initial_flush: bool,
        limits: RouterLimits,
    ) -> Self {
        let one_destination =
            matches!(&*server, ServerStream::Targeted(stream) if !stream.replies_need_source());
        let session_lookup = match server {
            ServerStream::Targeted(_) => SessionLookup::ByDestination(FxHashMap::default()),
            ServerStream::Session(_) => SessionLookup::BySessionId(FxHashMap::default()),
        };

        Self {
            server,
            session_lookup,
            sessions: IndexMap::with_hasher(FxBuildHasher),
            next_session_id: 0,
            session_poll_position: 0,
            blocked: LruCache::new(NonZeroUsize::new(MAX_BLOCKED_ENTRIES).unwrap()),
            pending_creates: Vec::new(),
            remote_write_queue: VecDeque::with_capacity(REMOTE_WRITE_POOL_SIZE),
            remote_flush_queue: VecDeque::with_capacity(REMOTE_WRITE_POOL_SIZE),
            server_write_queue: VecDeque::with_capacity(SERVER_WRITE_POOL_SIZE),
            one_destination,
            fake_ip: resolver.fake_ip().cloned(),
            local_answers: VecDeque::new(),
            needs_server_flush: need_initial_flush,
            server_read_eof: false,
            server_write_eof: false,
            sessions_to_remove: HashSet::new(),
            pending_shutdowns: VecDeque::new(),
            remote_write_pool: BufferPool::new(REMOTE_WRITE_POOL_SIZE),
            server_write_pool: BufferPool::new(SERVER_WRITE_POOL_SIZE),
            expiry_queue: DelayQueue::new(),
            ping_timer: tokio::time::interval(PING_CHECK_INTERVAL),
            expiry_iteration: 0,
            last_server_write: Instant::now(),
            activity: 0,
            activity_seen: (0, Instant::now()),
            selector,
            resolver,
            #[cfg(test)]
            remote_factory: None,
            limits,
            cap_reported: false,
        }
    }

    /// Whether a new session may be created, and the budget share it will
    /// hold if so. `Err` means drop the datagram: that is what a full
    /// conntrack table does to a new flow, and the flows already in the
    /// table are untouched by it.
    fn admit_session(
        &mut self,
        destination: &NetLocation,
    ) -> Result<Option<OwnedSemaphorePermit>, ()> {
        let refused_by =
            if self.sessions.len() + self.pending_creates.len() >= self.limits.max_sessions {
                "this listener's session cap"
            } else {
                let permit = match &self.limits.shared_budget {
                    None => Ok(None),
                    Some(budget) => budget.clone().try_acquire_owned().map(Some),
                };
                match permit {
                    Ok(permit) => {
                        self.cap_reported = false;
                        return Ok(permit);
                    }
                    Err(_) => "the session budget shared across this listener",
                }
            };

        if self.cap_reported {
            debug!("UDP datagram to {destination} dropped: {refused_by} is full");
        } else {
            self.cap_reported = true;
            warn!(
                "UDP datagram to {destination} dropped: {refused_by} is full; \
                 further drops are logged at debug until one is admitted again"
            );
        }
        Err(())
    }

    /// Set server read EOF and clean up pending session creates.
    /// Called when server read returns an error or zero-length read.
    #[inline]
    fn set_server_read_eof(&mut self) {
        if self.server_read_eof {
            return;
        }

        self.server_read_eof = true;
        // The client is done with a one-destination stream: it ends, as the
        // direct copy ends when either side does, rather than holding its
        // remote open until the session expires.
        if self.one_destination {
            self.set_server_write_eof();
        }

        // Clean up pending creates - remove lookup entries and drop futures
        // TODO: is this correct? what if the user wanted to send a single packet and closed their
        // connection?
        for pending in self.pending_creates.drain(..) {
            match (&mut self.session_lookup, pending.lookup_key) {
                (SessionLookup::ByDestination(map), LookupKey::Destination(dest)) => {
                    map.remove(&dest);
                }
                (SessionLookup::BySessionId(map), LookupKey::SessionId(id)) => {
                    map.remove(&id);
                }
                _ => unreachable!(),
            }
            // Future and initial_data are dropped
        }
    }

    /// Whether the end of a session to `destination` ends this stream: on a
    /// one-destination stream, yes, as for the direct copy; except DNS with
    /// fake IP on, where the session carries only the queries the pool does
    /// not answer, and the stream lives on for the ones it does, ending with
    /// the client or its idle timeout.
    fn session_ends_the_stream(&self, destination: &NetLocation) -> bool {
        self.one_destination
            && !(self.fake_ip.is_some() && destination.port() == crate::dns::fake_ip::DNS_PORT)
    }

    /// End a one-destination stream that has carried nothing either way for
    /// the session timeout, as the direct copy does.
    fn end_one_destination_if_idle(&mut self) {
        let now = Instant::now();
        if self.activity != self.activity_seen.0 {
            self.activity_seen = (self.activity, now);
        } else if now.duration_since(self.activity_seen.1) >= self.limits.session_timeout {
            debug!("[UdpRouter] one-destination stream idle, ending it");
            self.end_one_destination();
        }
    }

    /// End a one-destination stream in both directions.
    fn end_one_destination(&mut self) {
        self.set_server_read_eof();
        self.set_server_write_eof();
    }

    /// Set server write EOF and clean up server write queue.
    /// Called when server write or flush returns an error.
    #[inline]
    fn set_server_write_eof(&mut self) {
        if self.server_write_eof {
            return;
        }

        self.server_write_eof = true;
        self.needs_server_flush = false;

        // Return buffers to pool and clear queue.
        // We don't update session.in_server_write_queue counters here because:
        // 1. We're in shutdown mode - no more server writes will happen
        // 2. Sessions will be cleaned up through expiry anyway
        // 3. Avoids borrow conflicts when called from contexts that hold session refs
        self.local_answers.clear();
        for pending in self.server_write_queue.drain(..) {
            self.server_write_pool.release(pending.buf);
        }
        self.server_write_pool.park();
    }

    /// Drain pending session shutdowns (best-effort, non-blocking)
    fn drain_remote_shutdowns(&mut self, cx: &mut Context<'_>) {
        let count = self.pending_shutdowns.len();
        for _ in 0..count {
            let (mut stream, permit) = self.pending_shutdowns.pop_front().unwrap();
            if Pin::new(&mut stream).poll_shutdown_message(cx).is_pending() {
                self.pending_shutdowns.push_back((stream, permit));
            }
            // If Ready (success or error), stream and permit are dropped
        }
    }

    /// Read from server, route to sessions
    /// Returns (made_progress, exhausted) - exhausted only if read hit Pending, not pool exhaustion
    #[inline]
    fn poll_read_server(&mut self, cx: &mut Context<'_>) -> (bool, bool) {
        // Acquire buffer from outbound pool
        let Some(mut buf) = self.remote_write_pool.acquire() else {
            debug!("outbound pool exhausted, applying backpressure");
            return (false, false); // not exhausted, just pool-limited
        };

        let mut server_read_progress = false;
        let mut remote_writes_progress = false;

        loop {
            // Read packet from server directly into pool buffer
            let mut read_buf = ReadBuf::new(&mut buf);
            let polled = self.server.poll_read_message(cx, &mut read_buf);
            // The stream learns of an End while it is polled, so the routes
            // it closed are dropped now, whatever the poll returned: an
            // End-only read returns Pending, and a drain before the poll
            // would leave the remote and its budget held until some later
            // wakeup, with a new route for the same client refused against
            // the old one's share.
            self.cancel_closed_routes();
            let packet = match polled {
                Poll::Ready(Ok(p)) => {
                    server_read_progress = true;
                    debug!(
                        "[UdpRouter] poll_read_server got packet: {} bytes to {}",
                        read_buf.filled().len(),
                        p.destination
                    );
                    p
                }
                Poll::Ready(Err(e)) => {
                    warn!("server read error: {}", e);
                    self.set_server_read_eof();
                    break;
                }
                Poll::Pending => {
                    break;
                }
            };

            let len = read_buf.filled().len();
            self.remote_write_pool.mark_used(len);
            if len == 0 {
                self.set_server_read_eof();
                break;
            }
            self.activity = self.activity.wrapping_add(1);

            // Fake IP: a query to port 53 is answered here whatever server it
            // was sent to. A query the responder does not answer goes on to
            // the server the client addressed, through the rules, as on the
            // TUN. Decided while the responder is borrowed, acted on after:
            // the per-packet path clones nothing and takes no pool lock for a
            // datagram that is not a query.
            let mut packet = packet;
            let one_destination = self.one_destination;
            let verdict = match &self.fake_ip {
                Some(responder) if packet.destination.port() == crate::dns::fake_ip::DNS_PORT => {
                    use crate::dns::fake_ip::{DnsDecision, refuse_or_mark_used};
                    // A query sent to a fake address that stands for nothing
                    // is dropped like any datagram to one, not answered; one
                    // to a mapped fake address keeps that address in use.
                    if refuse_or_mark_used(&packet.destination, responder.pool()) {
                        self.release_route_if_unused(packet.session_id);
                        // Its one destination goes nowhere: ended at once,
                        // as on any other port.
                        if one_destination {
                            self.end_one_destination();
                        }
                        continue;
                    }
                    // Decided before any address is given out for the reply
                    // source, so a forwarded query takes no pool slot for the
                    // server's own name. A server named by hostname that
                    // cannot be given a fake address is not answered for;
                    // its query goes on to it like any other.
                    // Parsed once: the decision and the answer share it.
                    match responder.answerable(read_buf.filled()) {
                        None => FakeIpVerdict::Route,
                        Some(query) => {
                            // A one-destination stream drops reply sources,
                            // so a server named by hostname takes no slot.
                            let source = if one_destination {
                                Some(SocketAddr::new(
                                    std::net::Ipv4Addr::UNSPECIFIED.into(),
                                    packet.destination.port(),
                                ))
                            } else {
                                local_answer_source(&packet, responder.pool())
                            };
                            match source {
                                None => FakeIpVerdict::Route,
                                Some(from) => match responder.answer(query) {
                                    DnsDecision::Answer(answer) => {
                                        FakeIpVerdict::Answer(answer, from)
                                    }
                                    DnsDecision::Forward => FakeIpVerdict::Route,
                                },
                            }
                        }
                    }
                }
                // Anything else is routed; a fake address is restored to its
                // name when its session is made (below), once per flow.
                _ => FakeIpVerdict::Route,
            };
            match verdict {
                FakeIpVerdict::Route => {}
                FakeIpVerdict::Answer(answer, from) => {
                    // A one-destination stream ends with its session, so a
                    // query answered here keeps that session (made by a query
                    // forwarded earlier) alive: the stream is in use.
                    if self.one_destination
                        && let SessionLookup::ByDestination(map) = &self.session_lookup
                        && let Some(KeyState::Active(id)) = map.get(&packet.destination)
                        && let Some(session) = self.sessions.get_mut(id)
                    {
                        session.reset_expiry(
                            &mut self.expiry_queue,
                            *id,
                            self.expiry_iteration,
                            self.limits.session_timeout,
                        );
                    }
                    if self.local_answers.len() < MAX_LOCAL_ANSWERS {
                        self.local_answers
                            .push_back((answer, from, packet.session_id));
                    } else {
                        debug!("[UdpRouter] dropping a DNS answer: {MAX_LOCAL_ANSWERS} queued");
                        self.release_route_if_unused(packet.session_id);
                    }
                    continue;
                }
            }

            // Look up session
            let key_state = match &self.session_lookup {
                SessionLookup::ByDestination(map) => map.get(&packet.destination),
                SessionLookup::BySessionId(map) => map.get(&packet.session_id),
            };

            match key_state {
                Some(KeyState::Active(id)) => {
                    let Some(session) = self.sessions.get_mut(id) else {
                        // session is gone, skip message
                        continue;
                    };

                    // Skip if remote write is EOF
                    if session.remote_write_eof {
                        continue;
                    }

                    // Skip if session has too many pending writes (backpressure)
                    if session.in_remote_write_queue >= MAX_PENDING_REMOTE_WRITES_PER_SESSION {
                        continue;
                    }

                    // Always try to write immediately
                    match Pin::new(&mut session.remote).poll_write_message(cx, &buf[..len]) {
                        Poll::Ready(Ok(())) => {
                            remote_writes_progress = true;

                            session.last_write = Instant::now();
                            session.reset_expiry(
                                &mut self.expiry_queue,
                                *id,
                                self.expiry_iteration,
                                self.limits.session_timeout,
                            );
                            let now = session.last_write;
                            touch_fake_ip(self.fake_ip.as_deref(), session, || now);
                            if !session.in_remote_flush_queue {
                                session.in_remote_flush_queue = true;
                                self.remote_flush_queue.push_back(*id);
                            }
                        }
                        Poll::Pending => {
                            session.in_remote_write_queue += 1;
                            self.remote_write_queue
                                .push_back(PendingWrite { id: *id, buf, len });
                            let Some(new_buf) = self.remote_write_pool.acquire() else {
                                return (server_read_progress, remote_writes_progress);
                            };
                            buf = new_buf;
                        }
                        Poll::Ready(Err(e)) => {
                            warn!("remote write error: {}", e);
                            session.remote_write_eof = true;
                            if session.should_remove() {
                                self.sessions_to_remove.insert(*id);
                            }
                        }
                    }
                }
                Some(KeyState::Pending) => {
                    // Creation in progress - drop packet
                }
                None => {
                    // A fake address becomes the name it stands for as the
                    // session is made, once: a session that exists was
                    // restored when it was created, and its replies carry
                    // the fake address the client sent to. An address
                    // standing for nothing is dropped, as the TUN drops it,
                    // so the client resolves again rather than waiting on an
                    // address that goes nowhere.
                    let restored = self.fake_ip.as_ref().map(|responder| {
                        crate::dns::fake_ip::restore_location(&packet.destination, responder.pool())
                    });
                    match restored {
                        None | Some(crate::dns::fake_ip::Restored::Unchanged) => {}
                        Some(crate::dns::fake_ip::Restored::Hostname(name)) => {
                            packet.reply_as = packet.destination.to_socket_addr_nonblocking();
                            packet.route_to = Some(name);
                        }
                        Some(crate::dns::fake_ip::Restored::Unmapped) => {
                            self.release_route_if_unused(packet.session_id);
                            // Its one destination goes nowhere: the stream
                            // ends at once, as TCP refuses at once, so the
                            // client resolves again rather than waiting out
                            // the idle timeout.
                            if self.one_destination {
                                self.end_one_destination();
                            }
                            continue;
                        }
                    }

                    // No session - check blocked before creating
                    // A refused packet's route is released, or a session
                    // stream would keep counting it against its own limit.
                    // A restored flow is blocked by its name: the fake
                    // address may stand for another name later.
                    let judged = packet.route_to.as_ref().unwrap_or(&packet.destination);
                    if self.blocked.get(judged).is_some() {
                        debug!("UDP proxying blocked to {}", packet.destination);
                        self.release_route_if_unused(packet.session_id);
                        continue;
                    }

                    if self.pending_creates.len() >= MAX_PENDING_CREATES {
                        debug!(
                            "Too many pending creates, dropping new session creation for {}",
                            packet.destination
                        );
                        self.release_route_if_unused(packet.session_id);
                        continue;
                    }

                    let Ok(budget_permit) = self.admit_session(&packet.destination) else {
                        self.release_route_if_unused(packet.session_id);
                        continue;
                    };

                    self.start_session_creation(cx, packet, &buf[..len], budget_permit);
                }
            }
        }

        self.remote_write_pool.release(buf);
        (server_read_progress, remote_writes_progress)
    }

    /// Drain pending writes to remotes
    #[inline]
    fn drain_remote_writes(&mut self, cx: &mut Context<'_>) -> bool {
        let queue_len = self.remote_write_queue.len();

        for _ in 0..queue_len {
            let PendingWrite { id, buf, len } = self.remote_write_queue.pop_front().unwrap();

            let Some(session) = self.sessions.get_mut(&id) else {
                // Session gone, release buffer
                self.remote_write_pool.release(buf);
                continue;
            };

            // If remote_write_eof, can't write - release buffer
            if session.remote_write_eof {
                session.in_remote_write_queue -= 1;
                self.remote_write_pool.release(buf);
                if session.should_remove() {
                    self.sessions_to_remove.insert(id);
                }
                continue;
            }

            let data = &buf[..len];

            match Pin::new(&mut session.remote).poll_write_message(cx, data) {
                Poll::Ready(Ok(())) => {
                    session.in_remote_write_queue -= 1;
                    session.last_write = Instant::now();
                    let now = session.last_write;
                    touch_fake_ip(self.fake_ip.as_deref(), session, || now);
                    session.reset_expiry(
                        &mut self.expiry_queue,
                        id,
                        self.expiry_iteration,
                        self.limits.session_timeout,
                    );
                    if !session.in_remote_flush_queue {
                        session.in_remote_flush_queue = true;
                        self.remote_flush_queue.push_back(id);
                    }
                    self.remote_write_pool.release(buf);
                }
                Poll::Pending => {
                    self.remote_write_queue
                        .push_back(PendingWrite { id, buf, len });
                }
                Poll::Ready(Err(e)) => {
                    warn!("remote write error: {}", e);
                    session.in_remote_write_queue -= 1;
                    self.remote_write_pool.release(buf);
                    session.remote_write_eof = true;
                    if session.should_remove() {
                        self.sessions_to_remove.insert(id);
                    }
                }
            }
        }

        self.remote_write_queue.len() < queue_len
    }

    /// Drain pending flushes
    #[inline]
    fn drain_remote_flushes(&mut self, cx: &mut Context<'_>) -> bool {
        let queue_len = self.remote_flush_queue.len();

        for _ in 0..queue_len {
            let id = self.remote_flush_queue.pop_front().unwrap();

            let Some(session) = self.sessions.get_mut(&id) else {
                continue;
            };

            if !session.in_remote_flush_queue {
                continue;
            }

            match Pin::new(&mut session.remote).poll_flush_message(cx) {
                Poll::Ready(Ok(())) => {
                    session.in_remote_flush_queue = false;
                }
                Poll::Pending => {
                    self.remote_flush_queue.push_back(id);
                }
                Poll::Ready(Err(_)) => {
                    session.in_remote_flush_queue = false;
                    session.remote_write_eof = true;
                    if session.should_remove() {
                        self.sessions_to_remove.insert(id);
                    }
                }
            }
        }

        self.remote_flush_queue.len() < queue_len
    }

    /// Read from remotes, write to server
    /// Returns (made_progress, write_success, exhausted) - exhausted only if reads hit Pending, not pool exhaustion
    #[inline]
    fn poll_read_remotes(&mut self, cx: &mut Context<'_>) -> (bool, bool) {
        // Acquire one buffer upfront - reused across sessions
        let Some(mut buf) = self.server_write_pool.acquire() else {
            debug!("inbound pool exhausted, applying backpressure");
            return (false, false); // pool-limited, not exhausted
        };

        let mut remote_read_progress = false;
        let mut server_write_progress = false;

        // Read from sessions, using round-robin for fairness
        let session_count = self.sessions.len();

        for i in 0..session_count {
            let idx = (self.session_poll_position + i) % session_count;
            let Some((&id, session)) = self.sessions.get_index_mut(idx) else {
                continue;
            };

            if session.remote_read_eof
                || session.in_server_write_queue >= MAX_PENDING_SERVER_WRITES_PER_SESSION
            {
                continue;
            }

            for _ in session.in_server_write_queue..MAX_PENDING_SERVER_WRITES_PER_SESSION {
                let mut read_buf = ReadBuf::new(&mut buf);

                match Pin::new(&mut session.remote).poll_read_message(cx, &mut read_buf) {
                    Poll::Ready(Ok(())) => {
                        let len = read_buf.filled().len();
                        self.server_write_pool.mark_used(len);
                        debug!(
                            "[UdpRouter] Read {} bytes from session remote (session {})",
                            len, session.destination
                        );
                        if len == 0 {
                            session.remote_read_eof = true;
                            if session.should_remove() {
                                self.sessions_to_remove.insert(id);
                            }
                            break; // Stop bursting this session
                        }

                        remote_read_progress = true;
                        self.activity = self.activity.wrapping_add(1);
                        touch_fake_ip(self.fake_ip.as_deref(), session, Instant::now);
                        session.reset_expiry(
                            &mut self.expiry_queue,
                            id,
                            self.expiry_iteration,
                            self.limits.session_timeout,
                        );

                        match self.server.poll_write_message(
                            cx,
                            &buf[..len],
                            &session.resolved_addr,
                            session.session_id,
                        ) {
                            Poll::Ready(Ok(())) => {
                                debug!(
                                    "[UdpRouter] Wrote {} bytes to server (to {})",
                                    len, session.resolved_addr
                                );
                                server_write_progress = true;
                                // Buffer consumed and free, reuse `buf` for next burst or session
                            }
                            Poll::Pending => {
                                debug!("[UdpRouter] Write to server pending");
                                session.in_server_write_queue += 1;
                                self.server_write_queue
                                    .push_back(PendingWrite { id, buf, len });

                                match self.server_write_pool.acquire() {
                                    Some(new_buf) => {
                                        buf = new_buf;
                                        // Queued a write, break burst to allow other sessions/draining
                                        break;
                                    }
                                    None => {
                                        // Pool exhausted, pool_limited = true but we return
                                        // immediately
                                        return (remote_read_progress, server_write_progress);
                                    }
                                }
                            }
                            Poll::Ready(Err(e)) => {
                                warn!("server write error: {}", e);
                                self.server_write_pool.release(buf); // release in-hand buffer
                                self.set_server_write_eof();
                                return (remote_read_progress, server_write_progress);
                            }
                        }
                    }
                    Poll::Ready(Err(e)) => {
                        debug!("remote read error: {}", e);
                        session.remote_read_eof = true;
                        if session.should_remove() {
                            self.sessions_to_remove.insert(id);
                        }
                        break;
                    }
                    Poll::Pending => {
                        break;
                    }
                }
            }
        }

        // Advance position for fairness across poll calls
        if session_count > 0 {
            self.session_poll_position = (self.session_poll_position + 1) % session_count;
        }

        self.server_write_pool.release(buf);

        // exhausted only if we made no progress (all reads returned Pending)
        (remote_read_progress, server_write_progress)
    }

    /// Drain pending responses to server
    #[inline]
    fn drain_server_writes(&mut self, cx: &mut Context<'_>) -> bool {
        let mut server_write_progress = false;

        while let Some((answer, from, session_id)) = self.local_answers.pop_front() {
            match self
                .server
                .poll_write_message(cx, &answer, &from, session_id)
            {
                Poll::Ready(Ok(())) => {
                    server_write_progress = true;
                    self.release_route_if_unused(session_id);
                }
                Poll::Pending => {
                    self.local_answers.push_front((answer, from, session_id));
                    return server_write_progress;
                }
                Poll::Ready(Err(e)) => {
                    warn!("server write error: {}", e);
                    self.set_server_write_eof();
                    return server_write_progress;
                }
            }
        }

        while let Some(pending) = self.server_write_queue.pop_front() {
            let PendingWrite { id, buf, len } = pending;

            let Some(session) = self.sessions.get_mut(&id) else {
                // Session gone, release buffer
                self.server_write_pool.release(buf);
                continue;
            };

            match self.server.poll_write_message(
                cx,
                &buf[..len],
                &session.resolved_addr,
                session.session_id,
            ) {
                Poll::Ready(Ok(())) => {
                    session.in_server_write_queue -= 1;
                    if session.should_remove() {
                        self.sessions_to_remove.insert(id);
                    }
                    server_write_progress = true;
                    self.server_write_pool.release(buf);
                }
                Poll::Pending => {
                    self.server_write_queue
                        .push_front(PendingWrite { id, buf, len });
                    break;
                }
                Poll::Ready(Err(e)) => {
                    warn!("server write error: {}", e);
                    session.in_server_write_queue -= 1; // last use of session borrow
                    self.server_write_pool.release(buf); // release current buffer
                    self.set_server_write_eof(); // clears remaining queue
                    break;
                }
            }
        }

        server_write_progress
    }

    /// Poll pending session creates
    #[inline]
    fn poll_pending_creates(&mut self, cx: &mut Context<'_>) -> bool {
        let mut made_progress = false;

        // Iterate backwards so swap_remove doesn't invalidate indices
        for i in (0..self.pending_creates.len()).rev() {
            made_progress |= self.poll_pending_create(cx, i);
        }

        made_progress
    }

    #[inline]
    fn poll_pending_create(&mut self, cx: &mut Context<'_>, i: usize) -> bool {
        let result = match self.pending_creates[i].future.as_mut().poll(cx) {
            Poll::Ready(result) => result,
            Poll::Pending => {
                return false;
            }
        };

        let pending = self.pending_creates.swap_remove(i);

        let PendingSessionCreate {
            lookup_key,
            destination,
            judged,
            session_id,
            initial_data,
            future: _,
            budget_permit,
        } = pending;

        match result {
            Ok(CreateOutcome::Remote(SessionCreateResult {
                remote,
                resolved_addr,
            })) => {
                debug!(
                    "Session created for {} (resolved to {})",
                    destination, resolved_addr
                );

                let id = self.next_session_id;
                self.next_session_id += 1;

                // Update lookup map
                let pending_key_state = match (&mut self.session_lookup, &lookup_key) {
                    (SessionLookup::ByDestination(map), LookupKey::Destination(dest)) => {
                        map.insert(dest.clone(), KeyState::Active(id))
                    }
                    (SessionLookup::BySessionId(map), LookupKey::SessionId(sid)) => {
                        map.insert(*sid, KeyState::Active(id))
                    }
                    _ => unreachable!(),
                };
                debug_assert!(matches!(pending_key_state.unwrap(), KeyState::Pending));

                let mut session = RoutingSession::new(
                    destination,
                    session_id,
                    resolved_addr,
                    lookup_key,
                    remote,
                    budget_permit,
                );

                // A failed remote is removed on every one-destination stream,
                // so the next datagram makes a fresh one; whether that ends
                // the stream is `take_session`'s call.
                session.ends_on_either_side = self.one_destination;

                // TODO: part of constructor, we now know the id in advance
                let expiry_key = self.expiry_queue.insert(id, self.limits.session_timeout);
                session.expiry_key = Some(expiry_key);

                // Try to write immediately
                if !initial_data.is_empty() {
                    debug!(
                        "Writing initial_data ({} bytes) to session for {}",
                        initial_data.len(),
                        session.destination
                    );
                    match Pin::new(&mut session.remote).poll_write_message(cx, &initial_data) {
                        Poll::Ready(Ok(())) => {
                            debug!("Initial data write succeeded, queueing flush");
                            session.last_write = Instant::now();
                            // Note: expiry was just set above when inserting into expiry_queue
                            if !session.in_remote_flush_queue {
                                session.in_remote_flush_queue = true;
                                self.remote_flush_queue.push_back(id);
                            }
                        }
                        Poll::Pending => {
                            debug!("Initial data write pending, queueing for later");
                            if let Some(mut buf) = self.remote_write_pool.acquire() {
                                let len = initial_data.len();
                                buf[..len].copy_from_slice(&initial_data);
                                self.remote_write_pool.mark_used(len);
                                session.in_remote_write_queue += 1;
                                self.remote_write_queue
                                    .push_back(PendingWrite { id, buf, len });
                            }
                        }
                        Poll::Ready(Err(e)) => {
                            warn!("remote write error: {}", e);
                            session.remote_write_eof = true;
                            if session.should_remove() {
                                self.sessions_to_remove.insert(id);
                            }
                        }
                    }
                }
                self.sessions.insert(id, session);
                true
            }
            outcome @ (Ok(CreateOutcome::Blocked) | Err(_)) => {
                match outcome {
                    Ok(_) => {
                        debug!("UDP proxying blocked to {judged}");
                        self.blocked.put(judged, ());
                    }
                    // Not cached: a failure here is the socket's or the
                    // remote's, and the next packet should try again.
                    Err(e) => warn!("Failed to create session for {}: {}", destination, e),
                }
                // A stream with one fixed destination has nothing else to
                // carry: it ends, as the direct path ends when it is refused
                // or cannot connect, rather than dropping every datagram in
                // silence or leaving the client waiting on no remote. Not a
                // DNS stream answered here: the query that failed was one of
                // many, the rest are answered from the pool, and ending
                // would throw away answers still queued.
                if self.session_ends_the_stream(&destination) {
                    self.end_one_destination();
                }
                // Remove from pending in lookup. The route is released only
                // once nothing is queued under it: a query answered here on
                // the same route may still be waiting to be written.
                match (&mut self.session_lookup, &lookup_key) {
                    (SessionLookup::ByDestination(map), LookupKey::Destination(dest)) => {
                        map.remove(dest);
                    }
                    (SessionLookup::BySessionId(map), LookupKey::SessionId(sid)) => {
                        map.remove(sid);
                    }
                    _ => unreachable!(),
                }
                if let LookupKey::SessionId(sid) = lookup_key {
                    self.release_route_if_unused(sid);
                }
                false
            }
        }
    }

    /// Resolve, judge and connect: how a session gets its remote.
    fn connect_future(
        &self,
        destination: &NetLocation,
        reply_as: Option<SocketAddr>,
    ) -> SessionCreateFuture {
        let selector = Arc::clone(&self.selector);
        let resolver = Arc::clone(&self.resolver);
        let dest_for_future = destination.clone();
        let lazy_name =
            self.one_destination && matches!(destination.address(), Address::Hostname(_));

        Box::pin(async move {
            // A name restored from a fake address is judged as a name: a
            // rule or a direct route resolves it if it must, and a proxy gets
            // the name, so nothing is looked up here first. Its replies come
            // from the fake address the client sent to.
            let (resolved_location, resolved_addr) = match reply_as {
                Some(reply_as) => (ResolvedLocation::from(dest_for_future), reply_as),
                // The stream drops the reply source, so there is no address
                // to look up; the chain resolves the name if it must.
                None if lazy_name => {
                    let unused = SocketAddr::new(
                        std::net::Ipv4Addr::UNSPECIFIED.into(),
                        dest_for_future.port(),
                    );
                    (ResolvedLocation::from(dest_for_future), unused)
                }
                None => {
                    let resolved_addr = resolve_single_address(&resolver, &dest_for_future).await?;
                    (
                        ResolvedLocation::with_resolved(dest_for_future, resolved_addr),
                        resolved_addr,
                    )
                }
            };
            let decision = selector.judge(resolved_location, &resolver).await?;

            match decision {
                ConnectDecision::Allow {
                    chain_group,
                    remote_location,
                } => {
                    let client_stream = chain_group
                        .connect_udp_bidirectional(&resolver, remote_location)
                        .await?;

                    Ok(CreateOutcome::Remote(SessionCreateResult {
                        remote: client_stream,
                        resolved_addr,
                    }))
                }
                ConnectDecision::Block => Ok(CreateOutcome::Blocked),
            }
        })
    }

    /// Start session creation
    #[inline]
    fn start_session_creation(
        &mut self,
        cx: &mut Context<'_>,
        packet: InboundPacket,
        data: &[u8],
        budget_permit: Option<OwnedSemaphorePermit>,
    ) {
        let InboundPacket {
            destination,
            session_id,
            route_to,
            reply_as,
        } = packet;
        // The session is keyed by what the client addressed and routed to
        // the name a fake address stands for.
        let target = route_to.unwrap_or_else(|| destination.clone());

        let lookup_key = match &mut self.session_lookup {
            SessionLookup::ByDestination(map) => {
                map.insert(destination.clone(), KeyState::Pending);
                LookupKey::Destination(destination.clone())
            }
            SessionLookup::BySessionId(map) => {
                map.insert(packet.session_id, KeyState::Pending);
                LookupKey::SessionId(packet.session_id)
            }
        };

        debug!("Creating session for {}", destination);

        let initial_data = data.to_vec();

        #[cfg(test)]
        let future = match &self.remote_factory {
            Some(factory) => factory(&target),
            None => self.connect_future(&target, reply_as),
        };
        #[cfg(not(test))]
        let future = self.connect_future(&target, reply_as);

        let index = self.pending_creates.len();
        self.pending_creates.push(PendingSessionCreate {
            lookup_key,
            destination,
            judged: target,
            session_id,
            initial_data,
            future,
            budget_permit,
        });
        let _ = self.poll_pending_create(cx, index);
    }

    /// Hand a session stream's route back when this router holds nothing on
    /// it: a DNS query answered here, or a datagram to an unmapped fake
    /// address, admits a route (an XUDP stream counts it against its limit)
    /// but creates no session, so nothing else would release it. A route
    /// with a live or pending session, or with answers still queued, is kept.
    fn release_route_if_unused(&mut self, route: MessageSessionId) {
        if let SessionLookup::BySessionId(map) = &self.session_lookup
            && !map.contains_key(&route)
            // Several queries may share a route: its answers still queued
            // are written under it, so it stays until the last one is.
            && !self
                .local_answers
                .iter()
                .any(|(_, _, queued)| *queued == route)
        {
            self.server.release_session(route);
        }
    }

    /// Drop the routes whose wire session the client ended (an XUDP End):
    /// their remotes close at once, without the graceful shutdown a
    /// session that expired gets, and a reused session id can no longer
    /// land on the old remote (upstream cfal/shoes, "cancel closed XUDP
    /// routes").
    fn cancel_closed_routes(&mut self) {
        while let Some(route) = self.server.take_closed_session() {
            let SessionLookup::BySessionId(map) = &mut self.session_lookup else {
                return;
            };
            match map.get(&route) {
                Some(KeyState::Active(id)) => {
                    let id = *id;
                    self.cancel_session(id);
                }
                Some(KeyState::Pending) => {
                    map.remove(&route);
                    self.pending_creates
                        .retain(|pending| pending.session_id != route);
                }
                None => {}
            }
        }
    }

    /// Remove a session and close its remote at once.
    #[inline]
    fn cancel_session(&mut self, id: SessionKey) {
        drop(self.take_session(id));
    }

    /// Remove a session (split-borrow friendly version)
    #[inline]
    fn remove_session(&mut self, id: SessionKey) {
        let Some(mut session) = self.take_session(id) else {
            return;
        };

        // Queue remote stream for graceful shutdown. The permit goes with it:
        // the socket stays open until the shutdown finishes, and a budget
        // that came back before then would admit a new session while the old
        // descriptor was still held, which under churn is over the cap.
        self.pending_shutdowns
            .push_back((session.remote, session.budget_permit.take()));
    }

    /// Take a session out of the maps and its expiry timer; the caller
    /// decides what happens to its remote.
    #[inline]
    fn take_session(&mut self, id: SessionKey) -> Option<RoutingSession> {
        let mut session = self.sessions.swap_remove(&id)?;
        // A one-destination stream's session ends (expired, or its remote
        // closed or failed): so does the stream, as the direct copy does
        // after the same idle time, rather than re-creating the remote from
        // a new port, which a peer that pins the source port would refuse.
        // A DNS stream answered here outlives it; see `session_ends_the_stream`.
        if self.session_ends_the_stream(&session.destination) {
            self.end_one_destination();
        }

        debug!("Session removed: {}", session.destination);

        // Cancel expiry timer
        if let Some(key) = session.expiry_key.take() {
            self.expiry_queue.remove(&key);
        }

        // Remove from lookup map; the route goes once nothing is queued
        // under it, as above.
        match (&mut self.session_lookup, &session.lookup_key) {
            (SessionLookup::ByDestination(map), LookupKey::Destination(dest)) => {
                map.remove(dest);
            }
            (SessionLookup::BySessionId(map), LookupKey::SessionId(sid)) => {
                map.remove(sid);
            }
            _ => unreachable!(),
        }
        if let LookupKey::SessionId(sid) = session.lookup_key {
            self.release_route_if_unused(sid);
        }

        Some(session)
    }

    /// Process expired sessions
    fn process_expired(&mut self, cx: &mut Context<'_>) {
        while let Poll::Ready(Some(expired)) = self.expiry_queue.poll_expired(cx) {
            let id = expired.into_inner();
            // Clear expiry_key since poll_expired already removed it from the queue
            if let Some(session) = self.sessions.get_mut(&id) {
                debug!("Session expired: {}", session.destination);
                session.expiry_key = None;
            }
            self.remove_session(id);
        }
    }

    /// Mark idle sessions for pinging
    fn write_server_ping(&mut self, cx: &mut Context<'_>) -> bool {
        let now = Instant::now();

        if self.server.supports_ping()
            && self.server_write_queue.is_empty()
            && now.duration_since(self.last_server_write) >= PING_IDLE_THRESHOLD
        {
            match self.server.poll_write_ping(cx) {
                Poll::Ready(Ok(_wrote_ping)) => {
                    // Reset regardless of if ping was written, if false, it means that the
                    // stream was already busy and it's unnecessary
                    debug!("Sent ping to server stream");
                    return true;
                }
                Poll::Ready(Err(e)) => {
                    debug!("server ping error: {}", e);
                    self.set_server_write_eof();
                }
                Poll::Pending => {
                    // Skip and wait for next ping interval
                }
            }
        }

        false
    }

    fn write_remote_pings(&mut self, cx: &mut Context<'_>) -> bool {
        let now = Instant::now();
        let mut made_progress = false;

        // Mark idle sessions for pinging
        for (&id, session) in &mut self.sessions {
            if session.remote.supports_ping()
                && session.in_remote_write_queue == 0
                && now.duration_since(session.last_write) >= PING_IDLE_THRESHOLD
            {
                // Try to send ping immediately
                match Pin::new(&mut session.remote).poll_write_ping(cx) {
                    Poll::Ready(Ok(_wrote_ping)) => {
                        debug!("Sent ping to {}", session.destination);
                        made_progress = true;
                        session.last_write = now;
                        if !session.in_remote_flush_queue {
                            session.in_remote_flush_queue = true;
                            self.remote_flush_queue.push_back(id);
                        }
                    }
                    Poll::Ready(Err(e)) => {
                        debug!("remote ping error: {}", e);
                        session.remote_write_eof = true;
                        if session.should_remove() {
                            self.sessions_to_remove.insert(id);
                        }
                    }
                    Poll::Pending => {
                        // Skip and wait for next ping interval
                    }
                }
            }
        }

        made_progress
    }
}

impl<'a> Future for UdpRouter<'a> {
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        this.expiry_iteration = this.expiry_iteration.wrapping_add(1);

        let ping_triggered = this.ping_timer.poll_tick(cx).is_ready();
        if this.one_destination {
            // The idle check needs the timer to wake this task with nothing
            // else going on, so the tick is polled until it is pending,
            // which registers the wakeup. Other routers are woken by their
            // traffic and keep the one poll they had.
            while ping_triggered && this.ping_timer.poll_tick(cx).is_ready() {}
            if ping_triggered {
                this.end_one_destination_if_idle();
            }
        }

        // Each direction runs independently to exhaustion.
        this.poll_outbound(cx, ping_triggered);
        this.poll_inbound(cx, ping_triggered);

        if !this.sessions_to_remove.is_empty() {
            let sessions_to_remove = std::mem::take(&mut this.sessions_to_remove);
            for id in sessions_to_remove {
                this.remove_session(id);
            }
        }
        this.process_expired(cx);

        this.drain_remote_shutdowns(cx);

        this.remote_write_pool.park();
        this.server_write_pool.park();

        if this.server_read_eof && this.server_write_eof {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

impl UdpRouter<'_> {
    /// Poll outbound path: server -> remotes
    /// Runs until no progress (all operations pending or exhausted).
    #[inline]
    fn poll_outbound(&mut self, cx: &mut Context<'_>, ping_triggered: bool) {
        if !self.pending_creates.is_empty() {
            self.poll_pending_creates(cx);
        }

        loop {
            let mut server_read_progress = false;
            let mut remote_writes_progress = false;

            remote_writes_progress |= self.drain_remote_writes(cx);

            if ping_triggered {
                remote_writes_progress |= self.write_remote_pings(cx);
            }

            if !self.remote_flush_queue.is_empty() {
                remote_writes_progress |= self.drain_remote_flushes(cx);
            }

            // Read from server and route to remotes (if not EOF)
            if !self.server_read_eof {
                let (new_server_read_progress, new_remote_writes_progress) =
                    self.poll_read_server(cx);
                server_read_progress |= new_server_read_progress;
                remote_writes_progress |= new_remote_writes_progress;
            }

            if !server_read_progress && !remote_writes_progress {
                break;
            }

            // Cooperative yielding to prevent task starvation
            match tokio::task::coop::poll_proceed(cx) {
                Poll::Ready(coop) => coop.made_progress(),
                Poll::Pending => break,
            }
        }
    }

    /// Poll inbound path: remotes -> server
    /// Runs until no progress (all operations pending or exhausted).
    #[inline]
    fn poll_inbound(&mut self, cx: &mut Context<'_>, ping_triggered: bool) {
        loop {
            // Early exit if server write is EOF
            if self.server_write_eof {
                break;
            }

            let mut server_write_progress = false;

            // Drain pending writes to server
            server_write_progress |= self.drain_server_writes(cx);

            // Read from remotes and write to server
            let (remote_read_progress, new_server_write_progress) = self.poll_read_remotes(cx);
            server_write_progress |= new_server_write_progress;

            // Don't bother pinging if we wrote.
            if !server_write_progress && ping_triggered {
                server_write_progress |= self.write_server_ping(cx);
            }

            if server_write_progress {
                self.needs_server_flush = true;
                self.last_server_write = Instant::now();
            }

            if self.needs_server_flush {
                match self.server.poll_flush_message(cx) {
                    Poll::Ready(Ok(())) => {
                        self.needs_server_flush = false;
                        // this counts as server write progress since we can now retry writes
                        server_write_progress = true;
                    }
                    Poll::Ready(Err(e)) => {
                        warn!("server flush error: {}", e);
                        self.set_server_write_eof();
                    }
                    Poll::Pending => {}
                }
            }

            if !server_write_progress && !remote_read_progress {
                break;
            }

            // Cooperative yielding to prevent task starvation
            match tokio::task::coop::poll_proceed(cx) {
                Poll::Ready(coop) => coop.made_progress(),
                Poll::Pending => break,
            }
        }
    }
}

/// Run per-destination routing for any server UDP stream type.
pub async fn run_udp_routing(
    server: ServerStream,
    selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    need_initial_flush: bool,
) -> io::Result<()> {
    run_udp_routing_with_limits(
        server,
        selector,
        resolver,
        need_initial_flush,
        RouterLimits::default(),
    )
    .await
}

/// `run_udp_routing` for a listener with its own session timeout and cap.
pub async fn run_udp_routing_with_limits(
    mut server: ServerStream,
    selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    need_initial_flush: bool,
    limits: RouterLimits,
) -> io::Result<()> {
    let result = UdpRouter::new(&mut server, selector, resolver, need_initial_flush, limits).await;
    let _ = server.shutdown_message().await;
    result
}

#[cfg(test)]
mod tests;
