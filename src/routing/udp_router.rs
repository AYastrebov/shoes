//! UDP Router - Per-destination routing for multi-destination UDP streams.
//!
//! This implementation uses:
//! - IndexMap with FxHasher for fast session storage with stable iteration order
//! - Separate buffer pools for outbound/inbound to prevent starvation
//! - Zero-copy queuing: read directly into pool buffer, queue if write pending
//! - DelayQueue for O(1) session expiry (no iteration)
//! - Work queues for pending writes/flushes/responses (no iteration over all sessions)

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
use tokio_util::time::{DelayQueue, delay_queue};

use crate::address::{Address, NetLocation, ResolvedLocation};
use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncReadSessionMessage,
    AsyncReadTargetedMessage, AsyncSessionMessageStream, AsyncShutdownMessage,
    AsyncShutdownMessageExt, AsyncTargetedMessageStream, AsyncWriteMessage,
    AsyncWriteSessionMessage, AsyncWriteSourcedMessage,
};
use crate::client_proxy_selector::{ClientProxySelector, ConnectDecision};
use crate::resolver::{Resolver, resolve_single_address};
use crate::util::allocate_vec;

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
const MAX_UDP_PACKET_SIZE: usize = 65535;

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

/// How often to check if pings are needed
const PING_CHECK_INTERVAL: Duration = Duration::from_secs(15);

/// Ping streams that haven't had writes for this long
const PING_IDLE_THRESHOLD: Duration = Duration::from_secs(30);

/// Session identifier - incrementing counter, never reused
type SessionKey = usize;

/// Lazy buffer pool for backpressure management.
///
/// Buffers are created on-demand up to max_count, then reused.
/// Acquired buffers are either released immediately (if write succeeds)
/// or moved into a queue (zero-copy).
struct BufferPool {
    buffers: Vec<Box<[u8]>>,
    max_count: usize,
    created_count: usize,
}

impl BufferPool {
    fn new(max_count: usize) -> Self {
        Self {
            buffers: Vec::with_capacity(max_count),
            max_count,
            created_count: 0,
        }
    }

    #[inline]
    fn acquire(&mut self) -> Option<Box<[u8]>> {
        // Try to reuse existing buffer
        if let Some(buf) = self.buffers.pop() {
            return Some(buf);
        }

        // Create new if under limit
        if self.created_count < self.max_count {
            self.created_count += 1;
            Some(allocate_vec(MAX_UDP_PACKET_SIZE).into_boxed_slice())
        } else {
            None
        }
    }

    #[inline]
    fn release(&mut self, buf: Box<[u8]>) {
        self.buffers.push(buf);
    }

    #[inline]
    fn deallocate(&mut self) {
        let buffers = std::mem::take(&mut self.buffers);
        self.created_count -= buffers.len();
    }
}

/// State of a session key in the lookup map
enum KeyState {
    /// Session exists with this ID
    Active(SessionKey),
    /// Session creation in progress
    Pending,
}

/// How to look up the session for a packet
#[derive(Clone)]
enum LookupKey {
    /// For Targeted streams: use destination
    Destination(NetLocation),
    /// For SessionBased streams: use protocol session_id
    SessionId(u16),
}

/// Session lookup strategy - determined by server stream type
enum SessionLookup {
    /// For Targeted: destination -> KeyState
    ByDestination(FxHashMap<NetLocation, KeyState>),
    /// For SessionBased: session_id -> KeyState
    BySessionId(FxHashMap<u16, KeyState>),
}

/// A routing session (one per unique flow)
struct RoutingSession {
    /// The destination this session routes to
    destination: NetLocation,

    /// The session's session id if this is a session UDP stream
    session_id: u16,

    /// Resolved address for response source field
    resolved_addr: SocketAddr,

    /// The lookup key for this session (needed for removal from lookup map)
    lookup_key: LookupKey,

    /// The remote connection
    remote: Box<dyn AsyncMessageStream>,

    /// Count of pending writes in remote_write_queue for this session
    in_remote_write_queue: usize,

    /// Is there a pending flush?
    in_remote_flush_queue: bool,

    /// Count of pending responses in server_write_queue for this session
    in_server_write_queue: usize,

    /// Key for DelayQueue (to cancel/reset expiry timer)
    expiry_key: Option<delay_queue::Key>,

    /// Remote read returned EOF or error
    remote_read_eof: bool,

    /// Remote write returned error
    remote_write_eof: bool,

    /// Last time we wrote to the remote (for ping decisions)
    last_write: Instant,

    /// Last iteration when expiry was reset (to avoid redundant resets)
    last_expiry_iteration: usize,

    /// This session's share of `RouterLimits::shared_budget`. It follows
    /// `remote`, because the budget counts descriptors and the descriptor is
    /// the remote's: see `remove_session`.
    budget_permit: Option<OwnedSemaphorePermit>,
}

impl RoutingSession {
    fn new(
        destination: NetLocation,
        session_id: u16,
        resolved_addr: SocketAddr,
        lookup_key: LookupKey,
        remote: Box<dyn AsyncMessageStream>,
        budget_permit: Option<OwnedSemaphorePermit>,
    ) -> Self {
        Self {
            destination,
            session_id,
            resolved_addr,
            lookup_key,
            remote,
            in_remote_write_queue: 0,
            in_remote_flush_queue: false,
            in_server_write_queue: 0,
            expiry_key: None, // Set after insert when we have the SessionId
            remote_read_eof: false,
            remote_write_eof: false,
            last_write: Instant::now(),
            last_expiry_iteration: 0,
            budget_permit,
        }
    }

    /// Check if session should be removed.
    #[inline]
    fn should_remove(&self) -> bool {
        self.remote_read_eof && self.remote_write_eof
    }

    /// Reset session expiry timer (skips if already reset this iteration)
    #[inline]
    fn reset_expiry(
        &mut self,
        expiry_queue: &mut DelayQueue<SessionKey>,
        _id: SessionKey,
        iteration: usize,
        timeout: Duration,
    ) {
        if self.last_expiry_iteration == iteration {
            return; // Already reset this iteration
        }
        self.last_expiry_iteration = iteration;

        // Use reset() which is more efficient than remove() + insert()
        // as it reuses the same slab entry and key
        if let Some(ref key) = self.expiry_key {
            expiry_queue.reset(key, timeout);
        }
    }
}

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
                        }))
                    }
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }

    fn poll_write_message(
        &mut self,
        cx: &mut Context<'_>,
        data: &[u8],
        source: &SocketAddr,
        session_id: u16,
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
    session_id: u16,
}

/// Result of session creation
struct SessionCreateResult {
    remote: Box<dyn AsyncMessageStream>,
    resolved_addr: SocketAddr,
}

/// Type alias for the session creation future
type SessionCreateFuture = Pin<Box<dyn Future<Output = io::Result<SessionCreateResult>> + Send>>;

/// See `UdpRouter::remote_factory`.
#[cfg(test)]
type RemoteFactory = Box<dyn Fn(&NetLocation) -> SessionCreateFuture + Send + Sync>;

/// Pending session creation state
struct PendingSessionCreate {
    lookup_key: LookupKey,
    destination: NetLocation,
    session_id: u16,
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
        for pending in self.server_write_queue.drain(..) {
            self.server_write_pool.release(pending.buf);
        }
        self.server_write_pool.deallocate();
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
            let packet = match self.server.poll_read_message(cx, &mut read_buf) {
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
            if len == 0 {
                self.set_server_read_eof();
                break;
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
                    // No session - check blocked before creating
                    if self.blocked.get(&packet.destination).is_some() {
                        debug!("UDP proxying blocked to {}", packet.destination);
                        continue;
                    }

                    if self.pending_creates.len() >= MAX_PENDING_CREATES {
                        debug!(
                            "Too many pending creates, dropping new session creation for {}",
                            packet.destination
                        );
                        continue;
                    }

                    let Ok(budget_permit) = self.admit_session(&packet.destination) else {
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
            session_id,
            initial_data,
            future: _,
            budget_permit,
        } = pending;

        match result {
            Ok(SessionCreateResult {
                remote,
                resolved_addr,
            }) => {
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
            Err(e) => {
                warn!("Failed to create session for {}: {}", destination, e);
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    // Mark as blocked
                    self.blocked.put(destination.clone(), ());
                }
                // Remove from pending in lookup
                match (&mut self.session_lookup, &lookup_key) {
                    (SessionLookup::ByDestination(map), LookupKey::Destination(dest)) => {
                        map.remove(dest);
                    }
                    (SessionLookup::BySessionId(map), LookupKey::SessionId(sid)) => {
                        map.remove(sid);
                    }
                    _ => unreachable!(),
                }
                false
            }
        }
    }

    /// Resolve, judge and connect: how a session gets its remote.
    fn connect_future(&self, destination: &NetLocation) -> SessionCreateFuture {
        let selector = Arc::clone(&self.selector);
        let resolver = Arc::clone(&self.resolver);
        let dest_for_future = destination.clone();

        Box::pin(async move {
            let resolved_addr = resolve_single_address(&resolver, &dest_for_future).await?;
            // Create ResolvedLocation with pre-resolved address
            let resolved_location = ResolvedLocation::with_resolved(dest_for_future, resolved_addr);
            let decision = selector.judge(resolved_location, &resolver).await?;

            match decision {
                ConnectDecision::Allow {
                    chain_group,
                    remote_location,
                    ..
                } => {
                    let client_stream = chain_group
                        .connect_udp_bidirectional(&resolver, remote_location)
                        .await?;

                    Ok(SessionCreateResult {
                        remote: client_stream,
                        resolved_addr,
                    })
                }
                ConnectDecision::Block => Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Destination blocked by routing rules",
                )),
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
        } = packet;

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
            Some(factory) => factory(&destination),
            None => self.connect_future(&destination),
        };
        #[cfg(not(test))]
        let future = self.connect_future(&destination);

        let index = self.pending_creates.len();
        self.pending_creates.push(PendingSessionCreate {
            lookup_key,
            destination,
            session_id,
            initial_data,
            future,
            budget_permit,
        });
        let _ = self.poll_pending_create(cx, index);
    }

    /// Remove a session (split-borrow friendly version)
    #[inline]
    fn remove_session(&mut self, id: SessionKey) {
        let Some(mut session) = self.sessions.swap_remove(&id) else {
            return;
        };

        debug!("Session removed: {}", session.destination);

        // Cancel expiry timer
        if let Some(key) = session.expiry_key.take() {
            self.expiry_queue.remove(&key);
        }

        // Remove from lookup map
        match (&mut self.session_lookup, session.lookup_key) {
            (SessionLookup::ByDestination(map), LookupKey::Destination(dest)) => {
                map.remove(&dest);
            }
            (SessionLookup::BySessionId(map), LookupKey::SessionId(sid)) => {
                map.remove(&sid);
            }
            _ => unreachable!(),
        }

        // Queue remote stream for graceful shutdown. The permit goes with it:
        // the socket stays open until the shutdown finishes, and a budget
        // that came back before then would admit a new session while the old
        // descriptor was still held, which under churn is over the cap.
        self.pending_shutdowns
            .push_back((session.remote, session.budget_permit.take()));
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
mod tests {
    use super::*;
    use crate::config::{RuleActionConfig, RuleConfig};
    use crate::option_util::OneOrSome;
    use crate::quic_outbound::testing::{direct_selector, spawn_udp_echo, test_resolver};
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
        fn poll_shutdown_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
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
        fn poll_shutdown_message(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
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
                Ok(SessionCreateResult {
                    remote,
                    resolved_addr: "192.0.2.1:9".parse().unwrap(),
                })
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
}
