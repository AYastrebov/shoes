//! One routing session -- a flow to one destination -- and how a packet
//! finds its session.

use std::net::SocketAddr;
use std::time::Duration;

use rustc_hash::FxHashMap;
use tokio::sync::OwnedSemaphorePermit;
use tokio::time::Instant;
use tokio_util::time::{DelayQueue, delay_queue};

use crate::address::NetLocation;
use crate::async_stream::AsyncMessageStream;

/// Session identifier - incrementing counter, never reused
pub(super) type SessionKey = usize;

/// State of a session key in the lookup map
pub(super) enum KeyState {
    /// Session exists with this ID
    Active(SessionKey),
    /// Session creation in progress
    Pending,
}

/// How to look up the session for a packet
#[derive(Clone)]
pub(super) enum LookupKey {
    /// For Targeted streams: use destination
    Destination(NetLocation),
    /// For SessionBased streams: use protocol session_id
    SessionId(u16),
}

/// Session lookup strategy - determined by server stream type
pub(super) enum SessionLookup {
    /// For Targeted: destination -> KeyState
    ByDestination(FxHashMap<NetLocation, KeyState>),
    /// For SessionBased: session_id -> KeyState
    BySessionId(FxHashMap<u16, KeyState>),
}

/// A routing session (one per unique flow)
pub(super) struct RoutingSession {
    /// The destination this session routes to
    pub(super) destination: NetLocation,

    /// The session's session id if this is a session UDP stream
    pub(super) session_id: u16,

    /// Resolved address for response source field
    pub(super) resolved_addr: SocketAddr,

    /// The lookup key for this session (needed for removal from lookup map)
    pub(super) lookup_key: LookupKey,

    /// The remote connection
    pub(super) remote: Box<dyn AsyncMessageStream>,

    /// Count of pending writes in remote_write_queue for this session
    pub(super) in_remote_write_queue: usize,

    /// Is there a pending flush?
    pub(super) in_remote_flush_queue: bool,

    /// Count of pending responses in server_write_queue for this session
    pub(super) in_server_write_queue: usize,

    /// Key for DelayQueue (to cancel/reset expiry timer)
    pub(super) expiry_key: Option<delay_queue::Key>,

    /// Remote read returned EOF or error
    pub(super) remote_read_eof: bool,

    /// Remote write returned error
    pub(super) remote_write_eof: bool,

    /// Last time we wrote to the remote (for ping decisions)
    pub(super) last_write: Instant,

    /// Last iteration when expiry was reset (to avoid redundant resets)
    pub(super) last_expiry_iteration: usize,

    /// This session's share of `RouterLimits::shared_budget`. It follows
    /// `remote`, because the budget counts descriptors and the descriptor is
    /// the remote's: see `remove_session`.
    pub(super) budget_permit: Option<OwnedSemaphorePermit>,
}

impl RoutingSession {
    pub(super) fn new(
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
    pub(super) fn should_remove(&self) -> bool {
        self.remote_read_eof && self.remote_write_eof
    }

    /// Reset session expiry timer (skips if already reset this iteration)
    #[inline]
    pub(super) fn reset_expiry(
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
