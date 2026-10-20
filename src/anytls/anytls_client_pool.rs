//! The AnyTLS client's pool of idle sessions.
//!
//! The reference client (sing-anytls `client.go`) reuses sessions: a
//! connection takes the newest idle one, opens its stream there, and the
//! session goes back to the front of the idle list when that stream ends.
//! Idle sessions are checked every 30 seconds and closed once idle for 30,
//! keeping `min_idle_session` of them. A server may refuse a client that
//! never reuses (AT-A1/A2). Spec:
//! `docs/specs/2026-10-19-session-reuse-without-dialling.md`.

use std::collections::VecDeque;
use std::sync::{Arc, Weak};
use std::time::Duration;

use tokio::time::Instant;

use crate::anytls::anytls_client_session::AnyTlsClientSession;

/// How often idle sessions are checked (`defaultIdleSessionCheckInterval`).
const IDLE_CHECK_INTERVAL: Duration = Duration::from_secs(30);
/// How long a session may sit idle before it is closed
/// (`defaultIdleSessionTimeout`).
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

struct Idle {
    session: Arc<AnyTlsClientSession>,
    since: Instant,
}

struct State {
    /// Newest first.
    idle: VecDeque<Idle>,
    /// Sessions carrying a stream. Held here, as the reference client's
    /// `sessions` set holds them, because a session otherwise lives only as
    /// long as its streams: dropping the last one tore the session down with
    /// its FIN still queued, so nothing came back to be reused.
    in_use: Vec<Arc<AnyTlsClientSession>>,
    /// Whether the reaper task is running. Under the same lock as `idle`, so
    /// a session released as the reaper decides to stop cannot be left
    /// without one.
    reaper_running: bool,
}

pub struct ClientPool {
    state: parking_lot::Mutex<State>,
    min_idle: usize,
}

impl std::fmt::Debug for ClientPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientPool")
            .field("idle", &self.state.lock().idle.len())
            .field("min_idle", &self.min_idle)
            .finish()
    }
}

impl ClientPool {
    pub fn new(min_idle: usize) -> Arc<Self> {
        Arc::new(Self {
            state: parking_lot::Mutex::new(State {
                idle: VecDeque::new(),
                in_use: Vec::new(),
                reaper_running: false,
            }),
            min_idle,
        })
    }

    /// The newest idle session that is still open, out of the pool: it is in
    /// use until its stream ends.
    pub fn take(&self) -> Option<Arc<AnyTlsClientSession>> {
        let mut state = self.state.lock();
        state.in_use.retain(|session| !session.is_closed());
        while let Some(idle) = state.idle.pop_front() {
            if !idle.session.is_closed() {
                state.in_use.push(Arc::clone(&idle.session));
                return Some(idle.session);
            }
        }
        None
    }

    /// Put a session back as the newest idle one. A closed session, or one
    /// already idle, is left alone.
    pub fn release(self: &Arc<Self>, session: Arc<AnyTlsClientSession>) {
        let mut state = self.state.lock();
        state
            .in_use
            .retain(|in_use| !Arc::ptr_eq(in_use, &session) && !in_use.is_closed());
        if session.is_closed() {
            return;
        }
        if state
            .idle
            .iter()
            .any(|idle| Arc::ptr_eq(&idle.session, &session))
        {
            return;
        }
        state.idle.push_front(Idle {
            session,
            since: Instant::now(),
        });
        if !state.reaper_running {
            state.reaper_running = true;
            tokio::spawn(reap(Arc::downgrade(self)));
        }
    }

    /// A new session, in use from the start: held until it closes, and back
    /// here as idle whenever one of its streams finishes.
    pub fn attach(self: &Arc<Self>, session: &Arc<AnyTlsClientSession>) {
        {
            let mut state = self.state.lock();
            state.in_use.retain(|in_use| !in_use.is_closed());
            state.in_use.push(Arc::clone(session));
        }
        let pool = Arc::downgrade(self);
        let weak = Arc::downgrade(session);
        session.on_stream_finished(Box::new(move || {
            if let (Some(pool), Some(session)) = (pool.upgrade(), weak.upgrade()) {
                pool.release(session);
            }
        }));
    }

    /// Take out the sessions idle past the timeout, oldest first, keeping
    /// `min_idle`; closed ones go regardless. Stops the reaper, under the
    /// lock, once nothing is left.
    fn expire(&self, now: Instant) -> (Vec<Arc<AnyTlsClientSession>>, bool) {
        let mut state = self.state.lock();
        state.idle.retain(|idle| !idle.session.is_closed());
        state.in_use.retain(|session| !session.is_closed());
        let mut expired = Vec::new();
        while state.idle.len() > self.min_idle {
            match state.idle.back() {
                Some(oldest) if now.duration_since(oldest.since) >= IDLE_TIMEOUT => {
                    if let Some(oldest) = state.idle.pop_back() {
                        expired.push(oldest.session);
                    }
                }
                _ => break,
            }
        }
        let stop = state.idle.is_empty();
        if stop {
            state.reaper_running = false;
        }
        (expired, stop)
    }

    #[cfg(test)]
    pub fn idle_len(&self) -> usize {
        self.state.lock().idle.len()
    }

    /// Run the reaper's expiry as of `now`, closing what it takes out.
    #[cfg(test)]
    pub async fn expire_at(&self, now: Instant) -> usize {
        let (expired, _) = self.expire(now);
        let n = expired.len();
        for session in expired {
            session.shut().await;
        }
        n
    }
}

/// The pool's reaper: wakes every check interval and closes what expired.
/// Holds the pool weakly, so a dropped handler ends it at the next tick.
async fn reap(pool: Weak<ClientPool>) {
    loop {
        tokio::time::sleep(IDLE_CHECK_INTERVAL).await;
        let Some(pool) = pool.upgrade() else {
            return;
        };
        let (expired, stop) = pool.expire(Instant::now());
        drop(pool);
        for session in expired {
            session.shut().await;
        }
        if stop {
            return;
        }
    }
}
