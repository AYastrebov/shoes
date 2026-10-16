//! Ownership of the connections a set of listeners accepted.
//!
//! An accept loop used to hand each connection to `tokio::spawn` and keep
//! nothing, so stopping the loop stopped new connections and nothing else:
//! the live ones ran on, on the configuration they started with, owned by
//! no one. Spawned through a [`ConnectionSet`] instead, they can be waited
//! for or cancelled together -- tokio's tracker-and-token shutdown pattern
//! (<https://tokio.rs/tokio/topics/shutdown>).

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

tokio::task_local! {
    /// The set the running connection belongs to, so work it detaches --
    /// an h2mux session, a UDP association -- joins that set too, without
    /// every handler being handed one.
    static CURRENT: ConnectionSet;
}

/// Spawn `work` into the current connection's set, or detached when there is
/// none (a test, a task outside any listener). What a handler calls where it
/// used to call `tokio::spawn` for work that outlives its own future.
pub fn spawn<F>(work: F) -> JoinHandle<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    spawn_boxed(Box::pin(work))
}

/// A connection's future, boxed where it enters this module. Everything past
/// that point -- the tracker, the token, the task-local and tokio's task
/// harness -- is then compiled once rather than once per spawned future type
/// and per branch below. Generic, that cost 620 KB of the arm64 mobile
/// library; boxed, the library is 377 KB smaller than before the set existed.
type Work = Pin<Box<dyn Future<Output = ()> + Send>>;

fn spawn_boxed(work: Work) -> JoinHandle<()> {
    match CURRENT.try_with(|set| set.clone()) {
        Ok(set) => set.spawn_boxed(work),
        Err(_) => tokio::spawn(work),
    }
}

/// The connections one launch of a configuration accepted. Cheap to clone;
/// clones share the set.
#[derive(Clone, Default)]
pub struct ConnectionSet {
    tracker: TaskTracker,
    token: CancellationToken,
}

impl ConnectionSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Run a connection as a member of the set. Cancelling the set drops it
    /// where it stands, which closes its sockets.
    pub fn spawn<F>(&self, connection: F) -> JoinHandle<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.spawn_boxed(Box::pin(connection))
    }

    fn spawn_boxed(&self, connection: Work) -> JoinHandle<()> {
        let token = self.token.clone();
        let set = self.clone();
        self.tracker.spawn(CURRENT.scope(set, async move {
            let _ = token.run_until_cancelled_owned(connection).await;
        }))
    }

    /// Run `work` -- an accept loop -- with this as the current set, so the
    /// connections it hands to [`spawn`] join it. The loop itself is not a
    /// member: aborting it is the caller's, through its join handle.
    pub fn scope<F: Future>(&self, work: F) -> impl Future<Output = F::Output> + use<F> {
        CURRENT.scope(self.clone(), work)
    }

    /// Connections still running.
    pub fn len(&self) -> usize {
        self.tracker.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tracker.is_empty()
    }

    /// Let the live connections finish for up to `grace`, then cancel the
    /// rest. Returns how many were cancelled.
    pub async fn drain(&self, grace: Duration) -> usize {
        self.tracker.close();
        if tokio::time::timeout(grace, self.tracker.wait())
            .await
            .is_ok()
        {
            return 0;
        }
        let cancelled = self.tracker.len();
        self.abort().await;
        cancelled
    }

    /// Cancel every connection now, and wait until they are gone.
    pub async fn abort(&self) {
        self.tracker.close();
        self.token.cancel();
        self.tracker.wait().await;
    }
}

impl std::fmt::Debug for ConnectionSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionSet")
            .field("live", &self.tracker.len())
            .field("cancelled", &self.token.is_cancelled())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_drain_waits_for_connections_that_finish() {
        let set = ConnectionSet::new();
        set.spawn(tokio::time::sleep(Duration::from_millis(20)));
        assert_eq!(set.len(), 1);
        assert_eq!(set.drain(Duration::from_secs(5)).await, 0);
        assert!(set.is_empty());
    }

    #[tokio::test]
    async fn a_drain_cancels_what_outlives_its_grace() {
        let set = ConnectionSet::new();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        set.spawn(async move {
            // Dropped, not completed: the sender sees the receiver go.
            let _keep = tx;
            std::future::pending::<()>().await;
        });
        set.spawn(tokio::time::sleep(Duration::from_millis(1)));
        tokio::time::sleep(Duration::from_millis(20)).await;
        let started = tokio::time::Instant::now();
        assert_eq!(set.drain(Duration::from_millis(50)).await, 1);
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(rx.await.is_err(), "the cancelled connection was dropped");
        assert!(set.is_empty());
    }

    /// Work a connection detaches through `connections::spawn` belongs to
    /// the connection's set, so an abort reaches it.
    #[tokio::test]
    async fn detached_work_joins_its_connections_set() {
        let set = ConnectionSet::new();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        set.spawn(async move {
            super::spawn(async move {
                let _keep = tx;
                std::future::pending::<()>().await;
            });
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            set.len(),
            1,
            "the parent ended; the detached work is still in the set"
        );
        set.abort().await;
        assert!(rx.await.is_err());
    }

    #[tokio::test]
    async fn an_abort_drops_every_connection_at_once() {
        let set = ConnectionSet::new();
        for _ in 0..3 {
            set.spawn(std::future::pending());
        }
        set.abort().await;
        assert!(set.is_empty());
    }
}
