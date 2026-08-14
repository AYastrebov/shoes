use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::async_stream::{AsyncPing, AsyncStream};

/// Wraps a client stream and counts bytes in each direction. `up` is bytes read
/// from the client (client -> proxy); `down` is bytes written to the client
/// (proxy -> client). Applied once at the accept edge, so it is protocol-agnostic
/// and covers every downstream copy path without touching them.
pub struct CountingStream<S> {
    inner: S,
    up: Arc<AtomicU64>,
    down: Arc<AtomicU64>,
}

impl<S> CountingStream<S> {
    pub fn new(inner: S, up: Arc<AtomicU64>, down: Arc<AtomicU64>) -> Self {
        Self { inner, up, down }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CountingStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &r {
            let read = buf.filled().len() - before;
            if read > 0 {
                self.up.fetch_add(read as u64, Ordering::Relaxed);
            }
        }
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountingStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &r {
            self.down.fetch_add(*n as u64, Ordering::Relaxed);
        }
        r
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    // Forward vectored writes so wrapping the stream never silently disables a
    // vectored fast path the inner stream supports.
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(n)) = &r {
            self.down.fetch_add(*n as u64, Ordering::Relaxed);
        }
        r
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

impl<S: AsyncPing + Unpin> AsyncPing for CountingStream<S> {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }
    fn poll_write_ping(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        Pin::new(&mut self.inner).poll_write_ping(cx)
    }
}

impl<S: AsyncStream> AsyncStream for CountingStream<S> {}

/// Wrap a client stream so its bytes are counted, using the handle's counters.
/// Feature-off: identity (returns the stream unchanged), so there is no wrapper
/// in the hot path.
#[cfg(feature = "control-api")]
pub fn counted<S: crate::async_stream::AsyncStream>(
    stream: S,
    handle: &ConnectionHandle,
) -> CountingStream<S> {
    let (up, down) = handle.counters();
    CountingStream::new(stream, up, down)
}

#[cfg(not(feature = "control-api"))]
#[inline(always)]
pub fn counted<S: crate::async_stream::AsyncStream>(stream: S, _handle: &ConnectionHandle) -> S {
    stream
}

use std::net::SocketAddr;

#[cfg(feature = "control-api")]
mod imp {
    use super::*;
    use dashmap::DashMap;
    use serde::Serialize;
    use std::sync::LazyLock;
    use tokio::sync::broadcast;

    static EPOCH: LazyLock<std::time::Instant> = LazyLock::new(std::time::Instant::now);
    static NEXT_ID: AtomicU64 = AtomicU64::new(1);

    // Global counters for O(1) /metrics. These are updated per connection (in
    // register / Drop), NEVER per poll — the per-poll hot path touches only a
    // connection's own uncontended atomics, so there is no shared-cache-line
    // contention across connections. Byte totals are monotonic counters folded
    // in when a connection closes (standard Prometheus counter semantics).
    static ACTIVE_CONNECTIONS: AtomicU64 = AtomicU64::new(0);
    static TOTAL_CONNECTIONS: AtomicU64 = AtomicU64::new(0);
    static TOTAL_UP_BYTES: AtomicU64 = AtomicU64::new(0);
    static TOTAL_DOWN_BYTES: AtomicU64 = AtomicU64::new(0);

    pub struct MetricsCounters {
        pub active_connections: u64,
        pub total_connections: u64,
        pub total_up_bytes: u64,
        pub total_down_bytes: u64,
    }

    pub fn metrics_counters() -> MetricsCounters {
        MetricsCounters {
            active_connections: ACTIVE_CONNECTIONS.load(Ordering::Relaxed),
            total_connections: TOTAL_CONNECTIONS.load(Ordering::Relaxed),
            total_up_bytes: TOTAL_UP_BYTES.load(Ordering::Relaxed),
            total_down_bytes: TOTAL_DOWN_BYTES.load(Ordering::Relaxed),
        }
    }

    fn unix_now() -> u64 {
        std::time::SystemTime::UNIX_EPOCH
            .elapsed()
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    struct Entry {
        inbound: &'static str,
        client_addr: SocketAddr,
        started_unix: u64,
        up: Arc<AtomicU64>,
        down: Arc<AtomicU64>,
        protocol: parking_lot::Mutex<String>,
        target: parking_lot::Mutex<Option<String>>,
    }

    struct Registry {
        entries: DashMap<u64, Arc<Entry>>,
        events: broadcast::Sender<ConnectionEvent>,
    }

    static REGISTRY: LazyLock<Registry> = LazyLock::new(|| Registry {
        entries: DashMap::new(),
        events: broadcast::channel(1024).0,
    });

    #[derive(Clone, Serialize)]
    pub struct ConnectionSnapshot {
        pub id: u64,
        pub inbound: &'static str,
        pub protocol: String,
        pub client_addr: SocketAddr,
        pub target: Option<String>,
        pub started_unix: u64,
        pub up_bytes: u64,
        pub down_bytes: u64,
    }

    #[derive(Clone, Serialize)]
    #[serde(tag = "event", rename_all = "lowercase")]
    pub enum ConnectionEvent {
        Open(ConnectionSnapshot),
        Close {
            id: u64,
            up_bytes: u64,
            down_bytes: u64,
            ended_unix: u64,
        },
    }

    pub struct ConnectionHandle {
        id: u64,
        entry: Arc<Entry>,
    }

    pub fn register(client_addr: SocketAddr, inbound: &'static str) -> ConnectionHandle {
        LazyLock::force(&EPOCH);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let entry = Arc::new(Entry {
            inbound,
            client_addr,
            started_unix: unix_now(),
            up: Arc::new(AtomicU64::new(0)),
            down: Arc::new(AtomicU64::new(0)),
            protocol: parking_lot::Mutex::new(String::new()),
            target: parking_lot::Mutex::new(None),
        });
        REGISTRY.entries.insert(id, entry.clone());
        ACTIVE_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
        TOTAL_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
        // Only build + send the event if a panel is actually streaming; otherwise
        // a connection open costs just the receiver_count() atomic load.
        if REGISTRY.events.receiver_count() > 0 {
            let _ = REGISTRY
                .events
                .send(ConnectionEvent::Open(entry_snapshot(id, &entry)));
        }
        ConnectionHandle { id, entry }
    }

    fn entry_snapshot(id: u64, e: &Entry) -> ConnectionSnapshot {
        ConnectionSnapshot {
            id,
            inbound: e.inbound,
            protocol: e.protocol.lock().clone(),
            client_addr: e.client_addr,
            target: e.target.lock().clone(),
            started_unix: e.started_unix,
            up_bytes: e.up.load(Ordering::Relaxed),
            down_bytes: e.down.load(Ordering::Relaxed),
        }
    }

    impl ConnectionHandle {
        pub fn counters(&self) -> (Arc<AtomicU64>, Arc<AtomicU64>) {
            (self.entry.up.clone(), self.entry.down.clone())
        }
        pub fn set_target(&self, target: String) {
            *self.entry.target.lock() = Some(target);
        }
        pub fn set_protocol(&self, protocol: &str) {
            *self.entry.protocol.lock() = protocol.to_string();
        }
    }

    impl Drop for ConnectionHandle {
        fn drop(&mut self) {
            REGISTRY.entries.remove(&self.id);
            let up = self.entry.up.load(Ordering::Relaxed);
            let down = self.entry.down.load(Ordering::Relaxed);
            // Fold this connection's totals into the global counters once, here.
            ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
            TOTAL_UP_BYTES.fetch_add(up, Ordering::Relaxed);
            TOTAL_DOWN_BYTES.fetch_add(down, Ordering::Relaxed);
            if REGISTRY.events.receiver_count() > 0 {
                let _ = REGISTRY.events.send(ConnectionEvent::Close {
                    id: self.id,
                    up_bytes: up,
                    down_bytes: down,
                    ended_unix: unix_now(),
                });
            }
        }
    }

    pub fn snapshot() -> Vec<ConnectionSnapshot> {
        REGISTRY
            .entries
            .iter()
            .map(|kv| entry_snapshot(*kv.key(), kv.value()))
            .collect()
    }

    pub fn subscribe_events() -> broadcast::Receiver<ConnectionEvent> {
        REGISTRY.events.subscribe()
    }
}

#[cfg(feature = "control-api")]
pub use imp::{
    ConnectionEvent, ConnectionHandle, ConnectionSnapshot, MetricsCounters, metrics_counters,
    register, snapshot, subscribe_events,
};

#[cfg(not(feature = "control-api"))]
mod imp {
    use super::*;

    /// Zero-sized handle; all methods inline to nothing.
    pub struct ConnectionHandle;

    #[inline(always)]
    pub fn register(_client_addr: SocketAddr, _inbound: &'static str) -> ConnectionHandle {
        ConnectionHandle
    }

    impl ConnectionHandle {
        #[inline(always)]
        pub fn counters(&self) -> (Arc<AtomicU64>, Arc<AtomicU64>) {
            (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)))
        }
        #[inline(always)]
        pub fn set_target(&self, _target: String) {}
        #[inline(always)]
        pub fn set_protocol(&self, _protocol: &str) {}
    }
}

#[cfg(not(feature = "control-api"))]
pub use imp::{ConnectionHandle, register};

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn counts_bytes_in_both_directions() {
        let (mut a, b) = tokio::io::duplex(64);
        let up = Arc::new(AtomicU64::new(0));
        let down = Arc::new(AtomicU64::new(0));
        let mut counted = CountingStream::new(b, up.clone(), down.clone());

        // Peer writes 5 bytes; counted reads them -> up += 5.
        a.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        counted.read_exact(&mut buf).await.unwrap();
        assert_eq!(up.load(Ordering::Relaxed), 5);

        // counted writes 3 bytes to the peer -> down += 3.
        counted.write_all(b"abc").await.unwrap();
        assert_eq!(down.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn register_deregister_and_snapshot() {
        // Registry state is process-global; use a unique client_addr so this test
        // matches only its own entry regardless of other tests running in parallel,
        // and assert on that entry rather than on absolute counts.
        let addr: SocketAddr = "127.0.0.1:5555".parse().unwrap();
        let handle = register(addr, "socks");
        handle.set_target("example.com:443".to_string());
        let (up, down) = handle.counters();
        up.fetch_add(10, Ordering::Relaxed);
        down.fetch_add(20, Ordering::Relaxed);

        let mine = snapshot()
            .into_iter()
            .find(|c| c.client_addr == addr)
            .expect("our connection should be in the snapshot");
        assert_eq!(mine.inbound, "socks");
        assert_eq!(mine.target.as_deref(), Some("example.com:443"));
        assert_eq!(mine.up_bytes, 10);
        assert_eq!(mine.down_bytes, 20);

        drop(handle);
        assert!(snapshot().into_iter().all(|c| c.client_addr != addr));
    }
}
