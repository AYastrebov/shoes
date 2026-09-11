//! One entry per live connection, counted at the accept edge.
//!
//! Lifted from `feature/control-api` (see the spec's "Prior art") and
//! extended with what a Clash connection object needs: destination, exit
//! outbound, matching rule, and a way to close. Always compiled: without
//! `control-connections` every call here is an inlined no-op returning a
//! zero-sized handle, so the accept loops carry no `#[cfg]` and a mobile
//! build has the hot path it has today.
//!
//! Counting is at the *client* edge -- `up` is bytes read from the client,
//! `down` is bytes written to it -- which is what the client actually
//! transferred, handshake included. The per-outbound counters in
//! `crate::outbound_stats` measure at the outbound instead; the two differ
//! by the handshake and by anything written before a failed dial, which is
//! explainable rather than zero.
//!
//! See docs/specs/2026-09-09-clash-api.md.
//!
//! `allow(dead_code)` for the reason `crate::outbound_stats` gives about its
//! own accessors: the binary declares its modules in `main.rs` and the
//! library declares them again, so which of these has a caller depends on
//! the build -- the readers are the controller's, which only the CLI mounts,
//! and the writers are the accept paths', which only a server build has.
//! They are the accessors a registry owes its callers either way.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
// Std's on every target that has one; see `util::AtomicU64`.
use crate::util::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::address::NetLocation;
use crate::async_stream::{AsyncPing, AsyncStream};

/// What a connection carries. Clash's `metadata.network`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Tcp,
    Udp,
}

impl Network {
    pub fn as_str(self) -> &'static str {
        match self {
            Network::Tcp => "tcp",
            Network::Udp => "udp",
        }
    }
}

/// One rule as a dashboard shows it, computed once by the selector that
/// owns the rules. Re-exported so a reader of the registry does not need to
/// know where a connection's rule list came from.
///
/// `allow(unused_imports)` for the reason the module header gives: the
/// binary and the library declare this module separately, and which build
/// has a reader depends on the features. Gated like the selector's own
/// definition: without the registry nothing renders a rule.
#[cfg(feature = "control-connections")]
#[allow(unused_imports)]
pub use crate::client_proxy_selector::RuleSummary;

/// The two atomics a connection owns. Uncontended: nothing but this
/// connection's own stream touches them on the polling path.
#[derive(Debug, Default)]
pub struct ConnectionCounters {
    pub up: AtomicU64,
    pub down: AtomicU64,
}

/// Wraps a client stream and counts into `counters`.
///
/// Forwards vectored writes and pings so wrapping never silently disables a
/// fast path the inner stream supports.
pub struct CountingStream<S> {
    inner: S,
    counters: Arc<ConnectionCounters>,
}

impl<S> CountingStream<S> {
    pub fn new(inner: S, counters: Arc<ConnectionCounters>) -> Self {
        Self { inner, counters }
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
                self.counters.up.fetch_add(read as u64, Ordering::Relaxed);
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
            self.counters.down.fetch_add(*n as u64, Ordering::Relaxed);
        }
        r
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(n)) = &r {
            self.counters.down.fetch_add(*n as u64, Ordering::Relaxed);
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

/// A per-listener label, made once and kept for the process.
///
/// Interned rather than leaked per call: a reload rebuilds the same
/// listeners, and leaking a fresh copy each time would grow without bound in
/// a process that reloads on every config edit.
pub fn intern(label: String) -> &'static str {
    static LABELS: std::sync::Mutex<Vec<&'static str>> = std::sync::Mutex::new(Vec::new());
    let mut labels = LABELS.lock().unwrap();
    if let Some(existing) = labels.iter().find(|l| **l == label) {
        return existing;
    }
    let leaked: &'static str = Box::leak(label.into_boxed_str());
    labels.push(leaked);
    leaked
}

#[cfg(feature = "control-connections")]
mod imp {
    use super::*;

    use std::sync::LazyLock;
    use std::sync::atomic::AtomicUsize;

    use dashmap::DashMap;
    use parking_lot::Mutex;
    use tokio::sync::Notify;

    static NEXT_ID: AtomicU64 = AtomicU64::new(1);
    static CAP: AtomicUsize = AtomicUsize::new(4096);
    /// Tracked entries, admitted against `CAP` in one atomic step so the
    /// cap is a hard bound: a burst of accepts that each read the table's
    /// length and then inserted could all pass a check the last of them
    /// should have failed. Cheaper than the length too, which on a
    /// sharded map is a sum over every shard.
    static LIVE: AtomicUsize = AtomicUsize::new(0);

    // Process-wide totals, folded once per connection in `Drop` -- never on
    // the polling path, so no connection's bytes touch a line another
    // connection is writing.
    static TOTAL: AtomicU64 = AtomicU64::new(0);
    static UNTRACKED: AtomicU64 = AtomicU64::new(0);
    static FOLDED_UP: AtomicU64 = AtomicU64::new(0);
    static FOLDED_DOWN: AtomicU64 = AtomicU64::new(0);

    /// Counters for a connection nobody tracks. Shared, so passing the cap
    /// costs no allocation and the call sites still do not branch.
    fn void_counters() -> Arc<ConnectionCounters> {
        static VOID: LazyLock<Arc<ConnectionCounters>> =
            LazyLock::new(|| Arc::new(ConnectionCounters::default()));
        VOID.clone()
    }

    #[derive(Default)]
    struct InboundCounters {
        active: AtomicU64,
        total: AtomicU64,
        up: AtomicU64,
        down: AtomicU64,
    }

    struct Entry {
        id: u64,
        inbound: &'static str,
        network: Network,
        source: SocketAddr,
        started: std::time::SystemTime,
        counters: Arc<ConnectionCounters>,
        destination: Mutex<Option<NetLocation>>,
        sniffed_host: Mutex<Option<Arc<str>>>,
        chain: Mutex<Option<Arc<str>>>,
        group: Mutex<Option<Arc<str>>>,
        rule: Mutex<Option<usize>>,
        rules: Mutex<Option<Arc<[RuleSummary]>>>,
        close: Notify,
    }

    struct Registry {
        entries: DashMap<u64, Arc<Entry>>,
        inbounds: DashMap<&'static str, InboundCounters>,
        /// Every live listener's rule list, in the order the listeners were
        /// started.
        ///
        /// Here rather than in the router because a connection's rule index
        /// points into one of these, and the two have to be read together:
        /// a listing shows them all, and a connection names one.
        rule_lists: Mutex<Vec<Arc<[RuleSummary]>>>,
    }

    static REGISTRY: LazyLock<Registry> = LazyLock::new(|| Registry {
        entries: DashMap::new(),
        inbounds: DashMap::new(),
        rule_lists: Mutex::new(Vec::new()),
    });

    /// The registry is process-global and cargo runs tests in parallel, so
    /// every test that registers or reads totals takes this first -- the
    /// ones here, and the ones elsewhere that forward a real connection
    /// through an accept path. A tokio mutex, so an async test can hold it
    /// across its awaits; the sync tests here take it with `blocking_lock`
    /// before they build a runtime.
    #[cfg(test)]
    pub static REGISTRY_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// A connection's place in the table, for as long as the task lives.
    ///
    /// `None` past the cap: served, not tracked. The entry leaves the table
    /// when this drops, which is why it rides in the forwarding task's frame
    /// rather than in the table alone -- a reload aborts those tasks, and a
    /// panic unwinds them, and both must take their entries with them.
    pub struct ConnectionHandle {
        entry: Option<Arc<Entry>>,
    }

    /// How many live connections the table holds before it stops tracking.
    pub fn set_cap(cap: usize) {
        CAP.store(cap.max(1), Ordering::Relaxed);
    }

    pub fn register(
        source: SocketAddr,
        inbound: &'static str,
        network: Network,
    ) -> ConnectionHandle {
        let cap = CAP.load(Ordering::Relaxed);
        let admitted = LIVE.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |live| {
            (live < cap).then_some(live + 1)
        });
        if admitted.is_err() {
            UNTRACKED.fetch_add(1, Ordering::Relaxed);
            return ConnectionHandle { entry: None };
        }

        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let entry = Arc::new(Entry {
            id,
            inbound,
            network,
            source,
            started: std::time::SystemTime::now(),
            counters: Arc::new(ConnectionCounters::default()),
            destination: Mutex::new(None),
            sniffed_host: Mutex::new(None),
            chain: Mutex::new(None),
            group: Mutex::new(None),
            rule: Mutex::new(None),
            rules: Mutex::new(None),
            close: Notify::new(),
        });
        REGISTRY.entries.insert(id, entry.clone());
        TOTAL.fetch_add(1, Ordering::Relaxed);
        {
            let per = REGISTRY.inbounds.entry(inbound).or_default();
            per.active.fetch_add(1, Ordering::Relaxed);
            per.total.fetch_add(1, Ordering::Relaxed);
        }
        ConnectionHandle { entry: Some(entry) }
    }

    /// Wrap a client stream so its bytes reach this connection's counters.
    pub fn counted<S: AsyncStream>(stream: S, handle: &ConnectionHandle) -> CountingStream<S> {
        let counters = match &handle.entry {
            Some(e) => e.counters.clone(),
            None => void_counters(),
        };
        CountingStream::new(stream, counters)
    }

    impl ConnectionHandle {
        pub fn set_destination(&self, destination: &NetLocation) {
            if let Some(e) = &self.entry {
                *e.destination.lock() = Some(destination.clone());
            }
        }

        pub fn set_sniffed_host(&self, host: &str) {
            if let Some(e) = &self.entry {
                *e.sniffed_host.lock() = Some(Arc::from(host));
            }
        }

        /// What the rule engine decided: the exit outbound's key, the named
        /// group it routed through, the index of the rule that matched, and
        /// the rule list that index points into.
        pub fn set_route(
            &self,
            chain: Option<Arc<str>>,
            group: Option<Arc<str>>,
            rule: Option<usize>,
            rules: Option<Arc<[RuleSummary]>>,
        ) {
            if let Some(e) = &self.entry {
                *e.chain.lock() = chain;
                *e.group.lock() = group;
                *e.rule.lock() = rule;
                *e.rules.lock() = rules;
            }
        }

        /// Resolves when a controller asks for this connection to close.
        /// Pends forever for an untracked connection, which is what makes it
        /// safe to select on unconditionally.
        pub async fn closed(&self) {
            match &self.entry {
                Some(e) => e.close.notified().await,
                None => std::future::pending().await,
            }
        }

        /// The counters, for a path that does its own counting and wants a
        /// second target rather than a second wrapper.
        pub fn counters(&self) -> Option<Arc<ConnectionCounters>> {
            self.entry.as_ref().map(|e| e.counters.clone())
        }
    }

    impl Drop for ConnectionHandle {
        fn drop(&mut self) {
            let Some(e) = self.entry.take() else {
                return;
            };
            REGISTRY.entries.remove(&e.id);
            // Floors at zero for the reason the inbound counter below gives,
            // and more so: an underflow here would refuse every connection
            // the cap from then on.
            let _ = LIVE.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_sub(1))
            });
            let up = e.counters.up.load(Ordering::Relaxed);
            let down = e.counters.down.load(Ordering::Relaxed);
            FOLDED_UP.fetch_add(up, Ordering::Relaxed);
            FOLDED_DOWN.fetch_add(down, Ordering::Relaxed);
            if let Some(per) = REGISTRY.inbounds.get(e.inbound) {
                // Floors at zero for the reason `OutboundCounters` gives:
                // a cleanup path that ran twice would read as billions.
                let _ = per
                    .active
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                        Some(n.saturating_sub(1))
                    });
                per.up.fetch_add(up, Ordering::Relaxed);
                per.down.fetch_add(down, Ordering::Relaxed);
            }
        }
    }

    /// A point-in-time reading of one connection.
    #[derive(Debug, Clone)]
    pub struct ConnectionSnapshot {
        pub id: u64,
        pub inbound: &'static str,
        pub network: Network,
        pub source: SocketAddr,
        /// The destination as it was requested: a hostname when the inbound
        /// carried one, an address otherwise.
        pub destination: Option<String>,
        pub destination_host: Option<String>,
        pub destination_port: u16,
        pub sniffed_host: Option<String>,
        pub chain: Option<String>,
        pub group: Option<String>,
        pub rule: Option<usize>,
        /// The matching rule, rendered against the list that was live when
        /// this connection was judged -- which a reload may since have
        /// replaced.
        pub rule_summary: Option<RuleSummary>,
        pub started: std::time::SystemTime,
        pub up: u64,
        pub down: u64,
    }

    fn snapshot_entry(e: &Entry) -> ConnectionSnapshot {
        let destination = e.destination.lock().clone();
        let rule = *e.rule.lock();
        let rule_summary =
            rule.and_then(|i| e.rules.lock().as_ref().and_then(|r| r.get(i).cloned()));
        ConnectionSnapshot {
            id: e.id,
            inbound: e.inbound,
            network: e.network,
            source: e.source,
            destination: destination.as_ref().map(|d| d.to_string()),
            destination_host: destination.as_ref().map(|d| d.address().to_string()),
            destination_port: destination.as_ref().map(|d| d.port()).unwrap_or(0),
            sniffed_host: e.sniffed_host.lock().as_deref().map(str::to_string),
            chain: e.chain.lock().as_deref().map(str::to_string),
            group: e.group.lock().as_deref().map(str::to_string),
            rule,
            rule_summary,
            started: e.started,
            up: e.counters.up.load(Ordering::Relaxed),
            down: e.counters.down.load(Ordering::Relaxed),
        }
    }

    /// Every tracked connection, oldest first, so a dashboard redrawing on a
    /// timer does not reorder its own rows.
    pub fn snapshot() -> Vec<ConnectionSnapshot> {
        let mut out: Vec<_> = REGISTRY
            .entries
            .iter()
            .map(|kv| snapshot_entry(kv.value()))
            .collect();
        out.sort_by_key(|c| c.id);
        out
    }

    /// Ask one connection to close. `false` if no such connection is live.
    ///
    /// Asking is all this does: the entry leaves the table when the task
    /// that owns it drops its handle, so a dashboard that deletes and
    /// re-lists sees the connection until it is actually gone.
    pub fn close(id: u64) -> bool {
        match REGISTRY.entries.get(&id) {
            Some(e) => {
                e.close.notify_one();
                true
            }
            None => false,
        }
    }

    /// Ask every live connection to close; returns how many were asked.
    pub fn close_all() -> usize {
        let mut n = 0;
        for kv in REGISTRY.entries.iter() {
            kv.value().close.notify_one();
            n += 1;
        }
        n
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Totals {
        pub active: usize,
        pub total: u64,
        pub untracked: u64,
        pub up: u64,
        pub down: u64,
    }

    /// Folded totals plus what the live entries have counted so far.
    ///
    /// O(live), bounded by the cap, and read once a second by a subscriber
    /// rather than per connection. This is what `/traffic` differences, and
    /// it is populated in every mode -- unlike the TUN-edge globals, which
    /// stay at zero on a server.
    pub fn totals() -> Totals {
        let mut up = FOLDED_UP.load(Ordering::Relaxed);
        let mut down = FOLDED_DOWN.load(Ordering::Relaxed);
        for kv in REGISTRY.entries.iter() {
            up += kv.value().counters.up.load(Ordering::Relaxed);
            down += kv.value().counters.down.load(Ordering::Relaxed);
        }
        Totals {
            active: LIVE.load(Ordering::Relaxed),
            total: TOTAL.load(Ordering::Relaxed),
            untracked: UNTRACKED.load(Ordering::Relaxed),
            up,
            down,
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct InboundStats {
        pub inbound: &'static str,
        pub active: u64,
        pub total: u64,
        pub up: u64,
        pub down: u64,
    }

    /// Record a listener's rules, once, as it starts.
    ///
    /// Identity-deduplicated: several listeners of one config share a
    /// selector, and a controller should list those rules once.
    pub fn install_rule_list(list: Arc<[RuleSummary]>) {
        let mut lists = REGISTRY.rule_lists.lock();
        if !lists.iter().any(|l| Arc::ptr_eq(l, &list)) {
            lists.push(list);
        }
    }

    /// Forget every list. Called where a reload replaces the listeners, for
    /// the reason `install` gives about outbounds.
    pub fn reset_rule_lists() {
        REGISTRY.rule_lists.lock().clear();
    }

    pub fn rule_lists() -> Vec<Arc<[RuleSummary]>> {
        REGISTRY.rule_lists.lock().clone()
    }

    /// Per-listener counters, sorted by label. O(configured listeners).
    pub fn inbound_stats() -> Vec<InboundStats> {
        let mut out: Vec<_> = REGISTRY
            .inbounds
            .iter()
            .map(|kv| InboundStats {
                inbound: kv.key(),
                active: kv.value().active.load(Ordering::Relaxed),
                total: kv.value().total.load(Ordering::Relaxed),
                up: kv.value().up.load(Ordering::Relaxed),
                down: kv.value().down.load(Ordering::Relaxed),
            })
            .collect();
        out.sort_by_key(|i| i.inbound);
        out
    }
}

#[cfg(feature = "control-connections")]
#[allow(unused_imports)]
pub use imp::*;

#[cfg(not(feature = "control-connections"))]
mod imp {
    use super::*;

    /// Zero-sized; every method inlines to nothing.
    pub struct ConnectionHandle;

    #[inline(always)]
    pub fn register(
        _source: SocketAddr,
        _inbound: &'static str,
        _network: Network,
    ) -> ConnectionHandle {
        ConnectionHandle
    }

    /// Identity: no wrapper reaches the hot path in a build without the
    /// registry.
    #[inline(always)]
    pub fn counted<S: AsyncStream>(stream: S, _handle: &ConnectionHandle) -> S {
        stream
    }

    impl ConnectionHandle {
        #[inline(always)]
        pub fn set_destination(&self, _destination: &NetLocation) {}

        #[inline(always)]
        pub fn set_sniffed_host(&self, _host: &str) {}

        /// Generic in the rule list so a call site compiles without naming
        /// `RuleSummary`, which only the real body has a use for.
        #[inline(always)]
        pub fn set_route<R>(
            &self,
            _chain: Option<Arc<str>>,
            _group: Option<Arc<str>>,
            _rule: Option<usize>,
            _rules: Option<R>,
        ) {
        }

        /// Never resolves: there is no controller to ask.
        #[inline(always)]
        pub async fn closed(&self) {
            std::future::pending::<()>().await
        }

        #[inline(always)]
        pub fn counters(&self) -> Option<Arc<ConnectionCounters>> {
            None
        }
    }

    /// Nothing reads rules without a controller, so nothing keeps them.
    #[inline(always)]
    pub fn install_rule_list<R>(_list: R) {}

    #[inline(always)]
    pub fn reset_rule_lists() {}
}

#[cfg(not(feature = "control-connections"))]
#[allow(unused_imports)]
pub use imp::*;

#[cfg(test)]
mod tests {
    use super::*;

    /// A duplex pipe that satisfies `AsyncStream`, which `counted` requires
    /// and `DuplexStream` does not provide (it has no `AsyncPing`).
    struct TestStream(tokio::io::DuplexStream);

    impl AsyncRead for TestStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TestStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }
        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    impl AsyncPing for TestStream {
        fn supports_ping(&self) -> bool {
            false
        }
        fn poll_write_ping(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncStream for TestStream {}

    /// Sync tests around a `block_on` rather than `#[tokio::test]`: the
    /// registry is process-global, so these hold a lock, and a lock guard
    /// has no business crossing an await point.
    #[cfg(feature = "control-connections")]
    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    #[cfg(feature = "control-connections")]
    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    #[cfg(feature = "control-connections")]
    #[test]
    fn bytes_are_counted_at_the_client_edge() {
        let _guard = REGISTRY_TEST_LOCK.blocking_lock();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        block_on(async {
            let (mut peer, near) = tokio::io::duplex(64);
            let handle = register(addr(5001), "socks5@test", Network::Tcp);
            let mut stream = counted(TestStream(near), &handle);

            // Deliberately asymmetric: equal counts would pass either way
            // round, and a transposition is exactly the bug to catch.
            peer.write_all(b"hello").await.unwrap();
            let mut buf = [0u8; 5];
            stream.read_exact(&mut buf).await.unwrap();
            stream.write_all(b"abc").await.unwrap();

            let mine = snapshot()
                .into_iter()
                .find(|c| c.source == addr(5001))
                .expect("our connection is listed");
            assert_eq!((mine.up, mine.down), (5, 3));
        });
    }

    #[cfg(feature = "control-connections")]
    #[test]
    fn late_fields_appear_in_the_snapshot_and_drop_removes_the_entry() {
        let _guard = REGISTRY_TEST_LOCK.blocking_lock();

        let handle = register(addr(5002), "socks5@test", Network::Tcp);
        handle.set_destination(&NetLocation::from_str("example.com:443", None).unwrap());
        handle.set_sniffed_host("example.com");
        let rules: Arc<[RuleSummary]> = Arc::from(vec![
            RuleSummary {
                rule_type: "Match",
                payload: String::new(),
                proxy: "direct".to_string(),
            },
            RuleSummary {
                rule_type: "DomainSuffix",
                payload: "example.com".to_string(),
                proxy: "eu".to_string(),
            },
        ]);
        handle.set_route(Some("eu-1".into()), Some("eu".into()), Some(1), Some(rules));

        let mine = snapshot()
            .into_iter()
            .find(|c| c.source == addr(5002))
            .expect("our connection is listed");
        assert_eq!(mine.destination.as_deref(), Some("example.com:443"));
        assert_eq!(mine.destination_host.as_deref(), Some("example.com"));
        assert_eq!(mine.destination_port, 443);
        assert_eq!(mine.sniffed_host.as_deref(), Some("example.com"));
        assert_eq!(mine.chain.as_deref(), Some("eu-1"));
        assert_eq!(mine.group.as_deref(), Some("eu"));
        assert_eq!(mine.rule, Some(1));
        assert_eq!(
            mine.rule_summary.as_ref().map(|s| s.rule_type),
            Some("DomainSuffix"),
            "the summary is the rule the index points at"
        );

        drop(handle);
        assert!(
            snapshot().iter().all(|c| c.source != addr(5002)),
            "the entry leaves with its handle"
        );
    }

    #[cfg(feature = "control-connections")]
    #[test]
    fn drop_folds_bytes_into_the_process_and_inbound_totals() {
        let _guard = REGISTRY_TEST_LOCK.blocking_lock();

        let label = intern("fold@test".to_string());
        let before = inbound_stats().into_iter().find(|i| i.inbound == label);
        let (before_up, before_down) = before.map(|b| (b.up, b.down)).unwrap_or((0, 0));
        let totals_before = totals();

        let handle = register(addr(5003), label, Network::Tcp);
        let counters = handle.counters().expect("tracked");
        counters.up.fetch_add(10, Ordering::Relaxed);
        counters.down.fetch_add(20, Ordering::Relaxed);

        // Live bytes are in the totals before the connection ends: a
        // dashboard must not see a download flatline until it finishes.
        let during = totals();
        assert_eq!(during.up - totals_before.up, 10);
        assert_eq!(during.down - totals_before.down, 20);

        drop(handle);

        let after = inbound_stats()
            .into_iter()
            .find(|i| i.inbound == label)
            .expect("the listener is counted");
        assert_eq!((after.up - before_up, after.down - before_down), (10, 20));
        assert_eq!(after.active, 0, "the connection is no longer live");
        let totals_after = totals();
        assert_eq!(
            totals_after.up - totals_before.up,
            10,
            "folded once, not twice"
        );
        assert_eq!(totals_after.down - totals_before.down, 20);
    }

    #[cfg(feature = "control-connections")]
    #[test]
    fn close_wakes_the_holder_and_the_entry_leaves_only_on_drop() {
        let _guard = REGISTRY_TEST_LOCK.blocking_lock();

        block_on(async {
            let handle = register(addr(5004), "socks5@test", Network::Tcp);
            let id = snapshot()
                .into_iter()
                .find(|c| c.source == addr(5004))
                .expect("listed")
                .id;

            assert!(close(id), "a live connection can be asked to close");
            tokio::time::timeout(std::time::Duration::from_secs(1), handle.closed())
                .await
                .expect("closed() resolves once close() is called");
            assert!(
                snapshot().iter().any(|c| c.id == id),
                "still listed until the task lets go"
            );

            drop(handle);
            assert!(!close(id), "an unknown id is reported, not invented");
        });
    }

    #[cfg(feature = "control-connections")]
    #[test]
    fn over_the_cap_connections_are_served_but_not_tracked() {
        let _guard = REGISTRY_TEST_LOCK.blocking_lock();

        // Exactly the live count: every further registration is refused,
        // whatever else the process is doing.
        let live = totals().active;
        set_cap(live + 1);

        let tracked = register(addr(5005), "cap@test", Network::Tcp);
        assert!(tracked.counters().is_some());

        let untracked_before = totals().untracked;
        let over = register(addr(5006), "cap@test", Network::Tcp);
        assert!(
            over.counters().is_none(),
            "past the cap a connection is served without an entry"
        );
        assert_eq!(
            totals().untracked,
            untracked_before + 1,
            "the omission is counted, not hidden"
        );

        // It still counts into something, so the call sites do not branch.
        block_on(async {
            use tokio::io::AsyncWriteExt;
            let (_peer, near) = tokio::io::duplex(8);
            let mut stream = counted(TestStream(near), &over);
            stream.write_all(b"x").await.unwrap();
        });

        drop((tracked, over));
        set_cap(4096);
    }

    /// The cap holds under a burst: every thread registers at once, and
    /// exactly `cap` of them are tracked -- not "about", which is what a
    /// read-then-insert gives when the reads all land before the inserts.
    #[cfg(feature = "control-connections")]
    #[test]
    fn the_cap_is_a_hard_bound_under_concurrent_registration() {
        let _guard = REGISTRY_TEST_LOCK.blocking_lock();

        const ROOM: usize = 8;
        const THREADS: usize = 64;
        let live = totals().active;
        set_cap(live + ROOM);

        let gate = Arc::new(std::sync::Barrier::new(THREADS));
        // Every thread spawned before any is joined: a join in the same
        // chain as the spawn would wait on the first thread, which waits on
        // the barrier for the others.
        let threads: Vec<_> = (0..THREADS)
            .map(|i| {
                let gate = gate.clone();
                std::thread::spawn(move || {
                    gate.wait();
                    register(addr(6000 + i as u16), "burst@test", Network::Tcp)
                })
            })
            .collect();
        let handles: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();

        let tracked = handles.iter().filter(|h| h.counters().is_some()).count();
        assert_eq!(tracked, ROOM, "exactly the room the cap left, never more");
        assert_eq!(totals().active, live + ROOM);

        drop(handles);
        assert_eq!(totals().active, live, "every admission was released");
        set_cap(4096);
    }

    /// Without the feature the calls exist, cost nothing, and `closed()`
    /// never resolves -- which is what lets a forwarding task select on it
    /// unconditionally.
    #[cfg(not(feature = "control-connections"))]
    #[tokio::test]
    async fn the_shim_is_inert() {
        let handle = register(SocketAddr::from(([127, 0, 0, 1], 1)), "x", Network::Tcp);
        handle.set_sniffed_host("h");
        handle.set_route::<()>(None, None, Some(0), None);
        assert!(handle.counters().is_none());

        let (_peer, near) = tokio::io::duplex(8);
        // The identity `counted` returns the stream itself, not a wrapper:
        // naming the type is the assertion.
        let _same: TestStream = counted(TestStream(near), &handle);

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), handle.closed())
                .await
                .is_err(),
            "closed() pends forever without a controller"
        );
    }

    #[test]
    fn a_label_is_interned_once() {
        let a = intern("socks5@0.0.0.0:1080".to_string());
        let b = intern("socks5@0.0.0.0:1080".to_string());
        assert!(std::ptr::eq(a, b), "a reload must not leak a second copy");
    }
}
