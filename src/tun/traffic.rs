//! Traffic statistics tracking for the TUN server.
//!
//! Provides global atomic byte counters and a callback mechanism for reporting
//! traffic statistics to the host application (iOS/Android) via FFI.

use portable_atomic::AtomicU64;
#[cfg(feature = "control-stats")]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::{Arc, OnceLock};

use parking_lot::RwLock;

/// Cumulative upload bytes (device → proxy).
static UPLOAD_BYTES: AtomicU64 = AtomicU64::new(0);

/// Cumulative download bytes (proxy → device).
static DOWNLOAD_BYTES: AtomicU64 = AtomicU64::new(0);

/// Live TCP connections through the stack.
///
/// Here rather than in `crate::control::stats` because `tcp_stack_direct` is
/// compiled into the binary too, and main.rs has no `control` module. Same
/// reason the byte counters are here.
///
/// Behind the feature, like its call sites: these are `pub` in a `pub mod`, so
/// unconditionally they are exported API that nothing can drop, and a mobile
/// build with the feature off would still carry them. Measured at 720 bytes.
#[cfg(feature = "control-stats")]
static ACTIVE_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

/// Called when the stack accepts a connection.
#[cfg(feature = "control-stats")]
pub fn connection_opened() {
    ACTIVE_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
}

/// Called when the stack cleans one up.
#[cfg(feature = "control-stats")]
pub fn connection_closed() {
    // Saturating rather than wrapping: a close without a matching open would
    // otherwise show a host 18 quintillion live connections.
    let _ = ACTIVE_CONNECTIONS.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
        Some(n.saturating_sub(1))
    });
}

/// Live TCP connections right now.
///
/// Unlike its two writers, which the stack calls from both targets, the only
/// reader is `crate::control::stats` -- and main.rs has no `control`, so a
/// binary build compiles this with nothing to call it.
#[cfg(feature = "control-stats")]
#[allow(dead_code)]
pub fn active_connections() -> usize {
    ACTIVE_CONNECTIONS.load(Ordering::Relaxed)
}

/// Serialises tests that move [`ACTIVE_CONNECTIONS`].
///
/// The counter is process-global and cargo runs tests in parallel, so a test
/// in `control::stats` and one in `tun::tcp_stack_direct` can otherwise
/// interleave and read each other's increments. The lock lives here, next to
/// the state it guards, rather than in either caller.
#[cfg(all(test, feature = "control-stats"))]
pub static COUNTER_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serialises every test that mutates the process-wide traffic counters.
///
/// They assert absolute values, so a reset from another test running at the
/// same moment turns a real assertion into a flake. Anything that calls
/// `reset_traffic_counters` -- including `control::reset_counters`, which a
/// session start goes through -- has to take this first.
///
/// The lock is tokio's rather than std's for two reasons: it can be held
/// across the awaits in the stream tests, and it does not poison, so one
/// failing test reports its own failure instead of turning the others into
/// "poisoned". It lives here, next to the state it guards, rather than in any
/// one caller.
#[cfg(test)]
pub(crate) static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Zero the live-connection count.
///
/// Called when the stack thread exits: whatever it was still holding is gone
/// with it, so the count is zero by definition. Decrementing per surviving
/// socket would reach the same number by a longer route and drift if any path
/// missed one.
#[cfg(feature = "control-stats")]
pub fn reset_active_connections() {
    ACTIVE_CONNECTIONS.store(0, Ordering::Relaxed);
}

/// The values the last report carried, so an idle tunnel can stay quiet.
///
/// `NEVER_REPORTED` rather than zero for the initial state: a tunnel that has
/// just started and carried nothing yet should still report once, so the app
/// can zero its counters from the same source it reads them from.
const NEVER_REPORTED: u64 = u64::MAX;
static LAST_REPORTED_UPLOAD: AtomicU64 = AtomicU64::new(NEVER_REPORTED);
static LAST_REPORTED_DOWNLOAD: AtomicU64 = AtomicU64::new(NEVER_REPORTED);

/// Optional callback invoked with (upload_bytes, download_bytes).
type TrafficCallback = Arc<dyn Fn(u64, u64) + Send + Sync>;
static TRAFFIC_CALLBACK: OnceLock<RwLock<Option<TrafficCallback>>> = OnceLock::new();

/// Add bytes to the upload counter.
pub fn add_upload_bytes(bytes: u64) {
    UPLOAD_BYTES.fetch_add(bytes, Ordering::Relaxed);
}

/// Add bytes to the download counter.
pub fn add_download_bytes(bytes: u64) {
    DOWNLOAD_BYTES.fetch_add(bytes, Ordering::Relaxed);
}

/// Reset traffic counters (called on service start).
/// Called from platform FFI modules (ios.rs / android.rs).
#[allow(dead_code)]
pub fn reset_traffic_counters() {
    UPLOAD_BYTES.store(0, Ordering::Relaxed);
    DOWNLOAD_BYTES.store(0, Ordering::Relaxed);
    LAST_REPORTED_UPLOAD.store(NEVER_REPORTED, Ordering::Relaxed);
    LAST_REPORTED_DOWNLOAD.store(NEVER_REPORTED, Ordering::Relaxed);
}

/// Set the traffic callback function.
/// Called from platform FFI modules (ios.rs / android.rs).
#[allow(dead_code)]
pub fn set_traffic_callback(callback: Arc<dyn Fn(u64, u64) + Send + Sync>) {
    let lock = TRAFFIC_CALLBACK.get_or_init(|| RwLock::new(None));
    *lock.write() = Some(callback);
}

/// Clear the traffic callback.
/// Called from platform FFI modules (ios.rs / android.rs).
#[allow(dead_code)]
pub fn clear_traffic_callback() {
    if let Some(lock) = TRAFFIC_CALLBACK.get() {
        *lock.write() = None;
    }
}

/// Invoke the traffic callback with current counter values.
///
/// A tick where neither counter moved reports nothing. The counters are
/// cumulative, so repeating them tells the app what it already knows — and the
/// call is a crossing into the JVM or into Swift, once a second, on a device
/// that is otherwise trying to sleep.
pub fn report_traffic() {
    let Some(lock) = TRAFFIC_CALLBACK.get() else {
        return;
    };

    let upload = UPLOAD_BYTES.load(Ordering::Relaxed);
    let download = DOWNLOAD_BYTES.load(Ordering::Relaxed);

    let last_upload = LAST_REPORTED_UPLOAD.swap(upload, Ordering::Relaxed);
    let last_download = LAST_REPORTED_DOWNLOAD.swap(download, Ordering::Relaxed);
    if upload == last_upload && download == last_download {
        return;
    }

    let guard = lock.read();
    if let Some(ref cb) = *guard {
        cb(upload, download);
    }
}

// Wrapper around an `AsyncRead + AsyncWrite` stream that counts bytes
// transferred through the traffic counters in real time.
//
// Bytes read from the inner stream are counted as upload (device → proxy).
// Bytes written to the inner stream are counted as download (proxy → device).
//
// This is used instead of post-hoc counting so that long-lived TCP connections
// (large downloads, persistent streams) report traffic incrementally.
/// Where a flow's own byte counters live, when anything is reading them.
///
/// Zero-sized without the registry, so the struct below has the same layout
/// a mobile build has today: this is per TUN flow, and `pin_project_lite`
/// does not accept a `#[cfg]` on a field.
#[cfg(feature = "control-connections")]
type ConnectionTarget = Option<std::sync::Arc<crate::connection_registry::ConnectionCounters>>;
#[cfg(not(feature = "control-connections"))]
type ConnectionTarget = ();

pin_project_lite::pin_project! {
    pub struct TrafficCountingStream<S> {
        #[pin]
        inner: S,
        // A second target: this flow's own entry in the connection
        // registry. See ConnectionTarget above for why it is a type alias
        // rather than a cfg'd field.
        connection: ConnectionTarget,
    }
}

impl<S> TrafficCountingStream<S> {
    /// Count into the process-wide totals only.
    ///
    /// `allow(dead_code)` for the reason this module's accessors give: with
    /// the registry on, the TUN path uses `with_connection` instead, and
    /// which constructor has a caller depends on the build.
    #[allow(dead_code)]
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            connection: Default::default(),
        }
    }

    /// Count into the process-wide totals and into one connection's entry.
    #[cfg(feature = "control-connections")]
    pub fn with_connection(
        inner: S,
        connection: Option<std::sync::Arc<crate::connection_registry::ConnectionCounters>>,
    ) -> Self {
        Self { inner, connection }
    }
}

impl<S: tokio::io::AsyncRead> tokio::io::AsyncRead for TrafficCountingStream<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let this = self.project();
        let result = this.inner.poll_read(cx, buf);
        if let std::task::Poll::Ready(Ok(())) = &result {
            let n = buf.filled().len() - before;
            if n > 0 {
                add_upload_bytes(n as u64);
                #[cfg(feature = "control-connections")]
                if let Some(counters) = this.connection.as_ref() {
                    counters
                        .up
                        .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }
        result
    }
}

impl<S: tokio::io::AsyncWrite> tokio::io::AsyncWrite for TrafficCountingStream<S> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.project();
        let result = this.inner.poll_write(cx, buf);
        if let std::task::Poll::Ready(Ok(n @ 1..)) = &result {
            add_download_bytes(*n as u64);
            #[cfg(feature = "control-connections")]
            if let Some(counters) = this.connection.as_ref() {
                counters
                    .down
                    .fetch_add(*n as u64, std::sync::atomic::Ordering::Relaxed);
            }
        }
        result
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

/// Get current traffic counters.
///
/// Process-global rather than per-service, which is an invariant
/// `crate::control::start` documents: one service per process.
///
/// `allow(dead_code)` for the same reason as its neighbours here: the binary
/// declares its modules in main.rs, which has no `control`, so a binary build
/// compiles this with nothing to call it.
#[allow(dead_code)]
pub fn get_traffic_counters() -> (u64, u64) {
    (
        UPLOAD_BYTES.load(Ordering::Relaxed),
        DOWNLOAD_BYTES.load(Ordering::Relaxed),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use portable_atomic::AtomicU64;

    /// The TUN path counts once, into two places: the process-wide totals a
    /// mobile host reads, and this flow's own entry. A second wrapper would
    /// be a second poll per byte.
    #[cfg(feature = "control-connections")]
    #[tokio::test]
    async fn the_tun_counter_also_feeds_a_connection_entry() {
        use std::sync::atomic::Ordering;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let _guard = TEST_LOCK.lock().await;
        reset_traffic_counters();

        let (mut peer, near) = tokio::io::duplex(64);
        let handle = crate::connection_registry::register(
            "10.0.0.2:4000".parse().unwrap(),
            "tun",
            crate::connection_registry::Network::Tcp,
        );
        let mut stream = TrafficCountingStream::with_connection(near, handle.counters());

        // Asymmetric, so a transposition fails rather than passing.
        peer.write_all(b"12345").await.unwrap();
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await.unwrap();
        stream.write_all(b"ab").await.unwrap();

        let counters = handle.counters().expect("tracked");
        assert_eq!(counters.up.load(Ordering::Relaxed), 5);
        assert_eq!(counters.down.load(Ordering::Relaxed), 2);

        // And the process-wide totals still see the same bytes.
        assert_eq!(get_traffic_counters(), (5, 2));
    }

    #[tokio::test]
    async fn test_add_and_reset_counters() {
        let _guard = TEST_LOCK.lock().await;
        reset_traffic_counters();

        add_upload_bytes(100);
        add_download_bytes(200);
        add_upload_bytes(50);

        let (up, down) = get_traffic_counters();
        assert_eq!(up, 150);
        assert_eq!(down, 200);

        reset_traffic_counters();
        let (up, down) = get_traffic_counters();
        assert_eq!(up, 0);
        assert_eq!(down, 0);
    }

    #[tokio::test]
    async fn test_callback_invoked_with_current_counters() {
        let _guard = TEST_LOCK.lock().await;
        reset_traffic_counters();

        let captured_up = Arc::new(AtomicU64::new(0));
        let captured_down = Arc::new(AtomicU64::new(0));
        let up_clone = captured_up.clone();
        let down_clone = captured_down.clone();

        set_traffic_callback(Arc::new(move |up, down| {
            up_clone.store(up, Ordering::Relaxed);
            down_clone.store(down, Ordering::Relaxed);
        }));

        add_upload_bytes(1000);
        add_download_bytes(2000);
        report_traffic();

        assert_eq!(captured_up.load(Ordering::Relaxed), 1000);
        assert_eq!(captured_down.load(Ordering::Relaxed), 2000);

        clear_traffic_callback();
    }

    #[tokio::test]
    async fn test_clear_callback_stops_reporting() {
        let _guard = TEST_LOCK.lock().await;
        reset_traffic_counters();

        let call_count = Arc::new(AtomicU64::new(0));
        let count_clone = call_count.clone();

        set_traffic_callback(Arc::new(move |_, _| {
            count_clone.fetch_add(1, Ordering::Relaxed);
        }));

        report_traffic();
        assert_eq!(call_count.load(Ordering::Relaxed), 1);

        clear_traffic_callback();
        report_traffic();
        assert_eq!(
            call_count.load(Ordering::Relaxed),
            1,
            "callback should not fire after clear"
        );
    }

    #[tokio::test]
    async fn an_unchanged_tick_reports_nothing() {
        let _guard = TEST_LOCK.lock().await;
        reset_traffic_counters();

        let call_count = Arc::new(AtomicU64::new(0));
        let count_clone = call_count.clone();
        set_traffic_callback(Arc::new(move |_, _| {
            count_clone.fetch_add(1, Ordering::Relaxed);
        }));

        // The first tick always reports, so the app can zero its counters.
        report_traffic();
        assert_eq!(call_count.load(Ordering::Relaxed), 1);

        // An idle second: nothing moved, so nothing crosses the FFI boundary.
        report_traffic();
        report_traffic();
        assert_eq!(
            call_count.load(Ordering::Relaxed),
            1,
            "an idle tunnel should not wake the app once a second"
        );

        add_download_bytes(1);
        report_traffic();
        assert_eq!(
            call_count.load(Ordering::Relaxed),
            2,
            "a byte in either direction should report again"
        );

        clear_traffic_callback();
    }

    #[tokio::test]
    async fn test_counting_stream_reports_bytes() {
        let _guard = TEST_LOCK.lock().await;
        reset_traffic_counters();

        let data = b"hello world";
        let cursor = std::io::Cursor::new(data.to_vec());
        let mut stream = TrafficCountingStream::new(cursor);

        // Read from the stream — counted as upload
        let mut buf = vec![0u8; 32];
        let n = tokio::io::AsyncReadExt::read(&mut stream, &mut buf)
            .await
            .unwrap();
        assert_eq!(n, 11);

        let (up, down) = get_traffic_counters();
        assert_eq!(up, 11, "bytes read should be counted as upload");
        assert_eq!(down, 0, "no writes yet");
    }

    #[tokio::test]
    async fn test_counting_stream_reports_write_bytes() {
        let _guard = TEST_LOCK.lock().await;
        reset_traffic_counters();

        let buf = Vec::new();
        let mut stream = TrafficCountingStream::new(std::io::Cursor::new(buf));

        // Write to the stream — counted as download
        let n = tokio::io::AsyncWriteExt::write(&mut stream, b"response data")
            .await
            .unwrap();
        assert_eq!(n, 13);

        let (up, down) = get_traffic_counters();
        assert_eq!(up, 0, "no reads yet");
        assert_eq!(down, 13, "bytes written should be counted as download");
    }

    #[tokio::test]
    async fn test_report_without_callback_does_not_panic() {
        let _guard = TEST_LOCK.lock().await;
        clear_traffic_callback();
        report_traffic(); // should be a no-op
    }
}
