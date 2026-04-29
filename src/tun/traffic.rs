//! Traffic statistics tracking for the TUN server.
//!
//! Provides global atomic byte counters and a callback mechanism for reporting
//! traffic statistics to the host application (iOS/Android) via FFI.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};

/// Cumulative upload bytes (device → proxy).
static UPLOAD_BYTES: AtomicU64 = AtomicU64::new(0);

/// Cumulative download bytes (proxy → device).
static DOWNLOAD_BYTES: AtomicU64 = AtomicU64::new(0);

/// Optional callback invoked with (upload_bytes, download_bytes).
static TRAFFIC_CALLBACK: OnceLock<RwLock<Option<Arc<dyn Fn(u64, u64) + Send + Sync>>>> =
    OnceLock::new();

/// Add bytes to the upload counter.
pub fn add_upload_bytes(bytes: u64) {
    UPLOAD_BYTES.fetch_add(bytes, Ordering::Relaxed);
}

/// Add bytes to the download counter.
pub fn add_download_bytes(bytes: u64) {
    DOWNLOAD_BYTES.fetch_add(bytes, Ordering::Relaxed);
}

/// Reset traffic counters (called on service start).
pub fn reset_traffic_counters() {
    UPLOAD_BYTES.store(0, Ordering::Relaxed);
    DOWNLOAD_BYTES.store(0, Ordering::Relaxed);
}

/// Set the traffic callback function.
pub fn set_traffic_callback(callback: Arc<dyn Fn(u64, u64) + Send + Sync>) {
    let lock = TRAFFIC_CALLBACK.get_or_init(|| RwLock::new(None));
    *lock.write().unwrap() = Some(callback);
}

/// Clear the traffic callback.
pub fn clear_traffic_callback() {
    if let Some(lock) = TRAFFIC_CALLBACK.get() {
        *lock.write().unwrap() = None;
    }
}

/// Invoke the traffic callback with current counter values.
pub fn report_traffic() {
    if let Some(lock) = TRAFFIC_CALLBACK.get() {
        if let Ok(guard) = lock.read() {
            if let Some(ref cb) = *guard {
                let upload = UPLOAD_BYTES.load(Ordering::Relaxed);
                let download = DOWNLOAD_BYTES.load(Ordering::Relaxed);
                cb(upload, download);
            }
        }
    }
}

/// Get current traffic counters.
pub fn get_traffic_counters() -> (u64, u64) {
    (
        UPLOAD_BYTES.load(Ordering::Relaxed),
        DOWNLOAD_BYTES.load(Ordering::Relaxed),
    )
}
