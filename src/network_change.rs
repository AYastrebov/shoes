//! Telling the tunnels that the device's network moved.
//!
//! The mobile FFI's `shoes_network_changed` (and its JNI twin) lands here,
//! from an Android `ConnectivityManager.NetworkCallback` or an iOS
//! `NWPathMonitor`. Each tunnel decides what a change means for it: an
//! AmneziaWG endpoint rebinds its UDP socket and keeps its flows, an SSTP
//! session cannot outlive the TCP connection it rode on and ends at once.

#[cfg(test)]
use std::sync::Arc;
use std::sync::{Mutex, Weak};

use log::info;

/// Something that holds a connection the network can pull out from under it.
pub trait NetworkChangeListener: Send + Sync {
    /// Called on the notifying thread, which may be a platform callback
    /// thread: wake a task, do no I/O here.
    fn network_changed(&self);
}

/// A set of listeners. One is the process's; a test makes its own, because
/// tests run as threads of one process and a notification to the process's
/// registry would reach every other test's tunnels.
pub struct Registry {
    /// Weak, because the registry must not be what keeps a tunnel alive;
    /// dead entries are swept on registration and notification.
    listeners: Mutex<Vec<Weak<dyn NetworkChangeListener>>>,
}

static PROCESS: Registry = Registry::new();

impl Registry {
    pub const fn new() -> Self {
        Registry {
            listeners: Mutex::new(Vec::new()),
        }
    }

    /// Add a listener for as long as it lives.
    pub fn register(&self, listener: Weak<dyn NetworkChangeListener>) {
        let mut listeners = self.listeners.lock().unwrap_or_else(|e| e.into_inner());
        // Swept here as well as on notification, so a process that starts
        // many tunnels and never changes network does not accumulate dead
        // entries.
        listeners.retain(|weak| weak.strong_count() > 0);
        listeners.push(listener);
    }

    /// Tell every live listener that the network moved; how many there were.
    pub fn notify(&self) -> usize {
        let mut listeners = self.listeners.lock().unwrap_or_else(|e| e.into_inner());
        listeners.retain(|weak| weak.strong_count() > 0);
        for listener in listeners.iter() {
            if let Some(listener) = listener.upgrade() {
                listener.network_changed();
            }
        }
        listeners.len()
    }

    /// Whether `listener` is registered here.
    #[cfg(test)]
    pub fn is_registered(&self, listener: &Arc<dyn NetworkChangeListener>) -> bool {
        let target = Arc::downgrade(listener);
        self.listeners
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .any(|weak| weak.ptr_eq(&target))
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

/// Add a listener to the process's registry for as long as it lives.
pub fn register(listener: Weak<dyn NetworkChangeListener>) {
    PROCESS.register(listener);
}

/// Tell every live tunnel in the process that the network moved.
///
/// Safe to call from any thread at any time, including when no tunnel is
/// running: it takes an uncontended lock and does no I/O itself. Returns the
/// number of listeners notified.
// Called from the mobile FFI, which the desktop binary does not compile.
#[allow(dead_code)]
pub fn notify() -> usize {
    let count = PROCESS.notify();
    info!("network change: notified {count} tunnel(s)");
    count
}

/// Whether `listener` is in the process's registry: a test's way to check
/// that a tunnel registered itself without notifying everything else.
#[cfg(test)]
pub fn is_registered(listener: &Arc<dyn NetworkChangeListener>) -> bool {
    PROCESS.is_registered(listener)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Counter(Arc<AtomicUsize>);

    impl NetworkChangeListener for Counter {
        fn network_changed(&self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn listener(count: &Arc<AtomicUsize>) -> Arc<dyn NetworkChangeListener> {
        Arc::new(Counter(count.clone()))
    }

    /// On a registry of its own: the process's would end every SSTP
    /// session another test has up at that moment.
    #[test]
    fn a_change_reaches_a_live_listener_and_not_a_dropped_one() {
        let registry = Registry::new();
        let (live_count, dropped_count) = (Arc::default(), Arc::default());
        let live = listener(&live_count);
        let dropped = listener(&dropped_count);
        registry.register(Arc::downgrade(&live));
        registry.register(Arc::downgrade(&dropped));
        assert!(registry.is_registered(&live));
        drop(dropped);

        assert_eq!(registry.notify(), 1, "the dropped listener was swept");
        assert_eq!(live_count.load(Ordering::SeqCst), 1);
        assert_eq!(dropped_count.load(Ordering::SeqCst), 0);
    }
}
