//! A process-global "the engine must die" signal.
//!
//! The AmneziaWG tunnel is created lazily deep inside a connector chain
//! (`src/amneziawg/connector.rs`), far from any handle to the service task
//! whose end the host observes. When its receive path is unrecoverable,
//! the engine must stop rather than report healthy over a tunnel that
//! cannot hear its peer -- and the only route from there to
//! `control::run_prepared` is a process-global, the same pattern as the
//! endpoint registry and the traffic counters, resting on the documented
//! one-service-per-process invariant (`src/control/mod.rs`).
//!
//! In the standalone server binary nothing subscribes, so `report` is a
//! logged no-op there: a proxy server with many outbounds must not die
//! because one of them lost a socket.

use std::sync::LazyLock;

use log::{error, info};
use tokio::sync::watch;

static FATAL: LazyLock<watch::Sender<Option<String>>> = LazyLock::new(|| watch::channel(None).0);

/// Report a condition the engine cannot survive. The first report of a
/// session wins; later ones are logged and dropped, because the host
/// should hear the original cause, not the loudest consequence.
pub fn report(reason: String) {
    let stored = FATAL.send_if_modified(|slot| {
        if slot.is_none() {
            *slot = Some(reason.clone());
            true
        } else {
            false
        }
    });
    if stored {
        error!("fatal: {reason}");
    } else {
        info!("fatal (already reported, dropped): {reason}");
    }
}

/// Watch for a fatal report. The value is `None` until one arrives.
pub fn subscribe() -> watch::Receiver<Option<String>> {
    FATAL.subscribe()
}

/// Clear the slot. Called at the start of each service session, so a
/// reason from a previous session cannot stop the next one.
pub fn reset() {
    FATAL.send_replace(None);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The channel is process-global; tests that touch it must not
    /// interleave, the same rule as `outbound_stats::REGISTRY_TEST_LOCK`.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn the_first_reason_wins_and_reset_clears_it() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();

        let rx = subscribe();
        assert_eq!(*rx.borrow(), None);

        report("first".to_string());
        report("second".to_string());
        assert_eq!(rx.borrow().as_deref(), Some("first"));

        reset();
        assert_eq!(*rx.borrow(), None);
    }

    // The guard is held across the await on purpose. `#[tokio::test]` runs
    // a current-thread runtime, so there is no other task on this thread to
    // starve, and the lock exists precisely to stop these tests
    // interleaving on the process-global channel -- the same pattern as
    // control's outbound_install_tests.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn a_subscriber_is_woken_by_a_report() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();

        let mut rx = subscribe();
        report("boom".to_string());
        let value = rx.wait_for(|slot| slot.is_some()).await.unwrap();
        assert_eq!(value.as_deref(), Some("boom"));
        drop(value);

        reset();
    }
}
