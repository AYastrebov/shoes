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
//! Reports carry the session generation they belong to. A stopped
//! session's tasks outlive it -- the old tokio runtime shuts down on a
//! background thread while the next session is already starting -- and a
//! stale report landing after the new session's [`reset`] must not kill a
//! tunnel it never belonged to. A reporter captures [`generation`] when
//! it starts and the slot refuses a report from any other generation.
//!
//! In the standalone server binary nothing subscribes, so `report` is a
//! logged no-op there: a proxy server with many outbounds must not die
//! because one of them lost a socket.

use std::sync::LazyLock;

use log::{error, info};
use tokio::sync::watch;

/// (session generation, first fatal reason of that session).
static FATAL: LazyLock<watch::Sender<(u64, Option<String>)>> =
    LazyLock::new(|| watch::channel((0, None)).0);

/// The current session generation. A reporter captures this when it
/// starts and passes it back to [`report`], which is what lets the slot
/// tell a live session's death from a stale one's.
pub fn generation() -> u64 {
    FATAL.borrow().0
}

/// Report a condition the engine cannot survive. The first report of a
/// session wins; later ones -- and reports from a session that is no
/// longer the current one -- are logged and dropped, because the host
/// should hear the original cause of *this* session's death, not the
/// echo of a previous one's.
pub fn report(generation: u64, reason: String) {
    let stored = FATAL.send_if_modified(|slot| {
        if slot.0 == generation && slot.1.is_none() {
            slot.1 = Some(reason.clone());
            true
        } else {
            false
        }
    });
    if stored {
        error!("fatal: {reason}");
    } else {
        info!("fatal (stale or already reported, dropped): {reason}");
    }
}

/// Watch for a fatal report. The reason is `None` until one arrives for
/// the current generation.
pub fn subscribe() -> watch::Receiver<(u64, Option<String>)> {
    FATAL.subscribe()
}

/// Start a new session generation with an empty slot, orphaning any
/// report still in flight from the previous one.
pub fn reset() {
    FATAL.send_modify(|slot| {
        slot.0 += 1;
        slot.1 = None;
    });
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
        assert_eq!(rx.borrow().1, None);

        let generation = generation();
        report(generation, "first".to_string());
        report(generation, "second".to_string());
        assert_eq!(rx.borrow().1.as_deref(), Some("first"));

        reset();
        assert_eq!(rx.borrow().1, None);
    }

    /// A report from a session that reset() has already retired must not
    /// land: the old session's tasks outlive it on a background shutdown
    /// thread, and their death is not the new session's death.
    #[test]
    fn a_stale_generations_report_is_dropped() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();

        let stale = generation();
        reset(); // the session `stale` belongs to is over

        report(stale, "old tunnel died".to_string());
        assert_eq!(subscribe().borrow().1, None);

        report(generation(), "new tunnel died".to_string());
        assert_eq!(subscribe().borrow().1.as_deref(), Some("new tunnel died"));

        reset();
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
        report(generation(), "boom".to_string());
        let value = rx.wait_for(|slot| slot.1.is_some()).await.unwrap();
        assert_eq!(value.1.as_deref(), Some("boom"));
        drop(value);

        reset();
    }
}
