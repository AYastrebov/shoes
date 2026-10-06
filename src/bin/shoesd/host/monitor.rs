//! The route monitors' shared loop: wait for a change, let the burst settle,
//! report it, and look again a moment later.
//!
//! Every platform delivers the same thing -- a signal that the routing table
//! or an interface moved -- through a different pipe: `PF_ROUTE` on macOS,
//! netlink on Linux, IP Helper notifications on Windows. None of them is
//! parsed. Deciding from a routing delta what changed is where this class of
//! code goes wrong, and it is unnecessary: re-reading the table and comparing
//! gives the same answer and cannot drift. So every event means "look again",
//! the supervisor's handler is idempotent, and the timing around it -- the
//! part that took getting right -- lives here once rather than once per
//! platform.

/// How long to wait after a burst before reporting it.
///
/// A single network change produces a flurry of messages -- the link going
/// down, addresses being removed, the new default arriving -- and re-applying
/// on each would mean re-reading the table a dozen times while it is still
/// settling.
pub const SETTLE: std::time::Duration = std::time::Duration::from_millis(300);

/// And again, a moment later.
///
/// For whatever else on the host puts things back on its own schedule rather
/// than ours: macOS restores its own resolvers asynchronously after a change;
/// on Linux, NetworkManager and `netconfig` rewrite `/etc/resolv.conf` when
/// they choose. A re-apply that runs only once can be undone immediately
/// afterwards with nothing left to notice. Keeping one code path costs a
/// second re-read per change on hosts that do not need it -- cheaper than
/// per-platform monitors.
pub const SECOND_LOOK: std::time::Duration = std::time::Duration::from_secs(2);

/// What one wait on the platform's change source produced.
pub enum Event {
    /// Something moved.
    Changed,
    /// Nothing to report, but the source is still alive -- `ENOBUFS` after a
    /// burst overflowed the socket, `EINTR`. Losing the messages costs
    /// nothing, since none is parsed and the next re-apply re-reads the table.
    ///
    /// Never on Windows: its source is a channel fed by notifications, which
    /// cannot wake without one -- hence the allow there and only there.
    #[cfg_attr(windows, allow(dead_code))]
    Spurious,
    /// The source is gone. Reopening it is the next process's job; losing the
    /// monitor costs re-application on a network change, not the session.
    Ended(String),
}

/// Run the loop on the calling thread until the source ends.
///
/// `next` blocks for the next event. `drain` discards whatever else is queued
/// without blocking, so a burst becomes one re-apply.
pub fn run(mut next: impl FnMut() -> Event, mut drain: impl FnMut(), on_change: impl Fn()) {
    loop {
        match next() {
            Event::Changed => {}
            Event::Spurious => continue,
            Event::Ended(why) => {
                log::error!("the route monitor stopped: {why}");
                return;
            }
        }

        std::thread::sleep(SETTLE);
        drain();
        on_change();

        std::thread::sleep(SECOND_LOOK);
        drain();
        on_change();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// One event is reported twice -- once settled, once on the second look --
    /// and a spurious wake reports nothing.
    #[test]
    fn a_change_is_reported_twice_and_a_spurious_wake_not_at_all() {
        let script = Cell::new(0);
        let reports = AtomicUsize::new(0);
        let drains = Cell::new(0);

        run(
            || {
                script.set(script.get() + 1);
                match script.get() {
                    1 => Event::Spurious,
                    2 => Event::Changed,
                    _ => Event::Ended("done".into()),
                }
            },
            || drains.set(drains.get() + 1),
            || {
                reports.fetch_add(1, Ordering::SeqCst);
            },
        );

        assert_eq!(reports.load(Ordering::SeqCst), 2);
        assert_eq!(drains.get(), 2);
    }
}
