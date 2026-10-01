//! Replay detection for Shadowsocks: a salt seen once is refused if it is seen
//! again inside a window. An active prober replays a captured handshake to
//! learn whether the server is Shadowsocks; the reference implementations
//! answer such a replay as garbage, and so must this one.
//!
//! What is stored per salt is a 64-bit fingerprint and the time it was seen,
//! not the salt: the check only ever asks "was this exact salt seen", and a
//! fingerprint collision costs one genuine connection a refusal at odds of
//! entries in 2^64, while a replayed salt fingerprints identically every
//! time. The table is bounded by count as well as by time. A flood inside the
//! window used to grow it without limit, two copies of every salt.

use std::collections::{HashSet, VecDeque};
use std::hash::{BuildHasher, Hasher};
use std::time::Instant;

use rustc_hash::FxBuildHasher;

use super::salt_checker::SaltChecker;

/// Salts remembered at most. Past this the oldest is forgotten early, which
/// narrows the replay window under a flood to the last this-many
/// connections rather than the last `timeout_secs`; shadowsocks-rust's
/// ping-pong Bloom filters make the same trade at a million entries. At
/// about 40 bytes an entry this is under 3 MiB full, which a router or a
/// phone can hold, and normal traffic never fills it.
const MAX_ENTRIES: usize = 65_536;

#[derive(Debug)]
struct TimeEntry {
    instant: Instant,
    fingerprint: u64,
}

#[derive(Debug)]
pub struct TimedSaltChecker {
    /// Oldest first; what `known` holds, in the order it will be forgotten.
    entries: VecDeque<TimeEntry>,
    known: HashSet<u64, FxBuildHasher>,
    timeout_secs: u64,
    max_entries: usize,
}

impl TimedSaltChecker {
    pub fn new(timeout_secs: u64) -> Self {
        Self::with_capacity(timeout_secs, MAX_ENTRIES)
    }

    fn with_capacity(timeout_secs: u64, max_entries: usize) -> Self {
        Self {
            entries: VecDeque::with_capacity(2000),
            known: HashSet::with_capacity_and_hasher(2000, FxBuildHasher),
            timeout_secs,
            max_entries,
        }
    }

    fn fingerprint(salt: &[u8]) -> u64 {
        // Over the whole salt, so a client that fills its salt oddly is
        // still told apart from its neighbours, not only by a prefix.
        let mut hasher = FxBuildHasher.build_hasher();
        hasher.write(salt);
        hasher.finish()
    }

    fn forget_oldest(&mut self) {
        if let Some(oldest) = self.entries.pop_front() {
            self.known.remove(&oldest.fingerprint);
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

impl SaltChecker for TimedSaltChecker {
    fn insert_and_check(&mut self, salt: &[u8]) -> bool {
        while let Some(oldest) = self.entries.front() {
            if oldest.instant.elapsed().as_secs() < self.timeout_secs {
                break;
            }
            self.forget_oldest();
        }

        let fingerprint = Self::fingerprint(salt);
        if self.known.contains(&fingerprint) {
            return false;
        }

        // Bounded by count as well as time: at the cap the oldest goes early.
        while self.entries.len() >= self.max_entries {
            self.forget_oldest();
        }

        self.known.insert(fingerprint);
        self.entries.push_back(TimeEntry {
            instant: Instant::now(),
            fingerprint,
        });
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn salt(i: u32) -> [u8; 32] {
        let mut s = [0u8; 32];
        s[..4].copy_from_slice(&i.to_be_bytes());
        s[4..8].copy_from_slice(&i.wrapping_mul(0x9E37_79B9).to_be_bytes());
        s
    }

    #[test]
    fn a_salt_seen_inside_the_window_is_a_replay() {
        let mut checker = TimedSaltChecker::new(60);
        assert!(checker.insert_and_check(&salt(1)));
        assert!(
            !checker.insert_and_check(&salt(1)),
            "the same salt again is a replay"
        );
        assert!(checker.insert_and_check(&salt(2)), "a different one is not");
    }

    #[test]
    fn a_salt_past_the_window_is_forgotten() {
        // A zero-second window: everything has expired by the next call.
        let mut checker = TimedSaltChecker::new(0);
        assert!(checker.insert_and_check(&salt(1)));
        assert!(checker.insert_and_check(&salt(1)));
    }

    /// A flood inside the window used to grow the table without bound, two
    /// copies of every salt. It is capped, and the cap is a ceiling rather
    /// than a latch: entries keep being accepted, the oldest go early.
    #[test]
    fn a_flood_inside_the_window_stays_under_the_cap() {
        let mut checker = TimedSaltChecker::new(3600);
        for i in 0..(MAX_ENTRIES as u32 * 3) {
            assert!(checker.insert_and_check(&salt(i)));
            assert!(checker.len() <= MAX_ENTRIES);
        }
        assert_eq!(checker.len(), MAX_ENTRIES);
        assert!(
            !checker.insert_and_check(&salt(MAX_ENTRIES as u32 * 3 - 1)),
            "the newest salt is still remembered"
        );
    }

    /// The price of the cap, stated: a salt pushed out early is no longer a
    /// replay. Small capacity so the test reads as the rule, not as a count.
    #[test]
    fn a_salt_pushed_out_by_the_cap_is_no_longer_a_replay() {
        let mut checker = TimedSaltChecker::with_capacity(3600, 3);
        for i in 0..3 {
            assert!(checker.insert_and_check(&salt(i)));
        }
        assert!(
            !checker.insert_and_check(&salt(0)),
            "still inside the table"
        );
        assert!(
            checker.insert_and_check(&salt(3)),
            "the fourth evicts the first"
        );
        assert!(checker.insert_and_check(&salt(0)), "which is now forgotten");
        assert_eq!(checker.len(), 3);
    }
}
