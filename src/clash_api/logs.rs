//! The log tee.
//!
//! Logging initialises before the config is read, so whether a controller
//! exists is not yet known when the writer list is fixed. This writer is
//! installed unconditionally and costs one pointer until a controller
//! starts, at which point it allocates its ring -- the same trick
//! `DynamicFileLogWriter` uses for the mobile FFI's log file.
//!
//! See the spec, "Logs".

use std::sync::{Arc, OnceLock};

use crate::control::logs::BroadcastLogWriter;
use crate::logging::LogWriter;

static RING: OnceLock<Arc<BroadcastLogWriter>> = OnceLock::new();

/// A `LogWriter` that writes into the ring once there is one.
pub struct DynamicBroadcastWriter;

impl LogWriter for DynamicBroadcastWriter {
    fn write_log(&self, record: &log::Record, formatted: &str) {
        if let Some(ring) = RING.get() {
            ring.write_log(record, formatted);
        }
    }

    fn flush(&self) {}
}

/// Allocate the ring, once.
///
/// A second call hands back the first ring rather than replacing it: a
/// reload that restarts the controller must not drop the backlog a
/// subscriber is about to ask for.
pub fn install_ring(capacity: usize) -> Arc<BroadcastLogWriter> {
    RING.get_or_init(|| Arc::new(BroadcastLogWriter::new(capacity)))
        .clone()
}

pub fn ring() -> Option<Arc<BroadcastLogWriter>> {
    RING.get().cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ring_is_allocated_once() {
        let first = install_ring(8);
        let second = install_ring(4096);
        assert!(
            Arc::ptr_eq(&first, &second),
            "a restart must not drop the backlog"
        );
        assert!(ring().is_some());
    }
}
