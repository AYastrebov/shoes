//! Broadcast log sink for the control API's live log panel.
//!
//! `BroadcastLogWriter` is a `LogWriter` that fans formatted log lines out to
//! a global ring buffer (for replay on connect) and a `tokio::sync::broadcast`
//! channel (for live tailing). The channel is process-global (`SHARED`) so
//! multiple SSE subscribers can tail the same stream, and so the writer
//! installed in `main.rs` and the `/api/logs` handler agree on one source.

use std::collections::VecDeque;
use std::sync::LazyLock;

use log::Record;
use parking_lot::Mutex;
use tokio::sync::broadcast;

use crate::logging::LogWriter;

const RING_CAPACITY: usize = 500;

struct Shared {
    ring: Mutex<VecDeque<String>>,
    tx: broadcast::Sender<String>,
}

static SHARED: LazyLock<Shared> = LazyLock::new(|| Shared {
    ring: Mutex::new(VecDeque::with_capacity(RING_CAPACITY)),
    tx: broadcast::channel(1024).0,
});

pub struct BroadcastLogWriter;

impl BroadcastLogWriter {
    pub fn new() -> Self {
        LazyLock::force(&SHARED);
        BroadcastLogWriter
    }
    pub fn emit(&self, line: &str) {
        {
            let mut ring = SHARED.ring.lock();
            if ring.len() == RING_CAPACITY {
                ring.pop_front();
            }
            ring.push_back(line.to_string());
        }
        // Only pay for the broadcast (and its second allocation) when a panel is
        // actually streaming logs; otherwise this is just the ring push above.
        if SHARED.tx.receiver_count() > 0 {
            let _ = SHARED.tx.send(line.to_string());
        }
    }
}

impl Default for BroadcastLogWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl LogWriter for BroadcastLogWriter {
    fn write_log(&self, _record: &Record, formatted: &str) {
        self.emit(formatted);
    }
    fn flush(&self) {}
}

/// Ring-buffer replay plus a live receiver. New SSE clients replay then tail.
pub fn global_log_stream() -> (Vec<String>, broadcast::Receiver<String>) {
    let replay = SHARED.ring.lock().iter().cloned().collect();
    (replay, SHARED.tx.subscribe())
}

/// Test-only helper: returns a `BroadcastLogWriter` bound to the same global
/// `SHARED` state used by `global_log_stream`. Gated to test builds so it is
/// not part of the crate's release public API.
#[cfg(test)]
pub fn install_for_test() -> (BroadcastLogWriter, ()) {
    (BroadcastLogWriter::new(), ())
}

#[cfg(test)]
mod tests {
    #[test]
    fn broadcast_log_writer_delivers() {
        let (writer, _) = super::install_for_test();
        let (replay_before, mut rx) = super::global_log_stream();
        assert!(replay_before.is_empty());
        // Simulate a formatted line.
        writer.emit("[t INFO x] hello");
        let (replay_after, _) = super::global_log_stream();
        assert!(replay_after.iter().any(|l| l.contains("hello")));
        assert!(rx.try_recv().unwrap().contains("hello"));
    }
}
