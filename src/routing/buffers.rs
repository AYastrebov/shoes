//! Packet buffers for the UDP router: one router's pool, and the
//! process-wide spares idle routers park theirs in.

use crate::util::allocate_vec;

use super::udp_router::MAX_UDP_PACKET_SIZE;

/// Packet buffers idle routers have parked, at most, across the process:
/// 2 MiB, a fixed cost whatever the number of clients or worker threads.
pub(super) const SPARE_BUFFERS_MAX: usize = 32;

/// Packet buffers idle routers have given up, for the next router that needs
/// one. A router parks its free buffers each time it goes idle and takes from
/// here before allocating, so routers between datagrams hold none, and a
/// burst allocates only when more buffers are in use at once than this has
/// spare. Process-wide behind a lock, as the TUN read path's pool is, so the
/// shutdown path can empty it from any thread.
pub(super) struct SparePool {
    pub(super) buffers: std::sync::Mutex<Vec<Box<[u8]>>>,
    pub(super) max: usize,
}

impl SparePool {
    pub(super) const fn new(max: usize) -> Self {
        Self {
            buffers: std::sync::Mutex::new(Vec::new()),
            max,
        }
    }

    /// Best effort throughout: a poisoned lock means allocate or free.
    pub(super) fn take(&self) -> Option<Box<[u8]>> {
        self.buffers.lock().ok()?.pop()
    }

    /// Keep what fits, free the rest; `parked` is left empty.
    pub(super) fn give(&self, parked: &mut Vec<Box<[u8]>>) {
        if let Ok(mut buffers) = self.buffers.lock() {
            let keep = parked.len().min(self.max.saturating_sub(buffers.len()));
            buffers.extend(parked.drain(..keep));
        }
        parked.clear();
    }

    pub(super) fn clear(&self) {
        if let Ok(mut buffers) = self.buffers.lock() {
            *buffers = Vec::new();
        }
    }
}

pub(super) static SPARE_BUFFERS: SparePool = SparePool::new(SPARE_BUFFERS_MAX);

/// Free the buffers idle routers parked. For a tunnel's shutdown on mobile,
/// where the process outlives it and every resident page counts.
pub fn clear_spare_buffers() {
    SPARE_BUFFERS.clear();
}

/// A router's packet buffers, for backpressure management.
///
/// Up to `max_count` are held at once: free ones here, the rest queued with
/// a pending write. Acquired buffers are either released immediately (if the
/// write succeeds) or moved into a queue (zero-copy). Free buffers are parked
/// in the process's spares whenever the router goes idle.
pub(super) struct BufferPool {
    pub(super) buffers: Vec<Box<[u8]>>,
    pub(super) max_count: usize,
    /// Free and queued together; free ones leave when parked.
    pub(super) held: usize,
    /// How far into its buffers any read has written since this pool last
    /// held none: what must be zeroed before a buffer leaves for another
    /// router, which may be another client's or another user's.
    pub(super) dirty: usize,
    pub(super) spares: &'static SparePool,
}

impl BufferPool {
    pub(super) fn new(max_count: usize) -> Self {
        Self::with_spares(max_count, &SPARE_BUFFERS)
    }

    pub(super) fn with_spares(max_count: usize, spares: &'static SparePool) -> Self {
        Self {
            buffers: Vec::with_capacity(max_count),
            max_count,
            held: 0,
            dirty: 0,
            spares,
        }
    }

    #[inline]
    pub(super) fn acquire(&mut self) -> Option<Box<[u8]>> {
        // Try to reuse existing buffer
        if let Some(buf) = self.buffers.pop() {
            return Some(buf);
        }

        // Take one an idle router parked, or create one, if under limit
        if self.held < self.max_count {
            self.held += 1;
            Some(
                self.spares
                    .take()
                    .unwrap_or_else(|| allocate_vec(MAX_UDP_PACKET_SIZE).into_boxed_slice()),
            )
        } else {
            None
        }
    }

    #[inline]
    pub(super) fn release(&mut self, buf: Box<[u8]>) {
        self.buffers.push(buf);
    }

    /// Note that a read wrote `len` bytes into one of this pool's buffers.
    #[inline]
    pub(super) fn mark_used(&mut self, len: usize) {
        self.dirty = self.dirty.max(len);
    }

    /// Give the free buffers up, for when the router goes idle or its server
    /// side is gone. Each is zeroed as far as reads have written, since its
    /// next router may serve someone else; that is a datagram's length, not
    /// the buffer's. Buffers still queued are kept, and counted.
    pub(super) fn park(&mut self) {
        if !self.buffers.is_empty() {
            let dirty = self.dirty.min(MAX_UDP_PACKET_SIZE);
            for buf in &mut self.buffers {
                buf[..dirty].fill(0);
            }
            self.held -= self.buffers.len();
            self.spares.give(&mut self.buffers);
        }
        // A queued buffer carries data until it too is parked.
        if self.held == 0 {
            self.dirty = 0;
        }
    }
}
