//! How much memory a virtual TCP/IP stack may spend per connection.
//!
//! Two stacks in this crate run smoltcp over a byte pipe and allocate their
//! buffers up front, when a connection is opened rather than when it carries
//! anything: the TUN stack in `src/tun/tcp_stack_direct.rs`, and the AmneziaWG
//! virtual stack in `src/amneziawg/netstack.rs`. On a mobile VPN both are in
//! series — a browser connection is accepted by the first and initiated through
//! the second — so a number chosen in one of them is only half the bill.
//!
//! They do not, however, want the same number, and that difference is the whole
//! reason this module exists.
//!
//! # A local buffer versus a receive window
//!
//! Most of these buffers sit between two halves of this process: the TUN stack
//! faces an application on the same device, and both stacks keep ring buffers
//! between their smoltcp half and their async half. Nothing there spans a
//! network round trip. When such a buffer fills, the reader is a scheduling
//! quantum away, so it only has to cover jitter — a few tens of kilobytes is
//! generous, and more is memory spent on nothing.
//!
//! The AmneziaWG stack's *socket* buffers are a different thing wearing the
//! same shape. That smoltcp socket is the endpoint of a TCP connection whose
//! far end is a server on the internet, reached through the tunnel, so its
//! receive buffer is that connection's receive window and its send buffer holds
//! what is in flight and unacknowledged. Both are bandwidth-delay products, and
//! a window below one caps throughput at `window / RTT` however fast the link.
//!
//! That is not a theoretical distinction. Measured against a real AmneziaWG
//! peer at about 40 ms RTT, 50 MiB per transfer, five rounds each:
//!
//! | socket buffer | throughput | CPU per transfer |
//! |---|---|---|
//! | 256 KiB | 6.2 MB/s | 0.6-1.6 s |
//! | 64 KiB | 2.1 MB/s | 1.1-2.5 s |
//! | 32 KiB | 1.05 MB/s | 1.7-3.6 s |
//!
//! Throughput is linear in the window, which is what a window limit looks like,
//! and the smaller windows cost *more* CPU rather than less, because the same
//! bytes take five times as long to move. So the window keeps its size and the
//! local buffers get cut instead.
//!
//! # The linear region continues above 256 KiB
//!
//! Those measurements only went downward from 256 KiB, so they establish that
//! shrinking the window hurts without establishing that 256 KiB is enough. It
//! is not. Measured against an AmneziaWG 3.1 peer at 26 ms RTT, 50 MiB per
//! transfer, alternating each request with a native `amneziawg-go` tunnel to
//! the same server so that path drift hits both arms equally:
//!
//! | receive window | download | native arm, same run |
//! |---|---|---|
//! | 256 KiB | 47.5 Mbit/s | 156.7 Mbit/s |
//! | 2 MiB | 129.5 Mbit/s | 162.5 Mbit/s |
//! | 8 MiB | 142.7 Mbit/s | 151.4 Mbit/s |
//!
//! At 256 KiB the stack reached 30% of what the same path gave a kernel TCP
//! stack over the same tunnel; the shortfall was the window, not the crypto,
//! which ran at 34% of one core against `amneziawg-go`'s 125-140%. A kernel
//! peer auto-tunes its receive window into the megabytes and smoltcp cannot, so
//! the number it is given up front is the number it keeps.
//!
//! # Why receive and send are sized apart
//!
//! They were one constant, which made the send buffer inherit any increase
//! meant for the receive window. That is not free: raising both to 2 MiB took
//! upload from 49 to 16.6 Mbit/s, because smoltcp does not pace, and a send
//! buffer far larger than the tunnel's queue bursts into drops that Cubic reads
//! as congestion.
//!
//! So only the receive window grows here. The send buffer keeps the size it has
//! been measured at. Upload is *not* known to be well-sized — see
//! ROADMAP.md, which records why the measurement that would settle it does not
//! exist yet.
//!
//! # What a connection costs
//!
//! Through both stacks on mobile: four local buffers in the TUN stack, and two
//! window buffers plus two local buffers in the AmneziaWG stack — 128 KiB plus
//! 576 KiB, about 704 KiB. Against [`default_max_connections`] that is a
//! ceiling near 176 MiB, and roughly a third of that resident, since these are
//! zero pages the kernel faults in only as they are written.

/// Bytes of buffering per direction for a buffer that does not span a network
/// round trip: the TUN stack's socket buffers, and both stacks' ring buffers.
pub const fn default_local_buffer_size() -> usize {
    if cfg!(any(target_os = "ios", target_os = "android")) {
        32 * 1024
    } else {
        64 * 1024
    }
}

/// Bytes of receive window for a connection whose far end is across the
/// internet, reached through the AmneziaWG tunnel.
///
/// This is the ceiling on download throughput: `window / RTT`, since smoltcp
/// holds the size it is constructed with and never auto-tunes. 256 KiB carries
/// about 6 MB/s at 40 ms and about 2.5 MB/s at 100 ms; 4 MiB carries a gigabit
/// at 30 ms and does not become the limit until the round trip is long.
///
/// Unlike the other buffers here, this one is not saved by lazy zero pages: a
/// sustained transfer wraps smoltcp's ring across the whole buffer, so the
/// window goes fully resident. Measured at 26 ms RTT with 16 concurrent
/// downloads, against an idle baseline of 13 MiB:
///
/// | window | download | RSS per connection | RSS at 16 |
/// |---|---|---|---|
/// | 256 KiB | 52.0 Mbit/s | 1.08 MiB | 30 MiB |
/// | 1 MiB | 136.3 Mbit/s | 1.83 MiB | 42 MiB |
/// | 4 MiB | ~154 Mbit/s | 4.99 MiB | 91 MiB |
///
/// Hence three values rather than two. iOS keeps 256 KiB: an
/// `NEPacketTunnelProvider` is killed rather than warned at roughly 50 MB, and
/// MOBILE.md finding 1 records that kill actually happening. Android is not
/// under that limit — a `VpnService` runs in the app process with an ordinary
/// heap — so it takes 1 MiB, which buys most of the throughput for 0.75 MiB
/// per connection. Desktop takes 4 MiB, where the round trip rather than the
/// memory decides.
///
/// Only a connection that moves bulk data pays the full figure; the window goes
/// resident to the extent bytes flow through it, so a page of small assets does
/// not. Lifting iOS needs a *total* window budget rather than a larger
/// per-connection size — see MOBILE.md finding 1.
pub const fn default_remote_rx_window_size() -> usize {
    if cfg!(target_os = "ios") {
        256 * 1024
    } else if cfg!(target_os = "android") {
        1024 * 1024
    } else {
        4096 * 1024
    }
}

/// Bytes of unacknowledged send data for a connection whose far end is across
/// the internet.
///
/// Deliberately not raised alongside the receive window: smoltcp does not pace
/// its sends, so a send buffer much larger than the tunnel's queue converts
/// into drops rather than throughput. See the module documentation.
pub const fn default_remote_tx_window_size() -> usize {
    256 * 1024
}

/// Connections a virtual TCP stack accepts before it refuses more.
pub const fn default_max_connections() -> usize {
    if cfg!(any(target_os = "ios", target_os = "android")) {
        256
    } else {
        1024
    }
}
