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
//! meant for the receive window. That coupling was removed after raising both
//! to 2 MiB took upload from 49 to 16.6 Mbit/s. The size was blamed on pacing
//! alone, but the real mechanism was the tunnel's outbound channel overflowing
//! under the unpaced burst — the drop the ROADMAP could not place. The
//! netstack's virtual device now backpressures instead of letting the channel
//! drop (see `VirtualDevice::transmit` in src/amneziawg/netstack.rs), so the
//! send window scales cleanly and is sized per platform, apart from the
//! receive window because the two spend memory against different limits.
//!
//! # What a connection costs
//!
//! A connection through both stacks allocates four local buffers in the TUN
//! stack, and two window buffers plus two local buffers in the AmneziaWG
//! stack. Three of those four sizes differ by platform, so the total does too:
//!
//! | | per connection | against [`default_max_connections`] |
//! |---|---|---|
//! | Network Extension (iOS, macOS) | 704 KiB | 176 MiB |
//! | Android | 1.6875 MiB | 432 MiB |
//! | desktop | 5.375 MiB | 5.375 GiB |
//!
//! Those are ceilings on what a connection *allocates*, which is not what it
//! costs resident: the local and send buffers are zero pages the kernel faults
//! in only as they are written. The receive window is the exception, and
//! [`default_remote_rx_window_size`] carries the measured RSS.

/// Whether this build is linked into an Apple Network Extension, where the
/// system kills the process at a memory cap rather than warning it.
///
/// Deliberately not a `target_os` test, because `target_os` cannot answer the
/// question. Every iOS build of this crate is an extension, so iOS answers yes
/// by target. macOS is both: `scripts/build-apple.sh` builds the
/// `aarch64-apple-darwin` slice that `Package.swift` links into
/// `ShoesPacketTunnelProvider`, and the same target builds the desktop binary
/// and any Rust host linking the crate. Only the first is under a cap, and
/// nothing in `target_os` separates them — hence the feature.
///
/// A macOS extension takes the same budget as iOS rather than a looser one
/// because its own budget is unverified: docs/MACOS.md records that the
/// tunnel has not yet run there and that the limit is known only not to be
/// iOS's 50 MB. Inheriting the tightest known extension budget is the
/// conservative reading, and it is the one to revisit once the extension runs
/// and the limit is measured.
const fn in_network_extension() -> bool {
    cfg!(any(target_os = "ios", feature = "network-extension"))
}

/// Bytes of buffering per direction for a buffer that does not span a network
/// round trip: the TUN stack's socket buffers, and both stacks' ring buffers.
pub const fn default_local_buffer_size() -> usize {
    if in_network_extension() || cfg!(target_os = "android") {
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
/// Hence three values rather than two. A Network Extension keeps 256 KiB: an
/// `NEPacketTunnelProvider` is killed rather than warned at roughly 50 MB, and
/// MOBILE.md finding 1 records that kill actually happening. Android is not
/// under that limit — a `VpnService` runs in the app process with an ordinary
/// heap — so it takes 1 MiB, which buys most of the throughput for 0.75 MiB
/// per connection. Desktop takes 4 MiB, where the round trip rather than the
/// memory decides.
///
/// Only a connection that moves bulk data pays the full figure; the window goes
/// resident to the extent bytes flow through it, so a page of small assets does
/// not. Lifting the extension figure needs a *total* window budget rather than
/// a larger per-connection size — see MOBILE.md finding 1.
///
/// # The reassembly ceiling the window does not lift
///
/// `Cargo.toml` pins smoltcp to `assembler-max-segment-count-32`, which is its
/// largest setting: a socket tracks at most 32 discontiguous ranges however
/// wide its window. 4 MiB holds roughly 3000 segments in flight where 256 KiB
/// held 180, so the holes a lossy or reordering path opens scale with the
/// window while the assembler does not. Past 32 holes smoltcp drops the
/// arriving segment and returns without a reply — not even a duplicate ACK —
/// so recovery waits out the RTO rather than a fast retransmit. Every
/// measurement above ran on a clean path, which is where that does not show.
/// ROADMAP.md records the lossy-path measurement that would bound it.
pub const fn default_remote_rx_window_size() -> usize {
    if in_network_extension() {
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
/// This is the ceiling on upload throughput, `window / RTT`, the mirror of the
/// receive window's hold on download: smoltcp never grows it either. At 256 KiB
/// and a 24 ms path it caps upload near 85 Mbit/s, and the number is linear in
/// the window below the path's bandwidth-delay product.
///
/// It was held at 256 KiB after enlarging it was measured to make upload
/// *worse*, and the module documentation blamed the absence of pacing. The
/// real mechanism was narrower: an unpaced smoltcp send dumps the whole window
/// into `ip_to_tunnel` in one poll, and on a fast path that burst overflowed
/// that 256-slot channel — the drop the ROADMAP went looking for in the UDP
/// socket and did not find. The netstack's virtual device now applies
/// backpressure instead (`transmit` refuses tokens while the channel is full,
/// so the burst waits in the socket's own buffer), which removes the drops for
/// any window, any number of concurrent senders, and any configured MTU, and
/// lets the window scale: measured against an AmneziaWG 3.1 peer at 24 ms,
/// single stream, zero drops at every size,
///
/// | window | upload |
/// |---|---|
/// | 256 KiB | 56 Mbit/s |
/// | 512 KiB | 102 Mbit/s |
/// | 768 KiB | 136 Mbit/s |
/// | 1 MiB | 156 Mbit/s |
///
/// So three values, sized against the platform's memory the way the receive
/// window is. A Network Extension keeps 256 KiB — the 50 MB kill limit that
/// pins the receive window pins this one too. Android takes 512 KiB, doubling
/// upload for 0.25 MiB more per connection. Desktop takes 1 MiB, where memory
/// is not the constraint and the round trip is.
///
/// Unlike the receive window, the send buffer is lazy: it goes resident only to
/// the extent an upload fills it, and only a connection sending bulk data does.
pub const fn default_remote_tx_window_size() -> usize {
    if in_network_extension() {
        256 * 1024
    } else if cfg!(target_os = "android") {
        512 * 1024
    } else {
        1024 * 1024
    }
}

/// How many IP packets the tunnel's outbound channel (`ip_to_tunnel`) buffers.
///
/// Not a correctness bound: the netstack's virtual device refuses to emit past
/// the channel's free slots, so nothing overflows at any depth. What this sets
/// is pipelining and shared latency. Deeper keeps the encapsulate task fed
/// across scheduling gaps; shallower bounds how long a DNS query, a SYN, or a
/// competing flow's ACK can sit behind one connection's bulk upload, since
/// every packet through the tunnel crosses this one FIFO. 256 packets is a few
/// hundred kilobytes — milliseconds of standing queue on a fast path — and is
/// the depth every download measurement has been carried on.
pub const fn default_outbound_queue_depth() -> usize {
    256
}

/// How many IP packets the tunnel's inbound channel (`ip_from_tunnel`) buffers.
///
/// The network paces arrivals into this one, so it never sees a window-sized
/// burst the way the outbound side does; it only covers the netstack loop's
/// scheduling jitter. Download saturates the path at this depth.
pub const fn default_inbound_queue_depth() -> usize {
    256
}

/// Connections a virtual TCP stack accepts before it refuses more.
///
/// This is the multiplier on every size above, so it moves with them: a
/// platform on the constrained per-connection budget takes the constrained
/// count too.
pub const fn default_max_connections() -> usize {
    if in_network_extension() || cfg!(target_os = "android") {
        256
    } else {
        1024
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What one connection through both stacks allocates: four local buffers in
    /// the TUN stack, plus two window buffers and two local buffers in the
    /// AmneziaWG stack.
    fn per_connection_bytes() -> usize {
        6 * default_local_buffer_size()
            + default_remote_rx_window_size()
            + default_remote_tx_window_size()
    }

    /// The per-connection and ceiling figures in this module's documentation,
    /// in MOBILE.md and in CONFIG.md are derived from these constants by hand,
    /// and drifted from them once already. Pinning the arithmetic means the
    /// next retune that forgets a document fails here rather than in a
    /// reader's memory budget.
    #[test]
    fn the_documented_per_connection_cost_still_matches_the_constants() {
        let (per_connection, ceiling) = if in_network_extension() {
            (704 * 1024, 176 * 1024 * 1024)
        } else if cfg!(target_os = "android") {
            (1728 * 1024, 432 * 1024 * 1024)
        } else {
            (5504 * 1024, 5504 * 1024 * 1024)
        };

        assert_eq!(per_connection_bytes(), per_connection);
        assert_eq!(
            per_connection_bytes() * default_max_connections(),
            ceiling,
            "the worst-case column in MOBILE.md"
        );
    }

    /// The send window outgrew the outbound channel on purpose — the device's
    /// backpressure, not the channel's depth, is what keeps a window burst from
    /// overflowing. This pins the relationship so a future reader who sees
    /// window >> channel knows it is load-bearing design, not an oversight.
    #[test]
    fn the_send_window_is_allowed_to_exceed_the_outbound_queue() {
        let window_packets = default_remote_tx_window_size() / 1280;
        assert!(
            window_packets > default_outbound_queue_depth() / 2,
            "if the window has shrunk to fit the channel again, the device \
             backpressure in src/amneziawg/netstack.rs may no longer be earning \
             its keep -- re-read this module's history before simplifying either",
        );
    }
}
