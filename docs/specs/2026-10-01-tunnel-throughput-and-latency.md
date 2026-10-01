# Tunnel throughput and latency: the first pass

Seven changes from a performance audit of the TUN stack, the UDP tunnels and
the plain relay, and the benchmark kit that measured them. Written 2026-10-01
against `mobile` at `6551b78`, after the fact: the changes landed as one PR
(#33) with the measurements in `scripts/bench/README.md`, and this document
records the design decisions the README does not.

## Table of Contents

- [Problem](#problem)
- [Method](#method)
- [Two defects](#two-defects)
- [Throughput](#throughput)
- [Defaults that change](#defaults-that-change)
- [Error handling](#error-handling)
- [Testing](#testing)
- [Deliberately out of scope](#deliberately-out-of-scope)

## Problem

Measured on Linux against sing-box 1.14.2 as peer and yardstick, shoes was
behind on every data path that carries most traffic, and two of the gaps were
defects rather than slowness:

| Path | shoes | sing-box |
| --- | --- | --- |
| WireGuard, one byte each way | 13.6 ms | 0.2 ms |
| Hysteria2 upload to a slow destination | connection dies | holds |
| Hysteria2 + salamander, up / down | 1.8 / 1.9 Gbit/s | about 4.5 (unobfuscated) |
| SOCKS to direct | 21 / 22 Gbit/s | 65 to 80 Gbit/s |
| TUN UDP upload, 1 Gbit/s offered, loss | 7.7% | — |

## Method

`scripts/bench/` (added in the same PR) runs every case on Linux in Docker,
where the kernel TUN device, UDP segmentation offload and receive coalescing
exist. Each run reports Gbit/s and CPU-seconds per gigabyte for every process
involved; the second number distinguishes a path that waits from one that
works too hard. Every change below was measured before and after, alternating
the two builds in one sitting, because the Docker Desktop VM varies by a
factor of two between runs minutes apart. The README lists the distortions.

A change that measured no gain was not kept. One such: a cheaper sweep over
idle TUN sockets on our side of smoltcp.

## Two defects

**WireGuard and AmneziaWG added up to 10 ms to every write**
(`src/amneziawg/netstack.rs`). Each stream called `notify_waiters` on a
`Notify` of its own that nothing awaited, so a write sat until the netstack
loop's sleep ran out. The stack now owns one `Notify`, rung with `notify_one`
so a ring that lands while the loop is polling is stored rather than lost,
and the loop's select has an arm for it. UDP datagrams ring it as well. After
servicing the sockets the loop polls and flushes again, so what a stream has
just handed over leaves on this pass. It also takes up to 64 inbound packets
per pass instead of one, since every pass walks every socket.

**A Hysteria2 upload to a slow destination ended the QUIC connection** with
"too many gaps in stream buffer", with no packet loss. Once a stream's reader
fell about 2.4 MB behind, quinn-proto through 0.11.17 counted buffered
full-size chunks against a limit of 1024 without merging them; 0.11.18 merges
them. The lockfile moves to 0.11.19 and `Cargo.toml` names `quinn-proto` with
a `0.11.18` floor, although nothing uses it directly, so a later resolution
cannot go back under it. It reproduced from a sing-box client too, which is
what placed it in quinn rather than in our server.

## Throughput

**Salamander** (`src/quic_transport/obfs/`). The XOR was a byte loop with a
modulo in it, three to four times the cost of the AES-GCM over the same
packets. It now runs a key-sized block at a time. The constants and the
keystream are unchanged; the test checks the block loop against the byte
definition at every length around the block boundaries.

The obfuscating socket reported segmentation offload and receive coalescing
as unavailable, so every packet was its own system call. It now obfuscates
each segment of a batch on its own. The segments stay one size, larger by the
salt, which is what the kernel needs to cut them apart again. It decodes each
datagram of a coalesced read the same way and compacts the survivors. The
receive half was also a correctness problem: quinn's socket underneath asks
the kernel to coalesce whatever the wrapper reports, so a coalesced buffer
arrived regardless and was dropped whole. The port-hopping socket
(`src/quic_transport/hop.rs`) had the same two answers and now passes both
through. Every socket its factory makes is the same kind, so the answer holds
across a hop.

**Relay** (`src/buffer_sizing.rs`). `default_relay_buffer_size` is 64 KiB off
the constrained platforms, up from 16. The buffer is the unit of work per
pair of system calls, so it is the lever on a relay between two kernel
sockets: 37 Gbit/s at 0.23 CPU-s/GB against 21 at 0.4. The relay behind a TUN
connection used tokio's default 8 KiB, and each write into the stack's ring
wakes the stack thread; `default_tun_relay_buffer_size` gives it 64 KiB too.

**TUN UDP queues** (`src/tun/udp_manager.rs`). The stack thread reads the
device in batches of 64 and hands each over without waiting, and both queues
a flow crosses on its way out held 64, so one batch the receiving task had
not yet been scheduled to drain filled them. `default_udp_flow_queue_depth`
is 512 off the constrained platforms. A full queue still drops, as a full
socket buffer would.

## Defaults that change

- **A Linux TUN that leaves `mtu` unset gets 9000, not 1500.** Every packet
  through the device is one system call each way, and the inbound one runs
  the kernel's TCP receive path inline, so the stack thread's throughput
  follows the packet size: 9.0 / 6.5 Gbit/s at 1500 against 17.8 / 11.7 at
  9000. The MTU only covers the hop between the kernel and shoes, because the
  stack terminates connections; the link behind the proxy keeps its own.
  Android already defaulted to 9000. `CONFIG.md`, `default_mtu` and
  `TunServerConfig::default` all carry the per-platform list. Other desktop
  platforms stay at 1500 because nobody has measured them.
- **The constrained platforms keep every size they had.** On iOS, a macOS
  network extension and Android the buffers are held per connection for its
  whole life, and the connection count is what the memory budget is spent
  on. `buffer_sizing` is the one place these are decided.

## Error handling

- A segmented transmit through the hopping socket goes to the socket's
  current destination as one batch, so every segment shares one destination
  by construction. A send error is the underlying socket's, unchanged.
- In a coalesced read, a datagram that does not decode is dropped and the
  rest are kept. A buffer that is wholly garbage yields nothing, not an
  error, as a single garbage datagram already did.
- A UDP flow queue that is full drops the datagram rather than blocking the
  stack thread.

## Testing

- The netstack wake: a stream's write, shutdown and drop each leave a wake
  the loop will see, and a written datagram leaves the stack with a median
  under 3 ms over 41 samples taken from a sleeping loop. Without the wake
  arm that median was 9.2 ms.
- The block XOR against the byte-at-a-time definition at every length
  around the block boundary.
- Segmented send and coalesced receive through the obfuscating socket, and
  through the hopping socket; the batch decoder with partly and wholly
  garbage buffers. The hopping test fails if `segment_size` is dropped on
  the way down. The segmented tests return early where the platform has no
  segmentation offload, since quinn never hands such a socket a batch.
- The config defaults test expects the platform's MTU.
- Interop with a sing-box Hysteria2 peer, with and without salamander, in
  both directions, through `scripts/bench/tunnels.py`.

## Deliberately out of scope

These are recorded in `scripts/bench/README.md` under "Known and not fixed"
with the measurements behind them.

- **Idle TUN connections slowing busy ones.** The cost is in smoltcp's
  per-poll scan of every socket, and fixing it changes the stack loop. That
  is PR #34.
- **One system call per TUN packet.** A larger MTU is the lever available
  without the virtio header. Segmentation offload is PR #35.
- **Kernel splice for the relay.** That is PR #36.
- **WireGuard throughput**, which is level with sing-box at half the CPU and
  bounded by one task and one lock around the cipher state.
- **MTU defaults on macOS and Windows**, unmeasured.
