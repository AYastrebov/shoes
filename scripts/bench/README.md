# Benchmarks

Throughput and latency of the data paths that carry most traffic: the TUN
stack, the UDP tunnels (WireGuard and AmneziaWG, Hysteria2) and the plain
relay. sing-box is the peer for the protocols shoes only speaks as a client,
and the yardstick for the rest.

## Running

Linux is where the numbers mean something. The kernel TUN device, UDP
segmentation offload and receive coalescing exist only there, and it is the
platform a server and a router run. Docker is enough:

```sh
scripts/bench/run-linux.sh build              # release build into a volume
scripts/bench/run-linux.sh tunnels            # tunnels.py: U and D, one stream
scripts/bench/run-linux.sh tunnels MODES=P    # round-trip latency
scripts/bench/run-linux.sh tunnels MODES=S ONLY="-> shoes"   # slow destination
scripts/bench/run-linux.sh tun                # tun_linux.py: a real TUN device
scripts/bench/run-linux.sh tun CASES=idle PERF=1             # with a profile
scripts/bench/run-linux.sh tun SINGBOX=system                 # sing-box's TUN instead
scripts/bench/run-linux.sh tun CASES=verify,named             # integrity, and a device shoes creates
```

`VAR=value` arguments are passed to the script; each script's header lists
them. `PERF=1` needs symbols, so build with
`CARGO_PROFILE_RELEASE_STRIP=false CARGO_PROFILE_RELEASE_DEBUG=line-tables-only`
as arguments to `build`. To compare two builds, copy the first binary aside
inside the `shoes-bench-target` volume and pass `SHOES=/target/<copy>`.

On a macOS host, `tunnels.py` runs directly (it needs `sing-box` and `openssl`
on `PATH`), and `tunbench/` drives the TUN stack over a socketpair, since a
real utun needs root:

```sh
cargo build --release
python3 scripts/bench/tunnels.py
cargo build --release --manifest-path scripts/bench/tunbench/Cargo.toml
python3 scripts/bench/load.py server --port 25201 &
scripts/bench/tunbench/target/release/tunbench target/release/shoes D 5 <lan-ip> 25201 1
```

## What is measured

| Script | Path |
|---|---|
| `tunnels.py` | load tool -> SOCKS5 inbound -> tunnel -> peer -> local sink, over loopback |
| `tun_linux.py` | kernel TCP or UDP in a network namespace -> `tun0` -> shoes -> direct -> local sink |
| `tunbench` | a smoltcp client -> socketpair -> shoes' TUN stack -> direct -> local sink |

`tun_linux.py` is the shape of smoltcp's own `examples/benchmark.rs`, which
reports 7.9 Gbit/s writing and 3.7 reading over a tap device.

Each run prints Gbit/s and CPU-seconds per gigabyte for every process
involved. The second number is the one to trust when the first moves: a path
that is slow and cheap is waiting on something, one that is slow and
expensive is working too hard.

## Reading the numbers

- The Docker Desktop VM is noisy. The same binary has given half and double
  on the multi-connection TUN cases minutes apart. Compare two builds by
  alternating them in one sitting, and repeat anything surprising.
- Another VPN's network extension, active on a macOS host, makes every
  unconnected UDP send about thirty times dearer (87 us against 3 us with
  Tailscale connected). It caps every QUIC run near 100 Mbit/s and says
  nothing about shoes. Disconnect it, or measure on Linux.
- `tun_linux.py` creates its device with `IFF_VNET_HDR`. A build from before
  segmentation offload cannot read that framing and carries nothing: pass
  `VNET=0` to compare against one.
- One stream on loopback has no loss and no delay. These numbers are about
  cost per byte and per packet, not about congestion control on a real path.

## Results, 2026-10-01

Linux arm64 in Docker Desktop on an M2 Max, one stream, the build before the
changes below against the build after, alternated in one sitting.

| Path | Before | After |
|---|---|---|
| WireGuard, one byte each way | 13.6 ms | 0.16 ms |
| Hysteria2 upload to a slow destination | connection dies | holds |
| Hysteria2 upload, shoes to shoes | dies in some runs | 5.3 Gbit/s |
| Hysteria2 + salamander, up / down | 1.8 / 1.9 Gbit/s | 4.3 / 4.6 Gbit/s |
| SOCKS to direct, up / down | 21 / 22 Gbit/s | 33-62 / 49-66 Gbit/s |
| SOCKS to direct, CPU-seconds per gigabyte | 0.39 | 0.10 |
| SOCKS to direct, one byte each way | 69 us | 36 us |
| TUN on Linux, MTU left to the default, up / down | 9.0 / 6.5 Gbit/s | 17.8 / 11.7 Gbit/s |
| One TUN download with 500 idle connections open | 1.0 Gbit/s | 8.1 Gbit/s |
| One TUN upload with 500 idle connections open | 2.4 Gbit/s | 18.6 Gbit/s |
| Eight TUN downloads at once, MTU 1500 | 1.9 Gbit/s | 17.5 Gbit/s |
| One TUN upload, MTU 1500 | 10.0 Gbit/s | 20.9 Gbit/s |
| One TUN download, MTU 1500 | 7.4 Gbit/s | 9.7 Gbit/s |
| TUN UDP upload at 100 Mbit/s offered, loss | 0.5% | 0 |
| TUN UDP upload at 1 Gbit/s offered, loss | 7.7% | 0.12% |

For scale, on the same machine: sing-box WireGuard is 0.2 ms and about
2.2 Gbit/s; sing-box Hysteria2 to itself about 4.5 Gbit/s; sing-box SOCKS to
direct, which splices, 65 to 80 Gbit/s.

What changed:

- **WireGuard and AmneziaWG.** The streams now wake the netstack loop, which
  had been sleeping up to 10 ms on every write, and the loop transmits what
  it has just been handed instead of on its next pass.
- **Hysteria2 upload.** quinn-proto 0.11.19. Through 0.11.17 a stream whose
  reader fell about 2.4 MB behind ended the whole connection.
- **Salamander.** The XOR runs a key-sized block at a time, and the
  obfuscating socket keeps segmentation offload and receive coalescing by
  working on each segment of a batch. The port-hopping socket passes both
  through as well.
- **Relay.** 64 KiB copy buffers off the constrained platforms, up from 16
  (8 behind a TUN connection), which took SOCKS to direct to 37 Gbit/s at
  0.23 CPU-seconds per gigabyte. Then, on Linux, two ends that are each
  nothing more than a TCP socket are spliced inside the kernel
  (`src/splice.rs`), which is where the figures in the table come from.
  sing-box, which also splices, measured 48-62 up and 62-63 down at 0.09 to
  0.11 in the same runs: level, within what this machine can tell apart.
- **TUN.** Linux defaults to an MTU of 9000, as Android already did. UDP
  flow queues hold 512 datagrams off the constrained platforms, up from 64.
- **Idle TUN connections.** smoltcp searches every socket for each packet
  and scans every socket on each poll, so idle connections taxed busy ones.
  A socket quiet for a second is now parked in a second set that is polled
  only for its timers, and comes back when either side does anything.
  sing-box's system stack, for scale, holds 5.4 Gbit/s at any count. Parking
  alone took the 500-idle download from 1.0 to 5.3 Gbit/s.
- **TUN segmentation offload on Linux.** A device opened with
  `IFF_VNET_HDR` passes TCP segments several at a time: the kernel's arrive
  uncut, and the stack joins what smoltcp emits before writing it
  (`src/tun/vnet.rs`). shoes opens its own devices that way and asks a
  descriptor it is handed which kind it is. sing-box, for scale: 5.0 Gbit/s
  for the eight downloads on its system stack, 8.7 on gVisor.

## Known and not fixed

- **A single TUN connection is bounded by its buffer once offload is on.**
  A whole 64 KiB window leaves in one write and is acknowledged once, so the
  connection sends a window and waits. `tcp_buffer_size: 262144` measured
  34 Gbit/s up and 20 down for one stream, against 20 and 9.7 at the default;
  the default stays because it is paid four times per connection. Capping the
  joined packet at a quarter of the window was tried and cost eight
  downloads 40% for nothing measurable on one.
- **UDP download through the TUN loses packets at 1 Gbit/s offered**, between
  0.6% and 9% from run to run, with or without offload.
- **WireGuard throughput is set by the peer in these tests, not by shoes.**
  A download through shoes' client measured 1.8 to 2.0 Gbit/s against 2.1
  to 2.3 through sing-box's, with sing-box's server on the far end using
  over three cores either way. No stage of shoes is near a full core, and
  nothing is dropped: no queue overflows, no kernel UDP errors. Run with
  `SHOES_CLI_ARGS="-t 1"`, the whole client on one thread carries the same
  2 Gbit/s at 3.0 CPU-seconds per gigabyte, against 4.5 to 6.5 on the
  default thread count -- the receive, netstack and send tasks waking each
  other across threads is most of the difference. Folding them into one
  task would save that at the price of one core per tunnel; not done.
