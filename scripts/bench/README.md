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
| SOCKS to direct, up / down | 21 / 22 Gbit/s | 37 / 37 Gbit/s |
| TUN on Linux, MTU left to the default, up / down | 9.0 / 6.5 Gbit/s | 17.8 / 11.7 Gbit/s |
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
  (8 behind a TUN connection).
- **TUN.** Linux defaults to an MTU of 9000, as Android already did. UDP
  flow queues hold 512 datagrams off the constrained platforms, up from 64.

## Known and not fixed

- **The TUN stack's cost grows with open connections.** With 500 idle
  connections one busy download falls from 6.6 to 1.0 Gbit/s. The profile
  puts it inside smoltcp: its per-packet search for the socket a segment
  belongs to, and its scan of every socket on every poll for something to
  send. A cheaper sweep on our side measured no gain and was not kept. The
  fix is to keep idle sockets out of the set that is polled, which is a
  change to the stack loop of its own.
- **One system call per packet through the TUN.** The profile shows the stack
  thread inside `write`, which runs the kernel's TCP receive path inline.
  A larger MTU is the lever that exists today; Linux `IFF_VNET_HDR` with
  segmentation offload is the one that does not yet.
- **Eight downloads through the TUN at once** carry about 2 to 3 Gbit/s
  together against 6.6 for one, for the same reason.
- **The relay is still half of sing-box's**, which splices between sockets
  in the kernel on Linux.
- **WireGuard throughput** is level with sing-box's at half the CPU, and
  bounded by one task and one lock around the cipher state.
