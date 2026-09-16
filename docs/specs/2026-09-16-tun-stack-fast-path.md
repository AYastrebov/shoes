# TUN stack fast path: batched ingress and a real wakeup

Two changes to the shared smoltcp loop in `src/tun/`, taken from sing-tun's
1.15 userspace stack, chosen because they are the highest-value parts that
port cleanly onto smoltcp. Written 2026-09-16 against `mobile` at `a85cda6`.

## Table of Contents

- [Problem](#problem)
- [What sing-box 1.15 did](#what-sing-box-115-did)
- [What this ports, and what it does not](#what-this-ports-and-what-it-does-not)
- [Change 1: one poll per read batch](#change-1-one-poll-per-read-batch)
- [Change 2: a wakeup the stack thread can actually receive](#change-2-a-wakeup-the-stack-thread-can-actually-receive)
- [Correctness of the notifier](#correctness-of-the-notifier)
- [Testing](#testing)
- [Deliberately out of scope](#deliberately-out-of-scope)

## Problem

The TUN stack runs one smoltcp interface on a dedicated OS thread, reading IP
packets from the device and bridging TCP to the async side through ring
buffers. Two things in that loop were doing avoidable work.

**It polled smoltcp once per packet.** The read side collected a batch of up
to `MAX_PACKET_BATCH` packets, then handed them to smoltcp one at a time, with
a full `Interface::poll` — which runs an egress sweep over every socket —
after each one. With a page load's worth of connections open, that egress
sweep, repeated per ingress packet, was most of what the thread did.

**Nothing off the thread could wake it.** The thread sleeps in the platform
wait (`poll()` on Unix, `WaitForMultipleObjects` on Windows). The TCP side
reached for `Thread::unpark` to signal a segment written by tokio, a receive
buffer drained by tokio, or a dropped connection — but the thread never calls
`thread::park`, so `unpark` only sets a flag nothing reads. Those events
therefore waited for the next packet from the device or for the loop's timer
tick, which was capped at 10 ms precisely so the wait could not sit on them.
That cap cost a wakeup every 10 ms for as long as any socket was open, on a
phone with the screen off as much as anywhere. Only the UDP-response path had
a real wake (a byte down a pipe, an event set); TCP did not use it.

## What sing-box 1.15 did

sing-tun replaced gVisor with its own single-threaded engine per TUN queue.
Two of its ideas are independent of that rewrite:

- `processBurst` reads up to a batch off the device, feeds the whole batch to
  the stack, then flushes once (`stack_go_engine.go`).
- The engine parks in `epoll`/`kqueue`/AFD and is woken by a lock-free
  message push that writes an eventfd **only while the engine is parked**
  (`postMessage` and `park` in `stack_go_engine.go`).

## What this ports, and what it does not

Ported, because they fit smoltcp with no rewrite: batched ingress, and the
park/wake handshake. **Not** ported: the segmentation offload (`IFF_VNET_HDR`
+ TSO/GRO), multi-queue, and the direct-socket splice. smoltcp cannot emit or
accept super-segments, runs one interface, and always terminates the
connection itself, so those three need a stack smoltcp is not. They are noted
in ROADMAP as the remaining, larger, wins.

## Change 1: one poll per read batch

`StackDevice::store_packet` now queues into a `VecDeque` instead of holding a
single slot, and the loop hands smoltcp the whole batch before a single
`iface.poll`. `Interface::poll` drains everything `receive` offers before it
runs egress, so a batch of N packets is one egress sweep, not N, and the ACKs
and window updates the batch produces go out together. Both backend devices
(`FdDevice`, `WintunDevice`) and the test double hold the queue; the loop's
per-iteration `tcp_packets`/`sockets_to_remove` vectors are reused rather than
reallocated.

## Change 2: a wakeup the stack thread can actually receive

A `StackNotifier` wraps each backend's existing wake primitive — the Unix
wake-pipe write, the Windows `SetEvent` — which the device's `wait` already
selects on. Everything off the thread (a written segment, a drained receive
buffer, a dropped connection, a queued UDP response, a channel being wired,
shutdown) now goes through `notify()` instead of `unpark`. With a real wake in
hand, the loop's wait is no longer capped at 10 ms: it sleeps until smoltcp's
own next deadline (`poll_delay`) or until `notify` fires. An idle tunnel with
open connections now sleeps for seconds, not 10 ms at a time.

## Correctness of the notifier

`notify` sets `pending` then, if `armed`, fires the wake. The stack thread
calls `arm` just before sleeping: it sets `armed` and, if `pending` was
already set, declines to sleep. Both flags are `SeqCst`. The no-lost-wakeup
argument is Dekker's: of `notify`'s `pending` store and the thread's `armed`
store, a single total order makes one visible to the other side's load, so
either `notify` fires the wake or `arm` declines to sleep. A burst of
`notify`s costs one wake, because only the caller that swaps `armed` from true
fires it. `disarm` clears both flags on the way out of the wait, since the
iteration that follows covers whatever any `notify` was signalling; a wake
that raced in becomes at worst one spurious, harmless extra iteration.

## Testing

- `stored_packets_are_queued_and_drained_in_order` pins the batch contract:
  three stored packets all come back through `Device::receive`, in order.
  Reverting `store_packet` to a single slot fails it with `[3]` for
  `[1, 2, 3]` — the regression it guards.
- `every_syn_in_a_burst_becomes_a_connection` drives eight SYNs through the
  real loop and asserts eight connections; none dropped on the batched path.
- `notify_before_arm_makes_arm_decline_to_sleep` and
  `notify_while_armed_wakes_once` cover the two notifier orderings and the
  burst-coalescing.
- The existing loop tests (SYN handshake, UDP forward and response, prompt
  wake, shutdown, device death, connection-count reset) are unchanged and
  green, on the platform-neutral scripted device so Windows is covered too.
- Live: shoes on a real Linux TUN in a user namespace, a direct outbound
  bound to a veth toward an echo server in a second namespace. A small
  round-trip and a 1 MiB full-duplex transfer complete, and the stack starts
  and stops cleanly.
- The Windows backend was not compiled here (no mingw cross toolchain in the
  dev environment); its edits mirror the Unix backend's exactly.

## Deliberately out of scope

- `IFF_VNET_HDR` with TSO/GRO, multi-queue, and direct-socket splice — each
  needs a stack smoltcp is not. See ROADMAP.
- Congestion control and buffer sizing are unchanged; this is loop structure,
  not the TCP state machine.
