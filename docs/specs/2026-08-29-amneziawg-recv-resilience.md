# The AmneziaWG receive path survives errors, and its death stops the engine

Written 2026-08-29 against `mobile` at `7a5a3c1` (0.2.16), in answer to
KVN's field report (`docs/shoes-upstream-issues.md` in the KVN repo): a
Pixel 10 tunnel died six seconds after connect on `EMSGSIZE` (os error 90)
and the engine reported healthy for nine more minutes while deaf.

## Why

Three findings from the incident, in code terms:

1. **One recv error kills inbound forever.** `decapsulate_loop`
   (`src/amneziawg/tunnel.rs:192-210`) breaks on any recv error other than
   `ECONNREFUSED`/`ECONNRESET`. The error observed was `EMSGSIZE` — which
   on a connected UDP socket is not "the inbound datagram overflowed our
   buffer" (the buffer is 65536 bytes, and Linux silently truncates
   oversized inbound UDP anyway). Per `udp(7)` it is a *deferred send-path
   error*: an ICMP Fragmentation Needed for a datagram we sent, latched on
   the socket and delivered by the next syscall, which is the parked
   `recv`. The likely producer is AmneziaWG 3.1 random trailers, whose
   size is drawn from a high-water mark of datagrams seen on the path —
   a 1420-MTU peer pushes the mark to ~1480, and the client's own
   trailered sends start exceeding the path MTU even at `mtu: 1280`.
   The socket is perfectly usable after the error. Breaking the loop turns
   a dropped packet into a dead tunnel.

2. **Loop death is invisible.** The four tunnel tasks are detached
   `tokio::spawn`s (`src/amneziawg/tunnel.rs:107-147`); nothing observes
   their exit. The liveness machinery in `src/control/mod.rs` (`running`,
   `ExitGuard`, `on_exit` → stopped callback / `last_error`) watches only
   the service task — the TUN stack future. So `shoes_is_running()` stayed
   true and the 0.2.16 stopped callback never fired over a tunnel that
   could not receive.

3. **The trailer probe misdiagnoses silence.** `trailer_probe_loop` keys
   on "packets offered, handshake never completed"
   (`trailers_look_wrong`, `src/amneziawg/tunnel.rs:378`), which is also
   the signature of a dead receive path and of a blocked endpoint. Its
   message ("set random_trailers to match the peer") sent the debugging
   down a false path when both ends verifiably matched.

## Fix 1: the receive loop treats errors as weather, not as death

`decapsulate_loop` never exits on a *single* error. Each recv error is
classified:

```rust
enum RecvErrorAction {
    /// A routine ICMP echo on a connected UDP socket. Debug-log, continue.
    Ignore,
    /// EMSGSIZE: our own send exceeded the path MTU. Warn, reset the
    /// AmneziaWG trailer window (the state whose growth likely caused it),
    /// continue.
    ResetTrailerWindow,
    /// Anything else. Warn, continue — but count.
    Suspect,
}

fn classify_recv_error(e: &std::io::Error) -> RecvErrorAction
```

- `Ignore`: `ConnectionRefused`, `ConnectionReset` (as today), plus
  `HostUnreachable`, `NetworkUnreachable`, `NetworkDown`, `Interrupted` —
  all of them asynchronous ICMP echoes or noise on a connected UDP socket
  that say nothing about the socket's own health.
- `ResetTrailerWindow`: `raw_os_error() == Some(libc::EMSGSIZE)` (there is
  no stable `ErrorKind` for it; `libc` is already used this way in
  `endpoint.rs:217`). The response is `tunn.lock().reset_udp_window()` —
  the same call the rebind path makes, a no-op when trailers are off —
  because the trailer window has outgrown the path MTU and will keep
  producing oversized sends until it shrinks.
- `Suspect`: everything else (`EBADF` and friends). Still continue: on a
  connected UDP socket essentially every recv error is an echo of the
  past, and the cost of wrongly continuing is one log line, while the cost
  of wrongly breaking is the incident this spec exists for.

**Anti-spin and genuine death.** A truly dead socket (`EBADF` in a tight
loop) must not spin hot forever, and per the report, if the receive path
is ever really gone the engine must say so. Every error — of any class —
feeds a time-windowed streak:

```rust
/// Consecutive-error accounting for the receive loop.
///
/// "Consecutive" means back-to-back in time as well as in sequence: an
/// error more than STREAK_WINDOW after the previous one starts a new
/// streak. A blocked recv produces neither success nor error, so a peer
/// that is merely down (one ICMP echo per retry, seconds apart) never
/// accumulates a streak — only a socket returning errors continuously
/// does.
struct RecvErrorStreak { count: u32, last: Option<Instant> }

enum StreakVerdict { KeepGoing, Backoff, GiveUp }
```

Constants: `STREAK_WINDOW = 1s` (an error within a second of the previous
one continues the streak, otherwise the streak restarts at 1);
`Backoff` past 4 consecutive errors, sleeping 50 ms before the next recv;
`GiveUp` at 100. A dead fd therefore terminates the loop in ~5 seconds of
continuous errors; a server outage of any length never does (handshake
retries produce at most one latched ICMP error per attempt, seconds
apart). Any successful recv resets the streak to zero.

On `GiveUp` the loop returns a reason string instead of `()` — the only
remaining way out — and the death machinery below takes over.

## Fix 2: a dead receive path is an engine death

The service task in `src/control/mod.rs` is the thing whose end the host
observes (`ExitGuard` → `on_exit` → iOS `fire_stopped` / Android
`set_last_error`, and `running` → `shoes_is_running()`). The tunnel is
created lazily deep inside the connector chain
(`src/amneziawg/connector.rs:144`), far from any handle to that task, so
the signal travels through a process-global — the same pattern as the
endpoint registry (`endpoint.rs:38`) and the traffic counters, and
consistent with the documented one-service-per-process invariant
(`src/control/mod.rs:240-246`).

**New module `src/fatal.rs`** (top-level, because `amneziawg` compiles in
both the binary and the library, and `control` is library-only):

```rust
pub fn report(reason: String);                          // first report wins
pub fn subscribe() -> watch::Receiver<Option<String>>;
pub fn reset();                                         // new session, clean slate
```

One static `tokio::sync::watch` channel. `report` uses
`send_if_modified` so the first reason of a session is the one the host
hears; `reset` is called at the top of `run_prepared`, so a reason from a
previous session cannot kill the next one. In the standalone server
binary nothing subscribes and `report` is a logged no-op — a proxy server
with many outbounds should not die because one of them lost a socket.

**`run_prepared` races the TUN future against the signal.** It cannot
select directly over `run_tun_from_config` — dropping that future
mid-poll would skip the graceful teardown that releases the TUN
descriptor. Instead a small watcher task merges the two stop sources into
the oneshot the TUN already honours:

```rust
/// Forward either stop source into `forward_tx`; the reason, if it was a
/// fatal report rather than a host stop, comes back as Some.
async fn shutdown_or_fatal(
    shutdown_rx: oneshot::Receiver<()>,
    mut fatal_rx: watch::Receiver<Option<String>>,
    forward_tx: oneshot::Sender<()>,
) -> Option<String>
```

`run_prepared` calls `fatal::reset()`, spawns
`shutdown_or_fatal(shutdown_rx, fatal::subscribe(), tun_shutdown_tx)`,
runs the TUN on `tun_shutdown_rx`, then joins the watcher (abort + await;
a watcher that already finished yields its value). A `Some(reason)`
becomes `Err(io::Error::other(reason))` — overriding the `Ok(())` the TUN
returns for what it saw as a requested shutdown — and the existing
`ExitGuard` does the rest: `running` goes false, `on_exit(Some(reason))`
fires, iOS gets the stopped callback, Android gets `last_error`. A host
stop travels the same path with reason `None` and stays silent, exactly
as today.

**The tunnel reports its own death.** In `TunnelRuntime::start` the recv
task becomes:

```rust
let reason = decapsulate_loop(...).await;
dead.store(true, Ordering::SeqCst);
crate::fatal::report(format!("AmneziaWG receive path failed: {reason}"));
```

`dead: Arc<AtomicBool>` lives on `TunnelRuntime` behind
`pub fn is_dead(&self) -> bool`, and `AmneziaWgConnector::ensure_initialized`
checks it: a dead runtime is discarded and rebuilt on the next connection
(`TunnelState._runtime` is renamed `runtime`). That is what recovery
looks like in the standalone binary, where no engine listens for fatals;
in the mobile engine the fatal fires first and the rebuild path is moot.

## Fix 3: the probe says what it actually knows

`decapsulate_loop` counts successful recvs into a new
`datagrams_received: Arc<AtomicUsize>` (incremented on every `Ok(n)`,
before decapsulation — arrival is the fact of interest, parseability is
not). `trailer_probe_loop` takes the counter, remembers the value at its
previous tick, and words the flip by whether anything arrived since:

```rust
fn probe_message(offered: usize, new_state: &str, arrived_since_last_probe: usize) -> String
```

- Nothing arrived in the whole probe interval: the trailer setting is
  unfalsifiable, so the message must not point at it — *"AmneziaWG: no
  handshake after {offered} packets and nothing received from the peer;
  the endpoint may be unreachable or blocked, or the obfuscation
  parameters may not match — retrying with random trailers {state}
  anyway."*
- Datagrams arrived but no handshake completed: the peer answers and we
  cannot parse it, which genuinely does smell like a framing mismatch —
  the current message stays: *"...retrying with random trailers {state}.
  If this is what fixes the tunnel, set random_trailers to match the
  peer."*

The flip itself happens in both cases (it is harmless, and it is the only
probe available); `trailers_look_wrong` is unchanged. In the incident's
dead-loop state the counter is frozen, so the probe would have printed
the endpoint-silent wording — and with fixes 1 and 2 that state no longer
persists at all.

## Tests

- `src/fatal.rs`: report/subscribe round-trip; the first reason wins over
  a second; `reset` clears. Serialised with a test lock, the
  `REGISTRY_TEST_LOCK` pattern, because the channel is process-global.
- `src/control/mod.rs`, `shutdown_or_fatal` (takes its receivers as
  parameters precisely so tests build their own watch channel, no global):
  a fatal report resolves `forward_tx` and returns the reason; a host
  shutdown resolves `forward_tx` and returns `None`.
- `src/amneziawg/tunnel.rs`:
  - `classify_recv_error`: `EMSGSIZE` → `ResetTrailerWindow`; each
    `Ignore` kind; an unknown kind → `Suspect`.
  - `RecvErrorStreak` with injected `Instant`s: back-to-back errors reach
    `Backoff` then `GiveUp` at the thresholds; errors spaced past the
    window never leave streak 1; success resets.
  - `probe_message`: both wordings, chosen by `arrived_since_last_probe`.
  - The existing probe and handshake tests keep passing with the new
    `datagrams_received` parameter threaded through.
- The full recv-death → fatal → `on_exit` chain crosses a real TUN device
  and a real socket error, so it is verified manually against the KVN
  reproduction (peer at 1420 MTU, client at 1280, trailers on), not in CI.

## Docs and release

- CHANGELOG under a new `Unreleased` heading: the receive loop survives
  transient UDP errors including the deferred `EMSGSIZE` that killed
  tunnels against higher-MTU peers; a genuinely dead receive path now
  stops the engine with a reason (stopped callback on iOS/macOS,
  `shoes_get_last_error` on Android) instead of reporting healthy; the
  trailer-probe hint no longer blames `random_trailers` when nothing was
  received at all.
- No FFI surface change: both platforms already consume `on_exit`.

## Amendments after review (same day)

A `/code-review high` pass over the first implementation surfaced ten
findings; all were applied, and where they contradict the text above,
this section wins:

- **Only `Suspect` errors feed the fatal streak.** The original "every
  error of any class" rule turned a routine peer restart -- Ignore-class
  ICMP echoes arriving back-to-back under active traffic -- into an
  engine death in ~5 seconds. An outage is ridden out; only errors nobody
  can explain count toward `GiveUp`.
- **Fatal reports carry a session generation.** A stopped session's
  tunnel tasks outlive it on the background shutdown thread, and both FFI
  restart paths start the new session first. `fatal::reset()` bumps a
  generation; a reporter captures `fatal::generation()` at tunnel
  creation, and a report from any other generation is dropped, so a stale
  death cannot kill the next session.
- **EMSGSIZE is handled on the send path too.** Once the kernel caches
  the lower path MTU it rejects oversized sends synchronously, and the
  recv side may never see the error. `send_to_network` routes every send
  error through the same handler as recv.
- **The EMSGSIZE message respects the config.** Plain WireGuard has no
  trailer window; blaming one would be the same false-path hint issue 3
  removed. The live setting is an `AtomicBool` the trailer probe keeps
  current, and without trailers the message points at the path MTU.
- **The errno is per-platform.** `libc::EMSGSIZE` on Windows is the CRT
  errno a socket never produces; WinSock's `WSAEMSGSIZE` (10040) is
  matched there instead.
- **Route-gone evidence on recv triggers a rebind.** The recv side
  consults `endpoint::is_route_gone` -- the same table the send path
  uses -- because on an idle tunnel it sees the dead route first.
- **A panic in the receive loop still marks the tunnel dead.** The loop
  runs under `catch_unwind` on unwinding profiles; release-mobile builds
  with `panic = "abort"`, where the process's death is its own
  announcement.
- **A rebuild aborts the old netstack task.** Its `request_rx` and the
  pending reply senders drop with it, unblocking callers parked on a
  stack nobody feeds; the rebuild condition also checks
  `request_tx.is_closed()` so a netstack that died on its own is caught
  too. Residual gap, accepted: a request that races the `is_dead` check
  through a slow DNS resolution parks its caller until the next
  connection triggers that rebuild.
- **A fatal does not swallow the TUN's own teardown error.** It is
  logged before the fatal reason overrides the result, because the next
  start may fail on whatever the teardown failed to release.

## Out of scope

- KVN-side follow-ups from the report (degraded-state UI, stale ping
  decay, server-side MTU) — they belong to KVN.
- An Android JNI push callback for engine death (Android still learns via
  `shoes_is_running()`/`shoes_get_last_error`; parity with the iOS
  stopped callback is its own change).
- Capping trailer sizes to a discovered path MTU inside awgtun — upstream
  of this repo; the window reset on `EMSGSIZE` is the local mitigation.
- Netstack death detection (the virtual-stack channel closing is a
  separate, never-observed failure mode).
