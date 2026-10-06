# Hysteria2 runs BBR, as upstream does

Hysteria2 connections, client and server, use BBR as their congestion
controller instead of quinn's default, Cubic. TUIC keeps Cubic. Written
2026-10-01 against `mobile` at `2138a40`.

## Table of Contents

- [Problem](#problem)
- [What the references do](#what-the-references-do)
- [What quinn offers](#what-quinn-offers)
- [Design](#design)
- [A slowdown that was sing-box's, not ours](#a-slowdown-that-was-sing-boxs-not-ours)
- [What it costs](#what-it-costs)
- [Interaction with Brutal](#interaction-with-brutal)
- [Error handling](#error-handling)
- [Testing](#testing)
- [Deliberately out of scope](#deliberately-out-of-scope)

## Problem

Measured with `NETEM` in `scripts/bench/tunnels.py` (PR #39), which puts delay
and per-datagram loss between each tunnel client and its server, one stream,
Mbit/s:

| Path | shoes ↔ shoes | sing-box ↔ sing-box |
| --- | --- | --- |
| 20 ms, no added loss, 1 Gbit/s | 912 up / 534 down | 603 / 429 |
| 50 ms, 0.5% loss, 1 Gbit/s | 11 / 5 | 465 / 435 |
| 100 ms, 2% loss, 200 Mbit/s | 5 / 1 | 122 / 116 |

The collapse follows the sender, not the pairing. With a shoes client and a
sing-box server, the upload (shoes sending) carried 14 Mbit/s and the download
(sing-box sending) 367; with a sing-box client and a shoes server, 487 and 4.
In one clean-path run, a shoes server sending to a sing-box client managed
3 Mbit/s for the whole ten seconds: loss at the bottleneck queue alone was
enough.

A sender that halves on every loss runs at roughly MSS / RTT × 1.22 / √p, about
4 Mbit/s at 50 ms and 0.5%, which is what was measured. Lossy paths are where
people choose Hysteria.

## What the references do

**Upstream Hysteria** (`apernet/hysteria`, master):

- `core/internal/congestion/utils.go`: `NormalizeType` maps an empty type to
  `bbr`; `UseConfigured` installs BBR for anything but `reno`, and for `reno`
  installs nothing, leaving quic-go's own controller.
- `core/client/client.go`, after authentication: if the server answered
  `Hysteria-CC-RX: auto`, `UseConfigured`; otherwise Brutal at
  min(server rx, client max tx) if that is non-zero, else `UseConfigured`.
- `core/server/server.go`, on authentication: with `IgnoreClientBandwidth`,
  `UseConfigured`; otherwise Brutal at min(client rx, server max tx) if
  non-zero, else `UseConfigured`.

So with no bandwidth configured on either side, both ends run BBR. That is the
case shoes is always in: it implements no Brutal, its client declares `rx: 0`
(`src/hysteria2/auth.rs`) and its server answers `auto`
(`src/hysteria2/server.rs`).

**sing-box** behaves the same for Hysteria2. `SagerNet/sing-quic`,
`hysteria2/client.go`, after authentication: Brutal only when the server did
not answer `auto` and a send rate is known, otherwise
`congestion_meta2.NewBbrSenderWithProfile`. That is why it held 465 Mbit/s
above.

**TUIC** defaults to Cubic. sing-box's TUIC documentation
(`docs/configuration/inbound/tuic.md`, branch `stable`): "`cubic` is used by
default." TUIC is not changed here.

## What quinn offers

quinn-proto 0.11.19, the version in `Cargo.lock`:

- `congestion::BbrConfig` and `congestion::CubicConfig`, installed with
  `TransportConfig::congestion_controller_factory`. The default is
  `CubicConfig::default()` (`src/config/transport.rs`).
- `quinn::Connection::congestion_state()` returns the live controller, and
  `Controller::into_any` lets a test downcast it to `congestion::Bbr`.
- The congestion window and the pacer gate only ack-eliciting packets
  (`poll_transmit` in `src/connection/mod.rs`: `if ack_eliciting && …`). An
  acknowledgement is never held back by its sender's controller, which matters
  below.

## Design

`QuicTransportParams` (`src/quic_transport/mod.rs`) gains one field:

```rust
pub enum CongestionControl { Bbr, Cubic }
pub congestion: CongestionControl,
```

`build()` installs `BbrConfig::default()` or `CubicConfig::default()`. Cubic is
installed explicitly rather than by leaving quinn's default in place, so the
choice is visible where the other parameters are and does not change if quinn
changes its default.

The struct's own rule is that a field exists only where two protocols need
different values. This one does: Hysteria2 is `Bbr`, TUIC is `Cubic`.

- **Server.** `src/hysteria2/server.rs` and `src/tuic/server.rs` each build
  their parameters in a function, `transport_params`, so a test can check the
  choice without raising a listener.
- **Client.** The QUIC outbound is shared by both protocols.
  `QuicOutboundSettings` (`src/quic_outbound/mod.rs`) gains `congestion`,
  which `Hysteria2Connector` sets to `Bbr` and the TUIC connector to `Cubic`,
  and `build_endpoint` passes it into the parameters.

The controller is chosen when the connection is made, not after
authentication as upstream does. With Brutal absent the outcome is the same:
every branch of upstream's choice that does not install Brutal installs BBR.

Nothing is configurable. Upstream's `congestion.type` exists to choose `reno`
over the default; with no evidence that anyone needs that, it is left out (see
below).

## A slowdown that was sing-box's, not ours

The first matrix run showed a shoes client with BBR making a sing-box server's
download slower: 159 Mbit/s at 0.5% loss against 367 with Cubic. Before
shipping this, that had to be explained.

- Alone, the case does not reproduce. Four alternating runs each: Cubic 459,
  474, 471, 479; BBR 471, 486, 484, 469.
- It reproduces when the download follows an upload on the same connection,
  which is the order the matrix runs: Cubic 358 and 388, BBR 150 and 173.
- quinn's per-second statistics on the client, logged through both phases,
  show the client stops sending stream data the moment the upload ends, and
  its BBR window stays at 250–290 KB, not at a minimum. What climbs slowly is
  the data arriving: 162, 303, 538, 1006 … 24 122 packets a second over ten
  seconds. That is the sing-box server's sender ramping up on a connection
  that was receiving a moment before.
- The mirror case does not slow down: a sing-box client uploading and then
  downloading from a shoes server with BBR carried 463 then 455.

A shoes client with BBR puts a sing-box server's sender into that state by
uploading fast. With Cubic it never got the chance. Not a defect here, and not
something a client can fix.

## What it costs

On a clean path BBR is somewhat slower than Cubic wherever Cubic did not
collapse. At 20 ms and 1 Gbit/s: shoes ↔ shoes 820 / 810 against 912 / 534
(10% slower up, faster down, where Cubic had dropped). A shoes sender to a
sing-box receiver is about 20% slower: 504 against 640, and with salamander
496 against 621. The clean-path collapse is gone: a shoes server sending to a
sing-box client carried 511 against Cubic's 3. On loopback, with no bottleneck
at all, that same direction is where BBR costs most: 1.6–1.9 Gbit/s against
Cubic's 7.8. Shoes to shoes is unaffected there (10.5 to 11 either way), so it
is how quinn's BBR meets quic-go's receiver at rates no real path carries. On
every lossy path it is faster by one to two orders of magnitude:

| Path | Cubic | BBR | sing-box ↔ sing-box |
| --- | --- | --- | --- |
| 50 ms, 0.5% loss | 11 / 5 | 515 / 491 | 465 / 435 |
| 100 ms, 2% loss | 5 / 1 | 133 / 128 | 122 / 116 |
| 50 ms, 0.5% loss, salamander | 10 / 4 | 514 / 511 | — |

Upstream makes the same trade, and it is the right one for a protocol people
pick for bad paths.

## Interaction with Brutal

`ROADMAP.md` says the client's ignoring of `Hysteria-CC-RX: auto` "is
compliant only for as long as we install no congestion controller of our own".
That needs restating rather than reverting: upstream's client, given `auto`,
installs its configured controller, which is BBR by default, and so does this
client, unconditionally. Ignoring the header stays compliant for as long as no
Brutal exists, because without Brutal the only answer the header can lead to
is the one already in place.

The Brutal row stays open; BBR is upstream's fallback, not its headline
feature. The BBR-profile row now describes a knob on a controller that exists.

## Error handling

There is nothing to fail: no configuration is read, and both factories are
infallible. A connection's controller cannot be changed after it exists, so
there is no runtime switch to get wrong.

## Testing

- `src/quic_transport/mod.rs`: for each `CongestionControl`, a connection
  between the production listener (`start_quic_listeners`) and the production
  dialer (`QuicOutboundSettings::build_endpoint`) on loopback; both ends'
  `congestion_state()` downcasts to the selected type. Fails if `build()`
  ignores the field, or if the dialer drops it.
- `src/hysteria2/server.rs` and `src/tuic/server.rs`: `transport_params`
  selects `Bbr` and `Cubic`, with and without obfuscation.
- `src/hysteria2/client.rs` and `src/tuic/client.rs`: each connector asks for
  `Bbr` and `Cubic`.
- Each test was checked against its defect: making `build()` install Cubic
  for `Bbr`, or swapping the choice in any one of the four call sites, fails
  that test and no other.
- Throughput is not unit-tested: a loss-rate test would be slow and noisy. It
  is measured with `NETEM`, and the figures above came from that.

## Deliberately out of scope

- **Brutal** and the bandwidth negotiation; `ROADMAP.md` keeps that row.
- **A `congestion` option** (`type`, `bbrProfile`). Upstream's `type` exists to
  choose `reno`, and quinn has no BBR profiles. Add it when someone needs
  either.
- **TUIC's controller.** TUIC defaults to Cubic in the reference. A
  `congestion_control` option for TUIC is a separate change.
- **quinn's BBR against quic-go's.** They are different implementations, and
  this one is about 10% behind Cubic on a clean path. Tuning a controller is
  not this change.
