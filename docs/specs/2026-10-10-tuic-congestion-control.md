# TUIC takes a `congestion_control` option

TUIC's client and server accept `congestion_control: cubic | new_reno | bbr`,
defaulting to `cubic`, as the reference implementation and sing-box do. Written
2026-10-10 against `mobile` at `0f1d19c`.

## Table of Contents

- [Problem](#problem)
- [What the references do](#what-the-references-do)
- [Design](#design)
- [Why the default stays Cubic](#why-the-default-stays-cubic)
- [Error handling](#error-handling)
- [Testing](#testing)
- [Deliberately out of scope](#deliberately-out-of-scope)

## Problem

Measured with `NETEM` in `scripts/bench/tunnels.py`, which now carries TUIC
cases for all four pairings of shoes and sing-box. One stream, Mbit/s, upload /
download:

| Path | shoes ↔ shoes, Cubic | shoes ↔ shoes, BBR | sing-box ↔ sing-box, Cubic | sing-box ↔ sing-box, BBR |
| --- | --- | --- | --- | --- |
| 20 ms, no added loss, 1 Gbit/s | 911 / 905 | 920 / 911 | 647 / 62 | 722 / 530 |
| 50 ms, 0.5% loss, 1 Gbit/s | 11 / 5 | 503 / 517 | 7 / 5 | 376 / 373 |
| 100 ms, 2% loss, 200 Mbit/s | 6 / 1 | 130 / 123 | 2 / 1 | 105 / 104 |

The BBR column for shoes came from a scratch build with TUIC's controller
switched in code; sing-box's from its own `congestion_control: bbr`. Three
repeats of the 2% case gave 122–127 down; one earlier run gave 19 and did not
reproduce in six more.

Built and configured through the option (`TUIC_CC=bbr` now sets it at every
end, shoes and sing-box), shoes ↔ shoes carried 507 / 493 at 0.5% and
137 / 124 at 2%, against 13 / 5 and 6 / 1 on the default. One cell of that run
fell: a sing-box server sending to a shoes client at 2% loss gave 3, against
129 in the earlier run. That is sing-box's sender just after an upload on the
same connection, the effect `docs/specs/2026-10-01-hysteria2-bbr.md` traced to
sing-box rather than to us.

TUIC on Cubic collapses on a lossy path exactly as Hysteria2 did before
`docs/specs/2026-10-01-hysteria2-bbr.md`, in both implementations, because
that is what a loss-based controller does: about MSS / RTT × 1.22 / √p. Every
TUIC implementation people use lets the operator choose BBR for that path. We
do not, so a shoes TUIC endpoint on a lossy path is stuck at single-digit
Mbit/s with no way out short of switching protocol.

## What the references do

**The TUIC reference** (`tuic-protocol/tuic`, formerly `EAimTY/tuic`). Master
no longer carries an implementation; the last one is at tag
`tuic-server-1.0.0`:

- `tuic-server/src/config.rs` and `tuic-client/src/config.rs`: a
  `congestion_control` field on each, defaulting to `CongestionControl::Cubic`
  (`default::congestion_control`, `default::relay::congestion_control`).
- `tuic-server/src/utils.rs`: `enum CongestionControl { Cubic, NewReno, Bbr }`,
  parsed case-insensitively from `cubic`, `new_reno` or `newreno`, and `bbr`;
  anything else is "invalid congestion control".
- `tuic-server/src/server.rs`: each variant installs quinn's
  `CubicConfig::default()`, `NewRenoConfig::default()` or
  `BbrConfig::default()` through `congestion_controller_factory`. The reference
  is quinn-based, so these are the controllers we would install.

**sing-box** (`docs/configuration/inbound/tuic.md` and `outbound/tuic.md`,
branch `stable` at `7054cac`): `congestion_control`, "One of: `cubic`,
`new_reno`, `bbr`", "`cubic` is used by default", on the inbound and the
outbound alike.

Neither negotiates the choice. Each end picks its own sender's controller, so
a BBR client and a Cubic server is a legal pairing in which each direction runs
whatever its sender chose.

## Design

**Transport.** `quic_transport::CongestionControl` gains `NewReno`, and
`QuicTransportParams::build` installs `NewRenoConfig::default()` for it.

**Configuration.** A `TuicCongestionControl` enum in
`src/config/types/client.rs`, beside `TuicUdpRelayMode`, with the serde names
`cubic`, `new_reno` and `bbr`, `newreno` as an alias, and `Cubic` as the
default. It converts into `CongestionControl`.

- `ServerProxyConfig::TuicV5` gains `congestion_control`, defaulted.
- `TuicClientConfig` gains `congestion_control`, defaulted and omitted when
  serialising the default, as `udp_relay_mode` is.

**Plumbing.**

- Server: `tuic::server::transport_params` takes the controller as a second
  argument; `start_tuic_server` takes it and passes it on;
  `quic_server.rs` reads it out of the config.
- Client: `TuicConnector::new` takes it and puts it in
  `QuicOutboundSettings::congestion`; `chain_builder.rs` reads it out of the
  config.

Hysteria2 is unchanged: it stays on BBR with no option, as its spec decided.

## Why the default stays Cubic

Every number above argues for BBR, and the default stays Cubic anyway:

- Both references default to Cubic, and a shoes endpoint configured from a
  sing-box or reference config should behave like the one it replaces.
- BBR is not free on a clean path between different implementations. On the
  20 ms clean path a shoes client with BBR sending to a sing-box server carried
  554 against Cubic's 748 (the other direction gained, 76 to 790, because
  sing-box's own Cubic sender is the slow one there), and Hysteria2's spec
  records the same shape.
- The option is the fix, and the documentation says when to use it.

## Error handling

An unknown value is a configuration error, raised by serde when the config is
loaded, and the message names the value and the accepted ones. When this was
written it did not inside a whole config file: the untagged `NoneOrSome`
around a server's rules replaced every inner error with "data did not match
any variant of untagged enum NoneOrSome". That was fixed separately, for every
option at that depth, by deserialising `NoneOrSome` and its siblings by hand
(`src/option_util.rs`). The reference also rejects unknown values; it is
case-insensitive where we are not, so `BBR` is refused here. The factories are
infallible, and the choice is fixed when the connection is made.

## Testing

- `src/quic_transport/mod.rs`: the existing test that both ends of a real
  connection (production listener, production dialer) run the controller they
  were asked for covers all three variants, asked of quinn by downcasting
  `congestion_state()`.
- `src/tuic/server.rs`: `transport_params` passes each choice through, with
  and without obfuscation.
- `src/tuic/client.rs`: the connector's settings carry each choice.
- `src/tcp/chain_builder.rs`: the TUIC outbound built from a config, through
  the production `build_terminal_connector`, dials with that config's
  controller and with Cubic when the key is absent. `TuicConnector`'s `Debug`
  names the controller, which is what makes this observable.
- `src/config/types/`: the server and client configs parse each value and the
  `newreno` alias, default to Cubic when the key is absent, refuse an unknown
  value, a client config with the default serialises without the key, and a
  server config round-trips a chosen one.
- Each test is checked against its defect: `build` installing Cubic for
  `NewReno`, the connector or `transport_params` ignoring its argument,
  `chain_builder.rs` dropping the field, the default moving to BBR, and the
  `newreno` alias going missing each turn exactly the tests above red. The
  server's call site in `quic_server.rs` has no test of its own and needs
  none: it destructures the field by name, so ignoring it is an unused
  variable, which the gate's `-D warnings` refuses. That was checked too.
- Throughput is measured with `NETEM`, not unit-tested; the table above came
  from that.

## Deliberately out of scope

- **Making BBR the default.** See above.
- **A `congestion_control` option for Hysteria2.** Upstream's `congestion.type`
  exists to choose `reno` over BBR; the Hysteria2 spec deferred it until
  someone needs it, and nothing here changes that.
- **Case-insensitive parsing.** The reference lowercases; serde does not, and
  no config seen in the wild writes the names in another case.
