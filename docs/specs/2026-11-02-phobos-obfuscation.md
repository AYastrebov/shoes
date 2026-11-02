# Phobos obfuscation for the WireGuard outbound

Design for dialling a [Phobos](https://github.com/Ground-Zerro/Phobos)
server from shoes' `wireguard` outbound. A Phobos server is a plain kernel
WireGuard interface behind an obfuscating UDP proxy. The client has to apply
the same obfuscation to every datagram it exchanges with that proxy. Client
only.

Written 2026-11-02 against `mobile` at `ea46233`.

## Sources

| Source | Version read | Licence | Used for |
| --- | --- | --- | --- |
| [awgtun](https://github.com/AYastrebov/awgtun) `docs/phobos.md` and `awgtun::phobos` | `6992ff7` (master, #9 merged) | BSD-3-Clause | The wire format and the codec. Written from the spec, passes Phobos's published vectors, and checked against Phobos's own C decoder |
| [Ground-Zerro/Phobos](https://github.com/Ground-Zerro/Phobos) | `22aedef` (2026-10-12) | AGPL-3.0, GPL-3.0 in `src/phobos-obfuscator` | Server behaviour: `src/phobos-obfuscator/threading.c` (`process_packet`, `process_from_client`, the per-client state machine), `masking_stun.c`, `masking_media.c`, `config.c` (keys and ranges). The Android client `mobil/wireguard-phobos/tunnel/.../obfuscator/ObfuscatorConfigParser.kt` for the client-side key names |

No code is copied. The wire format lives in awgtun, and this document
covers what the shoes runtime has to do around it.

## Problem

A Phobos server's WireGuard port is never published. Only the obfuscator's
UDP ports are, one per preset, and a datagram that isn't obfuscated with the
preset's key is dropped. Phobos's own clients run the obfuscator as a loopback
proxy beside wireguard-go, or reimplement it in-process (the Android app).
shoes can do neither today. A user can only reach such a server by running
the reference proxy alongside shoes, which a mobile app can't do.

## Scope

- A `phobos:` block on the `wireguard` outbound with the reference's
  client-side keys: `key`, `masking`, `max_dummy`, `obfuscate_bytes`,
  `media_pt`, `media_ssrc`, `media_clock`.
- Every datagram to the endpoint is wrapped, and every datagram from it is
  unwrapped, in the tunnel runtime.
- Reference control traffic: a STUN Binding Request before each handshake
  initiation and on the masking's timer, and a Binding Success in reply to
  the server's requests.
- A rebind that forces a new handshake rather than announcing itself with a
  keepalive (see "Server state" below).

## What the reference does

### Placement

The server's obfuscator forwards to `127.0.0.1:51820`, a kernel WireGuard
interface (`README.md`, "How it works"). Its decoder classifies a datagram as
obfuscated unless bytes 1–3 of the WireGuard type field are zero
(`obfuscation.h`, `is_obfuscated`). Any AmneziaWG feature breaks that, and
the server's WireGuard couldn't parse AmneziaWG anyway. So Phobos goes on
the `wireguard` outbound, not `amneziawg`. That way the combination can't be
written, rather than being refused after the fact.

### Server state

`threading.c` keys each client by source address. A handshake initiation
creates the entry. A handshake response from WireGuard marks it handshaked.
Every other message is dropped while the entry isn't handshaked
(`process_packet`: `else if (!client_entry || !client_entry->handshaked)
return 0`).

A client that changes networks therefore arrives from an address with no
entry. Its keepalive and its data are dropped, and nothing reaches the
server's WireGuard until the next rekey initiates a handshake from the new
address, up to two minutes later. shoes' rebind announcement today is an
empty payload through the encapsulate loop, which is a keepalive when a
session exists. Against Phobos, that announcement is discarded.

Each client entry also has its own socket toward WireGuard, so the server's
WireGuard sees a roamed client as a new loopback source. A fresh handshake
from the new address repairs both directions.

### Control traffic

`masking_stun.c` sends a Binding Request when the obfuscator first sees a
plain handshake initiation (`stun_on_handshake_req`, called from
`process_packet` when `!obfuscated`). It sends one every
`timer_interval_s`: 10 for STUN and 5 for MEDIA. A Binding Request from the
peer is answered with a Binding Success carrying XOR-MAPPED-ADDRESS. None of
this counts as activity: a control datagram returns before `process_packet`
updates `last_activity_time`.

### MTU

The frame adds 24 bytes (STUN) or 12 (RTP). The random tail is applied only
below 1024 bytes (`encode`, `length < MAX_DUMMY_LENGTH_TOTAL`), so a
full-size transport packet grows by the frame alone.

## Architecture

`src/amneziawg/phobos.rs` holds the conversion from the shoes config to
`awgtun::phobos::PhobosConfig`, and `PhobosLayer`: one codec behind a
`parking_lot` mutex.

`EndpointSocket` owns the layer. Every datagram the tunnel sends already
goes through `EndpointSocket::send`, and every one it receives through
`EndpointSocket::recv`, so these two are the whole seam. The loops in
`tunnel.rs` keep their signatures, and with Phobos off nothing in them
changes.

- **Send:** wrap into a buffer taken from a small pool owned by the socket,
  send the Binding Request (if the codec returned one), then the wrapped
  datagram, and put the buffer back. The pool keeps the send path free of
  per-packet allocation once warm. It is bounded by the tasks that send
  concurrently (receive, encapsulate, timer, control), and a buffer whose
  send is cancelled is simply not returned. The codec lock is never held
  across an `await`.
- **Receive:** unwrap in place. A `Reply` goes back raw and the read
  continues; a `Drop` is skipped; a WireGuard message is moved to the front
  of the caller's buffer and its length returned. Control traffic never
  reaches the receive loop, so it is not counted as an arrival or a
  decapsulation.
- **Control timer:** a sixth task sends `binding_request()` every
  `control_interval()`, only when the masking has one. It stays quiet while
  the session is down (no handshake in the last 180 s, WireGuard's
  `REJECT_AFTER_TIME`). The reference stops too, when the server drops its
  idle client entry, and a phone should not power its radio every 10 s
  for a tunnel nobody uses.
- **Rebind:** each socket carries a generation, 0 for the first and one
  more per rebind, in the same `watch` value as the socket. `send` takes
  both from one snapshot. From a generation that no initiation has gone out
  on yet, it holds back every other WireGuard message (`Ok(0)`, nothing
  sent), which is exactly what the server would discard. A generation
  counts as initiated only once an initiation's send on it has succeeded:
  while that send is pending, and after it fails, the gate stays shut. The
  encapsulate loop asks `needs_initiation()` before every packet and, when it is owed,
  sends `format_handshake_initiation(out, true)` first. The announcement's
  empty payload still wakes an idle loop.

  A flag set by the rebind callback was the first version. Review
  (shoes#151) caught that the socket is published before the callback
  runs, so a transport message from the timer or encapsulate task could
  reach the new socket first. Gating by generation at the socket closes
  that window for every sender at once.

RTP sequence numbers are taken under the codec lock, but two tasks may send
in the other order. That is reordering, which RTP over UDP sees anyway. The
server reads neither the sequence number nor the timestamp
(`media_on_data_unwrap`).

## Configuration

```yaml
protocol:
  type: wireguard
  # ...the WireGuard fields...
  phobos:
    key: string            # required; the preset's key, as text
    masking: none          # none | stun | media | auto | tls, any case
    max_dummy: 4           # 0-1024
    obfuscate_bytes: 0     # 0 = all; 16 under media when 0
    media_pt: 0            # 0-127; 0 = a random preset
    media_ssrc: 0          # 0 = random
    media_clock: 0         # fps, 0-1000; 0 = a random preset
```

These are the reference's keys with `-` written `_`, the shoes convention.
Ranges and the `auto`/`tls` meanings are awgtun's, which mirrors
`config.c`. The endpoint (`client_chain.address`) is the preset's
obfuscator port, not WireGuard's. `target` and `source-lport` from a
Phobos client file have no equivalent: the first is the address, and the
second names a loopback port shoes doesn't need.

## Error handling

- A bad value is a load-time error naming the field. The key is never
  repeated in an error (`assert!(!err.contains(key))`).
- A key mismatch produces no error at all. The server drops everything,
  which looks exactly like an unreachable server. CONFIG.md says so.
- A malformed datagram from the network is dropped silently, since its
  sender chose the contents. A datagram `wrap` refuses (too short, or longer
  than STUN's 16-bit DATA length) is an `InvalidInput` error, so the send
  path's failure accounting sees it. The tunnel's own messages can't reach
  either case past validation.
- An `mtu` whose full-size packet cannot be sent at all is refused when the
  config loads. The message (`mtu + 32`) must fit the masking's own limit
  (STUN's 16-bit DATA length, `Masking::max_message_len` in awgtun), and
  the framed datagram (`mtu + 32 + frame`) must fit one IPv4 UDP payload,
  65507 bytes. That caps `mtu` at 65451 (STUN), 65463 (RTP) and
  65475 (none).
- Validation warns when `mtu + 60 + frame` exceeds 1500, in the shape of the
  AmneziaWG `s4` warning.

## Testing

- **Conversion:** every key maps across, a bad value names its field, and the
  key never appears in an error.
- **End to end, in-process:** a Phobos server double, which is a UDP socket,
  a server-side `PhobosCodec` and a server `Tunn`, in front of
  `TunnelRuntime`. An IP packet offered to the tunnel must arrive decrypted
  at the server's `Tunn`, through a Binding Request and a wrapped handshake.
  Run once per masking. The control is a double with a different key, which
  must see no plain-decodable handshake.
- **Rebind:** after a rebind with a live session, the first WireGuard message
  the double decodes from the new address is an initiation (type 1), not a
  transport message. At the socket, deterministically: a transport message
  sent straight after the swap is held back, and the initiation leaves the
  new socket first.
- Each new test is shown to fail with its defect planted.
- **Live, not yet run:** the reference `wg-obfuscator`, built from source in
  a container, in front of `wireguard-go`, through the built binary
  (`live-interop-check`). Apple's `container` VM kernel has no WireGuard
  module but does have TUN, so `wireguard-go` is the peer. Until this runs,
  interop rests on awgtun's checks against the reference's vectors and
  decoder, and on the double here.

## Out of scope

- Phobos's SOCKS5/TCP presets: a different transport and a different cipher.
- `phobos` on `amneziawg`: the server can't use it (see Placement).
- Importing a Phobos client package (`.conf` plus obfuscator section). That
  belongs to the app that imports profiles.
- A keystream cache per length, which the reference keeps. awgtun computes
  the keystream per packet, and that cost is unmeasured.
