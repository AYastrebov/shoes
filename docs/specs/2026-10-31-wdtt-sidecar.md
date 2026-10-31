# WDTT: a sidecar for VK-relayed WireGuard

Design for reaching a WDTT server from shoes. WDTT (and its continuation,
qWDTT) carries WireGuard datagrams through VK's video-call TURN relays,
each datagram wrapped to look like an RTP packet of a WebRTC call, so that
a carrier which whitelists VK's call traffic and blocks VPN protocols
passes it. The design puts the protocol in a separate Rust crate, a
sidecar, and leaves shoes unchanged: shoes' existing `wireguard` outbound
sends to a loopback UDP port the sidecar owns.

Written 2026-10-31 against `mobile` at `884938d` (v0.9.2). **Design only:
nothing here is scheduled, and no code exists.** It records what was read
and decided so the question does not have to be answered twice.

## Sources

Every wire detail below was read from these, not recalled. Each claim
cites where it came from. There is no specification: the protocol is what
the Go server accepts, and it has moved within the year (the RTP header
went from 12 bytes to 24 and back; the DTLS-less and WireGuard-less modes
are months old).

| Source | Version read | Licence | Used for |
| --- | --- | --- | --- |
| [SpaceNeuroX/proxy-turn-vk-android](https://github.com/SpaceNeuroX/proxy-turn-vk-android) (qWDTT) | `a296c57` (2026-09-13, release 1.4.4) | GPL-3.0 | The protocol: `go_client/` is the client, `server/` the server (`wdtt-server`), `app/` the Android app. Behaviour only, no code |
| [amurcanov/proxy-turn-vk-android](https://github.com/amurcanov/proxy-turn-vk-android) (WDTT) | `7355598` (2026-10-20), archived | GPL-3.0 | The origin; qWDTT is its continuation and the wire format is the same |
| [Regstar2/pwdtt](https://github.com/Regstar2/pwdtt) | `46c7c4a` (2026-10-16) | GPL-3.0 | A Go desktop client (Windows, Linux, macOS) for the same servers: proof that a client outside the Android app is enough |
| [spkprsnts/WireTurn](https://github.com/spkprsnts/WireTurn) | `d086333` (2026-10-19) | GPL-3.0 | An Android client that runs qWDTT as one of several tunnel cores beside Xray: the sidecar pattern, on Android |
| [saymer-alt/wdtt-suite](https://github.com/saymer-alt/wdtt-suite) | `2eb9719` (2026-10-30) | GPL-3.0 | A Go SOCKS5 client for Keenetic routers under Entware; its README reports 18 workers over two call hashes on an ARM64 router |
| RFC 5766 (TURN), RFC 5389 (STUN), RFC 3550 (RTP), RFC 5869 (HKDF), RFC 8439 (ChaCha20-Poly1305) | as published | — | The standard layers the protocol is built from |

All four implementations are GPL-3.0 and Go. They contribute behaviours
and reasons. No code is copied; the sidecar is written from the wire
format described here, and test vectors are produced by running the
reference, which is use, not copying.

## Problem

A user behind a mobile carrier that passes VK's call media and throttles
or drops everything else cannot reach their own VPS with any protocol shoes
speaks. WDTT exists for exactly that network. Its users run `wdtt-server`
on a VPS and the qWDTT app on the phone; nothing lets them use shoes, or
the apps built on shoes, on that path.

The protocol is niche, Russian-market only, unspecified, and depends on
VK's anonymous call-join API and relay quota, which VK can close any day.
That is why it does not belong in `src/`: a protocol that churns should
churn in a crate that shoes merely talks to.

## Scope

In scope, for the sidecar crate:

- The two newer server modes: **direct** (`-listen-direct`: the RTP wrap
  only, no DTLS) and the **WireGuard** data path through it. The server's
  original mode wraps DTLS inside the RTP wrap; qWDTT's own client calls
  that DTLS "pure overhead" (`go_client/session.go:42-50`) and the sidecar
  does not implement it.
- The TURN client: allocation, permission, channel binding, refresh, over
  UDP and over TCP.
- The worker group: several TURN allocations per call hash, with qWDTT's
  striping of packets across them.
- The text handshake that fetches the WireGuard configuration and
  authenticates each worker.
- A loopback UDP endpoint for shoes (or any WireGuard) to send to.
- A credential-provider interface: TURN credentials in, from whatever
  obtains them.
- A plain HTTPS implementation of VK's anonymous call-join, behind a
  feature flag, for headless use where no app can show a captcha.

Out of scope, and why, in "Out of scope" below: the DTLS mode, the raw-IP
mode, VK captcha solving, VK account login, and any change to shoes'
WireGuard outbound.

## What the references do

### The client (`go_client/`)

**Credentials** (`creds.go`, `creds_vkcalls.go`). A worker group needs a
TURN username, credential and relay list. The default path
(`-vk-anon-path vkcalls`) joins a VK call anonymously in five HTTPS
requests (`creds_vkcalls.go:184-300`):

1. `api.vk.me/method/auth.getAnonymToken` with VK Calls' web client id
   (`vkConnectClientID = "8093730"`, `creds_vkcalls.go:22`), the call
   link `https://vk.com/call/join/<hash>`, a fresh device UUID and a
   random display name; returns an anonymous token.
2. `messages.getCallPreview` with that token; returns a `user_id` and a
   `secret`.
3. `messages.getAnonymCallToken` with both; returns a token for OK's call
   backend.
4. `calls.okcdn.ru/fb.do?method=auth.anonymLogin` with a fixed
   `application_key`; returns a `session_key`.
5. `vchat.joinConversationByLink` with the hash, the OK token and the
   session key; returns `turn_server.{username, credential, urls[]}`.
   The URLs are `turn:host:port?transport=...`, cut at the `?`
   (`creds_vkcalls.go:332-345`).

The requests go through `bogdanfinn/tls-client` with a Chrome 146 TLS and
HTTP/2 fingerprint and one of nine browser profiles (`profiles.go`).
Credentials live ten minutes and are cached for nine
(`creds.go:118-119`); fetches are serialised and spaced three to six
seconds apart (`creds.go:282`); three authentication errors within ten
seconds invalidate the cache (`creds.go:189-212`). VK answers a suspected
bot with error 14, a captcha: the client either solves VK's
proof-of-work-and-slider captcha itself (`captcha_v2.go`, 819 lines, plus
`captcha_v2_slider.go`) or asks the Android app to show it in a WebView
(`creds.go:714`). A legacy path (`-vk-anon-path legacy`) uses `api.vk.ru`
with two of VK's own application id and secret pairs (`creds.go:33-36`).
An "account" mode takes credentials the Android app obtained from a
logged-in VK session, over stdin (`vk_account.go:48-49`), with a
nine-minute life (`vk_account.go:16`).

**TURN** (`session.go`). Each worker dials one relay from the list, UDP by
default or TCP with `-turn-tcp` for networks that throttle UDP to the
relay (`session.go:124-156`); TCP uses `pion/turn`'s `NewSTUNConn`, which
frames STUN and ChannelData messages on a stream. It builds a `pion/turn`
client with the credentials, allocates (`session.go:254`), and sends a
STUN Binding request every ten seconds to keep the NAT mapping
(`session.go:280-290`). pion creates a permission for the peer on the
first write and binds a channel, so data travels as ChannelData frames,
four bytes of header per datagram. Allocations across a group are gated
to one per 100 ms (`group.go:16`) because VK counts them against a quota
and refuses with error 486 (`session.go:259-262`).

**The wrap** (`obfs.go`, `wrap.go`). Every datagram on the relay is an
RTP-looking packet, the only layer in direct mode (`session.go:51-99`):

```
[RTP header 12 B][ChaCha20-Poly1305 ciphertext + 16 B tag][padding 0..N][pad length 1 B]
```

- Byte 0 is `0x80 | 0x20`: version 2, padding bit set, no extension, no
  CSRCs. Byte 1 is the payload type, 111 for the "audio" mode (OPUS) or
  96 for "video" (`obfs.go:122-138`, `obfs.go:241-242`).
- Sequence and timestamp come from a per-direction counter `c`:
  `seq = initSeq + c` (16-bit), `ts = initTs + c*960 + (c >> 16)`
  (`obfs.go:216-217`), with random initial values (`obfs.go:160-168`);
  960 is one 20 ms OPUS frame at 48 kHz. The SSRC is random per session.
- The nonce is the header's fields, `SSRC(4) | seq(2) | 00 00 | ts(4)`
  (`obfs.go:177-184`), and the 12-byte header is the associated data
  (`obfs.go:251`). The key is 32 bytes from HKDF-SHA256 with the
  connection password as input keying material, salt `WDTT-WRAP-v1` and
  info `rtp-obfs/chacha20poly1305` (`wrap.go:18-32`).
- Padding is `rand % PaddingMax` random bytes, 24 for audio and 60 for
  video, and the last byte holds the padding count including itself
  (`obfs.go:223-262`), as RFC 3550 §5.1 defines.
- A receiver accepts a packet if the version is 2 and the payload type is
  111 or 96 (`obfs.go:338-349`), honours an extension bit by skipping a
  24-byte header (older servers sent one, `obfs.go:186-194`,
  `obfs.go:285-292`), strips the padding, decrypts, and runs a replay
  window keyed by the nonce over an extended timestamp, spanning
  4096 × 961 ticks and at most 8192 entries, with the SSRC fixed for the
  connection (`obfs.go:34-99`).
- A keepalive is a frame of 25 to 44 bytes of `0xFF` every ten seconds,
  wrapped like any other (`session.go:29-39`, `session.go:556-575`); the
  server's one-byte `0xFF` answer is dropped on read
  (`session.go:670-672`).

**The handshake** (`protocol.go`). The first plaintext a worker sends is
text. One worker per group sends
`GETCONF:<localPort>|<deviceID>|<password>` and receives a wg-quick
configuration (private key, address, DNS, the server's public key,
endpoint, keepalive), or `NOCONF`, or `DENIED:<reason>` with reasons
`wrong_password`, `expired`, `device_mismatch`, `deactivated`
(`protocol.go:12-48`). The other workers send
`AUTH:<deviceID>|<password>` (`protocol.go:51-58`). In raw mode the
request is `GETCONF_RAW:<deviceID>|<password>` and the answer
`RAWCONF:<ip>|<dns>|<mtu>` (`protocol.go:63-108`).

**The dispatcher** (`dispatcher.go`, `group.go`). A group is nine workers
with one set of credentials (`group.go:14`); a profile's `workers` field
multiplies that, and the published profiles use 18. The client's local
UDP socket (`-listen 127.0.0.1:9000`) receives WireGuard datagrams from
the phone's WireGuard and distributes them across workers in runs: 64
consecutive packets to one worker when they exceed 1100 bytes, 24 from
701, 8 from 301, 3 from 101, else 1 (`dispatcher.go:68-83`), moving on
after 15 ms regardless (`dispatcher.go:46`), with packets of 128 bytes or
less on a separate priority queue per worker so acknowledgements do not
wait behind a run of data (`dispatcher.go:52`). The reason is given in
the source: round-robin per packet across relays of different latency
reorders TCP inside the tunnel into congestion collapse
(`dispatcher.go:56-66`). The downlink buffer is 512 packets, sized to the
bandwidth-delay product at 70–80 Mbit/s and 50–60 ms
(`dispatcher.go:35-39`).

**Modes** (`main.go:163-189`). `-mode vpn` hands the datagrams to the
system WireGuard through the local port; `-mode socks` runs
`wireguard-go`'s netstack in-process and serves SOCKS5 (`socks_wg.go`);
`-mode rawtun` skips WireGuard and writes raw IP packets to a TUN the app
passes in. `-notls` selects the direct mode; `-obfs audio|video` the
payload type.

### The server (`server/`)

`wdtt-server` listens on three UDP addresses (`main.go:26-28`): `-listen`
(default `:56000`) for the DTLS mode, `-listen-direct` for the wrap-only
mode, `-listen-raw` for raw IP. On the direct listener it trial-decrypts
each new source's first packet against every connection password it knows
(`obfs.go:354-392`, `keys.Unwrap`), remembers the key for that source,
and ties the password in the text handshake to the key that decrypted it
(`obfs.go:333-341`), so a `GETCONF` with another user's password is
refused. Handshake handling is in `connections.go:102-404` and
`raw.go:312-538`. WireGuard runs in userspace (`wireguard-go`) on an
interface `wdtt0`, `10.66.0.0/16`, MTU 1280, keepalive 25
(`core.go:3-9`), bound to loopback only (`wireguard.go:17-61`): a client's
WireGuard datagrams reach it through the server's own loopback hop. Raw
mode uses a second TUN at MTU 1300 (`core.go:12-22`). A Telegram bot and
an admin API manage passwords (`database_bot.go`, `admin_api.go`).

### The Android app and the siblings

The app runs the Go client as a child process and feeds it over stdin:
the TUN descriptor in raw mode, captcha results, account credentials. A
profile is `qwdtt://config?name=&peer=&hashes=&workers=&port=&pass=`
(`app/src/main/java/com/wdtt/client/ui/profiles/ExportProfileSheet.kt:55`,
parsed at `.../profiles/SubscriptionImport.kt:167-180`): the VPS
address, one or more VK call hashes, workers per hash, the local port and
the connection password. pwdtt is the same client with a desktop UI and a
local WireGuard interface. WireTurn runs the qWDTT core beside Xray and
calls it, in its README, "WireGuard over a DTLS relay with a local SOCKS5
on the client". wdtt-suite is the Go client cross-built for a Keenetic.
All four are the sidecar pattern already: a process that owns the VK side
and hands WireGuard a port.

## Protocol summary

What the sidecar speaks, from the above, in order:

1. Obtain TURN credentials (username, credential, relay URLs, expiry) from
   the provider.
2. For each worker: connect to a relay over UDP or TCP; Allocate with the
   long-term credential mechanism; Binding request every 10 s; permission
   and channel for the WDTT server's direct address.
3. On the first write, `GETCONF:<port>|<device>|<password>` on one worker
   and `AUTH:<device>|<password>` on the rest, each wrapped; parse the
   wg-quick answer; hand it to the user once.
4. Thereafter every datagram from the loopback socket is wrapped and sent
   through the worker the dispatcher picks; every wrapped datagram from a
   relay is unwrapped and written to the loopback peer.
5. A 25–44 byte `0xFF` keepalive every 10 s per worker; the server's
   `0xFF` byte is dropped.
6. Credentials are refreshed a minute before expiry and on a TURN
   authentication failure; a refused worker reconnects with the new ones.

## Architecture

### Where it plugs in

Nothing changes in shoes. The hop is the existing `wireguard` outbound
(`CONFIG.md`, "WireGuard Client"), whose endpoint is the hop's `address`
(`src/amneziawg/connector.rs:216` resolves it), pointed at the sidecar's
loopback port:

```yaml
client_chain:
  address: "127.0.0.1:9000"        # the sidecar
  protocol:
    type: wireguard
    private_key: ...                # from the server's GETCONF answer
    peer_public_key: ...
    local_addresses: ["10.66.0.7/32"]
    allowed_ips: ["0.0.0.0/0"]
    persistent_keepalive: 25
    mtu: 1280
```

The WireGuard tunnel's endpoint socket (`src/amneziawg/endpoint.rs`),
its liveness watchdog (`src/amneziawg/tunnel.rs:127-200`) and the stopped
callback behave as for any endpoint. A sidecar that loses every relay
stops delivering; the watchdog sees silence, asks for a rebind, and ends
the session the way it does for a dead AmneziaWG server. That is the
failure signal, and it needs no new channel.

The alternative of a SOCKS5 sidecar (qWDTT's `-mode socks`) was weighed
and left: it needs a userspace TCP/IP stack inside the sidecar to turn raw
IP or WireGuard-decrypted packets into streams, which duplicates
`src/netstack.rs`, and it would lose shoes' routing of UDP through the
same tunnel. Handing WireGuard datagrams across keeps the netstack, the
rules and the watchdog in one place.

### The crate

`wdtt` (working name), MIT, its own repository. Modules:

| Module | Does | Reference |
| --- | --- | --- |
| `wrap` | The RTP wrap and unwrap, nonce, padding, replay window, keepalive frames, HKDF key | `go_client/obfs.go`, `wrap.go` |
| `turn` | Allocation, permission, channel, refresh, Binding keepalive; UDP and the TCP framing | `go_client/session.go:124-290`, RFC 5766 |
| `worker` | One relay connection: TURN + wrap + keepalive + the per-worker handshake | `go_client/session.go:158-700` |
| `group` | N workers on one credential set, the allocation gate, refresh on expiry or auth failure | `go_client/group.go` |
| `dispatch` | The loopback UDP socket, run-based striping, priority lane, the downlink queue | `go_client/dispatcher.go` |
| `handshake` | `GETCONF`/`AUTH` text, the wg-quick parse, `DENIED` reasons | `go_client/protocol.go` |
| `provider` | The credential-provider trait; a `static` provider (credentials in the config); `vk-anon` behind a feature, plain HTTPS | `go_client/creds_vkcalls.go` |
| `bin/wdtt` | The CLI: config file, `--print-wg-config`, logging | `go_client/main.go` |

Crates: `turn` 0.17 (webrtc-rs, MIT/Apache-2.0, tokio) for the TURN client
if its connection abstraction takes a TCP stream with our framing, else a
client of our own, which is a few hundred lines since STUN is simple;
`chacha20poly1305`, `hkdf`, `sha2`, `tokio`; `reqwest` with rustls only
under the `vk-anon` feature.

### Per platform

- **Desktop and `shoesd`:** a process. The daemon or the user starts it
  before the tunnel; the config names the sidecar's port.
- **Android:** a thread in the app's process through a small JNI surface,
  or a native binary the app executes, which is how qWDTT runs its Go
  client. The loopback socket is not routed through the tunnel, so it
  needs no protection; the relay sockets do, and the crate takes a
  protect callback as shoes' `socket_util::protect_outbound` does.
- **iOS:** a Network Extension cannot spawn a process, so the crate is
  linked into the extension and started on a thread. Shoes and the
  sidecar then share one process and still talk over loopback, which is
  what the protocol expects on the phone anyway.

### The credential provider

```rust
trait CredentialProvider {
    async fn fetch(&self, hash: &str) -> Result<TurnCredentials, ProviderError>;
}
struct TurnCredentials { username: String, credential: Redacted<String>,
                         relays: Vec<RelayUrl>, expires_at: Instant }
```

The group calls `fetch` at start, a minute before `expires_at`, and after
a TURN authentication failure, with the same serialisation and spacing
qWDTT applies (one fetch at a time, three to six seconds apart), because
the quota is VK's and the throttle is what keeps a user under it.

The providers that matter are the apps': on Android and desktop, Kotlin
in KVN's shared module, with a WebView (or the system browser) for VK's
captcha; on iOS, the container app with `WKWebView`, and `URLSession` in
the extension for the refreshes that need no captcha. The `vk-anon`
provider in the crate is for headless hosts and accepts that it cannot
solve a captcha: it reports error 14 as a `ProviderError::Captcha` and
the operator uses a different host or a logged-in session's credentials
in the static provider.

## Configuration

The sidecar's own file, YAML to match shoes:

```yaml
listen: 127.0.0.1:9000          # where shoes' wireguard outbound sends
server: 203.0.113.5:56001       # wdtt-server's -listen-direct address
password: ...                   # the connection password (Redacted)
device_id: ...                  # stable per install; the server binds passwords to it
hashes: [ "<vk call hash>" ]    # one group per hash
workers: 9                      # per hash; qWDTT ships 18 in its profiles
transport: udp                  # or tcp, to the relay
payload_type: audio             # or video: PT 96 and up to 60 bytes of padding
credentials:                    # the provider
  vk_anon: {}                   # feature-gated; or
  static: { username: ..., credential: ..., relays: [...], expires_at: ... }
```

`wdtt --print-wg-config` performs one `GETCONF` and prints the wg-quick
text the user turns into the shoes hop; `--qwdtt-link` imports a
`qwdtt://config?...` profile into this file. Limits follow the reference:
`workers` 1 to 32 per hash, `payload_type` from the two the server
accepts (`server/obfs.go` sets padding by the type it sees), `password`
non-empty since the key is derived from it.

## Performance

Per packet, uplink: one AEAD seal in place into a reusable buffer, a
4-byte ChannelData header, one `send`. Downlink the reverse. No allocation
and no task per packet; one task per worker reading its relay, one for
the loopback socket; every queue bounded, with the uplink queue per
worker dropping on full as UDP should and the downlink queue of 512
sized as qWDTT's.

On the wire a 1280-byte WireGuard-inner packet becomes 1280 + 32
(WireGuard) + 12 + 16 + up to 25 (audio padding and count) + 4
(ChannelData) = at most 1369 bytes; video padding adds 36 more. Both fit
1500 without fragmentation, as `server/core.go:16-21` reasons for raw
mode. The `wireguard` hop's `mtu: 1280` is right as it stands.

The run-based striping is the part that decides throughput, and it is
copied as behaviour: qWDTT measured single-flow collapse with per-packet
round-robin and settled on the run sizes above. The sidecar keeps them as
constants with the reasoning in a comment, and the benchmark arm in
`scripts/bench/tunnels.py` gets a WDTT case against a local double so a
change to the constants is measured, not argued.

## Security

- The wrap gives confidentiality and integrity per datagram under a
  static password-derived key; it has no forward secrecy and no
  handshake. That is acceptable only because WireGuard inside it has
  both. The sidecar therefore refuses to carry anything but the loopback
  socket's datagrams, which are WireGuard's.
- The replay window is per worker and per SSRC, as the reference's; a
  packet outside the window or already seen is dropped and counted.
- The connection password authenticates the client to the server and
  derives the wrap key. It is `Redacted` in config and never in a log or
  error; a `DENIED:<reason>` is reported as the reason, not the password.
  TURN credentials are redacted the same way.
- The `vk-anon` provider carries VK Calls' public web client id and OK's
  application key, as every WDTT client does. They are not secrets, but
  they are VK's, and the provider is the only place they live.
- The relay is VK's and used outside its intended purpose. The sidecar
  does what the reference does to stay unremarkable (the allocation gate,
  the fetch spacing, the keepalive shape) and no more; a user accepts that
  VK may refuse service.
- Nothing from a live test enters the repository.

## Error handling

| Condition | What the sidecar does |
| --- | --- |
| Provider fails, or returns a captcha | Logs the kind; retries with backoff up to the credential's remaining life; after that the group stops and the loopback socket goes silent, which shoes' watchdog turns into a stopped session |
| TURN 401 or stale nonce | Counts it as the reference does; three in ten seconds invalidate the credentials and trigger a fetch |
| TURN 486 (quota) | Backs the allocation gate off to one per second and logs once; a group that cannot allocate any worker stops |
| `DENIED:<reason>` | Fatal for that password: reported to the operator with the reason, no retry |
| `NOCONF` | The server has not assigned this device; reported, no retry |
| A worker's relay goes quiet (no keepalive answer for 60 s) | The worker reconnects and re-allocates; the dispatcher skips it meanwhile |
| Every worker gone | The group reconnects with fresh credentials; the loopback socket stays open so shoes' WireGuard keeps retrying its handshake |
| A datagram that does not unwrap | Dropped and counted, never logged with content |
| Network change (the host tells the sidecar, or TCP relays break) | All workers reconnect; shoes' WireGuard rehandshakes on its own |

## Testing

- **Known-answer tests** for the wrap: vectors produced by running
  `obfsWrapPacket` and `deriveWrapKey` from the reference once, with fixed
  key, SSRC, counters and padding bytes, kept as `tests/data/kat/wdtt/`
  with the script that made them; the unwrap of each, and rejection of a
  wrong key, a wrong payload type, a bad pad byte, a replayed nonce.
- **The TURN layer** against an in-process relay: the `turn` crate ships a
  server, usable as a dev-dependency; the test checks Allocate with the
  long-term credential, a Refresh, a channel bind, a 486 answer, and the
  TCP framing round-trip.
- **End to end** against a server double in the crate: it takes wrapped
  datagrams from the relay, trial-decrypts as the server does, answers
  `GETCONF`/`AUTH`/`DENIED`, answers keepalives, and echoes WireGuard
  datagrams back, so the loopback endpoint is tested as a datagram pipe
  with shoes out of the picture. Striping is checked by counting which
  worker carried which packet. Every test proves it can fail first, in
  the shape AGENTS.md asks for.
- **With shoes:** one test in shoes is not needed; a live run is. A
  `wdtt-server` in a container on a VPS the user owns, a call hash the
  user creates, the sidecar on the workstation and `shoes` with the
  `wireguard` hop pointed at it, recorded in words per
  `.agent/skills/live-interop-check/`. The questions that only a live run
  answers: whether VK's relays pass the sidecar's TLS-less HTTPS client
  without a captcha on a given network, what throughput nine workers give
  from here, and whether TCP to the relay is needed.

## Out of scope

- **The DTLS mode.** The server's default listener. The reference client
  avoids it, there is no DTLS stack in shoes, and a user who controls the
  server enables `-listen-direct`.
- **The raw-IP mode.** It saves WireGuard's 32 bytes per packet and
  removes a layer; it also removes WireGuard's handshake and forward
  secrecy and needs the netstack in the sidecar. If it is ever wanted, it
  is a `type: wdtt` outbound in shoes, not a sidecar.
- **Captcha solving and VK account login.** Both belong to an app with a
  screen; the provider trait is where they plug in.
- **Changes to shoes' `wireguard` outbound.** None are needed. A note in
  `CONFIG.md` that the endpoint may be loopback, and a pointer to this
  document, are documentation.
- **Keeping up with the reference.** The sidecar tracks the direct mode
  as of the version read; a later server change is a later change here.

## Order of work

Not scheduled. If it is picked up:

1. `wrap` with its known-answer tests, and `handshake` with its parser.
2. `turn` over UDP against the in-process relay, then the TCP framing.
3. `worker`, `group`, `dispatch` and the server double; the striping
   test; the CLI with the static provider and `--print-wg-config`.
4. The live run with shoes, and the benchmark case.
5. The `vk-anon` provider.
6. KVN's providers, in KVN.

**Difficulty.** 3 of 5 for steps 1 to 4, about 3,500 lines including
tests, against SSTP's 2 (4,800 lines, in-tree, two days) and OpenConnect's
planned 3. The difficulty is not the protocol, which is small, but the
absence of a specification and the dependence on a third party's relay
and anti-bot policy, which no test in the crate can stand in for.
