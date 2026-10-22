# Lessons from steer: correctness, fingerprint and Brutal

Written 2026-10-21 against `mobile` at `bf5d5a6`. The source is a review of
[splify2/steer](https://github.com/splify2/steer) at `07303cb` (2.0.6, 15 Oct
2026). steer is a C routing core for OpenWrt with its own clients for
VLESS/REALITY, Hysteria2, trojan, Shadowsocks and VMess.

**steer is GPL-3.0 and shoes is MIT.** Nothing here is, or may become, code
taken from steer. Each item states a behaviour and a reason, and gives steer's
file only as the place the lesson was learned. Where steer is the authority
for a behaviour, the behaviour is checked against the protocol's own reference
(Xray, sing-box, apernet) before it is implemented.

Each finding has an ID, SF-n. The plan
(`docs/plans/2026-10-21-lessons-from-steer.md`) orders them into PRs.

## Summary

| ID | What | Kind | Size |
|---|---|---|---|
| SF-1 | A fake IP can be recycled while an app still holds it | bug | S |
| SF-2 | An in-pool address with no mapping is dialled as a literal 198.18.x.x | bug | S |
| SF-3 | Local names get fake IPs and go into the tunnel | default | S |
| SF-4 | REALITY with no SNI panics; an empty SNI cannot be expressed | bug | S |
| SF-5 | Only version-4 UUIDs load; Xray's string ids do not | compat | S |
| SF-6 | No fallback when a path drops the post-quantum ClientHello | resilience | M |
| SF-7 | AES-first cipher order on CPUs without AES instructions | perf | XS |
| SF-8 | No User-Agent on WebSocket and HTTPUpgrade requests | fingerprint | S |
| SF-9 | Brutal congestion control and its negotiation | feature | L |
| SF-10 | Probe and interop test methods for PR 4.3 | tests | (in 4.3) |
| SF-11 | Deferred: xhttp, gRPC, ECH, REALITY `pqv`, Gecko, DoQ | backlog | — |

## SF-1 — fake-IP recycling

**Fixed in #99.**

**Today.** When the pool is full, `FakeIpPool::assign` reuses the address of
the least recently *assigned* domain (`src/dns/fake_ip/pool.rs:184-215`). Only
`assign`, which DNS answers call, counts as use. `lookup`, which the connect
path calls (`pool.rs:225`), does not. So a domain whose address is in steady
use loses it after enough other names are resolved. An app that cached the
answer past its 1-second TTL can then connect to the same address and reach
**a different domain's** server, through that domain's rule. This misroutes
the connection and leaks it to the wrong destination.

**Required behaviour.**

1. `lookup` marks the mapping as used, the same way `assign` does.
2. An address is not reused while it is younger than `MIN_REUSE_AGE` (600 s)
   since its last use. If the least recently used mapping is younger than
   that, the pool is exhausted for this query:
   - The DNS answer is the **real** answer, forwarded to the upstream as a
     bypassed name would be. The routing rule for that name does not apply to
     this one connection, and a warning is logged once per exhaustion episode.
   - This is steer's fail-open (`src/dnsd/fakeip.c:281-309`). Failing open
     costs one connection its domain rule. Failing closed would cost it the
     connection. Recycling a hot address costs another domain's privacy, and
     that is the outcome this item removes.
3. A recycled address keeps no trace of its previous domain. This is already
   true; a test pins it.

**Tests.** A pool of 4: assign a–d, keep `lookup`ing a, assign e and check
that b, not a, was recycled. A pool whose mappings are all used within
`MIN_REUSE_AGE` answers e with the real address. Use tokio's paused time and
no wall clock.

## SF-2 — an in-pool address with no mapping

**Fixed in #99.**

**Today.** `destination_to_net_location` (`src/dns/fake_ip/mod.rs:55-72`)
falls through to the literal address when `lookup` returns `None`. That
happens after a restart (the table is in memory) or after a recycle. The
connection is dialled to 198.18.x.x, goes nowhere, and stalls until the
app's timeout.

**Required behaviour.** A destination inside the pool with no mapping is
refused at once:

- TCP: the netstack answers the SYN with RST.
- UDP: the datagram is dropped.

Both are counted and logged at debug, at most once a second. The app sees
the failure immediately and resolves again, which reaches the DNS
interception and gets a fresh mapping.

**Not now.** steer saves the table across restarts (`fakeip.c:139-275`). The
case for that is an iOS network-extension restart while apps hold
addresses. Refusing quickly covers it well enough. Reconsider persistence only
if a device run shows apps that do not re-resolve after a reset.

**Tests.** A TUN test connects to an unmapped in-pool address: it gets a
reset, and no outbound dial is made. A mapped address still connects.

## SF-3 — local names bypass fake IP by default

**Fixed in #99.**

**Today.** `bypass_domains` is empty unless configured (`src/tun/mod.rs:689`).
`printer`, `nas.lan` and `_ipp._tcp.local` get fake IPs and are routed into
the tunnel, where they cannot resolve.

**Required behaviour.** With fake IP on, these always resolve for real,
before the user's list is consulted:

- single-label names;
- names ending in `.local`, `.lan`, `.home.arpa`, `.internal`, `.localhost`,
  `.localdomain` or `.home`;
- `in-addr.arpa` and `ip6.arpa`.

"Resolve for real" means what a `bypass_domains` match already means: the
query is forwarded along the rules for the resolver address it was sent to.
It is not forced direct. steer runs beside the router's dnsmasq and can
always hand these to it; shoes on a phone does not know the LAN's
resolver, and forcing only the query direct would produce an answer whose
connection then follows the rules anyway. Reaching LAN hosts takes a direct
rule for the private ranges, which carries the query to the router and the
connection after it. CONFIG.md and `examples/tun_fake_ip.yaml` say so
(review on #99).

The user's `bypass_domains` adds to this list. `bypass_defaults: false` turns
the built-in list off for anyone who really wants these names tunnelled.
steer applies the same list (`src/dnsd/proxy.c:620-633`). The list follows
RFC 6762 (`.local`), RFC 8375 (`home.arpa`) and ICANN's 2024 reservation of
`.internal`.

**Tests.** Each built-in suffix bypasses; `bypass_defaults: false` turns them
off; a user entry still works with the defaults on.

## SF-4 — REALITY SNI: missing, empty, or an IP address

**Fixed in #100.**

**Today.** A REALITY client with no `sni_hostname` panics at config build
(`src/tcp/tcp_client_handler_factory.rs:271`). An empty string reaches an
`unwrap` on `ServerName::try_from`. Xray's REALITY server allows `""` in
`serverNames`, and its client then sends a ClientHello with no `server_name`
extension. steer reports a real subscription that depends on this
(`src/proto/tls/reality.c`, the server_name block).

**Required behaviour.**

- A missing `sni_hostname` is a config error, not a panic.
- `sni_hostname: ""` builds a ClientHello without the `server_name`
  extension.
- An IP-address `sni_hostname` also leaves the extension out, as Chrome does
  for an IP literal.
- The REALITY auth and certificate checks do not depend on the SNI, so
  nothing else changes. Check that `reality_client_verify.rs` doesn't
  compare against it.

**Server side.** shoes' REALITY server looked a hello without a name up as
"no SNI" and went straight to `default_tls_target`. It now tries the target
keyed `""` first (`tls_server_handler.rs` `select_target`), as both servers look the name up in their names map, and Go's parsed
hello has `serverName == ""` when the extension is absent: XTLS/REALITY
`tls.go` (`config.ServerNames[hs.clientHello.serverName]`), and
metacubex/utls v1.8.7 `reality.go:385`, which sing-box uses.

**Tests.** The config error. A hello built with `""` has no extension type 0,
and the rest of the hello is unchanged. The server test from #95 accepts a
hello without SNI when its `server_names` contains `""`; this needs that
server-side option if it doesn't exist yet.

## SF-5 — user ids beyond UUIDv4

**Fixed in #100.**

**Today.** `parse_uuid` (`src/uuid_util.rs:14-58`) accepts only hex and
refuses any version but 4. `config/types/uuid.rs` applies it to VLESS,
VMess and TUIC. So UUIDv7 ids fail to load, as do the string ids panels issue
(`TMG_74317ba5f91`).

**Required behaviour** (Xray's `common/uuid` rule, which steer follows in
`src/proto/vless/vless_proto.c:114-150`; confirm against Xray and sing-box
before implementing):

- 32 hex digits, with or without the four dashes: accepted as given, **any
  version and variant**.
- 1 to 30 characters of anything else: the id is
  `SHA-1(16 zero bytes ‖ string)[0..16]`, with the version nibble set to 5
  and the RFC 4122 variant bits set. This is a UUIDv5 in the nil namespace.
- 31 characters, or more than 36: a config error.
- Applies to VLESS and VMess, which both references treat this way. For
  TUIC, keep hex-only but drop the version check: sing-box's TUIC parses
  strictly.

**Tests.** A known-answer vector for the string rule, from the KAT generator
(`tests/data/kat/gen`) calling the reference's own function. A UUIDv7 loads.
The 31-character case is rejected.

**What the references do (checked 2026-10-22).**

- Xray `common/uuid/uuid.go` `ParseString`: an id of 32 to 36 bytes is
  parsed as hex groups 8-4-4-4-12, each optionally preceded by a dash. One
  of 1 to 30 bytes is `SHA-1(uuid.Nil ‖ name)[:16]`, with
  `u[6] = u[6]&0x0f | 0x50` and `u[8] = u[8]&0x3f | 0x80`. 0, 31 or more
  than 36 bytes is an error. Lengths are in bytes, so a non-ASCII name
  reaches the limit sooner.
- sing-vmess `vless/client.go` and `client.go` `NewClient`:
  `uuid.FromString(id)`, and on any error `uuid.NewV5(uuid.Nil, id)` (gofrs
  uuid). That is the same id for the same name, with **no length limit**: a
  31-byte or 40-byte name loads in sing-box and is refused by Xray.

shoes follows Xray's limits. A name only sing-box accepts would not work
against an Xray server. The `user-id` vector comes from gofrs `NewV5` in the
KAT generator, and includes a non-ASCII name.

## SF-6 — fall back from the post-quantum ClientHello

**Today.** The REALITY client always offers X25519MLKEM768
(`src/reality/reality_client_connection.rs:321-342`). The rustls paths offer
it first by default (ROADMAP, "Open risk: TLS fingerprinting"). Some DPI
boxes, reported on Russian networks, silently drop a connection whose
ClientHello carries the ML-KEM share. That hello is about 1.8 kB and spans
two TCP segments. On such a path every connection times out, with nothing to
say why. steer retries without the share and remembers the result
(`src/proto/transport/trsec.c:178-276`).

**Required behaviour.** A per-outbound option `post_quantum: auto | on | off`,
default `auto`:

- `on` always offers the hybrid group. `off` never does. Both are today's
  REALITY behaviour (`on`) and a classical-only hello (`off`).
- `auto`:
  1. The first attempt offers the hybrid group.
  2. If it fails **before any byte arrives from the server** (a timeout or a
     reset during the handshake), one immediate retry goes out with an
     X25519-only hello. It is otherwise the same: same cipher list, same
     extension set without the hybrid share, and fresh randomness.
  3. If the retry succeeds, the server's address is remembered as
     classical-only for one hour, in memory. Later connections to it skip
     straight to the classical hello. When the hour expires, the hybrid hello
     is tried again.
  4. If both attempts fail, nothing is remembered, so a dead server doesn't
     switch post-quantum off. The **first** attempt's error is the one
     reported.
- REALITY first. The rustls client config (`src/rustls_config_util.rs`)
  gets the same option in a second step, through its key-exchange group
  list.
- The memory is per process and keyed by resolved address and port. Nothing
  persists across restarts.

**Fingerprint note.** Without the share, the hello is Chrome's shape with
classical groups only. That is what Chrome sends with its post-quantum flag
off, so it doesn't create a new signature.

**Tests.** A local listener that drops a hello above 1500 bytes but answers
a smaller one: `auto` connects on the second attempt, and the next connection
sends the small hello first. A listener that drops everything leaves nothing
remembered and returns the first error. `on` and `off` never retry.

## SF-7 — ChaCha20 first without AES hardware

**Today.** `DEFAULT_CIPHER_SUITES` (`src/reality/reality_cipher_suite.rs:14-18`)
puts AES-GCM first everywhere. On a CPU without AES instructions, AES-GCM in
software is several times slower than ChaCha20. steer measured about 6× on
MIPS. Some low-end Android arm64 chips (Cortex-A53 without the crypto
extension) and most armv7 devices lack AES. Chrome (BoringSSL) puts ChaCha20
first on such hardware, and a Go server follows the client's order.

**Required behaviour.**

- At start-up, detect AES support:
  - aarch64: `is_aarch64_feature_detected!("aes")`;
  - x86/x86_64: `is_x86_feature_detected!("aes")`;
  - any other architecture: treat it as having no AES.
- Without AES, put `CHACHA20_POLY1305_SHA256` first in the REALITY hello's
  TLS 1.3 suites and in the rustls client's suite order.
- A configured `cipher_suites` still wins.

**Tests.** A unit test of the ordering function with the detection injected.

## SF-8 — headers on WebSocket and HTTPUpgrade requests

**Today.** The client request carries only Host, Upgrade, Connection and the
WebSocket keys (`src/websocket/websocket_handler.rs:321-365`,
`src/httpupgrade/client.rs:54-71`). There is no User-Agent at all. Xray sends
a Chrome User-Agent plus Chrome's client-hint and fetch headers, and sing-box
sends Go's. A request with none matches neither population and is its own
signature.

**Required behaviour.**

- When the user's `headers` set no `User-Agent`, send a Chrome User-Agent
  for the Chrome version the REALITY hello imitates (133, see
  `docs/specs/2026-10-19-reality-chrome-client-hello.md`). This keeps the
  HTTP layer consistent with the TLS layer beneath it.
- Order the headers the way Xray does: Host, then User-Agent, then the rest.
  Before choosing the client-hint and fetch headers, confirm Xray's exact set
  from a capture, made with the frame generator from #96.
- A user-set `User-Agent` replaces the default and is never duplicated.
  `headers: { User-Agent: "" }` sends none.

**Tests.** The request bytes, with and without a user User-Agent. A
golden-file test of the request against the reference capture.

## SF-9 — Brutal

The headline Hysteria feature (ROADMAP, "Performance"). Today the client
always sends `Hysteria-CC-RX: 0` (`src/hysteria2/auth.rs:35`), the server
always answers `auto` (`src/hysteria2/server.rs:186`), and both ends run BBR
(`src/quic_transport/mod.rs:53-66`). The algorithm is apernet's
(`core/internal/congestion/brutal`). steer's port to ngtcp2
(`build/ngtcp2/patches/0001-brutal-congestion-control.patch`) is where the
details below were checked, so the spec is written against apernet's
behaviour, not steer's code.

### Negotiation

Configuration, on both client and server: `bandwidth: { up, down }`, each a
rate string (`"100 mbps"`, `"12.5 MB/s"`) or absent.

- **Client.**
  - The auth request carries `Hysteria-CC-RX: <down in bytes/s>`, or `0`
    when `down` is unset ("I don't know my receive rate").
  - From the auth response's `Hysteria-CC-RX`, the client picks its own
    sending controller:
    - `up` unset: BBR.
    - The response says `auto`: BBR.
    - The response is `0`: Brutal at `up`. This is apernet's rule; Xray
      treats 0 as BBR, which we don't follow.
    - The response is `n > 0`: Brutal at `min(up, n)`.
- **Server.**
  - The auth response carries `Hysteria-CC-RX: <server down>`, or `auto`
    when the server's `down` is unset.
  - The server's sending controller toward that client:
    - the client sent `0`: BBR;
    - the server's `up` is unset: Brutal at the client's rate;
    - otherwise: Brutal at `min(server up, client rate)`.
- **Bounds.** Rates are capped at 2³¹ bytes/s (16 Gbit/s), so that
  rate × RTT cannot overflow, and below at 64 kB/s.

### The controller (quinn `Controller`)

quinn chooses the controller when the connection is created, but the rate is
only known after authentication. So the factory builds a **switchable**
controller:

- It runs BBR until told otherwise.
- It holds a shared handle (`Arc<AtomicU64>`, bytes/s, 0 meaning BBR) that
  the auth code sets once.
- On the next call after the handle changes, it moves to Brutal (or stays on
  BBR). The handle is never set twice.

Brutal state:

- `rate`: target bytes per second.
- `ack_rate` in [0.8, 1.0], computed as below.
- Five one-second slots, each `{second, acked, lost}`.

**Counting.** quinn reports bytes, not packets, so count bytes:

- `on_ack(now, sent, bytes, …)` adds `bytes` to `acked` in the slot for
  `now` (in whole seconds, mod 5).
- `on_congestion_event(now, sent, persistent, lost_bytes)` adds `lost_bytes`
  to `lost`.
- A slot whose stored second differs from the current one is reset before
  it is used.

**ack_rate.**

- Sum `acked` and `lost` over the slots no older than 5 s.
- Below 50 packets' worth of samples (50 × the current MTU), `ack_rate` is
  1.0.
- Otherwise it is `acked / (acked + lost)`, floored at 0.8.
- It is recomputed in `on_end_acks` and in `on_congestion_event`.

**Window.** Brutal never lowers its rate on loss; persistent congestion
doesn't lower it either.

- Before the first RTT sample, `window()` returns `initial_window()`, which
  is apernet's 10240 bytes.
- After that, `window()` returns
  `max(rate × srtt / ack_rate, 2 × MTU)`. Here `srtt` is the smoothed RTT
  from the `RttEstimator` that `on_ack` was given.

**Why that window, not apernet's 2 × BDP.** apernet sets the window to
2 × rate × RTT and paces at the rate separately. quinn paces internally and
does not let a controller choose the pacing rate. Its pacer refills at
**1.25 × window / srtt** (`quinn-proto-0.11.19/src/connection/pacing.rs`, the
`delay` refill), and switches pacing off above a `u32::MAX` window. If the
window were 2 × BDP, quinn would let traffic through at 2.5× the target, and
the window would bound the rate at 2×. So the rate is held by making the
window the binding limit:

- With the window at `rate × srtt / ack_rate`, delivery is window-limited at
  the target rate.
- quinn's pacer, at 1.25× that, smooths the bursts without being the limit.

The cost is a slight under-delivery while RTT climbs faster than `srtt`
follows. Check it on the bench (below). If it turns out to matter, the next
step is a send-side token bucket above quinn, not a patched quinn.

**Model tests**, as steer does in `tests/qcbrutal.c`. They use no network:
synthetic acks and losses with timestamps against the controller directly.

- below 50 samples, `ack_rate` is 1.0;
- 10% loss gives `ack_rate` 0.9 and a window of `rate × srtt / 0.9`;
- 50% loss is floored at 0.8;
- slots older than 5 s stop counting;
- persistent congestion leaves the rate unchanged;
- the extreme rates are clamped;
- the switchable controller stays on BBR when the handle is 0 and moves to
  Brutal when it is set.

**Interop and bench.**

- In the PR 4.3 nightly job, the apernet client and server against shoes, in
  both directions, for the negotiation table above.
- On the `scripts/bench` rig, with netem at 50 ms delay and 0.5% and 5%
  loss: BBR against Brutal at a declared rate below the link. Brutal should
  hold the declared rate within 10%.

**Related items.** `bandwidth.disableLossCompensation` (upstream 2.10.0) is
one boolean that pins `ack_rate` to 1.0, so it comes with this work. The
`congestion: bbr | reno` option is separate and not in this item.

## SF-10 — test methods for PR 4.3

**Part 1 done (4.3 part 1):** the ClientHello shape test, the Vision cut
property and the `.srs` oracle. The probe outcomes, corpus, slow drip and
loud skips come with the harness (part 2) and the nightly job (part 3).
Part 2 landed the outcomes, the corpus and the slow drip
(`docs/specs/2026-10-22-probe-harness.md`). Loud skips stay with part 3.

What part 1 found:

- sing-box's REALITY client strips X25519MLKEM768 from its hello. shoes
  offers it. That is input for S.4.
- Vision dropped a first read shorter than 16 bytes. Xray's
  `XtlsUnpadding` (`proxy/proxy.go:556-562`) treats any first read without
  the UUID and a whole frame header (21 bytes) as plain data. shoes now
  does the same.
- shoes accepted a version-0 `.srs` file, and sing-box does not
  (`option/rule_set.go:344-351`). sing-box also does not check the zlib
  trailer. shoes keeps checking it.

These fold into PR 4.3's probe harness and nightly job (plan,
`docs/plans/2026-10-15-quality-and-correctness.md`). They are not separate
work.

- **Three outcomes.** Every probe ends as one of `Data(n bytes)`,
  `Closed(after t)` or `Silent(until timeout)`. A probe asserts the outcome
  and a time bound, never error text. On real links a reset can look like a
  timeout, which is why steer's `tests/probe.sh:182-186` asserts this way.
- **Probe corpus:**
  - a real ClientHello with a foreign SNI;
  - plaintext `GET / HTTP/1.1`;
  - a short read under 17 bytes (VL-V1);
  - random bytes;
  - a wrong password.
- **Slow drip.** A client that writes one byte at a time. Each gap is
  shorter than any per-read timeout, but together they are longer than the
  handshake deadline. It tells a per-read timeout from a handshake deadline,
  which is the gap a prober exploits. Run it under tokio's paused time.
- **Loud skips.** A nightly cell whose reference binary or capability is
  missing reports "skipped". The summary requires a set number of passing
  cells, and opens the issue on skips as well as failures.
- **ClientHello shape.** shoes' own REALITY hello is compared with the
  sing-box hello captured in #95. The comparison covers the cipher list, the
  extension set with lengths, groups, signature algorithms and the
  key-share layout. It ignores GREASE values and extension order, which vary
  per connection.
- **Vision cut property.** A padded Vision stream fed in every split, at
  each single offset and each pair of offsets, must give identical output.
- **.srs oracle.** Expected matches are recorded from `sing-box rule-set
  match`, alongside corruption cases: bad magic, an unknown version,
  truncation, a zlib checksum failure and a garbage body.

## SF-11 — deferred

Recorded so they aren't rediscovered. None is planned now.

- **xhttp (stream-one, stream-up, packet-up) and gRPC transports.** Xray
  users ask for these. The pitfalls steer found (`src/proto/transport/trxhttp.c`,
  `trgrpc.c`):
  - the path must end in `/`;
  - every request is padded through `Referer` (`xPaddingBytes`);
  - packet-up POST sizes are random within the node's range;
  - the "auto" mode picks stream-one under REALITY;
  - gRPC's service name can be a full path, and `|` means multi mode.

  shoes' `h2` dependency could carry both directions on one connection,
  where steer opens two.
- **ECH for plain TLS.** rustls 0.23 has client ECH with aws-lc-rs. This is
  a fingerprint item, tracked under the ROADMAP's TLS-fingerprinting risk.
- **REALITY `pqv`.** Xray's optional ML-DSA-65 signature over the temporary
  certificate (`src/proto/tls/certverify.c:468-499`). Links that carry `pqv`
  already work; they just lose that check.
- **Hysteria Gecko obfuscation.** Salamander plus splitting long-header
  packets. It is experimental upstream.
- **DoQ** (RFC 9250).
- **Accepting `.srs` logical rules.** shoes rejects a file containing them
  (`src/rule_set/srs.rs:256-298`). steer drops what it can't express and
  warns. Failing closed is the safer default, so this needs a decision, not
  a backport.

## Where steer is worse, so not to follow

- **Vision.** steer sends the end command in the first frame and never
  `direct`, so the inner handshake goes unpadded. shoes' `vision_filter.rs`
  is the right model.
- **GREASE ECH and placeholder ML-KEM shares made of random bytes.** These
  are distinguishable. shoes uses real keys.
- **Port hopping on a single socket.** shoes rebinds a socket per hop, as
  apernet does.
- **Dropping Hysteria2 fragments over 1400 bytes.** This breaks once PMTUD
  raises the path MTU.
- **CI.** steer's CI runs no interop. PR 4.3's nightly job goes further.
