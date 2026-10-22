# Probe harness: what a server shows a client that is not one

Plan PR 4.3, part 2 (`docs/plans/2026-10-15-quality-and-correctness.md`);
SF-10 of `docs/specs/2026-10-21-lessons-from-steer.md`; the audit's testing
gap "no probe-behaviour tests" and theme 1, "failure behaviour is the
fingerprint" (`docs/audits/2026-10-15-quality-and-correctness-audit.md`,
XF-1). Written 2026-10-22.

## Problem

An active prober connects to a suspected proxy and sends something that is
not a valid client: random bytes, an HTTP request, a few bytes and then
nothing, a ClientHello for another site, a well-formed request with the
wrong key. What comes back, and when, is the fingerprint. Nothing in shoes
tests it. The audit lists the deviations (XF-1), but no test shows today's
behaviour, so neither a fix nor a regression is visible.

## Scope

- A harness that starts shoes' TCP servers from YAML **in-process, on real
  loopback sockets, through `start_servers`**, the accept path production
  uses. Server close behaviour, a FIN or a dropped socket, is then real.
- A fixed probe corpus, run against every server in a matrix, with each
  result asserted as an outcome and a time bound.
- A slow-drip prober, under paused time, through `process_stream`.

Not in scope:

- **Changing what any server does.** That is Phase 2 (XF-1 and the findings
  it groups), which comes after Phase 3. The matrix pins today's outcome and
  names the finding wherever that differs from the references. A Phase 2
  fix then changes a cell on purpose.
- QUIC servers (Hysteria2, TUIC) and NaiveProxy's HTTP/2 path. Their probes
  are a QUIC Initial and an h2 preface, which the nightly job (part 3)
  covers against the reference binaries.

The plan put the harness in `tests/probe_*.rs`. It lives in the crate
instead, under `#[cfg(test)]`. The wrong-key probe needs shoes' own client
handlers, and the slow drip needs `process_stream`; neither is public, and
neither should become public for a test.

## Outcomes

Every probe ends as exactly one of:

| Outcome | Meaning |
|---|---|
| `Data(n)` | The server sent `n > 0` bytes before closing or before the bound. |
| `Closed(t)` | The server closed (FIN or reset) without sending anything, `t` after the probe's last write. |
| `Silent` | Neither, until the bound. |

A probe asserts the outcome and a time bound, never error text. A reset
and a FIN are both `Closed`: on a real link a reset can look like a
timeout, and steer asserts this way for that reason (`tests/probe.sh:182-
186`). "Immediate" means within 1 s. `Silent` is observed for 2 s. That is
far below shoes' 60 s setup deadline, and long enough that a server which
closes "after reading what it needs" has done so.

## Corpus

| Probe | Bytes |
|---|---|
| `foreign_hello` | A real ClientHello for `www.example.com`, which no server here is configured for: the REALITY capture from #95 (`tests/data/kat/reality`). |
| `http_get` | `GET / HTTP/1.1\r\nHost: example.com\r\n\r\n` (37 bytes). |
| `short` | 16 random bytes, then idle: under every header (VL-V1 is a 17-byte peek). |
| `random` | 4096 random bytes, more than any header or drain. |
| `wrong_key` | A well-formed first flight from shoes' own client for that protocol, with the wrong password, key or UUID. |

The random bytes come from a fixed seed, so a run is reproducible.

## What the references do

From each reference's source; tags in the citations. sing-box sends every
handshake error to `N.CloseOnHandshakeFailure`, which sets `SO_LINGER(0)` on
a TCP conn, so its "close" is a reset (sing@v0.9.6
`common/network/handshake.go:36-55`). Neither sing-box nor the sing
libraries set a deadline on a protocol header; Xray's default handshake
policy is 60 s (`features/policy/policy.go:117-123`), chosen to match
nginx's `client_header_timeout`.

| Server | sing-box / sing library | Xray or other |
|---|---|---|
| Shadowsocks AEAD | Waits for salt + 18 bytes with no timeout, then resets; `http_get` and `short` hang (sing-shadowsocks@v0.2.8 `shadowaead/service.go:62-84`) | shadowsocks-rust reads to EOF, no limit or timeout (`server/tcprelay.rs:207-241`) |
| Shadowsocks 2022 | One read; under salt + 27 bytes resets at once (`shadowaead_2022/service.go:149-156`) | shadowsocks-rust: reset |
| VMess | One read; under 100 bytes resets at once; a bad auth id resets (sing-vmess@v0.2.8 `service.go:172-215`) | Xray drains 54 + Roll(3266) + Roll(Roll(64)+1) bytes, bounded by the 60 s deadline (`proxy/vmess/encoding/server.go:130-176`) |
| Trojan | One read of 56 bytes; anything else goes to the fallback if set, else resets (`transport/trojan/service.go:64-122`) | Xray: fallback if set, else close; idle waits 60 s (`proxy/trojan/server.go:153-206`) |
| VLESS | Reads the whole header, then resets on an unknown UUID; a short write hangs (sing-vmess `vless/service.go:56-63`) | Xray: under 18 bytes or a bad UUID goes to the fallback if set, else closes; a short write waits 60 s (`proxy/vless/inbound/inbound.go:282-316`) |
| Snell v3 | — | open-snell@v3.0.1: a FIN on a bad PSK; `http_get` and `short` hang (`snell/server.go:110-131`) |
| AnyTLS (in TLS) | Non-TLS bytes fail the TLS handshake; a bad password resets, since sing-box sets no fallback (sing-anytls@v0.0.13 `service.go:80-130`; sing-box `protocol/anytls/inbound.go:60-113`) | — |
| ShadowTLS v3 | Non-TLS bytes: reads the length in bytes 3–4 (8239 for `GET /`) with no timeout; a hello failing the HMAC is relayed whole to the handshake server (sing-shadowtls@v0.2.1 `v3_server.go:20-33`, `service.go:163-200`) | — |
| REALITY | — | Dials `dest` on accept and relays everything there on non-TLS bytes, a foreign SNI or failed auth; the prober sees `dest`'s answer; no timeout (XTLS/REALITY@9234c772 `tls.go:168-275`) |
| SOCKS5, HTTP | Not proxy-detection targets in the same way; a wrong password gets the protocol's own refusal | — |

So there is no single right cell. The two families differ: sing-box resets
early, and Xray drains, falls back or waits out a deadline. What no
reference does is close at once *on every input regardless of length*,
which is the audit's theme 1.

## The matrix

The test is a table of (server, probe) → expected outcome, with:

- `expected`: shoes' outcome today, as the harness observes it;
- `matches`: which reference family the cell matches (`sing`, `xray`,
  `relay`), or `none`;
- `finding`: the audit id that covers a `none` cell (SS-D3, VM-D6, VL-V1,
  RE-R1, ST-S2, NA-N3...).

Two rules are tests in their own right:

- every `none` cell names a finding that exists in the audit;
- a `relay` cell (REALITY, ShadowTLS) must be `Data` carrying the decoy's
  bytes, never `Closed`, since relaying is the whole point of those
  servers.

The servers, all on loopback, cert-free except the TLS-based ones, which use
`generate_certificate`:

- Shadowsocks `aes-256-gcm`
- Shadowsocks `2022-blake3-aes-256-gcm`
- VMess, VLESS and Trojan over plain TCP
- Snell
- SOCKS5 and HTTP with a password
- VLESS in TLS, standing for every TLS-wrapped server
- REALITY, with `dest` a local decoy that answers `decoy\n` to anything
- ShadowTLS v3, with its handshake server a local TLS listener

## What shoes does today (observed 2026-10-22)

`AO` is closed at once, `S` is silent for the bound, `D` is data.

| Server | foreign_hello | http_get | short | random | wrong_key |
|---|---|---|---|---|---|
| Shadowsocks AEAD | AO | S | S | AO | AO |
| Shadowsocks 2022 | AO | S | S | AO | AO |
| VMess | AO | AO | AO | AO | AO |
| VLESS | AO | AO | AO | AO | AO |
| Trojan | AO | AO | **S** | AO | AO |
| Snell | AO | AO | S | AO | AO |
| SOCKS5 | AO | AO | AO | AO | D (auth failure reply) |
| HTTP | AO | **AO** | S | AO | D (407) |
| VLESS in TLS | **AO** | AO | AO | AO | D (handshake) |
| REALITY | **AO** | **AO** | **AO** | **AO** | D (the decoy's answer) |
| ShadowTLS v3 | **AO** | **AO** | **AO** | **AO** | D (the decoy's answer) |

Most cells match one family:

- Shadowsocks AEAD and VMess behave as sing-box does.
- VLESS and Snell behave as Xray and open-snell do.
- Shadowsocks 2022 waits on a short header, as shadowsocks-rust does, where
  sing resets.

The bold cells match no reference:

- REALITY and ShadowTLS close on every malformed first flight that both
  references relay to the real site. That is RE-R1 and ST-S2, under XF-1.
  A failed REALITY or ShadowTLS authentication is relayed correctly.
- Three cells the audit did not record:
  - **PH-1** Trojan waits for 56 bytes. Both references judge the first
    read and refuse anything shorter at once (sing-box
    `transport/trojan/service.go:64-75`; Xray `proxy/trojan/server.go:176-
    206`). A 16-byte probe therefore holds a shoes Trojan connection open
    until the 60 s deadline, where a reference server would have closed it.
  - **PH-2** A TLS listener with no `default_tls_target` closes on a
    ClientHello whose name it does not know (`tls_server_handler.rs`,
    `select_target`). Go's `crypto/tls`, under every sing-box and Xray TLS
    inbound, completes the handshake with its certificate whatever the
    name. A REALITY server also relays an unknown name to `dest`. Probing
    with a foreign name tells a shoes listener apart.
  - **PH-3** The HTTP proxy closes without a word on an origin-form request
    (`GET / HTTP/1.1`), which is what a scanner sends first
    (`http_handler.rs`, the `http://` check). RFC 9112 section 3.2 expects
    a server to answer a request it cannot serve. A 400 would do.

All three are Phase 2 work, alongside XF-1.

## Slow drip

A client writes one byte every 5 s of the Shadowsocks AEAD header, never
completing it. Each gap is shorter than any per-read timeout would be, and
together they are longer than the 60 s setup deadline
(`tcp_server.rs`, `process_stream`). Under paused time the test asserts:

- the connection is still open at 55 s, so no per-read timeout fired;
- it is closed by 61 s, so the deadline is a deadline and the drip cannot
  extend it.

This matches Xray's handshake policy, which is also one 60 s deadline for
the whole header. sing-box has none, so a drip holds its connection open
forever.

## Testing the harness

- The outcome classifier is tested against a loopback listener that sends
  data, closes at once, resets, and does nothing.
- One matrix cell is changed and must fail, and the `none`-names-a-finding
  rule is shown to catch a cell without a finding.
- The suite's cost is bounded by `Silent`'s 2 s, with the cells running
  concurrently. The whole matrix should take about 2 s of wall time.
