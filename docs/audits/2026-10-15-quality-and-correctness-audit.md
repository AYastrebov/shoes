# Code quality, architecture and protocol correctness audit — 2026-10-15, at `mobile` 899ae0d

Companion plan: [docs/plans/2026-10-15-quality-and-correctness.md](../plans/2026-10-15-quality-and-correctness.md).

Scope: the whole crate, split into eight parallel read-only reviews — two on
Rust architecture and code quality (the data path; the shell of config,
control, FFI, daemon and CLI) and six on protocol correctness, each comparing
shoes against the reference specification *and* the reference implementation
it was fetched from on the day (not recalled). The references read are listed
at the end. Headline findings were re-verified by hand against the tree before
they were ranked: the two Shadowsocks/Snell aborts, the REALITY key-share rule
in `tls.go`, the VMess UDP padding writer, the Vision `u16` cast, the Reality
`unreachable!()` arms, the ShadowTLS client handshake loop, the WireGuard
sender index, and the `icmp_enabled` plumbing. Everything else carries the
reviewer's CONFIRMED/SUSPECTED mark. Known, deliberate gaps recorded in
ROADMAP.md, AGENTS.md and MOBILE.md are not re-reported.

Line numbers are against 899ae0d.

## Verdict

The engine's core is in better shape than its edges. The relay machinery
(`copy_bidirectional`, `splice`, `UdpRouter`), the connector trait split, the
control lifecycle, the daemon's host-network design and the mobile FFI are
careful, bounded and well tested. The byte layouts, key derivations and
constants of every protocol match their references with few exceptions —
the work AGENTS.md's "read the upstream source" rule was written to protect
is sound.

Where shoes diverges is in everything around the bytes: what a server does
to a client that fails authentication, what a client's first flight looks
like on the wire, how sessions and multiplexers behave past the first
stream, and what happens at the edges of a frame (empty, oversize, split,
truncated). Those are exactly the properties a censor or an active prober
measures, and they are exactly the properties that round-trip tests — which
is nearly all the test suite is — cannot see, because both ends share the
misreading.

Four defects end the process or corrupt a stream and are reachable from the
network or from a valid-looking config. One interoperability break is new
since the last audit because the reference moved (REALITY now requires a
hybrid post-quantum key share). On the Rust side there are no memory-safety
problems; the debt is structural: untyped errors, per-connection tasks with
no shutdown ownership, a config layer that validates strings and then
re-parses them with `expect`, a CLI that compiles the crate twice, and three
files whose tests outweigh their code.

## Cross-cutting themes

1. **Failure behaviour is the fingerprint.** On a bad password, a malformed
   first record or a short probe, nearly every shoes server closes the socket
   at once. Every reference does something slower and quieter: Shadowsocks
   drains to EOF or sets linger(0), VMess drains a seeded 54–3266 bytes,
   Trojan and VLESS fall back to a configured HTTP target, REALITY and
   ShadowTLS relay the whole connection to the real site, Hysteria2 keeps
   serving 404 with no deadline. "Instant FIN, byte-count-dependent FIN/RST"
   is one rule in a DPI box, and it applies to SS, SS2022, Snell, Trojan,
   VMess, VLESS, Reality (non-auth failures), ShadowTLS (malformed hello),
   Hysteria2 (the 3 s auth timeout with a reason phrase), WebSocket
   (unmatched path), NaiveProxy (401 without `WWW-Authenticate`).
2. **Four reachable aborts or corruptions.** The crate builds with
   `panic = "abort"`, so a panic is a process exit on every host, including
   a phone's Network Extension. Snell UDP: a reply datagram over ~16 KB hits a
   `panic!`. Shadowsocks 2022: a wrong-length PSK passes config validation
   and asserts on the first stream. ShadowTLS: a zero-length data frame (which
   shoes' own writer emits on an empty write) trips an assert. Reality: a
   post-handshake KeyUpdate or NewSessionTicket from an authenticated peer
   hits `unreachable!()`. VLESS Vision: a ≥64 KiB non-TLS write inside the
   first eight packets wraps `content_len` to zero and corrupts the stream.
3. **Clients send a different first flight than the reference.** The VLESS
   header, the Trojan header and the Shadowsocks header are each flushed as
   their own record before any payload; Xray, sing-box and shadowsocks-rust
   merge them. The ShadowTLS client never finishes the TLS 1.3 handshake, so
   every connection is "server flight, then client application data with no
   Finished". mieru's padding lengths are uniform where the Go client's are
   skewed small, the open request never carries payload, and sessions end
   without a close handshake. WireGuard and AmneziaWG 2.0 initiations carry a
   sender index of `0x000000xx` in plaintext. NaiveProxy performs a full TLS
   handshake and then drops it unused on every reused session. AnyTLS opens
   a fresh TLS connection per stream and never applies the server's padding
   update.
4. **Multiplexing and sessions stop at the first stream.** XUDP assigns its
   own session ids instead of echoing the client's and does not drain data
   on control frames; TUIC runs one connection reader per UDP association and
   they steal each other's replies; TUIC and Hysteria2 pin a UDP session to
   its first resolved address; NaiveProxy never replaces a dead H2 session;
   Snell's ConnectV2 zero-chunk half-close is missing; sing-mux's brutal
   exchange stream is dialled as a hostname and the session dies.
5. **Rust structure.** `io::Error` plus prose is the only error type on
   every path, so hosts and tests match on strings and the daemon maps every
   config failure to one gRPC code. Per-connection tasks are spawned and
   forgotten, so a reload cannot drain. The config layer decodes UUIDs, keys,
   prefixes and URLs during validation, throws the result away and re-parses
   at runtime behind twelve `expect`s. `src/main.rs` re-declares the module
   tree instead of linking the library, which is what forces the crate-wide
   `#![allow(dead_code)]` and makes it reimplement `control::prepare_configs`.
   Three files carry more test lines than code lines.
6. **Tests prove symmetry, not conformance.** Almost every protocol test is
   a shoes-client-to-shoes-server round trip; a symmetric misreading passes.
   There are no known-answer vectors for any KDF, no captured reference bytes
   decoded by shoes, no fixture for a reference `.srs`, and no test of what a
   failing client sees or how long it waits. Twenty-one files over 400 lines
   have no tests; `src/shadow_tls/` has none at all.

## Baseline metrics

| Metric | Value |
| --- | --- |
| Source lines (`src/`) | ~132k, of which `config/` 13.5k, `bin/shoesd` 13.6k, `tun/` 8.9k, `reality/` 7.8k |
| `unsafe` blocks | 205 (TUN direct stack 34, Windows daemon arms 38, iOS FFI 18, Linux/macOS daemon arms 23, splice 6, tproxy 6); 3 without a SAFETY comment on the data path |
| Test density, lowest | `shadow_tls` 0/kloc, `snell` 2.0, `websocket` 2.5, `crypto` 3.7, `shadowsocks` 3.7, `routing` 5.1, `ffi` 6.0, `tun` 7.1 |
| Test density, highest | `sniff` 35, `rule_set` 26, `quic_transport` 25, `mieru` 22, `uot` 22, `dns` 21, `hysteria2` 21 |
| Files >400 lines with zero tests | 21 (largest: `vless/vision_stream.rs` 1508, `shadow_tls/shadow_tls_server_handler.rs` 1198, `main.rs` 937, `anytls/anytls_client_session.rs` 880, `socks_handler.rs` 788) |
| Integration tests under `tests/` | 3 (`process_contract`, `rule_set_golden`, `transparent`); none protocol-level |
| `io::Error::new(.., format!(..))` sites | 107 in `config/`, 92 in `shoesd`, 24 in `socks_handler.rs`, 12 each in `http_handler.rs` and `socks5_udp_relay.rs` |
| `TODO` markers in `src/` | 61 |
| `cfg(feature = "control-stats")` sites | 49 in `client_proxy_chain.rs`, 18 in `tun/stack_common.rs` |

## Findings

IDs are prefixed by area so the plan can cite them. Severity: **P0** ends
the process, corrupts data or breaks interop with the current reference;
**P1** is a fingerprint or a correctness bug on the wire with a real
consumer; **P2** is robustness or spec conformance without a known consumer;
**P3** is quality. Size: S under a day, M a few days, L a week or more.

### P0 — aborts, corruption, interop breaks

| ID | Finding | Where | Size |
| --- | --- | --- | --- |
| SS-D1 | **Fixed in #55.** Snell UDP relay `panic!`s on a datagram whose encoded size exceeds the 0x3FFF+34 write buffer; a remote target (or attacker-chosen destination) replying with a 16.4–65 KB datagram aborts shoes. Same assert on the client path. CONFIRMED. | `snell_udp_stream.rs:152-155,339-341`; `shadowsocks_stream.rs:891-892` | S |
| SS-D2 | **Fixed in #55.** Shadowsocks 2022 PSK length is not validated; `Blake3Key::create_session_key` asserts `key_bytes.len() == salt_len` on the first stream. A 16-byte key for `2022-blake3-aes-256-gcm` loads and aborts. CONFIRMED. | `blake3_key.rs:26` (TODO admits it); `config/types/shadowsocks.rs:44-70` | S |
| ST-S3 | **Fixed in #55.** ShadowTLS zero-length data frame (len 4) passes `try_deframe` as a 0-byte success and trips `assert!(processed_end_offset > 0)`; shoes' own `poll_write` with an empty buffer emits one, and an authenticated peer can send one. CONFIRMED by inspection. | `shadow_tls_stream.rs:113-116,224-235,265` | S |
| RE-R6 | **Fixed in #55.** Reality post-handshake inner type 0x16 (KeyUpdate, NewSessionTicket) reaches `unreachable!()` on both client and server. CONFIRMED path. | `reality_server_connection.rs:969`; `reality_client_connection.rs:867` | S |
| VL-V4 | **Fixed in #55.** Vision `pad()` casts `data.len()` to `u16` with no reshape to ≤8171; a ≥65536-byte non-TLS write inside the first eight packets wraps to 0 and corrupts the stream. CONFIRMED. | `vision_pad.rs:19` | S |
| RE-R2 | REALITY `main` forwards any ClientHello without an `X25519MLKEM768` share placed before the optional X25519 (`tls.go:234-235`, verified). shoes' client offers X25519 only, so current REALITY servers forward it to the decoy and the client fails "Certificate HMAC verification failed". The server side cannot authenticate MLKEM-only clients either. CONFIRMED. | `reality_tls13_messages.rs:338-355`; `reality_util.rs:221-271` | L |
| VM-D2 | **Fixed in #57.** VMess UDP writer declares random padding in the chunk length but never writes the padding bytes (the stream path at 646-649 does). Any Xray client with GlobalPadding (default for AES/ChaCha) desyncs on the first non-zero padding. CONFIRMED. | `vmess_stream.rs:1057-1069` | S |
| RS-1 | **Fixed in #56.** `.srs` ip set that mixes IPv4 ranges with IPv6 ranges below `::ffff:0:0` is rejected ("ranges are not sorted and disjoint") because sing-box writes v4 then v6 and sorts after reading; shoes does not sort. Reproduced with `10/8, 192.168/16, ::1/128`. Any "private" set fails the whole config. CONFIRMED. | `rule_set/srs.rs:323-351`; `ip_set.rs:16-30` | S |
| TR-2 | **Fixed in #56.** WebSocket and HTTPUpgrade clients omit `Host` unless the user configures it; Go's `net/http` (every sing-box inbound, every CDN) answers 400. CONFIG.md:860-862 claims the opposite. CONFIRMED. | `websocket_handler.rs:163-185`; `httpupgrade/client.rs:56-60` | S |
| HY-D2 | **Fixed in #57.** Hysteria2 and TUIC servers pin a UDP session to the first resolved address whenever the first address was a hostname, and relabel replies with that hostname; upstream pins only when a request hook rewrote the address, TUIC resolves per packet ("Full Cone"). The citation in the code says the opposite of what it supports. CONFIRMED. | `hysteria2/server.rs:750-766,834-835`; `tuic/server.rs:1148-1155,652-688` | M |
| XU-X1/X2 | **X1 fixed in #56, X2 in #57.** XUDP: KeepAlive/End frames carrying OptionData are not drained (desync); the server invents session ids keyed by destination instead of echoing the client's, so mux.cool client workers (Xray `xudpConcurrency`, sing-box mux+xudp) drop every response. CONFIRMED. | `xudp/message_stream.rs:162-202,432-435,488-489,651-653` | M |
| TU-D6 | TUIC client runs one `accept_uni`/`read_datagram` loop per UDP association on the shared connection; with two associations each steals about half the other's replies. Acknowledged in a comment. CONFIRMED. | `tuic/udp.rs:213-300`; `tuic/client.rs:129-133` | M |
| NA-N1 | NaiveProxy client never replaces a dead H2 session (`is_ready` is hard-coded true; the slot is never cleared), so after one drop every connect fails until restart; and on the reuse path the freshly dialled TLS connection is discarded unused — one empty TLS handshake per proxied connection. CONFIRMED. | `naive_client_session.rs:102-106`; `naive_client_handler.rs:111-126` | M |
| H2-4 | **Fixed in #57.** sing-mux brutal exchange (`_BrutalBwExchange`) is dialled as a hostname, fails, and the client tears the session down; brutal-enabled sing-box clients never connect. CONFIRMED. | `h2mux_server_session.rs:411-465` | S |

### P1 — fingerprints and on-the-wire correctness with a known consumer

| ID | Finding | Where | Size |
| --- | --- | --- | --- |
| ST-S1 | ShadowTLS v3 client breaks out of the handshake loop at the first encrypted record and never sends CCS/Finished; the server's certificate and Finished are never verified. One-rule DPI signature on every connection. CONFIRMED. | `shadow_tls_client_handler.rs:111-159` | M |
| XF-1 | Handshake-failure behaviour across servers (theme 1): SS/SS2022/Snell/Trojan instant close (SS-D3), VMess instant close vs seeded drain (VM-D6), VLESS `peek_slice(17)` blocks a short probe instead of falling back (VL-V1), Reality returns Err on non-auth validation failures instead of forwarding (RE-R1), ShadowTLS closes on any malformed first record instead of relaying (ST-S2), Hysteria2 3 s auth timeout then `CONNECTION_CLOSE(0x100, "auth timeout")` (HY-D1), WebSocket drops unmatched paths instead of 404, NaiveProxy 401 without `WWW-Authenticate` (NA-N3). All CONFIRMED. | per protocol | M each |
| WG-A1 | **Fixed in #56.** WireGuard/AWG sender index is `0x000000xx` for the life of the process (index 0 passed at both `Tunn` constructions; awgtun shifts by 8). Plaintext in WG and AWG 2.0 initiations and in every server→client `receiver_index`. CONFIRMED. | `amneziawg/tunnel.rs:326,965` | S |
| VL-V3 | VLESS client flushes the header as its own outer TLS record before `VisionStream` exists; Xray hides it in the first 900–1400-byte padded frame or an empty frame after 500 ms. CONFIRMED. | `vless_client_handler.rs:105-117` | M |
| SS-D7 | Trojan (and SS classic/2022) clients flush the header alone; the references append the first payload. CONFIRMED. | `trojan_handler.rs:230-236`; `shadowsocks_tcp_handler.rs:347-348` | S |
| RE-R3/R5/R8 | Reality server synthesises its own ServerHello instead of mirroring the decoy's; sends no NewSessionTicket-sized dummy record; the client's hand-built ClientHello has no GREASE/psk_modes/EMS/status_request/SCT/padding (unique JA3/JA4, Xray mandates a uTLS fingerprint). CONFIRMED. | `reality_server_connection.rs:519-529`; `reality_tls13_messages.rs:20-86,260-422` | M / S / L |
| MI-M1/M2/M3 | mieru padding lengths uniform (mean ≈128 vs ≈51); open request never carries the ≤1024-byte first payload (+1 RTT, different first-packet shape); no close handshake before FIN. CONFIRMED. | `mieru/padding.rs:66,79,138`; `mieru/stream.rs:103-117,347,209-215` | S / M / S |
| AT-A1/A2 | AnyTLS client ignores `UpdatePaddingScheme` (default scheme forever, server re-sends every session) and has no session pool (spec: client MUST reuse; server may refuse). CONFIRMED. | `anytls_client_session.rs:652-673`; `anytls_client_handler.rs:5-10,65-69` | S / M |
| NA-N2 | NaiveProxy server fragmentation thresholds are 400<len<1024 in 200–300-byte pieces; reference is 200<len<1024 in 100–200. CONFIRMED. | `naive_padding_stream.rs:95-102,210-221` | S |
| SS-D4 | Snell ConnectV2 (cmd 5) accepted but the zero-chunk half-close is not implemented: v2 and pooled mihomo clients hang until the remote closes, and never reuse. CONFIRMED. | `snell_handler.rs:139-143`; `shadowsocks_stream.rs` | M |
| TU-D4 | **Fixed in #57.** TUIC server drops pre-auth uni streams instead of parking them; in `quic` relay mode the first packet (often DNS) is lost. CONFIRMED. | `tuic/server.rs:238-253` | S |
| TU-D3 | TUIC server reaps idle associations after 60 s; reference keeps them until Dissociate, so long-idle UDP (QUIC/WireGuard inside TUIC) loses its NAT mapping. CONFIRMED. | `tuic/server.rs:40-41,936-947` | S |
| TR-3 | WebSocket early data (`max_early_data`, `Sec-WebSocket-Protocol`, path suffix) unsupported on both sides; sing-box/Xray clients configured for it lose their first payload. MISSING. | `src/websocket/` | M |
| TR-5/6 | **Fixed in #58.** SOCKS5 sends no `05 FF`, no `01 01`, no CONNECT failure reply (RFC MUSTs); HTTP proxy drops the connection on a wrong password instead of 407. CONFIRMED. | `socks_handler.rs:143-148,197-201`; `tcp_forward.rs`; `http_handler.rs:160-167,268-275` | S |
| TR-8 | **Fixed in #58.** WebSocket server answers `101 Switching Protocol` (RFC: Protocols), echoes a `Host:` response header, has a dead `sec-websocket_version` echo, and validates none of Upgrade/Connection/Version. Unique on the wire. CONFIRMED. | `websocket_handler.rs:94-114` | S |
| TN-T1/T2/T3 | **Fixed in #56.** TUN: SYN over `max_connections` silently dropped (apps hang 1–2 min); `icmp_enabled: false` is a no-op (stored in the builder, never read); IP fragments are neither dropped nor checksummed, so non-first fragments parse as UDP/TCP and can open bogus sessions or emit stray RSTs. CONFIRMED. | `stack_common.rs:919-925,981-984,1498-1567`; `tun_server.rs:64,278`; `udp_handler.rs:161-223` | S / S / S |
| VM-D3/D1 | VMess AuthenticatedLength (opt 0x10) refused; security byte 5 "none" removed upstream so a shoes client with `cipher: none` fails against Xray. CONFIRMED. | `vmess_handler.rs:428-433,447-463` | M / doc |
| VL-V2/V6/V7 | XRV flow with UDP command accepted (Xray rejects); write side holds a TLS-looking suffix across `poll_flush` so non-TLS traffic ending in 0x16 stalls; TLS 1.3 not forced for Vision. CONFIRMED. | `vless_server_handler.rs:384-410`; `vision_stream.rs:1259-1268`; `tcp_client_handler_factory.rs:169` | S each |
| HY-D5 | "BBR" is quinn's: the pacer uses cwnd/RTT rather than BBR's pacing rate, and `initial_window` is 200×1200 vs upstream's 32 packets. The BBR spec overstates fidelity. CONFIRMED. | `quic_transport/mod.rs:144`; quinn-proto `bbr/mod.rs:534,648` | S (window) / L (pacer) |
| WG-A2 | awgtun has no 0–334 ms handshake retransmit jitter (comment claims it). CONFIRMED, in the fork. | awgtun `timers.rs:316-319` | S |

### P2 — robustness and conformance

| ID | Finding | Where |
| --- | --- | --- |
| SS-D5 | EOF mid-chunk reported as clean EOF (truncation undetected). | `shadowsocks_stream.rs:743-745` |
| SS-D6/D8 | SS2022 accepts padding 0 with empty payload; header may straddle chunks; classic AEAD salt stored before authentication (probe flood evicts real salts). | `shadowsocks_tcp_handler.rs:164-177`; `shadowsocks_stream.rs:413-419` |
| VL-V5 | Unpad `Initial` with <16 bytes discards instead of buffering (UUID straddling records). | `vision_unpad.rs:100-102` |
| XU-X3 | **Fixed in #57.** Unknown-session Keep errors the connection; metalen unbounded (reference ≤512); no 7526-byte response cap. | `xudp/message_stream.rs:179-186,333-341,671` |
| RE-R4/R7 | Client fails immediately on HMAC mismatch instead of x509 fallback + spider; version hardcoded 1.8.0; no alerts sent on any failure; no ServerHello sanity checks. | `reality_client_verify.rs`; `reality_client_connection.rs:183-195` |
| TL-1 | `max_early_data_size = u32::MAX` on every TLS server config with no `early_data()` reader; a resuming client's 0-RTT header is lost. Reported independently by two reviews. SUSPECTED low exposure. | `rustls_config_util.rs:294` |
| HY-D7/D8/D9 | Zero-length UDP payload emitted (upstream rejects); no HTTP served after auth; 0-RTT asymmetry; `Hysteria-UDP` absent read as true. | `hysteria2/frame.rs:359-365`; `auth.rs:60-67` |
| TU-D10 | Heartbeats per UDP session (none for TCP-only) and server-sent heartbeats the reference client logs as bad commands. | `tuic/udp.rs:303-319`; `tuic/server.rs:195-218` |
| AT-A3/A4 | Unknown AnyTLS command kills the session (reference skips); range draw off by one. | `anytls_types.rs:55,167-174`; `anytls_padding.rs:133` |
| MI-M4/M5 | `unack_seq`/`window_size`/`fragment` always 0; ASCII run length drawn per segment not per process. | `mieru/frame.rs:86-88`; `padding.rs:78` |
| NA-N4 | `padding-type-request: 0` answered with Variant1; `fastopen` header never sent; EOF mid padded frame silent. | `naive_hyper_service.rs:289-301`; `naive_padding_stream.rs:438` |
| ST-S4/S5 | Local handshake mode drops unauthenticated clients with RST; no relay when the handshake server negotiates TLS 1.2. | `shadow_tls_server_handler.rs` |
| TR-7/10/11/12 | **TR-7 and TR-11 fixed in #58; TR-10, TR-12 open.** WS ping >80 B or any pong payload kills the connection (RFC: ≤125, pongs may carry data), close frame ignored; TLS sniff rejects record versions 0x0300/0x0302; `write_location_to_vec` truncates >255-byte hostnames; SOCKS UDP BND.ADDR from the listener bind IP (0.0.0.0 on wildcard). | `websocket_stream.rs:291-296,324-329,339`; `sniff/tls.rs:78-82`; `socks_handler.rs:758,385` |
| WG-A3/A4 | `jc` accepts 129–255 (kernel: ≤128), `validate_for_mtu` not invoked; decoy/initiation ordering race between the timer task and encapsulate. | `amneziawg/config.rs:99-104`; `tunnel.rs:843-864` |
| DN-D1/D2/D3 | DNS 0x20 case randomisation off; DoH/DoT bootstrap resolved once at build; system-resolver cache 1 h fixed. | `dns/builder.rs:663`; `resolver.rs:366` |
| FI-1 | Fake IP intercepts UDP/53 only; a TCP-fallback resolver escapes. | `udp_manager.rs:133` |

### Architecture and code quality (A, Q)

| ID | Finding | Where | Size |
| --- | --- | --- | --- |
| A-1 | **Fixed in #61.** `src/main.rs` re-declares the module tree instead of `use shoes::`; forces `#![allow(dead_code)]` in `lib.rs:5` (hiding three dead FFI functions), duplicates `control::prepare_configs` step for step, doubles build time. `shoesd/main.rs:10-12` does it right. CONFIRMED. | `main.rs:1-96,720-860`; `control/mod.rs:~560-640` | L |
| A-2 | Validate-then-reparse: validation decodes UUIDs, keys, short ids, prefixes, hop settings and DNS URLs, discards them, and the runtime re-parses behind twelve `expect`s. Stringly fields throughout `config/types/client.rs`. CONFIRMED. | `validate.rs:1138-1797`; `tcp_client_handler_factory.rs:190-370`; `tcp_server_handler_factory.rs:134-515`; `chain_builder.rs:167` | M/L |
| A-3 | No typed errors anywhere: `io::Error::new(kind, format!)` ×107 in config, ×92 in shoesd; `ErrorKind::PermissionDenied` overloaded as "blocked by rules" in the UDP router so a real `EACCES` is cached as a routing block; the FFI detects a stop race by string comparison against `ENDED_UNREQUESTED`; the daemon maps every config failure to `INVALID_ARGUMENT`. CONFIRMED. | `udp_router.rs:1214,1259-1262`; `ffi/common.rs:~215-235`; `supervisor.rs:116`; `service.rs:~330` | M |
| A-4 | No cancellation ownership: accept loops `tokio::spawn` and drop handles; `start_servers` returns only listener handles; a reload kills accept loops while live connections keep the old selector with no drain. SOCKS5 UDP associate leaks its reader task and bound socket on the normal TCP close (no `Drop` aborts it). CONFIRMED. | `tcp_server.rs:114,176,349`; `quic_server.rs:111,160`; `socks_handler.rs:419,483-492`; `socks5_udp_relay.rs:220,429-437` | M |
| A-5 | Twenty hand-written `Deserialize` impls; `groups.rs` key-sniffs with an ordered `if` chain that has already bitten once; `server.rs` keeps a manual `VALID_FIELDS`; `rules.rs` has the same 80-line body twice. CONFIRMED. | `config/types/groups.rs:181-280`; `server.rs:193-240`; `rules.rs:184-300,517-640` | M |
| A-6 | **Fixed in #61.** Duplicate QUIC accept loop (semaphore, accept, admit-or-retry, spawn, triage) in `quic_server.rs` and `quic_transport`; only endpoint construction was meant to stay separate. The generic one logs per-stream failures at `error!`. CONFIRMED. | `quic_server.rs:87-143`; `quic_transport/mod.rs:278-311` | S |
| A-7 | Defaulted `AsyncStream::plain_tcp`/`original_destination` are a forwarding trap: 31 impls, 5 forward, contract held by memory. CONFIRMED. | `async_stream.rs:233-262` | M |
| A-8 | **`Supervisor::stop` fixed in #61; the two polling loops open.** Polling where a notification exists: `stop_handle` sleeps 5 ms in a loop; `await_interface` 20 ms. `Supervisor::stop` reports `Released` when the supervisor thread is gone. CONFIRMED. | `control/mod.rs:105-115`; `shoesd/supervisor.rs:~250,~465` | S |
| A-9 | `cfg(feature = "control-stats")` by statement (67 sites) instead of a ZST counter type; FFI state is six parallel statics under one lock (three past bugs were "a slot cleared outside the lock"). CONFIRMED. | `client_proxy_chain.rs`; `tun/stack_common.rs`; `ffi/common.rs:44-81` | M |
| Q-1 | **Fixed in #60.** Dead code: `stream_worker_pool.rs` (280 lines, unbounded channel, no users), `udp_message_stream.rs` (`#![allow(dead_code)]`, no callers), 14 h2mux items under unjustified local allows, `reality_aead::seal`, `outbound_stats::Entry.address`, three FFI functions. CONFIRMED by compiler. | listed in the plan | S |
| Q-2 | **Fixed in #60.** Three `unsafe` blocks without SAFETY comments, two with safe replacements (`socket2::SockRef::from`, `std::net::UdpSocket::from`). CONFIRMED. | `socket_util.rs:253,299`; `dns/proxy_runtime.rs:193,200` | S |
| Q-3 | **Lints table, thread_util, watcher and docs fixed in #60; test-file splits and serde_yaml open.** Tests in-file: `client_proxy_selector.rs` 641 code / 1668 test lines, `client_proxy_chain.rs` 900/895, `udp_router.rs` 1595/743. No `[lints]` table in Cargo.toml. `thread_util::get_num_threads` panics if uninitialised. `shoes missing.yaml` panics in the watcher before usage. Stale FFI docs at the crate root. `serde_yaml` 0.9 is archived (CI audit already red on `unsafe-libyaml`). CONFIRMED. | various | S each |
| Q-4 | **Fixed in #60.** XUDP constructs `NativeResolver::new()` per stream, bypassing DNS routing and fake IP. SUSPECTED. | `xudp/message_stream.rs:64` | S |

### What matched

For the record, so nobody re-audits it next month: Shadowsocks AEAD and 2022
derivations, nonces, salts, timestamps and chunk limits; Snell v3 argon2id,
commands and UDP framing; Trojan hash and layout; VMess KDF, AuthID, header,
response keys, ChaCha key and SHAKE mask; VLESS request/response, addons,
Vision padding sizes, unpad state machine, filter and direct-copy switch;
XUDP frame layout; Reality session id, AuthKey, AEAD, short id window, cert
HMAC, record-size mimic and the RFC 8446 key schedule; Hysteria2 TCP/UDP
frames, auth headers, defragger, salamander, port hopping, transport
parameters; TUIC v5 everything on the wire except the items above; mieru
KDF, nonces, metadata, entropy padding; AnyTLS auth, frames, padding scheme
and settings exchange; NaiveProxy padded frames and headers; ShadowTLS HMAC
derivations and switch; WireGuard/AWG timers, retries, decoys, header and
padding validation, 3.0 window and 3.1 trailer; TUN RST-on-unknown-flow,
MSS, ICMP echo, IPv6, UDP table and backpressure; fake IP pool semantics;
DNS port randomisation, response validation, TC fallback, EDNS0, DoH/DoT
shapes; HTTPUpgrade refusal codes; H2MUX framing; UoT v1/v2; SOCKS5 UDP
associate; HTTP CONNECT/407; sniff timeouts; `.srs` format and succinct set;
redirect and tproxy socket options.

## Test coverage gaps

- **No known-answer vectors**: EVP_BytesToKey, HKDF-SHA1 "ss-subkey", blake3
  2022 subkey, Argon2id (Snell), VMess KDF/AuthID/crc32, salamander key (its
  "known vector" test derives the expectation with the code under test),
  mieru PBKDF2, ShadowTLS HMACs. Every one is a self round-trip today.
- **No reference-captured bytes decoded by shoes** for any protocol; no
  reference `.srs` fixture that mixes v4 and v6; no Go-produced mieru or
  AmneziaWG I-packet.
- **No probe-behaviour tests**: what a wrong-password, short, malformed or
  slow client receives and after how long — the property every fallback path
  exists for.
- **Zero-test files on the data path**: `vision_stream.rs`, `vision_pad.rs`,
  `vless_{client,server}_handler.rs`, `vless_message_stream.rs`,
  `vless_response_stream.rs`, `xudp/message_stream.rs`, all four
  `shadow_tls/` files, `reality_{server,client}_handler.rs`,
  `tls_{client,server}_handler.rs`, `shadowsocks_tcp_handler.rs`,
  `default_key.rs`, `blake3_key.rs`, `snell_udp_stream.rs`,
  `snell_fixed_target_stream.rs`, `trojan_handler.rs`, `socks_handler.rs`
  address helpers, `stream_reader.rs`, `ffi/android.rs`.
- **No end-to-end Reality handshake test** (the client's Finished is never
  checked by a server in any test), no RFC 8448 vector.
- **No scripted-device TUN tests** for `icmp_enabled`, fragments, or a SYN
  past the cap; no test that two tunnels emit different sender indices.
- **Shell**: no property-based config round trip (the one round-trip test
  checks substrings), `StopOutcome::TimedOut` never produced by a real
  `stop_handle`, `ffi/android.rs` untested.

## References read by the reviewers

Rust: Rust API Guidelines checklist; tokio graceful-shutdown topic
(`CancellationToken`, `TaskTracker`); `tokio::select!` cancellation-safety
list; serde enum representations; `tracing` overview.

Protocols: shadowsocks.org AEAD spec, SIP022, shadowsocks-rust (`aead.rs`,
`aead_2022.rs`, `proxy_stream/protocol/v2.rs`, `server/tcprelay.rs`); mihomo
`transport/snell/`; trojan-gfw protocol page, sing-box `transport/trojan/`;
v2fly VMess page, Xray-core `proxy/vmess/{encoding,aead,inbound,outbound}`,
`proxy/vless/{encoding,inbound,outbound}`, `proxy/proxy.go`, `common/mux`,
`common/xudp`, `transport/internet/reality`; XTLS/REALITY `tls.go`,
`handshake_server_tls13.go`, `conn.go`, `key_schedule.go`; apernet/hysteria
master ca8fbd8 (`core/internal/protocol`, `core/client`, `core/server`,
`extras/obfs/salamander.go`, `extras/transport/udphop`,
`core/internal/congestion/{bbr,brutal}`); EAimTY/tuic tag `tuic-5.0.0`
(`SPEC.md`, `tuic/src/protocol`, `tuic-quinn`, `tuic-server`,
`tuic-client`); quinn-proto 0.11.19; enfein/mieru (`docs/protocol.md`,
`pkg/protocol`, `pkg/cipher`, `pkg/rng`); anytls-go (`docs/protocol.md`,
`proxy/session`, `proxy/padding`, `client.go`); klzgrad/naiveproxy
(`net/tools/naive/`) and the caddy `forwardproxy` naive branch;
ihciah/shadow-tls (`docs/protocol-en.md`, `src/{protocol,server,client,util}.rs`);
wireguard-go `device/{constants,timers}.go`; amneziawg-go v3.1.20260828
`device/{send,receive,timers,uapi,device}.go` and both READMEs; awgtun at
b6b4bcb; sing-tun `stack_system.go`; sing-box `dns/transport/fakeip`,
`common/srs/{binary,ip_set}.go`, `common/sniff/{tls,http,sniff}.go`,
`transport/v2ray{websocket,httpupgrade}`, `route/rule/rule_abstract.go`;
sing `common/domain`, `common/uot`; sing-mux `{protocol,server,client,h2mux,padding,brutal}.go`;
hickory-net/-resolver 0.26.1; smoltcp 0.14; RFC 6455, 1928, 1929, 9110, 8484,
7858, 9250, 5452, 2308, 8446.
