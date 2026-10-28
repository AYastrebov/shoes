# Code quality, architecture and protocol correctness — improvement plan

Written 2026-10-15 against `mobile` at 899ae0d, from
[docs/audits/2026-10-15-quality-and-correctness-audit.md](../audits/2026-10-15-quality-and-correctness-audit.md).
Finding IDs below refer to that audit. Read it first; this document only
sequences the work.

**Goal:** make shoes indistinguishable on the wire from the reference client
or server for every protocol it ships, make it impossible for a peer or a
config to abort the process, and leave the crate in a shape where the next
protocol or host is added without a second copy of anything.

**Shape of the plan.** Six phases, each a set of pull requests into `mobile`,
each PR small enough to review in one sitting and green on the full CI matrix
before the next starts. Phase 0 is strictly ordered and goes first; later
phases are ordered within themselves but can interleave. Every PR here is a
*scope*, not a task list: before a PR starts, its owner writes the task-level
plan with the superpowers writing-plans skill (failing test, run, implement,
run, commit) and, where the PR changes behaviour on the wire, a short spec in
`docs/specs/` with the reference citations the audit already gives. That is
the repo's existing convention and this plan does not replace it.

**Global constraints** (from AGENTS.md and the focus set on 2026-10-15):

- Mobile first: nothing in this plan may raise the per-connection RSS the
  MOBILE.md budget measures, add a feature flag that mobile builds must carry,
  or change the FFI/JNI/Swift surfaces without a MOBILE.md entry.
- The verification gate runs on every PR: `cargo fmt`, clippy with
  `-D warnings` for default, `ffi`, `desktop` and `daemon` feature sets, the
  full test suite on macOS and Linux (Linux-only paths in the container, see
  `scripts/bench/run-linux.sh`).
- Reference first: a byte-level change cites the reference file it was read
  from, in the spec and in the test. "The reference does X" without a path is
  not an argument.
- No new control planes, dashboards or management APIs. No new protocols.
- Each PR's description ends with the finding IDs it closes, and the audit's
  table gets a "fixed in #N" note in the same PR.

**Sizes:** S under a day, M two to four days, L a week or more. The whole plan
is roughly four months of one engineer's time; Phases 0 and 1 are about five
weeks of it and carry most of the value.

---

## Status, 2026-10-22

| Phase | State | PRs |
|---|---|---|
| 0 | Done; released as v0.6.0 | 0.1 #55, 0.2 #56, 0.3 #57, 0.4 #58, 0.5 #59 |
| 1 | Done | 1.1 #60, 1.2 #61, 1.3 #62, 1.4 #63–#69, 1.5 #70–#71, 1.6 #72–#77 (with #74 and #76 as fixes on the way) |
| 2 | **Not started.** Deferred after Phase 1, by choice: servers are off the current focus. The probe harness (4.3, part 2) now pins what each server does today, so each 2.x PR shows as changed matrix cells. | — |
| 3 | Done except 3.1 and 3.3's parts 2–3 | 3.1 deferred with tests (#78); 3.2 #79–#80; 3.3 part 1 #81 (parts 2 RE-R4/R7 and 3 ST-S1 not scheduled); 3.4 #83; 3.5 #84–#85; 3.6 #86; 3.7 #87–#88 |
| 4 | 4.1 and 4.2 done; 4.3 parts 1–2 done, part 3 left; 4.4 not started | 4.1 #94–#95; 4.2 #96–#97; 4.3 part 1 #101, part 2 #102 |
| 5 | Done | 5.1 #89, 5.2 #91, 5.3 #92 |

Releases: v0.6.0 after Phase 0 (#59), v0.7.0 after Phase 1 and 3.3 part 1
(#82), v0.8.0 after the fix-wave review (#106), v0.8.1 to v0.8.3 for the
daemon (#109, #111, #113), v0.8.4 after the Vision UDP fix and the
dependency sweep (#114 to #117), v0.9.0 after the Android stopped listener
and session ids (#119 to #121).

Reviewed 2026-10-22 (`docs/audits/2026-10-22-fix-wave-review.md`): every
fix claimed above is present and tested; the gaps found beside them (TUIC
`udp_timeout` bounds, TLS `sni_hostname: ""`, SS2022 padding rule, mixed
DNS groups, missing tests and docs) were closed in #105, before v0.8.0.

The steer plan (`docs/plans/2026-10-21-lessons-from-steer.md`) runs
alongside this one: S.1 #99, S.2 #100; S.3 to S.6 are next.

---

## Phase 0 — nothing aborts, nothing lies (strictly ordered, ~2 weeks)

Every item here is either a reachable process abort, a stream corruption, or
a one-line correctness bug with a known consumer. All are S except where
marked. Ship as five PRs in this order; each one is a release candidate.

### PR 0.1 — Reachable aborts become errors

Closes SS-D1, SS-D2, ST-S3, RE-R6, VL-V4.

- `src/snell/snell_udp_stream.rs:152-155,339-341`: replace the `panic!` with
  "log at debug, drop the datagram" (mihomo returns an error; a dropped reply
  is the UDP-correct outcome). `src/shadowsocks/shadowsocks_stream.rs:891`:
  `assert!(packet_size <= write_cache.len())` becomes
  `Err(InvalidInput)`; the assert at `:282,292,382` get the same review.
- `src/config/types/shadowsocks.rs`: in `from_fields`, require
  `key_bytes.len() == cipher.salt_len()` for every `2022-*` cipher and return
  the config error; remove the TODO and the assert in `blake3_key.rs:26`
  (keep a `debug_assert!`).
- `src/shadow_tls/shadow_tls_stream.rs`: `poll_write` with an empty buffer
  returns `Ready(Ok(0))` without a frame; `try_deframe` treats
  `payload_len == 0` as "consume the record, feed the tag to the running
  HMAC, continue" (mirror the handshake-frame branch).
- `src/reality/reality_{server,client}_connection.rs:969,867`: the
  post-handshake 0x16 arm returns `InvalidData("post-handshake message
  unsupported")` and closes with a `close_notify`; implementing KeyUpdate is
  Phase 2.
- `src/vless/vision_pad.rs`: split input into ≤8171-byte frames before
  padding (Xray `ReshapeMultiBuffer`, `proxy/proxy.go:463-495`); `content_len`
  becomes `u16::try_from` with the split guaranteeing success.

Tests (one per item, all byte-level, no round trips): a 20 000-byte reply
through `SnellUdpStream` yields no write and no panic; a 16-byte key for
`2022-blake3-aes-256-gcm` fails `from_fields` with the cipher name in the
message; an empty `poll_write` on `ShadowTlsStream` produces no bytes and a
4-byte data record is consumed without error; a Reality server fed a sealed
KeyUpdate after Finished returns `InvalidData` and the task does not panic;
`pad()` on a 70 000-byte non-TLS buffer yields frames whose declared lengths
sum to 70 000 and none exceeds 8171.

### PR 0.2 — One-line correctness bugs with a known consumer

Closes RS-1, WG-A1, TN-T2, TN-T1, TN-T3, TR-2 (+ CONFIG.md), XU-X1.

- `src/rule_set/srs.rs::read_ip_set`: sort ranges by start before
  `IpSet::new`, then validate disjointness (sing-box `ip_set.go` sorts after
  reading). Fixture: `tests/data/rule_set/mixed-v4-v6.srs` generated by
  sing-box with `10.0.0.0/8, 192.168.0.0/16, ::1/128` plus the generator
  script committed under `tests/data/rule_set/`.
- `src/amneziawg/tunnel.rs:326,965`: pass `rand::random::<u32>() & 0x00FF_FFFF`
  as the index. Test: two `TunnelRuntime`s' first initiations differ at bytes
  4..8 after S1.
- `src/tun/tun_server.rs` → `TcpStackOptions`: thread `icmp_enabled`; in
  `stack_common.rs:981-984` `continue` on `Icmp | Icmpv6` when false. Scripted-
  device test: echo request with the flag off yields no reply.
- `src/tun/stack_common.rs:919-925`: a SYN over the cap is passed to smoltcp
  with no listener so it answers RST (zero cost), rather than `continue`.
  Test: cap 1, second SYN draws a segment with `rst` set.
- `src/tun/stack_common.rs::should_filter_packet` and
  `src/tun/udp_handler.rs:161-223`: drop IPv4 packets with MF set or a
  non-zero fragment offset and IPv6 packets carrying a Fragment extension
  header. Test: a two-fragment UDP datagram opens no session and emits no
  write.
- `src/websocket/websocket_handler.rs`, `src/httpupgrade/client.rs`: always
  send `Host` (config `host`, else TLS server name, else the dial address —
  sing-box's order in `v2raywebsocket/client.go:40-46`); add `host` to
  `WebsocketClientConfig`; correct CONFIG.md:860-862. Test: the request bytes
  contain exactly one `Host:` line and it equals the configured value.
- `src/xudp/message_stream.rs:162-202`: on KeepAlive/End with `OptionData`,
  read and discard `u16 len + len` bytes. Test: a KeepAlive carrying 10 bytes
  followed by a New frame parses both.

### PR 0.3 — Mux and session correctness

Closes VM-D2, XU-X2, XU-X3, HY-D2, TU-D4, H2-4. Size M.

- `src/vmess/vmess_stream.rs:1057-1069`: after the tag, write `padding_len`
  random bytes and advance the end index (mirror the stream path at 646-649).
  Test: message-mode round trip with the length mask enabled and a forced
  non-zero padding decodes on the stream reader; and a captured Xray VMess UDP
  chunk (fixture) decodes.
- `src/xudp/message_stream.rs`: key server state by the client's session id
  and echo it in responses (`mux/client.go:350-357` owns ids on the client);
  on a Keep for an unknown id send End for that id and continue
  (`server.go:311-319`); bound metalen at 512 (`frame.go:119`); drop responses
  over 8192-666 bytes (`xudp.go:100`). Tests: id echo; unknown-id Keep;
  metalen 513 rejected.
- `src/hysteria2/server.rs:750-766,834-835` and `src/tuic/server.rs:1148-1155,652-688`:
  delete the `override_remote_write_address` pair; resolve each distinct
  address through the existing `last_location` cache; label replies with the
  real source as `udp.go:109-133` and `handle_task.rs:355-359` do. Fix the
  citation comment at `hysteria2/server.rs:748`. Test: one session, two
  hostnames, both datagrams reach their own target and replies carry IP
  sources.
- `src/tuic/server.rs:238-253`: park non-auth uni streams in a `Vec` during
  `auth_connection` and feed them to `process_uni_stream` once authenticated
  (SPEC.md:160, `handle_stream.rs:472-479`). Test: a `quic`-mode Packet stream
  sent before Authenticate is delivered after it.
- `src/h2mux/h2mux_server_session.rs:411-465`: recognise destination
  `_BrutalBwExchange`, read the u64, reply `bool(false) + varbin("brutal is
  not enabled")`, close the stream (`sing-mux/server.go:124-152`). Test with
  the exact bytes.

### PR 0.4 — RFC MUSTs on the inbound edge

Closes TR-5, TR-6, TR-8, TR-7, TR-11.

- SOCKS5: write `05 FF` on no acceptable method, `01 01` on auth failure, and
  a `05 01/05` reply on CONNECT failure before returning the error (the
  helper at `socks_handler.rs:433` exists). HTTP: 407 with the same body on a
  wrong password. WebSocket server: `101 Switching Protocols`, no `Host:` in
  the response, remove the dead version echo, validate `Upgrade`,
  `Connection` and `Sec-WebSocket-Version: 13` (400/426), answer unmatched
  paths with 404 as HTTPUpgrade does. WebSocket frames: 125-byte ping buffer,
  pong payloads skipped, Close answered with Close. `write_location_to_vec`
  returns an error over 255 bytes.
- Tests: byte-exact replies for each failure; a WS 101 golden; ping 125 and
  pong-with-data survive; a 300-byte hostname is refused.

### PR 0.5 — Release

Bump to the next minor, CHANGELOG entry listing the closed IDs, and the KVN
pin bump only after one device run (per the standing note in ROADMAP.md).

---

## Phase 1 — Rust foundations (~3 weeks)

The structural debt. Order matters within the phase because later PRs build
on the earlier shape.

### PR 1.1 — Lints, dead code, unsafe hygiene (S)

Closes Q-1, Q-2, Q-3 (lints, thread_util, watcher, docs), Q-4.

- Add a `[lints]` table to Cargo.toml: `rust.unsafe_op_in_unsafe_fn = "deny"`,
  `clippy.undocumented_unsafe_blocks = "deny"`, `clippy.large_enum_variant`,
  `clippy.needless_pass_by_value`, and `clippy.unwrap_used` /
  `clippy.expect_used` as `warn` with `#[expect]` on the justified sites (the
  config-time `expect`s are removed in PR 1.4, so they get a comment naming
  that PR until then).
- Delete `src/stream_worker_pool.rs` and `src/udp_message_stream.rs`; delete
  `write_to_log_file`, `flush_log_file`, `stop_service` in `ffi/common.rs`;
  delete or wire the 14 h2mux items, `reality_aead::seal`,
  `outbound_stats::Entry.address`. Every remaining local `allow(dead_code)`
  names the change that removes it, per AGENTS.md.
- `socket_util.rs:299` → `socket2::SockRef::from`; `socket_util.rs:253` and
  `dns/proxy_runtime.rs:193,200` → `std::net::UdpSocket::from(socket2)` on all
  platforms; SAFETY comments on what remains.
- `thread_util::get_num_threads` returns the documented default instead of
  panicking; `start_notify_thread` returns `Result` and is built after the
  first successful prepare; crate-root docs in `lib.rs:30-45`,
  `ffi/mod.rs:8-20`, `socket_protector.rs:30` describe the real entry points.
- `xudp/message_stream.rs:64` takes the configured resolver.

### PR 1.2 — One crate, one pipeline (L)

Closes A-1, A-6, A-8 (supervisor `Released`).

- `src/main.rs` becomes a client of the library: delete its module tree,
  `use shoes::{config, control, logging, ...}`. `control` gains
  `prepare_servers(configs) -> Prepared` that does not require a TUN entry;
  `PreparedService` becomes the TUN-flavoured wrapper; `main.rs`'s
  `prepare_servers`/`launch_servers` call it. Remove `#![allow(dead_code)]`
  from `lib.rs` and the "Traps" entry from AGENTS.md; fix whatever the
  compiler now reports.
- `quic_server.rs` accept loop replaced by a call into `quic_transport`'s
  with its own endpoint builder; per-stream failure logging through
  `connection_end_level`.
- `Supervisor::stop` returns `TimedOut { waited: 0 }` (or an `Unknown` arm)
  when the supervisor thread is gone, never `Released`.
- Tests: the existing suites; plus a `cargo build --bins` on every CI target
  proves the thin binary links. Measure and record the build-time change.

### PR 1.3 — Typed errors at the layer boundaries (M)

Closes A-3.

- `config::Error` (thiserror): `Yaml`, `UnknownField { path }`,
  `Unsupported { option, platform }`, `UnresolvedReference`, `Io`. Keep the
  `Display` text identical to today's strings so FFI and gRPC messages do
  not change; `shoesd` maps `Unsupported` to `FAILED_PRECONDITION` and the
  rest to `INVALID_ARGUMENT`.
- `control::ExitReason { Requested, Failed(Error), EndedUnrequested }`
  carried in `ExitGuard` and `on_exit`; `ffi/common.rs` compares the variant,
  not the `ENDED_UNREQUESTED` string.
- `SocksError`, `HttpProxyError` enums in their handlers, converted to
  `io::Error` only at the `TcpServerHandler` boundary.
- `routing/udp_router.rs`: `enum CreateOutcome { Blocked, Remote(..) }`
  replaces the `PermissionDenied` overload; a real `EACCES` is logged and the
  session fails, not cached as a block. Test: a send that returns `EACCES`
  does not populate the blocked LRU.

### PR 1.4 — Parse, don't validate (M/L, can be split per protocol)

Closes A-2, A-5.

- Newtypes with `Deserialize` impls: `Uuid([u8; 16])`, `WgKey([u8; 32])`,
  `IpNet`, `PortSet`, `DnsUrl(ParsedDnsUrl)`. Each conversion deletes a
  validate.rs block and the matching runtime `expect`. Order: VMess/VLESS
  UUID (smallest), WireGuard keys and prefixes (removes
  `amneziawg/config.rs:223`'s second parser), ports and hop settings, DNS
  URLs (removes the double parse in `dns/builder.rs:577`).
- `RuleActionConfig` as `#[serde(tag = "action", rename_all = "lowercase")]`
  with one shared `action_from_parts`; `groups.rs`'s discriminator reduced to
  a `kind_of(&Mapping) -> Kind` table with a test that every variant's
  serialisation re-discriminates to itself; `server.rs`'s `VALID_FIELDS`
  replaced by `deny_unknown_fields` on the derived type.
- Property test (`proptest`): a generated `Config` survives
  `from_str(to_string(c)) == c`; this needs `PartialEq` on config types, which
  the newtypes make cheap.
- `serde_yaml` 0.9 → `serde_yaml_ng` (or `serde-norway`): touches
  `groups.rs`, `server.rs`, `option_util.rs` and the three call sites that use
  `Value`/`from_value`. This also turns the daily audit job green
  (RUSTSEC-2024-0449); do it first in this PR, as its own commit, so the rest
  of the PR is reviewed against a green baseline.

### PR 1.5 — Cancellation ownership (M)

Closes A-4, A-8 (polling).

- `run_tcp_server`, `run_unix_server`, `start_quic_listeners`, the tproxy
  demux and the TUN accept edge spawn connections through a
  `tokio_util::task::TaskTracker` and carry a `CancellationToken`;
  `start_servers` returns `Vec<Listener { token, tracker, handle }>`; a
  reload chooses drain (close, `wait()` with a timeout) or abort explicitly.
  tokio's documented pattern (`tokio.rs/tokio/topics/shutdown`).
- `impl Drop for Socks5UdpRelayStream` aborts the reader task (or replace the
  task with `poll_recv_from`). Test: open an association, close the TCP side,
  assert the UDP port is released within 100 ms.
- `control::stop_handle` waits on a `Notify`/`oneshot` fired from
  `ExitGuard::drop` instead of a 5 ms loop; `shoesd::await_interface` awaits
  a `watch` of the device name. Test: `StopOutcome::TimedOut` produced by a
  real `stop_handle` against a service that ignores shutdown, with a
  shortened timeout.

### PR 1.6 — Files, traits, feature gates (M)

Closes Q-3 (file sizes), A-7, A-9.

- Move `mod tests` to sibling files for `client_proxy_selector.rs`,
  `client_proxy_chain.rs`, `routing/udp_router.rs`; split `udp_router.rs`'s
  `SparePool`/`BufferPool` and `RoutingSession` into `routing/buffers.rs`
  and `routing/session.rs`.
- `plain_tcp` and `original_destination` move to a `SocketPassthrough`
  trait implemented by the five pass-through types; `relay()` and the
  redirect handler require it where they need it. The forwarding contract
  becomes a compile error instead of a comment.
- A ZST `OutboundCounters` whose methods inline to nothing without
  `control-stats`; the 67 `cfg` sites become unconditional.
- FFI: one `static FFI: Mutex<Option<Session>>` with
  `Session { handle, protect_cb, traffic_cb, stopped_cb, log_file }` taken
  and dropped as a unit; MOBILE.md entry.

---

## Phase 2 — Servers that fail like the reference (~2 weeks)

Theme 1 of the audit. One PR per protocol family; each has a spec with the
reference's exact behaviour and a probe test that asserts bytes *and timing*.

### PR 2.1 — Shadowsocks, Snell, Trojan (SS-D3, SS-D4, SS-D5, SS-D6, SS-D8)

On a handshake error: SS classic and Snell `shutdown(SHUT_WR)` then drain to
EOF under the existing 60 s timeout (SIP022 strategy 2, shadowsocks-rust
`tcprelay.rs:227-241`); SS2022 sets linger(0) before drop; Trojan gains a
`fallback` destination fed the already-read bytes (trojan-gfw "Other
Protocols", sing-box `service.go:99-106`). Snell ConnectV2: a zero-length
chunk is EOF when the request was cmd 5, and `poll_shutdown` emits one
(mihomo `shadowaead_stream.go:122-125`, `snell_pool.go`). EOF mid-chunk
becomes `UnexpectedEof`. Reject padding 0 with empty payload; enforce the
header-within-chunk rule; store classic salts after the first authenticated
chunk.

### PR 2.2 — VMess and VLESS (VM-D6, VM-D4, VL-V1, VL-V2, VL-V5, VL-V6, VL-V7)

VMess: on pre-body failure drain a per-user-seed 54–3266 bytes before
closing (`server.go` `BehaviorSeedLimitedDrainer`); drop the ChunkStream
requirement. VLESS: single read with timeout and fallback on <18 bytes
(`inbound.go:306-336`); reject `flow == xtls-rprx-vision && cmd == UDP`;
force TLS 1.3 for Vision on both sides; unpad buffers <16 bytes in `Initial`;
`poll_flush` releases a held TLS-looking suffix as a Continue frame.

### PR 2.3 — Reality server (RE-R1, RE-R3, RE-R5, RE-R6 full)

Every validation failure after the ClientHello was forwarded becomes
"forward" (`tls.go:285-300`); reuse the decoy's parsed ServerHello with only
the key share swapped (`handshake_server_tls13.go:107-130`), forwarding if the
decoy picked an unsupported suite; emit the NewSessionTicket-sized dummy
record and the post-handshake length mimic (`tls.go:410-438`); implement
KeyUpdate. Send alerts on failure per RFC 8446 §6.2. Test: an end-to-end
`RealityClientConnection` ↔ `RealityServerConnection` handshake (none exists
today), plus a recorded decoy ServerHello whose bytes the server must
reproduce except the key share.

### PR 2.4 — ShadowTLS, Hysteria2, NaiveProxy, WebSocket (ST-S2, ST-S4, HY-D1, NA-N3, NA-N4)

ShadowTLS server relays every malformed or non-ClientHello first record to
the handshake server (`server.rs:721-723,280-285`), keeps the raw bytes for
that purpose, and relaxes the record-version check; Local mode completes the
rustls handshake and serves the inner fallback or is documented test-only.
Hysteria2 drops the 3 s auth timeout and the reason phrase; the idle timer
ends unauthenticated connections as upstream (`server.go:160-253`).
NaiveProxy answers `GET /` with 404 or the fallback file; `padding-type`
negotiation takes the client's first supported entry. (WebSocket 404 landed
in PR 0.4.)

Each PR in this phase adds a `tests/probe_<family>.rs` that connects as a
wrong-password client, a 16-random-byte client, a one-byte client and a
slow client, and asserts what comes back and when, against the behaviour the
spec cites from the reference.

---

## Phase 3 — Clients that look like the reference (~3 weeks)

Theme 3. Ordered by how cheap the DPI rule is that catches today's shape.

### PR 3.1 — ShadowTLS client completes the handshake (ST-S1, M)

Un-XOR with SHA256(pw‖sr), strip the 4-byte tag, feed rustls until
`!is_handshaking()`, write CCS and Finished unchanged
(`shadow-tls/src/client.rs:252-258,438-460`); strict mode sends the fake GET
on HMAC mismatch before closing (`client.rs:546-573`). Test: the client
asserts `!is_handshaking()` before building the stream, and the server
observes the Finished record. This is also the PR that gives
`src/shadow_tls/` its first tests: ClientHello modify/verify round trip,
residual frames interleaved with the first HMAC_S frame.

### PR 3.2 — First flight carries the payload (VL-V3, SS-D7, RE-R2 client half)

VLESS: pass the header into `VisionStream::new_client` and prepend it to the
first padded write, with a 500 ms timer emitting the empty long-padding frame
(`outbound.go:333-347`, `proxy.go:359-360`). Trojan and Shadowsocks clients:
defer the header to the first `poll_write`, or use the `early_data` plumbing
in `client_proxy_chain.rs:483-549`. Tests: the first outer record's size
range matches the reference's.

### PR 3.3 — Reality hybrid key share and ClientHello shape (RE-R2, RE-R8, RE-R4, RE-R7; L)

Client offers `X25519MLKEM768` (0x11EC: ML-KEM-768 encapsulation key 1184
bytes ‖ X25519 public 32) ahead of X25519 and derives AuthKey from the X25519
half; server accepts 0x11EC (len 1216), takes the tail for auth
(`tls.go:214-237`) and either implements the hybrid with aws-lc-rs ML-KEM-768
(shared secret = mlkem_ss ‖ x25519_ss, share = ct ‖ pub) or answers plain
X25519 when also offered. ClientHello gains GREASE, psk_key_exchange_modes,
extended_master_secret, status_request, SCT and padding in Chrome's order.
On HMAC mismatch the client falls back to x509 verification and the spider
behaviour. Spec required; the version deployed on the user's servers is the
compatibility target, confirmed before the PR is cut.

### PR 3.4 — mieru wire shape (MI-M1, MI-M2, MI-M3, MI-M4, MI-M5; M)

`scale_down()` and `intn()` reproducing `rng.Intn` (`pkg/rng/rng.go:34-36`)
for data, ASCII and entropy padding lengths; `MieruStream::open(initial_payload)`
sealing the ≤1024-byte socks5 request into the open request
(`session.go:343-371`); `closeSessionRequest` on shutdown and
`closeSessionResponse` on receipt; fill `unack_seq`/`window_size`/`fragment`;
ASCII run length drawn once. Tests: padding mean under 70 over 10k draws;
first segment carries a payload tag block; shutdown emits the close segment;
one vector against a Go-captured segment (fixed key, nonce, timestamp).

### PR 3.5 — AnyTLS and NaiveProxy sessions (AT-A1, AT-A2, AT-A3, AT-A4, NA-N1, NA-N2; M)

AnyTLS: `Arc<ArcSwap<PaddingFactory>>` in the client handler applying
`UpdatePaddingScheme`; a session pool keyed by sequence, newest idle first,
reaped at 30 s, `min_idle_session` config (`client.go:70-138,201-242`);
unknown commands skipped. NaiveProxy: clear the session slot on
`send_request` error or when the driver has finished; move session ownership
above the dial so a live session means no new TLS connection (a
`supports_connection_reuse()` hook on `TcpClientHandler`, shared with
AnyTLS); fragmentation thresholds 200/100–200. Both need the chain to be able
to *not* dial, which is the one architectural change in this phase; design it
once in a spec for both.

### PR 3.6 — WebSocket early data and SOCKS bind address (TR-3, TR-12; M)

Server: when `max_early_data` is configured, decode base64url from the
`early_data_header_name` header (default `Sec-WebSocket-Protocol`) or the
path suffix and feed it through `unprocessed_data`
(`v2raywebsocket/server.go:72-104`). Client: send the first write up to
`max_early_data` in the header the same way (`Xray websocket/dialer.go`).
Config: `max_early_data`, `early_data_header_name` on both sides, mirroring
sing-box's names. SOCKS5 UDP ASSOCIATE answers with the TCP connection's
local IP rather than the listener bind address. Tests: a recorded sing-box
early-data request decodes to the payload; BND.ADDR is never `0.0.0.0`.

### PR 3.7 — Small client parities (VM-D5, VM-D3, VM-D1 doc, WG-A2, WG-A3, WG-A4)

VMess client sends GlobalPadding (0x08) and supports AuthenticatedLength
(server too); document that `cipher: none` no longer works against Xray.
awgtun: handshake retransmit jitter 0–334 ms (`timers.rs:316`); shoes caps
`jc` at 128 and calls `validate_for_mtu`; decoys and the initiation are taken
inside one critical section. Rename `crc32c` to `crc32_ieee`.

---

## Phase 4 — Tests that can see the wire (~2 weeks, parallel with 2–3)

Theme 6. This phase is what stops the next audit from finding the same
classes.

### PR 4.1 — Known-answer corpus

`tests/data/kat/<protocol>/` with vectors computed by the reference
implementation for: EVP_BytesToKey, HKDF-SHA1 "ss-subkey", blake3 2022 subkey,
Argon2id (Snell), VMess KDF/AuthID/crc32, salamander key (replace the
self-derived "known vector"), mieru PBKDF2 chain, ShadowTLS HMACs, Reality
AuthKey and SessionId seal (from an Xray capture), RFC 8448 TLS 1.3 vectors
for the Reality key schedule. Each test reads the fixture and compares bytes.
The generator scripts live beside the fixtures and are run in a container,
never from the repo root.

### PR 4.2 — Reference-captured frames

For each protocol with a Go/C++ reference, one captured client flight and one
server flight (`.bin` + a short README with the config and commit used),
decoded by shoes' parser in a test. Minimum set: SS2022 request, VMess
request and UDP chunk with padding, VLESS Vision first frame, XUDP New+Keep,
Hysteria2 auth request and UDP message, TUIC Authenticate and Packet, mieru
open request, AnyTLS Settings+SYN, NaiveProxy padded frame, ShadowTLS
ClientHello, AmneziaWG I-packet and junk sequence, a sing-box `.srs` with
mixed ranges, a sing-box WebSocket request with early data.

### PR 4.3 — Probe harness and interop job

`tests/probe_*.rs` (started in Phase 2) gets a shared harness that records
bytes received and the time to close. A nightly (not per-PR) CI job runs
sing-box, Xray, hysteria, tuic, mieru, anytls and shadow-tls binaries in a
container as servers and clients against shoes for one TCP and one UDP
exchange each; failures open an issue rather than block merges. `scripts/bench`
already has the container plumbing.

Added 2026-10-21: SF-10 of `docs/specs/2026-10-21-lessons-from-steer.md` belongs
to this PR. It covers:

- a three-outcome probe result (data, closed, silent), asserted with time
  bounds rather than error text;
- a fixed probe corpus;
- a slow-drip prober that tells a per-read timeout from a handshake deadline;
- nightly cells whose skips count against the run;
- the ClientHello shape test against the #95 capture;
- a Vision cut property test;
- `.srs` oracle fixtures.

The fake-IP and config-loading fixes from that spec (PRs S.1 and S.2 of its
plan) come before this PR.

Split, 2026-10-22, since `tests/probe_*.rs` never landed (Phase 2 was
deferred):

1. The harness-free checks: the ClientHello shape test, the Vision cut
   property, the `.srs` oracle.
2. The probe harness: three outcomes with time bounds, the probe corpus,
   the slow-drip prober, against shoes' own servers in-process.
3. The nightly interop job, with loud skips.

### PR 4.4 — Zero-test files

Bring every file in the audit's zero-test list to at least the byte-level
cases the audit names for it; `ffi/android.rs` gets the equivalent of
`ios.rs`'s six tests through a JNI test double.

---

## Phase 5 — Performance fidelity and DNS hardening (~1 week)

Closes HY-D5, TU-D3, TU-D6, TU-D10, DN-D1, DN-D2, DN-D3, FI-1, TL-1.

- `BbrConfig::initial_window(32 * 1200)` for Hysteria2 now; a custom quinn
  `Controller` implementing upstream's token-bucket pacer later (the same
  work Brutal needs; spec first, measured with `scripts/bench`).
- TUIC: reuse `quic_outbound::DatagramRouter` with a uni-stream equivalent
  keyed on bytes 2..4 (closes TU-D6); association lifetime keyed on
  Dissociate with a large configurable idle default; one heartbeat task per
  connection gated on a live-task counter; no server-sent heartbeats.
- DNS: `case_randomization = true` for UDP upstreams; `RefreshingResolver`
  rebuilds on a max age as well as idle; system-resolver cache 5–10 min;
  fake IP responder also takes TCP/53.
- TLS: `max_early_data_size = 0` on every server config until a reader
  exists.

---

## Practices to adopt crate-wide, starting with Phase 1

These are the Rust-side conclusions of the audit, stated once so every PR
can cite them instead of re-arguing.

1. **Typed errors inside, `io::Error` at the trait boundary.** A protocol
   handler returns its own `thiserror` enum; conversion to `io::Error` happens
   once, where the `TcpServerHandler`/`TcpClientHandler` signature demands it
   (Rust API Guidelines C-GOOD-ERR). Never encode a decision in an
   `ErrorKind`.
2. **Parse, don't validate.** A config field is the decoded type with a
   `Deserialize` impl that fails at the field with serde's path; the runtime
   never re-parses a string the validator already read (C-NEWTYPE,
   C-VALIDATE). `expect("validated during config load")` is a smell the lints
   table now flags.
3. **Every spawned task has an owner.** `TaskTracker` + `CancellationToken`
   per listener; a struct that holds a `JoinHandle` aborts it in `Drop`.
   `select!` branches that are not cancel-safe (`read_exact`, `write_all`,
   `Mutex::lock`) are wrapped or moved out of the select; tokio's list is the
   reference.
4. **No polling where a notification exists.** `Notify`, `watch`, `oneshot`.
5. **One crate boundary.** Binaries link the library; the library has no
   crate-wide `allow(dead_code)`; a local allow names the change that removes
   it.
6. **Safe conversions over `from_raw_fd`.** `socket2::SockRef`,
   `UdpSocket::from(socket2)`; `unsafe` only where there is no safe API
   (`splice`, `mallopt`, platform arms) and always with a SAFETY comment the
   lint enforces.
7. **Tests prove conformance, not symmetry.** A new protocol or a byte-level
   change ships with a known-answer vector or a reference-captured frame, and
   with a probe test if it changes failure behaviour. Round trips remain
   useful for plumbing, not for layouts.
8. **Tests live beside the code they test** once a file's tests outgrow its
   code; a file over ~1500 lines is split by responsibility.
9. **Feature gates by type, not by statement.** A ZST with no-op methods
   replaces scattered `cfg` blocks (the `control-stats` counters are the
   model; `control-logs` can follow).
10. **Keep `log`.** The size budget, compile-time level filtering and the
    rotation tests argue against a `tracing` migration in the library; the
    daemon may adopt `tracing` with its `log` bridge if it ever wants spans.

## Order of work, restated

0.1 → 0.2 → 0.3 → 0.4 → 0.5 (release). Then 1.1 → 1.2 → 1.3 → 1.4 → 1.5 →
1.6. Phases 2, 3 and 4 interleave by protocol after Phase 1 is in; 3.1 and
3.3 are the two with the most user-visible effect and 3.3 is the only one
that needs a decision from the user first (which REALITY version the servers
run). Phase 5 last. A release after each phase.

## What this plan does not do

- Implement anything in ROADMAP.md's "Explicitly not planned" or the
  postponed awg-manager and management-API items.
- Add Shadowsocks native UDP, Trojan UDP, VMess/VLESS mux.cool, SOCKS4, DoQ,
  XUDP session migration, or sing-box early-data for HTTPUpgrade. Each is a
  feature with a consumer question, not a correctness fix; they are recorded
  in the audit as MISSING so the question can be asked later.
- Replace smoltcp, hickory, quinn or awgtun. Where the audit found a defect
  in awgtun (jitter), the fix goes to the fork.
