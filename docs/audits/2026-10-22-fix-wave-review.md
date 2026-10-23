# Review of the fix wave — 2026-10-22, at `mobile` b8a42c60

Companion to [the 2026-10-15 audit](./2026-10-15-quality-and-correctness-audit.md)
and [its plan](../plans/2026-10-15-quality-and-correctness.md), and to the
[steer spec](../specs/2026-10-21-lessons-from-steer.md). Twenty PRs
(#83–#103) merged since v0.7.0, on top of #55–#82; between them they mark
32 audit findings and five steer findings fixed. This review asks whether
each claim holds in the code as it is now, and what was missed beside it.

## Method

Four parallel read-only passes over the current tree, one per era of PRs,
each given the finding list, the claimed PR, and the instruction to be
skeptical: locate the fix by symbol (the audit's line numbers are stale),
confirm no later commit reverted it, name the test that exercises it, and
compare every constant against the reference source where it is on disk
(`~/go/pkg/mod`: sing-anytls v0.0.11, mieru v3.36.0, sing-shadowsocks
v0.2.7/v0.2.8, xray-core v1.260327.0; `~/VibeCode/awgtun` and
`amneziawg-go`). A fifth pass checked the documents against the code:
every CHANGELOG constant, every option added since v0.7.0 against
CONFIG.md and `examples/`, ROADMAP and AGENTS.md against the changelog,
Cyrillic in tracked files, credential-looking strings in new fixtures.
The full local gate ran on the same commit: five clippy configurations,
iOS and Android lints, `cargo fmt`, 1800 library tests plus the
integration and `shoesd` suites, all green.

## Verdict

**All 37 claimed fixes are present, none reverted, and each has a test.**
No security rule is broken in anything read: every authentication compare
goes through `ct_eq`, and no presented credential reaches a log or error.
What the review found is at the edges of the fixes — a new option without
bounds, a sibling path the fix did not reach, a test weaker than its
finding — and in the documents. Everything that is code is closed in the
PR this document lands with, #105; what is deliberately left is written down.

## The findings, one by one

Verdicts: **verified** is fix present with a test that exercises the
finding; **partial** names the part that was not covered.

### Phase 0 (#55–#58)

| ID | Verdict | Note |
|---|---|---|
| SS-D1 | verified | Snell *drops* an over-cap datagram (debug log, `Ok`), the SS message stream *errors*. Both tested; the audit row now says which is which. |
| SS-D2 | verified | `from_fields` is the only constructor; the error names lengths, not the key. |
| ST-S3 | verified | |
| RE-R6 | verified, narrowed | No longer an abort. The client discards NewSessionTicket; **KeyUpdate still ends the connection** with an error on both sides, since neither rotates keys. Recorded in the audit row. |
| VL-V4 | verified | 70,000-byte write test. |
| VM-D2 | verified | |
| RS-1 | verified | Against the sing-box-compiled fixture. |
| TR-2 | verified | |
| HY-D2 | verified; **e2e test added** | Only `UdpRouteCache`'s unit test covered it. Now one Hysteria2 session and one TUIC association each reach two targets, the second named by hostname, and each reply is checked to carry its real source (`hysteria2/client.rs`, `tuic/client.rs`). The test fails when the server labels replies with the first source. |
| WG-A1 | verified | The test builds `Tunn` itself; both production sites visibly call `session_index()`. |
| TU-D4 | verified | |
| TR-5/6 | verified | |
| TR-8 | verified | Byte-exact `101 Switching Protocols` test. |
| TN-T1/T2/T3 | verified; **T3 half deliberate** | Fragments are dropped; inbound checksums are *not* verified and will not be: on a TUN every inbound packet is the local kernel's, and on Linux with the vnet header the kernel hands over checksums it has left unfinished for offload (`tcp_stack_direct.rs`), so verifying would reject valid traffic. The audit row says so. |
| XU-X1/X2 | verified | |
| XU-X3 | verified | 512 metalen, 7526 response cap. |
| TR-7/11 | verified | TR-10 stays open. |

### Phase 3 (#79–#88)

| ID | Verdict | Note |
|---|---|---|
| SS-D7 | verified; **gap closed** | The SS2022 request always carried 1–900 bytes of padding; sing-shadowsocks adds it only when the first payload is under 900 (`shadowaead_2022/protocol.go:289-291`, `MaxPaddingLength`). The header is now built once the payload's length is known (`DeferredHeaderStream::new_with`), and padded by that rule. |
| VL-V3 | verified | 500 ms and the 900+rand(500) long padding match Xray. |
| MI-M1 | verified | Comment said the draw averages `0.4 n`; it is `0.2 n` (the test asserted the right number). Fixed. |
| MI-M2 | verified | 1024 confirmed upstream. |
| MI-M3 | verified | |
| MI-M4 | verified | shoes advertises `4096 − unstarted segments`; upstream is `4096 − recvBuf − recvQueue`. Identical for a reader that keeps up; an approximation under backlog. Cosmetic. The spec's "unack 0 over TCP" claim was traced to `session.go` and holds. |
| MI-M5 | verified | |
| AT-A1 | verified | |
| AT-A2 | verified | 30 s check and timeout match sing-anytls defaults. |
| AT-A3 | verified | shoes skips an unknown command *with* its declared payload; upstream skips the 7-byte header only. Diverges only for a future command with data; shoes' choice is the safer one. |
| AT-A4 | verified | |
| NA-N1 | verified | |
| NA-N2 | verified | naiveproxy (C++) is not on disk; the code cites `naive_padding_socket.cc`. A stale "200-300 bytes" comment fixed. |
| TR-3 | verified | |
| TR-12 | verified | |
| VM-D1 | documented, as claimed | |
| WG-A2 | verified in awgtun | `7a78f45` is an ancestor of the pinned `42a7e9f`. |
| WG-A3 | verified | The 128 is attributed to the kernel module, whose source is not on disk; amneziawg-go has no cap. |
| WG-A4 | verified | |

### Phases 4 and 5, 4.3 (#89–#102)

| ID | Verdict | Note |
|---|---|---|
| TU-D6 | verified | |
| TU-D3 | partial → **closed** | `udp_timeout` had no bounds (`0` loaded and reaped every association on the first sweep), no server-side test and no example. Now bounded 1–86400 like tproxy's, the sweep is one function with tests, and `examples/tuic_v5.yaml` carries it. The reference followed is sing-box's default, not tuic's keep-until-Dissociate; the audit row says so. |
| TU-D10 | verified, indirectly | Heartbeat gating is tested through `LiveCounts`, not by observing datagrams. |
| TL-1 | verified | |
| HY-D5 | verified | The spec records that the pacer stays quinn's. |
| DN-D1 | verified | The option flag; hickory owns the behaviour. |
| DN-D2 | partial → **closed** | A group mixing the system resolver with a DoH/DoT one was not wrapped in `RefreshingResolver` ("mixed groups stay as-is"), so its bootstrap was still resolved once. Every spec now yields a plan that can rebuild its entry, and a mixed group is rebuilt entry by entry on the same policy. |
| DN-D3 | verified | The 5-minute constant is asserted at `resolver.rs` (`DEFAULT_RESULT_TIMEOUT_SECS == 300`). |
| FI-1 | verified | |
| RE-R2 (client) | verified | The shape test sorts extensions, so their *order* against sing-box is unpinned; "Chrome 133" rests on sing-box's uTLS capture. |
| VL-V5 | **closed by #101, row was stale** | The audit's proposed remedy (buffer the UUID across records) was never Xray's behaviour: `XtlsUnpadding` returns a short or non-matching first read as plain data, which is what #101 did. The row is updated; the threshold is 21 bytes, not 16. |
| 4.1, 4.2 fixtures | verified | Every CHANGELOG item maps to a fixture and a test; the KAT README rows all resolve. |
| 4.3 probe harness | verified | 11 × 5 cells; PH-1..3 each present as a `Finding` cell and in the spec. |

### Steer (#99, #100)

| ID | Verdict | Note |
|---|---|---|
| SF-1 | verified | "Held" is the spec's "last use": DNS answer or connect-time lookup within 600 s. A single connection open longer than that with no new connect can still be recycled; that matches the spec's definition. |
| SF-2 | partial → **closed** | The TCP leg was tested; the UDP drop was not. `udp_manager.rs` now has the test. |
| SF-3 | verified | Suffix list, default and off switch all documented. |
| SF-4 | verified; **sibling closed** | REALITY was fixed; a plain TLS or ShadowTLS hop with `sni_hostname: ""` still reached rustls's `ServerName` unwrap. `""` now sends no name on both, and a name rustls cannot hold is a config error (`validate_tls_server_name`). |
| SF-5 | verified | KAT vectors, hex-only TUIC. |
| #100 review fixes | verified | Fallback chains validated; `under_tls` filters an empty name. |

## Documents

- **CHANGELOG `## Unreleased`** covers every code PR #83–#102, and every
  constant it names matches the code (600 s reuse, 300 s TUIC default,
  30 s AnyTLS idle, 32-packet window, 10-minute DoH rebuild, 5-minute
  cache, `max_early_data_size` 0/`u32::MAX`, `.srs` v0, 60 s deadline,
  100–200 pieces, `jc` 128, `crc32_ieee`, the dependency versions).
- **CONFIG.md** had no WireGuard or AmneziaWG client section at all, so
  the 16-bit `s1`–`s4` and the `jc`/`jmax` limits from #88/#90 reached only
  an example comment. Both sections exist now.
- **No example parsed** `max_early_data`, `early_data_header_name`,
  `min_idle_session`, TUIC `udp_timeout` or `bypass_defaults`. They do now,
  and `socks_through_wss_vmess` joined the smoke loop.
- **AGENTS.md** said `hysteria2/server.rs` still had its own fragment
  table; it moved to `Defragmenter`. Fixed.
- No Cyrillic in any text file. The new KAT fixtures carry real-looking
  keys and passwords; they are generator output (`tests/data/kat/gen/`),
  not live credentials.

## Left open, on purpose

- **TN-T3's checksum half**, for the reason above.
- **RE-R6**: KeyUpdate ends the connection; key rotation is Phase 2 work
  (PR 2.3, "RE-R6 full").
- **TU-D10**: a wire-level heartbeat test would pin the behaviour better
  than the counter test does; worth adding with 4.3 part 3's interop run.
- **RE-R2**: extension order is not pinned by the shape test.
- **AnyTLS server** authenticates by hashed lookup rather than `ct_eq`,
  as sing-anytls does. Predates this wave; noted for the Phase 2 pass.
- Reference numbers not checkable on disk: sing's 300 ms
  `ReadPayloadTimeout`, naiveproxy's 200/1024/100–200, the amneziawg kernel
  module's 128.

## Release

Nothing above is a regression from v0.7.0; every gap is newly added
surface that was slightly under-validated. With the fixes in this PR the
tree is ready for v0.8.0: the bump PR rewrites `## Unreleased` into notes.
