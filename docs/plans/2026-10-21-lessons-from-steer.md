# Lessons from steer: implementation plan

Spec: `docs/specs/2026-10-21-lessons-from-steer.md` (findings SF-1 to SF-11).
Written 2026-10-21. It runs alongside the quality plan
(`docs/plans/2026-10-15-quality-and-correctness.md`); the order below says
where each PR falls relative to that plan.

steer is GPL-3.0. No PR here copies its code. Each behaviour is checked
against the protocol's reference implementation, and where possible a vector
from `tests/data/kat/gen` pins it.

Per-PR rules, as in the quality plan:

- branch off `mobile`;
- pass the full local gate;
- add a CHANGELOG entry at the top of `## Unreleased`;
- mark the spec's SF row "**Fixed in #N.**" in a follow-up commit on the same
  PR.

## Status, 2026-10-22

S.1 merged as #99 and S.2 as #100. Quality-plan 4.3: parts 1 (#101) and 2
(#102) are done; part 3, the nightly job, is left. S.3 is next.

One finding changes S.4's starting point. #101 found that sing-box's
REALITY client strips X25519MLKEM768 from its hello
(`common/tls/reality_client.go:148-159` in v1.14.3), while shoes offers it
as Xray's client does. The `auto` default should be weighed against that:
a sing-box-shaped hello carries no hybrid share at all.

## Order

| Step | PR | Findings | Before or after quality-plan 4.3 |
|---|---|---|---|
| 1 | S.1 Fake IP: no recycling under a live address, no literal dial, local names bypass | SF-1, SF-2, SF-3 | before |
| 2 | S.2 Configs that should load: REALITY SNI, Xray user ids | SF-4, SF-5 | before |
| 3 | 4.3 Probe harness and nightly interop (quality plan), with SF-10 folded in | SF-10 | — |
| 4 | S.3 Fingerprint: cipher order by hardware, HTTP headers | SF-7, SF-8 | after |
| 5 | S.4 Post-quantum fallback (REALITY, then rustls) | SF-6 | after |
| 6 | S.5 Brutal controller with model tests | SF-9 | after |
| 7 | S.6 Brutal negotiation, both ends, interop and bench | SF-9 | after 4.3's rig exists |

S.1 and S.2 go first: two of them are real bugs in the fake-IP path, and the
other two keep valid configs from loading. S.5 and S.6 need 4.3's interop rig
to verify against apernet.

## PR S.1 — Fake IP safety (S)

Closes SF-1, SF-2, SF-3.

- `src/dns/fake_ip/pool.rs`:
  - `lookup` promotes the mapping in the LRU;
  - each entry records its last use;
  - `assign` won't recycle an entry used within `MIN_REUSE_AGE` (600 s), and
    reports the pool as exhausted instead.
- `src/dns/fake_ip/` responder: on exhaustion, the query is forwarded as a
  bypassed name would be, and a warning is logged once per episode.
- `src/tun/mod.rs`, `src/dns/fake_ip/mod.rs`:
  - an in-pool destination with no mapping is refused: RST for TCP, dropped
    for UDP;
  - the refusals are counted and logged at debug, at most once a second;
  - `destination_to_net_location` returns a type that can say "refuse".
- `src/config/types/tun.rs`: `bypass_defaults` (default true), with the
  built-in suffix list in `src/dns/fake_ip/bypass.rs` (or wherever
  `BypassList` lives).
- CONFIG.md: `bypass_defaults` and the exhaustion behaviour.
- Tests, as listed in the spec: recycling under `lookup`, exhaustion
  answering with the real address, the unmapped refusal (a TUN test), and
  the bypass list. Use paused time throughout.
- CHANGELOG: two behaviour changes, local names no longer tunnelled and
  unmapped fake IPs refused. Call them out.

## PR S.2 — Configs that should load (S)

Closes SF-4, SF-5.

- `src/tcp/tcp_client_handler_factory.rs`: a missing REALITY `sni_hostname`
  becomes a config error, reported by `config/validate.rs`.
- `src/reality/reality_client_hello.rs`: no `server_name` extension for `""`
  or an IP literal. The REALITY server side accepts `""` in its server
  names, if it doesn't already.
- `src/uuid_util.rs` and `src/config/types/uuid.rs`:
  - accept any version and variant of a 32-hex id;
  - turn a 1–30 character string into the nil-namespace v5 id, for VLESS and
    VMess;
  - reject 31 characters and anything over 36;
  - TUIC stays hex-only.
- `tests/data/kat/gen`: a vector for the string rule from the reference's
  own function. Check Xray `common/uuid` and sing-box's VLESS user parsing
  first; if the two differ, write that down in the spec.
- Tests: the config error, the hello without SNI, a UUIDv7, the string id
  vector, the 31-character rejection.

## PR 4.3 additions (quality plan)

SF-10 goes into PR 4.3's scope; it doesn't add a PR of its own:

- the three-outcome probe result with time bounds;
- the probe corpus;
- the slow-drip prober;
- skipped nightly cells that count against the run;
- the ClientHello shape test against the #95 capture;
- the Vision cut property test;
- the `.srs` oracle fixtures.

If 4.3 runs long, the shape test, the Vision cut test and the `.srs` oracle
can go into a small PR of their own, since they don't need the harness.

## PR S.3 — Fingerprint: cipher order and HTTP headers (S)

Closes SF-7, SF-8.

- `src/reality/reality_cipher_suite.rs` and `src/rustls_config_util.rs`:
  `aes_hardware()` detection (std's feature-detection macros; unknown
  architectures count as no AES), and ChaCha20 first without it. Configured
  suites still win.
- First, capture Xray's WebSocket and HTTPUpgrade client requests with the
  frame generator (`tests/data/kat/gen`, a `frames-xray-http` fixture).
  Then:
  - `src/websocket/websocket_handler.rs` and `src/httpupgrade/client.rs`
    send the default Chrome User-Agent and the headers the capture shows, in
    Xray's order;
  - a user-set `User-Agent` replaces the default, and an empty one removes
    it.
- Tests: the ordering function with detection injected; golden request
  bytes against the capture.

## PR S.4 — Post-quantum fallback (M)

Closes SF-6.

- Config `post_quantum: auto | on | off` on REALITY outbounds (default
  `auto`), documented in CONFIG.md.
- `src/reality/reality_client_hello.rs`: the hybrid share becomes optional.
- `src/reality_client_handler.rs`:
  - in `auto`, retry once with the classical hello when the first attempt
    fails before any server byte;
  - a per-process `ClassicalOnly` cache keyed by address, with a TTL of one
    hour;
  - report the first error.
- Second commit: the same option on the rustls client config, through the
  key-exchange group list.
- Tests: a local listener that drops hellos over 1500 bytes; one that drops
  everything; `on` and `off` never retry. Use paused time for the TTL.

## PR S.5 — Brutal controller (M)

Part of SF-9.

- `src/quic_transport/brutal.rs`: a quinn `Controller` and
  `ControllerFactory`:
  - the switchable BBR/Brutal controller holding `Arc<AtomicU64>`;
  - five one-second byte slots;
  - `ack_rate` with the 50-sample threshold and the 0.8 floor;
  - window `max(rate × srtt / ack_rate, 2 × MTU)`;
  - `initial_window` 10240.
- `src/quic_transport/mod.rs`: `controller_factory` builds the switchable
  controller for Hysteria2 connections.
- Model tests as listed in the spec. No network.
- No behaviour change yet: the handle stays 0, so the controller runs BBR
  as before. Check that the existing Hysteria2 throughput tests are
  unchanged.

## PR S.6 — Brutal negotiation and verification (M)

Completes SF-9.

- Config `bandwidth: { up, down }` on the Hysteria2 client and server, with
  a rate-string parser and the 64 kB/s to 2³¹ B/s bounds. Also
  `disable_loss_compensation`.
- `src/hysteria2/auth.rs` and `src/hysteria2/server.rs`:
  - send and parse `Hysteria-CC-RX` per the negotiation table;
  - set the handle once authentication succeeds.
- Tests:
  - every row of the negotiation table, as unit tests against the header
    logic;
  - a shoes-to-shoes connection whose controller switches;
  - the apernet client and server cells in the nightly job, both directions.
- Bench (`scripts/bench`, netem at 50 ms delay with 0.5% and 5% loss): BBR
  against Brutal, recorded in the PR. The acceptance bar is Brutal within
  10% of the declared rate.
- ROADMAP: update the Hysteria "Performance" rows.

## Not planned

SF-11 (xhttp, gRPC, ECH, REALITY `pqv`, Gecko, DoQ, `.srs` logical rules)
stays in the spec as a record. Each needs its own decision before a plan.
