# Roadmap

Where this fork stands against sing-box and Xray-core, and what is worth building
next. Written 2026-08-09 against `mobile` at `7ed9f0b`; the Hysteria section was
added 2026-08-11 against `apernet/hysteria` at `app/v2.12.1`. Refreshed
2026-08-23 against `mobile` at `c83ce5f`, 128 commits later: the protocol lists
and the mieru section were re-checked against the tree, and every Tier 2 and
Tier 3 item was confirmed still open. Refreshed again 2026-08-24 against
`mobile` at `a27b666`, when the desktop control API landed and earned a section
of its own. Refreshed again 2026-08-25 against `mobile` at `30346aa`, when the
first two phases of Hysteria2 conformance landed — which corrected two claims in
the Hysteria section that had been wrong rather than merely stale. Refreshed
again 2026-08-27 against `mobile` at `a84dcc6`, when runtime stats reached the
mobile FFI: that closed the naming blocker Tier 2 item 6 was waiting on, and
two claims here — HTTPUpgrade as pending, and per-connection statistics as
having nowhere to send a per-server figure — were stale rather than wrong.
Refreshed the same day on `windows-tun`, when the Windows TUN backend landed
and desktop sub-project #2 closed — which also turned the Windows CI job from
a check into the full test suite, and fixed two Windows defects the suite
surfaced the first time it ran there: QUIC inbounds panicking on SO_REUSEPORT,
and dual-stack UDP relays losing all their IPv4 traffic because Windows
defaults IPV6_V6ONLY on. Refreshed 2026-08-28 against `mobile` at `2cccb2e`
(v0.2.16), after the first external consumer of the Swift package measured
what it cost and asked for what it lacked: the package split into a host and
an extension product, the engine gained a stop callback that replaced the
provider's health check, and the rest of that list is a section of its own.
Refreshed 2026-09-01 against `mobile` at `a87c616` (v0.2.18), when the two
comparison sections were re-verified against the source tree and both
competitors were re-checked against their current releases — sing-box v1.14.0
and Xray-core v26.7.28, which is where Xray-core joined the table. That pass
corrected four claims about our own tree that had gone stale rather than
merely old: macOS was missing from the TUN platforms, HTTPUpgrade from both
protocol lists, destination-port matching from the routing row, and
`src/control/` was being described as a "control API" when it is an in-process
module with no network surface at all. Refreshed 2026-10-15, when the focus
was narrowed: mobile clients, desktop clients over the daemon, performance
and stability. The Clash API that had landed on 2026-09-11 (slice 1: the
controller, a connection registry threaded through every inbound, Prometheus
`/metrics`) was removed the same day, since its only consumers were the
postponed awg-manager engine and a web panel that was never started. The
awg-manager section below is now a note on what was postponed. Refreshed
2026-10-21 against `mobile` at `bf5d5a6`, after a review of steer (a GPL-3.0
C router with its own protocol clients) turned up two fake-IP bugs, two
configs that should load and do not, and the details a Brutal spec needed;
that review is a section of its own, with a spec and a plan behind it.
Refreshed 2026-10-22 against `mobile` at `83775cd`, nineteen PRs after
v0.7.0: the steer table caught up with S.1 and S.2, the quality plan got
a section of its own, and the fingerprinting risk now records that
sing-box's REALITY client sends no post-quantum share.

## Focus, as of 2026-10-15

In order: mobile clients (Android and iOS through the FFI), desktop clients
through `shoesd`, and performance, architecture and stability of what already
ships. Not now: the awg-manager engine, any web panel, and any management
interface over the network beyond the daemon's own socket. A network API that
reaches into every inbound is exactly the kind of surface this narrowing is
meant to stop accumulating; if one is wanted later it starts from a spec, not
from the removed code.

The audience is anyone deciding what to work on. Every gap below is stated with
the file it lands in, so the estimate is checkable rather than a guess.

## Quality and correctness plan

The work since 2026-10-15 follows
[docs/plans/2026-10-15-quality-and-correctness.md](./docs/plans/2026-10-15-quality-and-correctness.md),
sequenced from
[the audit](./docs/audits/2026-10-15-quality-and-correctness-audit.md);
the plan's status table says which PR closed what.

- **Done:** Phases 0 and 1, most of Phase 3, and Phase 5. A 2026-10-22
  review ([docs/audits/2026-10-22-fix-wave-review.md](./docs/audits/2026-10-22-fix-wave-review.md))
  checked every fix claimed since v0.7.0 against the code and the
  references: all present; the gaps beside them were closed in #105.
- **Phase 4:** known-answer vectors and reference-captured frames are
  done, as are the reference checks and the probe harness (PR 4.3, parts
  1 and 2). The nightly interop job against the reference binaries is left.
- **Phase 2 (servers that fail like the reference) has not started.** It
  was deferred because servers are off the current focus. The probe harness
  (`src/probe_tests.rs`, spec
  [docs/specs/2026-10-22-probe-harness.md](./docs/specs/2026-10-22-probe-harness.md))
  now records what every TCP server shows a prober. That is where Phase 2's
  work is visible: REALITY and ShadowTLS close on the malformed first
  flights the references relay (RE-R1, ST-S2). Three cells the audit had
  missed are recorded there too:
  - PH-1: Trojan waits for 56 bytes;
  - PH-2: a TLS listener with no default target refuses an unknown name;
  - PH-3: the HTTP proxy is silent on an origin-form `GET`.

## Recorded debt

Known and deliberately left, so that nobody rediscovers it as a surprise.
Moved here from `AGENTS.md` on 2026-10-23; the audit each came from is named.

- **Dependabot alerts are still off** (2026-08-20 audit). The other half of
  that entry is done: `cargo audit --deny warnings` runs on a daily
  `schedule:` trigger in `lint.yml`, added after the chacha20 yank failed
  the first push that came along instead of the day it was published.
- **`MOBILE.md`'s line references were last checked against `037018e`**;
  the branch has moved far since. Trust symbol names over line numbers until
  someone re-verifies them.
- **`src/tuic/server.rs` reassembles fragments with its own
  `FragmentedPacket` and `LruCache` pair** rather than
  `quic_transport::fragments::Defragmenter`, which `src/hysteria2/server.rs`
  moved to. It is already bounded, so there is no defect; it carries extra
  per-packet state (a received counter, the accumulated length, the reply
  address) that the shared type deliberately does not.
- **`src/quic_server.rs::start_quic_server`**, the generic QUIC listener
  behind VLESS and the other TCP protocols, builds its own endpoint and sets
  no transport parameters; a TODO in it proposes some. It was left out of the
  `quic_transport` consolidation on purpose: it binds with a different socket
  buffer size, and the shared parameters would change behaviour for every
  QUIC inbound rather than remove a duplicate.
- **The 2026-08-20 audit's zero-test list.** The data-path files that had no
  tests now have them, and most surfaced real defects: `vmess_handler.rs`,
  `shadowsocks_stream.rs`, `routing/udp_router.rs` (its tests drive
  `run_udp_routing` end to end through a scripted server-side stream against
  real loopback echo sockets; reuse that double), `vless/vision_stream.rs`
  (end to end over TLS in `vless/tests.rs`, #80; the unpadder at every cut,
  #101, which found dropped bytes), and
  `shadow_tls/shadow_tls_server_handler.rs` (`shadow_tls/tests.rs`, #78; a
  probe-matrix row, #102). The rest of the list is quality-plan PR 4.4.
- **`shoesd` takes no IPv6 proxy address** (2026-10-24, the daemon carries
  IPv6). `Start.exclude` refuses v6 on every arm because the exclusion
  route goes through the default gateway and `default_gateway()` reads only
  the IPv4 table (`ip -j route show default`, `netstat -rn -f inet`, the
  IPv4 forwarding table on Windows); a v6 proxy address would be blackholed
  and the session would come up with a proxy it cannot reach. Lifting it
  touches the gateway read on all three arms, `exclusion_routes`, the
  `reapply` comparison and the door in `service.rs`. Cost: a proxy reachable
  only over v6 cannot be used from the desktop.
- **Windows rejects IPv6** (same change). wintun's configuration path
  cannot express an IPv6 address (`src/tun/mod.rs`), and a route via a
  device with no v6 source is worse than a reject. Fixing it touches the
  wintun adapter setup and the Windows arm's `add_address`/`delete_address`;
  `carries_ipv6()` then answers true there and nothing else changes. Cost:
  v6-only destinations are unreachable from Windows; dual-stack ones fall
  back to v4 at once.
- **The tunnel's v6 source is a ULA, so dual-stack names go v4** (same
  change). RFC 6724 rule 5 ranks a v4 destination above a v6 one whose only
  source is `fc00::/7`, so only v6-only destinations and literals use the
  tunnel's v6. Flipping that means a source that looks global, which is a
  prefix that belongs to someone and a change to `host::TUNNEL_IPV6` alone.
  Cost: a dual-stack site is reached over v4 through the tunnel, which is
  what happened before, now without the failed v6 attempt first.
- **Two process-level tests flake on CI** (2026-10-28, seen on #114 and
  #115). `tests/transparent.rs`'s redirect test copies the `shoes` binary
  and spawns it; a sibling test's copy can hold the file open for writing
  across the spawn's fork, and the exec fails with `Text file busy`
  (ETXTBSY). `tests/process_contract.rs` waits 15 s for a line on the
  child's stdout, and a loaded runner (macOS CI; a local run alongside a
  cross-compile) can miss it. Fixing the first means copying the binary
  once per test process, or serialising copy and spawn; the second, a
  longer wait or a readiness signal that does not depend on scheduling.
  Cost: a red Test job that a rerun turns green, which hides a real
  failure when one comes.
- **The probe matrix's SOCKS wrong-password cell flakes on Windows**
  (2026-10-26, seen on #110). `src/probe_tests.rs` expects `Data` for
  `("socks", WrongKey)` and sometimes gets `ClosedAtOnce` on
  `windows-latest`. The probe pipelines greeting, auth and `CONNECT` in one
  write; on a wrong password the server writes its two-byte failure and
  drops the socket with `CONNECT` unread, which sends RST, and Windows
  discards received data still queued when an RST arrives (Linux does not).
  Fixing it means draining or half-closing before the drop in the SOCKS
  server's auth-failure path, or a probe that waits for the reply before
  sending `CONNECT`. Cost: the same as the entry above.
- **A release's publish step follows only the newest dispatched build**
  (2026-10-28, the 0.9.0 release). `release-apple.yml`'s `publish` job
  finds the newest `workflow_dispatch` run of `build.yml` and `mobile.yml`
  since the plan started and fails the release if that run is not green.
  A macOS job cancelled for want of a runner, which GitHub's arm64
  capacity made common that day, fails the release even when a re-run of
  the same build later attaches everything; 0.9.0 was published by hand
  after one did. Fixing it means waiting on the assets rather than on one
  run: poll the draft for the 14 names until a deadline, and fail only
  then. Cost: a re-dispatch of the release workflow, or a manual publish,
  each time a fan-out job is cancelled.

- **A name resolves to one address, with no say in its family** (2026-10-31,
  the SSTP review). The rule engine resolves a name to match it against an
  IP mask and keeps the first address in `ResolvedLocation`; nothing lets
  a transport say which family it carries. The SSTP connector, IPv4 only,
  resolves again when handed an IPv6 address (`src/sstp/connector.rs`,
  `resolve_target`); AmneziaWG hands whatever it gets to a tunnel that may
  have no address of that family. Fixing it means keeping every address in
  `ResolvedLocation`, or a family hint on `Resolver`, and then both tunnel
  connectors. Cost: one more resolver round trip, cached, per SSTP
  connection to a dual-stack name, and an IPv6 destination failing inside
  an IPv4-only AmneziaWG tunnel.

## Table of Contents

- [Quality and correctness plan](#quality-and-correctness-plan)
- [Where we already compete](#where-we-already-compete)
- [Where we do not](#where-we-do-not)
- [Tier 1 — closes most of the gap](#tier-1--closes-most-of-the-gap)
- [Tier 2 — worth doing after Tier 1](#tier-2--worth-doing-after-tier-1)
- [Tier 3 — real, but not urgent](#tier-3--not-urgent)
- [Desktop clients](#desktop-clients)
- [Apple integration: what the first consumer asked for](#apple-integration-what-the-first-consumer-asked-for)
- [awg-manager engine: postponed](#awg-manager-engine-postponed)
- [Hysteria: the rest of the surface](#hysteria-the-rest-of-the-surface)
- [mieru: what is left](#mieru-what-is-left)
- [Lessons from steer](#lessons-from-steer)
- [Classic VPN clients: OpenConnect](#classic-vpn-clients-openconnect)
- [Explicitly not planned](#explicitly-not-planned)
- [Open risk: TLS fingerprinting](#open-risk-tls-fingerprinting)
- [Resolved: AmneziaWG upload was capped by the send window, and the drop was the outbound channel](#resolved-amneziawg-upload-was-capped-by-the-send-window-and-the-drop-was-the-outbound-channel)
- [Open risk: Android's receive window is extrapolated from macOS](#open-risk-androids-receive-window-is-extrapolated-from-macos)

## Where we already compete

On circumvention protocols the surface is close to parity with sing-box, and
ahead of Xray-core in places.

That framing needs one update, though. sing-box 1.14 stopped being only a
circumvention proxy: it added an **OpenVPN client *and server*, an OpenConnect
client**, Snell, and a `bridge` outbound doing layer-3 forwarding. So the
protocol gap has widened along an axis that did not exist a year ago — classic
enterprise VPN — rather than along the one this list measures. The first
request on that axis came on 2026-10-30, for SSTP: the client is in, built
to [docs/specs/2026-10-30-sstp-client-outbound.md](./docs/specs/2026-10-30-sstp-client-outbound.md);
it has been run against a production server, and its runs against SoftEther
and accel-ppp are still to come. OpenConnect followed, the CSTP client built to
[docs/specs/2026-10-31-openconnect-client-outbound.md](./docs/specs/2026-10-31-openconnect-client-outbound.md)
and not yet run live; its DTLS step and the three protocols weighed and
left are in [Classic VPN clients: OpenConnect](#classic-vpn-clients-openconnect).

Server: HTTP, SOCKS5, Mixed, Shadowsocks (including 2022-blake3), VMess AEAD,
VLESS, Trojan, Snell v3, Hysteria2, TUIC v5, AnyTLS, NaiveProxy, port-forward,
TLS, WebSocket, HTTPUpgrade.

Client: Direct, HTTP, SOCKS5, Shadowsocks, Snell, VMess, VLESS, Trojan, AnyTLS,
NaiveProxy, Hysteria2, TUIC v5, mieru, WireGuard, AmneziaWG 2.0/3.0/3.1, SSTP,
port-forward, plus TLS, Reality, ShadowTLS, WebSocket and HTTPUpgrade as
wrapping layers.

Transports and obfuscation: TCP, UDP and QUIC — though not every protocol takes
every one, since mieru is TCP-only and Hysteria2 and TUIC are QUIC-native
terminal connectors. XTLS Reality (a hand-written TLS 1.3 stack, `src/reality/`),
XTLS Vision, ShadowTLS v3, H2MUX, SagerNet UDP-over-TCP, XUDP, QUIC Salamander
obfuscation and Hysteria2 port hopping.

TUN mode with a Fake IP pool, on Linux, Android, iOS, Windows 11 and macOS.
macOS has two hosts: the Network Extension system extension, and `shoesd`, a
root launchd daemon that also configures routes and DNS. `shoesd` now has a
Linux arm too — a systemd service over `ip` and systemd-resolved. None of the
three has been run end to end yet: the extension needs an entitlement a
Personal Team cannot hold, and both daemons' live runs are outstanding. See
[docs/MACOS.md](./docs/MACOS.md) and [docs/LINUX.md](./docs/LINUX.md). The
device-creation and validation arms that were missing on macOS now exist.

Three things worth naming because the table below has no row for them and they
are real work: a DNS subsystem with `system`, UDP, TCP, DoT, DoH and DoH3
resolvers, bootstrap chains, and per-server resolution over a proxy chain with
every DNS socket protected against routing into the tunnel it resolves for;
multi-hop proxy chains with per-hop round-robin; and mTLS with certificate
pinning in both directions.

Two protocols we have that **neither** competitor does: **mieru** (sing-box
rejected the PR in June 2026 and closed the thread; Xray has never had it) and
**AmneziaWG 2.0/3.0/3.1**, which is the whole reason this fork exists.

## Where we do not

The gap is not in protocols. It is in everything around them.

Checked 2026-09-01 against **sing-box v1.14.0** (2026-08-31) and **Xray-core
v26.7.28** (2026-07-28). Two caveats on those versions: Xray marks nearly every
release a pre-release, so `releases/latest` still resolves to v26.3.27 even
though v26.7.28 is the real head; and Xray publishes no changelog text, so its
column is reconstructed from the commit log and the docs site rather than from
release notes.

| Capability | shoes | sing-box 1.14 | Xray-core v26.7 |
| --- | --- | --- | --- |
| Routing rule matchers | CIDR and `*.domain` masks, destination port, plus rule-sets | ~45 fields, incl. process, package name (+ regex), WiFi SSID, network type, MAC and source hostname | ~14 fields, incl. `process` (macOS since 26.4, UID on Android) and `vlessRoute` |
| Domain/IP lists | `.srs` rule-sets, local files only | `.srs` local, remote with `update_interval`, and inline; `type: logical` | `geosite.dat`/`geoip.dat` + `ext:`, auto-updating and hot-reloading since 2026 |
| Protocol sniffing | TLS SNI and HTTP Host, TCP only | 10 protocols over TCP *and* UDP (QUIC, DNS, STUN, BitTorrent, DTLS, NTP, SSH, RDP), plus `protocol` and `client` matchers | sniffing with `domainsExcluded`/`ipsExcluded`, FakeDNS destination override |
| Per-app routing on Android | none | `package_name`, `package_name_regex` (1.14) | `process` matcher, by UID on Android |
| Outbound selection | round-robin, no health check | `urltest` (latency, tolerance, idle timeout), `selector` | `observatory`/`burstObservatory` + balancers: random, roundRobin, leastPing, leastLoad |
| Statistics | global byte counters, live connection count, per-outbound bytes | Clash API, V2Ray gRPC stats (per inbound/outbound/user) | gRPC StatsService per user/inbound/outbound, online users and per-user IP lists |
| Management interface | **none over the network** — an in-process Rust module plus the mobile FFI | Clash API, plus a first-party gRPC API and web Dashboard new in 1.14 | gRPC API: Handler, Logger, Stats, Routing services |
| Extra transports | WebSocket, HTTPUpgrade, H2MUX | + gRPC (build tag) and HTTP/2 | XHTTP over H2 and H3, gRPC, WebSocket, HTTPUpgrade, mKCP; WS and gRPC now soft-deprecated in favour of XHTTP |
| Modern TLS | `X25519MLKEM768` first on every rustls path (a rustls default we inherit); **no ECH**; Reality is classical X25519 | ECH; `X25519MLKEM768` in `curve_preferences` | ECH (forced when configured); ML-KEM-768 VLESS Encryption; ML-DSA-65 REALITY certificates |
| TUN | Linux, Android, iOS, Windows 11, macOS (unrun) | Linux, Windows, macOS; mobile via the platform VPN API in the GUI clients | Windows, Linux, macOS, FreeBSD natively; iOS and Android take an fd via `XRAY_TUN_FD` |
| Hysteria2 / TUIC as a *client* | both | both | Hysteria2 yes (since 26.1); **no TUIC, no AnyTLS** |
| Desktop client | a Swift package for the Apple extension and app; no GUI | full GUI on three platforms, plus a new desktop app for Windows and Linux | none — Xray is a core, GUIs are third-party |

Two rows deserve a caveat rather than a footnote.

**Statistics.** Ours are counters, not a table keyed by connection, and that is
deliberate — `Cargo.toml` records why, since a per-connection table is exactly
the runtime state a phone cannot spare. But the two top-level byte totals are
incremented only on the TUN path, so in plain server mode they read zero while
`outbounds[]` still populates. Anyone quoting them should know which mode they
were measured in.

**Management interface.** The previous version of this table called ours a
"control API", which oversold it. `src/control/` is an in-process Rust module
extracted from the FFI so a Rust host can drive a tunnel — no listener, no
endpoints, no port, no auth — and it is feature-gated off by default. Both
competitors ship a real network management API, and sing-box 1.14 just made
that a first-party gRPC service with its own dashboard rather than leaning on
the Clash API. This is the widest single gap in the table, and as of
2026-10-15 it is a deliberate one: see item 9 below.

## Tier 1 — closes most of the gap

Ordered by value per unit of work. All three built on code already in the tree,
and all three are now done.

### 1. Rule-sets — done

Shipped. Spec: [docs/specs/2026-08-09-rule-sets.md](./docs/specs/2026-08-09-rule-sets.md).
Plan: [docs/plans/2026-08-09-rule-sets.md](./docs/plans/2026-08-09-rule-sets.md).

`masks` was a literal list. A rule as ordinary as "Russian domains direct,
everything else through the tunnel" needed tens of thousands of YAML lines, so
in practice nobody wrote it.

sing-box `.srs` files are now read directly, so the existing ecosystem of
compiled lists — geosite, geoip, antifilter, Loyalsoldier — works as-is, with no
list-building pipeline of our own. `src/rule_set/` decodes the container and
holds the succinct trie in its on-disk shape; `ConnectRule` consults a rule's
sets when its masks miss.

Local files only. Remote rule-sets with `update_interval` are deliberately
deferred — see the spec's scope section — as are `source_ip_cidr`, inline rules
and `type: logical`.

### 2. Protocol sniffing — done

Shipped. Spec: [docs/specs/2026-08-10-protocol-sniffing.md](./docs/specs/2026-08-10-protocol-sniffing.md).
Plan: [docs/plans/2026-08-10-protocol-sniffing.md](./docs/plans/2026-08-10-protocol-sniffing.md).

A destination domain used to be known only when Fake IP assigned it. An app with
a hardcoded DoH resolver, or one that dials a literal IP, defeats that — and
every domain rule silently degraded to IP matching, which hit the rule-sets from
item 1 hardest, since geosite lists are domains only.

`src/sniff/` now reads the TLS ClientHello and the HTTP/1.x request line from
the first bytes of a connection. The recovered name goes into
`ResolvedLocation.location` with the original address in `resolved_addr`, so
domain rules and rule-sets match the name while CIDR masks still match the real
address and a direct connection dials it without a DNS lookup. Opt-in per
listener with `sniff: true`, on both TCP inbounds and the TUN.

A QUIC sniffer, DNS sniffing, protocol-only sniffers (`bittorrent`, `ssh`,
`stun` and friends) and the `protocol` rule matcher they would serve are
deliberately deferred — see the spec's scope section. Overriding the destination
for direct connections is not planned: Xray had to bolt an exclusion list onto
it and sing-box has deprecated it.

### 3. Hysteria2 and TUIC client outbounds — done

Shipped. Spec: [docs/specs/2026-08-11-quic-client-outbounds.md](./docs/specs/2026-08-11-quic-client-outbounds.md).
Plan: [docs/plans/2026-08-11-quic-client-outbounds.md](./docs/plans/2026-08-11-quic-client-outbounds.md).

shoes could serve Hysteria2 and could not dial it. The framing and crypto were
already in the server modules, so the gap was the client-side plumbing, and
Hysteria2 in particular is now one of the most widely deployed protocols in the
commercial market.

Neither protocol fits the chain model, which builds an outbound from a socket
connector that yields a stream and proxy connectors that wrap one: both
authenticate once per QUIC connection and key their UDP sessions to it. They
are `TerminalConnector`s instead — the escape hatch AmneziaWG already used —
and are therefore always the only hop in a chain. `src/quic_outbound/` holds
what they share: endpoint construction from `quic_settings`, one connection per
outbound re-established lazily, and the obfuscation layer.

Both speak TCP and UDP. Salamander obfuscation works on the client and the
server. Every protocol path is tested against this repository's own server
running in-process, and the Hysteria2 client has been checked by hand against a
third-party sing-box server for TCP and UDP alike.

TUIC carries UDP in both relay modes. `native` uses QUIC datagrams; `quic` uses
one unidirectional stream per packet, which is what the reference implementation
does and what our server now does — it used to hold a single stream open for the
association and write bare packet bodies onto it, without the version and
command bytes that make a `Packet` a command, so what it sent was something its
own receiving side would have rejected.

The two differ in congestion control, as their references do. Hysteria2 runs
BBR at both ends with no option, upstream's fallback when Brutal is not
negotiated. TUIC takes `congestion_control` (`cubic`, `new_reno`, `bbr`) on
the client and the server, Cubic by default as in the reference and sing-box;
on Cubic it carries single-digit Mbit/s at 0.5% loss, in sing-box too, and on
`bbr` about 500. See
[docs/specs/2026-10-10-tuic-congestion-control.md](./docs/specs/2026-10-10-tuic-congestion-control.md).

One option is refused at config load rather than silently ignored, because a
user who asks for it and does not get it should be told: TUIC's
`zero_rtt_handshake`. What else is missing is in
[Hysteria: the rest of the surface](#hysteria-the-rest-of-the-surface).

## Tier 2 — worth doing after Tier 1

### 4. `urltest`: latency-based selection with health checks

A pool is plain round-robin with no liveness probe, so a dead node keeps taking
every Nth connection. Needs a background prober, shared state, and a new variant
in `src/config/types/selection.rs`. A mobile UI gets something to display as a
side effect.

### 5. Per-app routing on Android

`src/tun/traffic.rs` aside, there is no notion of which app a flow belongs to.
sing-box resolves uid to package name and matches on it.

The leak this used to be entangled with is fixed: every outbound socket is now
excluded from the VPN route, because `socket_util`'s constructors consult the
protector rather than each caller remembering to. See
[MOBILE.md](./MOBILE.md) §2. Per-app routing is the remaining half.

### 6. Per-connection statistics — partly done

`src/tun/traffic.rs` keeps two global atomics and a callback, and a live
connection count beside them. `shoes::control::stats::snapshot()` reports
those plus a per-outbound breakdown behind the `control-stats` feature.

The naming blocker is gone. `ClientConfig` carries an optional `name`
(`src/config/types/client.rs`), outbounds without one are keyed by address and
a direct outbound by `direct`, and bytes are credited to the exit hop of a
chain — see `docs/specs/2026-08-26-named-outbounds.md`.

A mobile host can read all of it: `shoes_get_stats()` and
`ShoesNative.getStats()` return the snapshot as JSON, and both published
artifacts build with `control-stats`. See
`docs/specs/2026-08-27-stats-ffi.md`, and MOBILE.md
section 10 for what the counters cost.

What is left is a connection *list* — destination, protocol, the rule that
matched, and bytes each way, per connection rather than per outbound. That is
the part that would need a table keyed by connection, which is exactly the RSS
the mobile budget declined; it wants a design that lets a host ask for it
rather than one that keeps it always, and it would be over FFI or the daemon
socket. A connection registry was built for the Clash API in September 2026
and removed with it on 2026-10-15; the removal is the data point that an
always-on table threaded through every inbound is the wrong shape.

### 7. HTTPUpgrade transport — done

WebSocket's handshake without WebSocket's framing, client and server, wire
compatible with sing-box's `httpupgrade`. Configured as `type: httpupgrade`;
see `src/httpupgrade/` and `ClientProxyConfig::HttpUpgrade`. Shipped in
v0.2.13.

### 8. DNS rules

`DnsConfigGroup` exists (`src/config/types/dns.rs:166`) but nothing selects a
group per rule, so split DNS cannot be expressed. Half the mechanism is built.

### 9. A management interface over the network

Added 2026-09-01, out of the comparison refresh, where it is the widest single
gap. `shoes::control` is in-process only: a Rust host that links the crate gets
`status`, `stats::snapshot` and a log sink, and nothing else can reach them.
Every competitor ships a network API — Xray a gRPC service, sing-box the Clash
API and, as of 1.14, a first-party gRPC service with its own web dashboard —
and every third-party GUI and panel in this ecosystem is built against one of
those two. Not having one is what keeps shoes a library with a CLI rather than
something an existing panel can drive.

The pieces are mostly present: `StatsSnapshot` and `StatusSnapshot` already
serialise, the log sink is already subscribable, and `ServiceHandle` already
has the lifecycle. What is missing is a listener, an auth story, and a
decision about shape — Clash-API compatibility would inherit an ecosystem of
clients for free, where a native API would be cleaner and reach nobody. That
choice should be made deliberately rather than by whichever is easier to write,
and it wants a spec before code.

Note the mobile constraint this does *not* escape: a management API that keeps
a connection table costs the RSS item 6 declined. Whatever ships should be
feature-gated the way `control-logs` and `control-stats` already are, so a
Network Extension can decline it.

**Decided 2026-10-15: not now.** A Clash-compatible controller was built
(PRs #22 and #30, feature `clash-api`) and removed a month later, unrun by
any dashboard, because the consumers it was written for were postponed and
its registry reached into every inbound's accept path. The desktop GUI talks
to `shoesd` over gRPC on a local socket, and the mobile apps over FFI; neither
needs a network API. This item stays on the list as the known gap it is, and
reopens only with a consumer in hand.

## Tier 3 — not urgent

- **Network-change handling — done.** A Wi-Fi to cellular switch used to leave
  the AmneziaWG endpoint socket bound to a dead local address with no error
  path: it went quiet rather than failing, and the only recovery was a
  stop-and-start that tore down the TUN interface. The endpoint socket is
  replaceable now (`src/amneziawg/endpoint.rs`), swapped under the tunnel tasks
  through a `watch` channel. Two things trigger a rebind: the app, through the
  `notify_network_change()` FFI call meant for `ConnectivityManager` and
  `NWPathMonitor`, and a send that fails with a route-is-gone error, so an app
  that never wires up the callback still recovers one failed send later. No new
  handshake is needed — WireGuard peers roam. See [MOBILE.md](./MOBILE.md) §3.
- **Address-family fallback, everywhere else.** A dual-stack host can publish
  an IPv6 address whose UDP replies never come back while its IPv4 works. The
  QUIC outbound used to take the first resolved address and stay there, which
  made the outbound look permanently dead with no error; it now walks the whole
  list (`src/quic_outbound/connection.rs`). Two things are left.

  The AmneziaWG endpoint has the same shape and the same silence:
  `src/amneziawg/connector.rs:142` resolves the tunnel's UDP peer to one
  address and never reconsiders.

  And pre-resolution quietly defeats the fallback that does exist.
  `SocketConnectorImpl` walks every address only when handed an *unresolved*
  location (`src/tcp/socket_connector_impl.rs:218`), so each caller that
  resolves to a literal first — `src/http_handler.rs:417`,
  `src/routing/udp_router.rs:1043`, `src/tuic/server.rs:535` and `:1000`,
  `src/anytls/anytls_server_handler.rs:202`,
  `src/vless/vless_server_handler.rs:84` — collapses the list to one behind its
  back. That is the more interesting half: the mechanism is there and is being
  switched off by accident.

  None of this is happy eyeballs. RFC 8305 racing would also remove the three
  seconds the QUIC fallback now spends discovering that the first address is a
  black hole, and that is a larger change than walking a list.
- **Cache file.** The Fake IP pool is a `Mutex<PoolState>` and nothing else
  (`src/dns/fake_ip/pool.rs`), so every mapping is lost on restart. On mobile,
  where the process is killed routinely, this is felt more than the effort
  suggests. Rule-set downloads and a remembered outbound selection would belong
  in the same file, but neither exists yet — see Tier 1 item 1 and Tier 2
  item 4.
- **Multiplex interop** with sing-box's smux/yamux. `MuxProtocol` names both
  (`src/h2mux/mod.rs:60`), but they are identifiers only: no framing behind
  them. H2MUX covers our own deployments; this is purely about talking to other
  implementations.
- **Transparent inbounds on Linux: `redirect` and `tproxy` done.** This
  entry used to open "we have neither", and argued for both from a Linux
  router proxying *other* devices, where sing-box, mihomo and v2ray all ship
  them and where routing every byte through the userspace netstack in
  `src/tun/` costs more than plain `accept()` on kernel sockets. That argument
  acquired a consumer, awg-manager, which has since been postponed
  ([awg-manager engine: postponed](#awg-manager-engine-postponed)); both
  inbounds stay, as ordinary Linux inbounds.

  `redirect` shipped as `src/redirect_handler.rs` and `src/tproxy/sys.rs`. Two
  things this entry predicted turned out otherwise. The destination is not
  captured in `run_tcp_server`: it is a defaulted `AsyncStream` method that
  the accept path's wrappers forward, which keeps `TcpServerHandler` unchanged
  for every other protocol at the price that a new wrapper has to remember to
  forward it. And "it works on macOS pf as well" was not built: `SO_ORIGINAL_DST`
  is netfilter's, pf needs `DIOCNATLOOK` on `/dev/pf`, and validation refuses
  the inbound off Linux rather than pretend.

  `tproxy` for TCP is not planned: awg-manager uses NAT `REDIRECT` for TCP
  precisely because `-m socket --transparent` does not match on Keenetic's 4.9
  kernel. `tproxy` for UDP shipped in `src/tproxy/` as this entry described
  it: `IP_RECVORIGDSTADDR` and a hand-walked `recvmsg`, one socket seeing
  every client and so a source-keyed table with idle sweeping, and replies
  from `IP_TRANSPARENT` sockets bound to the original destination. Three
  details it did not foresee: the reply sockets must stay unconnected, or
  TPROXY hands the client's next datagrams to them instead of the listener;
  they need `SO_REUSEADDR`, or they cannot bind beside a router service on
  the remote's port, `dnsmasq` on 53 above all; and the listener must be
  loopback-only, because on the wildcard it relays ordinary traffic to
  itself. A fourth turned up in the host: with `src_valid_mark` on, as
  `wg-quick` leaves it, the kernel drops every forwarded datagram TPROXY
  marks as a martian, so shoes warns about it at startup. One prediction was wrong in a useful way: the
  interesting paths *can* run in CI. GitHub's Linux runners have passwordless
  `sudo`, and both inbounds' tests under real netfilter rules run there on
  every push.

## Desktop clients

Linux, macOS and Windows, with one Tauri GUI across all three and native
platform integration underneath. Design in
`docs/specs/2026-08-24-desktop-control-api.md`, task breakdown in
`docs/plans/2026-08-24-desktop-control-api.md`.

Seven sub-projects. The first two are done; the other five are open, and the
order below is roughly the order they unblock each other.

### 1. Control API — done

`shoes::control` is the lifecycle that used to be locked inside
`src/ffi/common.rs`, compiled out on every non-mobile target. A privileged host
now gets `prepare_from_config` with a `DevicePolicy`, `start`, `status`,
`stats::snapshot`, a subscribable log sink, and a `stop` that reports whether
the device was released. Verified by building an external crate against it, not
by inspection.

Two facts worth carrying forward. `Status` has no `Starting` variant, because
nothing can produce one: `start` returns as soon as the task is spawned and the
stack offers no readiness signal, so a GUI that shows "connected" at that moment
is lying. Adding one is a change to `run_tun_from_config`, and it should land
before a tray icon does. And `ServiceHandle` must not be stopped or dropped from
async code — it owns a `Runtime`, and dropping a runtime inside another panics.

Since v0.2.16 the handle also reports its own end. `start` takes
`on_exit(Option<String>)`, called from the service task for any exit the host
did not ask for — the error's message, or `None` for a clean but unrequested
return — with `running` already false, so a callback that stops the engine
does not wait out the five-second poll. Three consequences worth knowing:
dropping a handle instead of calling `stop_handle` cancels the task and
counts as an exit the host did not ask for; a host that keeps the handle
somewhere the callback can see wants `start_and_install`, which stores the
handle before the task can run; and a panic reaches none of it, because the
crate builds with `panic = "abort"`. The mobile FFI is the first user; a
desktop helper polling `status()` gets the same fact from `StopReason`.

### 2. Windows TUN backend — done

Shipped. Spec: [docs/specs/2026-08-27-windows-tun-backend.md](./docs/specs/2026-08-27-windows-tun-backend.md).
Plan: [docs/plans/2026-08-27-windows-tun-backend.md](./docs/plans/2026-08-27-windows-tun-backend.md).

The smoltcp loop moved to `src/tun/stack_common.rs` behind a `StackDevice`
trait and a shared `StackHandle` manager, unchanged in behaviour; the Unix
backend keeps its descriptor and `poll()`, and `src/tun/tcp_stack_wintun.rs`
drives a wintun ring-buffer session, waiting on the session's event handles
and woken at shutdown through `Session::shutdown()` — the design wireguard-go
uses, dedicated thread and dead-device backstop preserved. Windows 11 only,
attaching at `DevicePolicy::Owned`: shoes creates and configures the adapter
(`src/tun/wintun_device.rs`, deterministic GUID per name, ring sized as
wireguard-go's) and never touches routes or DNS — `destination` is refused on
Windows because the wintun path would turn it into a system default route,
and the adapter address must be IPv4 because wintun-bindings' netsh arm
cannot express IPv6.

Upstream PR cfal/shoes#102 was read for which knobs matter and deliberately
not adopted: it deletes the dedicated-thread design and the
`phy_wait_error_count` backstop, both of which this backend keeps.

The shared loop is tested through a scripted device double on every platform,
so Windows CI went from `cargo check` to the full suite — which surfaced and
fixed two unrelated Windows defects on its first run: QUIC inbounds panicked
on SO_REUSEPORT (now one endpoint there, logged), and every dual-stack UDP
relay lost its IPv4 traffic because Windows defaults `IPV6_V6ONLY` on.
Adapter creation itself needs Administrator and `wintun.dll`, so that half
lives in an `#[ignore]`d test run by hand, plus a live end-to-end run —
TCP, UDP/DNS, Fake IP and ICMP through a real adapter with routed traffic.

#### TUN stack fast path — done, and what is left

Spec: [docs/specs/2026-09-16-tun-stack-fast-path.md](./docs/specs/2026-09-16-tun-stack-fast-path.md).

Two structural wins taken from sing-tun's 1.15 stack and fitted onto smoltcp:
the shared loop now hands smoltcp a whole read batch and polls once (one
egress sweep per batch, not per packet), and a `StackNotifier` gives the stack
thread a wakeup it can actually receive, so a written segment or a dropped
connection no longer waits out a timer tick and the wait is no longer capped
at 10 ms — an idle tunnel with open connections stops waking a hundred times a
second.

What sing-tun has and this does not, in descending order of expected benefit,
each blocked on smoltcp rather than on effort:

- **Segmentation offload** (`IFF_VNET_HDR` + TSO on TX, GRO on RX). The
  largest throughput win — 64 KiB super-segments cut per-byte syscalls and
  poll sweeps by an order of magnitude — but smoltcp neither emits nor accepts
  super-segments, so it needs changes below the loop.
- **Multi-queue**: one interface per queue with the kernel steering by flow
  hash. smoltcp runs a single interface; this is more surface than the two
  changes above.
- **Direct-socket splice**: bytes moved TUN↔socket inside the loop for direct
  outbounds, bypassing the ring-buffer bridge. smoltcp always terminates the
  connection itself, so there is no fd to splice; it helps direct outbounds
  only, not proxy chains, which is shoes' main case.

### 3. macOS Network Extension provider — done

Design: [docs/specs/2026-08-28-macos-network-extension.md](./docs/specs/2026-08-28-macos-network-extension.md).

"No new Rust" was nearly right. One function of it: `shoes_start_with_fd`,
which takes the descriptor as a parameter so a config generated by the app
needs no placeholder patched into it inside the extension. What was missing
was the artifact: the XCFramework had no macOS slice. It has one now, arm64
only, built with `--features ffi` because on macOS the FFI module is a
feature rather than a target — deliberately, so the desktop binary does not
carry it.

And the Swift, which the roadmap had placed in the GUI repository, ships from
here as the `ShoesTunnel` package (`swift/`, `Package.swift`): a provider base
class that owns the ordering against `shoes_stop`, a host-side manager for
the TN3120 sequence, and typed app messages, shared between iOS and macOS.
Reading the one existing consumer found the rules we had documented were not
the rules it implemented, and documentation does not execute.

Decisions recorded in the design: Developer ID and a DMG rather than the Mac
App Store (Guideline 5.4 wants an organization account), therefore a system
extension rather than an app extension, and the KVN roadmap's alternative —
the shoes binary as a subprocess behind the system proxy — seen and
declined, because system proxy settings bind only cooperating applications.

Not verified: the tunnel has never run on macOS, because activating the
extension needs the NetworkExtension entitlement in a real profile. Steps up
to the C boundary are tested in CI; the rest compiles. On iOS it has: KVN,
a KMP VPN client, adopted the package from v0.2.15, and what it found is the
[Apple integration](#apple-integration-what-the-first-consumer-asked-for)
section.

The package is two products since v0.2.16. `ShoesTunnel` is what the
extension links; `ShoesTunnelHost` is what the app links, and it never
depends on the engine — with one product the app carried every `shoes_*`
symbol, about 15 MB of `__TEXT` for code it never ran, because
`ShoesEngine.shared` roots the engine and SwiftPM compiles a module whole.
Both sit on a `ShoesTunnelCore` target holding the wire types, so the two
processes cannot disagree about a message, and `mobile.yml` builds one
executable per product for the simulator and asserts with `nm` that the
host has no engine symbol and the extension does. Design:
[docs/specs/2026-08-28-spm-host-extension-split.md](./docs/specs/2026-08-28-spm-host-extension-split.md).

### 4. Privileged helper and IPC contract — macOS, Linux and Windows done, pending their live runs

`shoesd` (`src/bin/shoesd/`, `--features daemon`) is a root daemon -- launchd
on macOS, systemd on Linux -- serving gRPC over a Unix domain socket, with the `.proto` owned here in
`proto/shoes/daemon/v1/`. It hosts `shoes::control` in-process and configures
the host around it: the split default route, a host route per excluded address,
the same split for IPv6 via the device (rejects only on Windows), and DNS through `SCDynamicStore` — reverted on stop, and after a
crash from a record written before each change. Authentication is the socket's
peer credentials; there is no token and no TCP listener. Design and the
decisions taken:
[docs/specs/2026-09-04-macos-privileged-daemon.md](./docs/specs/2026-09-04-macos-privileged-daemon.md).

The GUI has no platform branches because it asks: `Hello` reports
`capabilities`, so a build without a routes or DNS arm says so rather than
failing at `Start`.

This is where **host network configuration** lives, and shoes still deliberately
does not do it: nothing in `src/` touches routes, `resolv.conf`,
systemd-resolved or `netsh`. shoes moves packets; the host owns the network,
and the daemon is a host — the same seat as `NEPacketTunnelProvider`, written
in Rust and linking the library rather than crossing a C boundary.

A `PF_ROUTE` monitor re-points the exclusion routes and rewrites the resolvers
when the default gateway moves, which is the ordinary case on a laptop rather
than an edge one. There is no `SCDynamicStore` watcher: a network change is
what makes macOS revert DNS, and the routing table already reports that.

**Linux is the second arm**, and the same trait and the same revert sequencer
carry it: routes through `ip`, DNS through either systemd-resolved on the
tunnel's own link or a managed `/etc/resolv.conf`, chosen by a probe at
startup, and the route monitor ported to `AF_NETLINK`. Which backend was chosen
is reported in `capabilities`, because it is the first question any Linux DNS
bug report needs answered. Design:
[docs/specs/2026-09-04-linux-privileged-daemon.md](./docs/specs/2026-09-04-linux-privileged-daemon.md);
what it does to a host and what is still unverified:
[docs/LINUX.md](./docs/LINUX.md).

**Windows is the third**, on the same trait, sequencer and protocol. The
socket is AF_UNIX there too, not a named pipe -- the first consumer is a JVM
client and grpc-java has no pipe transport -- at
`%ProgramFiles%\shoesd\shoesd.sock`, where no standard user can create
anything first. The peer check reads the client's token through
`SIO_AF_UNIX_GETPEERPID` and admits SYSTEM or a member of Administrators in
any state, because an administrator's unelevated token carries that group as
deny-only. Routes go through the IP Helper API rather than localised
`route.exe` output; DNS is the tunnel adapter's plus an NRPT rule for `.`,
without which multi-homed name resolution leaks every lookup to the local
resolver. It runs under the Service Control Manager, and `install` reports
failures by exit code, since a UAC-elevated child's output cannot be
captured. wintun.dll is still not shipped by shoes; `install` copies it from
beside `shoesd.exe`, so the packager supplies it. The route monitors' settle
and second-look loop moved to `host/monitor.rs`, shared by all three. Design:
[docs/specs/2026-10-06-windows-privileged-daemon.md](./docs/specs/2026-10-06-windows-privileged-daemon.md).

**What is left.** Both live runs — on Apple Silicon (step 8 of
[the macOS plan](./docs/plans/2026-09-04-macos-privileged-daemon.md)) and on
Linux (step 8 of
[its own](./docs/plans/2026-09-04-linux-privileged-daemon.md), nine items,
against a Fedora host with systemd-resolved and Tailscale up) -- and on
Windows 11, whose five open measurements are listed in its spec: what a
Windows AF_UNIX `connect` checks on the socket file, whether a loopback route
makes IPv6 fail fast, that NRPT stops port-53 traffic on the physical
adapter, the deny-only peer case, and an end-to-end start/stop/crash run.

Linux was expected to be the awkward one, and the four mechanisms are real:
the answer is two backends chosen by a probe at startup, not four arms. What
made it awkward was not the count but that "systemd-resolved, where it is
running" is not a sufficient test — in resolved's `uplink` and `foreign` modes
every glibc client bypasses it, so per-link configuration succeeds and DNS
leaks with nothing saying so.

### 5. The Tauri GUI

Tray, popover, dashboard, config editor. Can be built against a mocked helper in
parallel with #2 and #4. Config validation needs none of that plumbing:
`shoes::config::load_config_str` and `create_server_configs` are public and give
the editor real parse and semantic errors from the same code that will run the
connection.

Known rough edge on Linux: the tray goes through StatusNotifierItem, which works
on KDE and needs a user-installed extension on stock GNOME.

### 6. Packaging, signing, notarization, updater

Signed DMG, MSI and NSIS, deb and AppImage, plus a signed updater feed.

### 7. Share-link import

`vless://`, `ss://`, `hysteria2://` and friends. Nothing in `src/` parses one
today — the only mention in the tree is a doc comment at
`src/config/types/client.rs:238`. A parser per protocol, mapping query
parameters onto the config types. Belongs in the GUI repository rather than
here: no mobile caller wants it, and it would cost mobile bytes for no mobile
benefit.

## Apple integration: what the first consumer asked for

KVN adopted `ShoesTunnel` at v0.2.15 and sent back a list, in value order.
Three of its eight items shipped in v0.2.16; the rest are here so they are
not lost. Nothing below is protocol work: it is all about how an engine
inside a packet tunnel provider talks to the app that owns it.

### Done in v0.2.16

- **Errors are pushed, not polled.** The provider used to learn of an engine
  death from a 30-second health check. `shoes_start_with_fd` takes a
  `ShoesStoppedCallback` now, fired from the service task the instant it
  ends without `shoes_stop` having been called; the provider reports it and
  cancels the tunnel at once, and the health check is gone — it observed the
  same event, the service task ending, thirty seconds later. What neither
  could see, a task that lives while nothing flows, is still unobserved.
  Design:
  [docs/specs/2026-08-28-engine-stopped-callback.md](./docs/specs/2026-08-28-engine-stopped-callback.md).
- **Host conditions have their own error cases.** `ShoesTunnelManager.send`
  threw `.engine("no tunnel session")` for a condition that was the host's;
  it throws `.noSession` and `.providerNoReply` now, and `.engineStopped`
  carries the callback's reason. `ShoesError` is `Codable`.
- **The message channel carries errors.** `.lastError` asks the provider for
  the last error it reported, as the case. It answers while the extension is
  alive; after an engine death the process exits and the app sees only
  `.disconnected`, so a host still persists fatal reasons from
  `report(error:)` — that half of KVN's App Group file stays.

### Open

- **Log growth — done.** `shoes_set_log_file` appended forever, and on iOS
  an App Group log outlives the process, so it grew across sessions. It now
  rotates at 4 MiB to `<path>.1`, keeping one previous file; it still appends
  when set, and a previous session's log past the cap is rotated before the
  first write, so the log of a crash is kept whole. Spec:
  [docs/specs/2026-10-10-mobile-log-rotation-and-ceiling.md](./docs/specs/2026-10-10-mobile-log-rotation-and-ceiling.md).
- **The compiled log ceiling — done.** Release builds carry
  `release_max_level_info`, so `debug` and `trace` behave as `info`.
  `shoes_max_log_level()` and `ShoesNative.maxLogLevel()` return the ceiling,
  `ShoesEngine.maxLogLevel` surfaces it in Swift, and the host app can ask the
  extension with `ShoesAppMessage.maxLogLevel`. It is `maxLogLevel`, not the
  `effectiveLogLevel` this entry proposed, because it is the build's ceiling
  rather than the level in effect.
- **Path changes.** The provider wakes on every `.satisfied` path after the
  first (`ShoesPacketTunnelProvider.swift`, `startPathObservation`). A wake
  costs one `shoes_network_changed` call and a full rebind only when the
  engine says it did not recover, so a captive-portal flap is cheap rather
  than disruptive. Comparing `availableInterfaces` and gateways against the
  last path would be fine hygiene; it is not worth a release on its own.
- **Stats push.** The traffic callback carries bytes only; `active_connections`
  and the per-outbound figures are a JSON poll. Pushing them changes a C
  signature for something the UI polls at its own rate anyway. If it ever
  happens, it rides the stop callback's channel as a general event callback
  rather than a third function pointer.

### Not asked for, and since done

Android has the same callback since v0.9.0: `ShoesNative.start` takes a
`StoppedListener`, called with the session id and the reason for an end the
host did not ask for, in place of `getLastError()` and a poll of
`isRunning()`.

## awg-manager engine: postponed

shoes as the engine behind awg-manager on Keenetic routers, in place of a
61 MB sing-box fork. Postponed 2026-10-15 in favour of the mobile and desktop
clients; the spec and plan (`docs/specs/2026-09-11-awg-manager-engine.md`,
`docs/plans/2026-09-11-awg-manager-engine.md`) were removed from the tree
and live in git history at `bf1740f`.

What stays, because it is useful without awg-manager: the process contract
(`check`, `version`, `SIGHUP`), the `redirect` and `tproxy` inbounds, and
`scripts/build-keenetic.sh` with its measurements in
[docs/keenetic-build-2026-09-11.md](./docs/keenetic-build-2026-09-11.md).
What went with the Clash API: the health probe and log tail awg-manager would
have read. What was never built: logical and source-address rules, per-rule
UDP timeouts, an `.srs` encoder, DNS rules outside TUN, a Chrome-shaped
ClientHello, and a run on a router's kernel. The Keenetic script is kept as
a build, not a release, and nothing checks it in CI.

## Hysteria: the rest of the surface

Written against [apernet/hysteria](https://github.com/apernet/hysteria) at
`app/v2.12.1` (2026-08-09), read from `PROTOCOL.md` and the `serverConfig` and
`clientConfig` structs in `app/cmd/`.

Speaking the protocol is not the same as matching the implementation. This
section is the difference, so that "we support Hysteria2" is never claimed
wider than it is true.

### Conformance with the reference — phases 1 and 2 done

A review that read the Go source of
[HyNetworks/hysteria](https://github.com/HyNetworks/hysteria) at `619a6f8`
found fifteen divergences across 5500 lines of our Hysteria2 code. Design:
[docs/specs/2026-08-24-hysteria2-conformance.md](./docs/specs/2026-08-24-hysteria2-conformance.md).

**Phase 1 — the ones that made a real peer fail — done.** An IPv6 target went
on the wire unbracketed, so `2001:db8::1` port 443 became `2001:db8::1:443` and
Go's `net.SplitHostPort` refused it outright. Concurrent UDP sessions each ran
their own reader on the shared connection and dropped what was not theirs, so
with two sessions each won about half the datagrams; one demultiplexer per
connection routes by session id now. The server answered success before it
dialled, so a refused target reached the client as a connection that succeeded
and immediately closed with no diagnosis. And it sent `Hysteria-CC-RX: 0`,
which the protocol defines as "no limit, transmit at any rate" — not the
"run your own congestion control" signal it was taken for — so an official
client configured with `up: 200 mbps` switched to fixed-rate Brutal against a
server running ordinary congestion control.

One of the five has no fix available here and is documented rather than closed:
our server cannot carry UDP to a peer that omits `max_datagram_frame_size`,
because quinn refuses to send a datagram to such a peer and has no equivalent of
upstream's `AssumePeerMaxDatagramFrameSize`. An official client does this only
with `disableChromeParrot: true`, so a stock client is unaffected. It names the
cause in the operator's log now instead of silently never replying.

**Phase 2 — robustness — done.** A UDP session tracked up to 256 incomplete
packets of up to 255 fragments each — about 78 MB — and opening sessions cost a
peer nothing; holding one packet id in flight, as upstream does, caps it at
roughly 300 KB. A session whose send failed was dropped from the map without its
reply task being cancelled, leaving a socket and a parked task for the life of
the connection. Idle sessions were swept only when another datagram happened to
arrive, so a client that went quiet kept everything it had opened. And an
`assert!` on two peer-chosen values sat on the reply path beside a fragment
count that truncated to a byte.

**Phase 3 is a decision, not a repair, and it is open.** Auth and request
padding sizes, connection ID length, stream limits and the masquerade body are
all places where we differ from the Go client — some deliberately, some not —
and choosing means answering one question first: *are we imitating that client,
or merely interoperating with it?* The tables below are what phase 3 would draw
from. Structural work waits behind the same decision: the server keeps a second
datagram encoder beside `frame.rs`, and two encoders for one wire format is
exactly the arrangement that produced this list.

Which is the part worth carrying away. In almost every case **our encoder and
our decoder shared a misreading, so every test passed** — the same shape that
produced nine defects in mieru and then eight more. Reading the reference found
each one. A live run against the official client then disproved one of the
findings as written, which no test of ours could have done, because the claim
was about a peer we do not control.

### Interoperability — a server we cannot talk to

| Gap | Effect |
| --- | --- |
| **Gecko obfuscation** (`obfs.type: gecko`, upstream 2.9.2) | A server with it configured is unreachable. Experimental upstream, and it builds on Salamander's scrambling rather than replacing it, so it is an added framing layer rather than a second cipher. |
| **`Hysteria-CC-RX: "auto"`, on the client** | The protocol allows the literal string as well as an integer. Our *server* sends `auto` now — see the conformance section above — but our client still ignores the header it receives. Upstream's client, given `auto`, installs its configured controller, BBR by default, and ours runs BBR unconditionally (`docs/specs/2026-10-01-hysteria2-bbr.md`), so ignoring the header is compliant for as long as there is no Brutal for it to choose. It becomes a real gap the day Brutal lands. |
| **Multiple users on our server** (`auth.type: userpass`, `http`, `command`) | `ServerProxyConfig::Hysteria2` takes one password. Upstream supports a user map, an HTTP callback and an external command. A client authenticating as `user:pass` works against us today only because we compare the whole string. |

**Port hopping — done, client side.** A server published as a port range is
reachable now. `src/quic_transport/hop.rs` binds a fresh UDP socket on a timer
and rotates the destination across the configured union, reporting one constant
address to QUIC so the connection never sees a path change. The local port
moves with it, which is the half that stops the 4-tuple being a handle for a
middlebox — rotating only the destination would have looked like the feature
while leaving the flow linkable. Spec:
[docs/specs/2026-08-23-hysteria2-port-hopping.md](./docs/specs/2026-08-23-hysteria2-port-hopping.md).

It is covered by an in-process bank of UDP relays standing in for an iptables
REDIRECT, which asserts that more than one port was used at each end rather
than only that the transfer succeeded.

It has also been run by hand against a real third-party Hysteria2 server on a
VPS, over the internet, with Salamander obfuscation. A local relay bank
supplied the port range, so what this proves is the client half: across a
90-second stream the client used all six destination ports and forty-two
distinct local ports, twenty consecutive requests returned 200, a 20 MB
download hashed identically to the same file fetched directly, DNS went
through the socks5 UDP associate, and no hop failed. What it does not prove is
a server natively published on a range: upstream supports
`listen: :20000-50000` on Linux and programs the firewall rules itself, ours
still listens on a single port, and the server in that run saw one port and
several source addresses rather than a range.

That run also turned up something unrelated to hopping: the same server
reached by hostname hung, because the name resolved to an IPv6 address whose
UDP replies never came back and the outbound never tried the working IPv4 one.
That is fixed, and what is left of it is the Tier 3 entry on address-family
fallback.

### Performance — the reason people pick Hysteria

| Gap | Effect |
| --- | --- |
| **Brutal congestion control** and the bandwidth negotiation behind it (`bandwidth.up`/`down`, `Hysteria-CC-RX` in both directions) | This is the headline feature. Brutal sends at a declared rate instead of backing off on loss, which is why Hysteria is fast on lossy intercontinental paths. Our server answers `auto` (`server.rs:176`), the value for a server that declines to set a rate, and our client declares `0` (`auth.rs:35`), meaning it does not know its own receive rate. Neither end installs Brutal either way; both run BBR, upstream's fallback, so a lossy path is no longer the collapse it was under Cubic (500 against 11 Mbit/s at 50 ms and 0.5% loss), but a fixed declared rate is still not available. Needs a `quinn` congestion controller; specified as SF-9 in `docs/specs/2026-10-21-lessons-from-steer.md`, which also says why quinn's internal pacer forces a different window from apernet's 2 × BDP. This row said we sent `0` in both directions and called `0` the "use ordinary congestion control" signal; both halves were wrong, and the second was the defect phase 1 fixed. |
| **`congestion` option** (`type: bbr \| reno`, `bbrProfile`: conservative/standard/aggressive) | We run BBR, upstream's default, with no way to choose `reno` or tune it. quinn's BBR has no profiles, so `bbrProfile` would need its own controller. |
| **`bandwidth.disableLossCompensation`** (upstream 2.10.0) | Only meaningful once Brutal exists. |
| **QUIC stateless resets** (upstream 2.12.1) | Server side. Without them a client holding a connection that died while the device slept waits out its idle timeout before reconnecting. Upstream called this out as most noticeable on mobile, which is this branch's entire audience. |
| **QUIC window and timeout tuning** (`quic.*`) | We hard-code the values the reference implementation uses. Exposing them is easy; whether it is worth the configuration surface is a separate question. |
| **Salamander's overhead is not deducted from the MTU** | `quic_transport::effective_mtu` subtracts the obfuscator's 8 bytes, but `quinn` clamps both `initial_mtu` and `min_mtu` with `.max(1200)` — 1200 being QUIC's own floor — so the subtraction has no effect. An obfuscated packet is therefore 1208 bytes on the wire, and a path that honours exactly 1200 will drop or fragment it. `quinn` exposes no way to send QUIC packets under the floor, so closing this means shrinking the payload some other way or carrying a patched transport. The code says this where the subtraction happens. |

### Detectability

| Gap | Effect |
| --- | --- |
| **Chrome QUIC fingerprint parroting** | Upstream since 2.11.0 and **on by default** there, with `quic.disableChromeParrot` to turn it off; sing-box followed. So the population a censor sees is moving to a Chrome-shaped handshake, and a default `quinn` client stands out more each release. This is the QUIC twin of the uTLS gap below, and closing it properly is a project rather than a backport. |
| **Masquerade** (`masquerade.type`: file/proxy/string) | Server side. The protocol requires a Hysteria server to behave like an ordinary HTTP/3 web server for anything that is not an auth request. Ours answers a bare 404 to everything, which is a constant response pattern — exactly what the specification warns active probers look for. |
| **ECH** (upstream 2.10.0) | Encrypts the ClientHello's SNI. Already listed under "explicitly not planned" for the TLS stack generally. |
| **mimic** (upstream 2.12.0) | Disguises the connection as TCP for networks that block UDP outright. Linux only, needs an XDP program and a separately installed binary. |

### Operational, server side

Not protocol, but part of what a Hysteria server is expected to do: **ACME**
certificate issuance, **SNI guard** (`tls.sniGuard`), **`speedTest`**, and
**Hysteria Realms** — the STUN and hole-punching rendezvous (upstream 2.9.0,
with UPnP/NAT-PMP in 2.9.3) that lets a server run behind NAT with no public
address.

### Deliberately not our problem

Upstream bundles a whole proxy application. Several of its configuration
sections have shoes equivalents that are broader, and copying them would be a
regression rather than a gain:

| Upstream | Ours |
| --- | --- |
| `acl` and `outbounds` | `rules`, `client_chains` and rule-sets |
| `sniff` | the `sniff` block, on every inbound and the TUN |
| `resolver` | the `dns` configuration |
| `socks5`, `http`, `tcpForwarding`, `udpForwarding`, `tcpTProxy`, `tcpRedirect`, `tun` on the client | server types in their own right, usable in front of any outbound |
| `trafficStats` | global counters today; per-connection statistics is Tier 2 item 6 |

One genuinely missing convenience: shoes cannot import a `hysteria2://` sharing
link. Every client in the ecosystem can, and it is how servers are distributed
in practice.

## mieru: what is left

The client outbound is verified against a real mieru server — a routebox
deployment on a VPS, TCP transport, one user, traffic pattern off. Two runs,
the second after the review fixes below:

- **Bulk, both directions.** 10 MB down and 20 MB up, at 6–10 MB/s. The
  10 MB download hashes byte for byte against the same file fetched
  directly, so the multi-segment path neither drops nor reorders.
- **Concurrency.** Eight simultaneous sessions, 4 MB in total, in 0.35 s.
- **A long session.** A server-sent-events stream held for 185 s: 8.7 MB,
  5656 events, no break, the last event intact.
- **Idle.** A keep-alive connection reused after 45 s and after 90 s of
  silence. mieru has no keepalive of its own over TCP, so this is the case
  that would fail first.
- **UDP.** DNS through the socks5 UDP associate, ten queries down one
  association, each reply matching its transaction id; and TCP on a fresh
  connection immediately after.
- **Address families.** An IPv6 destination through the tunnel, and the
  server reached over both its IPv4 and its IPv6 address.

A wrong password is reported as `the mieru server closed the connection
before answering the session request` — but only after about 44 seconds.
That is the server, not us: probed with random bytes it holds the
connection open, silent, for roughly 42 s before closing, which is mieru's
defence against active probing. A client-side timeout shorter than that
turns a clear refusal into what looks like a hang.

Those runs are what the tests could not give. They exercise the client against
a scripted peer built from this repository's own codec, and that construction
cannot detect a shared misreading of the specification — encode a field
wrongly, decode it wrongly to match, and every test passes. A code review
that read the Go implementation found nine defects while all of them were
green, four of which broke the protocol outright. A second review, after the
first live run, found eight more: the entropy padding was filling with the wrong
bit and so emitted a near-constant byte run, the segment encoders fell back
to a zero timestamp that a peer rejects, the handshake accepted a response
for someone else's session, and a UDP datagram spanning segments was refused
outright. Reading the reference is what found each of those; the live run is
the check that neither tests nor review can substitute for.

What is still worth doing, in order:

- **A `mita` run in CI.** The verification above was manual and is not
  repeated on any commit, so the next protocol change is unguarded. This
  is now part of quality-plan PR 4.3, part 3, the nightly interop job.
- **A mieru server here.** It would turn the scripted peer into a real
  interoperability test, the way the Hysteria2 and TUIC servers do for their
  clients, and cost roughly a third more work than the client did.
- **Read the reference for the remaining codecs** — mostly done.
  - The UDP encapsulation was compared line by line against upstream
    (`apis/common/packet_over_stream.go`).
  - The key derivation is pinned by vectors that mieru's own
    `cipher.HashPassword` and `BlockCipherFromPassword` computed (#94).
  - The reference client's first flight decodes with shoes' segment
    decoder to the request shoes sends (#97).
  - Padding, the open payload and the close handshake follow the Go client,
    checked against mita 3.38.1 (#83).

  What remains is the segment codec's less common paths: data segments
  after the first, and acknowledgements under loss. Only a live peer
  exercises those, which is the nightly job again.

Unimplemented, and refused in configuration rather than ignored: mieru's UDP
transport, session multiplexing, the low entropy encoding, port ranges, the
0-RTT handshake mode, and configurable traffic patterns. Only the first two
can make a server unreachable, and both are deployment choices. The
traffic-pattern options are the ones that matter for the protocol's purpose:
this client reproduces the default Go client's padding behaviour, so a
deployment using a customised pattern would look different on the wire.

## Lessons from steer

Spec: `docs/specs/2026-10-21-lessons-from-steer.md`. Plan:
`docs/plans/2026-10-21-lessons-from-steer.md`. Written 2026-10-21 from a
review of [splify2/steer](https://github.com/splify2/steer) at `07303cb`.
steer is GPL-3.0, so what it contributes is behaviours and reasons, not code.

| ID | Item | Status |
|---|---|---|
| SF-1 | A fake IP can be recycled while an app still holds it, so the app reaches another domain's server (`pool.rs:184`, `lookup` does not count as use) | fixed in #99 |
| SF-2 | An in-pool address with no mapping is dialled as a literal 198.18.x.x and stalls (`fake_ip/mod.rs:55-72`) | fixed in #99 |
| SF-3 | Local names (`.lan`, `.local`, single-label) get fake IPs and go into the tunnel | fixed in #99 |
| SF-4 | REALITY with no SNI panics (`tcp_client_handler_factory.rs:271`); Xray's empty SNI can't be expressed | fixed in #100 |
| SF-5 | Only UUIDv4 ids load; Xray's string ids and UUIDv7 don't (`uuid_util.rs`) | fixed in #100 |
| SF-6 | No fallback when a path drops the ~1.8 kB post-quantum ClientHello | planned, PR S.4 |
| SF-7 | AES-first cipher order on CPUs without AES instructions | planned, PR S.3 |
| SF-8 | No User-Agent on WebSocket and HTTPUpgrade requests, which matches neither Xray nor sing-box | planned, PR S.3 |
| SF-9 | Brutal and its `Hysteria-CC-RX` negotiation, specified against quinn's pacer | planned, PRs S.5 and S.6 |
| SF-10 | Probe and interop test methods | quality-plan PR 4.3: reference checks #101, probe harness #102; the nightly job is left |
| SF-11 | xhttp, gRPC, ECH, REALITY `pqv`, Gecko, DoQ, `.srs` logical rules | recorded, not planned |

Order: S.1 and S.2 came first, because they were bugs and configs that
failed to load; both are in. S.3 and S.4 come next. Brutal (S.5, S.6) comes
last: verifying it needs 4.3's interop rig against apernet, which is the
part of 4.3 still to do.

## Classic VPN clients: OpenConnect

Written 2026-10-31, after SSTP landed (#135) and the four classic client
protocols were weighed against what the tree now has. OpenConnect is the
one worth building; the other three are below, with why not.

**Status.** The CSTP client is built, later the same day, to the spec
named above: about 3,900 lines including the server double and 50 tests,
against this section's estimate of 2,400 for the pieces short of DTLS. What
the plan below did not know: ocserv reads one TLS record per frame and
ends a session whose record holds anything else, so the writer cannot
batch frames as SSTP's does; and an IETF draft by ocserv's author
(draft-mavrogiannopoulos-openconnect-04) documents the protocol, which the
openconnect source alone does not. Still to do: a live run against the
user's Keenetic and against ocserv in a container, and the DTLS step on
the terms below.

**What it is.** The protocol of Cisco AnyConnect and of
[ocserv](https://gitlab.com/openconnect/ocserv) (GPL), spoken by the
[openconnect](https://gitlab.com/openconnect/openconnect) client (LGPL-2.1),
whose maintainers document it at
[infradead.org/openconnect/protocols.html](https://www.infradead.org/openconnect/protocols.html).
Keenetic ships an ocserv-based server in KeeneticOS 4.x with the same
camouflage mode SSTP has (`oc-server camouflage`, the secret as the URL's
query string), so a Keenetic user has it beside SSTP. sing-box 1.14 added a
client, [sing-openconnect](https://github.com/SagerNet/sing-openconnect),
about 1 MB of Go over `pion/dtls`; its licence is unstated, so it is
behaviour to read, not code.

**The shape.** HTTPS throughout, which is why it crosses what blocks UDP:

1. Authentication over ordinary HTTPS: an XML form exchange (`POST /`,
   `<config-auth client="vpn" type="init">`, the server's form, the reply
   with username and password), ending in a `webvpn` session cookie.
2. The tunnel: `CONNECT /CSCOSSLC/tunnel` with `X-CSTP-*` headers (MTU,
   address request, keepalive and DPD intervals) answered with the
   assigned address, DNS, split routes and the server's own intervals;
   then CSTP frames on the same TLS stream, an 8-byte header (`STF`, a
   version byte, a 16-bit length, a type byte: data, DPD request and
   response, keepalive, disconnect) in front of each IP packet.
3. Optionally the data path moves to DTLS over UDP, negotiated by
   `X-DTLS-*` headers: the server names the port, cipher and a session
   identity the client resumes without a full handshake (the master
   secret, or ocserv's PSK form). Same frames, one UDP datagram each.

**What the tree gives it.** All of it from SSTP's shape: the shared
netstack (`src/netstack.rs`), the TLS setup and pinning
(`src/rustls_config_util.rs`), the HTTP parsing (`src/http_parse.rs`),
the connector lifecycle with its cooldown and the network-change listener
(`src/sstp/connector.rs`, to copy, or to extract into a trait now that a
third tunnel needs it), the single-hop rule and the terminal-connector
arm (`src/config/validate.rs`, `src/tcp/chain_builder.rs`), and the test
server double's pattern (`src/sstp/testing.rs`). No PPP, no crypto
binding: this is simpler than SSTP on the control plane.

**What is new.**

| Piece | Lands in | Size |
| --- | --- | --- |
| The auth exchange: form XML, the cookie, the error forms a server sends for a wrong password or a second factor it wants | `src/openconnect/auth.rs` | ~600 lines |
| CSTP: the CONNECT, the headers both ways, the frame codec, DPD and keepalive on the server's intervals | `src/openconnect/cstp.rs`, `session.rs` | ~800 lines |
| The connector and config: `type: openconnect`, username, password, `tls`, `camouflage_secret`, an optional server certificate pin as Keenetic users will need | `src/openconnect/connector.rs`, `src/config/` | ~400 lines |
| The server double for the end-to-end tests: ocserv's side of the form exchange and CSTP, echoing from a smoltcp interface as SSTP's does | `src/openconnect/testing.rs` | ~600 lines |
| DTLS: a stack (none in the tree; `dimpl`, DTLS 1.2/1.3, sans-IO, MIT/Apache, is the candidate), the `X-DTLS-*` negotiation, resuming the session the server named, the same frames over UDP, falling back to CSTP when DTLS does not come up within its timeout | `src/openconnect/dtls.rs` | 2–3 kLOC, and the risk |

Without DTLS it is TCP in TCP, like SSTP, and the same path-MTU and
loss costs apply; with it, the data path is UDP and the netstack's
windows do what they do for AmneziaWG. The order of work is therefore
CSTP first, as a complete client, measured; DTLS second, if the
measurement says the TCP path is what limits a user. ocserv's session
handoff to DTLS is not the standard resumption, and whether `dimpl`
lets a client drive it is the question to answer before promising it.

**Difficulty.** 3 of 5 for the CSTP client, 4 of 5 with DTLS, against
SSTP's 2 (about 4,800 lines including tests, two days). Verification as
for SSTP: a spec first, read from the openconnect client and ocserv with
file-level citations; known-answer tests where the protocol computes
anything; the in-process double; a live run against the user's Keenetic
and against ocserv in a container, recorded in words.

**Weighed and left, for now.**

- **OpenVPN** (4 of 5; 8–12 kLOC). Nothing in it is standard: TLS inside
  its own reliable transport, `tls-crypt` around the control channel, its
  own key derivation and data-channel format, replay window, ping and
  option push. There is no Rust implementation to lean on, and the OpenVPN
  3 Core bindings on crates.io are AGPL, which a mobile library cannot
  carry. sing-openvpn is 640 KB of Go. Keenetic's own documentation calls
  OpenVPN resource-intensive and steers users to other types. Worth doing
  only when a deployment that offers nothing else asks.
- **IKEv2/IPsec** (5 of 5; 10–15 kLOC). The IKE state machine, userspace
  ESP with anti-replay, NAT-T, rekeying, DPD, MOBIKE, fragmentation, and
  then the quirks of Windows, Apple, strongSwan and Keenetic each. The one
  Rust crate claiming a client (`ryke`) is eleven days old with no users;
  `ipsec-parser` only parses. And every phone and desktop OS has a native
  IKEv2 client already: on iOS the extension would be reimplementing what
  `NEVPNManager` gives an app for free.
- **L2TP/IPsec** (5 of 5 overall). L2TP alone is small (about 1.5 kLOC)
  and would reuse SSTP's PPP and MS-CHAPv2 whole, but every server that
  offers it, Keenetic's included, requires IPsec transport mode negotiated
  with IKEv1, a separate and deprecated protocol from IKEv2. More work
  than IKEv2 for a protocol every OS speaks natively.

## Explicitly not planned

- **gRPC transport** — considerable work, and less used in practice than
  WebSocket.
- **ECH** — no demand behind it yet.
- **mKCP** — effectively dead.

## Open risk: TLS fingerprinting

Not a missing feature; a property of the stack.

Xray and sing-box both use uTLS to imitate a Chrome ClientHello. shoes goes
through rustls, whose handshake is fixed and quite recognisable. Where a DPI
classifies by TLS fingerprint, Reality protects us and a plain TLS client does
not.

There is no mature uTLS equivalent in Rust. Closing this would mean writing one,
which is a project rather than a backport, and it should be decided as such.

The same exposure now exists over QUIC, and it is getting worse rather than
staying still. Hysteria has parroted Chrome's QUIC handshake by default since
its 2.11.0, sing-box followed, and both pin transport parameters — idle timeout
and receive windows — as part of the imitation. Every release moves more of the
observable population toward one shape, which makes a default `quinn` client
easier to pick out by standing still. Our QUIC outbounds at least take their
transport parameters from the reference implementations rather than inventing
plausible-looking numbers, so we do not pay for a unique signature we never
chose; the handshake itself remains ours.

A second divergence opened in 2026, and checking it corrected an assumption
worth recording, because the intuition was wrong in our favour.

**Post-quantum key exchange we already have, by accident rather than by
decision.** `prefer-post-quantum` is a default feature of rustls, our build
resolves it on, and `src/rustls_config_util.rs:191` takes
`aws_lc_rs::default_provider()` — so `X25519MLKEM768` is the *first* group
offered on every rustls path, client and server, QUIC included. Nobody chose
that here; it arrived with a dependency default. It should be treated as a
property to hold deliberately rather than one to keep by luck: nothing in the
tree pins the group list or would fail if a future rustls reordered it.

Two places did not inherit it. **`src/reality/`** was classical X25519 only
until #81 (2026-10-19), which gave the client Chrome 133's X25519MLKEM768
share (`docs/specs/2026-10-19-reality-chrome-client-hello.md`). Some paths
drop that larger hello, which is SF-6 under "Lessons from steer". The
reference clients disagree about sending it at all. Xray's REALITY client
sends the hybrid share. sing-box's strips X25519MLKEM768 from both
supported_groups and key_share before the handshake
(`common/tls/reality_client.go:148-159` in v1.14.3; found by the shape test
in #101). So shoes' hello matches Xray's, not sing-box's, and that is the
starting point for S.4's `post_quantum` default. Xray has
gone further, signing REALITY certificates with ML-DSA-65 via `mldsa65Seed`
(the `pqv` check, SF-11), a protocol-level change we would have to follow
rather than invent. And **we have no ECH at all**, where sing-box
supports it and Xray now forces it whenever it is configured.

ECH is the real gap of the two, and it is a fingerprinting gap rather than a
confidentiality one: without it the SNI is in the clear on every plain-TLS
path, which is exactly what Reality exists to work around and exactly what a
non-Reality deployment still leaks. Worth scoping against rustls' ECH support
rather than assuming, the way the post-quantum question should have been.

## Resolved: AmneziaWG upload was capped by the send window, and the drop was the outbound channel

The send window was raised per platform (`default_remote_tx_window_size` in
`src/buffer_sizing.rs`), and the netstack's virtual device now backpressures
when the tunnel's outbound channel is full — `VirtualDevice::transmit` refuses
tokens, the burst waits in the socket's own buffer, and what an `iface.poll`
emitted but the channel would not take is carried to the next pass instead of
dropped. That holds for any window size, any number of concurrent uploads
sharing the channel, and any configured MTU, and it keeps the channel itself
small, so the standing queue that everything else in the tunnel (DNS, SYNs, a
concurrent download's ACKs) waits behind stays bounded at the depth every
earlier measurement ran on. What follows is the investigation, kept because it
corrects two earlier readings.

**The drop the previous note went looking for was the `tunnel TX full` path
after all.** That earlier note said the warning "never fired" and put the drop
below it in the endpoint UDP socket. It never fired on that path because it was
too slow to burst past the 256-slot `ip_to_tunnel` channel. Measured against an
AmneziaWG 3.1 peer at ~24 ms with a ~240 Mbit/s raw path, raising the send
window with the channel still at 256 fired it hundreds of times per transfer
(224 at 512 KiB, 602 at 2 MiB), and each burst of drops was what Cubic read as
congestion. The send buffer was never the cause; the channel behind it was.

**With the burst kept out of the channel, the window scales cleanly.** Same
peer, single stream, zero outbound drops at every size:

| window | upload |
|---|---|
| 256 KiB | 56 Mbit/s |
| 512 KiB | 102 Mbit/s |
| 768 KiB | 136 Mbit/s |
| 1 MiB | 156 Mbit/s |

Linear in the window, which is the signature of a window-limited transfer:
upload is `window / RTT` below the path's bandwidth-delay product, exactly as
download is. Download was unaffected (~200 Mbit/s throughout) — its inbound
channel stays at 256 because the network paces arrivals into it, where the
send side dumps a whole window in one poll.

**The bimodal spread was the same collapse.** The A/A control's 13-55 range was
this: whenever a burst overflowed the channel, that connection fell into the bad
state and Cubic climbed back out. Over the public internet the residual RTT and
path-bandwidth drift are still large enough (13-152 Mbit/s within minutes as RTT
moves 13-66 ms) that a clean absolute A/B is not possible from a WAN client, but
the fixed build no longer collapses: across interleaved rounds it held 103-160
Mbit/s where the 256 KiB baseline still dropped to 11 and 45.

**Still open: ~19% of upload wall-clock is idle gaps even at a window above the
BDP**, a per-cycle send-refill stall that raising the window does not remove. It
caps the ceiling below the raw path and is the next thing to chase, on a
controlled path rather than the WAN.

## Open risk: Android's receive window is extrapolated from macOS

The other half of this entry is settled. It asked whether the 4 MiB desktop
receive window is *slower* than 256 KiB on a lossy path, because smoltcp's
reassembler tracks at most 32 holes (`assembler-max-segment-count-32`, its
largest setting) and drops a segment past that without even a duplicate ACK.
Measured 2026-10-10 with `NETEM` in `scripts/bench/tunnels.py`: a WireGuard
download from a sing-box server into a shoes client, 50 ms round trip,
1 Gbit/s, the window changed in code and everything else equal, two rounds
each, Mbit/s:

| loss | 4 MiB | 1 MiB | 256 KiB |
| --- | --- | --- | --- |
| none | 541, 547 | 161, 161 | 40, 40 |
| 0.5% | 5, 6 | 5, 5 | 5, 5 |
| 1% | 3, 3 | 3, 3 | 3, 4 |
| 2% | 2, 2 | 2, 2 | 2, 2 |

On a clean path the window is the whole story, `window / RTT` to within a few
percent. On a lossy one every size collapses to the same few Mbit/s, which is
the loss-based sender inside the tunnel (gVisor's TCP in sing-box) running at
about MSS / RTT × 1.22 / √p. The reassembler is not involved: sing-box's own
client, whose receiver has no such ceiling, carried 4 Mbit/s on the same
0.5% path. So there is no crossover and no reason to shrink the window. What
decides a lossy download is the sender's controller, which is never ours: in
the benchmark it is sing-box's netstack, and through a kernel WireGuard server
it is the destination host's TCP.

**Android's window is extrapolated from macOS RSS.** The per-connection RSS
table in MOBILE.md was sampled on macOS, and Android's 1 MiB was chosen from
it rather than from a device. Android's worst case works out near 330 MiB
resident under sustained bulk load, and a `VpnService` at that RSS is a
low-memory-killer candidate on a budget device — where losing the app loses the
tunnel. Sampling RSS on a low-RAM device under concurrent downloads would
either confirm 1 MiB or argue it down. Related: the remote window has no config
knob, unlike the TUN side's `tcp_buffer_size`, so an operator who hits this
cannot lower it without a rebuild. Exposing it is cheap and worth doing if the
measurement bites.
