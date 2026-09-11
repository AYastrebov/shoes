# shoes as an engine for awg-manager

What shoes must gain to stand beside, and later replace, the sing-box fork
that awg-manager runs on Keenetic routers, in the order the modes matter and
with the MIPS build last.

Written 2026-09-11 against `mobile` at `f9f7795` (v0.4.1) and awg-manager at
its `1.14.0-awgm.16` engine pin. The Clash API this depends on is
[docs/specs/2026-09-09-clash-api.md](./2026-09-09-clash-api.md), revised the
same day for awg-manager's call list; nothing there is repeated here.

## Table of Contents

- [Problem](#problem)
- [What awg-manager is](#what-awg-manager-is)
- [The measured win](#the-measured-win)
- [The gap table](#the-gap-table)
- [Scope and slices](#scope-and-slices)
- [Slice 1: the process contract](#slice-1-the-process-contract)
- [Slice 2: redirect and tproxy inbounds](#slice-2-redirect-and-tproxy-inbounds)
- [Slice 3: rules](#slice-3-rules)
- [Slice 4: DNS rules](#slice-4-dns-rules)
- [Slice 5: a Chrome-shaped ClientHello](#slice-5-a-chrome-shaped-clienthello)
- [Slice 6: MIPS](#slice-6-mips)
- [The config mapping](#the-config-mapping)
- [RSS budget](#rss-budget)
- [Security notes](#security-notes)
- [Testing](#testing)
- [Order of work](#order-of-work)
- [Decisions](#decisions)
- [Deliberately out of scope](#deliberately-out-of-scope)

## Problem

awg-manager manages AmneziaWG tunnels on Keenetic routers and, "in test
mode", proxies: vless, hysteria2, trojan, shadowsocks, naive, socks and
mieru, through a sing-box fork (`hoaxisr/amnezia-box`: sing-box plus
AmneziaWG endpoints, mieru and `xhttp`). The fork is 61 MB on aarch64 and
74 MB on mipsel, idles at 47 MB resident and reaches 82 MB under load, and
awg-manager pins it at `GOMEMLIMIT=128MiB` and treats an OOM kill as an
expected failure with its own user-facing message. On a 256 MB Keenetic the
engine is a quarter of memory before it has carried a byte.

shoes is 13 MB, idles at 12 MB and reaches 18 MB under the same load, with
the same CPU per byte. It already speaks every protocol awg-manager's share
links produce except `xhttp`, gRPC and mieru over UDP, and its AmneziaWG
implementation is the more complete of the two. What it lacks is not
protocols. It lacks the process contract awg-manager holds sing-box to, the
two transparent-proxy inbounds awg-manager's main router mode is built on,
the rule and DNS features awg-manager emits, a ClientHello that looks like a
browser's, and a MIPS build.

## What awg-manager is

Facts this design rests on, from a survey of the repository on 2026-09-11.
File references are into `~/VibeCode/awg-manager`.

**Three targets**: `aarch64-3.10`, `mipsel-3.4`, `mips-3.4`
(`cmd/awg-manager/sysenv.go:23-36`). The number after the dash is the
kernel. KeeneticOS 5.x is required for the two tun modes
(`internal/singbox/router/opkgtun_support.go:18-27`).

**Three modes**, from `internal/singbox/router/`:

- *Legacy tunnel*: one `mixed` listener per tunnel slot on
  `127.0.0.1:1080+slot`, one outbound, one route rule `inbound → outbound`;
  NDMS `ProxyN` interfaces point at the port (`internal/singbox/config.go:16,225-236`,
  `proxy.go:74-81`). No kernel plumbing by the engine.
- *tproxy router*: a `redirect` inbound for TCP on `51272` and a `tproxy`
  inbound for UDP on `51271` (`service_lifecycle.go:1240-1260`,
  `iptables.go:22,34`). awg-manager owns every iptables chain, `ip rule`
  (fwmark `0x1`, table `100`, priority `30000`) and the NDMS hooks that
  re-apply them. TCP goes through NAT `REDIRECT` rather than `TPROXY`
  because the 4.9 Keenetic kernel's `-m socket --transparent` does not match
  (`iptables.go:23-33`). This is the mode Keenetic 4.x users run.
- *fakeip-tun* and *policy-tun*: a `tun` inbound with `auto_route`,
  `auto_redirect` and `strict_route` all `false`; routes and the fake-IP pool
  are installed into NDMS by awg-manager (`config_fakeip.go:77-89`,
  `fakeip_cidr_routes.go`). KeeneticOS 5 only.

**Config** is a `config.d/` of numbered JSON slots merged by sing-box, arrays
concatenated and scalars first-wins (`orchestrator/types.go:84-104`). Every
share-link format is parsed by awg-manager itself into sing-box outbound JSON
(`internal/singbox/vlink/`); the engine never sees a URI.

**Runtime**: started from Go with `run -C <dir>`, checked with `check -C`,
reloaded with `SIGHUP` except when a tun inbound is present, health-probed
through Clash `/version`, watched every 30 s, restarted with backoff, logs
tailed from stdout/stderr files and from the Clash `/logs` stream
(`internal/singbox/process.go`, `watchdog.go`, `logs.go`).

**Emitted but not by every mode**: rule sets as remote `.srs` with
`update_interval`, inline rule sets compiled to `.srs` by shelling out to
`sing-box rule-set compile`, DNS rules with `hijack-dns`, `predefined`
answers and per-outbound `detour` resolvers, logical `and`/`or` rules,
`source_ip_cidr`, `route-options` with `udp_timeout`, `selector` and
`urltest` groups.

## The measured win

Measured 2026-09-11 on an Apple M-series host, identical configs, identical
load, a direct outbound over loopback:

| | sing-box 1.14 | shoes 0.4.1 | ratio |
|---|---|---|---|
| Binary, aarch64 Linux, static | 61.4 MB (fork) | 13.3 MB | 4.6× |
| Binary, mipsel Linux | 74.3 MB (fork) | no stable build | |
| Idle RSS, one `mixed` inbound | 47 MB | 12.4 MB | 3.8× |
| Idle RSS, plus Reality and Hysteria2 outbounds | 48 MB | 12.8 MB | 3.7× |
| Peak RSS, 8 streams × 50 MB × 3 | 55 MB | 14 MB | 3.9× |
| Peak RSS, 32 streams × 50 MB × 10 (16 GB) | 82 MB | 18 MB | 4.6× |
| CPU for those 16 GB | 11.4 s | 11.4 s | 1.0× |

Two caveats the numbers carry. The CPU row is a plain TCP relay: it says
shoes adds no per-byte overhead, not that it wins on Reality or Hysteria2
crypto, neither of which was exercised. And the host is not a Keenetic; the
first item of work is the same two figures on a real router. The disk and
memory rows do not depend on the host: a router that had to UPX the fork to
fit it (`installer/installer.go:181-208` tolerates that) does not have to
UPX shoes, and the 13 s that hashing an 80 MB binary costs on softfloat MIPS
(`installer.go:58-62`) shrinks with the binary.

## The gap table

Every sing-box feature awg-manager emits or calls, against shoes today.
"Slice" is where this design closes it; "out" means deliberately not.

| Feature | awg-manager site | shoes today | Slice |
|---|---|---|---|
| `mixed` inbound, optional users | `config.go:225,777` | yes | — |
| `SIGHUP` reload | `process.go:582` | file watcher only | 1 |
| `check -C` | `validate.go:64` | `--dry-run` | 1 (alias) |
| `version` subcommand and `/version` | `installer.go:286` | `--version`, prints `shoes 0.4.1` | 1 |
| Log lines classifiable as inbound/outbound/dns/router | `logs.go:94` | Clash spec, `/logs` | done in Clash spec |
| Clash API: proxies, select, delay, logs, connections | `clash.go` | Clash spec slices 1–3 | Clash spec |
| `selector` with `default`, `urltest` | `subscription/materialize.go` | Clash spec slices 2–3 | Clash spec |
| `cache_file` selection persistence | `operator_baseconfig.go:1146` | Clash spec `state_file` | Clash spec |
| `redirect` inbound (TCP, `SO_ORIGINAL_DST`) | `service_lifecycle.go:1252` | **no** | 2 |
| `tproxy` inbound (UDP, `IP_TRANSPARENT`), `udp_timeout`, `udp_nat_max` | `service_lifecycle.go:1240` | **no** | 2 |
| `tun` with routes left to the host | `config_fakeip.go:77` | yes, smoltcp stack | — |
| Fake IP with configurable ranges | `config_fakeip.go:93` | yes (`fake_ip` on TUN) | — |
| Rules: `domain_suffix`, `domain`, `ip_cidr`, port, `ip_is_private`, `reject`, `sniff` | `router/types.go:86` | yes | — |
| Rules: `logical` `and`/`or` | `router/config.go:300-368` | **no** (one rule = masks OR'd) | 3 |
| Rules: `source_ip_cidr` | `router/types.go:96` | **no** | 3 |
| Rules: `route-options` `udp_timeout` | `types.go:134` | **no** | 3 |
| Rules: `source_mac_address` | `types.go:97` | no | out |
| Remote `.srs` with `update_interval` | `preset.go:92` | reads `.srs` from disk | out (awg-manager fetches) |
| `rule-set compile` of inline sets | `ruleset_materializer.go:462` | decoder only | 3 |
| `rule-set match` | `inspector_ruleset.go:212` | no | 3 (same encoder work) |
| DNS: servers with `detour`, bootstrap, strategy | `awgoutbounds/config.go:51` | yes (`dns_group`, per-server chain) | — |
| DNS: rules by domain to a server | `router/types.go:410` | **no** | 4 |
| DNS: `predefined` answers (rewrites) | `dnsrewrite/compile.go:67` | **no** | 4 |
| DNS: `hijack-dns` on port 53 for non-TUN modes | `router/config.go:420` | TUN fake-IP path only | 4 |
| DNS: `fakeip` server type with `inet4_range` | `config_fakeip.go:93` | on TUN only | 4 |
| `utls` `chrome` fingerprint on Reality and TLS | `vlink/stream.go:280` | **no**; hand-built ClientHello | 5 (gated) |
| Reality, Vision | `vlink/vless.go` | yes | — |
| Hysteria2 obfs, `server_ports` hopping | `vlink/hysteria2.go` | yes | — |
| Hysteria2 `brutal`, `tls.ech` | `vlink/hysteria2.go:70-96` | no | out |
| `xhttp`, gRPC, `http` (h2) transports | `vlink/stream.go:243` | no | out |
| mieru over UDP | `vlink/mieru.go` | TCP only | out |
| `vmess` | `vlink/vlink.go:95` | n/a, dropped by awg-manager | — |
| AmneziaWG 2/3 endpoint | `awg3endpoint/conf.go` | yes, 3.0 and 3.1 | — |
| `GOMEMLIMIT` | `process.go:160` | n/a | — |
| mipsel, mips builds | `sysenv.go:23` | **no** (Rust tier 3) | 6 |

## Scope and slices

Six slices, each a shippable increment that unlocks one awg-manager mode or
removes one risk. The order is by what it unlocks against what it costs, and
MIPS is last because the user placed it last: it is a toolchain project
with no guaranteed outcome, and the aarch64 routers get every other slice
without it.

1. **The process contract.** `SIGHUP` reload, `check` and `version`
   subcommands, exit and log conventions. Unlocks the legacy-tunnel mode on
   aarch64 with nothing else, once awg-manager has a shoes emitter.
2. **`redirect` and `tproxy` inbounds.** Unlocks the tproxy router mode.
3. **Rules**: logical groups, source CIDR, per-rule UDP timeout, and an
   `.srs` encoder behind `rule-set compile` and `rule-set match`. Unlocks
   awg-manager's full rule editor.
4. **DNS rules**: domain-to-server routing, predefined answers, port-53
   hijack outside TUN, fake IP as a DNS server type. Unlocks the tun modes'
   DNS behaviour and DNS rewrites everywhere.
5. **A Chrome-shaped ClientHello** for Reality and plain TLS. Gated on a
   live test that shows the current ClientHello being reset where a uTLS one
   is not; if it is not, this slice is not built.
6. **MIPS.** A nightly `build-std` toolchain for `mipsel-unknown-linux-musl`
   and `mips-unknown-linux-musl`, and the CI job to ship them.

Slices 1 and 2 are specified in full below and planned in
[docs/plans/2026-09-11-awg-manager-engine.md](../plans/2026-09-11-awg-manager-engine.md).
Slices 3 to 6 are specified to their contracts and get their own plans, each
after the previous slice has run under awg-manager.

The awg-manager side, a shoes config emitter and a second installer entry,
is in scope of the awg-manager repository. [The config mapping](#the-config-mapping)
is the contract it implements and is kept here so both repositories read
one table.

## Slice 1: the process contract

Everything awg-manager does to the engine process other than through the
Clash API, and what shoes answers.

**`SIGHUP` reloads.** `src/main.rs` installs `SIGINT` and `SIGTERM`
(`ShutdownSignals`, `:526-600`) and reloads only from the file watcher with
a three-second debounce. `SIGHUP` joins the signal set and takes the reload
path immediately, with no debounce: the process that sent the signal has
finished writing. A `SIGHUP` with `--no-reload` still reloads; the flag
disables the watcher, not the operator. Reloading a config with a TUN
server restarts the TUN the way the watcher path does today; awg-manager
already special-cases that and does a stop-start.

**`check` and `version` subcommands.** `shoes check <config>...` is
`--dry-run` under the name awg-manager's code already uses, exit code 0 or
1, the error on stderr. `shoes version` prints `shoes 0.4.1` on one line, the
same as `--version`. Neither changes any existing flag.

**Exit conventions.** A config that fails validation at start exits 1 with
the message on stderr, as today. A fatal runtime error exits non-zero with
the last line on stderr; awg-manager captures the last 16 KB of stderr on
early exit and reads it back to the user (`process.go:271-285`).

**Log lines on stderr** keep their current format. The classifier
awg-manager runs is on the Clash `/logs` stream, which the Clash spec shapes.

**What awg-manager changes on its side**, listed so the two halves agree:
`RequiredVersion` grows a second pin for shoes; the version probe strips
`shoes ` as it strips `sing-box `; the config path becomes one YAML file
rather than a directory; `Reload()` sends `SIGHUP` as it does today.

## Slice 2: redirect and tproxy inbounds

Both are inbounds with no protocol of their own: the kernel delivered the
connection, and the only question is where it was going.

### `redirect`

```yaml
- address: 127.0.0.1:51272
  protocol:
    type: redirect
  rules: [...]
```

Linux only; validation refuses it elsewhere. A connection arrives through
NAT `REDIRECT`, and the original destination is in the socket:
`getsockopt(fd, SOL_IP, SO_ORIGINAL_DST)` for IPv4,
`SOL_IPV6, IP6T_SO_ORIGINAL_DST` for IPv6. That read has to happen on the
accepted socket before it is boxed into `dyn AsyncStream`, which is where
the accept loop is. `AsyncStream` gains one method with a default:

```rust
fn original_destination(&self) -> Option<SocketAddr> { None }
```

implemented for `tokio::net::TcpStream` under `cfg(target_os = "linux")`
by the `getsockopt` above, forwarded by `PermitStream` and the counting
stream, and `None` everywhere else. A `RedirectServerHandler` calls it and
answers `TcpForward` with that destination, exactly as `PortForwardServerHandler`
answers with a configured one. A stream that reports `None` on a `redirect`
listener is refused with a logged error: a connection that was not
redirected has no destination and must not be forwarded to the listener
itself.

The destination is an IP and port; sniffing gives rules a hostname, as it
does for every other inbound.

### `tproxy`

```yaml
- address: 127.0.0.1:51271
  transport: udp
  protocol:
    type: tproxy
    udp_timeout: 300      # seconds; sing-box's udp_timeout
    udp_nat_max: 4096     # sing-box's udp_nat_max
  rules: [...]
```

Linux only. `Transport::Udp` exists in the config and is `todo!()` in
`start_tcp_or_quic_servers` (`src/tcp/tcp_server.rs:394`); this is its first
implementation, and it is specific to `tproxy` until another UDP-native
inbound wants it.

The socket is bound with `IP_TRANSPARENT` and `IP_RECVORIGDSTADDR` (and the
IPv6 pair), so `recvmsg` yields the original destination in ancillary data.
Each datagram is `(source, original destination, payload)`. That is the
shape of `AsyncTargetedMessageStream` already: reads return a target, writes
take a source. A `TproxyUdpStream` implements it over the listening socket,
and the accept path hands it to `run_udp_routing(ServerStream::Targeted(..))`,
which already keeps one session per destination, routes each through the
rules, and expires them. `udp_timeout` becomes the router's session expiry
for this listener and `udp_nat_max` its session cap; both are per-listener
settings passed into `UdpRouter` rather than constants.

Replies must appear to come from the original destination. A reply socket
per `(original destination)` is bound with `IP_TRANSPARENT` to that address
and port, sends to the client, and is closed with the session. That is what
every tproxy implementation does; it costs one socket per live session,
which is bounded by `udp_nat_max`.

The kernel side is awg-manager's: the `fwmark 0x1` policy route into table
`100` with a `local` default is what makes a transparent socket receive the
datagram, and it is installed by `iptables.go`, not by shoes.

### What both share

Registration in the connection registry at the accept edge like every
other inbound, with inbound labels `redirect@…` and `tproxy@…`; the same
rules, sniffing and outbound path; the same per-listener limits. Neither
has users or a handshake, so `connection_success_response` is `None` and
`need_initial_flush` is `true`.

## Slice 3: rules

Contract only; the plan comes after slice 2 runs.

**Logical rules.** A rule gains `all_of` and `any_of`, each a list of
sub-rules with the same fields, nestable. Today's `masks` list is `any_of`
over masks; it stays. `all_of` is what sing-box's `logical: and` is and what
awg-manager's `normalizeAddressOrRule` produces when a rule carries both a
rule set and its own addresses.

**Source matching.** `source_masks`, the same mask syntax as `masks`, against
the connection's source. The registry already carries the source; the
selector gets it as a second argument to `judge`. Nothing per connection is
allocated.

**Per-rule UDP timeout.** `udp_timeout` on an allow rule overrides the
listener's session expiry for sessions that matched it.

**`.srs` encoder.** `src/rule_set/` decodes sing-box's binary rule sets;
it gains an encoder for the subset awg-manager writes (`domain`,
`domain_suffix`, `domain_keyword`, `ip_cidr`), and two subcommands:
`shoes rule-set compile --output <file> <source.json>` and
`shoes rule-set match -f <format> <file> <input>`, with sing-box's argument
order so awg-manager's shell-outs work by changing the binary name.

## Slice 4: DNS rules

Contract only.

Today a `dns_group` is a list of servers with chains, bootstrap and
strategy, and every query in the group goes to every server by strategy.
awg-manager routes by domain, rewrites some answers, and hijacks port 53.

**Rules on a group.** `dns_rules`, evaluated in order before the servers:

```yaml
- dns_group: main
  dns_servers: [ { url: udp://1.1.1.1, name: cf }, { url: udp://10.0.0.1, name: lan } ]
  dns_rules:
    - masks: [.lan, .home]
      server: lan
    - masks: [ads.example]
      action: reject             # NXDOMAIN
    - masks: [printer.home]
      answer: [192.168.1.50]     # predefined
```

The mask syntax is the routing one. `server` names a server in the group;
`reject` answers NXDOMAIN; `answer` returns the given addresses with a
fixed TTL. No `query_type` filter in this slice: a predefined rule answers
A and AAAA from the addresses it is given and nothing else.

**Hijack.** A `redirect` or `tproxy` listener with `hijack_dns: true`
answers any connection or datagram to port 53 from its own resolver instead
of forwarding it, which is sing-box's `hijack-dns` action for those
inbounds. The TUN fake-IP path already intercepts port 53 and keeps doing
so.

**Fake IP as a server.** `dns_servers` accepts `{ fake_ip: { network:
198.18.0.0/15 } }` as a server, so a `dns_rules` entry can send some
domains to fake IP and others to a real resolver, which is what
awg-manager's fakeip-tun does with its `fakeip` and `real` servers.

## Slice 5: a Chrome-shaped ClientHello

Gated, not scheduled. awg-manager sets `utls: { fingerprint: chrome }` on
every Reality and TLS outbound (`vlink/stream.go:280`). shoes' Reality client
builds its ClientHello by hand (`src/reality/reality_tls13_messages.rs:279`)
with a fixed extension list and no GREASE, and its plain TLS client is
rustls, whose ClientHello is rustls-shaped. Whether that matters is an
empirical question about the DPI between the user and the server.

**The gate.** Before this slice is planned: a vless-Reality link to a real
server, from a network where a uTLS ClientHello is known to pass, opened
with shoes. If it connects and stays connected across a day of use, this
slice is not built. If it is reset or stalls where the fork's is not, this
slice is the next one.

**The shape if built.** For Reality, the hand-built ClientHello gains
Chrome's extension order, GREASE values, ALPS and the padding target that
uTLS's `HelloChrome_Auto` emits, generated from a recorded Chrome hello
rather than typed. For rustls, the ClientHello is not shapeable from
outside; the plain-TLS client would move onto the Reality module's TLS 1.3
implementation for the handshake, which is a larger change and is why the
gate exists.

## Slice 6: MIPS

Last, by the user's instruction. `mipsel-unknown-linux-musl` and
`mips-unknown-linux-musl` are Rust tier 3: no prebuilt standard library, so
`-Z build-std` on a nightly toolchain, and aws-lc-rs documents "requires
nightly Rust toolchain" for MIPS. The Keenetic targets are kernel 3.4,
below Rust's documented 3.2 minimum only by a version that does not matter,
and softfloat, which the target triples above assume.

**What it takes.** A CI job that installs nightly with `rust-src`, builds
`--target mipsel-unknown-linux-musl -Z build-std=std,panic_abort` with a
`musl` cross linker, and ships `shoes-linux-mipsel-musl.tar.gz` and the
`mips` twin. A test that the binary starts on a real KN-1010 and carries
a connection.

**What could stop it.** jemalloc on MIPS (`tikv-jemallocator` is the CLI's
allocator; switching the MIPS build to the system allocator is the fallback
and costs a `cfg`); aws-lc-sys's C build under the cross toolchain; and
smoltcp, ring-free by construction, is fine. None of these are known to
fail; none are known to pass.

## The config mapping

The contract the awg-manager emitter implements. Left: what awg-manager
emits for sing-box. Right: what it emits for shoes.

| sing-box | shoes |
|---|---|
| `inbounds[].type: mixed`, `listen`, `listen_port`, `users` | `- address: <listen>:<port>`, `protocol: { type: mixed, username, password }` (one user; a second user is a second listener) |
| `inbounds[].type: redirect` | `protocol: { type: redirect }` (slice 2) |
| `inbounds[].type: tproxy`, `udp_timeout`, `udp_nat_max` | `transport: udp`, `protocol: { type: tproxy, udp_timeout, udp_nat_max }` (slice 2) |
| `inbounds[].type: tun`, `interface_name`, `address`, `mtu`, `auto_route: false` | `- device_name`, `address`, `netmask`, `mtu`; routes stay the host's |
| `outbounds[].tag` | `name` on the `ClientConfig`; the key everywhere else |
| `outbounds[].type: vless`, `uuid`, `flow`, `tls.reality`, `tls.server_name` | `protocol: { type: reality, public_key, short_id, sni_hostname, protocol: { type: vless, user_id } }`; Vision from `flow` |
| `outbounds[].type: vless` with `tls` and no reality | `protocol: { type: tls, sni_hostname, protocol: { type: vless, ... } }` |
| `outbounds[].type: trojan`, `shadowsocks`, `socks`, `naive` | the same-named `protocol.type` |
| `outbounds[].type: hysteria2`, `obfs`, `server_ports`, `hop_interval` | `protocol: { type: hysteria2, password, obfs }`, `quic_settings: { sni_hostname }`, hopping per the hysteria2 spec |
| `outbounds[].type: mieru`, `transport: TCP` | `protocol: { type: mieru }`; `UDP` links are refused by the emitter |
| `outbounds[].transport.type: ws` / `httpupgrade` | `transport: { websocket: ... }` / `httpupgrade` |
| `outbounds[].transport.type: grpc` / `xhttp` / `http` | refused by the emitter; the link stays on sing-box |
| `outbounds[].tls.utls` | dropped (slice 5) |
| `outbounds[].bind_interface` | `bind_interface` on the `ClientConfig` |
| `outbounds[].type: direct`, `bind_interface`, `domain_resolver` | `direct` with `bind_interface`; the resolver is the rule's `dns` group |
| `outbounds[].type: selector`, `outbounds`, `default` | `client_group` with `mode: select`, `default` (Clash spec slice 2) |
| `outbounds[].type: urltest`, `url`, `interval`, `tolerance` | `client_group` with `mode: urltest` (Clash spec slice 3) |
| `endpoints[].type: awg` and its fields | `protocol: { type: amneziawg, ... }` per the AmneziaWG README examples |
| `route.rules[].{domain_suffix, domain, ip_cidr, port, ip_is_private}` | `masks` |
| `route.rules[].rule_set` | `rule_sets` naming a `- rule_set:` entry with a `path`; awg-manager downloads the `.srs` |
| `route.rules[].action: reject` | `action: block` |
| `route.rules[].action: sniff` | `sniff:` on the listener |
| `route.rules[].action: hijack-dns` | `hijack_dns: true` on the listener (slice 4) |
| `route.rules[].type: logical` | `all_of` / `any_of` (slice 3) |
| `route.rules[].source_ip_cidr` | `source_masks` (slice 3) |
| `route.final` | the last rule, `masks: 0.0.0.0/0` |
| `dns.servers[].{type: udp/tls/https, server, detour}` | `dns_group` with `dns_servers[].{url, client_chain}` |
| `dns.servers[].type: fakeip`, `inet4_range` | `fake_ip` on the TUN entry today; a server (slice 4) |
| `dns.rules[]` | `dns_rules` (slice 4) |
| `dns.rules[].action: predefined` | `dns_rules[].answer` (slice 4) |
| `experimental.clash_api.external_controller` | `clash_api: { listen }` |
| `experimental.cache_file` | `clash_api: { state_file }` |
| `log.level` | the `RUST_LOG`-style directive; `--log-file` |

Every row marked with a slice is refused by the emitter until that slice
ships, with the reason in awg-manager's UI, so a tunnel never silently runs
with less than it was configured for.

## RSS budget

Slice 2 adds per-session state for `tproxy`: one reply socket and the
router's existing session struct per live UDP flow, bounded by
`udp_nat_max`. At the default 4096 that is 4096 file descriptors, which is
above Entware's default `ulimit -n` of 1024 on some models; the listener
raises `RLIMIT_NOFILE` to the soft maximum at start and logs the figure it
got, and `udp_nat_max` is validated against it with a warning. Everything
else in slices 1 to 4 is per configured item. The measurement that matters
is the one this document opens with, repeated on the router after each
slice.

## Security notes

- **`redirect` and `tproxy` listeners trust the kernel.** They forward
  whatever arrives to wherever the kernel says it was going. Bound to
  loopback by default; a non-loopback bind is refused at validation, the
  same rule as the Clash API's, because a transparent listener reachable
  from the LAN is an open proxy to the original destination of any packet
  a host can craft.
- **`IP_TRANSPARENT` needs `CAP_NET_ADMIN`.** The listener reports the
  failure to set it as a startup error naming the capability rather than
  falling through to a socket that receives nothing.
- **`SIGHUP` is a control path** from anything that can signal the process.
  It reloads the same file the process was started with and nothing else;
  it cannot be made to read a different one.
- **Predefined DNS answers** (slice 4) are what a config says they are; a
  config that can be written by the panel can point a name anywhere, which
  is the panel's trust boundary, not shoes'.

## Testing

Slice 1 and 2 tests, at the level where a missing call is visible:

- **`SIGHUP`**: start the binary with a config, rewrite the config, send
  `SIGHUP`, assert the new listener is up within one second and the old one
  is gone; then the same with `--no-reload`.
- **`check`**: exit 0 on a valid file, exit 1 and the message on stderr for
  an invalid one; `version` prints the crate version.
- **`redirect`**: on Linux CI, a `redirect` listener and a loopback target
  with an `iptables -t nat -A OUTPUT -p tcp --dport <target> -j REDIRECT
  --to-ports <listener>` rule under `sudo`; a client connects to the target
  and reaches it through shoes; `/connections` shows the original
  destination. Without `sudo`, the unit test drives `original_destination`
  on a socket pair where the option is absent and asserts the refusal.
- **`tproxy`**: on Linux CI under `sudo`, the `ip rule`/`ip route local`
  pair and a mangle `TPROXY` rule; a UDP echo target; a client datagram
  reaches the echo and the reply arrives with the echo's address as source.
  The session cap and expiry are unit-tested on `UdpRouter` with a fake
  targeted stream.
- **Registry**: both inbounds appear in `/connections` with their labels
  and the original destination.
- **awg-manager**: the tproxy router mode on a Keenetic aarch64 with shoes
  as the engine, all three awg-manager health probes green (`/proc/net/tcp`
  LISTEN on 51272, `/proc/net/udp` on 51271, Clash `/version`), and the RSS
  table repeated.

## Order of work

1. Slice 1 (plan tasks 1–2). Then the awg-manager emitter for the
   legacy-tunnel mode, and the first router run: the RSS table and a
   Reality link, which is also slice 5's gate.
2. Slice 2 (plan tasks 3–6). Then the tproxy router mode under awg-manager.
3. Clash API slices 1–3 interleave here as awg-manager needs them: slice 1
   for health and logs is needed with the first router run; slices 2–3 for
   subscriptions.
4. Slice 3, then slice 4, each planned after the previous one has run.
5. Slice 5 only if its gate says so.
6. Slice 6.

## Decisions

| Question | Decision | Why |
|---|---|---|
| Swap or second engine | Second engine, opt-in per mode | The gap table has six slices; the legacy mode works with one |
| Config translation | awg-manager emits shoes YAML from its model | It already parses every link format itself; a Clash importer in shoes was rejected on 2026-09-09 |
| Where redirect reads the destination | A default method on `AsyncStream`, implemented on `TcpStream` | The handler only sees `dyn AsyncStream`; the accept loop has the socket |
| tproxy UDP model | `AsyncTargetedMessageStream` into the existing `UdpRouter` | The router already does per-destination sessions, routing and expiry |
| Reply spoofing | One `IP_TRANSPARENT` socket per session | The only portable way; bounded by `udp_nat_max` |
| Logical rules syntax | `all_of` / `any_of` | Reads as what it is; `masks` stays `any_of` |
| `.srs` encoder | In shoes, behind sing-box's subcommand names | awg-manager shells out with those arguments today |
| Chrome ClientHello | Gated on a live DPI test | The cost is large and the need is unmeasured |
| MIPS | Last | Toolchain project; the user's ordering |
| `SIGHUP` debounce | None | The sender finished writing |

## Deliberately out of scope

- **`xhttp`, gRPC, h2 transports; Hysteria2 `brutal` and ECH; mieru over
  UDP.** Links carrying them stay on sing-box, and the emitter says so.
- **`source_mac_address`.** A router matches MACs in its firewall, which is
  where awg-manager already does it.
- **Remote rule-set download and `update_interval`.** awg-manager already
  downloads `.dat` and can download `.srs`; shoes reads files.
- **`GOMEMLIMIT`-style memory caps.** There is no runtime to cap.
- **A shoes emitter in this repository.** It is awg-manager code, written
  against the mapping table above.
- **The two tun modes' NDMS plumbing.** awg-manager's, unchanged.
