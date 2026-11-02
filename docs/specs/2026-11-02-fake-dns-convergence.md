# One fake DNS mechanism, for the TUN and every listener

**Status:** specified 2026-11-02, not yet built. Supersedes the phase split in
`docs/plans/2026-11-02-fake-dns.md`, whose phase 2 (fake IP on listeners,
PR #152) this builds on; that plan's open items become the phases below.

## Sources

- sing-box, the reference the TUN's fake IP was built against in September:
  `dns/transport/fakeip` (the server type `fakeip` with `inet4_range` and
  `inet6_range`, 1.12 and later), and `experimental.cache_file` with
  `store_fakeip`, which keeps mappings across restarts. Its documentation gives
  `198.18.0.0/15` as the IPv4 example range.
- cfal/shoes, the upstream this repository forked from, whose Fake DNS landed
  in its #195 and later (`docs/src/content/docs/dns/fake.md` is its spec of
  record; `src/dns/fake_ip/{options,pool,responder,persistence}.rs` the
  implementation). Its behaviour is taken as the specification where this
  document says so; its code is not ported, for the reasons the plan gives
  (an ingress refactor, a raw-wire resolver trait and a hickory fork that this
  tree does not have).
- This tree: `src/dns/fake_ip/` (pool, responder, bypass, DNS over TCP), the
  TUN's wiring in `src/tun/mod.rs` and `src/tun/udp_manager.rs`, and PR #152's
  listener wiring in `src/tcp/tcp_forward.rs`, `src/routing/udp_router.rs`,
  `src/h2mux/h2mux_server_session.rs` and `src/dns/builder.rs`.

## Problem

Fake IP exists twice. The TUN has had it since September under its own
`fake_ip` key; PR #152 gives SOCKS, HTTP, mixed and tproxy listeners the same
thing under `dns:`. The two share the pool and responder code but not the
wiring, and the wiring is where the defects are:

- Restoration (a fake address back into its name) is done per protocol: in
  `forward_tcp`, in the UDP router, in h2mux, and on the TUN in two places.
  AnyTLS and NaiveProxy judge their destinations themselves and were missed,
  so a client of theirs is handed a fake address over UDP and then dials it
  as a literal (review of #152, finding 1). Every future protocol would have
  to remember the same hook.
- A group's `fake_ip` is lost when the group is reached through composition
  (a list with more than one entry, or a group listing the group), with
  nothing said (finding 2).
- The responder answers IPv4 only and forwards HTTPS/SVCB records whole, so a
  browser that gets an `ipv4hint` connects to a real address and skips the
  hostname route the feature exists for.
- Nothing checks that the fake range overlaps nothing real: the TUN's own
  address, a proxy's literal address, a DNS upstream, a rule's
  `override_address`.
- A pool dies with its process. On Android the engine is stopped and started
  on every network handover (KVN's controller, `EngineEvent.NetworkChanged`),
  so every address an app has cached becomes an unmapped one, refused until
  the app resolves again.
- Forwarded queries go to the resolver the app addressed, through the rules.
  An app that points at a public resolver and asks for a record the pool does
  not answer gets that query sent wherever the rules send the resolver's
  address, which with a direct rule for it is the ISP's view of the question.

KVN does not turn fake IP on yet; it will once it is one mechanism it can
trust on a phone. This document says what that mechanism is.

## Scope

One fake DNS context type, owned by the DNS registry, used identically by the
TUN and every listener; one restoration site; a responder that handles both
address families, HTTPS/SVCB and the TTL by configuration; validation that
refuses overlaps and silent no-ops; forwarding through the configured
resolver; and mappings that survive an engine restart in the same process.
Delivered in four PRs, in the order under "Delivery".

Out of scope is listed at the end.

## What the references do

### sing-box

- A DNS server of type `fakeip` with `inet4_range` and `inet6_range`; a name
  gets one address per configured family, allocated in sequence from the
  range. Answers carry a TTL of one second, so a client comes back often and
  the mapping stays fresh.
- Routing restores the name before rules run; `sniff` can override it for
  domain rules.
- `experimental.cache_file.store_fakeip: true` writes the mappings to the
  cache database so a restart hands the same addresses back. This is the
  setting every mobile deployment turns on, because apps cache answers past
  any TTL and a restart otherwise strands them.

### cfal/shoes (upstream)

From `docs/src/content/docs/dns/fake.md`:

- Interception "on port 53 after inbound authentication/admission, before
  destination rules", on TCP and UDP, for every inbound including TUN and
  WireGuard. Intercepted DNS is "answered locally or forwarded through
  `dns.servers`, never to the application's requested resolver".
- One pool per named DNS group, shared by every inbound naming it; an inline
  `fake_ip` is a private context. "Combining fake-enabled groups requires an
  explicit policy on the composed group."
- Options and defaults: `ipv4_range: 198.18.0.0/15`, `ipv6_range: null`,
  `max_entries: 65536`, `bypass_domains: []`, `missing_family: forward`,
  `https_records: forward`, `state_file: null`. Base and base+1 of a range
  are reserved. Synthetic answers have a 60-second TTL, "not a guarantee that
  a mapping remains valid for 60 seconds under pressure".
- Overlap rules: real upstreams, bootstraps, proxies, forwarding targets and
  literal rule overrides "cannot be inside any active or retained fake range",
  checked "even to inbounds without Fake DNS"; TUN interface and gateway
  addresses cannot overlap a pool.
- `missing_family: forward` sends a query for a family that has no range to
  the upstream; `nodata` answers it empty. `https_records: suppress` answers
  HTTPS and SVCB with an empty success, trading ECH and the HTTP/3 hint for
  hostname routing that holds.
- Unmapped addresses in a context's own range fail closed; addresses from
  another context's range are routed as ordinary IPs.
- Persistence with a state file, atomic replacement, a lock file, owner
  identity derived from the listener's transport and addresses or the TUN's
  device name, and reload retention.

### This tree today

- `src/dns/fake_ip/pool.rs`: an IPv4 `FakeIpNetwork` (prefix 8 to 30), an LRU
  pool capped at `max_entries` (8192 by default, chosen for the iOS
  extension's memory), and `MIN_REUSE_AGE` of ten minutes: an address used
  more recently than that is never handed to another name, and when nothing
  can be recycled the query gets the real answer (SF-1). Upstream has no such
  guard; its 60-second TTL carries the risk instead.
- `src/dns/fake_ip/responder.rs`: answers single-question `A` queries with a
  1-second TTL, answers `AAAA` with NODATA, forwards every other type and
  every bypassed name. `src/dns/fake_ip/bypass.rs`: glob patterns and the
  local-name defaults (`*.local`, `*.lan`, `home.arpa`, single labels, the
  reverse zones), which upstream lacks.
- The TUN: `syn_refusal` resets a SYN to an unmapped fake address at the
  stack (`src/tun/mod.rs`), `destination_to_net_location` restores before
  judging, DNS over UDP is answered in `udp_manager.rs` with the reply from
  the address the client sent to, DNS over TCP by `dns/fake_ip/tcp.rs`.
- PR #152: `Resolver::fake_ip()` and a `FakeIpResolver` wrapper the registry
  hands out, restoration in `forward_tcp`, the router (`route_to`,
  `reply_as`, local answers) and h2mux, a one-destination UDP adapter so
  VLESS UDP goes through the router, refusals for the TUN's `dns:` block and
  QUIC listeners.

## Design

### One context, owned by the registry

`FakeDnsContext` (the present `FakeIpResponder`, renamed where it is touched,
no mass rename) holds the pool, the bypass list and the policy options. The
registry builds one per named group with `fake_ip`, and one per inline
`fake_ip` under the generated group name `extract_inline_dns` already
assigns, so the identity of a private pool is the listener's config, not the
number of times the resolver was asked for. `get_for_server` and
`get_for_tun` wrap the group's resolver in `FakeIpResolver` when the group,
named or generated, has a context. The TUN's top-level `fake_ip` is moved
onto its `dns:` block at validation and documented as an alias of it; the
refusal of a `fake_ip` on a TUN's `dns:` block goes away with the reason for
it. A TUN naming a group shares the group's pool with the listeners naming
it, which the plan wanted and upstream has.

Composition is refused, not silently dropped: a `dns:` list with more than
one entry that names a fake-enabled group, and a group whose `dns_servers`
lists one, fail validation with a message naming the group and the shape.
Upstream asks for an explicit policy on the composed group; we have no use
for one yet, and refusing is what the project rule for an unimplemented
option says.

### One restoration site

`ClientProxySelector::judge` already receives the listener's resolver. It
becomes the place where a fake address turns into its name:

1. If `resolver.fake_ip()` is `Some` and the location is an IP literal
   (an IPv4-mapped IPv6 literal read as its IPv4, as `restore_location`
   does), look it up in the context's pool.
2. Mapped: replace the location with the name at the same port and go on to
   the cache and the rules as for any hostname. Unmapped: return
   `ConnectDecision::Block` and count it (`UNMAPPED_REFUSED`), which every
   caller already turns into its protocol's refusal.
3. Not fake: unchanged.

The per-protocol restore calls in `forward_tcp` and h2mux are removed. What
stays outside `judge` is what `judge` cannot know: the reply source for UDP
(the router restores too, once per flow as its session is made, to label
replies with the fake address and to drop an unmapped datagram before a
session is created; a live flow marks its mapping used once a minute
rather than per datagram; the TUN UDP manager swaps the source), and
port-53 interception, which must run before any judging and so refuses a
query to an unmapped fake address itself (forward_tcp, h2mux TCP, the
router). AnyTLS,
NaiveProxy, Hysteria2 and TUIC TCP streams get restoration through this
without a change of their own. The QUIC refusal in validation stays until a
test shows their UDP relays label replies with the fake address; it is
narrowed to the UDP side when they do.

`judge`'s cache is keyed by the restored location, so a name is cached once
whether it arrived as itself or as a fake address, and a fake address is
never cached as a literal.

### The responder

- `ipv6_network` (optional, a ULA range such as `fd00:fa1e::/64`): when set,
  a name gets one address per family, allocated together under one pool entry
  so the LRU and the reuse guard see one mapping. `restore` takes either
  family. A range inside `::ffff:0:0/96` is refused.
- `missing_family: nodata | forward`, default `nodata`: with no IPv6 range an
  `AAAA` query is answered empty, as today, so the client falls back to `A`
  and the tunnel is never asked to carry IPv6 it may not have. Upstream's
  default is `forward`; on a phone a forwarded `AAAA` hands the app a real
  address it then connects to around the hostname route.
- `https_records: suppress | forward`, default `suppress`: HTTPS and SVCB
  are answered with an empty success. This is the plan's decision and the
  reverse of upstream's default, for the reason the plan gives: hostname
  routing holding matters more than ECH and the HTTP/3 hint.
- `ttl_secs`, default 1. Raising it cuts query volume; it does not weaken the
  reuse guard, which protects a mapping by use, not by TTL.
- Counters beside `UNMAPPED_REFUSED`: answered, forwarded, bypassed,
  suppressed. The validation message that still says DNS "arrives over UDP"
  is corrected.

### Validation

A fake range (either family) must not contain: the TUN's own address and
netmask, any literal client-chain hop address in any chain group, any DNS
upstream or bootstrap literal, any rule `override_address` literal, nor any
other context's range in the same configuration. Checked for every context,
with the offending item named. Upstream checks these against inbounds without
fake DNS too; we check only configurations that have a context, since an
address inside `198.18.0.0/15` with no pool anywhere is reachable.

### Forwarding through the configured resolver

A query the responder does not answer (a type it forwards, a bypassed name,
`missing_family: forward`, a pool with nothing to recycle) goes through the
listener's `dns.servers` when they are configured, and to the resolver the
app addressed only when they are not. This is upstream's rule and the leak
the plan's phase 3 names. It needs a raw-message exchange on `Resolver`:
`exchange(&[u8]) -> ResolveFuture<Vec<u8>>`, which hickory provides for the
groups we build (`DnsExchangeFuture` already exists in `resolver.rs` for the
bootstrap path), and which the native and system resolvers do not implement,
in which case the query goes to the addressed server as today. Answers that
come back through the configured resolver pass the same guard
`FakeIpResolver::resolve_location` applies: an address inside any fake range
is dropped from the answer.

### Surviving an engine restart

The mobile FFI stops and starts the engine in one process on every network
handover. A pool that dies with the engine refuses every cached address
afterwards. The context registry keeps a pool for a short time after its
engine stops, keyed by the context's identity (the group name, or the
generated inline name plus the listener's bind addresses, or the TUN's device
name) and its configuration (both ranges, `max_entries`); the next start with
the same key takes it over instead of allocating a new one. The retention
window is `MIN_REUSE_AGE`, ten minutes: beyond it the apps' caches have
expired anyway and nothing is owed. Memory held meanwhile is the pool's,
bounded by `max_entries`. A changed range or capacity is a new key and an
empty pool. This is what `store_fakeip` buys on sing-box for the one case
that matters on a phone, without a file, a lock or an owner check. A state
file for cold restarts is out of scope until a measurement shows a handover
loses mappings in practice; the counter above is how that is measured.

## Configuration

```yaml
dns:
  servers: string | [DnsServerSpec]   # optional; omitted = the default resolver
  fake_ip:                             # optional; on a dns_group too
    network: "198.18.0.0/16"           # IPv4 range, as today
    ipv6_network: string?              # a ULA range; unset = no IPv6 answers
    max_entries: 8192
    bypass_domains: [string]
    bypass_defaults: true
    missing_family: nodata             # or forward
    https_records: suppress            # or forward
    ttl_secs: 1
```

The TUN's top-level `fake_ip` is accepted as an alias and moved onto its
`dns:` block. A `dns:` block may omit `servers` to set only `fake_ip`.
Refused: a fake-enabled group named inside a list of more than one server or
inside another group's `dns_servers`; a range overlapping anything listed
under "Validation"; `fake_ip` on a QUIC listener until its UDP relays are
shown to reply from the fake address, and on listeners carrying AnyTLS or
NaiveProxy at any depth (TLS, Reality, WebSocket around them) until their
own stream handling answers port 53; a `dns:` block
with neither servers nor `fake_ip`; `ipv6_network` inside the IPv4-mapped
range; `ttl_secs: 0`.

## Error handling

- An unmapped fake address: `ConnectDecision::Block`, counted, refused by
  the protocol's own means (the inbound's blocked reply on SOCKS, a TUN
  reset, a dropped datagram). Never dialled.
- A real answer inside a fake range: dropped from the answer; an answer with
  nothing left is an error naming the name.
- A forwarded query whose configured resolver fails: the error reaches the
  client as SERVFAIL where the protocol can carry it (the responder builds
  it), else the query is dropped and the client retries.
- A bad range, overlap or composition: a startup error naming the owner and
  the item, as `validate_fake_ip_config` does today.
- Nothing from a query enters a log above debug: names are the user's.

## Testing

Each test is watched failing with its defect planted back, as the project
rule says.

- Choke point: a fake address reaching `judge` from a path with no restore
  hook of its own (AnyTLS, NaiveProxy, Hysteria2 TCP) comes out as the name;
  an unmapped one is `Block` and counted; the cache holds the name, not the
  address.
- Registry: an inline context is the same object on a second
  `get_for_server`; a group's context is shared by a TUN and a listener
  naming it; composition shapes are refused with the group named.
- Responder: `A` and `AAAA` with and without `ipv6_network`, `missing_family`
  both ways, `https_records` both ways, the TTL on the wire, the counters.
- Validation: each overlap kind refused with the item named; an IPv4-mapped
  v6 range refused.
- Forwarding: a TXT query over a listener with `dns.servers` reaches the
  configured resolver double, not the addressed server; without `dns.servers`
  it reaches the addressed server; a configured answer inside the fake range
  is dropped.
- Restart survival: stop and start a TUN session with the same config in one
  process, a cached fake address still restores; with a changed range it is
  refused; after the retention window it is refused.
- Live: the SOCKS listener with a browser doing its own DNS, and the TUN on
  the Android emulator through a network handover, recorded in words.

## Delivery

1. **A: one mechanism.** The registry owns inline contexts; the TUN's key
   becomes an alias; composition refused; restoration moves into `judge`;
   per-protocol hooks removed. Landed in #152 itself, with that PR's review
   findings; the counters moved to B.
2. **B: the responder.** `ipv6_network`, `missing_family`, `https_records`,
   `ttl_secs`, overlap validation, the message fix, the counters (answered,
   forwarded, bypassed beside `UNMAPPED_REFUSED`).
3. **C: forwarding through `dns.servers`.** `Resolver::exchange`, the guard
   on configured answers.
4. **D: restart survival.** The retained-pool registry, measured on the
   Android emulator handover before and after.

## Out of scope

A state file for cold restarts (measure first); `global_settings.default_dns`;
a standalone DNS listener; a WireGuard server inbound (none here); sniffed
names overriding a restored name for IP rules (upstream's rule; ours keeps
the restored name as the target and lets `sniff` inform hostname rules as it
does today); DNSSEC on synthetic answers (unsigned, as upstream's).
