# The TUN server honours its `dns:` config

2026-08-31. Status: agreed; scope fixed by the requester.

## The gap

A TUN entry's `dns:` block parses, validates, and has its resolvers built —
and the TUN datapath then uses the system resolver anyway:

- `control::run_prepared` builds the `DnsRegistry` and consults it only for
  the TCP/QUIC listeners; the TUN branch calls `run_tun_from_config` without
  a resolver.
- `tun::start_tun_server(config, _resolver)` takes a resolver — chosen
  correctly by the standalone binary's `launch_servers`, which already maps
  `Config::TunServer(t) => t.dns.as_ref()` — and discards it.
- `run_tun_from_config` hardcodes `Arc::new(NativeResolver::new())`.

KVN (the first mobile consumer) ships a DoH block
(`url: "https://1.1.1.1/dns-query"`) believing it stops the proxy hostname
from leaking over plaintext UDP:53. It does nothing today. For
WireGuard/AmneziaWG chains the endpoint hostname is also re-resolved on the
network-change rebind and on connector rebuilds, so the leak repeats
mid-session.

## The fix

Thread the resolver instead of building one in place:

- `run_tun_from_config` gains a `resolver: Arc<dyn Resolver>` parameter and
  loses the `NativeResolver::new()` line. Everything downstream is already
  parameterized: the selector via `create_tcp_client_proxy_selector`, the
  chain's `connect_tcp`, the UDP manager's `create_connection`, and the
  AWG connector's endpoint (re-)resolution all take the resolver
  `run_tun_server` receives.
- `control::run_prepared` selects
  `dns_registry.get_for_tun(tun_config.dns.as_ref())` and passes it.
  Absent `dns:`, `get_for_tun(None)` answers a fresh uncached
  `NativeResolver` — the pre-`dns:` TUN behaviour. The registry's caching
  default is deliberately NOT used here: its flat one-hour cache would pin
  a WireGuard/AmneziaWG endpoint to a dead address across rebuild failover.
- `start_tun_server` passes its (already-correct) resolver through instead
  of discarding it.

No FFI surface change: `dns:` rides inside the config YAML.

## Constraint 1: DNS upstream sockets and the socket protector

**Already satisfied structurally, verified in source.** Every hickory
resolver variant (`udp`, `tcp`, `tls`, `https`, `quic`/h3) is built on
`ProxyRuntimeProvider` (`src/dns/hickory_resolver.rs`), whose three socket
paths all protect:

- `bind_udp`: `socket_util::new_udp_socket` (protects) or a direct bind
  followed by `protect_outbound` (`src/dns/proxy_runtime.rs:151-158`).
- `connect_tcp` (also carries TLS and DoH): routed through
  `chain_group.connect_tcp`, i.e. the same `socket_util` constructors every
  proxied connection uses.
- `bind_quic`: both branches call `protect_outbound`
  (`src/dns/proxy_runtime.rs:211`).

hickory opens no sockets of its own outside the `RuntimeProvider` /
`QuicSocketBinder` seams. A regression test pins the UDP path: a counting
protector installed for the test observes the DNS socket pass through it.

## Constraint 2: no silent system-resolver fallback in TUN mode

`https://1.1.1.1/dns-query` needs no resolution before use and keeps
working with no bootstrap. A **hostname** URL, by contrast, is resolved via
the entry's `bootstrap_resolver`, which without `bootstrap_url` is the
system resolver — exactly the silent fallback the block exists to prevent,
and in TUN mode a plaintext leak dressed as DoH.

Validation therefore rejects, for any dns group a TUN entry references
(transitively through `bootstrap_url` group references): a spec whose URL
carries a hostname and no `bootstrap_url`. The message names both fixes
(IP-address URL, or `bootstrap_url`). `url: system` stays allowed — it is
the status quo made explicit, not a silent fallback. Non-TUN servers keep
today's behaviour: the system-bootstrap default is a documented convenience
there.

## Tests

1. End-to-end through the registry: a TUN config with
   `dns: { servers: [udp://127.0.0.1:<mock>] }` run through
   `create_server_configs` → `build_dns_registry` → `get_for_tun`
   resolves a client-chain hostname through the mock (which records the
   query and answers a canned A record) and the connection reaches the
   answered address. A small in-test UDP DNS responder; no such mock existed.
2. Without `dns:`: `get_for_tun(None)` yields a fresh uncached resolver, and
   the existing TUN datapath tests (which inject their own resolver) keep
   passing unchanged.
3. Validation: a hostname-URL DoH server without bootstrap in a TUN config
   fails `create_server_configs` with the message naming the fix; the same
   group on a plain server config still validates.
4. Protection: a counting `SocketProtector` sees the DNS upstream socket on
   the `bind_udp` path.

## Docs

- CONFIG.md: the TUN section gains the `dns:` block — previously
  undocumented there — with the socket-protection behaviour and the
  IP-URL-for-TUN recommendation.
- CHANGELOG (Unreleased): behaviour change only for configs already
  carrying `dns:` on a TUN entry (previously ignored); said explicitly.
