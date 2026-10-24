# The daemon carries IPv6

`shoesd` installed `::/1` and `8000::/1` as reject routes for the life of a
session and refused IPv6 in `Start.exclude` and `Start.dns`: v1's leak guard,
failing v6 fast so Happy Eyeballs fell back to v4. This change carries v6 on
Linux and macOS instead, and says so in `Hello`, so a client can choose its
config shape per session.

Written 2026-10-24 against `mobile` at `f6e925e` (v0.8.0 + 1). The consuming
client's requirements are KVN's `docs/shoes-agent-prompt-ipv6-desktop.md`
and its design `docs/superpowers/specs/2026-10-24-desktop-ipv6-design.md`.

## Problem

A v6-only destination is unreachable through the desktop tunnel, and every
dual-stack destination costs a Happy Eyeballs fallback. The reject was the
right v1 answer -- leaking v6 to the physical interface is the one thing a
VPN must not do -- but it is not the end state, and the engine already
forwards v6: `stack_common.rs` registers `::1/0` and a v6 default route on
the smoltcp interface. What stood between v6 and the proxy was the host
configuration this daemon owns.

## Scope

Linux and macOS. Windows keeps the rejects: wintun's configuration path
cannot express an IPv6 address (`src/tun/mod.rs`), and a route via a device
with no v6 source is worse than a reject. The proxy's own address stays
IPv4 on every arm (below). No change to `TunConfig`, the FFI or the mobile
builds; no change to the `v1` protocol package.

## What changes

1. **`host::carries_ipv6()`** -- `cfg!(any(linux, macos))` -- is the one
   answer, read by the supervisor when it builds the `Plan` and by
   `service::capabilities` when it answers `Hello`. One function, so a
   session whose `Hello` promised v6 while its routes rejected it cannot
   exist.
2. **A ULA on the device**, `fd00:6b76:6e00::2/64` (`kvn` in hex, so a
   capture names its owner), added by the host arm -- `ip address add … dev`
   on Linux, `ifconfig utunN inet6 … prefixlen 64 alias` on macOS -- after
   the exclusions and before any tunnel route. The order matters: a v6 route
   via a device with no v6 address is accepted by the kernel but has no
   source to send from, and the host would pick the physical interface's
   global address. The address is host policy, like the routes, not a
   `TunConfig` field: it is recorded in `AppliedState` (`addresses`, which
   older records load as empty) and removed on revert **after** the routes,
   with "not there" -- the device is gone -- treated as success.
3. **`tunnel_routes`** routes the v6 halves via the device where
   `carry_ipv6`, rejects where not.
4. **`Start.dns`** takes a v6 resolver on a carrying arm; **`Start.exclude`**
   refuses v6 everywhere, with the reason: the exclusion route goes through
   the default gateway, and `default_gateway()` reads the IPv4 table
   (`ip route show default`, `netstat -rn -f inet`). A v6 proxy address would
   be blackholed and the session would come up with a proxy it cannot reach.
   Lifting this means reading the v6 table too; it is recorded, not done.
5. **`Hello.capabilities`** gains `"ipv6"` on a carrying arm.

## Error handling

A failed address add reverts the exclusions already installed and never
reaches the tunnel routes (`an_address_failure_undoes_the_exclusion_and_stops`).
`AlreadyExists` on the address means the device already had it -- not ours,
not recorded, as for a route. Revert continues past a failed address removal
and reports it with the rest.

## Testing

`plan.rs`: the carrying order as a whole sequence; revert removes the address
last; an address failure undoes the exclusion. `state.rs`: a record with
addresses round-trips; one without loads. `linux/routes.rs` and
`macos/mod.rs`: the argv of the address commands and the matchers for "not
there" and "already there". `service.rs`: the capability matches
`carries_ipv6()`; `exclude` refused on every arm; `dns` refused only where
not carried, over the real transport. Live, by KVN on its Linux host:
`curl -6` exits through the VPS's v6 address with the tunnel up; both route
tables byte-identical after stop; `kill -9` leaves no v6 route behind.

## Out of scope

A v6 proxy address. Windows carrying v6. Changing the v4 address, which
stays the engine's own `10.0.0.2` through `TunConfig`.
