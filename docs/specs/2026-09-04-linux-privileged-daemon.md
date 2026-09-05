# The Linux privileged daemon

The Linux arm of `shoesd`: a `HostNetwork` implementation over `ip` and
systemd-resolved, a netlink route monitor, a systemd install path, and the four
small ungatings that let the binary build off macOS at all.

Written 2026-09-04 against `mobile` at `40291cc` (v0.3.0). Sibling of
[docs/specs/2026-09-04-macos-privileged-daemon.md](./2026-09-04-macos-privileged-daemon.md),
and everything that spec decided still stands unless this one says otherwise.
The consumer's requirements are in KVN's
`docs/shoes-agent-prompt-linux-daemon.md`, and KVN's own side is designed in
`docs/superpowers/specs/2026-09-04-linux-daemon-engine-design.md`; where either
said "decide", the choice is recorded in
[Decisions](#decisions-the-brief-left-open).

Unlike the macOS milestone, this one runs on the author's own machine. Several
things the macOS spec had to defer to a live run are therefore settled here as
measurements, and they are marked as such — see
[Measured on the development host](#measured-on-the-development-host).

## Table of Contents

- [Problem](#problem)
- [Scope](#scope)
- [What is already done](#what-is-already-done)
- [Ungating](#ungating)
- [The trait change](#the-trait-change)
- [Routes](#routes)
- [DNS](#dns)
- [The routing-domain contest](#the-routing-domain-contest)
- [Route monitor](#route-monitor)
- [Crash recovery](#crash-recovery)
- [Install](#install)
- [Buffer sizing](#buffer-sizing)
- [Measured on the development host](#measured-on-the-development-host)
- [Testing](#testing)
- [Release artifacts](#release-artifacts)
- [Order of work](#order-of-work)
- [Decisions the brief left open](#decisions-the-brief-left-open)
- [Deliberately out of scope](#deliberately-out-of-scope)

## Problem

`shoesd` exists and refuses to build anywhere but macOS, by an explicit
`compile_error!` at `src/bin/shoesd/main.rs:22`. The macOS spec's "Deliberately
out of scope" says why: Linux has four resolver mechanisms and deserves its own
spec. This is that spec.

It is also the milestone that first makes the daemon *runnable by its author*.
The macOS spec's step 8 — the live verification — is unchecked: no route, no
DNS write and no service-manager call in `src/bin/shoesd/` has ever executed on
any platform. That is the strongest argument for doing Linux next, and it is
why this spec's verification section is longer than its macOS sibling's rather
than shorter.

## Scope

- **Four ungatings** so the binary compiles on Linux.
- **One trait change**: `primary_dns_service` takes the tunnel interface.
- **`src/bin/shoesd/host/linux/`** — routes over `ip`, DNS over two backends
  chosen by probe, and a netlink route monitor.
- **A Linux arm in `install.rs`** — a systemd unit, group detection, SELinux
  relabelling.
- **Two release artifacts** and the documentation naming them.

Nothing under `src/` changes, and that is a claim with a residual risk rather
than a guarantee. `create_sync_device`'s Linux arm applies all five fields, and
the three ioctls it issues were confirmed against a real `IFF_TUN` device — but
what has *not* run is that path inside shoes, alongside the crate's own
`ensure_root_privileges(true)` and `up()`. If the first live bring-up needs a
`src/` change, that is a finding to report rather than one to make quietly.

Out of scope is listed at the end. The three largest omissions come from the
consumer and are unchanged from macOS: no kill switch, no split tunnelling, no
IPv6 inside the tunnel.

## What is already done

Verified by reading `mobile` at `40291cc`, because a brief that says "nothing
needs to change here" is worth confirming before trusting.

**The portable spine is portable.** `host/plan.rs`, `host/state.rs`,
`supervisor.rs`, `service.rs`, `auth.rs` and `socket.rs` need no Linux arm. The
apply/revert ordering, the record, the session state machine, the gRPC surface
and the peer-credential check are already OS-agnostic: `auth.rs` is `getgrnam`
/ `getgrouplist` / `getpwuid_r`, `socket.rs` is `chown`, and `utun` appears in
`plan.rs` and `supervisor.rs` only in comments and test string data — never in
a branch. `device_policy()` (`supervisor.rs:35`) has no platform branch and
needs none.

**Device creation is already done**, and this is the reason the milestone is
smaller than its sibling. `create_sync_device` (`src/tun/tun_server.rs:266`)
applies `tun_name`, `address`, `netmask`, `destination` and `up()` under
`cfg(target_os = "linux")`, and `validate_tun_config` already has a Linux arm.
That arm predates the macOS one.

**Two exceptions in `auth.rs`**, which the brief and this spec's first draft
both said needed nothing. Both were found by building, not by reading, and the
second contradicts "the peer-credential check is already OS-agnostic" outright.

*The test asserts a Darwin gid.* Ungating makes `cargo test --features daemon`
run `auth.rs`'s tests on Linux for the first time, and `a_known_group_resolves`
asserts that `wheel` resolves to **gid 0**. That is a Darwin fact: on Fedora 44
`getent group wheel` reports gid **10**. Asserting a constant tested the host
rather than the lookup; the expected value now comes from an
independent `getgrnam` call, which is where a user's would come from too. The
doc comment on `groups_of` carried the same mistake in prose — "gid 0 is
`wheel`" — and now names both platforms. The security reasoning there is
unaffected: the hole it describes is `getgrouplist` echoing a fixed `basegid`
back, which is true whatever gid the admin group has.

*`getgrouplist` has a different signature.* Darwin declares the base gid and
the array it fills as `c_int`; glibc declares both as `gid_t`, which is
unsigned. Same values, pure signedness, and a hard `E0308` at the call site —
`expected u32, found i32`, and `expected *mut u32, found *mut i32`. It cannot
be cast away, because the array crosses as a raw pointer and a mismatch would
have `getgrouplist` writing `u32`s into an `i32` buffer. A `GroupListGid` alias
carries the difference so the surrounding code stays one path. `ngroups` is
`*mut c_int` on both and does not move.

That is the honest correction to "the portable spine is portable": it is,
except where `libc` disagrees with itself, and the only way to find those is to
compile.

## Ungating

Four edits, and one consequence worth stating.

- **`src/bin/shoesd/main.rs:22`** — the `compile_error!`. Its text keeps saying
  what it says, for Windows.
- **`src/bin/shoesd/service.rs:52`** — `capabilities()` returns `[]` off macOS.
  Linux returns `["routes", "dns"]`.
- **`Cargo.toml:192`** — `[target.'cfg(target_os = "macos")'.dependencies]`
  holds `tonic`, `tonic-prost`, `prost`, `tokio-stream` and `serde_json`, all
  portable and merely mis-gated, alongside `system-configuration` and
  `core-foundation`, which are not. Split into a `cfg(any(target_os = "macos",
  target_os = "linux"))` section for the first five and a macOS-only section for
  the last two. Same for the `dev-dependencies` at `:214` and its `tower`.
- **The `daemon` feature's doc comment** (`Cargo.toml:65-87`), which says
  macOS-only in three places.

  This spec first said the feature's `dep:system-configuration` /
  `dep:core-foundation` entries "must become optional per-target rather than
  unconditional members". **That was wrong**, and building proved it: naming a
  target-specific optional dependency from a portable feature is simply a no-op
  off that target. The entries are unchanged, and now carry a comment saying so
  — it is exactly the kind of line a later reader would otherwise "fix".

The consequence: `capabilities()` is currently `cfg!(target_os = "macos")`
inside a function, not a `#[cfg]` on the item, so a third arm is a third branch
rather than a third copy.

**Reporting the DNS backend.** The brief offered `"dns-backend:systemd-resolved"`
against `"dns-backend:resolv.conf"` as an optional extra capability, and it is
taken. `capabilities` is a repeated string and unknown values are ignored, so it
costs no proto change and KVN will not branch on it — but which backend was
selected is the first question any Linux DNS bug report needs answered, and the
alternative is asking the reporter to find a log line. The value is computed
once, at the same moment the probe runs, and reported thereafter.

## The trait change

`HostNetwork::primary_dns_service(&self)` takes no arguments because on macOS
the answer is the primary *physical* service: you override its resolvers and
restore them later. `apply_dns` calls it that way at `host/plan.rs:215`.

Bending Linux into that shape means writing our resolvers onto `eno1`, where
NetworkManager clobbers them on the next DHCP renew — reintroducing exactly the
contention the macOS arm needed a watchdog for, on a platform that does not
otherwise have it. So:

```rust
fn primary_dns_service(&self, interface: &str) -> std::io::Result<String>;
```

The macOS arm ignores the argument. The call site already has `plan.interface`
in hand, so this much *is* one line in the trait and one at the call site. The
Linux resolved backend returns the tunnel link name; the direct backend returns
a sentinel naming the file, so that `DnsBackup::service` stays meaningful in the
record for both.

**A second change, which this spec originally missed.** The direct backend has
to record the symlink target — see below — and `read_dns` returned a bare
`Vec<IpAddr>`, so there was nowhere for it to go. The two DNS methods therefore
carry a `DnsState` rather than a resolver list:

```rust
fn read_dns(&self, service: &str) -> std::io::Result<DnsState>;
fn write_dns(&self, service: &str, state: &DnsState) -> std::io::Result<()>;
```

`DnsState` is `{ servers: Vec<IpAddr>, symlink_target: Option<PathBuf> }`, and
`DnsState::servers(&[..])` is the constructor for the *apply* direction, which
by definition has no restore information. `DnsBackup` holds one, `#[serde(flatten)]`ed,
so the record on disk stays `{ service, servers }` exactly as before rather than
growing a nested object — which matters because `AppliedState::load` reports a
parse failure rather than ignoring one.

The alternative was encoding the target into the `service` string, which is
already persisted and already round-trips to `write_dns`. It was rejected: the
field is documented as a service id, it appears in log lines and error
messages, and an overloaded string is exactly the kind of thing that reads fine
and breaks silently later.

**And one clause.** `write_dns` gains the rule `delete_route`'s doc comment
already states: **a target that is not there is success.** Revert runs after the
link is gone, and a `write_dns` that returned an error there would abort the
revert partway — which is the failure `delete_route`'s rule exists to prevent,
arriving through the other door.

That is not hypothetical. `resolvectl revert` on an absent link exits 1 with
`Failed to resolve interface "nosuchlink0": No such device` (measured). Matched
on the message, as `is_absent_route` already does on macOS, because the exit
status is 1 for every failure alike.

The clause is narrow, and deliberately so: only "the link is gone" is success.
A D-Bus refusal, a missing `resolvectl`, a permission error — all propagate,
for the reason `delete_route`'s comment gives. Swallowing them would report a
clean revert, delete the record, and leave the host's resolvers pointed into a
tunnel that no longer exists.

## Routes

`ip` with an argv array and an absolute path, the same posture `install.rs`
already takes with `/bin/launchctl`. Nothing that crossed the socket is
interpolated into a shell; the addresses are parsed by `service.rs` and
re-serialised, never forwarded as strings.

| `Via` | Linux |
|---|---|
| `Interface(n)` | `ip route add <dst> dev <n>` |
| `Gateway(g)` | `ip route add <dst> via <g>` |
| `Blackhole` | `ip route add blackhole <dst>` |
| `Reject` | `ip route add unreachable <dst>` |

`Blackhole` and `Reject` are native route types here rather than the
loopback-plus-flag workaround macOS needs, so `Via`'s existing distinction maps
directly and the "a next hop is required even though nothing is delivered"
comment in `route_args` has no Linux counterpart. Both forms were confirmed to
install (measured).

`delete_route` names only the destination, as on macOS and for the same reason.
An absent route makes `ip route del` exit **2** with `RTNETLINK answers: No such
process` — ESRCH, surfaced as a message rather than an errno (measured). That
string is what `is_absent_route`'s Linux twin matches, and nothing else.

**Locating `ip`.** Resolved once at startup from a fixed candidate list —
`/usr/sbin/ip`, `/sbin/ip`, `/usr/bin/ip` — failing loudly and naming all three
if none is present. Not searched on `PATH`, which a root daemon should not
trust. Three entries rather than two because merged-`/usr` layouts vary: on
Fedora 44 `/sbin → usr/sbin` and `/usr/sbin → bin`, so both of the brief's
candidates resolve to `/usr/bin/ip`, while on Debian `/usr/sbin/ip` is the real
file. Whichever is found first is used for the life of the process; the path is
logged once.

**`default_gateway` reads `ip -j route show default`.** The brief left the
choice between that and netlink open; `ip -j` wins on the same grounds
`netstat -rn` beat a `sysctl` `NET_RT_DUMP` on macOS. Walking `rtnetlink`
messages is unsafe code that cannot be unit-tested without root, whereas a JSON
parse is a pure function over a fixture with tests, and `serde_json` is already
a daemon dependency.

`-j` is old enough not to be a concern on the distributions in scope, but the
oldest of them has not been checked — only iproute2 6.17.0 on this host has
(measured). If step 3 finds a supported release without it, the fallback is the
column parse `netstat -rn` already uses on macOS, which is strictly worse and
therefore not the default.

`ip route show default` matches the literal `default` destination, so — unlike
`ip route get 0.0.0.0`, which is the direct analogue of the `route get default`
trap the macOS spec documents — it cannot be fooled by this daemon's own
`0.0.0.0/1`. `0.0.0.0/1` is not `default`.

Two parsing rules, both testable and both with a macOS ancestor:

- **Entries with no `gateway` key are skipped.** A default route through a
  point-to-point interface has none — this is the exact analogue of macOS's
  `link#N` pseudo-gateway filter, and it exists for the same reason: taking it
  would send an excluded address into the tunnel it is excluded from. The same
  rule covers non-unicast defaults for free: a `blackhole` route serialises as
  `{"type":"blackhole","dst":...}` with neither `dev` nor `gateway` (measured).
- **The lowest `metric` wins**, ties broken by table order. A laptop with
  Ethernet and Wi-Fi both up has two default routes at different metrics —
  `eno1` here is 100 (measured), and NetworkManager gives Wi-Fi a higher one.
  macOS's "first row" rule has no equivalent problem because `netstat` reports
  one; here, taking the first would be a coin flip between two live gateways.
  **Absent `metric` sorts as 0**: `ip -j` omits the key entirely when the
  metric is zero, which was confirmed by adding a route with `metric 0` and
  reading it back (measured), so treating absence as a large number would
  invert the ordering for exactly the route most likely to be the real default.

## DNS

The part with no macOS counterpart, because macOS has one mechanism and Linux
has four. KVN's scope is Fedora, Ubuntu, Debian, Arch and openSUSE, and their
defaults split:

| Distribution | Default |
|---|---|
| Fedora 40+, Ubuntu 22.04+ | systemd-resolved |
| Debian 12 | NetworkManager → `/etc/resolv.conf` |
| Arch | no default |
| openSUSE | `netconfig` → `/etc/resolv.conf` |

Two backends cover all five. Selected once at daemon start by probing, logged,
reported through `capabilities`, and not re-probed per session.

### The probe, and the trap in it

The brief and KVN's design both say "systemd-resolved, where it is running".
That is not sufficient, and the reason is in `systemd-resolved.service(8)`'s
`/ETC/RESOLV.CONF` section, which enumerates **four** modes:

1. `/etc/resolv.conf` → `/run/systemd/resolve/stub-resolv.conf` — lists
   `127.0.0.53`. Per-link configuration reaches every client.
2. `/etc/resolv.conf` → `/usr/lib/systemd/resolv.conf` — also `127.0.0.53`.
   Same.
3. `/etc/resolv.conf` → `/run/systemd/resolve/resolv.conf` — lists the *uplink*
   servers directly. The man page is explicit: "local clients that bypass any
   local DNS API will also bypass systemd-resolved and will talk directly to the
   known DNS servers."
4. `/etc/resolv.conf` managed by another package, with resolved as a consumer of
   it rather than a provider.

In modes 3 and 4, resolved can be running, `resolvectl dns <tun>` can succeed,
and every glibc client that reads `/etc/resolv.conf` directly still queries the
host's own resolvers. The tunnel comes up, the daemon reports `RUNNING`, and DNS
leaks — silently, which is the worst shape a leak can have.

So the probe is three conditions, all cheap, all at startup:

1. `resolvectl` is present at one of `/usr/bin/resolvectl`, `/bin/resolvectl`.
2. `resolvectl status` exits 0 — positive proof the daemon answers on D-Bus,
   rather than a proxy for it like `systemctl is-active`.
3. `/etc/resolv.conf`, read through its symlink, points **only** at
   `127.0.0.53`.

All three, or the direct backend. Condition 3 is a pure function over file
contents and is where the tests are; it is also precisely what the man page says
resolved's own mode detection keys on, so it is not a heuristic standing in for
the real question — it *is* the real question.

**Two tightenings on condition 3, both found while implementing it.** The
spec first said "lists `nameserver 127.0.0.53`", and both are cases where that
reading passes and the host still leaks:

- **At least one nameserver, and every one of them the stub.** A file listing
  `127.0.0.53` *beside* an upstream server is one glibc falls back from
  whenever resolved is slow to answer — so the leak appears only under load,
  which is the hardest kind to attribute.
- **`127.0.0.54` is rejected.** It is also a resolved stub, so a substring
  reading accepts it, but `systemd-resolved.service(8)` says it "operates in
  'proxy' mode only, i.e. it will pass most DNS messages relatively unmodified
  to the current upstream DNS servers and back, but not try to process the
  messages locally". Not processing locally means not applying the per-link
  configuration this daemon writes — the same leak under a different address.

### systemd-resolved

`resolvectl dns <tun> <ips>`, `resolvectl domain <tun> ~.`, `resolvectl
flush-caches`; `resolvectl revert <tun>` to undo. All four confirmed against a
real tun link (measured).

Configure the **tunnel's** link, not the physical one. That is what the trait
change is for. Putting our resolvers on `eno1` means NetworkManager rewrites
them on every DHCP renew; putting them on the tunnel link means nothing
competes, and revert is nearly free because `resolvectl(1)` states that "when a
network interface disappears all configuration is lost automatically".

The macOS objection to `networksetup` — that it addresses a service by *display
name*, which is why libnyanpasu/nyanpasu-service#26 has been open since macOS
14.3 — does not transfer. `resolvectl` addresses a link by name or ifindex, both
stable.

**Not D-Bus, for now.** `org.freedesktop.resolve1.Manager.SetLinkDNS` is more
precise and avoids shelling out at all, and it is the upgrade if a reason
appears. It loses today on cost: it pulls an async D-Bus stack into a blocking
supervisor thread, to replace four argv arrays whose shape is asserted in unit
tests. `install.rs` already shells to `launchctl` under the same rules.

**The physical link's resolvers are not carried across.** A Linux physical link
commonly advertises a v6 resolver beside its v4 ones — this host's `eno1` offers
`192.168.1.1` and `fd57:69ae:43c6::1`. The tunnel link gets exactly what the
client asked for and nothing else.

### Direct `/etc/resolv.conf`

Back it up, write `nameserver` lines, restore on revert.

**The backup must record whether the path was a symlink and where it pointed.**
On a resolved host it is a symlink to `stub-resolv.conf`; elsewhere it may point
into `/run`. Restoring a flattened regular file where a symlink was is how this
class of tool breaks a host permanently — the next time the real manager
rewrites its target, nothing follows — and `AppliedState` is the only thing
standing between us and that.

`DnsBackup` is extended rather than joined by a second record, so that one
`AppliedState` field means one thing:

```rust
pub struct DnsState {
    pub servers: Vec<IpAddr>,
    /// Where the path pointed, if it was a symlink.
    pub symlink_target: Option<PathBuf>,
    /// The bytes a regular-file original held, replayed on restore.
    pub verbatim: Option<String>,
}
```

**`verbatim` was not in the first draft of this spec, and its absence was a
defect.** `servers` is the *parsed* view. A `/etc/resolv.conf` also carries
`search`, `options` and `sortlist` lines, and a revert rebuilt from the
resolver list drops every one of them. The symptom is a host whose short names
stop resolving after a session ends — `ssh fileserver` failing where it worked
an hour ago — with nothing in any log connecting it to the VPN, and no repair
until whatever manages the file next rewrites it, which on a `netconfig` host
is its own schedule rather than ours. So a regular-file original is replayed
byte for byte and `servers` is ignored on that path.

A symlinked original still records `symlink_target` and no `verbatim`: the link
is restored as a link, and its target's contents were never ours to rewrite. A
path that did not exist records neither, so "there was no file" and "there was
an empty file" stay distinguishable.

`#[serde(default)]` is load-bearing rather than defensive, and the reason is
`skip_serializing_if` beside it: a resolved-backend session has no symlink to
record, so it writes the field out as absent and must be able to read it back.
It also keeps a record written by an earlier build readable, which matters
because `AppliedState::load` reports a parse failure rather than ignoring one —
correctly, but that means an added field without a default turns every
in-flight record into a refusal to start.

Restoring a symlink is `remove_file` then `symlink`, not a write — writing
through the link would rewrite the manager's own file.

**This backend is contended and needs a watcher.** NetworkManager rewrites the
file on reconnect and openSUSE's `netconfig` on its own schedule. Re-apply from
an `inotify` watch on the *directory* — not the file, because both managers
write a temporary and rename over it, which detaches an inode watch — rate
limited to the same 300 ms settle the route monitor uses. This is a port of the
shape `host/macos` already carries for `SCDynamicStore`, not a new mechanism.

It cannot make the losing window zero, only short. That is stated here so it is
a known property rather than a bug report.

**Each backend refuses the other's record.** Not in the first draft, and it
closes the one door `symlink_target` does not. `DnsBackup::service` survives a
restart, and the probe's answer can differ across one — installing or removing
systemd-resolved is all it takes. A resolved record names a link and carries no
resolvers, so a direct backend that accepted it would replace `/etc/resolv.conf`
with an empty regular file: precisely the permanent breakage the symlink rule
exists to prevent, arriving by the route that rule does not cover. So the direct
backend accepts only its own `file:<path>` sentinel, and the resolved backend
accepts only a kernel-shaped link name — which the sentinel is not.

## The routing-domain contest

The brief's verification item 5 asks what happens when `tailscale0` and our
tunnel both claim a `~.` routing domain, "because it decides whether KVN can be
used on a machine that also runs Tailscale". It is answerable now, from
`systemd-resolved.service(8)`'s PROTOCOLS AND ROUTING section plus the state of
the development host, and the answer has three parts.

**There is no contest in Tailscale's default configuration.** `tailscale0` on
this host reports `-DefaultRoute` and routing domains `tailf8307c.ts.net`,
`~100.100.in-addr.arpa` and the rest of the `100.64.0.0/10` reverse space — and
**no `~.`** (measured). Resolved routes each query to the link whose matching
routing domain has the most labels, so `foo.tailf8307c.ts.net` goes to
Tailscale, `100.x.y.z` reverse lookups go to Tailscale, and everything else
matches only our `~.` and goes to us. MagicDNS keeps working and nothing leaks.

**Our `~.` is sufficient on its own; `eno1` staying `+DefaultRoute` is
harmless.** Both links end up `Default Route: yes` after we configure ours
(measured), which looks alarming and is not. The default-route branch of the
routing logic is reached only "if a query does not match any configured routing
domain", and with `~.` present every query matches one. So the daemon does not
need to touch `eno1` at all — which is what keeps the revert path as small as
it is.

The one leak this leaves is real and worth naming: `eno1`'s search domain `lan`
is one label and beats our zero, so `*.lan` still resolves on the LAN. That is
almost certainly what a user wants from a split-DNS point of view, and it is not
what a strict "all DNS goes through the tunnel" reading promises. Recorded
rather than fixed; fixing it means `resolvectl domain eno1 ""`, which is
physical-link state we would then have to restore, and that is the contention
this design exists to avoid.

**The contest does exist when Tailscale is an exit node.** In that mode
Tailscale sets `~.` on its own link, and the man page's rule is that when more
than one link ties on the best-matching routing domain, "the query is sent to
all of them in parallel" and the first successful response wins. Two VPNs each
claiming all of DNS is a race with no defined winner, and no configuration on
our side resolves it. The answer for KVN is that the two are mutually exclusive
in that mode, and the daemon should say so rather than produce a tunnel whose
DNS is nondeterministic: at start, if another link already carries `~.`, log a
warning naming it. Not an error — the user may have made that trade knowingly —
but not silent either.

## Route monitor

`host/macos/monitor.rs` reads a `PF_ROUTE` socket purely as a signal, never
parsing the delta, and posts `Command::NetworkChanged` onto the same channel as
`Start` and `Stop` so the re-apply is serialised rather than racing them. The
300 ms settle, the 2 s second look, and treating `ENOBUFS` as recoverable are
the details that make it work.

That shape ports to `AF_NETLINK` with `RTMGRP_IPV4_ROUTE | RTMGRP_LINK` almost
literally, and needs no new dependency: `sockaddr_nl`, `RTMGRP_IPV4_ROUTE` and
`RTMGRP_LINK` are all reachable from the locked `libc` 0.2.189, confirmed by
compiling against it.

`recoverable()` transfers unchanged, and `netlink(7)` is where that comes from
rather than from analogy with `PF_ROUTE`: "The kernel can't send a netlink
message if the socket buffer is full: the message will be dropped and the kernel
and the user-space process will no longer have the same view of kernel state. It
is up to the application to detect when this happens (via the `ENOBUFS` error
returned by `recvmsg(2)`) and resynchronize." Resynchronising is exactly what
this monitor does anyway, because it re-reads the table rather than tracking a
delta — which is why losing messages costs nothing here.

For the same reason, `NETLINK_NO_ENOBUFS` is **not** set. It exists to suppress
these errors, and suppressing them would turn a dropped burst into silence
rather than into a re-read.

The monitor stays per-process and detached,
and keeps the recorded consequence: a non-recoverable read error kills it for
the life of the process, so a daemon up for weeks may no longer be watching and
nothing says so.

Two Linux differences:

- **`bind` is required**, and `PF_ROUTE` needs none. A netlink socket receives
  nothing until it is bound to a `sockaddr_nl` with `nl_groups` set. That is the
  one place this can fail that the macOS version cannot, and it is what the
  unit test covers — `open_route_socket`'s twin returns the bound fd, and the
  test asserts an unprivileged process can get one, exactly as the macOS test
  does and for the same reason.
- **The second look is kept**, even though its macOS rationale — resolved DNS
  being restored asynchronously — does not apply to the resolved backend, whose
  configuration nothing else touches. It applies squarely to the *direct*
  backend, which contends with NetworkManager, so the cost of keeping one code
  path is two `resolvectl` calls per network change on hosts that do not need
  them. Cheap, and cheaper than two monitors.

Note finding 3 of `shoes-agent-prompt-daemon-review-2.md`: the macOS monitor's
test leaks a detached thread. The Linux test tests `open_route_socket`'s twin
and never calls `spawn`, which is the shape that avoids it.

## Crash recovery

**Simpler on Linux, and the record gets smaller.** The kernel deletes a link's
routes when the link disappears, and resolved's per-link configuration goes with
it — `resolvectl(1)` says so, and it was confirmed: after the test tun closed,
`resolvectl status tuntest0` reported the device does not exist and its
configuration was gone (measured).

So `kill -9` on the daemon cleans up, unaided:

- the tunnel's own `0.0.0.0/1` and `128.0.0.0/1`, and the v6 `unreachable`
  halves, since all four name the device;
- the kernel's own on-link route for the tunnel prefix (below);
- and, on a resolved host, the whole DNS override.

What survives, and therefore what `AppliedState` is for here:

- the **exclusion host routes**, which hang off the physical interface and have
  nothing to do with the tunnel's lifetime;
- the **direct backend's `/etc/resolv.conf`**.

Narrower than macOS. The same record and the same `recover()` path handle it,
and `Session::revert`'s idempotence requirement is what makes the overlap
harmless: it is routinely asked to delete routes the kernel already took.

**One route the daemon does not own.** Setting `address` + `netmask` on the
device makes the kernel install `10.0.0.0/24 proto kernel scope link src
10.0.0.2` (measured). It is not in `AppliedState`, must not be added to it, and
dies with the link. This is the Linux counterpart of the macOS `enable_routing`
question, and it arrives already answered: unlike the `tun` crate's macOS
`set_route`, which shells to `route` and installs a route that outlives nothing
in particular, this one is the kernel's own on-link entry and is reverted by the
same event that removes the interface.

It carries one collision worth recording. `10.0.0.0/24` is the tunnel prefix
`device_policy()` chose to match iOS, and it is also one of the most common home
LAN ranges. On such a LAN the kernel's on-link route is as specific as the
physical link's and the tie is broken by metric, which nothing here sets. That
is a pre-existing consequence of the address pair rather than something this
milestone introduces — the same pair is used on macOS — but Linux is where it
becomes concrete, and it is a follow-up, not a blocker: the fix is to pick a
less common prefix, and that changes iOS too.

## Install

`install.rs` is entirely launchd. The Linux arm keeps every rule it enforces and
changes only the mechanism.

- Copy the running executable to `/usr/local/libexec/shoesd`, `root:root`,
  `0755`. **Never run from the path it was invoked at** — that path is inside a
  user-writable app bundle, and a root daemon whose binary a user can rewrite is
  a privilege escalation. `stage()`'s discipline carries over unchanged,
  including removing a leftover staged file first because `create` on an
  existing file keeps the mode it already has.
- Write `/etc/systemd/system/shoesd.service`, then `systemctl daemon-reload` and
  `systemctl enable --now shoesd`.
- `uninstall` reverses it, stopping the unit first — which sends `SIGTERM`, so
  the session is reverted by the same path a shutdown uses rather than a second
  one written here, exactly as `bootout` does on macOS.

The unit replaces the plist and needs no XML escaping, but it needs its own:
systemd unit files are `key=value` with no quoting for most keys, and `ExecStart`
*is* parsed for quotes and escapes. Paths and the group name come from the
command line, so `ExecStart` is written with each argument quoted per
`systemd.service(5)`'s rules, and the same "every argument is its own element"
test the plist has is kept in the form that applies here.

**Quoting is not enough, and this spec first said it was.** Two substitutions
happen to `ExecStart` regardless of quotes, and both were found by loading a
rendered unit into the real systemd and reading `ExecStart` back rather than by
reading the manual:

- **`%` specifiers expand at unit load, inside double quotes.** A unit whose
  `ExecStart` contains `"%h"` comes back with `/home/<user>` substituted
  (measured on systemd 259). So `%` is escaped to `%%`.
- **`$` expands at exec time**, as an environment variable, and is escaped to
  `$$`.

Both matter because these values crossed a boundary: a `--socket` path or a
`--group` name containing `%h` would silently become a different path in the job
that actually runs as root. XML escaping on macOS protects against a *malformed*
document; this protects against a well-formed one that means something else.
`"`, `\`, and the control characters are escaped as well, newline most of all —
a raw one ends the line and takes the rest of the command with it.

**`Restart=always` is not `KeepAlive`, and the difference would have broken
crash recovery.** launchd throttles a job that exits quickly and repeatedly to
roughly one launch per ten seconds and keeps trying forever. systemd does not
throttle — it gives up. `systemd.unit(5)`: "units which are configured for
`Restart=`, and which reach the start limit are not attempted to be restarted
anymore", and the defaults are `DefaultStartLimitBurst=5` within
`DefaultStartLimitIntervalSec=10s` (`systemd-system.conf(5)`).

So a daemon that fails five times in ten seconds stops being restarted, and the
recovery pass that runs before anything else on the next start — the one that
undoes the exclusion routes and restores `/etc/resolv.conf` — never runs. On a
machine whose network is down, whose user therefore cannot fetch a fix, and
where the whole point of the on-disk record is that the restart is automatic.
That is precisely the failure `AppliedState` exists to prevent, reached through
the service manager instead of through the code.

The unit therefore sets `StartLimitIntervalSec=0`, disabling the rate limit
outright, with `RestartSec=5` bounding the retry so it is a slow loop rather
than a hot one. That restores launchd's behaviour deliberately rather than
inheriting a different one by writing the obvious `Restart=always` and stopping.
It also keeps the reason recovery must be idempotent rather than merely fast:
the retry is unbounded, so a recovery that is not safe to run twice is a
recovery that is not safe.

The socket directory is `/run/shoesd/`, which `DEFAULT_SOCKET_PATH` already
names via `/var/run` — a symlink to `/run` on every distribution in scope. The
daemon creates it, so `RuntimeDirectory=` is *not* used: it would have systemd
create the directory with a mode of its choosing before the process starts, and
the directory's `0750 root:group` is the thing that closes the bind-and-chmod
window `socket.rs` documents. One owner for that decision.

Two things with no macOS counterpart:

**Group detection.** `--group admin` has no meaning here: the administrators'
group is `wheel` on Fedora, Arch and openSUSE and `sudo` on Debian and Ubuntu.
With no explicit `--group`, pick the first of `wheel`, `sudo`, `adm` that exists
*and* contains the invoking user — read from `PKEXEC_UID`, falling back to
`SUDO_UID`. The daemon knows who invoked it and the calling app does not, which
is why this belongs here.

Both halves of that conjunction matter, and this host shows why: `wheel` exists
and contains the user, `adm` exists and is empty, `sudo` is absent
(measured). A rule that stopped at "exists" would be right here by luck and
wrong on a Debian box where `adm` exists and holds only log readers.

Failing loudly and naming all three candidates is the required behaviour when
none matches, rather than installing a socket nobody can reach. `DEFAULT_GROUP`
therefore becomes a per-platform default rather than the constant `"admin"`, and
detection runs only when `--group` was not given — an explicit group is always
honoured, including one the invoker is not in, because `install` is the one
place an administrator may legitimately set up a daemon for someone else.

**SELinux.** Fedora enforces by default — this host reports `Enforcing`
(measured) — and recent openSUSE does too, though that has not been checked
here. A binary written to `/usr/local/libexec` can land
with a label that stops systemd executing it. Run `restorecon` on the installed
binary where it exists (`/usr/sbin/restorecon`, present here as a symlink to
`setfiles`), and tolerate its absence on Debian, Ubuntu and Arch rather than
failing the install. Tolerating absence is not tolerating failure: a
`restorecon` that exists and returns non-zero is reported.

**Elevation is KVN's problem.** The app runs `pkexec <bundled path>/shoesd
install`; `shoesd install` itself only needs to work when it is already root,
exactly as on macOS.

## Buffer sizing

`shoesd` is built `--features daemon` and **without** `network-extension`, so
`src/buffer_sizing.rs` gives it desktop sizing. The brief flags this and it is
worth keeping flagged: the buffer budget is keyed off that feature, and a Linux
desktop daemon picking up the 256 KiB AmneziaWG windows sized for a 50 MB iOS
extension would silently cost most of the throughput 0.2.19 and 0.2.20 added.

Nothing enforces that today beyond convention, and the release job is where it
can go wrong. RSS idle and under load is a verification item, for comparison
against the macOS figure.

## Measured on the development host

Fedora 44, kernel 7.1.13, systemd 259, SELinux enforcing, GNOME/Wayland,
systemd-resolved in stub mode, `tailscale0` up. Everything here was run rather
than reasoned, using the same three ioctls `AbstractDevice::configure`
(`tun-0.8.14/src/device.rs:23-49`) issues, in the same order.

| Question | Answer |
|---|---|
| Do `address` + `destination` + `netmask` all apply to an `IFF_TUN` device? | Yes. `SIOCSIFADDR`, `SIOCSIFDSTADDR`, `SIOCSIFNETMASK` each returned 0 |
| Does `SIOCSIFDSTADDR` need `IFF_POINTOPOINT` requested up front? | No, and not because the ioctl sets it: a bare `IFF_TUN` device reads `<POINTOPOINT,MULTICAST,NOARP>` immediately after `TUNSETIFF`, before any address ioctl. The kernel makes tun devices point-to-point at creation |
| What does `device_policy()`'s pair produce? | `inet 10.0.0.2 peer 10.0.0.1/24 scope global` — the `/24` attaches to the peer |
| Does it install a route of its own? | Yes: `10.0.0.0/24 proto kernel scope link src 10.0.0.2` |
| Can a half-default be pinned to it? | Yes. `ip route add 0.0.0.0/1 dev tuntest0` → rc 0 |
| Native blackhole and reject? | Yes, both. `ip route add blackhole\|unreachable <dst>` → rc 0 |
| What does deleting an absent route give? | rc 2, `RTNETLINK answers: No such process` (ESRCH) |
| Do the four `resolvectl` calls work on a tun link? | Yes, all rc 0: `dns`, `domain ~.`, `flush-caches`, `revert` |
| What does reverting an absent link give? | rc 1, `Failed to resolve interface "nosuchlink0": No such device` |
| Does the config survive the link? | No. Both the link's routes and its resolved configuration were gone once the fd closed |
| Does `~.` on the tunnel leave `eno1` a default route? | Yes, both report `Default Route: yes` — and it does not matter; see [the contest](#the-routing-domain-contest) |
| Does Tailscale claim `~.`? | Not by default. `-DefaultRoute`, and its routing domains are `ts.net` plus the `100.64/10` reverse space |
| `ip -j route show default` | shape confirmed: `dst`, `gateway`, `dev`, `protocol`, `prefsrc`, `metric`, `flags` — one default route, `metric` present and non-zero |
| Admin group | `wheel` gid **10**, contains the user; `adm` gid 4, empty; `sudo` absent |
| `ip` location | `/sbin → usr/sbin → bin`, so all three candidates reach the same inode. `Path::exists()` follows the symlink but the located path keeps the name it was given, so `locate()` stores and logs `/usr/sbin/ip` here — the shared inode is not the string the daemon prints |

The device was created and torn down by an out-of-tree script; nothing in this
table required a build of `shoesd`.

## Testing

The privileged parts cannot run in CI, which is what `HostNetwork` and the
recording double already exist for. Everything below is a unit test on every
platform, with no root and no device, unless it says otherwise. Per AGENTS.md
each is written first and watched to fail for the expected reason.

**Pure functions, which is most of it.** The argv for every `ip` invocation,
asserted as a vector rather than a formatted string and asserted to contain no
whitespace or `;` in any element; the `ip -j route show default` parse, against
fixtures covering no default, a gateway-less point-to-point default, two
defaults with different metrics, and the real capture above; `is_absent_route`'s
Linux twin, asserting that ESRCH is swallowed and that a permission error, a
missing binary and a kernel refusal are not; the DNS backend probe against
fixture `resolv.conf` contents for all four resolved modes; the systemd unit
render, including a path containing a space and one containing a quote; and
group detection against an injected "does this group exist and contain this
uid" predicate, covering the Fedora shape, the Debian shape, and none-matching.

**Sequencing**, which is where the damage is, is already covered by
`host/plan.rs`'s tests against `Recorder` and gains only what the trait change
touches: `primary_dns_service` now receives the interface, so `Step::PrimaryService`
carries it and the existing ordering assertions gain that argument.

**Two new sequencing tests**, because the Linux backends have failure modes the
macOS one does not:

- A `write_dns` that fails with "no such device" during revert must not abort
  the rest of the revert. This is the clause added in
  [The trait change](#the-trait-change), and it is the one whose absence would
  strand exclusion routes.
- The direct backend's symlink round trip: a `DnsBackup` recording a symlink
  restores a symlink, and one recording a regular file restores a regular file.
  Asserted on the filesystem in a `tempdir`, since the operation is `remove_file`
  plus `symlink` rather than a write.

**`a_known_group_resolves` is fixed** as described in
[What is already done](#what-is-already-done), so that `cargo test --features
daemon` is green on Linux and macOS both.

**Live verification**, all of it on the author's own machine except item 2:

1. `start` with a real AmneziaWG config, `curl` through the tunnel, `stop`, and
   `ip route show` plus `resolvectl status` byte-identical before and after.
   Both diffs pasted.
2. The same on a distribution using the direct backend — Debian or openSUSE in a
   VM — including a NetworkManager reconnect mid-session to prove the watcher
   re-applies, and a revert that restores the symlink **as a symlink**.
3. `kill -9` mid-session, then start again, and show routes and DNS come back.
   The reply states which parts the kernel cleaned up unaided and which the
   record had to undo; the division is different from macOS and the claim in
   [Crash recovery](#crash-recovery) is what is being checked. Then `kill -9`
   six times inside ten seconds and confirm systemd is still restarting it —
   that is the `StartLimitIntervalSec=0` line, and it cannot be checked any
   other way.
4. A network change mid-session: unplug Ethernet, fall to Wi-Fi, and show the
   exclusion host route re-pointed at the new gateway.
5. Coexistence with Tailscale, in both of its modes — default, where
   [the contest](#the-routing-domain-contest) predicts no interference, and exit
   node, where it predicts a warning and a race.
6. Coexistence with Docker: bridge routes are RFC1918 and therefore more
   specific than `0.0.0.0/1`, so containers should be unaffected. Asserted, not
   assumed.
7. A call from a uid outside the detected group gets `PERMISSION_DENIED` as a
   gRPC status, not a dropped socket.
8. RSS idle and under a sustained download, against the macOS figure, confirming
   the desktop buffer sizing took effect.
9. `shoesd install` under `pkexec`, from a binary inside a user-writable bundle.
   That is KVN's Task 0 spike and not our code, but our install path is what it
   exercises, and it is what `PKEXEC_UID`-based group detection rests on.

Live-run credentials follow the existing rule: a config outside the working
tree, deleted afterwards, and `git status` checked before committing.

**The CI gate is separate from those**, and two things it is often assumed to
prove are worth separating too. `mobile.yml`'s link check compares `_shoes_`
symbol counts between the iOS host executable and the extension: it proves the
host/extension split, not the absence of `control-logs`. What actually keeps the
daemon's dependencies out of the mobile artifacts is that `daemon` is off by
default and no mobile build enables it — and the check for *that* is
`cargo tree --target x86_64-unknown-linux-gnu` on a default build, which must
still show no gRPC stack after the target sections are split. Both run; they are
not the same assurance.

## Release artifacts

Two, separate from the `shoes-*` tarballs for the three reasons the macOS spec
gives — different feature set, different audience, and a consumer that fetches by
asset name. KVN's `DownloadShoesAssetTask` verifies the SHA-256 the GitHub API
reports, so a stable name per artifact is what it wants.

Built by their own `cargo build --bin shoesd --features daemon`, because
features are additive per build and folding them into the existing job would
compile `control-stats` and `control-logs` into the `shoes` CLI. `--features
desktop` will not do: `[[bin]] shoesd` carries `required-features = ["daemon"]`.

**The x86-64 name is `shoesd-linux-x86_64.tar.gz`; the arm64 one is unsettled.**
KVN's brief and design both say `shoesd-linux-aarch64.tar.gz`, and their Gradle
task fetches by exact name, so this is the consumer's to decide. But
`build.yml`'s matrix calls that leg `linux-arm64`, the macOS daemon artifact is
`shoesd-macos-arm64.tar.gz`, and KVN already consumes that name — so their own
two platforms would disagree. Recommendation is `shoesd-linux-arm64.tar.gz`,
confirmed with KVN before the release job lands. It is one string in one place
whichever way it goes; the plan tracks it.

**The gnu legs only, and not musl.** A statically linked musl build uses musl's
own `getpwuid_r` and `getgrnam`, which read `/etc/passwd` and `/etc/group`
directly and know nothing of NSS plugins. On a host with SSSD- or LDAP-backed
accounts, both the peer-credential check in `auth.rs` and install-time group
detection would fail to resolve a real user — a daemon that refuses everyone,
with nothing in the error saying why. glibc is a requirement of this binary
rather than a default it happens to have.

Named in the release notes and in `README.md` beside the macOS one.

## Order of work

1. **Ungate**, and fix `a_known_group_resolves`. First because everything else
   needs a binary that compiles, and because it is the step that reveals
   whatever else the macOS gating was hiding.
2. **The trait change** and its call site, with the `write_dns` clause and its
   two sequencing tests. All logic, no privilege, and it gates 3 and 4.
3. **`host/linux/routes.rs`** — the `ip` wrapper, the argv builders, the
   gateway parse, `is_absent_route`'s twin, and the tool resolution.
4. **`host/linux/dns.rs`** — the probe, then the two backends, then the
   direct backend's inotify watcher.
5. **`host/linux/monitor.rs`** — the netlink port.
6. **`install.rs`'s Linux arm** — the unit, group detection, `restorecon`.
7. **Docs and release** — `docs/LINUX.md` beside `docs/MACOS.md`, `CONFIG.md`'s
   TUN platform notes, `README.md`, `ROADMAP.md`, `CHANGELOG.md`, and the build
   workflow's two new artifacts.
8. **Verification** — the full gate, then the nine live items.

The step-by-step form of this, with the verification each step has to pass, is
[docs/plans/2026-09-04-linux-privileged-daemon.md](../plans/2026-09-04-linux-privileged-daemon.md).

Steps 3, 4 and 5 are independent of each other and can go in any order once 2
lands.

## Decisions the brief left open

| Question | Decision | Why |
| --- | --- | --- |
| `default_gateway`: `ip -j` or netlink? | `ip -j route show default`, parsed with `serde_json` | Netlink means walking `rtnetlink` messages in unsafe code that cannot be tested without root; a JSON parse is a pure function with fixtures. Same trade the macOS arm made against `NET_RT_DUMP`, and `serde_json` is already a dependency |
| Which default route, when there are two? | Lowest `metric`, ties by table order; entries with no `gateway` skipped | Ethernet and Wi-Fi both up is the ordinary case and NetworkManager gives them 100 and 600. The gateway-less skip is macOS's `link#N` filter under another name |
| `resolvectl` or D-Bus `SetLinkDNS`? | `resolvectl`, argv, absolute path | D-Bus is more precise and is the upgrade if a reason appears; today it pulls an async stack into a blocking supervisor thread to replace four argv arrays whose shape is unit-tested. `install.rs` already shells to `launchctl` under the same rules |
| How is the DNS backend chosen? | Three conditions: `resolvectl` present, `resolvectl status` exits 0, and `/etc/resolv.conf` lists `127.0.0.53` | "resolved is running" is not enough. In resolved's `uplink` and `foreign` modes every glibc client bypasses it, so per-link configuration silently leaks. The third condition is what resolved's own mode detection keys on |
| Report the DNS backend in `capabilities`? | Yes — `dns-backend:systemd-resolved` or `dns-backend:resolv.conf` | Costs no proto change, unknown values are ignored, and it is the first question a Linux DNS bug report needs answered |
| Does `destination` + `/24` work on `IFF_TUN`? | Yes | Measured. Tun devices are already point-to-point at creation, so `SIOCSIFDSTADDR` has the flag it needs. It also installs an on-link `10.0.0.0/24` the daemon does not own and must not record |
| Do we also clear `~.`/default-route on the physical link? | No | Our `~.` alone captures every query that does not match a longer routing domain, so the physical link's default-route status is never consulted. Touching it would create physical-link state to restore — the contention this design avoids |
| What happens with Tailscale? | Nothing, by default; a warning in exit-node mode | Tailscale sets no `~.` unless it is an exit node. When it does, resolved queries both links in parallel and takes the first answer, which no configuration on our side resolves — so it is named rather than papered over |
| Keep the monitor's 2 s second look? | Yes | Its macOS rationale does not apply to the resolved backend, but applies squarely to the direct one. Two extra `resolvectl` calls per network change is cheaper than two monitors |
| Watch the file or the directory for the direct backend? | The directory | Both NetworkManager and `netconfig` write a temporary and rename over it, which detaches an inode watch |
| `RuntimeDirectory=` for the socket directory? | No; the daemon creates it | Its `0750 root:group` is what closes the bind-and-chmod window `socket.rs` documents. One owner for that decision |
| `Restart=always` alone, as the `KeepAlive` equivalent? | No — `StartLimitIntervalSec=0` and `RestartSec=5` as well | systemd's default is to *stop* restarting after 5 failures in 10 s, where launchd throttles and keeps trying. Inheriting that would mean crash recovery never runs on the machine that needs it most |
| `--group` default on Linux | Detected: first of `wheel`, `sudo`, `adm` that exists *and* contains the invoker | `admin` does not exist on Linux, and "exists" alone is wrong — `adm` exists on Fedora and is empty. An explicit `--group` is always honoured |
| Extend `DnsBackup` or add a record? | Extend, with `#[serde(default)]` | One `AppliedState` field means one thing, and the default keeps records written before the field readable — `load` reports a parse failure rather than ignoring it |

## Deliberately out of scope

- **No `nftables`, no kill switch, no split tunnelling.** The macOS spec left
  the shape for a `pf` anchor as a follow-up by keeping application behind
  `HostNetwork`; the same shape is left here and nothing is built.
- **No `SO_MARK` and no `ip rule` policy routing.** wg-quick's canonical Linux
  approach needs a firewall mark on the engine's outbound sockets, and there is
  no `SO_MARK` anywhere in the tree. The exclusion host route is sufficient.
  Recorded so its absence reads as known rather than overlooked.
- **No `bind_interface` in the daemon.** `SO_BINDTODEVICE` *is* supported on
  Linux, and it is the better long-term answer the first brief deferred: it
  would remove the exclusion host route entirely and survive the proxy server's
  address changing. It is not adopted because it lives in the *outbound* section
  of the config, and the daemon's contract — settled by the macOS spec's
  `prepare_from_config_owning_device` decision — is that it rewrites the TUN
  section and nothing else. Changing that contract means the daemon editing a
  part of the config the client owns, and re-deciding what a client may rely on
  surviving `Start`. Larger than this milestone.
- **No IPv6 inside the tunnel.** Same posture as macOS: `::/1` and `8000::/1` as
  native `unreachable` routes, and v6 refused in both `exclude` and `dns`.
- **No Windows.**
- **No changes under `src/`.** Device creation and validation already have Linux
  arms; if the live run finds otherwise, that is a finding to report rather than
  a change to make quietly.
- **The `10.0.0.0/24` LAN collision is not fixed here.** It predates this
  milestone and changing the prefix reaches iOS.
