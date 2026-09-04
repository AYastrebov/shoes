# The macOS privileged daemon

A root launchd daemon that hosts `shoes::control` in-process and serves a
desktop GUI over gRPC on a Unix domain socket. It creates the `utun`, installs
routes and DNS, reverts them on stop, and reports status, statistics and logs
as data rather than as a log to grep.

Written 2026-09-04 against `mobile` at `6a50086` (v0.2.20). Sub-project #4 of
the desktop client, and the "privileged helper and IPC contract" that
[docs/specs/2026-08-24-desktop-control-api.md](./2026-08-24-desktop-control-api.md)
listed as out of its own scope. The consuming client's requirements are stated
in KVN's `docs/shoes-agent-prompt-desktop-daemon.md`; where that brief said
"decide", the choice made here is recorded in
[Decisions](#decisions-the-brief-left-open).

## Table of Contents

- [Problem](#problem)
- [Scope](#scope)
- [Why a daemon and not the Network Extension](#why-a-daemon-and-not-the-network-extension)
- [Division of labour](#division-of-labour)
- [What the library must gain](#what-the-library-must-gain)
- [Process shape](#process-shape)
- [The IPC surface](#the-ipc-surface)
- [Error mapping](#error-mapping)
- [macOS network setup](#macos-network-setup)
- [Crash recovery](#crash-recovery)
- [Install and lifecycle](#install-and-lifecycle)
- [Buffer sizing and RSS](#buffer-sizing-and-rss)
- [Security notes](#security-notes)
- [Testing](#testing)
- [Release artifact](#release-artifact)
- [Order of work](#order-of-work)
- [Decisions the brief left open](#decisions-the-brief-left-open)
- [Deliberately out of scope](#deliberately-out-of-scope)

## Problem

`shoes::control` gives a privileged host a real lifecycle — `prepare_from_config`
with a `DevicePolicy`, `start` with an exit callback, `status`, `stats::snapshot`,
a subscribable log sink, and a `stop` that reports whether the device was
released. Nothing consumes it. The control API spec verified the surface by
building an external crate against it and then deleted the crate, so the only
evidence that it works as a host-facing API is a test that no longer exists.

Meanwhile the macOS TUN path has never executed. `docs/MACOS.md` says so
outright, and the reason is structural rather than incidental: everything that
makes a TUN device usable — name, address, netmask, destination, `up()` — is
applied inside `#[cfg(target_os = "linux")]` in `create_sync_device`
(`src/tun/tun_server.rs:256`). On macOS today the crate opens a bare `utun`,
the kernel assigns a name nobody records, and the device carries no address.
`validate_tun_config` (`src/config/validate.rs:1918`) has arms for Linux,
Android, iOS and Windows and none for macOS, so that config is not rejected
either — it is accepted and then quietly does nothing.

So the daemon is not only new code. It is the first thing that will run the
macOS device path at all, and roughly a third of this work is making that path
exist.

## Scope

In this repository:

- **Library.** A macOS arm in `create_sync_device`; a macOS arm in
  `validate_tun_config`; and the created interface's name surfaced through
  `control::StatusSnapshot`.
- **A second binary**, `shoesd`, under `src/bin/shoesd/`, linking the library
  crate. Subcommands `run`, `install`, `uninstall`.
- **Host network configuration for macOS** inside that binary: routes, DNS, and
  reverting both — including after a crash.
- **The gRPC contract**, `proto/shoes/daemon/v1/daemon.proto`, owned here and
  vendored by consumers.
- **A release artifact** and the documentation that names it.

Out of scope is listed at the end. The two largest omissions are deliberate and
come from the consumer: no kill switch and no `pf` in v1, and no Linux or
Windows implementation of routes and DNS — the protocol must leave room for
them, the arms may return `unimplemented`.

## Why a daemon and not the Network Extension

The consumer's developer is on an Apple Personal Team. A system extension needs
`com.apple.developer.networking.networkextension` with
`packet-tunnel-provider-systemextension`, which is granted by request to Apple
and which `docs/MACOS.md` already records as unusable by a free Personal Team.
That closes the `ShoesTunnel` path until a team holds the entitlement.

It is not merely a fallback. KVN's survey of fourteen open-source macOS VPN
clients (`docs/macos-vpn-privilege-survey.md` in their tree) found the root
launchd daemon is the majority mechanism — Tunnelblick, OpenVPN Connect,
Mullvad, AmneziaVPN, the Clash family, `tailscaled` — and that Mullvad chose it
over an extension it was entitled to, because an extension cannot touch `pf`.
A kill switch is out of scope for v1, but it is the reason not to treat this
path as temporary.

The Network Extension work is untouched. `src/ffi/ios.rs` stays compiled for
macOS, the Swift package stays as it is, and the two hosts coexist: the
extension takes `DevicePolicy::BorrowedFd`, the daemon takes
`DevicePolicy::Owned`. Both shapes must therefore pass validation on macOS,
which is why the new validation arm accepts either and not one.

## Division of labour

The rule that has kept this codebase honest stays: **nothing under `src/`
touches routes, resolvers, `resolv.conf` or `SCDynamicStore`.** shoes moves
packets; the host owns the network. That is stated in `ROADMAP.md` under
desktop sub-project #4 and it is not being relaxed here — it is being staffed.
The daemon is a host, in the same seat as `NEPacketTunnelProvider` on iOS and
`VpnService` on Android. The only difference is that it is written in Rust and
links the library directly instead of crossing a C boundary.

That places the host code in `src/bin/shoesd/`, importing `shoes::` as an
ordinary dependent crate. This matters more than it looks. `src/main.rs`
re-declares the entire module tree (`mod address; mod amneziawg; …`) rather than
using the library, which is the source of the dead-code trap AGENTS.md warns
about — a module declared there but unused by the binary's code path fails
`-D warnings`. A binary that says `use shoes::control` inherits none of that: it
sees exactly the public surface, and anything it needs that is not public is a
compile error naming the thing to export. It also makes `shoesd` a permanent
in-tree replacement for the deleted external crate that once proved
`shoes::control` usable from outside.

The seam is narrow enough to state completely. The daemon calls
`control::prepare_from_config(yaml, DevicePolicy::Owned)`, `control::start`,
`ServiceHandle::status`, `control::stats::snapshot`,
`control::logs::BroadcastLogWriter::subscribe`, and `ServiceHandle::stop`. It
passes nothing else across, and the library learns nothing about routes.

## What the library must gain

Three changes, all small, all on the macOS path that has never run.

### 1. Device creation

`create_sync_device` gets a `#[cfg(target_os = "macos")]` arm. The rules come
from `tun` 0.8.14, read from the vendored source rather than from the docs,
because two of them are silent when violated:

- **The name must be `utunN` or absent.** `Device::new` parses `tun_name[4..]`
  as a `u32`, adds one, and uses it as the `sockaddr_ctl.sc_unit`; anything not
  starting with `utun` is `Error::InvalidName` and a non-numeric suffix is a
  parse error (`platform/macos/device.rs:84-95`). Absent means `sc_unit = 0`,
  which asks the kernel for the next free unit.
- **The address is applied only if `address`, `destination` and `netmask` are
  all present.** `Device::new` ends with
  `if config.platform_config.enable_routing && let (Some(a), Some(dest), Some(m)) = …
  { device.set_alias(a, dest, m)? }` (`:164-169`). Miss any one and the branch
  is skipped with no error at all, producing exactly today's failure: a device
  that exists, is up, and is reachable by nothing. This is why the validation
  arm below requires all three together rather than mirroring Linux's
  `device_name` + `address` pair.
- **`up()` is required.** `Configuration::up()` sets `enabled`, and
  `AbstractDevice::configure` turns that into `enabled(true)`, which ORs
  `IFF_UP | IFF_RUNNING` through `SIOCSIFFLAGS` (`platform/macos/device.rs:336`).
  Without it the interface never comes up.

**The crate installs a route of its own, and the flag that disables it does more
than it says.** `set_alias` ends by calling `set_route`, which shells out to
`route -n add -net <subnet>/<prefix> <dest>` (`platform/macos/device.rs:249-266`),
and macOS `enable_routing` defaults to `true` (`platform/macos/mod.rs:33-38`).
The obvious move is `platform_config(|p| p.enable_routing(false))` so that the
daemon owns every route it will later have to revert. The trap is that
`enable_routing` guards the whole `set_alias` call, not just its last line — so
turning it off also skips the `SIOCAIFADDR` that installs the point-to-point
alias.

What survives that is not nothing: `AbstractDevice::configure` runs
unconditionally first and applies the address (`SIOCSIFADDR`), destination
(`SIOCSIFDSTADDR`), netmask and MTU, then `up()`. Whether a `utun` configured
that way is usable without the additional alias is the one thing here that
cannot be settled by reading, because this path has never run. So: the daemon
sets `enable_routing(false)` and owns its routes, and **the first live bring-up
verifies the interface is usable**; if it is not, the fallback is to leave
`enable_routing` at its default and record the crate's on-link route as one the
daemon did not install and must not revert. That fallback is written into the
plan as a decision point rather than left to be rediscovered.

Either way the crate is not a security exception: it invokes `route` through
`run_command` with an argv array rather than a shell, which is the same rule the
daemon holds itself to.

### 2. Validation

A macOS arm in `validate_tun_config`, modelled on the Windows arm rather than
the Linux one, because Windows is the other platform where a missing field
produces a silently useless device and the arm is written to say so.

macOS differs from Windows in accepting both device shapes, since the Network
Extension provider is a real consumer of the same code:

- `device_fd` present — the NE shape. Nothing else required.
- `device_fd` absent — the daemon shape. `address`, `netmask` **and**
  `destination` are all required, with a message that says the address is
  applied as a point-to-point alias and is skipped entirely if any of the three
  is missing.
- `device_name`, if present, must match `utun` followed by digits. Rejecting it
  here turns the crate's opaque `InvalidName` into a message naming the rule.

### 3. The interface name

Routes and DNS need the `utunN` the kernel picked, and today it is discarded.
`src/tun/mod.rs:98` does `config.create_sync_device()?` immediately followed by
`.into_raw_fd()`, consuming the `Device` and with it the name;
`AbstractDevice::tun_name()` exists on the macOS device
(`platform/macos/device.rs:327`) and is simply never called.

The name is captured there and published through a
`Arc<parking_lot::Mutex<Option<String>>>` created in `control::start`, threaded
through `PreparedService` → `run_prepared` → `run_tun_from_config` →
`TunServerConfig`, and read back by `StatusSnapshot`, which gains
`device_name: Option<String>`. That field maps directly onto the protocol's
`Status.interface`.

**Why not let the daemon choose the name.** The brief offered that alternative,
and it loses to a race. Between scanning the interface list for a free `utunN`
and the crate's `connect()` on the chosen `sc_unit`, any other utun user — a
second VPN, a corporate client, Docker — can take it, and the failure is an
errno from `connect` with no retry logic anywhere near it. Asking the kernel
for unit 0 has no such window. The cost of the robust option is one field on
three structs that already thread config from the host to the device.

## Process shape

The daemon holds **two tokio runtimes**, and this is forced rather than chosen.
`ServiceHandle` owns the engine's runtime, and its documentation — repeated in
`docs/MACOS.md` — says it must be stopped from a blocking context and never
dropped inside another runtime, because `stop_handle` sleeps the calling thread
in a poll loop for up to `STOP_TIMEOUT` (5 s) and may drop the runtime inline.
A gRPC handler is the worst possible place to call that from.

So the daemon is structured around a **supervisor thread** that owns the
`ServiceHandle` and nothing else touches it:

- A plain `std::thread` running a `std::sync::mpsc` command loop:
  `Start(prepared, exclude, dns, reply)`, `Stop(reply)`, `EngineExited(reason)`.
- gRPC handlers send a command with a `oneshot` reply channel and await it. The
  channel is the serialization point, so a second `Start` while a session exists
  is answered `ALREADY_EXISTS` by the supervisor's own state machine rather than
  by a lock nobody holds consistently.
- `control::start`'s `on_exit` callback posts `EngineExited` to the same queue,
  so an engine that dies on its own and a `Stop` request converge on one revert
  path instead of two.
- The gRPC server runs on the daemon's own multi-thread runtime, which never
  owns a `ServiceHandle`.

The supervisor is also where the ordering that matters lives. On start: write
the revert state file, create the device, apply routes, apply DNS, spawn the
engine, publish `RUNNING`. On any failure after the first applied change, undo
in reverse and answer with the mapped error. On stop, or on `EngineExited`: stop
the engine, undo in reverse, publish `STOPPED` with the reason, and keep that
reason for the next `GetStatus`, since the GUI may not have been connected when
it happened.

## The IPC surface

gRPC over a Unix domain socket, `tonic` 0.14.6 on this side (0.14 split the
codec out, so the dependencies are `tonic`, `tonic-prost` and, in the build
script, `tonic-prost-build`), grpc-kotlin with Netty's kqueue transport on
KVN's. The `.proto` lives here and is vendored by the consumer, pinned to a
shoes release.

The service is the one the brief specifies, unchanged: `Hello`, `Start`, `Stop`,
`GetStatus`, and three server streams `WatchStatus`, `WatchStats`, `WatchLogs`.
Two notes where it meets the library:

- `Stats` is documented as cumulative since `RUNNING`, and that is exactly what
  the library provides rather than something the daemon must arrange:
  `control::start` calls `reset_counters()` before spawning, precisely so a
  second session does not report the first one's bytes.
- **One proposed amendment**, for the consumer to accept or decline:
  `Stats` gains `uint32 active_connections`. `control::stats::snapshot` already
  carries it behind `control-stats`, the daemon builds with that feature, and it
  is the one number a GUI wants that two byte totals cannot give. Nothing else
  in the schema changes; a client that ignores the field is unaffected.

**Authentication is peer credentials and nothing else.** The socket is
`/var/run/shoesd/shoesd.sock`, owner `root`, mode `0660`, group from an install
flag defaulting to `admin`. In its own directory, which the daemon creates
`0750` root:group -- `bind` takes no mode, so the socket exists at whatever the
umask allowed for an instant, and a connection made in that instant is queued
on the same listener and survives the mode being corrected. Reaching a socket
requires search permission on every directory above it, so the directory is
what closes that window; narrowing the umask instead would apply to every
other thread creating a file at the same moment. Every call reads the peer's uid and rejects one that is
neither 0 nor a member of that group with `PERMISSION_DENIED` — a returned
status, not a dropped connection, because a dropped socket is indistinguishable
from a daemon that is not running and the client would offer to install it
again. There is no token and no TLS, and **no TCP listener**: a loopback port is
reachable by every process on the machine, which is the Clash family's
weakness.

The shape in tonic 0.14 is a `UnixListener` wrapped in
`tokio_stream::wrappers::UnixListenerStream` — so `tokio-stream` is needed with
its `net` feature — handed to `serve_with_incoming_shutdown`, whose shutdown
future is what `SIGTERM` completes. Peer credentials arrive as
`tonic::transport::server::UdsConnectInfo` in the request extensions, `#[cfg(unix)]`
and behind no extra feature flag:

```rust
pub struct UdsConnectInfo {
    pub peer_addr: Option<Arc<tokio::net::unix::SocketAddr>>,
    pub peer_cred: Option<tokio::net::unix::UCred>,
}
```

Authorization reads `UCred::uid()`. `UCred::pid()` exists on Darwin but is
advisory — it races process reuse — so it may be logged and must not be trusted.

Two things the upstream example does not do and this daemon must. `UnixListener::bind`
fails with `EADDRINUSE` on a socket file left behind by a crash, so the path is
unlinked first. And `bind` honours the process umask rather than taking a mode,
so ownership and permissions are set explicitly immediately after binding,
before the listener accepts.

## Error mapping

gRPC status codes, message in `status.message`, because the client switches on
the code. The daemon produces exactly the six below that are not marked
reserved -- checked against the source rather than asserted, because a
documented code nothing returns is a promise a client writes a branch for:

| Code | When |
| --- | --- |
| `ALREADY_EXISTS` | `Start` while a session exists. Never a silent replace. |
| `NOT_FOUND` | **Reserved, and not currently produced.** The consumer's brief listed it for "something needing a session has none", but nothing needs one: `GetStatus` answers `STOPPED`, `Stop` answers `RELEASED`, and the watches stream nothing rather than failing. A client may switch on it; the daemon will not send it until a method exists that has no other answer. |
| `INVALID_ARGUMENT` | `prepare_from_config` failed — parse, validation, resolver. Message forwarded verbatim. |
| `FAILED_PRECONDITION` | The `utun` could not be created. |
| `UNAVAILABLE` | Routes or DNS failed. The daemon has already reverted what it applied. |
| `PERMISSION_DENIED` | Peer uid is neither root nor in the group. |
| `INTERNAL` | Everything else. |

`StopOutcome::TimedOut` is **not** an error and does not map to a code. It is
`StopReply.outcome = TIMED_OUT` on a successful call, preserving the distinction
the type exists to force: the engine did not confirm it released the device.
The daemon's own consequence is concrete — it does not delete the revert state
file on a `TimedOut` stop, so a subsequent start still knows there may be
routes to undo.

## macOS network setup

What the daemon does between device creation and `RUNNING`, and undoes in
reverse on stop or on any failure past the point it was applied.

**Interface.** `10.0.0.2` peer `10.0.0.1`, netmask `255.255.255.0`, MTU from the
config. These are the values the iOS provider uses, kept so that one config
behaves identically on both.

**The default route, split in two.**

```
route -q -n add -inet 0.0.0.0/1   -interface utunN
route -q -n add -inet 128.0.0.0/1 -interface utunN
```

Two halves rather than a replaced `default`, because they are more specific than
the physical interface's default and so win without deleting it — which means
the pre-tunnel default is still there to hang the exclusion routes off, and a
crash leaves a machine whose original default route was never touched. This is
also what wg-quick's `darwin.bash` does (`add_route`, and it likewise pins the
tunnel by `-interface` rather than by gateway).

**Exclusions.** One host route per address in `StartRequest.exclude` — the proxy
server, which the client resolves to a literal IP before sending — via the
pre-tunnel default gateway:

```
route -q -n add -inet <endpoint> -gateway <gateway>
```

This is not a preference. `bind_interface` is Linux/Android/Fuchsia only, and on
every other platform `socket_util::new_tcp_socket` reaches a
`panic!("Could not bind to device, unsupported platform.")`
(`src/socket_util.rs:187`) — unreachable only because `validate.rs:1164` rejects
the option first. `protect_outbound` is likewise a no-op here, since nothing
installs a protector outside the mobile FFI. So there is no per-socket escape on
macOS today, and without the host route the proxy's own connection routes into
the tunnel it is carrying.

**When there is no gateway, blackhole the endpoint.** wg-quick handles this case
explicitly, with the comment `# Prevent routing loop`:

```
route -q -n add -inet <endpoint> 127.0.0.1 -blackhole
```

It matters more than it looks. A machine on a link with no default gateway, or
one caught mid-transition between Wi-Fi and Ethernet, has an endpoint address
matched by nothing but the tunnel's own `0.0.0.0/1` — so the proxy's packets
enter the tunnel that is trying to carry them. Blackholing fails the connection
instead, which is recoverable; the loop is not.

**Finding the gateway, and noticing when it changes.** Two mechanisms for two
questions, which is the part this kind of code usually gets wrong:

- *What is the gateway?* The first `default` row of `netstat -rn -f inet`
  whose gateway is not a `link#N` pseudo-gateway, read fresh each time it is
  needed. This is what wg-quick does, and both alternatives lose. A `sysctl`
  `NET_RT_DUMP` dump avoids the text round-trip but means walking `rt_msghdr`
  and its sockaddr array in unsafe code that cannot be tested without root.
  And `route -n get default` is actively wrong: `route get` does a
  longest-prefix lookup for the address `0.0.0.0`, so once this daemon has
  installed `0.0.0.0/1` it answers with the tunnel — the very interface the
  exclusion exists to avoid. Matching the literal `default` destination cannot
  be fooled that way, and the parse is a pure function with tests.
- *Has it changed?* A `PF_ROUTE` socket, used purely as a signal — the same
  thing `route -n monitor` is underneath, and what wg-quick's `darwin.bash`
  uses. The daemon does not parse the delta; it re-reads the table and
  re-applies the exclusion routes if the gateway differs.
  (`src/bin/shoesd/host/macos/monitor.rs`, feeding `Command::NetworkChanged`
  so the re-apply is serialised with `Start` and `Stop` rather than racing
  them.)

Parsing routing messages to decide what changed is where the bugs live, and it
is unnecessary — a signal plus an idempotent re-read gives the same answer and
cannot drift. A Mac moving from Wi-Fi to Ethernet is the ordinary case this
serves, not an edge one.

**IPv6.** The utun has no v6 address in v1, so v6 traffic would leak to the
physical interface. Silent leak is not acceptable and silent blackhole is a poor
second — an app with a v6 route that never answers waits out its connect timeout
before falling back. The daemon installs `::/1` and `8000::/1` as **reject**
routes instead, so v6 fails immediately and Happy Eyeballs falls back to v4 at
once, and removes them on stop. Whether the reject route behaves that way on the
target macOS version is a verification item, not an assumption; the documented
fallback is a blackhole route, which is the form wg-quick uses and is therefore
known to work.

**DNS.** Through `SCDynamicStore` — `system-configuration` 0.8.0, Mullvad's
crate, whose own `set_dns` example is precisely this operation. The daemon reads
the `PrimaryService` property (`kSCDynamicStorePropNetPrimaryService`) of
`State:/Network/Global/IPv4`, then writes a dictionary keyed
`kSCPropNetDNSServerAddresses` to both
`State:/Network/Service/<primary>/DNS` and `Setup:/Network/Service/<primary>/DNS`.
The previous values are remembered — in the state file, not only in memory —
and restored on stop. `SCDynamicStore::set` returns `bool` rather than a
`Result`, so every call is checked.

Explicitly **not** `networksetup`, which is what wg-quick uses. Two reasons, and
the second is the one that decides it. Clash Nyanpasu's DNS has been broken that
way since macOS 14.3 (libnyanpasu/nyanpasu-service#26), because `networksetup`
addresses a service by display name; `SCDynamicStore` addresses it by id. And
wg-quick keeps its saved DNS state in shell variables, so a killed process can
never restore it — a daemon that must survive `kill -9` needs the backup on
disk regardless of which API writes it.

**Re-applying it.** macOS reverts DNS asynchronously a moment after a network
change, which wg-quick works around by re-running `set_dns` and then kicking
itself with `SIGALRM` two seconds later to do it again. The daemon does the same
thing without the signal: the route monitor reports a change once it has
settled, and again a couple of seconds later, and the supervisor writes the
resolvers on both.

That reuses one mechanism for two jobs, and it is why there is no
`SCDynamicStore` watcher. Watching the store would mean a dedicated thread
running `CFRunLoop::run_current()`, because
`SCDynamicStore::set_notification_keys` plus `create_run_loop_source` deliver
callbacks on a CFRunLoop that a tokio worker cannot drive — a second thread and
a second notification path for the same event the routing table already
reports. If a DNS change that is *not* accompanied by a routing change turns
out to matter, that watcher is the thing to add, and it posts the same
`Command::NetworkChanged`.

Finally, `mDNSResponder` is flushed (`killall -HUP mDNSResponder`, argv, no
shell).

The resolvers themselves are inside the tunnel by design — the client chooses
them and the daemon only advertises them.

## Crash recovery

A daemon that dies with routes applied leaves the Mac offline, and that is the
failure mode with the worst blast radius in this design.

Before the first privileged change, the daemon writes a root-owned state file
(`/var/db/shoesd/applied.json`, mode `0600`) describing everything it is about
to apply: the routes with their gateways, the DNS service id with the previous
resolver list, and the interface name. It is written and fsynced *before* the
change, not after, so the window where a change exists and is unrecorded is
closed rather than merely small.

On start, if the file exists, the daemon reverts what it describes before doing
anything else, then deletes it. `KeepAlive` in the launchd plist means a crash
is followed by a restart, so this runs within seconds without anyone logging
in. It is also idempotent: reverting a route that is already gone is not an
error.

The state file never contains the config YAML. See
[Security notes](#security-notes).

## Install and lifecycle

`shoesd install [--group admin]`:

1. Copy the running executable to `/Library/PrivilegedHelperTools/shoesd`,
   `root:wheel`, `0755`.
2. Write `/Library/LaunchDaemons/com.shoesproxy.daemon.plist`, `root:wheel`,
   `0644`, with `Label`, `ProgramArguments` and `KeepAlive`.
3. `launchctl bootstrap system /Library/LaunchDaemons/com.shoesproxy.daemon.plist`.

`uninstall` reverses it — stopping any session and reverting first, then
`launchctl bootout system/com.shoesproxy.daemon`, which addresses the service by
its `Label` rather than by path.

Three details that are behaviour rather than documented contract, and that this
class of installer routinely gets wrong. `KeepAlive` implicitly implies
`RunAtLoad`, so both need not be set (the plan sets both anyway, since it is
conventional and harmless). launchd refuses a plist — and the executable it
names — whose ownership or permissions are group- or world-writable, which is
the real rule behind the `root:wheel 0644` convention that every plist installed
on a stock system follows; the failure is an opaque bootstrap error, so
`install` checks the result of its own `chown`/`chmod` rather than assuming.
And a job that exits quickly and repeatedly under `KeepAlive` is throttled to
roughly one launch per ten seconds, which bounds how fast crash recovery can
loop and is the reason recovery must be idempotent rather than merely fast.

**The daemon is never run from the path it was invoked at.** That path is inside
a user-writable app bundle, and a root daemon whose binary a user can rewrite is
a privilege escalation, not a convenience. The label `com.shoesproxy.daemon`
follows the namespace the JNI entry points already use.

The daemon binds its own socket rather than taking a launchd-activated one.
`Sockets` in the plist is genuinely attractive — `SockPathOwner`, `SockPathGroup`
and `SockPathMode` would let launchd create the socket with the right ownership
before the process runs, closing the bind-and-then-chmod window described above.
It loses on two counts. Its purpose is on-demand launch, which is worthless for
a process that must run continuously to hold a tunnel and must run at boot to
perform crash recovery whether or not a client ever connects. And collecting the
descriptor requires hand-written FFI to `launch_activate_socket(3)`, including
freeing the array it allocates, for which no maintained Rust wrapper was found.
Paying `unsafe` to close a window that an explicit `chown`/`chmod` closes anyway
is the wrong trade.

Other lifecycle rules, all from the consumer: one session per daemon; a client
disconnecting does nothing to the session; `SIGTERM` stops the session, reverts,
and exits.

## Buffer sizing and RSS

`shoesd` is built with `--features daemon`, which pulls in `desktop`
(`control-stats` + `control-logs`) along with the gRPC stack, and **without**
`network-extension`, so `src/buffer_sizing.rs` gives it desktop sizing: a 1 MiB TCP send window and ~5.375 MiB per connection, per the v0.2.20
changes. That is the right budget for a root process on a Mac and the wrong one
for a 50 MB extension, which is exactly the split the two feature flags exist to
express.

It also makes this the first desktop-sized configuration ever to run on macOS.
`docs/MACOS.md` records the extension's memory budget as unknown and, on that
basis, builds the macOS NE slice with iOS's sizes. The daemon's idle and
under-load RSS is therefore a number to measure and write down, not to predict —
it is a verification item below, and the answer belongs in `docs/MACOS.md`.

Building it needs its own cargo invocation. Features are additive per build, so
`cargo build --release --features daemon` would also compile `control-stats`
and `control-logs` into the `shoes` CLI. The release job builds
`--bin shoes` with no features and `--bin shoesd --features daemon`
separately -- and the feature name is not interchangeable with `desktop`:
`[[bin]] shoesd` carries `required-features = ["daemon"]`, so
`--features desktop` refuses to build it at all.

## Security notes

**Nothing that crossed the socket is interpolated into a shell.** Where a step
runs a command it is `std::process::Command` with an argv array, and every
address in that array is a parsed `IpAddr` re-serialised — never a string
forwarded from the request. OpenVPN Connect shipped CVE-2026-9560 by doing
otherwise. The `tun` crate's own `run_command` already follows this shape, which
is why leaving its on-link route in place costs nothing here.

**The YAML is validated before anything privileged happens.**
`prepare_from_config` runs first, on the supervisor thread, and its failure is
`INVALID_ARGUMENT` with no device created and no route touched.

**The config carries credentials.** It is the user's own config and it crosses
from their session to root legitimately, but the daemon must not persist or
print it: it is not written to the state file, not logged at any level, and not
echoed in an error. `Redacted<T>` already keeps configured secrets out of
`Debug` output inside the library; the daemon's obligation is to not defeat that
by formatting the raw YAML.

**Log lines cross a privilege boundary.** They go to a user-session GUI, subject
to the same `Directive` filtering as every other sink — enabling a subscriber
must not raise the global level, and the sink does no redaction, because a line
that needs redacting is a bug at its call site. This fork has already had to fix
REALITY key material reaching the log, so this is a demonstrated risk.

**A slow log subscriber loses lines rather than stalling the writer.** That is
already `BroadcastLogWriter`'s behaviour and the daemon must not add buffering
that undoes it.

## Testing

The privileged parts are the ones that cannot run in CI, so the design puts them
behind a seam on purpose.

**`HostNetwork` trait.** Routes and DNS go behind one trait with a macOS
implementation and a recording double. That makes the sequencing testable
everywhere, and the sequencing is where the damage is: apply-then-fail must
revert in reverse order and leave nothing behind; a failure in DNS must undo the
routes; a second start must revert a stale state file first. These are unit
tests on all platforms, with no root and no device.

Also unit-testable, and worth it: the validation arm (each missing field
rejected with the message that names it); state-file round trip and idempotent
revert; the argv construction for every command the daemon runs, asserting the
vector rather than a formatted string, and asserting that an address in it came
from a parsed `IpAddr`; the error-to-status mapping table; and the peer-credential
predicate.

Per AGENTS.md, each new test is written first and watched to fail for the
expected reason.

**Live verification on Apple Silicon**, which the consumer will ask for:

1. `start` with a real AmneziaWG config, `curl` through the tunnel, `stop`, and
   `netstat -rn` plus `scutil --dns` identical before and after. Both diffs
   pasted.
2. `kill -9` the daemon mid-session; on restart, routes and DNS come back.
3. A call from a uid outside the group returns `PERMISSION_DENIED` as a status,
   not a dropped socket.
4. Daemon RSS idle and under a sustained download.
5. The full verification gate on macOS and Linux, plus the existing mobile link
   checks — the new binary must not pull `control-logs` into the mobile
   artifacts.

Live-run credentials follow the existing rule: a config outside the working
tree, deleted afterwards, and `git status` checked before committing.

## Release artifact

A separate `shoesd-macos-arm64.tar.gz`, not an addition to
`shoes-macos-arm64.tar.gz`. Three reasons: the two binaries are built with
different features and so cannot share a `cargo build`; the existing tarball's
consumers want a proxy CLI and should not silently start receiving a root
daemon; and the consumer's Gradle `DownloadShoesAssetTask` fetches by asset name
and verifies the SHA-256 the GitHub API reports, so a stable name per artifact
is what it wants. The name goes in the release notes and in `README.md`.

## Order of work

1. **Pin the IPC stack.** Add `tonic`, `tonic-prost`, `tonic-prost-build` and
   `tokio-stream`/`net`, write the `.proto`, and get an empty service answering
   on a `UnixListener` with peer credentials read and checked. First because
   everything else is easier to build against a socket that already answers.
2. **The library's three gaps** — device creation, validation, interface name —
   with their unit tests. Independently useful, and the only part that touches
   `src/`.
3. **`HostNetwork` and the recording double**: routes, DNS, state file, revert
   ordering. All the logic, none of the privilege.
4. **The macOS implementation** of that trait.
5. **The supervisor and the service methods**, including the streams.
6. **`install`/`uninstall`, the plist, and `SIGTERM`.**
7. **Docs and release**: `docs/MACOS.md`, `CONFIG.md`'s TUN platform notes,
   `README.md`, `ROADMAP.md` desktop section, `CHANGELOG.md`, an
   `examples/tun_macos.yaml` added to the macOS leg of the build workflow's
   smoke-test loop the way `tun_windows.yaml` is added to Windows'.
8. **Verification**: the full gate, then the five live items.

Steps 1 and 2 are independent and can go in either order; 3 gates 4 and 5.

## Decisions the brief left open

| Question | Decision | Why |
| --- | --- | --- |
| Interface name: daemon picks, or shoes reports? | shoes reports it, via `StatusSnapshot.device_name` | Picking races with any other utun user; `sc_unit = 0` cannot race |
| How to read the gateway? | Parse `netstat -rn -f inet`, skipping `link#N` rows | `route get default` returns the tunnel once `0.0.0.0/1` is installed; a `sysctl` dump is untestable unsafe code. Revised during implementation — the spec first chose sysctl |
| How to notice it changing? | `PF_ROUTE` only as a signal; re-read and re-apply | Never parse a routing delta; a signal plus an idempotent re-read cannot drift |
| Watch `SCDynamicStore` for DNS changes too? | No — the route monitor's second look covers it | A network change is what makes macOS revert DNS, and the routing table already reports that. A CFRunLoop thread for a second notification of the same event is added only if a DNS change without a routing change proves to matter |
| Exclusions before the tunnel routes, or after? | Before, and the gateway read before either | The other order leaves a window in which the proxy's address matches the tunnel and nothing else. Nothing is connected during it, so the cost is likely zero — which is not a reason to order it the dangerous way round |
| IPv6: leak or drop? | Neither — `::/1` and `8000::/1` as reject routes | Fails fast so Happy Eyeballs falls back at once, instead of waiting out a timeout on a blackhole |
| `IP_BOUND_IF` instead of exclusion routes? | Not in v1; recorded as the long-term answer | It needs a macOS arm where `socket_util` currently has an unreachable `panic!`, plus plumbing through every outbound constructor. The host route is needed for the gateway anyway |
| Close `Status::Starting` now? | No | The daemon reports its own `STARTING` — device, routes, DNS, engine spawn — which is the interval a GUI can see. The library's own starting window is the microseconds before `start` returns, and widening `Status` reaches mobile |
| Daemon in the existing tarball, or its own? | Its own, `shoesd-macos-arm64.tar.gz` | Different feature set, different build, different audience |
| Who owns the TUN section? | The daemon, through `control::prepare_from_config_owning_device` | The consumer's brief requires it and the proto promises it; it was documented and not implemented until a review caught it. A client sends one document for every platform with `device_fd: 0` as a stand-in, and a host that creates its own device cannot validate that shape -- it has to replace it. `mtu` stays the client's |
| IPv6 addresses in `exclude`? | Refused at `Start` with `INVALID_ARGUMENT` | The gateway lookup reads `netstat -rn -f inet`, so a v6 exclusion would fail the family check and be blackholed -- and with `::/1` rejected, the proxy would be unreachable behind a session that looked healthy. Carrying v6 is what would change this |
| launchd socket activation? | No; `KeepAlive`, daemon binds its own socket | The process must run continuously and must run at boot for crash recovery, and `launch_activate_socket(3)` needs hand-written FFI to close a window `chown`/`chmod` already closes |
| Let the `tun` crate install its route? | No — `enable_routing(false)`, daemon owns every route | One owner for everything the revert path must undo. Carries a live-verification obligation, since the same flag also skips the point-to-point alias |
| `networksetup` or `SCDynamicStore` for DNS? | `SCDynamicStore`, with the previous values saved to the state file | `networksetup` addresses a service by display name and has been broken since macOS 14.3; and a `kill -9`-survivable revert needs the backup on disk either way |

## Deliberately out of scope

- **No SOCKS or HTTP listener of any kind.** The consumer's founding rule.
- **No kill switch, no `pf` anchor, no split tunnelling.** The shape for a `pf`
  anchor is left open by keeping route and DNS application behind `HostNetwork`;
  nothing is built.
- **No Linux or Windows routes and DNS.** The protocol carries `capabilities`
  so a client can ask rather than infer, and those arms return `unimplemented`
  with a clear error. Linux is the awkward one — systemd-resolved, resolvconf,
  NetworkManager and a bare `/etc/resolv.conf` are four mechanisms — and it
  deserves its own spec.
- **No Network Extension changes.** `ShoesTunnel` stays exactly as it is.
- **No share-link parsing**, no tray, no GUI. Already placed in the GUI
  repository by the control API spec.
- **No IPv6 inside the tunnel.** Reject routes are the v1 answer; carrying v6
  needs a v6 alias on the utun and a stack path that has never been exercised.
- **No second concurrent session.** One per daemon, which matches the library's
  documented one-service-per-process invariant — the traffic counters in
  `src/tun/traffic.rs` are process-global statics.
