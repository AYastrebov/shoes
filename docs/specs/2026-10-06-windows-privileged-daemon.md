# The Windows privileged daemon

`shoesd` runs on macOS and Linux. This is its Windows 11 arm: a `LocalSystem`
service hosting `shoes::control` over the existing wintun backend, serving the
unchanged gRPC protocol on an AF_UNIX socket, and configuring routes and DNS
around the tunnel. It is the third consumer of the macOS design
([2026-09-04-macos-privileged-daemon.md](./2026-09-04-macos-privileged-daemon.md))
after Linux ([2026-09-04-linux-privileged-daemon.md](./2026-09-04-linux-privileged-daemon.md));
where this says nothing, those still apply.

The consumer is KVN, whose Windows client is already built against the
contract below (KVN repo: `docs/shoes-agent-prompt-windows-daemon.md`). Paths,
names and exit codes this spec fixes are ones KVN depends on.

## Table of Contents

- [Problem](#problem)
- [Scope](#scope)
- [Transport: AF_UNIX, measured](#transport-af_unix-measured)
- [Blockers inside shoes](#blockers-inside-shoes)
- [Paths, and who can create them](#paths-and-who-can-create-them)
- [Authorization](#authorization)
- [Routes](#routes)
- [DNS](#dns)
- [Route monitor](#route-monitor)
- [The service](#the-service)
- [Install](#install)
- [Testing](#testing)
- [Release artifacts](#release-artifacts)
- [To measure on a real host](#to-measure-on-a-real-host)
- [Deliberately out of scope](#deliberately-out-of-scope)

## Problem

KVN on Windows runs `SimulatedEngine`: it reports Connected and carries
nothing, because there is no daemon to drive. shoes already has the hard part
— the wintun backend, live-tested end to end
([2026-08-27-windows-tun-backend.md](./2026-08-27-windows-tun-backend.md)) —
and deliberately left the host half to "the privileged-helper sub-project".
This is that sub-project.

## Scope

In: a Windows `HostNetwork`; an AF_UNIX listener and a Windows peer check;
running under the Service Control Manager; `install`/`uninstall`; the three
fixes inside `src/tun/` and the supervisor that a Windows session needs; the
`shoesd-windows-<arch>.tar.gz` release assets; Windows in the daemon's CI.

Out: see the last section. Notably no kill switch and no IPv6 in the tunnel,
the same posture as the other two arms.

## Transport: AF_UNIX, measured

Earlier briefs assumed a named pipe. grpc-java and Netty have no named-pipe
transport, so KVN could not dial one. Windows 10 1803+ has AF_UNIX, and both
ends were measured on Windows 11 (2026-10-06):

- **Client.** KVN's `DaemonChannel` reaches AF_UNIX through Netty's
  `NioDomainSocketChannel` (JDK 16+); its `DaemonChannelTest` completes a
  `Hello` on Windows.
- **Server.** A throwaway tonic 0.14 server — `uds_windows::UnixListener` for
  bind/listen/accept on a dedicated thread, each accepted socket handed to
  tokio as a `TcpStream` via `from_raw_socket` — answered three `Hello`s from
  KVN's real client.
- **Peer identity.** `WSAIoctl(SIO_AF_UNIX_GETPEERPID)` on the accepted socket
  returned the client JVM's PID exactly (5092 = `ProcessHandle.current().pid()`).

Why a thread for accept: tokio's `UnixListener` is `cfg(unix)`, and std's
`TcpListener::accept` parses the peer address as inet and fails on AF_UNIX.
Reads and writes are fine through tokio's `TcpStream`: mio polls the socket
through AFD, which does not care about the address family.

`sockaddr_un.sun_path` is 108 bytes on Windows as elsewhere — measured: a long
temp path fails bind with "path must be shorter than SUN_LEN". The default path
below is 35.

## Blockers inside shoes

Found by reading, each with the file it lives in:

1. **The interface name is never published on Windows.** The supervisor waits
   for `shoes::tun::device_name()` (`supervisor.rs`, `await_interface`), but
   `set_device_name` is `cfg(any(unix, test))` and only the Unix device path
   calls it (`src/tun/mod.rs`). Every Windows `Start` would end with "no TUN
   device appeared within 10s". Fix: publish the name after `open_wintun`
   succeeds, and widen the `cfg`.
2. **`device_policy()` is Unix-shaped.** It sets no name and
   `destination: 10.0.0.1`; wintun requires a name and refuses `destination`
   (`src/tun/mod.rs`, `config/validate.rs`). `DeviceOverride`'s own doc already
   says a Windows host must supply both. Fix: a `cfg(windows)` policy with
   `device_name: "shoesd"`, `10.0.0.2/24`, no destination.
3. **No LUID or index is exposed.** Not fixed in shoes: the host resolves the
   adapter by alias with `ConvertInterfaceAliasToLuid`, the same way the other
   arms name an interface — keeps `src/` free of host-networking surface.

## Paths, and who can create them

| What | Path |
| --- | --- |
| Installed binary | `%ProgramFiles%\shoesd\shoesd.exe` |
| wintun.dll | `%ProgramFiles%\shoesd\wintun.dll` |
| Control socket | `%ProgramFiles%\shoesd\shoesd.sock` |
| Revert record | `%ProgramFiles%\shoesd\state\applied.json` |
| Install log | `%ProgramFiles%\shoesd\install.log` |

All under `%ProgramFiles%`, not `%ProgramData%`, for one reason: **any user
can create a subdirectory of `%ProgramData%`.** A standard user who
pre-created `shoesd\` there could bind a socket of their own before the daemon
is installed and receive every config a client sends — credentials included —
or seed a revert record that makes a SYSTEM process delete routes of their
choosing. `/var/run` and `/var/db` close this on Unix because only root can
write there; `%ProgramFiles%` is the Windows equivalent. KVN considered a
client-side owner check instead and could not do it robustly (no SID lookup
in the JDK; localised account names), so placement *is* the check.

`install` creates `shoesd\` with an explicit protected DACL — SYSTEM and
Administrators full control, Users read and execute — rather than inheriting.
The socket is the only thing a client touches; what access an AF_UNIX
`connect` checks on Windows is [to be measured](#to-measure-on-a-real-host),
and the socket file gets exactly that for Authenticated Users and no more.
The directory is never loosened to admit clients.

## Authorization

The Unix rule is "root, or a member of the admin group" — the set of users who
could have installed the daemon anyway, so membership grants nothing new. The
Windows translation: **the peer is `LocalSystem`, or its token carries
`BUILTIN\Administrators` (S-1-5-32-544).**

The trap is UAC. KVN runs unelevated, and an administrator's unelevated token
carries the Administrators SID as **deny-only** (`SE_GROUP_USE_FOR_DENY_ONLY`).
An ACL granting Administrators therefore admits nobody but elevated processes,
and a check that asks "is Administrators *enabled*" refuses every real
client. The check looks at membership in any state — enabled or deny-only —
because that is the property that means "this user could have installed it".

Mechanics, per accepted connection:

1. `WSAIoctl(SIO_AF_UNIX_GETPEERPID)` → PID (measured above).
2. `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` → `OpenProcessToken`
   (`TOKEN_QUERY`) → `GetTokenInformation(TokenUser)` and `(TokenGroups)`.
3. Allowed iff the user SID is `S-1-5-18`, or any group equals the
   Administrators SID (`EqualSid` against `CreateWellKnownSid`).

The PID is only a number, so the lookup is bound to the connection: the
accept time is taken as soon as `accept` returns, and the process opened for
that PID must have been created before it (`GetProcessTimes`), its handle
held while the token is read. A client that exits in between is refused --
either there is no process to open, or the PID's new owner was born after the
accept and so cannot be the peer.
The result rides into each request as a `Connected::ConnectInfo`, and
`check_peer` reads it instead of `UdsConnectInfo`. Refusal stays a gRPC
`PERMISSION_DENIED` per call, never a dropped socket. The pure decision —
"user SID, group SIDs → allowed?" — is a function tested on every platform,
as `authorize()` is today.

## Routes

The plan is unchanged (`host/plan.rs`): exclusion host routes via the old
gateway, `0.0.0.0/1` and `128.0.0.0/1` into the tunnel, `::/1` and `8000::/1`
refused. The Windows `HostNetwork` implements it over the **IP Helper API**
rather than `route.exe`/`netsh`: those print localised text, and the other two
arms' error matching ("No such process", "not in table") has no stable
Windows counterpart to match. `windows-sys` is already a dependency.

- `default_gateway`: `GetIpForwardTable2(AF_INET)`, the `0.0.0.0/0` rows with a
  non-zero next hop, lowest `Metric + interface metric` wins — the same
  question `ip route show default` answers by lowest metric.
- `add_route` / `delete_route`: `CreateIpForwardEntry2` / `DeleteIpForwardEntry2`
  with `MIB_IPFORWARD_ROW2`. `Via::Interface(alias)` resolves the LUID with
  `ConvertInterfaceAliasToLuid`; `Via::Gateway` uses `GetBestRoute2` to find
  the interface that reaches the gateway. Delete maps `ERROR_NOT_FOUND` (and a
  vanished interface) to success, as the trait requires. Routes are not
  persistent: `CreateIpForwardEntry2` writes the active store only, so a
  reboot cannot leave one behind.
- `Via::Blackhole` and `Via::Reject`: Windows has neither route type. Both are
  a route to the loopback interface (`Loopback Pseudo-Interface 1`), which
  drops anything not addressed to itself. That makes `Reject` a blackhole;
  whether IPv6 then fails fast or waits out a timeout is
  [to be measured](#to-measure-on-a-real-host) and recorded, since it decides
  how long Happy Eyeballs stalls.

## DNS

`primary_dns_service(interface)` returns the **tunnel adapter's alias**, as on
Linux: resolvers go on the tunnel's own interface, which nothing else
rewrites. `read_dns` reports what it has (nothing, on a fresh adapter).

That alone leaks. **Smart multi-homed name resolution** sends each query out
of every interface in parallel and takes the first answer, so the local
resolver still sees every hostname — the exact leak a client's encrypted-DNS
setting exists to prevent. So `write_dns` with servers also adds a **Name
Resolution Policy Table rule for `.`** naming them, and `write_dns` with an
empty list (the revert) removes it:

- Set: `SetInterfaceDnsSettings` on the adapter's GUID, then
  `Add-DnsClientNrptRule -Namespace "." -NameServers <ips> -Comment shoesd`.
- Revert: `Remove-DnsClientNrptRule` for rules whose comment is `shoesd`. A
  missing rule or a missing adapter is success.

NRPT through PowerShell's `DnsClient` module, run by absolute path
(`%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`) with argv-only
arguments built from parsed `IpAddr`s — nothing user-typed reaches it. It is
the documented interface; writing `DnsPolicyConfig` in the registry directly
works but bypasses the notification the cmdlet sends. The rule lives in the
revert record through the existing DNS backup, so a crash leaves it to be
removed by `recover`, not forever.

`flush_dns_cache`: `DnsFlushResolverCache` is undocumented; `ipconfig
/flushdns` by absolute path is what is used.

`capabilities()` reports `["routes", "dns", "dns-backend:nrpt"]`, the last
following Linux's `dns-backend:<name>` so a client can log which ran.

## Route monitor

`NotifyRouteChange2(AF_UNSPEC)` and `NotifyIpInterfaceChange`, feeding the same
`on_change` callback with the same settle (300 ms) and second look (2 s) the
netlink and PF_ROUTE monitors use — Windows delivers bursts on a Wi-Fi to
Ethernet change exactly as they do. The callbacks run on a system thread pool
and only post to a channel; the existing monitor thread shape drains it.

## The service

`shoesd service` is what the SCM runs: `windows-service`'s dispatcher, a
control handler mapping Stop and Shutdown onto the same shutdown future SIGTERM
drives on Unix, and `SERVICE_RUNNING` reported once the socket is bound.
`shoesd run` stays a console mode (Ctrl-C) for development, as on the other
two. The service is **`shoesd`**, `LocalSystem`, automatic start, with SCM
recovery actions restarting it — the counterpart of `Restart=always`.

## Install

KVN raises UAC with `Start-Process -Verb RunAs` and waits; `shoesd install`
needs only to work when elevated, as `sudo shoesd install` does elsewhere.

1. Refuse unless elevated (`TokenElevation`).
2. Create `%ProgramFiles%\shoesd\` with the DACL above.
3. Stage and copy the running executable to `shoesd.exe` there — **never run
   from the invoked path**, which is inside a possibly per-user, user-writable
   app install. The existing `stage()` discipline (remove a leftover staged
   file, write, rename) carries over.
4. Copy `wintun.dll` from beside the invoked executable to beside the
   installed one, or fail with the exit code that names it. **shoes does not
   ship the DLL** — the existing decision for the CLI's Windows release
   (`build.yml`): it is WireGuard's signed binary under its own license — so
   the packager supplies it. KVN's MSI carries it next to `shoesd.exe`, fetched
   from wintun.net with a pinned SHA-256. Embedding it in `shoesd.exe` was
   considered and declined for the same reason. shoes verifies the DLL's
   Authenticode signer when loading it, so the copy is checked where it
   matters regardless of who shipped it.
5. Create (or reconfigure) and start the service, then wait for `RUNNING`.

**Exit codes are the only feedback** — `Start-Process -Verb RunAs` cannot
redirect the elevated child's output — so `install` uses distinct codes and
writes `install.log`:

| Code | Meaning |
| --- | --- |
| 0 | installed and running |
| 2 | not elevated |
| 3 | could not create or secure the install directory |
| 4 | could not copy the binary |
| 5 | no wintun.dll available |
| 6 | service could not be created or configured |
| 7 | service did not reach RUNNING |

Never 1223: that is `ERROR_CANCELLED`, which KVN reads as "the UAC prompt was
dismissed". When the service starts but stops before listening, `install`
says so at once and points at the service's log, `%ProgramFiles%\shoesd\logs\
shoesd.log` -- under the SCM nothing captures stderr, so the service also
logs to that file, in a directory only SYSTEM and Administrators can read
(the Unix arms keep their logs from other users the same way).

`uninstall` stops the service (which reverts a running session), deletes it,
then replays any revert record still on disk through `Session::recover`
before removing the directory. The replay is for a service that had already
crashed: stopping a stopped service reverts nothing, and the record --
found at the `--state` the service was registered with -- is the only thing
that knows which routes and NRPT rule to remove. A failed replay stops the
uninstall with the record kept, so it can be run again.

## Testing

What runs everywhere, in CI, unprivileged: the pure authorization decision;
route-row construction from `Route` (prefix, next hop, loopback for
blackhole); default-gateway selection from a synthetic forward table; NRPT
argv construction; the exit-code table. `Session` ordering is already covered
by `host/double.rs` and needs nothing new.

What runs on Windows unprivileged: bind/accept/peer-PID over a real AF_UNIX
socket in a temp directory, with a real tonic client — the server half of the
measurement above as a test.

What needs Administrator and a real adapter, `#[ignore]`d and run by hand as
the TUN backend's adapter test is: add/delete a route on a real wintun
adapter; NRPT add/remove; the live end-to-end run below.

## Release artifacts

`shoesd-windows-x86_64.tar.gz` and `shoesd-windows-arm64.tar.gz`, each a single
bare `shoesd.exe` (no wintun.dll, as for the CLI), built with `--features
daemon` on the existing `windows-latest` and `windows-11-arm` runners. CI
gains the daemon feature on Windows in `test.yml`, and a Windows entry in
`lint.yml`'s daemon clippy matrix that also runs the default-feature clippy
Windows had no job for.

## To measure on a real host

Recorded here and answered in the plan's verification section; none is
assumed in code beyond the fallback named.

1. Which access right a Windows AF_UNIX `connect` checks on the socket file,
   and therefore the minimum ACE for Authenticated Users.
2. Whether a loopback route makes IPv6 fail fast or time out.
3. That NRPT for `.` stops port-53 traffic on the physical adapter (capture).
4. That an unelevated administrator's KVN connects and a standard user's
   process is refused — the deny-only case.
5. A live run: start with a real config, traffic through the tunnel, stop,
   `route print` and `Get-DnsClientNrptRule` identical before and after; and
   the same after killing the service mid-session.

## Deliberately out of scope

- **Kill switch.** WFP is the mechanism; left as `pf`/`nftables` are left.
- **IPv6 in the tunnel.** Refused, as on the other two.
- **Named pipes.** See [Transport](#transport-af_unix-measured).
- **MSI-time service registration.** KVN's installer is a jpackage MSI with no
  service hook; the in-app `install` flow is the same on all three platforms.
- **Exposing LUID/index from `src/`.** The host resolves by alias.
- **Choosing a policy other than "Administrators".** Interactive users, or the
  installing user, are defensible; the Unix arms' rule translated is the one
  that grants nothing new.
