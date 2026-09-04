# The macOS privileged daemon — implementation plan

Spec: [docs/specs/2026-09-04-macos-privileged-daemon.md](../specs/2026-09-04-macos-privileged-daemon.md).
Kept in sync with reality; a step is marked done when its verification has run.

Steps 1 and 2 are independent. Step 3 gates 4 and 5. Nothing before step 8 needs
root or a Mac with a working tunnel, which is deliberate — the privileged parts
are behind a trait so the logic lands and is tested before the first live run.

## Steps

1. **The IPC stack, answering.** Dependencies: `tonic` 0.14, `tonic-prost`,
   `tokio-stream` with `net`, and `tonic-prost-build` + `prost` under
   `[build-dependencies]`, all under `[target.'cfg(target_os = "macos")'.dependencies]`
   so no other target's build or lockfile resolution grows a gRPC stack. New
   `proto/shoes/daemon/v1/daemon.proto` carrying the service from the spec, plus
   the proposed `Stats.active_connections`. A `build.rs` that compiles it only
   for macOS. `src/bin/shoesd/main.rs` with a `run` subcommand that binds
   `/var/run/shoesd/shoesd.sock` — unlinking a stale path first, then `chown` to
   `root:<group>` and `chmod 0660` before accepting — and serves a `Hello` that
   answers with version and capabilities. An interceptor rejects a peer whose
   `UCred::uid()` is neither 0 nor in the group, with `PERMISSION_DENIED`.
   Verification: `grpcurl` (or a small Rust client test) gets `HelloReply` as a
   non-root member of the group and `PERMISSION_DENIED` as a non-member; the
   full gate on macOS and Linux, with the Linux build proving the macOS-only
   dependencies really are macOS-only.

2. **The library's three gaps.** `#[cfg(target_os = "macos")]` arm in
   `create_sync_device` (`src/tun/tun_server.rs`) applying `tun_name`,
   `address`, `netmask`, `destination`, `up()`, and
   `platform_config(|p| p.enable_routing(false))`. A macOS arm in
   `validate_tun_config` (`src/config/validate.rs`) accepting either
   `device_fd` (the NE shape) or `address` + `netmask` + `destination` together
   (the daemon shape), and rejecting a `device_name` that is not `utun` followed
   by digits. The interface name captured from `AbstractDevice::tun_name()` at
   `src/tun/mod.rs:98` before `into_raw_fd()` consumes the device, published
   through an `Arc<Mutex<Option<String>>>` threaded `control::start` →
   `PreparedService` → `run_prepared` → `run_tun_from_config` →
   `TunServerConfig`, and read back as `StatusSnapshot::device_name`.
   Verification: unit tests over the validation arm — each missing field
   rejected with the message naming it, both accepted shapes accepted, a bad
   `device_name` rejected — each written first and watched to fail. The FFI
   feature configurations from AGENTS.md, since this touches `src/tun/` and
   `src/config/`.

3. **`HostNetwork` and its recording double.** A trait covering exactly the
   privileged operations: read the default gateway, add and delete a route, read
   and write the DNS of the primary service, flush the resolver cache. An
   `AppliedState` type that serialises to the state file, and the apply/revert
   sequencer over both. All of it platform-neutral, so it compiles and tests
   everywhere. Verification: unit tests for revert ordering (a DNS failure
   undoes the routes; a route failure undoes the routes already added and
   nothing else), idempotent revert (deleting an absent route is not an error),
   state-file round trip, recovery from a stale file at startup, and the argv
   built for every command — asserted as a vector, with each address
   re-serialised from a parsed `IpAddr`. Prove each test can fail.

4. **The macOS implementation** of that trait. Gateway by parsing
   `netstat -rn -f inet`, skipping `link#N` pseudo-gateways. Routes through
   `Command` with argv: the `0.0.0.0/1` + `128.0.0.0/1` pair by `-interface`,
   exclusions by `-gateway`, the no-gateway case as `-blackhole` via `127.0.0.1`,
   and `::/1` + `8000::/1` as reject routes. DNS through
   `system-configuration` 0.8: `PrimaryService` from `State:/Network/Global/IPv4`,
   `kSCPropNetDNSServerAddresses` written to both the `State:` and `Setup:` keys,
   every `set` return value checked. A `PF_ROUTE` socket and a CFRunLoop thread
   as change signals, both posting to the supervisor rather than acting.
   `killall -HUP mDNSResponder` to flush.

5. **The supervisor and the service.** A `std::thread` owning the
   `ServiceHandle`, driven by an `mpsc` of `Start`/`Stop`/`EngineExited`, with
   gRPC handlers sending a command plus a `oneshot` reply. `control::start`'s
   `on_exit` posts `EngineExited` so a spontaneous death and a requested stop
   share one revert path. Then the streams: `WatchStatus` (current state first),
   `WatchStats` (at `interval_ms`, only while `RUNNING`), `WatchLogs` (backlog
   then live, from `BroadcastLogWriter::subscribe`). The error-mapping table from
   the spec. Verification: a client test driving start → status → stop against a
   `HostNetwork` double and a config with no TUN section, asserting the state
   sequence, that a second `Start` is `ALREADY_EXISTS`, that `Stop` with nothing
   running is `RELEASED` rather than an error, and that a `TimedOut` stop leaves
   the state file in place.

6. **`install` / `uninstall` / signals.** Copy the running executable to
   `/Library/PrivilegedHelperTools/shoesd` as `root:wheel 0755` — never running
   from the invoked path — write the plist as `root:wheel 0644` with `Label`,
   `ProgramArguments` and `KeepAlive`, and `launchctl bootstrap system <plist>`.
   `uninstall` stops, reverts, `launchctl bootout system/<label>`, and removes
   both files. `SIGTERM` completes the `serve_with_incoming_shutdown` future,
   which stops the session and reverts before exit. Every `chown`/`chmod` result
   is checked rather than assumed.

7. **Docs and release.** `docs/MACOS.md` gains the daemon as a second host
   alongside the extension, and the RSS figures from step 8. `CONFIG.md` gains
   the macOS TUN requirements (all three address fields, `utunN` naming) beside
   the existing Windows notes. `README.md` and `ROADMAP.md`'s desktop section
   record sub-project #4 as done and name the new asset. `CHANGELOG.md`.
   `examples/tun_macos.yaml`, added to the macOS leg of `build.yml`'s smoke-test
   loop the way `tun_windows.yaml` is added to Windows'. A `shoesd-macos-arm64.tar.gz`
   release job building `--bin shoesd --features daemon` in its own cargo
   invocation, so the `shoes` CLI keeps its feature-free build.

8. **Verification.** The full gate on macOS and Linux, including the `ffi` and
   `desktop` configurations, plus the mobile link checks — `control-logs` must
   not reach the mobile artifacts. Then the five live items on Apple Silicon:
   a real AmneziaWG session with `curl` through it and `netstat -rn` +
   `scutil --dns` diffs before and after; `kill -9` mid-session and recovery on
   restart; `PERMISSION_DENIED` from a uid outside the group; daemon RSS idle
   and under sustained download. Live-run credentials stay outside the tree and
   `git status` is checked before committing.

## Open decision, to be settled by the first live bring-up

`enable_routing(false)` (step 2) also skips the `SIOCAIFADDR` point-to-point
alias, not just the crate's `route` call — the flag guards the whole `set_alias`
branch. `AbstractDevice::configure` still applies address, destination, netmask,
MTU and `up()` through the individual `SIOC*` ioctls, and whether that is enough
for a usable `utun` cannot be settled by reading, because this path has never
run.

If step 8's first bring-up gives an interface that will not pass traffic, the
fallback is to restore `enable_routing` to its default and treat the crate's
on-link route as one the daemon did not install and must not revert. Record
which way it went here, with what was observed.

## Review findings, addressed

A `/code-review high` over the branch's own commits found seven, all real. The
two that mattered:

- **The daemon hung forever when `serve` failed during setup.** `Inner` holds a
  clone of its own command sender, so the receive loop never sees a closed
  channel — only `Command::Shutdown` ends the thread. `serve` sent that after
  serving, past two `?` returns (an unknown group, a socket it cannot bind), so
  a mistyped `--group` gave a process that printed nothing, exited never, and
  looked alive to launchd's `KeepAlive`. The caller now sends it on every path
  out.
- **`delete_route` turned every failure into success**, not just "not in
  table". A revert blocked by EPERM was therefore reported clean, the record
  deleted, and the Mac left with its default routed into a utun that no longer
  exists — the exact failure the record exists to prevent. Only an absent route
  counts now, matched on the message.

The rest: a failed recovery could be overwritten by the next `apply` (a start
is refused until it succeeds, and retries); the `getgrouplist` retry was a
no-op on Darwin, locking out anyone in more than 32 groups; `getpwuid` is
non-reentrant and ran on concurrent gRPC workers (now `getpwuid_r`); the plist
interpolated paths and the group name into XML unescaped; and a client `Stop`
erased the reason an engine death had recorded, which is the only place a
tunnel's cause of death is reported.

## KVN's review of PR #20, addressed

The consumer reviewed at `7404581` and accepted the contract. Four findings.

- **The gateway-change monitor was described in three places and did not
  exist** — the spec's decision table, the spec's network-setup section, and a
  comment in `plan.rs` claiming the caller re-applies exclusions. Step 4 above
  described the signal threads and was checked off without them. That is the
  worst shape a comment can take: the next reader budgets for behaviour the
  code does not have. Implemented rather than deleted, because it is the
  ordinary case — a laptop moving from Wi-Fi to Ethernet leaves the exclusion
  route pointing at a router that is gone, and the proxy connection dies with
  the tunnel still nominally up. `src/bin/shoesd/host/macos/monitor.rs` reads a
  `PF_ROUTE` socket purely as a signal and posts `Command::NetworkChanged`;
  `Session::reapply` re-reads the table, compares, and swaps the exclusions if
  the gateway moved. It reports twice per change — once settled, once a couple
  of seconds later — which also covers the resolvers macOS restores on its own
  schedule, and is why no `SCDynamicStore` watcher was added.
- **Exclusions now go on before the tunnel routes**, with the gateway read
  before either. The reviewer was right that the window was probably harmless
  and equally right that it is not a reason to keep it.
- **The staged binary is created at 0600** rather than copied and then
  tightened: `std::fs::copy` carries the source's permission bits across.
- **The log moved to `/var/log/shoesd/`, 0750 root:wheel.** launchd creates the
  file it is pointed at as 0644, and a log every local user can read undoes the
  care `WatchLogs` takes.
- **Every tool is named by absolute path.** `shoesd install` and `shoesd run`
  under `sudo` inherit the invoker's `PATH`.

## Second review pass, addressed

A `/code-review high` over the branch found ten. One was already fixed
(`clear_device_name`, `d3c950f`); two were wrong (`crate::config::tun` resolves
through `pub use types::*`, which CI proves on five runners). The rest:

- **The revert record was deleted even when the revert failed** — clearing was
  gated on `StopOutcome::device_released()` alone, contradicting the invariant
  `delete_route`'s own comment states. A `route delete` blocked by EPERM would
  have erased the only record of routes still pointing into a utun about to
  disappear. Now the record survives, and `recovery_pending` blocks the next
  start until it can be finished.
- **A failed `apply` whose own revert also failed left an orphan record** that
  the next start would overwrite on its first route, destroying the DNS backup.
  The file's presence after a failed apply is now the signal to set
  `recovery_pending`.
- **The daemon never owned the TUN section**, though the consumer's brief
  requires it and the proto promised it: a client sending `device_fd: 0` as the
  documented stand-in got `INVALID_ARGUMENT` on every `Start`. Added
  `control::prepare_from_config_owning_device`, mirroring the existing
  `_with_fd` entry point for the other kind of host.
- **`WatchStats` leaked a task per connection** opened against an idle daemon:
  the only thing that observed a closed channel was a send the not-running
  branch skips.
- **Restoring "no resolvers" was not idempotent** — `SCDynamicStore::remove`
  answers `false` for an absent key as well as a failure, which would have left
  a DHCP machine permanently unable to start after a partial revert.
- **An IPv6 exclusion was silently blackholed**, since the gateway lookup reads
  `-f inet` only. Refused at `Start` instead; carrying v6 is what would change
  that.
- **A `Runtime::new()` failure wedged the state machine in `Starting`**, so
  every later `Start` answered `ALREADY_EXISTS`.
- **The route monitor died permanently on `ENOBUFS`**, which is exactly what a
  burst produces while it sleeps between its two looks.
- **`install`/`uninstall` exited 0 in silence**, because only `run` installs a
  logger.

## What CI caught that the review did not

The device override landed applied *after* `create_server_configs`, so the
per-platform arms in `validate_tun_config` judged the client's document as
written. Windows refuses a `device_fd` outright, so both Windows unit-test jobs
went red; macOS had passed only because its arm short-circuits when a
descriptor is present. The override now runs on the parsed configs before
validation, which is the only position where it can do what it promises.

`DeviceOverride` was also macOS-shaped: it cleared `device_name` and set
`destination`, and Windows requires the first and refuses the second. It now
carries `device_name`, and every field is replaced rather than merged -- a
document written for another host holds values that are wrong here rather than
absent.

Two things this is a reminder of. Adding a macOS-only feature still needs the
other platforms' arms thought through, because the library half is shared. And
the macOS runner added in this branch would not have caught it: the bug was
visible only where the arm does *not* short-circuit.

## Status

- [x] 1. IPC stack answering on the socket, peer check enforced (`HEAD`).
  Nineteen tests; the peer check and the stale-socket rule each proven able to
  fail. Three things the plan had not anticipated:
  - `getgrouplist` echoes the base gid back into the list it fills, so passing
    a fixed `0` would have reported every caller as a member of gid 0 — and
    gid 0 is `wheel`, a plausible `--group`. It takes the peer's real primary
    gid instead. Checking only `UCred::gid()` would also have rejected every
    macOS administrator, whose primary group is `staff` and whose `admin` is
    supplementary.
  - The socket is chowned with `-1` for the uid rather than `0`. The daemon
    runs as root so the file is already root-owned; naming root explicitly
    would have made this the one step that cannot run outside production, and
    it is the step whose correctness most wants a test.
  - Feature cfgs *do* reach build scripts, so `build.rs` gates on
    `#[cfg(feature = "daemon")]`. The `CARGO_FEATURE_*` env var does not help
    on its own: the reference to the optional build dependency still has to
    compile.
- [x] 2. Library gaps: macOS device creation, validation arm, interface name
  (`d0a5aa1`). Nine tests, each proven able to fail by reintroducing its
  defect. Two things the plan had not anticipated, both fixed in the same
  commit:
  - A TUN entry was recognised only by `device_name` or `device_fd`, so the
    shape the daemon writes — no descriptor, and deliberately no name — parsed
    as a *server* config. `netmask` and `destination` joined the
    discriminators; both are fields only `TunConfig` has.
  - `destination` is warned about, not required. The crate hazard that would
    have justified demanding it (the all-three-or-silently-skip alias) is not
    on the path shoes takes once `enable_routing` is off, and requiring it
    would have made macOS the only platform whose valid config Windows
    refuses. The 14 test failures that surfaced this were each correct.
- [x] 3. `HostNetwork` trait, state file, revert sequencing + tests (`HEAD`).
  Eighteen tests over a recording double; the five sequencing rules each proven
  able to fail (revert order, revert-on-failed-apply, revert not stopping at
  the first failure, the no-gateway blackhole, and record-before-apply). Two
  refinements to what the plan described:
  - `apply` reverts the route whose *install* failed, not only the ones before
    it. That is record-before-apply showing through: the route was written down
    before it was attempted, so a crash between those moments leaves it
    described. `delete_route` is therefore required to treat an absent route as
    success, which is now part of the trait's contract.
  - The exclusion gateway is family-checked. A machine with only an IPv6
    default route would otherwise get a v4 host route through a v6 gateway,
    which the kernel rejects with an error that explains nothing; it blackholes
    instead.
- [x] 4. macOS implementation of `HostNetwork` (`HEAD`). Fourteen tests over
  the pure halves — the routing-table parse and the argv for every command —
  plus three that read the real `SCDynamicStore`. One decision reversed and one
  test found to be worthless:
  - **The gateway is read by parsing `netstat -rn`, not a `sysctl NET_RT_DUMP`
    dump.** The spec chose sysctl to avoid a text round-trip. But walking
    `rt_msghdr` and its sockaddr array is unsafe code that cannot be tested
    without root, and the alternative the spec named — `route -n get default`
    — is actively wrong here: `route get` does a longest-prefix lookup for
    `0.0.0.0`, so once this daemon installs `0.0.0.0/1` it answers with the
    tunnel, which is the interface the exclusion exists to avoid. Matching the
    literal `default` destination in the table cannot be fooled that way, is a
    pure function with tests, and is what wg-quick does.
  - The first `link#`-filter test passed with the filter removed: the fixture
    captured from this machine happens to list the real gateway before the
    tunnel's row. A second fixture with the order reversed is what actually
    pins the rule.
- [x] 5. Supervisor, service methods, streams (`HEAD`). Sixty-six daemon tests,
  including gRPC round-trips over a real Unix socket for `Stop`, `GetStatus`,
  a rejected `Start` and `WatchStatus`. Three things the plan had not
  anticipated:
  - **The host is built on the supervisor thread, not moved onto it.**
    `SCDynamicStore` is a CoreFoundation object behind a raw pointer and so not
    `Send`. `Supervisor::spawn` takes a factory and waits for it to report, so
    "the configuration store would not open" fails the daemon's startup rather
    than returning a supervisor about to die.
  - **The interface name has to be waited for.** `control::start` returns once
    the service task is spawned, which is before the TUN device exists — and
    routes are addressed to the interface. The supervisor polls
    `shoes::tun::device_name()` to a 10 s deadline, failing the start rather
    than applying routes to an interface that is not there. Threading a channel
    out through `run_tun_from_config` would put a daemon's concern into code
    four other hosts share.
  - **A stop that timed out keeps the record.** `StopOutcome::TimedOut` means
    the engine never confirmed it released the device, so the next start must
    still know there may be something to undo. That is the decision the type
    exists to force, and it is now made in `Inner::revert` rather than
    discarded.
- [x] 6. `install`/`uninstall`/`SIGTERM` (`HEAD`). Seven tests over the
  rendered plist and the root check, each proven able to fail. Two details
  worth keeping:
  - The binary is staged as `shoesd.new` and renamed into place rather than
    written over. Overwriting a running executable is how a copy that is half
    old and half new gets executed.
  - `install` boots the old job out before bootstrapping the new plist, so
    installing over an existing install is not refused as "already loaded".
    `uninstall` relies on `bootout` sending `SIGTERM`, which is what makes the
    daemon revert its routes and DNS through the same path a shutdown uses
    rather than a second one written for the occasion.
- [x] 7. Docs, example, release job (`HEAD`). `docs/MACOS.md`, `CONFIG.md`,
  `README.md`, `ROADMAP.md` (sub-project #4 now describes what shipped and what
  is left), `CHANGELOG.md`, `examples/tun_macos.yaml` added to the macOS leg of
  `build.yml`'s smoke loop and to the example-validation list, and a release
  step building `--bin shoesd --features daemon` in its own cargo invocation
  into `shoesd-macos-arm64.tar.gz`. That step installs `protoc` first, since
  `prost-build` no longer vendors one. The RSS figures `docs/MACOS.md` still
  records as unknown come from step 8.
- [ ] 8. Full gate + five live items — **gate green, live run outstanding**.
  On macOS: `cargo fmt --check` clean; 1442 lib, 1420 bin, 8 integration, 1485
  under `ffi,control-stats,network-extension`, and 72 daemon tests, all passing;
  clippy clean on every file this work touched (the four pre-existing warnings
  in `src/util.rs` and `src/config/types/dns.rs` are untouched). Linux is CI's
  to run, and `cargo tree --target x86_64-unknown-linux-gnu` confirms a default
  build there pulls no gRPC stack.

  The five live items all need root and a real config, so they need the
  machine's owner:
  1. `start` with a real AmneziaWG config, `curl` through it, `stop`, and
     `netstat -rn` + `scutil --dns` identical before and after — both diffs
     pasted.
  2. `kill -9` mid-session; routes and DNS come back on the restart.
  3. A call from a uid outside the group gets `PERMISSION_DENIED`.
  4. Daemon RSS idle and under sustained download — the number `docs/MACOS.md`
     records as unknown, and the first desktop-sized buffer configuration to
     run on macOS.
  5. Whichever way the `enable_routing` question above settles, recorded here.

  Live-run credentials stay outside the working tree and are deleted
  afterwards; `git status` is checked before committing anything from that
  session.
