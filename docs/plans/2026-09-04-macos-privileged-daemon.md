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
   `/var/run/shoesd.sock` — unlinking a stale path first, then `chown` to
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
   release job building `--bin shoesd --features desktop` in its own cargo
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
- [ ] 6. `install`/`uninstall`/`SIGTERM`
- [ ] 7. Docs, example, release job
- [ ] 8. Full gate + five live items
