# The Linux privileged daemon — implementation plan

Spec: [docs/specs/2026-09-04-linux-privileged-daemon.md](../specs/2026-09-04-linux-privileged-daemon.md).
Kept in sync with reality; a step is marked done when its verification has run.

Step 1 gates everything — nothing else compiles until the binary does. Step 2
gates 4. Steps 3, 4 and 5 are independent of each other. Nothing before step 8
needs root, which is the same deliberate shape the macOS plan has: the
privileged parts sit behind `HostNetwork` so the logic lands and is tested
before the first live run.

Unlike the macOS milestone, step 8 is answerable by whoever writes step 1 — the
development host is a machine the author can run this on. That is the reason to
do it in this order, and the reason step 8 is nine items rather than five.

## Steps

1. **Ungate, and fix what ungating breaks.** Remove the `compile_error!` at
   `src/bin/shoesd/main.rs:22`, keeping its text for Windows. Split
   `Cargo.toml:192` into a `cfg(any(target_os = "macos", target_os = "linux"))`
   section holding `tonic`, `tonic-prost`, `prost`, `tokio-stream` and
   `serde_json`, and a macOS-only section holding `system-configuration` and
   `core-foundation`; same split for the `dev-dependencies` at `:214` and its
   `tower`. Make the `daemon` feature's `dep:system-configuration` and
   `dep:core-foundation` entries per-target rather than unconditional members,
   and rewrite the feature's doc comment (`Cargo.toml:65-87`), which says
   macOS-only in three places. Add the Linux arm to `capabilities()`
   (`service.rs:52`). `build.rs` needs no change: it already gates on
   `#[cfg(feature = "daemon")]` rather than on the target.

   Then fix `a_known_group_resolves` (`auth.rs:288`), which asserts `wheel` is
   gid 0 — a Darwin fact that is false on Fedora, where it is gid 10. Assert
   against what the system reports for the name rather than a constant, and
   correct the same mistake in `groups_of`'s doc comment (`auth.rs:107`); the
   security reasoning there is unaffected, only its example is wrong.

   Verification: `cargo build --features daemon` on Linux and macOS; the full
   gate on both, with `cargo test --features daemon` green on Linux for the
   first time — which is what proves the `auth.rs` fix rather than merely
   asserting it. `cargo tree --target x86_64-unknown-linux-gnu` still shows a
   *default* Linux build pulling no gRPC stack; that is the property the
   target-section split can silently lose, and it is not the same check as
   `mobile.yml`'s link step, which compares `_shoes_` symbol counts between the
   iOS host and extension and would stay green either way. `protoc` is needed on
   the build machine from here on (`dnf install protobuf-compiler`).

2. **The trait change.** `primary_dns_service(&self, interface: &str)` in
   `host/mod.rs`, ignored by the macOS arm, with the call site at
   `host/plan.rs:215` passing `plan.interface`. `Step::PrimaryService` in
   `host/double.rs` carries the interface, and `plan.rs`'s existing ordering
   assertions gain the argument.

   Add to `write_dns`'s doc comment the clause `delete_route` already has: a
   target that is not there is success, and *only* that. Narrow on purpose — a
   D-Bus refusal, a missing binary, a permission error all propagate, for the
   reason `delete_route`'s comment gives.

   Verification: two new sequencing tests over `Recorder`, each written first
   and watched to fail. A `write_dns` failing with "no such device" during
   revert does not abort the remaining steps — the test whose absence would
   strand exclusion routes. And `apply_dns` passes the plan's interface through,
   not a fixed string, which is the whole point of the signature change and is
   otherwise invisible.

3. **`host/linux/routes.rs`.** Tool resolution first: `ip` from the candidate
   list `/usr/sbin/ip`, `/sbin/ip`, `/usr/bin/ip`, resolved once at startup,
   failing loudly and naming all three if none is present, never searched on
   `PATH`. Three candidates rather than the brief's two because merged-`/usr`
   layouts vary — on Fedora 44 both of the brief's resolve to `/usr/bin/ip`,
   while on Debian `/usr/sbin/ip` is the real file.

   Then the argv builders for the four `Via` forms — `dev`, `via`, `blackhole`,
   `unreachable`, the last two native here rather than the loopback-plus-flag
   workaround macOS needs. `delete_route` names only the destination, as on
   macOS and for the same reason. `is_absent_route`'s Linux twin matches
   `RTNETLINK answers: No such process` and nothing else; `ip` exits 2 for that
   case, so it is matched on the message rather than the status.

   `default_gateway` parses `ip -j route show default` with `serde_json`,
   skipping entries with no `gateway` key (the analogue of macOS's `link#N`
   filter, and there for the same reason) and taking the lowest `metric`, ties
   by table order.

   Verification: unit tests over the pure halves only, since that is all of it
   except the `Command` wrapper. The argv for every route form, asserted as a
   vector, with no element containing whitespace or `;` — the addresses arrive
   over the control socket. The gateway parse against five fixtures: no default
   route, a gateway-less point-to-point default, a `{"type":"blackhole"}` entry
   with neither `dev` nor `gateway`, two defaults at different metrics, and one
   whose `metric` key is *absent* — `ip -j` omits it at zero, so a parse that
   treats absence as a large number inverts the ordering for the route most
   likely to be the real default. Plus `is_absent_route` asserting ESRCH is
   swallowed and that a permission error, a missing binary and a kernel refusal
   are not. Each proven able to fail.

   Also record which iproute2 release is the oldest in scope and whether it has
   `-j`. Only 6.17.0 on this host has been checked; if a supported distribution
   ships one without it, say so here and fall back to the column parse rather
   than discovering it on a user's machine.

4. **`host/linux/dns.rs`.** The probe first, because it decides which backend
   exists: `resolvectl` present at `/usr/bin/resolvectl` or `/bin/resolvectl`,
   `resolvectl status` exiting 0, and `/etc/resolv.conf` — read through its
   symlink — listing `nameserver 127.0.0.53`. All three, or the direct backend.
   The third condition is the one the brief and KVN's design both omit, and it
   is not optional: in resolved's `uplink` and `foreign` modes the first two
   hold while every glibc client bypasses resolved entirely, so per-link
   configuration succeeds and DNS leaks silently. Log the choice once and report
   it through `capabilities` as `dns-backend:systemd-resolved` or
   `dns-backend:resolv.conf`.

   The resolved backend is four argv arrays — `dns <tun> <ips>`, `domain <tun>
   ~.`, `flush-caches`, `revert <tun>` — against the *tunnel* link, never the
   physical one. At start, if another link already carries `~.`, log a warning
   naming it: that is the Tailscale-as-exit-node case, where resolved queries
   both links in parallel and takes the first answer, and no configuration on
   our side resolves it.

   The direct backend extends `DnsBackup` with `symlink_target: Option<PathBuf>`
   under `#[serde(default, skip_serializing_if = "Option::is_none")]`. The
   `default` is load-bearing, not defensive: `skip_serializing_if` means a
   resolved-backend session writes the field out as absent and has to read it
   back, and `AppliedState::load` reports a parse failure rather than ignoring
   one — so an added field without a default turns every in-flight record into a
   refusal to start. Restoring a symlink is `remove_file`
   then `symlink`, never a write, because writing through the link would rewrite
   the manager's own file. Then the watcher: `inotify` on the *directory*, not
   the file, because NetworkManager and `netconfig` both write a temporary and
   rename over it, which detaches an inode watch; rate-limited to the same
   300 ms settle the route monitor uses, and posting `Command::NetworkChanged`
   rather than acting.

   Verification: the probe against fixture `resolv.conf` contents for all four
   resolved modes from `systemd-resolved.service(8)` — stub, static, uplink and
   foreign — asserting the last two select the direct backend. The argv for each
   `resolvectl` call. The symlink round trip on a real `tempdir`: a backup
   recording a symlink restores a symlink, one recording a regular file restores
   a regular file, and neither writes through a link. Each proven able to fail —
   the symlink one by restoring with `fs::write` and watching it clobber the
   target, which is the permanent-host-breakage this test exists for.

5. **`host/linux/monitor.rs`.** A port of `host/macos/monitor.rs`'s shape, not a
   redesign: `AF_NETLINK` with `RTMGRP_IPV4_ROUTE | RTMGRP_LINK`, read purely as
   a signal, never parsing the delta, posting `Command::NetworkChanged` so the
   re-apply is serialised with `Start` and `Stop` rather than racing them. The
   300 ms settle, the 2 s second look, and `recoverable()` transfer unchanged —
   `netlink(7)` names `ENOBUFS` from `recvmsg(2)` as the overrun signal and says
   it is the application's job to resynchronize, which is what re-reading the
   table already does. `NETLINK_NO_ENOBUFS` is deliberately not set: it would
   turn a dropped burst into silence instead of into a re-read.

   No new dependency — `sockaddr_nl`, `RTMGRP_IPV4_ROUTE` and `RTMGRP_LINK` are
   all reachable from the locked `libc` 0.2.189, confirmed by compiling against
   it before writing this.

   One Linux difference: the socket must be `bind`ed to a `sockaddr_nl` with
   `nl_groups` set, and `PF_ROUTE` needs no bind. That is the one place this can
   fail that the macOS version cannot.

   The second look is kept even though its macOS rationale does not apply to the
   resolved backend, whose configuration nothing else touches. It applies
   squarely to the direct backend. Two extra calls per network change on hosts
   that do not need them is cheaper than two monitors.

   Verification: a test over the bind-and-open half alone, which is the half
   that can fail, asserting an unprivileged process gets a bound fd — and
   deliberately *not* calling `spawn`, whose thread is detached and blocks in
   `read` until the kernel says otherwise. That is finding 3 of
   `shoes-agent-prompt-daemon-review-2.md`, and the macOS monitor's test leaks a
   thread for the life of the test binary by making exactly that mistake. Plus
   the `ENOBUFS`-is-recoverable test, which is the macOS one unchanged.

6. **`install.rs`'s Linux arm.** `/etc/systemd/system/shoesd.service`, the
   binary staged to `/usr/local/libexec/shoesd` `root:root 0755`, then
   `systemctl daemon-reload` and `systemctl enable --now shoesd`. `uninstall`
   reverses it, stopping the unit first — which sends `SIGTERM`, so the session
   is reverted through the same path a shutdown uses rather than a second one
   written here, exactly as `bootout` does on macOS. `stage()`'s discipline is
   unchanged, including removing a leftover staged file first because `create`
   on an existing file keeps the mode it already has, and so is the rule the
   module exists to enforce: never run from the path it was invoked at.

   The unit needs no XML escaping and gains its own hazard — `ExecStart` *is*
   parsed for quotes and escapes per `systemd.service(5)`, and the paths and
   group name come from the command line. Each argument is quoted, and the
   plist's "every argument is its own element" test is kept in the form that
   applies here.

   **`Restart=always` on its own is a trap.** systemd stops restarting a unit
   that hits the start limit — 5 in 10 s by default — where launchd throttles
   and keeps trying. A daemon that crash-loops would therefore be abandoned with
   its exclusion routes and `/etc/resolv.conf` still applied, on a machine whose
   network is down. The unit sets `StartLimitIntervalSec=0` and `RestartSec=5`
   to restore launchd's behaviour on purpose.

   `RuntimeDirectory=` is deliberately *not* used for `/run/shoesd/`. It would
   have systemd create the directory with a mode of its choosing before the
   process starts, and that directory's `0750 root:group` is what closes the
   bind-and-chmod window `socket.rs` documents. One owner for that decision.

   Group detection: with no explicit `--group`, the first of `wheel`, `sudo`,
   `adm` that exists **and** contains the invoking user, read from `PKEXEC_UID`
   falling back to `SUDO_UID`. Both halves of the conjunction matter — on this
   host `wheel` exists and contains the user, `adm` exists and is empty, `sudo`
   is absent, so a rule stopping at "exists" would be right here by luck and
   wrong on a Debian box. Failing loudly and naming all three candidates when
   none matches, rather than installing a socket nobody can reach.
   `DEFAULT_GROUP` becomes a per-platform default; an explicit `--group` is
   always honoured, including one the invoker is not in.

   SELinux: `restorecon` on the installed binary where it exists, tolerating its
   absence on Debian, Ubuntu and Arch. Tolerating absence is not tolerating
   failure — a `restorecon` that exists and returns non-zero is reported.

   Verification: the rendered unit, including a path containing a space and one
   containing a quote, asserted to survive `systemd.service(5)`'s parsing rules,
   and asserted to carry `StartLimitIntervalSec=0` — a test for that line
   specifically, because its absence is invisible until a crash loop, and the
   symptom then is "the daemon stopped coming back" with nothing pointing at the
   unit file. Group detection against an injected "does this group exist and
   contain this uid" predicate, covering the Fedora shape, the Debian shape, and
   none-matching. The non-root refusal, as on macOS. Each proven able to fail.

7. **Docs and release.** A `docs/LINUX.md` beside `docs/MACOS.md`, carrying the
   two backends, the probe, the routing-domain behaviour, the Tailscale answer,
   and the RSS figures from step 8. `CONFIG.md`'s TUN platform notes.
   `README.md` and `ROADMAP.md`'s desktop section naming the new assets.
   `CHANGELOG.md`.

   `build.yml` gains a `shoesd` build on the two Linux gnu legs, mirroring the
   macOS one: its own `cargo build --release --locked --features daemon --bin
   shoesd`, its own tarball, `protoc` installed first
   (`apt-get install -y protobuf-compiler` rather than `brew`).

   **The gnu legs only, and not musl.** A statically linked musl `shoesd` uses
   musl's own `getpwuid_r`/`getgrnam`, which read `/etc/passwd` and `/etc/group`
   directly and know nothing of NSS plugins. On a host with SSSD- or
   LDAP-backed accounts the peer-credential check and the install-time group
   detection would both silently fail to resolve a real user — a daemon that
   refuses everyone, with no error saying why. glibc is a requirement of this
   binary, not a default.

8. **Verification.** The full gate on Linux and macOS — `cargo fmt --check`,
   `clippy --locked --lib --bins --tests -- -D warnings`, the three `cargo test`
   invocations, and both `--features ffi` clippy configurations. `mobile.yml`
   still green, and separately `cargo tree` on a default Linux build still
   showing no gRPC stack; those are two different assurances and only the second
   is about the daemon's dependencies. Then the nine live items, all on the
   development host except item 2:

   1. `start` with a real AmneziaWG or VLESS config, `curl` through the tunnel,
      `stop`, and `ip route show` plus `resolvectl status` byte-identical before
      and after. Both diffs pasted.
   2. The same on a distribution using the direct backend — Debian or openSUSE
      in a VM — including a NetworkManager reconnect mid-session to prove the
      watcher re-applies, and a revert that restores the symlink **as a
      symlink**.
   3. `kill -9` mid-session, then start again, and show routes and DNS come
      back. State which parts the kernel cleaned up unaided and which the record
      had to undo — the spec claims that division is narrower than macOS, and
      this is what checks the claim. Then `kill -9` six times inside ten seconds
      and confirm systemd keeps restarting it, which is the only way to check
      `StartLimitIntervalSec=0` actually took.
   4. A network change mid-session: unplug Ethernet, fall to Wi-Fi, and show the
      exclusion host route re-pointed at the new gateway.
   5. Tailscale coexistence in both modes — default, where the spec predicts no
      interference, and exit node, where it predicts a warning and a race.
   6. Docker: bridge routes are RFC1918 and so more specific than `0.0.0.0/1`,
      and containers should be unaffected. Asserted, not assumed.
   7. A call from a uid outside the detected group gets `PERMISSION_DENIED` as a
      gRPC status, not a dropped socket.
   8. Daemon RSS idle and under a sustained download, against the macOS figure,
      confirming the desktop buffer sizing took effect. The number goes into
      `docs/LINUX.md`.
   9. `shoesd install` under `pkexec` with a binary inside a user-writable
      bundle, which is KVN's Task 0 spike. Not our code, but our install path is
      what it exercises, and discovering otherwise after step 6 would invalidate
      the group-detection design that reads `PKEXEC_UID`.

   Live-run credentials stay outside the working tree and are deleted
   afterwards; `git status` is checked before committing anything from that
   session.

## Open decisions, to be settled before step 7 ships

**The arm64 asset name conflicts with the repository's own convention.** KVN's
brief and design both name `shoesd-linux-aarch64.tar.gz`, and their
`DownloadShoesAssetTask` fetches by asset name and verifies the published
SHA-256 — so the string has to be exactly right or their build breaks. But
`build.yml`'s matrix calls that leg `linux-arm64`, the macOS daemon artifact is
`shoesd-macos-arm64.tar.gz`, and KVN already consumes *that* name happily.
Following the existing pattern gives `shoesd-linux-arm64.tar.gz`.

Recommendation: `linux-arm64`, for consistency with the macOS artifact the same
Gradle task already fetches, and confirm it with KVN before the release job
lands. Whichever way it goes, one string changes and it changes in one place.
Record the answer here.

**Whether the first live bring-up needs `create_sync_device` touched at all.**
The spec claims nothing under `src/` changes, on the strength of
`create_sync_device`'s Linux arm applying all five fields and the three ioctls
having been confirmed to succeed against a real `IFF_TUN` device
(`SIOCSIFADDR`, `SIOCSIFDSTADDR`, `SIOCSIFNETMASK`, in the order
`AbstractDevice::configure` issues them). What was *not* exercised is that path
running inside shoes, with the crate's own `ensure_root_privileges(true)` and
`up()` alongside it. If step 8 item 1 gives an interface that will not pass
traffic, record here what was observed and what changed — a `src/` change is a
finding to report, not one to make quietly.

## Status

- [x] 1. Ungate + `auth.rs` fix. **81 daemon tests green on Linux**, which is
  the first time they have ever run there. Three things the plan had not
  anticipated:
  - **`getgrouplist`'s signature is not portable.** Darwin takes `c_int` for
    the base gid and the array; glibc takes `gid_t`. A hard `E0308` that a cast
    cannot paper over, since the array crosses as a raw pointer. A
    `GroupListGid` alias states the difference once and keeps one code path.
    This contradicts the spec's "`auth.rs` needs no Linux arm" — it needed two.
  - **The `Cargo.toml` split really was load-bearing.** Removing only the
    `compile_error!` gave `unresolved import tonic` / `tokio_stream` and a
    `proto` module with no generated contents, which confirms the target
    sections were doing real work rather than merely documenting an intent. The
    `daemon` feature's `dep:system-configuration` / `dep:core-foundation`
    entries needed **no** change, though: naming a target-specific optional
    dependency from a portable feature is a no-op off that target, so the spec's
    "must become optional per-target" was wrong and the entries stay as they
    are, now with a comment saying why.
  - `capabilities()`'s test asserted the *old* behaviour ("a build off macOS
    must promise nothing") and had to be rewritten rather than merely extended.
    It is renamed off `macos_` since it is no longer about one platform.
- [x] 2. Trait change and the `write_dns` clause. Also **larger than the spec
  described**, and the reason is the symlink rule. `primary_dns_service` really
  is one line in the trait and one at the call site — but `DnsBackup` cannot
  gain `symlink_target` unless the trait can carry it, and `read_dns` returned
  a bare `Vec<IpAddr>`. So `read_dns`/`write_dns` now carry a `DnsState`
  (`servers` + `symlink_target`), `DnsBackup` holds one `#[serde(flatten)]`ed
  so the on-disk record is byte-identical to before, and `DnsState::servers()`
  is the constructor for the apply direction, which never has a target. The
  spec's "one line in the trait" is corrected there.
- [x] 3. `host/linux/routes.rs`. 17 tests, each mutated to confirm it can fail.
  Three judgement calls the plan did not settle:
  - **Unparseable JSON at exit 0 is an error, not `None`.** An `ip` too old for
    `-j` exits non-zero and never reaches the parse, so garbage from a
    successful run means the output is not understood — and answering `None`
    there would silently blackhole every exclusion on a host with a perfectly
    good gateway, which reads to the user as the proxy being unreachable.
  - `is_absent_route` matches the whole `rtnetlink answers: no such process`
    string rather than a substring, because `ip` also exits 2 for EPERM and for
    an unreachable next hop.
  - `DefaultRoute` deliberately does **not** `deny_unknown_fields`: the key set
    varies by route type and iproute2 release, and a daemon that refused to
    start on a new key would be broken by upgrading a package it only reads.

  It also corrected the spec's measurement table: all three `ip` candidates
  share an inode on Fedora, but `Path::exists()` follows the symlink while the
  located path keeps the name it was given, so the daemon logs `/usr/sbin/ip`.
- [x] 4. `host/linux/dns.rs`. 22 tests. Three things beyond what step 4
  described, two of them corrections to the spec:
  - **`DnsState` was lossy and the spec was wrong to stop at `symlink_target`.**
    Rebuilding a regular-file original from the parsed resolver list drops
    `search`, `options` and `sortlist`. Added `verbatim`, which replays the
    original bytes; the pre-existing round-trip test could not see the defect
    because it compared only nameservers. The new test was confirmed to be the
    only one that reddens when the defect is reintroduced.
  - **The probe needed two tightenings**: every nameserver must be the stub, not
    merely one of them (a file listing the stub beside an upstream server is one
    glibc falls back from under load — a leak that appears only when resolved is
    slow), and `127.0.0.54` is rejected, because it "operates in 'proxy' mode
    only… not try to process the messages locally" and so bypasses the per-link
    configuration entirely.
  - **Each backend refuses the other's record**, which closes the one door
    `symlink_target` does not: the probe's answer can change across a restart,
    and a resolved record fed to the direct backend would flatten
    `/etc/resolv.conf` to an empty regular file.
- [x] 5. `host/linux/monitor.rs`. 2 tests, 4 mutations. The plan asked only that
  an unprivileged process get a bound fd; that is not enough, because `fd >= 0`
  cannot distinguish a bound socket from one whose bind never happened — the
  exact silent-forever failure the bind exists to prevent. The test asserts
  `getsockname` reports a non-zero `nl_pid` and the exact group mask. That the
  bind really subscribes was confirmed out of tree under `unshare -Urn`
  (`RTM_NEWLINK` received); the loop around it remains the live run's to show.
  A descriptor leak the naive port would have had is closed: bind is a second
  fallible step, so the fd is guarded from `socket()` and errno is read before
  the guard's `close`.
- [x] 6. `install.rs`'s Linux arm. 21 tests, 17 mutations, every macOS test kept.
  **One finding changes what "safe" means here**, and it came from loading a
  rendered unit into the real systemd rather than from reading the manual:
  `ExecStart` expands `%` specifiers **at load time, inside double quotes**, and
  `$` at exec time. A `--socket` or `--group` value containing `%h` would
  silently become a different path in a job running as root. Quoting alone does
  not stop it; `%`→`%%` and `$`→`$$` do. Independently reproduced on systemd 259
  before accepting. Also: `enable` + `restart` rather than `enable --now`, since
  `--now` leaves an already-running unit alone and a reinstall would keep
  executing the binary just replaced.
  The inotify watcher, which step 4 called for and the first pass did not
  build, landed with it. Implementing it exposed a **feedback loop between two
  modules that neither reviewed alone would show**: `Session::reapply` writes
  DNS unconditionally on every `NetworkChanged` -- deliberately, since its macOS
  arm has no signal to compare against -- and on the direct backend that write
  is a rename over the very file the watcher watches. Manager rewrites, we
  re-apply, our own re-apply wakes the watcher, and `/etc/resolv.conf` is
  rewritten several times a second for the life of the process with nothing in
  any log saying so. Fixed at the source: `replace_with_regular_file` returns
  early when the path is already a regular file with exactly the wanted bytes,
  with `symlink_metadata` so that replacing a *symlink* whose target reads the
  same still happens. Two tests, each proven to redden alone.

  Also fixed here, from the install arm's report: `parse_run_args` substituted
  `DEFAULT_GROUP` when `--group` was absent, so `install` could not tell an
  explicit `--group wheel` from no flag at all -- making the one value a Fedora
  administrator is most likely to type the one that got silently re-derived.
  `RunArgs::group` is now `Option<String>`.
- [ ] 7. Docs and release.
- [ ] 8. Full gate + nine live items — **CI gate green, live run outstanding.**
  On Linux: `cargo fmt --all -- --check` clean; all five clippy configurations
  clean under `-D warnings`; 1440 lib, 1414 bins, 8 integration and **147 daemon
  tests** passing; `cargo tree --target x86_64-unknown-linux-gnu` confirms a
  default build still pulls no gRPC stack. macOS is CI's to run.

  One change outside this milestone was needed to get there. `src/util.rs` had a
  pre-existing `clippy::items_after_test_module` that failed `-D warnings` on a
  clean checkout of `40291cc`, so AGENTS.md's "every clippy configuration is
  clean" was already false on Linux before any of this work. Its `#[cfg(test)]
  mod tests` moved to the end of the file -- a pure move, no logic touched --
  because leaving it red meant none of the work above could be verified.

  The nine live items all need root and a real config, so they need the
  machine's owner. Nothing in them has been run.
