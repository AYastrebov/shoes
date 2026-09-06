# Linux integration notes

Linux is the platform shoes was written on, so most of this file is about the
one part that is new: `shoesd`, the privileged daemon, and what it does to a
host it is installed on.

The TUN path itself needs no notes. `create_sync_device` has had a Linux arm
since before the mobile work, `validate_tun_config` has had one for as long,
and the device path has run.

## What has not been verified

**The daemon has not run.** Every route, DNS write and `systemctl` call in
`src/bin/shoesd/` is unit-tested and none has executed against a real session.
The nine live checks it owes are step 8 of
[the plan](plans/2026-09-04-linux-privileged-daemon.md), and until they are
done this is a candidate for that run rather than tested software.

Several things the macOS notes had to defer *were* settled here, by measurement
on a Fedora 44 host rather than by reading — the ioctls a `IFF_TUN` device
accepts, what `ip -j route show default` emits for a multipath default, what
`resolvectl` does to a tun link and what survives the link disappearing, and
what `systemd` does to a unit that fails repeatedly. Those are recorded with
their numbers in
[the spec](specs/2026-09-04-linux-privileged-daemon.md#measured-on-the-development-host).

The daemon's RSS, idle and under load, is not among them. It is the figure the
macOS notes also record as unknown, and it wants the same live run.

## A root systemd daemon: `shoesd`

`shoesd` (`src/bin/shoesd/`, `--features daemon`) hosts `shoes::control`
in-process and serves gRPC over a Unix domain socket at `/run/shoesd/shoesd.sock`.
It is the same binary and the same contract as the macOS launchd daemon; only
the `HostNetwork` implementation underneath differs. Authentication is the
socket's peer credentials — no token, no TCP listener.

Install with `shoesd install`, which must already be root. Elevation is the
calling application's problem: KVN runs `pkexec <bundled path>/shoesd install`.

### Routes

`ip` by absolute path from a fixed candidate list, never `PATH`. The split
default (`0.0.0.0/1` and `128.0.0.0/1`) pins to the device, one host route per
excluded address goes through the pre-tunnel gateway, and IPv6 gets native
`unreachable` routes rather than the loopback-and-flag shape macOS needs.

The gateway comes from `ip -j route show default`, parsed as JSON. Two rules
that are not obvious: an entry with no `gateway` is skipped, because a
point-to-point default has none and taking it would send an excluded address
into the tunnel it is excluded from — but a **multipath** default is not that
case, and carries its gateways in a `nexthops` array. And an absent `metric`
means zero, because `ip -j` omits the key entirely at zero, so treating absence
as "unknown, therefore last" inverts the ordering for the route most likely to
be the real default.

### DNS, and the probe that decides which backend

Linux has four resolver mechanisms where macOS has one. Two backends cover the
five distributions in scope, chosen once at startup and reported to clients as
`dns-backend:systemd-resolved` or `dns-backend:resolv.conf` in `Hello`'s
`capabilities`.

**systemd-resolved** is used only when all three of these hold:

1. `resolvectl` exists at a known absolute path;
2. `resolvectl status` exits 0 — the daemon answers, rather than a unit merely
   being active;
3. `/etc/resolv.conf`, read through its symlink, points **only** at
   `127.0.0.53`.

The third is the one an obvious reading leaves out, and leaving it out leaks
DNS silently. `systemd-resolved.service(8)` documents four modes for that file,
and in two of them — `uplink` and `foreign` — resolved is running,
`resolvectl dns <link>` succeeds, and `/etc/resolv.conf` still lists the real
upstream servers. Every glibc client reads that file directly, so the tunnel
comes up, the daemon reports `RUNNING`, and lookups go out of the physical
interface with nothing anywhere saying so.

Two refinements on the same condition: *every* nameserver must be the stub, not
merely one of them, because a file listing `127.0.0.53` beside an upstream
server is one glibc falls back from whenever resolved is slow — a leak that
appears only under load. And `127.0.0.54` is rejected: it is also a resolved
stub, but it "operates in 'proxy' mode only… not try to process the messages
locally", so the per-link configuration this daemon writes would be bypassed.

Where resolved is used, the resolvers go on **the tunnel's own link**, never
the physical one. NetworkManager rewrites a physical link's resolvers on every
DHCP renew; nothing competes for the tunnel's, and the configuration dies with
the link, which is what makes revert nearly free.

**Otherwise `/etc/resolv.conf` is managed directly** — Debian with
NetworkManager, openSUSE with `netconfig`, a bare Arch install. That file is
contended, so this backend runs an `inotify` watcher on its *directory* (both
managers write a temporary and rename over the path, which detaches an inode
watch) and re-applies. The window cannot be closed, only kept short.

The backup records whether the path was a symlink and where it pointed, and the
original bytes when it was a regular file. Both matter: restoring a flattened
regular file where a symlink was breaks a host permanently, and rebuilding from
the parsed resolver list drops `search`, `options` and `sortlist` — the symptom
being a host whose short names stop resolving after a session ends, with
nothing connecting it to the VPN.

### Coexisting with another VPN

Two links each claiming a `~.` routing domain is a resolved priority contest,
and it has a real answer. Queries go to the link whose matching routing domain
has the most labels; `~.` matches everything with zero, so a longer domain on
another link wins for the names it covers and ours takes the rest.

**Tailscale in its default configuration sets no `~.`** — it is
`-DefaultRoute` with routing domains for `ts.net` and the `100.64.0.0/10`
reverse space — so MagicDNS keeps working and everything else comes to us, with
no interference in either direction. **As an exit node it does set `~.`**, and
then resolved sends each query to both links in parallel and takes the first
answer. Nothing on our side resolves that, so the daemon logs a warning naming
the other link at start rather than producing a tunnel whose DNS is
nondeterministic.

One leak this leaves, named rather than fixed: a physical link's search domain
is one label and beats our zero, so `*.lan` still resolves on the LAN. That is
usually what a user wants, and it is not what a strict reading of "all DNS
through the tunnel" promises.

### Install, and two things with no macOS counterpart

**The administrators' group is not portable.** It is `wheel` on Fedora, Arch
and openSUSE and `sudo` on Debian and Ubuntu, and `admin` — the macOS default —
exists nowhere. With no explicit `--group`, `install` picks the first of
`wheel`, `sudo`, `adm` that exists *and* contains the invoking user, read from
`PKEXEC_UID` falling back to `SUDO_UID`. Both halves of that conjunction
matter: `adm` exists on Fedora and is empty, so a rule stopping at "exists"
would be right there by luck and wrong on Debian, installing a socket the
administrator cannot reach. An explicit `--group` is always honoured, including
one the invoker is not in.

**SELinux.** A binary written to `/usr/local/libexec` can land with a label
that stops systemd executing it, so `install` runs `restorecon` where the tool
exists and tolerates its absence elsewhere — tolerating absence, not failure.

### `Restart=always` is not `KeepAlive`

Worth stating because the two service managers differ in a way that defeats
crash recovery. launchd throttles a job that fails repeatedly and keeps trying
forever; **systemd gives up** — `systemd.unit(5)`: "units which are configured
for `Restart=`, and which reach the start limit are not attempted to be
restarted anymore", with a default of five failures in ten seconds.

A daemon abandoned that way keeps its exclusion routes and its
`/etc/resolv.conf` applied, on a machine whose network is down and whose user
therefore cannot fetch a fix — the exact failure the on-disk revert record
exists to prevent, reached through the service manager instead of through the
code. The unit sets `StartLimitIntervalSec=0` with `RestartSec=5`, restoring
launchd's behaviour deliberately rather than inheriting a different one.

### What the kernel cleans up, and what the record is for

Narrower than macOS. The kernel deletes a link's routes when the link goes, and
resolved's per-link configuration goes with it, so `kill -9` on the daemon
takes the tunnel's own routes and — on a resolved host — the whole DNS override
with it, unaided.

What survives, and therefore what `AppliedState` exists for here: the exclusion
host routes, which hang off the physical interface, and the direct backend's
`/etc/resolv.conf`.

## Release artifacts

`shoesd-linux-x86_64.tar.gz` and `shoesd-linux-arm64.tar.gz`, built separately
from the `shoes` CLI because the feature sets differ.

**glibc only, never musl.** A statically linked musl build uses musl's own
`getpwuid_r` and `getgrnam`, which read `/etc/passwd` and `/etc/group` directly
and know nothing of NSS plugins — so on a host with SSSD- or LDAP-backed
accounts both the peer-credential check and install-time group detection would
fail to resolve a real user, giving a daemon that refuses everyone with nothing
in the error saying why.

## Deliberately absent

No `nftables` and no kill switch. No `SO_MARK` or `ip rule` policy routing —
wg-quick's canonical approach needs a firewall mark on the engine's outbound
sockets and there is no `SO_MARK` in the tree; the exclusion host route is
sufficient. No `bind_interface` in the daemon: `SO_BINDTODEVICE` *is* supported
on Linux and would remove the exclusion route entirely, but it lives in the
config's outbound section and the daemon's contract is that it rewrites the TUN
section and nothing else. No IPv6 inside the tunnel.
