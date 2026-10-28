# Changelog

## v0.9.0

A minor version, for the mobile FFI: Android gains a stopped listener,
`start` returns a session id on both platforms, and `stop(handle)` acts on
that session only (#121). A host that passes `stop` what `start` returned,
as KVN's Android app and the Swift package do, needs no change; a host
that passed a constant must pass the id now. The C symbol list and callback
types are unchanged, so the Apple framework is a drop-in; the Kotlin
bridge keeps its three-argument `start`. Also the Android build tooling
moves to AGP 9.4.1 and Gradle 9.8.2 (#120), and the tag build no longer
runs the macOS C-surface check (#119). No configuration change.

Android gets a stopped listener, and both platforms a real session id.
`ShoesNative.start` takes a fourth argument, a `StoppedListener` or null,
behind a three-argument overload that keeps every existing caller as it
was; the listener is called once, from a shoes worker thread, if the
engine stops without `stop` having been called for it, with the session id
and the reason, never for a requested stop and never for a failed start.
That is the callback iOS has had since `shoes_start_with_fd`, delivered by
the same code; Android's start simply installed nothing in it, and KVN had
to poll `isRunning()` every two seconds to notice a dead engine.

`start` now returns a session id, from a counter that starts at 1, instead
of the literal 1, and `stop(handle)` acts on the session with that id and
on no other: any other value stops nothing and reports released, with a
warning in the log, so a late death handler can release its own session
without touching the one that replaced it. The one thing this stops
tolerating is a host passing a constant instead of what `start` returned;
the only such caller was this repository's Swift wrapper, which called
`shoes_stop(1)` and now passes the id it was given. The C symbol list and
the C callback types are unchanged.

Also fixed with it, found in the design review: an exit and a start could
cross, since the exit guard marks a service stopped before it delivers the
exit, and the old session's exit then overwrote the error the new start
had cleared and reached the new session's callback. An exit now names its
session, and one for a session no longer in the slot is dropped -- unless
a stop is waiting on that session, in which case it is recorded without a
callback, so a crash that raced the host's stop still reaches
`getLastError`, as an earlier fix made sure of. The Swift wrapper also
waits for a start still inside the native call before it stops, so
disconnecting while still connecting stops the session that start made.

The Android AAR builds with AGP 9.4.1 and Gradle 9.8.2, up from 9.0.1 and
9.5.0; nothing in the module's build script changes, since it enables no
minification and ships no keep rules, which is where the 9.1 to 9.4
behaviour changes live. CI's Gradle setup action moves to its current
release and publishes a Build Scan of every AAR build to the public
scans.gradle.com, linked from the job log, so a slow or oddly cached build
can be read from its task timeline rather than guessed at.

## v0.8.4

One protocol fix and a dependency sweep. VLESS UDP under the Vision flow
now reaches sing-box servers, carried as XUDP under the Mux command the
way Xray and sing-box send it (#114), with two defects its review found
fixed alongside: a panic in the XUDP metadata decoder on a frame whose
destination ran past its declared length, and a datagram ending in `0x16`
held back by the Vision writer. awgtun 0.12.0 corrects the AmneziaWG
handshake timestamp epoch to the one kernel WireGuard and wireguard-go use
(#117). Every dependency is on its current major (#115, #116). No FFI or
configuration change; the mobile libraries and the daemons are rebuilt
with the new dependencies.

awgtun moves to 0.12.0 (738ce7e). The change that reaches the wire: the
AmneziaWG handshake timestamp now uses the epoch every reference uses
(+10, as kernel WireGuard and wireguard-go), so moving a peer identity
between shoes and a kernel or Go client no longer stalls its next
handshake for 27 seconds. A server that has already accepted a timestamp
from an older build may make that window expire once on upgrade. The
rest is housekeeping shoes inherits: awgtun is on the digest 0.11 and
rand_core 0.10 RustCrypto generation this crate already uses, with
`x25519-dalek` 3 and `curve25519-dalek` 5, so the old `blake2`,
`chacha20poly1305`, `digest` 0.10 and `rand_core` 0.6 lines leave the
graph along with their eleven supporting crates. No shoes code changes:
the x25519 types it uses are the same.

The five direct dependencies the lockfile update left on an old major
move up, one commit each: `blake2` 0.11 and `chacha20poly1305` 0.11 join
the digest 0.11 and rand_core 0.10 lines the rest of the crate uses;
`lru` 0.19, `base64` 0.23 and `parking_lot` 0.13 compile unchanged. The
one code change is in the mieru cipher, where the nonce is built with
`From` rather than the `from_slice` that 0.11 deprecates. The old lines
of all five stay in the graph behind `awgtun`'s pin, and `parking_lot`
0.12 also behind `hickory-resolver`; they leave when those move.

The lockfile moves to the newest versions Cargo.toml already allows:
89 crates, no code change. Of note on the paths this binary runs,
`aws-lc-sys` 0.46 (the crypto backend's native build), `hickory` 0.26.3,
`quinn` 0.11.12, `tokio-rustls` 0.26.6, `hyper` 1.12, `tonic` 0.14.8 and
`rustls-platform-verifier-android` 0.2. `pem` 4 and `miniz_oxide` 0.9
move behind `rcgen` and `flate2`, and `pem` 4 brings a second `base64`
(0.23) into the graph beside the 0.22 this crate uses. The `windows-*`
0.53 crates and `fsevent-sys` leave the graph. Five direct dependencies
have a newer major release that this does not take (`parking_lot` 0.13,
`base64` 0.23, `lru` 0.19, `chacha20poly1305` 0.11, `blake2` 0.11); each
needs code changes and gets its own change.

VLESS UDP under the Vision flow now reaches sing-box servers. The client
sent it as the plain UDP command with no flow named; sing-box refuses that
for a Vision user (`flow mismatch: expected xtls-rprx-vision, but got
none`), so every UDP packet over a sing-box VLESS Vision server was dropped
while TCP worked. It now goes as both reference clients send it (Xray's
VLESS outbound, sing-vmess's `DialEarlyXUDPPacketConn`): the Mux command
under the Vision flow, inside a Vision stream, with the packets as XUDP
frames. That is also the only UDP an Xray server takes under the flow, and
the form shoes' own server already read. The TLS and REALITY Vision
clients both change; VLESS without Vision still sends the plain UDP
command.

The new client XUDP stream frames packets byte for byte as sing-box's
client does (session 0, a New frame and then Keep frames naming the
target, no global ID), checked against the captured sing-box flight in
`tests/data/kat/frames-sing`. It closes the session with an End frame on
shutdown, as Xray's client does, and drops a packet over 8192 - 666 bytes,
the most an Xray server reads in one frame. UDP/443 is carried, as
sing-box's client carries it; Xray's client refuses it under plain
`xtls-rprx-vision` to push QUIC back onto TCP, which is a client policy
rather than something either server enforces. The whole-frame decode the
server used is now shared by both directions (`xudp::frame::decode_frame`).

Two defects the review of that change found are fixed with it. The XUDP
metadata decoder read a frame's destination from the whole buffer rather
than from the bytes the frame declared, so a frame that named a UDP
destination and then ended (`00 05 00 00 02 00 02`) panicked the task that
read it, on the server as well as the new client; a destination that runs
past the declared metadata is now refused as invalid data. And the Vision
client looked inside each XUDP write for TLS records, so a datagram ending
in a byte that could begin one (`0x16`) had that byte held back for a
record that never came, and the datagram waited on the next write; a Vision
stream that carries XUDP now pads each write whole, as Xray's VisionWriter
pads each buffer.

## v0.8.3

One fix, for the desktop daemon on macOS: `sudo shoesd install` over a
running daemon no longer fails with `Bootstrap failed: 5: Input/output
error` (#112). No protocol, FFI or configuration change; the Linux and
Windows daemons and the mobile libraries are rebuilt unchanged.

`shoesd install` on macOS retries `launchctl bootstrap` while launchd
answers status 5 (#112). Upgrading 0.8.1 to 0.8.2 in place failed twice
that way, leaving the new binary installed and no daemon running, and a
third run succeeded: `install` boots the old job out and bootstraps the new
plist straight after, and the bootout returns before launchd has finished
with the old job. Waiting for the job to disappear from `launchctl print`
would not have been enough, since the second failure came with the service
already gone; launchd has to be asked again. The bootstrap is retried six
times with the wait doubling from 250 ms, under eight seconds in all; any
other status is reported at once. Status 5 is also launchd's answer for a
plist it will not load, so a genuine refusal now costs those few seconds
before it is reported, and the final error says what the machine is left
with and that running the install again usually loads it. The bootstrap
and the sleep are parameters, so the tests script launchd's answers without
waiting. Not done: a `launchctl print` after a successful bootstrap, since
with `RunAtLoad` and `KeepAlive` a loaded job is launchd's to start and
restart. Not verified live, which needs root over a running daemon.

## v0.8.2

One fix, for the desktop daemon on macOS: a session no longer leaves the
host's DNS changed after a clean stop (#110). The revert record carries the
service's `State:` and `Setup:` keys whole and puts back exactly those, so a
DHCP lease's search domain survives and `Setup:` no longer pins the lease's
resolvers on the next network. A 0.8.1 record still loads. No protocol, FFI
or configuration change; the Linux and Windows daemons and the mobile
libraries are rebuilt unchanged.

`shoesd` on macOS restores a service's DNS keys exactly, not as the parsed
servers (#110). KVN's first live macOS run against 0.8.1 found every session
leaving the host's DNS changed after a clean stop: the revert record was the
`ServerAddresses` of `State:`, written back to both keys, which dropped the
lease's `DomainName` and left `Setup:` -- the user's configuration, which
overrides DHCP -- pinning the lease's resolvers on the next network the Mac
joined. The record now carries each key whole (`DnsState::store_keys`, the
macOS counterpart of Linux's `verbatim`), as the XML property list of its
dictionary or as absent, and the revert puts back exactly that: absent by
removing the key, since an empty dictionary is a service that resolves
nothing. A 0.8.1 record still loads and is restored from its servers. The
dynamic store is behind a `Store` trait, so the restore runs in tests
against a store in memory -- the real one refuses writes from anything but
root, which is why 0.8.1 shipped the one path no test reached. Applying
still writes a servers-only dictionary, so a lease's search domain is not in
force while a session is up; recorded in `ROADMAP.md`.

## v0.8.1

The desktop daemon carries IPv6 (#108), the agent guidelines are
reorganised along `agents.md` (#107), and tokio moves to 1.54.1 for
RUSTSEC-2026-0386. `shoesd` on Linux and macOS routes the v6 halves via the
tunnel device behind a ULA and says `ipv6` in `Hello`; on Linux it probes
`disable_ipv6` first, so a host that turns IPv6 off keeps the rejects and
starts as before, and Windows keeps them by design. No `v1` protocol change:
a client that does not read the capability sees the `Start` contract it
had, and one that does may hand the daemon a v6 resolver where v6 is
carried.

tokio 1.54.1, for RUSTSEC-2026-0386: `AsyncFd::new` took any `AsRawFd`, a
bare descriptor nobody owned included, and is deprecated in favour of the
unsafe `AsyncFd::register`, whose contract is that the descriptor stays open
and the same for the `AsyncFd`'s life. The TPROXY UDP listener is the one
caller; it moves an owned `socket2::Socket` in, which already met that
contract, and now says so in a `SAFETY` comment; `Cargo.toml` asks for
tokio 1.53.3 at least, where that constructor appears. No behaviour change. The
scheduled audit went red on this on 2026-10-24, and `cargo audit --deny
warnings` also runs on every push and pull request.

`shoesd` carries IPv6 on Linux and macOS. The two v6 halves (`::/1`,
`8000::/1`) are routed via the tunnel device instead of being rejected, the
device gets a ULA (`fd00:6b76:6e00::2/64`) from the host arm so the kernel
accepts the routes and picks a v6 source, and `Hello.capabilities` gains
`"ipv6"` where that is so -- a client then generates a config that proxies v6.
What gets through that did not: v6-only destinations and v6 literals. A
dual-stack name still connects over v4, because RFC 6724 ranks a v4
destination above a v6 one whose only source is a ULA. `Start.dns` takes a
v6 resolver on a carrying arm; `Start.exclude` stays IPv4-only on every arm,
because the exclusion route goes through the IPv4 default gateway. On Linux
the capability is probed once at startup from
`net.ipv6.conf.{all,default}.disable_ipv6`: a host that disables IPv6 keeps
the rejects and starts as before, rather than failing every `Start` on an
address the kernel refuses. The macOS arm reads `ifconfig <utun> inet6`
before adding the address, because `alias` of one already there exits 0
silently and would otherwise record someone else's address as ours. The
address is recorded in `AppliedState` and reverted after the routes; records
from older builds load with none. Windows keeps the rejects and does not
advertise the capability until wintun can take a v6 address. Design:
`docs/specs/2026-10-24-daemon-carries-ipv6.md`; the three gaps left are in
`ROADMAP.md`, "Recorded debt".

Agent guidelines reorganised along `agents.md` and Android's AI-tools
guides:

- `AGENTS.md` keeps only what applies to almost every change: orientation,
  the commands CI runs, code style, testing, security, the configuration
  surface, and commits. It is a third of its former length.
- Subtrees with their own build and contract carry their own `AGENTS.md`:
  `src/ffi/`, `src/bin/shoesd/`, `swift/`, `android/`.
- Procedures only some tasks need are Agent Skills under `.agent/skills/`:
  `implementing-a-protocol`, `adding-a-config-option`, `live-interop-check`.
- The recorded debt moved from `AGENTS.md` to `ROADMAP.md`, "Recorded debt".

## v0.8.0

The rest of Phase 3 and all of Phases 4 and 5 of the 2026-10-15 quality plan
(`docs/plans/2026-10-15-quality-and-correctness.md`): every client is now
checked against its reference for what it sends and when (#83-#88), the
known-answer vectors and reference-captured frames pin the cryptography and
first flights (#94-#97), the probe harness pins what every server shows a
stranger (#101, #102), and the sessions and UDP paths that lost data under
load are fixed (#89-#92). The steer plan's first two PRs (#99, #100) make
fake IP safe and let configs from other clients load. A review of the whole
wave (#105, `docs/audits/2026-10-22-fix-wave-review.md`) found every claimed
fix present and tested and closed the gaps beside them. The REALITY client
now reports a version current Xray servers accept (#104). The audit IDs
closed are MI-M1 to MI-M5 (#83); NA-N1, NA-N2 (#84); AT-A1 to AT-A4 (#85);
TR-3, TR-12 (#86); VM-D1, VM-D5 (#87); WG-A2 to WG-A4 (#88); HY-D5, TL-1,
DN-D1 to DN-D3 (#89); TU-D3, TU-D6, TU-D10 (#91); FI-1 (#92); VL-V5 (#101);
the version part of RE-R4/R7 (#104); and SF-1 to SF-5 and SF-10 of the steer
spec (#99-#102).

Behaviour changes to know before upgrading:

- **The REALITY client reports Xray-core 26.3.27, not 1.8.0** (#104). Xray
  v26.7.28 sends anything older to the decoy, which is what every Amnezia-
  installed server did to shoes. A server pinning `max_client_version` below
  26.3.27 now needs `client_version` set on the client.
- **With fake IP on, local names are no longer tunnelled** (#99):
  single-label names and `.local`, `.lan`, `.home.arpa`, `.internal`,
  `.localhost`, `.localdomain`, `.home` and the reverse zones resolve for
  real. `bypass_defaults: false` restores the old behaviour. **An unmapped
  fake IP is refused** rather than dialled: TCP gets a reset, UDP is dropped.
- **TLS-over-TCP servers refuse 0-RTT** (#89); nothing read the early data.
  QUIC servers are unchanged.
- **UDP DNS answers that do not echo the query's randomised case are
  dropped** (#89). A resolver that lowercases names will time out; point
  `dns` at one that does not.
- **The TUIC server sends no heartbeats and keeps an idle association for
  `udp_timeout` seconds, 300 by default** (#91), bounded 1 to 86400 (#105).
  The client sends one heartbeat per connection, not one per association.
- **AnyTLS and NaiveProxy clients reuse sessions** (#84, #85). A reused
  session means no new TCP connection or TLS handshake per proxied
  connection; AnyTLS closes sessions idle for 30 s and keeps
  `min_idle_session` (new, default 0).
- **The VMess client asks for global padding** (#87) and **mieru's open
  request carries the socks5 request, with the Go client's padding
  distribution** (#83): both now look like their reference clients on the
  wire.
- **AmneziaWG `s1`-`s4` and `jc` are 16-bit** (#88, #90); `jc` over 128 or
  junk larger than the tunnel's datagrams is refused at config load.
- A version-0 `.srs` rule set is refused, as sing-box refuses it (#101).
- `sni_hostname: ""` on a TLS, ShadowTLS or REALITY client sends no server
  name (#100, #105); with `verify: true` the certificate is checked against
  the address dialled. A REALITY client with no name and no hostname to
  fall back on is a config error instead of a panic.
- VLESS and VMess user ids load as a UUID of any version or a name of up to
  30 bytes (#100); only version-4 UUIDs loaded before.
- DNS over TCP to port 53 gets fake-IP answers, as UDP did (#92).

No change to the C or JNI surface or the `shoesd` protocol. New config
options, all documented in CONFIG.md with an example: `max_early_data` and
`early_data_header_name` (#86), `min_idle_session` (#85), TUIC `udp_timeout`
(#91), `bypass_defaults` (#99), REALITY `client_version` (#104).

REALITY client version (the version part of RE-R4/R7):

- **The REALITY client reports Xray-core's latest stable release, 26.3.27,
  instead of a fixed 1.8.0.** Xray v26.7.28 refuses clients below 26.3.27
  unless its config says otherwise, and the Amnezia app installs exactly
  that version, so every server it creates handed shoes to its decoy site
  and the client failed with a certificate error. A new `client_version:
  [major, minor, patch]` on the Reality client sets the version explicitly.

Review of the fix wave (`docs/audits/2026-10-22-fix-wave-review.md`, #105):

- Every fix claimed since v0.7.0 was checked against the code and the
  reference sources; all 37 are present and tested. The gaps found beside
  them are closed here.
- **A TUIC server's `udp_timeout` is bounded, 1 to 86400 seconds.** `0`
  loaded and reaped every association on the first sweep.
- **A TLS or ShadowTLS client with `sni_hostname: ""` sends no server
  name** instead of panicking when the chain is built, as REALITY has since
  S.2; a name rustls cannot hold is a config error. With no name sent and
  `verify: true`, the certificate is checked against the address dialled
  (hostname or IP) rather than against a placeholder no certificate has.
- **The SS2022 request is padded only when its first payload is under 900
  bytes**, as sing-shadowsocks pads it. A large first write used to carry a
  header no sing client sends.
- **A DNS group mixing the system resolver with a DoH/DoT one is rebuilt**
  on the same 10-minute policy as a pure group; it was built once and kept.
- Examples carry every option added since v0.7.0, and CONFIG.md documents
  the WireGuard and AmneziaWG clients, which it never had.
- Inbound checksums on a TUN stay unverified, on purpose: every inbound
  packet is the local kernel's, and Linux offload hands over unfinished
  ones. The audit row says so now.

Probe harness (plan PR 4.3, part 2; SF-10):

- What every TCP server shows a client that is not one is now a test.
  Five probes (a foreign ClientHello, an HTTP `GET`, 16 bytes then
  silence, random bytes, and shoes' own client with the wrong key) go to
  eleven servers on real loopback sockets. Each ends as data, a close or
  silence within a time bound. The table pins today's behaviour and names
  the reference family each cell matches. The cells that match none are
  REALITY and ShadowTLS closing where the references relay, plus three new
  findings recorded in `docs/specs/2026-10-22-probe-harness.md`.
- A slow drip of one byte every 5 s holds a connection open past every
  gap and is still cut at the 60 s setup deadline.

Checks against the references (plan PR 4.3, part 1; SF-10):

- shoes' REALITY ClientHello is compared with the one sing-box's REALITY
  client sent (the #95 capture): cipher list, every extension's body,
  groups, signature algorithms and key-share layout. They differ in one
  place, which the test now asserts: sing-box removes X25519MLKEM768 from
  its REALITY hello, and shoes offers it, as Xray's client does.
- A Vision stream reads the same however it is cut, at every offset and
  every pair of offsets. The check found that a first read of fewer than
  16 bytes was dropped. It is now returned as plain data, as is a first
  read too short to hold the UUID and a frame header, matching Xray's
  `XtlsUnpadding`.
- Rule-set matching is checked against `sing-box rule-set match` on 34
  cases across the fixtures, and corrupt files against what sing-box
  refuses. A version-0 `.srs` file is now refused, as sing-box refuses it.
  shoes still refuses a file whose zlib checksum is wrong or missing, which
  sing-box loads.

Configs that should load (steer plan PR S.2):

- VLESS and VMess user ids load as Xray and sing-box read them: a UUID of
  any version, so UUIDv7 ids work, or a name of up to 30 bytes, which
  stands for its version-5 UUID. Before, only version-4 UUIDs loaded. TUIC
  keeps the UUID form, of any version. A refused id is no longer repeated in
  the error (SF-5).
- A REALITY client with no `sni_hostname` and no hostname to fall back on
  is a config error instead of a panic. `sni_hostname: ""` and an IP
  address send a ClientHello with no server name, and a REALITY server
  answers such a hello from its `""` target (SF-4).

Fake IP safety (steer plan PR S.1):

- **Behaviour change: local names are no longer tunnelled.** With fake IP
  on, single-label names and names under `.local`, `.lan`, `.home.arpa`,
  `.internal`, `.localhost`, `.localdomain` and `.home`, plus the reverse
  zones, now resolve for real instead of getting a fake address that sent
  them into the tunnel, where they could not resolve. The query follows the
  rules for the resolver it was sent to, so reaching LAN hosts still needs
  a direct rule for the private ranges. `bypass_defaults: false` restores
  the old behaviour (SF-3).
- **Behaviour change: an unmapped fake IP is refused.** A connection to an
  address in the pool that stands for no domain (after a restart, or a
  recycle) used to be dialled as that address and stall until the app gave
  up. TCP now gets a reset at the SYN and UDP is dropped, so the app
  resolves again (SF-2).
- An address in use is no longer recycled. Connections now count as use
  alongside DNS answers, and an address is only reused after 10 minutes
  unused. Before, a domain the app kept connecting to without asking DNS
  again could lose its address to another domain, and the next connection
  reached that domain's server. When nothing can be recycled, the query
  gets the real answer and a warning is logged (SF-1).

Reference-captured frames (plan PR 4.2, part 2):

- mieru's open-session request, as the reference client sends it, decodes
  with shoes' segment decoder to the socks5 request shoes' own client sends.
  Hysteria2, TUIC, NaiveProxy and AmneziaWG move to the interop job (PR 4.3):
  their references do not expose their encoders, and TUIC's authentication
  is bound to the TLS session it was made in.

Reference-captured frames (plan PR 4.2, part 1):

- Client first flights from the sing references are replayed into shoes'
  servers: SS2022, VMess (TCP, and UDP with GlobalPadding), VLESS, XUDP New
  then Keep, AnyTLS, VLESS over sing-box's WebSocket with early data in the
  path, and VLESS Vision's first padded frame. Each yields the target and
  payload the reference was given. All of them already did.

Known-answer vectors (plan PR 4.1, part 2):

- ShadowTLS v3's ClientHello tag and data-frame HMACs are checked against a
  connection recorded between sing-shadowtls' own client and server.
  REALITY's AuthKey and SessionId seal are checked against a ClientHello from
  sing-box's client. The Reality TLS 1.3 key schedule is checked end to end
  against RFC 8448. All of them already matched.

Known-answer vectors (plan PR 4.1, part 1):

- Shadowsocks EVP_BytesToKey, its HKDF-SHA1 "ss-subkey" and the 2022 blake3
  subkey, Snell's Argon2id key, VMess's command key, KDF, crc32 and AuthID,
  the salamander key and mieru's PBKDF2 key are now checked against bytes the
  reference implementations computed (`tests/data/kat/`), not only against
  shoes' own other half. All of them already matched.

Fake IP over TCP (plan PR 5.3; FI-1):

- **DNS over TCP to port 53 gets fake-IP answers too.** Only UDP/53 was
  intercepted, so a resolver that fell back to TCP got real addresses and
  the domain rules never saw the name. Each TCP DNS message is now offered to
  the same responder; what it does not answer reaches the resolver the app
  addressed, through the rules, over one connection.

Dependencies and CI:

- rustls-webpki 0.103.16 and webpki-roots / webpki-root-certs 1.0.10, for
  RUSTSEC-2026-0381, -0382 and -0383 (distrusted intermediates).
- The root tproxy tests give their `setcap` copy of shoes a directory under
  `/var/tmp`: Ubuntu 26.04, now `ubuntu-latest`, mounts `/tmp` `nosuid`,
  which drops file capabilities.

awgtun 0.11.0:

- **AmneziaWG `s1`-`s4` and `jc` are 16-bit**, as amneziawg-go, the kernel
  module and amneziawg-tools parse them. A server whose `s2` is above 255
  could not be configured before. `jc` keeps its limit of 128.
- A padded message that does not fit its buffer is an error from awgtun
  rather than a panic.

TUIC UDP (plan PR 5.2; TU-D6, TU-D10, TU-D3):

- **Two TUIC UDP associations on one connection no longer take each other's
  replies.** Each ran its own reader on the shared connection and dropped
  what was not its own, so with two associations each lost about half its
  replies. One router per connection now hands each association its own
  packets, in both relay modes.
- **The client sends one heartbeat per connection**, while any stream or
  association is open, as the reference does. It sent one per UDP
  association, and none for TCP.
- **The server sends no heartbeats** (the reference client logs them as bad
  commands), and a UDP association lives `udp_timeout` seconds idle (new,
  default 300, sing-box's), not 60, so a quiet tunnel inside TUIC keeps its
  NAT mapping.

Performance fidelity and DNS (plan PR 5.1; HY-D5, TL-1, DN-D1 to DN-D3):

- **Hysteria2's BBR starts at upstream's 32-packet window**, not quinn's
  200. The first flight of a connection is no longer a burst no reference
  sends.
- **TLS-over-TCP servers refuse 0-RTT.** No handler read early data, so a
  resuming client's 0-RTT bytes were accepted and lost. QUIC servers still
  take it, since quinn reads it, so TUIC's `zero_rtt_handshake` is unchanged.
- **DNS queries over UDP randomise the name's case** (DNS 0x20), and an
  answer that does not echo it is dropped, which an off-path spoofer cannot
  do without guessing the case.
- **A busy DoH or DoT resolver is rebuilt every 10 minutes**, re-resolving
  its server's name through the bootstrap. Only idleness rebuilt it before,
  so a resolver in constant use kept the address it started with.
- **Cached system-resolver answers last 5 minutes**, not an hour.

AmneziaWG client parity (plan PR 3.7, AmneziaWG half; WG-A2 to WG-A4):

- **Handshake retransmits carry the reference's 0-334 ms jitter.** awgtun
  only claimed it in a comment, so every retry fired on a whole second; the
  retransmit and new-handshake timers now add it, as wireguard-go and
  amneziawg-go do (awgtun `7a78f45`).
- **A handshake's decoys always go out ahead of it.** The decoys were taken
  under a second lock after the initiation was made, so the timer task could
  send them with an ordinary packet and leave the initiation without them.
  They are now taken in the same critical section.
- **`jc` over 128, or junk larger than the tunnel's own datagrams (the MTU
  plus S4 plus 32), is refused** at config load. The kernel module refuses the
  first, and the path fragments or drops the second.

VMess client parity (plan PR 3.7, VMess half; VM-D5, VM-D1):

- **The VMess client asks for global padding** when it encrypts, as Xray's
  client does, so its chunks carry random padding in both directions. A
  client without it was one Xray never is.
- CONFIG.md notes that current Xray servers refuse `cipher: none`.
- The VMess AuthID checksum is renamed `crc32_ieee`: it is the IEEE CRC32
  Go's `ChecksumIEEE` computes, never the Castagnoli one its name said.

WebSocket early data and the SOCKS UDP address (plan PR 3.6; TR-3, TR-12):

- **WebSocket early data**, on both sides, with sing-box's names and wire
  format. `max_early_data` sends up to that many bytes of the client's first
  write in the upgrade request, base64url-encoded, saving a round trip.
  `early_data_header_name` puts them in that header instead of the path; Xray
  needs `Sec-WebSocket-Protocol`. The client sends its upgrade request with
  its first write, as sing-box does. A server target with either option
  accepts the data, and a client configured for it used to lose its first
  payload.
- **SOCKS5 UDP ASSOCIATE on a wildcard listener answers with a real
  address.** The reply named `0.0.0.0`; it now names the address the
  connection arrived on, and the relay is bound to it.

AnyTLS client sessions are pooled (plan PR 3.5b; AT-A1 to AT-A4):

- **The AnyTLS client reuses sessions** the way the reference client does,
  instead of opening a new TLS connection and session for every connection. A
  connection takes the most recently idle session, with no new TCP connection
  or TLS handshake, and the session goes back to the pool when the connection
  ends. Sessions idle for 30 seconds are closed, keeping `min_idle_session` (a
  new client option, sing-box's name, default 0). A server may refuse a client
  that never reuses.
- **The server's padding scheme is applied.** `UpdatePaddingScheme` used to be
  ignored, so the server resent it on every session. It now replaces the
  client's scheme for later packets and sessions.
- An unknown AnyTLS command is skipped instead of ending the session, and
  padding ranges are drawn from `[min, max)`, as the reference draws them.

NaiveProxy sessions survive a dropped connection (plan PR 3.5a; NA-N1, NA-N2):

- **A NaiveProxy client recovers when its connection to the server drops.**
  Its H2 session was never replaced: `is_ready` always answered yes and the
  slot was never cleared, so after one dropped connection -- a server restart,
  a network change on a phone -- every new connection failed until shoes
  restarted. A dead session is now noticed and the next connection dials a new
  one. Checked against sing-box's NaiveProxy inbound, restarted mid-run.
- **Reusing the NaiveProxy session no longer dials a TLS connection it throws
  away.** Every proxied connection used to open and handshake a fresh TLS
  connection only to drop it unused when a session already existed. The chain
  now asks a hop for a live session before it dials (a new
  `try_reuse_tcp_stream` on `TcpClientHandler`, forwarded through TLS), so a
  reused session means no new TCP connection and no TLS handshake. Spec:
  `docs/specs/2026-10-19-session-reuse-without-dialling.md`; AnyTLS's session
  pool will use the same hook.
- A NaiveProxy stream the server has already reset shuts down cleanly. Against
  a sing-box server every connection used to end with an `ERROR ... H2 send
  END_STREAM failed: inactive stream` log line.
- The NaiveProxy server cuts a 200-1024-byte write into 100-200-byte pieces,
  as naiveproxy's server does, instead of 400-1024 into 200-300.

mieru looks like the Go client (plan PR 3.4; MI-M1 to MI-M5):

- **mieru padding lengths follow the Go client's distribution.** Every length
  goes through a port of mieru's `rng.Intn`, a uniform draw scaled by
  `sqrt(u^3)`, so data padding averages about 51 bytes where it averaged 128.
  The printable run is one length for the process, as upstream fixes it per
  host, and its bytes are made printable as `ToPrintableChar` does.
- **The open request carries the socks5 request**, as the Go client sends it,
  instead of a data segment one round trip later: a mieru connection is ready
  one round trip sooner. A first write over 1024 bytes still follows as data.
- **A session ends with the close handshake.** Shutting down sends
  closeSessionRequest before the FIN, and a closeSessionRequest from the
  server is answered with closeSessionResponse.
- Data segments carry the Go client's receive window instead of zero, a
  segment freeing its slot when its first byte is read. `unack_seq` and
  `fragment` stay 0, which is what upstream sends over TCP.

Checked against the mieru server (mita 3.38.1) in Docker: small requests and
8 MiB intact, and the server logging the close handshake.

## v0.7.0

Phase 1 of the 2026-10-15 quality plan
(`docs/plans/2026-10-15-quality-and-correctness.md`) -- the Rust foundations --
and the first client-fidelity work of Phase 3. The audit IDs closed are Q-1 to
Q-4 (#60); A-1, A-6, A-8 (#61); A-3 (#62); A-2 (#63-#69); A-4 (#70, #71); A-7
(#73); A-9 (#75, #77); SS-D7 (#79); VL-V3 (#80); and the client half of RE-R2
(#81). ST-S1 is deferred with its reason recorded (#78).

Behaviour changes to know before upgrading:

- **A config with an unknown or misspelled field in a `protocol:` block no
  longer loads** (#69). It used to load with the setting silently ignored.
  Run `shoes check` on configs an app or a script generated.
- Malformed user ids, WireGuard keys and prefixes, port-hopping ranges and DNS
  URLs fail when the config loads, naming the field, where some used to fail
  later or panic (#64-#67).
- A reload lets the previous configuration's connections finish for up to
  30 seconds, then cancels them (#71); before, they ran on with nothing
  owning them.
- Trojan and Shadowsocks clients send their header with the first payload
  (#79), and VLESS Vision sends its request inside the first padded frame
  (#80). A protocol where the server speaks first (SSH, SMTP) starts up to
  300 ms (Trojan, Shadowsocks) or 500 ms (Vision) later.
- The Reality client sends a Chrome 133 ClientHello with an X25519MLKEM768 key
  share (#81). It is about 1.8 KB, and the client now also completes the
  ML-KEM exchange when the decoy picks it.
- h2mux's `max_connections`, `min_streams` and `max_streams` have no effect
  and log that they don't (#60); they never did.

No change to the C or JNI surface (#77), the mobile size budget (#74 brought
the arm64 library back under it), or the `shoesd` protocol.


Lints, dead code and unsafe hygiene (plan PR 1.1; Q-1 to Q-4):

- **h2mux client sessions are no longer kept forever.** Every connection's
  session was pushed into a pool that only dead code ever pruned, so a
  long-running h2mux outbound held every session it had opened. The pool and
  the unused `max_connections`, `min_streams` and `max_streams` handling are
  gone; the three settings still load, and setting one logs that it has no
  effect -- each connection has always opened its own session. CONFIG.md says
  so.
- **The `shoes` binary no longer panics on a watcher it cannot start.** The
  file watcher is built after the first configuration loads, so a missing
  file is reported by the load, and a watcher that fails (an inotify limit)
  costs reload-on-edit rather than the servers; SIGHUP still reloads.
- **The library's thread count defaults** to the binary's (the CPU count, at
  least two) where nothing set it, instead of panicking -- the QUIC endpoint
  count under FFI or `shoesd` reached it.
- **XUDP resolves hostnames through the server's configured resolver**, so
  DNS routing and fake IP apply, instead of a fresh system resolver per stream.
- **TCP keepalive is set on Windows**, where `set_tcp_keepalive` did nothing.
- A `[lints]` table: `unsafe_op_in_unsafe_fn` and
  `undocumented_unsafe_blocks` deny, `unwrap_used` and `expect_used` warn
  (tests exempt in `clippy.toml`; files that predate the lint carry a
  file-level allow). Every unsafe block has a SAFETY comment; the raw-fd
  conversions in `socket_util` and the DNS runtime are safe conversions now.
- Dead code removed: `stream_worker_pool.rs`, `udp_message_stream.rs`, three
  FFI functions, the unused h2mux items, `outbound_stats::Entry.address`.
  Crate-root and FFI docs describe the real entry points.

One crate, one pipeline (plan PR 1.2; A-1, A-6, A-8):

- **The `shoes` binary links the library** instead of compiling its own copy
  of every module. The library's crate-wide `allow(dead_code)` is gone with
  it, and the allows that only existed for the second copy. The binary's test
  target no longer runs the whole suite a second time.
- **One server pipeline.** `control::servers` loads certificates, validates,
  builds the DNS registry and starts servers, for the binary and the TUN
  hosts alike. A configuration whose second server fails to start no longer
  leaves the first one running under a TUN host.
- **The generic QUIC transport uses `quic_transport`'s accept loop**, with
  quinn's default parameters as before; a failed stream is logged at the
  level its cause warrants.
- **`shoesd` reports a stop the supervisor could not confirm as timed out**,
  not released, so a client does not reuse a device nothing vouched for.

Typed outcomes at the layer boundaries (plan PR 1.3; A-3):

- **A socket's own `EACCES` is no longer cached as a routing block.** The UDP
  router used `PermissionDenied` to mean "blocked by rules", so a real
  permission failure kept its destination unreachable for as long as the
  block cache held it. A block is now an outcome of its own; a failure is
  retried on the next packet.
- **`on_exit` carries an `ExitReason`** -- `Failed(message)` or
  `EndedUnrequested` -- instead of an optional string, and the FFI tells a
  stop's own echo from a real failure by that variant rather than by
  comparing sentences. A failure whose message happened to read like the
  unrequested sentence used to be discarded.
- **`shoesd` answers a config this platform cannot run with
  `FAILED_PRECONDITION`**, not `INVALID_ARGUMENT`: the document is well-formed,
  and what fails is the host.

- **YAML parsing moves to `serde_norway`**, a maintained fork of the
  archived `serde_yaml` 0.9 with the same behaviour, which takes the
  unmaintained `unsafe-libyaml` (RUSTSEC-2024-0449) out of the build. The
  security-advisory check is green again.

Parse, don't validate: user ids (plan PR 1.4, part 2; A-2):

- **VLESS, VMess and TUIC user ids are parsed when the config loads**, into
  a `Uuid` the handlers take as bytes. Client-side ids were never checked at
  load: a malformed one panicked when its handler was built. One of the
  shipped examples, `socks_through_vmess.yaml`, had exactly that typo and is
  corrected.

- **WireGuard and AmneziaWG keys and prefixes are parsed when the config
  loads** (`WgKey`, `IpPrefix`), and the tunnel takes the parsed values. The
  error names the field -- `preshared_key: key must be 32 bytes, got 3` --
  where it used to say "AmneziaWG" for a plain WireGuard config too.

- **Hysteria2 `port_hopping` is parsed into its hop settings when the config
  loads.** Every rule -- the port set, port 0, interval exclusivity, the
  5000 ms floor -- is checked in one place, and the runtime no longer
  re-parses and `expect`s it.

- **DNS server and bootstrap URLs are parsed once**, during config
  expansion; the TUN-DNS check and the resolver builder use the parsed form
  instead of parsing the string again.

- **Config parsing is read one way per concept.** A rule's action is parsed
  by one function whether it sits beside its masks or on its own; the
  top-level entry types are told apart by one ordered table, with a test that
  every type, written back out, is read back as itself; a server entry's
  unknown fields are refused by serde rather than a hand-kept list.

- **A misspelled field in a protocol block is an error.** `protocol:` blocks,
  inbound and outbound, ignored unknown fields: `usrname:` on a SOCKS
  inbound or `pasword:` on a Trojan outbound loaded, and the setting the
  user meant silently did not apply. Both are refused at load, naming the
  field and the expected ones. **A config that carries extra fields in a
  protocol block -- one an app generated, say -- now fails to load.**
- A property test checks that a generated config parses, writes back, and
  parses to the same thing.

Cancellation and waiting (plan PR 1.5, part 1; A-4 in part, A-8):

- **A SOCKS5 UDP association releases its port when it ends.** Its reader
  task was aborted only by an explicit shutdown; on the normal end, the TCP
  control connection closing, it stayed parked in `recv`, holding the bound
  socket for the life of the process.
- **Stopping a service waits on its exit instead of polling** every 5 ms, and
  `shoesd` waits on the TUN device being published instead of every 20 ms.

Connection ownership (plan PR 1.5, part 2; A-4):

- **A reload drains the previous configuration's connections instead of
  orphaning them.** The accept loops stopped on a reload, and every live
  connection ran on, on the old rules and outbounds, with nothing that could
  end it. The binary now closes the old listeners, starts the new
  configuration at once, and lets the old connections finish for up to 30
  seconds before cancelling the rest; it logs how many did which. A stop
  (SIGTERM, SIGINT) cancels them outright. TUN hosts end their listeners'
  connections with the service.
- Connections are owned by the launch that accepted them -- TCP, Unix-socket,
  QUIC (generic, Hysteria2, TUIC) and tproxy listeners, and the work a
  connection detaches (mux sessions, UDP associations, per-stream tasks).
- **The mobile library is 377 KB smaller than before connection ownership,
  instead of 620 KB larger.** `connections::spawn` boxes the future it is
  handed, so the set's wrappers and tokio's task harness compile once, not
  once per spawned future type. The arm64 `.so` is 9,548,384 bytes; the size
  baseline is lowered to match.

One trait per concern (plan PR 1.6, part 2; A-7):

- `AsyncStream`'s two socket queries, `plain_tcp` (for `splice`) and
  `original_destination` (for tproxy and redirect), move to their own
  `SocketPassthrough` trait, a supertrait of `AsyncStream`. Every stream
  states whether it hands its socket through, rather than inheriting a
  default inside the stream trait; the wrappers that encrypt or re-frame say
  so with an empty impl.

One attribution path (plan PR 1.6, part 3; A-9 in part):

- Outbound traffic attribution is written once instead of once per feature
  setting. Without `control-stats` the counter handle is a zero-sized type
  and `count_tcp`/`count_messages` hand the stream back unwrapped, so the
  chain, the chain builder and the TUN stack carry no `cfg` of their own:
  the crate goes from 97 `control-stats` gates to 31, most of what remains
  being the feature's own implementation and the tests that read counters.
  The shipped (with-stats) arm64 library is 664 bytes smaller; a build
  without the feature is 5,632 bytes larger.

One session value on the FFI side (plan PR 1.6, part 4; A-9):

- The mobile FFI keeps a session as one value -- the service handle and, on
  iOS, the stopped callback -- installed whole by `start` and taken whole by
  `stop`, where it was three parallel statics (`TUN_SERVICE`,
  `STOPPED_CALLBACK`, `PROTECT_CALLBACK`). The socket protector and traffic
  callback are installed by one function and cleared by the stop on both
  platforms; the iOS protector holds its callback itself. No change to the C
  or JNI surface or to callback timing.

First flight carries the payload (plan PR 3.2, part 1; SS-D7):

- **Trojan and Shadowsocks clients send their request header with the first
  payload** instead of flushing it as a record of its own, as the reference
  clients do -- a fixed-size first record on every connection was a cheap rule
  to match. For SS2022 the payload is now inside the request's
  variable-length header, as SIP022 lays it out. Up to 8 KiB of the first write
  joins the header. A client that writes nothing (a server-first protocol such
  as SSH or SMTP) sends the header alone after 300 ms, the wait sing-box uses
  (`C.ReadPayloadTimeout`), so those protocols start up to 300 ms later; a
  shutdown sends it at once.
- **The VLESS Vision client sends its request inside the first padded frame.**
  It wrote the request as a TLS record of its own before the Vision stream
  existed -- about 60 bytes, the same on every connection -- where Xray puts it
  in the same record as the first padded frame. When the client has nothing to
  send first, the request goes out with an empty long-padded frame after
  500 ms, as Xray's outbound does. A Vision server likewise sends its two-byte
  response in the same record as its first frame.

Reality client looks like Chrome (plan PR 3.3, part 1; RE-R2 client half):

- **The Reality client sends a Chrome 133 ClientHello** (uTLS `HelloChrome_133`,
  what sing-box and Xray clients send by default) instead of a six-extension
  hello with X25519 only: GREASE, Chrome's 15 cipher suites, the full extension
  set in an order shuffled per connection, a GREASE ECH extension, and an
  X25519MLKEM768 key share ahead of X25519. When the decoy picks the hybrid,
  the client completes the ML-KEM-768 exchange (aws-lc-rs). This also makes the
  client work against Xray's REALITY, which refuses a hello without the hybrid
  share. Checked against sing-box 1.14.3 with the decoy choosing
  X25519MLKEM768, with it restricted to X25519, and with Vision. Spec:
  `docs/specs/2026-10-19-reality-chrome-client-hello.md`.

## v0.6.0

Phase 0 of the 2026-10-15 quality plan
(`docs/plans/2026-10-15-quality-and-correctness.md`): every reachable abort
becomes an error, and the correctness bugs with a known consumer are fixed.
The audit IDs closed are SS-D1, SS-D2, ST-S3, RE-R6, VL-V4 (#55); RS-1,
WG-A1, TN-T1, TN-T2, TN-T3, TR-2, XU-X1 (#56); VM-D2, XU-X2, XU-X3, HY-D2,
TU-D4, H2-4 (#57); TR-5, TR-6, TR-7, TR-8, TR-11 (#58).

Behaviour changes to know before upgrading:

- The `clash_api` block is refused at validation (#54).
- A WebSocket client with no `Host` in `matching_headers` now sends the
  proxy address as `Host`, where it sent none (#56).
- Hysteria2 and TUIC replies carry their real source address, not the
  hostname the client asked for (#57).
- After a WebSocket peer sends Close, writing to the stream is an error
  (#58).

The project narrows its focus to the mobile clients, the desktop clients
over `shoesd`, and performance and stability. The awg-manager engine and
any web panel are postponed, and the Clash API built for them is removed:

- **Removed the `clash_api` config block, the `clash-api` and
  `control-connections` features, the controller, the Prometheus `/metrics`
  endpoint and the per-connection registry.** A config that still carries a
  `clash_api:` block is refused at validation as an unknown block, so an
  operator hears about it at `check` rather than after a restart. No mobile
  or daemon surface changes: neither ever served the controller, and
  `control-stats` counters are untouched.
- **`scripts/build-keenetic.sh` defaults to no features** instead of
  `clash-api`. The Keenetic build stays; its specs moved to git history.

No peer or config can abort the process any more through these paths, all
reachable under `panic = "abort"` (audit 2026-10-15, SS-D1, SS-D2, ST-S3,
RE-R6, VL-V4):

- **Snell UDP drops a datagram too large for one Shadowsocks chunk** instead
  of panicking; a target answering with a 16–65 KB datagram used to take the
  process down. The Shadowsocks message writer returns `InvalidInput` for one.
- **A Shadowsocks 2022 key of the wrong length is refused at config load**,
  naming the cipher and the length it needs, instead of aborting on the first
  stream.
- **ShadowTLS consumes an authenticated empty data frame and never sends
  one**; either used to trip an assertion.
- **A REALITY peer that sends KeyUpdate fails the connection** rather than
  aborting. The client discards a NewSessionTicket and keeps reading.
- **Vision splits a padded write over 8171 bytes into several frames**, as
  Xray does; one of 64 KB or more used to wrap the u16 length and corrupt the
  stream.

Seven correctness bugs, each with a known consumer (RS-1, WG-A1, TN-T1,
TN-T2, TN-T3, TR-2, XU-X1):

- **A sing-box rule-set mixing IPv4 with low IPv6 ranges loads.** One holding
  `::1/128` or `64:ff9b::/96` next to IPv4 was refused as unsorted, which
  failed the whole config.
- **AmneziaWG and WireGuard initiations carry a random sender index.** It was
  always `0x000000xx`, in clear, on every shoes client.
- **`icmp_enabled: false` drops ICMP.** It was stored and never read, so ping
  through the tunnel was still answered.
- **A SYN over the TUN connection cap is reset** rather than dropped, so the
  client fails at once instead of retrying for a minute.
- **The TUN drops IP fragments.** Nothing reassembles them, and a UDP
  fragment was read as a whole datagram.
- **WebSocket and HTTPUpgrade clients always send `Host`**, which Go servers
  require. WebSocket takes it from `matching_headers`, else the proxy address
  as dialled; HTTPUpgrade from `host`, else the TLS server name, else the
  address -- sing-box's orders. CONFIG.md said otherwise and is corrected.
- **XUDP consumes data attached to a KeepAlive or End frame**; it used to
  read the next frame from the middle of it.

Mux and session correctness against the reference clients (VM-D2, XU-X2,
XU-X3, HY-D2, TU-D4, H2-4):

- **VMess UDP writes the padding its chunk length declares.** With global
  padding, on by default for AES and ChaCha in Xray, the reader lost the
  chunk boundary at the first non-zero padding.
- **The XUDP server keeps the client's session ids.** Each packet is
  reported under the id it arrived with, and each response is a Keep frame
  echoing it, as Xray's mux server answers. Ids used to be invented per
  destination and sent with New, so mux.cool clients (Xray `xudpConcurrency`,
  sing-box mux with XUDP) dropped every response. A Keep for an unknown
  session is answered with End instead of failing the connection; frame
  metadata over 512 bytes is refused; a response over 7526 bytes is dropped,
  as Xray's own writer drops it.
- **Hysteria2 and TUIC send each UDP datagram to the target it names.** A
  session opened with a hostname used to be pinned to that hostname's
  address for its whole life, with replies relabelled as the hostname.
  Replies now carry their real source, IPv4 sources as IPv4.
- **TUIC holds uni streams that arrive before Authenticate** and runs them
  once the client authenticates. They were read and discarded, which lost
  the first packet of a `quic`-mode association, often a DNS query.
- **h2mux declines the sing-mux TCP Brutal exchange** the way a sing-box
  server without brutal does. It used to dial `_BrutalBwExchange` as a
  hostname, fail, and make a brutal-enabled client tear the session down.

The inbound edge answers as the RFCs say it MUST (TR-5, TR-6, TR-7, TR-8,
TR-11):

- **SOCKS5 says why it refuses.** `05 FF` when no offered method is
  acceptable, `01 01` on a failed login, `07` for BIND, and a reply before
  closing when CONNECT fails: `02` when the rules block it, `05` when it is
  refused, `03`/`04` when unreachable, `01` otherwise. Clients used to see
  only a closed connection.
- **The HTTP proxy answers a wrong password with 407**, as it does a missing
  one, so a browser asks again instead of reporting a network error.
- **The WebSocket server checks the handshake and answers it as RFC 6455
  does**: `101 Switching Protocols` with no `Host` echoed, 400 for a request
  that is not an upgrade, 426 naming version 13 for another version, 404 for
  a path no target serves.
- **WebSocket frames:** a ping may carry up to 125 bytes (it was refused over
  80), a pong's payload is skipped instead of failing the connection, and a
  Close is answered with a Close and ends the stream. A ping with any payload
  used to desync the stream: its payload was read again as a frame header.
- **A hostname over 255 bytes is refused** when encoding a SOCKS-style
  address (SOCKS, Shadowsocks, Trojan, AnyTLS, Mieru) instead of wrapping its
  one-byte length and misframing the stream.

## v0.4.1

`awgtun` 0.9.0 -> 0.10.0, which is a dependency bump and nothing else: no
shoes source changed, and every test configuration is unchanged and green.

Two things in that release matter to an AmneziaWG tunnel, and both are
behavioural rather than API:

- **`DisableCookies` now gates the whole under-load path** rather than only
  suppressing the cookie reply, following upstream boringtun. Previously the
  rate limiter still demanded a valid MAC2 while the peer never received the
  cookie needed to build one, so every handshake against a busy device died in
  silence -- worse than not having the switch. shoes drives `Tunn` with no rate
  limiter, so this reaches shoes only through what a *peer* will now accept.
- **AWG 3.0 content padding is bounded by the sliding UDP window rather than
  the MTU**, following amneziawg-go `da11c9f` and the kernel module `7fc0145`,
  with the MTU kept as a second bound. A padded packet now grows towards the
  sizes the tunnel has actually carried instead of towards the link size. This
  is the same mechanism behind the ~8x ACK-stream inflation recorded in
  `docs/awg-throughput-findings-2026-09-01.md`, so a 3.0 tunnel's upload
  overhead changes shape; `content_padding_addition` is still the setting that
  controls it.

`awgtun` 0.10.0 also makes `RateLimiter::verify_packet` take a
`disable_cookies` argument, which is a breaking change in that crate and not
one shoes can see: shoes uses the `Tunn` path and constructs no rate limiter.
The new `Tunn::set_mtu` is likewise for awgtun's own device loop, which polls a
live interface -- shoes passes its MTU in `Amnezia3Config` at construction and
has nothing to poll.

## v0.4.0

`shoesd` gains a Linux arm. Nothing in the library's public surface changed --
`src/` is untouched apart from moving a test module -- so a library consumer,
the CLI and both mobile artifacts are unaffected. The minor moves because there
are two new shipped artifacts and a second platform the daemon configures a host
on, which is what a minor is for under 0.x.

### The daemon still has not run, on either platform

`shoesd-linux-x86_64.tar.gz` and `shoesd-linux-arm64.tar.gz` are published for
the first time, and as with the macOS artifact in 0.3.0, **no part of what they
do to a host has executed against a real session** -- no `ip route`, no
`resolvectl`, no `systemctl`, and no netlink notification from a real network
change. Everything is unit-tested. Treat it as a candidate for the live run
rather than as tested software; [docs/LINUX.md](docs/LINUX.md) and
[the plan](docs/plans/2026-09-04-linux-privileged-daemon.md) carry the nine
checks it owes.

What *is* verified, and was not last release: the Linux arm now compiles and
runs its tests in CI. Both daemon jobs were gated to macOS, so until this
release the Linux half of `src/bin/shoesd/` was built by nothing. That gate
came off, and the first run of the new job immediately found a test asserting a
group name that does not exist on Ubuntu.

### A Linux `HostNetwork`: routes, DNS, and a netlink monitor

Routes go through `ip` by absolute path, with native `blackhole` and
`unreachable` types rather than the loopback-and-flag shape macOS needs. The
default gateway is read from `ip -j route show default` as JSON, skipping
gateway-less entries -- a point-to-point default has none, and taking it would
send an excluded address into the tunnel it is excluded from -- while reading a
**multipath** default's gateways out of its `nexthops` array, because that entry
also has no top-level `gateway` and skipping it would blackhole the proxy on
every bonded host.

DNS is two backends chosen by a probe at startup and reported to clients as
`dns-backend:` in `Hello`'s `capabilities`. Where systemd-resolved is genuinely
in the path, the resolvers go on the **tunnel's own link**, where nothing
competes for them and the configuration dies with the link. Otherwise
`/etc/resolv.conf` is managed directly, with an inotify watcher because
NetworkManager and `netconfig` both rewrite it on their own schedule.

**"systemd-resolved, where it is running" is not the test**, and getting that
wrong leaks DNS silently: in resolved's `uplink` and `foreign` modes it is
running, `resolvectl dns <link>` succeeds, and `/etc/resolv.conf` still lists
the real upstream servers that every glibc client reads. The probe requires the
stub to actually be in that file -- every nameserver, not merely one, since a
file listing it beside an upstream server is one glibc falls back from under
load.

The direct backend's backup records whether the path was a symlink and where it
pointed, and the original bytes when it was a regular file. Restoring a
flattened regular file where a symlink was breaks a host permanently, and
rebuilding from the parsed resolver list drops `search`, `options` and
`sortlist` -- a host whose short names stop resolving after a session ends,
with nothing connecting it to the VPN.

### Coexisting with another VPN, answered rather than deferred

Two links each claiming a `~.` routing domain is a resolved priority contest.
Tailscale in its default configuration sets no `~.`, so MagicDNS keeps working
and everything else comes to the tunnel with no interference either way. As an
exit node it does, and then resolved queries both links in parallel and takes
the first answer -- which nothing on our side can resolve, so the daemon logs a
warning naming the other link rather than producing a tunnel whose DNS is
nondeterministic.

### Install: a systemd unit, and two Linux-shaped hazards

The administrators' group is not portable -- `wheel` on Fedora, Arch and
openSUSE, `sudo` on Debian and Ubuntu, and `admin` nowhere -- so `install`
detects it, requiring that the group both exist *and* contain the invoking
user. `adm` exists on Fedora and is empty, so a rule stopping at "exists" would
install a socket the administrator cannot reach.

Two things that would have been silent. `ExecStart` expands `%` specifiers at
unit **load** time, inside double quotes, and `$` at exec time, so a socket path
containing `%h` would have become a different path in a job running as root;
both are escaped. And `Restart=always` is not `KeepAlive`: systemd *stops*
restarting a unit that fails five times in ten seconds, where launchd throttles
and keeps trying -- which would have abandoned a crash-looping daemon with its
routes and `resolv.conf` still applied, on a machine whose network is down. The
unit sets `StartLimitIntervalSec=0`.

### glibc only

The Linux daemon artifacts are built from the gnu targets and there is no musl
build. A statically linked musl `shoesd` uses musl's own `getpwuid_r` and
`getgrnam`, which read `/etc/passwd` and `/etc/group` directly and know nothing
of NSS -- so on an SSSD- or LDAP-backed host the peer-credential check and the
install-time group detection would both fail to resolve a real user, giving a
daemon that refuses everyone with nothing in the error saying why. The `shoes`
CLI's musl artifacts are unaffected.

## v0.3.0

The minor moves rather than the patch. `control::StatusSnapshot` gained a
field, so anything constructing one no longer compiles; a macOS TUN config that
was previously accepted and did nothing is now validated and may be rejected at
startup; and there is a new shipped artifact. Under 0.x that is what a minor
bump is for.

### `shoesd` ships, and has never run

`shoesd-macos-arm64.tar.gz` is published for the first time, and **no part of
what it does to a host has executed yet** -- no `route`, no `netstat`, no
`launchctl`, no `SCDynamicStore` write, and no `PF_ROUTE` notification against
a real network change. Everything is unit-tested, and the gRPC surface is
exercised over a real Unix socket against a recording double, which is not the
same thing.

It is shipped anyway because the live run needs an artifact to install, and
withholding it would block the only thing that can verify it. Treat this
release's daemon as a candidate for that run rather than as tested software.
`docs/MACOS.md` and `docs/plans/2026-09-04-macos-privileged-daemon.md` carry
the five checks it owes.

The rest of the release -- the CLI, both mobile artifacts, the Apple
XCFramework -- is unaffected: the daemon is behind a `daemon` feature whose
dependencies sit under a macOS target section, so every other build compiles
none of it.

### A privileged macOS daemon, and a macOS TUN path that works

The macOS TUN path had never run, and the reason was structural rather than
incidental: everything that makes a device usable -- name, address, netmask,
destination, `up()` -- was applied inside `cfg(target_os = "linux")`, and
`validate_tun_config` had arms for Linux, Android, iOS and Windows and none for
macOS. A macOS TUN config was therefore accepted and then quietly did nothing.
Both arms now exist, and the interface name the kernel assigns is reported
through `control::StatusSnapshot::device_name` -- a host needs it and cannot
derive it, because choosing a `utun` unit races every other utun user on the
machine.

Two things surfaced while doing that. A TUN entry was recognised only by
`device_name` or `device_fd`, so the shape a privileged host writes -- no
descriptor, and deliberately no name -- parsed as a *server* config; `netmask`
and `destination` join the discriminators. And `destination` is warned about
rather than required: the `tun` crate hazard that would have justified
demanding it is not on the path shoes takes, and requiring it would have made
macOS the only platform whose valid config Windows refuses.

On top of that, `shoesd`: a root launchd daemon behind a new `daemon` feature,
shipped as `shoesd-macos-arm64.tar.gz`. It hosts `shoes::control` in-process
and serves a desktop GUI over gRPC on a Unix domain socket, with the `.proto`
owned in this repository. It configures the host -- the split default route, a
host route per excluded address so the proxy's own connection escapes the
tunnel, IPv6 rejects, and DNS through `SCDynamicStore` -- and reverts all of it
on stop, on a failed start, and after a crash, from a record written before
each change rather than after it.

shoes itself still touches none of that. Nothing under `src/` configures routes
or resolvers; the daemon is a host, in the same seat as the iOS packet-tunnel
provider, and it links the library rather than crossing a C boundary. Every
other build -- the CLI, both mobile artifacts, a library consumer -- compiles
none of it.

Authentication is the socket's peer credentials, `uid == 0` or membership of
one group. No token, no TLS, and no TCP listener: a loopback port is reachable
by every process on the machine.

The live run on Apple Silicon is still outstanding, and `docs/MACOS.md` says
so.

## v0.2.20

### AmneziaWG upload is two to four times faster, and the reason corrects v0.2.19

v0.2.19 raised the receive window and said the send buffer stays at 256 KiB
everywhere, deliberately, because raising it had measured upload getting
*worse*. That measurement was real and the conclusion was wrong. The send
window is the same `window / RTT` ceiling on upload that the receive window is
on download -- 256 KiB caps a 24 ms path at ~85 Mbit/s however fast the link --
and what made raising it backfire was never pacing in the abstract: smoltcp
dumps an opened window into the tunnel's outbound channel in one poll, the
256-slot channel overflowed, and the stack's own dropped segments read back to
Cubic as path congestion. The bimodal 13-55 Mbit/s upload this produced is the
"falls into a bad state and climbs out of it" spread ROADMAP.md used to carry
as an open risk.

Three changes, each closing the failure the previous one exposes:

- **The virtual device backpressures instead of letting the channel drop.**
  `transmit` refuses tokens past the channel's free slots, so a burst waits in
  the socket's own buffer, and what a poll emitted but the channel would not
  take carries to the next pass. Correct for any window size, any number of
  concurrent uploads, any MTU -- and the channel stays at 256 slots, so DNS,
  SYNs and a concurrent download's ACKs never queue behind a deep FIFO.
- **The send window is sized per platform like the receive window**: 1 MiB on
  desktop, 512 KiB on Android, 256 KiB inside an Apple Network Extension
  (unchanged there -- the same ~50 MB kill limit that pins the receive window).
  Single stream at 24 ms measured 56 / 102 / 136 / 156 Mbit/s at
  256 KiB / 512 KiB / 768 KiB / 1 MiB, zero drops at every size.
- **The endpoint UDP socket asks for real buffers** (4 MiB each way,
  best-effort descending -- macOS gives a datagram socket ~9 KB by default,
  which surfaced as a thousand consecutive ENOBUFS once the channel stopped
  dropping), and a send that hits transient ENOBUFS waits it out briefly
  instead of converting kernel queue pressure into loss.

Interleaved against v0.2.19 on the same minutes: single-stream upload median
52 to 82 Mbit/s with 143-157 in stable windows, four-stream aggregate 41 to
~192 Mbit/s, download unchanged at path rate. The memory cost lands on the
send buffer, which is lazy -- resident only to the extent an upload fills
it -- and the per-platform ceilings in MOBILE.md moved accordingly (Android
worst case 368 to 432 MiB, desktop per-connection 4.625 to 5.375 MiB
allocated).

### A config that would fragment now says so at startup

A full-size AmneziaWG transport packet reaches the wire at `mtu + s4 + 60`
bytes, and S4 -- unlike the content padding and the random trailer -- is never
clamped against the MTU. Amnezia's own generator pairs MTU 1420 with S4 drawn
up to 27, so a copied config silently fragments every large packet as soon as
S4 >= 21. shoes now warns at startup when the sum crosses 1500. The example
config documents that rule and one more from the same survey: with random
trailers on, keep S1-S4 equal on the server side -- unequal values expose a
classifier defect in unpatched amneziawg-go peers that silently drops ~3.5% of
transport packets (amnezia-vpn/amneziawg-go#183; the AmneziaWG implementation
this crate ships is immune in both directions, but only one end of a tunnel is
ever shoes).


## v0.2.19

### AmneziaWG download is roughly three times faster

One constant fed both smoltcp socket buffers, so an AmneziaWG connection's
receive window was 256 KiB. smoltcp never auto-tunes, which makes that a hard
ceiling of `window / RTT` on download. Measured against an AmneziaWG 3.1 peer
at 26 ms RTT, alternating each request with a native `amneziawg-go` tunnel to
the same server so path drift hit both arms equally, that was **47.5 Mbit/s
where the kernel stack over the same tunnel reached 156.7**. Crypto was not the
limit -- 34% of one core against `amneziawg-go`'s 125-140%.

The receive window is now sized apart from the send buffer, and by platform:
4 MiB on desktop, 1 MiB on Android, 256 KiB inside an Apple Network Extension.
The send buffer stays at 256 KiB everywhere, deliberately -- raising both to
2 MiB took *upload* from 49 to 16.6 Mbit/s, because smoltcp does not pace and a
send buffer larger than the tunnel's queue bursts into drops that Cubic reads
as congestion.

**This costs memory, and the receive window is the one buffer that does not get
the zero-page discount** -- a sustained transfer wraps smoltcp's ring across the
whole thing, so it goes fully resident. A desktop connection now allocates
4.625 MiB against 704 KiB before. The per-platform ceilings are tabulated in
`src/buffer_sizing.rs` and MOBILE.md. Both are defaults, and the TUN side's
`tcp_buffer_size` still covers the device half.

### The macOS Network Extension gets an extension's buffer budget

The per-connection buffer sizes split on `target_os`, but the constraint they
model is "runs inside a Network Extension" -- and macOS is where those two
diverge. `aarch64-apple-darwin` builds both the XCFramework slice that
`ShoesPacketTunnelProvider` links and the desktop binary, so the macOS
extension was silently taking desktop's: a 4 MiB receive window against 1024
connections, an allocation ceiling near 4.25 GiB where iOS sits at 176 MiB.
`scripts/build-apple.sh` now sets a `network-extension` feature on every Apple
slice and `src/buffer_sizing.rs` keys the budget off that instead. A macOS
extension takes iOS's sizes, which is conservative rather than measured -- its
real limit is still unverified, and docs/MACOS.md records that as the knob to
revisit. **No effect on the desktop binary or on iOS**; only the macOS slice of
the XCFramework changes.

Alongside it, the reassembly ceiling the wider window runs into is now written
down where the window is chosen: smoltcp is pinned at
`assembler-max-segment-count-32`, which is its largest setting, so a 4 MiB
window's ~3000 in-flight segments can open more holes than the assembler
tracks, and past 32 smoltcp drops the segment without even a duplicate ACK.
Every measurement behind the window ran on a clean path, so this is unbounded
rather than known-bad; ROADMAP.md carries the lossy-path benchmark that would
settle it, along with the note that Android's window is extrapolated from macOS
RSS rather than measured on a device.

### Documentation

ROADMAP.md's competitive comparison is current again and now has three columns:
it was re-checked against sing-box v1.14.0 and Xray-core v26.7.28, and
Xray-core, previously named in the framing but absent from the table, is a
column of its own. Our own side was re-verified against the tree rather than
against the table, which corrected four stale claims -- macOS missing from the
TUN platforms, HTTPUpgrade missing from both protocol lists, destination-port
matching missing from the routing row, and `src/control/` described as a
"control API" when it is an in-process module with no network surface. The
same pass established that `X25519MLKEM768` is already the first key-exchange
group we offer on every rustls path, inherited from a rustls default rather
than chosen, and that ECH remains a genuine gap.

## v0.2.18

### The TUN server honours its `dns:` config

A TUN entry's `dns:` block parsed, validated, had its resolvers built --
and the datapath used the system resolver anyway. It is real now: the
configured resolver answers client-chain hostnames, UDP destinations,
and the WireGuard/AmneziaWG endpoint's re-resolution on tunnel
rebuilds. (A network-change rebind reuses the address already resolved;
only a rebuild -- which the liveness watchdog forces when a rebind does
not help -- resolves again.) **Behaviour changes only for configs that already carry
`dns:` on a TUN entry** (previously ignored); without the block nothing
changes. Every DNS upstream socket goes through the socket protector,
so a query cannot route into the tunnel it resolves for. One new
validation rule: a hostname DNS URL without a `bootstrap_url` is
rejected in TUN configs -- it would silently use the system resolver,
the exact leak the block exists to prevent; IP-address URLs
(`https://1.1.1.1/dns-query`) keep needing no bootstrap.

### The desktop binary behaves like a daemon

SIGINT and SIGTERM stop the accept loops, flush the logs, and exit
with the conventional signal codes (130/143) instead of the OS default
death -- and they reach through the reload debounce and prepare, where
they used to buffer until systemd's escalation. Every listener -- TCP,
unix socket, and QUIC alike -- caps its concurrent connections at 4096,
with the permit riding inside the connection so protocol-session paths
cannot escape it. Routine client disconnects log at debug and timeouts
at info (visible in release builds, which compile debug out); a QUIC
endpoint that closes says so instead of silently ending its accept
task; and the `-l` log file rotates at 32 MiB to `<path>.old`,
refusing -- audibly -- the cases it cannot rotate safely (symlinked
paths, directories that refuse the rename).

### The Swift package grows up around its lifecycle

The provider is sleep-aware (guaranteeing `wake()` delivery), stamps
engine sessions so a stale death cannot be mistaken for the current
one, lets a scheduled rebind recover from the death it was scheduled
for instead of cancelling the tunnel mid-recovery, re-runs a rebind for
a path change that landed while one was executing, runs
`loadConfiguration` inside the start timeout, and reports the system's
stop reason through a new `report(stopReason:)` hook. `ShoesErrorStore`
in Core is the synchronous App Group persistence the fatal-error docs
mandate. On the host side, `start(configure:)` gains a two-parameter
form that can express on-demand rules, a stale manager is reloaded and
retried once, `send()` times out instead of hanging on a dead
extension, and the macOS installer reports approval-pending and throws
`RebootRequired` instead of calling a deferred activation a success.
`engine.stop()` returns whether the descriptor was actually released.
CallbackBridge and the new store are under test.

### The FFI surface answers honestly and refuses what would kill it

Also from the audit's should-fix list. `shoes_stop` returns whether the
descriptor is actually released (1/0; the Android `stop` returns a
`Boolean`, which changes its Kotlin declaration) instead of telling the
host to close the fd even after a timeout. An unrequested clean exit
carries "service ended without being asked" through the stopped
callback and `shoes_get_last_error` instead of a NULL that left a stale
message readable; an interior NUL in a reason no longer silences the
failure into a clean-stop shape; and a requested stop no longer keeps
an error the exit-guard race wrote mid-stop. A `shoes_start` from
inside a callback is refused with a reason instead of aborting the
process, a stack thread that cannot spawn fails the start instead of
aborting the app, a release FFI build without `panic = "abort"` is a
compile error naming the right profile, and the socket protector calls
into Swift with its lock released.

### The reconnection paths sand off their remaining edges

From the resilience audit's should-fix list, the Rust-core cluster. A
failed endpoint rebind retries by itself (1 s doubling to 30 s) instead
of waiting for a trigger that may never come; the route-gone table
covers WinSock's EINVAL and the EPERM/EACCES Android returns when a
socket loses its VPN exemption. Ignore-class recv errors join the
backoff ladder -- a persistent ENETDOWN no longer spins the receive
loop at full CPU -- and a permanently failing send path warns once per
streak instead of once per packet. Both virtual TCP stacks run on the
monotonic clock, so an NTP step on wake no longer stalls or mass-fires
their timers. Outbound TCP connects get a 10-second deadline, the UDP
response queue to the stack thread is bounded with drop-on-full, a
failed AmneziaWG tunnel build fails fast for three seconds instead of
re-resolving per inbound connection, and a new UDP destination connects
in its own task instead of stalling every sibling flow behind its DNS
lookup and proxy handshake.

### The resilience audit's critical findings, fixed

Silent failures are now detected. A liveness watchdog watches the traffic
counters: sustained outbound traffic with nothing received first rebinds
the endpoint socket -- the cheap repair for a NAT mapping that expired
during sleep or a path that moved without an errno -- and, only once a
rebind succeeded and the peer still says nothing, stops the engine with
the reason (the standalone binary rebuilds instead). A device that
cannot rebind is between networks, and that outage is still ridden out.
A rebind also announces itself: a keepalive (or handshake) goes out on
the fresh socket immediately, so the server learns the new address
before app traffic happens to tell it. WireGuard's own session-expiry
signal is logged at warn instead of swallowed at debug.

The AmneziaWG virtual TCP stack gained what the TUN stack already had:
a 30-second connect deadline (smoltcp otherwise retransmits a SYN
forever, parking the caller and its ~576 KiB of buffers for good),
keepalive and timeout on established flows, and a per-platform socket
cap instead of unbounded growth into the extension's memory ceiling.

FFI start/stop transitions are serialized. A stop empties the service
slot before its five-second wait, and a start landing in that window
used to pass the already-running guard and put a second engine on the
same device descriptor. On iOS, a rebind past its debounce could
restart the engine after stopTunnel's completion handler had returned;
it now stands down at every step once a stop begins.

Desktop: an edit that breaks the config no longer kills the running
proxy -- the last-good configuration keeps serving and each further
edit is retried; `--dry-run` failures exit 1 so tooling can tell; and
fd exhaustion backs the accept loop off instead of spinning it hot.

## v0.2.17

### The AmneziaWG receive path survives errors, and its death stops the engine

One `EMSGSIZE` on the tunnel's UDP socket used to kill inbound for the
rest of the session while the engine kept reporting healthy. On a
connected UDP socket that error is a deferred echo of our own send
exceeding the path MTU -- with 3.1 random trailers, the trailer window
grows past what the path carries when the peer runs a higher MTU -- and
the socket is fine afterwards. The receive loop now classifies recv
errors and continues: routine ICMP echoes are logged and dropped,
`EMSGSIZE` additionally shrinks the trailer window, and unknown errors
are tolerated too. Only a socket producing nothing but errors for ~5
seconds straight ends the loop -- and that now stops the engine with the
reason (the stopped callback on iOS/macOS, `shoes_get_last_error` on
Android) instead of leaving `shoes_is_running()` true over a deaf tunnel.
The standalone binary instead rebuilds the tunnel on the next connection.

The trailer-probe hint no longer says "set random_trailers to match the
peer" when nothing was received from the peer at all -- silence cannot
falsify the trailer setting, and the old wording sent a real debugging
session down a false path.

## v0.2.16

### `ShoesTunnelHost`

The Swift package now has two products. `ShoesTunnel` is unchanged for the
extension: same name, same API, a version bump is the whole migration.
`ShoesTunnelHost` is new for the app: `ShoesTunnelManager` and
`SystemExtensionInstaller` over a shared `ShoesTunnelCore` target, with no
dependency on the engine, so an app that links it carries no `shoes_*`
symbol -- previously linking the one product into the app kept the whole
engine in the app binary. Apps swap their dependency from `ShoesTunnel` to
`ShoesTunnelHost` and `import ShoesTunnelHost`. Source-compatible for
extension consumers, additive for hosts. CI asserts the link-time property
on a Release simulator build.

### The engine says when it stops

`shoes_start_with_fd` takes a `ShoesStoppedCallback`, called once from a
worker thread when the engine stops without `shoes_stop` -- the failure
message, or NULL. Never for a requested stop; a call already in flight when
`shoes_stop` begins may still complete after `shoes_stop` returns. The
reason is in `shoes_get_last_error` as well. `shoes_start` is unchanged; the
`_with_fd` signature changes one release after it appeared, with the Swift
package its only consumer. The surface count stays at 12.

In the package, `ShoesEngine.start` gains a required `onStopped:` and
`ShoesPacketTunnelProvider` reports an engine death at once instead of
noticing it on a 30-second health check, which is removed together with
`healthCheckInterval` (a subclass that overrode it no longer compiles; the
override did nothing). `ShoesError` gains `.noSession` and
`.providerNoReply` -- what `ShoesTunnelManager.send` now throws instead of
`.engine` -- and `.engineStopped(String?)`; it is `Codable`. An exhaustive
`switch` over `ShoesError` needs the new cases. `ShoesAppMessage.lastError`
asks the provider for the last error it reported, as the case; it answers
while the extension is alive, and after an engine death the process is gone
and the app sees only `.disconnected`.

## v0.2.15

### macOS slice and the ShoesTunnel Swift package

`scripts/build-apple.sh` (was `build-ios.sh`) emits `Shoes.xcframework` with a
`macos-arm64` slice beside the two iOS ones, and every slice now carries a
module map so a Swift package can import the C surface without a bridging
header. Deployment targets are iOS 18 and macOS 15.

The Swift that drives shoes in a packet tunnel provider ships from this
repository: `ShoesTunnel` (`Package.swift` at the root, sources under
`swift/`), with `ShoesPacketTunnelProvider` to subclass, `ShoesTunnelManager`
for the app side, `ShoesEngine` over the FFI, and typed stats and messages.
Swift 6. Integration is described in `swift/README.md`; what is specific to a
macOS system extension is in `docs/MACOS.md`.

Releases that carry the package are cut by the `Release Apple` workflow,
which publishes the XCFramework and commits its checksum into `Package.swift`
before tagging. `mobile.yml`'s tag run attaches the AAR only.

### `shoes_start_with_fd`

`shoes_start` with the TUN descriptor as a parameter. It overrides a `device_fd`
the YAML carries and fills one it omits, so a config generated by the app can be
handed to a packet tunnel provider that learns its descriptor from `packetFlow`
without patching a placeholder into the string first. `shoes_start` is
unchanged. The C surface goes 11 → 12; no existing symbol changed.

### Windows TUN backend

TUN mode works on Windows 11. shoes creates a [wintun](https://www.wintun.net)
adapter named `device_name`, assigns it the config's IPv4 `address` and
`netmask`, and runs the same smoltcp stack the other platforms use — the loop
moved to a shared module behind a small device trait, so the Unix backends are
unchanged in behaviour and the Windows one drives wintun's ring-buffer session
with event-based waits. Requires Administrator and `wintun.dll` (whose
signature is verified before it is loaded). shoes configures the adapter only;
routes and DNS stay the host's — `destination` is refused on Windows because
the wintun configuration path would turn it into a system default route, and
`device_fd` is refused because there is no descriptor to inject.
`examples/tun_windows.yaml` shows the config and the routing commands.

Windows CI went from `cargo check` to the full test suite, which surfaced two
Windows defects that predate this work, both fixed: QUIC inbounds panicked at
startup because SO_REUSEPORT does not exist there (they now bind one endpoint
and say so when reducing a configured `num_endpoints`), and the Hysteria2 and
TUIC UDP relays lost all their IPv4 traffic because Windows defaults
`IPV6_V6ONLY` on where Linux defaults it off — dual-stack sockets now request
it explicitly everywhere.

The live run then caught two defects that were never Windows-specific, both
fixed on every platform. A UDP response queued while the TUN stack thread was
idle waited out the stack's one-second poll timeout, because nothing woke the
thread on enqueue — measured at ~500 ms added to every cold DNS lookup, which
Fake IP answers in microseconds. The response path now carries a waker: a
byte down the wake pipe on Unix, an auto-reset event in the Windows wait. And
`icmp_enabled` never actually answered pings: smoltcp only builds its echo
reply arm under the `auto-icmp-echo-reply` feature, which was not enabled.
It is now, so a TUN answers pings on every platform.

## v0.2.14

### Runtime stats through the FFI

`shoes_get_stats()` on iOS and `ShoesNative.getStats()` on Android return
`control::stats::snapshot()` as a JSON string: the two byte totals the traffic
callback already delivers, a live connection count, and one entry per
configured outbound with its own bytes and connection count. The C string is
freed with `shoes_free_string`, the same call that frees the error string, so
there is no new ownership rule to learn. The traffic callback and every
existing symbol are unchanged.

The symbol exists in every build and only its body is behind `control-stats`;
without the feature it returns NULL. NULL also covers a string that could not
be allocated, so a host should poll rather than read the first NULL as a
permanent verdict on the build. That keeps `include/shoes.h` identical
whatever features generated it, which is the property a host relies on when it
diffs the header to decide whether a version bump is a drop-in.

Both published mobile artifacts now build with `control-stats`. Measured on
the arm64 library it costs 24,904 bytes of download, and 304 bytes for a build
that leaves the feature off. Resident cost at the 256-connection mobile
ceiling is 2 KiB -- below one page, and below what RSS can resolve; MOBILE.md
section 10 records the measurement and the control arm that rules out a false
positive.

**This release is additive.** `include/shoes.h` and the Kotlin bridge both
change, so a consumer that watches those paths to decide whether a bump is a
drop-in will see a diff — but nothing existing moved. No symbol changed
signature or behaviour, `ShoesTrafficCallback` and `TrafficListener` are
untouched, and the only edit to an existing declaration is the comment on
`shoes_free_string`, which now names the second function whose strings it
frees. The surface goes from 9 JNI and 10 C symbols to 10 and 11.

## v0.2.13

### Named outbounds

An outbound can carry a `name`, and with the `control-stats` feature
`control::stats::snapshot()` reports upload, download and active-connection
counts against it. An outbound without a name is keyed by its address, so
existing configs get the same figures under a less friendly label; a `direct`
outbound is keyed `direct`, since its address is unspecified and would
otherwise collide with every other direct outbound.

Bytes are credited to the **exit** hop of a chain rather than to the relay the
socket actually opens, because the exit is the server a person means. Two
outbounds sharing a name but not an address are rejected at config load, on
every build, and `direct` is reserved.

A ShadowTLS remote handshake chain and a REALITY `dest_client_chain` are now
expanded during validation like every other chain. They were not, which meant
a group reference in either one panicked when the server started; now it
resolves, and their outbounds are counted rather than silently dropped.

### Hysteria2 port hopping

The client can rotate its UDP port across a published range, which is what a
Hysteria2 server behind an `iptables REDIRECT` range expects. Configured as
`port_hopping: { ports, interval_ms }`; the local port moves with the remote
one, so the whole 4-tuple changes rather than half of it.

Verified against a real deployment behind an `iptables REDIRECT` rule: over
seven hops the server saw eight distinct client source ports and traffic to
every published port, with no request lost. A UDP association survives a hop
too, though a datagram sent as one happens can be lost — QUIC datagrams are not
retransmitted, and the new path has to be validated before the peer will use it.

A QUIC outbound also walks every resolved address instead of only the first. A
dual-stack host whose IPv6 is published but whose return UDP never arrives used
to look permanently dead; each address now gets a bounded attempt before the
next is tried, with the last one left unbounded so a single-address outbound
behaves exactly as it did.

### Hysteria2 conformance with the reference implementation

Four divergences that made a real Hysteria2 peer fail against us, found by
reading the Go source rather than by any test — in every case our encoder and
our decoder shared the misreading, so both ends agreed and nothing failed.

- **An IPv6 target now works.** We put `2001:db8::1:443` on the wire, which Go's
  `net.SplitHostPort` rejects outright. Addresses leaving the process are now
  bracketed per RFC 3986. `Display` is unchanged: it is what logs and errors use
  throughout the tree.
- **Concurrent UDP sessions no longer lose each other's traffic.** Every session
  ran its own datagram reader on the shared connection and discarded what was
  not its own; with two sessions the second could receive nothing at all. One
  demultiplexer per connection now routes by session id, as upstream does.
- **A failed dial now says why.** The server answered "OK" before it had dialled
  anything, so a refused target reached the client as a connection that
  succeeded and immediately closed with no diagnosis. The response now waits for
  the dial and carries the outcome, with `Connected` on success.
- **`Hysteria-CC-RX: auto` instead of `0`.** `0` means "no limit, send as fast as
  you like", which made an official client switch to fixed-rate Brutal
  congestion control against a server running ordinary congestion control.

One known limitation remains: our server cannot send UDP to a peer that omits
`max_datagram_frame_size`, because quinn refuses to send datagrams to such a
peer and has no equivalent of upstream's `AssumePeerMaxDatagramFrameSize`. An
official Hysteria2 client does this only with `disableChromeParrot: true` — its
Chrome parroting otherwise forces the parameter to be advertised — so a stock
client's UDP works. Such a peer now produces a log line naming the cause instead
of a session that silently never answers.

All four fixes were verified against a real Hysteria2 server, and the two
server-side ones against the official client built from upstream: an IPv6 target
that the reference implementation used to dial as port 0, two simultaneous UDP
associations that previously lost most of their answers, a failed dial whose
reason now reaches the official client, and a client that honours `auto` by
ignoring its own configured bandwidth.

Four robustness fixes in the same UDP path followed, none of which changes
anything on the wire.

- **A UDP session can no longer be made to hold about 78 MB.** It tracked up to
  256 incomplete packets of up to 255 fragments each, and a peer that sends
  every fragment of every packet but one fills that. Upstream keeps one packet
  id in flight and discards it the moment another arrives, which caps the same
  attack at roughly 300 KB. Both of our ends changed, and the one that matters
  most is the phone.
- **A session whose send fails no longer leaks its socket and its task.**
  Removing it from the map left its reply loop parked on `recv_from` for the
  rest of the connection; the idle sweep did it correctly, so there were two
  removal paths and one of them was wrong. Cancelling when the session is
  dropped makes them the same by construction.
- **Idle sessions are reaped on a timer.** The sweep ran only when another
  datagram happened to arrive, so a client that went quiet kept every session it
  had opened — each with a socket and a task — until the connection ended.
- **An unsendable reply is now an error rather than a panic or a corrupt one.**
  The size check was an `assert!` on two values the peer chooses, so a peer
  could abort the process; and a payload needing more than the 255 fragments the
  protocol counts had its count truncated, telling the receiver to expect a
  handful and then sending it fragment ids past that count. Both now return an
  error naming the sizes.

TUIC shares the same connection machinery and has the same one-reader-per-
session defect. It is untouched here and remains to be fixed.

### HTTPUpgrade transport

WebSocket's HTTP handshake without WebSocket's framing, on the server and the
client, compatible with sing-box's `httpupgrade`. A `GET` carrying
`Connection: Upgrade`, a `101`, and raw bytes after that -- no masking and no
frame header on every write, which is what a proxy pays WebSocket for and gets
nothing back for. Configured as `type: httpupgrade` on either side; see
CONFIG.md.

Read from the reference implementation rather than from its documentation,
which is where the two rules that decide interoperability live. A real
WebSocket handshake is *refused* rather than served: our client never sends
`Sec-WebSocket-Key` and our server answers `404` to a request carrying one,
because a framed peer would read the unframed bytes that follow as garbage. And
bytes arriving in the same packet as the header block are the tunnel's first
payload; there is no stream wrapper here to hold them, so they go in front of
the connection instead. Both rules are pinned by tests watched failing with the
fix removed.

One deviation, deliberate: sing-box answers `400` for a Host mismatch and `404`
for everything else, while `Host` here is an ordinary entry in
`matching_headers` and indistinguishable at the point of refusal, so every
mismatch is `404`. No client can tell -- sing-box's own inspects nothing but the
`101` and the two headers.

Not implemented: Xray's `ed` early data, which hands back a stream before its
response has been read and so does not fit `setup_client_tcp_stream`'s
contract, and Xray's browser-shaped default headers.

Verified against a real sing-box, release 1.13.19, in both directions with
VMess inside the tunnel. Our client through their server and their client
through our server each fetched a page and then 10 MB in each direction — a
download and a `POST` body — with every transfer hashing byte for byte against
the same content fetched directly, so nothing was dropped, duplicated or
reordered across segment boundaries.

The two refusal cases were checked against that client rather than against our
own: sing-box asking for a path we do not serve got `unexpected status: 404 Not
Found` while our log named the path that missed, and sing-box configured with
`type: ws` — a genuine WebSocket handshake — was refused with the same `404`,
our log reading `real websocket request received`. That is the rule the whole
design turns on, and it now holds against a peer we do not control.

Not covered by that run: TLS in front of the transport, a CDN between the ends,
and a `Host` mismatch, since sing-box only enforces `host` when its own
configuration names one.

### A request line with no path no longer panics

`GET HTTP/1.1` satisfies a `GET ` prefix test and a ` HTTP/1.1` suffix test at
the same time while carrying no request target between them, and both HTTP
upgrade transports then sliced out the bytes "in between" a three-byte string.
The parse runs before any header is examined, so nothing authenticates ahead of
it: one request from any peer that reaches the listener did it. On a desktop
build that killed the connection task; the `release-mobile` profile sets
`panic = "abort"`, so on a phone it took the process down.

The defect was in the WebSocket handler before HTTPUpgrade copied it, and both
are fixed together — they now share one request-line parser that splits the line
rather than slicing between two tests that can each pass on nothing.

### AmneziaWG 3.1 carries traffic

The awgtun pin moves to the fixes it made after v0.9.0. Three of them are on a
path shoes uses, and all three were found against a live AmneziaWG 3.1 server:

- **A data packet is no longer misparsed as a handshake.** 3.1 relaxes the three
  handshake size tests from `==` to `>`, since a random trailer makes the
  datagram longer than the message, and those tests ran before the transport
  one. All that separated a full-size data packet from a handshake was a type
  field read over ciphertext, so uniformly random: with the ranges Amnezia's own
  generator emits, ~3.5% of received packets were dropped. Classification now
  tries transport first.
- **We stop sending packets a 3.1 peer will drop for the same reason.** Its
  receive path is not ours to fix, but the value it reads is masked by a
  keystream derived from our S4 prefix, so the prefix is redrawn until all three
  candidates miss. Upstream measured 0.17 MB/s to 12.55 MB/s on the affected
  direction.
- **A real `I1` chain is accepted.** The `<r>` length cap was an invented 1000
  bytes; production chains pad the initiation to the size of a TLS record and
  were rejected at config load, so the tunnel never sent a packet. The bound is
  now the largest UDP datagram, which is the only one amneziawg-go has.

Nothing in shoes changes; the pin move is the whole diff. A 2.0 tunnel is
untouched, and a 3.0 one keeps its wire format: the relaxed size tests apply
only with random trailers on, so a 3.0 sender redraws its prefix only for the
much rarer case of a transport datagram whose length equals a handshake
message's — a collision the reference classifier would have misparsed too, and
one the prefix being random already made arbitrary.

## v0.2.12

### Synced with upstream

`cfal/shoes` moved seven commits ahead; this branch is rebased onto them. Most
land on the server side and change nothing a mobile client does, but two touch
code this branch had also rewritten, and those needed a decision rather than a
merge:

- **The resolver cache holds a list, not an address.** Upstream bounded both
  resolver caches and reduced `ResolverCache` to a single pending lookup; this
  branch had separately made `CachingNativeResolver` cache every resolved
  address, so a cache hit still feeds the per-address connect fallback. Both
  changes are kept: the cache is bounded *and* holds the full list.
- **Sniffing survives multiple bind addresses.** Upstream let a server config
  bind several addresses, sharing one protocol handler per IP; this branch had
  threaded the sniff settings into `run_tcp_server`. The sniff settings are now
  cloned per spawned listener inside the new per-address loop.

Also arriving from upstream: a bound on the REALITY client handshake plaintext,
pending ciphertext counted against the REALITY outgoing limit, and a `WriteZero`
error instead of a silent success on a zero-byte TLS direct write. The AGP 9.0
Android migration that landed upstream as #136 is this fork's own change coming
back the other way.

### mieru client outbound

A new protocol, client side only. XChaCha20-Poly1305 with a 24-byte nonce; the
key derived from the password, the username and the current time rounded to two
minutes; an implicit nonce sent once per direction and then incremented; three
metadata formats; both of upstream's padding strategies. socks5 rides inside
the session, and UDP is framed inside that.

No ARQ: over the TCP transport upstream makes ACK handling a no-op, because TCP
already orders and retransmits.

Verified against a real mieru server over the internet — bulk transfer in both
directions with a byte-exact hash against a direct fetch, eight concurrent
sessions, a three-minute stream, idle keep-alive reuse, DNS through the socks5
UDP associate, and both address families. That run mattered: the tests exercise
the client against a scripted peer built from this repository's own codec, and
two reviews reading the Go implementation found seventeen defects while every
one of those tests was green.

Refused at config load rather than silently ignored: mieru's UDP transport,
session multiplexing, the low-entropy encoding, port ranges, the 0-RTT
handshake mode, and configurable traffic patterns.

### Fixes

- **Bracketed IPv6 addresses are parsed.** `[2001:db8::1]:443` — the form RFC
  3986 defines and the form HTTP clients send — was classified as a hostname
  and handed to the resolver, which answered "Name or service not known". An
  IPv6 outbound was unreachable and the message said nothing about why. The
  same defect made the HTTP inbound refuse `CONNECT [2001:db8::1]:443`, since
  it split the authority on the first colon.
- **`set_log_level` says when a level is compiled out.** Release builds compile
  out `debug!` and `trace!`, so raising the level through the mobile FFI did
  nothing and said nothing. The host cannot see stderr, so the warning now goes
  through the log pipeline it is already reading.

## Earlier work that was never written up

This file starts at v0.2.5 and describes v0.2.9 onward in detail, but a body of
work that landed before v0.2.9 never got an entry. Listed here so the omission
is visible rather than silent. [ROADMAP.md](./ROADMAP.md) carries the detail
and the scope decisions for each.

- **Rule-sets.** sing-box `.srs` files are read directly — the succinct trie in
  its on-disk shape, IP range sets, headless matching — so the existing
  ecosystem of compiled lists works as-is. Before this, a rule as ordinary as
  "Russian domains direct, everything else tunnelled" needed tens of thousands
  of YAML lines. Local files only.
- **Protocol sniffing.** The TLS ClientHello and the HTTP/1.x request line are
  read from the first bytes of a connection, so domain rules keep working for
  an app with a hardcoded DoH resolver or one that dials a literal IP. Opt-in
  per listener.
- **Hysteria2 and TUIC v5 client outbounds.** The servers existed; dialling
  somebody else's did not. Both own their transport and are therefore terminal
  in a chain. Both carry TCP and UDP, TUIC in both relay modes.
- **Salamander obfuscation**, on the client and on our Hysteria2 server.
- **Vanilla WireGuard and AmneziaWG 2.0 and 3.0**, with the tunnel runtime and
  its virtual network stack. 3.1 arrived later and is described under v0.2.11.
- **Fake IP** in TUN mode.
- **The iOS and Android FFI**: start, stop, traffic statistics and last-error
  reporting, made to behave on a phone rather than only in tests.

## v0.2.11

### AmneziaWG 3.1

The two parameters awgtun gained in v0.9.0 are configurable now. Both default
to off, so a 2.0 or 3.0 tunnel is byte-identical on the wire to what it was
before this change, and each generation stays opt-in on top of the last — a
2.0 config may adopt a 3.1 parameter without adopting anything from 3.0.

- `random_trailers` appends a random number of bytes to each datagram, so a
  message with a fixed size stops having one. **Both peers must enable it.** A
  receiver only tolerates bytes past the end of a handshake message when it is
  on, so one-sided it breaks the handshake in the direction that grew — and
  breaks it the same silent way every other wire-shaping mismatch does. Pinned
  by a test that feeds a trailered initiation to a 3.0 peer.
- **A one-sided `random_trailers` recovers by itself.** The setting is not on
  the wire and a disagreeing peer does not answer, so there is nothing to ask:
  a tunnel that was given packets to send and has still not handshaked after
  15 seconds rebuilds with the setting flipped, and alternates until one works.
  Whichever setting handshakes is the one it keeps — a `Tunn` that has
  handshaked is never flipped, so an established tunnel that later goes idle is
  never disturbed. Each flip is logged at warning level and names the setting
  to correct. A misconfiguration costs a delay instead of an outage.
- `disable_cookies` withholds the cookie reply. The rate limiter still decides
  a cookie is warranted, so a peer under load gets silence rather than a retry
  hint. This changes only what we send, so the two ends need not agree.
- A trailer's length is drawn from a high-water mark of datagram sizes seen on
  the path, which stops describing anything once the path changes. The endpoint
  rebind — the mobile network-change recovery — now resets it, the way
  upstream's `Device` does on a peer roam. awgtun leaves this to the caller
  because `Tunn` has no endpoint of its own.

## v0.2.10

Security and packaging. No protocol changes; a server deployment is affected
only by the REALITY logging fix.

### Security

- REALITY logged key material at debug level: the TLS traffic secret and the
  key and IV derived from it on every derivation, the authentication key on
  every client handshake, and the peer's short_id on the server — which also
  appeared in the rejection error text. Debug logging is switchable at runtime
  and MOBILE.md tells users a log file is safe to hand to support; with these
  lines it was a transcript-decryption kit. All of it is gone. What remains
  logged is lengths, cipher-suite parameters and outcomes, and a rejected
  short_id is no longer echoed anywhere — it may be a valid credential for a
  different deployment.
- The crate's only `unsafe` block is gone. `allocate_vec` handed out
  uninitialized memory as initialized bytes — formally undefined behaviour.
  Buffers are zeroed now, which costs nothing that matters: large allocations
  arrive as lazy zero pages, the same mechanism the resident-memory numbers
  already relied on.

### The tunnel library is now awgtun

- The boringtun fork became its own project. shoes follows it through v0.8.0
  — AmneziaWG 3.1 in the library (random trailers, cookie suppression), not
  yet exposed in shoes configuration — to v0.9.0, which split the C/JNI
  exports into a separate crate at shoes' request: Rust consumers no longer
  build artifacts they discard, and nothing foreign lands in the Android AAR
  to begin with. The delete step and the CI check on the AAR remain as guards.
- The dependency is pinned to a release tag now rather than a moving branch.

### Packaging

- The Android AAR carries an `x86_64` slice, so the stock emulator can load
  the library at all; previously `System.loadLibrary` failed at startup on any
  non-ARM image. Verified in CI by the AAR content check.
- Intel macOS binaries are no longer published; nothing deploys there.

### Dependencies

- Everything on the latest released versions as of this release, and
  `cargo audit` is clean: 333 crates against 1225 advisories, nothing flagged.
- `digest` is pinned to its major (`"0.11"`). The wildcard requirement let a
  routine re-resolution flip it to 0.10, whose `XofReader` trait does not match
  the one `shake` implements — caught when it broke this release's build.

Note for the app side: `shoes_get_version()` and `ShoesNative.getVersion()`
now report 0.2.10.


## v0.2.9

Mobile integration work. Everything below is on the client side; a server
deployment is unaffected except for the dependency update.

### Fixes

#### The TUN stack and the app's file descriptor
- The stack closed the TUN descriptor even when told not to. `close_fd_on_drop`
  was only honoured on the path that creates the device, so every Android and
  iOS start had the library closing a descriptor the app owns — a double close
  once the app closed its own, which in a process opening sockets constantly
  means closing whichever socket has taken the number since.
- Shutting down a quiet tunnel could block indefinitely. The stack thread sleeps
  in a syscall that `unpark` does not interrupt, so `stop` waited for a packet
  that might never arrive. There is a wake pipe now, and the sleep is bounded.
- The wait uses `poll()` rather than `select()`, whose `fd_set` cannot hold a
  descriptor numbered above `FD_SETSIZE`.

#### AmneziaWG across a network change
- The endpoint socket is rebindable. A UDP socket bound to an address that no
  longer exists does not report an error — it goes silent — so leaving Wi-Fi
  used to mean stopping and starting the whole tunnel.
- `networkChanged()` / `shoes_network_changed()` let the app report the change
  from `ConnectivityManager.NetworkCallback` or `NWPathMonitor`. A send that
  fails with a route error also triggers a rebind on its own, so an app that
  never wires the callback still recovers.

#### FFI
- `start` validates the config on the calling thread, so a `-1` is a real
  verdict with `getLastError()` behind it rather than a failure the app has to
  discover by polling `isRunning()`.
- `stop` no longer blocks on dropping the runtime, and polls at 5 ms rather than
  100 ms. It still waits for the stack thread to release the TUN descriptor,
  which is what makes it safe for the app to close its own copy afterwards.
- `stop` clears the socket protector, which on Android held a JNI global
  reference keeping a destroyed `VpnService` and its `Context` alive.
- `setLogLevel()` / `shoes_set_log_level()` change the level of a running
  library, so debug logs no longer need an app restart.
- The traffic callback reports once per session start and then only when a
  counter moved, instead of crossing into the JVM or Swift once a second on an
  idle tunnel.

### Memory

- Per-connection buffering is configurable (`tcp_buffer_size`,
  `max_connections`) and sized by platform. A connection through the TUN and
  AmneziaWG stacks costs 704 KiB rather than 2.3 MB.
- Buffers that face the network keep their size. Cutting the AmneziaWG socket
  buffers to the size of a local buffer measured as a 6x throughput loss, since
  those are a receive window rather than local buffering; `src/buffer_sizing.rs`
  documents the distinction and the measurement.
- The AmneziaWG data path and the TUN write path no longer allocate per packet.
- Stopping a tunnel drops the read path's buffer pool and asks the allocator to
  release what it is holding.

### Security

- `h2` updated to 0.4.16 for RUSTSEC-2026-0258 (unbounded empty DATA frames).

## v0.2.7

### Improvements

#### H2MUX Stability
- Added connection-level activity tracking that counts HTTP/2 control frames (PING, SETTINGS) as activity, ensuring keepalives properly reset idle detection
- Removed application-level idle timeout in favor of PING-based dead connection detection, matching sing-mux behavior for better compatibility
- Added drain timeout for graceful session shutdown
- Updated window sizes to match Go http2 defaults (256KB per stream, 1MB per connection)

#### AnyTLS Memory Leak Fixes
- Stream handler tasks are now tracked and aborted when session closes, preventing memory leaks from orphaned tasks
- Added 5-minute stream handler timeout to prevent hung streams (slow DNS, stuck connections) from leaking memory
- Reduced allocations in padding frame generation

#### TUN Connection Tracking
- Refactored TCP connection state machine with explicit states (Normal, Close, Closing, Closed) for proper lifecycle management
- Improved connection teardown handling following shadowsocks-rust patterns

## v0.2.6

### New Features

#### H2MUX (sing-box Compatible HTTP/2 Multiplexing)

H2MUX multiplexes multiple proxy streams over a single HTTP/2 connection, reducing connection overhead and improving performance for many concurrent streams. This is compatible with sing-box's h2mux implementation.

**Client configuration (VMess, VLESS, Trojan):**
```yaml
client_chain:
  address: "example.com:443"
  protocol:
    type: tls
    protocol:
      type: vmess
      cipher: aes-128-gcm
      user_id: "uuid"
      h2mux:
        max_connections: 4    # Maximum connections to maintain
        min_streams: 4        # Min streams before opening new connection
        max_streams: 0        # Max streams per connection (0 = unlimited)
        padding: true         # Enable padding for traffic obfuscation
```

**Server support:** H2MUX is auto-detected on the server side for VMess, VLESS, Trojan, Shadowsocks, and Snell protocols. No server configuration changes are needed.

#### H2MUX Client Compatibility

The Go H2MUX library contained a bug that prevents data upload from finishing successfully, see [https://github.com/SagerNet/sing-mux/pull/8](https://github.com/SagerNet/sing-mux/pull/8)

sing-box now contains this fix, but other clients (eg mihomo) that depend on sing-mux without this change can have issues.

#### DNS Resolution Timeout

DNS servers now support a configurable timeout to prevent hanging on unresponsive DNS servers.

```yaml
- dns_group: my-dns
  servers:
    - url: "tls://dns.example.com"
      timeout_secs: 10      # Default: 5. Set to 0 to disable.
```

### Improvements

- **DNS connection timeout**: DNS-over-TLS/HTTPS connections now respect a 5-second connection timeout, preventing hangs when DNS servers are unreachable
- **Reality server**: Improved shutdown handling with proper flush after every forward operation

## v0.2.5

### New Features

#### AnyTLS Protocol

**Server:**
```yaml
protocol:
  type: tls
  tls_targets:
    "example.com":
      cert: cert.pem
      key: key.pem
      protocol:
        type: anytls
        users:
          - name: user1
            password: secret123
        udp_enabled: true
        padding_scheme: ["stop=8", "0=30-30"]  # Optional custom padding
        fallback: "127.0.0.1:80"               # Optional fallback
```

**Client:**
```yaml
client_chain:
  address: "example.com:443"
  protocol:
    type: tls
    protocol:
      type: anytls
      password: secret123
```

#### NaiveProxy Protocol

**Server:**
```yaml
protocol:
  type: tls
  tls_targets:
    "example.com":
      cert: cert.pem
      key: key.pem
      alpn_protocols: ["h2"]
      protocol:
        type: naiveproxy
        users:
          - username: user1
            password: secret123
        padding: true
        fallback: "/var/www/html"  # Optional static file fallback
```

**Client:**
```yaml
client_chain:
  address: "example.com:443"
  protocol:
    type: tls
    alpn_protocols: ["h2"]
    protocol:
      type: naiveproxy
      username: user1
      password: secret123
```

#### Mixed Port (HTTP + SOCKS5)
Auto-detects HTTP or SOCKS5 protocol.

```yaml
- address: "0.0.0.0:7890"
  protocol:
    type: mixed
    username: user
    password: pass
    udp_enabled: true  # Enable SOCKS5 UDP ASSOCIATE
```

#### TUN/VPN Support
Layer 3 VPN mode using TUN devices for transparent proxying. Supports Linux, Android, and iOS.

```yaml
- device_name: "tun0"
  address: "10.0.0.1"
  netmask: "255.255.255.0"
  mtu: 1500
  tcp_enabled: true
  udp_enabled: true
  icmp_enabled: true
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        address: "proxy.example.com:443"
        protocol:
          type: vless
          user_id: "uuid"
```

**Platform support:**
- Linux: Creates TUN device with specified name/address (requires root)
- Android: Use `device_fd` from `VpnService.Builder.establish()`
- iOS: Use `device_fd` from `NEPacketTunnelProvider.packetFlow`

#### SOCKS5 UDP ASSOCIATE
Full UDP support for SOCKS5 servers including UDP ASSOCIATE command. Enable with `udp_enabled: true` (default).

```yaml
protocol:
  type: socks
  udp_enabled: true  # Default: true
```

#### VLESS Fallback
Route failed authentication attempts to a fallback destination instead of rejecting them.

```yaml
protocol:
  type: vless
  user_id: "uuid"
  fallback: "127.0.0.1:80"  # Serve web content for invalid clients
```

#### Reality `dest_client_chain`
Route Reality fallback (dest) connections through a proxy chain.

```yaml
reality_targets:
  "www.example.com":
    private_key: "..."
    dest: "www.example.com:443"
    dest_client_chain:
      address: "proxy.example.com:1080"
      protocol:
        type: socks
    protocol:
      type: vless
      user_id: "uuid"
```

### Improvements

- **UDP routing**: Comprehensive rewrite of UDP session routing with better multiplexing support
- **Reality**: Improved active probing resistance with TLS 1.3 verification
- **Performance**: Optimized buffer handling and reduced allocations
- **QUIC**: Better buffer sizing based on quic-go recommendations

### Mobile Support

- **iOS FFI**: Added iOS bindings via `NEPacketTunnelProvider` integration
- **Android FFI**: Added Android bindings via `VpnService` integration
- Library now builds as `rlib`, `cdylib`, and `staticlib` for mobile embedding

---

## v0.2.1

## New Features

### Client Chaining (`client_chains`)
Multi-hop proxy chains with load balancing support. Traffic can now be routed through multiple proxies in sequence.

- **Multi-hop chains**: Route traffic through multiple proxies sequentially (e.g., `proxy1 -> proxy2 -> target`)
- **Round-robin chains**: Specify multiple chains and rotate between them for load distribution
- **Pool-based load balancing**: At each hop, use a pool of proxies for load balancing
- New config fields: `client_chain` (singular) and `client_chains` (multiple)
- See `examples/multi_hop_chain.yaml` for usage examples

### TUIC v5 Zero-RTT Handshake
New `zero_rtt_handshake` option for TUIC v5 servers enables 0-RTT (0.5-RTT for server) handshakes for faster connection establishment.

```yaml
protocol:
  type: tuic
  uuid: "..."
  password: "..."
  zero_rtt_handshake: true  # Default: false
```

Note: 0-RTT is vulnerable to replay attacks. Only enable if the latency benefit outweighs security concerns.

### Reality Cipher Suites
Both Reality server and client now support specifying TLS 1.3 cipher suites.

```yaml
# Server
reality_targets:
  "example.com":
    cipher_suites: ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"]
    ...

# Client
protocol:
  type: reality
  cipher_suites: ["TLS_AES_256_GCM_SHA384"]
  ...
```

Valid values: `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`

### Reality Client Version Control
Server-side Reality configuration can now restrict client versions:

```yaml
reality_targets:
  "example.com":
    min_client_version: [1, 8, 0]  # [major, minor, patch]
    max_client_version: [2, 0, 0]
    ...
```

## Deprecations

### `client_proxy` / `client_proxies` in Rules
The `client_proxy` and `client_proxies` fields in rule configurations are deprecated in favor of `client_chain` and `client_chains`.

**Migration**: Replace `client_proxy:` with `client_chain:` in your configuration files. The old fields still work but will emit a warning and may be removed in a future version.

Before:
```yaml
rules:
  - masks: "0.0.0.0/0"
    action: allow
    client_proxy: my-proxy-group
```

After:
```yaml
rules:
  - masks: "0.0.0.0/0"
    action: allow
    client_chain: my-proxy-group
```

### VMess `force_aead` / `aead` Fields
The `force_aead` and `aead` fields in VMess configuration are deprecated. AEAD mode is now always enabled, and non-AEAD (legacy) mode is no longer supported.

**Migration**: Remove `force_aead` and `aead` fields from your VMess configurations. They have no effect and will be ignored.

## Removed / Breaking Changes

### VMess Non-AEAD Mode Removed
VMess non-AEAD (legacy) mode is no longer supported. All VMess connections now use AEAD encryption exclusively. This improves security but breaks compatibility with very old VMess clients that don't support AEAD.

## Other Changes

- Hysteria2 and TUIC servers now have authentication timeouts (3 seconds by default) to prevent connection hogging
- Improved fragment packet handling with LRU cache eviction
- TUIC server now sends heartbeat packets to maintain connection liveness
