# macOS Network Extension provider, and a shared Swift package

Written 2026-08-28 against `mobile` at `f8e26ff`. Closes desktop sub-project #3
in [ROADMAP.md](../../../ROADMAP.md), and changes its shape: the roadmap
described the work as "no new Rust, just Swift and packaging", which was nearly
right about the Rust and wrong about where the Swift belongs.

## Goal

A macOS host can run shoes in TUN mode inside a Network Extension provider, and
the Swift that drives shoes on macOS is the same Swift that drives it on iOS.

The second half is the larger part of this design. shoes has shipped an Apple
FFI since 0.2.x and has never shipped a line of Swift, so every consumer writes
the lifecycle themselves. There is currently one such consumer, and reading it
showed that the rules we wrote down were not the rules that got implemented.

## Decisions taken before this document

Recorded with their reasons, because each one closed off alternatives that look
reasonable from the outside.

**Network Extension, not a privileged root helper.** A helper daemon owning a
`utun` would make the GUI framework irrelevant and would match the Windows and
Linux sub-projects. It was rejected: it needs an admin install, gets no sandbox,
and puts route and DNS management inside shoes, which `src/` deliberately does
not do.

**Developer ID, not the Mac App Store.** App Store Review Guideline 5.4 requires
that a VPN app be offered by a developer enrolled as an *organization*. The
account here is an individual account, so the App Store is closed regardless of
preference. Developer ID has no such restriction: sign with a Developer ID
Application certificate, notarize, staple, and ship a DMG. macOS is the platform
this account can actually release on.

Worth recording because it is counter-intuitive: iOS is the constrained one. The
App Store is the only mass-distribution route there — TestFlight is beta-only
and reviewed, ad-hoc caps at 100 devices — and Guideline 5.4 is in the unified
guidelines, so it gates an iOS VPN release just as it gates a Mac App Store one.
Nothing in this design depends on how that resolves; the package is identical
either way. But if an organization enrollment is needed for iOS regardless, that
same enrollment reopens the Mac App Store, and the sysex-versus-appex decision
above would deserve a second look.

**Therefore a system extension, not an app extension.** Developer ID
distribution of a packet-tunnel provider means a `.systemextension` under
`Contents/Library/SystemExtensions`, activated at runtime through
`OSSystemExtensionRequest` and approved once by the user in System Settings —
not an `.appex` under `Contents/PlugIns`. The provider *class* is identical
either way; only the target type and activation differ.

**arm64 only for the macOS slice.** No `x86_64-apple-darwin`. A product
decision, taken deliberately: no Intel Mac support.

**The Swift ships as a SwiftPM package in this repo.** Alternatives were a
separate repository (versioning drifts from the FFI it wraps, which is the one
thing co-location buys) and shipping no Swift at all (the status quo, whose
result is documented below). `android/` is precedent that platform glue is
welcome in this tree.

## Non-goals

Not in this work, and deferred to the GUI repository:

- The system-extension target itself. An extension target **cannot** be a
  SwiftPM product; it must be a real Xcode target in the app's project, signed
  with the app's team ID and embedded in its bundle. What ships here is the
  class it subclasses.
- The host application, the GUI, and the Tauri-vs-Compose decision.
- The Apple Developer Program enrollment, the NetworkExtension entitlement
  request, signing, notarization and the DMG.
- Any change to how shoes manages routes or DNS. It does not, and this does not
  start.

## What reading the tree found

### The FFI is a feature on macOS, and that is right

`src/lib.rs:135` gates the whole FFI module:

```rust
#[cfg(any(target_os = "android", target_os = "ios", feature = "ffi"))]
pub mod ffi;
```

On iOS and Android the module is compiled by target; on macOS only with
`--features ffi`. An earlier draft of this document read that gate as a defect
that broke the default-features macOS build. It does not: with the feature off
the module is absent and the crate builds, which is what the desktop binary
and any Rust host linking the crate want — twelve `#[no_mangle]` exports have
no business in `target/release/shoes`. The gate stays.

What follows for this work is one flag: the macOS slice of the XCFramework is
built with `--features ffi,control-stats`, where the iOS slices need only
`control-stats`. `.github/workflows/mobile.yml`'s `macos` job already does
exactly that, and `test.yml`'s macOS leg covers the feature-off build.

### The descriptor as a parameter

The one Rust change, and the only addition to the C surface. Today the fd
travels inside the YAML: `device_fd: 42` in the `tun` section, and
`DevicePolicy::BorrowedFd` refuses a config without it
(`src/control/device.rs:39`). That is fine for a host that generates the YAML
where the fd is known. The Apple host is not that host: the config is generated
elsewhere — in KVN's case by Kotlin, in a shared module, on the app side — and
the fd is known only inside the extension, after `packetFlow` exists. KVN's
answer is a private `__TUN_FD__` placeholder and `replacingOccurrences`. It
works, and it is a textual patch on a document whose schema belongs to shoes,
made by a language with no YAML parser.

So `shoes_start_with_fd(config_yaml, device_fd, protect, traffic)` joins the
surface: identical to `shoes_start` except that it sets `tun.device_fd` after
parsing, replacing whatever the document carried. `shoes_start` stays, unchanged,
for hosts that already inject the fd themselves. Inside, both reach the same
`prepare_from_config`; the new function is a few lines in `src/ffi/ios.rs` and a
`with_device_fd` on the prepared config in `src/control`. The package then
never edits YAML, and the fd contract is stated by a parameter type rather than
by a placeholder convention. It exports on every platform that builds the FFI,
so the symbol count the CI check compares against `include/shoes.h` becomes
twelve.

That is the entire Rust change.

### A scare that was not one

`run_tun_from_config` (`src/tun/mod.rs:538`) sets `packet_information(true)` for
`target_os = "macos"`, and `create_sync_device` (`src/tun/tun_server.rs:276`)
forwards it only under `target_os = "ios"`. That looks like a defect that would
feed the utun 4-byte protocol header into smoltcp as packet data.

It is not. `tun-0.8.14`'s macOS `PlatformConfig` defaults `packet_information`
to `true` (`platform/macos/mod.rs:35`, *"default is true in macOS"*), and its
doc comment covers the Network Extension case explicitly: an fd obtained from
`packetFlow`'s `socket.fileDescriptor` carries the header. iOS is the platform
whose default differs, which is why iOS is the platform with the explicit call.

Behaviour is correct today. The builder field is dead on macOS, which is worth
tidying with a comment saying why it is a no-op, and is not worth calling a fix.

### Work already done in advance

`.github/workflows/mobile.yml:81-149` already builds the full FFI surface on
`aarch64-apple-darwin`, counts exported `_shoes_*` symbols in the dylib against
`include/shoes.h`, and is the only place in CI that compiles the
`not(control-stats)` arms of `src/ffi/ios.rs`. Its comment says why:

> The desktop client's privileged host on macOS is a Network Extension provider,
> which is Swift and so consumes the same C API as iOS […] Building it here
> means a change to the FFI cannot break the macOS host silently.

So the FFI half of this sub-project was built defensively before the host
existed. What is missing is the artifact a provider links against.

### A bridging header cannot be used

`scripts/build-ios.sh:90` ends by instructing the consumer to "add a bridging
header that includes `shoes.h`". That works for an Xcode app target and is what
the current consumer does (`iosApp/KVNTunnel/KVNTunnel-Bridging-Header.h`).

A SwiftPM library target has no bridging header. So `include/module.modulemap`
becomes a required new file, hand-written next to the cbindgen-generated header,
declaring the C module. `-headers include/` sweeps it into every XCFramework
slice.

### A filesystem collision

SwiftPM's conventions want `Sources/` and `Tests/` beside `Package.swift` at the
repo root. This repo already has `tests/`, and macOS APFS is case-insensitive by
default, so `Tests/` and `tests/` are one directory. Every target therefore
declares an explicit `path:` under `swift/`, mirroring `android/`.

## What reading the consumer found

`~/VibeCode/KRay` — the KVN client, Kotlin/Compose on Android and iOS, consuming
shoes 0.2.14. `iosApp/KVNTunnel/PacketTunnelProvider.swift` is 404 lines and is
the only existing implementation of the thing this package would replace.
Re-read at `40198b4` before the plan was written; the facts below are from that
tree.

### How it consumes shoes today

The XCFramework is vendored at `iosApp/PacketTunnel/Shoes.xcframework`, fetched
from a GitHub release by a Gradle task (`downloadShoesIos` in
`build-logic/.../ShoesBinaryPlugin.kt`) and referenced by path in the Xcode
project, linked by the `KVNTunnel` and `KVNTunnelTests` targets only — the app
target never touches the C surface. Migrating to the package retires that task
and that file reference; the remote `binaryTarget` is the same download by
another route.

The extension targets already build for `IPHONEOS_DEPLOYMENT_TARGET = 18.6`;
the app target sits at `16.2`, and every target is `SWIFT_VERSION = 5.0`. So the
package's iOS 18 floor moves the *app*, not the extension, and a Swift 5-mode
target importing a Swift 6-mode package is an ordinary arrangement — language
mode is per module.

The fd reaches shoes through two textual patches: `ShoesConfigGenerator.kt:38`
emits `device_fd: 0`, `IosVpnController.kt:87` rewrites that to
`device_fd: __TUN_FD__` on iOS, and `PacketTunnelProvider.swift:293` rewrites
the placeholder to the number. With `shoes_start_with_fd` the Kotlin side keeps
emitting `device_fd: 0` and both rewrites are deleted — which fixes a
requirement on the new function: it must *override* a present value, not only
fill an absent one.

And the iOS app has no live connection count. `45cad39` wired
`ShoesNative.getStats()` on Android; the iOS extension never calls
`shoes_get_stats`, and the host reads a two-number `traffic-stats.json` from the
App Group. `ShoesStats` plus a `stats` app message is what gets 0.2.14's
counters to iOS — the first concrete thing the migration delivers beyond
correctness.

### The split

Roughly 60% is shoes lifecycle and would move into the package unchanged: fd
extraction, `shoes_init`/`start`/`stop` sequencing, `shoes_get_last_error` paired
with `shoes_free_string`, a 14-second `startTunnel` timeout guard, a 30-second
`shoes_is_running()` health check, the weak-global bridge that gives a C function
pointer somewhere to send its callback, the no-op protect callback iOS needs,
`handleAppMessage` for version/status/`loglevel:`, and `shoes_network_changed()`
behind a debounced rebind.

Roughly 40% is KVN's own architecture and must stay theirs: the App Group
identifier, the `config.yaml` / `tunnel-error.txt` / `traffic-stats.json` files,
the Darwin notification names, and the hardcoded network settings.

That ratio is what makes a template-method base class the right shape rather
than a utility library.

### One piece that belongs to shoes, not to a consumer

```swift
private var chainRebindsInPlace: Bool {
    guard let yaml = configYaml else { return false }
    return yaml.contains("type: amneziawg") || yaml.contains("type: wireguard")
}
```

A substring search against shoes' own configuration schema, encoding shoes' own
knowledge that a UDP tunnel's endpoint socket rebinds in place so a full restart
is strictly worse. Correct today, and silently wrong the day a protocol is
renamed.

The engine already answers the question, and nobody asked it.
`shoes_network_changed()` returns *the number of endpoints told to rebind*. Zero
means nothing rebound in place and the full rebind is the only recovery;
non-zero means the tunnel has already recovered and a full rebind would only
drop the settings and restart the engine for nothing. The base class calls it
first, unconditionally, and branches on the count. No config inspection, no
new Rust, and the fact lives in the one place that can keep it true.

### Two rules we documented and the consumer did not follow

**`startTunnel` blocks on `shoes_stop`.** It calls `stopShoesIfRunning()`
synchronously near the top to clear a previous session, and that calls
`shoes_stop`, which blocks up to five seconds. `rebindTunnel` does the same.
MOBILE.md §4 documents exactly this hazard, and the code is inside a path the
author guarded with a 14-second timeout — so the risk was understood in one
place and missed in another.

**`stopTunnel` returns before shoes has released the descriptor.** `shoes_stop`
is dispatched to a background queue and `completionHandler()` is called
immediately, deliberately, to avoid the platform's stop deadline. On iOS the
descriptor belongs to NE, so this is not the use-after-free the fd-ownership
documentation warns about — but it is the same ordering rule, answered the other
way, in a consumer that had just been sent documentation about it.

Both were found by reading, not by a test, and neither is a criticism of the
author. They are the argument for the package: we wrote the rules down, the
rules were still not followed, and documentation does not execute.

### And a divergence worth recording

KRay's roadmap plans macOS desktop as `ProcessBuilder` running the shoes
*binary* with the system proxy pointed at it — not a Network Extension. That
architecture needs no entitlement, no enrollment and no Swift, and it is what
"shoes as a daemon the GUI controls" actually looks like. It was raised and the
decision was to build the Network Extension anyway, on the grounds that system
proxy settings are honoured only by cooperating applications and leave UDP and
uncooperative stacks uncovered, which is not an acceptable answer for a
circumvention client.

Recorded so the next reader knows the alternative was seen and declined, not
missed. `desktopApp/` in KRay is presently a 19-line `Main.kt`, so nothing is
committed either way yet.

## Architecture

```
┌───────────────────────────────────────────── consumer's Xcode project ──┐
│  App target                     Extension target (appex or sysex)       │
│  · ShoesTunnelManager           · final class Provider:                 │
│  · SystemExtensionInstaller       ShoesPacketTunnelProvider { ~20 ln }  │
└──────────────────────┬──────────────────────────────┬───────────────────┘
                       │            import ShoesTunnel │
┌──────────────────────┴──────────────────────────────┴───────────────────┐
│  ShoesTunnel  (SwiftPM library target, swift/Sources/ShoesTunnel)        │
│  ShoesConfiguration · ShoesStats · ShoesError · ShoesEngine              │
│  ShoesPacketTunnelProvider · ShoesTunnelManager                          │
│  SystemExtensionInstaller (#if os(macOS))                                │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │ import ShoesFFI
┌──────────────────────────────┴──────────────────────────────────────────┐
│  ShoesFFI  (binaryTarget → Shoes.xcframework)                           │
│  include/shoes.h + include/module.modulemap                             │
│  slices: ios-arm64 · ios-arm64-simulator · macos-arm64                  │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │ staticlib, profile release-mobile
┌──────────────────────────────┴──────────────────────────────────────────┐
│  shoes  (Rust)  src/ffi/ios.rs → 12 shoes_* symbols                     │
└─────────────────────────────────────────────────────────────────────────┘
```

### Components

| Type | Responsibility | Depends on | Testable |
| --- | --- | --- | --- |
| `ShoesConfiguration` | wraps the YAML a host generated elsewhere, plus the log level; **does not** parse or edit it | nothing | pure, fully |
| `ShoesStats` | `Codable` over `shoes_get_stats` JSON, unknown keys ignored | nothing | pure, fully |
| `ShoesError` | `shoes_get_last_error` → typed error, owns the `shoes_free_string` pairing | `ShoesFFI` | pure, fully |
| `ShoesEngine` | `init`/`start(fd:)`/`stop`/`isRunning`/`networkChanged`/`stats`/`version`/`setLogFile`/`setLogLevel`; owns the ordering rules | `ShoesFFI` | integration, really runs |
| `ShoesPacketTunnelProvider` | NE glue only: lifecycle overrides, fd extraction, health check, path observation | NetworkExtension, `ShoesEngine` | not unit-testable, kept thin |
| `ShoesTunnelManager` | host side: the TN3120 sequence, status as an `AsyncStream`, typed app messages | NetworkExtension | not unit-testable, kept thin |
| `SystemExtensionInstaller` | `OSSystemExtensionRequest` activation, `#if os(macOS)` | SystemExtensions | not unit-testable |

The split exists so the parts worth testing do not import NetworkExtension, and
the part that imports NetworkExtension holds no logic worth testing.

`ShoesConfiguration` is deliberately opaque. KVN generates its YAML in Kotlin
(`shared/.../ShoesConfigGenerator.kt`: seven protocols, tested, shared with
Android) and the provider receives a string from the App Group. A typed Swift
model of the config would force that consumer to either duplicate the generator
or parse YAML back into types with a Foundation that has no YAML parser — which
would make `loadConfiguration()` the one hook the existing implementation could
not satisfy. The engine takes the fd as a parameter (above) precisely so the
package never needs to look inside the document.

### The host side

`ShoesTunnelManager` is the app-process half, and it exists for the same reason
the provider does. KVN's `VPNManagerBridge.swift` is 193 lines, of which about a
hundred are Apple's TN3120 sequence — `loadAllFromPreferences`, find or create
the manager by provider bundle identifier, configure the
`NETunnelProviderProtocol`, `saveToPreferences`, `loadFromPreferences` *again*,
then `startVPNTunnel` — and the rest is Swift Export glue to Kotlin. The
sequence is where hosts get the ordering wrong (the second load is the step
everyone omits, and the start silently fails without it), it is identical on
macOS, and the macOS host needs it plus system-extension activation before it
can do anything at all.

The manager takes the provider bundle identifier and a `NETunnelProviderProtocol`
the host has configured (`includeAllNetworks` and the exclusion flags are the
host's policy, not the package's), exposes `start()`, `stop()`, `status` as an
`AsyncStream<NEVPNStatus>`, and `send(_:)` for the app messages the provider
answers — `version`, `status`, `stats`, `loglevel:` — as typed requests rather
than strings both sides have to spell the same way. On macOS `start()` runs
`SystemExtensionInstaller` first, so the one platform branch lives in the
package and not in the host. Nothing here touches the App Group: how a host
carries a config or an error between its two processes is its own affair, and
KVN's file-and-Darwin-notification scheme keeps working beside it.

### The provider as a template method

`ShoesPacketTunnelProvider` owns the sequence and leaves four holes. A consumer
subclass supplies only what is genuinely theirs:

```swift
open func loadConfiguration() throws -> ShoesConfiguration
open func makeNetworkSettings() -> NEPacketTunnelNetworkSettings
open func report(error: ShoesError)
open func report(upload: UInt64, download: UInt64)
```

Everything else — the timeout guard, the ordering, the health check, the
debounce, the callback bridging — is inherited and cannot be got wrong by
omission. KVN's App Group plumbing becomes the bodies of `report(error:)` and
`report(upload:download:)`; their `makeTunnelSettings()` becomes
`makeNetworkSettings()`.

### The ordering rules, encoded

Two rules that are currently prose become properties of `ShoesEngine`:

- `stop()` is `async`; the synchronous `shoes_stop` is not exposed. In
  `stopTunnel` the base class awaits it and *then* calls the completion handler,
  so the platform cannot tear the extension down while the engine still reads
  `packetFlow`. That is tolerable inside the platform's stop deadline only
  because shoes bounds the wait at five seconds, which is why the bound exists.
  `startTunnel` clears a previous session the same way, awaited rather than
  blocking the callback's thread — the hazard MOBILE.md §4 describes and the
  existing consumer has.
- `start(fd:)` takes the descriptor as a parameter — it is
  `shoes_start_with_fd` underneath — and documents in its signature that the
  engine borrows it. The engine never closes it, and the base class never
  releases `packetFlow` before `stop()` has returned.

A consumer cannot reach the hazardous ordering without deliberately dropping
down to `ShoesFFI`, which stays public for exactly that escape hatch.

## Build and distribution

### Script

`scripts/build-ios.sh` → `scripts/build-apple.sh`; `output/ios/` →
`output/apple/`; the artifact stays `Shoes.xcframework`. One slice added,
`aarch64-apple-darwin`. Deployment targets rise to
`IPHONEOS_DEPLOYMENT_TARGET=18.0` and `MACOSX_DEPLOYMENT_TARGET=15.0`, matching
the package's declared platforms — a split floor between the Rust objects and
the Swift that wraps them is a trap nobody would enjoy debugging. The iOS
slices build with `--features control-stats`; the macOS slice adds `ffi`,
since that is what compiles the module there. `control-logs` stays off on
every slice: it is a Rust-side subscribable sink that no C caller can reach.

**Profile: `release-mobile` for the macOS slice too, and not for size.** There is
no `catch_unwind` anywhere in `src/ffi/`, so the only thing preventing a panic
unwinding across the C boundary into Swift is `panic = "abort"`, which
`release-mobile` sets and `[profile.release]` does not. Using `release` here
would be unsound.

Open and deliberately not acted on: `opt-level = "s"` is a mobile size decision
that nobody has measured against desktop throughput. A third profile is not
worth adding before someone measures.

### Package manifest

`Package.swift` at the repo root (SwiftPM requires it there),
`swift-tools-version: 6.0`, Swift 6 language mode, platforms `.iOS(.v18)` and
`.macOS(.v15)`.

Swift 6 strict concurrency is a deliberate choice here rather than a default,
and it has one concrete consequence for the design. A C function pointer cannot
capture context, so the traffic callback needs somewhere process-global to send
its result; the existing consumer uses a `private weak var activeProvider`,
which is exactly the mutable global state Swift 6 rejects. The package instead
holds the callback in a `final class`, `@unchecked Sendable`, guarding a single
stored closure with an `NSLock` — the escape hatch taken once, in one file, with
its reason written next to it, rather than `nonisolated(unsafe)` sprinkled at
each call site. shoes supports one running engine per process anyway
(`shoes_is_running` is process-global and `shoes_stop` ignores the handle it is
given), so a registry keyed by handle would be inventing a multiplicity the
engine does not have.

The platform floor is a product decision with a consumer-visible cost:
SwiftPM's `platforms:` is a minimum, so any app importing this package inherits
it. KVN's extension already builds for 18.6; its app target is at 16.2, and
adopting the package moves that to 18.

The binary target resolves two ways. When `SHOES_LOCAL_XCFRAMEWORK` is set in the
environment, `path:` points at `output/apple/Shoes.xcframework`; otherwise a
remote `url:` plus `checksum:` pinned to a release. CI and local development use
the first; an external consumer gets the second. Two limits, so nobody
rediscovers them: Xcode does not pass the shell environment to manifest
evaluation, so opening the package in Xcode gets the remote binary regardless —
the switch is for `swift build` and `swift test` — and SwiftPM caches the
evaluated manifest, so toggling it needs `swift package reset`.

Less new machinery than expected: `mobile.yml`'s `release` job already zips
the XCFramework to `Shoes.xcframework.zip` and attaches it to the tag release,
so the URL shape a consumer needs already exists and only the checksum is new.
SwiftPM's checksum is the archive's plain SHA-256, so `shasum -a 256` computes
it on the existing ubuntu release runner with no Swift toolchain.

What is not solved by that is an ordering problem, addressed under CI below.

## CI

### Existing jobs

`mobile.yml`'s `ios` job becomes `apple` and runs the renamed script, so the
macOS slice is covered with no new job and the uploaded artifact keeps its
name. The `macos` job keeps both things that earn its runtime — the symbol count
against `include/shoes.h`, and the only compile of the `not(control-stats)`
arms — and is renamed from "Build macOS staticlib", since the check
deliberately reads the dylib.

`build.yml`'s `paths-ignore` gains `swift/**` and `Package.swift`: a Swift-only
change has no business spending seven release builds. `mobile.yml`'s stays as
it is — those paths *should* trigger it.

### The new `swift` job

`needs: [apple]`, downloading the XCFramework artifact rather than rebuilding
it. Building it twice would cost roughly twenty minutes on the most expensive
runner in the pipeline for no coverage.

With `SHOES_LOCAL_XCFRAMEWORK` pointing at the downloaded framework: `swift
build`, `swift test`, an `xcodebuild -destination 'generic/platform=iOS'`
typecheck so the iOS slice cannot rot while only macOS is exercised, and
`swift-format lint --strict`. The formatter lives here rather than in `lint.yml`
because `lint.yml` is entirely ubuntu and Swift formatting is not worth a macOS
runner of its own.

Xcode gets pinned explicitly rather than inherited from `macos-latest`. Swift 6
language mode and the iOS 18 SDK have a floor, `macos-latest` moves without
notice, and this repository already pins its actions by SHA for the same
reason.

### When the Swift is built, which is a real question

`mobile.yml` deliberately does not run on branch pushes — its header says so and
accepts the cost: "a break in them is caught when a tag is pushed rather than
when the code lands." That reasoning was written about cross-compiled artifacts
nothing downloads between tags.

Swift sources in `swift/` are different in kind: they are this repository's own
code, compiled by no other workflow, and `test.yml` runs on ubuntu where they
cannot be built at all. Leaving them in `mobile.yml` means a `mobile` push that
breaks the package stays green until someone opens a PR.

Recommended: run the `swift` job on branch pushes as well, scoped with `paths:`
to `swift/**`, `Package.swift`, `include/**` and `src/ffi/**`, so it costs a
macOS runner only when something it covers actually changed. One mechanical
consequence: `on.push.paths` triggers the *workflow*, and `swift` needs `apple`
in the same run, so `apple` runs on those pushes too — that is the point — while
`android`, `macos` and `release` take a job-level
`if: github.event_name != 'push' || startsWith(github.ref, 'refs/tags/')` so a
Swift push does not also buy an NDK build. The alternative — consistency with
the existing policy — is defensible and cheaper, and the choice is noted here
rather than assumed.

### The checksum ordering problem

A remote `binaryTarget` needs the checksum of the zip *for the tag it is on*.
The zip is produced by that tag's build. So the tag's `Package.swift` cannot
contain its own release's checksum, and there is no arrangement of the current
tag-triggered flow that makes it.

Pointing at the previous release is not an acceptable fallback: it is exactly
the Swift-versus-FFI version skew that putting the package in this repository
was meant to prevent, and it is only safe when the FFI happens not to have
changed, which nothing can determine automatically.

Recommended: **release, then tag.** A `workflow_dispatch` release flow taking a
version input builds the XCFramework, uploads the zip to a draft release,
computes `shasum -a 256`, commits the updated `Package.swift`, tags *that*
commit, and publishes. The tag then points at a commit whose manifest is
correct, and nothing force-moves a published tag.

That flow has a trap of its own, found in review: the tag push it ends with
triggers `mobile.yml`, whose `apple` job rebuilds the XCFramework and whose
`release` job re-attaches `Shoes.xcframework.zip` — and `action-gh-release`
overwrites an existing asset by default. Zip timestamps alone make the rebuild
byte-different, so the checksum committed a minute earlier would stop matching
the asset it names, for every consumer, on every release. So the dispatch flow
must be the *only* producer of that zip: `mobile.yml`'s tag-triggered `release`
job attaches the AAR and nothing else, and its `apple` job on a tag is a build
check rather than a publisher. The plan should make the tag-triggered run
incapable of touching the zip, not merely unlikely to.

The cost is that tagging stops being `git tag && git push` and becomes a
workflow run, which changes a release habit and is the reason this is called out
rather than decided quietly. A second option exists — a thin `shoes-spm`
repository that CI pushes a manifest and tag into after each release, decoupling
the two entirely — and was not recommended because it reintroduces the split
this design rejected, even though CI would keep it in step.

## Documentation

`docs/MACOS.md`, new, holding only what is genuinely macOS-specific: system
extension versus app extension and why Developer ID forces the former, the
entitlement and that it is the long pole, `OSSystemExtensionRequest` and the
`/Applications` requirement, and the `ServiceHandle` async-drop rule from
`src/control/mod.rs`.

Integration guidance goes in the package's own README, where a consumer will
look for it. `MOBILE.md` keeps its title and gains a cross-reference; a desktop
system extension does not belong under "Mobile integration notes".

`ROADMAP.md` sub-project #3 gets corrected — "no new Rust" was nearly right, but
the XCFramework had no macOS slice — and gains the decisions recorded at the top
of this document.

## Testing

What can be proven with no Apple Developer account, which is the situation today:

- `build-apple.sh` emits an XCFramework whose `Info.plist` lists a `macos-arm64`
  slice, and `nm` finds the same 12 `shoes_*` symbols in it.
- `swift build` and `swift test` succeed on a macOS runner.
  `NetworkExtension.framework` ships in the SDK, so the provider class compiles
  even though it cannot run.
- `ShoesConfiguration`, `ShoesStats` and `ShoesError` are unit-tested outright.
- `ShoesEngine` is integration-tested against the real static library: version,
  init idempotence, `isRunning` before start, a rejected config reporting through
  `shoes_get_last_error`, stats before start. KVN's `ShoesLibraryTests.swift`
  already demonstrates this works and is a reasonable starting point.

What cannot be verified, and what the documentation will say plainly rather than
imply otherwise: **the tunnel has never run on macOS.** Nor has the protect
callback's no-op been shown safe there: on iOS it is, because the system keeps a
packet tunnel provider's own sockets out of its tunnel, and whether a macOS
system extension gets the same treatment is something neither this tree nor the
consumer can show. Activating a system
extension needs the entitlement in a real provisioning profile, which needs the
$99 enrollment; `systemextensionsctl developer on` relaxes the `/Applications`
and notarization requirements but not that one, and a free Personal Team cannot
use NetworkExtension entitlements at all.

## Risks

**The entitlement is the long pole.** `com.apple.developer.networking.networkextension`
for Developer ID distribution is granted by request to Apple, not self-serve in
the portal. Whether an individual account is granted it should be asked now, in
parallel: it gates running steps 5 onward and nothing before them. Step 5's
macOS-only file is compile-checked and small, so writing it before the answer
arrives risks little; what should wait for the answer is the host application,
which is out of scope here anyway.

**The consumer migration is coordination, not a gamble.** KVN will migrate its
iOS provider to this package, so the API has a committed user from the start —
which is the good case, and also the demanding one: the four `open` hooks have
to be sufficient for an implementation that already exists. The 60/40 split
above was measured against that implementation precisely so the hooks are shaped
by it rather than guessed. The migration also moves KVN's app floor from 16.2
to 18, deletes two placeholder rewrites on the Kotlin and Swift sides, retires
the `downloadShoesIos` Gradle task, and moves their traffic reporting from the
`ShoesTrafficCallback` to the `report(upload:download:)` hook.

**A public Swift API is a compatibility surface.** Today the FFI can change with
a header regeneration and a note. After this, `open` methods on a base class are
a contract with anyone who subclassed it, and the host-side manager widens that
surface to both processes. The app-message vocabulary in particular is shared
between a provider and a manager that may be built from different package
versions — the extension and the app ship together, so in practice they match,
but the encoding should tolerate an unknown request rather than crash on one.

## Order of work

1. A comment on the macOS `packet_information` no-op, and the CI job rename.
2. `shoes_start_with_fd` in `src/ffi/ios.rs` and `src/control`, header
   regenerated, symbol count in CI raised to twelve.
3. `build-apple.sh` with the macOS slice, and `include/module.modulemap`.
4. `Package.swift` and the pure types — `ShoesConfiguration`, `ShoesStats`,
   `ShoesError` — with their tests. Nothing here imports NetworkExtension.
5. `ShoesEngine` and its integration tests.
6. `ShoesPacketTunnelProvider`, `ShoesTunnelManager`, and
   `SystemExtensionInstaller` behind `#if os(macOS)`.
7. CI `swift` job, the job-level guards, and the dispatch release flow.
8. `docs/MACOS.md`, package README, `MOBILE.md` cross-reference, `ROADMAP.md`.

Steps 1–5 are verifiable end to end with no Apple account. Steps 6 onward
compile but cannot run until enrollment.
