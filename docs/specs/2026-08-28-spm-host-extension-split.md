# ShoesTunnel: a host product beside the extension product

Written 2026-08-28 against `mobile` at `8faa430` (v0.2.15), in answer to the
KVN request to split the package so an app can use `ShoesTunnelManager`
without linking the engine.

## Why

`swift/README.md` tells a consumer to depend on `ShoesTunnel` from both the
app target and the extension target. KVN measured what that costs: with one
product, all 11 `shoes_*` symbols survive `-dead_strip` in the Release app
executable and its `__TEXT` grows by roughly the size of the extension
(~15 MB). The engine is reachable from `ShoesEngine.shared` and the two
`@convention(c)` globals in `TrafficCallbackBridge`, and the module is
compiled whole, so the linker cannot separate `ShoesTunnelManager` from
`ShoesFFI`. KVN therefore kept its own `NEVPNManager` code and does not link
the package from the app at all. The fix is in the package graph, not in
linker flags.

## Layout

```
targets
  ShoesFFI          binary target, unchanged
  ShoesTunnelCore   ShoesConfiguration, ShoesLogLevel, ShoesError, ShoesStats,
                    ShoesAppMessage, ShoesAppReply          (no dependencies)
  ShoesTunnelHost   ShoesTunnelManager, SystemExtensionInstaller
                    depends on ShoesTunnelCore              (never on ShoesFFI)
  ShoesTunnel       ShoesEngine, ShoesPacketTunnelProvider, TrafficCallbackBridge
                    depends on ShoesTunnelCore, ShoesFFI

products
  ShoesTunnel       → ShoesTunnel        the extension links this, name unchanged
  ShoesTunnelHost   → ShoesTunnelHost    the app links this
```

Sources move under `swift/Sources/<TargetName>/`; every file moves whole, no
file is split. The current sources already respect the boundary:
`ShoesTunnelManager` reaches only `SystemExtensionInstaller` and Core types;
`ShoesEngine` reaches only `TrafficCallbackBridge`, `ShoesFFI` and Core types.
`ShoesTunnelCore` is a target, not a product — nothing needs the wire types
alone today.

### Rules the split keeps

- One definition of the wire format. `ShoesAppMessage`, `ShoesAppReply`,
  `ShoesStats`, `ShoesLogLevel` live in Core and are compiled into both
  products from the same source. `ShoesError` is in Core too:
  `ShoesTunnelManager.send` throws `.engine`, and the provider reports the
  same enum.
- Core imports Foundation only — no `ShoesFFI`, no `NetworkExtension`. It
  must build with `swift build --target ShoesTunnelCore` on a machine that
  has never downloaded the XCFramework.
- Linker settings travel with the code: `NetworkExtension` on Host and on
  ShoesTunnel; `SystemExtensions` (macOS only) on Host.
- `@_exported import ShoesTunnelCore` in both `ShoesTunnel` and
  `ShoesTunnelHost`, so `import ShoesTunnel` alone still sees
  `ShoesConfiguration` and the provider subclass compiles as before.
  `@_exported` is underscored API; it is stable in practice and the README
  says the choice is deliberate. The README also says the preferred
  spelling: `import ShoesTunnel` in the extension, `import ShoesTunnelHost`
  in the app; `import ShoesTunnelCore` is not recommended but keeps working.
- Public API is unchanged: a `ShoesPacketTunnelProvider` subclass and a
  `ShoesTunnelManager` caller compile as before once they import the right
  product. Extension consumers need only a version bump; the app side swaps
  its dependency from `ShoesTunnel` to `ShoesTunnelHost`.
- `Package.swift` keeps `shoesRelease`, `shoesChecksum` and the `shoesFFI`
  target exactly as they are; `release-apple.yml`'s two `sed` lines keep
  matching.

## The property, as a test

The reason for the split is a link-time property and it must not regress
silently. To be precise about what the check proves: the host side is
guaranteed by the graph, not by the linker — `ShoesTunnelHost` never depends
on `ShoesFFI`, so `libshoes.a` is not on the app's link line at all and the
`nm` count cannot be non-zero today. The check guards against someone adding
that dependency back; the extension-side positive count is what makes the
pair meaningful. Two `executableTarget`s are added to the manifest, named as
fixtures rather than examples:

- `swift/LinkCheck/HostLinkCheck` — `import ShoesTunnelHost`, constructs a
  `ShoesTunnelManager` and references `send`, so the host surface is live.
- `swift/LinkCheck/ExtensionLinkCheck` — `import ShoesTunnel`, references
  `ShoesEngine.shared`, so the engine is live.

Neither is declared as a product. A root package's `executableTarget` gets
an automatic executable product anyway — that is what makes `--product
HostLinkCheck` resolvable — and Xcode's add-package dialog lists only
declared library products, so consumers never see them; the manifest says
this in a comment so nobody "fixes" it by declaring them. The macOS
`swift build` / `swift test` run builds them too (SystemExtensions links
there); that is expected. They are under `swift/`, so `swift format lint
--strict` covers them and they must pass it.

A new step in `mobile.yml`'s `swift` job, after the macOS test run, builds
both for the iOS Simulator in Release. The first attempt is `xcodebuild`,
because the repo already has a working iOS invocation of it and linking an
executable against `NetworkExtension.framework` under `swift build --sdk`
is the shaky part:

```
xcodebuild -scheme HostLinkCheck -configuration Release \
  -destination 'generic/platform=iOS Simulator' \
  CODE_SIGNING_ALLOWED=NO -derivedDataPath build/linkcheck build
```

(and the same for `ExtensionLinkCheck`); `swift build -c release --triple
arm64-apple-ios18.0-simulator --sdk "$(xcrun --sdk iphonesimulator
--show-sdk-path)"` is the fallback if the scheme route does not yield an
executable. Either way the step asserts, with `shell: bash` so the pipe
cannot hide a failure:

- `nm -U <HostLinkCheck> | grep -c ' T _shoes_'` is `0`;
- `nm -U <ExtensionLinkCheck> | grep -c ' T _shoes_'` is greater than `0`,
  which proves the check reads real binaries.

The step also prints `size -m` `__TEXT` for both; those two numbers are the
measurement the README quotes.

## Tests

- `ShoesAppMessageTests`, `ShoesStatsTests`, `ShoesConfigurationTests` move
  to `swift/Tests/ShoesTunnelCoreTests`, a test target depending only on
  Core, with `@testable import ShoesTunnelCore`.
  `swift test --filter ShoesTunnelCoreTests` runs without the XCFramework.
- `ShoesEngineTests` stays in `ShoesTunnelTests` against `ShoesTunnel` and
  still needs `SHOES_LOCAL_XCFRAMEWORK` or the release binary.
- The existing `xcodebuild -scheme ShoesTunnel` iOS typecheck gains
  `ShoesTunnelHost` (a second invocation, or the package's `-Package`
  scheme) so the host slice is typechecked against the iOS SDK too.

## Docs and release

- `swift/README.md`: the two products and which target links which, the
  `import` spelling, and the size fact in one sentence with the measured
  number.
- `docs/MACOS.md`: a line where it says "the Swift package" does the system
  extension activation, naming `ShoesTunnelHost`.
- CHANGELOG under the next version: source-compatible for extension
  consumers, additive for hosts; the app side changes one product name.

## Out of scope

A sample app, a `ShoesTunnelCore` product, and any change to the release
workflow or the checksum mechanism.

Follow-up, not in this change: `ShoesTunnelManager` throws
`ShoesError.engine("no tunnel session")` for a host-side condition. Once the
enum lives in Core the natural fix is a `.noSession` case; that is an API
addition and gets its own change.
