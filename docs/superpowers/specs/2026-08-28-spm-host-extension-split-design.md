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
  `ShoesConfiguration` and the provider subclass compiles as before. The
  README says the preferred spelling: `import ShoesTunnel` in the extension,
  `import ShoesTunnelHost` in the app, never `import ShoesTunnelCore`
  directly.
- Public API is unchanged: a `ShoesPacketTunnelProvider` subclass and a
  `ShoesTunnelManager` caller compile as before once they import the right
  product. Extension consumers need only a version bump; the app side swaps
  its dependency from `ShoesTunnel` to `ShoesTunnelHost`.
- `Package.swift` keeps `shoesRelease`, `shoesChecksum` and the `shoesFFI`
  target exactly as they are; `release-apple.yml`'s two `sed` lines keep
  matching.

## The property, as a test

The reason for the split is a link-time property and it must not regress
silently. Two `executableTarget`s are added to the manifest, named as
fixtures rather than examples:

- `swift/LinkCheck/HostLinkCheck` — `import ShoesTunnelHost`, constructs a
  `ShoesTunnelManager` and references `send`, so the host surface is live.
- `swift/LinkCheck/ExtensionLinkCheck` — `import ShoesTunnel`, references
  `ShoesEngine.shared`, so the engine is live.

Neither is a product; consumers do not build them. A new step in
`mobile.yml`'s `swift` job, after the macOS test run, builds both for the
iOS Simulator in Release:

```
swift build -c release \
  --triple arm64-apple-ios18.0-simulator \
  --sdk "$(xcrun --sdk iphonesimulator --show-sdk-path)" \
  --product HostLinkCheck --product ExtensionLinkCheck
```

and asserts, with `shell: bash` so the pipe cannot hide a failure:

- `nm -U <HostLinkCheck> | grep -c ' T _shoes_'` is `0`;
- `nm -U <ExtensionLinkCheck> | grep -c ' T _shoes_'` is greater than `0`,
  which proves the check reads real binaries.

The step also prints `size -m` `__TEXT` for both; those two numbers are the
measurement the README quotes. If `swift build` cannot produce a simulator
executable with this toolchain, the fallback is `xcodebuild` on the same two
targets with `-destination 'generic/platform=iOS Simulator'` and
`CODE_SIGNING_ALLOWED=NO`; the assertion is the same.

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
