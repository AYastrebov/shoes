# ShoesTunnelHost Product Split Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split the `ShoesTunnel` Swift package into a Core target under two products — `ShoesTunnel` (extension, links the engine) and `ShoesTunnelHost` (app, never links the engine) — with a CI check that proves no `shoes_*` symbol reaches a host executable.

**Architecture:** Three source targets over the unchanged `ShoesFFI` binary target: `ShoesTunnelCore` (wire types, Foundation only), `ShoesTunnelHost` (`ShoesTunnelManager`, `SystemExtensionInstaller`; depends on Core), `ShoesTunnel` (`ShoesEngine`, `ShoesPacketTunnelProvider`, `TrafficCallbackBridge`; depends on Core + FFI). Both leaf targets `@_exported import ShoesTunnelCore`. Two `executableTarget` link-check fixtures are built for the iOS Simulator in CI and inspected with `nm`.

**Tech Stack:** Swift 6 / SwiftPM (tools 6.0), Swift Testing, `swift format`, `xcodebuild`, GitHub Actions (`mobile.yml`).

**Spec:** `docs/superpowers/specs/2026-08-28-spm-host-extension-split-design.md`

## Global Constraints

- `Package.swift` lines `let shoesRelease = "v0.2.15"` and `let shoesChecksum = "52f7…"` and the `shoesFFI` target stay byte-for-byte unchanged; `release-apple.yml` seds them by `^let shoesRelease`/`^let shoesChecksum`.
- Every file moves whole; no file is split; no public API changes.
- `ShoesTunnelCore` imports Foundation only — no `ShoesFFI`, no `NetworkExtension`.
- `ShoesTunnelHost` never depends on `ShoesFFI`.
- Linker settings: `NetworkExtension` on Host and ShoesTunnel; `SystemExtensions` (macOS only) on Host.
- Everything under `swift/` and `Package.swift` must pass `swift format lint --strict --recursive swift Package.swift` (config in `.swift-format`: 4 spaces, 120 cols).
- Local builds/tests need the framework: `bash scripts/build-apple.sh` once, then `SHOES_LOCAL_XCFRAMEWORK=1` on every `swift build`/`swift test`. After toggling that variable run `swift package reset`.
- Commits: imperative subject, body says why, author `Andrey Yastrebov <ayastrebov@gmail.com>`.
- Platforms `.iOS(.v18), .macOS(.v15)`, `swiftLanguageModes: [.v6]`.

## File Structure

```
Package.swift                                          modify: targets/products
swift/Sources/ShoesTunnelCore/ShoesConfiguration.swift  git mv (ShoesLogLevel lives here)
swift/Sources/ShoesTunnelCore/ShoesError.swift          git mv
swift/Sources/ShoesTunnelCore/ShoesStats.swift          git mv
swift/Sources/ShoesTunnelCore/ShoesAppMessage.swift     git mv
swift/Sources/ShoesTunnelHost/ShoesTunnelManager.swift  git mv + re-export
swift/Sources/ShoesTunnelHost/SystemExtensionInstaller.swift  git mv
swift/Sources/ShoesTunnel/ShoesEngine.swift             stays + re-export
swift/Sources/ShoesTunnel/ShoesPacketTunnelProvider.swift  stays
swift/Sources/ShoesTunnel/TrafficCallbackBridge.swift   stays
swift/Tests/ShoesTunnelCoreTests/{ShoesAppMessage,ShoesStats,ShoesConfiguration}Tests.swift  git mv
swift/Tests/ShoesTunnelTests/ShoesEngineTests.swift     stays
swift/LinkCheck/HostLinkCheck/main.swift                create
swift/LinkCheck/ExtensionLinkCheck/main.swift           create
.github/workflows/mobile.yml                            modify: typecheck + link check
swift/README.md, docs/MACOS.md, CHANGELOG.md            modify
```

---

### Task 1: Core target and its tests

**Files:**
- Modify: `Package.swift:35-58`
- Move: four sources to `swift/Sources/ShoesTunnelCore/`, three tests to `swift/Tests/ShoesTunnelCoreTests/`
- Modify: `swift/Sources/ShoesTunnel/ShoesEngine.swift:1-2`, `swift/Sources/ShoesTunnel/ShoesPacketTunnelProvider.swift:1` (no change needed beyond re-export in ShoesEngine)

**Interfaces:**
- Produces: target `ShoesTunnelCore` exporting `ShoesConfiguration`, `ShoesLogLevel`, `ShoesError`, `ShoesStats`, `ShoesAppMessage`, `ShoesAppReply`; test target `ShoesTunnelCoreTests`.

- [ ] **Step 1: Move the files**

```bash
cd /Users/Andrey.Yastrebov/VibeCode/shoes
mkdir -p swift/Sources/ShoesTunnelCore swift/Tests/ShoesTunnelCoreTests
git mv swift/Sources/ShoesTunnel/ShoesConfiguration.swift swift/Sources/ShoesTunnelCore/
git mv swift/Sources/ShoesTunnel/ShoesError.swift         swift/Sources/ShoesTunnelCore/
git mv swift/Sources/ShoesTunnel/ShoesStats.swift         swift/Sources/ShoesTunnelCore/
git mv swift/Sources/ShoesTunnel/ShoesAppMessage.swift    swift/Sources/ShoesTunnelCore/
git mv swift/Tests/ShoesTunnelTests/ShoesAppMessageTests.swift    swift/Tests/ShoesTunnelCoreTests/
git mv swift/Tests/ShoesTunnelTests/ShoesStatsTests.swift         swift/Tests/ShoesTunnelCoreTests/
git mv swift/Tests/ShoesTunnelTests/ShoesConfigurationTests.swift swift/Tests/ShoesTunnelCoreTests/
```

- [ ] **Step 2: Retarget the moved tests**

In each of the three files under `swift/Tests/ShoesTunnelCoreTests/`, change `@testable import ShoesTunnel` to `@testable import ShoesTunnelCore`.

```bash
sed -i '' 's/^@testable import ShoesTunnel$/@testable import ShoesTunnelCore/' swift/Tests/ShoesTunnelCoreTests/*.swift
grep -n '@testable' swift/Tests/ShoesTunnelCoreTests/*.swift   # all three say ShoesTunnelCore
```

- [ ] **Step 3: Add the Core target to the manifest**

Replace the `targets:` array in `Package.swift` (keep `shoesFFI` first; leave `products:` alone for now):

```swift
    targets: [
        shoesFFI,
        // The wire format and the types both processes share. Foundation
        // only: it must build where the XCFramework was never downloaded.
        .target(
            name: "ShoesTunnelCore",
            path: "swift/Sources/ShoesTunnelCore"),
        .target(
            name: "ShoesTunnel",
            dependencies: ["ShoesTunnelCore", "ShoesFFI"],
            path: "swift/Sources/ShoesTunnel",
            linkerSettings: [
                .linkedFramework("NetworkExtension"),
                .linkedFramework("SystemExtensions", .when(platforms: [.macOS])),
            ]),
        .testTarget(
            name: "ShoesTunnelCoreTests",
            dependencies: ["ShoesTunnelCore"],
            path: "swift/Tests/ShoesTunnelCoreTests"),
        .testTarget(
            name: "ShoesTunnelTests",
            dependencies: ["ShoesTunnel"],
            path: "swift/Tests/ShoesTunnelTests"),
    ],
```

- [ ] **Step 4: Re-export Core from ShoesTunnel**

Edit `swift/Sources/ShoesTunnel/ShoesEngine.swift` lines 1–2 to:

```swift
import Foundation
import ShoesFFI

// Re-exported so `import ShoesTunnel` alone sees ShoesConfiguration and
// the rest of the wire types, as it did before the split.
@_exported import ShoesTunnelCore
```

(`ShoesPacketTunnelProvider.swift` and `TrafficCallbackBridge.swift` see Core through the module's own dependency; no import line needed.)

- [ ] **Step 5: Prove Core builds without the framework**

```bash
swift package reset
unset SHOES_LOCAL_XCFRAMEWORK
swift build --target ShoesTunnelCore
```
Expected: `Build complete!` with no download of `Shoes.xcframework.zip` attempted for this target (SwiftPM resolves the binary target lazily; if it does try to fetch, the manifest — not this task — is wrong).

- [ ] **Step 6: Run the Core tests without the framework, then everything with it**

```bash
swift test --filter ShoesTunnelCoreTests
```
Expected: all `ShoesAppMessageTests`, `ShoesStatsTests`, `ShoesConfigurationTests` pass.

```bash
swift package reset
bash scripts/build-apple.sh          # skip if output/apple/Shoes.xcframework is current
SHOES_LOCAL_XCFRAMEWORK=1 swift build
SHOES_LOCAL_XCFRAMEWORK=1 swift test
swift format lint --strict --recursive swift Package.swift
```
Expected: build clean, all four suites pass, lint silent.

- [ ] **Step 7: Commit**

```bash
git add -A Package.swift swift
git commit -m "swift: move the wire types into a ShoesTunnelCore target

The types both processes must agree on -- configuration, log level,
error, stats, app messages -- now compile from one target with no
dependencies, so a host product can be added beside the extension
without duplicating them. ShoesTunnel re-exports Core; consumers see no
change. Their tests move with them and run without the XCFramework."
```

---

### Task 2: Host target and the two products

**Files:**
- Modify: `Package.swift` products and targets
- Move: `ShoesTunnelManager.swift`, `SystemExtensionInstaller.swift` to `swift/Sources/ShoesTunnelHost/`

**Interfaces:**
- Consumes: `ShoesTunnelCore` from Task 1.
- Produces: product `ShoesTunnelHost` exporting `ShoesTunnelManager` (`init(providerBundleIdentifier:)`, `load()`, `start`, `statusUpdates`, `send(_:)`) and `SystemExtensionInstaller`, plus every Core type via re-export.

- [ ] **Step 1: Move the files**

```bash
mkdir -p swift/Sources/ShoesTunnelHost
git mv swift/Sources/ShoesTunnel/ShoesTunnelManager.swift       swift/Sources/ShoesTunnelHost/
git mv swift/Sources/ShoesTunnel/SystemExtensionInstaller.swift swift/Sources/ShoesTunnelHost/
```

- [ ] **Step 2: Re-export Core from the Host**

Edit `swift/Sources/ShoesTunnelHost/ShoesTunnelManager.swift` lines 1–2 to:

```swift
import Foundation
@preconcurrency import NetworkExtension

// Re-exported so `import ShoesTunnelHost` alone sees ShoesAppMessage,
// ShoesError and the other wire types.
@_exported import ShoesTunnelCore
```

- [ ] **Step 3: Manifest — products and the Host target**

Replace `products:` with:

```swift
    products: [
        // The extension links this: the provider base class over the engine.
        .library(name: "ShoesTunnel", targets: ["ShoesTunnel"]),
        // The app links this. It never depends on ShoesFFI, so no shoes_*
        // symbol can reach the app executable -- the link check in
        // mobile.yml holds the package to that.
        .library(name: "ShoesTunnelHost", targets: ["ShoesTunnelHost"]),
    ],
```

Insert after the `ShoesTunnelCore` target and before the `ShoesTunnel` target:

```swift
        .target(
            name: "ShoesTunnelHost",
            dependencies: ["ShoesTunnelCore"],
            path: "swift/Sources/ShoesTunnelHost",
            linkerSettings: [
                .linkedFramework("NetworkExtension"),
                .linkedFramework("SystemExtensions", .when(platforms: [.macOS])),
            ]),
```

Remove `.linkedFramework("SystemExtensions", .when(platforms: [.macOS]))` from the `ShoesTunnel` target, whose `linkerSettings` becomes `[.linkedFramework("NetworkExtension")]`.

- [ ] **Step 4: Build, test, lint**

```bash
SHOES_LOCAL_XCFRAMEWORK=1 swift build
SHOES_LOCAL_XCFRAMEWORK=1 swift test
swift format lint --strict --recursive swift Package.swift
grep -n "ShoesFFI\|NetworkExtension" swift/Sources/ShoesTunnelCore/*.swift   # expect no output
grep -n "ShoesFFI" swift/Sources/ShoesTunnelHost/*.swift                     # expect no output
```
Expected: clean build, all suites pass, lint silent, both greps empty.

- [ ] **Step 5: Confirm the release seds still match**

```bash
grep -n '^let shoesRelease = "\|^let shoesChecksum = "' Package.swift
git diff HEAD~1 -- Package.swift | grep '^[-+]let shoes'   # expect no output
```

- [ ] **Step 6: Commit**

```bash
git add -A Package.swift swift
git commit -m "swift: add the ShoesTunnelHost product for the app process

Linking ShoesTunnel into an app kept every shoes_* symbol alive in the
app executable -- KVN measured about 15 MB of __TEXT for code the app
never runs -- because ShoesEngine.shared and the C callback globals
root the engine and the module is compiled whole. ShoesTunnelManager and
SystemExtensionInstaller now ship as ShoesTunnelHost, which depends on
Core only. The extension product keeps its name and API."
```

---

### Task 3: Link-check fixtures and the CI property

**Files:**
- Create: `swift/LinkCheck/HostLinkCheck/main.swift`, `swift/LinkCheck/ExtensionLinkCheck/main.swift`
- Modify: `Package.swift` targets; `.github/workflows/mobile.yml:130-138`

**Interfaces:**
- Consumes: products `ShoesTunnelHost`, `ShoesTunnel`.
- Produces: schemes `HostLinkCheck`, `ExtensionLinkCheck` (automatic executable products); CI step `Link check (iOS Simulator, Release)`.

- [ ] **Step 1: Write the fixtures**

`swift/LinkCheck/HostLinkCheck/main.swift`:

```swift
// A link-check fixture, not an example. It is the smallest executable that
// links ShoesTunnelHost with the host surface live; mobile.yml builds it
// for the iOS Simulator in Release and asserts no shoes_* symbol survives.
import ShoesTunnelHost

@MainActor
func run() async {
    let tunnel = ShoesTunnelManager(providerBundleIdentifier: "com.example.linkcheck.tunnel")
    do {
        let reply = try await tunnel.send(.stats)
        print("reply: \(reply)")
    } catch {
        print("expected outside a VPN session: \(error)")
    }
}

await run()
```

`swift/LinkCheck/ExtensionLinkCheck/main.swift`:

```swift
// The positive half of the link check: an executable that links ShoesTunnel
// with the engine live, so `nm` must find shoes_* here. Without it the host
// assertion could pass against an empty binary.
import ShoesTunnel

let engine = ShoesEngine.shared
print("shoes \(engine.version)")
```

(`ShoesEngine.version` is `public var version: String` at `ShoesEngine.swift:28`.)

- [ ] **Step 2: Add the executable targets**

Append to the `targets:` array in `Package.swift`, after the test targets:

```swift
        // Link-check fixtures, not examples. Not declared as products: a root
        // package's executableTarget gets an automatic executable product,
        // which is what `xcodebuild -scheme HostLinkCheck` resolves, and
        // Xcode's add-package dialog lists library products only. Do not
        // "fix" this by declaring them.
        .executableTarget(
            name: "HostLinkCheck",
            dependencies: ["ShoesTunnelHost"],
            path: "swift/LinkCheck/HostLinkCheck"),
        .executableTarget(
            name: "ExtensionLinkCheck",
            dependencies: ["ShoesTunnel"],
            path: "swift/LinkCheck/ExtensionLinkCheck"),
```

- [ ] **Step 3: Build locally on macOS and the simulator; measure**

```bash
SHOES_LOCAL_XCFRAMEWORK=1 swift build            # macOS: both fixtures compile
swift format lint --strict --recursive swift Package.swift
for s in HostLinkCheck ExtensionLinkCheck; do
  SHOES_LOCAL_XCFRAMEWORK=1 xcodebuild -scheme "$s" -configuration Release \
    -destination 'generic/platform=iOS Simulator' \
    CODE_SIGNING_ALLOWED=NO -derivedDataPath build/linkcheck build | tail -5
done
host=$(find build/linkcheck/Build/Products -type f -perm +111 -name HostLinkCheck | head -1)
ext=$(find build/linkcheck/Build/Products -type f -perm +111 -name ExtensionLinkCheck | head -1)
echo "host: $(nm -U "$host" | grep -c ' T _shoes_')  ext: $(nm -U "$ext" | grep -c ' T _shoes_')"
size -m "$host" | grep __TEXT; size -m "$ext" | grep __TEXT
```
Expected: host count `0`, ext count ≥ 1 (currently 12 symbols). Record both `__TEXT` sizes — they go into the README in Task 4. Note that Xcode does not read `SHOES_LOCAL_XCFRAMEWORK` from the environment for manifest evaluation, so this xcodebuild run resolves the release binary (v0.2.15), which is acceptable locally. If `xcodebuild` produces no executable (find returns nothing), use the fallback from the spec:

```bash
SHOES_LOCAL_XCFRAMEWORK=1 swift build -c release \
  --triple arm64-apple-ios18.0-simulator \
  --sdk "$(xcrun --sdk iphonesimulator --show-sdk-path)" \
  --product HostLinkCheck --product ExtensionLinkCheck
host=.build/arm64-apple-ios18.0-simulator/release/HostLinkCheck
ext=.build/arm64-apple-ios18.0-simulator/release/ExtensionLinkCheck
```
and use the same invocation in the workflow step below.

- [ ] **Step 4: Extend the CI typecheck and add the link check**

In `.github/workflows/mobile.yml`, replace the `Typecheck (iOS)` step (line ~134–138) with:

```yaml
      - name: Typecheck (iOS)
        shell: bash
        env:
          SHOES_LOCAL_XCFRAMEWORK: "1"
        run: |
          xcodebuild -scheme ShoesTunnel     -destination 'generic/platform=iOS' build | tail -20
          xcodebuild -scheme ShoesTunnelHost -destination 'generic/platform=iOS' build | tail -20

      # The property the ShoesTunnelHost product exists for: an app that
      # links it carries no engine. Host is guaranteed by the graph (Host
      # never depends on ShoesFFI), so the count is a guard against that
      # dependency coming back; the extension count > 0 proves the check
      # reads real binaries. __TEXT is printed so the README number can be
      # re-measured from the log.
      - name: Link check (iOS Simulator, Release)
        shell: bash
        env:
          SHOES_LOCAL_XCFRAMEWORK: "1"
        run: |
          set -euo pipefail
          for s in HostLinkCheck ExtensionLinkCheck; do
            xcodebuild -scheme "$s" -configuration Release \
              -destination 'generic/platform=iOS Simulator' \
              CODE_SIGNING_ALLOWED=NO -derivedDataPath build/linkcheck build | tail -5
          done
          host=$(find build/linkcheck/Build/Products -type f -perm +111 -name HostLinkCheck | head -1)
          ext=$(find build/linkcheck/Build/Products -type f -perm +111 -name ExtensionLinkCheck | head -1)
          test -n "$host" && test -n "$ext"
          host_n=$(nm -U "$host" | grep -c ' T _shoes_' || true)
          ext_n=$(nm -U "$ext" | grep -c ' T _shoes_' || true)
          echo "shoes_* in host: $host_n; in extension: $ext_n"
          size -m "$host" | grep __TEXT
          size -m "$ext"  | grep __TEXT
          [ "$host_n" -eq 0 ] || { echo "engine symbols reached the host executable"; exit 1; }
          [ "$ext_n" -gt 0 ] || { echo "no engine symbols in the extension: check is not reading real binaries"; exit 1; }
```

(If Step 3 needed the `swift build --triple` fallback, substitute that invocation and the `.build/...` paths for the `xcodebuild` block and `find` lines.)

- [ ] **Step 5: Verify the workflow parses and the ignore list**

```bash
python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/mobile.yml'))" 2>/dev/null || ruby -ryaml -e 'YAML.load_file(".github/workflows/mobile.yml")'
grep -n "^build/\|^/build" .gitignore || echo "build/ not ignored"
```
`build/` is not in `.gitignore` today, so add a line `build/linkcheck/` to it.

- [ ] **Step 6: Commit**

```bash
git add Package.swift swift/LinkCheck .github/workflows/mobile.yml .gitignore
git commit -m "ci: assert no shoes_* symbol reaches a ShoesTunnelHost executable

Two executable fixtures, one per product, are built for the iOS
Simulator in Release; nm must find no shoes_* in the host and some in
the extension, so the pair proves it looks at real binaries. Host is
guaranteed by the package graph today; the check keeps the ShoesFFI
dependency from creeping back. The iOS typecheck now covers Host too."
```

---

### Task 4: Docs and changelog

**Files:**
- Modify: `swift/README.md:8-14` and the app section; `docs/MACOS.md:12-13`; `CHANGELOG.md:3`

**Interfaces:**
- Consumes: the two `__TEXT` numbers measured in Task 3 Step 3.

- [ ] **Step 1: README — products and imports**

Replace the "Add it" paragraph after the code block with:

```markdown
Two products: the extension target depends on `ShoesTunnel`, the app target
on `ShoesTunnelHost`. They share one `ShoesTunnelCore` target with the wire
types, so the two processes cannot disagree about a message. Linking
`ShoesTunnel` into the app is what the split avoids: it kept all
`shoes_*` symbols in the app executable, `__TEXT` <HOST> with the host product
against <EXT> with the engine in a Release simulator build (numbers from
the link check in `mobile.yml`). Platforms: iOS 18, macOS 15. The package
pulls `Shoes.xcframework.zip` from the matching release; the checksum in
`Package.swift` names that release and is written by the release workflow.

Write `import ShoesTunnel` in the extension and `import ShoesTunnelHost` in
the app; both re-export Core (`@_exported`, deliberately -- it is the one
underscored attribute in the package), so `ShoesConfiguration` and friends
are visible without a second import. `import ShoesTunnelCore` also works but
is not the recommended spelling.
```

Replace `<HOST>` and `<EXT>` with the measured sizes (e.g. `1.2 MB` vs `16.4 MB`). In "## The app", prefix the code block with `import ShoesTunnelHost` as its first line.

- [ ] **Step 2: docs/MACOS.md**

Change `(\`SystemExtensionInstaller\` in the package does this)` to `(\`SystemExtensionInstaller\` in the package's \`ShoesTunnelHost\` product does this)`.

- [ ] **Step 3: CHANGELOG**

Insert after line 2 (`# Changelog`):

```markdown
## Unreleased

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
```

- [ ] **Step 4: Verify and commit**

```bash
grep -n "ShoesTunnelHost" swift/README.md docs/MACOS.md CHANGELOG.md | wc -l   # > 0 in each
grep -n "<HOST>\|<EXT>" swift/README.md                                       # expect none
git add swift/README.md docs/MACOS.md CHANGELOG.md
git commit -m "docs: describe the two ShoesTunnel products

Which target links which, the import spelling, the measured __TEXT cost
that motivated the split, and the changelog entry."
```

---

### Task 5: Final verification

- [ ] **Step 1: Full run, exactly what CI does**

```bash
swift format lint --strict --recursive swift Package.swift
SHOES_LOCAL_XCFRAMEWORK=1 swift build
SHOES_LOCAL_XCFRAMEWORK=1 swift test
swift package reset && unset SHOES_LOCAL_XCFRAMEWORK && swift test --filter ShoesTunnelCoreTests
```
Expected: lint silent; all suites pass; Core tests pass without the framework. Then re-run the Task 3 Step 3 link check once more and confirm `host: 0`, `ext: ≥1`.

- [ ] **Step 2: Report**

State the measured `__TEXT` sizes for both fixtures, the `nm` counts, and the test results verbatim in the completion message. Push and open the PR against `master` from `mobile` only when asked.
