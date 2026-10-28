# ShoesTunnel (Swift package)

The Swift that drives shoes inside an Apple packet tunnel provider. Three
targets: `ShoesTunnel` (the extension), `ShoesTunnelHost` (the app), and
`ShoesTunnelCore` (the wire types both share). `README.md` here is the
consumer's guide; `MOBILE.md` at the root holds the contract the C surface
promises; `docs/MACOS.md` the system-extension specifics.

## Commands

Swift 6 or later. The package pulls `Shoes.xcframework.zip` from the release
`Package.swift` names; to build against the working tree:

```bash
bash scripts/build-apple.sh                      # Shoes.xcframework from this tree
SHOES_LOCAL_XCFRAMEWORK=1 swift build
SHOES_LOCAL_XCFRAMEWORK=1 swift test
swift format lint --strict --recursive swift Package.swift
```

`.github/workflows/mobile.yml`, run by hand, also builds both schemes for
`generic/platform=iOS` and runs the link check under `swift/LinkCheck`, which
proves the app product does not pull the engine's symbols. No pull request or
push runs it: the framework is built only for a release, so run the workflow
(Actions -> Run workflow, no `release_tag`) before a release that changed
anything here, and say in the PR that you did.

## Rules

- `ShoesTunnel` is linked by the extension only; `ShoesTunnelHost` by the
  app only. Linking the engine into the app is what the split exists to
  prevent (7.1 MB of `__TEXT` against 80 KB). The link check fails the PR
  that does it.
- The one underscored attribute in the package is the `@_exported import` of
  Core from both products. Do not add another.
- `ShoesEngine` carries the C surface's ordering rules as its API: `stop()`
  is `async` with no synchronous variant; `start(_:deviceFD:)` borrows the
  descriptor and never closes it. A change to those rules starts in
  `src/ffi/` and `MOBILE.md`, not here.
- `Package.swift`'s release and checksum are written by the `Release Apple`
  workflow. Never hand-edit them and never hand-push a `v*` tag: the
  tag-triggered job checks the manifest against the tag and fails.
