# ShoesTunnel

The Swift that drives shoes inside an Apple packet tunnel provider, for iOS
and macOS, from the repository that owns the C API it wraps.

## Add it

```swift
.package(url: "https://github.com/AYastrebov/shoes.git", from: "0.2.15")
```

and depend on the `ShoesTunnel` product from both the app target and the
extension target. Platforms: iOS 18, macOS 15. The package pulls
`Shoes.xcframework.zip` from the matching release; the checksum in
`Package.swift` names that release and is written by the release workflow.

To develop against an unreleased shoes: `bash scripts/build-apple.sh`, then
`SHOES_LOCAL_XCFRAMEWORK=1 swift build`. Xcode does not see that variable --
opening the package there uses the release binary.

## The extension

Subclass `ShoesPacketTunnelProvider` and supply what is yours:

```swift
import ShoesTunnel

final class Provider: ShoesPacketTunnelProvider {
    override func loadConfiguration() throws -> ShoesConfiguration {
        // However your app hands the config over -- an App Group file, for
        // instance. The YAML is passed through verbatim; write
        // `device_fd: 0` or omit the field, the descriptor is supplied by
        // the provider.
        ShoesConfiguration(yaml: try String(contentsOf: configURL, encoding: .utf8))
    }

    override func makeNetworkSettings() -> NEPacketTunnelNetworkSettings {
        // Addresses, routes, DNS, MTU: your policy.
    }

    override func report(error: ShoesError) { /* surface it to the app */ }
    override func report(upload: UInt64, download: UInt64) { /* stats */ }
}
```

Everything else is inherited: the start timeout, `shoes_stop` awaited before
`stopTunnel` completes, a health check, path observation with the engine asked
first and a full rebind only when it did not recover in place, and typed app
messages. The class is `@MainActor`; all four hooks run there.

## The app

```swift
let tunnel = ShoesTunnelManager(providerBundleIdentifier: "com.example.app.tunnel")
try await tunnel.start { proto in
    proto.serverAddress = "shoes"
    proto.includeAllNetworks = true
    proto.excludeLocalNetworks = true
}
for await status in tunnel.statusUpdates { /* update the UI */ }
let reply = try await tunnel.send(.stats)
```

On macOS `start` activates the system extension first. See
[docs/MACOS.md](../docs/MACOS.md) for what that needs.

## Below the package

`ShoesEngine` is the C surface with the ordering rules as properties: `stop()`
is `async` and there is no synchronous variant; `start(_:deviceFD:)` borrows
the descriptor and never closes it. `import ShoesFFI` directly if you need
the raw functions -- the module map in the framework makes that work without
a bridging header.
