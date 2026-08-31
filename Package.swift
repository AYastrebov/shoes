// swift-tools-version: 6.0

// At the repository root because `.package(url:)` resolves the manifest
// there; the sources are under swift/ so that SwiftPM's default Tests/
// cannot collide with the Rust tests/ on a case-insensitive filesystem.
import Foundation
import PackageDescription

// The binary target resolves two ways. With SHOES_LOCAL_XCFRAMEWORK set --
// `swift build` and `swift test` from a shell, and CI -- it is the framework
// scripts/build-apple.sh just produced. Otherwise it is the zip attached to
// the release named below, which is what an external consumer gets.
//
// Two limits: Xcode does not pass the shell environment to manifest
// evaluation, so opening the package in Xcode gets the remote binary
// regardless; and SwiftPM caches the evaluated manifest, so toggling the
// variable needs `swift package reset`.
//
// The release name and checksum are written by .github/workflows/release-apple.yml,
// which builds the zip, computes the checksum, commits this file and only
// then tags -- so the tag points at a manifest that names its own release.
// A checksum of all zeros means no release has published this manifest yet.
let shoesRelease = "v0.2.17"
let shoesChecksum = "db8d61d5bcf816aa1914f9e1177a016866cd91888f90a17c634c211b743ad76c"

let shoesFFI: Target =
    ProcessInfo.processInfo.environment["SHOES_LOCAL_XCFRAMEWORK"] != nil
    ? .binaryTarget(name: "ShoesFFI", path: "output/apple/Shoes.xcframework")
    : .binaryTarget(
        name: "ShoesFFI",
        url: "https://github.com/AYastrebov/shoes/releases/download/\(shoesRelease)/Shoes.xcframework.zip",
        checksum: shoesChecksum)

let package = Package(
    name: "ShoesTunnel",
    platforms: [.iOS(.v18), .macOS(.v15)],
    products: [
        // The extension links this: the provider base class over the engine.
        .library(name: "ShoesTunnel", targets: ["ShoesTunnel"]),
        // The app links this. It never depends on ShoesFFI, so no shoes_*
        // symbol can reach the app executable -- the link check in
        // mobile.yml holds the package to that.
        .library(name: "ShoesTunnelHost", targets: ["ShoesTunnelHost"]),
    ],
    targets: [
        shoesFFI,
        // The wire format and the types both processes share. Foundation
        // only: it must build where the XCFramework was never downloaded.
        .target(
            name: "ShoesTunnelCore",
            path: "swift/Sources/ShoesTunnelCore"),
        .target(
            name: "ShoesTunnelHost",
            dependencies: ["ShoesTunnelCore"],
            path: "swift/Sources/ShoesTunnelHost",
            linkerSettings: [
                .linkedFramework("NetworkExtension"),
                .linkedFramework("SystemExtensions", .when(platforms: [.macOS])),
            ]),
        .target(
            name: "ShoesTunnel",
            dependencies: ["ShoesTunnelCore", "ShoesFFI"],
            path: "swift/Sources/ShoesTunnel",
            linkerSettings: [
                .linkedFramework("NetworkExtension")
            ]),
        .testTarget(
            name: "ShoesTunnelCoreTests",
            dependencies: ["ShoesTunnelCore"],
            path: "swift/Tests/ShoesTunnelCoreTests"),
        .testTarget(
            name: "ShoesTunnelTests",
            dependencies: ["ShoesTunnel"],
            path: "swift/Tests/ShoesTunnelTests"),
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
    ],
    swiftLanguageModes: [.v6]
)
