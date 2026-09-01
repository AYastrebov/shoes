# macOS integration notes

What is specific to running shoes inside a macOS Network Extension. The
integration itself -- the Swift package, its API, how a provider and a host
use it -- is in [swift/README.md](../swift/README.md); the mobile notes in
[MOBILE.md](../MOBILE.md) cover the FFI contract that macOS shares with iOS.

## System extension, not app extension

A packet tunnel provider distributed outside the Mac App Store ships as a
`.systemextension` under `Contents/Library/SystemExtensions`, activated at
runtime with `OSSystemExtensionRequest` (`SystemExtensionInstaller` in the
package's `ShoesTunnelHost` product does this) and approved once by the user in System Settings. An
`.appex` under `Contents/PlugIns` is the Mac App Store shape, and App Store
Review Guideline 5.4 requires an organization account to publish a VPN app
there. This project ships under Developer ID: signed, notarized, stapled, as
a DMG.

The provider class is identical either way. Only the Xcode target type and
the activation step differ.

## Requirements the code cannot check

- **The entitlement.** `com.apple.developer.networking.networkextension` with
  `packet-tunnel-provider-systemextension`, in a provisioning profile for the
  extension. Granted by request to Apple, not self-serve. This is the long
  pole: nothing below runs without it, and a free Personal Team cannot use it
  at all.
- **Location.** A system extension activates only from an app running in
  `/Applications`, unless `systemextensionsctl developer on` is set -- which
  relaxes that and notarization, and not the entitlement.
- **Team.** The app and the extension are signed with the same team ID, and
  the extension's bundle identifier is prefixed by the app's.

## What the extension gets and what it must do

The descriptor comes from `packetFlow`'s `socket.fileDescriptor`, as on iOS,
and carries the 4-byte utun protocol header; the `tun` crate defaults
`packet_information` to true on macOS, so nothing configures that. shoes
borrows the descriptor and never closes it. The provider must not let the
system release it before `shoes_stop` returns; `ShoesPacketTunnelProvider`
awaits `ShoesEngine.stop()` inside `stopTunnel` for exactly that reason.

Routes and DNS are `NEPacketTunnelNetworkSettings`, applied by the provider.
shoes reads packets and configures nothing on the host.

## What has not been verified

The tunnel has not run on macOS. Everything above compiles and is tested up
to the C boundary; activating an extension needs the entitlement. Two
behaviours are expected from iOS and not yet shown here: that the system
keeps the extension's own sockets out of its tunnel (the protect callback is
a no-op on that assumption), and the memory budget a macOS system extension
gets, which is not iOS's 50 MB.

Because that budget is unverified, the macOS slice takes iOS's per-connection
buffer sizes rather than desktop's: `scripts/build-apple.sh` builds it with the
`network-extension` feature, which `src/buffer_sizing.rs` reads. That is the
conservative reading, not a measured one — a 256 KiB receive window caps
download near 50 Mbit/s where 4 MiB reaches 150. Once the extension runs and
its real limit is known, this is the knob to revisit.

## A Rust host instead

`shoes::control` (`src/control/mod.rs`) is the same lifecycle without the C
boundary, for a host written in Rust. Its `ServiceHandle` owns a tokio
runtime and must be stopped from a blocking context, never dropped inside
another runtime -- the type's documentation says why. A Network Extension is
Swift and wants the C API; this is for a helper daemon, which is desktop
sub-project #4 in [ROADMAP.md](../ROADMAP.md).
