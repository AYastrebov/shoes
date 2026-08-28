#!/usr/bin/env bash
#
# Build shoes as an XCFramework for iOS and macOS.
#
# Output: output/apple/Shoes.xcframework
#   slices: ios-arm64, ios-arm64-simulator, macos-arm64
#
# Requirements:
#   - macOS with Xcode installed (xcodebuild)
#   - Rust with rustup (targets added automatically)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="$ROOT_DIR/output/apple"
XCFRAMEWORK_NAME="Shoes"
LIB_NAME="libshoes.a"

cd "$ROOT_DIR"

echo "==> Generating C header via cbindgen"
if command -v cbindgen &>/dev/null; then
    cbindgen --config "$ROOT_DIR/cbindgen.toml" --output "$ROOT_DIR/include/shoes.h"
else
    echo "  cbindgen not found, using existing include/shoes.h"
fi

echo "==> Cleaning output directory"
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR/ios-device" "$OUTPUT_DIR/ios-sim" "$OUTPUT_DIR/macos"

# One floor for the Rust objects and the Swift that wraps them: Package.swift
# declares .iOS(.v18) and .macOS(.v15), and a slice built for an older OS
# than the package that links it is a trap nobody would enjoy debugging.
export IPHONEOS_DEPLOYMENT_TARGET="18.0"
export MACOSX_DEPLOYMENT_TARGET="15.0"

echo "==> Adding Apple Rust targets"
rustup target add \
    aarch64-apple-ios \
    aarch64-apple-ios-sim \
    aarch64-apple-darwin

# release-mobile rather than release, on every slice including macOS, and not
# for size: nothing in src/ffi/ catches unwinds, so panic = "abort" in that
# profile is the only thing keeping a Rust panic from unwinding into Swift.
# See the profile comment in Cargo.toml.
PROFILE_DIR="release-mobile"

# --features control-stats: the counters shoes_get_stats reads. On for the
# published artifact because the resident cost is one atomic, a few hundred
# bytes per configured outbound and 8 bytes per live connection -- 2 KiB at
# the 256-connection mobile ceiling, below one page. MOBILE.md section 10
# carries the measurement. control-logs stays off: it is a Rust-side sink no
# C caller can reach.
FEATURES="control-stats"

echo "==> Building for aarch64-apple-ios (physical device)"
cargo build --profile release-mobile --features "$FEATURES" --target aarch64-apple-ios

echo "==> Building for aarch64-apple-ios-sim (Apple Silicon simulator)"
cargo build --profile release-mobile --features "$FEATURES" --target aarch64-apple-ios-sim

# arm64 only. No Intel Mac support -- a product decision, recorded in
# docs/superpowers/specs/2026-08-28-macos-network-extension-design.md.
#
# --features ffi as well: on iOS the FFI module is compiled by target, on
# macOS only by feature (src/lib.rs), so that the desktop binary and a Rust
# host linking the crate do not carry twelve exported C symbols.
echo "==> Building for aarch64-apple-darwin (macOS)"
cargo build --profile release-mobile --features "ffi,$FEATURES" --target aarch64-apple-darwin

echo "==> Copying libraries"
cp "target/aarch64-apple-ios/$PROFILE_DIR/$LIB_NAME"     "$OUTPUT_DIR/ios-device/$LIB_NAME"
cp "target/aarch64-apple-ios-sim/$PROFILE_DIR/$LIB_NAME" "$OUTPUT_DIR/ios-sim/$LIB_NAME"
cp "target/aarch64-apple-darwin/$PROFILE_DIR/$LIB_NAME"  "$OUTPUT_DIR/macos/$LIB_NAME"

# cargo's `strip = true` (release profile) applies to linked binaries, not to a
# staticlib, so the .a keeps every object file's debug and local symbols and
# ends up very large (~180MB). -S drops debug symbols and -x drops local
# (non-global) symbols; the global symbols the linker needs to resolve the FFI
# surface are preserved, so the framework still links. ranlib rebuilds the
# archive's symbol table afterwards.
echo "==> Stripping symbols from the static libraries"
for lib in "$OUTPUT_DIR/ios-device/$LIB_NAME" "$OUTPUT_DIR/ios-sim/$LIB_NAME" "$OUTPUT_DIR/macos/$LIB_NAME"; do
    before=$(du -h "$lib" | cut -f1)
    strip -S -x "$lib"
    ranlib "$lib" >/dev/null 2>&1 || true
    echo "  $(basename "$(dirname "$lib")")/$LIB_NAME: $before -> $(du -h "$lib" | cut -f1)"
done

# -headers include/ carries shoes.h and module.modulemap into every slice.
echo "==> Packaging as XCFramework"
xcodebuild -create-xcframework \
    -library "$OUTPUT_DIR/ios-device/$LIB_NAME" \
    -headers "$ROOT_DIR/include" \
    -library "$OUTPUT_DIR/ios-sim/$LIB_NAME" \
    -headers "$ROOT_DIR/include" \
    -library "$OUTPUT_DIR/macos/$LIB_NAME" \
    -headers "$ROOT_DIR/include" \
    -output "$OUTPUT_DIR/$XCFRAMEWORK_NAME.xcframework"

echo ""
echo "Done: $OUTPUT_DIR/$XCFRAMEWORK_NAME.xcframework"
echo ""
echo "Integration: add this repository as a Swift package and depend on the"
echo "ShoesTunnel product; see swift/README.md. To link the C surface directly"
echo "instead, drag the XCFramework into Xcode and \`import ShoesFFI\`."
