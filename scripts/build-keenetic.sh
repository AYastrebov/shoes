#!/usr/bin/env bash
# Build shoes for Keenetic routers (Entware): aarch64-3.10 and mipsel-3.4.
#
# Cross-compiles in cross-rs containers (podman or docker). The mipsel target
# is tier 3 in Rust -- no prebuilt std -- so it needs a nightly toolchain with
# rust-src and is built with `build-std`; see Cross.toml and .cargo/config.toml
# for the rest of what that target needs, and docs/keenetic-build-2026-09-11.md
# for why each of those is there and what the binaries measured.
#
# Prerequisites:
#   cargo install cross --locked
#   rustup target add aarch64-unknown-linux-musl
#   rustup toolchain install nightly --profile minimal --component rust-src
#
# Usage: scripts/build-keenetic.sh [profile] [features]
#   profile   release (default) or release-mobile (opt-level s, panic abort)
#   features  default: clash-api
#
# Output: dist/keenetic/shoes-<profile>-<entware arch>
set -euo pipefail
cd "$(dirname "$0")/.."

profile=${1:-release}
features=${2:-clash-api}
export CROSS_CONTAINER_ENGINE=${CROSS_CONTAINER_ENGINE:-$(command -v podman >/dev/null && echo podman || echo docker)}
mkdir -p dist/keenetic

build() {
    local triple=$1 arch=$2 toolchain=$3 extra=$4
    echo "==> $arch ($triple, $profile, features: $features$extra)"
    # The nightly MIPS backend crashes now and then (a transient SIGSEGV in
    # LLVM's scheduler); a resumed build keeps everything that compiled.
    local attempt
    for attempt in 1 2 3; do
        if cross $toolchain build --profile "$profile" --target "$triple" \
            --features "$features$extra"; then
            break
        fi
        [ "$attempt" -lt 3 ] || { echo "$arch: build failed"; exit 1; }
        echo "==> $arch: retrying ($attempt)"
    done
    cp "target/$triple/$profile/shoes" "dist/keenetic/shoes-$profile-$arch"
}

build aarch64-unknown-linux-musl aarch64-3.10 "" ""

# aws-lc-sys has no prebuilt bindings for MIPS (hence bindgen), and its
# prefixed bindings hit an LLVM MIPS bug (see Cross.toml), hence no prefix.
AWS_LC_SYS_NO_PREFIX=1 build mipsel-unknown-linux-musl mipsel-3.4 +nightly ",aws-lc-rs/bindgen"

ls -l dist/keenetic/
