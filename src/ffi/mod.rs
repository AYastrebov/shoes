//! FFI (Foreign Function Interface) for mobile platforms.
//!
//! This module provides C-compatible functions that can be called from
//! Android (via JNI) and iOS (via Swift/ObjC).
//!
//! # Android
//!
//! `android.rs` exports the JNI functions behind `com.shoesproxy.ShoesNative`
//! (`android/src/main/java/com/shoesproxy/ShoesNative.kt`):
//!
//! ```kotlin
//! ShoesNative.init("info")
//! val handle = ShoesNative.start(configYaml, protectCallback, trafficCallback)
//! ShoesNative.stop(handle)
//! ```
//!
//! # iOS and macOS
//!
//! `ios.rs` exports the C functions declared in `include/shoes.h`:
//!
//! ```swift
//! shoes_init("info")
//! let handle = shoes_start(configYaml, protectCallback, trafficCallback)
//! shoes_stop(handle)
//! ```
//!
//! `shoes_start_with_fd` takes the packet tunnel's descriptor and a stopped
//! callback as well.
//!
//! # Thread safety
//!
//! - `init` / `shoes_init` must be called once before any other function.
//! - A start runs the engine on its own threads and returns a handle.
//! - A stop signals shutdown and waits, up to five seconds, for the engine to
//!   release the TUN descriptor. Starts and stops are serialised.

// The whole surface is written against panic = "abort": ExitGuard's Drop
// never runs on a panic (a claim control/mod.rs states outright), the
// callback contract promises a panicking engine cannot report a clean
// stop, and a panic that reaches an extern "C" or "system" entry point aborts
// anyway (Rust 1.81 made those ABIs non-unwinding). Only the
// release-mobile profile sets abort, so an artifact cut with plain
// --release silently got the unwinding behavior: a panicking engine
// delivered on_exit as a reasonless clean stop. Refuse the build
// instead. Debug and test builds unwind by design and are exempt --
// cargo test runs this module's suites under unwinding.
#[cfg(all(not(panic = "abort"), not(test), not(debug_assertions)))]
compile_error!("release FFI builds require panic = \"abort\"; build with --profile release-mobile");

// Common utilities shared between the Apple and Android surfaces
#[cfg(any(target_os = "android", target_os = "ios", target_os = "macos", test))]
mod common;

#[cfg(target_os = "android")]
mod android;

#[cfg(target_os = "android")]
pub use android::*;

// macOS as well as iOS. A Network Extension provider on macOS receives its
// descriptor from packetFlow exactly as on iOS, and the code that consumes it
// -- TunServerConfig::raw_fd, and the macos arm already present in
// src/tun/mod.rs -- is written and shipping. The desktop client's privileged
// host is that provider, and it is Swift, so it wants this C API rather than
// the Rust one in crate::control.
#[cfg(any(target_os = "ios", target_os = "macos"))]
mod ios;

#[cfg(any(target_os = "ios", target_os = "macos"))]
pub use ios::*;

// Re-export for platforms with no packet-tunnel host (stub implementations)
#[cfg(not(any(target_os = "android", target_os = "ios", target_os = "macos")))]
mod stub;

#[cfg(not(any(target_os = "android", target_os = "ios", target_os = "macos")))]
pub use stub::*;
