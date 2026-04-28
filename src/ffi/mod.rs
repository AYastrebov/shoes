//! FFI (Foreign Function Interface) for mobile platforms.
//!
//! This module provides C-compatible functions that can be called from
//! Android (via JNI) and iOS (via Swift/ObjC).
//!
//! # Android Usage
//!
//! ```kotlin
//! // Load native library
//! System.loadLibrary("shoes")
//!
//! // Declare native methods
//! external fun shoesInit(logLevel: String): Int
//! external fun shoesStartTun(
//!     fd: Int,
//!     configYaml: String,
//!     protectCallback: (Int) -> Boolean
//! ): Long
//! external fun shoesStop(handle: Long)
//! ```
//!
//! # iOS Usage
//!
//! ```swift
//! // Initialize
//! shoes_init("info")
//!
//! // Start VPN
//! let handle = shoes_start(configYaml, protectCallback)
//!
//! // Stop VPN
//! shoes_stop(handle)
//! ```
//!
//! # Thread Safety
//!
//! - `shoes_init` must be called once before any other function
//! - `shoes_start` / `shoes_start_tun` starts a background thread for the TUN service
//! - `shoes_stop` signals shutdown and waits for cleanup

// Common utilities shared between all FFI targets
#[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
mod common;

#[cfg(target_os = "android")]
mod android;

#[cfg(target_os = "android")]
pub use android::*;

// iOS and macOS share the same C FFI (same Unix platform, same API surface)
#[cfg(any(target_os = "ios", target_os = "macos"))]
mod ios;

#[cfg(any(target_os = "ios", target_os = "macos"))]
pub use ios::*;

// Stub for platforms without FFI support
#[cfg(not(any(target_os = "android", target_os = "ios", target_os = "macos")))]
mod stub;

#[cfg(not(any(target_os = "android", target_os = "ios", target_os = "macos")))]
pub use stub::*;
