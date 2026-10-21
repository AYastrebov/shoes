//! shoes - A high-performance multi-protocol proxy server.
//!
//! This library provides the core functionality for shoes, enabling it to be
//! embedded in mobile applications (Android/iOS) as a VPN backend.
//!
//! # Features
//!
//! - **Multi-protocol support**: VLESS, VMess, Trojan, Shadowsocks, and more
//! - **TUN device support**: Virtual network interface for VPN mode
//! - **Proxy chaining**: Connect through multiple proxies
//! - **Flexible routing**: Rule-based traffic routing
//!
//! # Entry points
//!
//! - The `shoes` binary (`src/main.rs`) runs servers from config files.
//! - `shoesd` (`src/bin/shoesd`) is the desktop daemon; it drives [`control`]
//!   over a local socket.
//! - Android calls the JNI functions in `ffi/android.rs` through the
//!   `com.shoesproxy.ShoesNative` object in `android/`:
//!
//! ```kotlin
//! ShoesNative.init("info")
//! val handle = ShoesNative.start(configYaml, protectCallback, trafficCallback)
//! ShoesNative.stop(handle)  // off the main thread: it waits for the engine
//! ```
//!
//! - iOS and macOS call the C functions in `ffi/ios.rs`, whose header is
//!   `include/shoes.h` and whose Swift package is `Package.swift`:
//!
//! ```swift
//! shoes_init("info")
//! let handle = shoes_start(configYaml, protectCallback, trafficCallback)
//! // or shoes_start_with_fd(configYaml, fd, protect, traffic, stopped)
//! shoes_stop(handle)
//! ```
//!
//! # Platform Support
//!
//! - Linux (x86_64, aarch64)
//! - Android (arm64-v8a, armeabi-v7a, x86_64)
//! - iOS (arm64)

// Modules are declared here (mirroring main.rs) so the library crate can
// expose them for FFI/mobile integration.
mod address;
mod amneziawg;
mod anytls;
mod async_stream;
mod buf_reader;
mod buffer_sizing;
mod client_proxy_chain;
mod client_proxy_selector;
pub mod connections;
mod copy_bidirectional;
mod copy_bidirectional_message;
mod crypto;
mod deferred_header_stream;
pub mod dns;
mod fatal;
mod h2mux;
mod http_handler;
mod http_parse;
mod httpupgrade;
pub mod hysteria2;
mod memory;
pub mod mieru;
mod mixed_handler;
mod naiveproxy;
mod option_util;
#[cfg(feature = "control-stats")]
mod outbound_counting_stream;
mod outbound_stats;
mod port_forward_handler;
mod prepend_stream;
pub mod quic_outbound;
mod quic_server;
mod quic_stream;
pub mod quic_transport;
mod reality;
mod reality_client_handler;
mod redirect_handler;
pub mod resolver;
mod routing;
pub mod rule_set;
mod rustls_config_util;
mod rustls_connection_util;
mod shadow_tls;
mod shadowsocks;
mod slide_buffer;
mod snell;
pub mod sniff;
pub mod socket_protector;
mod socket_util;
mod socks5_udp_relay;
mod socks_handler;
#[cfg(target_os = "linux")]
mod splice;
mod stream_reader;
mod sync_adapter;
mod tcp;
mod thread_util;
mod tls_client_handler;
mod tls_server_handler;
mod tproxy;
mod trojan_handler;
pub mod tuic;
mod udp_route_cache;
mod uot;
mod util;
mod uuid_util;
mod vless;
mod vmess;
mod websocket;
mod xudp;

#[cfg(test)]
mod kat;
#[cfg(test)]
mod reference_frames;

/// Configuration types.
pub mod config;

/// Multi-output logging infrastructure.
pub mod logging;

/// Service lifecycle for embedding hosts.
pub mod control;

/// The `shoes` binary's own needs: key generators and the worker count.
pub mod cli;

/// TUN device support for VPN mode.
#[cfg(any(unix, windows))]
pub mod tun;

/// FFI bindings for mobile platforms.
#[cfg(any(target_os = "android", target_os = "ios", feature = "ffi"))]
pub mod ffi;
