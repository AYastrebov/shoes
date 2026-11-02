//! AmneziaWG client outbound module.
//!
//! Implements a virtual network tunnel using the AmneziaWG protocol, backed by
//! awgtun, the boringtun fork with AmneziaWG support. Plain WireGuard is
//! the same code path with every obfuscation parameter left at its default.

mod config;
mod connector;
mod endpoint;
mod phobos;
mod tunnel;

pub use config::convert_amnezia_config;
pub use phobos::{convert_phobos_config, frame_overhead as phobos_frame_overhead};
// Used by the mobile FFI, which is compiled only for Android and iOS; nothing
// on a desktop target calls it.
pub use connector::AmneziaWgConnector;
