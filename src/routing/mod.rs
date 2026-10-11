//! UDP routing module for per-destination routing.
//!
//! This module provides the `UdpRouter` which handles multi-destination UDP streams
//! (both `AsyncTargetedMessageStream` and `AsyncSessionMessageStream`) by creating
//! per-destination sessions that each route through the appropriate upstream chain
//! based on routing rules.

mod udp_router;

pub use udp_router::{ServerStream, run_udp_routing};
// Their one caller is the `tproxy` inbound, which only Linux compiles.
#[cfg(target_os = "linux")]
pub use udp_router::{RouterLimits, run_udp_routing_with_limits};
