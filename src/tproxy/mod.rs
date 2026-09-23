//! Transparent proxying on Linux: inbounds with no protocol of their own,
//! where the kernel delivered the connection and the only question is where
//! it was going. See docs/specs/2026-09-11-awg-manager-engine.md.
//!
//! Only the socket calls live here so far. The `redirect` inbound built on
//! them is `src/redirect_handler.rs`; the `tproxy` UDP inbound lands here.

pub mod sys;
