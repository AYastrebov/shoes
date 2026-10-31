//! SSTP client outbound: Microsoft's Secure Socket Tunneling Protocol, PPP
//! over HTTPS. Design and sources: `docs/specs/2026-10-30-sstp-client-outbound.md`.

mod connector;
mod crypto;
mod handshake;
mod packet;
mod ppp;
mod session;
#[cfg(test)]
mod testing;
#[cfg(test)]
mod tests;

pub use connector::SstpConnector;
/// Shared with the OpenConnect outbound, whose `tls` block is the same.
pub(crate) use handshake::tls_settings;
