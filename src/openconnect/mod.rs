//! OpenConnect client outbound: Cisco AnyConnect's protocol as ocserv and
//! the openconnect client speak it, CSTP over TLS. Design and sources:
//! `docs/specs/2026-10-31-openconnect-client-outbound.md`.

mod auth;
mod connector;
mod cstp;
mod handshake;
mod http;
mod session;
#[cfg(test)]
mod testing;
#[cfg(test)]
mod tests;
mod xml;

pub use connector::OpenConnectConnector;
