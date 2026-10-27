// XUDP (Extended UDP) protocol implementation
// Protocol-agnostic UDP multiplexing over TCP connections
// Used by both VLESS and VMess protocols

pub mod client_stream;
pub mod frame;
pub mod message_stream;

pub use client_stream::XudpClientStream;
pub use message_stream::XudpMessageStream;
