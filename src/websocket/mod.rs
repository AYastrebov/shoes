// `pub(crate)`: the Clash API's streaming routes reuse the handshake's
// accept-key computation and this module's frame packer rather than taking
// a WebSocket dependency for one-way text frames.
pub(crate) mod websocket_handler;
pub(crate) mod websocket_stream;

pub use websocket_handler::{
    WebsocketServerTarget, WebsocketTcpClientHandler, WebsocketTcpServerHandler,
};
