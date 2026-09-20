//! The `redirect` inbound: a connection NAT `REDIRECT` delivered, forwarded
//! to where it was going. See docs/specs/2026-09-11-awg-manager-engine.md.
//!
//! It is `PortForwardServerHandler` with the target read from the socket
//! rather than from the config, and nothing else: no handshake, no users,
//! the same rules and sniffing as every other inbound.

use std::sync::Arc;

use async_trait::async_trait;

use crate::address::NetLocation;
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::ClientProxySelector;
use crate::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};

#[derive(Debug)]
pub struct RedirectServerHandler {
    proxy_selector: Arc<ClientProxySelector>,
}

impl RedirectServerHandler {
    pub fn new(proxy_selector: Arc<ClientProxySelector>) -> Self {
        Self { proxy_selector }
    }
}

#[async_trait]
impl TcpServerHandler for RedirectServerHandler {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        // No original destination means nobody redirected this: a client
        // dialled the listener directly. Forwarding it could only go to the
        // listener's own address, which is a loop, and refusing it is also
        // what keeps a listener on a reachable address from being an open
        // proxy: the kernel chooses the destination, never the client.
        let Some(destination) = server_stream.original_destination() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "connection was not redirected (no original destination but this listener); \
                 refusing to forward it",
            ));
        };

        // A link-local address means nothing without its interface, and
        // `NetLocation` has nowhere to carry the scope the kernel reported.
        // Dialled bare it fails with EINVAL or goes out of whichever
        // interface the route table picks; say why instead.
        if let std::net::SocketAddr::V6(v6) = destination
            && v6.ip().is_unicast_link_local()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "redirected connection to link-local {destination} cannot be forwarded: \
                     the interface scope is not carried past this point"
                ),
            ));
        }

        Ok(TcpServerSetupResult::TcpForward {
            remote_location: NetLocation::from(destination),
            stream: server_stream,
            need_initial_flush: true,
            connection_success_response: None,
            initial_remote_data: None,
            proxy_selector: self.proxy_selector.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;
    use crate::async_stream::testing::RedirectedStream;

    fn handler() -> RedirectServerHandler {
        // The handler only carries the selector to the forwarding code.
        RedirectServerHandler::new(Arc::new(ClientProxySelector::new(vec![])))
    }

    #[tokio::test]
    async fn a_redirected_stream_forwards_to_its_original_destination() {
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let stream = Box::new(RedirectedStream::new(Some(target)));
        match handler().setup_server_stream(stream).await.unwrap() {
            TcpServerSetupResult::TcpForward {
                remote_location, ..
            } => assert_eq!(remote_location.to_socket_addr_nonblocking(), Some(target)),
            _ => panic!("a redirect listener only ever forwards TCP"),
        }
    }

    #[tokio::test]
    async fn a_link_local_destination_is_refused_rather_than_dialled_without_its_scope() {
        let target: SocketAddr = "[fe80::1%3]:443".parse().unwrap();
        let stream = Box::new(RedirectedStream::new(Some(target)));
        let err = match handler().setup_server_stream(stream).await {
            Err(e) => e,
            Ok(_) => panic!("the scope would be lost on the way to the dial"),
        };
        assert!(err.to_string().contains("link-local"), "{err}");
    }

    #[tokio::test]
    async fn a_stream_without_an_original_destination_is_refused() {
        let stream = Box::new(RedirectedStream::new(None));
        let err = match handler().setup_server_stream(stream).await {
            Err(e) => e,
            Ok(_) => panic!("a connection that was not redirected must not be forwarded"),
        };
        assert!(err.to_string().contains("not redirected"), "{err}");
    }
}
