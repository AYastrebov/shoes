//! Every handler that wraps another passes the reuse question inward. A
//! wrapper that kept the default answered `None` for a live NaiveProxy
//! session behind it, so the chain dialled and the session was replaced on
//! every connection.

use std::sync::Arc;

use async_trait::async_trait;

use crate::address::{NetLocation, ResolvedLocation};
use crate::async_stream::AsyncStream;
use crate::tcp::tcp_handler::{TcpClientHandler, TcpClientSetupResult};

/// An inner handler that always holds a session; its answer is marked so the
/// test can tell it came through.
#[derive(Debug)]
struct SessionHolder;

const MARK: &str = "answered by the inner session";

#[async_trait]
impl TcpClientHandler for SessionHolder {
    async fn try_reuse_tcp_stream(
        &self,
        _remote_location: &ResolvedLocation,
    ) -> Option<std::io::Result<TcpClientSetupResult>> {
        Some(Err(std::io::Error::other(MARK)))
    }

    async fn setup_client_tcp_stream(
        &self,
        _client_stream: Box<dyn AsyncStream>,
        _remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        unreachable!("the wrapper must not be set up when the inner session answers")
    }
}

fn inner() -> Box<dyn TcpClientHandler> {
    Box::new(SessionHolder)
}

fn server_name() -> rustls::pki_types::ServerName<'static> {
    rustls::pki_types::ServerName::try_from("example.com").unwrap()
}

fn client_config() -> Arc<rustls::ClientConfig> {
    Arc::new(crate::rustls_config_util::create_client_config(
        false,
        &[],
        &[],
        true,
        None,
        false,
    ))
}

async fn forwards(name: &str, wrapper: &dyn TcpClientHandler) {
    let target: ResolvedLocation = NetLocation::from_ip_addr(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)),
        443,
    )
    .into();
    match wrapper.try_reuse_tcp_stream(&target).await {
        Some(Err(e)) if e.to_string() == MARK => {}
        Some(Ok(_)) => panic!("{name}: an answer that did not come from the inner session"),
        Some(Err(e)) => panic!("{name}: {e}"),
        None => panic!("{name} did not forward the reuse question"),
    }
}

#[tokio::test]
async fn every_wrapper_forwards_the_reuse_question() {
    forwards(
        "tls",
        &crate::tls_client_handler::TlsClientHandler::new(
            client_config(),
            None,
            server_name(),
            inner(),
        ),
    )
    .await;
    forwards(
        "reality",
        &crate::reality_client_handler::RealityClientHandler::new(
            [7u8; 32],
            [0u8; 8],
            "example.com".to_string(),
            Vec::new(),
            None,
            inner(),
        ),
    )
    .await;
    forwards(
        "websocket",
        &crate::websocket::WebsocketTcpClientHandler::new(
            "example.com:443".to_string(),
            None,
            None,
            crate::config::WebsocketPingType::Disabled,
            None,
            inner(),
        ),
    )
    .await;
    forwards(
        "httpupgrade",
        &crate::httpupgrade::HttpUpgradeTcpClientHandler::new(
            "example.com".to_string(),
            None,
            None,
            inner(),
        ),
    )
    .await;
    forwards(
        "shadowtls",
        &crate::shadow_tls::ShadowTlsClientHandler::new(
            "password".to_string(),
            client_config(),
            server_name(),
            inner(),
        ),
    )
    .await;
}
