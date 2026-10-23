//! A REALITY client and server over real TCP, built from config the way the
//! binary builds them, with a real TLS 1.3 server as the decoy the server
//! hands a refused client to.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::address::NetLocation;
use crate::config::{ClientProxyConfig, ServerProxyConfig};
use crate::quic_outbound::testing::direct_selector;
use crate::resolver::Resolver;
use crate::tcp::tcp_client_handler_factory::{HopContext, create_tcp_client_handler};
use crate::tcp::tcp_handler::{
    TcpClientHandler, TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult,
};
use crate::tcp::tcp_server_handler_factory::create_tcp_server_handler;

/// Long enough that only a hang trips it, on the slowest CI runner.
const HANG: Duration = Duration::from_secs(30);

const USER_ID: &str = "b0e80a62-8a51-47f0-91f1-f0f7faf8d9d4";
const SHORT_ID: &str = "0123456789abcdef";
const SNI: &str = "decoy.test";

/// Resolves every name to loopback: the REALITY server needs its decoy
/// under a hostname, which it puts in the certificate it signs.
#[derive(Debug)]
struct Loopback;

impl Resolver for Loopback {
    fn resolve_location(
        &self,
        location: &NetLocation,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<Vec<SocketAddr>>> + Send>>
    {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), location.port());
        Box::pin(async move { Ok(vec![addr]) })
    }
}

/// A TLS 1.3 server on a free loopback port. It answers one connection's
/// handshake and then holds the connection until the peer closes it.
async fn spawn_decoy() -> u16 {
    let certified = rcgen::generate_simple_self_signed(vec![SNI.to_string()]).unwrap();
    let config = Arc::new(crate::rustls_config_util::create_server_config(
        certified.cert.pem().as_bytes(),
        certified.signing_key.serialize_pem().as_bytes(),
        vec![],
        &[],
        &[],
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        if let Ok(mut tls) = tokio_rustls::TlsAcceptor::from(config).accept(tcp).await {
            let mut sink = Vec::new();
            let _ = tls.read_to_end(&mut sink).await;
        }
    });
    addr.port()
}

/// A `key: [major, minor, patch]` line, or nothing when the version is unset.
fn version_line(indent: &str, key: &str, version: Option<[u8; 3]>) -> String {
    version
        .map(|version| format!("{indent}{key}: {version:?}\n"))
        .unwrap_or_default()
}

/// The server and the client the binary would build from these settings:
/// the server accepts versions from `min` to `max`, either optional, and
/// the client reports `client_version`, or the default when `None`.
fn handlers(
    decoy_port: u16,
    min: Option<[u8; 3]>,
    max: Option<[u8; 3]>,
    client_version: Option<[u8; 3]>,
) -> (Box<dyn TcpServerHandler>, Box<dyn TcpClientHandler>) {
    let resolver: Arc<dyn Resolver> = Arc::new(Loopback);
    let (private_key, public_key) = crate::reality::generate_keypair().unwrap();

    let server_yaml = format!(
        "type: tls\nreality_targets:\n    {SNI}:\n        private_key: {private_key}\n        short_ids: [\"{SHORT_ID}\"]\n        dest: \"{SNI}:{decoy_port}\"\n{}{}        protocol:\n            type: vless\n            user_id: {USER_ID}\n",
        version_line("        ", "min_client_version", min),
        version_line("        ", "max_client_version", max),
    );
    let server_config: ServerProxyConfig = serde_yaml::from_str(&server_yaml).unwrap();

    let client_yaml = format!(
        "type: reality\npublic_key: {public_key}\nshort_id: \"{SHORT_ID}\"\nsni_hostname: {SNI}\n{}protocol:\n    type: vless\n    user_id: {USER_ID}\n",
        version_line("", "client_version", client_version),
    );
    let client_config: ClientProxyConfig = serde_yaml::from_str(&client_yaml).unwrap();

    let selector = direct_selector(resolver.clone());
    let server = create_tcp_server_handler(server_config, &selector, &resolver, None);
    let proxy = NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
    let client = create_tcp_client_handler(client_config, None, &HopContext::new(&proxy), resolver);
    (server, client)
}

async fn tcp_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (connected, accepted) =
        tokio::join!(tokio::net::TcpStream::connect(addr), listener.accept());
    (connected.unwrap(), accepted.unwrap().0)
}

fn target() -> NetLocation {
    NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)), 443)
}

/// One connection from the client through the server, built as `handlers`
/// says: what each side's setup returned.
async fn connect(
    min: Option<[u8; 3]>,
    max: Option<[u8; 3]>,
    client_version: Option<[u8; 3]>,
) -> (
    io::Result<TcpClientSetupResult>,
    io::Result<TcpServerSetupResult>,
) {
    let decoy_port = spawn_decoy().await;
    let (server, client) = handlers(decoy_port, min, max, client_version);
    let (client_end, server_end) = tcp_pair().await;
    let server_side =
        tokio::spawn(async move { server.setup_server_stream(Box::new(server_end)).await });
    let client_side = tokio::time::timeout(
        HANG,
        client.setup_client_tcp_stream(Box::new(client_end), target().into()),
    )
    .await
    .expect("the client setup returned");
    let server_side = tokio::time::timeout(HANG, server_side)
        .await
        .expect("the server setup returned")
        .unwrap();
    (client_side, server_side)
}

/// The connection carries data both ways once both sides are set up.
async fn assert_connected(
    client_side: io::Result<TcpClientSetupResult>,
    server_side: io::Result<TcpServerSetupResult>,
) {
    let (client_side, server_side) = match (client_side, server_side) {
        (Ok(client_side), Ok(server_side)) => (client_side, server_side),
        (client_side, server_side) => panic!(
            "client: {:?}; server: {:?}",
            client_side.err(),
            server_side.err()
        ),
    };
    let mut client_stream = client_side.client_stream;
    let TcpServerSetupResult::TcpForward {
        remote_location,
        stream: mut server_stream,
        initial_remote_data,
        connection_success_response,
        ..
    } = server_side
    else {
        panic!("not a TCP forward");
    };
    assert_eq!(remote_location, target());
    assert!(initial_remote_data.is_none(), "nothing was sent yet");

    client_stream.write_all(b"ping").await.unwrap();
    client_stream.flush().await.unwrap();
    let mut buf = [0u8; 4];
    server_stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");

    // What the server loop writes once the remote is connected.
    if let Some(response) = connection_success_response {
        server_stream.write_all(&response).await.unwrap();
    }
    server_stream.write_all(b"pong").await.unwrap();
    server_stream.flush().await.unwrap();
    client_stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"pong");
}

/// Xray-core v26.7.28, the release Amnezia installs, refuses clients below
/// 26.3.27 unless its config says otherwise. The default version passes it.
#[tokio::test]
async fn the_default_version_passes_xrays_floor() {
    let (client_side, server_side) = connect(Some([26, 3, 27]), None, None).await;
    assert_connected(client_side, server_side).await;
}

/// A server that accepts one version only sees the configured one.
#[tokio::test]
async fn a_configured_version_is_what_the_server_checks() {
    let (client_side, server_side) =
        connect(Some([26, 9, 8]), Some([26, 9, 8]), Some([26, 9, 8])).await;
    assert_connected(client_side, server_side).await;
}

#[tokio::test]
async fn a_client_above_the_minimum_connects() {
    let (client_side, server_side) = connect(Some([26, 3, 27]), None, Some([26, 9, 8])).await;
    assert_connected(client_side, server_side).await;
}

/// The failure this fixes, reproduced: a client below the minimum is handed
/// to the decoy, whose certificate carries no REALITY signature, so the
/// client refuses the certificate rather than finishing a handshake.
#[tokio::test]
async fn a_client_below_the_minimum_is_sent_to_the_decoy() {
    let (client_side, server_side) = connect(Some([26, 3, 27]), None, Some([1, 8, 0])).await;

    let server_err = server_side.map(|_| ()).unwrap_err();
    assert_eq!(server_err.kind(), io::ErrorKind::PermissionDenied);
    let server_err = server_err.to_string();
    assert!(server_err.contains("below minimum"), "{server_err}");
    assert!(server_err.contains("forwarding to dest"), "{server_err}");

    // The decoy's key is not the Ed25519 key a REALITY server signs with.
    let client_err = client_side.map(|_| ()).unwrap_err();
    assert_eq!(client_err.kind(), io::ErrorKind::InvalidData);
    assert!(client_err.to_string().contains("Ed25519"), "{client_err}");
}
