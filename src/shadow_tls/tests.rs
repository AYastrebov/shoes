//! A ShadowTLS v3 client, the ShadowTLS server in remote-handshake mode, and a
//! real TLS 1.3 server as the decoy, all in one process.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::shadow_tls_client_handler::{ShadowTlsClientHandler, modify_client_hello};
use super::shadow_tls_hmac::{ShadowTlsHmac, ShadowTlsXorContext};
use super::shadow_tls_server_handler::{
    read_client_hello, setup_remote_handshake, validate_shadowtls_client_hello,
};
use crate::address::{NetLocation, ResolvedLocation};
use crate::async_stream::AsyncStream;
use crate::config::{ClientChainHop, ClientConfig, ConfigSelection};
use crate::option_util::OneOrSome;
use crate::port_forward_handler::PortForwardClientHandler;
use crate::resolver::{NativeResolver, Resolver};
use crate::tcp::tcp_handler::TcpClientHandler;

const PASSWORD: &str = "shadow-tls-test-password";
const DECOY: &str = "decoy.test";

fn initial_hmac(password: &str) -> ShadowTlsHmac {
    let key = aws_lc_rs::hmac::Key::new(
        aws_lc_rs::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        password.as_bytes(),
    );
    ShadowTlsHmac::new(&key)
}

fn client(password: &str) -> ShadowTlsClientHandler {
    // The production configuration: TLS 1.3 only, no certificate checks.
    let config = Arc::new(crate::rustls_config_util::create_client_config(
        false,
        &[],
        &[],
        true,
        None,
        true,
    ));
    ShadowTlsClientHandler::new(
        password.to_string(),
        config,
        rustls::pki_types::ServerName::try_from(DECOY).unwrap(),
        Box::new(PortForwardClientHandler),
    )
}

/// A TLS 1.3 server on a free port. The receiver reports whether its
/// handshake completed, which a rustls server only says once it has read and
/// verified the client's Finished. The connection is then held open until the
/// peer closes it.
async fn spawn_decoy() -> (NetLocation, tokio::sync::oneshot::Receiver<bool>) {
    let certified = rcgen::generate_simple_self_signed(vec![DECOY.to_string()]).unwrap();
    let config = Arc::new(crate::rustls_config_util::create_server_config(
        certified.cert.pem().as_bytes(),
        certified.signing_key.serialize_pem().as_bytes(),
        vec![],
        &[],
        &[],
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        match tokio_rustls::TlsAcceptor::from(config).accept(tcp).await {
            Ok(mut tls) => {
                let _ = done_tx.send(true);
                let mut sink = Vec::new();
                let _ = tls.read_to_end(&mut sink).await;
            }
            Err(_) => {
                let _ = done_tx.send(false);
            }
        }
    });
    (
        NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port()),
        done_rx,
    )
}

/// Two ends of a loopback TCP connection.
async fn tcp_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (connected, accepted) =
        tokio::join!(tokio::net::TcpStream::connect(addr), listener.accept());
    (connected.unwrap(), accepted.unwrap().0)
}

fn target() -> ResolvedLocation {
    NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::LOCALHOST), 9).into()
}

/// Client, server and decoy end to end: the client's ClientHello passes the
/// server's check, the decoy's handshake reaches the client tagged, and
/// authenticated data flows both ways.
#[tokio::test]
async fn data_flows_both_ways_after_the_handshake() {
    run_through_a_decoy().await;
}

/// ST-S1, deferred: the reference client completes the decoy's handshake, so
/// the decoy receives a Finished. This one cannot yet. The tag it writes into
/// the ClientHello's session id is not in the transcript stock rustls hashes,
/// so the two sides derive different handshake keys and the decoy's records
/// cannot be decrypted -- the reference uses a rustls fork for exactly this.
/// The fix is a TLS 1.3 client that owns its ClientHello, built on the
/// Reality module's primitives; see the audit entry.
#[tokio::test]
#[ignore = "ST-S1: needs a TLS 1.3 client that owns its ClientHello"]
async fn the_decoy_receives_the_clients_finished() {
    let decoy_done = run_through_a_decoy().await;
    assert!(
        decoy_done.await.unwrap(),
        "the decoy completed its handshake: it received and verified the client's Finished"
    );
}

/// Run one connection through the server to a decoy and exchange data;
/// return the decoy's report of whether its handshake completed.
async fn run_through_a_decoy() -> tokio::sync::oneshot::Receiver<bool> {
    let (decoy, decoy_done) = spawn_decoy().await;
    let (client_end, server_end) = tcp_pair().await;

    let server = tokio::spawn(async move {
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let chain = crate::tcp::chain_builder::build_client_proxy_chain(
            OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(
                ClientConfig::default(),
            ))),
            resolver.clone(),
        );
        let hmac = initial_hmac(PASSWORD);
        let mut stream: Box<dyn AsyncStream> = Box::new(server_end);
        let hello = read_client_hello(&mut stream).await.unwrap();
        validate_shadowtls_client_hello(&hello, &hmac).unwrap();
        setup_remote_handshake(
            stream,
            hello.client_reader,
            hello.client_hello_frame,
            &hmac,
            &ShadowTlsXorContext::new(PASSWORD.as_bytes()),
            decoy,
            &chain,
            &resolver,
        )
        .await
    });

    let mut client_stream = client(PASSWORD)
        .setup_client_tcp_stream(Box::new(client_end), target())
        .await
        .expect("the client handshake")
        .client_stream;

    client_stream.write_all(b"ping").await.unwrap();
    client_stream.flush().await.unwrap();
    let mut server_stream = server.await.unwrap().expect("the server handshake");
    let mut buf = [0u8; 4];
    server_stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");

    server_stream.write_all(b"pong").await.unwrap();
    server_stream.flush().await.unwrap();
    client_stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"pong");
    decoy_done
}

/// Reaching the decoy itself -- no ShadowTLS server in between, or one with
/// another password -- yields encrypted records with no valid tag. The
/// client refuses rather than handing the decoy's bytes up as data.
#[tokio::test]
async fn a_server_that_does_not_tag_its_records_is_refused() {
    let (decoy, _decoy_done) = spawn_decoy().await;
    let tcp = tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, decoy.port()))
        .await
        .unwrap();
    let err = client(PASSWORD)
        .setup_client_tcp_stream(Box::new(tcp), target())
        .await
        .map(|_| ())
        .unwrap_err();
    assert!(err.to_string().contains("invalid HMAC"), "got: {err}");
}

/// The tag the client writes into the session id is the one the server
/// checks, and only under the same password.
#[tokio::test]
async fn the_client_hello_tag_verifies_under_its_password_only() {
    let config = Arc::new(crate::rustls_config_util::create_client_config(
        false,
        &[],
        &[],
        true,
        None,
        true,
    ));
    let mut conn = rustls::ClientConnection::new(
        config,
        rustls::pki_types::ServerName::try_from(DECOY).unwrap(),
    )
    .unwrap();
    let mut hello = Vec::new();
    conn.write_tls(&mut std::io::Cursor::new(&mut hello))
        .unwrap();
    let modified = modify_client_hello(&hello, &initial_hmac(PASSWORD)).unwrap();

    for (password, valid) in [(PASSWORD, true), ("another-password", false)] {
        let (mut ours, theirs) = tcp_pair().await;
        ours.write_all(&modified).await.unwrap();
        let mut stream: Box<dyn AsyncStream> = Box::new(theirs);
        let parsed = read_client_hello(&mut stream).await.unwrap();
        assert_eq!(
            validate_shadowtls_client_hello(&parsed, &initial_hmac(password)).is_ok(),
            valid,
            "password {password:?}"
        );
    }
}
