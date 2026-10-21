//! Client first flights captured from the reference implementations
//! (`tests/data/kat/frames-*`), replayed into shoes' own server handlers. A
//! shoes-to-shoes round trip passes when both halves share a misreading;
//! these pass only if shoes reads what the reference actually sends.

use std::pin::Pin;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};

use crate::address::NetLocation;
use crate::async_stream::AsyncStream;
use crate::async_stream::testing::TestStream;
use crate::config::{RuleConfig, ServerProxyConfig};
use crate::kat::{hex, text, vectors};
use crate::resolver::{NativeResolver, Resolver};
use crate::tcp::tcp_client_handler_factory::create_tcp_client_proxy_selector;
use crate::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};
use crate::tcp::tcp_server_handler_factory::create_tcp_server_handler;

fn server(yaml: &str) -> Box<dyn TcpServerHandler> {
    server_with_rules(yaml, "- masks: 0.0.0.0/0\n  action: allow\n")
}

fn server_with_rules(yaml: &str, rules: &str) -> Box<dyn TcpServerHandler> {
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let rules: Vec<RuleConfig> = serde_yaml::from_str(rules).unwrap();
    let selector = Arc::new(create_tcp_client_proxy_selector(rules, resolver.clone()));
    let config: ServerProxyConfig = serde_yaml::from_str(yaml).unwrap();
    create_tcp_server_handler(config, &selector, &resolver, None)
}

/// A stream that yields `bytes`, then holds the connection open: a client
/// that has sent its first flight and waits for the answer.
fn stream_of(bytes: Vec<u8>) -> Box<dyn AsyncStream> {
    let (near, mut far) = tokio::io::duplex(1 << 16);
    tokio::spawn(async move {
        far.write_all(&bytes).await.unwrap();
        let _ = far.read_to_end(&mut Vec::new()).await;
    });
    Box::new(TestStream(near))
}

fn target(case: &serde_json::Value) -> NetLocation {
    NetLocation::from_str(text(&case["target"]), None).unwrap()
}

/// The target and the first payload bytes a TCP flight carries.
async fn forwarded(server: Box<dyn TcpServerHandler>, case: &serde_json::Value) {
    let result = server
        .setup_server_stream(stream_of(hex(&case["wire"])))
        .await
        .unwrap();
    let TcpServerSetupResult::TcpForward {
        remote_location,
        mut stream,
        initial_remote_data,
        ..
    } = result
    else {
        panic!("not a TCP forward");
    };
    assert_eq!(remote_location, target(case));

    let payload = hex(&case["payload"]);
    let mut received = initial_remote_data.map(Vec::from).unwrap_or_default();
    while received.len() < payload.len() {
        let mut more = vec![0u8; payload.len() - received.len()];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut more))
            .await
            .expect("the payload never arrived")
            .unwrap();
        assert!(n > 0, "the stream ended before the payload");
        received.extend_from_slice(&more[..n]);
    }
    assert_eq!(received, payload);
}

fn sing() -> serde_json::Value {
    vectors("frames-sing")
}

/// The time the sing flights were made at, which their servers check.
fn at_capture_time(vectors: &serde_json::Value) -> impl Drop {
    crate::util::pin_unix_time(crate::kat::number(&vectors["unix_time"]))
}

#[tokio::test]
async fn shadowsocks_2022_reads_the_sing_request() {
    let v = sing();
    let _clock = at_capture_time(&v);
    let psk = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(hex(&v["psk"]))
    };
    forwarded(
        server(&format!(
            "type: shadowsocks\ncipher: 2022-blake3-aes-256-gcm\npassword: {psk}\n"
        )),
        &v["ss2022_tcp"],
    )
    .await;
}

#[tokio::test]
async fn vmess_reads_the_sing_request() {
    let v = sing();
    let _clock = at_capture_time(&v);
    forwarded(
        server(&format!(
            "type: vmess\ncipher: aes-128-gcm\nuser_id: {}\n",
            text(&v["user_id"])
        )),
        &v["vmess_tcp"],
    )
    .await;
}

#[tokio::test]
async fn vless_reads_the_sing_request() {
    let v = sing();
    forwarded(
        server(&format!("type: vless\nuser_id: {}\n", text(&v["user_id"]))),
        &v["vless_tcp"],
    )
    .await;
}

/// VMess UDP from a client with GlobalPadding: each chunk carries random
/// padding whose length the client's length mask decides.
#[tokio::test]
async fn vmess_reads_a_sing_udp_chunk_with_padding() {
    let v = sing();
    let _clock = at_capture_time(&v);
    let case = &v["vmess_udp_padded"];
    let result = server(&format!(
        "type: vmess\ncipher: aes-128-gcm\nuser_id: {}\n",
        text(&v["user_id"])
    ))
    .setup_server_stream(stream_of(hex(&case["wire"])))
    .await
    .unwrap();
    let TcpServerSetupResult::BidirectionalUdp {
        remote_location,
        mut stream,
        ..
    } = result
    else {
        panic!("not a UDP association");
    };
    assert_eq!(remote_location, target(case));

    let mut buf = vec![0u8; 65535];
    let mut read = ReadBuf::new(&mut buf);
    std::future::poll_fn(|cx| Pin::new(&mut *stream).poll_read_message(cx, &mut read))
        .await
        .unwrap();
    assert_eq!(read.filled(), hex(&case["payload"]));
}

/// XUDP over VLESS: a New frame carrying the first packet, then a Keep.
#[tokio::test]
async fn vless_reads_sing_xudp_new_then_keep() {
    let v = sing();
    let case = &v["xudp"];
    let result = server(&format!("type: vless\nuser_id: {}\n", text(&v["user_id"])))
        .setup_server_stream(stream_of(hex(&case["wire"])))
        .await
        .unwrap();
    let TcpServerSetupResult::SessionBasedUdp { mut stream, .. } = result else {
        panic!("not an XUDP session stream");
    };
    let expected_source: std::net::SocketAddr = text(&case["target"]).parse().unwrap();
    let mut sessions = Vec::new();
    for packet in case["packets"].as_array().unwrap() {
        let mut buf = vec![0u8; 65535];
        let mut read = ReadBuf::new(&mut buf);
        let (session, destination) = std::future::poll_fn(|cx| {
            Pin::new(&mut *stream).poll_read_session_message(cx, &mut read)
        })
        .await
        .unwrap();
        assert_eq!(destination, expected_source);
        assert_eq!(read.filled(), hex(packet));
        sessions.push(session);
    }
    assert_eq!(
        sessions[0], sessions[1],
        "the Keep continues the New's session"
    );
}

fn sing_tls() -> serde_json::Value {
    vectors("frames-sing-tls")
}

/// AnyTLS runs its session itself and dials each stream's target, so the
/// only rule sends `example.com` to a local listener: a SYN read with the
/// wrong destination matches nothing, and nothing arrives.
#[tokio::test]
async fn anytls_reads_the_sing_session_open() {
    let v = sing_tls();
    let case = &v["anytls"];
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rules = format!(
        "- masks: {}\n  action: allow\n  override_address: {}\n",
        target(case).address(),
        listener.local_addr().unwrap()
    );
    let result = server_with_rules(
        &format!(
            "type: anytls\nusers:\n  - password: {}\n",
            text(&v["anytls_password"])
        ),
        &rules,
    )
    .setup_server_stream(stream_of(hex(&case["wire"])))
    .await
    .unwrap();
    assert!(matches!(result, TcpServerSetupResult::AlreadyHandled));

    let (mut target_side, _) =
        tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept())
            .await
            .expect("the session never opened its stream")
            .unwrap();
    let payload = hex(&case["payload"]);
    let mut received = vec![0u8; payload.len()];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        target_side.read_exact(&mut received),
    )
    .await
    .expect("the payload never arrived")
    .unwrap();
    assert_eq!(received, payload);
}

/// VLESS over sing-box's WebSocket client in early-data path mode: the
/// request and payload ride in the upgrade request's path.
#[tokio::test]
async fn websocket_reads_sing_early_data_in_the_path() {
    let v = sing_tls();
    forwarded(
        server(&format!(
            "type: websocket\ntargets:\n  - matching_path: /ws\n    max_early_data: 2048\n    protocol:\n      type: vless\n      user_id: {}\n",
            text(&v["user_id"])
        )),
        &v["websocket_vless"],
    )
    .await;
}

/// VLESS with Vision: the plaintext sing-vless wrote inside TLS, written
/// here through a rustls client into shoes' TLS server, which must find the
/// target and strip Vision's padding off the inner ClientHello.
#[tokio::test]
async fn vision_reads_the_sing_first_padded_frame() {
    let v = sing_tls();
    let case = &v["vision"];
    let certified = rcgen::generate_simple_self_signed(vec!["vision.test".to_string()]).unwrap();
    let indent = |pem: String| {
        pem.lines()
            .map(|line| format!("        {line}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let handler = server(&format!(
        "type: tls\ndefault_tls_target:\n    cert: |\n{}\n    key: |\n{}\n    vision: true\n    protocol:\n        type: vless\n        user_id: {}\n",
        indent(certified.cert.pem()),
        indent(certified.signing_key.serialize_pem()),
        text(&v["user_id"])
    ));

    let (near, far) = tokio::io::duplex(1 << 16);
    let accepted =
        tokio::spawn(async move { handler.setup_server_stream(Box::new(TestStream(far))).await });
    let config = Arc::new(crate::rustls_config_util::create_client_config(
        false,
        &[],
        &[],
        true,
        None,
        false,
    ));
    let mut tls = tokio_rustls::TlsConnector::from(config)
        .connect(
            rustls::pki_types::ServerName::try_from("vision.test").unwrap(),
            near,
        )
        .await
        .unwrap();
    tls.write_all(&hex(&case["wire"])).await.unwrap();
    tls.flush().await.unwrap();

    let TcpServerSetupResult::TcpForward {
        remote_location,
        mut stream,
        initial_remote_data,
        ..
    } = tokio::time::timeout(std::time::Duration::from_secs(5), accepted)
        .await
        .expect("the server never read the request")
        .unwrap()
        .unwrap()
    else {
        panic!("not a TCP forward");
    };
    assert_eq!(remote_location, target(case));
    let inner = hex(&case["payload"]);
    let mut received = initial_remote_data.map(Vec::from).unwrap_or_default();
    while received.len() < inner.len() {
        let mut more = vec![0u8; inner.len() - received.len()];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut more))
            .await
            .expect("the inner ClientHello never arrived")
            .unwrap();
        assert!(n > 0, "the stream ended before the inner ClientHello");
        received.extend_from_slice(&more[..n]);
    }
    assert_eq!(received, inner, "the padding is stripped");
    drop(tls);
}
