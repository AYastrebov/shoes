#![cfg(feature = "control-api")]

//! End-to-end test for the control API: binds a real listener, drives it
//! through `shoes::api::serve_on`, and talks to it over raw TCP the way an
//! external management panel would.

use shoes::api::config_section::ControlApiConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Mirrors `src/config/validate.rs`'s minimal socks-inbound fixture used by
/// the unit tests in `src/api/mod.rs`: a single socks inbound with no other
/// clauses, which is the smallest config `create_server_configs` accepts.
const MINIMAL_VALID_CONFIG_YAML: &str = "- address: 127.0.0.1:1080\n  protocol:\n    type: socks\n";

async fn spawn_server() -> (std::net::SocketAddr, String, tempfile::NamedTempFile) {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), MINIMAL_VALID_CONFIG_YAML).unwrap();

    let token = "test-token".to_string();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = ControlApiConfig {
        bind: addr,
        token: token.clone(),
        config_path: file.path().to_path_buf(),
        tls: None,
    };
    tokio::spawn(shoes::api::serve_on(listener, cfg));

    (addr, token, file)
}

async fn http_get(addr: std::net::SocketAddr, path: &str, token: Option<&str>) -> (u16, String) {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut request = format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n");
    if let Some(token) = token {
        request.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.unwrap();
    let response = String::from_utf8_lossy(&raw).to_string();

    let status_line = response.split("\r\n").next().unwrap_or("");
    let code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let body = response.split("\r\n\r\n").nth(1).unwrap_or("").to_string();

    (code, body)
}

async fn http_put(
    addr: std::net::SocketAddr,
    path: &str,
    token: &str,
    body: &str,
) -> (u16, String) {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut request = format!(
        "PUT {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\nAuthorization: Bearer {token}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    request.push_str(body);
    stream.write_all(request.as_bytes()).await.unwrap();

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.unwrap();
    let response = String::from_utf8_lossy(&raw).to_string();

    let status_line = response.split("\r\n").next().unwrap_or("");
    let code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let resp_body = response.split("\r\n\r\n").nth(1).unwrap_or("").to_string();

    (code, resp_body)
}

#[tokio::test]
async fn status_ok_with_token_401_without() {
    let (addr, token, _file) = spawn_server().await;

    let (code, _) = http_get(addr, "/api/status", Some(&token)).await;
    assert_eq!(code, 200);

    let (code, _) = http_get(addr, "/api/status", None).await;
    assert_eq!(code, 401);
}

#[tokio::test]
async fn put_invalid_config_is_rejected_and_leaves_file_unchanged() {
    let (addr, token, file) = spawn_server().await;
    let before = std::fs::read(file.path()).unwrap();

    let (code, body) = http_put(addr, "/api/config", &token, "not json at all").await;
    assert_eq!(code, 400, "body was: {body}");

    let after = std::fs::read(file.path()).unwrap();
    assert_eq!(
        before, after,
        "file must be unchanged on validation failure"
    );
}

#[tokio::test]
async fn put_valid_config_is_applied_and_persisted() {
    let (addr, token, file) = spawn_server().await;

    let new_config = serde_json::json!([{
        "address": "127.0.0.1:1081",
        "protocol": {"type": "socks"},
    }]);
    let (code, body) = http_put(addr, "/api/config", &token, &new_config.to_string()).await;
    assert_eq!(code, 200, "body was: {body}");

    let on_disk = std::fs::read_to_string(file.path()).unwrap();
    let on_disk_yaml: serde_yaml::Value = serde_yaml::from_str(&on_disk).unwrap();
    let expected_yaml: serde_yaml::Value = serde_yaml::from_str(&new_config.to_string()).unwrap();
    assert_eq!(
        on_disk_yaml, expected_yaml,
        "managed config file must now contain the PUT body"
    );
}

#[tokio::test]
async fn connections_returns_empty_array() {
    let (addr, token, _file) = spawn_server().await;

    let (code, body) = http_get(addr, "/api/connections", Some(&token)).await;
    assert_eq!(code, 200, "body was: {body}");
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    assert_eq!(parsed, serde_json::json!([]));
}
