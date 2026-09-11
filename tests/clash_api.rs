#![cfg(feature = "clash-api")]

//! Wire-level tests: a real listener on `127.0.0.1:0`, raw HTTP/1.1 over a
//! `TcpStream`, the way a dashboard's `fetch()` reaches the controller.
//!
//! The shape assertions deserialise into structs written from mihomo's
//! schema, so a renamed key fails this build rather than a panel in
//! production.

use std::net::SocketAddr;
use std::sync::Arc;

use shoes::clash_api::{ApiState, Ports, serve_on};
use shoes::config::ClashApiConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Start a controller on an ephemeral port. The returned sender stops it
/// when dropped, so a test that panics does not leave a listener behind.
pub async fn spawn(
    secret: Option<&str>,
    allow_origins: Vec<String>,
) -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = Arc::new(ApiState {
        config: ClashApiConfig {
            listen: addr,
            secret: secret.map(str::to_string),
            allow_origins,
            max_tracked_connections: 4096,
            state_file: None,
        },
        ports: Ports {
            socks: 1080,
            http: 0,
            mixed: 0,
            tun: false,
        },
        started: std::time::Instant::now(),
        log: None,
    });
    let (stop, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(serve_on(listener, state, rx));
    (addr, stop)
}

pub struct Reply {
    pub code: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Reply {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

pub async fn request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Reply {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(body);
    stream.write_all(req.as_bytes()).await.unwrap();

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.unwrap();
    let text = String::from_utf8_lossy(&raw).to_string();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let mut lines = head.split("\r\n");
    let code = lines
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers = lines
        .filter_map(|l| l.split_once(": "))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    Reply {
        code,
        headers,
        body: body.to_string(),
    }
}

pub async fn get(addr: SocketAddr, path: &str, secret: Option<&str>) -> Reply {
    let auth = secret.map(|s| format!("Bearer {s}"));
    let headers: Vec<(&str, &str)> = auth.iter().map(|a| ("Authorization", a.as_str())).collect();
    request(addr, "GET", path, &headers, "").await
}

/// Write one line into a ring the way the global logger would.
fn push(
    ring: &shoes::control::logs::BroadcastLogWriter,
    level: log::Level,
    target: &str,
    message: &str,
) {
    use shoes::logging::LogWriter as _;
    // Built and used in one statement: `format_args!` borrows a temporary.
    ring.write_log(
        &log::Record::builder()
            .level(level)
            .target(target)
            .args(format_args!("{message}"))
            .build(),
        message,
    );
}

fn json(reply: &Reply) -> serde_json::Value {
    serde_json::from_str(&reply.body).unwrap_or_else(|e| panic!("{e}: {}", reply.body))
}

/// A WebSocket handshake, checked against RFC 6455's example accept key.
pub async fn ws_open(addr: SocketAddr, path: &str) -> tokio::net::TcpStream {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await.unwrap();

    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await.unwrap();
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head).to_string();
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    assert!(
        head.to_ascii_lowercase()
            .contains("sec-websocket-accept: s3pplmbitxaq9kygzzhzrbk+xoo="),
        "the accept key must be the RFC's: {head}"
    );
    stream
}

/// One server text frame. Server frames are unmasked, and these payloads
/// are well under 64 KiB.
pub async fn ws_read_text(stream: &mut tokio::net::TcpStream) -> String {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await.unwrap();
    assert_eq!(header[0] & 0x0f, 0x1, "expected a text frame");
    assert_eq!(header[1] & 0x80, 0, "a server must not mask");

    let len = match header[1] & 0x7f {
        126 => {
            let mut extended = [0u8; 2];
            stream.read_exact(&mut extended).await.unwrap();
            u16::from_be_bytes(extended) as usize
        }
        n => n as usize,
    };
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await.unwrap();
    String::from_utf8(payload).unwrap()
}

#[tokio::test]
async fn traffic_streams_and_a_token_query_authorises_a_socket() {
    let (addr, _stop) = spawn(Some("s"), vec![]).await;

    // A browser cannot set a header on a handshake, so the secret rides on
    // the query string.
    let mut ws = ws_open(addr, "/traffic?token=s").await;
    let frame: serde_json::Value = serde_json::from_str(&ws_read_text(&mut ws).await).unwrap();
    assert!(
        frame.get("up").is_some() && frame.get("down").is_some(),
        "{frame}"
    );
}

#[tokio::test]
async fn a_socket_without_the_token_is_refused() {
    let (addr, _stop) = spawn(Some("s"), vec![]).await;
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(
            b"GET /traffic HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        )
        .await
        .unwrap();
    // The status line only: a refused upgrade is answered on a connection
    // that stays open, so reading to EOF would wait for a close that a
    // keep-alive response never sends.
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n") {
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read_exact(&mut byte),
        )
        .await
        .expect("a status line within five seconds")
        .unwrap();
        head.push(byte[0]);
    }
    assert!(
        String::from_utf8_lossy(&head).starts_with("HTTP/1.1 401"),
        "an unauthorised upgrade must not become a socket: {}",
        String::from_utf8_lossy(&head)
    );
}

#[tokio::test]
async fn memory_and_connections_stream_over_a_socket() {
    let (addr, _stop) = spawn(None, vec![]).await;

    let mut ws = ws_open(addr, "/memory").await;
    let frame: serde_json::Value = serde_json::from_str(&ws_read_text(&mut ws).await).unwrap();
    assert!(frame["inuse"].is_number(), "{frame}");

    let mut ws = ws_open(addr, "/connections?interval=100").await;
    let frame: serde_json::Value = serde_json::from_str(&ws_read_text(&mut ws).await).unwrap();
    assert!(frame["connections"].is_array(), "{frame}");
}

/// mihomo serves these to a plain GET as well, and scripts use that.
#[tokio::test]
async fn a_plain_get_streams_json_lines() {
    let (addr, _stop) = spawn(None, vec![]).await;

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /traffic HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();

    let mut buf = vec![0u8; 4096];
    let mut text = String::new();
    for _ in 0..5 {
        let n = tokio::time::timeout(std::time::Duration::from_secs(3), stream.read(&mut buf))
            .await
            .expect("a frame within three seconds")
            .unwrap();
        text.push_str(&String::from_utf8_lossy(&buf[..n]));
        if text.contains("\"up\"") {
            break;
        }
    }
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    assert!(text.contains("\"up\""), "{text}");
}

/// A snapshot fetch must stay a snapshot: `/connections` without an
/// interval is one body that ends.
#[tokio::test]
async fn connections_without_an_interval_is_a_snapshot() {
    let (addr, _stop) = spawn(None, vec![]).await;
    let reply = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        get(addr, "/connections", None),
    )
    .await
    .expect("the body ends rather than streaming");
    assert_eq!(reply.code, 200);
    assert!(json(&reply)["connections"].is_array());
}

/// The backlog first, then live lines, in the payload shape a sing-box
/// client's classifier splits on.
#[tokio::test]
async fn logs_replay_the_backlog_then_stream() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let ring = shoes::clash_api::logs::install_ring(16);
    let state = Arc::new(ApiState {
        config: ClashApiConfig {
            listen: addr,
            secret: None,
            allow_origins: vec![],
            max_tracked_connections: 4096,
            state_file: None,
        },
        ports: Ports::default(),
        started: std::time::Instant::now(),
        log: Some(ring.clone()),
    });
    let (_stop, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(serve_on(listener, state, rx));

    // Through the public writer rather than the global logger: that one is
    // process-wide and initialised once, so a test that installed one would
    // fight every other test in the binary.
    push(
        &ring,
        log::Level::Info,
        "shoes::tcp::tcp_server",
        "before-subscribe",
    );

    let mut ws = ws_open(addr, "/logs?level=trace").await;
    let first: serde_json::Value = serde_json::from_str(&ws_read_text(&mut ws).await).unwrap();
    assert_eq!(first["type"], "info");
    let payload = first["payload"].as_str().unwrap();
    assert!(payload.contains("before-subscribe"), "{payload}");
    assert!(
        payload.starts_with("inbound[]: "),
        "a sing-box classifier splits on category[tag]: {payload}"
    );

    push(&ring, log::Level::Warn, "shoes", "live");
    let second: serde_json::Value = serde_json::from_str(&ws_read_text(&mut ws).await).unwrap();
    assert_eq!(second["type"], "warning");
    assert!(
        second["payload"]
            .as_str()
            .unwrap()
            .starts_with("runtime[shoes]: "),
        "{second}"
    );
}

#[tokio::test]
async fn an_unknown_log_level_is_refused() {
    let (addr, _stop) = spawn(None, vec![]).await;
    assert_eq!(get(addr, "/logs?level=shouting", None).await.code, 400);
}

#[tokio::test]
async fn auth_is_required_when_a_secret_is_set() {
    let (addr, _stop) = spawn(Some("s3cret"), vec![]).await;

    assert_eq!(get(addr, "/version", None).await.code, 401);
    assert_eq!(get(addr, "/version", Some("wrong")).await.code, 401);
    assert_eq!(
        json(&get(addr, "/version", None).await)["message"],
        "Unauthorized"
    );

    let ok = get(addr, "/version", Some("s3cret")).await;
    assert_eq!(ok.code, 200);
    assert_eq!(json(&ok)["meta"], true, "a dashboard tests this");
    assert_eq!(json(&ok)["version"], env!("CARGO_PKG_VERSION"));
}

#[tokio::test]
async fn no_secret_on_loopback_means_no_auth() {
    let (addr, _stop) = spawn(None, vec![]).await;
    let hello = get(addr, "/", None).await;
    assert_eq!(hello.code, 200);
    assert_eq!(json(&hello)["hello"], "shoes");
}

#[tokio::test]
async fn cors_preflight_needs_no_auth_and_every_reply_names_an_origin() {
    let (addr, _stop) = spawn(Some("s"), vec![]).await;

    // Preflight carries no credentials, so it must not be refused.
    let preflight = request(
        addr,
        "OPTIONS",
        "/proxies",
        &[("Origin", "http://yacd.example")],
        "",
    )
    .await;
    assert_eq!(preflight.code, 204);
    assert_eq!(preflight.header("Access-Control-Allow-Origin"), Some("*"));
    assert!(
        preflight
            .header("Access-Control-Allow-Headers")
            .unwrap()
            .contains("Authorization")
    );

    let ok = get(addr, "/version", Some("s")).await;
    assert_eq!(ok.header("Access-Control-Allow-Origin"), Some("*"));
}

#[tokio::test]
async fn a_configured_origin_list_allows_only_those_origins() {
    let (addr, _stop) = spawn(Some("s"), vec!["http://allowed.example".to_string()]).await;

    let allowed = request(
        addr,
        "GET",
        "/version",
        &[
            ("Origin", "http://allowed.example"),
            ("Authorization", "Bearer s"),
        ],
        "",
    )
    .await;
    assert_eq!(
        allowed.header("Access-Control-Allow-Origin"),
        Some("http://allowed.example")
    );

    let other = request(
        addr,
        "GET",
        "/version",
        &[
            ("Origin", "http://other.example"),
            ("Authorization", "Bearer s"),
        ],
        "",
    )
    .await;
    assert_eq!(
        other.header("Access-Control-Allow-Origin"),
        None,
        "an origin outside the list gets no header, so a browser refuses the read"
    );
}

#[tokio::test]
async fn unknown_routes_and_methods_map_per_the_error_table() {
    let (addr, _stop) = spawn(None, vec![]).await;

    // Absent, so a dashboard hides the panel rather than retrying.
    assert_eq!(get(addr, "/providers/proxies", None).await.code, 404);
    assert_eq!(get(addr, "/ui", None).await.code, 404);
    assert_eq!(get(addr, "/dns/query", None).await.code, 404);

    // Present, but not with that method.
    assert_eq!(request(addr, "PUT", "/configs", &[], "{}").await.code, 405);
    assert_eq!(
        request(addr, "PUT", "/proxies/GLOBAL", &[], "{\"name\":\"x\"}")
            .await
            .code,
        405
    );

    assert_eq!(
        json(&get(addr, "/proxies/nope", None).await)["message"],
        "proxy not found"
    );
    assert_eq!(
        request(addr, "DELETE", "/connections/999999", &[], "")
            .await
            .code,
        404
    );
}

#[tokio::test]
async fn one_shot_shapes_match_mihomo() {
    let (addr, _stop) = spawn(None, vec![]).await;

    let configs = json(&get(addr, "/configs", None).await);
    assert_eq!(configs["mode"], "rule");
    assert_eq!(configs["socks-port"], 1080);
    assert_eq!(configs["tun"]["enable"], false);
    for key in [
        "port",
        "mixed-port",
        "redir-port",
        "tproxy-port",
        "allow-lan",
        "bind-address",
        "log-level",
        "ipv6",
    ] {
        assert!(configs.get(key).is_some(), "missing {key}: {configs}");
    }

    let proxies = json(&get(addr, "/proxies", None).await);
    let global = &proxies["proxies"]["GLOBAL"];
    assert_eq!(global["type"], "Selector", "every dashboard assumes GLOBAL");
    assert!(global["all"].is_array());
    assert!(global["history"].is_array());

    let group = json(&get(addr, "/group", None).await);
    assert!(group["proxies"].is_object());

    let rules = json(&get(addr, "/rules", None).await);
    assert!(rules["rules"].is_array());

    let conns = json(&get(addr, "/connections", None).await);
    assert!(conns["connections"].is_array());
    for key in ["downloadTotal", "uploadTotal", "memory", "untracked"] {
        assert!(conns.get(key).is_some(), "missing {key}: {conns}");
    }

    assert_eq!(
        request(addr, "DELETE", "/connections", &[], "").await.code,
        204
    );
}

#[tokio::test]
async fn metrics_carry_every_family_in_the_spec() {
    let (addr, _stop) = spawn(None, vec![]).await;

    let reply = get(addr, "/metrics", None).await;
    assert_eq!(reply.code, 200);
    assert!(
        reply
            .header("Content-Type")
            .unwrap()
            .starts_with("text/plain"),
        "Prometheus refuses anything else"
    );

    for family in [
        "shoes_build_info",
        "shoes_connections_active",
        "shoes_connections_total",
        "shoes_connections_untracked_total",
        "shoes_bytes_total",
        "shoes_inbound_connections_active",
        "shoes_inbound_bytes_total",
        "shoes_outbound_connections_active",
        "shoes_outbound_bytes_total",
    ] {
        assert!(
            reply.body.contains(&format!("# TYPE {family} ")),
            "missing {family}:\n{}",
            reply.body
        );
    }
}

/// Dropping the sender is how a host stops the controller across a config
/// change, so it has to actually stop it.
#[tokio::test]
async fn dropping_the_shutdown_sender_stops_the_listener() {
    let (addr, stop) = spawn(None, vec![]).await;
    assert_eq!(get(addr, "/", None).await.code, 200);

    drop(stop);

    for _ in 0..100 {
        if tokio::net::TcpStream::connect(addr).await.is_err() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("the listener on {addr} is still accepting");
}
