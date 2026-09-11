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
        ports: parking_lot::RwLock::new(Ports {
            socks: 1080,
            http: 0,
            mixed: 0,
            tun: false,
        }),
        started: std::time::Instant::now(),
        shutdown: tokio_util::sync::CancellationToken::new(),
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
    try_request(addr, method, path, headers, body)
        .await
        .unwrap_or_else(|| panic!("{method} {path} on {addr}: no reply"))
}

/// `None` when the listener is not there or drops the connection: for a
/// test that polls across a controller restart.
pub async fn try_request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Option<Reply> {
    let mut stream = tokio::net::TcpStream::connect(addr).await.ok()?;
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(body);
    stream.write_all(req.as_bytes()).await.ok()?;

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.ok()?;
    let text = String::from_utf8_lossy(&raw).to_string();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let mut lines = head.split("\r\n");
    let code = lines.next()?.split_whitespace().nth(1)?.parse().ok()?;
    let headers = lines
        .filter_map(|l| l.split_once(": "))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    Some(Reply {
        code,
        headers,
        body: body.to_string(),
    })
}

fn bearer(secret: Option<&str>) -> Option<String> {
    secret.map(|s| format!("Bearer {s}"))
}

pub async fn get(addr: SocketAddr, path: &str, secret: Option<&str>) -> Reply {
    let auth = bearer(secret);
    let headers: Vec<(&str, &str)> = auth.iter().map(|a| ("Authorization", a.as_str())).collect();
    request(addr, "GET", path, &headers, "").await
}

pub async fn try_get(addr: SocketAddr, path: &str, secret: Option<&str>) -> Option<Reply> {
    let auth = bearer(secret);
    let headers: Vec<(&str, &str)> = auth.iter().map(|a| ("Authorization", a.as_str())).collect();
    try_request(addr, "GET", path, &headers, "").await
}

/// A child that dies with the test, whichever way the test ends.
struct Child(std::process::Child);

impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// `N` distinct free ports.
///
/// Every listener stays bound until all are allocated: binding and
/// releasing one at a time can hand the same port back twice, and a
/// process told to listen on it twice fails to start.
fn free_ports<const N: usize>() -> [u16; N] {
    let listeners: Vec<std::net::TcpListener> = (0..N)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let ports: Vec<u16> = listeners
        .iter()
        .map(|l| l.local_addr().unwrap().port())
        .collect();
    ports.try_into().unwrap()
}

async fn wait_for(addr: SocketAddr) {
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("{addr} never came up");
}

/// SOCKS5 CONNECT with no authentication, returning the stream past the
/// reply so the caller can talk to the target.
async fn socks_connect(proxy: SocketAddr, target: SocketAddr) -> tokio::net::TcpStream {
    let mut stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 0], "no-auth must be accepted");

    let std::net::SocketAddr::V4(v4) = target else {
        panic!("the test targets are v4")
    };
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&v4.ip().octets());
    request.extend_from_slice(&v4.port().to_be_bytes());
    stream.write_all(&request).await.unwrap();

    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0, "the CONNECT was refused");
    stream
}

/// The claim this test exists for: a connection through a running shoes is
/// listed with its route, can be closed from the controller, and moves the
/// traffic stream -- which on a server has no TUN to count at.
#[tokio::test]
async fn a_forwarded_connection_is_listed_counted_and_closable() {
    let [socks_port, api_port] = free_ports::<2>();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.yaml");
    std::fs::write(
        &config_path,
        format!(
            "- address: 127.0.0.1:{socks_port}\n  protocol:\n    type: socks\n\
             - clash_api:\n    listen: 127.0.0.1:{api_port}\n"
        ),
    )
    .unwrap();

    let child = Child(
        std::process::Command::new(env!("CARGO_BIN_EXE_shoes"))
            .arg("--no-reload")
            .arg(&config_path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    let api: SocketAddr = format!("127.0.0.1:{api_port}").parse().unwrap();
    let proxy: SocketAddr = format!("127.0.0.1:{socks_port}").parse().unwrap();
    wait_for(api).await;
    wait_for(proxy).await;

    // An upstream that answers three bytes for every five, so the two
    // directions differ and a transposition fails rather than passing.
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let mut buf = [0u8; 5];
        while stream.read_exact(&mut buf).await.is_ok() {
            if stream.write_all(b"abc").await.is_err() {
                break;
            }
        }
    });

    let mut traffic = ws_open(api, "/traffic").await;
    let _first_is_zero = ws_read_text(&mut traffic).await;

    let mut client = socks_connect(proxy, upstream_addr).await;
    let mut echo = [0u8; 3];
    for _ in 0..4 {
        client.write_all(b"12345").await.unwrap();
        client.read_exact(&mut echo).await.unwrap();
    }

    // Wait for the route, which is recorded after the dial.
    //
    // The port is a string in this metadata, as mihomo sends it, so the
    // comparison is against a string rather than the number it looks like.
    let want_port = upstream_addr.port().to_string();
    let mut listed = None;
    for _ in 0..100 {
        let body = json(&get(api, "/connections", None).await);
        if let Some(found) = body["connections"].as_array().unwrap().iter().find(|c| {
            c["metadata"]["destinationPort"] == want_port.as_str()
                && !c["chains"].as_array().unwrap().is_empty()
        }) {
            listed = Some(found.clone());
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let listed = listed.expect("the connection is listed with its route");

    assert_eq!(listed["metadata"]["type"], "socks5");
    assert_eq!(listed["metadata"]["network"], "tcp");
    assert_eq!(
        listed["metadata"]["inboundName"],
        format!("socks5@127.0.0.1:{socks_port}")
    );
    assert_eq!(listed["chains"][0], "direct", "the exit outbound");
    assert_eq!(listed["rule"], "Match", "the catch-all rule allowed it");
    // The SOCKS handshake is counted at the client edge too, hence ">=".
    assert!(listed["upload"].as_u64().unwrap() >= 20, "{listed}");
    assert!(listed["download"].as_u64().unwrap() >= 12, "{listed}");

    // The server-mode traffic claim: a non-zero tick with no TUN anywhere.
    let mut saw_bytes = false;
    for _ in 0..4 {
        client.write_all(b"12345").await.unwrap();
        client.read_exact(&mut echo).await.unwrap();
        let tick: serde_json::Value =
            serde_json::from_str(&ws_read_text(&mut traffic).await).unwrap();
        if tick["up"].as_u64().unwrap() > 0 && tick["down"].as_u64().unwrap() > 0 {
            saw_bytes = true;
            break;
        }
    }
    assert!(saw_bytes, "/traffic stayed flat in server mode");

    // Counted under the listener's own label. Not an exact figure: the
    // readiness probe above also connected, and a count is a count.
    let metrics = get(api, "/metrics", None).await.body;
    let label = format!("socks5@127.0.0.1:{socks_port}");
    let counted = metrics
        .lines()
        .find(|l| l.starts_with("shoes_inbound_connections_total{") && l.contains(&label))
        .and_then(|l| l.rsplit(' ').next())
        .and_then(|n| n.parse::<u64>().ok())
        .unwrap_or(0);
    assert!(counted >= 1, "expected {label} in:\n{metrics}");

    // Closing it from the controller ends the client's stream, which is the
    // only thing that makes a dashboard's disconnect button mean anything.
    let id = listed["id"].as_str().unwrap().to_string();
    assert_eq!(
        request(api, "DELETE", &format!("/connections/{id}"), &[], "")
            .await
            .code,
        204
    );
    let mut probe = [0u8; 1];
    let ended =
        tokio::time::timeout(std::time::Duration::from_secs(5), client.read(&mut probe)).await;
    assert!(
        matches!(ended, Ok(Ok(0)) | Ok(Err(_))),
        "the client's stream should end after DELETE: {ended:?}"
    );

    for _ in 0..100 {
        let body = json(&get(api, "/connections", None).await);
        if body["connections"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["id"] != id)
        {
            drop(child);
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("the entry outlived its connection");
}

/// A reload replaces the proxies; the controller and its open sockets stay.
#[tokio::test]
async fn the_listener_survives_a_config_reload() {
    let [socks_port, api_port] = free_ports::<2>();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.yaml");

    let write = |name: &str| {
        // A group nothing references is still a configured outbound, so it
        // appears in /proxies -- which is how this test sees the swap
        // without needing traffic to flow through it.
        let yaml = format!(
            "- address: 127.0.0.1:{socks_port}\n\
             \x20 protocol:\n\
             \x20   type: socks\n\
             - client_group: pool\n\
             \x20 client_proxies:\n\
             \x20   - name: {name}\n\
             \x20     address: 127.0.0.1:1\n\
             \x20     protocol:\n\
             \x20       type: socks\n\
             - clash_api:\n\
             \x20   listen: 127.0.0.1:{api_port}\n"
        );
        std::fs::write(&config_path, yaml).unwrap();
    };

    write("first");
    let child = Child(
        std::process::Command::new(env!("CARGO_BIN_EXE_shoes"))
            .arg(&config_path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    let api: SocketAddr = format!("127.0.0.1:{api_port}").parse().unwrap();
    wait_for(api).await;

    let proxies = json(&get(api, "/proxies", None).await);
    assert!(
        proxies["proxies"].get("first").is_some(),
        "the first config's outbound: {proxies}"
    );

    let mut ws = ws_open(api, "/traffic").await;
    let _ = ws_read_text(&mut ws).await;

    write("second");

    // The file watcher debounces for three seconds, so this polls well past
    // that rather than sleeping a fixed amount.
    let mut swapped = false;
    for _ in 0..200 {
        let proxies = json(&get(api, "/proxies", None).await);
        if proxies["proxies"].get("second").is_some() {
            assert!(
                proxies["proxies"].get("first").is_none(),
                "a reload replaces rather than accumulates: {proxies}"
            );
            swapped = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(swapped, "the reload never took");

    let still_open =
        tokio::time::timeout(std::time::Duration::from_secs(3), ws_read_text(&mut ws)).await;
    assert!(
        still_open.is_ok(),
        "the dashboard's socket died across a reload"
    );
    drop(child);
}

/// A reload that changes the secret restarts the controller on the same
/// port, and the old secret stops working. The old task releases the socket
/// only when it is next polled, so a bind that did not wait for it was
/// "address in use" and the controller was gone until the next edit.
#[tokio::test]
async fn a_changed_secret_restarts_the_controller_on_the_same_port() {
    let [socks_port, api_port] = free_ports::<2>();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.yaml");
    let write = |secret: &str| {
        std::fs::write(
            &config_path,
            format!(
                "- address: 127.0.0.1:{socks_port}\n  protocol:\n    type: socks\n\
                 - clash_api:\n    listen: 127.0.0.1:{api_port}\n    secret: {secret}\n"
            ),
        )
        .unwrap();
    };
    write("first");

    let child = Child(
        std::process::Command::new(env!("CARGO_BIN_EXE_shoes"))
            // The watcher on: the rotation is an edit, as an operator makes it.
            .arg(&config_path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    let api: SocketAddr = format!("127.0.0.1:{api_port}").parse().unwrap();
    wait_for(api).await;
    assert_eq!(get(api, "/version", Some("first")).await.code, 200);

    write("second");

    // Past the debounce and the restart; polled rather than slept, and
    // tolerant of the moment between the old listener and the new.
    let mut rotated = false;
    for _ in 0..300 {
        if let Some(reply) = try_get(api, "/version", Some("second")).await
            && reply.code == 200
        {
            rotated = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        rotated,
        "the controller never came back with the new secret"
    );
    assert_eq!(
        get(api, "/version", Some("first")).await.code,
        401,
        "the old secret is gone with the old controller"
    );
    drop(child);
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

/// RFC 6455 has a client mask every frame, and a server fail the connection
/// on one that is not. The failure is a close frame with the protocol-error
/// code, then the socket goes; the frame itself is never read as a frame.
#[tokio::test]
async fn an_unmasked_client_frame_is_answered_with_a_protocol_error_close() {
    let (addr, _stop) = spawn(Some("s"), vec![]).await;
    let mut ws = ws_open(addr, "/traffic?token=s").await;

    // A ping with the mask bit clear: FIN, opcode 9, length 0.
    ws.write_all(&[0x89, 0x00]).await.unwrap();

    assert_eq!(
        ws_read_until_close(&mut ws).await,
        1002u16.to_be_bytes(),
        "the close code is 1002, protocol error"
    );
    assert_ws_hung_up(&mut ws).await;
}

/// A ping is answered with a pong even when it lands between two ticks,
/// split across two segments: the reader keeps its place across the select
/// that drops it each tick, so no byte is lost and no frame is split.
#[tokio::test]
async fn a_ping_split_across_ticks_is_still_answered() {
    let (addr, _stop) = spawn(None, vec![]).await;
    let mut ws = ws_open(addr, "/traffic").await;
    let _ = ws_read_text(&mut ws).await;

    // A masked ping "hi": header and one mask byte now, the rest after a
    // traffic tick has come and gone.
    ws.write_all(&[0x89, 0x82, 1]).await.unwrap();
    let _ = ws_read_text(&mut ws).await;
    ws.write_all(&[2, 3, 4, b'h' ^ 1, b'i' ^ 2]).await.unwrap();

    // The pong, among the text frames.
    let payload = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let mut header = [0u8; 2];
            ws.read_exact(&mut header).await.unwrap();
            let len = match header[1] & 0x7f {
                126 => {
                    let mut extended = [0u8; 2];
                    ws.read_exact(&mut extended).await.unwrap();
                    u16::from_be_bytes(extended) as usize
                }
                n => n as usize,
            };
            let mut payload = vec![0u8; len];
            ws.read_exact(&mut payload).await.unwrap();
            if header[0] & 0x0f == 0xA {
                break payload;
            }
        }
    })
    .await
    .expect("a pong within 3 s");
    assert_eq!(
        payload, b"hi",
        "the pong carries the ping's payload, unmasked"
    );
}

/// Stopping the controller ends the streams it served, close frame first:
/// a subscriber that authenticated with a rotated secret must not stream on
/// after the reload that rotated it.
#[tokio::test]
async fn stopping_the_controller_closes_its_open_streams() {
    let (addr, stop) = spawn(None, vec![]).await;
    let mut ws = ws_open(addr, "/traffic").await;
    let _ = ws_read_text(&mut ws).await;

    drop(stop);

    let payload = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        ws_read_until_close(&mut ws),
    )
    .await
    .expect("a close frame within 3 s of the stop");
    assert_eq!(payload, 1001u16.to_be_bytes(), "1001: going away");
    assert_ws_hung_up(&mut ws).await;
}

/// Frames until a close arrives; its payload, which carries the code.
/// Text frames already in flight ahead of the close are read past.
pub async fn ws_read_until_close(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
    loop {
        let mut header = [0u8; 2];
        stream.read_exact(&mut header).await.unwrap();
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
        if header[0] & 0x0f == 0x8 {
            return payload;
        }
    }
}

/// After a close the server hangs up: nothing but EOF or a reset follows.
pub async fn assert_ws_hung_up(stream: &mut tokio::net::TcpStream) {
    let mut rest = [0u8; 16];
    let read =
        tokio::time::timeout(std::time::Duration::from_secs(3), stream.read(&mut rest)).await;
    assert!(
        matches!(read, Ok(Ok(0)) | Ok(Err(_))),
        "the socket must be closed after the close frame: {read:?}"
    );
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
        ports: parking_lot::RwLock::new(Ports::default()),
        started: std::time::Instant::now(),
        shutdown: tokio_util::sync::CancellationToken::new(),
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
