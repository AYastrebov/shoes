//! Feature-gated HTTP control API for a management panel.
pub mod config_section;
pub mod handlers;
pub mod logsink;

use std::convert::Infallible;
use std::sync::Arc;

use futures::StreamExt;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Bytes, Frame};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use subtle::ConstantTimeEq;

use config_section::ControlApiConfig;

pub(crate) struct ApiState {
    token: String,
    #[allow(dead_code)]
    config_path: std::path::PathBuf,
    started: std::time::Instant,
}

pub async fn serve(config: ControlApiConfig) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    log::info!("control API listening on {}", config.bind);
    serve_on(listener, config).await
}

pub async fn serve_on(
    listener: tokio::net::TcpListener,
    config: ControlApiConfig,
) -> std::io::Result<()> {
    let state = Arc::new(ApiState {
        token: config.token,
        config_path: config.config_path,
        started: std::time::Instant::now(),
    });
    loop {
        let (stream, _) = listener.accept().await?;
        let state = state.clone();
        let io = hyper_util::rt::TokioIo::new(stream);
        tokio::spawn(async move {
            let svc = service_fn(move |req| {
                let state = state.clone();
                async move { Ok::<_, Infallible>(route(req, state).await) }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, svc)
                .await;
        });
    }
}

fn authorized(headers: &hyper::HeaderMap, token: &str) -> bool {
    let Some(v) = headers.get(hyper::header::AUTHORIZATION) else {
        return false;
    };
    let Ok(v) = v.to_str() else { return false };
    let Some(bearer) = v.strip_prefix("Bearer ") else {
        return false;
    };
    bearer.as_bytes().ct_eq(token.as_bytes()).into()
}

pub(crate) type ApiBody = BoxBody<Bytes, Infallible>;

pub(crate) fn json(status: StatusCode, body: String) -> Response<ApiBody> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)).boxed())
        .unwrap()
}

// GET /api/logs returns a text/event-stream body built from a broadcast
// receiver. Lagged receivers get a "data: {\"lag\":N}\n\n" marker rather than
// backpressure; the loop continues.
fn sse_response<S>(stream: S) -> Response<ApiBody>
where
    S: futures::Stream<Item = Result<Bytes, Infallible>> + Send + Sync + 'static,
{
    let body = StreamBody::new(stream.map(|res| res.map(Frame::data)));
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/event-stream")
        // Conventional for SSE: stop intermediaries buffering the stream.
        .header("cache-control", "no-cache")
        .body(BodyExt::boxed(body))
        .unwrap()
}

// GET /api/events returns a text/event-stream body of connection open/close
// events plus a periodic metrics snapshot tick. Subscribing before entering
// the select loop matters: `connection_registry::register`/`Drop` only send
// an event when `receiver_count() > 0`, so subscribing first guarantees this
// handler observes every open/close that happens after the client connects.
fn events_stream() -> impl futures::Stream<Item = Result<Bytes, Infallible>> + Send + Sync + 'static
{
    let rx = crate::connection_registry::subscribe_events();
    let interval = tokio::time::interval(std::time::Duration::from_secs(5));
    futures::stream::unfold((rx, interval), |(mut rx, mut interval)| async move {
        tokio::select! {
            ev = rx.recv() => {
                let frame = match ev {
                    Ok(ev) => Bytes::from(format!(
                        "data: {}\n\n",
                        serde_json::to_string(&ev).unwrap()
                    )),
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        Bytes::from(format!("data: {{\"event\":\"lag\",\"skipped\":{n}}}\n\n"))
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
                };
                Some((Ok(frame), (rx, interval)))
            }
            _ = interval.tick() => {
                let m = crate::connection_registry::metrics_counters();
                let frame = Bytes::from(format!(
                    "data: {{\"event\":\"metrics\",\"active_connections\":{},\"total_connections\":{},\"total_up_bytes\":{},\"total_down_bytes\":{}}}\n\n",
                    m.active_connections, m.total_connections, m.total_up_bytes, m.total_down_bytes,
                ));
                Some((Ok(frame), (rx, interval)))
            }
        }
    })
}

fn logs_stream() -> impl futures::Stream<Item = Result<Bytes, Infallible>> + Send + Sync + 'static {
    let (replay, rx) = logsink::global_log_stream();
    let replay_stream = futures::stream::iter(
        replay
            .into_iter()
            .map(|line| Ok(Bytes::from(format!("data: {line}\n\n")))),
    );
    let tail_stream = futures::stream::unfold(rx, |mut rx| async move {
        match rx.recv().await {
            Ok(line) => Some((Ok(Bytes::from(format!("data: {line}\n\n"))), rx)),
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                Some((Ok(Bytes::from(format!("data: {{\"lag\":{n}}}\n\n"))), rx))
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => None,
        }
    });
    replay_stream.chain(tail_stream)
}

async fn route(req: Request<hyper::body::Incoming>, state: Arc<ApiState>) -> Response<ApiBody> {
    if !authorized(req.headers(), &state.token) {
        return json(
            StatusCode::UNAUTHORIZED,
            r#"{"error":"unauthorized"}"#.to_string(),
        );
    }
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    match (&method, path.as_str()) {
        (&hyper::Method::GET, "/api/status") => handlers::status(&state),
        (&hyper::Method::GET, "/api/connections") => handlers::connections(&state),
        (&hyper::Method::GET, "/api/metrics") => handlers::metrics(&state),
        (&hyper::Method::GET, "/api/config") => handlers::get_config(&state),
        (&hyper::Method::GET, "/api/logs") => sse_response(logs_stream()),
        (&hyper::Method::GET, "/api/events") => sse_response(events_stream()),
        (&hyper::Method::PUT, "/api/config") => {
            let bytes = match http_body_util::BodyExt::collect(req.into_body()).await {
                Ok(c) => c.to_bytes(),
                Err(e) => {
                    return json(
                        StatusCode::BAD_REQUEST,
                        serde_json::json!({"error": format!("body read error: {e}")}).to_string(),
                    );
                }
            };
            handlers::put_config(&state, bytes).await
        }
        _ => json(
            StatusCode::NOT_FOUND,
            r#"{"error":"not found"}"#.to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::config_section::ControlApiConfig;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn spawn() -> (std::net::SocketAddr, String) {
        spawn_with_config_path("/nonexistent".into()).await
    }

    async fn spawn_with_config_path(
        config_path: std::path::PathBuf,
    ) -> (std::net::SocketAddr, String) {
        let token = "test-token".to_string();
        let cfg = ControlApiConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            token: token.clone(),
            config_path,
            tls: None,
        };
        let listener = tokio::net::TcpListener::bind(cfg.bind).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_on(listener, cfg));
        (addr, token)
    }

    async fn http_get(
        addr: std::net::SocketAddr,
        path: &str,
        token: Option<&str>,
    ) -> (u16, String) {
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

        let mut lines = response.splitn(2, "\r\n");
        let status_line = lines.next().unwrap_or("");
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

        let mut lines = response.splitn(2, "\r\n");
        let status_line = lines.next().unwrap_or("");
        let code: u16 = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let resp_body = response.split("\r\n\r\n").nth(1).unwrap_or("").to_string();

        (code, resp_body)
    }

    /// A minimal config that passes `create_server_configs`: a single socks
    /// inbound with no other clauses (mirrors
    /// `src/config/validate.rs`'s `sniff_shorthand_parses_on_a_server`-style
    /// fixtures, minus the `sniff` field, which isn't needed to be valid).
    const MINIMAL_VALID_CONFIG_YAML: &str =
        "- address: 127.0.0.1:1080\n  protocol:\n    type: socks\n";

    #[test]
    fn minimal_valid_config_fixture_actually_validates() {
        crate::config::validate_config_str(MINIMAL_VALID_CONFIG_YAML)
            .expect("fixture must pass create_server_configs");
    }

    #[tokio::test]
    async fn status_requires_auth() {
        let (addr, token) = spawn().await;
        let unauth = http_get(addr, "/api/status", None).await;
        assert_eq!(unauth.0, 401);
        let ok = http_get(addr, "/api/status", Some(&token)).await;
        assert_eq!(ok.0, 200);
        assert!(ok.1.contains("version"));
    }

    #[tokio::test]
    async fn connections_returns_an_empty_array_initially() {
        let (addr, token) = spawn().await;
        let (code, body) = http_get(addr, "/api/connections", Some(&token)).await;
        assert_eq!(code, 200);
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid json");
        assert!(parsed.is_array());
        assert_eq!(parsed.as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn metrics_returns_prometheus_text() {
        let (addr, token) = spawn().await;
        let (code, body) = http_get(addr, "/api/metrics", Some(&token)).await;
        assert_eq!(code, 200);
        assert!(
            body.contains("shoes_connections_active"),
            "body was: {body}"
        );
    }

    #[tokio::test]
    async fn put_config_with_invalid_body_returns_400_and_leaves_file_unchanged() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), MINIMAL_VALID_CONFIG_YAML).unwrap();
        let before = std::fs::read(file.path()).unwrap();

        let (addr, token) = spawn_with_config_path(file.path().to_path_buf()).await;
        // Not valid JSON at all, so it fails at the JSON-parse step before
        // ever reaching validate_config_str / the filesystem write.
        let (code, body) = http_put(addr, "/api/config", &token, "not json").await;
        assert_eq!(code, 400, "body was: {body}");
        assert!(body.contains("error"));

        let after = std::fs::read(file.path()).unwrap();
        assert_eq!(
            before, after,
            "file must be unchanged on validation failure"
        );
    }

    #[tokio::test]
    async fn put_config_with_invalid_config_returns_400_and_leaves_file_unchanged() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), MINIMAL_VALID_CONFIG_YAML).unwrap();
        let before = std::fs::read(file.path()).unwrap();

        let (addr, token) = spawn_with_config_path(file.path().to_path_buf()).await;
        // Valid JSON, but not a config that `create_server_configs` accepts:
        // a rule referencing a rule-set that was never declared.
        let invalid_config = serde_json::json!([{
            "address": "0.0.0.0:1080",
            "protocol": {"type": "socks"},
            "rules": [{"masks": "0.0.0.0/0", "rule_sets": ["does-not-exist"], "action": "allow"}],
        }]);
        let (code, body) = http_put(addr, "/api/config", &token, &invalid_config.to_string()).await;
        assert_eq!(code, 400, "body was: {body}");
        assert!(body.contains("error"));

        let after = std::fs::read(file.path()).unwrap();
        assert_eq!(
            before, after,
            "file must be unchanged on validation failure"
        );
    }

    /// SSE is long-lived, so we can't `read_to_end` like `http_get` does.
    /// Read only until the header block terminates, then drop the
    /// connection instead of waiting for EOF (which would never come).
    ///
    /// This deliberately does NOT assert that a specific line was delivered
    /// over the wire: `BroadcastLogWriter`'s global ring buffer is
    /// process-global and shared with `api::logsink::tests::
    /// broadcast_log_writer_delivers`, which asserts the ring is empty
    /// before it emits. Constructing a second writer here and emitting a
    /// marker line would race with that assertion under the parallel test
    /// runner. Frame delivery (replay + live tail + lag handling) is
    /// already covered by that unit test; this test only needs to confirm
    /// the route is wired up and returns the right status/headers.
    async fn http_get_sse_headers(
        addr: std::net::SocketAddr,
        path: &str,
        token: &str,
    ) -> (u16, String) {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let request =
            format!("GET {path} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\n\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();

        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let n = tokio::time::timeout(remaining, stream.read(&mut chunk))
                .await
                .expect("timed out waiting for response headers")
                .unwrap();
            assert!(n > 0, "connection closed before headers arrived");
            buf.extend_from_slice(&chunk[..n]);
            if String::from_utf8_lossy(&buf).contains("\r\n\r\n") {
                break;
            }
        }
        let response = String::from_utf8_lossy(&buf).to_string();
        let head = response.split("\r\n\r\n").next().unwrap_or("").to_string();

        let status_line = head.split("\r\n").next().unwrap_or("");
        let code: u16 = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        (code, head)
    }

    #[tokio::test]
    async fn logs_endpoint_returns_event_stream() {
        let (addr, token) = spawn().await;
        let (code, head) = http_get_sse_headers(addr, "/api/logs", &token).await;
        assert_eq!(code, 200, "head was: {head}");
        assert!(
            head.to_lowercase()
                .contains("content-type: text/event-stream"),
            "head was: {head}"
        );
    }

    /// Reads from an already-connected SSE stream until `needle` appears in
    /// the accumulated buffer, or the overall timeout elapses. SSE is an
    /// infinite stream, so `read_to_end` (as `http_get` uses) would hang
    /// forever; this polls incrementally instead.
    async fn read_sse_until(
        stream: &mut tokio::net::TcpStream,
        buf: &mut String,
        needle: &str,
        timeout: std::time::Duration,
    ) {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut chunk = [0u8; 4096];
        while !buf.contains(needle) {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            assert!(
                remaining > std::time::Duration::ZERO,
                "timed out waiting for {needle:?}; buffer so far: {buf}"
            );
            let n = tokio::time::timeout(remaining, stream.read(&mut chunk))
                .await
                .unwrap_or_else(|_| {
                    panic!("timed out waiting for {needle:?}; buffer so far: {buf}")
                })
                .unwrap();
            assert!(
                n > 0,
                "connection closed before {needle:?} arrived; buffer so far: {buf}"
            );
            buf.push_str(&String::from_utf8_lossy(&chunk[..n]));
        }
    }

    #[tokio::test]
    async fn events_stream() {
        let (addr, token) = spawn().await;
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let request =
            format!("GET /api/events HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\n\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();

        let mut buf = String::new();
        let per_phase = std::time::Duration::from_secs(5);

        // The immediate first tick of `tokio::time::interval` fires right
        // after connecting, before any real 5s has elapsed. Its arrival
        // proves the handler has already subscribed to the events channel
        // (subscribe happens before the select loop that produces the
        // tick), which is the precondition for `register()` below to emit
        // an "open" event at all (it only sends when receiver_count() > 0).
        read_sse_until(&mut stream, &mut buf, "\"event\":\"metrics\"", per_phase).await;

        let addr_for_event: std::net::SocketAddr = "127.0.0.1:54321".parse().unwrap();
        let handle = crate::connection_registry::register(addr_for_event, "test");
        buf.clear();
        read_sse_until(&mut stream, &mut buf, "\"event\":\"open\"", per_phase).await;
        assert!(
            buf.contains("54321"),
            "open event should carry our unique client_addr; buffer was: {buf}"
        );

        drop(handle);
        buf.clear();
        read_sse_until(&mut stream, &mut buf, "\"event\":\"close\"", per_phase).await;
    }

    #[tokio::test]
    async fn config_get_put_round_trip() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), MINIMAL_VALID_CONFIG_YAML).unwrap();

        let (addr, token) = spawn_with_config_path(file.path().to_path_buf()).await;

        let (get_code, get_body) = http_get(addr, "/api/config", Some(&token)).await;
        assert_eq!(get_code, 200, "body was: {get_body}");
        let original: serde_yaml::Value = serde_yaml::from_str(MINIMAL_VALID_CONFIG_YAML).unwrap();
        let fetched_as_json: serde_json::Value =
            serde_json::from_str(&get_body).expect("GET body must be valid json");
        let fetched_as_yaml: serde_yaml::Value =
            serde_yaml::from_str(&serde_json::to_string(&fetched_as_json).unwrap()).unwrap();
        assert_eq!(
            original, fetched_as_yaml,
            "GET must be semantically equal to the on-disk config"
        );

        let (put_code, put_body) = http_put(addr, "/api/config", &token, &get_body).await;
        assert_eq!(put_code, 200, "body was: {put_body}");

        let after_text = std::fs::read_to_string(file.path()).unwrap();
        let after: serde_yaml::Value = serde_yaml::from_str(&after_text).unwrap();
        assert_eq!(
            original, after,
            "round-tripped config must be semantically equal to the original"
        );
    }
}
