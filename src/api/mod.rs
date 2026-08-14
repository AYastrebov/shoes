//! Feature-gated HTTP control API for a management panel.
pub mod config_section;
pub mod handlers;
// logsink module added in a later task

use std::convert::Infallible;
use std::sync::Arc;

use http_body_util::Full;
use hyper::body::Bytes;
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

async fn serve_on(
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

pub(crate) fn json(status: StatusCode, body: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

async fn route(req: Request<hyper::body::Incoming>, state: Arc<ApiState>) -> Response<Full<Bytes>> {
    if !authorized(req.headers(), &state.token) {
        return json(
            StatusCode::UNAUTHORIZED,
            r#"{"error":"unauthorized"}"#.to_string(),
        );
    }
    match (req.method(), req.uri().path()) {
        (&hyper::Method::GET, "/api/status") => handlers::status(&state),
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
        let token = "test-token".to_string();
        let cfg = ControlApiConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            token: token.clone(),
            config_path: "/nonexistent".into(),
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

    #[tokio::test]
    async fn status_requires_auth() {
        let (addr, token) = spawn().await;
        let unauth = http_get(addr, "/api/status", None).await;
        assert_eq!(unauth.0, 401);
        let ok = http_get(addr, "/api/status", Some(&token)).await;
        assert_eq!(ok.0, 200);
        assert!(ok.1.contains("version"));
    }
}
