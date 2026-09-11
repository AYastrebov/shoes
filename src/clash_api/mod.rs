//! A Clash-compatible controller, plus a Prometheus `/metrics` beside it.
//!
//! Reads the connection registry, the outbound registry and the log ring;
//! serves none of it unless a config carries a `clash_api:` block. The
//! module knows nothing about who mounts it -- the CLI does today, and the
//! daemon could -- so it takes its state and a shutdown receiver and runs.
//!
//! See docs/specs/2026-09-09-clash-api.md.
//!
//! `allow(dead_code)` for the reason the connection registry gives: the
//! binary and the library declare their modules separately, and until a host
//! mounts the listener the renderers here have no caller in one of them.
#![allow(dead_code)]

pub mod memory;
pub mod metrics;
pub mod render;

use std::convert::Infallible;
use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{HeaderMap, Method, Request, Response, StatusCode};
use subtle::ConstantTimeEq;

use crate::config::ClashApiConfig;

pub(crate) type ApiBody = http_body_util::combinators::BoxBody<Bytes, Infallible>;

/// The listener ports a dashboard reads out of `/configs`.
///
/// A dashboard shows these as the ports to point a browser at; shoes may
/// have several listeners of one protocol, and the first is the one it can
/// show.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ports {
    pub socks: u16,
    pub http: u16,
    pub mixed: u16,
    pub tun: bool,
}

impl Ports {
    pub fn from_configs(configs: &[crate::config::Config]) -> Self {
        use crate::config::{BindLocation, Config, ServerProxyConfig as P};

        let mut ports = Ports::default();
        for config in configs {
            match config {
                Config::TunServer(_) => ports.tun = true,
                Config::Server(server) => {
                    let BindLocation::Address(addresses) = &server.bind_location else {
                        // A Unix socket has no port to show.
                        continue;
                    };
                    let Some(port) = addresses
                        .iter()
                        .next()
                        .and_then(|a| a.to_socket_addrs().ok())
                        .and_then(|addrs| addrs.first().map(|a| a.port()))
                    else {
                        continue;
                    };
                    let slot = match &server.protocol {
                        P::Socks { .. } => &mut ports.socks,
                        P::Http { .. } => &mut ports.http,
                        P::Mixed { .. } => &mut ports.mixed,
                        _ => continue,
                    };
                    if *slot == 0 {
                        *slot = port;
                    }
                }
                _ => {}
            }
        }
        ports
    }
}

/// Everything a request needs that is not in a registry.
pub struct ApiState {
    pub config: ClashApiConfig,
    pub ports: Ports,
    pub started: std::time::Instant,
    /// The log ring, when one was installed. `None` means `/logs` has
    /// nothing to stream rather than that it is unsupported.
    #[cfg(feature = "control-logs")]
    pub log: Option<Arc<crate::control::logs::BroadcastLogWriter>>,
}

/// Serve until the shutdown receiver fires or its sender is dropped.
pub async fn serve_on(
    listener: tokio::net::TcpListener,
    state: Arc<ApiState>,
    mut shutdown: tokio::sync::oneshot::Receiver<()>,
) -> std::io::Result<()> {
    log::info!("Clash API listening on {}", state.config.listen);
    loop {
        let accepted = tokio::select! {
            result = listener.accept() => result,
            _ = &mut shutdown => {
                log::info!("Clash API on {} stopping", state.config.listen);
                return Ok(());
            }
        };

        let (stream, _peer) = match accepted {
            Ok(v) => v,
            Err(e) => {
                // A failed accept is per-connection; the listener lives on,
                // for the reason the proxy accept loops give.
                log::error!("Clash API accept failed: {e}");
                continue;
            }
        };

        let state = state.clone();
        tokio::spawn(async move {
            let io = hyper_util::rt::TokioIo::new(stream);
            let service = service_fn(move |req| {
                let state = state.clone();
                async move { Ok::<_, Infallible>(route(req, state).await) }
            });
            // `with_upgrades`, so the streaming routes can take the socket.
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .with_upgrades()
                .await;
        });
    }
}

/// A browser cannot set a header on a WebSocket handshake, so a socket may
/// carry the secret as `?token=`; that is what every dashboard sends.
fn authorized(req: &Request<Incoming>, secret: &str) -> bool {
    let is_upgrade = req
        .headers()
        .get(hyper::header::UPGRADE)
        .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"websocket"));
    if is_upgrade && let Some(token) = query_param(req.uri().query(), "token") {
        return token.as_bytes().ct_eq(secret.as_bytes()).into();
    }

    let Some(value) = req
        .headers()
        .get(hyper::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let Some(bearer) = value.strip_prefix("Bearer ") else {
        return false;
    };
    bearer.as_bytes().ct_eq(secret.as_bytes()).into()
}

pub(crate) fn query_param(query: Option<&str>, name: &str) -> Option<String> {
    query?
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_string())
}

/// `*` when no origins are configured, which is what a dashboard served
/// from elsewhere needs; otherwise the request's origin if it is allowed,
/// and nothing at all if it is not.
fn cors_origin(headers: &HeaderMap, allow: &[String]) -> Option<String> {
    if allow.is_empty() {
        return Some("*".to_string());
    }
    let origin = headers.get(hyper::header::ORIGIN)?.to_str().ok()?;
    allow
        .iter()
        .any(|a| a == origin)
        .then(|| origin.to_string())
}

fn with_cors(mut response: Response<ApiBody>, origin: Option<String>) -> Response<ApiBody> {
    if let Some(origin) = origin
        && let Ok(value) = origin.parse()
    {
        let headers = response.headers_mut();
        headers.insert("access-control-allow-origin", value);
        headers.insert(
            "access-control-allow-headers",
            "Authorization, Content-Type".parse().unwrap(),
        );
        headers.insert(
            "access-control-allow-methods",
            "GET, POST, PUT, PATCH, DELETE, OPTIONS".parse().unwrap(),
        );
    }
    response
}

pub(crate) fn body(text: String) -> ApiBody {
    Full::new(Bytes::from(text))
        .map_err(|never| match never {})
        .boxed()
}

pub(crate) fn json(status: StatusCode, value: serde_json::Value) -> Response<ApiBody> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(body(value.to_string()))
        .unwrap()
}

/// Every error body is JSON with a `message`, which is what a dashboard
/// displays.
pub(crate) fn error(status: StatusCode, message: &str) -> Response<ApiBody> {
    json(status, serde_json::json!({ "message": message }))
}

fn empty(status: StatusCode) -> Response<ApiBody> {
    Response::builder()
        .status(status)
        .body(body(String::new()))
        .unwrap()
}

/// Read a request body, bounded. Nothing here needs a large one, and an
/// unbounded read is a way to spend the process's memory from outside.
pub(crate) async fn read_body(req: Request<Incoming>) -> Result<Bytes, Response<ApiBody>> {
    const LIMIT: usize = 64 * 1024;
    let limited = http_body_util::Limited::new(req.into_body(), LIMIT);
    match limited.collect().await {
        Ok(collected) => Ok(collected.to_bytes()),
        Err(_) => Err(error(
            StatusCode::BAD_REQUEST,
            "body too large or unreadable",
        )),
    }
}

pub(crate) async fn route(req: Request<Incoming>, state: Arc<ApiState>) -> Response<ApiBody> {
    let origin = cors_origin(req.headers(), &state.config.allow_origins);

    // Preflight carries no credentials by definition, so it is answered
    // before the secret is checked.
    if req.method() == Method::OPTIONS {
        return with_cors(empty(StatusCode::NO_CONTENT), origin);
    }

    if let Some(secret) = &state.config.secret
        && !authorized(&req, secret)
    {
        return with_cors(error(StatusCode::UNAUTHORIZED, "Unauthorized"), origin);
    }

    let path = req.uri().path().trim_end_matches('/').to_string();
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let response = dispatch(req, &segments, &state).await;
    with_cors(response, origin)
}

async fn dispatch(
    req: Request<Incoming>,
    segments: &[&str],
    state: &Arc<ApiState>,
) -> Response<ApiBody> {
    match (req.method().clone(), segments) {
        (Method::GET, []) => json(StatusCode::OK, render::hello()),
        (Method::GET, ["version"]) => json(StatusCode::OK, render::version()),

        (Method::GET, ["configs"]) => json(StatusCode::OK, render::configs(state)),
        (Method::PATCH, ["configs"]) => {
            // `mode` gets meaning in the selection slice. Until then every
            // field is accepted and ignored, so a dashboard writing
            // log-level does not see an error it cannot act on.
            let _ = read_body(req).await;
            empty(StatusCode::NO_CONTENT)
        }
        // Config reload is the file watcher's job, and a SIGHUP's.
        (Method::PUT, ["configs"]) => error(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed"),

        (Method::GET, ["proxies"]) => json(StatusCode::OK, render::proxies(false)),
        (Method::GET, ["group"]) => json(StatusCode::OK, render::proxies(true)),
        (Method::GET, ["proxies", name]) | (Method::GET, ["group", name]) => {
            match render::proxy(name) {
                Some(proxy) => json(StatusCode::OK, proxy),
                None => error(StatusCode::NOT_FOUND, "proxy not found"),
            }
        }
        // Selecting a member needs a selectable group, which is the next
        // slice. Refusing honestly beats a fake success.
        (Method::PUT, ["proxies", _]) | (Method::DELETE, ["proxies", _]) => {
            error(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed")
        }

        (Method::GET, ["rules"]) => json(StatusCode::OK, render::rules()),

        (Method::GET, ["connections"]) => json(StatusCode::OK, render::connections()),
        (Method::DELETE, ["connections"]) => {
            crate::connection_registry::close_all();
            empty(StatusCode::NO_CONTENT)
        }
        (Method::DELETE, ["connections", id]) => match id.parse::<u64>() {
            Ok(id) if crate::connection_registry::close(id) => empty(StatusCode::NO_CONTENT),
            _ => error(StatusCode::NOT_FOUND, "connection not found"),
        },

        (Method::GET, ["metrics"]) => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain; version=0.0.4; charset=utf-8")
            .body(body(metrics::render()))
            .unwrap(),

        // A route that exists with another method says so; everything else
        // is absent, which is what makes a dashboard hide the panel rather
        // than retry.
        (_, [])
        | (_, ["version"])
        | (_, ["configs"])
        | (_, ["proxies", ..])
        | (_, ["group", ..])
        | (_, ["rules"])
        | (_, ["connections", ..])
        | (_, ["metrics"]) => error(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed"),
        _ => error(StatusCode::NOT_FOUND, "Not Found"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(yaml: &str) -> Vec<crate::config::Config> {
        serde_yaml::from_str(yaml).unwrap()
    }

    #[test]
    fn ports_are_taken_from_the_first_listener_of_each_kind() {
        let configs = config(
            "
- address: 127.0.0.1:1080
  protocol:
    type: socks
- address: 127.0.0.1:1081
  protocol:
    type: socks
- address: 127.0.0.1:8080
  protocol:
    type: http
",
        );
        let ports = Ports::from_configs(&configs);
        assert_eq!(ports.socks, 1080, "the first, not the last");
        assert_eq!(ports.http, 8080);
        assert_eq!(ports.mixed, 0, "none configured");
        assert!(!ports.tun);
    }

    /// A Unix-socket listener has no port a dashboard can show, and must
    /// not be reported as port 0 of a TCP listener that does not exist.
    #[test]
    fn a_unix_socket_listener_contributes_no_port() {
        let configs = config(
            "
- path: /run/shoes.sock
  protocol:
    type: socks
",
        );
        assert_eq!(Ports::from_configs(&configs), Ports::default());
    }

    #[test]
    fn a_query_parameter_is_found_among_others() {
        assert_eq!(
            query_param(Some("level=debug&token=s"), "token").as_deref(),
            Some("s")
        );
        assert_eq!(query_param(Some("level=debug"), "token"), None);
        assert_eq!(query_param(None, "token"), None);
    }

    #[test]
    fn cors_allows_everything_by_default_and_only_the_listed_otherwise() {
        let mut headers = HeaderMap::new();
        headers.insert(hyper::header::ORIGIN, "http://a.example".parse().unwrap());

        assert_eq!(cors_origin(&headers, &[]).as_deref(), Some("*"));
        assert_eq!(
            cors_origin(&headers, &["http://a.example".to_string()]).as_deref(),
            Some("http://a.example")
        );
        assert_eq!(
            cors_origin(&headers, &["http://b.example".to_string()]),
            None
        );
        // No Origin header at all, with a list configured: nothing to allow.
        assert_eq!(
            cors_origin(&HeaderMap::new(), &["http://a.example".to_string()]),
            None
        );
    }
}
