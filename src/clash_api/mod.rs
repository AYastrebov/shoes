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

pub mod logs;
pub mod memory;
pub mod metrics;
pub mod render;
pub mod streams;
pub mod ws;

use std::convert::Infallible;
use std::net::SocketAddr;
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
    /// Behind a lock: a reload that keeps this controller -- same listen,
    /// same secret -- may still have moved the proxies' ports.
    pub ports: parking_lot::RwLock<Ports>,
    pub started: std::time::Instant,
    /// Cancelled when the controller stops. Every stream it served ends on
    /// it, close frame first, and so does every connection still being
    /// read: stopping the listener alone would leave a subscriber that
    /// authenticated with a rotated secret streaming indefinitely.
    pub shutdown: tokio_util::sync::CancellationToken,
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
                // The streams and the connections go with the listener; see
                // `ApiState::shutdown`.
                state.shutdown.cancel();
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
            let stopping = state.shutdown.clone();
            let service = service_fn(move |req| {
                let state = state.clone();
                async move { Ok::<_, Infallible>(route(req, state).await) }
            });
            // A timer, so hyper's header-read timeout is in force: without
            // one it is silently off, and a client that connects and says
            // nothing holds a task for as long as it likes, before any
            // secret is checked. `with_upgrades`, so the streaming routes
            // can take the socket.
            let connection = hyper::server::conn::http1::Builder::new()
                .timer(hyper_util::rt::TokioTimer::new())
                .serve_connection(io, service)
                .with_upgrades();
            tokio::select! {
                result = connection => {
                    let _ = result;
                }
                () = stopping.cancelled() => {}
            }
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

/// mihomo streams `/connections` on a plain GET only when asked for an
/// interval; the one-shot is the default.
fn wants_stream(req: &Request<Incoming>) -> bool {
    query_param(req.uri().query(), "interval").is_some()
}

pub(crate) fn query_param(query: Option<&str>, name: &str) -> Option<String> {
    query?
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| percent_decode(v, true))
}

/// `%XX` escapes undone, and `+` read as a space where the text is a
/// form-encoded query. mihomo decodes both -- Go's `URL.Query` for a token,
/// `PathUnescape` for a proxy name -- and a dashboard escapes what it puts
/// in a URL, so a secret with a `+` or an outbound named with a space or
/// a flag arrives here escaped and must be compared unescaped.
pub(crate) fn percent_decode(raw: &str, plus_is_space: bool) -> String {
    fn hex(b: u8) -> Option<u8> {
        (b as char).to_digit(16).map(|d| d as u8)
    }
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => match (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                (Some(hi), Some(lo)) => {
                    out.push(hi << 4 | lo);
                    i += 3;
                }
                // Not an escape: kept as written, like Go does on a
                // malformed one it is lenient about.
                _ => {
                    out.push(b'%');
                    i += 1;
                }
            },
            b'+' if plus_is_space => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The origin a response may be read from in a browser, or none.
///
/// With origins configured, the request's origin if it is on the list. With
/// none configured, `*`, which a dashboard served from elsewhere needs --
/// but only when a secret is set. A controller with no secret relies on the
/// browser's same-origin policy to keep other sites' scripts out, and `*`
/// is exactly the header that switches that policy off: any page the user
/// had open could then read the connection table from `127.0.0.1:9090` and
/// send the `PUT`s and `DELETE`s that preflight would otherwise refuse. So
/// no secret and no list means no CORS header at all, and a dashboard on
/// another origin needs a secret first. `browser_permitted` is the other
/// half of that policy, for the requests CORS does not cover.
fn cors_origin(headers: &HeaderMap, allow: &[String], has_secret: bool) -> Option<String> {
    if allow.is_empty() {
        return has_secret.then(|| "*".to_string());
    }
    let origin = headers.get(hyper::header::ORIGIN)?.to_str().ok()?;
    allow
        .iter()
        .any(|a| a == origin)
        .then(|| origin.to_string())
}

/// Whether a request may reach a controller that has no secret.
///
/// Withholding the CORS header (`cors_origin`) keeps a page on another
/// origin from reading a `fetch`, but that is not enough on its own:
///
/// - A WebSocket is not subject to the same-origin policy. The browser
///   opens one to any origin and hands the page every frame, so without an
///   origin check any page could stream `/connections` or `/logs`.
/// - DNS rebinding turns a foreign page into a same-origin one. A page
///   served from `evil.example` whose name is then resolved to `127.0.0.1`
///   reaches the loopback listener with `Host: evil.example:9090`, and its
///   same-origin `GET` carries no `Origin` at all. So an `Origin` that
///   matches `Host` proves nothing, and neither does the absence of one.
///
/// Hence two rules, checked on every request without a secret. The `Host`
/// must be one of the controller's own names: the listen address, or
/// `localhost` or a loopback literal with its port -- a rebinding page
/// cannot produce those, and a secretless listener is loopback by
/// validation. Then an `Origin`, if there is one, must be on
/// `allow_origins` or be the controller's own, which after the first rule
/// is a page the controller served itself. A request with no `Origin` is a
/// non-browser client (awg-manager, `curl`, a tunnelled dashboard's
/// server) or a same-origin one, and passes; one with no `Host` is not a
/// browser's either. The set this admits is the set `cors_origin` would
/// answer, so no working dashboard loses anything. With a secret the
/// secret decides, and none of this runs.
fn browser_permitted(headers: &HeaderMap, listen: SocketAddr, allow: &[String]) -> bool {
    if let Some(host) = headers.get(hyper::header::HOST) {
        let Ok(host) = host.to_str() else {
            return false;
        };
        let port = listen.port();
        let own = [
            listen.to_string(),
            format!("localhost:{port}"),
            format!("127.0.0.1:{port}"),
            format!("[::1]:{port}"),
        ];
        if !own.iter().any(|o| o.eq_ignore_ascii_case(host)) {
            return false;
        }
    }
    let Some(origin) = headers.get(hyper::header::ORIGIN) else {
        return true;
    };
    let Ok(origin) = origin.to_str() else {
        return false;
    };
    if allow.iter().any(|a| a == origin) {
        return true;
    }
    // The controller's own origin, now that `Host` is known to be its own
    // name: a page it served itself. Nothing else can carry it, since a
    // browser sets both headers and a page cannot.
    let Some(host) = headers
        .get(hyper::header::HOST)
        .and_then(|h| h.to_str().ok())
    else {
        return false;
    };
    origin.split_once("://").is_some_and(|(scheme, authority)| {
        scheme.eq_ignore_ascii_case("http") && authority.eq_ignore_ascii_case(host)
    })
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
    let origin = cors_origin(
        req.headers(),
        &state.config.allow_origins,
        state.config.secret.is_some(),
    );

    // Without a secret the browser rules are the access control, and they
    // apply to a preflight too: an origin refused here is one `cors_origin`
    // would not have answered, so the refusal carries no CORS header.
    if state.config.secret.is_none()
        && !browser_permitted(
            req.headers(),
            state.config.listen,
            &state.config.allow_origins,
        )
    {
        return error(StatusCode::FORBIDDEN, "Forbidden");
    }

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
            // Escaped on the wire: hyper refuses a non-ASCII request line,
            // so a name with a flag or a space only ever arrives this way.
            match render::proxy(&percent_decode(name, false)) {
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

        // The streaming routes come first: a dashboard opens them as
        // WebSockets, and mihomo also serves them as chunked JSON lines on a
        // plain GET. Two arms each, because the two sinks are different
        // types and a producer is generic over them.
        (Method::GET, ["traffic"]) => {
            let state = state.clone();
            if ws::is_upgrade(&req) {
                ws::upgrade(req, move |sink| streams::traffic(state, sink))
            } else {
                streams::chunked(move |sink| streams::traffic(state, sink))
            }
        }

        (Method::GET, ["memory"]) => {
            let state = state.clone();
            if ws::is_upgrade(&req) {
                ws::upgrade(req, move |sink| streams::memory(state, sink))
            } else {
                streams::chunked(move |sink| streams::memory(state, sink))
            }
        }

        (Method::GET, ["logs"]) => {
            let Some(filter) = streams::parse_level(req.uri().query()) else {
                return error(StatusCode::BAD_REQUEST, "unknown level");
            };
            let state = state.clone();
            if ws::is_upgrade(&req) {
                ws::upgrade(req, move |sink| streams::logs(state, filter, sink))
            } else {
                streams::chunked(move |sink| streams::logs(state, filter, sink))
            }
        }

        // `/connections` is a snapshot unless asked to stream: a dashboard's
        // list fetch must not become a subscription.
        (Method::GET, ["connections"]) if ws::is_upgrade(&req) || wants_stream(&req) => {
            let interval = query_param(req.uri().query(), "interval")
                .and_then(|s| s.parse().ok())
                .unwrap_or(1000);
            let state = state.clone();
            if ws::is_upgrade(&req) {
                ws::upgrade(req, move |sink| streams::connections(state, sink, interval))
            } else {
                streams::chunked(move |sink| streams::connections(state, sink, interval))
            }
        }
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
        | (_, ["traffic"])
        | (_, ["memory"])
        | (_, ["logs"])
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

    /// What a dashboard's `encodeURIComponent` makes of a secret or a name
    /// has to compare equal to what the config holds.
    #[test]
    fn escapes_are_undone_the_way_a_browser_made_them() {
        assert_eq!(
            query_param(Some("token=p%2Bq+r%20s"), "token").as_deref(),
            Some("p+q r s"),
            "a query is form-encoded: `+` is a space, `%2B` is a plus"
        );
        assert_eq!(
            percent_decode("%F0%9F%87%AF%F0%9F%87%B5+Tokyo", false),
            "\u{1F1EF}\u{1F1F5}+Tokyo",
            "a path is not form-encoded: `+` stays"
        );
        assert_eq!(percent_decode("100%", false), "100%", "a stray `%` is kept");
        assert_eq!(
            percent_decode("%zz", false),
            "%zz",
            "and so is a malformed escape"
        );
    }

    #[test]
    fn cors_allows_everything_by_default_with_a_secret_and_only_the_listed_otherwise() {
        let mut headers = HeaderMap::new();
        headers.insert(hyper::header::ORIGIN, "http://a.example".parse().unwrap());

        assert_eq!(cors_origin(&headers, &[], true).as_deref(), Some("*"));
        assert_eq!(
            cors_origin(&headers, &["http://a.example".to_string()], true).as_deref(),
            Some("http://a.example")
        );
        assert_eq!(
            cors_origin(&headers, &["http://b.example".to_string()], true),
            None
        );
        // No Origin header at all, with a list configured: nothing to allow.
        assert_eq!(
            cors_origin(&HeaderMap::new(), &["http://a.example".to_string()], true),
            None
        );
    }

    /// Without a secret the browser's same-origin policy is the only thing
    /// between another site's script and the controller, and `*` would turn
    /// it off. An explicit list is still honoured: the operator chose it.
    #[test]
    fn cors_never_answers_star_without_a_secret() {
        let mut headers = HeaderMap::new();
        headers.insert(hyper::header::ORIGIN, "http://a.example".parse().unwrap());

        assert_eq!(cors_origin(&headers, &[], false), None);
        assert_eq!(
            cors_origin(&headers, &["http://a.example".to_string()], false).as_deref(),
            Some("http://a.example")
        );
    }

    /// Without a secret, `Host` must be one of the controller's own names
    /// and an origin must be listed or the controller's own; a request
    /// with no origin is not a browser's, or is a same-origin one.
    #[test]
    fn without_a_secret_only_an_own_host_and_a_listed_or_own_origin_pass() {
        let listen: SocketAddr = "127.0.0.1:9090".parse().unwrap();
        let allow = vec!["http://a.example".to_string()];
        let with = |origin: Option<&str>, host: Option<&str>| {
            let mut headers = HeaderMap::new();
            if let Some(origin) = origin {
                headers.insert(hyper::header::ORIGIN, origin.parse().unwrap());
            }
            if let Some(host) = host {
                headers.insert(hyper::header::HOST, host.parse().unwrap());
            }
            headers
        };
        let ok = |origin, host| browser_permitted(&with(origin, host), listen, &allow);

        // Non-browser clients, and the names a browser reaches loopback by.
        assert!(ok(None, None));
        assert!(ok(None, Some("127.0.0.1:9090")));
        assert!(ok(None, Some("localhost:9090")));
        assert!(ok(None, Some("LOCALHOST:9090")));
        assert!(ok(None, Some("[::1]:9090")));
        // A listed origin, and the controller's own.
        assert!(ok(Some("http://a.example"), Some("127.0.0.1:9090")));
        assert!(ok(Some("http://127.0.0.1:9090"), Some("127.0.0.1:9090")));
        assert!(ok(Some("http://localhost:9090"), Some("localhost:9090")));

        // A foreign origin, listed or not.
        assert!(!ok(Some("http://b.example"), Some("127.0.0.1:9090")));
        assert!(!browser_permitted(
            &with(Some("http://b.example"), Some("127.0.0.1:9090")),
            listen,
            &[]
        ));
        // A controller serves no TLS, so an `https` origin with its own
        // authority is another site.
        assert!(!ok(Some("https://127.0.0.1:9090"), Some("127.0.0.1:9090")));
        assert!(!ok(Some("null"), Some("127.0.0.1:9090")));
        // DNS rebinding: a foreign name resolved to loopback. The origin
        // matches the host, and the same-origin GET has no origin at all;
        // the host gives both away.
        assert!(!ok(
            Some("http://evil.example:9090"),
            Some("evil.example:9090")
        ));
        assert!(!ok(None, Some("evil.example:9090")));
        // Another port on loopback is another origin, not this controller.
        assert!(!ok(None, Some("127.0.0.1:9091")));
        assert!(!ok(Some("http://127.0.0.1:9090"), None));
    }
}
