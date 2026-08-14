use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Response, StatusCode};

use super::ApiState;

pub(crate) fn status(state: &ApiState) -> Response<Full<Bytes>> {
    let body = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_secs": state.started.elapsed().as_secs(),
        "connections": crate::connection_registry::snapshot().len(),
    });
    super::json(StatusCode::OK, body.to_string())
}
