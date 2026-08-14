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

pub(crate) fn connections(_state: &ApiState) -> Response<Full<Bytes>> {
    let snap = crate::connection_registry::snapshot();
    super::json(StatusCode::OK, serde_json::to_string(&snap).unwrap())
}

pub(crate) fn metrics(_state: &ApiState) -> Response<Full<Bytes>> {
    // O(1): read the global counters, do NOT scan the connection map. Byte
    // totals are cumulative over closed connections (a still-open connection's
    // bytes are attributed when it closes), which is correct counter semantics.
    let m = crate::connection_registry::metrics_counters();
    let body = format!(
        "# TYPE shoes_connections_active gauge\nshoes_connections_active {}\n\
         # TYPE shoes_connections_total counter\nshoes_connections_total {}\n\
         # TYPE shoes_up_bytes_total counter\nshoes_up_bytes_total {}\n\
         # TYPE shoes_down_bytes_total counter\nshoes_down_bytes_total {}\n",
        m.active_connections, m.total_connections, m.total_up_bytes, m.total_down_bytes,
    );
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/plain; version=0.0.4")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

pub(crate) fn get_config(state: &ApiState) -> Response<Full<Bytes>> {
    match std::fs::read_to_string(&state.config_path) {
        Ok(text) => match serde_yaml::from_str::<serde_yaml::Value>(&text) {
            // A hand-edited config with non-string YAML map keys serializes to
            // no valid JSON; return 500 rather than panicking the handler.
            Ok(value) => match serde_json::to_string(&value) {
                Ok(json) => super::json(StatusCode::OK, json),
                Err(e) => super::json(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    serde_json::json!({"error": format!("stored config is not representable as json: {e}")})
                        .to_string(),
                ),
            },
            Err(e) => super::json(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({"error": format!("stored config is not valid yaml: {e}")})
                    .to_string(),
            ),
        },
        Err(e) => super::json(
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({"error": format!("cannot read config: {e}")}).to_string(),
        ),
    }
}

pub(crate) async fn put_config(state: &ApiState, body: Bytes) -> Response<Full<Bytes>> {
    // 1. JSON body -> yaml text.
    let value: serde_yaml::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return super::json(
                StatusCode::BAD_REQUEST,
                serde_json::json!({"error": format!("invalid json: {e}")}).to_string(),
            );
        }
    };
    let yaml_text = match serde_yaml::to_string(&value) {
        Ok(t) => t,
        Err(e) => {
            return super::json(
                StatusCode::BAD_REQUEST,
                serde_json::json!({"error": format!("cannot serialize: {e}")}).to_string(),
            );
        }
    };
    // 2. Validate by parsing through the real config loader against the yaml text.
    if let Err(e) = crate::config::validate_config_str(&yaml_text) {
        return super::json(
            StatusCode::BAD_REQUEST,
            serde_json::json!({"error": format!("invalid config: {e}")}).to_string(),
        );
    }
    // 3. Atomic write: temp file in the same dir + rename; the file watcher reloads.
    if let Err(e) = atomic_write(&state.config_path, yaml_text.as_bytes()) {
        return super::json(
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({"error": format!("write failed: {e}")}).to_string(),
        );
    }
    super::json(StatusCode::OK, r#"{"status":"applied"}"#.to_string())
}

fn atomic_write(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    std::io::Write::write_all(&mut tmp, bytes)?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}
