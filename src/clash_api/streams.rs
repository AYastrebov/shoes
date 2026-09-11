//! The four producers, and the chunked fallback.
//!
//! Each producer is written against [`Sink`], so the same body serves a
//! WebSocket and a plain `GET`. mihomo serves both, and dashboards use the
//! first while scripts use the second.

use std::sync::Arc;
use std::time::Duration;

use super::ws::Sink;
use super::{ApiState, render};

/// Send `tick()`'s frame every `every` until the client goes away or the
/// controller does.
async fn periodic<S: Sink, F: FnMut() -> String + Send>(
    state: &ApiState,
    mut sink: S,
    every: Duration,
    mut tick: F,
) {
    let mut interval = tokio::time::interval(every);
    loop {
        tokio::select! {
            _ = interval.tick() => {
                if sink.send(&tick()).await.is_err() {
                    return;
                }
            }
            () = sink.closed() => return,
            // The controller stopping -- a reload that changed its secret
            // or its listen, or dropped the block -- ends every stream it
            // served: a subscriber that authenticated with the old secret
            // must not outlive it.
            () = state.shutdown.cancelled() => {
                sink.close().await;
                return;
            }
        }
    }
}

/// Bytes since the last tick. The first frame is zero, which is what a
/// dashboard's graph starts from.
pub async fn traffic<S: Sink>(state: Arc<ApiState>, sink: S) {
    let mut last = crate::connection_registry::totals();
    periodic(&state, sink, Duration::from_secs(1), move || {
        let now = crate::connection_registry::totals();
        let frame = serde_json::json!({
            "up": now.up.saturating_sub(last.up),
            "down": now.down.saturating_sub(last.down),
        });
        // A reading taken between an entry leaving the table and its bytes
        // being folded into the totals is short by that connection. The
        // mark keeps the higher value, so the next tick reports what moved
        // since, rather than that connection's whole life again.
        last.up = last.up.max(now.up);
        last.down = last.down.max(now.down);
        frame.to_string()
    })
    .await
}

pub async fn memory<S: Sink>(state: Arc<ApiState>, sink: S) {
    periodic(&state, sink, Duration::from_secs(1), || {
        // `oslimit` is mihomo's cap on itself; shoes has none to report.
        serde_json::json!({ "inuse": super::memory::rss(), "oslimit": 0 }).to_string()
    })
    .await
}

pub async fn connections<S: Sink>(state: Arc<ApiState>, sink: S, interval_ms: u64) {
    periodic(
        &state,
        sink,
        // Clamped: a dashboard asking for a millisecond would have the
        // process render the whole table a thousand times a second.
        Duration::from_millis(interval_ms.clamp(100, 60_000)),
        || render::connections().to_string(),
    )
    .await
}

fn level_name(level: log::Level) -> &'static str {
    match level {
        log::Level::Error => "error",
        log::Level::Warn => "warning",
        log::Level::Info => "info",
        log::Level::Debug | log::Level::Trace => "debug",
    }
}

fn level_filter(name: &str) -> Option<log::LevelFilter> {
    Some(match name {
        "silent" => log::LevelFilter::Off,
        "error" => log::LevelFilter::Error,
        "warning" => log::LevelFilter::Warn,
        "info" => log::LevelFilter::Info,
        // sing-box accepts `trace` and awg-manager sends it; mihomo does
        // not, and shoes compiles Trace out of a release build, so it is an
        // alias rather than a fifth level.
        "debug" | "trace" => log::LevelFilter::Debug,
        _ => return None,
    })
}

/// `?level=`, defaulting to `info`. `None` is a level nobody defines.
pub fn parse_level(query: Option<&str>) -> Option<log::LevelFilter> {
    match super::query_param(query, "level") {
        None => Some(log::LevelFilter::Info),
        Some(name) => level_filter(&name),
    }
}

/// sing-box writes `inbound/mixed[tag]: message`, and awg-manager's log
/// classifier (`internal/singbox/logs.go`) splits on that shape to file a
/// line under inbound, outbound, dns, router or runtime. The spec's table
/// under "Logs" is the source of truth for this mapping.
pub fn category_for(target: &str) -> (&'static str, &str) {
    let t = target.strip_prefix("shoes::").unwrap_or(target);
    let category = if t.starts_with("tcp::tcp_server")
        || t.starts_with("quic_server")
        || t.starts_with("hysteria2::server")
        || t.starts_with("tuic::server")
        || t.ends_with("_handler")
        || t.starts_with("tun")
    {
        "inbound"
    } else if t.starts_with("client_proxy_chain")
        || t.starts_with("tcp::proxy_connector")
        || t.starts_with("tcp::socket_connector")
        || t.ends_with("::client")
        || t.starts_with("amneziawg")
        || t.starts_with("quic_outbound")
    {
        "outbound"
    } else if t.starts_with("dns") {
        "dns"
    } else if t.starts_with("client_proxy_selector")
        || t.starts_with("routing")
        || t.starts_with("rule_set")
        || t.starts_with("sniff")
    {
        "router"
    } else {
        "runtime"
    };
    // An unmapped target keeps its own name as the tag, so nothing is
    // hidden behind a category it did not earn.
    let tag = if category == "runtime" { target } else { "" };
    (category, tag)
}

/// The backlog, then everything after it.
///
/// A subscriber that falls behind the ring is disconnected rather than
/// buffered without bound: a log stream must not be able to grow the
/// process it is reporting on.
pub async fn logs<S: Sink>(state: Arc<ApiState>, filter: log::LevelFilter, mut sink: S) {
    let Some(ring) = state.log.clone() else {
        return;
    };
    let (backlog, mut rx) = ring.subscribe();

    let frame = |line: &crate::control::logs::LogLine| {
        let (category, tag) = category_for(&line.target);
        serde_json::json!({
            "type": level_name(line.level),
            "payload": format!("{category}[{tag}]: {}", line.message),
        })
        .to_string()
    };

    for line in backlog.iter().filter(|l| l.level <= filter) {
        if sink.send(&frame(line)).await.is_err() {
            return;
        }
    }

    loop {
        tokio::select! {
            next = rx.recv() => match next {
                Ok(line) if line.level <= filter => {
                    if sink.send(&frame(&line)).await.is_err() {
                        return;
                    }
                }
                Ok(_) => {}
                Err(_) => return,
            },
            () = sink.closed() => return,
            () = state.shutdown.cancelled() => {
                sink.close().await;
                return;
            }
        }
    }
}

/// The chunked fallback: JSON lines on a plain `GET`.
pub struct ChunkedSink {
    tx: tokio::sync::mpsc::Sender<
        Result<hyper::body::Frame<hyper::body::Bytes>, std::convert::Infallible>,
    >,
}

impl Sink for ChunkedSink {
    async fn send(&mut self, text: &str) -> std::io::Result<()> {
        let mut line = text.to_string();
        line.push('\n');
        self.tx
            .send(Ok(hyper::body::Frame::data(hyper::body::Bytes::from(line))))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "client went away"))
    }

    /// Resolves when hyper drops the body, which it does when the client
    /// disconnects.
    async fn closed(&mut self) {
        self.tx.closed().await
    }

    /// Nothing to say: dropping the sender ends the body, which is how a
    /// chunked response ends.
    async fn close(&mut self) {}
}

pub fn chunked<F, Fut>(run: F) -> hyper::Response<super::ApiBody>
where
    F: FnOnce(ChunkedSink) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    use http_body_util::{BodyExt, StreamBody};

    let (tx, rx) = tokio::sync::mpsc::channel(8);
    tokio::spawn(run(ChunkedSink { tx }));
    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);

    hyper::Response::builder()
        .status(hyper::StatusCode::OK)
        .header("content-type", "application/json")
        .header("cache-control", "no-cache")
        .body(StreamBody::new(stream).boxed())
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_map_onto_the_categories_a_sing_box_client_expects() {
        assert_eq!(category_for("shoes::tcp::tcp_server").0, "inbound");
        assert_eq!(category_for("shoes::socks_handler").0, "inbound");
        assert_eq!(category_for("shoes::client_proxy_chain").0, "outbound");
        assert_eq!(category_for("shoes::dns::hickory_resolver").0, "dns");
        assert_eq!(category_for("shoes::client_proxy_selector").0, "router");
        assert_eq!(
            category_for("shoes"),
            ("runtime", "shoes"),
            "an unmapped target keeps its name"
        );
    }

    #[test]
    fn levels_parse_including_the_sing_box_alias() {
        assert_eq!(parse_level(None), Some(log::LevelFilter::Info));
        assert_eq!(
            parse_level(Some("level=trace")),
            Some(log::LevelFilter::Debug),
            "sing-box's trace is debug here"
        );
        assert_eq!(
            parse_level(Some("level=silent")),
            Some(log::LevelFilter::Off)
        );
        assert_eq!(parse_level(Some("level=shouting")), None);
    }

    #[test]
    fn level_names_are_the_ones_a_dashboard_filters_on() {
        assert_eq!(level_name(log::Level::Warn), "warning");
        assert_eq!(level_name(log::Level::Trace), "debug");
    }
}
