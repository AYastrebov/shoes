use async_trait::async_trait;
use aws_lc_rs::digest::{SHA1_FOR_LEGACY_USE_ONLY, digest};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rustc_hash::FxHashMap;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

use super::early_data::{self, EarlyData, EarlyDataStream};
use super::websocket_stream::WebsocketStream;
use crate::address::ResolvedLocation;
use crate::async_stream::AsyncMessageStream;
use crate::async_stream::AsyncStream;
use crate::config::WebsocketPingType;
use crate::http_parse::{ParsedHttpData, parse_request_line};
use crate::prepend_stream::PrependStream;
use crate::tcp::tcp_handler::{
    TcpClientHandler, TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult,
};

#[derive(Debug)]
pub struct WebsocketServerTarget {
    pub matching_path: Option<String>,
    pub matching_headers: Option<FxHashMap<String, String>>,
    pub ping_type: WebsocketPingType,
    /// With `header_name` lowercased. In path mode `matching_path` is a
    /// prefix, `/` if unset, and the rest of the request target is the data.
    pub early_data: Option<EarlyData>,
    pub handler: Box<dyn TcpServerHandler>,
}

#[derive(Debug)]
pub struct WebsocketTcpServerHandler {
    server_targets: Vec<WebsocketServerTarget>,
}

impl WebsocketTcpServerHandler {
    pub fn new(server_targets: Vec<WebsocketServerTarget>) -> Self {
        Self { server_targets }
    }
}

/// Refuse a handshake with `status` and close: RFC 6455 section 4.2.1 has the
/// server answer an invalid one with an HTTP error, not silence.
async fn refuse(
    stream: &mut Box<dyn AsyncStream>,
    status: &str,
    extra_headers: &str,
    reason: String,
) -> std::io::Error {
    let response = format!(
        "HTTP/1.1 {status}\r\n{extra_headers}Content-Length: 0\r\nConnection: close\r\n\r\n"
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.flush().await;
    std::io::Error::other(reason)
}

/// Whether a comma-separated header such as `Connection: keep-alive, Upgrade`
/// carries `token`.
fn header_has_token(
    headers: &std::collections::HashMap<String, String>,
    key: &str,
    token: &str,
) -> bool {
    headers.get(key).is_some_and(|value| {
        value
            .split(',')
            .any(|item| item.trim().eq_ignore_ascii_case(token))
    })
}

#[async_trait]
impl TcpServerHandler for WebsocketTcpServerHandler {
    async fn setup_server_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let ParsedHttpData {
            first_line,
            headers: mut request_headers,
            stream_reader,
        } = ParsedHttpData::parse(&mut server_stream).await?;

        let Some((method, request_path)) = parse_request_line(&first_line) else {
            return Err(refuse(
                &mut server_stream,
                "400 Bad Request",
                "",
                format!("invalid http request line: {first_line}"),
            )
            .await);
        };

        if method != "GET" {
            return Err(refuse(
                &mut server_stream,
                "400 Bad Request",
                "",
                format!("invalid http request method: {method}"),
            )
            .await);
        }

        // RFC 6455 section 4.2.1, items 3 to 6.
        if !header_has_token(&request_headers, "upgrade", "websocket")
            || !header_has_token(&request_headers, "connection", "upgrade")
        {
            return Err(refuse(
                &mut server_stream,
                "400 Bad Request",
                "",
                "not a websocket upgrade request".to_string(),
            )
            .await);
        }
        if request_headers
            .get("sec-websocket-version")
            .map(|v| v.trim())
            != Some("13")
        {
            // Section 4.4: name the version this server speaks.
            return Err(refuse(
                &mut server_stream,
                "426 Upgrade Required",
                "Sec-WebSocket-Version: 13\r\n",
                "unsupported websocket version".to_string(),
            )
            .await);
        }
        let Some(websocket_key) = request_headers.remove("sec-websocket-key") else {
            return Err(refuse(
                &mut server_stream,
                "400 Bad Request",
                "",
                "missing websocket key header".to_string(),
            )
            .await);
        };

        let mut path_early_data = None;
        let target = self.server_targets.iter().find(|target| {
            let in_path = match &target.early_data {
                Some(EarlyData {
                    header_name: None, ..
                }) => {
                    let prefix = target.matching_path.as_deref().unwrap_or("/");
                    let Some(rest) = request_path.strip_prefix(prefix) else {
                        return false;
                    };
                    // A query is not data; sing-box would fail to decode it.
                    Some(rest.split_once('?').map_or(rest, |(data, _)| data))
                }
                _ => {
                    if let Some(path) = &target.matching_path
                        && path != request_path
                    {
                        return false;
                    }
                    None
                }
            };
            let matched = target.matching_headers.as_ref().is_none_or(|headers| {
                headers
                    .iter()
                    .all(|(key, value)| request_headers.get(key) == Some(value))
            });
            if matched {
                path_early_data = in_path;
            }
            matched
        });
        let Some(WebsocketServerTarget {
            ping_type,
            early_data: target_early_data,
            handler,
            ..
        }) = target
        else {
            // As the HTTPUpgrade server does, and sing-box: an unknown path
            // is not found.
            return Err(refuse(
                &mut server_stream,
                "404 Not Found",
                "",
                "No matching websocket targets".to_string(),
            )
            .await);
        };

        // TR-3: the client's first bytes, from the path or a header.
        let mut echoed_protocol = String::new();
        let encoded_early_data = match target_early_data {
            None => None,
            Some(EarlyData {
                header_name: None, ..
            }) => path_early_data.filter(|data| !data.is_empty()),
            Some(EarlyData {
                header_name: Some(name),
                ..
            }) => {
                let value = request_headers.get(name).map(String::as_str);
                // Xray's server answers with the protocol it was offered, as
                // a browser requires of a server that was offered one.
                if name == "sec-websocket-protocol"
                    && let Some(value) = value
                {
                    echoed_protocol = format!("Sec-WebSocket-Protocol: {value}\r\n");
                }
                value.filter(|data| !data.is_empty())
            }
        };
        let initial_data = match encoded_early_data.map(early_data::decode).transpose() {
            Ok(data) => data,
            Err(e) => {
                return Err(refuse(&mut server_stream, "400 Bad Request", "", e.to_string()).await);
            }
        };

        let http_response = format!(
            concat!(
                "HTTP/1.1 101 Switching Protocols\r\n",
                "Upgrade: websocket\r\n",
                "Connection: Upgrade\r\n",
                "Sec-WebSocket-Accept: {}\r\n",
                "{}",
                "\r\n"
            ),
            create_websocket_key_response(websocket_key),
            echoed_protocol,
        );

        server_stream.write_all(http_response.as_bytes()).await?;

        let websocket_stream = WebsocketStream::new(
            server_stream,
            false,
            ping_type.clone(),
            stream_reader.unparsed_data(),
        );
        let websocket_stream: Box<dyn AsyncStream> = match initial_data {
            Some(data) => Box::new(PrependStream::new(
                websocket_stream,
                Some(data.into_boxed_slice()),
            )),
            None => Box::new(websocket_stream),
        };

        let mut target_setup_result = handler.setup_server_stream(websocket_stream).await;

        if let Ok(ref mut setup_result) = target_setup_result {
            if matches!(setup_result, TcpServerSetupResult::AlreadyHandled) {
                return target_setup_result;
            }
            setup_result.set_need_initial_flush(true);
            // Inner handler already has effective_selector from construction
        }

        target_setup_result
    }
}

/// What every upgrade request of one client handler carries.
#[derive(Debug)]
pub struct ClientRequest {
    /// A `Host` header from the configured headers, else the proxy address as
    /// dialled, as sing-box does (transport/v2raywebsocket/client.go). Always
    /// sent: a Go server refuses a request without one.
    host: String,
    matching_path: Option<String>,
    matching_headers: Option<FxHashMap<String, String>>,
    pub ping_type: WebsocketPingType,
}

/// Upgrade `client_stream`. Early data, already encoded, goes in
/// `early_data_header` when one is named and is otherwise appended to the
/// path, before any query, as sing-box appends it to the URL's path.
pub async fn client_handshake(
    request: Arc<ClientRequest>,
    mut client_stream: Box<dyn AsyncStream>,
    early_data_header: Option<String>,
    encoded_early_data: Option<String>,
) -> std::io::Result<WebsocketStream> {
    let request_path = request.matching_path.as_deref().unwrap_or("/");
    let (path, query) = match request_path.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (request_path, None),
    };
    let (early_data_header, encoded_early_data) = match (early_data_header, encoded_early_data) {
        (Some(header), Some(data)) => (Some((header, data)), None),
        (None, data) => (None, data),
        (Some(_), None) => (None, None),
    };

    let websocket_key = create_websocket_key();
    let mut http_request = String::with_capacity(1024);
    http_request.push_str("GET ");
    http_request.push_str(path);
    if let Some(data) = &encoded_early_data {
        http_request.push_str(data);
    }
    if let Some(query) = query {
        http_request.push('?');
        http_request.push_str(query);
    }
    http_request.push_str(" HTTP/1.1\r\nHost: ");
    http_request.push_str(&request.host);
    http_request.push_str("\r\n");
    http_request.push_str(concat!("Connection: Upgrade\r\n", "Upgrade: websocket\r\n",));

    if let Some(ref headers) = request.matching_headers {
        for (header_key, header_val) in headers {
            // The early data replaces a configured header of its name, as
            // sing-box's `Set` does.
            if early_data_header
                .as_ref()
                .is_some_and(|(name, _)| name.eq_ignore_ascii_case(header_key))
            {
                continue;
            }
            http_request.push_str(header_key);
            http_request.push_str(": ");
            http_request.push_str(header_val);
            http_request.push_str("\r\n");
        }
    }
    if let Some((name, data)) = &early_data_header {
        http_request.push_str(name);
        http_request.push_str(": ");
        http_request.push_str(data);
        http_request.push_str("\r\n");
    }

    http_request.push_str(concat!(
        "Sec-WebSocket-Version: 13\r\n",
        "Sec-WebSocket-Key: "
    ));
    http_request.push_str(&websocket_key);
    http_request.push_str("\r\n\r\n");

    client_stream.write_all(&http_request.into_bytes()).await?;
    client_stream.flush().await?;

    let ParsedHttpData {
        first_line,
        headers: response_headers,
        stream_reader,
    } = ParsedHttpData::parse(&mut client_stream).await?;

    if !first_line.starts_with("HTTP/1.1 101") && !first_line.starts_with("HTTP/1.0 101") {
        return Err(std::io::Error::other(format!(
            "Bad websocket response: {first_line}"
        )));
    }

    let websocket_key_response = response_headers
        .get("sec-websocket-accept")
        .ok_or_else(|| std::io::Error::other("missing websocket key response header"))?;

    let expected_key_response = create_websocket_key_response(websocket_key);
    if websocket_key_response != &expected_key_response {
        return Err(std::io::Error::other(format!(
            "incorrect websocket key response, expected {expected_key_response}, got {websocket_key_response}"
        )));
    }

    Ok(WebsocketStream::new(
        client_stream,
        true,
        request.ping_type.clone(),
        stream_reader.unparsed_data(),
    ))
}

#[derive(Debug)]
pub struct WebsocketTcpClientHandler {
    request: Arc<ClientRequest>,
    early_data: Option<EarlyData>,
    handler: Box<dyn TcpClientHandler>,
}

impl WebsocketTcpClientHandler {
    pub fn new(
        dialled_address: String,
        matching_path: Option<String>,
        mut matching_headers: Option<FxHashMap<String, String>>,
        ping_type: WebsocketPingType,
        early_data: Option<EarlyData>,
        handler: Box<dyn TcpClientHandler>,
    ) -> Self {
        let configured_host = matching_headers.as_mut().and_then(|headers| {
            let key = headers
                .keys()
                .find(|key| key.eq_ignore_ascii_case("host"))?
                .clone();
            headers.remove(&key)
        });
        Self {
            request: Arc::new(ClientRequest {
                host: configured_host.unwrap_or(dialled_address),
                matching_path,
                matching_headers,
                ping_type,
            }),
            early_data,
            handler,
        }
    }

    /// The upgraded stream; with early data on, one that upgrades on its
    /// first write.
    async fn setup_client_stream_common(
        &self,
        client_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        match &self.early_data {
            Some(early_data) => Ok(Box::new(EarlyDataStream::new(
                client_stream,
                Arc::clone(&self.request),
                early_data,
            ))),
            None => Ok(Box::new(
                client_handshake(Arc::clone(&self.request), client_stream, None, None).await?,
            )),
        }
    }
}

#[async_trait]
impl TcpClientHandler for WebsocketTcpClientHandler {
    async fn setup_client_tcp_stream(
        &self,
        client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        let websocket_stream = self.setup_client_stream_common(client_stream).await?;
        self.handler
            .setup_client_tcp_stream(websocket_stream, remote_location)
            .await
    }

    /// A multiplexing protocol inside rides on the transport this handler
    /// sets up, so the reuse question goes inward: a live session there
    /// means this layer is not set up again either.
    async fn try_reuse_tcp_stream(
        &self,
        remote_location: &ResolvedLocation,
    ) -> Option<std::io::Result<TcpClientSetupResult>> {
        self.handler.try_reuse_tcp_stream(remote_location).await
    }

    fn supports_udp_over_tcp(&self) -> bool {
        self.handler.supports_udp_over_tcp()
    }

    async fn setup_client_udp_bidirectional(
        &self,
        client_stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        let websocket_stream = self.setup_client_stream_common(client_stream).await?;
        self.handler
            .setup_client_udp_bidirectional(websocket_stream, target)
            .await
    }
}

fn create_websocket_key() -> String {
    let key: [u8; 16] = rand::random();
    BASE64.encode(key)
}

fn create_websocket_key_response(key: String) -> String {
    const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut input = key.into_bytes();
    input.extend_from_slice(WS_GUID);
    let hash = digest(&SHA1_FOR_LEGACY_USE_ONLY, &input);
    BASE64.encode(hash.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::async_stream::testing::TestStream;
    use tokio::io::{AsyncWriteExt, duplex};

    /// The same shape that panicked in the HTTPUpgrade server: `GET HTTP/1.1`
    /// passes a prefix test and a suffix test while carrying no request target.
    /// Both transports now split the line rather than slicing between the two.
    #[derive(Debug)]
    struct NeverCalled;

    #[async_trait]
    impl TcpClientHandler for NeverCalled {
        async fn setup_client_tcp_stream(
            &self,
            _client_stream: Box<dyn AsyncStream>,
            _remote_location: ResolvedLocation,
        ) -> std::io::Result<TcpClientSetupResult> {
            unreachable!("the handshake is never answered")
        }
    }

    /// The request a client writes, given its configured headers.
    async fn client_request(headers: &[(&str, &str)]) -> String {
        let headers = headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let handler = WebsocketTcpClientHandler::new(
            "proxy.example.com:443".to_string(),
            Some("/ws".to_string()),
            Some(headers),
            WebsocketPingType::default(),
            None,
            Box::new(NeverCalled),
        );
        let (near, mut far) = duplex(8192);
        let task = tokio::spawn(async move {
            let _ = handler
                .setup_client_stream_common(Box::new(TestStream(near)))
                .await;
        });
        let mut request = vec![0u8; 1024];
        let n = tokio::io::AsyncReadExt::read(&mut far, &mut request)
            .await
            .unwrap();
        task.abort();
        String::from_utf8(request[..n].to_vec()).unwrap()
    }

    #[tokio::test]
    async fn a_request_without_a_configured_host_names_the_dialled_address() {
        let request = client_request(&[]).await;
        assert!(
            request.starts_with("GET /ws HTTP/1.1\r\nHost: proxy.example.com:443\r\n"),
            "{request}"
        );
        assert_eq!(request.matches("Host:").count(), 1, "{request}");
    }

    #[tokio::test]
    async fn a_configured_host_header_is_sent_once_in_its_place() {
        let request = client_request(&[("host", "cdn.example.com"), ("X-A", "b")]).await;
        assert!(
            request.starts_with("GET /ws HTTP/1.1\r\nHost: cdn.example.com\r\n"),
            "{request}"
        );
        assert_eq!(
            request.to_lowercase().matches("host:").count(),
            1,
            "{request}"
        );
        assert!(request.contains("\r\nX-A: b\r\n"), "{request}");
    }

    #[derive(Debug)]
    struct StopsAfterHandshake;

    #[async_trait]
    impl TcpServerHandler for StopsAfterHandshake {
        async fn setup_server_stream(
            &self,
            _server_stream: Box<dyn AsyncStream>,
        ) -> std::io::Result<TcpServerSetupResult> {
            Err(std::io::Error::other("handshake done"))
        }
    }

    /// What a server with one target at `/ws` answers to `request`.
    async fn server_response(request: &str) -> String {
        let handler = WebsocketTcpServerHandler::new(vec![WebsocketServerTarget {
            matching_path: Some("/ws".to_string()),
            matching_headers: None,
            ping_type: WebsocketPingType::default(),
            early_data: None,
            handler: Box::new(StopsAfterHandshake),
        }]);
        let (near, mut far) = duplex(8192);
        far.write_all(request.as_bytes()).await.unwrap();
        let _ = handler
            .setup_server_stream(Box::new(TestStream(near)))
            .await;
        let mut response = vec![0u8; 1024];
        let n = tokio::io::AsyncReadExt::read(&mut far, &mut response)
            .await
            .unwrap();
        String::from_utf8(response[..n].to_vec()).unwrap()
    }

    fn upgrade_request(path: &str, version: &str, connection: &str) -> String {
        format!(
            "GET {path} HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\n\
             Connection: {connection}\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: {version}\r\n\r\n"
        )
    }

    /// RFC 6455 section 1.3's example key, and the exact response: the
    /// reason phrase is "Switching Protocols", and nothing is echoed back.
    #[tokio::test]
    async fn the_101_response_is_exactly_the_rfcs() {
        let response = server_response(&upgrade_request("/ws", "13", "keep-alive, Upgrade")).await;
        assert_eq!(
            response,
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn another_version_is_answered_426_naming_13() {
        let response = server_response(&upgrade_request("/ws", "8", "Upgrade")).await;
        assert!(
            response.starts_with("HTTP/1.1 426 Upgrade Required\r\n"),
            "{response}"
        );
        assert!(
            response.contains("\r\nSec-WebSocket-Version: 13\r\n"),
            "{response}"
        );
    }

    #[tokio::test]
    async fn a_request_that_is_not_an_upgrade_is_answered_400() {
        let response = server_response(&upgrade_request("/ws", "13", "keep-alive")).await;
        assert!(
            response.starts_with("HTTP/1.1 400 Bad Request\r\n"),
            "{response}"
        );
    }

    #[tokio::test]
    async fn an_unknown_path_is_answered_404() {
        let response = server_response(&upgrade_request("/other", "13", "Upgrade")).await;
        assert!(
            response.starts_with("HTTP/1.1 404 Not Found\r\n"),
            "{response}"
        );
    }

    #[tokio::test]
    async fn a_request_line_with_no_path_is_an_error_not_a_panic() {
        let handler = WebsocketTcpServerHandler::new(vec![]);
        let (near, mut far) = duplex(8192);
        far.write_all(
            b"GET HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
        )
        .await
        .unwrap();
        let result = handler
            .setup_server_stream(Box::new(TestStream(near)))
            .await;
        assert!(result.is_err());
    }
}
