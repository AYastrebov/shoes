use async_trait::async_trait;
use aws_lc_rs::digest::{SHA1_FOR_LEGACY_USE_ONLY, digest};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rustc_hash::FxHashMap;
use tokio::io::AsyncWriteExt;

use super::websocket_stream::WebsocketStream;
use crate::address::ResolvedLocation;
use crate::async_stream::AsyncMessageStream;
use crate::async_stream::AsyncStream;
use crate::config::WebsocketPingType;
use crate::http_parse::{ParsedHttpData, parse_request_line};
use crate::tcp::tcp_handler::{
    TcpClientHandler, TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult,
};

#[derive(Debug)]
pub struct WebsocketServerTarget {
    pub matching_path: Option<String>,
    pub matching_headers: Option<FxHashMap<String, String>>,
    pub ping_type: WebsocketPingType,
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

        let (method, request_path) = parse_request_line(&first_line).ok_or_else(|| {
            std::io::Error::other(format!("invalid http request line: {first_line}"))
        })?;

        if method != "GET" {
            return Err(std::io::Error::other(format!(
                "invalid http request method: {method}"
            )));
        }

        let websocket_key = request_headers
            .remove("sec-websocket-key")
            .ok_or_else(|| std::io::Error::other("missing websocket key header"))?;

        'outer: for server_target in self.server_targets.iter() {
            let WebsocketServerTarget {
                matching_path,
                matching_headers,
                ping_type,
                handler,
            } = server_target;

            if let Some(path) = matching_path
                && path != request_path
            {
                continue;
            }

            if let Some(headers) = matching_headers {
                for (header_key, header_val) in headers {
                    if request_headers.get(header_key) != Some(header_val) {
                        continue 'outer;
                    }
                }
            }

            let websocket_key_response = create_websocket_key_response(websocket_key);

            let host_response_header = match request_headers.get("host") {
                Some(v) => format!("Host: {v}\r\n"),
                None => "".to_string(),
            };

            let websocket_version_response_header =
                match request_headers.get("sec-websocket_version") {
                    Some(v) => format!("Sec-WebSocket-Version: {v}\r\n"),
                    None => "".to_string(),
                };

            let http_response = format!(
                concat!(
                    "HTTP/1.1 101 Switching Protocol\r\n",
                    "{}",
                    "Upgrade: websocket\r\n",
                    "Connection: Upgrade\r\n",
                    "{}",
                    "Sec-WebSocket-Accept: {}\r\n",
                    "\r\n"
                ),
                host_response_header, websocket_version_response_header, websocket_key_response,
            );

            server_stream.write_all(http_response.as_bytes()).await?;

            let websocket_stream = Box::new(WebsocketStream::new(
                server_stream,
                false,
                ping_type.clone(),
                stream_reader.unparsed_data(),
            ));

            let mut target_setup_result = handler.setup_server_stream(websocket_stream).await;

            if let Ok(ref mut setup_result) = target_setup_result {
                if matches!(setup_result, TcpServerSetupResult::AlreadyHandled) {
                    return target_setup_result;
                }
                setup_result.set_need_initial_flush(true);
                // Inner handler already has effective_selector from construction
            }

            return target_setup_result;
        }

        Err(std::io::Error::other("No matching websocket targets"))
    }
}

#[derive(Debug)]
pub struct WebsocketTcpClientHandler {
    /// A `Host` header from the configured headers, else the proxy address as
    /// dialled, as sing-box does (transport/v2raywebsocket/client.go). Always
    /// sent: a Go server refuses a request without one.
    host: String,
    matching_path: Option<String>,
    matching_headers: Option<FxHashMap<String, String>>,
    ping_type: WebsocketPingType,
    handler: Box<dyn TcpClientHandler>,
}

impl WebsocketTcpClientHandler {
    pub fn new(
        dialled_address: String,
        matching_path: Option<String>,
        mut matching_headers: Option<FxHashMap<String, String>>,
        ping_type: WebsocketPingType,
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
            host: configured_host.unwrap_or(dialled_address),
            matching_path,
            matching_headers,
            ping_type,
            handler,
        }
    }

    async fn setup_client_stream_common(
        &self,
        mut client_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<WebsocketStream> {
        let request_path = self.matching_path.as_deref().unwrap_or("/");

        let websocket_key = create_websocket_key();
        let mut http_request = String::with_capacity(1024);
        http_request.push_str("GET ");
        http_request.push_str(request_path);
        http_request.push_str(" HTTP/1.1\r\nHost: ");
        http_request.push_str(&self.host);
        http_request.push_str("\r\n");
        http_request.push_str(concat!("Connection: Upgrade\r\n", "Upgrade: websocket\r\n",));

        if let Some(ref headers) = self.matching_headers {
            for (header_key, header_val) in headers {
                http_request.push_str(header_key);
                http_request.push_str(": ");
                http_request.push_str(header_val);
                http_request.push_str("\r\n");
            }
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
            self.ping_type.clone(),
            stream_reader.unparsed_data(),
        ))
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
            .setup_client_tcp_stream(Box::new(websocket_stream), remote_location)
            .await
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
            .setup_client_udp_bidirectional(Box::new(websocket_stream), target)
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
