//! A client header that travels with the first payload.
//!
//! A Trojan or Shadowsocks client that writes its request header and flushes
//! it puts the header in an outer record of its own -- a fixed-size first
//! record on every connection, which is a cheap rule for a censor to write.
//! The references append the first payload to it (SS-D7). This holds the
//! header back until the first write and sends the two as one.
//!
//! Some protocols speak server-first (SSH, SMTP, a MySQL greeting): the
//! client reads before it ever writes, and a header held for a write that
//! will not come would hang the connection. So the header also goes out
//! alone once [`HEADER_ALONE_AFTER`] has passed with nothing to write, and
//! before a shutdown.

use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::async_stream::{AsyncPing, AsyncStream, SocketPassthrough};

/// How long the header waits for a first payload to ride with. sing-box's
/// wait for the same thing (`C.ReadPayloadTimeout`).
pub const HEADER_ALONE_AFTER: Duration = Duration::from_millis(300);

/// The most first-write payload that joins the header. Small enough that
/// header and payload fit one AEAD chunk of classic Shadowsocks (0x3FFF) and
/// the SS2022 request header; the rest of a large write follows normally.
const FIRST_PAYLOAD_MAX: usize = 8 * 1024;

enum State {
    /// The header, not yet written, and the timer for sending it alone.
    Holding {
        header: Vec<u8>,
        timer: Option<Pin<Box<tokio::time::Sleep>>>,
    },
    /// Bytes accepted from the caller but not yet written to the inner
    /// stream: the header, and the first payload if one came in time.
    Draining {
        pending: Vec<u8>,
        written: usize,
    },
    Passthrough,
}

pub struct DeferredHeaderStream<S> {
    inner: S,
    state: State,
}

impl<S> DeferredHeaderStream<S> {
    pub fn new(inner: S, header: Vec<u8>) -> Self {
        Self {
            inner,
            state: State::Holding {
                header,
                timer: None,
            },
        }
    }
}

impl<S: AsyncWrite + Unpin> DeferredHeaderStream<S> {
    /// Stop holding: what is to be written is the header, then `payload`.
    fn release(&mut self, payload: &[u8]) {
        if let State::Holding { header, .. } = &mut self.state {
            let mut pending = std::mem::take(header);
            pending.extend_from_slice(payload);
            self.state = State::Draining {
                pending,
                written: 0,
            };
        }
    }

    /// Write out what was accepted. Ready once it all has been.
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while let State::Draining { pending, written } = &mut self.state {
            if *written == pending.len() {
                self.state = State::Passthrough;
                break;
            }
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &pending[*written..]))?;
            if n == 0 {
                return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()));
            }
            *written += n;
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for DeferredHeaderStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if let State::Holding { timer, .. } = &mut this.state {
            let timer =
                timer.get_or_insert_with(|| Box::pin(tokio::time::sleep(HEADER_ALONE_AFTER)));
            if timer.as_mut().poll(cx).is_ready() {
                this.release(&[]);
            }
        }
        // Progress on the header without making the read wait for it: the
        // server cannot answer before it arrives anyway, and the write side
        // finishes it if this cannot.
        if let State::Draining { .. } = this.state
            && let Poll::Ready(Err(e)) = this.poll_drain(cx)
        {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for DeferredHeaderStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if let State::Holding { .. } = this.state {
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let taken = buf.len().min(FIRST_PAYLOAD_MAX);
            this.release(&buf[..taken]);
            // Accepted: the bytes are ours to deliver now, and a write the
            // inner stream cannot take yet finishes on the next poll.
            if let Poll::Ready(Err(e)) = this.poll_drain(cx) {
                return Poll::Ready(Err(e));
            }
            return Poll::Ready(Ok(taken));
        }
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        // A flush with nothing written leaves the header waiting: flushing it
        // alone is the very record this exists to avoid.
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        // A client that closes without writing still owes the server its
        // request, or the server cannot tell where the connection was for.
        this.release(&[]);
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl<S: AsyncPing + AsyncWrite + Unpin> AsyncPing for DeferredHeaderStream<S> {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }

    fn poll_write_ping(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        let this = self.get_mut();
        // Nothing may reach the server ahead of the header.
        if !matches!(this.state, State::Passthrough) {
            return Poll::Ready(Ok(false));
        }
        Pin::new(&mut this.inner).poll_write_ping(cx)
    }
}

// Opaque: the bytes on the socket are not the bytes written here.
impl<S> SocketPassthrough for DeferredHeaderStream<S> {}
impl<S: AsyncStream> AsyncStream for DeferredHeaderStream<S> {}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A stream that records each write it receives, so a test can tell one
    /// write from two.
    #[derive(Default)]
    struct Recorder {
        writes: Vec<Vec<u8>>,
        reads: Vec<u8>,
    }

    impl AsyncRead for Recorder {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let this = self.get_mut();
            if this.reads.is_empty() {
                return Poll::Pending;
            }
            let n = this.reads.len().min(buf.remaining());
            buf.put_slice(&this.reads[..n]);
            this.reads.drain(..n);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for Recorder {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.get_mut().writes.push(buf.to_vec());
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// SS-D7: the header and the first payload reach the inner stream as one
    /// write, so they leave as one record.
    #[tokio::test]
    async fn the_header_rides_with_the_first_payload() {
        let mut stream = DeferredHeaderStream::new(Recorder::default(), b"HDR".to_vec());
        stream.flush().await.unwrap();
        assert!(stream.inner.writes.is_empty(), "a bare flush sends nothing");

        stream.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
        stream.write_all(b"more").await.unwrap();
        assert_eq!(
            stream.inner.writes,
            vec![b"HDRGET / HTTP/1.1\r\n".to_vec(), b"more".to_vec()]
        );
    }

    /// A large first write is split: a bounded payload joins the header and
    /// the rest follows, so the combined write fits one AEAD chunk.
    #[tokio::test]
    async fn only_a_bounded_payload_joins_the_header() {
        let mut stream = DeferredHeaderStream::new(Recorder::default(), b"HDR".to_vec());
        let big = vec![7u8; FIRST_PAYLOAD_MAX * 2];
        stream.write_all(&big).await.unwrap();
        assert_eq!(stream.inner.writes[0].len(), 3 + FIRST_PAYLOAD_MAX);
        let total: usize = stream.inner.writes.iter().map(Vec::len).sum();
        assert_eq!(total, 3 + big.len());
    }

    /// Server-first protocols: with nothing to write, the header goes alone
    /// after the wait, and the reply is read.
    #[tokio::test(start_paused = true)]
    async fn a_client_that_only_reads_sends_the_header_after_the_wait() {
        let mut stream = DeferredHeaderStream::new(Recorder::default(), b"HDR".to_vec());
        let mut buf = [0u8; 8];

        let started = tokio::time::Instant::now();
        let read = tokio::time::timeout(HEADER_ALONE_AFTER * 2, stream.read(&mut buf)).await;
        assert!(read.is_err(), "nothing to read yet");
        assert_eq!(stream.inner.writes, vec![b"HDR".to_vec()]);
        assert!(started.elapsed() >= HEADER_ALONE_AFTER);

        stream.inner.reads.extend_from_slice(b"SSH-2.0");
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"SSH-2.0");
    }

    /// A client that closes without writing still sends its request.
    #[tokio::test]
    async fn a_shutdown_sends_the_header() {
        let mut stream = DeferredHeaderStream::new(Recorder::default(), b"HDR".to_vec());
        stream.shutdown().await.unwrap();
        assert_eq!(stream.inner.writes, vec![b"HDR".to_vec()]);
    }

    /// Each client and the matching server, built from config as the binary
    /// builds them: the server reads the destination and finds the client's
    /// first payload already there -- for SS2022, inside the request's
    /// variable-length header.
    mod round_trip {
        use std::net::{IpAddr, Ipv4Addr};
        use std::sync::Arc;

        use tokio::io::AsyncWriteExt;

        use crate::address::NetLocation;
        use crate::config::{ClientProxyConfig, RuleConfig, ServerProxyConfig};
        use crate::resolver::{NativeResolver, Resolver};
        use crate::tcp::tcp_client_handler_factory::{
            HopContext, create_tcp_client_handler, create_tcp_client_proxy_selector,
        };
        use crate::tcp::tcp_handler::TcpServerSetupResult;
        use crate::tcp::tcp_server_handler_factory::create_tcp_server_handler;

        async fn tcp_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (connected, accepted) =
                tokio::join!(tokio::net::TcpStream::connect(addr), listener.accept());
            (connected.unwrap(), accepted.unwrap().0)
        }

        async fn first_flight(protocol: &str) {
            let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
            let server_config: ServerProxyConfig = serde_yaml::from_str(protocol).unwrap();
            let client_config: ClientProxyConfig = serde_yaml::from_str(protocol).unwrap();
            let rules: Vec<RuleConfig> =
                serde_yaml::from_str("- masks: 0.0.0.0/0\n  action: allow\n").unwrap();
            let selector = Arc::new(create_tcp_client_proxy_selector(rules, resolver.clone()));
            let server = create_tcp_server_handler(server_config, &selector, &resolver, None);
            let proxy = NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
            let client = create_tcp_client_handler(
                client_config,
                None,
                &HopContext::new(&proxy),
                resolver.clone(),
            );

            let target = NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), 8443);
            let (client_end, server_end) = tcp_pair().await;
            let accepted =
                tokio::spawn(async move { server.setup_server_stream(Box::new(server_end)).await });

            let mut stream = client
                .setup_client_tcp_stream(Box::new(client_end), target.clone().into())
                .await
                .unwrap()
                .client_stream;
            stream.write_all(b"first payload").await.unwrap();
            stream.flush().await.unwrap();

            match accepted.await.unwrap().unwrap() {
                TcpServerSetupResult::TcpForward {
                    remote_location,
                    initial_remote_data,
                    ..
                } => {
                    assert_eq!(remote_location, target, "{protocol}");
                    assert_eq!(
                        initial_remote_data.as_deref(),
                        Some(&b"first payload"[..]),
                        "{protocol}: the payload arrived with the header"
                    );
                }
                _ => panic!("{protocol}: not a TCP forward"),
            }
        }

        #[tokio::test]
        async fn shadowsocks() {
            first_flight("type: shadowsocks\ncipher: aes-128-gcm\npassword: secret\n").await;
        }

        #[tokio::test]
        async fn shadowsocks_2022() {
            first_flight(
                "type: shadowsocks\ncipher: 2022-blake3-aes-128-gcm\npassword: AAECAwQFBgcICQoLDA0ODw==\n",
            )
            .await;
        }

        #[tokio::test]
        async fn trojan() {
            first_flight("type: trojan\npassword: secret\n").await;
        }
    }
}
