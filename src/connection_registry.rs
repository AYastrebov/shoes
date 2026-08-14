use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::async_stream::{AsyncPing, AsyncStream};

/// Wraps a client stream and counts bytes in each direction. `up` is bytes read
/// from the client (client -> proxy); `down` is bytes written to the client
/// (proxy -> client). Applied once at the accept edge, so it is protocol-agnostic
/// and covers every downstream copy path without touching them.
pub struct CountingStream<S> {
    inner: S,
    up: Arc<AtomicU64>,
    down: Arc<AtomicU64>,
}

impl<S> CountingStream<S> {
    pub fn new(inner: S, up: Arc<AtomicU64>, down: Arc<AtomicU64>) -> Self {
        Self { inner, up, down }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CountingStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &r {
            let read = buf.filled().len() - before;
            if read > 0 {
                self.up.fetch_add(read as u64, Ordering::Relaxed);
            }
        }
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountingStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &r {
            self.down.fetch_add(*n as u64, Ordering::Relaxed);
        }
        r
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    // Forward vectored writes so wrapping the stream never silently disables a
    // vectored fast path the inner stream supports.
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(n)) = &r {
            self.down.fetch_add(*n as u64, Ordering::Relaxed);
        }
        r
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

impl<S: AsyncPing + Unpin> AsyncPing for CountingStream<S> {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }
    fn poll_write_ping(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        Pin::new(&mut self.inner).poll_write_ping(cx)
    }
}

impl<S: AsyncStream> AsyncStream for CountingStream<S> {}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn counts_bytes_in_both_directions() {
        let (mut a, b) = tokio::io::duplex(64);
        let up = Arc::new(AtomicU64::new(0));
        let down = Arc::new(AtomicU64::new(0));
        let mut counted = CountingStream::new(b, up.clone(), down.clone());

        // Peer writes 5 bytes; counted reads them -> up += 5.
        a.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        counted.read_exact(&mut buf).await.unwrap();
        assert_eq!(up.load(Ordering::Relaxed), 5);

        // counted writes 3 bytes to the peer -> down += 3.
        counted.write_all(b"abc").await.unwrap();
        assert_eq!(down.load(Ordering::Relaxed), 3);
    }
}
