use futures::ready;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::ReadBuf;

use crate::address::{Address, NetLocation};
use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncReadSourcedMessage,
    AsyncReadTargetedMessage, AsyncShutdownMessage, AsyncSourcedMessageStream,
    AsyncTargetedMessageStream, AsyncWriteMessage, AsyncWriteSourcedMessage,
    AsyncWriteTargetedMessage,
};
use crate::util::allocate_vec;

pub struct SnellUdpStream {
    stream: Box<dyn AsyncMessageStream>,
    max_payload_size: usize,

    read_buf: Box<[u8]>,

    write_buf: Box<[u8]>,
    write_buf_end_offset: usize,

    is_eof: bool,
}

impl SnellUdpStream {
    pub fn new(stream: Box<dyn AsyncMessageStream>, max_payload_size: usize) -> Self {
        Self {
            stream,
            max_payload_size,

            read_buf: allocate_vec(65535).into_boxed_slice(),

            write_buf: allocate_vec(max_payload_size).into_boxed_slice(),
            write_buf_end_offset: 0,

            is_eof: false,
        }
    }
}

impl AsyncReadTargetedMessage for SnellUdpStream {
    fn poll_read_targeted_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<NetLocation>> {
        let this = self.get_mut();
        if this.is_eof {
            return Poll::Ready(Ok(NetLocation::UNSPECIFIED));
        }

        let mut read_buf = ReadBuf::new(&mut this.read_buf);
        ready!(Pin::new(&mut this.stream).poll_read_message(cx, &mut read_buf))?;

        let len = read_buf.filled().len();
        if len == 0 {
            this.is_eof = true;
            return Poll::Ready(Ok(NetLocation::UNSPECIFIED));
        }

        if len < 4 {
            return Poll::Ready(Err(std::io::Error::other("snell packet size too small")));
        }

        if len > this.max_payload_size {
            return Poll::Ready(Err(std::io::Error::other("snell packet size too big")));
        }

        let cmd = this.read_buf[0];
        if cmd != 1 {
            return Poll::Ready(Err(std::io::Error::other(format!(
                "invalid snell command: {cmd}"
            ))));
        }

        let address_len = this.read_buf[1] as usize;
        let (location, data_offset) = if address_len == 0 {
            let ip_version = this.read_buf[2];
            if ip_version == 4 {
                if len < 9 {
                    return Poll::Ready(Err(std::io::Error::other(
                        "invalid snell packet size for ipv4 target",
                    )));
                }
                let ip_bytes: [u8; 4] = this.read_buf[3..7].try_into().unwrap();
                let ip_addr = Ipv4Addr::from(ip_bytes);
                let port = u16::from_be_bytes(this.read_buf[7..9].try_into().unwrap());
                (NetLocation::new(Address::Ipv4(ip_addr), port), 9)
            } else if ip_version == 6 {
                if len < 21 {
                    return Poll::Ready(Err(std::io::Error::other(
                        "invalid snell packet size for ipv6 target",
                    )));
                }
                let ip_bytes: [u8; 16] = this.read_buf[3..19].try_into().unwrap();
                let ip_addr = Ipv6Addr::from(ip_bytes);
                let port = u16::from_be_bytes(this.read_buf[19..21].try_into().unwrap());
                (NetLocation::new(Address::Ipv6(ip_addr), port), 21)
            } else {
                return Poll::Ready(Err(std::io::Error::other(format!(
                    "invalid ip version: {ip_version}"
                ))));
            }
        } else {
            if len < 4 + address_len {
                return Poll::Ready(Err(std::io::Error::other(
                    "invalid snell packet size for host target",
                )));
            }
            let hostname_bytes = &this.read_buf[2..2 + address_len];
            let hostname = std::str::from_utf8(hostname_bytes)
                .map_err(|e| std::io::Error::other(format!("could not parse hostname: {e}")))?;
            let port = u16::from_be_bytes(
                this.read_buf[2 + address_len..4 + address_len]
                    .try_into()
                    .unwrap(),
            );
            (
                NetLocation::new(Address::Hostname(hostname.to_string()), port),
                4 + address_len,
            )
        };

        buf.put_slice(&this.read_buf[data_offset..len]);
        Poll::Ready(Ok(location))
    }
}

impl AsyncWriteSourcedMessage for SnellUdpStream {
    fn poll_write_sourced_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        source: &SocketAddr,
    ) -> Poll<std::io::Result<()>> {
        let mut this = self.get_mut();

        if this.write_buf_end_offset > 0 {
            // Buffer may be written but flush incomplete; continues in that case.
            if let Poll::Ready(Err(e)) = Pin::new(&mut this).poll_flush_message(cx) {
                return Poll::Ready(Err(e));
            }
            if this.write_buf_end_offset > 0 {
                return Poll::Pending;
            }
        }

        let buf_len = buf.len();
        let header_len = if source.is_ipv4() { 7 } else { 19 };
        if header_len + buf_len > this.max_payload_size {
            // One Snell UDP datagram is one Shadowsocks AEAD chunk, capped at 0x3FFF bytes.
            // A reply that cannot fit is dropped, as the network would drop it.
            log::debug!(
                "snell: dropping {buf_len}-byte UDP reply from {source}: over the chunk cap"
            );
            return Poll::Ready(Ok(()));
        }

        let offset = match source {
            SocketAddr::V4(socket_addr) => {
                this.write_buf[0] = 4;
                this.write_buf[1..5].copy_from_slice(&socket_addr.ip().octets());
                this.write_buf[5..7].copy_from_slice(&socket_addr.port().to_be_bytes());
                7
            }
            SocketAddr::V6(socket_addr) => {
                this.write_buf[0] = 6;
                this.write_buf[1..17].copy_from_slice(&socket_addr.ip().octets());
                this.write_buf[17..19].copy_from_slice(&socket_addr.port().to_be_bytes());
                19
            }
        };

        this.write_buf[offset..offset + buf_len].copy_from_slice(buf);
        this.write_buf_end_offset = offset + buf_len;

        Poll::Ready(Ok(()))
    }
}

impl AsyncFlushMessage for SnellUdpStream {
    fn poll_flush_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.write_buf_end_offset > 0 {
            ready!(
                Pin::new(&mut this.stream)
                    .poll_write_message(cx, &this.write_buf[0..this.write_buf_end_offset])
            )?;
            this.write_buf_end_offset = 0;
        }
        Pin::new(&mut this.stream).poll_flush_message(cx)
    }
}

impl AsyncShutdownMessage for SnellUdpStream {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut this = self.get_mut();
        ready!(Pin::new(&mut this).poll_flush_message(cx))?;
        Pin::new(&mut this.stream).poll_shutdown_message(cx)
    }
}

impl AsyncPing for SnellUdpStream {
    fn supports_ping(&self) -> bool {
        self.stream.supports_ping()
    }

    /// Writes a ping message to the highest level stream abstraction that supports pings.
    fn poll_write_ping(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Pin::new(&mut self.get_mut().stream).poll_write_ping(cx)
    }
}

impl AsyncTargetedMessageStream for SnellUdpStream {}

/// Client-side Snell UDP stream.
/// Writes requests with target (cmd + address format) and reads responses with source (ip_version format).
pub struct SnellUdpClientStream {
    stream: Box<dyn AsyncMessageStream>,
    max_payload_size: usize,

    read_buf: Box<[u8]>,

    write_buf: Box<[u8]>,
    write_buf_end_offset: usize,

    is_eof: bool,
}

impl SnellUdpClientStream {
    pub fn new(stream: Box<dyn AsyncMessageStream>, max_payload_size: usize) -> Self {
        Self {
            stream,
            max_payload_size,

            read_buf: allocate_vec(65535).into_boxed_slice(),

            write_buf: allocate_vec(max_payload_size).into_boxed_slice(),
            write_buf_end_offset: 0,

            is_eof: false,
        }
    }
}

/// Reads response format: ip_version(1) + ip(4/16) + port(2) + data
/// Returns the source SocketAddr
impl AsyncReadSourcedMessage for SnellUdpClientStream {
    fn poll_read_sourced_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<SocketAddr>> {
        let this = self.get_mut();
        if this.is_eof {
            return Poll::Ready(Ok(SocketAddr::new(
                std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                0,
            )));
        }

        let mut read_buf = ReadBuf::new(&mut this.read_buf);
        ready!(Pin::new(&mut this.stream).poll_read_message(cx, &mut read_buf))?;

        let len = read_buf.filled().len();
        if len == 0 {
            this.is_eof = true;
            return Poll::Ready(Ok(SocketAddr::new(
                std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                0,
            )));
        }

        // Response format: ip_version(1) + ip(4/16) + port(2) + data
        if len < 7 {
            return Poll::Ready(Err(std::io::Error::other(
                "snell response packet too small",
            )));
        }

        if len > this.max_payload_size {
            return Poll::Ready(Err(std::io::Error::other("snell response packet too big")));
        }

        let ip_version = this.read_buf[0];
        let (source_addr, data_offset) = if ip_version == 4 {
            if len < 7 {
                return Poll::Ready(Err(std::io::Error::other(
                    "invalid snell response packet size for ipv4",
                )));
            }
            let ip_bytes: [u8; 4] = this.read_buf[1..5].try_into().unwrap();
            let ip_addr = Ipv4Addr::from(ip_bytes);
            let port = u16::from_be_bytes(this.read_buf[5..7].try_into().unwrap());
            (SocketAddr::new(std::net::IpAddr::V4(ip_addr), port), 7)
        } else if ip_version == 6 {
            if len < 19 {
                return Poll::Ready(Err(std::io::Error::other(
                    "invalid snell response packet size for ipv6",
                )));
            }
            let ip_bytes: [u8; 16] = this.read_buf[1..17].try_into().unwrap();
            let ip_addr = Ipv6Addr::from(ip_bytes);
            let port = u16::from_be_bytes(this.read_buf[17..19].try_into().unwrap());
            (SocketAddr::new(std::net::IpAddr::V6(ip_addr), port), 19)
        } else {
            return Poll::Ready(Err(std::io::Error::other(format!(
                "invalid snell response ip version: {ip_version}"
            ))));
        };

        buf.put_slice(&this.read_buf[data_offset..len]);
        Poll::Ready(Ok(source_addr))
    }
}

/// Writes request format: cmd(1=0x01) + address_len(1) + [hostname bytes | ip_version(1) + ip(4/16)] + port(2) + data
impl AsyncWriteTargetedMessage for SnellUdpClientStream {
    fn poll_write_targeted_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: &NetLocation,
    ) -> Poll<std::io::Result<()>> {
        let mut this = self.get_mut();

        if this.write_buf_end_offset > 0 {
            if let Poll::Ready(Err(e)) = Pin::new(&mut this).poll_flush_message(cx) {
                return Poll::Ready(Err(e));
            }
            if this.write_buf_end_offset > 0 {
                return Poll::Pending;
            }
        }

        let buf_len = buf.len();
        // cmd(1) + addr_len(1), then ip_version(1) + ip + port(2), or hostname + port(2).
        let header_len = match target.address() {
            Address::Ipv4(_) => 9,
            Address::Ipv6(_) => 21,
            Address::Hostname(hostname) => 4 + hostname.len(),
        };
        if header_len + buf_len > this.max_payload_size {
            log::debug!(
                "snell: dropping {buf_len}-byte UDP datagram to {target}: over the chunk cap"
            );
            return Poll::Ready(Ok(()));
        }

        this.write_buf[0] = 1; // cmd = data

        let offset = match target.address() {
            Address::Ipv4(ip) => {
                // address_len = 0 means IP address follows
                this.write_buf[1] = 0;
                this.write_buf[2] = 4; // ip_version
                this.write_buf[3..7].copy_from_slice(&ip.octets());
                this.write_buf[7..9].copy_from_slice(&target.port().to_be_bytes());
                9
            }
            Address::Ipv6(ip) => {
                this.write_buf[1] = 0;
                this.write_buf[2] = 6; // ip_version
                this.write_buf[3..19].copy_from_slice(&ip.octets());
                this.write_buf[19..21].copy_from_slice(&target.port().to_be_bytes());
                21
            }
            Address::Hostname(hostname) => {
                let hostname_bytes = hostname.as_bytes();
                let hostname_len = hostname_bytes.len();
                if hostname_len > 255 {
                    return Poll::Ready(Err(std::io::Error::other("hostname too long")));
                }
                this.write_buf[1] = hostname_len as u8;
                this.write_buf[2..2 + hostname_len].copy_from_slice(hostname_bytes);
                let port_offset = 2 + hostname_len;
                this.write_buf[port_offset..port_offset + 2]
                    .copy_from_slice(&target.port().to_be_bytes());
                port_offset + 2
            }
        };

        this.write_buf[offset..offset + buf_len].copy_from_slice(buf);
        this.write_buf_end_offset = offset + buf_len;

        Poll::Ready(Ok(()))
    }
}

impl AsyncFlushMessage for SnellUdpClientStream {
    fn poll_flush_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.write_buf_end_offset > 0 {
            ready!(
                Pin::new(&mut this.stream)
                    .poll_write_message(cx, &this.write_buf[0..this.write_buf_end_offset])
            )?;
            this.write_buf_end_offset = 0;
        }
        Pin::new(&mut this.stream).poll_flush_message(cx)
    }
}

impl AsyncShutdownMessage for SnellUdpClientStream {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut this = self.get_mut();
        ready!(Pin::new(&mut this).poll_flush_message(cx))?;
        Pin::new(&mut this.stream).poll_shutdown_message(cx)
    }
}

impl AsyncPing for SnellUdpClientStream {
    fn supports_ping(&self) -> bool {
        self.stream.supports_ping()
    }

    fn poll_write_ping(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Pin::new(&mut self.get_mut().stream).poll_write_ping(cx)
    }
}

impl AsyncSourcedMessageStream for SnellUdpClientStream {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shadowsocks::ShadowsocksStreamType;
    use std::future::poll_fn;
    use std::sync::{Arc, Mutex};

    /// Records every message written to it.
    #[derive(Clone, Default)]
    struct Recorder(Arc<Mutex<Vec<Vec<u8>>>>);

    impl AsyncReadMessage for Recorder {
        fn poll_read_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWriteMessage for Recorder {
        fn poll_write_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<()>> {
            self.0.lock().unwrap().push(buf.to_vec());
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncFlushMessage for Recorder {
        fn poll_flush_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncShutdownMessage for Recorder {
        fn poll_shutdown_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncPing for Recorder {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncMessageStream for Recorder {}

    fn cap() -> usize {
        ShadowsocksStreamType::Aead.max_payload_len()
    }

    #[tokio::test]
    async fn a_reply_over_the_chunk_cap_is_dropped_not_fatal() {
        let recorder = Recorder::default();
        let mut stream = SnellUdpStream::new(Box::new(recorder.clone()), cap());
        let source: SocketAddr = "203.0.113.7:53".parse().unwrap();

        let big = vec![0u8; 20_000];
        poll_fn(|cx| Pin::new(&mut stream).poll_write_sourced_message(cx, &big, &source))
            .await
            .unwrap();
        poll_fn(|cx| Pin::new(&mut stream).poll_flush_message(cx))
            .await
            .unwrap();
        assert!(recorder.0.lock().unwrap().is_empty());

        // The largest reply that fits still goes out, header included.
        let fits = vec![1u8; cap() - 7];
        poll_fn(|cx| Pin::new(&mut stream).poll_write_sourced_message(cx, &fits, &source))
            .await
            .unwrap();
        poll_fn(|cx| Pin::new(&mut stream).poll_flush_message(cx))
            .await
            .unwrap();
        let written = recorder.0.lock().unwrap();
        assert_eq!(written.len(), 1);
        assert_eq!(written[0].len(), cap());
    }

    #[tokio::test]
    async fn a_datagram_over_the_chunk_cap_is_dropped_client_side() {
        let recorder = Recorder::default();
        let mut stream = SnellUdpClientStream::new(Box::new(recorder.clone()), cap());
        let target = NetLocation::new(Address::Hostname("example.com".to_string()), 53);

        let big = vec![0u8; 20_000];
        poll_fn(|cx| Pin::new(&mut stream).poll_write_targeted_message(cx, &big, &target))
            .await
            .unwrap();
        poll_fn(|cx| Pin::new(&mut stream).poll_flush_message(cx))
            .await
            .unwrap();
        assert!(recorder.0.lock().unwrap().is_empty());
    }
}
