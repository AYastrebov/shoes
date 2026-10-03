//! In-process servers for the QUIC outbound tests.
//!
//! Every end-to-end test here runs the real server from this repository, so a
//! change to either side that breaks the pairing fails a test rather than
//! waiting for a user to notice.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, LazyLock, Mutex};

use crate::async_stream::AsyncMessageStream;
use crate::client_proxy_selector::ClientProxySelector;
use crate::config::{ClientQuicConfig, RuleConfig};
use crate::option_util::{NoneOrOne, NoneOrSome};
use crate::resolver::{NativeResolver, Resolver};
use crate::rustls_config_util::create_server_config;
use crate::tcp::tcp_client_handler_factory::create_tcp_client_proxy_selector;

/// A self-signed certificate for `localhost`, as PEM.
pub struct TestCertificate {
    pub cert_pem: String,
    pub key_pem: String,
}

pub fn generate_certificate() -> TestCertificate {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("generating a self-signed certificate");
    TestCertificate {
        cert_pem: certified.cert.pem(),
        key_pem: certified.signing_key.serialize_pem(),
    }
}

pub fn test_resolver() -> Arc<dyn Resolver> {
    Arc::new(NativeResolver::new())
}

/// A selector that allows everything and dials it directly.
///
/// This is the same construction the real server startup uses, so the tests
/// exercise the production routing path rather than a stand-in.
pub fn direct_selector(resolver: Arc<dyn Resolver>) -> Arc<ClientProxySelector> {
    Arc::new(create_tcp_client_proxy_selector(
        vec![RuleConfig::default()],
        resolver,
    ))
}

/// Client-side QUIC settings for the harness.
///
/// Verification is off: the certificate is self-signed, generated seconds
/// earlier by this same process, and reachable only over loopback. Pinning its
/// fingerprint would prove nothing that generating it did not already prove.
pub fn client_quic_config() -> ClientQuicConfig {
    ClientQuicConfig {
        verify: false,
        server_fingerprints: NoneOrSome::Unspecified,
        sni_hostname: NoneOrOne::One("localhost".to_string()),
        alpn_protocols: NoneOrSome::Unspecified,
        key: None,
        cert: None,
    }
}

/// Build the QUIC server config the in-process servers need.
pub fn quic_server_config(
    cert: &TestCertificate,
    alpn: &[String],
) -> Arc<quinn::crypto::rustls::QuicServerConfig> {
    let server_config = Arc::new(create_server_config(
        cert.cert_pem.as_bytes(),
        cert.key_pem.as_bytes(),
        vec![],
        alpn,
        &[],
    ));
    let quic: quinn::crypto::rustls::QuicServerConfig = server_config
        .try_into()
        .expect("a valid QUIC server config");
    Arc::new(quic)
}

/// Ports this process has already handed out.
///
/// The probe socket is closed before its port is returned, so nothing stops the
/// operating system handing the same ephemeral port to the next caller. That is
/// not the harmless collision it looks like: test servers bind with
/// `SO_REUSEPORT` (`quic_transport::build_server_endpoint` passes `true`), so
/// two servers on one port both bind successfully and the kernel splits the
/// datagrams between them. The client then talks to a server that has never
/// heard of its connection and waits out its timeout, with no bind error
/// anywhere - `SO_REUSEPORT` is precisely what suppresses it.
static ISSUED_PORTS: LazyLock<Mutex<HashSet<u16>>> = LazyLock::new(Mutex::default);

/// Reserve a loopback UDP port and release it, so a server can bind it.
///
/// Binding to port 0 inside the server is not an option: the caller needs to
/// know the address to dial, and the server does not report it back.
///
/// A port is never handed out twice in one process, which is what makes
/// concurrent tests safe from each other - `cargo test` runs them as threads of
/// a single process. A port taken by something else on the machine is still
/// possible and is not something this can fix.
pub fn reserve_udp_port() -> SocketAddr {
    const ATTEMPTS: usize = 64;

    for _ in 0..ATTEMPTS {
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").expect("binding a probe socket");
        let addr = probe.local_addr().expect("probe address");
        drop(probe);

        if ISSUED_PORTS
            .lock()
            .expect("the issued-port set is never held across a panic")
            .insert(addr.port())
        {
            return addr;
        }
    }

    panic!("the operating system offered no unused ephemeral port in {ATTEMPTS} attempts");
}

/// An echo server on a fresh TCP port. Returns its address.
pub async fn spawn_tcp_echo() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    addr
}

/// An echo server on a fresh UDP port. Returns its address.
/// How long [`udp_echo_exchange`] keeps trying in all, and how long it waits
/// for a reply before sending the payload again.
const ECHO_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);
const ECHO_RESEND: std::time::Duration = std::time::Duration::from_millis(250);

/// Send `payload` through a UDP relay to [`spawn_udp_echo`] and return the
/// reply that matches it, sending it again whenever none has come back for a
/// while.
///
/// UDP may drop a datagram, and nothing on these paths sends one again: not
/// the echo, not the plain UDP hop between the relay server and the echo, and
/// for Hysteria2 not QUIC either, whose datagrams are unreliable by design.
/// Sending once and waiting failed on macOS runners, whose loopback drops
/// under the suite's parallel load, even with a whole minute to wait (TUIC's
/// `quic` mode, run 36267194840): a lost datagram does not arrive late, it
/// does not arrive. Sending again is what a real UDP client does.
///
/// A reply that is not the payload -- a late duplicate of an earlier send --
/// is skipped and counted, and the count is reported if nothing matching ever
/// arrives, so an echo that comes back altered still fails the test.
pub async fn udp_echo_exchange(
    stream: &mut Box<dyn AsyncMessageStream>,
    payload: &[u8],
) -> std::io::Result<Vec<u8>> {
    use crate::async_stream::{AsyncReadMessage, AsyncWriteMessage};
    use std::pin::Pin;
    use tokio::time::{Instant, timeout_at};

    let deadline = Instant::now() + ECHO_DEADLINE;
    let mut other_replies = 0usize;
    let mut buf = vec![0u8; 65535];
    loop {
        std::future::poll_fn(|cx| Pin::new(&mut *stream).poll_write_message(cx, payload)).await?;
        let resend_at = (Instant::now() + ECHO_RESEND).min(deadline);
        loop {
            let mut read_buf = tokio::io::ReadBuf::new(&mut buf);
            let read = std::future::poll_fn(|cx| {
                Pin::new(&mut *stream).poll_read_message(cx, &mut read_buf)
            });
            match timeout_at(resend_at, read).await {
                Ok(Ok(())) if read_buf.filled() == payload => {
                    return Ok(read_buf.filled().to_vec());
                }
                Ok(Ok(())) => other_replies += 1,
                Ok(Err(e)) => return Err(e),
                Err(_) => break,
            }
        }
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("no matching reply arrived; {other_replies} other replies did"),
            ));
        }
    }
}

pub async fn spawn_udp_echo() -> SocketAddr {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        while let Ok((len, from)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..len], from).await;
        }
    });
    addr
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_tcp_echo_harness() {
        let addr = spawn_tcp_echo().await;
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
    }

    #[tokio::test]
    async fn test_udp_echo_harness() {
        let addr = spawn_udp_echo().await;
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.send_to(b"ping", addr).await.unwrap();
        let mut buf = [0u8; 4];
        let (len, _) = socket.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"ping");
    }

    #[test]
    fn test_certificate_generation() {
        let cert = generate_certificate();
        assert!(cert.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(cert.key_pem.contains("PRIVATE KEY"));
    }

    #[test]
    fn test_quic_server_config_accepts_the_generated_certificate() {
        let cert = generate_certificate();
        let _ = quic_server_config(&cert, &["h3".to_string()]);
    }

    #[test]
    fn test_reserved_ports_differ() {
        assert_ne!(reserve_udp_port(), reserve_udp_port());
    }

    /// One repeat is enough to make a test wait out a ten-second timeout for a
    /// reply that went to somebody else's server, so "usually different" is not
    /// the property wanted here.
    #[test]
    fn test_no_port_is_ever_reserved_twice() {
        let ports: HashSet<u16> = (0..200).map(|_| reserve_udp_port().port()).collect();
        assert_eq!(ports.len(), 200, "every reservation must be distinct");
    }
}
