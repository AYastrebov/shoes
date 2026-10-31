//! From nothing to an open PPP link: TCP, TLS, the HTTP request, SSTP's
//! call setup, and PPP up to IPCP, under one deadline ([MS-SSTP] §3.2.2.1's
//! negotiation timer).
//!
//! One task, reading and writing in turn: nothing here is on the data path,
//! so clarity beats throughput. The session takes over the stream, with any
//! bytes already read past the last packet handled.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use log::{debug, info};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::crypto;
use super::packet::{self, Packet, message};
use super::ppp::{self, Credentials, Link, Ppp};
use crate::async_stream::AsyncStream;
use crate::crypto::{CryptoConnection, CryptoTlsStream, perform_crypto_handshake};

/// [MS-SSTP] §3.2.2.1: 60 seconds.
pub const NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(60);

/// The HTTP response's header block is refused past this: a server that
/// talks this much before `\r\n\r\n` is not an SSTP server.
const MAX_HTTP_HEADER: usize = 8192;

pub type TlsStream = CryptoTlsStream<Box<dyn AsyncStream>>;

/// Everything the handshake needs, built once per connector; the server's
/// address is resolved per build and passed beside it.
pub struct Settings {
    pub address: crate::address::NetLocation,
    /// The `Host` header: the configured hostname, or the literal.
    pub host: String,
    pub tls: Arc<rustls::ClientConfig>,
    pub server_name: rustls::pki_types::ServerName<'static>,
    pub bind_interface: Option<String>,
    pub no_delay: bool,
    pub username: String,
    pub password: crate::config::Redacted<String>,
    pub methods: Vec<ppp::AuthMethod>,
    pub mtu: u16,
    /// Keenetic's camouflage: the query string the SSTP URI must carry.
    pub camouflage_secret: Option<crate::config::Redacted<String>>,
}

pub struct Established {
    pub stream: TlsStream,
    /// Bytes read past the last packet the handshake consumed.
    pub pending: Vec<u8>,
    pub ppp: Ppp,
    pub link: Link,
}

/// `servers` are the address's resolved addresses, tried in order until one
/// accepts the TCP connection; the whole of it is under the negotiation
/// timeout.
pub async fn establish(settings: &Settings, servers: &[SocketAddr]) -> io::Result<Established> {
    match tokio::time::timeout(NEGOTIATION_TIMEOUT, run(settings, servers)).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "SSTP: no link to {} within {} s",
                settings.address,
                NEGOTIATION_TIMEOUT.as_secs()
            ),
        )),
    }
}

/// The first of `servers` that accepts the connection, as
/// `SocketConnectorImpl::connect` does for the other outbounds: a name's
/// first answer being unreachable is no reason to fail while the rest are
/// untried, and a rebuild against the same cached answer would fail the
/// same way.
async fn connect_any(
    settings: &Settings,
    servers: &[SocketAddr],
) -> io::Result<(tokio::net::TcpStream, SocketAddr)> {
    let mut last = None;
    for &server in servers {
        let attempt = async {
            let socket = crate::socket_util::new_tcp_socket(
                settings.bind_interface.as_deref(),
                server.is_ipv6(),
            )?;
            socket.connect(server).await
        };
        match attempt.await {
            Ok(tcp) => return Ok((tcp, server)),
            Err(e) => {
                debug!("SSTP: connecting to {server}: {e}; trying the next address");
                last = Some(io::Error::new(
                    e.kind(),
                    format!("SSTP: connecting to {server}: {e}"),
                ));
            }
        }
    }
    Err(last.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("SSTP: {} resolved to no address", settings.address),
        )
    }))
}

async fn run(settings: &Settings, servers: &[SocketAddr]) -> io::Result<Established> {
    let (tcp, server) = connect_any(settings, servers).await?;
    let context =
        |e: io::Error| io::Error::new(e.kind(), format!("SSTP: connecting to {}: {e}", server));
    if settings.no_delay {
        tcp.set_nodelay(true).map_err(context)?;
    }
    let mut io: Box<dyn AsyncStream> = Box::new(tcp);

    let client = rustls::ClientConnection::new(settings.tls.clone(), settings.server_name.clone())
        .map_err(|e| context(io::Error::other(e)))?;
    let mut connection = CryptoConnection::new_rustls_client(client);
    perform_crypto_handshake(&mut connection, &mut io, 16384)
        .await
        .map_err(context)?;
    // The leaf certificate, whose hash crypto binding sends: the one this
    // client verified, or pinned.
    let certificate = match &connection {
        CryptoConnection::RustlsClient(client) => client
            .peer_certificates()
            .and_then(|chain| chain.first())
            .map(|leaf| leaf.as_ref().to_vec()),
        _ => None,
    }
    .ok_or_else(|| context(io::Error::other("the server presented no certificate")))?;
    let mut stream = CryptoTlsStream::new(io, connection);

    let mut reader = PacketReader::default();
    http_request(
        &mut stream,
        &mut reader,
        &settings.host,
        settings
            .camouflage_secret
            .as_ref()
            .map(|s| s.expose().as_str()),
    )
    .await?;

    stream.write_all(&packet::call_connect_request()).await?;
    stream.flush().await?;
    let binding = await_ack(&mut stream, &mut reader).await?;
    let hash = binding.choose_hash().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "SSTP: the server offered no usable crypto binding",
        )
    })?;
    debug!("SSTP: call accepted, binding with {hash:?}");

    let mut ppp = Ppp::new(
        Credentials {
            username: settings.username.clone(),
            password: settings.password.clone(),
        },
        settings.methods.clone(),
        settings.mtu,
    );
    let frames = ppp.start(Instant::now());
    write_frames(&mut stream, &[], &frames).await?;

    loop {
        if let Some(link) = ppp.link() {
            info!(
                "SSTP: connected to {}: address {}, MTU {}, DNS {:?}",
                server,
                link.address,
                link.peer_mru.min(link.local_mru).min(settings.mtu),
                link.dns
            );
            return Ok(Established {
                stream,
                pending: reader.into_pending(),
                ppp,
                link,
            });
        }

        let next = match ppp.deadline() {
            Some(deadline) => {
                let wait = deadline.saturating_duration_since(Instant::now());
                match tokio::time::timeout(wait, reader.next(&mut stream)).await {
                    Ok(next) => Some(next?),
                    Err(_) => None,
                }
            }
            None => Some(reader.next(&mut stream).await?),
        };
        let now = Instant::now();
        let Some(raw) = next else {
            let frames = ppp.on_timer(now)?;
            write_frames(&mut stream, &[], &frames).await?;
            continue;
        };

        match packet::parse(&raw)? {
            Packet::Data(frame) => {
                // RFC 1661 §5: a malformed packet is discarded, not fatal;
                // a server's retransmission follows.
                let frames = match ppp.input(frame, now) {
                    Ok(frames) => frames,
                    Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                        debug!("SSTP: discarding a PPP packet during setup: {e}");
                        continue;
                    }
                    Err(e) => return Err(e),
                };
                // Authentication done: Call Connected and IPCP's first
                // request share one write (the spec's "Performance").
                let control = match ppp.take_authenticated() {
                    Some(hlak) => {
                        let mut call_connected = packet::call_connected(
                            hash,
                            &binding.nonce,
                            &hash.cert_hash(&certificate),
                        );
                        let mac = crypto::compound_mac(&hlak, hash, &call_connected);
                        packet::set_compound_mac(&mut call_connected, &mac);
                        let mut frames = frames;
                        frames.extend(ppp.start_network(now));
                        write_frames(&mut stream, &call_connected, &frames).await?;
                        continue;
                    }
                    None => frames,
                };
                write_frames(&mut stream, &[], &control).await?;
                if let Some(reason) = ppp.terminated() {
                    // The Terminate-Ack went out with that write.
                    return Err(io::Error::new(io::ErrorKind::ConnectionAborted, reason));
                }
            }
            Packet::Control(control) => match control.message {
                message::ECHO_REQUEST => {
                    stream
                        .write_all(&packet::bare_control(message::ECHO_RESPONSE))
                        .await?;
                    stream.flush().await?;
                }
                message::CALL_ABORT | message::CALL_DISCONNECT => {
                    return Err(refused(&control, "ended the call during setup"));
                }
                _ => {}
            },
        }
    }
}

fn refused(control: &packet::Control<'_>, what: &str) -> io::Error {
    let status = match packet::status(control) {
        Some((attribute, status)) => format!(" (attribute {attribute}, status {status:#x})"),
        None => String::new(),
    };
    io::Error::new(
        io::ErrorKind::ConnectionRefused,
        format!("SSTP: the server {what}{status}"),
    )
}

/// The request of [MS-SSTP] §3.2.4.1 and §4.1, and the server's `200`.
///
/// With Keenetic's camouflage on, the server answers only when the URI
/// carries the secret as its bare query string (`/sra_{...}/?<secret>`)
/// and is a web server to every other request: 404 to the standard URI,
/// 200 to `GET /`. Found by probing a KeeneticOS 4.3 router, since nothing
/// documents it; `secret=<secret>`, a cookie and the secret as a path all
/// got the 404. [MS-SSTP] §3.2.4.1 allows a query variable on the URI.
async fn http_request(
    stream: &mut TlsStream,
    reader: &mut PacketReader,
    host: &str,
    camouflage_secret: Option<&str>,
) -> io::Result<()> {
    let correlation: [u8; 16] = rand::random();
    let h = |range: std::ops::Range<usize>| {
        correlation[range]
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<String>()
    };
    let query = camouflage_secret
        .map(|s| format!("?{s}"))
        .unwrap_or_default();
    let request = format!(
        "SSTP_DUPLEX_POST /sra_{{BA195980-CD49-458b-9E23-C84EE0ADCD75}}/{query} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Length: 18446744073709551615\r\n\
         SSTPCORRELATIONID: {{{}-{}-{}-{}-{}}}\r\n\r\n",
        h(0..4),
        h(4..6),
        h(6..8),
        h(8..10),
        h(10..16)
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let header = reader.http_header(stream).await?;
    let status_line = header.split(|&b| b == b'\r').next().unwrap_or_default();
    let mut fields = status_line.split(|&b| b == b' ').filter(|f| !f.is_empty());
    let version = fields.next().unwrap_or_default();
    let code = fields.next().unwrap_or_default();
    if !(version.starts_with(b"HTTP/1.") && code == b"200") {
        let printable: String = String::from_utf8_lossy(status_line)
            .chars()
            .filter(|c| !c.is_control())
            .take(120)
            .collect();
        // A 404 is what a camouflaged server says to a request without its
        // secret, or with the wrong one; the secret itself stays out of it.
        let hint = match (code, camouflage_secret) {
            (b"404", None) => {
                " (a server with camouflage on answers this way: set camouflage_secret)"
            }
            (b"404", Some(_)) => " (the camouflage secret may be wrong)",
            _ => "",
        };
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("SSTP: the server answered the SSTP request with {printable:?}{hint}"),
        ));
    }
    Ok(())
}

/// Wait for the Call Connect Ack, answering echoes; a Nak or an Abort is
/// the server's refusal, and a Nak is not retried: it arrives only when the
/// server does not carry PPP ([MS-SSTP] note <10>), which a retry cannot
/// change.
async fn await_ack(
    stream: &mut TlsStream,
    reader: &mut PacketReader,
) -> io::Result<packet::BindingRequest> {
    loop {
        let raw = reader.next(stream).await?;
        let Packet::Control(control) = packet::parse(&raw)? else {
            // PPP before the Ack: the spec has the client drop it.
            continue;
        };
        match control.message {
            message::CALL_CONNECT_ACK => {
                return packet::binding_request(&control)?.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::Unsupported,
                        "SSTP: the server offered no usable crypto binding",
                    )
                });
            }
            message::CALL_CONNECT_NAK => return Err(refused(&control, "refused the call")),
            message::CALL_ABORT | message::CALL_DISCONNECT => {
                return Err(refused(&control, "ended the call during setup"));
            }
            message::ECHO_REQUEST => {
                stream
                    .write_all(&packet::bare_control(message::ECHO_RESPONSE))
                    .await?;
                stream.flush().await?;
            }
            _ => {}
        }
    }
}

/// `control` (a whole SSTP packet, or nothing), then each PPP frame as a
/// data packet, in one write.
async fn write_frames(
    stream: &mut TlsStream,
    control: &[u8],
    frames: &[Vec<u8>],
) -> io::Result<()> {
    if control.is_empty() && frames.is_empty() {
        return Ok(());
    }
    let mut out = control.to_vec();
    for frame in frames {
        out.extend_from_slice(&packet::data_header(frame.len()));
        out.extend_from_slice(frame);
    }
    stream.write_all(&out).await?;
    stream.flush().await
}

/// Reads whole SSTP packets out of the stream, keeping what arrives past
/// the last one.
#[derive(Default)]
struct PacketReader {
    buf: Vec<u8>,
}

impl PacketReader {
    async fn fill(&mut self, stream: &mut TlsStream) -> io::Result<()> {
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "SSTP: the server closed the connection during setup",
            ));
        }
        self.buf.extend_from_slice(&chunk[..n]);
        Ok(())
    }

    async fn next(&mut self, stream: &mut TlsStream) -> io::Result<Vec<u8>> {
        loop {
            if let Some(len) = packet::packet_len(&self.buf)?
                && self.buf.len() >= len
            {
                return Ok(self.buf.drain(..len).collect());
            }
            self.fill(stream).await?;
        }
    }

    async fn http_header(&mut self, stream: &mut TlsStream) -> io::Result<Vec<u8>> {
        loop {
            if let Some(end) = self.buf.windows(4).position(|w| w == b"\r\n\r\n") {
                return Ok(self.buf.drain(..end + 4).collect());
            }
            if self.buf.len() > MAX_HTTP_HEADER {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SSTP: the server's HTTP response has no end to its headers",
                ));
            }
            self.fill(stream).await?;
        }
    }

    fn into_pending(self) -> Vec<u8> {
        self.buf
    }
}

/// Settings from the outbound's config: the TLS client config, the name to
/// verify, the `Host` header.
pub fn tls_settings(
    tls: &crate::config::SstpTlsConfig,
    host: Option<&str>,
) -> io::Result<(
    Arc<rustls::ClientConfig>,
    rustls::pki_types::ServerName<'static>,
)> {
    let sni = if tls.sni_hostname.is_unspecified() {
        host.map(str::to_string)
    } else {
        // `""` sends no server name, as for the `tls` client.
        tls.sni_hostname
            .clone()
            .into_option()
            .filter(|s| !s.is_empty())
    };
    let config = Arc::new(crate::rustls_config_util::create_client_config(
        tls.verify,
        &tls.server_fingerprints.clone().into_vec(),
        &[],
        sni.is_some(),
        None,
        false,
    ));
    let name = sni.or_else(|| host.map(str::to_string)).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "SSTP: no name to verify the server certificate against",
        )
    })?;
    let server_name = rustls::pki_types::ServerName::try_from(name).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("SSTP: invalid server name: {e}"),
        )
    })?;
    Ok((config, server_name))
}
