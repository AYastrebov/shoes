//! From nothing to an open tunnel: TCP, TLS, the authentication exchange
//! (or a cookie from last time), `CONNECT`, under one deadline.
//!
//! One task, reading and writing in turn; nothing here is on the data
//! path. The session takes over the stream with any bytes already read
//! past the `CONNECT` reply.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use log::{debug, info, warn};
use tokio::io::AsyncWriteExt;

use super::auth::{self, Response};
use super::http::{self, Head, Request};
use crate::async_stream::AsyncStream;
use crate::config::Redacted;
use crate::crypto::{CryptoConnection, CryptoTlsStream, perform_crypto_handshake};

/// As SSTP's negotiation timer: the whole setup, from the first SYN to
/// the tunnel, in one minute.
pub const NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(60);
/// How long one address may take to accept the TCP connection before the
/// next is tried.
pub const CONNECT_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);
/// Forms answered before giving up: ocserv answers a username-and-password
/// form in one round, a server with a group choice in two; past that the
/// server is asking for something this client does not have.
const MAX_AUTH_ROUNDS: usize = 4;
/// The tunnel path, `cstp.c:243`.
const TUNNEL_PATH: &str = "/CSCOSSLC/tunnel";
/// The longest DPD or keepalive interval honoured, in seconds.
const MAX_INTERVAL_SECS: u64 = 86_400;
/// Headers on every auth request (`cstp.c:1280-1290`): the version of the
/// aggregate-auth exchange this client speaks.
const AUTH_HEADERS: [(&str, &str); 4] = [
    ("Accept", "*/*"),
    ("Accept-Encoding", "identity"),
    ("X-Transcend-Version", "1"),
    ("X-Aggregate-Auth", "1"),
];

pub type TlsStream = CryptoTlsStream<Box<dyn AsyncStream>>;

/// Everything the handshake needs, built once per connector.
pub struct Settings {
    pub address: crate::address::NetLocation,
    /// The `Host` header: the name the certificate is checked against, with
    /// the port when it is not 443.
    pub host: String,
    pub tls: Arc<rustls::ClientConfig>,
    pub server_name: rustls::pki_types::ServerName<'static>,
    pub bind_interface: Option<String>,
    pub no_delay: bool,
    pub username: String,
    pub password: Redacted<String>,
    pub group: Option<String>,
    /// The path the authentication is posted to.
    pub path: String,
    pub mtu: u16,
    pub camouflage_secret: Option<Redacted<String>>,
    pub connect_attempt_timeout: Duration,
}

/// What the `CONNECT` reply assigned (`cstp.c:397-651`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Link {
    pub ipv4: Option<(Ipv4Addr, u8)>,
    pub ipv6: Option<(Ipv6Addr, u8)>,
    pub dns: Vec<IpAddr>,
    /// The server's `X-CSTP-MTU`, capped by the configured one.
    pub mtu: u16,
    /// `X-CSTP-DPD`: send a DPD request after this long without receiving.
    pub dpd: Option<Duration>,
    /// `X-CSTP-Keepalive`: send a keepalive after this long without sending.
    pub keepalive: Option<Duration>,
    pub banner: Option<String>,
    pub split_includes: Vec<String>,
    pub split_excludes: Vec<String>,
}

pub struct Established {
    pub stream: TlsStream,
    /// Bytes read past the `CONNECT` reply: the first frames.
    pub pending: Vec<u8>,
    pub link: Link,
    /// The cookies to present next time, `webvpn` among them.
    pub cookies: Vec<(String, Redacted<String>)>,
}

/// `servers` are the address's resolved addresses, tried in order; the
/// whole of it is under `deadline`, which the caller sets so that a
/// cookie refused and the fresh login that follows share one negotiation
/// timeout ([`NEGOTIATION_TIMEOUT`]) rather than taking two. With
/// `cookies` from a previous session the authentication is skipped, and a
/// server that refuses them answers with `PermissionDenied`, which the
/// connector turns into a fresh authentication.
pub async fn establish_by(
    settings: &Settings,
    servers: &[SocketAddr],
    cookies: Option<&[(String, Redacted<String>)]>,
    deadline: tokio::time::Instant,
) -> io::Result<Established> {
    match tokio::time::timeout_at(deadline, run(settings, servers, cookies)).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "OpenConnect: no tunnel to {} within {} s",
                settings.address,
                NEGOTIATION_TIMEOUT.as_secs()
            ),
        )),
    }
}

/// The first of `servers` that accepts the connection, as
/// `SocketConnectorImpl::connect` does for the other outbounds.
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
        let attempt = async {
            match tokio::time::timeout(settings.connect_attempt_timeout, attempt).await {
                Ok(result) => result,
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "no answer within {} s",
                        settings.connect_attempt_timeout.as_secs_f32()
                    ),
                )),
            }
        };
        match attempt.await {
            Ok(tcp) => return Ok((tcp, server)),
            Err(e) => {
                debug!("OpenConnect: connecting to {server}: {e}; trying the next address");
                last = Some(io::Error::new(
                    e.kind(),
                    format!("OpenConnect: connecting to {server}: {e}"),
                ));
            }
        }
    }
    Err(last.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("OpenConnect: {} resolved to no address", settings.address),
        )
    }))
}

async fn run(
    settings: &Settings,
    servers: &[SocketAddr],
    cookies: Option<&[(String, Redacted<String>)]>,
) -> io::Result<Established> {
    let (tcp, server) = connect_any(settings, servers).await?;
    let context = |e: io::Error| {
        io::Error::new(
            e.kind(),
            format!("OpenConnect: connecting to {server}: {e}"),
        )
    };
    if settings.no_delay {
        tcp.set_nodelay(true).map_err(context)?;
    }
    let mut io: Box<dyn AsyncStream> = Box::new(tcp);
    let mut client =
        rustls::ClientConnection::new(settings.tls.clone(), settings.server_name.clone())
            .map_err(|e| context(io::Error::other(e)))?;
    // rustls truncates a plaintext write to the room under its 64 KiB
    // buffer limit (`vecbuf.rs:65-72`, rustls 0.23), and a truncated frame
    // would go out as two records, which ocserv ends the session on.
    // `CryptoTlsStream::poll_write` drains each write's record to the
    // socket before the next, so the limit cannot bite a frame today (a
    // stalled server was tried, and no write was ever truncated); lifting
    // it keeps the one-frame-per-record rule from depending on that. What
    // rustls buffers is bounded by the writer, which hands it one frame at
    // a time and flushes each burst.
    client.set_buffer_limit(None);
    let mut connection = CryptoConnection::new_rustls_client(client);
    perform_crypto_handshake(&mut connection, &mut io, 16384)
        .await
        .map_err(context)?;
    let mut stream = CryptoTlsStream::new(io, connection);
    let mut reader = http::Reader::default();

    let mut jar = Jar {
        cookies: cookies.map(<[_]>::to_vec).unwrap_or_default(),
    };
    // ocserv checks the camouflage secret on the first POST of a
    // connection and then not again (`worker-vpn.c:1060-1073`); on a later
    // request it would stay in the URL and miss the handler. A reconnect
    // with the cookie makes no POST and sends no secret: the tunnel is
    // gated on the cookie.
    let mut first_request = true;
    if jar.webvpn().is_none() {
        authenticate(
            settings,
            &mut stream,
            &mut reader,
            &mut jar,
            &mut first_request,
        )
        .await?;
    } else {
        debug!("OpenConnect: reconnecting to {server} with the session cookie");
    }

    let link = connect(settings, server, &mut stream, &mut reader, &jar).await?;
    info!(
        "OpenConnect: connected to {server}: {}{}, MTU {}, DNS {:?}",
        link.ipv4
            .map(|(a, p)| format!("{a}/{p}"))
            .unwrap_or_else(|| "no IPv4".into()),
        link.ipv6
            .map(|(a, p)| format!(" {a}/{p}"))
            .unwrap_or_default(),
        link.mtu,
        link.dns
    );
    Ok(Established {
        stream,
        pending: reader.into_pending(),
        link,
        cookies: jar.cookies,
    })
}

struct Jar {
    cookies: Vec<(String, Redacted<String>)>,
}

impl Jar {
    fn webvpn(&self) -> Option<&str> {
        self.cookies
            .iter()
            .find(|(name, _)| name == "webvpn")
            .map(|(_, v)| v.expose().as_str())
    }

    /// Every `Set-Cookie` the server sends is kept and returned, as
    /// openconnect does (`http.c:1432-1437`); an empty value is the
    /// server deleting it.
    fn take(&mut self, head: &Head) {
        for (name, value) in head.cookies() {
            self.cookies.retain(|(n, _)| n != name);
            if !value.is_empty() {
                self.cookies
                    .push((name.to_string(), value.to_string().into()));
            }
        }
    }

    fn exposed(&self) -> Vec<(String, String)> {
        self.cookies
            .iter()
            .map(|(n, v)| (n.clone(), v.expose().clone()))
            .collect()
    }
}

fn target(path: &str, secret: Option<&Redacted<String>>, first_request: &mut bool) -> String {
    let with_secret = std::mem::replace(first_request, false);
    match secret {
        Some(secret) if with_secret => format!("{path}?{}", secret.expose()),
        _ => path.to_string(),
    }
}

/// The exchange of `auth.c:1386-1789`, reduced to what a username and
/// password can answer.
async fn authenticate(
    settings: &Settings,
    stream: &mut TlsStream,
    reader: &mut http::Reader,
    jar: &mut Jar,
    first_request: &mut bool,
) -> io::Result<()> {
    let group_access = format!("https://{}{}", settings.host, settings.path);
    let mut document = auth::init_document(&group_access, settings.group.as_deref());
    let mut path = settings.path.clone();
    let mut credentials_posted = false;
    for _ in 0..MAX_AUTH_ROUNDS {
        let (head, body) = post(
            settings,
            stream,
            reader,
            jar,
            &target(&path, settings.camouflage_secret.as_ref(), first_request),
            &document,
        )
        .await?;
        jar.take(&head);
        match head.status {
            200 => {}
            // A 401 before any credential went out is not a refusal of the
            // credentials: ocserv with `camouflage_realm` set answers the
            // secretless request that way (`worker-vpn.c:1066-1069`).
            401 if credentials_posted => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "OpenConnect: authentication failed ({})",
                        server_text(settings, &head.reason)
                    ),
                ));
            }
            status => return Err(refused(settings, status, &head)),
        }
        let body = String::from_utf8_lossy(&body);
        match auth::parse_response(&body)? {
            Response::Success { session_token } => {
                if let Some(token) = session_token
                    && jar.webvpn().is_none()
                {
                    jar.cookies.push(("webvpn".to_string(), token.into()));
                }
                if jar.webvpn().is_none() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "OpenConnect: the server said the login succeeded but set no session cookie",
                    ));
                }
                return Ok(());
            }
            Response::Auth {
                id,
                form,
                opaque,
                message,
                error,
            } => {
                let Some(form) = form else {
                    let what = error
                        .or(message)
                        .map(|m| server_text(settings, &m))
                        .unwrap_or_else(|| format!("auth {id:?} with no form"));
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!("OpenConnect: authentication failed: {what}"),
                    ));
                };
                if let Some(error) = &error {
                    // A form with an error is the server asking again after
                    // a refusal; the credentials are what they are.
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!(
                            "OpenConnect: authentication failed: {}",
                            server_text(settings, error)
                        ),
                    ));
                }
                document = auth::reply_document(
                    &form,
                    opaque.as_ref(),
                    &settings.username,
                    settings.password.expose(),
                    settings.group.as_deref(),
                )?;
                credentials_posted = true;
                if let Some(action) = form.action.filter(|a| !a.is_empty()) {
                    path = action;
                }
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "OpenConnect: the server kept asking for credentials after {MAX_AUTH_ROUNDS} forms"
        ),
    ))
}

async fn post(
    settings: &Settings,
    stream: &mut TlsStream,
    reader: &mut http::Reader,
    jar: &Jar,
    target: &str,
    document: &str,
) -> io::Result<(Head, Vec<u8>)> {
    let cookies = jar.exposed();
    let mut headers: Vec<(&str, String)> = AUTH_HEADERS
        .iter()
        .map(|(k, v)| (*k, v.to_string()))
        .collect();
    if auth::IS_MOBILE {
        headers.push((
            "X-AnyConnect-Identifier-Platform",
            auth::PLATFORM.to_string(),
        ));
    }
    // draft §2.2.2: pad the request to a multiple of 64 bytes so the
    // credentials' lengths do not show in the record sizes.
    let unpadded = Request {
        method: "POST",
        target,
        host: &settings.host,
        user_agent: auth::USER_AGENT,
        cookies: &cookies,
        headers: &headers,
        body: Some(("application/xml; charset=utf-8", document.as_bytes())),
    }
    .encoded_len();
    // "X-Pad: " and "\r\n" are 9 bytes; the value fills the rest.
    let pad = (64 - (unpadded + 9) % 64) % 64;
    headers.push(("X-Pad", "0".repeat(pad)));
    let request = Request {
        method: "POST",
        target,
        host: &settings.host,
        user_agent: auth::USER_AGENT,
        cookies: &cookies,
        headers: &headers,
        body: Some(("application/xml; charset=utf-8", document.as_bytes())),
    };
    stream.write_all(&request.to_bytes()).await?;
    stream.flush().await?;
    let head = reader.head(stream).await?;
    let body = reader.body(stream, &head).await?;
    Ok((head, body))
}

fn printable(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).take(200).collect()
}

/// Server-supplied text for an error, with the credentials taken out: a
/// gateway that echoes the username, or worse, into its refusal must not
/// have it land in a log.
fn server_text(settings: &Settings, text: &str) -> String {
    redacted(text, &settings.username, settings.password.expose())
}

/// The redaction first, on the text as the server sent it, then the
/// filtering and the cut: a password that straddles the cut, or one with
/// a control character in it, would otherwise escape the match.
fn redacted(text: &str, username: &str, password: &str) -> String {
    let mut text = text.to_string();
    for secret in [password, username] {
        if !secret.is_empty() {
            text = text.replace(secret, "[redacted]");
        }
    }
    printable(&text)
}

/// A status other than 200 to an auth request or to `CONNECT`. A 404 is
/// what a camouflaged server says without its secret; ocserv's `401` with
/// a realm is the same with `camouflage_realm` set, and its `405` is a
/// refused cookie under camouflage.
fn refused(settings: &Settings, status: u16, head: &Head) -> io::Error {
    let camouflaged = settings.camouflage_secret.is_some();
    let hint = match (status, camouflaged) {
        (401 | 404, false) => {
            " (a server with camouflage on answers this way: set camouflage_secret)"
        }
        (401 | 404 | 405, true) => " (the camouflage secret may be wrong)",
        _ => "",
    };
    let reason = head.get("x-reason").unwrap_or(head.reason.as_str());
    io::Error::new(
        io::ErrorKind::ConnectionRefused,
        format!(
            "OpenConnect: the server answered {status} {}{hint}",
            server_text(settings, reason)
        ),
    )
}

/// `CONNECT /CSCOSSLC/tunnel` (`cstp.c:243-325`) and its reply.
async fn connect(
    settings: &Settings,
    server: SocketAddr,
    stream: &mut TlsStream,
    reader: &mut http::Reader,
    jar: &Jar,
) -> io::Result<Link> {
    // The tunnel MTU this side wants, and the link MTU it implies: ocserv
    // takes the smaller of its own and `X-CSTP-Base-MTU` as the link MTU
    // and answers with it less the IP and UDP headers (`worker-vpn.c:2315-2317`,
    // `:2724-2728`, `worker.h:219-220`), so the base is the tunnel MTU
    // plus those.
    let ip_header: u16 = if server.is_ipv6() { 40 } else { 20 };
    let base_mtu = settings.mtu.saturating_add(ip_header + 8);
    let cookies = jar.exposed();
    let headers: Vec<(&str, String)> = vec![
        ("X-CSTP-Version", "1".into()),
        ("X-CSTP-Hostname", "shoes".into()),
        // `cstp.c:253-255`: "some servers only allow connection if they
        // see a shibboleth in the form of a standard copyright blurb".
        (
            "X-CSTP-Protocol",
            "Copyright (c) 2004 Cisco Systems, Inc.".into(),
        ),
        ("X-CSTP-Base-MTU", base_mtu.to_string()),
        ("X-CSTP-MTU", settings.mtu.to_string()),
        ("X-CSTP-Address-Type", "IPv6,IPv4".into()),
        ("X-CSTP-Full-IPv6-Capability", "true".into()),
    ];
    // Never with the secret: ocserv does not run the camouflage check on
    // CONNECT (`worker-vpn.c:1060-1061`), compares the URL whole
    // (`worker-vpn.c:2219-2226`), and gates the tunnel on the cookie alone
    // (`worker-auth.c:1280-1320`).
    let request = Request {
        method: "CONNECT",
        target: TUNNEL_PATH,
        host: &settings.host,
        user_agent: auth::USER_AGENT,
        cookies: &cookies,
        headers: &headers,
        body: None,
    };
    stream.write_all(&request.to_bytes()).await?;
    stream.flush().await?;
    let head = reader.head(stream).await?;
    match head.status {
        200 => {}
        // `cstp.c:379-380`; and ocserv under camouflage answers a refused
        // cookie with 405 instead (`worker-auth.c:1300-1304`).
        401 | 405 => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "OpenConnect: the server refused the session cookie",
            ));
        }
        status => return Err(refused(settings, status, &head)),
    }
    parse_connect_reply(&head, settings.mtu)
}

fn prefix_of_netmask(mask: Ipv4Addr) -> u8 {
    u32::from(mask).count_ones() as u8
}

/// The headers of `cstp.c:527-651` that this client acts on.
pub fn parse_connect_reply(head: &Head, configured_mtu: u16) -> io::Result<Link> {
    let mut link = Link::default();
    let mut ipv4: Option<Ipv4Addr> = None;
    let mut netmask4: Option<Ipv4Addr> = None;
    let mut ipv6: Option<Ipv6Addr> = None;
    let mut prefix6: Option<u16> = None;
    let mut mtu: Option<u16> = None;
    // A day is longer than any interval a server means; past it the
    // deadline arithmetic (`2 * dpd`, `Instant + keepalive`) would overflow
    // on a value a server chose badly or maliciously.
    let seconds = |v: &str| {
        v.trim()
            .parse::<u64>()
            .ok()
            .filter(|s| *s > 0)
            .map(|s| s.min(MAX_INTERVAL_SECS))
    };
    for (name, value) in &head.headers {
        let Some(key) = name.strip_prefix("x-cstp-") else {
            continue;
        };
        let value = value.trim();
        match key {
            "address" => {
                if let Ok(a) = value.parse::<Ipv6Addr>() {
                    ipv6 = Some(a);
                } else if let Ok(a) = value.parse::<Ipv4Addr>() {
                    ipv4 = Some(a);
                }
            }
            "netmask" => {
                if let Ok(m) = value.parse::<Ipv4Addr>() {
                    netmask4 = Some(m);
                } else if let Some((_, p)) = value.split_once('/') {
                    prefix6 = Some(p.parse::<u16>().unwrap_or(u16::MAX));
                }
            }
            "address-ip6" => {
                if let Some((a, p)) = value.split_once('/')
                    && let Ok(a) = a.parse::<Ipv6Addr>()
                {
                    ipv6 = Some(a);
                    prefix6 = Some(p.parse::<u16>().unwrap_or(u16::MAX));
                }
            }
            "dns" | "dns-ip6" => {
                if let Ok(ip) = value.parse::<IpAddr>() {
                    link.dns.push(ip);
                }
            }
            "mtu" => mtu = value.parse::<u16>().ok(),
            "dpd" => link.dpd = seconds(value).map(Duration::from_secs),
            "keepalive" => link.keepalive = seconds(value).map(Duration::from_secs),
            "banner" => link.banner = Some(printable(value)),
            "split-include" | "split-include-ip6" => link.split_includes.push(value.into()),
            "split-exclude" | "split-exclude-ip6" => link.split_excludes.push(value.into()),
            "content-encoding" => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!(
                        "OpenConnect: the server chose compression {value:?}, which was not offered"
                    ),
                ));
            }
            _ => {}
        }
    }
    let Some(mtu) = mtu else {
        // `cstp.c:645-650`: "No MTU received. Aborting".
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "OpenConnect: the server named no MTU",
        ));
    };
    // Below IPv4's minimum reassembly size nothing can cross the tunnel;
    // zero would refuse every packet the netstack offered.
    if mtu < 576 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("OpenConnect: the server named an MTU of {mtu}, below 576"),
        ));
    }
    link.mtu = mtu.min(configured_mtu);
    link.ipv4 = ipv4.map(|a| (a, netmask4.map(prefix_of_netmask).unwrap_or(32)));
    // smoltcp's `IpCidr::new` panics on a prefix past 128; a server's
    // reply must fail, not the process.
    if let Some(prefix) = prefix6
        && prefix > 128
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("OpenConnect: the server's IPv6 prefix /{prefix} is not valid"),
        ));
    }
    link.ipv6 = ipv6.map(|a| (a, prefix6.map(|p| p as u8).unwrap_or(128)));
    if link.ipv4.is_none() && link.ipv6.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "OpenConnect: the server assigned no address",
        ));
    }
    if !link.split_includes.is_empty() {
        warn!(
            "OpenConnect: the server sent split routes {:?}; shoes routes by its own rules and carries whatever they send",
            link.split_includes
        );
    }
    Ok(link)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests")]
    use super::*;

    fn head(lines: &[(&str, &str)]) -> Head {
        Head {
            status: 200,
            reason: "CONNECTED".into(),
            headers: lines
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    /// The reply ocserv sends (`worker-vpn.c:2260-2760`), as the HTTP
    /// reader lowercases it.
    #[test]
    fn ocservs_connect_reply_is_read() {
        let link = parse_connect_reply(
            &head(&[
                ("x-cstp-version", "1"),
                ("x-cstp-server-name", "ocserv"),
                ("x-cstp-dpd", "90"),
                ("x-cstp-default-domain", "example.com"),
                ("x-cstp-address", "192.168.1.7"),
                ("x-cstp-netmask", "255.255.255.0"),
                ("x-cstp-address-ip6", "fd00::7/64"),
                ("x-cstp-netmask", "fd00::7/64"),
                ("x-cstp-dns", "192.168.1.1"),
                ("x-cstp-dns", "fd00::1"),
                ("x-cstp-split-include", "10.0.0.0/255.0.0.0"),
                ("x-cstp-keepalive", "32400"),
                ("x-cstp-idle-timeout", "none"),
                ("x-cstp-rekey-time", "172800"),
                ("x-cstp-rekey-method", "ssl"),
                ("x-cstp-base-mtu", "1434"),
                ("x-cstp-mtu", "1406"),
                ("x-cstp-banner", "Welcome"),
            ]),
            1500,
        )
        .unwrap();
        assert_eq!(link.ipv4, Some((Ipv4Addr::new(192, 168, 1, 7), 24)));
        assert_eq!(link.ipv6, Some(("fd00::7".parse().unwrap(), 64)));
        assert_eq!(
            link.dns,
            [
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                "fd00::1".parse().unwrap()
            ]
        );
        assert_eq!(link.mtu, 1406);
        assert_eq!(link.dpd, Some(Duration::from_secs(90)));
        assert_eq!(link.keepalive, Some(Duration::from_secs(32400)));
        assert_eq!(link.banner.as_deref(), Some("Welcome"));
        assert_eq!(link.split_includes, ["10.0.0.0/255.0.0.0"]);
    }

    #[test]
    fn the_configured_mtu_caps_the_servers() {
        let link = parse_connect_reply(
            &head(&[("x-cstp-address", "10.0.0.2"), ("x-cstp-mtu", "1406")]),
            1280,
        )
        .unwrap();
        assert_eq!(
            (link.mtu, link.ipv4),
            (1280, Some((Ipv4Addr::new(10, 0, 0, 2), 32)))
        );
    }

    #[test]
    fn no_mtu_no_address_or_compression_is_refused() {
        let err = parse_connect_reply(&head(&[("x-cstp-address", "10.0.0.2")]), 1280).unwrap_err();
        assert!(err.to_string().contains("no MTU"), "{err}");
        let err = parse_connect_reply(&head(&[("x-cstp-mtu", "1300")]), 1280).unwrap_err();
        assert!(err.to_string().contains("no address"), "{err}");
        let err = parse_connect_reply(
            &head(&[
                ("x-cstp-address", "10.0.0.2"),
                ("x-cstp-mtu", "1300"),
                ("x-cstp-content-encoding", "lzs"),
            ]),
            1280,
        )
        .unwrap_err();
        assert!(err.to_string().contains("compression"), "{err}");
    }

    /// A prefix smoltcp would panic on fails the reply instead, and one
    /// that is not a number is not silently /128.
    #[test]
    fn an_invalid_ipv6_prefix_is_refused() {
        for bad in ["fd00::7/129", "fd00::7/300", "fd00::7/x"] {
            let err = parse_connect_reply(
                &head(&[("x-cstp-address-ip6", bad), ("x-cstp-mtu", "1300")]),
                1280,
            )
            .unwrap_err();
            assert!(err.to_string().contains("prefix"), "{bad}: {err}");
        }
        let link = parse_connect_reply(
            &head(&[
                ("x-cstp-address", "fd00::7"),
                ("x-cstp-netmask", "fd00::/127"),
                ("x-cstp-mtu", "1300"),
            ]),
            1280,
        )
        .unwrap();
        assert_eq!(link.ipv6, Some(("fd00::7".parse().unwrap(), 127)));
    }

    /// An interval past a day is a day: `2 * dpd` must not overflow.
    #[test]
    fn an_absurd_interval_is_clamped() {
        let link = parse_connect_reply(
            &head(&[
                ("x-cstp-address", "10.0.0.2"),
                ("x-cstp-mtu", "1300"),
                ("x-cstp-dpd", "18446744073709551615"),
                ("x-cstp-keepalive", "99999999999999999999999"),
            ]),
            1280,
        )
        .unwrap();
        assert_eq!(link.dpd, Some(Duration::from_secs(86_400)));
        assert_eq!(link.keepalive, None, "not a u64: no keepalive");
    }

    #[test]
    fn a_tiny_mtu_is_refused() {
        for bad in ["0", "575"] {
            let err = parse_connect_reply(
                &head(&[("x-cstp-address", "10.0.0.2"), ("x-cstp-mtu", bad)]),
                1280,
            )
            .unwrap_err();
            assert!(err.to_string().contains("below 576"), "{bad}: {err}");
        }
    }

    /// The credentials come out of server text before it is filtered or
    /// cut: a password across the 200-character cut, or one carrying a
    /// control character, must not survive as a fragment.
    #[test]
    fn credentials_are_redacted_before_the_text_is_cut_or_filtered() {
        let password = "hunter2hunter2";
        let straddling = format!("{}{password}", "x".repeat(195));
        let out = redacted(&straddling, "alice", password);
        assert!(!out.contains("hunter"), "{out}");
        assert!(
            out.len() <= 200 && out.ends_with("[reda"),
            "the cut falls on the marker: {out}"
        );
        let tabbed = "a\tb";
        let out = redacted("refused: a\tb for alice", "alice", tabbed);
        assert_eq!(out, "refused: [redacted] for [redacted]");
        assert_eq!(redacted("plain", "", ""), "plain");
    }

    #[test]
    fn a_zero_dpd_means_none() {
        let link = parse_connect_reply(
            &head(&[
                ("x-cstp-address", "10.0.0.2"),
                ("x-cstp-mtu", "1300"),
                ("x-cstp-dpd", "0"),
            ]),
            1280,
        )
        .unwrap();
        assert_eq!(link.dpd, None);
    }

    #[test]
    fn the_secret_goes_on_the_first_request_only() {
        let secret: Redacted<String> = "s3cret".to_string().into();
        let mut first = true;
        assert_eq!(target("/", Some(&secret), &mut first), "/?s3cret");
        assert_eq!(target("/auth", Some(&secret), &mut first), "/auth");
        let mut first = true;
        assert_eq!(target("/", None, &mut first), "/");
    }
}
