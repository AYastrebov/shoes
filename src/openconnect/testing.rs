//! An OpenConnect server in miniature, for the end-to-end tests: ocserv's
//! half of the exchange. The auth forms are ocserv's templates
//! (`worker-auth.c:51-106`), the `CONNECT` reply its headers
//! (`worker-vpn.c:2260-2760`), the frames its rules (`worker-vpn.c:2837-3040`).
//! The IP packets the client sends go into a smoltcp interface at
//! [`SERVER_IP`] (and [`SERVER_IP6`]) that echoes TCP and UDP on
//! [`ECHO_PORT`], so the client's whole data path runs.
//!
//! ocserv reads one TLS record per frame and fails a session whose record
//! holds other than one (`worker-vpn.c:1836-1843`, `:3005-3030`). This
//! double cannot see record boundaries through the TLS library, so it
//! counts the client's application-data records on the raw socket and the
//! client's frames after `CONNECT`; a test asserts they match.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "a test double: a panic is the failure report"
)]

use std::cell::RefCell;
use std::collections::{HashSet, VecDeque};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use smoltcp::iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{Notify, mpsc};

use super::cstp::{self, kind};
use super::xml;

pub const SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 99, 1, 1);
pub const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 99, 1, 7);
pub const SERVER_IP6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x99, 0, 0, 0, 0, 0, 1);
pub const CLIENT_IP6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x99, 0, 0, 0, 0, 0, 7);
pub const DNS_IP: Ipv4Addr = Ipv4Addr::new(10, 99, 1, 53);
pub const ECHO_PORT: u16 = 7;

#[derive(Clone)]
pub struct Options {
    /// ocserv's camouflage: the first request of a connection must carry
    /// this as its query string, else the answer is a web server's 404.
    pub camouflage_secret: Option<&'static str>,
    /// With camouflage: answer the secretless request with ocserv's
    /// `camouflage_realm` 401 instead of the 404.
    pub camouflage_realm: bool,
    pub username: &'static str,
    pub password: &'static str,
    /// The groups offered in a `<select>`; none means no select.
    pub groups: Vec<&'static str>,
    /// Ask for a second password in a second form, as ocserv with two
    /// passwords configured does.
    pub second_password: bool,
    /// Echo the submitted username and password in the 401's reason and in
    /// a second form's label, as a careless gateway might; the client's
    /// error must not repeat them.
    pub echo_credentials: bool,
    /// After a correct login, ask for the password again in a form, as a
    /// challenge or one-time-code server does.
    pub ask_password_again: bool,
    /// Assign an IPv6 address too.
    pub ipv6: bool,
    /// `X-CSTP-DPD` and `X-CSTP-Keepalive`, in seconds; 0 omits the header.
    pub dpd: u32,
    pub keepalive: u32,
    /// The link MTU, from which `X-CSTP-MTU` is derived as ocserv does.
    pub link_mtu: u16,
    /// Shrink the accepted socket's receive buffer to this, so a stalled
    /// server backs the client up within a few kilobytes instead of the
    /// megabytes loopback otherwise absorbs.
    pub receive_buffer: Option<usize>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            camouflage_secret: None,
            camouflage_realm: false,
            username: "alice",
            password: "correct horse",
            groups: vec![],
            second_password: false,
            echo_credentials: false,
            ask_password_again: false,
            ipv6: false,
            dpd: 90,
            keepalive: 32400,
            link_mtu: 1434,
            receive_buffer: None,
        }
    }
}

#[derive(Default)]
pub struct Stats {
    /// Successful authentications.
    pub logins: AtomicUsize,
    /// `CONNECT`s accepted.
    pub sessions: AtomicUsize,
    /// TLS records of application data the client sent, on every
    /// connection.
    pub client_records: AtomicUsize,
    /// CSTP frames the client sent after `CONNECT`, of every type.
    pub client_frames: AtomicUsize,
    /// IP packets among them.
    pub client_packets: AtomicUsize,
    /// DPD requests the client sent.
    pub client_dpd_requests: AtomicUsize,
    /// DPD responses the client sent to this server's requests.
    pub client_dpd_responses: AtomicUsize,
    /// Keepalives the client sent.
    pub client_keepalives: AtomicUsize,
    /// DISCONNECT frames the client sent, with the user-disconnect reason.
    pub byes: AtomicUsize,
    /// The groups the client selected, in order.
    pub groups_selected: Mutex<Vec<String>>,
    /// Make the next `CONNECT` refuse its cookie with a 401, once.
    pub refuse_next_cookie: AtomicBool,
    /// Stop answering DPD requests and sending anything: a dead peer.
    pub mute: AtomicBool,
    /// Milliseconds the tunnel stops reading the client for, once: the
    /// client's socket fills, and its TLS layer with it.
    pub stall_ms: AtomicU64,
    /// Rung to make the far side send a 1400-byte UDP datagram to the last
    /// UDP peer it heard from.
    pub big_packet: Notify,
    /// The last UDP endpoint the far side received from.
    last_udp_peer: Mutex<Option<smoltcp::wire::IpEndpoint>>,
    /// Rung to make every live session send DISCONNECT.
    pub disconnect: Notify,
    /// Rung to make every live session send TERMINATE.
    pub terminate: Notify,
    /// Rung to make every live session send a DPD request with a payload.
    pub dpd: Notify,
    /// Rung to make every live session send a DPD request whose echo would
    /// not fit one TLS record.
    pub big_dpd: Notify,
    /// Rung to make every live session send a frame of an unknown type and
    /// then a data packet.
    pub unknown_frame: Notify,
    /// Cookies issued, which `CONNECT` must present one of.
    cookies: Mutex<HashSet<String>>,
}

pub struct TestServer {
    pub address: SocketAddr,
    /// SHA-256 of the certificate, as `server_fingerprints` takes it.
    pub fingerprint: String,
    pub stats: Arc<Stats>,
}

pub async fn start(options: Options) -> TestServer {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = certified.cert.der().to_vec();
    let config = Arc::new(crate::rustls_config_util::create_server_config(
        certified.cert.pem().as_bytes(),
        certified.signing_key.serialize_pem().as_bytes(),
        vec![],
        &[],
        &[],
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let stats = Arc::new(Stats::default());
    let fingerprint = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &cert_der)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    let server_stats = stats.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let (config, options, stats) = (config.clone(), options.clone(), server_stats.clone());
            tokio::spawn(async move {
                let _ = serve(tcp, config, options, stats).await;
            });
        }
    });

    TestServer {
        address,
        fingerprint,
        stats,
    }
}

struct RequestHead {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
}

impl RequestHead {
    fn get(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    fn cookie(&self, name: &str) -> Option<&str> {
        self.get("cookie")?
            .split(';')
            .filter_map(|c| c.trim().split_once('='))
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v)
    }
}

/// One request's head and body; `Ok(None)` when the client went away.
async fn read_request<S: AsyncRead + Unpin>(
    stream: &mut S,
    buf: &mut Vec<u8>,
) -> std::io::Result<Option<(RequestHead, Vec<u8>, usize)>> {
    let mut chunk = [0u8; 4096];
    let end = loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break end + 4;
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let text = String::from_utf8_lossy(&buf[..end]).to_string();
    let mut lines = text.split("\r\n");
    let mut words = lines.next().unwrap_or_default().split(' ');
    let head = RequestHead {
        method: words.next().unwrap_or_default().to_string(),
        target: words.next().unwrap_or_default().to_string(),
        headers: lines
            .filter_map(|l| l.split_once(':'))
            .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
            .collect(),
    };
    buf.drain(..end);
    let len: usize = head
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    while buf.len() < len {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let body: Vec<u8> = buf.drain(..len).collect();
    Ok(Some((head, body, end + len)))
}

const FORM_HEAD: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
    <config-auth client=\"vpn\" type=\"auth-request\">\n<version who=\"sg\">0.1(1)</version>\n";

fn login_form(options: &Options, message: &str, second: bool) -> String {
    let mut doc = format!(
        "{FORM_HEAD}<auth id=\"main\">\n<message>{message}</message>\n<form method=\"post\" action=\"/auth\">\n"
    );
    if second {
        let label = if options.echo_credentials {
            format!("Password2 ({}):", options.password)
        } else {
            "Password2:".to_string()
        };
        doc.push_str(&format!(
            "<input type=\"password\" name=\"secondary_password\" label=\"{label}\" />\n",
        ));
    } else {
        doc.push_str("<input type=\"text\" name=\"username\" label=\"Username:\" />\n");
        doc.push_str("<input type=\"password\" name=\"password\" label=\"Password:\" />\n");
        if !options.groups.is_empty() {
            doc.push_str("<select name=\"group_list\" label=\"Group:\">\n");
            for group in &options.groups {
                doc.push_str(&format!("<option>{group}</option>\n"));
            }
            doc.push_str("</select>\n");
        }
    }
    doc.push_str("</form></auth>\n</config-auth>");
    doc
}

const SUCCESS: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
    <config-auth client=\"vpn\" type=\"complete\">\n<version who=\"sg\">0.1(1)</version>\n\
    <auth id=\"success\">\n<title>SSL VPN Service</title></auth></config-auth>\n";

async fn respond<S: AsyncWrite + Unpin>(
    stream: &mut S,
    status: &str,
    extra_headers: &[String],
    body: &str,
) -> std::io::Result<()> {
    let mut out = format!("HTTP/1.1 {status}\r\n");
    for h in extra_headers {
        out.push_str(h);
        out.push_str("\r\n");
    }
    out.push_str(&format!(
        "Content-Type: text/xml; charset=utf-8\r\nContent-Length: {}\r\nX-Transcend-Version: 1\r\n\r\n{body}",
        body.len()
    ));
    stream.write_all(out.as_bytes()).await?;
    stream.flush().await
}

async fn serve(
    tcp: TcpStream,
    config: Arc<rustls::ServerConfig>,
    options: Options,
    stats: Arc<Stats>,
) -> std::io::Result<()> {
    if let Some(size) = options.receive_buffer {
        socket2::SockRef::from(&tcp)
            .set_recv_buffer_size(size)
            .unwrap();
    }
    let counted = RecordCounter {
        inner: tcp,
        stats: stats.clone(),
        header: Vec::new(),
        remaining: 0,
    };
    let mut tls = tokio_rustls::TlsAcceptor::from(config)
        .accept(counted)
        .await?;
    let mut buf = Vec::new();
    let mut camouflage_passed = options.camouflage_secret.is_none();
    let mut auth_state = AuthState::Inactive;
    let context: String = (0..8)
        .map(|_| format!("{:02x}", rand::random::<u8>()))
        .collect();

    loop {
        let Some((head, body, request_len)) = read_request(&mut tls, &mut buf).await? else {
            return Ok(());
        };
        // ocserv checks the secret on GET and POST until it has passed once
        // on the connection (`worker-vpn.c:1060-1073`), and strips it from
        // the URL only then: a query on any other request stays in the URL
        // and matches no handler, a 404 (`worker-vpn.c:1076-1082`).
        let checked_before = camouflage_passed;
        if head.target.contains('?') && (checked_before || head.method == "CONNECT") {
            tls.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                .await?;
            return Ok(());
        }
        if !camouflage_passed && head.method != "CONNECT" {
            let secret = options.camouflage_secret.unwrap();
            match head.target.split_once('?') {
                Some((_, query)) if query == secret || query.starts_with(&format!("{secret}&")) => {
                    camouflage_passed = true;
                }
                _ => {
                    // `worker-vpn.c:1066-1069`: a 401 with the realm when
                    // one is configured, else a 404.
                    if options.camouflage_realm {
                        tls.write_all(
                            b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"intranet\"\r\nContent-Length: 0\r\n\r\n",
                        )
                        .await?;
                    } else {
                        tls.write_all(
                            b"HTTP/1.1 404 Not Found\r\nServer: nginx\r\nContent-Length: 0\r\n\r\n",
                        )
                        .await?;
                    }
                    return Ok(());
                }
            }
        }
        let path = head
            .target
            .split('?')
            .next()
            .unwrap_or_default()
            .to_string();
        let agent = head.get("user-agent").unwrap_or_default();
        assert!(
            agent.starts_with("AnyConnect-compatible OpenConnect"),
            "the user agent selects ocserv's modern forms: {agent}"
        );
        match head.method.as_str() {
            "POST" => {
                assert_eq!(head.get("x-aggregate-auth"), Some("1"));
                assert!(head.get("x-pad").is_some(), "the request is padded");
                assert_eq!(
                    request_len % 64,
                    0,
                    "the padded request is a multiple of 64 bytes, not {request_len}"
                );
                let doc = xml::parse(&String::from_utf8_lossy(&body)).unwrap();
                assert_eq!(doc.name, "config-auth");
                let kind = doc.attribute("type").unwrap_or_default().to_string();
                let set_context =
                    format!("Set-Cookie: webvpncontext={context}; Max-Age=300; Secure; HttpOnly");
                match (kind.as_str(), &auth_state) {
                    ("init", _) => {
                        assert_eq!(path, "/");
                        assert_eq!(doc.child("version").unwrap().attribute("who"), Some("vpn"));
                        assert!(doc.child("device-id").is_some());
                        assert!(
                            doc.child("group-access")
                                .unwrap()
                                .text()
                                .starts_with("https://"),
                            "group-access is the URL"
                        );
                        auth_state = AuthState::Asked;
                        respond(
                            &mut tls,
                            "200 OK",
                            &[set_context],
                            &login_form(
                                &options,
                                "Please enter your username and password.",
                                false,
                            ),
                        )
                        .await?;
                    }
                    ("auth-reply", AuthState::Asked) => {
                        assert_eq!(path, "/auth");
                        assert_eq!(head.cookie("webvpncontext"), Some(context.as_str()));
                        let auth = doc.child("auth").unwrap();
                        let username = auth.child("username").map(xml::Element::text);
                        let password = auth.child("password").map(xml::Element::text);
                        if let Some(group) = doc.child("group-select") {
                            let group = group.text();
                            assert!(options.groups.contains(&group.as_str()), "{group}");
                            stats.groups_selected.lock().unwrap().push(group);
                        } else {
                            assert!(
                                options.groups.is_empty(),
                                "a group was offered and none chosen"
                            );
                        }
                        let ok = username.as_deref() == Some(options.username)
                            && password.as_deref() == Some(options.password);
                        if !ok {
                            // `worker-auth.c:2287-2297`.
                            let reason = if options.echo_credentials {
                                format!(
                                    "Authentication failed for {}:{}",
                                    username.unwrap_or_default(),
                                    password.unwrap_or_default()
                                )
                            } else {
                                "Authentication failed".to_string()
                            };
                            tls.write_all(
                                format!("HTTP/1.1 401 {reason}\r\nContent-Length: 0\r\n\r\n")
                                    .as_bytes(),
                            )
                            .await?;
                            return Ok(());
                        }
                        if options.second_password {
                            auth_state = AuthState::AskedSecond;
                            respond(
                                &mut tls,
                                "200 OK",
                                &[set_context],
                                &login_form(&options, "Please enter your password.", true),
                            )
                            .await?;
                            continue;
                        }
                        if options.ask_password_again {
                            auth_state = AuthState::AskedSecond;
                            let challenge = format!(
                                "{FORM_HEAD}<auth id=\"main\">\n<message>Enter the next token</message>\n\
                                 <form method=\"post\" action=\"/auth\">\n\
                                 <input type=\"password\" name=\"password\" label=\"Challenge:\" />\n\
                                 </form></auth>\n</config-auth>"
                            );
                            respond(&mut tls, "200 OK", &[set_context], &challenge).await?;
                            continue;
                        }
                        auth_state = AuthState::Done;
                        let cookie: String = (0..16)
                            .map(|_| format!("{:02x}", rand::random::<u8>()))
                            .collect();
                        stats.cookies.lock().unwrap().insert(cookie.clone());
                        stats.logins.fetch_add(1, Ordering::SeqCst);
                        respond(
                            &mut tls,
                            "200 OK",
                            &[
                                "Connection: Keep-Alive".to_string(),
                                format!("Set-Cookie: webvpncontext={context}; Secure; HttpOnly"),
                                format!("Set-Cookie: webvpn={cookie}; Secure; HttpOnly"),
                                "Set-Cookie: webvpnc=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/; Secure; HttpOnly".to_string(),
                            ],
                            SUCCESS,
                        )
                        .await?;
                    }
                    ("auth-reply", AuthState::AskedSecond) => {
                        panic!(
                            "the client answered a second-factor form: {}",
                            String::from_utf8_lossy(&body)
                        );
                    }
                    other => panic!("unexpected {other:?}"),
                }
            }
            "CONNECT" => {
                assert_eq!(path, "/CSCOSSLC/tunnel");
                let presented = head.cookie("webvpn").map(str::to_string);
                let known = presented
                    .as_ref()
                    .is_some_and(|c| stats.cookies.lock().unwrap().contains(c));
                if !known || stats.refuse_next_cookie.swap(false, Ordering::SeqCst) {
                    // `worker-auth.c:1296-1312`: 405 under camouflage
                    // before the check passed, else 401.
                    let status = if options.camouflage_secret.is_some() && !camouflage_passed {
                        "405 Method Not Allowed"
                    } else {
                        "401 Cookie is not acceptable"
                    };
                    tls.write_all(format!("HTTP/1.1 {status}\r\n\r\n").as_bytes())
                        .await?;
                    return Ok(());
                }
                assert_eq!(head.get("x-cstp-version"), Some("1"));
                assert!(head.get("x-cstp-mtu").is_some());
                assert!(head.get("x-cstp-base-mtu").is_some());
                assert!(
                    head.get("x-cstp-address-type")
                        .is_some_and(|t| t.contains("IPv4"))
                );
                stats.sessions.fetch_add(1, Ordering::SeqCst);
                let link_mtu: u16 = head
                    .get("x-cstp-base-mtu")
                    .and_then(|v| v.parse().ok())
                    .map(|v: u16| v.min(options.link_mtu))
                    .unwrap_or(options.link_mtu);
                // `worker-vpn.c:2724-2728`, `worker.h:219`: the data MTU
                // is the link MTU less the IP and UDP headers.
                let data_mtu = link_mtu - 28;
                let mut reply = String::from(
                    "HTTP/1.1 200 CONNECTED\r\nX-CSTP-Version: 1\r\nX-CSTP-Server-Name: ocserv\r\n",
                );
                if options.dpd > 0 {
                    reply.push_str(&format!("X-CSTP-DPD: {}\r\n", options.dpd));
                }
                reply.push_str(&format!(
                    "X-CSTP-Address: {CLIENT_IP}\r\nX-CSTP-Netmask: 255.255.255.0\r\n"
                ));
                if options.ipv6 {
                    reply.push_str(&format!(
                        "X-CSTP-Address-IP6: {CLIENT_IP6}/64\r\nX-CSTP-Netmask: {CLIENT_IP6}/64\r\n"
                    ));
                }
                reply.push_str(&format!("X-CSTP-DNS: {DNS_IP}\r\n"));
                if options.keepalive > 0 {
                    reply.push_str(&format!("X-CSTP-Keepalive: {}\r\n", options.keepalive));
                }
                reply.push_str(&format!(
                    "X-CSTP-Idle-Timeout: none\r\nX-CSTP-Smartcard-Removal-Disconnect: true\r\n\
                     X-CSTP-Rekey-Time: 172800\r\nX-CSTP-Rekey-Method: ssl\r\n\
                     X-CSTP-Session-Timeout: none\r\nX-CSTP-Disconnected-Timeout: none\r\n\
                     X-CSTP-Keep: true\r\nX-CSTP-TCP-Keepalive: true\r\nX-CSTP-License: accept\r\n\
                     X-CSTP-Base-MTU: {link_mtu}\r\nX-CSTP-MTU: {data_mtu}\r\n\r\n"
                ));
                tls.write_all(reply.as_bytes()).await?;
                tls.flush().await?;
                return tunnel(tls, buf, options, stats).await;
            }
            other => panic!("unexpected method {other}"),
        }
    }
}

#[derive(Debug)]
enum AuthState {
    Inactive,
    Asked,
    AskedSecond,
    Done,
}

async fn tunnel(
    tls: tokio_rustls::server::TlsStream<RecordCounter>,
    mut buf: Vec<u8>,
    options: Options,
    stats: Arc<Stats>,
) -> std::io::Result<()> {
    let (mut read, mut write) = tokio::io::split(tls);
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(async move {
        // One frame per write, as ocserv sends them.
        while let Some(bytes) = out_rx.recv().await {
            if write.write_all(&bytes).await.is_err() || write.flush().await.is_err() {
                return;
            }
        }
    });
    let (ip_tx, ip_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(far_side(ip_rx, out_tx.clone(), options.ipv6, stats.clone()));
    let send = |kind: u8, payload: &[u8]| {
        let mut frame = Vec::new();
        cstp::encode(&mut frame, kind, payload);
        let _ = out_tx.send(frame);
    };

    let mut chunk = [0u8; 4096];
    loop {
        let stall = stats.stall_ms.swap(0, Ordering::SeqCst);
        if stall > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(stall)).await;
        }
        while let Some(len) = cstp::frame_len(&buf)? {
            if buf.len() < len {
                break;
            }
            let frame: Vec<u8> = buf.drain(..len).collect();
            stats.client_frames.fetch_add(1, Ordering::SeqCst);
            let (kind, payload) = cstp::parse(&frame);
            match kind {
                kind::DATA => {
                    stats.client_packets.fetch_add(1, Ordering::SeqCst);
                    let _ = ip_tx.send(payload.to_vec());
                }
                kind::DPD_REQUEST => {
                    stats.client_dpd_requests.fetch_add(1, Ordering::SeqCst);
                    if !stats.mute.load(Ordering::SeqCst) {
                        send(kind::DPD_RESPONSE, payload);
                    }
                }
                kind::DPD_RESPONSE => {
                    assert!(
                        payload == b"probe" || payload.is_empty(),
                        "the response carries the request's contents, or nothing for a request too big to echo"
                    );
                    stats.client_dpd_responses.fetch_add(1, Ordering::SeqCst);
                }
                kind::KEEPALIVE => {
                    stats.client_keepalives.fetch_add(1, Ordering::SeqCst);
                }
                kind::DISCONNECT => {
                    assert_eq!(payload.first(), Some(&cstp::BYE_USER_DISCONNECT));
                    stats.byes.fetch_add(1, Ordering::SeqCst);
                    return Ok(());
                }
                other => panic!("the client sent a frame of type {other}"),
            }
        }
        tokio::select! {
            read = read.read(&mut chunk) => {
                let n = read?;
                if n == 0 {
                    return Ok(());
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            _ = stats.disconnect.notified() => {
                send(kind::DISCONNECT, &[cstp::BYE_USER_DISCONNECT]);
                return Ok(());
            }
            _ = stats.terminate.notified() => {
                send(kind::TERMINATE, &[]);
                return Ok(());
            }
            _ = stats.dpd.notified() => send(kind::DPD_REQUEST, b"probe"),
            _ = stats.big_dpd.notified() => send(kind::DPD_REQUEST, &[0x41; cstp::MAX_PAYLOAD]),
            _ = stats.unknown_frame.notified() => {
                send(42, b"what is this");
                send(kind::KEEPALIVE, &[]);
            }
        }
    }
}

/// The network behind the server: an interface at [`SERVER_IP`] (and
/// [`SERVER_IP6`]) echoing TCP and UDP on [`ECHO_PORT`].
async fn far_side(
    mut ip_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    out: mpsc::UnboundedSender<Vec<u8>>,
    ipv6: bool,
    stats: Arc<Stats>,
) {
    let mut send_big = false;
    let mut device = Queue::default();
    let mut config = InterfaceConfig::new(HardwareAddress::Ip);
    config.random_seed = rand::random();
    let mut iface = Interface::new(config, &mut device, crate::util::smol_now());
    iface.update_ip_addrs(|addrs| {
        addrs
            .push(IpCidr::new(IpAddress::Ipv4(SERVER_IP), 24))
            .unwrap();
        if ipv6 {
            addrs
                .push(IpCidr::new(IpAddress::Ipv6(SERVER_IP6), 64))
                .unwrap();
        }
    });
    let mut sockets = SocketSet::new(vec![]);
    let mut tcp: Vec<SocketHandle> = Vec::new();
    for _ in 0..16 {
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 256 * 1024]),
            tcp::SocketBuffer::new(vec![0; 256 * 1024]),
        );
        socket.listen(ECHO_PORT).unwrap();
        tcp.push(sockets.add(socket));
    }
    let mut socket = udp::Socket::new(
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 64], vec![0; 64 * 2048]),
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 64], vec![0; 64 * 2048]),
    );
    socket.bind(ECHO_PORT).unwrap();
    let udp_handle = sockets.add(socket);
    let mut scratch = vec![0u8; 64 * 1024];

    loop {
        let now = crate::util::smol_now();
        iface.poll(now, &mut device, &mut sockets);
        for handle in &tcp {
            let socket = sockets.get_mut::<tcp::Socket>(*handle);
            while socket.can_recv() && socket.can_send() {
                let room = socket.send_capacity() - socket.send_queue();
                let take = room.min(scratch.len());
                let n = socket.recv_slice(&mut scratch[..take]).unwrap();
                if n == 0 {
                    break;
                }
                socket.send_slice(&scratch[..n]).unwrap();
            }
            if socket.state() == tcp::State::CloseWait && socket.send_queue() == 0 {
                socket.close();
            }
            if socket.state() == tcp::State::Closed {
                socket.listen(ECHO_PORT).unwrap();
            }
        }
        let socket = sockets.get_mut::<udp::Socket>(udp_handle);
        while let Ok((n, meta)) = socket.recv_slice(&mut scratch) {
            *stats.last_udp_peer.lock().unwrap() = Some(meta.endpoint);
            let _ = socket.send_slice(&scratch[..n], meta.endpoint);
        }
        if std::mem::take(&mut send_big)
            && let Some(peer) = *stats.last_udp_peer.lock().unwrap()
        {
            socket.send_slice(&[0x42; 1400], peer).unwrap();
        }
        iface.poll(now, &mut device, &mut sockets);
        for ip in device.tx.borrow_mut().drain(..) {
            let mut frame = Vec::with_capacity(cstp::HEADER_LEN + ip.len());
            cstp::encode(&mut frame, kind::DATA, &ip);
            let _ = out.send(frame);
        }

        let delay = iface
            .poll_delay(crate::util::smol_now(), &sockets)
            .map(|d| std::time::Duration::from_micros(d.total_micros()))
            .unwrap_or(std::time::Duration::from_millis(50))
            .min(std::time::Duration::from_millis(5));
        tokio::select! {
            packet = ip_rx.recv() => match packet {
                Some(packet) => {
                    device.rx.push_back(packet);
                    while let Ok(packet) = ip_rx.try_recv() {
                        device.rx.push_back(packet);
                    }
                }
                None => return,
            },
            _ = stats.big_packet.notified() => send_big = true,
            _ = tokio::time::sleep(delay) => {}
        }
    }
}

#[derive(Default)]
struct Queue {
    rx: VecDeque<Vec<u8>>,
    tx: RefCell<Vec<Vec<u8>>>,
}

impl Device for Queue {
    type RxToken<'a> = QueueRx;
    type TxToken<'a> = QueueTx<'a>;

    fn receive(
        &mut self,
        _: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx.pop_front()?;
        Some((QueueRx(packet), QueueTx(&self.tx)))
    }

    fn transmit(&mut self, _: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        Some(QueueTx(&self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1500;
        caps
    }
}

struct QueueRx(Vec<u8>);

impl RxToken for QueueRx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

struct QueueTx<'a>(&'a RefCell<Vec<Vec<u8>>>);

impl TxToken for QueueTx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        self.0.borrow_mut().push(buffer);
        result
    }
}

/// The server's TCP stream, counting the TLS records of type application
/// data (23) the client sends.
pub struct RecordCounter {
    inner: TcpStream,
    stats: Arc<Stats>,
    header: Vec<u8>,
    remaining: usize,
}

impl RecordCounter {
    fn observe(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            if self.remaining > 0 {
                let n = self.remaining.min(bytes.len());
                self.remaining -= n;
                bytes = &bytes[n..];
                continue;
            }
            let n = (5 - self.header.len()).min(bytes.len());
            self.header.extend_from_slice(&bytes[..n]);
            bytes = &bytes[n..];
            if self.header.len() == 5 {
                if self.header[0] == 23 {
                    self.stats.client_records.fetch_add(1, Ordering::SeqCst);
                }
                self.remaining = usize::from(u16::from_be_bytes([self.header[3], self.header[4]]));
                self.header.clear();
            }
        }
    }
}

impl AsyncRead for RecordCounter {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = result {
            let read = buf.filled()[before..].to_vec();
            self.observe(&read);
        }
        result
    }
}

impl AsyncWrite for RecordCounter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
