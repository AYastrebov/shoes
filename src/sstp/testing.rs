//! An SSTP server in miniature, for the end-to-end tests.
//!
//! It speaks the server's half of everything the client does: the HTTP
//! request, SSTP call setup, LCP, MS-CHAPv2 or PAP, IPCP. It checks crypto
//! binding as accel-ppp does (`accel-pppd/ctrl/sstp/sstp.c:1737-1792`):
//! the Cert Hash against its own certificate, the Compound MAC against one
//! it computes from its own side's keys. The IP packets the client sends go
//! into a small smoltcp interface at [`SERVER_IP`] that echoes TCP and UDP
//! on [`ECHO_PORT`], so the client's whole data path runs: netstack, PPP,
//! SSTP, TLS, TCP.
//!
//! The spec put the far side in shoes' TUN stack; that module compiles only
//! for the mobile targets and `--features ffi`, so the default test build
//! could not have run it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "a test double: a panic is the failure report"
)]

use std::cell::RefCell;
use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

use smoltcp::iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{Notify, mpsc};

use super::crypto::{self, BindingHash};
use super::packet::{self, Packet, message};
use super::ppp::{self, code, protocol};

pub const SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 1);
pub const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 2);
pub const DNS_IP: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 53);
pub const ECHO_PORT: u16 = 7;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ServerAuth {
    MsChapV2,
    Pap,
    /// Proposes EAP first and moves to MS-CHAPv2 when refused, as SoftEther
    /// does (`Proto_PPP.c:946-961`).
    EapThenMsChapV2,
    /// Insists on EAP however often it is refused.
    EapOnly,
}

#[derive(Clone)]
pub struct Options {
    /// Keenetic's camouflage: answer the SSTP request only when its URI
    /// carries this as the query string, and be a web server otherwise.
    pub camouflage_secret: Option<&'static str>,
    pub auth: ServerAuth,
    pub hash_bitmask: u8,
    pub username: &'static str,
    pub password: &'static str,
    pub mru: u16,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            camouflage_secret: None,
            auth: ServerAuth::MsChapV2,
            hash_bitmask: 0x03,
            username: "alice",
            password: "correct horse",
            mru: 1500,
        }
    }
}

#[derive(Default)]
pub struct Stats {
    pub sessions: AtomicUsize,
    pub bindings_verified: AtomicUsize,
    pub bindings_refused: AtomicUsize,
    /// TLS records of type application data the client sent.
    pub client_records: AtomicUsize,
    /// IP packets the client sent.
    pub client_packets: AtomicUsize,
    /// Call Disconnect Acks the client sent: its answer to this server's
    /// Call Disconnect, which must get out before the session ends.
    pub disconnect_acks: AtomicUsize,
    /// IP packets that arrived before Call Connected, which the spec has a
    /// client never send.
    pub early_packets: AtomicUsize,
    /// Rung to make every live session send Call Disconnect.
    pub disconnect: Notify,
    /// Rung to make every live session send three malformed PPP frames: an
    /// empty one, one of `FF 03` alone, and an LCP packet whose Length
    /// field runs past it. RFC 1661 §5 has the client discard them.
    pub garbage: Notify,
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
    let fingerprint = BindingHash::Sha256
        .cert_hash(&cert_der)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    let server_stats = stats.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let (config, cert_der, options, stats) = (
                config.clone(),
                cert_der.clone(),
                options.clone(),
                server_stats.clone(),
            );
            tokio::spawn(async move {
                let _ = serve(tcp, config, cert_der, options, stats).await;
            });
        }
    });

    TestServer {
        address,
        fingerprint,
        stats,
    }
}

async fn serve(
    tcp: TcpStream,
    config: Arc<rustls::ServerConfig>,
    cert_der: Vec<u8>,
    options: Options,
    stats: Arc<Stats>,
) -> std::io::Result<()> {
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
    let mut chunk = [0u8; 4096];
    let end = loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break end + 4;
        }
        let n = tls.read(&mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let expected_target = match options.camouflage_secret {
        Some(secret) => format!("/sra_{{BA195980-CD49-458b-9E23-C84EE0ADCD75}}/?{secret}"),
        None => "/sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/".to_string(),
    };
    let request_line =
        String::from_utf8_lossy(buf.split(|&b| b == b'\r').next().unwrap_or_default()).to_string();
    let mut words = request_line.split(' ');
    let (method, target) = (words.next().unwrap_or(""), words.next().unwrap_or(""));
    assert_eq!(method, "SSTP_DUPLEX_POST", "{request_line}");
    if target != expected_target {
        // What a Keenetic with camouflage on says to a request without its
        // secret: a web server's 404, and nothing that names SSTP.
        assert!(options.camouflage_secret.is_some(), "{request_line}");
        tls.write_all(b"HTTP/1.1 404 Not Found\r\nServer: Web server\r\nContent-Length: 0\r\n\r\n")
            .await?;
        return Ok(());
    }
    let header = String::from_utf8_lossy(&buf[..end]).to_string();
    assert!(
        header.contains("Content-Length: 18446744073709551615\r\n"),
        "{header}"
    );
    assert!(header.contains("SSTPCORRELATIONID: {"), "{header}");
    buf.drain(..end);
    tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\n\r\n")
        .await?;
    stats.sessions.fetch_add(1, Ordering::SeqCst);

    let (mut read, mut write) = tokio::io::split(tls);
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(async move {
        while let Some(bytes) = out_rx.recv().await {
            if write.write_all(&bytes).await.is_err() || write.flush().await.is_err() {
                return;
            }
        }
    });
    let (ip_tx, ip_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(far_side(ip_rx, out_tx.clone()));

    let mut server = Session {
        options,
        cert_der,
        stats: stats.clone(),
        out: out_tx,
        ip: ip_tx,
        nonce: rand::random(),
        challenge: rand::random(),
        hlak: None,
        lcp_acked_by_client: false,
        lcp_acked_client: false,
        auth_started: false,
        ipcp_requested: false,
        connected: false,
        eap_refusals: 0,
    };
    loop {
        while let Some(len) = packet::packet_len(&buf)? {
            if buf.len() < len {
                break;
            }
            let raw: Vec<u8> = buf.drain(..len).collect();
            if !server.handle(&raw)? {
                return Ok(());
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
                server.send_control(packet::bare_control(message::CALL_DISCONNECT));
            }
            _ = stats.garbage.notified() => {
                for frame in [vec![], vec![0xff, 0x03], ppp::frame(protocol::LCP, &[9, 1, 0xff, 0xff])] {
                    let mut bytes = packet::data_header(frame.len()).to_vec();
                    bytes.extend_from_slice(&frame);
                    server.send_control(bytes);
                }
            }
        }
    }
}

struct Session {
    options: Options,
    cert_der: Vec<u8>,
    stats: Arc<Stats>,
    out: mpsc::UnboundedSender<Vec<u8>>,
    ip: mpsc::UnboundedSender<Vec<u8>>,
    nonce: [u8; 32],
    challenge: [u8; 16],
    hlak: Option<[u8; 32]>,
    lcp_acked_by_client: bool,
    lcp_acked_client: bool,
    auth_started: bool,
    ipcp_requested: bool,
    connected: bool,
    eap_refusals: u32,
}

fn send_frame(out: &mpsc::UnboundedSender<Vec<u8>>, protocol: u16, info: &[u8]) {
    let frame = ppp::frame(protocol, info);
    let mut bytes = packet::data_header(frame.len()).to_vec();
    bytes.extend_from_slice(&frame);
    let _ = out.send(bytes);
}

impl Session {
    fn send_control(&self, bytes: Vec<u8>) {
        let _ = self.out.send(bytes);
    }

    fn send(&self, protocol: u16, info: &[u8]) {
        send_frame(&self.out, protocol, info);
    }

    fn auth_option(&self) -> Vec<u8> {
        match self.options.auth {
            ServerAuth::MsChapV2 => vec![0xc2, 0x23, 0x81],
            ServerAuth::Pap => vec![0xc0, 0x23],
            ServerAuth::EapThenMsChapV2 if self.eap_refusals > 0 => vec![0xc2, 0x23, 0x81],
            ServerAuth::EapThenMsChapV2 | ServerAuth::EapOnly => vec![0xc2, 0x27],
        }
    }

    fn lcp_request(&self) {
        let options = vec![
            (1u8, self.options.mru.to_be_bytes().to_vec()),
            (3, self.auth_option()),
            (5, vec![0xca, 0xfe, 0xba, 0xbe]),
        ];
        self.send(
            protocol::LCP,
            &ppp::control(code::CONFIGURE_REQUEST, 1, &ppp::encode_options(&options)),
        );
    }

    /// Handle one SSTP packet; `false` ends the session.
    fn handle(&mut self, raw: &[u8]) -> std::io::Result<bool> {
        match packet::parse(raw)? {
            Packet::Control(control) => match control.message {
                message::CALL_CONNECT_REQUEST => {
                    self.send_control(packet::call_connect_ack(
                        self.options.hash_bitmask,
                        &self.nonce,
                    ));
                    self.lcp_request();
                }
                message::CALL_CONNECTED => return Ok(self.check_binding(raw)),
                message::ECHO_REQUEST => {
                    self.send_control(packet::bare_control(message::ECHO_RESPONSE))
                }
                message::CALL_DISCONNECT => {
                    self.send_control(packet::bare_control(message::CALL_DISCONNECT_ACK));
                    return Ok(false);
                }
                message::CALL_DISCONNECT_ACK => {
                    self.stats.disconnect_acks.fetch_add(1, Ordering::SeqCst);
                    return Ok(false);
                }
                message::CALL_ABORT => return Ok(false),
                _ => {}
            },
            Packet::Data(frame) => {
                let (proto, info) = ppp::split_frame(frame)?;
                match proto {
                    protocol::IPV4 => {
                        if self.connected {
                            self.stats.client_packets.fetch_add(1, Ordering::SeqCst);
                            let _ = self.ip.send(info.to_vec());
                        } else {
                            self.stats.early_packets.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                    protocol::LCP => self.lcp(info),
                    protocol::CHAP => self.chap(info),
                    protocol::PAP => self.pap(info),
                    protocol::IPCP => self.ipcp(info),
                    _ => {}
                }
            }
        }
        Ok(true)
    }

    fn lcp(&mut self, info: &[u8]) {
        let packet = ppp::parse_control(info).unwrap();
        match packet.code {
            code::CONFIGURE_REQUEST => {
                let options = ppp::parse_options(packet.data).unwrap();
                assert!(
                    options.iter().all(|(k, _)| [1, 5].contains(k)),
                    "the client asks only for MRU and a magic number: {options:?}"
                );
                self.send(
                    protocol::LCP,
                    &ppp::control(code::CONFIGURE_ACK, packet.id, packet.data),
                );
                self.lcp_acked_client = true;
            }
            code::CONFIGURE_ACK => self.lcp_acked_by_client = true,
            code::CONFIGURE_NAK => {
                self.eap_refusals += 1;
                self.lcp_request();
            }
            code::ECHO_REQUEST => {
                let mut data = vec![0xca, 0xfe, 0xba, 0xbe];
                data.extend_from_slice(&packet.data[4..]);
                self.send(
                    protocol::LCP,
                    &ppp::control(code::ECHO_REPLY, packet.id, &data),
                );
            }
            code::TERMINATE_REQUEST => self.send(
                protocol::LCP,
                &ppp::control(code::TERMINATE_ACK, packet.id, &[]),
            ),
            _ => {}
        }
        if self.lcp_acked_by_client && self.lcp_acked_client && !self.auth_started {
            self.auth_started = true;
            if self.auth_option() == [0xc2, 0x23, 0x81] {
                let mut data = vec![16];
                data.extend_from_slice(&self.challenge);
                data.extend_from_slice(b"test-server");
                self.send(protocol::CHAP, &ppp::control(1, 1, &data));
            }
        }
    }

    fn chap(&mut self, info: &[u8]) {
        let packet = ppp::parse_control(info).unwrap();
        if packet.code != 2 {
            return;
        }
        let value = &packet.data[1..50];
        let peer_challenge: [u8; 16] = value[..16].try_into().unwrap();
        let nt_response: [u8; 24] = value[24..48].try_into().unwrap();
        let name = std::str::from_utf8(&packet.data[50..]).unwrap();
        let expected = crypto::generate_nt_response(
            &self.challenge,
            &peer_challenge,
            name,
            self.options.password,
        );
        if name != self.options.username || expected != nt_response {
            self.send(
                protocol::CHAP,
                &ppp::control(
                    4,
                    packet.id,
                    b"E=691 R=0 C=00000000000000000000000000000000 V=3 M=refused",
                ),
            );
            return;
        }
        let authenticator = crypto::authenticator_response(
            self.options.password,
            &nt_response,
            &peer_challenge,
            &self.challenge,
            name,
        );
        let hex: String = authenticator.iter().map(|b| format!("{b:02X}")).collect();
        self.send(
            protocol::CHAP,
            &ppp::control(3, packet.id, format!("S={hex} M=welcome").as_bytes()),
        );
        // The server's HLAK is its MasterReceiveKey | MasterSendKey
        // ([MS-SSTP] §3.2.5.2.2), from its own side of RFC 3079.
        let keys = crypto::mppe_keys(self.options.password, &nt_response, true);
        let mut hlak = [0u8; 32];
        hlak[..16].copy_from_slice(&*keys.receive);
        hlak[16..].copy_from_slice(&*keys.send);
        self.hlak = Some(hlak);
    }

    fn pap(&mut self, info: &[u8]) {
        let packet = ppp::parse_control(info).unwrap();
        let user_len = usize::from(packet.data[0]);
        let user = &packet.data[1..1 + user_len];
        let pass = &packet.data[2 + user_len..];
        if user == self.options.username.as_bytes() && pass == self.options.password.as_bytes() {
            self.send(protocol::PAP, &ppp::control(2, packet.id, &[0]));
            self.hlak = Some([0; 32]);
        } else {
            self.send(protocol::PAP, &ppp::control(3, packet.id, b"\x07refused"));
        }
    }

    fn check_binding(&mut self, raw: &[u8]) -> bool {
        let parsed = packet::parse_call_connected(raw).unwrap();
        let hash = match parsed.hash_protocol {
            0x01 => BindingHash::Sha1,
            _ => BindingHash::Sha256,
        };
        let good = self.hlak.is_some_and(|hlak| {
            parsed.nonce == self.nonce
                && parsed.cert_hash == hash.cert_hash(&self.cert_der)
                && parsed.compound_mac == crypto::compound_mac(&hlak, hash, &parsed.zeroed)
        });
        if good {
            self.stats.bindings_verified.fetch_add(1, Ordering::SeqCst);
            self.connected = true;
        } else {
            self.stats.bindings_refused.fetch_add(1, Ordering::SeqCst);
            self.send_control(packet::bare_control(message::CALL_ABORT));
        }
        good
    }

    fn ipcp(&mut self, info: &[u8]) {
        let packet = ppp::parse_control(info).unwrap();
        // The client's Configure-Ack of the server's request needs nothing.
        if packet.code != code::CONFIGURE_REQUEST {
            return;
        }
        if !self.ipcp_requested {
            self.ipcp_requested = true;
            let options = vec![(3u8, SERVER_IP.octets().to_vec())];
            self.send(
                protocol::IPCP,
                &ppp::control(code::CONFIGURE_REQUEST, 1, &ppp::encode_options(&options)),
            );
        }
        let options = ppp::parse_options(packet.data).unwrap();
        // No secondary DNS here: the client must cope with a reject.
        let reject: ppp::Options = options.iter().filter(|(k, _)| *k == 131).cloned().collect();
        if !reject.is_empty() {
            self.send(
                protocol::IPCP,
                &ppp::control(
                    code::CONFIGURE_REJECT,
                    packet.id,
                    &ppp::encode_options(&reject),
                ),
            );
            return;
        }
        let mut nak = ppp::Options::new();
        for (kind, value) in &options {
            match (*kind, value.as_slice()) {
                (3, v) if v != CLIENT_IP.octets() => nak.push((3, CLIENT_IP.octets().to_vec())),
                (129, v) if v != DNS_IP.octets() => nak.push((129, DNS_IP.octets().to_vec())),
                _ => {}
            }
        }
        let reply = if nak.is_empty() {
            ppp::control(code::CONFIGURE_ACK, packet.id, packet.data)
        } else {
            ppp::control(code::CONFIGURE_NAK, packet.id, &ppp::encode_options(&nak))
        };
        self.send(protocol::IPCP, &reply);
    }
}

/// The network behind the server: an interface at [`SERVER_IP`] echoing
/// TCP and UDP on [`ECHO_PORT`].
async fn far_side(
    mut ip_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    out: mpsc::UnboundedSender<Vec<u8>>,
) {
    let mut device = Queue::default();
    let mut config = InterfaceConfig::new(HardwareAddress::Ip);
    config.random_seed = rand::random();
    let mut iface = Interface::new(config, &mut device, crate::util::smol_now());
    iface.update_ip_addrs(|addrs| {
        addrs
            .push(IpCidr::new(IpAddress::Ipv4(SERVER_IP), 24))
            .unwrap();
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
            let _ = socket.send_slice(&scratch[..n], meta.endpoint);
        }
        iface.poll(now, &mut device, &mut sockets);
        for ip in device.tx.borrow_mut().drain(..) {
            send_frame(&out, protocol::IPV4, &ip);
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
/// data (23) the client sends: how the batching test sees records.
struct RecordCounter {
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
