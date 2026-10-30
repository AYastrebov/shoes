//! The client side of PPP over SSTP: LCP, MS-CHAPv2 or PAP, and IPCP, as a
//! state machine with no I/O. The handshake feeds it frames and the time,
//! and writes what it returns.
//!
//! RFC 1661's automaton reduced to a client that negotiates once
//! (docs/specs/2026-10-30-sstp-client-outbound.md, "Protocol summary"):
//! Configure-Requests are retransmitted every 3 s, at most 10 times;
//! Terminate-Request, Echo-Request and unknown protocols are answered; a
//! Configure-Request after the link opened ends the session rather than
//! being followed, because following it would change the MTU of a live
//! smoltcp interface.

use std::io;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use subtle::ConstantTimeEq;

use super::crypto::{self, Hlak};

pub mod protocol {
    pub const IPV4: u16 = 0x0021;
    pub const IPCP: u16 = 0x8021;
    pub const LCP: u16 = 0xc021;
    pub const PAP: u16 = 0xc023;
    pub const CHAP: u16 = 0xc223;
}

/// Configure-Request, -Ack, -Nak and -Reject, then the LCP-only codes.
pub mod code {
    pub const CONFIGURE_REQUEST: u8 = 1;
    pub const CONFIGURE_ACK: u8 = 2;
    pub const CONFIGURE_NAK: u8 = 3;
    pub const CONFIGURE_REJECT: u8 = 4;
    pub const TERMINATE_REQUEST: u8 = 5;
    pub const TERMINATE_ACK: u8 = 6;
    pub const CODE_REJECT: u8 = 7;
    pub const PROTOCOL_REJECT: u8 = 8;
    pub const ECHO_REQUEST: u8 = 9;
    pub const ECHO_REPLY: u8 = 10;
    pub const DISCARD_REQUEST: u8 = 11;
}

pub mod lcp_option {
    pub const MRU: u8 = 1;
    pub const AUTH_PROTOCOL: u8 = 3;
    pub const MAGIC_NUMBER: u8 = 5;
}

pub mod ipcp_option {
    pub const IP_ADDRESS: u8 = 3;
    pub const PRIMARY_DNS: u8 = 129;
    pub const SECONDARY_DNS: u8 = 131;
}

/// MS-CHAPv2's CHAP algorithm number (RFC 2759 §2).
const CHAP_MS_V2: u8 = 0x81;

/// RFC 1661 §4.6: the Restart timer and Max-Configure.
const RESTART: Duration = Duration::from_secs(3);
const MAX_CONFIGURE: u32 = 10;
/// How many Configure-Naks of the server's auth proposal before giving up
/// on a server that insists on a method we did not enable.
const MAX_AUTH_NAKS: u32 = 3;

/// The smallest MRU this accepts a peer naming. Below IPv4's minimum
/// reassembly size a TCP connection cannot carry an MSS worth having.
pub const MIN_MRU: u16 = 576;
/// The largest PPP information field an SSTP packet has room for: 4095,
/// less the SSTP header and `FF 03` plus the protocol.
pub const MAX_MRU: u16 = 4087;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    MsChapV2,
    Pap,
}

impl AuthMethod {
    fn name(self) -> &'static str {
        match self {
            AuthMethod::MsChapV2 => "MS-CHAPv2",
            AuthMethod::Pap => "PAP",
        }
    }

    /// The Auth-Protocol option's value for this method.
    fn option_value(self) -> Vec<u8> {
        match self {
            AuthMethod::MsChapV2 => {
                let [hi, lo] = protocol::CHAP.to_be_bytes();
                vec![hi, lo, CHAP_MS_V2]
            }
            AuthMethod::Pap => protocol::PAP.to_be_bytes().to_vec(),
        }
    }
}

/// The name of whatever an Auth-Protocol option asks for, for an error.
fn describe_auth(value: &[u8]) -> String {
    match value {
        [0xc2, 0x23, 0x81] => "MS-CHAPv2".into(),
        [0xc2, 0x23, 0x80] => "MS-CHAPv1".into(),
        [0xc2, 0x23, 0x05] => "CHAP-MD5".into(),
        [0xc2, 0x23, ..] => "CHAP".into(),
        [0xc0, 0x23] => "PAP".into(),
        [0xc2, 0x27, ..] => "EAP".into(),
        [hi, lo, ..] => format!("protocol 0x{hi:02x}{lo:02x}"),
        _ => "an unreadable method".into(),
    }
}

pub struct Credentials {
    pub username: String,
    pub password: crate::config::Redacted<String>,
}

/// What the network phase produced: the address the server assigned, the
/// DNS servers it offered, and the largest frame each side takes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub address: Ipv4Addr,
    pub dns: Vec<Ipv4Addr>,
    /// The server's MRU: the largest IP packet this side may send.
    pub peer_mru: u16,
}

fn malformed(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("PPP: malformed {what}"))
}

fn failed(kind: io::ErrorKind, message: String) -> io::Error {
    io::Error::new(kind, message)
}

/// A PPP frame: `FF 03`, the protocol, the information field.
pub fn frame(protocol: u16, info: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + info.len());
    out.extend_from_slice(&[0xff, 0x03]);
    out.extend_from_slice(&protocol.to_be_bytes());
    out.extend_from_slice(info);
    out
}

/// Split a PPP frame into its protocol and information field. Accepts a
/// frame without `FF 03` and a one-byte protocol, which RFC 1661 §6.5-6.6
/// forbid before ACFC and PFC are negotiated and this never negotiates:
/// tolerating a peer's slip costs a comparison, refusing it a dead tunnel.
pub fn split_frame(frame: &[u8]) -> io::Result<(u16, &[u8])> {
    let rest = frame.strip_prefix(&[0xff, 0x03]).unwrap_or(frame);
    match rest {
        [first, rest @ ..] if first & 1 == 1 => Ok((u16::from(*first), rest)),
        [hi, lo, rest @ ..] => Ok((u16::from_be_bytes([*hi, *lo]), rest)),
        _ => Err(malformed("frame")),
    }
}

/// A control packet: code, identifier, data. LCP, IPCP, PAP and CHAP share
/// the shape (RFC 1661 §5).
pub struct ControlPacket<'a> {
    pub code: u8,
    pub id: u8,
    pub data: &'a [u8],
}

pub fn parse_control(info: &[u8]) -> io::Result<ControlPacket<'_>> {
    if info.len() < 4 {
        return Err(malformed("control packet"));
    }
    let len = usize::from(u16::from_be_bytes([info[2], info[3]]));
    // Octets past the length are padding (§5); a length past the frame is
    // malformed.
    if len < 4 || len > info.len() {
        return Err(malformed("control packet length"));
    }
    Ok(ControlPacket {
        code: info[0],
        id: info[1],
        data: &info[4..len],
    })
}

pub fn control(code: u8, id: u8, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + data.len());
    out.extend_from_slice(&[code, id]);
    out.extend_from_slice(&((4 + data.len()) as u16).to_be_bytes());
    out.extend_from_slice(data);
    out
}

pub type Options = Vec<(u8, Vec<u8>)>;

pub fn parse_options(data: &[u8]) -> io::Result<Options> {
    let mut out = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        if rest.len() < 2 || rest[1] < 2 || usize::from(rest[1]) > rest.len() {
            return Err(malformed("option"));
        }
        let len = usize::from(rest[1]);
        out.push((rest[0], rest[2..len].to_vec()));
        rest = &rest[len..];
    }
    Ok(out)
}

pub fn encode_options(options: &Options) -> Vec<u8> {
    let mut out = Vec::new();
    for (kind, value) in options {
        out.push(*kind);
        out.push((2 + value.len()) as u8);
        out.extend_from_slice(value);
    }
    out
}

/// Our side of one control protocol's negotiation: the request we keep
/// sending until the peer acks it, and whether we have acked the peer's.
struct Negotiation {
    protocol: u16,
    options: Options,
    id: u8,
    sent_at: Option<Instant>,
    sent_count: u32,
    acked_by_peer: bool,
    acked_peer: bool,
}

impl Negotiation {
    fn new(protocol: u16, options: Options) -> Self {
        Negotiation {
            protocol,
            options,
            id: 0,
            sent_at: None,
            sent_count: 0,
            acked_by_peer: false,
            acked_peer: false,
        }
    }

    fn opened(&self) -> bool {
        self.acked_by_peer && self.acked_peer
    }

    fn request(&mut self, now: Instant) -> Vec<u8> {
        self.id = self.id.wrapping_add(1);
        self.sent_at = Some(now);
        self.sent_count += 1;
        frame(
            self.protocol,
            &control(
                code::CONFIGURE_REQUEST,
                self.id,
                &encode_options(&self.options),
            ),
        )
    }

    fn deadline(&self) -> Option<Instant> {
        match self.sent_at {
            Some(at) if !self.acked_by_peer => Some(at + RESTART),
            _ => None,
        }
    }

    fn retransmit(&mut self, now: Instant, name: &str) -> io::Result<Option<Vec<u8>>> {
        match self.deadline() {
            Some(deadline) if now >= deadline => {
                if self.sent_count >= MAX_CONFIGURE {
                    return Err(failed(
                        io::ErrorKind::TimedOut,
                        format!(
                            "PPP: {name} did not converge after {MAX_CONFIGURE} Configure-Requests"
                        ),
                    ));
                }
                Ok(Some(self.request(now)))
            }
            _ => Ok(None),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Establish,
    Authenticate,
    /// Authentication finished; the handshake has yet to send Call
    /// Connected and start IPCP.
    Authenticated,
    Network,
    Opened,
}

enum Auth {
    None,
    MsChapV2 {
        peer_challenge: [u8; 16],
        authenticator_challenge: [u8; 16],
        nt_response: [u8; 24],
        responded: bool,
    },
    Pap {
        id: u8,
        sent_at: Option<Instant>,
        sent_count: u32,
    },
}

pub struct Ppp {
    credentials: Credentials,
    methods: Vec<AuthMethod>,
    phase: Phase,
    lcp: Negotiation,
    ipcp: Negotiation,
    magic: u32,
    peer_mru: u16,
    auth_method: Option<AuthMethod>,
    auth: Auth,
    auth_naks: u32,
    hlak: Option<Hlak>,
    echo_id: u8,
}

impl Ppp {
    pub fn new(credentials: Credentials, methods: Vec<AuthMethod>, mru: u16) -> Self {
        let magic = nonzero_magic();
        Ppp {
            credentials,
            methods,
            phase: Phase::Establish,
            lcp: Negotiation::new(
                protocol::LCP,
                vec![
                    (lcp_option::MRU, mru.to_be_bytes().to_vec()),
                    (lcp_option::MAGIC_NUMBER, magic.to_be_bytes().to_vec()),
                ],
            ),
            ipcp: Negotiation::new(
                protocol::IPCP,
                vec![
                    (ipcp_option::IP_ADDRESS, vec![0; 4]),
                    (ipcp_option::PRIMARY_DNS, vec![0; 4]),
                    (ipcp_option::SECONDARY_DNS, vec![0; 4]),
                ],
            ),
            magic,
            // RFC 1661 §6.1: the default when the peer does not say.
            peer_mru: 1500,
            auth_method: None,
            auth: Auth::None,
            auth_naks: 0,
            hlak: None,
            echo_id: 0,
        }
    }

    /// The first LCP Configure-Request, sent the moment the Call Connect
    /// Ack arrives rather than after the server's own request.
    pub fn start(&mut self, now: Instant) -> Vec<Vec<u8>> {
        vec![self.lcp.request(now)]
    }

    /// The HLAK, once, when authentication has finished: the moment the
    /// handshake sends Call Connected. Then [`Ppp::start_network`].
    pub fn take_authenticated(&mut self) -> Option<Hlak> {
        if self.phase == Phase::Authenticated {
            self.hlak.take()
        } else {
            None
        }
    }

    /// IPCP's first Configure-Request, written in the same TLS write as
    /// Call Connected.
    pub fn start_network(&mut self, now: Instant) -> Vec<Vec<u8>> {
        self.phase = Phase::Network;
        vec![self.ipcp.request(now)]
    }

    /// The link, once IPCP has opened.
    pub fn link(&self) -> Option<Link> {
        if self.phase != Phase::Opened {
            return None;
        }
        let value = |kind| {
            self.ipcp
                .options
                .iter()
                .find(|(k, _)| *k == kind)
                .and_then(|(_, v)| <[u8; 4]>::try_from(v.as_slice()).ok())
                .map(Ipv4Addr::from)
        };
        Some(Link {
            address: value(ipcp_option::IP_ADDRESS)?,
            dns: [ipcp_option::PRIMARY_DNS, ipcp_option::SECONDARY_DNS]
                .into_iter()
                .filter_map(value)
                .filter(|a| !a.is_unspecified())
                .collect(),
            peer_mru: self.peer_mru,
        })
    }

    /// When [`Ppp::on_timer`] next has something to do.
    pub fn deadline(&self) -> Option<Instant> {
        let pap = match self.auth {
            Auth::Pap {
                sent_at: Some(at), ..
            } if self.phase == Phase::Authenticate => Some(at + RESTART),
            _ => None,
        };
        [self.lcp.deadline(), self.ipcp.deadline(), pap]
            .into_iter()
            .flatten()
            .min()
    }

    pub fn on_timer(&mut self, now: Instant) -> io::Result<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        out.extend(self.lcp.retransmit(now, "LCP")?);
        if self.phase == Phase::Network {
            out.extend(self.ipcp.retransmit(now, "IPCP")?);
        }
        if self.phase == Phase::Authenticate
            && let Auth::Pap {
                sent_at: Some(at),
                sent_count,
                ..
            } = self.auth
            && now >= at + RESTART
        {
            if sent_count >= MAX_CONFIGURE {
                return Err(failed(
                    io::ErrorKind::TimedOut,
                    "PPP: the server never answered PAP".into(),
                ));
            }
            out.push(self.pap_request(now));
        }
        Ok(out)
    }

    /// One PPP frame from the server, as a control protocol frame. IP
    /// packets are the session's, not this machine's.
    pub fn input(&mut self, frame: &[u8], now: Instant) -> io::Result<Vec<Vec<u8>>> {
        let (protocol, info) = split_frame(frame)?;
        match protocol {
            protocol::LCP => self.lcp_input(info, now),
            protocol::CHAP if self.phase == Phase::Authenticate => self.chap_input(info),
            protocol::PAP if self.phase == Phase::Authenticate => self.pap_input(info),
            protocol::IPCP if matches!(self.phase, Phase::Network | Phase::Opened) => {
                self.ipcp_input(info, now)
            }
            // RFC 1661 §3.4: NCP packets before the network phase, and
            // authentication packets outside it, are silently discarded.
            protocol::IPCP | protocol::CHAP | protocol::PAP | protocol::IPV4 => Ok(Vec::new()),
            other if self.phase != Phase::Establish => Ok(vec![self.protocol_reject(other, info)]),
            _ => Ok(Vec::new()),
        }
    }

    /// LCP Protocol-Reject (§5.7) of a protocol this does not speak: IPv6CP,
    /// CCP, anything else a server offers.
    fn protocol_reject(&mut self, protocol: u16, info: &[u8]) -> Vec<u8> {
        self.echo_id = self.echo_id.wrapping_add(1);
        let mut data = protocol.to_be_bytes().to_vec();
        // The rejected information, truncated to what fits the peer's MRU.
        let room = usize::from(self.peer_mru).saturating_sub(6);
        data.extend_from_slice(&info[..info.len().min(room)]);
        frame(
            protocol::LCP,
            &control(code::PROTOCOL_REJECT, self.echo_id, &data),
        )
    }

    fn lcp_input(&mut self, info: &[u8], now: Instant) -> io::Result<Vec<Vec<u8>>> {
        let packet = parse_control(info)?;
        match packet.code {
            code::CONFIGURE_REQUEST => {
                if self.phase != Phase::Establish {
                    return Err(failed(
                        io::ErrorKind::ConnectionAborted,
                        "PPP: the server restarted LCP negotiation, which this client does not follow".into(),
                    ));
                }
                let reply = self.lcp_evaluate(&packet)?;
                let mut out = vec![reply];
                out.extend(self.lcp_check_opened(now));
                Ok(out)
            }
            code::CONFIGURE_ACK if packet.id == self.lcp.id => {
                self.lcp.acked_by_peer = true;
                Ok(self.lcp_check_opened(now))
            }
            code::CONFIGURE_NAK if packet.id == self.lcp.id => {
                for (kind, value) in parse_options(packet.data)? {
                    match kind {
                        lcp_option::MRU if value.len() == 2 => {
                            let mru = u16::from_be_bytes([value[0], value[1]]);
                            set_option(
                                &mut self.lcp.options,
                                kind,
                                mru.clamp(MIN_MRU, MAX_MRU).to_be_bytes().to_vec(),
                            );
                        }
                        lcp_option::MAGIC_NUMBER => {
                            self.magic = nonzero_magic();
                            set_option(
                                &mut self.lcp.options,
                                kind,
                                self.magic.to_be_bytes().to_vec(),
                            );
                        }
                        // A Nak naming an option we did not send is a hint
                        // (§5.3); none we take.
                        _ => {}
                    }
                }
                Ok(vec![self.lcp.request(now)])
            }
            code::CONFIGURE_REJECT if packet.id == self.lcp.id => {
                for (kind, _) in parse_options(packet.data)? {
                    self.lcp.options.retain(|(k, _)| *k != kind);
                    if kind == lcp_option::MAGIC_NUMBER {
                        self.magic = 0;
                    }
                }
                Ok(vec![self.lcp.request(now)])
            }
            code::TERMINATE_REQUEST => Err(failed(
                io::ErrorKind::ConnectionAborted,
                "PPP: the server terminated the link".into(),
            )),
            code::ECHO_REQUEST if self.phase != Phase::Establish => {
                let mut data = self.magic.to_be_bytes().to_vec();
                data.extend_from_slice(packet.data.get(4..).unwrap_or_default());
                Ok(vec![frame(
                    protocol::LCP,
                    &control(code::ECHO_REPLY, packet.id, &data),
                )])
            }
            code::PROTOCOL_REJECT => {
                let rejected = packet
                    .data
                    .get(..2)
                    .map(|p| u16::from_be_bytes([p[0], p[1]]));
                match rejected {
                    Some(protocol::IPCP) => Err(failed(
                        io::ErrorKind::Unsupported,
                        "PPP: the server rejected IPCP, so it offers no IPv4".into(),
                    )),
                    _ => Ok(Vec::new()),
                }
            }
            code::CODE_REJECT => Err(failed(
                io::ErrorKind::Unsupported,
                "PPP: the server rejected an LCP code this client needs".into(),
            )),
            code::TERMINATE_ACK
            | code::ECHO_REQUEST
            | code::ECHO_REPLY
            | code::DISCARD_REQUEST
            | code::CONFIGURE_ACK
            | code::CONFIGURE_NAK
            | code::CONFIGURE_REJECT => Ok(Vec::new()),
            _ => {
                self.echo_id = self.echo_id.wrapping_add(1);
                Ok(vec![frame(
                    protocol::LCP,
                    &control(
                        code::CODE_REJECT,
                        self.echo_id,
                        &info[..info.len().min(1496)],
                    ),
                )])
            }
        }
    }

    /// Answer the server's LCP Configure-Request: reject what this does not
    /// know, nak what it cannot accept, ack the rest (RFC 1661 §5.1-5.4).
    fn lcp_evaluate(&mut self, packet: &ControlPacket<'_>) -> io::Result<Vec<u8>> {
        let options = parse_options(packet.data)?;
        let reject: Options = options
            .iter()
            .filter(|(kind, _)| {
                !matches!(
                    *kind,
                    lcp_option::MRU | lcp_option::AUTH_PROTOCOL | lcp_option::MAGIC_NUMBER
                )
            })
            .cloned()
            .collect();
        if !reject.is_empty() {
            return Ok(frame(
                protocol::LCP,
                &control(code::CONFIGURE_REJECT, packet.id, &encode_options(&reject)),
            ));
        }

        let mut nak = Options::new();
        let mut mru = 1500;
        let mut method = None;
        for (kind, value) in &options {
            match *kind {
                lcp_option::MRU => match <[u8; 2]>::try_from(value.as_slice()) {
                    Ok(v) if u16::from_be_bytes(v) >= MIN_MRU => mru = u16::from_be_bytes(v),
                    _ => nak.push((*kind, MIN_MRU.to_be_bytes().to_vec())),
                },
                lcp_option::AUTH_PROTOCOL => {
                    let offered = self
                        .methods
                        .iter()
                        .copied()
                        .find(|m| m.option_value() == *value);
                    match offered {
                        Some(m) => method = Some(m),
                        None => {
                            self.auth_naks += 1;
                            if self.auth_naks > MAX_AUTH_NAKS {
                                let enabled = self
                                    .methods
                                    .iter()
                                    .map(|m| m.name())
                                    .collect::<Vec<_>>()
                                    .join(", ");
                                return Err(failed(
                                    io::ErrorKind::Unsupported,
                                    format!(
                                        "SSTP: the server requires {}, and only {enabled} is enabled",
                                        describe_auth(value)
                                    ),
                                ));
                            }
                            nak.push((*kind, self.methods[0].option_value()));
                        }
                    }
                }
                // Our own number back: a looped-back link (§6.4).
                lcp_option::MAGIC_NUMBER if value.as_slice() == self.magic.to_be_bytes() => {
                    nak.push((*kind, nonzero_magic().to_be_bytes().to_vec()));
                }
                _ => {}
            }
        }
        if !nak.is_empty() {
            return Ok(frame(
                protocol::LCP,
                &control(code::CONFIGURE_NAK, packet.id, &encode_options(&nak)),
            ));
        }

        self.peer_mru = mru;
        self.auth_method = method;
        self.lcp.acked_peer = true;
        Ok(frame(
            protocol::LCP,
            &control(code::CONFIGURE_ACK, packet.id, packet.data),
        ))
    }

    fn lcp_check_opened(&mut self, now: Instant) -> Vec<Vec<u8>> {
        if self.phase != Phase::Establish || !self.lcp.opened() {
            return Vec::new();
        }
        match self.auth_method {
            None => {
                // The server asked for no authentication: nothing produced
                // keys, so the HLAK is zeros (MS-SSTP §3.2.5.2.2).
                self.hlak = Some(crypto::zero_hlak());
                self.phase = Phase::Authenticated;
                Vec::new()
            }
            Some(AuthMethod::MsChapV2) => {
                self.phase = Phase::Authenticate;
                self.auth = Auth::MsChapV2 {
                    peer_challenge: [0; 16],
                    authenticator_challenge: [0; 16],
                    nt_response: [0; 24],
                    responded: false,
                };
                Vec::new()
            }
            Some(AuthMethod::Pap) => {
                self.phase = Phase::Authenticate;
                self.auth = Auth::Pap {
                    id: 0,
                    sent_at: None,
                    sent_count: 0,
                };
                vec![self.pap_request(now)]
            }
        }
    }

    fn chap_input(&mut self, info: &[u8]) -> io::Result<Vec<Vec<u8>>> {
        let packet = parse_control(info)?;
        let Auth::MsChapV2 {
            peer_challenge,
            authenticator_challenge,
            nt_response,
            responded,
        } = &mut self.auth
        else {
            return Ok(Vec::new());
        };
        match packet.code {
            // Challenge.
            1 => {
                let challenge = match packet.data {
                    [16, challenge @ ..] if challenge.len() >= 16 => &challenge[..16],
                    _ => return Err(malformed("MS-CHAPv2 challenge")),
                };
                // A repeated challenge gets the same answer; a new one, a
                // new peer challenge.
                if !*responded || authenticator_challenge.as_slice() != challenge {
                    authenticator_challenge.copy_from_slice(challenge);
                    rand::fill(&mut peer_challenge[..]);
                    *nt_response = crypto::generate_nt_response(
                        authenticator_challenge,
                        peer_challenge,
                        &self.credentials.username,
                        self.credentials.password.expose(),
                    );
                    *responded = true;
                }
                // RFC 2759 §4: Value-Size 49, the peer challenge, 8 reserved
                // zeros, the NT-Response, a zero flag, then the name.
                let mut data = vec![49];
                data.extend_from_slice(&peer_challenge[..]);
                data.extend_from_slice(&[0; 8]);
                data.extend_from_slice(&nt_response[..]);
                data.push(0);
                data.extend_from_slice(self.credentials.username.as_bytes());
                Ok(vec![frame(protocol::CHAP, &control(2, packet.id, &data))])
            }
            // Success.
            3 if *responded => {
                let expected = crypto::authenticator_response(
                    self.credentials.password.expose(),
                    nt_response,
                    peer_challenge,
                    authenticator_challenge,
                    &self.credentials.username,
                );
                let proven = parse_authenticator(packet.data)
                    .is_some_and(|received| bool::from(received.ct_eq(&expected)));
                if !proven {
                    return Err(failed(
                        io::ErrorKind::PermissionDenied,
                        "SSTP: the server did not prove it knows the password (MS-CHAPv2 authenticator mismatch)".into(),
                    ));
                }
                let keys =
                    crypto::mppe_keys(self.credentials.password.expose(), nt_response, false);
                self.hlak = Some(keys.hlak());
                self.phase = Phase::Authenticated;
                Ok(Vec::new())
            }
            // Failure.
            4 => Err(chap_failure(packet.data)),
            _ => Ok(Vec::new()),
        }
    }

    fn pap_request(&mut self, now: Instant) -> Vec<u8> {
        let Auth::Pap {
            id,
            sent_at,
            sent_count,
        } = &mut self.auth
        else {
            return Vec::new();
        };
        *id = id.wrapping_add(1);
        *sent_at = Some(now);
        *sent_count += 1;
        let user = self.credentials.username.as_bytes();
        let password = self.credentials.password.expose().as_bytes();
        let mut data = zeroize::Zeroizing::new(Vec::with_capacity(2 + user.len() + password.len()));
        data.push(user.len() as u8);
        data.extend_from_slice(user);
        data.push(password.len() as u8);
        data.extend_from_slice(password);
        frame(protocol::PAP, &control(1, *id, &data))
    }

    fn pap_input(&mut self, info: &[u8]) -> io::Result<Vec<Vec<u8>>> {
        let packet = parse_control(info)?;
        let Auth::Pap { id, .. } = self.auth else {
            return Ok(Vec::new());
        };
        if packet.id != id {
            return Ok(Vec::new());
        }
        match packet.code {
            // Authenticate-Ack. PAP produces no keys: the HLAK is zeros.
            2 => {
                self.hlak = Some(crypto::zero_hlak());
                self.phase = Phase::Authenticated;
                Ok(Vec::new())
            }
            3 => Err(failed(
                io::ErrorKind::PermissionDenied,
                format!(
                    "SSTP authentication failed: the server refused the credentials (PAP{})",
                    pap_message(packet.data)
                ),
            )),
            _ => Ok(Vec::new()),
        }
    }

    fn ipcp_input(&mut self, info: &[u8], now: Instant) -> io::Result<Vec<Vec<u8>>> {
        let packet = parse_control(info)?;
        match packet.code {
            code::CONFIGURE_REQUEST => {
                if self.phase == Phase::Opened {
                    return Err(failed(
                        io::ErrorKind::ConnectionAborted,
                        "PPP: the server restarted IPCP negotiation, which this client does not follow".into(),
                    ));
                }
                let options = parse_options(packet.data)?;
                // The server's own address is all we ack; VJ compression
                // and anything else are rejected.
                let reject: Options = options
                    .iter()
                    .filter(|(kind, _)| *kind != ipcp_option::IP_ADDRESS)
                    .cloned()
                    .collect();
                let out = if reject.is_empty() {
                    self.ipcp.acked_peer = true;
                    vec![frame(
                        protocol::IPCP,
                        &control(code::CONFIGURE_ACK, packet.id, packet.data),
                    )]
                } else {
                    vec![frame(
                        protocol::IPCP,
                        &control(code::CONFIGURE_REJECT, packet.id, &encode_options(&reject)),
                    )]
                };
                self.check_opened();
                Ok(out)
            }
            code::CONFIGURE_ACK if packet.id == self.ipcp.id && self.phase == Phase::Network => {
                self.ipcp.acked_by_peer = true;
                self.check_opened();
                Ok(Vec::new())
            }
            code::CONFIGURE_NAK if packet.id == self.ipcp.id && self.phase == Phase::Network => {
                for (kind, value) in parse_options(packet.data)? {
                    if value.len() == 4 && self.ipcp.options.iter().any(|(k, _)| *k == kind) {
                        set_option(&mut self.ipcp.options, kind, value);
                    }
                }
                Ok(vec![self.ipcp.request(now)])
            }
            code::CONFIGURE_REJECT if packet.id == self.ipcp.id && self.phase == Phase::Network => {
                for (kind, _) in parse_options(packet.data)? {
                    if kind == ipcp_option::IP_ADDRESS {
                        return Err(failed(
                            io::ErrorKind::Unsupported,
                            "PPP: the server will not assign an IPv4 address".into(),
                        ));
                    }
                    // A server without DNS to offer rejects those options.
                    self.ipcp.options.retain(|(k, _)| *k != kind);
                }
                Ok(vec![self.ipcp.request(now)])
            }
            code::TERMINATE_REQUEST => Err(failed(
                io::ErrorKind::ConnectionAborted,
                "PPP: the server closed IPCP".into(),
            )),
            _ => Ok(Vec::new()),
        }
    }

    fn check_opened(&mut self) {
        if self.phase == Phase::Network && self.ipcp.opened() {
            let assigned = self
                .ipcp
                .options
                .iter()
                .any(|(k, v)| *k == ipcp_option::IP_ADDRESS && v.as_slice() != [0; 4]);
            if assigned {
                self.phase = Phase::Opened;
            }
        }
    }
}

fn set_option(options: &mut Options, kind: u8, value: Vec<u8>) {
    match options.iter_mut().find(|(k, _)| *k == kind) {
        Some(slot) => slot.1 = value,
        None => options.push((kind, value)),
    }
}

/// A magic number other than zero, which RFC 1661 §6.4 reserves for "not
/// negotiated".
fn nonzero_magic() -> u32 {
    loop {
        let magic: u32 = rand::random();
        if magic != 0 {
            return magic;
        }
    }
}

/// The 20 bytes of a Success message's `S=` field (RFC 2759 §5), which is
/// 40 hex digits; the RFC writes them upper case, and either case parses.
fn parse_authenticator(message: &[u8]) -> Option<[u8; 20]> {
    let hex = message.strip_prefix(b"S=")?.get(..40)?;
    let mut out = [0u8; 20];
    for (i, pair) in hex.chunks_exact(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

/// The error a Failure message (RFC 2759 §6) describes: its `E=` code and
/// the code's name. The server's free text is left out, being the server's.
fn chap_failure(message: &[u8]) -> io::Error {
    let text = String::from_utf8_lossy(message);
    let code = text
        .split_whitespace()
        .find_map(|field| field.strip_prefix("E="))
        .and_then(|code| code.parse::<u32>().ok());
    let name = match code {
        Some(646) => " (restricted logon hours)",
        Some(647) => " (account disabled)",
        Some(648) => " (password expired)",
        Some(649) => " (no dial-in permission)",
        Some(691) => " (authentication failure)",
        Some(709) => " (error changing password)",
        _ => "",
    };
    failed(
        io::ErrorKind::PermissionDenied,
        match code {
            Some(code) => format!(
                "SSTP authentication failed: the server refused the credentials (MS-CHAPv2 error {code}{name})"
            ),
            None => {
                "SSTP authentication failed: the server refused the credentials (MS-CHAPv2)".into()
            }
        },
    )
}

/// A PAP Nak's message, printable characters only and capped, for the error.
fn pap_message(data: &[u8]) -> String {
    let Some((&len, rest)) = data.split_first() else {
        return String::new();
    };
    let text: String = String::from_utf8_lossy(&rest[..usize::from(len).min(rest.len())])
        .chars()
        .filter(|c| !c.is_control())
        .take(120)
        .collect();
    if text.is_empty() {
        String::new()
    } else {
        format!(": {text}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credentials() -> Credentials {
        Credentials {
            username: "User".into(),
            password: "clientPass".to_string().into(),
        }
    }

    fn lcp(code: u8, id: u8, options: &Options) -> Vec<u8> {
        frame(protocol::LCP, &control(code, id, &encode_options(options)))
    }

    fn reply(out: &[Vec<u8>], index: usize) -> (u16, u8, u8, Options) {
        let (protocol, info) = split_frame(&out[index]).unwrap();
        let packet = parse_control(info).unwrap();
        let options = parse_options(packet.data).unwrap_or_default();
        (protocol, packet.code, packet.id, options)
    }

    /// LCP up with the server asking for `auth`, the client's request acked.
    fn establish(ppp: &mut Ppp, auth: Vec<u8>) -> Vec<Vec<u8>> {
        let now = Instant::now();
        let request = ppp.start(now);
        let (_, _, id, _) = reply(&request, 0);
        let mut out = ppp
            .input(
                &lcp(
                    code::CONFIGURE_REQUEST,
                    7,
                    &vec![
                        (lcp_option::MRU, 1400u16.to_be_bytes().to_vec()),
                        (lcp_option::AUTH_PROTOCOL, auth),
                        (lcp_option::MAGIC_NUMBER, vec![1, 2, 3, 4]),
                    ],
                ),
                now,
            )
            .unwrap();
        out.extend(
            ppp.input(&lcp(code::CONFIGURE_ACK, id, &Options::new()), now)
                .unwrap(),
        );
        out
    }

    #[test]
    fn frames_are_tolerated_without_the_address_field_or_a_full_protocol() {
        assert_eq!(
            split_frame(&[0xff, 0x03, 0xc0, 0x21, 9]).unwrap(),
            (0xc021, &[9u8][..])
        );
        assert_eq!(split_frame(&[0xc0, 0x21, 9]).unwrap(), (0xc021, &[9u8][..]));
        assert_eq!(split_frame(&[0x21, 0x45]).unwrap(), (0x0021, &[0x45u8][..]));
    }

    #[test]
    fn the_first_request_carries_mru_and_a_magic_number() {
        let mut ppp = Ppp::new(credentials(), vec![AuthMethod::MsChapV2], 1500);
        let out = ppp.start(Instant::now());
        let (protocol, code, _, options) = reply(&out, 0);
        assert_eq!((protocol, code), (protocol::LCP, code::CONFIGURE_REQUEST));
        assert_eq!(options[0], (lcp_option::MRU, vec![0x05, 0xdc]));
        assert_eq!(options[1].0, lcp_option::MAGIC_NUMBER);
        assert_ne!(options[1].1, vec![0; 4]);
    }

    #[test]
    fn unknown_lcp_options_are_rejected_before_anything_is_naked() {
        let mut ppp = Ppp::new(credentials(), vec![AuthMethod::MsChapV2], 1500);
        ppp.start(Instant::now());
        // ACFC (8) and PFC (7), and an EAP auth that would be naked.
        let out = ppp
            .input(
                &lcp(
                    code::CONFIGURE_REQUEST,
                    1,
                    &vec![(8, vec![]), (7, vec![]), (3, vec![0xc2, 0x27])],
                ),
                Instant::now(),
            )
            .unwrap();
        let (_, code, id, options) = reply(&out, 0);
        assert_eq!((code, id), (code::CONFIGURE_REJECT, 1));
        assert_eq!(options, vec![(8, vec![]), (7, vec![])]);
    }

    #[test]
    fn an_auth_method_not_enabled_is_naked_then_refused_by_name() {
        let mut ppp = Ppp::new(credentials(), vec![AuthMethod::MsChapV2], 1500);
        ppp.start(Instant::now());
        let eap = lcp(code::CONFIGURE_REQUEST, 1, &vec![(3, vec![0xc2, 0x27])]);
        for _ in 0..MAX_AUTH_NAKS {
            let out = ppp.input(&eap, Instant::now()).unwrap();
            let (_, code, _, options) = reply(&out, 0);
            assert_eq!(code, code::CONFIGURE_NAK);
            assert_eq!(options, vec![(3, vec![0xc2, 0x23, 0x81])]);
        }
        let err = ppp.input(&eap, Instant::now()).unwrap_err();
        assert!(err.to_string().contains("requires EAP"), "{err}");
    }

    /// PAP is a downgrade: a server proposing it is naked to MS-CHAPv2
    /// unless the configuration lists PAP.
    #[test]
    fn pap_is_used_only_when_listed() {
        let mut ppp = Ppp::new(credentials(), vec![AuthMethod::MsChapV2], 1500);
        ppp.start(Instant::now());
        let out = ppp
            .input(
                &lcp(code::CONFIGURE_REQUEST, 1, &vec![(3, vec![0xc0, 0x23])]),
                Instant::now(),
            )
            .unwrap();
        assert_eq!(reply(&out, 0).1, code::CONFIGURE_NAK);

        let mut ppp = Ppp::new(credentials(), vec![AuthMethod::Pap], 1500);
        let out = establish(&mut ppp, vec![0xc0, 0x23]);
        assert_eq!(reply(&out, 0).1, code::CONFIGURE_ACK);
        let (protocol, code, _, _) = reply(&out, 1);
        assert_eq!((protocol, code), (protocol::PAP, 1));
    }

    #[test]
    fn ms_chap_v2_answers_the_challenge_and_checks_the_server() {
        let mut ppp = Ppp::new(credentials(), vec![AuthMethod::MsChapV2], 1500);
        establish(&mut ppp, vec![0xc2, 0x23, 0x81]);
        let challenge = [0x5bu8; 16];
        let mut data = vec![16];
        data.extend_from_slice(&challenge);
        data.extend_from_slice(b"server");
        let out = ppp
            .input(
                &frame(protocol::CHAP, &control(1, 42, &data)),
                Instant::now(),
            )
            .unwrap();
        let (protocol, info) = split_frame(&out[0]).unwrap();
        let response = parse_control(info).unwrap();
        assert_eq!(
            (protocol, response.code, response.id),
            (protocol::CHAP, 2, 42)
        );
        assert_eq!(response.data[0], 49);
        assert_eq!(&response.data[50..], b"User");
        let peer_challenge: [u8; 16] = response.data[1..17].try_into().unwrap();
        let nt_response: [u8; 24] = response.data[25..49].try_into().unwrap();
        assert_eq!(
            nt_response,
            crypto::generate_nt_response(&challenge, &peer_challenge, "User", "clientPass")
        );

        // A Success the server could only compute knowing the password.
        let authenticator = crypto::authenticator_response(
            "clientPass",
            &nt_response,
            &peer_challenge,
            &challenge,
            "User",
        );
        let hex: String = authenticator.iter().map(|b| format!("{b:02X}")).collect();
        let success = format!("S={hex} M=welcome");
        ppp.input(
            &frame(protocol::CHAP, &control(3, 42, success.as_bytes())),
            Instant::now(),
        )
        .unwrap();
        let hlak = ppp.take_authenticated().expect("authenticated");
        let keys = crypto::mppe_keys("clientPass", &nt_response, false);
        assert_eq!(*hlak, *keys.hlak());
    }

    #[test]
    fn a_wrong_authenticator_is_refused() {
        let mut ppp = Ppp::new(credentials(), vec![AuthMethod::MsChapV2], 1500);
        establish(&mut ppp, vec![0xc2, 0x23, 0x81]);
        let mut data = vec![16];
        data.extend_from_slice(&[1u8; 16]);
        ppp.input(
            &frame(protocol::CHAP, &control(1, 1, &data)),
            Instant::now(),
        )
        .unwrap();
        let forged = format!("S={}", "AB".repeat(20));
        let err = ppp
            .input(
                &frame(protocol::CHAP, &control(3, 1, forged.as_bytes())),
                Instant::now(),
            )
            .unwrap_err();
        assert!(err.to_string().contains("did not prove"), "{err}");
        assert!(ppp.take_authenticated().is_none());
    }

    #[test]
    fn a_failure_names_its_code_and_not_the_credentials() {
        let mut ppp = Ppp::new(credentials(), vec![AuthMethod::MsChapV2], 1500);
        establish(&mut ppp, vec![0xc2, 0x23, 0x81]);
        let mut data = vec![16];
        data.extend_from_slice(&[1u8; 16]);
        ppp.input(
            &frame(protocol::CHAP, &control(1, 1, &data)),
            Instant::now(),
        )
        .unwrap();
        let err = ppp
            .input(
                &frame(
                    protocol::CHAP,
                    &control(
                        4,
                        1,
                        b"E=691 R=0 C=00000000000000000000000000000000 V=3 M=no",
                    ),
                ),
                Instant::now(),
            )
            .unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("691") && text.contains("authentication failure"),
            "{text}"
        );
        assert!(
            !text.contains("clientPass") && !text.contains("User"),
            "{text}"
        );
    }

    #[test]
    fn ipcp_takes_the_assigned_address_and_dns_then_opens() {
        let mut ppp = Ppp::new(credentials(), vec![AuthMethod::Pap], 1500);
        let out = establish(&mut ppp, vec![0xc0, 0x23]);
        let pap_id = reply(&out, 1).2;
        ppp.input(
            &frame(protocol::PAP, &control(2, pap_id, &[0])),
            Instant::now(),
        )
        .unwrap();
        assert_eq!(
            *ppp.take_authenticated().unwrap(),
            [0u8; 32],
            "PAP's HLAK is zeros"
        );

        let out = ppp.start_network(Instant::now());
        let (protocol, code, id, options) = reply(&out, 0);
        assert_eq!((protocol, code), (protocol::IPCP, code::CONFIGURE_REQUEST));
        assert_eq!(options.len(), 3);

        // The server: its own address, VJ compression (rejected).
        let out = ppp
            .input(
                &frame(
                    protocol::IPCP,
                    &control(
                        code::CONFIGURE_REQUEST,
                        9,
                        &encode_options(&vec![(3, vec![10, 0, 0, 1]), (2, vec![0, 0x2d, 15, 1])]),
                    ),
                ),
                Instant::now(),
            )
            .unwrap();
        assert_eq!(reply(&out, 0).1, code::CONFIGURE_REJECT);
        let out = ppp
            .input(
                &frame(
                    protocol::IPCP,
                    &control(
                        code::CONFIGURE_REQUEST,
                        10,
                        &encode_options(&vec![(3, vec![10, 0, 0, 1])]),
                    ),
                ),
                Instant::now(),
            )
            .unwrap();
        assert_eq!(reply(&out, 0).1, code::CONFIGURE_ACK);

        // Nak with the assignment; no secondary DNS (rejected).
        let out = ppp
            .input(
                &frame(
                    protocol::IPCP,
                    &control(
                        code::CONFIGURE_NAK,
                        id,
                        &encode_options(&vec![(3, vec![10, 0, 0, 7]), (129, vec![10, 0, 0, 53])]),
                    ),
                ),
                Instant::now(),
            )
            .unwrap();
        let (_, _, id, _) = reply(&out, 0);
        let out = ppp
            .input(
                &frame(
                    protocol::IPCP,
                    &control(
                        code::CONFIGURE_REJECT,
                        id,
                        &encode_options(&vec![(131, vec![0; 4])]),
                    ),
                ),
                Instant::now(),
            )
            .unwrap();
        let (_, _, id, options) = reply(&out, 0);
        assert!(ppp.link().is_none());
        ppp.input(
            &frame(
                protocol::IPCP,
                &control(code::CONFIGURE_ACK, id, &encode_options(&options)),
            ),
            Instant::now(),
        )
        .unwrap();
        assert_eq!(
            ppp.link(),
            Some(Link {
                address: Ipv4Addr::new(10, 0, 0, 7),
                dns: vec![Ipv4Addr::new(10, 0, 0, 53)],
                peer_mru: 1400,
            })
        );
    }

    #[test]
    fn ipv6cp_and_ccp_are_protocol_rejected() {
        let mut ppp = Ppp::new(credentials(), vec![AuthMethod::MsChapV2], 1500);
        establish(&mut ppp, vec![0xc2, 0x23, 0x81]);
        for rejected in [0x8057u16, 0x80fd] {
            let out = ppp
                .input(
                    &frame(rejected, &control(code::CONFIGURE_REQUEST, 1, &[])),
                    Instant::now(),
                )
                .unwrap();
            let (protocol, info) = split_frame(&out[0]).unwrap();
            let packet = parse_control(info).unwrap();
            assert_eq!(
                (protocol, packet.code),
                (protocol::LCP, code::PROTOCOL_REJECT)
            );
            assert_eq!(&packet.data[..2], rejected.to_be_bytes());
        }
    }

    #[test]
    fn configure_requests_are_retransmitted_then_given_up() {
        let mut ppp = Ppp::new(credentials(), vec![AuthMethod::MsChapV2], 1500);
        let start = Instant::now();
        ppp.start(start);
        let mut now = start;
        for _ in 1..MAX_CONFIGURE {
            assert!(ppp.on_timer(now).unwrap().is_empty(), "not yet due");
            now += RESTART;
            assert_eq!(ppp.on_timer(now).unwrap().len(), 1);
        }
        now += RESTART;
        assert!(ppp.on_timer(now).is_err());
    }

    #[test]
    fn echo_requests_are_answered_with_our_magic() {
        let mut ppp = Ppp::new(credentials(), vec![AuthMethod::MsChapV2], 1500);
        establish(&mut ppp, vec![0xc2, 0x23, 0x81]);
        let out = ppp
            .input(
                &frame(
                    protocol::LCP,
                    &control(code::ECHO_REQUEST, 5, &[9, 9, 9, 9, 1, 2]),
                ),
                Instant::now(),
            )
            .unwrap();
        let (_, info) = split_frame(&out[0]).unwrap();
        let packet = parse_control(info).unwrap();
        assert_eq!((packet.code, packet.id), (code::ECHO_REPLY, 5));
        assert_eq!(&packet.data[..4], ppp.magic.to_be_bytes());
        assert_eq!(&packet.data[4..], [1, 2]);
    }
}
