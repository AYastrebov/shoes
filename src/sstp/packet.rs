//! The SSTP packet codec ([MS-SSTP] §2.2): a 4-byte header, then either one
//! PPP frame (a data packet) or a control message with attributes.
//!
//! Encodes and decodes both directions, so the server double in
//! `testing.rs` speaks with the same code. No I/O.

use super::crypto::BindingHash;

/// Version 1.0 (§2.2.1): major 1 in the upper nibble, minor 0.
pub const VERSION: u8 = 0x10;
pub const HEADER_LEN: usize = 4;
/// The 12-bit length field covers the whole packet, header included.
pub const MAX_PACKET_LEN: usize = 0x0fff;

/// SSTP_ENCAPSULATED_PROTOCOL_PPP (§2.2.5).
const PROTOCOL_PPP: u16 = 0x0001;

pub mod message {
    pub const CALL_CONNECT_REQUEST: u16 = 0x0001;
    pub const CALL_CONNECT_ACK: u16 = 0x0002;
    pub const CALL_CONNECT_NAK: u16 = 0x0003;
    pub const CALL_CONNECTED: u16 = 0x0004;
    pub const CALL_ABORT: u16 = 0x0005;
    pub const CALL_DISCONNECT: u16 = 0x0006;
    pub const CALL_DISCONNECT_ACK: u16 = 0x0007;
    pub const ECHO_REQUEST: u16 = 0x0008;
    pub const ECHO_RESPONSE: u16 = 0x0009;
}

pub mod attribute {
    pub const ENCAPSULATED_PROTOCOL_ID: u8 = 0x01;
    pub const STATUS_INFO: u8 = 0x02;
    pub const CRYPTO_BINDING: u8 = 0x03;
    pub const CRYPTO_BINDING_REQ: u8 = 0x04;
}

/// Length of a Call Connected message (§2.2.11), which the Compound MAC is
/// computed over.
pub const CALL_CONNECTED_LEN: usize = 112;
/// Where the Compound MAC field starts inside a Call Connected message:
/// 8 bytes of header, 4 of attribute header, 4 of reserved bytes and hash
/// protocol, 32 of nonce, 32 of cert hash and its padding.
const COMPOUND_MAC_OFFSET: usize = 80;

fn malformed(what: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("SSTP: malformed packet ({what})"),
    )
}

/// The length of the packet at the front of `buf`, once its header has
/// arrived: `Ok(None)` while fewer than 4 bytes are buffered.
pub fn packet_len(buf: &[u8]) -> std::io::Result<Option<usize>> {
    if buf.len() < HEADER_LEN {
        return Ok(None);
    }
    if buf[0] != VERSION {
        return Err(malformed("version is not 1.0"));
    }
    let len = usize::from(u16::from_be_bytes([buf[2], buf[3]]) & 0x0fff);
    if len < HEADER_LEN {
        return Err(malformed("length shorter than the header"));
    }
    Ok(Some(len))
}

/// One SSTP packet, borrowed from the buffer it was parsed out of.
pub enum Packet<'a> {
    /// A PPP frame.
    Data(&'a [u8]),
    Control(Control<'a>),
}

pub struct Control<'a> {
    pub message: u16,
    attributes: &'a [u8],
    count: u16,
}

impl<'a> Control<'a> {
    /// The attributes, each checked against the message's bounds. An
    /// attribute overrunning the message, or fewer attributes than the count
    /// says, is malformed.
    pub fn attributes(&self) -> std::io::Result<Vec<(u8, &'a [u8])>> {
        // The count is the wire's; an attribute is at least 4 bytes, so the
        // message bounds what it can be before anything is reserved.
        let mut out = Vec::with_capacity(usize::from(self.count).min(self.attributes.len() / 4));
        let mut rest = self.attributes;
        for _ in 0..self.count {
            if rest.len() < 4 {
                return Err(malformed("attribute header past the message"));
            }
            let len = usize::from(u16::from_be_bytes([rest[2], rest[3]]) & 0x0fff);
            if len < 4 || len > rest.len() {
                return Err(malformed("attribute overruns the message"));
            }
            out.push((rest[1], &rest[4..len]));
            rest = &rest[len..];
        }
        Ok(out)
    }

    fn attribute(&self, id: u8) -> std::io::Result<Option<&'a [u8]>> {
        Ok(self
            .attributes()?
            .into_iter()
            .find(|(found, _)| *found == id)
            .map(|(_, value)| value))
    }
}

/// Parse one whole packet: `packet.len()` is what [`packet_len`] returned.
/// The Reserved and R bits are ignored, as §2.2.1 says.
pub fn parse(packet: &[u8]) -> std::io::Result<Packet<'_>> {
    if packet[1] & 0x01 == 0 {
        return Ok(Packet::Data(&packet[HEADER_LEN..]));
    }
    if packet.len() < 8 {
        return Err(malformed("control packet shorter than its header"));
    }
    Ok(Packet::Control(Control {
        message: u16::from_be_bytes([packet[4], packet[5]]),
        count: u16::from_be_bytes([packet[6], packet[7]]),
        attributes: &packet[8..],
    }))
}

/// The 4-byte header of a data packet carrying `frame_len` bytes of PPP.
pub fn data_header(frame_len: usize) -> [u8; 4] {
    let len = (HEADER_LEN + frame_len) as u16;
    debug_assert!(usize::from(len) <= MAX_PACKET_LEN);
    let [hi, lo] = len.to_be_bytes();
    [VERSION, 0x00, hi, lo]
}

/// A control message with the given attributes, appended to `out`.
pub fn encode_control(out: &mut Vec<u8>, message: u16, attributes: &[(u8, &[u8])]) {
    let len = 8 + attributes
        .iter()
        .map(|(_, value)| 4 + value.len())
        .sum::<usize>();
    out.extend_from_slice(&[VERSION, 0x01]);
    out.extend_from_slice(&(len as u16).to_be_bytes());
    out.extend_from_slice(&message.to_be_bytes());
    out.extend_from_slice(&(attributes.len() as u16).to_be_bytes());
    for (id, value) in attributes {
        out.extend_from_slice(&[0x00, *id]);
        out.extend_from_slice(&((4 + value.len()) as u16).to_be_bytes());
        out.extend_from_slice(value);
    }
}

/// Call Connect Request (§2.2.9): PPP, the one protocol SSTP carries.
pub fn call_connect_request() -> Vec<u8> {
    let mut out = Vec::with_capacity(14);
    encode_control(
        &mut out,
        message::CALL_CONNECT_REQUEST,
        &[(
            attribute::ENCAPSULATED_PROTOCOL_ID,
            &PROTOCOL_PPP.to_be_bytes(),
        )],
    );
    out
}

/// A control message with no attributes: echo, disconnect and their
/// answers, and an abort that gives no reason.
pub fn bare_control(message: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(8);
    encode_control(&mut out, message, &[]);
    out
}

/// What a Call Connect Ack asks the client to bind with (§2.2.6).
pub struct BindingRequest {
    /// Bit 0 SHA-1, bit 1 SHA-256.
    pub hash_bitmask: u8,
    pub nonce: [u8; 32],
}

impl BindingRequest {
    /// The stronger hash both sides support (§1.7: SHA-256 over SHA-1).
    pub fn choose_hash(&self) -> Option<BindingHash> {
        if self.hash_bitmask & 0x02 != 0 {
            Some(BindingHash::Sha256)
        } else if self.hash_bitmask & 0x01 != 0 {
            Some(BindingHash::Sha1)
        } else {
            None
        }
    }
}

/// The Crypto Binding Request carried by a Call Connect Ack, if present and
/// well formed.
pub fn binding_request(control: &Control<'_>) -> std::io::Result<Option<BindingRequest>> {
    let Some(value) = control.attribute(attribute::CRYPTO_BINDING_REQ)? else {
        return Ok(None);
    };
    if value.len() != 36 {
        return Err(malformed("crypto binding request is not 40 bytes"));
    }
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&value[4..36]);
    Ok(Some(BindingRequest {
        hash_bitmask: value[3],
        nonce,
    }))
}

/// The first Status Info attribute's attribute id and status (§2.2.8), for
/// an error message: the server's reason for a Nak or an Abort.
pub fn status(control: &Control<'_>) -> Option<(u8, u32)> {
    let value = control.attribute(attribute::STATUS_INFO).ok()??;
    if value.len() < 8 {
        return None;
    }
    Some((
        value[3],
        u32::from_be_bytes([value[4], value[5], value[6], value[7]]),
    ))
}

/// A Call Connected message (§2.2.11) with its Compound MAC field zeroed,
/// as the MAC is computed over; [`set_compound_mac`] fills it in.
pub fn call_connected(hash: BindingHash, nonce: &[u8; 32], cert_hash: &[u8]) -> Vec<u8> {
    let mut binding = [0u8; 100];
    binding[3] = hash.protocol_byte();
    binding[4..36].copy_from_slice(nonce);
    // A SHA-1 Cert Hash is 20 bytes and 12 of zero padding (§2.2.7).
    binding[36..36 + cert_hash.len()].copy_from_slice(cert_hash);
    let mut out = Vec::with_capacity(CALL_CONNECTED_LEN);
    encode_control(
        &mut out,
        message::CALL_CONNECTED,
        &[(attribute::CRYPTO_BINDING, &binding)],
    );
    debug_assert_eq!(out.len(), CALL_CONNECTED_LEN);
    out
}

pub fn set_compound_mac(call_connected: &mut [u8], mac: &[u8]) {
    call_connected[COMPOUND_MAC_OFFSET..COMPOUND_MAC_OFFSET + mac.len()].copy_from_slice(mac);
}

/// What a Call Connected message carries, for the server double to check.
#[cfg(test)]
pub struct CallConnected {
    pub hash_protocol: u8,
    pub nonce: [u8; 32],
    pub cert_hash: Vec<u8>,
    pub compound_mac: Vec<u8>,
    /// The message with its MAC zeroed, as the MAC was computed over.
    pub zeroed: Vec<u8>,
}

#[cfg(test)]
pub fn parse_call_connected(packet: &[u8]) -> std::io::Result<CallConnected> {
    if packet.len() != CALL_CONNECTED_LEN {
        return Err(malformed("call connected is not 112 bytes"));
    }
    let len = match packet[15] {
        0x01 => 20,
        0x02 => 32,
        _ => return Err(malformed("unknown hash protocol")),
    };
    let mut zeroed = packet.to_vec();
    zeroed[COMPOUND_MAC_OFFSET..].fill(0);
    Ok(CallConnected {
        hash_protocol: packet[15],
        nonce: packet[16..48].try_into().unwrap(),
        cert_hash: packet[48..48 + len].to_vec(),
        compound_mac: packet[COMPOUND_MAC_OFFSET..COMPOUND_MAC_OFFSET + len].to_vec(),
        zeroed,
    })
}

/// A Call Connect Ack (§2.2.10), for the server double.
#[cfg(test)]
pub fn call_connect_ack(hash_bitmask: u8, nonce: &[u8; 32]) -> Vec<u8> {
    let mut value = [0u8; 36];
    value[3] = hash_bitmask;
    value[4..].copy_from_slice(nonce);
    let mut out = Vec::with_capacity(48);
    encode_control(
        &mut out,
        message::CALL_CONNECT_ACK,
        &[(attribute::CRYPTO_BINDING_REQ, &value)],
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_call_connect_request_is_the_14_bytes_the_spec_draws() {
        assert_eq!(
            call_connect_request(),
            [
                0x10, 0x01, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x06, 0x00, 0x01
            ]
        );
    }

    /// The header the KAT vectors' Call Connected messages start with, and
    /// the MAC landing where the vectors put it.
    #[test]
    fn a_call_connected_message_matches_the_vectors_layout() {
        let vectors = crate::kat::vectors("sstp");
        for case in crate::kat::cases(&vectors, "binding") {
            let reference = crate::kat::hex(&case["call_connected"]);
            let hash = match crate::kat::text(&case["hash"]) {
                "sha1" => BindingHash::Sha1,
                _ => BindingHash::Sha256,
            };
            let nonce: [u8; 32] = reference[16..48].try_into().unwrap();
            let cert_hash = &reference[48..48 + hash.len()];
            assert_eq!(call_connected(hash, &nonce, cert_hash), reference);

            let mut message = reference.clone();
            let mac = crate::kat::hex(&case["compound_mac"]);
            set_compound_mac(&mut message, &mac);
            let parsed = parse_call_connected(&message).unwrap();
            assert_eq!(parsed.compound_mac, mac);
            assert_eq!(parsed.zeroed, reference);
        }
    }

    #[test]
    fn an_ack_round_trips_and_the_client_prefers_sha256() {
        let nonce = [9u8; 32];
        for (bitmask, chosen) in [
            (0x01, Some(BindingHash::Sha1)),
            (0x02, Some(BindingHash::Sha256)),
            (0x03, Some(BindingHash::Sha256)),
            (0x00, None),
        ] {
            let ack = call_connect_ack(bitmask, &nonce);
            assert_eq!(ack.len(), 48);
            assert_eq!(packet_len(&ack).unwrap(), Some(48));
            let Packet::Control(control) = parse(&ack).unwrap() else {
                panic!("an ack is a control packet");
            };
            assert_eq!(control.message, message::CALL_CONNECT_ACK);
            let request = binding_request(&control).unwrap().unwrap();
            assert_eq!(request.nonce, nonce);
            assert_eq!(request.choose_hash(), chosen);
        }
    }

    #[test]
    fn lengths_and_versions_are_checked() {
        assert_eq!(packet_len(&[0x10, 0x00, 0x00]).unwrap(), None);
        assert_eq!(packet_len(&[0x10, 0x00, 0x0f, 0xff]).unwrap(), Some(4095));
        // The R nibble is ignored, not part of the length.
        assert_eq!(packet_len(&[0x10, 0x00, 0xf0, 0x08]).unwrap(), Some(8));
        assert!(packet_len(&[0x10, 0x00, 0x00, 0x03]).is_err());
        assert!(packet_len(&[0x20, 0x00, 0x00, 0x08]).is_err());
        assert_eq!(data_header(4091), [0x10, 0x00, 0x0f, 0xff]);
    }

    /// A count the message cannot hold reserves nothing for it.
    #[test]
    fn an_attribute_count_past_the_message_reserves_nothing_for_it() {
        let packet = [
            0x10, 0x01, 0x00, 0x0c, 0x00, 0x05, 0xff, 0xff, 0x00, 0x02, 0x00, 0x08,
        ];
        let Packet::Control(control) = parse(&packet).unwrap() else {
            panic!("control");
        };
        assert!(control.attributes().is_err());
    }

    #[test]
    fn an_attribute_overrunning_its_message_is_malformed() {
        let mut packet = Vec::new();
        encode_control(
            &mut packet,
            message::CALL_ABORT,
            &[(attribute::STATUS_INFO, &[0; 8])],
        );
        // Claim a longer attribute than the message holds.
        packet[11] = 0x40;
        let Packet::Control(control) = parse(&packet).unwrap() else {
            panic!("control");
        };
        assert!(control.attributes().is_err());
    }

    #[test]
    fn a_reserved_bit_on_a_data_packet_does_not_make_it_control() {
        let packet = [0x10, 0xfe, 0x00, 0x06, 0xff, 0x03];
        assert!(matches!(
            parse(&packet).unwrap(),
            Packet::Data(&[0xff, 0x03])
        ));
    }
}
