//! The CSTP frame: what the tunnel carries after `CONNECT`.
//!
//! openconnect `cstp.c:46-60` and draft-mavrogiannopoulos-openconnect-04
//! §2.3: an 8-byte header, then the payload.
//!
//! ```text
//! 'S' 'T' 'F' 0x01 | length (u16 BE, payload only) | type | 0x00 | payload
//! ```
//!
//! ocserv reads one TLS record and requires it to hold exactly one frame
//! (`worker-vpn.c:3005-3030`), so a frame is written with its own `write`
//! and never shares a record. The reader here accepts frames however the
//! stream splits them.

use std::io;

pub const HEADER_LEN: usize = 8;
/// openconnect allows for servers that send more than the negotiated MTU
/// (`cstp.c:961-964`: "we reserve some extra space"); a payload past this
/// is not a frame, and the stream is out of sync.
pub const MAX_PAYLOAD: usize = 16384;

/// Frame types, `openconnect-internal.h:1076-1082`.
pub mod kind {
    pub const DATA: u8 = 0;
    pub const DPD_REQUEST: u8 = 3;
    pub const DPD_RESPONSE: u8 = 4;
    pub const DISCONNECT: u8 = 5;
    pub const KEEPALIVE: u8 = 7;
    pub const COMPRESSED: u8 = 8;
    pub const TERMINATE: u8 = 9;
}

/// The reason byte that opens a DISCONNECT's payload: the user asked
/// (ocserv `vpn.h:131`, openconnect `cstp.c:1262`).
pub const BYE_USER_DISCONNECT: u8 = 0xb0;

const MAGIC: [u8; 4] = [b'S', b'T', b'F', 1];

/// The header for a frame of `kind` carrying `payload_len` bytes.
pub fn header(kind: u8, payload_len: usize) -> [u8; HEADER_LEN] {
    debug_assert!(payload_len <= usize::from(u16::MAX));
    let len = (payload_len as u16).to_be_bytes();
    [b'S', b'T', b'F', 1, len[0], len[1], kind, 0]
}

/// Append a whole frame to `out`.
pub fn encode(out: &mut Vec<u8>, kind: u8, payload: &[u8]) {
    out.extend_from_slice(&header(kind, payload.len()));
    out.extend_from_slice(payload);
}

/// A frame with no payload: keepalive, DPD request and response.
pub fn bare(kind: u8) -> [u8; HEADER_LEN] {
    header(kind, 0)
}

/// The client's goodbye: the reason byte, then the text
/// (`cstp.c:1237-1278`).
pub fn disconnect(reason: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + 1 + reason.len());
    out.extend_from_slice(&header(kind::DISCONNECT, 1 + reason.len()));
    out.push(BYE_USER_DISCONNECT);
    out.extend_from_slice(reason.as_bytes());
    out
}

/// The length of the frame at the front of `buf`, or `None` when the
/// header is not all there yet. A header that is not CSTP's is an error:
/// the stream is out of sync, and nothing after it can be trusted
/// (`cstp.c:986-989`, `worker-vpn.c:3014-3019`).
pub fn frame_len(buf: &[u8]) -> io::Result<Option<usize>> {
    if buf.len() < HEADER_LEN {
        return Ok(None);
    }
    if buf[..4] != MAGIC || buf[7] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "OpenConnect: not a CSTP frame; the stream is out of sync",
        ));
    }
    let payload_len = usize::from(u16::from_be_bytes([buf[4], buf[5]]));
    if payload_len > MAX_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("OpenConnect: a CSTP frame claims {payload_len} bytes"),
        ));
    }
    Ok(Some(HEADER_LEN + payload_len))
}

/// Split a whole frame into its type and payload. `frame` is exactly what
/// [`frame_len`] measured.
pub fn parse(frame: &[u8]) -> (u8, &[u8]) {
    (frame[6], &frame[HEADER_LEN..])
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests")]
    use super::*;

    #[test]
    fn a_data_frame_round_trips() {
        let mut out = Vec::new();
        encode(&mut out, kind::DATA, b"packet");
        assert_eq!(&out[..8], &[b'S', b'T', b'F', 1, 0, 6, 0, 0]);
        assert_eq!(frame_len(&out).unwrap(), Some(14));
        assert_eq!(parse(&out), (kind::DATA, &b"packet"[..]));
    }

    #[test]
    fn a_partial_header_is_not_yet_a_frame() {
        assert_eq!(frame_len(b"STF\x01\x00").unwrap(), None);
        assert_eq!(frame_len(&[]).unwrap(), None);
    }

    #[test]
    fn a_wrong_magic_or_reserved_byte_is_out_of_sync() {
        assert!(frame_len(b"HTTP/1.1").is_err());
        assert!(frame_len(&[b'S', b'T', b'F', 1, 0, 0, 0, 1]).is_err());
        assert!(frame_len(&[b'S', b'T', b'F', 2, 0, 0, 0, 0]).is_err());
    }

    #[test]
    fn an_oversized_frame_is_refused() {
        let len = (MAX_PAYLOAD as u16 + 1).to_be_bytes();
        assert!(frame_len(&[b'S', b'T', b'F', 1, len[0], len[1], 0, 0]).is_err());
        let len = (MAX_PAYLOAD as u16).to_be_bytes();
        assert_eq!(
            frame_len(&[b'S', b'T', b'F', 1, len[0], len[1], 0, 0]).unwrap(),
            Some(HEADER_LEN + MAX_PAYLOAD)
        );
    }

    #[test]
    fn the_goodbye_carries_the_reason_byte_then_the_text() {
        let bye = disconnect("user");
        assert_eq!(parse(&bye), (kind::DISCONNECT, &b"\xb0user"[..]));
        assert_eq!(frame_len(&bye).unwrap(), Some(bye.len()));
    }

    #[test]
    fn bare_frames_have_no_payload() {
        let keepalive = bare(kind::KEEPALIVE);
        assert_eq!(parse(&keepalive), (kind::KEEPALIVE, &[][..]));
    }
}
