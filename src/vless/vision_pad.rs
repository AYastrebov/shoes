use bytes::{BufMut, Bytes, BytesMut};
use rand::RngExt;

// Padding parameters
const LONG_PADDING_MIN: usize = 900;
const LONG_PADDING_RANDOM_MAX: usize = 500;
const SHORT_PADDING_RANDOM_MAX: usize = 256;
const MAX_PADDING_SIZE: usize = 8171; // buf.Size - 21
const COMMAND_CONTINUE: u8 = 0x00;

pub fn pad_with_uuid_and_command(data: &[u8], uuid: &[u8; 16], command: u8, is_tls: bool) -> Bytes {
    pad(data, Some(uuid), command, is_tls)
}
//
pub fn pad_with_command(data: &[u8], command: u8, is_tls: bool) -> Bytes {
    pad(data, None, command, is_tls)
}

/// Pad `data` into one or more Vision frames.
///
/// A frame's content length is a u16 and Xray never sends one over `MAX_PADDING_SIZE`
/// (`ReshapeMultiBuffer`, proxy/proxy.go:463-495), so a larger write is split. Only the
/// first frame carries the UUID and only the last carries `command`; earlier frames say
/// Continue, as Xray's VisionWriter does for all but the last buffer (proxy.go:386-393).
fn pad(data: &[u8], mut uuid: Option<&[u8; 16]>, command: u8, is_tls: bool) -> Bytes {
    let mut output = BytesMut::new();
    let mut chunks = data.chunks(MAX_PADDING_SIZE).peekable();
    if chunks.peek().is_none() {
        pad_one(&mut output, data, uuid, command, is_tls);
        return output.freeze();
    }
    while let Some(chunk) = chunks.next() {
        let chunk_command = if chunks.peek().is_some() {
            COMMAND_CONTINUE
        } else {
            command
        };
        pad_one(&mut output, chunk, uuid.take(), chunk_command, is_tls);
    }
    output.freeze()
}

fn pad_one(output: &mut BytesMut, data: &[u8], uuid: Option<&[u8; 16]>, command: u8, is_tls: bool) {
    let content_len = data.len();
    debug_assert!(content_len <= MAX_PADDING_SIZE);
    let padding_len = calculate_padding_length(content_len, is_tls);

    let uuid_len = if uuid.is_some() { 16 } else { 0 };
    output.reserve(uuid_len + 1 + 2 + 2 + content_len + padding_len);

    if let Some(uuid) = uuid {
        output.put_slice(uuid);
    }

    output.put_u8(command);
    output.put_u16(content_len as u16);
    output.put_u16(padding_len as u16);
    output.put_slice(data);

    // Write random padding
    if padding_len > 0 {
        let padding_start = output.len();
        output.resize(padding_start + padding_len, 0);
        rand::rng().fill(&mut output[padding_start..]);
    }
}

/// Calculate padding length based on content size and TLS detection
fn calculate_padding_length(content_len: usize, is_tls: bool) -> usize {
    let mut rng = rand::rng();

    // Calculate maximum allowable padding (avoid overflow)
    // Matches Xray-core logic: buf.Size - 21 - contentLen
    // MAX_PADDING_SIZE is already (buf.Size - 21), so we only subtract content_len
    let max_allowable = MAX_PADDING_SIZE.saturating_sub(content_len);

    if is_tls && content_len < LONG_PADDING_MIN {
        // Long padding for TLS handshake phase
        let random_part = rng.random_range(0..LONG_PADDING_RANDOM_MAX);
        let padding = LONG_PADDING_MIN
            .saturating_sub(content_len)
            .saturating_add(random_part);
        std::cmp::min(padding, max_allowable)
    } else {
        // Short random padding
        let padding = rng.random_range(0..SHORT_PADDING_RANDOM_MAX);
        std::cmp::min(padding, max_allowable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// (uuid present, command, content) of each frame.
    fn frames(mut wire: &[u8], uuid: &[u8; 16]) -> Vec<(bool, u8, Vec<u8>)> {
        let mut out = Vec::new();
        while !wire.is_empty() {
            let has_uuid = out.is_empty() && wire.starts_with(uuid);
            if has_uuid {
                wire = &wire[16..];
            }
            let command = wire[0];
            let content_len = u16::from_be_bytes([wire[1], wire[2]]) as usize;
            let padding_len = u16::from_be_bytes([wire[3], wire[4]]) as usize;
            out.push((has_uuid, command, wire[5..5 + content_len].to_vec()));
            wire = &wire[5 + content_len + padding_len..];
        }
        out
    }

    #[test]
    fn a_write_over_the_frame_cap_is_split_and_keeps_its_length() {
        let uuid = [9u8; 16];
        let data: Vec<u8> = (0..70_000u32).map(|i| i as u8).collect();
        let wire = pad_with_uuid_and_command(&data, &uuid, 0x01, false);

        let frames = frames(&wire, &uuid);
        assert_eq!(frames.len(), 70_000usize.div_ceil(MAX_PADDING_SIZE));
        assert!(frames.iter().all(|(_, _, c)| c.len() <= MAX_PADDING_SIZE));
        let content: Vec<u8> = frames.iter().flat_map(|(_, _, c)| c.clone()).collect();
        assert_eq!(content, data);
        assert!(frames[0].0, "the first frame carries the UUID");
        assert!(frames[1..].iter().all(|(u, _, _)| !u));
        assert!(
            frames[..frames.len() - 1]
                .iter()
                .all(|(_, c, _)| *c == COMMAND_CONTINUE)
        );
        assert_eq!(
            frames.last().unwrap().1,
            0x01,
            "only the last carries the command"
        );
    }

    #[test]
    fn an_empty_write_is_one_frame() {
        let uuid = [9u8; 16];
        let frames = frames(
            &pad_with_uuid_and_command(&[], &uuid, COMMAND_CONTINUE, true),
            &uuid,
        );
        assert_eq!(frames, vec![(true, COMMAND_CONTINUE, vec![])]);
    }
}
