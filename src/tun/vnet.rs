//! Segmentation offload for a Linux TUN opened with `IFF_VNET_HDR`.
//!
//! Without it every packet through the device is one system call, and on the
//! way in that call runs the kernel's whole TCP receive path for one MSS of
//! data. The stack thread's throughput is then the packet rate it can sustain:
//! through a real TUN, 7.4 Gbit/s down at an MTU of 1500 and 35 at 65535, and
//! eight downloads at once 1.9 Gbit/s between them.
//!
//! With the flag, every read and write carries a `virtio_net_hdr`, and that
//! header can say "this is several TCP segments of `gso_size` bytes laid end to
//! end; cut them apart yourself". The kernel does so in both directions:
//!
//! - **In.** A local sender's segments arrive uncut, up to 64 KiB each. They
//!   are handed to smoltcp as they are: one segment, one ACK.
//! - **Out.** smoltcp emits one MSS at a time, since that is what the peer
//!   asked for. [`TxCoalescer`] joins consecutive segments of a flow into one
//!   packet before it is written, which is what wireguard-go does for its own
//!   TUN (`tun/offload_linux.go`) and what GRO does on a network card.
//!
//! The header is in native byte order: that is what the kernel reads unless
//! `TUNSETVNETLE` says otherwise, and a big-endian router is a target here.

use std::io;

/// `sizeof(struct virtio_net_hdr)`, which is what a TUN prepends unless
/// `TUNSETVNETHDRSZ` changes it.
pub const VNET_HDR_LEN: usize = 10;

/// The largest IP packet there is, which is the largest thing a TUN with
/// segmentation offload hands over in one read.
pub const MAX_OFFLOAD_PACKET: usize = 65535;

const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;
const VIRTIO_NET_HDR_GSO_TCPV4: u8 = 1;
const VIRTIO_NET_HDR_GSO_TCPV6: u8 = 4;

/// Segments joined into one packet at most. The kernel's own limit on a GSO
/// packet's segment count is higher; 64 KiB of data is the bound that binds.
const MAX_SEGMENTS: u16 = 64;

/// Entries a batch holds before it is written out regardless. A poll emits a
/// window per connection, which coalesces to an entry or two each, so this is
/// only reached with many connections sending at once.
const MAX_ENTRIES: usize = 128;

const TCP_FLAG_FIN: u8 = 0x01;
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_RST: u8 = 0x04;
const TCP_FLAG_PSH: u8 = 0x08;
const TCP_FLAG_ACK: u8 = 0x10;
const TCP_FLAG_URG: u8 = 0x20;

/// Where the TCP segment sits in a packet, and what it carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TcpLayout {
    ipv6: bool,
    /// Length of the IP header, which is also where the TCP header starts.
    ip_len: usize,
    /// Length of the TCP header, options included.
    tcp_len: usize,
    flags: u8,
    seq: u32,
}

impl TcpLayout {
    fn headers(&self) -> usize {
        self.ip_len + self.tcp_len
    }

    /// Parse `packet` as an unfragmented TCP segment. Anything else -- another
    /// protocol, a fragment, an IPv6 packet with extension headers, something
    /// truncated -- is `None`, and is written out untouched.
    fn parse(packet: &[u8]) -> Option<Self> {
        let (ipv6, ip_len) = match packet.first()? >> 4 {
            4 => {
                let ip_len = usize::from(packet[0] & 0x0f) * 4;
                if ip_len < 20 || packet.len() < ip_len || packet[9] != 6 {
                    return None;
                }
                // More-fragments set, or a fragment offset: not a whole segment.
                if u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff != 0 {
                    return None;
                }
                if usize::from(u16::from_be_bytes([packet[2], packet[3]])) != packet.len() {
                    return None;
                }
                (false, ip_len)
            }
            6 => {
                if packet.len() < 40 || packet[6] != 6 {
                    return None;
                }
                if usize::from(u16::from_be_bytes([packet[4], packet[5]])) + 40 != packet.len() {
                    return None;
                }
                (true, 40)
            }
            _ => return None,
        };
        let tcp = packet.get(ip_len..)?;
        if tcp.len() < 20 {
            return None;
        }
        let tcp_len = usize::from(tcp[12] >> 4) * 4;
        if tcp_len < 20 || tcp.len() < tcp_len {
            return None;
        }
        Some(Self {
            ipv6,
            ip_len,
            tcp_len,
            flags: tcp[13],
            seq: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
        })
    }

    /// Whether a segment with these flags can be part of a joined packet: it
    /// acknowledges and carries data, and does nothing else.
    fn joinable_flags(&self) -> bool {
        self.flags & (TCP_FLAG_FIN | TCP_FLAG_SYN | TCP_FLAG_RST | TCP_FLAG_URG) == 0
            && self.flags & TCP_FLAG_ACK != 0
    }
}

/// One packet waiting to be written: a segment on its own, or several joined.
struct Entry {
    /// `VNET_HDR_LEN` bytes of room for the header, then the packet.
    buf: Vec<u8>,
    tcp: Option<TcpLayout>,
    /// Payload bytes of the first segment, which every later one but the last
    /// must match: it becomes `gso_size`.
    segment_size: usize,
    segments: u16,
    /// Sequence number the next segment has to carry to be joined on.
    next_seq: u32,
    /// Whether more segments may still be joined on.
    open: bool,
}

impl Entry {
    fn packet(&self) -> &[u8] {
        &self.buf[VNET_HDR_LEN..]
    }
}

/// Joins the TCP segments smoltcp emits during one poll into as few packets
/// as the kernel will take, and writes them with their `virtio_net_hdr`.
pub struct TxCoalescer {
    entries: Vec<Entry>,
    /// Buffers kept from earlier batches, so a batch allocates nothing.
    spare: Vec<Vec<u8>>,
    /// The most one joined packet may hold, headers included.
    max_packet: usize,
}

impl TxCoalescer {
    /// `max_packet` bounds a joined packet, headers included, and is itself
    /// bounded by the largest IP packet.
    ///
    /// The device passes that largest size. A smaller bound was tried, a
    /// quarter of a connection's send buffer, on the reasoning that a packet
    /// holding the whole window makes the connection send, stop, and wait for
    /// one acknowledgement. It gained a single download nothing measurable
    /// and cost eight at once 40%, so it is here only as a limit.
    pub fn new(max_packet: usize) -> Self {
        Self {
            entries: Vec::new(),
            spare: Vec::new(),
            max_packet: max_packet.min(MAX_OFFLOAD_PACKET),
        }
    }

    /// Whether the batch should be written out before it takes more.
    pub fn is_full(&self) -> bool {
        self.entries.len() >= MAX_ENTRIES
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Take one packet of `len` bytes, filled in by `fill`, into the batch.
    pub fn push<R>(&mut self, len: usize, fill: impl FnOnce(&mut [u8]) -> R) -> R {
        let mut buf = self.spare.pop().unwrap_or_default();
        buf.clear();
        buf.resize(VNET_HDR_LEN + len, 0);
        let result = fill(&mut buf[VNET_HDR_LEN..]);

        let tcp = TcpLayout::parse(&buf[VNET_HDR_LEN..]);
        if let Some(layout) = tcp {
            let packet = &buf[VNET_HDR_LEN..];
            if let Some(index) = self.open_entry_for(packet, &layout) {
                if self.try_join(index, packet, &layout) {
                    self.spare.push(buf);
                    return result;
                }
                // Same flow, but it does not follow on: nothing later may be
                // joined ahead of this packet, or the flow would be reordered.
                self.entries[index].open = false;
            }
        }

        let payload = tcp.map_or(0, |l| len - l.headers());
        let open =
            tcp.is_some_and(|l| l.joinable_flags() && l.flags & TCP_FLAG_PSH == 0 && payload > 0);
        self.entries.push(Entry {
            buf,
            tcp,
            segment_size: payload,
            segments: 1,
            next_seq: tcp.map_or(0, |l| l.seq.wrapping_add(payload as u32)),
            open,
        });
        result
    }

    /// The entry still open for the flow `packet` belongs to, if there is one.
    /// Newest first: a flow has at most one open entry, and it is its latest.
    fn open_entry_for(&self, packet: &[u8], layout: &TcpLayout) -> Option<usize> {
        self.entries.iter().rposition(|entry| {
            entry.open
                && entry.tcp.is_some_and(|other| {
                    other.ipv6 == layout.ipv6
                        && other.ip_len == layout.ip_len
                        && same_flow(entry.packet(), packet, layout)
                })
        })
    }

    /// Join `packet` onto entry `index` if it is the next segment of it.
    fn try_join(&mut self, index: usize, packet: &[u8], layout: &TcpLayout) -> bool {
        let max_packet = self.max_packet;
        let entry = &mut self.entries[index];
        let head = entry.tcp.expect("only TCP entries are open");
        let payload = &packet[layout.headers()..];

        let joinable = layout.joinable_flags()
            && !payload.is_empty()
            && layout.tcp_len == head.tcp_len
            && layout.seq == entry.next_seq
            && payload.len() <= entry.segment_size
            && entry.segments < MAX_SEGMENTS
            && entry.packet().len() + payload.len() <= max_packet
            // Acknowledgement, window and options: the joined packet has one
            // TCP header, so every segment in it has to agree with it. Bytes
            // 8..12 are the acknowledgement number, 14..16 the window, and
            // everything from 20 the options.
            && tcp_header(entry.packet(), &head)[8..12] == tcp_header(packet, layout)[8..12]
            && tcp_header(entry.packet(), &head)[14..16] == tcp_header(packet, layout)[14..16]
            && tcp_header(entry.packet(), &head)[20..] == tcp_header(packet, layout)[20..];
        if !joinable {
            return false;
        }

        entry.buf.extend_from_slice(payload);
        entry.segments += 1;
        entry.next_seq = entry.next_seq.wrapping_add(payload.len() as u32);
        // A short segment or a push ends the run: only the last segment of a
        // joined packet may be short, and a push belongs to the last byte.
        if payload.len() < entry.segment_size || layout.flags & TCP_FLAG_PSH != 0 {
            entry.open = false;
        }
        if layout.flags & TCP_FLAG_PSH != 0 {
            let flags_at = VNET_HDR_LEN + head.ip_len + 13;
            entry.buf[flags_at] |= TCP_FLAG_PSH;
        }
        true
    }

    /// Write every packet in the batch, in the order its first segment was
    /// emitted, each as one call to `write`.
    pub fn flush(&mut self, mut write: impl FnMut(&[u8]) -> io::Result<()>) -> io::Result<()> {
        let mut outcome = Ok(());
        for mut entry in self.entries.drain(..) {
            if entry.segments > 1 {
                finish_joined(&mut entry);
            }
            // The header stays zeroed for a lone packet: nothing to cut, and
            // its checksums are already whole.
            if let Err(e) = write(&entry.buf) {
                outcome = Err(e);
            }
            self.spare.push(entry.buf);
        }
        outcome
    }
}

fn tcp_header<'a>(packet: &'a [u8], layout: &TcpLayout) -> &'a [u8] {
    &packet[layout.ip_len..layout.headers()]
}

/// Whether two packets of one layout share addresses and ports.
fn same_flow(a: &[u8], b: &[u8], layout: &TcpLayout) -> bool {
    let addresses = if layout.ipv6 { 8..40 } else { 12..20 };
    let ports = layout.ip_len..layout.ip_len + 4;
    a[addresses.clone()] == b[addresses] && a[ports.clone()] == b[ports]
}

/// Turn an entry of several joined segments into one packet the kernel will
/// cut apart again: the lengths cover the whole of it, the TCP checksum is
/// left for the kernel to finish per segment, and the header says how.
fn finish_joined(entry: &mut Entry) {
    let layout = entry.tcp.expect("only TCP entries are joined");
    let packet_len = entry.buf.len() - VNET_HDR_LEN;
    let tcp_total = packet_len - layout.ip_len;
    let (header, packet) = entry.buf.split_at_mut(VNET_HDR_LEN);

    let pseudo = if layout.ipv6 {
        packet[4..6].copy_from_slice(&((packet_len - 40) as u16).to_be_bytes());
        ones_complement_sum(&packet[8..40], u32::from(6u16) + tcp_total as u32)
    } else {
        packet[2..4].copy_from_slice(&(packet_len as u16).to_be_bytes());
        packet[10..12].fill(0);
        let ip_checksum = !fold(ones_complement_sum(&packet[..layout.ip_len], 0));
        packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
        ones_complement_sum(&packet[12..20], u32::from(6u16) + tcp_total as u32)
    };
    // What Linux expects of a packet whose checksum it is to finish: the
    // folded sum of the pseudo-header, not complemented, in the checksum
    // field. Segmentation adjusts it for each piece's own length.
    let checksum_at = layout.ip_len + 16;
    packet[checksum_at..checksum_at + 2].copy_from_slice(&fold(pseudo).to_be_bytes());

    header[0] = VIRTIO_NET_HDR_F_NEEDS_CSUM;
    header[1] = if layout.ipv6 {
        VIRTIO_NET_HDR_GSO_TCPV6
    } else {
        VIRTIO_NET_HDR_GSO_TCPV4
    };
    header[2..4].copy_from_slice(&(layout.headers() as u16).to_ne_bytes());
    header[4..6].copy_from_slice(&(entry.segment_size as u16).to_ne_bytes());
    header[6..8].copy_from_slice(&(layout.ip_len as u16).to_ne_bytes());
    header[8..10].copy_from_slice(&16u16.to_ne_bytes());
}

/// The Internet checksum's running sum over `data`, big-endian 16-bit words,
/// starting from `initial`.
fn ones_complement_sum(data: &[u8], initial: u32) -> u32 {
    let mut sum = initial;
    let (words, remainder) = data.as_chunks::<2>();
    for word in words {
        sum += u32::from(u16::from_be_bytes(*word));
    }
    if let [last] = remainder {
        sum += u32::from(*last) << 8;
    }
    sum
}

fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

#[cfg(test)]
mod tests {
    use smoltcp::phy::ChecksumCapabilities;
    use smoltcp::wire::{
        IpAddress, IpProtocol, Ipv4Address, Ipv4Packet, Ipv4Repr, Ipv6Address, Ipv6Packet,
        Ipv6Repr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber,
    };

    use super::*;

    /// A fully checksummed segment from 93.184.216.34:443 to 10.0.0.2:`port`,
    /// or the IPv6 equivalent: the direction this stack sends in.
    fn segment(ipv6: bool, port: u16, seq: u32, control: TcpControl, payload: &[u8]) -> Vec<u8> {
        let tcp = TcpRepr {
            src_port: 443,
            dst_port: port,
            control,
            seq_number: TcpSeqNumber(seq as i32),
            ack_number: Some(TcpSeqNumber(7)),
            window_len: 4096,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload,
        };
        let checksums = ChecksumCapabilities::default();
        if ipv6 {
            let src = Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
            let dst = Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
            let ip = Ipv6Repr {
                src_addr: src,
                dst_addr: dst,
                next_header: IpProtocol::Tcp,
                payload_len: tcp.buffer_len(),
                hop_limit: 64,
            };
            let mut buffer = vec![0u8; ip.buffer_len() + tcp.buffer_len()];
            ip.emit(&mut Ipv6Packet::new_unchecked(&mut buffer));
            tcp.emit(
                &mut TcpPacket::new_unchecked(&mut buffer[ip.buffer_len()..]),
                &src.into(),
                &dst.into(),
                &checksums,
            );
            buffer
        } else {
            let src = Ipv4Address::new(93, 184, 216, 34);
            let dst = Ipv4Address::new(10, 0, 0, 2);
            let ip = Ipv4Repr {
                src_addr: src,
                dst_addr: dst,
                next_header: IpProtocol::Tcp,
                payload_len: tcp.buffer_len(),
                hop_limit: 64,
            };
            let mut buffer = vec![0u8; ip.buffer_len() + tcp.buffer_len()];
            ip.emit(&mut Ipv4Packet::new_unchecked(&mut buffer), &checksums);
            tcp.emit(
                &mut TcpPacket::new_unchecked(&mut buffer[ip.buffer_len()..]),
                &src.into(),
                &dst.into(),
                &checksums,
            );
            buffer
        }
    }

    fn push(batch: &mut TxCoalescer, packet: &[u8]) {
        batch.push(packet.len(), |buf| buf.copy_from_slice(packet));
    }

    fn flushed(batch: &mut TxCoalescer) -> Vec<Vec<u8>> {
        let mut written = Vec::new();
        batch
            .flush(|bytes| {
                written.push(bytes.to_vec());
                Ok(())
            })
            .unwrap();
        written
    }

    /// What the kernel does with a written packet: read the header, and if it
    /// says so, cut the packet into segments of `gso_size`, giving each its
    /// own lengths, sequence number and checksums. Returns whole, verified
    /// packets, so a test can compare them with what went in.
    fn kernel_segments(written: &[u8]) -> Vec<Vec<u8>> {
        let (header, packet) = written.split_at(VNET_HDR_LEN);
        if header[1] == 0 {
            assert_eq!(
                header, [0u8; VNET_HDR_LEN],
                "a lone packet has an empty header"
            );
            return vec![packet.to_vec()];
        }
        assert_eq!(header[0], VIRTIO_NET_HDR_F_NEEDS_CSUM);
        let headers = usize::from(u16::from_ne_bytes([header[2], header[3]]));
        let gso_size = usize::from(u16::from_ne_bytes([header[4], header[5]]));
        let csum_start = usize::from(u16::from_ne_bytes([header[6], header[7]]));
        let csum_offset = usize::from(u16::from_ne_bytes([header[8], header[9]]));
        let layout = TcpLayout::parse(packet).expect("a joined packet parses as TCP");
        assert_eq!(headers, layout.headers());
        assert_eq!(csum_start, layout.ip_len);
        assert_eq!(csum_offset, 16);
        assert_eq!(header[1] == VIRTIO_NET_HDR_GSO_TCPV6, layout.ipv6);

        // The partial checksum must be the pseudo-header's, over the whole.
        let tcp_total = packet.len() - layout.ip_len;
        let addresses = if layout.ipv6 { 8..40 } else { 12..20 };
        let expected = fold(ones_complement_sum(
            &packet[addresses],
            6 + tcp_total as u32,
        ));
        let at = csum_start + csum_offset;
        assert_eq!(u16::from_be_bytes([packet[at], packet[at + 1]]), expected);
        if !layout.ipv6 {
            assert!(Ipv4Packet::new_checked(packet).unwrap().verify_checksum());
        }

        let payload = &packet[headers..];
        let pieces: Vec<&[u8]> = payload.chunks(gso_size).collect();
        let last = pieces.len() - 1;
        pieces
            .iter()
            .enumerate()
            .map(|(i, piece)| {
                let mut out = packet[..headers].to_vec();
                out.extend_from_slice(piece);
                let seq = layout.seq.wrapping_add((i * gso_size) as u32);
                let tcp_at = layout.ip_len;
                out[tcp_at + 4..tcp_at + 8].copy_from_slice(&seq.to_be_bytes());
                if i != last {
                    out[tcp_at + 13] &= !TCP_FLAG_PSH;
                }
                let (src, dst): (IpAddress, IpAddress) = if layout.ipv6 {
                    let len = (out.len() - 40) as u16;
                    out[4..6].copy_from_slice(&len.to_be_bytes());
                    let ip = Ipv6Packet::new_unchecked(&out[..]);
                    (ip.src_addr().into(), ip.dst_addr().into())
                } else {
                    let len = out.len() as u16;
                    out[2..4].copy_from_slice(&len.to_be_bytes());
                    let mut ip = Ipv4Packet::new_unchecked(&mut out[..]);
                    ip.fill_checksum();
                    (ip.src_addr().into(), ip.dst_addr().into())
                };
                TcpPacket::new_unchecked(&mut out[tcp_at..]).fill_checksum(&src, &dst);
                out
            })
            .collect()
    }

    /// The property everything else rests on: whatever is joined, the kernel
    /// cutting it apart again yields exactly the packets that went in.
    fn assert_round_trips(packets: &[Vec<u8>]) -> Vec<Vec<u8>> {
        let mut batch = TxCoalescer::new(MAX_OFFLOAD_PACKET);
        for packet in packets {
            push(&mut batch, packet);
        }
        let written = flushed(&mut batch);
        let recovered: Vec<Vec<u8>> = written.iter().flat_map(|w| kernel_segments(w)).collect();
        assert_eq!(recovered.len(), packets.len());
        for (i, (got, want)) in recovered.iter().zip(packets).enumerate() {
            assert_eq!(got, want, "packet {i} did not survive");
        }
        written
    }

    #[test]
    fn consecutive_segments_of_a_flow_become_one_write() {
        for ipv6 in [false, true] {
            let packets: Vec<Vec<u8>> = (0..5)
                .map(|i| {
                    segment(
                        ipv6,
                        50000,
                        1 + i * 1000,
                        TcpControl::None,
                        &[i as u8; 1000],
                    )
                })
                .collect();
            let written = assert_round_trips(&packets);
            assert_eq!(written.len(), 1, "ipv6={ipv6}");
            assert_ne!(written[0][1], 0, "the header names a segmentation type");
        }
    }

    #[test]
    fn a_short_or_pushed_segment_ends_the_run_and_stays_last() {
        let packets = vec![
            segment(false, 50000, 1, TcpControl::None, &[1; 1000]),
            segment(false, 50000, 1001, TcpControl::None, &[2; 1000]),
            segment(false, 50000, 2001, TcpControl::Psh, &[3; 400]),
            // After the push: a new run.
            segment(false, 50000, 2401, TcpControl::None, &[4; 1000]),
            segment(false, 50000, 3401, TcpControl::None, &[5; 1000]),
        ];
        let written = assert_round_trips(&packets);
        assert_eq!(written.len(), 2);
    }

    #[test]
    fn flows_interleaved_by_the_poll_are_joined_each_with_its_own() {
        let mut packets = Vec::new();
        for i in 0..4u32 {
            for port in [50000u16, 50001, 50002] {
                packets.push(segment(
                    false,
                    port,
                    1 + i * 1200,
                    TcpControl::None,
                    &[port as u8; 1200],
                ));
            }
        }
        let mut batch = TxCoalescer::new(MAX_OFFLOAD_PACKET);
        for packet in &packets {
            push(&mut batch, packet);
        }
        let written = flushed(&mut batch);
        assert_eq!(written.len(), 3, "one packet per flow");
        for (flow, packet) in written.iter().enumerate() {
            let segments = kernel_segments(packet);
            let expected: Vec<&Vec<u8>> = packets.iter().skip(flow).step_by(3).collect();
            assert_eq!(segments.iter().collect::<Vec<_>>(), expected);
        }
    }

    #[test]
    fn what_cannot_be_joined_is_written_as_it_was_and_in_order() {
        let packets = vec![
            segment(false, 50000, 1, TcpControl::None, &[1; 500]),
            // A gap in the sequence: not the next segment.
            segment(false, 50000, 9001, TcpControl::None, &[2; 500]),
            // A pure acknowledgement, a FIN, and a SYN+ACK carry nothing to join.
            segment(false, 50000, 9501, TcpControl::None, &[]),
            segment(false, 50000, 9501, TcpControl::Fin, &[]),
            segment(false, 50001, 0, TcpControl::Syn, &[]),
            // A larger segment than the run's first cannot follow it.
            segment(false, 50002, 1, TcpControl::None, &[3; 300]),
            segment(false, 50002, 301, TcpControl::None, &[4; 600]),
        ];
        let written = assert_round_trips(&packets);
        assert_eq!(written.len(), packets.len());
        for packet in &written {
            assert_eq!(&packet[..VNET_HDR_LEN], [0u8; VNET_HDR_LEN]);
        }
    }

    #[test]
    fn a_differing_acknowledgement_or_window_is_not_joined() {
        let first = segment(false, 50000, 1, TcpControl::None, &[1; 500]);
        let mut newer_ack = segment(false, 50000, 501, TcpControl::None, &[2; 500]);
        newer_ack[20 + 8..20 + 12].copy_from_slice(&99u32.to_be_bytes());
        let mut batch = TxCoalescer::new(MAX_OFFLOAD_PACKET);
        push(&mut batch, &first);
        push(&mut batch, &newer_ack);
        assert_eq!(flushed(&mut batch).len(), 2);

        let mut other_window = segment(false, 50000, 501, TcpControl::None, &[2; 500]);
        other_window[20 + 14..20 + 16].copy_from_slice(&1u16.to_be_bytes());
        push(&mut batch, &first);
        push(&mut batch, &other_window);
        assert_eq!(flushed(&mut batch).len(), 2);
    }

    #[test]
    fn a_joined_packet_never_exceeds_the_largest_ip_packet() {
        let packets: Vec<Vec<u8>> = (0..60)
            .map(|i| {
                segment(
                    false,
                    50000,
                    1 + i * 1400,
                    TcpControl::None,
                    &[i as u8; 1400],
                )
            })
            .collect();
        let written = assert_round_trips(&packets);
        assert!(written.len() >= 2);
        for packet in &written {
            assert!(packet.len() - VNET_HDR_LEN <= MAX_OFFLOAD_PACKET);
        }
    }

    /// A joined packet stays under the bound it was given.
    #[test]
    fn a_joined_packet_respects_the_bound_it_was_given() {
        let packets: Vec<Vec<u8>> = (0..12)
            .map(|i| {
                segment(
                    false,
                    50000,
                    1 + i * 1000,
                    TcpControl::None,
                    &[i as u8; 1000],
                )
            })
            .collect();
        let mut batch = TxCoalescer::new(4096);
        for packet in &packets {
            push(&mut batch, packet);
        }
        let written = flushed(&mut batch);
        assert_eq!(
            written.len(),
            3,
            "four segments and their headers fit in 4096"
        );
        for packet in &written {
            assert!(packet.len() - VNET_HDR_LEN <= 4096);
        }
        let recovered: Vec<Vec<u8>> = written.iter().flat_map(|w| kernel_segments(w)).collect();
        assert_eq!(recovered, packets);
    }

    /// A batch of packets that cannot be joined asks to be written out
    /// before it grows without bound.
    #[test]
    fn a_batch_of_unjoinable_packets_reports_itself_full() {
        let mut batch = TxCoalescer::new(MAX_OFFLOAD_PACKET);
        for port in 0..MAX_ENTRIES as u16 {
            assert!(!batch.is_full());
            push(
                &mut batch,
                &segment(false, 40000 + port, 1, TcpControl::None, &[1; 10]),
            );
        }
        assert!(batch.is_full());
        assert_eq!(flushed(&mut batch).len(), MAX_ENTRIES);
        assert!(!batch.is_full());
    }

    #[test]
    fn packets_that_are_not_tcp_pass_through_untouched() {
        let udp_like = {
            let mut p = segment(false, 50000, 1, TcpControl::None, &[1; 100]);
            p[9] = 17;
            p
        };
        let garbage = vec![0xffu8; 30];
        let mut batch = TxCoalescer::new(MAX_OFFLOAD_PACKET);
        push(&mut batch, &udp_like);
        push(&mut batch, &udp_like);
        push(&mut batch, &garbage);
        let written = flushed(&mut batch);
        assert_eq!(written.len(), 3);
        assert_eq!(&written[0][VNET_HDR_LEN..], &udp_like[..]);
        assert_eq!(&written[2][VNET_HDR_LEN..], &garbage[..]);
        assert!(batch.is_empty());
    }
}
