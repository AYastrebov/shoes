//! An AsyncUdpSocket that obfuscates every datagram.

use std::cell::RefCell;
use std::io::IoSliceMut;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, Runtime, TokioRuntime, UdpPoller};

use super::Obfuscator;

/// Initial size of the send scratch buffer: a batch of ten full-size QUIC
/// packets, which is the most quinn sends at once. Anything larger grows it.
const SCRATCH_CAPACITY: usize = 16 * 1024;

thread_local! {
    /// Scratch space for the send path. `Transmit::contents` is an immutable
    /// slice, so obfuscation needs somewhere to write. A thread-local avoids
    /// both an allocation per packet and a lock that would serialise sends.
    static SEND_SCRATCH: RefCell<Vec<u8>> = RefCell::new(vec![0u8; SCRATCH_CAPACITY]);
}

/// Deobfuscate the first `count` buffers of a received batch in place,
/// dropping any that is not ours and compacting the survivors to the front.
///
/// A buffer holds one datagram, or several of one size laid end to end when
/// the kernel has coalesced them (`stride` is that size, the last may be
/// shorter). Each is deobfuscated on its own -- it carries its own salt --
/// and the results are packed back end to end, so what quinn sees is the
/// same layout with a stride `overhead` bytes smaller.
///
/// Returns how many buffers survived. Buffers past the returned count are
/// left as they are; quinn only reads the first `kept` entries.
fn deobfuscate_batch(
    obfs: &dyn Obfuscator,
    bufs: &mut [IoSliceMut<'_>],
    meta: &mut [RecvMeta],
    count: usize,
) -> usize {
    let mut kept = 0;
    for i in 0..count {
        let len = meta[i].len;
        let Some((decoded_len, decoded_stride)) =
            deobfuscate_segments(obfs, &mut bufs[i][..len], meta[i].stride)
        else {
            log::debug!(
                "dropping {len} bytes from {} that are not obfuscated for us",
                meta[i].addr
            );
            continue;
        };

        // quinn pairs meta[n] with bufs[n], so a survivor that moves forward
        // in the metadata must have its bytes move with it.
        if kept != i {
            meta[kept] = meta[i];
            let (left, right) = bufs.split_at_mut(i);
            left[kept][..decoded_len].copy_from_slice(&right[0][..decoded_len]);
        }
        meta[kept].len = decoded_len;
        meta[kept].stride = decoded_stride;
        kept += 1;
    }
    kept
}

/// Deobfuscate the datagrams in one received buffer, `stride` bytes each,
/// and pack the payloads at its front. Returns the bytes now in use and the
/// stride they are laid out at, or None if nothing in it was ours.
fn deobfuscate_segments(
    obfs: &dyn Obfuscator,
    buf: &mut [u8],
    stride: usize,
) -> Option<(usize, usize)> {
    let len = buf.len();
    if stride == 0 || stride >= len {
        // One datagram: the common case off Linux, and for a lone packet.
        let decoded = obfs.deobfuscate_in_place(buf)?;
        return Some((decoded, decoded));
    }

    // Every segment but the last is `stride` long and must decode to the
    // same length, or the layout quinn splits on no longer holds.
    let decoded_stride = stride.checked_sub(obfs.overhead()).filter(|n| *n > 0)?;
    let mut out = 0;
    let mut start = 0;
    while start < len {
        let end = (start + stride).min(len);
        match obfs.deobfuscate_in_place(&mut buf[start..end]) {
            Some(decoded) if end - start < stride || decoded == decoded_stride => {
                buf.copy_within(start..start + decoded, out);
                out += decoded;
            }
            // A short tail that is not a packet is dropped on its own; the
            // full segments before it are still good.
            None if end == len && out > 0 => {}
            _ => return None,
        }
        start = end;
    }
    (out > 0).then_some((out, decoded_stride))
}

/// Wraps quinn's own UDP socket and applies an obfuscator to every datagram.
///
/// Segmentation and receive offload pass through. With GSO a single `sendmsg`
/// carries several QUIC packets of one size, and the kernel splits them apart
/// again; each is obfuscated on its own here, so they stay one size, larger
/// by the obfuscator's overhead. Receive coalescing is the same in reverse.
///
/// Both used to be reported as unavailable, which cost a system call per
/// packet -- 2.0 Gbit/s against 5 for the same transfer unobfuscated -- and
/// was not safe either: quinn's own socket underneath asks the kernel to
/// coalesce regardless, and a coalesced buffer was then dropped whole.
#[derive(Debug)]
pub struct ObfuscatedUdpSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    obfs: Arc<dyn Obfuscator>,
}

impl ObfuscatedUdpSocket {
    /// Wrap a std socket. quinn's own `UdpSocketState::new` puts it into
    /// non-blocking mode, so the caller does not have to.
    pub fn new(socket: std::net::UdpSocket, obfs: Arc<dyn Obfuscator>) -> std::io::Result<Self> {
        Ok(Self {
            inner: TokioRuntime.wrap_udp_socket(socket)?,
            obfs,
        })
    }
}

impl AsyncUdpSocket for ObfuscatedUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> std::io::Result<()> {
        let overhead = self.obfs.overhead();
        // One segment unless quinn batched several of `segment_size` each,
        // the last possibly shorter.
        let segment = transmit
            .segment_size
            .unwrap_or(transmit.contents.len())
            .max(1);

        SEND_SCRATCH.with(|scratch| {
            let mut scratch = scratch.borrow_mut();
            let segments = transmit.contents.len().div_ceil(segment).max(1);
            let needed = transmit.contents.len() + segments * overhead;
            if scratch.len() < needed {
                scratch.resize(needed, 0);
            }

            let too_small = || std::io::Error::other("obfuscation buffer too small");
            let mut written = 0;
            if transmit.contents.is_empty() {
                written = self
                    .obfs
                    .obfuscate(transmit.contents, &mut scratch)
                    .ok_or_else(too_small)?;
            }
            for chunk in transmit.contents.chunks(segment) {
                let n = self
                    .obfs
                    .obfuscate(chunk, &mut scratch[written..])
                    .ok_or_else(too_small)?;
                // The kernel cuts the buffer every `segment + overhead`
                // bytes; an obfuscator that added anything else would have
                // its packets cut in the wrong places.
                if n != chunk.len() + overhead {
                    return Err(std::io::Error::other(
                        "obfuscator did not add its declared overhead",
                    ));
                }
                written += n;
            }

            self.inner.try_send(&Transmit {
                destination: transmit.destination,
                ecn: transmit.ecn,
                contents: &scratch[..written],
                segment_size: transmit.segment_size.map(|size| size + overhead),
                src_ip: transmit.src_ip,
            })
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<std::io::Result<usize>> {
        loop {
            let count = ready!(self.inner.poll_recv(cx, bufs, meta))?;
            let kept = deobfuscate_batch(self.obfs.as_ref(), bufs, meta, count);

            // Every datagram in this batch was garbage; wait for the next one
            // rather than reporting zero, which quinn reads as "nothing to do".
            if kept > 0 {
                return Poll::Ready(Ok(kept));
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic_transport::obfs::Salamander;

    fn wrap(std_socket: std::net::UdpSocket) -> Arc<ObfuscatedUdpSocket> {
        let obfs: Arc<dyn Obfuscator> = Arc::new(Salamander::new(b"a password").unwrap());
        Arc::new(ObfuscatedUdpSocket::new(std_socket, obfs).unwrap())
    }

    fn bind() -> std::net::UdpSocket {
        std::net::UdpSocket::bind("127.0.0.1:0").unwrap()
    }

    /// Poll until one datagram arrives, returning its length.
    async fn recv_one(socket: &ObfuscatedUdpSocket, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut meta = [RecvMeta::default()];
        let count = std::future::poll_fn(|cx| {
            let mut bufs = [IoSliceMut::new(buf)];
            socket.poll_recv(cx, &mut bufs, &mut meta)
        })
        .await?;
        assert_eq!(count, 1);
        assert_eq!(meta[0].stride, meta[0].len);
        Ok(meta[0].len)
    }

    /// Send one datagram, waiting for writability the way quinn does.
    ///
    /// `try_send` is allowed to return WouldBlock until tokio has observed the
    /// socket as writable, and the contract says the caller must then poll the
    /// socket's own `UdpPoller`. Doing that here also exercises the poller we
    /// delegate to the inner socket.
    async fn send(socket: &Arc<ObfuscatedUdpSocket>, destination: SocketAddr, contents: &[u8]) {
        let mut poller = socket.clone().create_io_poller();
        loop {
            match socket.try_send(&Transmit {
                destination,
                ecn: None,
                contents,
                segment_size: None,
                src_ip: None,
            }) {
                Ok(()) => return,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::future::poll_fn(|cx| poller.as_mut().poll_writable(cx))
                        .await
                        .unwrap();
                }
                Err(e) => panic!("try_send failed: {e}"),
            }
        }
    }

    #[tokio::test]
    async fn test_round_trip_between_two_wrapped_sockets() {
        let a = wrap(bind());
        let b = wrap(bind());
        let b_addr = b.local_addr().unwrap();

        let payload = b"a quic packet would go here";
        send(&a, b_addr, payload).await;

        let mut buf = [0u8; 2048];
        let len = recv_one(&b, &mut buf).await.unwrap();
        assert_eq!(len, payload.len());
        assert_eq!(&buf[..len], payload);
    }

    #[tokio::test]
    async fn test_offload_is_whatever_the_socket_underneath_offers() {
        let std_socket = bind();
        let plain = TokioRuntime
            .wrap_udp_socket(std_socket.try_clone().unwrap())
            .unwrap();
        let a = wrap(std_socket);
        assert_eq!(a.max_transmit_segments(), plain.max_transmit_segments());
        assert_eq!(a.max_receive_segments(), plain.max_receive_segments());
    }

    /// A segmented transmit is several packets of one size; each is
    /// obfuscated on its own and arrives as its own packet, whether the
    /// kernel delivers them one by one or coalesced.
    #[tokio::test]
    async fn test_segmented_transmit_arrives_as_its_packets() {
        let a = wrap(bind());
        if a.max_transmit_segments() < 3 {
            // No segmentation offload on this platform; quinn will never
            // hand this socket a segmented transmit.
            return;
        }
        let b = wrap(bind());
        let b_addr = b.local_addr().unwrap();

        let mut contents = Vec::new();
        contents.extend_from_slice(&[1u8; 1200]);
        contents.extend_from_slice(&[2u8; 1200]);
        contents.extend_from_slice(&[3u8; 700]);
        let mut poller = a.clone().create_io_poller();
        loop {
            match a.try_send(&Transmit {
                destination: b_addr,
                ecn: None,
                contents: &contents,
                segment_size: Some(1200),
                src_ip: None,
            }) {
                Ok(()) => break,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::future::poll_fn(|cx| poller.as_mut().poll_writable(cx))
                        .await
                        .unwrap();
                }
                Err(e) => panic!("try_send failed: {e}"),
            }
        }

        // Read until all three have arrived, in however many buffers.
        let mut received: Vec<Vec<u8>> = Vec::new();
        while received.len() < 3 {
            let mut buf = vec![0u8; 65536];
            let mut meta = [RecvMeta::default()];
            let count = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                std::future::poll_fn(|cx| {
                    let mut bufs = [IoSliceMut::new(&mut buf)];
                    b.poll_recv(cx, &mut bufs, &mut meta)
                }),
            )
            .await
            .expect("the segments never arrived")
            .unwrap();
            assert_eq!(count, 1);
            for packet in buf[..meta[0].len].chunks(meta[0].stride.max(1)) {
                received.push(packet.to_vec());
            }
        }
        assert_eq!(received[0], vec![1u8; 1200]);
        assert_eq!(received[1], vec![2u8; 1200]);
        assert_eq!(received[2], vec![3u8; 700]);
    }

    #[tokio::test]
    async fn test_garbage_datagram_is_dropped_not_returned() {
        let receiver = wrap(bind());
        let addr = receiver.local_addr().unwrap();

        // A plain sender: whatever it sends cannot deobfuscate to anything we
        // would accept, because it carries no salt we agreed on.
        let plain = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        plain.send_to(&[0u8; 4], addr).await.unwrap();

        // Then a well-formed packet, which must still arrive.
        let good = wrap(bind());
        send(&good, addr, b"real").await;

        let mut buf = [0u8; 2048];
        let len = recv_one(&receiver, &mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"real");
    }

    fn obfuscator() -> Salamander {
        Salamander::new(b"a password").unwrap()
    }

    /// Lay out a batch of raw buffers and their metadata the way the inner
    /// socket would hand them over.
    fn batch(packets: &[Vec<u8>]) -> (Vec<Vec<u8>>, Vec<RecvMeta>) {
        let storage: Vec<Vec<u8>> = packets
            .iter()
            .map(|p| {
                let mut buf = vec![0u8; 2048];
                buf[..p.len()].copy_from_slice(p);
                buf
            })
            .collect();
        let meta = packets
            .iter()
            .enumerate()
            .map(|(i, p)| RecvMeta {
                addr: format!("127.0.0.1:{}", 1000 + i).parse().unwrap(),
                len: p.len(),
                stride: p.len(),
                ecn: None,
                dst_ip: None,
            })
            .collect();
        (storage, meta)
    }

    fn wire(obfs: &Salamander, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; payload.len() + obfs.overhead()];
        let written = obfs.obfuscate(payload, &mut out).unwrap();
        out.truncate(written);
        out
    }

    #[test]
    fn test_batch_keeps_every_valid_datagram() {
        let obfs = obfuscator();
        let packets = vec![wire(&obfs, b"one"), wire(&obfs, b"two")];
        let (mut storage, mut meta) = batch(&packets);
        let mut bufs: Vec<IoSliceMut<'_>> =
            storage.iter_mut().map(|b| IoSliceMut::new(b)).collect();

        let kept = deobfuscate_batch(&obfs, &mut bufs, &mut meta, 2);

        assert_eq!(kept, 2);
        assert_eq!(&bufs[0][..meta[0].len], b"one");
        assert_eq!(&bufs[1][..meta[1].len], b"two");
    }

    /// The case the compaction exists for: a stray packet ahead of a real one
    /// in the same recvmmsg batch. quinn pairs meta[n] with bufs[n], so the
    /// survivor's bytes have to end up in the buffer its metadata names.
    #[test]
    fn test_batch_compacts_payload_and_metadata_together() {
        let obfs = obfuscator();
        let packets = vec![vec![0u8; 4], wire(&obfs, b"the real payload")];
        let (mut storage, mut meta) = batch(&packets);
        let good_addr = meta[1].addr;
        let mut bufs: Vec<IoSliceMut<'_>> =
            storage.iter_mut().map(|b| IoSliceMut::new(b)).collect();

        let kept = deobfuscate_batch(&obfs, &mut bufs, &mut meta, 2);

        assert_eq!(kept, 1);
        assert_eq!(meta[0].addr, good_addr, "metadata moved forward");
        assert_eq!(meta[0].len, b"the real payload".len());
        assert_eq!(
            &bufs[0][..meta[0].len],
            b"the real payload",
            "the payload must move with its metadata"
        );
    }

    /// A coalesced buffer is several datagrams of one size end to end, the
    /// last possibly shorter. Each carries its own salt, so each is decoded
    /// on its own, and the payloads come back packed at the smaller stride.
    /// This buffer used to be dropped whole.
    #[test]
    fn test_batch_decodes_each_datagram_of_a_coalesced_buffer() {
        let obfs = obfuscator();
        let coalesced: Vec<u8> = [
            wire(&obfs, &[1u8; 100]),
            wire(&obfs, &[2u8; 100]),
            wire(&obfs, &[3u8; 40]),
        ]
        .concat();
        let (mut storage, mut meta) = batch(&[coalesced]);
        meta[0].stride = 100 + obfs.overhead();
        let mut bufs: Vec<IoSliceMut<'_>> =
            storage.iter_mut().map(|b| IoSliceMut::new(b)).collect();

        let kept = deobfuscate_batch(&obfs, &mut bufs, &mut meta, 1);

        assert_eq!(kept, 1);
        assert_eq!(meta[0].stride, 100);
        assert_eq!(meta[0].len, 240);
        let payloads: Vec<&[u8]> = bufs[0][..meta[0].len].chunks(meta[0].stride).collect();
        assert_eq!(payloads, [&[1u8; 100][..], &[2u8; 100][..], &[3u8; 40][..]]);
    }

    /// A tail too short to be a packet is dropped on its own; a buffer
    /// whose stride cannot hold a packet at all is dropped whole.
    #[test]
    fn test_batch_handles_a_coalesced_buffer_that_is_partly_or_wholly_garbage() {
        let obfs = obfuscator();

        let mut with_runt = [wire(&obfs, &[1u8; 100]), wire(&obfs, &[2u8; 100])].concat();
        with_runt.extend_from_slice(&[0u8; 3]);
        let (mut storage, mut meta) = batch(&[with_runt]);
        meta[0].stride = 100 + obfs.overhead();
        let mut bufs: Vec<IoSliceMut<'_>> =
            storage.iter_mut().map(|b| IoSliceMut::new(b)).collect();
        assert_eq!(deobfuscate_batch(&obfs, &mut bufs, &mut meta, 1), 1);
        assert_eq!((meta[0].len, meta[0].stride), (200, 100));

        let (mut storage, mut meta) = batch(&[vec![0u8; 64]]);
        meta[0].stride = obfs.overhead();
        let mut bufs: Vec<IoSliceMut<'_>> =
            storage.iter_mut().map(|b| IoSliceMut::new(b)).collect();
        assert_eq!(deobfuscate_batch(&obfs, &mut bufs, &mut meta, 1), 0);
    }

    #[test]
    fn test_batch_drops_everything_when_nothing_is_ours() {
        let obfs = obfuscator();
        let packets = vec![vec![0u8; 4], vec![1u8; 6]];
        let (mut storage, mut meta) = batch(&packets);
        let mut bufs: Vec<IoSliceMut<'_>> =
            storage.iter_mut().map(|b| IoSliceMut::new(b)).collect();

        assert_eq!(deobfuscate_batch(&obfs, &mut bufs, &mut meta, 2), 0);
    }

    #[tokio::test]
    async fn test_an_obfuscated_packet_is_not_readable_in_the_clear() {
        let sender = wrap(bind());
        let plain = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let plain_addr = plain.local_addr().unwrap();

        let payload = b"plaintext marker";
        send(&sender, plain_addr, payload).await;

        let mut buf = [0u8; 2048];
        let (len, _) = plain.recv_from(&mut buf).await.unwrap();
        assert_eq!(len, payload.len() + 8, "salt is prefixed on the wire");
        assert!(
            !buf[..len].windows(payload.len()).any(|w| w == payload),
            "the payload must not appear verbatim on the wire"
        );
    }
}
