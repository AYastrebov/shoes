//! An established SSTP session: the data path and its upkeep.
//!
//! Two tasks beside the netstack's own (one worker per session, nothing
//! spawned per packet):
//!
//! ```text
//! netstack ──ip_to_tunnel (backpressured)──► writer ──TLS──► TCP
//! netstack ◄─ip_from_tunnel (awaited)─────── reader ◄─TLS─── TCP
//!                         control (16) ────► writer (polled first)
//! ```
//!
//! The writer drains every packet already queued into one buffer and writes
//! it once, so a burst shares a TLS record: rustls encrypts each `write`
//! into its own records and never merges across calls (`common_state.rs`
//! in rustls 0.23). Open-SSTP-Client does the same
//! (`io/OutgoingManager.kt:31-53`); sstp-client writes one record per
//! packet. The reader parses packets in place out of one buffer.
//!
//! Nothing between the inner TCP and the socket drops a packet. The netstack
//! refuses to emit past the outbound channel's free slots, and the reader
//! waits on a full inbound channel, which stops it reading, which closes the
//! server's TCP window. The outer TCP is flow-controlled, so waiting is free;
//! a drop would cost an inner retransmission that crosses the outer TCP a
//! second time.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use log::{debug, info, warn};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{Notify, mpsc};

use super::handshake::{Established, TlsStream};
use super::packet::{self, Packet, message};
use super::ppp::{self, Ppp};

/// TLS's largest record plaintext: a batch that fills it is one record.
const BATCH: usize = 16 * 1024;
/// Room left for one more packet before a batch closes: the largest SSTP
/// packet.
const MAX_SSTP_PACKET: usize = packet::MAX_PACKET_LEN;
/// The reader's buffer: room for whole records and a straddling packet.
const READ_BUFFER: usize = 32 * 1024 + MAX_SSTP_PACKET;
/// Control messages the reader queues for the writer: echo answers, LCP
/// replies. A full queue means a peer sending control faster than one TLS
/// write drains it, which only a broken or hostile peer does, so the
/// session ends rather than queueing without bound.
const CONTROL_QUEUE: usize = 16;
/// [MS-SSTP] §3.1.2.3: an Echo Request after 60 s with nothing received,
/// and the connection given up 60 s after that.
const HELLO: Duration = Duration::from_secs(60);
/// How long a stop waits for the server's Call Disconnect Ack. The spec's
/// 5 s is for an orderly cleanup that closing the connection also brings
/// about; on mobile, stop latency is what the user sees.
const STOP_WAIT: Duration = Duration::from_secs(1);

/// A session's liveness, shared by its tasks and the connector.
pub struct SessionState {
    dead: AtomicBool,
    stopping: AtomicBool,
    /// Rung on a stop and on a death.
    wake: Notify,
    /// Rung on a death only.
    died: Notify,
}

impl SessionState {
    fn new() -> Arc<Self> {
        Arc::new(SessionState {
            dead: AtomicBool::new(false),
            stopping: AtomicBool::new(false),
            wake: Notify::new(),
            died: Notify::new(),
        })
    }

    pub fn is_dead(&self) -> bool {
        self.dead.load(Ordering::Acquire)
    }

    fn kill(&self) {
        self.dead.store(true, Ordering::Release);
        self.wake.notify_waiters();
        self.died.notify_waiters();
    }

    /// Ask the writer to say goodbye and the session to end.
    pub fn stop(&self) {
        self.stopping.store(true, Ordering::Release);
        self.wake.notify_waiters();
    }

    fn stopping(&self) -> bool {
        self.stopping.load(Ordering::Acquire)
    }

    /// Resolves when the session is killed or asked to stop. Registered
    /// before the flags are read, so a change landing between the two is
    /// not missed: `notify_waiters` only wakes futures already waiting.
    async fn changed(&self) {
        let notified = self.wake.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if self.is_dead() || self.stopping() {
            return;
        }
        notified.await;
    }

    /// Resolves once the session is dead, on the same terms as `changed`.
    async fn dead(&self) {
        let notified = self.died.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if self.is_dead() {
            return;
        }
        notified.await;
    }
}

impl crate::network_change::NetworkChangeListener for SessionState {
    /// A TCP connection does not survive its interface going away, and the
    /// new PPP session may get another address, so the flows on this one
    /// could not continue anyway. End it now rather than after two silent
    /// hello intervals; the next connection builds a new one.
    fn network_changed(&self) {
        info!("SSTP: network changed; ending the session");
        self.kill();
    }
}

/// The halves the netstack talks to.
pub struct Channels {
    pub ip_to_tunnel: mpsc::Receiver<Vec<u8>>,
    pub ip_from_tunnel: mpsc::Sender<Vec<u8>>,
}

/// Start the reader and writer on an established session.
pub fn spawn(established: Established, channels: Channels, mtu: u16) -> Arc<SessionState> {
    let state = SessionState::new();
    let Established {
        stream,
        pending,
        ppp,
        link: _,
    } = established;
    let (read, write) = tokio::io::split(stream);
    let (control_tx, control_rx) = mpsc::channel(CONTROL_QUEUE);

    let writer_state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = writer(write, channels.ip_to_tunnel, control_rx, &writer_state, mtu).await {
            debug!("SSTP: writer ended: {e}");
        }
        writer_state.kill();
    });

    let reader_state = state.clone();
    tokio::spawn(async move {
        let reader = Reader {
            read,
            buf: vec![0u8; READ_BUFFER].into_boxed_slice(),
            start: 0,
            end: 0,
            ppp,
            ip_from_tunnel: channels.ip_from_tunnel,
            control: control_tx,
        };
        if let Err(e) = reader.run(pending, &reader_state).await {
            if reader_state.stopping() {
                debug!("SSTP: session stopped: {e}");
            } else {
                warn!("SSTP: session ended: {e}");
            }
        }
        reader_state.kill();
    });

    state
}

/// One SSTP data packet carrying an IPv4 packet: the SSTP header, `FF 03`,
/// protocol 0x0021, then the packet, appended to `out`.
fn encode_ip(out: &mut Vec<u8>, ip: &[u8]) {
    out.extend_from_slice(&packet::data_header(4 + ip.len()));
    out.extend_from_slice(&[0xff, 0x03, 0x00, 0x21]);
    out.extend_from_slice(ip);
}

async fn writer(
    mut write: WriteHalf<TlsStream>,
    mut ip_to_tunnel: mpsc::Receiver<Vec<u8>>,
    mut control: mpsc::Receiver<Vec<u8>>,
    state: &SessionState,
    mtu: u16,
) -> io::Result<()> {
    // The largest data packet: SSTP and PPP headers, then an MTU of IP.
    let largest = 8 + usize::from(mtu);
    let mut batch = Vec::with_capacity(BATCH + largest);
    loop {
        if state.is_dead() {
            return Ok(());
        }
        if state.stopping() {
            return goodbye(&mut write, state).await;
        }
        batch.clear();
        tokio::select! {
            // Control first: an echo answer must not wait behind an upload.
            biased;
            _ = state.changed() => continue,
            Some(packet) = control.recv() => batch.extend_from_slice(&packet),
            packet = ip_to_tunnel.recv() => match packet {
                Some(ip) => push_ip(&mut batch, &ip, mtu),
                // The netstack is gone; so is the session.
                None => return Ok(()),
            },
        }
        // Everything already queued joins this write, while a record has
        // room for one more packet of the largest size.
        while batch.len() + largest <= BATCH {
            if let Ok(packet) = control.try_recv() {
                batch.extend_from_slice(&packet);
                continue;
            }
            match ip_to_tunnel.try_recv() {
                Ok(ip) => push_ip(&mut batch, &ip, mtu),
                Err(_) => break,
            }
        }
        if !batch.is_empty() {
            write.write_all(&batch).await?;
            write.flush().await?;
        }
    }
}

/// Queue one IP packet for the server. IPv4 only: the session negotiated no
/// IPv6, so the netstack has no IPv6 address to send from, and a packet
/// over the server's MRU would be refused by it.
fn push_ip(batch: &mut Vec<u8>, ip: &[u8], mtu: u16) {
    if ip.first().map(|b| b >> 4) != Some(4) || ip.len() > usize::from(mtu) {
        debug!(
            "SSTP: dropping a packet the link cannot carry ({} bytes)",
            ip.len()
        );
        return;
    }
    encode_ip(batch, ip);
}

/// LCP Terminate-Request and Call Disconnect in one write, then close once
/// the reader has seen the Ack, or after [`STOP_WAIT`].
async fn goodbye(write: &mut WriteHalf<TlsStream>, state: &SessionState) -> io::Result<()> {
    let mut out = Vec::new();
    let terminate = ppp::frame(
        ppp::protocol::LCP,
        &ppp::control(ppp::code::TERMINATE_REQUEST, 0xfe, &[]),
    );
    out.extend_from_slice(&packet::data_header(terminate.len()));
    out.extend_from_slice(&terminate);
    out.extend_from_slice(&packet::bare_control(message::CALL_DISCONNECT));
    write.write_all(&out).await?;
    write.flush().await?;
    let _ = tokio::time::timeout(STOP_WAIT, state.dead()).await;
    write.shutdown().await
}

struct Reader {
    read: ReadHalf<TlsStream>,
    buf: Box<[u8]>,
    start: usize,
    end: usize,
    ppp: Ppp,
    ip_from_tunnel: mpsc::Sender<Vec<u8>>,
    control: mpsc::Sender<Vec<u8>>,
}

impl Reader {
    async fn run(mut self, pending: Vec<u8>, state: &SessionState) -> io::Result<()> {
        self.buf[..pending.len()].copy_from_slice(&pending);
        self.end = pending.len();
        let mut last_received = Instant::now();
        let mut echo_sent = false;
        loop {
            self.drain().await?;
            if state.is_dead() {
                return Ok(());
            }

            // Compact: the incomplete tail, at most one packet less a byte,
            // moves to the front.
            if self.start > 0 {
                self.buf.copy_within(self.start..self.end, 0);
                self.end -= self.start;
                self.start = 0;
            }

            let idle_until = tokio::time::Instant::from_std(last_received + HELLO);
            let read = tokio::select! {
                // A stop keeps reading: the Disconnect Ack ends it.
                _ = state.changed(), if !state.stopping() => continue,
                read = tokio::time::timeout_at(idle_until, self.read.read(&mut self.buf[self.end..])) => read,
            };
            match read {
                Ok(Ok(0)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "the server closed the connection",
                    ));
                }
                Ok(Ok(n)) => {
                    self.end += n;
                    last_received = Instant::now();
                    echo_sent = false;
                }
                Ok(Err(e)) => return Err(e),
                Err(_) if echo_sent => {
                    // §3.1.2.3: abort without a Call Abort.
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "nothing from the server for two hello intervals",
                    ));
                }
                Err(_) => {
                    self.send_control(packet::bare_control(message::ECHO_REQUEST))?;
                    echo_sent = true;
                    last_received = Instant::now();
                }
            }
        }
    }

    /// Handle every whole packet in the buffer.
    async fn drain(&mut self) -> io::Result<()> {
        while let Some(len) = packet::packet_len(&self.buf[self.start..self.end])? {
            if self.end - self.start < len {
                break;
            }
            let range = self.start..self.start + len;
            self.start += len;
            match packet::parse(&self.buf[range])? {
                Packet::Data(frame) => {
                    let (protocol, info) = ppp::split_frame(frame)?;
                    if protocol == ppp::protocol::IPV4 {
                        // The one allocation per inbound packet: the
                        // netstack channel carries owned packets.
                        let ip = info.to_vec();
                        if self.ip_from_tunnel.send(ip).await.is_err() {
                            return Err(io::Error::other("the netstack stopped"));
                        }
                        continue;
                    }
                    let frame = frame.to_vec();
                    for reply in self.ppp.input(&frame, Instant::now())? {
                        let mut out = Vec::with_capacity(4 + reply.len());
                        out.extend_from_slice(&packet::data_header(reply.len()));
                        out.extend_from_slice(&reply);
                        self.send_control(out)?;
                    }
                }
                Packet::Control(control) => match control.message {
                    message::ECHO_REQUEST => {
                        self.send_control(packet::bare_control(message::ECHO_RESPONSE))?;
                    }
                    message::CALL_DISCONNECT => {
                        self.send_control(packet::bare_control(message::CALL_DISCONNECT_ACK))?;
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "the server disconnected the call",
                        ));
                    }
                    message::CALL_DISCONNECT_ACK => {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "the call was disconnected",
                        ));
                    }
                    message::CALL_ABORT => {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "the server aborted the call",
                        ));
                    }
                    _ => {}
                },
            }
        }
        Ok(())
    }

    fn send_control(&self, packet: Vec<u8>) -> io::Result<()> {
        self.control.try_send(packet).map_err(|_| {
            io::Error::other("the server sent control messages faster than they could be answered")
        })
    }
}
