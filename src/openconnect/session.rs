//! An established tunnel: the data path and its upkeep.
//!
//! Two tasks beside the netstack's own (one worker per session, nothing
//! spawned per packet):
//!
//! ```text
//! netstack ──ip_to_tunnel (backpressured)──► writer ──one TLS record per frame──► TCP
//! netstack ◄─ip_from_tunnel (awaited)─────── reader ◄─frames parsed as a stream─── TCP
//!                         control (16) ────► writer (polled first)
//! ```
//!
//! Each frame goes out with its own `write`, and a burst is flushed once:
//! ocserv requires a TLS record to hold exactly one frame
//! (`worker-vpn.c:3005-3030`), and rustls encrypts each `write` into its
//! own record. The reader parses frames out of one buffer however the
//! records split them.
//!
//! Nothing between the inner TCP and the socket drops a packet: the
//! netstack refuses to emit past the outbound channel's free slots, and
//! the reader waits on a full inbound channel, which closes the server's
//! TCP window. The outer TCP is flow-controlled, so waiting is free.
//!
//! Keepalive and DPD follow `mainloop.c:454-492`: a DPD request after the
//! server's interval without receiving, repeated after half of it, and
//! the peer declared dead after two intervals; a keepalive after the
//! keepalive interval without sending. Anything received is life
//! (`cstp.c:1004`).

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use log::{debug, info, warn};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{Notify, mpsc};

use super::cstp::{self, kind};
use super::handshake::{Established, Link, TlsStream};

/// The reader's buffer: room for whole records and a straddling frame.
const READ_BUFFER: usize = 32 * 1024 + cstp::MAX_PAYLOAD + cstp::HEADER_LEN;
/// Control frames the reader queues for the writer: DPD answers. A full
/// queue means a peer sending DPD faster than one write drains it, which
/// only a broken or hostile peer does.
const CONTROL_QUEUE: usize = 16;
/// How long a stop waits for its goodbye to go out.
const STOP_WAIT: Duration = Duration::from_secs(1);
/// What the writer tells the server on a stop (`cstp.c:1237-1278`).
const BYE_REASON: &str = "user disconnect";

/// A session's liveness, shared by its tasks and the connector.
pub struct SessionState {
    dead: AtomicBool,
    stopping: AtomicBool,
    /// Rung on a stop and on a death.
    wake: Notify,
    /// Rung on a death only.
    died: Notify,
    /// When the session started: the clock the timestamps count from.
    epoch: Instant,
    /// Milliseconds since `epoch` of the last frame received, for DPD.
    last_rx: AtomicU64,
}

impl SessionState {
    fn new() -> Arc<Self> {
        Arc::new(SessionState {
            dead: AtomicBool::new(false),
            stopping: AtomicBool::new(false),
            wake: Notify::new(),
            died: Notify::new(),
            epoch: Instant::now(),
            last_rx: AtomicU64::new(0),
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

    fn received(&self) {
        let ms = self.epoch.elapsed().as_millis() as u64;
        self.last_rx.store(ms, Ordering::Release);
    }

    fn last_received(&self) -> Instant {
        self.epoch + Duration::from_millis(self.last_rx.load(Ordering::Acquire))
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
    /// A TCP connection does not survive its interface going away. End the
    /// session now rather than after two DPD intervals; the next connection
    /// reconnects with the cookie.
    fn network_changed(&self) {
        info!("OpenConnect: network changed; ending the session");
        self.kill();
    }
}

/// The halves the netstack talks to.
pub struct Channels {
    pub ip_to_tunnel: mpsc::Receiver<Vec<u8>>,
    pub ip_from_tunnel: mpsc::Sender<Vec<u8>>,
}

/// Start the reader and writer on an established tunnel.
pub fn spawn(established: Established, channels: Channels) -> Arc<SessionState> {
    let state = SessionState::new();
    state.received();
    let Established {
        stream,
        pending,
        link,
        cookies: _,
    } = established;
    let (read, write) = tokio::io::split(stream);
    let (control_tx, control_rx) = mpsc::channel(CONTROL_QUEUE);

    let writer_state = state.clone();
    let writer_link = link.clone();
    tokio::spawn(async move {
        if let Err(e) = writer(
            write,
            channels.ip_to_tunnel,
            control_rx,
            &writer_state,
            &writer_link,
        )
        .await
        {
            if writer_state.stopping() || writer_state.is_dead() {
                debug!("OpenConnect: writer ended: {e}");
            } else {
                warn!("OpenConnect: session ended: {e}");
            }
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
            link,
            ip_from_tunnel: channels.ip_from_tunnel,
            control: control_tx,
        };
        if let Err(e) = reader.run(pending, &reader_state).await {
            if reader_state.stopping() {
                debug!("OpenConnect: session stopped: {e}");
            } else {
                warn!("OpenConnect: session ended: {e}");
            }
        }
        reader_state.kill();
    });

    state
}

/// Whether the link carries a packet of this family and size.
fn carried(link: &Link, ip: &[u8]) -> bool {
    if ip.len() > usize::from(link.mtu) {
        return false;
    }
    match ip.first().map(|b| b >> 4) {
        Some(4) => link.ipv4.is_some(),
        Some(6) => link.ipv6.is_some(),
        _ => false,
    }
}

/// What the keepalive logic decides at an instant (`mainloop.c:454-492`).
#[derive(Debug, PartialEq, Eq)]
enum Upkeep {
    None,
    Keepalive,
    Dpd,
    Dead,
}

struct Timers {
    dpd: Option<Duration>,
    keepalive: Option<Duration>,
    last_tx: Instant,
    last_dpd: Option<Instant>,
}

impl Timers {
    /// The action due at `now`, given the last receipt.
    fn due(&mut self, now: Instant, last_rx: Instant) -> Upkeep {
        if let Some(dpd) = self.dpd {
            if now >= last_rx + 2 * dpd {
                return Upkeep::Dead;
            }
            let due = match self.last_dpd {
                // One is outstanding: repeat after half the period, not
                // on every tick.
                Some(sent) if sent > last_rx => sent + dpd / 2,
                _ => last_rx + dpd,
            };
            if now >= due {
                self.last_dpd = Some(now);
                return Upkeep::Dpd;
            }
        }
        if let Some(keepalive) = self.keepalive
            && now >= self.last_tx + keepalive
        {
            return Upkeep::Keepalive;
        }
        Upkeep::None
    }

    /// When to look again.
    fn next(&self, now: Instant, last_rx: Instant) -> Instant {
        let mut next = now + Duration::from_secs(3600);
        if let Some(dpd) = self.dpd {
            let due = match self.last_dpd {
                Some(sent) if sent > last_rx => sent + dpd / 2,
                _ => last_rx + dpd,
            };
            next = next.min(due).min(last_rx + 2 * dpd);
        }
        if let Some(keepalive) = self.keepalive {
            next = next.min(self.last_tx + keepalive);
        }
        next
    }
}

async fn writer(
    mut write: WriteHalf<TlsStream>,
    mut ip_to_tunnel: mpsc::Receiver<Vec<u8>>,
    mut control: mpsc::Receiver<Vec<u8>>,
    state: &SessionState,
    link: &Link,
) -> io::Result<()> {
    let mut frame = Vec::with_capacity(cstp::HEADER_LEN + usize::from(link.mtu));
    let mut timers = Timers {
        dpd: link.dpd,
        keepalive: link.keepalive,
        last_tx: Instant::now(),
        last_dpd: None,
    };
    loop {
        if state.is_dead() || state.stopping() {
            return finish(&mut write, &mut control, state).await;
        }
        let now = Instant::now();
        let last_rx = state.last_received();
        match timers.due(now, last_rx) {
            Upkeep::None => {}
            Upkeep::Dead => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "nothing from the server for two DPD intervals",
                ));
            }
            Upkeep::Dpd => {
                debug!("OpenConnect: sending a DPD request");
                write.write_all(&cstp::bare(kind::DPD_REQUEST)).await?;
                write.flush().await?;
                timers.last_tx = now;
                continue;
            }
            Upkeep::Keepalive => {
                write.write_all(&cstp::bare(kind::KEEPALIVE)).await?;
                write.flush().await?;
                timers.last_tx = now;
                continue;
            }
        }
        let wake_at = tokio::time::Instant::from_std(timers.next(now, last_rx));
        let mut wrote = false;
        tokio::select! {
            // Control first: a DPD answer must not wait behind an upload.
            biased;
            _ = state.changed() => continue,
            Some(packet) = control.recv() => {
                write.write_all(&packet).await?;
                wrote = true;
            }
            packet = ip_to_tunnel.recv() => match packet {
                Some(ip) => wrote |= write_ip(&mut write, &mut frame, &ip, link).await?,
                // The netstack is gone; so is the session.
                None => return Ok(()),
            },
            _ = tokio::time::sleep_until(wake_at) => continue,
        }
        // Everything already queued joins this flush, each frame in its
        // own record.
        loop {
            if let Ok(packet) = control.try_recv() {
                write.write_all(&packet).await?;
                wrote = true;
                continue;
            }
            match ip_to_tunnel.try_recv() {
                Ok(ip) => wrote |= write_ip(&mut write, &mut frame, &ip, link).await?,
                Err(_) => break,
            }
        }
        if wrote {
            // A write parked on a socket whose interface is gone would hold
            // this task until the kernel gave up; the session is dead by
            // then and has a successor.
            tokio::select! {
                biased;
                _ = state.changed() => return Ok(()),
                flushed = write.flush() => flushed?,
            }
            timers.last_tx = Instant::now();
        }
    }
}

/// One IP packet as one data frame, if the link carries it.
async fn write_ip(
    write: &mut WriteHalf<TlsStream>,
    frame: &mut Vec<u8>,
    ip: &[u8],
    link: &Link,
) -> io::Result<bool> {
    if !carried(link, ip) {
        debug!(
            "OpenConnect: dropping a packet the link cannot carry ({} bytes)",
            ip.len()
        );
        return Ok(false);
    }
    frame.clear();
    cstp::encode(frame, kind::DATA, ip);
    write.write_all(frame).await?;
    Ok(true)
}

/// The writer's last act: whatever the reader queued last, then, if this
/// side is the one leaving, the goodbye, and the TLS close, each under
/// [`STOP_WAIT`].
async fn finish(
    write: &mut WriteHalf<TlsStream>,
    control: &mut mpsc::Receiver<Vec<u8>>,
    state: &SessionState,
) -> io::Result<()> {
    let mut out = Vec::new();
    while let Ok(packet) = control.try_recv() {
        out.extend_from_slice(&packet);
    }
    let leaving = !state.is_dead();
    if leaving {
        out.extend_from_slice(&cstp::disconnect(BYE_REASON));
    }
    let _ = tokio::time::timeout(STOP_WAIT, async {
        if !out.is_empty() {
            write.write_all(&out).await?;
            write.flush().await?;
        }
        Ok::<(), io::Error>(())
    })
    .await;
    let _ = tokio::time::timeout(STOP_WAIT, write.shutdown()).await;
    Ok(())
}

struct Reader {
    read: ReadHalf<TlsStream>,
    buf: Box<[u8]>,
    start: usize,
    end: usize,
    link: Link,
    ip_from_tunnel: mpsc::Sender<Vec<u8>>,
    control: mpsc::Sender<Vec<u8>>,
}

impl Reader {
    async fn run(mut self, pending: Vec<u8>, state: &SessionState) -> io::Result<()> {
        self.buf[..pending.len()].copy_from_slice(&pending);
        self.end = pending.len();
        loop {
            self.drain(state).await?;
            if state.is_dead() {
                return Ok(());
            }
            if self.start > 0 {
                self.buf.copy_within(self.start..self.end, 0);
                self.end -= self.start;
                self.start = 0;
            }
            let read = tokio::select! {
                // A stop keeps reading until the goodbye is out; a death
                // ends it at once.
                _ = state.dead() => return Ok(()),
                read = self.read.read(&mut self.buf[self.end..]) => read,
            };
            match read? {
                0 => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "the server closed the connection",
                    ));
                }
                n => {
                    self.end += n;
                    state.received();
                }
            }
        }
    }

    /// Handle every whole frame in the buffer.
    async fn drain(&mut self, state: &SessionState) -> io::Result<()> {
        while let Some(len) = cstp::frame_len(&self.buf[self.start..self.end])? {
            if self.end - self.start < len {
                break;
            }
            let range = self.start..self.start + len;
            self.start += len;
            let (kind, payload) = cstp::parse(&self.buf[range]);
            match kind {
                kind::DATA => {
                    if !carried(&self.link, payload) {
                        debug!("OpenConnect: discarding a packet the link does not carry");
                        continue;
                    }
                    // The one allocation per inbound packet: the netstack
                    // channel carries owned packets.
                    if self.ip_from_tunnel.send(payload.to_vec()).await.is_err() {
                        return Err(io::Error::other("the netstack stopped"));
                    }
                }
                kind::DPD_REQUEST => {
                    // ocserv answers with the request's contents
                    // (`worker-vpn.c:2865-2868`); so does this.
                    let mut answer = Vec::with_capacity(cstp::HEADER_LEN + payload.len());
                    cstp::encode(&mut answer, kind::DPD_RESPONSE, payload);
                    self.control.try_send(answer).map_err(|_| {
                        io::Error::other("the server sent DPD faster than it could be answered")
                    })?;
                }
                kind::DPD_RESPONSE | kind::KEEPALIVE => {}
                kind::DISCONNECT => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "the server disconnected the session",
                    ));
                }
                kind::TERMINATE => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "the server is shutting down",
                    ));
                }
                kind::COMPRESSED => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "the server sent a compressed frame; no compression was negotiated",
                    ));
                }
                other => {
                    // ocserv logs and carries on (`worker-vpn.c:2995-2998`).
                    debug!("OpenConnect: ignoring a frame of type {other}");
                }
            }
            if state.is_dead() {
                return Ok(());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `mainloop.c:454-492`: a DPD after the interval, a repeat after half
    /// of it, dead after two, a keepalive after its own interval of sending
    /// nothing.
    #[test]
    fn the_timers_follow_openconnects_keepalive_action() {
        let t0 = Instant::now();
        let mut timers = Timers {
            dpd: Some(Duration::from_secs(30)),
            keepalive: Some(Duration::from_secs(20)),
            last_tx: t0,
            last_dpd: None,
        };
        assert_eq!(timers.due(t0 + Duration::from_secs(10), t0), Upkeep::None);
        assert_eq!(
            timers.next(t0 + Duration::from_secs(10), t0),
            t0 + Duration::from_secs(20)
        );
        assert_eq!(
            timers.due(t0 + Duration::from_secs(21), t0),
            Upkeep::Keepalive
        );
        timers.last_tx = t0 + Duration::from_secs(21);
        assert_eq!(timers.due(t0 + Duration::from_secs(31), t0), Upkeep::Dpd);
        // Outstanding: the repeat is due at 31 + 15.
        assert_eq!(timers.due(t0 + Duration::from_secs(40), t0), Upkeep::None);
        assert_eq!(
            timers.next(t0 + Duration::from_secs(40), t0),
            t0 + Duration::from_secs(41)
        );
        assert_eq!(timers.due(t0 + Duration::from_secs(47), t0), Upkeep::Dpd);
        assert_eq!(timers.due(t0 + Duration::from_secs(61), t0), Upkeep::Dead);
        // Something received resets DPD; the keepalive clock is the
        // sending side's, so it is reset by sending.
        let rx = t0 + Duration::from_secs(61);
        assert_eq!(
            timers.due(rx + Duration::from_secs(1), rx),
            Upkeep::Keepalive
        );
        timers.last_tx = rx;
        assert_eq!(timers.due(rx + Duration::from_secs(1), rx), Upkeep::None);
        assert_eq!(
            timers.next(rx + Duration::from_secs(1), rx),
            rx + Duration::from_secs(20)
        );
        let mut none = Timers {
            dpd: None,
            keepalive: None,
            last_tx: t0,
            last_dpd: None,
        };
        assert_eq!(none.due(t0 + Duration::from_secs(99999), t0), Upkeep::None);
    }

    #[test]
    fn only_a_carried_family_within_the_mtu_goes_out() {
        let link = Link {
            ipv4: Some((std::net::Ipv4Addr::new(10, 0, 0, 2), 32)),
            mtu: 100,
            ..Link::default()
        };
        assert!(carried(&link, &[0x45; 100]));
        assert!(!carried(&link, &[0x45; 101]));
        assert!(!carried(&link, &[0x60; 60]));
        assert!(!carried(&link, &[]));
    }
}
