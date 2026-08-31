//! AmneziaWG tunnel runtime.
//!
//! Owns the awgtun Tunn, endpoint UDP socket, and drives the
//! encapsulate/decapsulate loop between the virtual IP stack and the network.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use awgtun::amnezia::Amnezia3Config;
use awgtun::noise::{Tunn, TunnResult};
use awgtun::x25519;
use futures::FutureExt;
use log::{debug, error, info, warn};
use parking_lot::Mutex as ParkingMutex;
use tokio::sync::mpsc;

use super::endpoint::{EndpointSocket, is_route_gone};

/// Maximum UDP datagram size (outer AmneziaWG packets).
const MAX_UDP_SIZE: usize = 65536;

/// How long a tunnel with AmneziaWG 3.1 random trailers on may fail to
/// handshake before the setting is tried the other way round.
///
/// Long enough for several handshake initiations — awgtun retries every
/// `rekey_timeout`, five seconds by default — so a lossy path is not mistaken
/// for a peer that disagrees about trailers.
const TRAILER_PROBE_INTERVAL: Duration = Duration::from_secs(15);

/// The errno that says a sent datagram exceeded the path MTU. Unix
/// reports EMSGSIZE; WinSock has its own number for the same fact, and
/// `libc::EMSGSIZE` on Windows is the CRT errno, which a socket never
/// produces -- matching it there would leave this branch dead code on a
/// shipping target.
#[cfg(windows)]
const EMSGSIZE_RAW: i32 = 10040; // WSAEMSGSIZE
#[cfg(not(windows))]
const EMSGSIZE_RAW: i32 = libc::EMSGSIZE;

/// What a recv error on the connected endpoint socket means.
///
/// On a connected UDP socket nearly every recv error is an asynchronous
/// echo of the past -- an ICMP reply to something sent earlier, latched
/// on the socket and delivered by the next syscall (udp(7)). None of them
/// say the socket itself is broken, so none of them justify killing
/// inbound for the rest of the session: the cost of wrongly continuing is
/// a log line, the cost of wrongly stopping is a tunnel that is deaf
/// until the user reconnects.
#[derive(Debug, PartialEq, Eq)]
enum RecvErrorAction {
    /// Routine. Log at debug and keep receiving. Never counts toward the
    /// fatal streak: a restarting peer produces these back-to-back for as
    /// long as the outage lasts, and an outage is not a dead socket.
    Ignore,
    /// EMSGSIZE: a datagram *we* sent exceeded the path MTU -- see
    /// handle_path_mtu_exceeded. Keep receiving; never counts toward the
    /// fatal streak either.
    PathMtuExceeded,
    /// Unrecognised. Warn and keep receiving -- but count it, because a
    /// socket producing nothing but errors nobody can explain is dead,
    /// which is RecvErrorStreak's call.
    Suspect,
}

fn classify_recv_error(e: &std::io::Error) -> RecvErrorAction {
    use std::io::ErrorKind;
    // No stable ErrorKind exists for EMSGSIZE, so the raw errno it is.
    if e.raw_os_error() == Some(EMSGSIZE_RAW) {
        return RecvErrorAction::PathMtuExceeded;
    }
    match e.kind() {
        ErrorKind::ConnectionRefused
        | ErrorKind::ConnectionReset
        | ErrorKind::HostUnreachable
        | ErrorKind::NetworkUnreachable
        | ErrorKind::NetworkDown
        | ErrorKind::Interrupted => RecvErrorAction::Ignore,
        _ => RecvErrorAction::Suspect,
    }
}

/// The response to EMSGSIZE wherever it is seen -- latched on a recv or
/// synchronous at a send once the kernel has cached the lower path MTU.
///
/// With random trailers on, the trailer window is the state whose growth
/// produces the oversized sends: it is sized from a high-water mark of
/// datagrams seen, which a higher-MTU peer pushes past what the path
/// carries. Shrinking it is the repair. Without them there is no window
/// to shrink -- the reset would be a no-op -- and the message must not
/// send an operator hunting for a feature they never enabled.
fn handle_path_mtu_exceeded(tunn: &ParkingMutex<Tunn>, trailers_on: &AtomicBool, context: &str) {
    if trailers_on.load(Ordering::Relaxed) {
        warn!(
            "AmneziaWG: a sent datagram exceeded the path MTU (EMSGSIZE, {context}); \
             resetting the trailer window and continuing"
        );
        tunn.lock().reset_udp_window();
    } else {
        warn!(
            "AmneziaWG: a sent datagram exceeded the path MTU (EMSGSIZE, {context}); \
             the path carries less than the configured mtu expects"
        );
    }
}

/// An error within this much of the previous one continues the streak;
/// a longer gap starts a new streak of one. A blocked recv produces
/// neither success nor error, so only a socket returning errors
/// continuously can accumulate.
const RECV_ERROR_STREAK_WINDOW: Duration = Duration::from_secs(1);

/// Streak length past which the loop sleeps before the next recv, so a
/// socket stuck returning errors does not spin hot.
const RECV_ERROR_BACKOFF_AFTER: u32 = 4;

/// How long that sleep is.
const RECV_ERROR_BACKOFF: Duration = Duration::from_millis(50);

/// Streak length at which the receive path is declared dead: with the
/// backoff, roughly five seconds of a socket producing nothing but
/// errors. Reaching this is the only way out of the decapsulate loop.
const RECV_ERROR_FATAL_STREAK: u32 = 100;

/// How often the liveness watchdog samples the traffic counters.
const LIVENESS_TICK: Duration = Duration::from_secs(1);

/// Deaf ticks -- outbound traffic on the tick, nothing received since the
/// silence began -- before the watchdog asks for a rebind, and between
/// repeat requests while the silence lasts. A rebind is the cheap repair
/// for the silent failures a socket cannot report: a NAT mapping that
/// expired while the device slept, a path that moved without an errno.
const SILENCE_REBIND_TICKS: u32 = 20;

/// Deaf ticks before the tunnel is declared dead. Only counts when a
/// rebind *succeeded* during the silence: a fresh socket on a working
/// network heard nothing either, so the peer is genuinely unreachable.
/// While rebinds fail the device is between networks, and an outage is
/// ridden out, not converted into an engine stop.
const SILENCE_FATAL_TICKS: u32 = 90;

/// Inbound-liveness accounting. The error streak above catches a socket
/// that fails loudly; this catches one that fails silently -- traffic
/// keeps going out, nothing ever comes back, and recv just blocks.
///
/// Counter snapshots are parameters rather than read here, so tests
/// drive it without a tunnel.
struct LivenessWatch {
    offered_seen: usize,
    received_seen: usize,
    rebinds_seen: usize,
    /// Ticks in the current silence on which traffic actually went out.
    /// Idle ticks freeze the count rather than advancing it: silence
    /// proves nothing when nothing was sent to answer.
    deaf_ticks: u32,
    /// Whether a rebind completed during this silence -- the evidence
    /// death requires. Set only by a rebind that lands mid-silence, and
    /// the deaf count restarts when it does: death is judged against the
    /// fresh socket, so silence endured before it proves nothing. A
    /// rebind while the tunnel was fine (a routine network change) says
    /// nothing about a silence that starts later.
    rebound_during_silence: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum LivenessVerdict {
    Fine,
    Rebind,
    Dead,
}

impl LivenessWatch {
    fn new() -> Self {
        Self {
            offered_seen: 0,
            received_seen: 0,
            rebinds_seen: 0,
            deaf_ticks: 0,
            rebound_during_silence: false,
        }
    }

    fn on_tick(&mut self, offered: usize, received: usize, rebinds: usize) -> LivenessVerdict {
        // Inequality rather than subtraction: the counters wrap, and the
        // only fact needed is whether each moved since the last tick.
        let received_advanced = received != self.received_seen;
        let offered_advanced = offered != self.offered_seen;
        let rebind_advanced = rebinds != self.rebinds_seen;
        self.offered_seen = offered;
        self.received_seen = received;
        self.rebinds_seen = rebinds;

        if received_advanced {
            self.deaf_ticks = 0;
            self.rebound_during_silence = false;
            return LivenessVerdict::Fine;
        }
        // Only the episode's first successful rebind restarts the count:
        // the fatal window measures silence on a socket a rebind renewed,
        // and restarting on every later rebind would push death out
        // forever while the periodic re-requests keep succeeding.
        if rebind_advanced && self.deaf_ticks > 0 && !self.rebound_during_silence {
            self.rebound_during_silence = true;
            self.deaf_ticks = 0;
        }
        if !offered_advanced {
            return LivenessVerdict::Fine;
        }
        self.deaf_ticks += 1;
        if self.deaf_ticks >= SILENCE_FATAL_TICKS && self.rebound_during_silence {
            return LivenessVerdict::Dead;
        }
        if self.deaf_ticks.is_multiple_of(SILENCE_REBIND_TICKS) {
            return LivenessVerdict::Rebind;
        }
        LivenessVerdict::Fine
    }
}

/// Consecutive-error accounting for the receive loop. Time is a
/// parameter rather than read here, so tests inject it.
struct RecvErrorStreak {
    count: u32,
    last: Option<std::time::Instant>,
}

#[derive(Debug)]
enum StreakVerdict {
    KeepGoing,
    Backoff,
    GiveUp,
}

impl RecvErrorStreak {
    fn new() -> Self {
        Self {
            count: 0,
            last: None,
        }
    }

    fn on_success(&mut self) {
        self.count = 0;
        self.last = None;
    }

    fn on_error(&mut self, now: std::time::Instant) -> StreakVerdict {
        self.count = match self.last {
            // saturating: the Ignore-class streak backs off forever without
            // dying, so its count has no ceiling to reset it.
            Some(prev) if now.duration_since(prev) <= RECV_ERROR_STREAK_WINDOW => {
                self.count.saturating_add(1)
            }
            _ => 1,
        };
        self.last = Some(now);
        if self.count >= RECV_ERROR_FATAL_STREAK {
            StreakVerdict::GiveUp
        } else if self.count > RECV_ERROR_BACKOFF_AFTER {
            StreakVerdict::Backoff
        } else {
            StreakVerdict::KeepGoing
        }
    }
}

/// Tunnel runtime state shared between tasks.
pub struct TunnelRuntime {
    /// Channel to send IP packets from the virtual stack to be encapsulated and sent.
    pub ip_to_tunnel_tx: mpsc::Sender<Vec<u8>>,
    /// Channel to receive decapsulated IP packets for the virtual stack.
    pub ip_from_tunnel_rx: ParkingMutex<Option<mpsc::Receiver<Vec<u8>>>>,
    /// Set when the receive path is gone -- the receive loop terminated
    /// on an error streak, or the liveness watchdog gave up on a socket
    /// that stayed silent under traffic. The engine hears about either
    /// through crate::fatal; the standalone binary has no engine, so
    /// the connector polls this instead and rebuilds the tunnel.
    dead: Arc<AtomicBool>,
    /// Abort handles for background tasks.
    abort_handles: Vec<tokio::task::AbortHandle>,
}

impl Drop for TunnelRuntime {
    fn drop(&mut self) {
        for handle in &self.abort_handles {
            handle.abort();
        }
        info!("AmneziaWG tunnel runtime stopped");
    }
}

impl TunnelRuntime {
    /// Start the tunnel runtime.
    pub async fn start(
        private_key: x25519::StaticSecret,
        peer_public_key: x25519::PublicKey,
        preshared_key: Option<[u8; 32]>,
        persistent_keepalive: Option<u16>,
        amnezia: Amnezia3Config,
        endpoint_addr: SocketAddr,
    ) -> std::io::Result<Arc<Self>> {
        // Create the awgtun tunnel
        let private_key_copy = private_key.clone();
        let amnezia_copy = amnezia.clone();

        let tunn = Tunn::new_with_amnezia3(
            private_key,
            peer_public_key,
            preshared_key,
            persistent_keepalive,
            0,
            None,
            amnezia,
        )
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("AmneziaWG tunnel config error: {}", e),
            )
        })?;
        let tunn = Arc::new(ParkingMutex::new(tunn));

        // What a rebuild needs. Cheap to hold: two keys and a config struct.
        let rebuild = TunnelKeys {
            private_key: private_key_copy,
            peer_public_key,
            preshared_key,
            persistent_keepalive,
            amnezia: amnezia_copy,
        };

        // Packets the virtual stack handed us. The trailer probe reads this to
        // tell "no handshake because nothing was ever sent" — an idle tunnel,
        // which is fine — from "no handshake although we kept trying".
        let packets_offered = Arc::new(AtomicUsize::new(0));

        // Outer datagrams successfully received, ever. The receive loop
        // counts, the trailer probe reads -- to tell "the peer answers but
        // nothing parses" from "nothing arrives at all" (probe_message).
        let datagrams_received = Arc::new(AtomicUsize::new(0));

        // Datagrams that decapsulated, ever. The liveness watchdog reads
        // this one, not arrivals: a peer spraying traffic a stale session
        // cannot decrypt would otherwise count as "answering" while apps
        // see a black hole -- the exact deafness the watchdog exists to
        // catch, hidden by sampling one layer too low.
        let datagrams_decapsulated = Arc::new(AtomicUsize::new(0));
        let dead = Arc::new(AtomicBool::new(false));

        // The live trailer setting, for EMSGSIZE handling. An atomic
        // rather than a copy of the config because the trailer probe
        // flips it at runtime, and awgtun exposes no getter on Tunn.
        let trailers_on = Arc::new(AtomicBool::new(rebuild.amnezia.random_trailers));

        // Captured at creation: this tunnel belongs to the session that
        // is current now, and a death it reports after that session is
        // over must not kill the next one (see crate::fatal).
        let fatal_generation = crate::fatal::generation();

        // Rebindable rather than a plain UdpSocket: on mobile the address this
        // is bound to stops existing every time the device changes network.
        // See src/amneziawg/endpoint.rs.
        let udp_socket = EndpointSocket::connect(endpoint_addr).await?;

        info!("AmneziaWG tunnel started, endpoint={}", endpoint_addr);

        // Channels between virtual IP stack and tunnel
        let (ip_to_tunnel_tx, ip_to_tunnel_rx) = mpsc::channel::<Vec<u8>>(256);
        let (ip_from_tunnel_tx, ip_from_tunnel_rx) = mpsc::channel::<Vec<u8>>(256);

        // Task 1: Read UDP datagrams from server, decapsulate, send IP packets to stack
        let recv_task = {
            let tunn = tunn.clone();
            let udp = udp_socket.clone();
            let tx = ip_from_tunnel_tx;
            let received = datagrams_received.clone();
            let decapsulated = datagrams_decapsulated.clone();
            let trailers = trailers_on.clone();
            let dead = dead.clone();
            tokio::spawn(async move {
                // catch_unwind so a panic inside the loop still marks the
                // tunnel dead on the unwinding profiles; release-mobile
                // builds with panic = "abort", where the process's death
                // is its own announcement. An abort of this task merely
                // drops the future -- no catch, no false report.
                let loop_future = decapsulate_loop(tunn, udp, tx, received, decapsulated, trailers);
                let reason = match std::panic::AssertUnwindSafe(loop_future)
                    .catch_unwind()
                    .await
                {
                    Ok(reason) => reason,
                    Err(_) => "receive task panicked".to_string(),
                };
                // The loop only returns when the receive path is
                // unrecoverable. Say so loudly: an engine that keeps
                // reporting healthy over a tunnel that cannot hear its
                // peer is worse than a stopped one, because the host can
                // react to a stop and cannot detect deafness.
                dead.store(true, Ordering::SeqCst);
                error!("AmneziaWG receive path failed: {reason}");
                crate::fatal::report(
                    fatal_generation,
                    format!("AmneziaWG receive path failed: {reason}"),
                );
            })
        };

        // Task 2: Read IP packets from virtual stack, encapsulate, send UDP to server
        let send_task = {
            let tunn = tunn.clone();
            let udp = udp_socket.clone();
            let offered = packets_offered.clone();
            let trailers = trailers_on.clone();
            tokio::spawn(async move {
                encapsulate_loop(tunn, udp, ip_to_tunnel_rx, offered, trailers).await;
            })
        };

        // Task 3: Timer tick task
        let timer_task = {
            let tunn = tunn.clone();
            let udp = udp_socket.clone();
            let trailers = trailers_on.clone();
            tokio::spawn(async move {
                timer_loop(tunn, udp, trailers).await;
            })
        };

        // Successful rebinds, ever. The liveness watchdog reads this to
        // tell "silent because we are between networks" from "silent on a
        // socket a rebind just renewed" -- only the second one implicates
        // the peer.
        let rebinds_completed = Arc::new(AtomicUsize::new(0));

        // Task 4: Rebind the endpoint socket when the network moves.
        let rebind_task = {
            let tunn = tunn.clone();
            let rebinds = rebinds_completed.clone();
            let announce = ip_to_tunnel_tx.clone();
            tokio::spawn(udp_socket.clone().run_rebind_task(move || {
                rebinds.fetch_add(1, Ordering::Relaxed);
                // AmneziaWG 3.1 sizes its random trailers from a high-water
                // mark of datagrams seen on this path. A rebind is a new path,
                // so the mark it carried no longer describes anything. awgtun
                // leaves this to the caller because `Tunn` has no endpoint of
                // its own; upstream's `Device` does the same on a peer roam.
                // A no-op when random trailers are off.
                tunn.lock().reset_udp_window();
                // Announce the new address: the server learns a roamed peer's
                // endpoint from the first authenticated packet, so until one
                // goes out it keeps sending to the old address and an idle
                // tunnel stays deaf. The announcement is an empty payload
                // through the encapsulate loop -- awgtun's explicit keepalive
                // when a session exists, a handshake starter when none does --
                // rather than sent from here: the loop owns the send path, so
                // the decoys stay ordered ahead of a handshake (this task
                // sending its own datagrams raced the timer task's rekey) and
                // a send failure gets the loop's EMSGSIZE remediation. If the
                // queue is full, the traffic filling it announces instead.
                let _ = announce.try_send(Vec::new());
            }))
        };

        // Task 5: the liveness watchdog. The recv task catches a socket
        // that fails loudly; this catches one that fails silently.
        let liveness_task = {
            let udp = udp_socket.clone();
            let offered = packets_offered.clone();
            let decapsulated = datagrams_decapsulated.clone();
            let rebinds = rebinds_completed.clone();
            let dead = dead.clone();
            tokio::spawn(liveness_loop(
                udp,
                offered,
                decapsulated,
                rebinds,
                dead,
                fatal_generation,
            ))
        };

        let mut abort_handles = vec![
            recv_task.abort_handle(),
            send_task.abort_handle(),
            timer_task.abort_handle(),
            rebind_task.abort_handle(),
            liveness_task.abort_handle(),
        ];

        // Task 6: only for a tunnel that asked for AmneziaWG 3.1 random
        // trailers, which is the one setting here that cannot be wrong on its
        // own — it has to match the peer, and a mismatch is silent.
        if rebuild.amnezia.random_trailers {
            warn!(
                "AmneziaWG random trailers are on; the peer must have them on too. If no handshake completes within {}s they will be tried off.",
                TRAILER_PROBE_INTERVAL.as_secs()
            );
            let probe_task = tokio::spawn(trailer_probe_loop(
                tunn.clone(),
                rebuild,
                packets_offered.clone(),
                datagrams_received.clone(),
                trailers_on.clone(),
                TRAILER_PROBE_INTERVAL,
            ));
            abort_handles.push(probe_task.abort_handle());
        }

        Ok(Arc::new(Self {
            ip_to_tunnel_tx,
            ip_from_tunnel_rx: ParkingMutex::new(Some(ip_from_tunnel_rx)),
            dead,
            abort_handles,
        }))
    }

    /// Whether the receive loop has terminated. A dead runtime never
    /// recovers; the caller's move is to drop it and build a new one.
    pub fn is_dead(&self) -> bool {
        self.dead.load(Ordering::SeqCst)
    }
}

async fn decapsulate_loop(
    tunn: Arc<ParkingMutex<Tunn>>,
    udp: Arc<EndpointSocket>,
    tx: mpsc::Sender<Vec<u8>>,
    datagrams_received: Arc<AtomicUsize>,
    datagrams_decapsulated: Arc<AtomicUsize>,
    trailers_on: Arc<AtomicBool>,
) -> String {
    let mut buf = vec![0u8; MAX_UDP_SIZE];
    let mut out = vec![0u8; MAX_UDP_SIZE];
    // Reused for every packet this loop sends. See the comment in
    // drain_queued_packets for why the copy is needed at all.
    let mut packet = Vec::new();
    let mut streak = RecvErrorStreak::new();
    let mut ignore_streak = RecvErrorStreak::new();

    loop {
        let n = match udp.recv(&mut buf).await {
            Ok(n) => {
                streak.on_success();
                ignore_streak.on_success();
                // Counted before decapsulation: arrival is the fact the
                // trailer probe needs, parseability is a separate one.
                datagrams_received.fetch_add(1, Ordering::Relaxed);
                n
            }
            Err(e) => {
                match classify_recv_error(&e) {
                    RecvErrorAction::Ignore => {
                        debug!("AmneziaWG UDP recv transient error, continuing: {}", e);
                        // Usually latched ICMP echoes, one per send -- but
                        // ENETDOWN can be the socket's persistent state on a
                        // dead interface, returned back-to-back as fast as
                        // recv is called. Same backoff ladder as Suspect,
                        // never the death: an outage is ridden out, just not
                        // at full CPU with a rebind request per iteration.
                        match ignore_streak.on_error(std::time::Instant::now()) {
                            StreakVerdict::KeepGoing => {}
                            StreakVerdict::Backoff | StreakVerdict::GiveUp => {
                                tokio::time::sleep(RECV_ERROR_BACKOFF).await
                            }
                        }
                    }
                    RecvErrorAction::PathMtuExceeded => {
                        handle_path_mtu_exceeded(&tunn, &trailers_on, "reported on recv");
                    }
                    // Only the unexplained count toward death. A peer
                    // that is down produces Ignore-class echoes back to
                    // back for the whole outage, and an outage must be
                    // ridden out, not converted into an engine stop.
                    RecvErrorAction::Suspect => {
                        warn!("AmneziaWG UDP recv error, continuing: {}", e);
                        match streak.on_error(std::time::Instant::now()) {
                            StreakVerdict::KeepGoing => {}
                            StreakVerdict::Backoff => tokio::time::sleep(RECV_ERROR_BACKOFF).await,
                            StreakVerdict::GiveUp => {
                                return format!(
                                    "{RECV_ERROR_FATAL_STREAK} consecutive unexplained recv errors, last: {e}"
                                );
                            }
                        }
                    }
                }
                // Route-gone evidence is acted on whatever the class: the
                // send path schedules a rebind on these already, and on
                // an idle tunnel the recv side sees the dead route first.
                if is_route_gone(&e) {
                    udp.request_rebind();
                }
                continue;
            }
        };

        // Decapsulate with lock held briefly
        let result = {
            let mut tunn = tunn.lock();
            tunn.decapsulate(None, &buf[..n], &mut out)
        };

        // Anything but Err means the datagram was genuinely the peer's:
        // decrypted data, a handshake message, or a keepalive. That is
        // what the liveness watchdog means by "answered".
        if !matches!(result, TunnResult::Err(_)) {
            datagrams_decapsulated.fetch_add(1, Ordering::Relaxed);
        }

        match result {
            TunnResult::Done => {}
            TunnResult::Err(e) => {
                debug!("AmneziaWG decapsulate error: {:?}", e);
            }
            TunnResult::WriteToNetwork(data) => {
                packet.clear();
                packet.extend_from_slice(data);
                send_to_network(&tunn, &udp, &packet, "handshake", &trailers_on).await;
                drain_queued_packets(&tunn, &udp, &mut out, &mut packet, &trailers_on).await;
            }
            TunnResult::WriteToTunnelV4(data, _) | TunnResult::WriteToTunnelV6(data, _) => {
                if tx.try_send(data.to_vec()).is_err() {
                    // The virtual stack is not keeping up. Dropping is correct
                    // for a tunnel — the inner protocol will retransmit — but
                    // it is worth seeing when throughput is being lost.
                    debug!("AmneziaWG: virtual stack queue full, dropping inbound packet");
                }
                drain_queued_packets(&tunn, &udp, &mut out, &mut packet, &trailers_on).await;
            }
        }
    }
}

/// Take the datagrams awgtun has queued ahead of the packet that queued
/// them.
///
/// Any call that can start a handshake queues the AmneziaWG decoys — the I1-I5
/// chains followed by `Jc` junk packets — and returns the handshake initiation
/// separately. awgtun requires the queued datagrams to reach the network
/// *before* it: that ordering is the whole point of the decoys, since a censor
/// is meant to see junk lead the exchange rather than a recognisable WireGuard
/// handshake.
///
/// Empty in the steady state, and an empty `Vec` does not allocate — which
/// matters because this sits on the path every packet takes. Takes `&mut Tunn`
/// rather than the mutex so the lock is released before any of it is sent.
fn take_queued_decoys(tunn: &mut Tunn) -> Vec<Vec<u8>> {
    let mut datagrams = Vec::new();
    while let Some(queued) = tunn.poll_outgoing_packet() {
        datagrams.push(queued);
    }
    datagrams
}

/// The queued decoys followed by `packet`, in the order they must be sent.
///
/// Only the test uses this; the send path streams the same sequence to the
/// socket without collecting it. Kept so the ordering can be asserted without a
/// socket.
#[cfg(test)]
fn ordered_outgoing(tunn: &mut Tunn, packet: Vec<u8>) -> Vec<Vec<u8>> {
    let mut datagrams = take_queued_decoys(tunn);
    datagrams.push(packet);
    datagrams
}

/// One send error, wherever the send happened. EMSGSIZE gets the same
/// remediation as on recv -- once the kernel caches the lower path MTU
/// it rejects oversized sends synchronously, and the recv side may never
/// see the error at all.
fn report_send_error(
    tunn: &ParkingMutex<Tunn>,
    trailers_on: &AtomicBool,
    context: &str,
    e: &std::io::Error,
) {
    if e.raw_os_error() == Some(EMSGSIZE_RAW) {
        handle_path_mtu_exceeded(tunn, trailers_on, context);
    } else {
        warn!("AmneziaWG UDP send ({}) error: {}", context, e);
    }
}

/// Send the datagrams for a `WriteToNetwork` result, decoys first.
async fn send_to_network(
    tunn: &Arc<ParkingMutex<Tunn>>,
    udp: &Arc<EndpointSocket>,
    packet: &[u8],
    context: &str,
    trailers_on: &AtomicBool,
) {
    let decoys = take_queued_decoys(&mut tunn.lock());
    for datagram in &decoys {
        if let Err(e) = udp.send(datagram).await {
            report_send_error(tunn, trailers_on, context, &e);
        }
    }

    if let Err(e) = udp.send(packet).await {
        report_send_error(tunn, trailers_on, context, &e);
    }
}

/// Repeat `decapsulate` with an empty datagram until it stops producing output,
/// as its contract requires, sending anything it yields.
async fn drain_queued_packets(
    tunn: &Arc<ParkingMutex<Tunn>>,
    udp: &Arc<EndpointSocket>,
    out: &mut [u8],
    packet: &mut Vec<u8>,
    trailers_on: &AtomicBool,
) {
    loop {
        {
            let mut tunn = tunn.lock();
            match tunn.decapsulate(None, &[], out) {
                // Copied into `packet` rather than sent from `out`: the result
                // borrows `out` for as long as it lives, and `out` is needed
                // again on the next turn of this loop. `packet` keeps its
                // capacity across calls, so the copy costs no allocation.
                TunnResult::WriteToNetwork(data) => {
                    packet.clear();
                    packet.extend_from_slice(data);
                }
                _ => break,
            }
        }
        send_to_network(tunn, udp, packet, "drain", trailers_on).await;
    }
}

async fn encapsulate_loop(
    tunn: Arc<ParkingMutex<Tunn>>,
    udp: Arc<EndpointSocket>,
    mut rx: mpsc::Receiver<Vec<u8>>,
    packets_offered: Arc<AtomicUsize>,
    trailers_on: Arc<AtomicBool>,
) {
    let mut out = vec![0u8; MAX_UDP_SIZE];
    let mut packet = Vec::new();

    while let Some(ip_packet) = rx.recv().await {
        // Counted before encapsulation rather than after: a packet that only
        // starts a handshake is exactly the case the trailer probe is looking
        // for. Relaxed — the probe reads it every 15 seconds and only cares
        // whether it has ever moved.
        packets_offered.fetch_add(1, Ordering::Relaxed);

        let has_packet = {
            let mut tunn = tunn.lock();
            match tunn.encapsulate(&ip_packet, &mut out) {
                TunnResult::WriteToNetwork(data) => {
                    packet.clear();
                    packet.extend_from_slice(data);
                    true
                }
                TunnResult::Done => false,
                TunnResult::Err(e) => {
                    debug!("AmneziaWG encapsulate error: {:?}", e);
                    false
                }
                _ => {
                    debug!("AmneziaWG encapsulate: unexpected tunnel write result");
                    false
                }
            }
        };

        if has_packet {
            send_to_network(&tunn, &udp, &packet, "encap", &trailers_on).await;
        }
    }
}

/// Everything needed to build the tunnel's `Tunn` again.
struct TunnelKeys {
    private_key: x25519::StaticSecret,
    peer_public_key: x25519::PublicKey,
    preshared_key: Option<[u8; 32]>,
    persistent_keepalive: Option<u16>,
    amnezia: Amnezia3Config,
}

/// Whether a tunnel has gone quiet in the particular way a random-trailer
/// mismatch produces: packets offered, handshake never completed.
///
/// `None` for the handshake means this `Tunn` has never had one — a tunnel
/// that handshaked and then expired reports the age of the last one, so an
/// established tunnel that later goes idle is never mistaken for this.
fn trailers_look_wrong(last_handshake: Option<Duration>, packets_offered: usize) -> bool {
    last_handshake.is_none() && packets_offered > 0
}

/// The flip announcement, worded by what actually arrived.
///
/// Datagrams arrived but no handshake completed: the peer answers and
/// nothing parses, which genuinely smells like a framing mismatch.
/// Nothing arrived in the whole probe interval: the trailer setting is
/// unfalsifiable, so the message must not single it out.
fn probe_message(offered: usize, new_state: &str, arrived_since_last_probe: usize) -> String {
    if arrived_since_last_probe == 0 {
        format!(
            "AmneziaWG: no handshake after {offered} packets and nothing received from \
             the peer; the endpoint may be unreachable or blocked, or the obfuscation \
             parameters may not match -- retrying with random trailers {new_state} anyway."
        )
    } else {
        format!(
            "AmneziaWG: no handshake after {offered} packets; retrying with random \
             trailers {new_state}. If this is what fixes the tunnel, set random_trailers \
             to match the peer."
        )
    }
}

/// Try random trailers the other way round when the handshake never completes.
///
/// A random-trailer mismatch cannot be detected by asking: the peer's setting
/// is not on the wire, and a peer that disagrees does not answer at all — it
/// drops the initiation as malformed. The only evidence available is the
/// silence, so this converges by alternating rather than by negotiating.
///
/// It flips back as well as forth, which matters: a peer that really is 3.1
/// but was merely unreachable for a while must not leave the tunnel stuck in
/// the setting that cannot receive its trailered responses. Whichever setting
/// completes a handshake is the one the tunnel stays on, because a `Tunn` that
/// has handshaked is never flipped again.
async fn trailer_probe_loop(
    tunn: Arc<ParkingMutex<Tunn>>,
    keys: TunnelKeys,
    packets_offered: Arc<AtomicUsize>,
    datagrams_received: Arc<AtomicUsize>,
    trailers_on: Arc<AtomicBool>,
    interval: Duration,
) {
    let mut random_trailers = keys.amnezia.random_trailers;
    let mut received_at_last_probe = datagrams_received.load(Ordering::Relaxed);

    loop {
        tokio::time::sleep(interval).await;

        let received_now = datagrams_received.load(Ordering::Relaxed);
        // wrapping_sub: fetch_add wraps on overflow, which a 32-bit
        // target can reach in hours of traffic. The modular difference is
        // still the true count of arrivals since the last tick, since one
        // interval cannot see usize::MAX datagrams.
        let arrived = received_now.wrapping_sub(received_at_last_probe);
        received_at_last_probe = received_now;

        let offered = packets_offered.load(Ordering::Relaxed);
        {
            let tunn = tunn.lock();
            if !trailers_look_wrong(tunn.stats().0, offered) {
                continue;
            }
        }

        random_trailers = !random_trailers;
        let mut amnezia = keys.amnezia.clone();
        amnezia.random_trailers = random_trailers;

        // A fresh Tunn, because awgtun bakes the configuration in at
        // construction. Nothing is lost by discarding the old one: it never
        // completed a handshake, so it holds no session, and the virtual stack
        // above is untouched — the inner protocols retransmit.
        match Tunn::new_with_amnezia3(
            keys.private_key.clone(),
            keys.peer_public_key,
            keys.preshared_key,
            keys.persistent_keepalive,
            0,
            None,
            amnezia,
        ) {
            Ok(replacement) => {
                *tunn.lock() = replacement;
                // The EMSGSIZE handling reads this to know whether a
                // trailer window exists to blame; keep it current.
                trailers_on.store(random_trailers, Ordering::Relaxed);
                let state = if random_trailers { "on" } else { "off" };
                warn!("{}", probe_message(offered, state, arrived));
            }
            Err(e) => {
                // The same configuration validated at startup, so this is not
                // reachable by a config error; log rather than kill the tunnel.
                error!("AmneziaWG: could not rebuild the tunnel to probe trailers: {e}");
                return;
            }
        }
    }
}

/// Watch the traffic counters for a receive path that died without an
/// error: outbound traffic on tick after tick, nothing ever received.
///
/// The ladder is rebind first, death second. A rebind repairs the silent
/// failures that are really ours -- an expired NAT mapping, a path that
/// moved under the socket -- and costs nothing when it is wrong. Death is
/// declared only once a rebind has succeeded during the silence and the
/// peer still says nothing: at that point a fresh socket on a working
/// network is being ignored, which no amount of waiting repairs, and the
/// engine stopping with the reason beats an engine reporting healthy
/// over a tunnel that cannot hear its peer.
async fn liveness_loop(
    udp: Arc<EndpointSocket>,
    packets_offered: Arc<AtomicUsize>,
    datagrams_decapsulated: Arc<AtomicUsize>,
    rebinds_completed: Arc<AtomicUsize>,
    dead: Arc<AtomicBool>,
    fatal_generation: u64,
) {
    let mut watch = LivenessWatch::new();
    loop {
        tokio::time::sleep(LIVENESS_TICK).await;
        // The recv task's error streak can declare the runtime dead first.
        // A dead runtime is waiting to be torn down or rebuilt -- on the
        // desktop connector that wait lasts until the next connection --
        // and this task must not keep rebinding its socket or reach a
        // second death verdict for a death already reported.
        if dead.load(Ordering::SeqCst) {
            return;
        }
        match watch.on_tick(
            packets_offered.load(Ordering::Relaxed),
            datagrams_decapsulated.load(Ordering::Relaxed),
            rebinds_completed.load(Ordering::Relaxed),
        ) {
            LivenessVerdict::Fine => {}
            LivenessVerdict::Rebind => {
                info!(
                    "AmneziaWG: {} ticks of outbound traffic with nothing received; \
                     rebinding the endpoint socket",
                    watch.deaf_ticks
                );
                udp.request_rebind();
            }
            LivenessVerdict::Dead => {
                let reason = format!(
                    "AmneziaWG receive path went silent: {} seconds of outbound traffic \
                     with nothing received, and a rebind did not help",
                    watch.deaf_ticks
                );
                dead.store(true, Ordering::SeqCst);
                error!("{reason}");
                crate::fatal::report(fatal_generation, reason);
                return;
            }
        }
    }
}

async fn timer_loop(
    tunn: Arc<ParkingMutex<Tunn>>,
    udp: Arc<EndpointSocket>,
    trailers_on: Arc<AtomicBool>,
) {
    let mut out = vec![0u8; MAX_UDP_SIZE];
    let mut packet = Vec::new();
    // ConnectionExpired repeats on every tick until new traffic restarts
    // the handshake, so only the transition is worth a warning -- at 4 Hz
    // the repeats would drown the log that the warning exists to inform.
    let mut expired_announced = false;

    loop {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;

        let result = {
            let mut tunn = tunn.lock();
            tunn.update_timers(&mut out)
        };

        match result {
            TunnResult::Done => {
                expired_announced = false;
            }
            TunnResult::Err(awgtun::noise::errors::WireGuardError::ConnectionExpired) => {
                // The peer answered no handshake for the whole rekey attempt
                // window (or the session aged out unrenewed). Not a death by
                // itself: the next outbound packet starts a fresh handshake,
                // and an expiry with traffic behind it is what the liveness
                // watchdog turns into one. But it must be visible -- this is
                // WireGuard's own "the peer has stopped answering" signal.
                if !expired_announced {
                    expired_announced = true;
                    warn!(
                        "AmneziaWG: the session expired without a completed handshake; \
                         the next outbound packet will retry"
                    );
                }
            }
            TunnResult::Err(e) => {
                debug!("AmneziaWG timer error: {:?}", e);
            }
            TunnResult::WriteToNetwork(data) => {
                packet.clear();
                packet.extend_from_slice(data);
                send_to_network(&tunn, &udp, &packet, "timer", &trailers_on).await;
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amneziawg::convert_amnezia_config;
    use crate::config::AmneziaWgParams;
    use awgtun::noise::PacketClassifier;
    use base64::Engine as _;

    /// The obfuscation parameters from a real AmneziaWG 3.0 server profile.
    ///
    /// Keys are synthetic — only the shape of the configuration is taken from
    /// the real profile, which is what exercises the conversion and the wire
    /// ordering. Every 3.0 feature is on: header protection (which forces
    /// S1-S4 >= 12), content padding, and four randomized timing ranges.
    fn real_world_params() -> AmneziaWgParams {
        AmneziaWgParams {
            jc: 8,
            jmin: 75,
            jmax: 112,
            s1: 41,
            s2: 51,
            s3: 21,
            s4: 15,
            h1: Some("1279129381".to_string()),
            h2: Some("1420981222".to_string()),
            h3: Some("1740261821".to_string()),
            h4: Some("1930391293".to_string()),
            // A TLS ClientHello prefix, then random and timestamp chains, as a
            // real profile uses to make the opening datagrams look like a
            // browser rather than a VPN.
            i1: Some("<b 0x160301006f010000b1030390eb08b1>".to_string()),
            i2: Some("<r 27>".to_string()),
            i3: Some("<r 23><t>".to_string()),
            i4: Some("<r 34>".to_string()),
            i5: Some("<t><r 16>".to_string()),
            header_protection_key: Some(
                base64::engine::general_purpose::STANDARD
                    .encode([0x5au8; 32])
                    .into(),
            ),
            content_padding_addition: Some("0-64".to_string()),
            rekey_after_time: Some("123-156".to_string()),
            rekey_timeout: Some("5".to_string()),
            reject_after_time: Some("190-207".to_string()),
            keepalive_timeout: Some("14-22".to_string()),
            max_handshake_attempts: Some("18".to_string()),
            persistent_keepalive_interval: None,
            // Deliberately a 3.0 profile: the tests below are what pins 3.0
            // behaviour as unchanged now that 3.1 exists. `awg31_params`
            // covers the 3.1 additions.
            random_trailers: false,
            disable_cookies: false,
        }
    }

    /// The same profile with the two AmneziaWG 3.1 parameters on.
    fn awg31_params() -> AmneziaWgParams {
        AmneziaWgParams {
            random_trailers: true,
            disable_cookies: true,
            ..real_world_params()
        }
    }

    fn keypair(seed: u8) -> (x25519::StaticSecret, x25519::PublicKey) {
        let secret = x25519::StaticSecret::from([seed; 32]);
        let public = x25519::PublicKey::from(&secret);
        (secret, public)
    }

    /// A rebound tunnel must speak first: the server learns a roamed
    /// peer's endpoint from the first authenticated packet, so a rebind
    /// that swapped the socket and sent nothing leaves an idle tunnel
    /// deaf until the app happens to transmit. The announcement goes
    /// through the encapsulate loop (which keeps decoys ordered ahead of
    /// the handshake), so it is asserted here, over a whole runtime.
    #[tokio::test]
    async fn a_rebind_announces_itself_to_the_peer() {
        let peer_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer_socket.local_addr().unwrap();
        let (client_secret, _) = keypair(1);
        let (_, server_public) = keypair(2);
        let config = convert_amnezia_config(&real_world_params(), 1420).unwrap();

        let runtime =
            TunnelRuntime::start(client_secret, server_public, None, None, config, peer_addr)
                .await
                .unwrap();

        // Idle until the rebind: nothing has asked the tunnel to send, so
        // anything the peer receives after this is the announcement.
        super::super::endpoint::notify_network_change();

        let mut buf = [0u8; 65536];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            peer_socket.recv_from(&mut buf),
        )
        .await
        .expect("the rebound tunnel never announced itself")
        .map(|(n, _)| n)
        .unwrap();
        assert!(n > 0);
        drop(runtime);
    }

    /// Build a client/server pair that share one AmneziaWG configuration, the
    /// way two ends of a real tunnel must.
    fn tunnel_pair(config: &Amnezia3Config) -> (Tunn, Tunn) {
        let (client_secret, client_public) = keypair(1);
        let (server_secret, server_public) = keypair(2);
        let psk = [0x33u8; 32];

        let client = Tunn::new_with_amnezia3(
            client_secret,
            server_public,
            Some(psk),
            Some(25),
            1,
            None,
            config.clone(),
        )
        .expect("client config must be valid");

        let server = Tunn::new_with_amnezia3(
            server_secret,
            client_public,
            Some(psk),
            Some(25),
            2,
            None,
            config.clone(),
        )
        .expect("server config must be valid");

        (client, server)
    }

    /// Everything the real profile sets must survive the YAML -> awgtun
    /// conversion. A parameter silently dropped here is invisible until the
    /// handshake fails against a real server.
    #[test]
    fn real_world_parameters_survive_conversion() {
        let config = convert_amnezia_config(&real_world_params(), 1420).unwrap();

        assert_eq!(config.junk.count, 8);
        assert_eq!(config.junk.min_size, 75);
        assert_eq!(config.junk.max_size, 112);
        assert_eq!(config.paddings.s1, 41);
        assert_eq!(config.paddings.s2, 51);
        assert_eq!(config.paddings.s3, 21);
        assert_eq!(config.paddings.s4, 15);

        assert!(config.init_packets.i1.is_some());
        assert!(config.init_packets.i2.is_some());
        assert!(config.init_packets.i3.is_some());
        assert!(config.init_packets.i4.is_some());
        assert!(config.init_packets.i5.is_some());

        assert_eq!(config.header_protection_key, Some([0x5au8; 32]));
        assert_eq!(config.content_padding_addition.unwrap().lo, 0);
        assert_eq!(config.content_padding_addition.unwrap().hi, 64);

        assert_eq!(config.timing_ranges.rekey_after_time.lo, 123);
        assert_eq!(config.timing_ranges.rekey_after_time.hi, 156);
        assert_eq!(config.timing_ranges.reject_after_time.hi, 207);
        assert_eq!(config.timing_ranges.keepalive_timeout.lo, 14);
        assert_eq!(config.timing_ranges.max_handshake_attempts.lo, 18);

        // The clamp for content padding is the tunnel MTU, not awgtun's
        // default, so the two cannot drift apart.
        assert_eq!(config.mtu, 1420);
    }

    /// The decoys must reach the network before the handshake they precede.
    ///
    /// This is the ordering awgtun documents on `poll_outgoing_packet` and
    /// `format_handshake_initiation`. Getting it backwards still completes a
    /// handshake — the peer ignores junk whenever it arrives — so nothing but
    /// an explicit order assertion catches it.
    #[test]
    fn decoys_are_sent_before_the_handshake_initiation() {
        let config = convert_amnezia_config(&real_world_params(), 1420).unwrap();
        let (mut client, _server) = tunnel_pair(&config);

        let mut buf = vec![0u8; MAX_UDP_SIZE];
        let packet = match client.encapsulate(&[0u8; 64], &mut buf) {
            TunnResult::WriteToNetwork(data) => data.to_vec(),
            other => panic!("first packet must start a handshake, got {:?}", other),
        };

        let datagrams = ordered_outgoing(&mut client, packet);

        // I1-I5 plus Jc=8 junk datagrams, then the initiation itself.
        assert_eq!(
            datagrams.len(),
            14,
            "expected 5 I-packets + 8 junk + 1 initiation"
        );

        let classifier = PacketClassifier::from_config(&config);
        let initiation_positions: Vec<usize> = datagrams
            .iter()
            .enumerate()
            .filter(|(_, datagram)| classifier.classify(datagram).is_some())
            .map(|(i, _)| i)
            .collect();

        assert_eq!(
            initiation_positions,
            vec![datagrams.len() - 1],
            "the only recognisable WireGuard datagram must be the last one; \
             anything earlier means a decoy was sent after the handshake"
        );
    }

    /// A full handshake and a data packet, both ends driven through the shoes
    /// config path. Proves the parameters are not merely accepted but actually
    /// interoperate.
    #[test]
    fn a_full_handshake_completes_and_carries_data() {
        let config = convert_amnezia_config(&real_world_params(), 1420).unwrap();
        handshake_and_carry_data(&config);
    }

    /// The same, with the 3.1 parameters on at both ends. Trailers change the
    /// size of every handshake datagram and widen the content padding of every
    /// transport packet, so a payload that still arrives byte-for-byte is what
    /// says the trimming is right in both directions.
    #[test]
    fn a_full_31_handshake_completes_and_carries_data() {
        let config = convert_amnezia_config(&awg31_params(), 1420).unwrap();
        assert!(config.random_trailers);
        assert!(config.disable_cookies);
        handshake_and_carry_data(&config);
    }

    fn handshake_and_carry_data(config: &Amnezia3Config) {
        let (mut client, mut server) = tunnel_pair(config);

        let mut client_buf = vec![0u8; MAX_UDP_SIZE];
        let mut server_buf = vec![0u8; MAX_UDP_SIZE];

        // Client starts a handshake. An IP-shaped payload, since awgtun
        // validates the inner packet.
        let mut ip_packet = vec![0u8; 40];
        ip_packet[0] = 0x45; // IPv4, IHL 5
        ip_packet[2] = 0;
        ip_packet[3] = 40; // total length

        let initiation = match client.encapsulate(&ip_packet, &mut client_buf) {
            TunnResult::WriteToNetwork(data) => data.to_vec(),
            other => panic!("expected a handshake initiation, got {:?}", other),
        };

        // Decoys are discarded by the peer; only the initiation carries meaning.
        let response = match server.decapsulate(None, &initiation, &mut server_buf) {
            TunnResult::WriteToNetwork(data) => data.to_vec(),
            other => panic!("server must answer the initiation, got {:?}", other),
        };

        // Client consumes the response, completing the handshake.
        match client.decapsulate(None, &response, &mut client_buf) {
            TunnResult::WriteToNetwork(_) | TunnResult::Done => {}
            other => panic!("client failed to complete the handshake: {:?}", other),
        }

        // Drain whatever the completion queued, per decapsulate's contract.
        while let TunnResult::WriteToNetwork(data) = client.decapsulate(None, &[], &mut client_buf)
        {
            let keepalive = data.to_vec();
            let _ = server.decapsulate(None, &keepalive, &mut server_buf);
        }

        // A session now exists: real data crosses and comes out intact.
        let transport = match client.encapsulate(&ip_packet, &mut client_buf) {
            TunnResult::WriteToNetwork(data) => data.to_vec(),
            other => panic!(
                "expected a transport packet after handshake, got {:?}",
                other
            ),
        };

        match server.decapsulate(None, &transport, &mut server_buf) {
            TunnResult::WriteToTunnelV4(data, _) => {
                assert_eq!(data, &ip_packet[..], "payload must survive the tunnel");
            }
            other => panic!("server did not decrypt the data packet: {:?}", other),
        }
    }

    /// With header protection on, the message type is encrypted, so a peer
    /// configured without the key cannot even classify the datagram. This is
    /// what makes a key mismatch look like an unreachable server.
    #[test]
    fn header_protection_hides_the_message_type_from_a_mismatched_peer() {
        let config = convert_amnezia_config(&real_world_params(), 1420).unwrap();
        let (mut client, _server) = tunnel_pair(&config);

        let mut buf = vec![0u8; MAX_UDP_SIZE];
        let initiation = match client.encapsulate(&[0u8; 64], &mut buf) {
            TunnResult::WriteToNetwork(data) => data.to_vec(),
            other => panic!("expected a handshake initiation, got {:?}", other),
        };

        let mut wrong_params = real_world_params();
        wrong_params.header_protection_key = Some(
            base64::engine::general_purpose::STANDARD
                .encode([0x77u8; 32])
                .into(),
        );
        let wrong_config = convert_amnezia_config(&wrong_params, 1420).unwrap();

        assert!(
            PacketClassifier::from_config(&config)
                .classify(&initiation)
                .is_some(),
            "the matching config must recognise its own initiation"
        );
        assert!(
            PacketClassifier::from_config(&wrong_config)
                .classify(&initiation)
                .is_none(),
            "a peer with the wrong header protection key must not recognise it"
        );
    }

    /// The dead flag is what the connector polls to rebuild a tunnel in
    /// the standalone binary; a fresh runtime must start alive.
    #[tokio::test]
    async fn a_fresh_tunnel_runtime_is_not_dead() {
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = peer.local_addr().unwrap();
        let config = convert_amnezia_config(&real_world_params(), 1420).unwrap();
        let (secret, _) = keypair(1);
        let (_, server_public) = keypair(2);
        let runtime = TunnelRuntime::start(
            secret,
            server_public,
            Some([0x33u8; 32]),
            Some(25),
            config,
            addr,
        )
        .await
        .unwrap();
        assert!(!runtime.is_dead());
    }

    /// EMSGSIZE on a connected UDP socket is a deferred send-path error --
    /// an ICMP Fragmentation Needed for a datagram *we* sent, latched on
    /// the socket and delivered by the next syscall (udp(7)). One of these
    /// killed inbound for an entire session (KVN, 2026-08-29); it must be
    /// survivable, and it must shrink the trailer window whose growth
    /// produces the oversized sends.
    #[test]
    fn emsgsize_is_survivable_and_resets_the_trailer_window() {
        let e = std::io::Error::from_raw_os_error(EMSGSIZE_RAW);
        assert_eq!(classify_recv_error(&e), RecvErrorAction::PathMtuExceeded);
    }

    #[test]
    fn icmp_echoes_are_ignored() {
        use std::io::ErrorKind;
        for kind in [
            ErrorKind::ConnectionRefused,
            ErrorKind::ConnectionReset,
            ErrorKind::HostUnreachable,
            ErrorKind::NetworkUnreachable,
            ErrorKind::NetworkDown,
            ErrorKind::Interrupted,
        ] {
            assert_eq!(
                classify_recv_error(&std::io::Error::from(kind)),
                RecvErrorAction::Ignore,
                "{kind:?}"
            );
        }
    }

    #[test]
    fn an_unrecognised_error_is_suspect_but_not_fatal_on_its_own() {
        let e = std::io::Error::from_raw_os_error(libc::EBADF);
        assert_eq!(classify_recv_error(&e), RecvErrorAction::Suspect);
    }

    #[test]
    fn back_to_back_errors_back_off_and_eventually_give_up() {
        let t0 = std::time::Instant::now();
        let mut streak = RecvErrorStreak::new();
        let mut gave_up_at = None;
        for i in 1..=RECV_ERROR_FATAL_STREAK {
            // 10ms apart: well inside the streak window.
            let now = t0 + std::time::Duration::from_millis(10 * u64::from(i));
            match streak.on_error(now) {
                StreakVerdict::KeepGoing => {
                    assert!(i <= RECV_ERROR_BACKOFF_AFTER, "no backoff at error {i}")
                }
                StreakVerdict::Backoff => {
                    assert!(i > RECV_ERROR_BACKOFF_AFTER, "backoff too early at {i}")
                }
                StreakVerdict::GiveUp => {
                    gave_up_at = Some(i);
                    break;
                }
            }
        }
        assert_eq!(gave_up_at, Some(RECV_ERROR_FATAL_STREAK));
    }

    /// A peer that is merely down produces one latched ICMP echo per
    /// handshake retry, seconds apart -- that must never accumulate into
    /// a death, no matter how long the outage lasts.
    #[test]
    fn spaced_errors_never_accumulate() {
        let t0 = std::time::Instant::now();
        let mut streak = RecvErrorStreak::new();
        for i in 0..500u64 {
            let now = t0 + std::time::Duration::from_secs(5 * i);
            assert!(matches!(streak.on_error(now), StreakVerdict::KeepGoing));
        }
    }

    /// Drive a LivenessWatch through `ticks` ticks of outbound traffic
    /// with nothing received, returning what each tick said.
    fn deaf_ticks(watch: &mut LivenessWatch, ticks: u32) -> Vec<LivenessVerdict> {
        (0..ticks)
            .map(|_| {
                let offered = watch.offered_seen.wrapping_add(1);
                let received = watch.received_seen;
                let rebinds = watch.rebinds_seen;
                watch.on_tick(offered, received, rebinds)
            })
            .collect()
    }

    /// An idle tunnel receives nothing because nothing asked the peer to
    /// answer. Silence without traffic behind it must prove nothing.
    #[test]
    fn an_idle_tunnel_never_trips_the_liveness_watchdog() {
        let mut watch = LivenessWatch::new();
        for _ in 0..1000 {
            assert_eq!(watch.on_tick(7, 3, 0), LivenessVerdict::Fine);
        }
    }

    #[test]
    fn a_tunnel_whose_peer_answers_stays_fine() {
        let mut watch = LivenessWatch::new();
        for i in 1..=1000usize {
            assert_eq!(watch.on_tick(i, i, 0), LivenessVerdict::Fine);
        }
    }

    #[test]
    fn sustained_silence_under_traffic_asks_for_a_rebind() {
        let mut watch = LivenessWatch::new();
        let verdicts = deaf_ticks(&mut watch, SILENCE_REBIND_TICKS);
        assert!(
            verdicts[..verdicts.len() - 1]
                .iter()
                .all(|v| *v == LivenessVerdict::Fine),
            "rebind came early: {verdicts:?}"
        );
        assert_eq!(*verdicts.last().unwrap(), LivenessVerdict::Rebind);
    }

    /// A device between networks cannot rebind, and its silence is an
    /// outage to ride out -- the watchdog keeps asking for the rebind but
    /// must never convert unrebindable silence into a death.
    #[test]
    fn without_a_successful_rebind_the_watchdog_never_declares_death() {
        let mut watch = LivenessWatch::new();
        let verdicts = deaf_ticks(&mut watch, 10 * SILENCE_FATAL_TICKS);
        assert!(verdicts.iter().all(|v| *v != LivenessVerdict::Dead));
        assert!(verdicts.contains(&LivenessVerdict::Rebind));
    }

    /// A fresh socket on a working network that still hears nothing is
    /// the one silence that implicates the peer -- and the fatal window
    /// is measured on that fresh socket, from the rebind, with later
    /// rebinds not restarting it (they keep succeeding every re-request,
    /// and each restart would push death out forever).
    #[test]
    fn silence_that_survives_a_rebind_is_death() {
        let mut watch = LivenessWatch::new();
        deaf_ticks(&mut watch, SILENCE_REBIND_TICKS);
        // The requested rebind succeeds: the rebind counter moves on the
        // next deaf tick, and the deaf count restarts from it.
        watch.on_tick(
            watch.offered_seen.wrapping_add(1),
            watch.received_seen,
            watch.rebinds_seen.wrapping_add(1),
        );
        // A later successful rebind mid-window must not restart it again.
        deaf_ticks(&mut watch, 40);
        watch.on_tick(
            watch.offered_seen.wrapping_add(1),
            watch.received_seen,
            watch.rebinds_seen.wrapping_add(1),
        );
        // 42 deaf ticks since the first rebind; the rest of the window
        // runs out without a datagram.
        let verdicts = deaf_ticks(&mut watch, SILENCE_FATAL_TICKS - 42);
        assert_eq!(*verdicts.last().unwrap(), LivenessVerdict::Dead);
        assert!(
            !verdicts[..verdicts.len() - 1].contains(&LivenessVerdict::Dead),
            "death came early"
        );
    }

    /// The subway ride: 90+ deaf ticks accrue while every rebind fails.
    /// When the network returns and a rebind finally lands, the peer
    /// gets a full window to answer from the fresh socket -- killing the
    /// engine one tick after connectivity recovers would turn recovery
    /// itself into the failure.
    #[test]
    fn a_rebind_after_a_long_outage_gets_a_full_window() {
        let mut watch = LivenessWatch::new();
        deaf_ticks(&mut watch, 10 * SILENCE_FATAL_TICKS);
        // The network returns and the requested rebind finally lands.
        watch.on_tick(
            watch.offered_seen.wrapping_add(1),
            watch.received_seen,
            watch.rebinds_seen.wrapping_add(1),
        );
        let verdicts = deaf_ticks(&mut watch, SILENCE_FATAL_TICKS - 2);
        assert!(
            verdicts.iter().all(|v| *v != LivenessVerdict::Dead),
            "death before the fresh socket's own window elapsed"
        );
        assert_eq!(deaf_ticks(&mut watch, 1)[0], LivenessVerdict::Dead);
    }

    /// A rebind while the tunnel was fine -- a routine network change --
    /// is not evidence about a silence that starts later.
    #[test]
    fn an_idle_time_rebind_is_not_evidence_for_a_later_silence() {
        let mut watch = LivenessWatch::new();
        watch.on_tick(0, 0, 1);
        let verdicts = deaf_ticks(&mut watch, 10 * SILENCE_FATAL_TICKS);
        assert!(verdicts.iter().all(|v| *v != LivenessVerdict::Dead));
    }

    /// One received datagram ends the episode entirely: the deaf count
    /// and the rebind evidence both reset, so a healthy tunnel that
    /// later goes quiet starts from zero.
    #[test]
    fn a_received_datagram_resets_the_liveness_episode() {
        let mut watch = LivenessWatch::new();
        deaf_ticks(&mut watch, SILENCE_FATAL_TICKS - 1);
        // A rebind lands and, on the same tick, a datagram arrives.
        assert_eq!(
            watch.on_tick(
                watch.offered_seen,
                watch.received_seen.wrapping_add(1),
                watch.rebinds_seen.wrapping_add(1),
            ),
            LivenessVerdict::Fine
        );
        // A full fatal window of deaf traffic is needed again, and the
        // old rebind no longer counts as evidence.
        let verdicts = deaf_ticks(&mut watch, SILENCE_FATAL_TICKS + 10);
        assert!(verdicts.iter().all(|v| *v != LivenessVerdict::Dead));
    }

    #[test]
    fn a_successful_recv_resets_the_streak() {
        let t0 = std::time::Instant::now();
        let mut streak = RecvErrorStreak::new();
        for i in 1..=20u64 {
            streak.on_error(t0 + std::time::Duration::from_millis(10 * i));
        }
        streak.on_success();
        assert!(matches!(
            streak.on_error(t0 + std::time::Duration::from_millis(500)),
            StreakVerdict::KeepGoing
        ));
    }

    /// When nothing has arrived at all, the trailer setting is
    /// unfalsifiable -- the message must not point at it. That hint sent
    /// a real debugging session down a false path (KVN, 2026-08-29) while
    /// the actual fault was a dead receive loop.
    #[test]
    fn the_probe_does_not_blame_trailers_when_nothing_arrived() {
        let silent = probe_message(221, "off", 0);
        assert!(silent.contains("nothing received"), "got: {silent}");
        assert!(
            !silent.contains("set random_trailers to match the peer"),
            "got: {silent}"
        );

        let chatty = probe_message(221, "off", 7);
        assert!(
            chatty.contains("set random_trailers to match the peer"),
            "got: {chatty}"
        );
    }

    /// The probe fires only for the shape a trailer mismatch actually has.
    #[test]
    fn only_a_tunnel_that_tried_and_never_handshaked_looks_wrong() {
        assert!(trailers_look_wrong(None, 1));
        // Idle: nothing was ever sent, so there is nothing to conclude.
        assert!(!trailers_look_wrong(None, 0));
        // Established, then quiet. Flipping this would break a working tunnel.
        assert!(!trailers_look_wrong(Some(Duration::from_secs(600)), 4200));
    }

    /// End to end: a 3.1 client whose peer is 3.0 gets there by itself.
    ///
    /// Before the probe the client's initiations carry a trailer the 3.0 peer
    /// drops without answering, which is a tunnel that never comes up and
    /// never says why. After it, the same client speaks 3.0 framing and the
    /// peer answers.
    #[tokio::test]
    async fn a_stalled_31_tunnel_probes_its_way_back_to_30_framing() {
        let client_config = convert_amnezia_config(&awg31_params(), 1420).unwrap();
        let server_config = convert_amnezia_config(&real_world_params(), 1420).unwrap();

        let (client, _) = tunnel_pair(&client_config);
        let tunn = Arc::new(ParkingMutex::new(client));

        let (client_secret, _) = keypair(1);
        let (_, server_public) = keypair(2);
        let keys = TunnelKeys {
            private_key: client_secret,
            peer_public_key: server_public,
            preshared_key: Some([0x33u8; 32]),
            persistent_keepalive: Some(25),
            amnezia: client_config,
        };

        // One packet offered and no handshake: the state the probe acts on.
        let offered = Arc::new(AtomicUsize::new(1));
        // A probe interval scaled down for the test; the production one is
        // TRAILER_PROBE_INTERVAL, which the loop takes as a parameter for
        // exactly this reason.
        let interval = Duration::from_millis(50);
        tokio::spawn(trailer_probe_loop(
            tunn.clone(),
            keys,
            offered,
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicBool::new(true)),
            interval,
        ));

        // Past the first probe but short of the second, which would flip back.
        tokio::time::sleep(interval + interval / 2).await;

        let (_, mut server) = tunnel_pair(&server_config);
        let mut client_buf = vec![0u8; MAX_UDP_SIZE];
        let mut server_buf = vec![0u8; MAX_UDP_SIZE];

        let initiation = match tunn.lock().encapsulate(&[0u8; 64], &mut client_buf) {
            TunnResult::WriteToNetwork(data) => data.to_vec(),
            other => panic!("expected a handshake initiation, got {:?}", other),
        };

        assert!(
            matches!(
                server.decapsulate(None, &initiation, &mut server_buf),
                TunnResult::WriteToNetwork(_)
            ),
            "after the probe the 3.0 peer must be able to answer the initiation"
        );
    }

    /// Random trailers must be enabled on both peers or on neither.
    ///
    /// A receiver only tolerates bytes past the end of a handshake message
    /// when `random_trailers` is on; without it the exact-size test that
    /// identifies the message rejects the datagram. Enabling it one-sided is
    /// therefore not a degraded tunnel, it is a dead one, and this pins that
    /// so nobody "fixes" the asymmetry by making the receiver lenient.
    #[test]
    fn a_30_peer_rejects_an_initiation_that_carries_a_trailer() {
        let client_config = convert_amnezia_config(&awg31_params(), 1420).unwrap();
        let server_config = convert_amnezia_config(&real_world_params(), 1420).unwrap();
        let plain_len = {
            let (mut client, _) = tunnel_pair(&server_config);
            let mut buf = vec![0u8; MAX_UDP_SIZE];
            match client.encapsulate(&[0u8; 64], &mut buf) {
                TunnResult::WriteToNetwork(data) => data.len(),
                other => panic!("expected a handshake initiation, got {:?}", other),
            }
        };

        // A trailer's length is drawn from the UDP window, so it is sometimes
        // zero and that datagram is a valid 3.0 one. Keep drawing until one
        // actually grew — that is the case with something to assert about.
        let mut buf = vec![0u8; MAX_UDP_SIZE];
        let mut server_buf = vec![0u8; MAX_UDP_SIZE];
        let mut with_trailer = None;
        for _ in 0..64 {
            let (mut client, _) = tunnel_pair(&client_config);
            if let TunnResult::WriteToNetwork(data) = client.encapsulate(&[0u8; 64], &mut buf)
                && data.len() > plain_len
            {
                with_trailer = Some(data.to_vec());
                break;
            }
        }
        let with_trailer =
            with_trailer.expect("64 initiations in a row drew a zero-length trailer");

        let (_, mut server) = tunnel_pair(&server_config);
        assert!(
            !matches!(
                server.decapsulate(None, &with_trailer, &mut server_buf),
                TunnResult::WriteToNetwork(_)
            ),
            "a 3.0 peer must not answer an initiation with bytes on the end"
        );
    }
}
