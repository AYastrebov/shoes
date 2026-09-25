//! The platform-neutral half of the TUN TCP stack.
//!
//! The smoltcp loop — batching, packet classification, socket servicing, the
//! dead-device backstop — is the same on every platform. What differs is how
//! packets are read and written and how the thread sleeps: a file descriptor
//! with `poll()` on Unix, a wintun ring-buffer session with event handles on
//! Windows. [`StackDevice`] is that seam, and [`run_stack_loop`] is the loop,
//! moved here verbatim from `tcp_stack_direct.rs` so both backends share it.

use std::{
    collections::HashMap,
    io, mem,
    net::SocketAddr,
    ops::{Deref, DerefMut},
    panic::{self, AssertUnwindSafe},
    sync::{
        Arc, LazyLock, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use bytes::BytesMut;

use log::{debug, error, info, trace, warn};
use smoltcp::{
    iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet},
    phy::Device,
    socket::tcp::{
        CongestionControl, Socket as TcpSocket, SocketBuffer as TcpSocketBuffer, State as TcpState,
    },
    time::Duration as SmolDuration,
    wire::{
        HardwareAddress, IpAddress, IpCidr, IpProtocol, Ipv4Address, Ipv4Packet, Ipv6Address,
        Ipv6Packet, TcpPacket,
    },
};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::util::smol_now;

use super::tcp_conn::{TcpConnection, TcpConnectionControl, TcpSocketState};

pub type PacketBuffer = Vec<u8>;

/// Wakes the stack thread out of its idle wait, so a UDP response queued by
/// tokio is written now rather than when the wait next times out.
///
/// Without this, a reply to a quiet tunnel sat until [`MAX_POLL_WAIT_MILLIS`]
/// expired — measured at ~500 ms on every cold DNS lookup, against the
/// microseconds the Fake IP responder takes to produce the answer. Each
/// backend supplies its own: a byte down the wake pipe on Unix, an event set
/// on Windows.
pub type StackWaker = Arc<dyn Fn() + Send + Sync>;

/// The one way anything off the stack thread gets its attention.
///
/// The stack thread sleeps inside the platform wait — `poll()` on Unix,
/// `WaitForMultipleObjects` on Windows — and only the device becoming
/// readable, the backend's wake primitive, or the timeout gets it out. The
/// TCP side used to reach for `Thread::unpark`, which does none of those: it
/// sets a flag the next `thread::park()` would observe, and this thread never
/// parks. So a segment written by tokio, a receive buffer drained by tokio, a
/// connection dropped by tokio, and a new-connection channel being wired all
/// sat until the next packet arrived or the loop's timer tick fired. The loop
/// capped that tick at 10 ms to keep the latency bearable, which cost a wakeup
/// every 10 ms for as long as any socket was open — on a phone with the screen
/// off as much as anywhere.
///
/// This routes every such event through the backend's real wake primitive,
/// and uses it — a syscall — only when the thread is actually asleep. `armed`
/// is set by the stack thread just before it sleeps and cleared when it wakes;
/// `pending` records that something happened while it was awake, so it skips
/// the coming sleep rather than being woken from it. Both are sequentially
/// consistent on purpose: the proof that no wakeup is lost is Dekker's — of
/// the notifier's `pending` store and the thread's `armed` store, one is
/// visible to the other side's load, so either the notifier fires the wake or
/// the thread declines to sleep. That argument needs a single total order.
///
/// sing-tun's engine is the same shape (`stack_go_engine.go`: `postMessage`
/// pushes a lock-free node and writes an eventfd only while the engine is
/// parked; `park` clears it). smoltcp does the socket work here, so this wraps
/// the existing per-backend wake pipe / event rather than an eventfd, but the
/// arm/pending handshake is the part worth copying.
pub struct StackNotifier {
    /// Something changed since the stack thread last looked.
    pending: AtomicBool,
    /// The stack thread is asleep, or about to be, and nobody has woken it.
    armed: AtomicBool,
    /// The backend's real wake primitive: the Unix wake-pipe write, the
    /// Windows `SetEvent`. Called only when `armed`.
    wake: StackWaker,
}

impl StackNotifier {
    pub fn new(wake: StackWaker) -> Arc<Self> {
        Arc::new(Self {
            pending: AtomicBool::new(false),
            armed: AtomicBool::new(false),
            wake,
        })
    }

    /// Ask the stack thread to run an iteration. Two atomics and no syscall
    /// when it is awake; a single wake when it is asleep, however many callers
    /// arrive before it gets up.
    pub fn notify(&self) {
        self.pending.store(true, Ordering::SeqCst);
        // Swap rather than a plain load-then-store: only the caller that flips
        // `armed` from true fires the wake, so two racing notifiers do not
        // both write the pipe.
        if self.armed.swap(false, Ordering::SeqCst) {
            (self.wake)();
        }
    }

    /// Stack thread only: declare that a sleep is next. Returns true when
    /// something is already pending, in which case the caller must not sleep.
    fn arm(&self) -> bool {
        self.armed.store(true, Ordering::SeqCst);
        if self.pending.swap(false, Ordering::SeqCst) {
            // A notify that landed before this arm may or may not have seen
            // `armed` set; clear it ourselves so its wake, if it fired, is the
            // harmless spurious kind rather than a lost one.
            self.armed.store(false, Ordering::SeqCst);
            true
        } else {
            false
        }
    }

    /// Stack thread only: back from the sleep, however it ended. Also drains
    /// the `pending` flag, since the thread is about to do a full iteration
    /// that covers whatever set it.
    fn disarm(&self) {
        self.armed.store(false, Ordering::SeqCst);
        self.pending.store(false, Ordering::SeqCst);
    }

    /// Test only: read and clear the `pending` flag, so a test can assert that
    /// a caller (a `TcpConnection` write, read-drain or drop) reached `notify`.
    /// With the notifier never armed, `notify` sets `pending` without firing
    /// the wake, which this observes.
    #[cfg(test)]
    pub(crate) fn take_pending(&self) -> bool {
        self.pending.swap(false, Ordering::SeqCst)
    }
}

/// Maximum number of read buffers cached globally.
///
/// Each holds one MTU plus the four-byte packet-information header, so the pool
/// retains 64 * (mtu + 4): about 576 KiB at Android's 9000-byte default and
/// 260 KiB at iOS's 4064. It is cleared when a tunnel stops, since a mobile app
/// outlives its tunnel and has no use for the memory in between.
const BUFFER_POOL_MAX_SIZE: usize = 64;

static BUFFER_POOL: LazyLock<Mutex<Vec<BytesMut>>> = LazyLock::new(|| Mutex::new(Vec::new()));

/// Pooled buffer that returns to pool on drop instead of deallocating.
pub struct PooledBuffer {
    buffer: BytesMut,
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        if let Ok(mut pool) = BUFFER_POOL.lock()
            && pool.len() < BUFFER_POOL_MAX_SIZE
        {
            let empty = BytesMut::new();
            let mut buffer = mem::replace(&mut self.buffer, empty);
            buffer.clear();
            pool.push(buffer);
        }
    }
}

/// Drop every buffer the pool is holding.
///
/// Called when a tunnel stops. The pool exists to keep the read path from
/// allocating per packet, which is worth a few hundred kilobytes while a tunnel
/// runs and nothing at all once it has stopped.
pub fn clear_buffer_pool() {
    if let Ok(mut pool) = BUFFER_POOL.lock() {
        pool.clear();
        pool.shrink_to_fit();
    }
}

impl PooledBuffer {
    /// Get a buffer from the pool or create a new one.
    pub fn with_capacity(cap: usize) -> Self {
        if let Ok(mut pool) = BUFFER_POOL.lock()
            && let Some(mut buffer) = pool.pop()
        {
            buffer.reserve(cap);
            return Self { buffer };
        }
        Self {
            buffer: BytesMut::with_capacity(cap),
        }
    }
}

impl Deref for PooledBuffer {
    type Target = BytesMut;

    fn deref(&self) -> &Self::Target {
        &self.buffer
    }
}

impl DerefMut for PooledBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buffer
    }
}

/// Tracks socket info including addresses for proper cleanup.
struct SocketInfo {
    control: Arc<TcpConnectionControl>,
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    /// When the app hung up on this connection (its `TcpConnection` was
    /// dropped), if it has. From then on the peer has `orphan_timeout` to
    /// close its side before the socket is reset: see the sweep.
    orphaned_since: Option<std::time::Instant>,
}

/// Information about a new TCP connection from the stack.
pub struct NewTcpConnection {
    pub connection: TcpConnection,
    pub remote_addr: SocketAddr,
    /// The address inside the tunnel that opened it. Known here from the
    /// SYN, and carried out so a connection can say who it belongs to.
    pub local_addr: SocketAddr,
}

/// Shared state for communication between main thread and stack thread.
pub struct SharedState {
    /// Channel for UDP responses to write to TUN. Bounded, with
    /// drop-on-full at the sender: a stalled stack thread must shed
    /// datagrams, not queue them without limit.
    pub udp_response_rx: Option<tokio::sync::mpsc::Receiver<PacketBuffer>>,
    /// Channel for notifying tokio about new TCP connections
    pub new_conn_tx: Option<UnboundedSender<NewTcpConnection>>,
}

pub const MAX_PACKET_BATCH: usize = 64; // Process more packets per poll iteration

/// Datagrams queued on each hop of the UDP response pipeline (destination
/// task -> session manager -> stack thread). One constant for both hops,
/// so tuning one cannot silently leave the other as the bottleneck.
///
/// Sizing honestly: entries come from a destination task's 64 KiB read
/// buffer over stream transports, which are not MTU-clamped, so the worst
/// case per queue is ~32 MiB -- not "a few megabytes". In practice
/// entries are MTU-sized and a full queue is a few hundred KiB; the
/// bound exists for the stalled-consumer case, where drop-on-full is the
/// right answer for datagrams either way.
pub const UDP_RESPONSE_QUEUE: usize = 512;

/// How the stack thread is sized and who owns its descriptor.
#[derive(Clone, Copy, Debug)]
pub struct TcpStackOptions {
    /// Maximum transmission unit of the TUN device.
    pub mtu: usize,
    /// Bytes per direction, per connection. Four buffers of this size are
    /// allocated when a connection is accepted: two smoltcp socket buffers and
    /// the two ring buffers in `TcpConnectionControl`.
    pub tcp_buffer_size: usize,
    /// Connections the stack will hold before it starts dropping SYNs.
    pub max_connections: usize,
    /// Whether the TUN descriptor is ours to close. Read by the Unix
    /// backend's constructor; on Windows the session is structurally ours, so
    /// nothing reads it there — a property of the platform split, not
    /// something a later change will fix.
    #[cfg_attr(windows, allow(dead_code))]
    pub close_fd_on_drop: bool,
    /// Whether the device frames every packet with utun's 4-byte address
    /// family header. True on macOS and iOS, where utun is the only TUN and
    /// the kernel always frames; false everywhere else. Read by the Unix
    /// backend, which strips the header on the way in and prepends it on the
    /// way out; the Windows session has no such header, so nothing reads it
    /// there.
    #[cfg_attr(windows, allow(dead_code))]
    pub utun_header: bool,
    /// How long a connection the app has dropped may wait for the peer to
    /// close its side before it is reset. smoltcp has no FIN-WAIT-2 timer,
    /// and a peer that answers keepalives keeps the idle timeout from ever
    /// firing, so without this a dropped connection whose peer never closes
    /// holds its four buffers for as long as the peer likes. Linux's
    /// `tcp_fin_timeout` is 60 s.
    pub orphan_timeout: Duration,
}

/// Longest the stack thread sleeps with nothing to do.
///
/// A descriptor closed underneath a blocked `poll()` does not wake it — the
/// platform is under no obligation to, and macOS does not — so an idle stack
/// on a device whose TUN was torn down would sit there until a packet that is
/// never coming arrives. One wakeup a second bounds that, and is nothing
/// against what a tunnel does when it is carrying anything at all.
pub const MAX_POLL_WAIT_MILLIS: u64 = 1000;

/// What the shared stack loop needs from a platform device, beyond smoltcp's
/// [`Device`] (which supplies the RxToken/TxToken pair).
pub trait StackDevice: Device {
    /// Non-blocking read of one packet into a pooled buffer.
    ///
    /// `Ok(None)` means nothing is available right now; `Err` means the
    /// device is gone and the loop must stop.
    fn try_recv(&mut self) -> io::Result<Option<PooledBuffer>>;

    /// Queue a packet for smoltcp, behind any already queued.
    ///
    /// A queue rather than one slot: the loop reads a whole batch off the
    /// device, hands it all over, then polls once. `Interface::poll` drains
    /// everything `receive` offers before it runs egress, so a batch of N
    /// packets costs one egress sweep over the sockets instead of N. The old
    /// shape polled after every stored packet, which with a page load's worth
    /// of connections open was most of what the thread did. This mirrors
    /// sing-tun's `processBurst` (read up to a batch, then one flush).
    fn store_packet(&mut self, pkt: PooledBuffer);

    /// Whether any queued packet is still waiting to be polled.
    fn has_pending(&self) -> bool;

    /// Write one packet, dropping it (and returning `Ok`) when the device
    /// queue is full — for a UDP-shaped device that is what a full socket
    /// buffer does too.
    fn write_packet(&self, data: &[u8]) -> io::Result<()>;

    /// Sleep until the device is readable, the backend's shutdown signal
    /// fires, or `duration` elapses. `None` waits [`MAX_POLL_WAIT_MILLIS`].
    fn wait(&self, duration: Option<SmolDuration>) -> io::Result<()>;
}

/// The platform-neutral half of a stack manager: the thread, the running
/// flag, and the channels. Each backend embeds one and adds only its device
/// state and its wake primitive — the pipe byte on Unix, the session
/// shutdown event on Windows.
///
/// Shared so that a fix to this surface cannot land on one platform and be
/// silently absent from the other: only one backend compiles per platform,
/// so duplicated copies would drift with no test able to notice.
pub struct StackHandle {
    /// Handle to the stack thread
    thread_handle: Option<thread::JoinHandle<()>>,
    /// How anything off the stack thread wakes it: sets a flag and, only when
    /// the thread is parked, fires the backend's wake primitive.
    notifier: Arc<StackNotifier>,
    /// Flag to signal thread shutdown
    running: Arc<AtomicBool>,
    /// Receiver for UDP packets (filtered from TUN by the stack thread)
    udp_rx: Option<UnboundedReceiver<PacketBuffer>>,
    /// Shared state with the stack thread
    shared_state: Arc<Mutex<SharedState>>,
}

impl StackHandle {
    /// Spawn `thread_name` running the guarded stack loop over the device
    /// `make_device` builds — on the stack thread itself, so a device whose
    /// handles are not `Send` (raw Windows event handles) never crosses a
    /// thread boundary.
    ///
    /// `wake` is the backend's primitive for getting that thread out of its
    /// wait — the Unix wake-pipe write, the Windows `SetEvent` — and the
    /// [`StackNotifier`] built around it is what the device's `wait` must also
    /// select on, so a `notify` actually interrupts the sleep.
    ///
    /// Fallible: `thread::spawn` fails with EAGAIN under thread or
    /// memory pressure -- plausible inside a Network Extension's memory
    /// cap -- and an `expect` here aborted the whole host app instead of
    /// failing the start with a reason.
    pub fn spawn<D, F>(
        thread_name: &str,
        options: TcpStackOptions,
        wake: StackWaker,
        make_device: F,
    ) -> io::Result<Self>
    where
        D: StackDevice,
        F: FnOnce() -> io::Result<D> + Send + 'static,
    {
        let (udp_tx, udp_rx) = tokio::sync::mpsc::unbounded_channel();
        let running = Arc::new(AtomicBool::new(true));
        let notifier = StackNotifier::new(wake);
        let shared_state = Arc::new(Mutex::new(SharedState {
            udp_response_rx: None,
            new_conn_tx: None,
        }));

        let thread_handle = {
            let running = running.clone();
            let shared_state = shared_state.clone();
            let notifier = notifier.clone();

            thread::Builder::new()
                .name(thread_name.to_owned())
                .spawn(move || {
                    run_stack_thread_guarded(running.clone(), || {
                        let device = match make_device() {
                            Ok(device) => device,
                            Err(e) => {
                                error!("Failed to prepare the TUN device: {e}");
                                return;
                            }
                        };
                        run_stack_loop(
                            device,
                            options,
                            udp_tx,
                            running.clone(),
                            shared_state,
                            notifier,
                        );
                    });
                })
                .map_err(|e| {
                    io::Error::other(format!("failed to spawn the smoltcp stack thread: {e}"))
                })?
        };

        Ok(Self {
            thread_handle: Some(thread_handle),
            notifier,
            running,
            udp_rx: Some(udp_rx),
            shared_state,
        })
    }

    /// Take the receiver for UDP packets (filtered from TUN by the stack).
    pub fn take_udp_rx(&mut self) -> Option<UnboundedReceiver<PacketBuffer>> {
        self.udp_rx.take()
    }

    /// A waker the tokio side calls after queueing a UDP response, so the
    /// stack thread writes it now rather than on its next wakeup. Coalesced
    /// through the notifier: a burst of responses costs one wake, not one per
    /// datagram. This is what backends now hand out as their `udp_waker`.
    pub fn waker(&self) -> StackWaker {
        let notifier = self.notifier.clone();
        Arc::new(move || notifier.notify())
    }

    /// Set the channel for UDP responses to write back to TUN.
    pub fn set_udp_response_tx(&mut self, rx: tokio::sync::mpsc::Receiver<PacketBuffer>) {
        if let Ok(mut state) = self.shared_state.lock() {
            state.udp_response_rx = Some(rx);
        }
        self.notifier.notify();
    }

    /// Set the channel for notifying about new TCP connections.
    pub fn set_new_conn_tx(&mut self, tx: UnboundedSender<NewTcpConnection>) {
        if let Ok(mut state) = self.shared_state.lock() {
            state.new_conn_tx = Some(tx);
        }
        self.notifier.notify();
    }

    /// Check if the stack thread is still running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// First half of shutdown: mark the loop stopped and wake the thread so
    /// it sees the flag now rather than at its next packet or timer tick. A
    /// backend that has a second reason to wake — Windows shutting the session
    /// down, which is also what unblocks a read in progress — still fires that
    /// between this and [`Self::join`].
    pub fn signal_stop(&self) {
        self.running.store(false, Ordering::Relaxed);
        self.notifier.notify();
    }

    /// Wait for the stack thread to finish. The join is what guarantees the
    /// device has been let go, so backends must not skip it.
    pub fn join(&mut self) {
        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }
    }
}

/// The device capabilities every backend advertises: an IP-medium device
/// that offloads nothing but wants transmit checksums filled in.
pub fn ip_capabilities(mtu: usize) -> smoltcp::phy::DeviceCapabilities {
    let mut caps = smoltcp::phy::DeviceCapabilities::default();
    caps.medium = smoltcp::phy::Medium::Ip;
    caps.max_transmission_unit = mtu;
    caps.checksum.ipv4 = smoltcp::phy::Checksum::Tx;
    caps.checksum.tcp = smoltcp::phy::Checksum::Tx;
    caps.checksum.udp = smoltcp::phy::Checksum::Tx;
    caps.checksum.icmpv4 = smoltcp::phy::Checksum::Tx;
    caps.checksum.icmpv6 = smoltcp::phy::Checksum::Tx;
    caps
}

/// The receive token every backend uses: a pooled buffer handed to smoltcp
/// and returned to the pool when dropped.
pub struct PooledRxToken {
    pub buffer: PooledBuffer,
}

impl smoltcp::phy::RxToken for PooledRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
        // buffer is returned to pool when dropped
    }
}

/// Run `f` as the body of a stack thread: log a panic instead of unwinding
/// across the thread boundary, and mark the stack stopped either way.
pub fn run_stack_thread_guarded(running: Arc<AtomicBool>, f: impl FnOnce()) {
    let result = panic::catch_unwind(AssertUnwindSafe(f));

    match result {
        Ok(()) => {
            info!("smoltcp stack thread exited normally");
        }
        Err(panic_info) => {
            let msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_info.downcast_ref::<String>() {
                s.clone()
            } else {
                "Unknown panic".to_string()
            };
            error!("smoltcp stack thread PANICKED: {}", msg);
        }
    }

    running.store(false, Ordering::Relaxed);
}

/// Run the smoltcp stack loop over a platform device.
///
/// This is the body that used to live in `tcp_stack_direct.rs` as
/// `run_direct_stack_thread`, with the fd-specific `wait_readable` behind
/// [`StackDevice::wait`].
pub fn run_stack_loop<D: StackDevice>(
    mut device: D,
    options: TcpStackOptions,
    udp_tx: UnboundedSender<PacketBuffer>,
    running: Arc<AtomicBool>,
    shared_state: Arc<Mutex<SharedState>>,
    notifier: Arc<StackNotifier>,
) {
    info!("smoltcp stack thread initializing...");

    let TcpStackOptions {
        tcp_buffer_size,
        max_connections,
        orphan_timeout,
        ..
    } = options;

    let mut iface_config = InterfaceConfig::new(HardwareAddress::Ip);
    iface_config.random_seed = rand::random();

    let mut iface = Interface::new(iface_config, &mut device, smol_now());

    iface.update_ip_addrs(|addrs| {
        if let Err(e) = addrs.push(IpCidr::new(IpAddress::v4(0, 0, 0, 1), 0)) {
            warn!("Failed to add IPv4 address: {:?}", e);
        }
        if let Err(e) = addrs.push(IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1), 0)) {
            warn!("Failed to add IPv6 address: {:?}", e);
        }
    });

    if let Err(e) = iface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address::new(0, 0, 0, 1))
    {
        warn!("Failed to add IPv4 route: {:?}", e);
    }
    if let Err(e) = iface
        .routes_mut()
        .add_default_ipv6_route(Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 1))
    {
        warn!("Failed to add IPv6 route: {:?}", e);
    }

    iface.set_any_ip(true);

    let mut socket_set = SocketSet::new(vec![]);
    let mut sockets: HashMap<SocketHandle, SocketInfo> = HashMap::new();
    let mut active_connections: std::collections::HashSet<(SocketAddr, SocketAddr)> =
        std::collections::HashSet::new();

    let mut poll_count: u64 = 0;
    let mut last_log_time = std::time::Instant::now();

    let mut phy_wait_error_count: u32 = 0;
    const MAX_PHY_WAIT_ERRORS: u32 = 10;

    // Reused across iterations rather than freshly allocated each time: this
    // is the path everything the tunnel carries goes through, so a `Vec` per
    // batch is an allocation per batch.
    let mut tcp_packets: Vec<PooledBuffer> = Vec::with_capacity(MAX_PACKET_BATCH);
    let mut sockets_to_remove: Vec<SocketHandle> = Vec::new();

    info!("smoltcp stack thread started, entering main loop");

    while running.load(Ordering::Relaxed) {
        // Checks for UDP responses to write to TUN.
        if let Ok(mut state) = shared_state.try_lock()
            && let Some(ref mut udp_rx) = state.udp_response_rx
        {
            while let Ok(pkt) = udp_rx.try_recv() {
                if let Err(e) = device.write_packet(&pkt) {
                    warn!("Failed to write UDP response to TUN: {}", e);
                }
            }
        }

        // Reads packets from TUN and filters by protocol (batch processing).
        tcp_packets.clear();
        let mut packets_read = 0;

        while packets_read < MAX_PACKET_BATCH {
            let pkt = match device.try_recv() {
                Ok(Some(p)) => p,
                Ok(None) => break,
                Err(e) => {
                    // Critical error reading from TUN (EOF or EIO)
                    error!("TUN device read failed: {}. Stack thread stopping.", e);
                    running.store(false, Ordering::Relaxed);
                    break;
                }
            };
            packets_read += 1;

            if should_filter_packet(&pkt) {
                trace!("Filtered packet, len={}", pkt.len());
                continue;
            }

            if let Some(protocol) = get_ip_protocol(&pkt) {
                trace!(
                    "Received packet: protocol={:?}, len={}",
                    protocol,
                    pkt.len()
                );
                match protocol {
                    IpProtocol::Tcp => {
                        match extract_tcp_info(&pkt) {
                            Some((src_addr, dst_addr, is_syn)) => {
                                trace!("TCP packet: {} -> {}, SYN={}", src_addr, dst_addr, is_syn);
                                if is_syn && !active_connections.contains(&(src_addr, dst_addr)) {
                                    // Check connection limit
                                    if sockets.len() >= max_connections {
                                        warn!(
                                            "Connection limit reached ({}), dropping SYN from {}",
                                            max_connections, src_addr
                                        );
                                        continue;
                                    }

                                    // debug, not info: one line per connection
                                    // at info level fills a mobile log file
                                    // with a page load's worth of noise.
                                    debug!("New TCP SYN: {} -> {}", src_addr, dst_addr);

                                    if let Some((new_conn, control)) = create_tcp_connection(
                                        src_addr,
                                        dst_addr,
                                        tcp_buffer_size,
                                        &mut socket_set,
                                        &notifier,
                                    ) {
                                        sockets.insert(
                                            new_conn.handle,
                                            SocketInfo {
                                                control,
                                                src_addr,
                                                dst_addr,
                                                orphaned_since: None,
                                            },
                                        );
                                        active_connections.insert((src_addr, dst_addr));
                                        // On a SYN, not per packet, so a
                                        // relaxed atomic here is not
                                        // measurable.
                                        #[cfg(feature = "control-stats")]
                                        super::traffic::connection_opened();

                                        // `lock`, not `try_lock`: the other
                                        // holders are the setup-time setters
                                        // and the UDP drain above, all brief,
                                        // and a `try_lock` that lost the race
                                        // dropped the connection on the floor.
                                        // The client saw a handshake followed
                                        // by a FIN, with nothing logged.
                                        if let Ok(state) = shared_state.lock()
                                            && let Some(ref tx) = state.new_conn_tx
                                        {
                                            let _ = tx.send(new_conn.new_tcp_conn);
                                        }
                                    }
                                }
                            }
                            None => {
                                warn!("Failed to parse TCP packet, len={}", pkt.len());
                            }
                        }

                        tcp_packets.push(pkt);
                    }
                    IpProtocol::Icmp | IpProtocol::Icmpv6 => {
                        // ICMP goes to smoltcp immediately
                        tcp_packets.push(pkt);
                    }
                    IpProtocol::Udp => {
                        // UDP goes to tokio - convert to Vec since it leaves our pool
                        let _ = udp_tx.send(pkt.to_vec());
                    }
                    _ => {
                        trace!("ignoring packet with protocol {:?}", protocol);
                    }
                }
            }
        }

        if packets_read > 0 {
            phy_wait_error_count = 0;
        }

        // Skip remaining work if a fatal read error was detected above.
        if !running.load(Ordering::Relaxed) {
            break;
        }

        // Hands the whole batch to smoltcp and polls once. `Interface::poll`
        // drains everything the device offers through `receive` before it runs
        // egress, so a batch of N packets is one egress sweep over the sockets
        // rather than N, and the ACKs and window updates the batch produces go
        // out together. The device queues what it is handed; see
        // `StackDevice::store_packet`.
        let has_tcp_packet = !tcp_packets.is_empty();
        for pkt in tcp_packets.drain(..) {
            device.store_packet(pkt);
        }

        let now = smol_now();
        iface.poll(now, &mut device, &mut socket_set);

        sockets_to_remove.clear();

        // One clock read per sweep, for the orphan timer.
        let sweep_now = std::time::Instant::now();

        for (handle, socket_info) in sockets.iter_mut() {
            let handle = *handle;
            let control = &socket_info.control;
            let socket = socket_set.get_mut::<TcpSocket>(handle);

            // Remove socket only when smoltcp reports Closed state
            if socket.state() == TcpState::Closed {
                sockets_to_remove.push(handle);
                control.set_closed();
                trace!("socket {:?} closed", handle);
                continue;
            }

            // The app hung up on both halves: its `TcpConnection` was
            // dropped, and nothing will ever read from this socket again.
            // Only the send half used to be acted on (a FIN once drained,
            // below); the receive half kept accepting into a buffer nobody
            // drained, and the socket sat in FIN-WAIT-2 with all four buffers
            // until the peer chose to close, which a peer that keeps sending
            // or keeps answering keepalives need never do.
            //
            // What Linux does, and what this does: data the app never read,
            // or data arriving after it hung up, is answered with a reset at
            // once (RFC 2525 §2.17); a peer that goes quiet without closing
            // gets `orphan_timeout`, its `tcp_fin_timeout`, and then a reset.
            // A clean hang-up, with nothing unread and a peer that closes,
            // still ends in the FIN exchange below.
            if control.recv_state() == TcpSocketState::Close {
                let orphaned_since = *socket_info.orphaned_since.get_or_insert(sweep_now);
                let peer_still_talking = control.has_unread_data() || socket.can_recv();
                if peer_still_talking || sweep_now.duration_since(orphaned_since) >= orphan_timeout
                {
                    trace!(
                        "socket {:?}: app hung up, {}; reset",
                        handle,
                        if peer_still_talking {
                            "peer still sending"
                        } else {
                            "peer never closed"
                        }
                    );
                    // Closed now; the RST goes out on this iteration's poll and
                    // the socket is removed on the next sweep.
                    socket.abort();
                    control.set_closed();
                    continue;
                }
            }

            // Handle SHUT_WR: Close -> Closing transition
            // Must check send_queue() to ensure smoltcp has transmitted all data
            if control.send_state() == TcpSocketState::Close
                && socket.send_queue() == 0
                && control.send_buffer_empty()
            {
                trace!(
                    "socket {:?}: closing write half, state={:?}",
                    handle,
                    socket.state()
                );
                socket.close();
                control.set_send_state(TcpSocketState::Closing);
            }

            // Receive data from smoltcp into our buffer
            let mut wake_receiver = false;
            while socket.can_recv() && !control.recv_buffer_full() {
                match socket.recv(|data| {
                    let n = control.enqueue_recv_data(data);
                    (n, n)
                }) {
                    Ok(n) if n > 0 => {
                        wake_receiver = true;
                    }
                    Ok(_) => break,
                    Err(e) => {
                        error!(
                            "socket {:?} recv error: {:?}, state={:?}",
                            handle,
                            e,
                            socket.state()
                        );
                        socket.abort();
                        if control.recv_state() == TcpSocketState::Normal {
                            control.set_recv_state(TcpSocketState::Closed);
                        }
                        wake_receiver = true;
                        break;
                    }
                }
            }

            // Detect recv half close using negative state matching.
            // If socket can't receive and is not in an active receiving state, mark recv closed.
            if control.recv_state() == TcpSocketState::Normal
                && !socket.may_recv()
                && !matches!(
                    socket.state(),
                    TcpState::Listen
                        | TcpState::SynReceived
                        | TcpState::Established
                        | TcpState::FinWait1
                        | TcpState::FinWait2
                )
            {
                trace!(
                    "socket {:?}: recv half closed, state={:?}",
                    handle,
                    socket.state()
                );
                control.set_recv_state(TcpSocketState::Closed);
                wake_receiver = true;
            }

            if wake_receiver {
                control.wake_receiver();
            }

            // Send data from our buffer to smoltcp
            let mut wake_sender = false;
            while socket.can_send() && !control.send_buffer_empty() {
                match socket.send(|buf| {
                    let n = control.dequeue_send_data(buf);
                    (n, n)
                }) {
                    Ok(n) if n > 0 => {
                        wake_sender = true;
                    }
                    Ok(_) => break,
                    Err(e) => {
                        error!(
                            "socket {:?} send error: {:?}, state={:?}",
                            handle,
                            e,
                            socket.state()
                        );
                        socket.abort();
                        if control.send_state() == TcpSocketState::Normal {
                            control.set_send_state(TcpSocketState::Closed);
                        }
                        wake_sender = true;
                        break;
                    }
                }
            }

            if wake_sender {
                control.wake_sender();
            }
        }

        for handle in sockets_to_remove.drain(..) {
            if let Some(socket_info) = sockets.remove(&handle) {
                active_connections.remove(&(socket_info.src_addr, socket_info.dst_addr));
                #[cfg(feature = "control-stats")]
                super::traffic::connection_closed();
                trace!(
                    "Cleaned up connection: {} -> {}",
                    socket_info.src_addr, socket_info.dst_addr
                );
            }
            socket_set.remove(handle);
        }

        poll_count += 1;
        if last_log_time.elapsed() >= Duration::from_secs(30) {
            debug!(
                "smoltcp stack: polls={}, active_sockets={}",
                poll_count,
                sockets.len()
            );
            last_log_time = std::time::Instant::now();
        }

        // Polls again after data transfer (critical for performance).
        let after_transfer = smol_now();
        iface.poll(after_transfer, &mut device, &mut socket_set);

        // Wait for data using the platform's readiness primitive - this is
        // the key for event-driven I/O
        if !has_tcp_packet && !device.has_pending() {
            // Sleep until smoltcp's own next deadline — a retransmit, a
            // keepalive, a closing timer — or, when it has none, until the
            // one-second dead-device backstop below. What is gone is the old
            // 10 ms cap, which existed only because a segment or response
            // handed over by tokio could not otherwise wake the thread before
            // the next tick; the notifier does that now. So an idle connection
            // with no sub-second timer wakes at most once a second (to notice a
            // torn-down device the platform did not report — see
            // `MAX_POLL_WAIT_MILLIS`), not a hundred times. `arm` publishes that
            // a sleep is next and returns true if a `notify` already raced in,
            // in which case we skip the sleep and loop again to handle it.
            //
            // The `min` is belt-and-braces: both backend `wait`s clamp to
            // `MAX_POLL_WAIT_MILLIS` too, so a `None` deadline already becomes
            // the one-second wait. Capping here as well keeps the backstop true
            // of any future backend whose `wait` forgets to.
            let wait_duration = iface
                .poll_delay(after_transfer, &socket_set)
                .map(|d| SmolDuration::from_millis(d.total_millis().min(MAX_POLL_WAIT_MILLIS)));

            if notifier.arm() {
                notifier.disarm();
            } else {
                // Sleeps until the TUN has something to read, the notifier
                // fires the backend's wake primitive, the backend's shutdown
                // signal says to stop, or the delay elapses. If the device
                // becomes invalid (e.g. removed), the wait returns an error
                // immediately with no sleep, creating a hot spin loop. The
                // try_recv path usually catches this first, but this counter
                // acts as a backstop: after 10 consecutive non-EINTR errors
                // with no successful reads in between, treat the device as
                // dead.
                let wait_result = device.wait(wait_duration);
                notifier.disarm();
                if let Err(e) = wait_result
                    && e.kind() != io::ErrorKind::Interrupted
                {
                    phy_wait_error_count += 1;
                    if phy_wait_error_count >= MAX_PHY_WAIT_ERRORS {
                        error!(
                            "device wait failed {} consecutive times (last: {}). Stack thread stopping.",
                            phy_wait_error_count, e
                        );
                        running.store(false, Ordering::Relaxed);
                    } else {
                        warn!("device wait error ({}): {}", phy_wait_error_count, e);
                    }
                }
            }
        }
    }

    // Sockets still live when the loop breaks -- on a shutdown request, on TUN
    // EOF, or after MAX_PHY_WAIT_ERRORS -- never reach the cleanup sweep that
    // decrements, so without this the count keeps whatever was open at the
    // moment the tunnel stopped. Being process-global, that error then
    // compounds across every start/stop for the life of the process.
    #[cfg(feature = "control-stats")]
    super::traffic::reset_active_connections();

    info!("smoltcp stack thread stopped");
}

/// Result of creating a TCP connection.
struct CreateConnectionResult {
    handle: SocketHandle,
    new_tcp_conn: NewTcpConnection,
}

/// Create a new TCP connection in the smoltcp stack.
fn create_tcp_connection(
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    buffer_size: usize,
    socket_set: &mut SocketSet<'static>,
    notifier: &Arc<StackNotifier>,
) -> Option<(CreateConnectionResult, Arc<TcpConnectionControl>)> {
    let mut socket = TcpSocket::new(
        TcpSocketBuffer::new(vec![0u8; buffer_size]),
        TcpSocketBuffer::new(vec![0u8; buffer_size]),
    );

    // Matched to netstack-smoltcp settings for optimal performance
    socket.set_congestion_control(CongestionControl::Cubic);
    socket.set_keep_alive(Some(SmolDuration::from_secs(28)));
    // smoltcp's `timeout` is not Linux's `tcp_keepalive_time`, though the
    // value is the same and shadowsocks-rust carries the same FIXME: with
    // keep-alive on, it aborts when the peer goes this long without sending
    // anything, probes included. The peer here is this host's own kernel,
    // which answers a probe at once for as long as the app's socket exists,
    // so this only ever fires when the device is gone -- and then the loop
    // is already stopping. A connection the app has dropped is the case that
    // used to hide behind this figure; the sweep resets those itself.
    socket.set_timeout(Some(SmolDuration::from_secs(7200)));
    socket.set_nagle_enabled(false);
    socket.set_ack_delay(None);

    if let Err(e) = socket.listen(dst_addr) {
        warn!("Failed to listen on socket for {}: {:?}", dst_addr, e);
        return None;
    }

    debug!("Creating TCP connection: {} -> {}", src_addr, dst_addr);

    let control = Arc::new(TcpConnectionControl::new(buffer_size, buffer_size));

    let handle = socket_set.add(socket);
    let connection = TcpConnection::new(control.clone(), notifier.clone());

    Some((
        CreateConnectionResult {
            handle,
            new_tcp_conn: NewTcpConnection {
                connection,
                remote_addr: dst_addr,
                local_addr: src_addr,
            },
        },
        control,
    ))
}

/// Extract IP protocol from a raw IP packet.
fn get_ip_protocol(packet: &[u8]) -> Option<IpProtocol> {
    if packet.is_empty() {
        return None;
    }

    let version = packet[0] >> 4;
    match version {
        4 => Ipv4Packet::new_checked(packet)
            .ok()
            .map(|p| p.next_header()),
        6 => Ipv6Packet::new_checked(packet)
            .ok()
            .map(|p| p.next_header()),
        _ => None,
    }
}

/// Extract TCP connection info from a raw IP packet.
fn extract_tcp_info(packet: &[u8]) -> Option<(SocketAddr, SocketAddr, bool)> {
    if packet.is_empty() {
        return None;
    }

    let version = packet[0] >> 4;
    match version {
        4 => {
            let ip = Ipv4Packet::new_checked(packet).ok()?;
            if ip.next_header() != IpProtocol::Tcp {
                return None;
            }
            let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
            let src_addr = SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(ip.src_addr().octets())),
                tcp.src_port(),
            );
            let dst_addr = SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(ip.dst_addr().octets())),
                tcp.dst_port(),
            );
            let is_syn = tcp.syn() && !tcp.ack();
            Some((src_addr, dst_addr, is_syn))
        }
        6 => {
            let ip = Ipv6Packet::new_checked(packet).ok()?;
            if ip.next_header() != IpProtocol::Tcp {
                return None;
            }
            let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
            let src_addr = SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip.src_addr().octets())),
                tcp.src_port(),
            );
            let dst_addr = SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip.dst_addr().octets())),
                tcp.dst_port(),
            );
            let is_syn = tcp.syn() && !tcp.ack();
            Some((src_addr, dst_addr, is_syn))
        }
        _ => None,
    }
}

/// Check if an IP packet should be filtered.
fn should_filter_packet(packet: &[u8]) -> bool {
    if packet.is_empty() {
        return true;
    }

    let version = packet[0] >> 4;
    match version {
        4 => {
            if let Ok(ip) = Ipv4Packet::new_checked(packet) {
                let src = ip.src_addr();
                let dst = ip.dst_addr();

                let src_bytes = src.octets();
                let dst_bytes = dst.octets();

                // Filter unspecified source
                if src_bytes == [0, 0, 0, 0] {
                    return true;
                }
                // Filter multicast source
                if src_bytes[0] >= 224 && src_bytes[0] <= 239 {
                    return true;
                }
                // Filter broadcast destination
                if dst_bytes == [255, 255, 255, 255] {
                    return true;
                }
                // Filter multicast destination
                if dst_bytes[0] >= 224 && dst_bytes[0] <= 239 {
                    return true;
                }
                // Filter unspecified destination
                if dst_bytes == [0, 0, 0, 0] {
                    return true;
                }

                false
            } else {
                true
            }
        }
        6 => {
            if let Ok(ip) = Ipv6Packet::new_checked(packet) {
                let src = ip.src_addr();
                let dst = ip.dst_addr();

                let src_bytes = src.octets();
                let dst_bytes = dst.octets();

                // Filter unspecified source
                if src_bytes == [0u8; 16] {
                    return true;
                }
                // Filter multicast destination
                if dst_bytes[0] == 0xff {
                    return true;
                }
                // Filter unspecified destination
                if dst_bytes == [0u8; 16] {
                    return true;
                }

                false
            } else {
                true
            }
        }
        _ => true,
    }
}

/// Packet builders shared by both backends' test modules, so the two suites
/// cannot quietly start testing different inputs.
#[cfg(test)]
pub mod test_util {
    use smoltcp::phy::ChecksumCapabilities;
    use smoltcp::wire::{
        IpProtocol, Ipv4Address, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber,
    };

    /// One IPv4 SYN, checksummed, from 10.0.0.2:`src_port` to
    /// 93.184.216.34:443, with initial sequence number 0.
    pub fn syn_packet(src_port: u16) -> Vec<u8> {
        tcp_packet(src_port, TcpControl::Syn, 0, None, &[])
    }

    /// A segment from the same client to the same server. `seq` is relative
    /// to the SYN above (the first data byte is 1); `ack` is absolute.
    pub fn tcp_packet(
        src_port: u16,
        control: TcpControl,
        seq: u32,
        ack: Option<u32>,
        payload: &[u8],
    ) -> Vec<u8> {
        let tcp = TcpRepr {
            src_port,
            dst_port: 443,
            control,
            seq_number: TcpSeqNumber(seq as i32),
            ack_number: ack.map(|a| TcpSeqNumber(a as i32)),
            window_len: 64240,
            window_scale: None,
            max_seg_size: if control == TcpControl::Syn {
                Some(1400)
            } else {
                None
            },
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload,
        };
        let src_addr = Ipv4Address::new(10, 0, 0, 2);
        let dst_addr = Ipv4Address::new(93, 184, 216, 34);
        let ip = Ipv4Repr {
            src_addr,
            dst_addr,
            next_header: IpProtocol::Tcp,
            payload_len: tcp.buffer_len(),
            hop_limit: 64,
        };

        let checksums = ChecksumCapabilities::default();
        let mut buffer = vec![0u8; ip.buffer_len() + tcp.buffer_len()];
        ip.emit(&mut Ipv4Packet::new_unchecked(&mut buffer), &checksums);
        tcp.emit(
            &mut TcpPacket::new_unchecked(&mut buffer[ip.buffer_len()..]),
            &src_addr.into(),
            &dst_addr.into(),
            &checksums,
        );
        buffer
    }

    /// The TCP flags and sequence number of a packet the stack wrote, if it
    /// is a segment from 93.184.216.34:443.
    pub struct Segment {
        pub syn: bool,
        pub ack: bool,
        pub fin: bool,
        pub rst: bool,
        pub seq: u32,
    }

    pub fn segment_from_server(packet: &[u8]) -> Option<Segment> {
        let ip = Ipv4Packet::new_checked(packet).ok()?;
        if ip.next_header() != IpProtocol::Tcp {
            return None;
        }
        let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
        (tcp.src_port() == 443).then(|| Segment {
            syn: tcp.syn(),
            ack: tcp.ack(),
            fin: tcp.fin(),
            rst: tcp.rst(),
            seq: tcp.seq_number().0 as u32,
        })
    }

    /// Whether `packet` is a TCP SYN+ACK from 93.184.216.34:443, which is
    /// what the stack answers `syn_packet` with.
    pub fn is_syn_ack(packet: &[u8]) -> bool {
        segment_from_server(packet).is_some_and(|s| s.syn && s.ack)
    }
}

// Platform-neutral by construction: these drive [`run_stack_loop`] through a
// scripted device, so the shared loop's behaviour — accepting a SYN,
// forwarding UDP, dying with its device, honouring the shutdown flag — is
// asserted on every platform, including the one (Windows) whose real device
// needs a driver and Administrator to exist.
#[cfg(test)]
mod tests {
    use smoltcp::time::Instant as SmolInstant;

    use std::collections::VecDeque;
    use std::sync::mpsc as std_mpsc;
    use std::time::Duration as StdDuration;

    use smoltcp::phy::TxToken;

    use super::test_util::{is_syn_ack, segment_from_server, syn_packet, tcp_packet};
    use super::*;

    /// One step of a scripted device's life.
    enum Script {
        /// A packet arrives from the TUN.
        Packet(Vec<u8>),
        /// The device dies with this error on the next read.
        Die(io::ErrorKind),
    }

    /// A [`StackDevice`] driven by a test through a channel, recording
    /// everything the stack writes back.
    struct ScriptedDevice {
        rx: std_mpsc::Receiver<Script>,
        /// Scripts observed by `wait`, which takes `&self`, parked here for
        /// the `&mut self` read path to consume.
        queued: Mutex<VecDeque<Script>>,
        written: Arc<Mutex<Vec<Vec<u8>>>>,
        pending: VecDeque<PooledBuffer>,
        mtu: usize,
    }

    impl ScriptedDevice {
        fn next_script(&mut self) -> Option<Script> {
            if let Some(s) = self.queued.lock().unwrap().pop_front() {
                return Some(s);
            }
            self.rx.try_recv().ok()
        }
    }

    impl StackDevice for ScriptedDevice {
        fn try_recv(&mut self) -> io::Result<Option<PooledBuffer>> {
            if let Some(pkt) = self.pending.pop_front() {
                return Ok(Some(pkt));
            }
            match self.next_script() {
                Some(Script::Packet(data)) => {
                    let mut buffer = PooledBuffer::with_capacity(self.mtu + 4);
                    buffer.extend_from_slice(&data);
                    Ok(Some(buffer))
                }
                Some(Script::Die(kind)) => Err(io::Error::new(kind, "scripted device death")),
                None => Ok(None),
            }
        }

        fn store_packet(&mut self, pkt: PooledBuffer) {
            self.pending.push_back(pkt);
        }

        fn has_pending(&self) -> bool {
            !self.pending.is_empty()
        }

        fn write_packet(&self, data: &[u8]) -> io::Result<()> {
            self.written.lock().unwrap().push(data.to_vec());
            Ok(())
        }

        fn wait(&self, duration: Option<SmolDuration>) -> io::Result<()> {
            let timeout = duration
                .map(|d| d.total_millis())
                .unwrap_or(MAX_POLL_WAIT_MILLIS)
                .min(MAX_POLL_WAIT_MILLIS);
            match self.rx.recv_timeout(StdDuration::from_millis(timeout)) {
                // Parked for the read path; wait must not swallow what it saw.
                Ok(s) => {
                    self.queued.lock().unwrap().push_back(s);
                    Ok(())
                }
                Err(std_mpsc::RecvTimeoutError::Timeout) => Ok(()),
                // The test dropped its sender; behave like a quiet device
                // rather than spinning on an instant return.
                Err(std_mpsc::RecvTimeoutError::Disconnected) => {
                    thread::sleep(StdDuration::from_millis(timeout));
                    Ok(())
                }
            }
        }
    }

    impl Device for ScriptedDevice {
        type RxToken<'a> = PooledRxToken;
        type TxToken<'a> = ScriptedTxToken;

        fn receive(
            &mut self,
            _timestamp: SmolInstant,
        ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
            self.pending.pop_front().map(|buffer| {
                (
                    PooledRxToken { buffer },
                    ScriptedTxToken {
                        written: self.written.clone(),
                    },
                )
            })
        }

        fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
            Some(ScriptedTxToken {
                written: self.written.clone(),
            })
        }

        fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
            ip_capabilities(self.mtu)
        }
    }

    struct ScriptedTxToken {
        written: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl TxToken for ScriptedTxToken {
        fn consume<R, F>(self, len: usize, f: F) -> R
        where
            F: FnOnce(&mut [u8]) -> R,
        {
            let mut buffer = vec![0u8; len];
            let result = f(&mut buffer);
            self.written.lock().unwrap().push(buffer);
            result
        }
    }

    /// A running loop over a scripted device, with every channel a test needs.
    struct Harness {
        script_tx: std_mpsc::Sender<Script>,
        written: Arc<Mutex<Vec<Vec<u8>>>>,
        running: Arc<AtomicBool>,
        conn_rx: UnboundedReceiver<NewTcpConnection>,
        udp_rx: UnboundedReceiver<PacketBuffer>,
        udp_response_tx: tokio::sync::mpsc::Sender<PacketBuffer>,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl Harness {
        /// With the production orphan timeout, so only a peer still talking
        /// can get a dropped connection reset inside a test's two seconds.
        fn spawn() -> Self {
            Self::spawn_with(StdDuration::from_secs(60))
        }

        fn spawn_with(orphan_timeout: StdDuration) -> Self {
            let (script_tx, script_rx) = std_mpsc::channel();
            let written = Arc::new(Mutex::new(Vec::new()));
            let running = Arc::new(AtomicBool::new(true));
            let (conn_tx, conn_rx) = tokio::sync::mpsc::unbounded_channel();
            let (udp_tx, udp_rx) = tokio::sync::mpsc::unbounded_channel();
            let (udp_response_tx, udp_response_rx) = tokio::sync::mpsc::channel(64);

            let device = ScriptedDevice {
                rx: script_rx,
                queued: Mutex::new(VecDeque::new()),
                written: written.clone(),
                pending: VecDeque::new(),
                mtu: 1500,
            };

            let options = TcpStackOptions {
                mtu: 1500,
                tcp_buffer_size: 32 * 1024,
                max_connections: 16,
                close_fd_on_drop: false,
                utun_header: false,
                orphan_timeout,
            };

            let shared_state = Arc::new(Mutex::new(SharedState {
                udp_response_rx: Some(udp_response_rx),
                new_conn_tx: Some(conn_tx),
            }));

            // The scripted device's `wait` sleeps on the script channel, which
            // a test drives directly, so the notifier's wake need do nothing:
            // a `notify` sets `pending` and the next `arm` sees it. Real
            // backends pass a pipe/event waker here instead.
            let notifier = StackNotifier::new(Arc::new(|| {}));

            let handle = {
                let running = running.clone();
                thread::spawn(move || {
                    run_stack_loop(device, options, udp_tx, running, shared_state, notifier);
                })
            };

            Self {
                script_tx,
                written,
                running,
                conn_rx,
                udp_rx,
                udp_response_tx,
                handle: Some(handle),
            }
        }

        /// Wait until `predicate` holds over the packets the stack has
        /// written, or panic after two seconds.
        fn wait_for_written(&self, what: &str, predicate: impl Fn(&[Vec<u8>]) -> bool) {
            let start = std::time::Instant::now();
            loop {
                if predicate(&self.written.lock().unwrap()) {
                    return;
                }
                assert!(
                    start.elapsed() < StdDuration::from_secs(2),
                    "timed out waiting for {what}; got {:?}",
                    self.written
                        .lock()
                        .unwrap()
                        .iter()
                        .map(|p| p.len())
                        .collect::<Vec<_>>()
                );
                thread::sleep(StdDuration::from_millis(10));
            }
        }

        fn stop(mut self) {
            self.running.store(false, Ordering::Relaxed);
            if let Some(handle) = self.handle.take() {
                handle.join().expect("stack loop panicked");
            }
        }
    }

    impl Drop for Harness {
        fn drop(&mut self) {
            self.running.store(false, Ordering::Relaxed);
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    /// Serialise against everything else that reads the process-global
    /// connection counter: a SYN increments it and the loop's exit path
    /// resets it, so any harness test can zero another test's count.
    ///
    /// A poisoned lock is taken anyway: the guard protects a counter the
    /// next test resets before use, so the only thing poisoning would add
    /// is turning one test's failure into a `PoisonError` cascade across
    /// every other test that uses the counter -- which is exactly what a
    /// Windows CI run produced (one real assertion failure, four phantoms).
    #[cfg(feature = "control-stats")]
    fn counter_guard() -> std::sync::MutexGuard<'static, ()> {
        super::super::traffic::COUNTER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Receive with a deadline, so a loop that stops delivering fails the
    /// test in two seconds instead of hanging the whole suite on a
    /// `blocking_recv` that nothing will ever satisfy.
    fn recv_within<T>(rx: &mut UnboundedReceiver<T>, what: &str) -> T {
        let start = std::time::Instant::now();
        loop {
            match rx.try_recv() {
                Ok(value) => return value,
                Err(_) => {
                    assert!(
                        start.elapsed() < StdDuration::from_secs(2),
                        "timed out waiting for {what}"
                    );
                    thread::sleep(StdDuration::from_millis(10));
                }
            }
        }
    }

    #[test]
    fn a_syn_becomes_a_connection_and_a_syn_ack() {
        #[cfg(feature = "control-stats")]
        let _guard = counter_guard();
        let mut harness = Harness::spawn();

        harness
            .script_tx
            .send(Script::Packet(syn_packet(20001)))
            .unwrap();

        let conn = recv_within(&mut harness.conn_rx, "the connection to reach tokio");
        assert_eq!(conn.remote_addr.to_string(), "93.184.216.34:443");

        harness.wait_for_written("a SYN+ACK", |written| written.iter().any(|p| is_syn_ack(p)));

        harness.stop();
    }

    impl Harness {
        /// Find the first written packet that `pick` accepts.
        fn find_written<T>(&self, pick: impl Fn(&[u8]) -> Option<T>) -> Option<T> {
            self.written.lock().unwrap().iter().find_map(|p| pick(p))
        }

        /// The full handshake from 10.0.0.2:`src_port`: SYN, SYN+ACK, ACK.
        /// Returns the connection tokio was handed and the server's initial
        /// sequence number, so the caller can keep sending in sequence.
        fn establish(&mut self, src_port: u16) -> (NewTcpConnection, u32) {
            self.script_tx
                .send(Script::Packet(syn_packet(src_port)))
                .unwrap();
            let conn = recv_within(&mut self.conn_rx, "the connection to reach tokio");
            self.wait_for_written("a SYN+ACK", |written| written.iter().any(|p| is_syn_ack(p)));
            let server_isn = self
                .find_written(|p| segment_from_server(p).filter(|s| s.syn && s.ack))
                .unwrap()
                .seq;
            self.script_tx
                .send(Script::Packet(tcp_packet(
                    src_port,
                    smoltcp::wire::TcpControl::None,
                    1,
                    Some(server_isn.wrapping_add(1)),
                    &[],
                )))
                .unwrap();
            (conn, server_isn)
        }
    }

    /// Every test here needs to see the socket go away, and the one
    /// observable that does not depend on a feature flag is the SYN guard:
    /// a SYN from a 4-tuple the stack still holds is dropped, so a second
    /// connection from the same port proves the first is gone.
    fn assert_tuple_is_free(harness: &mut Harness, src_port: u16) {
        harness
            .script_tx
            .send(Script::Packet(syn_packet(src_port)))
            .unwrap();
        recv_within(
            &mut harness.conn_rx,
            "a second connection from the same port, which the stack refuses while it still holds the first",
        );
    }

    /// The app drops the connection (an upstream that failed, a rule that
    /// blocked) with bytes the peer sent still unread. Nobody will read
    /// them, so the answer is a reset, as it would be from Linux; what it
    /// must not be is a socket that keeps the peer's data and its own four
    /// buffers until the peer gives up.
    #[test]
    fn dropping_a_connection_with_unread_data_resets_it() {
        #[cfg(feature = "control-stats")]
        let _guard = counter_guard();
        let mut harness = Harness::spawn();
        let (conn, server_isn) = harness.establish(20020);

        harness
            .script_tx
            .send(Script::Packet(tcp_packet(
                20020,
                smoltcp::wire::TcpControl::Psh,
                1,
                Some(server_isn.wrapping_add(1)),
                b"GET / HTTP/1.0\r\n\r\n",
            )))
            .unwrap();
        // Let the stack accept the data before the app hangs up, so this is
        // the unread-data case and not the peer-still-sending one.
        harness.wait_for_written("the ACK for the data", |written| {
            written
                .iter()
                .filter_map(|p| segment_from_server(p))
                .any(|s| s.ack && !s.syn)
        });

        drop(conn);
        // Something has to wake the loop; the notifier in the harness is a
        // no-op, so give it a packet-shaped reason.
        harness
            .script_tx
            .send(Script::Packet(syn_packet(20021)))
            .unwrap();

        harness.wait_for_written("a RST", |written| {
            written
                .iter()
                .filter_map(|p| segment_from_server(p))
                .any(|s| s.rst)
        });
        assert_tuple_is_free(&mut harness, 20020);
        harness.stop();
    }

    /// The app drops a connection nothing is unread on, so the stack sends
    /// FIN. The peer acknowledges it and then neither closes nor sends:
    /// FIN-WAIT-2, which smoltcp will hold forever and Linux holds for
    /// `tcp_fin_timeout`. After the harness's short orphan timeout the
    /// socket must be reset and its 4-tuple free again.
    #[test]
    fn an_orphaned_connection_the_peer_never_closes_is_reset_after_the_timeout() {
        #[cfg(feature = "control-stats")]
        let _guard = counter_guard();
        // Short enough to wait out; long against the tests' 10 ms polling.
        let mut harness = Harness::spawn_with(StdDuration::from_millis(300));
        let (conn, _server_isn) = harness.establish(20030);

        drop(conn);
        harness
            .script_tx
            .send(Script::Packet(syn_packet(20031)))
            .unwrap();
        harness.wait_for_written("a FIN", |written| {
            written
                .iter()
                .filter_map(|p| segment_from_server(p))
                .any(|s| s.fin)
        });
        let fin_seq = harness
            .find_written(|p| segment_from_server(p).filter(|s| s.fin))
            .unwrap()
            .seq;
        // The peer acknowledges the FIN and then says nothing more.
        harness
            .script_tx
            .send(Script::Packet(tcp_packet(
                20030,
                smoltcp::wire::TcpControl::None,
                1,
                Some(fin_seq.wrapping_add(1)),
                &[],
            )))
            .unwrap();

        // Past the orphan timeout; the loop's own timer wakes it to notice.
        thread::sleep(StdDuration::from_millis(400));
        harness
            .script_tx
            .send(Script::Packet(syn_packet(20032)))
            .unwrap();
        harness.wait_for_written("a RST after the orphan timeout", |written| {
            written
                .iter()
                .filter_map(|p| segment_from_server(p))
                .any(|s| s.rst)
        });
        assert_tuple_is_free(&mut harness, 20030);
        harness.stop();
    }

    #[test]
    fn udp_is_forwarded_to_tokio_not_smoltcp() {
        #[cfg(feature = "control-stats")]
        let _guard = counter_guard();
        let mut harness = Harness::spawn();

        let query = super::super::udp_handler::build_udp_packet(
            b"hello",
            "10.0.0.2:5353".parse().unwrap(),
            "8.8.8.8:53".parse().unwrap(),
        )
        .unwrap();
        harness
            .script_tx
            .send(Script::Packet(query.clone()))
            .unwrap();

        let forwarded = recv_within(&mut harness.udp_rx, "the UDP packet to reach tokio");
        assert_eq!(forwarded, query);

        harness.stop();
    }

    #[test]
    fn udp_responses_are_written_back_to_the_device() {
        #[cfg(feature = "control-stats")]
        let _guard = counter_guard();
        let harness = Harness::spawn();

        let response = super::super::udp_handler::build_udp_packet(
            b"answer",
            "8.8.8.8:53".parse().unwrap(),
            "10.0.0.2:5353".parse().unwrap(),
        )
        .unwrap();
        harness.udp_response_tx.try_send(response.clone()).unwrap();
        // The loop only drains the response channel when it wakes; give it a
        // packet-shaped reason rather than waiting out the idle timeout.
        harness
            .script_tx
            .send(Script::Packet(syn_packet(20002)))
            .unwrap();

        harness.wait_for_written("the UDP response", |written| {
            written.iter().any(|p| p == &response)
        });

        harness.stop();
    }

    #[test]
    fn the_loop_stops_when_its_device_dies() {
        #[cfg(feature = "control-stats")]
        let _guard = counter_guard();
        let harness = Harness::spawn();

        harness
            .script_tx
            .send(Script::Die(io::ErrorKind::UnexpectedEof))
            .unwrap();

        let start = std::time::Instant::now();
        while harness.running.load(Ordering::Relaxed) {
            assert!(
                start.elapsed() < StdDuration::from_secs(2),
                "the loop kept running after its device died"
            );
            thread::sleep(StdDuration::from_millis(10));
        }
    }

    #[test]
    fn the_shutdown_flag_stops_the_loop() {
        #[cfg(feature = "control-stats")]
        let _guard = counter_guard();
        let mut harness = Harness::spawn();

        harness.running.store(false, Ordering::Relaxed);

        let start = std::time::Instant::now();
        let handle = harness.handle.take().unwrap();
        handle.join().expect("stack loop panicked");
        // The scripted wait sleeps up to the loop's idle maximum; anything
        // much past that means the flag is not being consulted.
        assert!(
            start.elapsed() < StdDuration::from_secs(3),
            "the loop outlived the shutdown flag by {:?}",
            start.elapsed()
        );
    }

    /// A loop that exits with connections still open must reset the
    /// process-global count, whatever platform it ran on.
    #[cfg(feature = "control-stats")]
    #[test]
    fn the_connection_count_does_not_survive_the_loop() {
        let _guard = counter_guard();
        super::super::traffic::reset_active_connections();

        let mut harness = Harness::spawn();

        harness
            .script_tx
            .send(Script::Packet(syn_packet(20003)))
            .unwrap();
        let _conn = recv_within(&mut harness.conn_rx, "the connection to reach tokio");
        assert_eq!(super::super::traffic::active_connections(), 1);

        harness
            .script_tx
            .send(Script::Die(io::ErrorKind::UnexpectedEof))
            .unwrap();

        // `running` goes false at the failure site, inside the loop; the
        // counter reset runs later, on the way out of the stack function. A
        // loaded runner can schedule this thread into that gap, so the count
        // is polled to the same deadline rather than asserted the instant the
        // flag flips -- what the test owes the loop is "the count does not
        // survive the exit", not "the exit is atomic".
        let start = std::time::Instant::now();
        while harness.running.load(Ordering::Relaxed)
            || super::super::traffic::active_connections() != 0
        {
            assert!(
                start.elapsed() < StdDuration::from_secs(2),
                "the loop exited but the connection count survived it: {}",
                super::super::traffic::active_connections()
            );
            thread::sleep(StdDuration::from_millis(10));
        }
    }

    /// The batched-ingress contract the loop depends on: `store_packet` queues
    /// rather than overwrites, so a whole read batch survives to be drained by
    /// one `poll`. A single-slot device would keep only the last, which is the
    /// regression this guards.
    #[test]
    fn stored_packets_are_queued_and_drained_in_order() {
        let mut device = ScriptedDevice {
            rx: std_mpsc::channel().1,
            queued: Mutex::new(VecDeque::new()),
            written: Arc::new(Mutex::new(Vec::new())),
            pending: VecDeque::new(),
            mtu: 1500,
        };

        assert!(!device.has_pending());
        for port in [1u16, 2, 3] {
            let mut buffer = PooledBuffer::with_capacity(device.mtu + 4);
            buffer.extend_from_slice(&syn_packet(port));
            device.store_packet(buffer);
        }
        assert!(device.has_pending());

        // smoltcp drains through `Device::receive`; each stored packet must
        // come back, in order, before the device reports empty.
        let mut drained = Vec::new();
        while let Some((rx, _tx)) = Device::receive(&mut device, SmolInstant::from_millis(0)) {
            let port = smoltcp::phy::RxToken::consume(rx, |frame| {
                let ip = Ipv4Packet::new_checked(frame).unwrap();
                TcpPacket::new_checked(ip.payload()).unwrap().src_port()
            });
            drained.push(port);
        }
        assert_eq!(
            drained,
            vec![1, 2, 3],
            "the whole batch must survive in order"
        );
        assert!(!device.has_pending());
    }

    /// End to end: a burst of SYNs read in one batch and polled once must each
    /// become a connection. None may be dropped on the way through the loop.
    #[test]
    fn every_syn_in_a_burst_becomes_a_connection() {
        #[cfg(feature = "control-stats")]
        let _guard = counter_guard();
        let mut harness = Harness::spawn();

        const BURST: u16 = 8;
        for i in 0..BURST {
            harness
                .script_tx
                .send(Script::Packet(syn_packet(30000 + i)))
                .unwrap();
        }

        let mut seen = std::collections::HashSet::new();
        for _ in 0..BURST {
            let conn = recv_within(&mut harness.conn_rx, "a connection from the burst");
            seen.insert(conn.local_addr.port());
        }
        assert_eq!(
            seen.len(),
            BURST as usize,
            "every SYN in the batch must open its own connection"
        );

        harness.stop();
    }

    /// A `notify` that lands while the thread is between iterations — before it
    /// arms — must make the coming `arm` decline to sleep, not be lost.
    #[test]
    fn notify_before_arm_makes_arm_decline_to_sleep() {
        let woke = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let notifier = {
            let woke = woke.clone();
            StackNotifier::new(Arc::new(move || {
                woke.fetch_add(1, Ordering::SeqCst);
            }))
        };

        // Not armed yet: notify records pending but does not touch the wake
        // primitive, since the thread is awake.
        notifier.notify();
        assert_eq!(woke.load(Ordering::SeqCst), 0);
        // The thread now goes to arm: it must see the pending flag and refuse
        // to sleep.
        assert!(
            notifier.arm(),
            "arm must see the earlier notify and skip the sleep"
        );
        notifier.disarm();

        // With nothing pending, the next arm sleeps.
        assert!(!notifier.arm());
        notifier.disarm();
    }

    /// A `notify` that lands while the thread is parked must fire the wake
    /// primitive exactly once, however many notifies pile up before it wakes.
    #[test]
    fn notify_while_armed_wakes_once() {
        let woke = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let notifier = {
            let woke = woke.clone();
            StackNotifier::new(Arc::new(move || {
                woke.fetch_add(1, Ordering::SeqCst);
            }))
        };

        // The thread arms and, with nothing pending, commits to sleeping.
        assert!(!notifier.arm());
        // Three notifies arrive while it is parked: the first fires the wake,
        // the rest coalesce because `armed` is already cleared.
        notifier.notify();
        notifier.notify();
        notifier.notify();
        assert_eq!(woke.load(Ordering::SeqCst), 1, "a burst must cost one wake");

        notifier.disarm();
    }
}
