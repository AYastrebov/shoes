//! Virtual network stack for AmneziaWG outbound connections.
//!
//! Uses smoltcp to provide a virtual TCP/IP stack that emits IP packets
//! for the AmneziaWG tunnel to encapsulate, and accepts decapsulated
//! IP packets from the tunnel.
//!
//! TCP connections use the TcpConnectionControl ring-buffer+waker pattern
//! (from tun/tcp_conn.rs) for bridging smoltcp's synchronous sockets to
//! tokio's async traits.

use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

use log::{debug, info, warn};
use parking_lot::Mutex;
use smoltcp::iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{
    CongestionControl, Socket as SmolTcpSocket, SocketBuffer as TcpSocketBuffer, State as TcpState,
};
use smoltcp::socket::udp::Socket as SmolUdpSocket;
use smoltcp::socket::udp::{PacketBuffer as UdpPacketBuffer, PacketMetadata as UdpPacketMetadata};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;
use tokio::sync::mpsc;

use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncShutdownMessage,
    AsyncStream, AsyncWriteMessage,
};

// ---------------------------------------------------------------------------
// Virtual smoltcp device
// ---------------------------------------------------------------------------

struct VirtualDevice {
    rx_queue: Vec<Vec<u8>>,
    /// RefCell avoids a raw pointer: smoltcp's `receive()` needs to hand out
    /// both an RxToken (consuming from rx_queue) and a TxToken (pushing to
    /// tx_queue) simultaneously.  RefCell lets us borrow tx_queue separately
    /// through a shared reference while rx_queue is being mutated.
    tx_queue: RefCell<std::collections::VecDeque<Vec<u8>>>,
    /// How many more packets this poll may emit -- the outbound channel's free
    /// slots, set by the run loop before each `iface.poll`. When the queue
    /// reaches it, `transmit` refuses the token: smoltcp keeps the segment in
    /// its socket buffer and retries on a later poll, exactly as it would with
    /// a busy NIC ring. That refusal is the device's backpressure, and it is
    /// what makes overflowing the outbound channel impossible no matter how
    /// many sockets burst their windows into one poll -- without it, an unpaced
    /// window-sized burst overflowed the channel, and Cubic read the dropped
    /// segments as congestion (the bimodal upload collapse ROADMAP.md records).
    tx_budget: usize,
    mtu: usize,
}

impl VirtualDevice {
    fn new(mtu: usize) -> Self {
        Self {
            rx_queue: Vec::new(),
            tx_queue: RefCell::new(std::collections::VecDeque::new()),
            tx_budget: 0,
            mtu,
        }
    }

    fn has_pending_tx(&self) -> bool {
        !self.tx_queue.borrow().is_empty()
    }
}

impl Device for VirtualDevice {
    type RxToken<'a> = VirtualRxToken;
    type TxToken<'a> = VirtualTxToken<'a>;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.rx_queue.is_empty() {
            return None;
        }
        let packet = self.rx_queue.remove(0);
        // The paired TxToken ignores the budget: it exists so smoltcp can
        // answer what it is receiving (an RST, an ICMP reply), and refusing it
        // would drop the reply entirely rather than defer it. The overshoot is
        // at most one packet per inbound packet processed.
        Some((
            VirtualRxToken { buffer: packet },
            VirtualTxToken {
                tx_queue: &self.tx_queue,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        // See `tx_budget`: refusing the token here is the backpressure that
        // keeps a window-sized burst inside the socket's own buffer instead of
        // overflowing the outbound channel.
        if self.tx_queue.borrow().len() >= self.tx_budget {
            return None;
        }
        Some(VirtualTxToken {
            tx_queue: &self.tx_queue,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

struct VirtualRxToken {
    buffer: Vec<u8>,
}

impl RxToken for VirtualRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

struct VirtualTxToken<'a> {
    tx_queue: &'a RefCell<std::collections::VecDeque<Vec<u8>>>,
}

impl TxToken for VirtualTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        self.tx_queue.borrow_mut().push_back(buffer);
        result
    }
}

// ---------------------------------------------------------------------------
// TCP: shared control buffer (ring-buffer + waker pattern)
// ---------------------------------------------------------------------------

/// The socket's receive window.
///
/// This socket's peer is a server on the internet, so this is a
/// bandwidth-delay product rather than local buffering: it is the ceiling on
/// download throughput, `window / RTT`, and smoltcp never grows it. See
/// src/buffer_sizing.rs.
const TCP_RX_WINDOW: usize = crate::buffer_sizing::default_remote_rx_window_size();

/// The socket's in-flight, unacknowledged send data.
///
/// The mirror of the receive window: the ceiling on upload throughput,
/// `window / RTT`. It scales safely because `VirtualDevice::transmit` refuses
/// tokens once the outbound channel is full -- smoltcp does not pace, and
/// without that backpressure an unpaced window-sized burst overflowed the
/// channel and read back as congestion. See src/buffer_sizing.rs for the
/// sizing and the measurements.
const TCP_TX_WINDOW: usize = crate::buffer_sizing::default_remote_tx_window_size();

/// The ring buffers between this socket and the async side, which are local and
/// so need only cover scheduling jitter.
const TCP_PIPE_BUF: usize = crate::buffer_sizing::default_local_buffer_size();

/// Payload bytes each virtual UDP socket buffers per direction.
///
/// UDP has no window to keep open, and datagrams through the tunnel are
/// MTU-bounded in practice, so the 64 KiB this replaced — 128 KiB per session,
/// before metadata — was sized for a datagram nothing sends.
const UDP_PAYLOAD_BUF: usize = crate::buffer_sizing::default_local_buffer_size();

/// Datagrams each virtual UDP socket queues per direction.
const UDP_PACKET_SLOTS: usize = 32;

/// Shared state between the smoltcp poll loop and the async VirtualTcpStream.
struct TcpControl {
    /// Data written by async side, consumed by smoltcp send.
    send_buf: smoltcp::storage::RingBuffer<'static, u8>,
    send_waker: Option<Waker>,
    send_closed: bool,

    /// Data written by smoltcp recv, consumed by async side.
    recv_buf: smoltcp::storage::RingBuffer<'static, u8>,
    recv_waker: Option<Waker>,
    recv_closed: bool,

    /// The async side is gone -- VirtualTcpStream was dropped. The poll
    /// loop aborts the socket (RST, like a real socket dropped with the
    /// connection up) and frees its slot. Without this, a stream dropped
    /// without shutdown left the socket Established forever: the peer
    /// answers keepalive probes, so the idle timeout never fires, and
    /// each leak pinned that socket's whole buffer set plus one slot of
    /// MAX_TCP_SOCKETS until the leaks alone had the cap refusing every
    /// new connect.
    dropped: bool,
}

// ---------------------------------------------------------------------------
// Netstack requests
// ---------------------------------------------------------------------------

pub enum NetStackRequest {
    ConnectTcp {
        target: SocketAddr,
        reply: tokio::sync::oneshot::Sender<std::io::Result<VirtualTcpStream>>,
    },
    ConnectUdp {
        target: SocketAddr,
        reply: tokio::sync::oneshot::Sender<std::io::Result<VirtualUdpStream>>,
    },
}

// ---------------------------------------------------------------------------
// Tracking structs inside the poll loop
// ---------------------------------------------------------------------------

struct ActiveTcp {
    control: Arc<Mutex<TcpControl>>,
}

struct ActiveUdp {
    target: IpEndpoint,
    outgoing_rx: mpsc::Receiver<Vec<u8>>,
    incoming_tx: mpsc::Sender<Vec<u8>>,
}

struct PendingTcp {
    control: Arc<Mutex<TcpControl>>,
    notify: Arc<Notify>,
    reply: tokio::sync::oneshot::Sender<std::io::Result<VirtualTcpStream>>,
    target: SocketAddr,
    /// When the connect gives up. smoltcp has no SYN retry limit -- with
    /// no timeout it retransmits forever -- so an unreachable server
    /// would otherwise park the caller for good and pin this entry's
    /// buffers with it.
    deadline: std::time::Instant,
}

/// How long a virtual TCP connect may wait for the peer. Under the
/// forwarder's 60 s budget, and near what mobile OS stacks allow a SYN.
const TCP_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Sockets this stack will hold at once, pending and established
/// together. Each one owns a receive window, a send buffer and two local
/// buffers -- 576 KiB inside a Network Extension, but 1.3 MiB on Android
/// and 4.4 MiB on desktop, since the window is sized per platform (see
/// `crate::buffer_sizing`). At any of those an unbounded map is an OOM;
/// the TUN stack has the same cap on its side.
const MAX_TCP_SOCKETS: usize = crate::buffer_sizing::default_max_connections();

/// UDP sessions this stack holds at once.
///
/// A quarter of the TCP ceiling rather than the same number, because the two
/// are not alike in either cost or count. A UDP session owns two
/// `UdpPacketBuffer`s of [`UDP_PAYLOAD_BUF`] -- 64 KiB the pair on Android --
/// and unlike a TCP receive window those are packet buffers that go resident
/// as soon as anything is queued in them. And real UDP through a tunnel is
/// DNS, which is transient, plus a browser's QUIC connections, which number in
/// the tens rather than the hundreds. 64 sessions is 4 MiB on mobile, against
/// an iOS extension killed at roughly 50 MB.
///
/// Any number here is better than the none this had. `initiate_tcp` has
/// refused past its ceiling since it was written, on the reasoning above
/// `MAX_TCP_SOCKETS` that an unbounded map is an OOM; `initiate_udp` was
/// simply left out of it, so a QUIC-heavy page could allocate without limit.
const MAX_UDP_SOCKETS: usize = MAX_TCP_SOCKETS / 4;

// ---------------------------------------------------------------------------
// VirtualNetStack
// ---------------------------------------------------------------------------

pub struct VirtualNetStack {
    ip_to_tunnel: mpsc::Sender<Vec<u8>>,
    ip_from_tunnel: mpsc::Receiver<Vec<u8>>,
    iface: Interface,
    device: VirtualDevice,
    sockets: SocketSet<'static>,
    pending_tcp: HashMap<SocketHandle, PendingTcp>,
    active_tcp: HashMap<SocketHandle, ActiveTcp>,
    active_udp: HashMap<SocketHandle, ActiveUdp>,
    /// Every packet this stack offers the outbound queue, delivered or
    /// dropped. The tunnel's liveness watchdog reads it as its evidence of
    /// demand -- from here, upstream of the drain loop it is watching,
    /// because a counter the drain loop increments stops when the drain
    /// loop does. See the field doc on `TunnelRuntime::outbound_offered`.
    outbound_offered: Arc<AtomicUsize>,
}

impl VirtualNetStack {
    pub fn new(
        local_addresses: &[(IpAddr, u8)],
        mtu: u16,
        ip_to_tunnel: mpsc::Sender<Vec<u8>>,
        ip_from_tunnel: mpsc::Receiver<Vec<u8>>,
        outbound_offered: Arc<AtomicUsize>,
    ) -> Self {
        let mut device = VirtualDevice::new(mtu as usize);

        let mut config = InterfaceConfig::new(HardwareAddress::Ip);
        config.random_seed = rand::random();
        let mut iface = Interface::new(config, &mut device, crate::util::smol_now());

        let cidrs: Vec<IpCidr> = local_addresses
            .iter()
            .map(|(addr, prefix)| {
                let ip = match addr {
                    IpAddr::V4(v4) => IpAddress::Ipv4(*v4),
                    IpAddr::V6(v6) => IpAddress::Ipv6(*v6),
                };
                IpCidr::new(ip, *prefix)
            })
            .collect();

        iface.update_ip_addrs(|addrs| {
            for cidr in &cidrs {
                addrs.push(*cidr).ok();
            }
        });

        for (addr, _) in local_addresses {
            match addr {
                IpAddr::V4(_) => {
                    iface
                        .routes_mut()
                        .add_default_ipv4_route(smoltcp::wire::Ipv4Address::new(0, 0, 0, 1))
                        .ok();
                }
                IpAddr::V6(_) => {
                    iface
                        .routes_mut()
                        .add_default_ipv6_route(smoltcp::wire::Ipv6Address::new(
                            0, 0, 0, 0, 0, 0, 0, 1,
                        ))
                        .ok();
                }
            }
        }

        Self {
            ip_to_tunnel,
            ip_from_tunnel,
            iface,
            device,
            sockets: SocketSet::new(vec![]),
            pending_tcp: HashMap::new(),
            active_tcp: HashMap::new(),
            active_udp: HashMap::new(),
            outbound_offered,
        }
    }

    // ------------------------------------------------------------------
    // Main event loop
    // ------------------------------------------------------------------

    pub async fn run(mut self, mut conn_rx: mpsc::Receiver<NetStackRequest>) {
        loop {
            // Use smoltcp's poll_delay to determine how long to sleep,
            // capped at 10ms to balance CPU usage vs throughput (matches
            // the existing TUN stack in tcp_stack_direct.rs).
            //
            // While the outbound channel is the constraint -- deferred packets
            // waiting, or every slot taken -- poll on a 1ms tick instead: the
            // encapsulate task frees slots at its own pace and holds no waker
            // to this loop, so a 10ms sleep here would quantize the send rate
            // to a channel-full per 10ms.
            let tx_backlogged = self.device.has_pending_tx() || self.ip_to_tunnel.capacity() == 0;
            let cap_ms = if tx_backlogged { 1 } else { 10 };
            let delay = self
                .iface
                .poll_delay(crate::util::smol_now(), &self.sockets)
                .map(|d| std::time::Duration::from_millis(d.total_millis().min(cap_ms)))
                .unwrap_or(std::time::Duration::from_millis(cap_ms));
            let sleep = tokio::time::sleep(delay);

            tokio::select! {
                request = conn_rx.recv() => {
                    match request {
                        Some(NetStackRequest::ConnectTcp { target, reply }) => {
                            self.initiate_tcp(target, reply);
                        }
                        Some(NetStackRequest::ConnectUdp { target, reply }) => {
                            self.initiate_udp(target, reply);
                        }
                        None => {
                            debug!("AmneziaWG netstack: request channel closed");
                            break;
                        }
                    }
                }
                packet = self.ip_from_tunnel.recv() => {
                    match packet {
                        Some(packet) => self.device.rx_queue.push(packet),
                        // The decapsulate task owns the only sender, so a
                        // closed channel means the tunnel's receive path is
                        // gone and nothing will ever arrive again. Matched
                        // explicitly rather than left as a `Some(..)` pattern:
                        // a failed pattern only disables the branch, so this
                        // loop went on polling smoltcp and servicing every
                        // socket at up to 100 Hz for the life of the process,
                        // with no possible input. On a phone that is a wakeup
                        // source that never stops.
                        //
                        // Returning drops `request_rx`, which closes the
                        // sender the connector holds, which is what its
                        // `is_closed()` check rebuilds on.
                        None => {
                            info!("AmneziaWG netstack: tunnel receive path gone, stopping");
                            return;
                        }
                    }
                }
                _ = sleep => {}
            }

            // Poll smoltcp. The budget hands the device the channel's free
            // slots, less what earlier polls already emitted and the channel
            // has not yet accepted; `transmit` refuses tokens past it.
            self.device.tx_budget = self.ip_to_tunnel.capacity();
            let now = crate::util::smol_now();
            self.iface.poll(now, &mut self.device, &mut self.sockets);

            // Flush outbound IP packets to the tunnel. What the channel will
            // not take stays queued for the next pass rather than being
            // dropped: a drop here is invisible to the peer, so smoltcp's
            // congestion control would read it as path loss and collapse --
            // the bimodal upload ROADMAP.md records. Each attempt counts as
            // demand (a deferred packet counts again when retried), which is
            // what keeps the liveness watchdog seeing an active tunnel while
            // the channel is jammed.
            {
                let mut tx_queue = self.device.tx_queue.borrow_mut();
                while let Some(packet) = tx_queue.pop_front() {
                    self.outbound_offered.fetch_add(1, Ordering::Relaxed);
                    match self.ip_to_tunnel.try_send(packet) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(packet)) => {
                            tx_queue.push_front(packet);
                            break;
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => break,
                    }
                }
            }

            // Service TCP connections
            self.service_pending_tcp();
            self.service_active_tcp();

            // Service UDP sockets
            self.service_active_udp();
        }
    }

    // ------------------------------------------------------------------
    // TCP initiation
    // ------------------------------------------------------------------

    fn initiate_tcp(
        &mut self,
        target: SocketAddr,
        reply: tokio::sync::oneshot::Sender<std::io::Result<VirtualTcpStream>>,
    ) {
        if self.pending_tcp.len() + self.active_tcp.len() >= MAX_TCP_SOCKETS {
            let _ = reply.send(Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("virtual TCP socket limit reached ({MAX_TCP_SOCKETS})"),
            )));
            return;
        }

        let rx_buf = TcpSocketBuffer::new(vec![0u8; TCP_RX_WINDOW]);
        let tx_buf = TcpSocketBuffer::new(vec![0u8; TCP_TX_WINDOW]);
        let mut socket = SmolTcpSocket::new(rx_buf, tx_buf);
        socket.set_nagle_enabled(false);
        socket.set_congestion_control(CongestionControl::Cubic);
        // Matched to the TUN stack (stack_common.rs): probe an idle peer,
        // and abort one that stops answering. Without a timeout smoltcp
        // waits on a dead peer forever.
        socket.set_keep_alive(Some(smoltcp::time::Duration::from_secs(28)));
        socket.set_timeout(Some(smoltcp::time::Duration::from_secs(7200)));

        let local_port = allocate_ephemeral_port();
        let remote = to_smol_endpoint(target);

        if let Err(e) = socket.connect(self.iface.context(), remote, local_port) {
            let _ = reply.send(Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("smoltcp connect: {}", e),
            )));
            return;
        }

        let control = Arc::new(Mutex::new(TcpControl {
            send_buf: smoltcp::storage::RingBuffer::new(vec![0u8; TCP_PIPE_BUF]),
            send_waker: None,
            send_closed: false,
            recv_buf: smoltcp::storage::RingBuffer::new(vec![0u8; TCP_PIPE_BUF]),
            recv_waker: None,
            recv_closed: false,
            dropped: false,
        }));
        let notify = Arc::new(Notify::new());

        let handle = self.sockets.add(socket);
        self.pending_tcp.insert(
            handle,
            PendingTcp {
                control,
                notify,
                reply,
                target,
                deadline: std::time::Instant::now() + TCP_CONNECT_TIMEOUT,
            },
        );
    }

    fn service_pending_tcp(&mut self) {
        self.service_pending_tcp_at(std::time::Instant::now());
    }

    // Time is a parameter so tests reach the deadline without waiting it out.
    fn service_pending_tcp_at(&mut self, now: std::time::Instant) {
        enum Outcome {
            Established,
            Failed,
            TimedOut,
        }
        let mut completed = Vec::new();

        for (handle, pending) in &self.pending_tcp {
            let socket = self.sockets.get::<SmolTcpSocket>(*handle);
            match socket.state() {
                TcpState::Established => completed.push((*handle, Outcome::Established)),
                TcpState::Closed | TcpState::TimeWait => completed.push((*handle, Outcome::Failed)),
                _ if now >= pending.deadline => completed.push((*handle, Outcome::TimedOut)),
                _ => {}
            }
        }

        for (handle, outcome) in completed {
            let pending = self.pending_tcp.remove(&handle).unwrap();
            match outcome {
                Outcome::Established => {
                    let stream = VirtualTcpStream {
                        control: pending.control.clone(),
                        notify: pending.notify.clone(),
                    };
                    self.active_tcp.insert(
                        handle,
                        ActiveTcp {
                            control: pending.control,
                        },
                    );
                    let _ = pending.reply.send(Ok(stream));
                }
                Outcome::Failed => {
                    let _ = pending.reply.send(Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        format!("TCP to {} failed", pending.target),
                    )));
                    self.sockets.remove(handle);
                }
                Outcome::TimedOut => {
                    let _ = pending.reply.send(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!(
                            "TCP connect to {} got no answer in {}s",
                            pending.target,
                            TCP_CONNECT_TIMEOUT.as_secs()
                        ),
                    )));
                    self.sockets.remove(handle);
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // TCP data transfer
    // ------------------------------------------------------------------

    fn service_active_tcp(&mut self) {
        let mut to_remove = Vec::new();

        for (handle, active) in &self.active_tcp {
            let socket = self.sockets.get_mut::<SmolTcpSocket>(*handle);
            let mut ctrl = active.control.lock();

            // The async side is gone; nobody will read or write again.
            // Abort rather than close: no FIN handshake to wait out, so
            // the slot frees this pass (the Closed check below removes
            // it). smoltcp's abort sends nothing itself -- the peer's
            // next segment finds no socket and draws the interface's RST.
            if ctrl.dropped {
                socket.abort();
            }

            // smoltcp recv -> ctrl.recv_buf (data for the async reader)
            if socket.can_recv() && !ctrl.recv_buf.is_full() {
                let _ = socket.recv(|data| {
                    let n = ctrl.recv_buf.enqueue_slice(data);
                    (n, ())
                });
                // Wake the async reader
                if let Some(w) = ctrl.recv_waker.take() {
                    w.wake();
                }
            }

            // ctrl.send_buf -> smoltcp send (data from the async writer)
            if socket.can_send() && !ctrl.send_buf.is_empty() {
                let _ = socket.send(|buf| {
                    let n = ctrl.send_buf.dequeue_slice(buf);
                    (n, ())
                });
                // Wake the async writer (buffer space freed)
                if let Some(w) = ctrl.send_waker.take() {
                    w.wake();
                }
            }

            // Handle send-side close: async side requested shutdown
            if ctrl.send_closed && ctrl.send_buf.is_empty() && socket.send_queue() == 0 {
                socket.close();
            }

            // Detect recv-side close from remote
            if !socket.may_recv() && !ctrl.recv_closed {
                ctrl.recv_closed = true;
                if let Some(w) = ctrl.recv_waker.take() {
                    w.wake();
                }
            }

            // Detect fully closed
            if socket.state() == TcpState::Closed || socket.state() == TcpState::TimeWait {
                ctrl.recv_closed = true;
                ctrl.send_closed = true;
                if let Some(w) = ctrl.recv_waker.take() {
                    w.wake();
                }
                if let Some(w) = ctrl.send_waker.take() {
                    w.wake();
                }
                to_remove.push(*handle);
            }
        }

        for handle in to_remove {
            self.active_tcp.remove(&handle);
            self.sockets.remove(handle);
        }
    }

    // ------------------------------------------------------------------
    // UDP initiation + data transfer
    // ------------------------------------------------------------------

    fn initiate_udp(
        &mut self,
        target: SocketAddr,
        reply: tokio::sync::oneshot::Sender<std::io::Result<VirtualUdpStream>>,
    ) {
        if self.active_udp.len() >= MAX_UDP_SOCKETS {
            let _ = reply.send(Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("virtual UDP socket limit reached ({MAX_UDP_SOCKETS})"),
            )));
            return;
        }

        let rx_buf = UdpPacketBuffer::new(
            vec![UdpPacketMetadata::EMPTY; UDP_PACKET_SLOTS],
            vec![0u8; UDP_PAYLOAD_BUF],
        );
        let tx_buf = UdpPacketBuffer::new(
            vec![UdpPacketMetadata::EMPTY; UDP_PACKET_SLOTS],
            vec![0u8; UDP_PAYLOAD_BUF],
        );
        let mut socket = SmolUdpSocket::new(rx_buf, tx_buf);

        let local_port = allocate_ephemeral_port();
        if let Err(e) = socket.bind(local_port) {
            let _ = reply.send(Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!("smoltcp UDP bind: {}", e),
            )));
            return;
        }

        let handle = self.sockets.add(socket);
        let endpoint = to_smol_endpoint(target);

        let (outgoing_tx, outgoing_rx) = mpsc::channel::<Vec<u8>>(128);
        let (incoming_tx, incoming_rx) = mpsc::channel::<Vec<u8>>(128);

        self.active_udp.insert(
            handle,
            ActiveUdp {
                target: endpoint,
                outgoing_rx,
                incoming_tx,
            },
        );

        let stream = VirtualUdpStream {
            send_tx: outgoing_tx,
            recv_rx: incoming_rx,
        };

        let _ = reply.send(Ok(stream));
    }

    fn service_active_udp(&mut self) {
        let mut to_remove = Vec::new();

        for (handle, active) in &mut self.active_udp {
            let socket = self.sockets.get_mut::<SmolUdpSocket>(*handle);

            // Drain outgoing packets from async side -> smoltcp send.
            //
            // The `can_send` test gates the dequeue rather than the send. It
            // used to sit inside the loop body, after `try_recv` had already
            // taken the datagram, so a socket that could not send discarded
            // every datagram in the channel instead of leaving them queued --
            // and said so in a `debug!` that release builds compile out.
            while socket.can_send() {
                let Ok(data) = active.outgoing_rx.try_recv() else {
                    break;
                };
                if let Err(e) = socket.send_slice(&data, active.target) {
                    debug!("AmneziaWG UDP send error: {}", e);
                }
            }

            // Drain incoming packets from smoltcp recv -> async side
            while socket.can_recv() {
                match socket.recv() {
                    Ok((data, _endpoint)) => {
                        let _ = active.incoming_tx.try_send(data.to_vec());
                    }
                    Err(_) => break,
                }
            }

            // If the sender was dropped, mark for cleanup
            if active.outgoing_rx.is_closed() && active.incoming_tx.is_closed() {
                to_remove.push(*handle);
            }
        }

        for handle in to_remove {
            self.active_udp.remove(&handle);
            self.sockets.remove(handle);
        }
    }
}

// ---------------------------------------------------------------------------
// VirtualTcpStream: AsyncRead + AsyncWrite + AsyncPing => AsyncStream
// ---------------------------------------------------------------------------

pub struct VirtualTcpStream {
    control: Arc<Mutex<TcpControl>>,
    notify: Arc<Notify>,
}

/// See `TcpControl::dropped`: without this, a stream dropped without
/// shutdown pinned its socket, buffers, and cap slot forever.
impl Drop for VirtualTcpStream {
    fn drop(&mut self) {
        self.control.lock().dropped = true;
    }
}

impl AsyncRead for VirtualTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut ctrl = self.control.lock();

        if !ctrl.recv_buf.is_empty() {
            let unfilled = buf.initialize_unfilled();
            let n = ctrl.recv_buf.dequeue_slice(unfilled);
            buf.advance(n);
            // Notify netstack that buffer space is available
            drop(ctrl);
            self.notify.notify_waiters();
            return Poll::Ready(Ok(()));
        }

        if ctrl.recv_closed {
            return Poll::Ready(Ok(())); // EOF
        }

        // Register waker
        ctrl.recv_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for VirtualTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut ctrl = self.control.lock();

        if ctrl.send_closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }

        if !ctrl.send_buf.is_full() {
            let n = ctrl.send_buf.enqueue_slice(buf);
            drop(ctrl);
            self.notify.notify_waiters();
            return Poll::Ready(Ok(n));
        }

        ctrl.send_waker = Some(cx.waker().clone());
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut ctrl = self.control.lock();
        ctrl.send_closed = true;
        drop(ctrl);
        self.notify.notify_waiters();
        Poll::Ready(Ok(()))
    }
}

impl AsyncPing for VirtualTcpStream {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl Unpin for VirtualTcpStream {}

impl AsyncStream for VirtualTcpStream {}

// ---------------------------------------------------------------------------
// VirtualUdpStream: AsyncMessageStream
// ---------------------------------------------------------------------------

pub struct VirtualUdpStream {
    send_tx: mpsc::Sender<Vec<u8>>,
    recv_rx: mpsc::Receiver<Vec<u8>>,
}

impl AsyncReadMessage for VirtualUdpStream {
    fn poll_read_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.recv_rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let unfilled = buf.initialize_unfilled();
                let n = data.len().min(unfilled.len());
                unfilled[..n].copy_from_slice(&data[..n]);
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWriteMessage for VirtualUdpStream {
    fn poll_write_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.send_tx.try_send(buf.to_vec()) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(mpsc::error::TrySendError::Full(_)) => {
                // Drop the packet — UDP is lossy
                warn!("AmneziaWG: UDP send buffer full, dropping packet");
                Poll::Ready(Ok(()))
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
            }
        }
    }
}

impl AsyncFlushMessage for VirtualUdpStream {
    fn poll_flush_message(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncShutdownMessage for VirtualUdpStream {
    fn poll_shutdown_message(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncPing for VirtualUdpStream {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl Unpin for VirtualUdpStream {}

impl AsyncMessageStream for VirtualUdpStream {}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn to_smol_endpoint(addr: SocketAddr) -> IpEndpoint {
    IpEndpoint::new(
        match addr.ip() {
            IpAddr::V4(v4) => IpAddress::Ipv4(v4),
            IpAddr::V6(v6) => IpAddress::Ipv6(v6),
        },
        addr.port(),
    )
}

static NEXT_PORT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(40000);

fn allocate_ephemeral_port() -> u16 {
    let port = NEXT_PORT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if port == 0 || port == u16::MAX {
        NEXT_PORT.store(40000, std::sync::atomic::Ordering::Relaxed);
        40000
    } else {
        port
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_smol_endpoint_v4() {
        let addr: SocketAddr = "1.2.3.4:443".parse().unwrap();
        let ep = to_smol_endpoint(addr);
        assert_eq!(ep.port, 443);
        assert_eq!(
            ep.addr,
            IpAddress::Ipv4(smoltcp::wire::Ipv4Address::new(1, 2, 3, 4))
        );
    }

    #[test]
    fn test_to_smol_endpoint_v6() {
        let addr: SocketAddr = "[::1]:8080".parse().unwrap();
        let ep = to_smol_endpoint(addr);
        assert_eq!(ep.port, 8080);
        assert_eq!(
            ep.addr,
            IpAddress::Ipv6(smoltcp::wire::Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 1))
        );
    }

    #[test]
    fn test_allocate_ephemeral_port_increments() {
        let p1 = allocate_ephemeral_port();
        let p2 = allocate_ephemeral_port();
        assert_eq!(p2, p1 + 1);
    }

    fn stack() -> (VirtualNetStack, mpsc::Receiver<Vec<u8>>) {
        let (to_tunnel_tx, to_tunnel_rx) = mpsc::channel(16);
        let (_from_tunnel_tx, from_tunnel_rx) = mpsc::channel::<Vec<u8>>(16);
        let stack = VirtualNetStack::new(
            &[("10.0.0.2".parse().unwrap(), 32)],
            1400,
            to_tunnel_tx,
            from_tunnel_rx,
            Arc::new(AtomicUsize::new(0)),
        );
        (stack, to_tunnel_rx)
    }

    /// smoltcp has no SYN retry limit, so without the deadline a connect
    /// nobody answers parked the caller forever and pinned a whole
    /// buffer set per stuck flow -- a browser retrying against a dead
    /// tunnel was an OOM on the extension's memory cap.
    #[test]
    fn a_connect_nobody_answers_fails_at_the_deadline() {
        let (mut stack, _tunnel_rx) = stack();
        let (reply_tx, mut reply_rx) = tokio::sync::oneshot::channel();
        stack.initiate_tcp("192.0.2.1:443".parse().unwrap(), reply_tx);

        let now = std::time::Instant::now();
        stack.service_pending_tcp_at(now);
        assert!(reply_rx.try_recv().is_err(), "failed before the deadline");
        assert_eq!(stack.pending_tcp.len(), 1);

        stack.service_pending_tcp_at(now + TCP_CONNECT_TIMEOUT + std::time::Duration::from_secs(1));
        let err = reply_rx
            .try_recv()
            .expect("the deadline must resolve the connect")
            .map(|_| ())
            .expect_err("nobody answered, so it cannot succeed");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        // The entry and its buffers are gone, not parked.
        assert!(stack.pending_tcp.is_empty());
        assert!(stack.sockets.iter().next().is_none());
    }

    /// UDP had no budget at all: `initiate_tcp` refused past its ceiling
    /// from the day it was written and `initiate_udp` was left out, so a
    /// QUIC-heavy page could allocate two packet buffers per flow without
    /// limit -- 64 KiB a session on Android, against an extension the system
    /// kills at roughly 50 MB.
    #[test]
    fn the_udp_budget_refuses_the_overflow_session() {
        let (mut stack, _tunnel_rx) = stack();

        for i in 0..MAX_UDP_SOCKETS {
            let (reply_tx, mut reply_rx) = tokio::sync::oneshot::channel();
            stack.initiate_udp(format!("192.0.2.1:{}", 1000 + i).parse().unwrap(), reply_tx);
            assert!(
                reply_rx.try_recv().expect("a reply").is_ok(),
                "session {i} is inside the budget"
            );
        }
        assert_eq!(stack.active_udp.len(), MAX_UDP_SOCKETS);

        let (reply_tx, mut reply_rx) = tokio::sync::oneshot::channel();
        stack.initiate_udp("192.0.2.1:9999".parse().unwrap(), reply_tx);
        let err = reply_rx
            .try_recv()
            .expect("the overflow session must be answered, not parked")
            .map(|_| ())
            .expect_err("it is past the budget");
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
        // Refused, not admitted-then-trimmed: no buffers were allocated.
        assert_eq!(stack.active_udp.len(), MAX_UDP_SOCKETS);
    }

    /// The stack refuses the socket that would exceed its budget instead
    /// of growing without bound.
    #[test]
    fn the_socket_budget_refuses_the_overflow_connect() {
        let (mut stack, _tunnel_rx) = stack();
        // Occupy the whole budget cheaply: entries in pending_tcp are
        // what the cap counts, so seed the map's len without paying for
        // real sockets.
        for i in 0..MAX_TCP_SOCKETS {
            let handle = stack.sockets.add(SmolTcpSocket::new(
                TcpSocketBuffer::new(vec![0u8; 1]),
                TcpSocketBuffer::new(vec![0u8; 1]),
            ));
            stack.pending_tcp.insert(
                handle,
                PendingTcp {
                    control: Arc::new(Mutex::new(TcpControl {
                        send_buf: smoltcp::storage::RingBuffer::new(vec![0u8; 1]),
                        send_waker: None,
                        send_closed: false,
                        recv_buf: smoltcp::storage::RingBuffer::new(vec![0u8; 1]),
                        recv_waker: None,
                        recv_closed: false,
                        dropped: false,
                    })),
                    notify: Arc::new(Notify::new()),
                    reply: {
                        let (tx, _) = tokio::sync::oneshot::channel();
                        tx
                    },
                    target: format!("192.0.2.1:{}", 1 + (i % 60000)).parse().unwrap(),
                    deadline: std::time::Instant::now(),
                },
            );
        }

        let (reply_tx, mut reply_rx) = tokio::sync::oneshot::channel();
        stack.initiate_tcp("192.0.2.2:443".parse().unwrap(), reply_tx);
        let err = reply_rx
            .try_recv()
            .expect("the refusal must be immediate")
            .map(|_| ())
            .expect_err("over budget, so it cannot succeed");
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
    }
}
