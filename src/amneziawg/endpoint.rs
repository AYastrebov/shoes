//! The tunnel's own UDP socket, and how it survives the network moving.
//!
//! A phone changes networks constantly — Wi-Fi to cellular, one cell to the
//! next, a new address on the same interface after a doze wake-up. A UDP socket
//! bound to the old local address does not report this. It simply stops
//! receiving, and sends either vanish or fail with `ENETUNREACH`. The tunnel
//! does not error; it goes quiet, and stays quiet until something restarts it.
//!
//! So the socket here is replaceable. The three tunnel tasks hold this type
//! rather than a `UdpSocket`, read the live socket through a `watch` channel,
//! and are woken when it is swapped underneath them.
//!
//! A rebind is triggered two ways:
//!
//! * the app tells us, through [`crate::network_change::notify`] — the FFI call an
//!   Android `ConnectivityManager.NetworkCallback` or an iOS `NWPathMonitor`
//!   should make; and
//! * we notice, when a send fails with an error that means the route is gone.
//!   Apps that never wire up the callback still recover this way, one failed
//!   send later.
//!
//! Rebinding is enough on its own: WireGuard peers roam. The server updates the
//! endpoint it has for us as soon as an authenticated packet arrives from the
//! new address, so the first packet after the swap repairs the path without a
//! new handshake. A Phobos server is the exception: it drops everything but a
//! handshake from an address it has not seen complete one, so the tunnel
//! sends a handshake after a rebind there (`tunnel.rs`, the encapsulate loop).
//!
//! With Phobos configured, this socket is also where the obfuscation is
//! applied: [`send`](EndpointSocket::send) wraps and
//! [`recv`](EndpointSocket::recv) unwraps, so the tunnel's loops only ever
//! see WireGuard messages.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use awgtun::phobos::Unwrapped;
use log::{debug, info, warn};
use parking_lot::Mutex as ParkingMutex;
use tokio::net::UdpSocket;
use tokio::sync::{Notify, watch};

use super::phobos::PhobosLayer;

/// Wrapped-datagram buffers kept for reuse. A send takes one and puts it
/// back, so the pool holds at most one per task that sends concurrently
/// (receive, encapsulate, timer, Phobos control). This bounds it with room
/// to spare. A buffer past the bound is dropped, and one whose send was
/// cancelled is never returned. Both only cost a later allocation.
const WIRE_POOL_MAX: usize = 8;

/// One bound socket, and which one it is. The generation travels with the
/// socket in a single `watch` value, so a sender reads both from the same
/// snapshot and cannot judge one socket while sending on another.
struct Bound {
    socket: UdpSocket,
    /// 0 for the socket `connect` bound, one more for each rebind.
    generation: u64,
}

/// A UDP socket to the tunnel's peer that can be replaced underneath its users.
pub struct EndpointSocket {
    endpoint: SocketAddr,
    /// The socket in use. `watch` rather than a lock plus a notify because it
    /// closes the race between reading the socket and waiting for a change:
    /// a swap that lands in between is still seen by the next `changed()`.
    socket: watch::Sender<Arc<Bound>>,
    rebind_requested: Notify,
    /// Phobos obfuscation for every datagram, when configured.
    phobos: Option<PhobosLayer>,
    /// See [`WIRE_POOL_MAX`]. Empty and untouched without Phobos.
    wire_pool: ParkingMutex<Vec<Vec<u8>>>,
    /// The newest socket generation a handshake initiation has gone out on.
    /// Behind Phobos, a generation newer than this carries nothing but an
    /// initiation (see [`send`](Self::send)). The first socket needs none:
    /// before a session, the tunnel has nothing else to send.
    initiated_generation: AtomicU64,
}

/// Whether a WireGuard datagram is a handshake initiation: type 1 in the
/// little-endian type field, with the three reserved bytes zero.
fn is_initiation(datagram: &[u8]) -> bool {
    datagram.len() >= 4 && datagram[..4] == [1, 0, 0, 0]
}

impl crate::network_change::NetworkChangeListener for EndpointSocket {
    /// A UDP tunnel survives a network change by rebinding under its peer,
    /// which roams to the new address on the next authenticated packet.
    fn network_changed(&self) {
        self.request_rebind();
    }
}

impl EndpointSocket {
    /// Bind a socket to the peer and register it for network-change notices.
    pub async fn connect(
        endpoint: SocketAddr,
        phobos: Option<PhobosLayer>,
    ) -> std::io::Result<Arc<Self>> {
        let socket = Self::bind(endpoint).await?;
        let (tx, _) = watch::channel(Arc::new(Bound {
            socket,
            generation: 0,
        }));

        let endpoint_socket = Arc::new(Self {
            endpoint,
            socket: tx,
            rebind_requested: Notify::new(),
            phobos,
            wire_pool: ParkingMutex::new(Vec::new()),
            initiated_generation: AtomicU64::new(0),
        });

        let listener: Arc<dyn crate::network_change::NetworkChangeListener> =
            endpoint_socket.clone();
        crate::network_change::register(Arc::downgrade(&listener));

        Ok(endpoint_socket)
    }

    async fn bind(endpoint: SocketAddr) -> std::io::Result<UdpSocket> {
        let bind_addr = if endpoint.is_ipv6() {
            SocketAddr::from(([0u8; 16], 0u16))
        } else {
            SocketAddr::from(([0u8; 4], 0u16))
        };

        let socket = UdpSocket::bind(bind_addr).await?;

        // The OS defaults are sized for request-reply UDP, not for carrying a
        // TCP send window: macOS gives a datagram socket about 9 KB of send
        // buffer -- seven tunnel packets -- so the first real upload burst
        // came back ENOBUFS a thousand sends in a row. wireguard-go asks for
        // 7 MiB on its sockets for the same reason. Best-effort and
        // descending, because macOS rejects a request above its sockbuf limit
        // where Linux silently clamps, and a socket at the OS default still
        // works -- it just paces harder through the ENOBUFS retry in `send`.
        {
            let sock_ref = socket2::SockRef::from(&socket);
            for bytes in [4 << 20, 1 << 20, 256 << 10] {
                if sock_ref.set_send_buffer_size(bytes).is_ok() {
                    break;
                }
            }
            for bytes in [4 << 20, 1 << 20, 256 << 10] {
                if sock_ref.set_recv_buffer_size(bytes).is_ok() {
                    break;
                }
            }
        }

        // Exclude the endpoint socket from the VPN route before connecting.
        // Without this the tunnel's own UDP is captured by the TUN interface it
        // feeds, and every packet loops back into itself. This socket is bound
        // directly rather than through socket_util, so it protects itself.
        crate::socket_util::protect_outbound(&socket).map_err(|e| {
            std::io::Error::other(format!("failed to protect AmneziaWG endpoint socket: {e}"))
        })?;

        socket.connect(endpoint).await?;
        Ok(socket)
    }

    /// Ask for a rebind. Returns immediately; the work happens in
    /// [`run_rebind_task`].
    pub fn request_rebind(&self) {
        self.rebind_requested.notify_one();
    }

    /// The Phobos layer, when this tunnel has one.
    pub fn phobos(&self) -> Option<&PhobosLayer> {
        self.phobos.as_ref()
    }

    /// Send a Phobos control datagram (a STUN Binding message) as it is.
    /// Control traffic is never wrapped: it is the cover protocol itself.
    pub async fn send_control(&self, datagram: &[u8]) -> std::io::Result<usize> {
        self.send_raw(datagram).await
    }

    /// Whether the current socket still owes a Phobos server its handshake
    /// initiation: a rebind has replaced it, and no initiation has gone out
    /// on the replacement yet. Always false without Phobos.
    pub fn needs_initiation(&self) -> bool {
        self.phobos.is_some()
            && self.initiated_generation.load(Ordering::Acquire) < self.socket.borrow().generation
    }

    /// Send one WireGuard datagram, Phobos-wrapped when configured.
    ///
    /// Behind Phobos, a socket a rebind brought in sends nothing but a
    /// handshake initiation until one has gone out on it. The server drops
    /// everything else from an address it has not seen complete a handshake
    /// (`threading.c`, `process_packet`), so this is the datagram it would
    /// have discarded, held back here instead: `Ok(0)`, nothing sent. The
    /// socket and its generation come from one snapshot, so a rebind landing
    /// mid-call cannot let a transport message reach the new socket first.
    /// The gate opens only after the initiation's send has succeeded: while
    /// it is pending, and after it fails, the generation still owes one.
    /// The tunnel sends the initiation as soon as [`needs_initiation`]
    /// says so (`tunnel.rs`, the encapsulate loop).
    ///
    /// A Binding Request the codec puts ahead of a handshake initiation is
    /// sent first, as the reference does. Its failure is only logged: it
    /// carries nothing the server needs, and the datagram behind it meets
    /// the same path and reports for both. A datagram the codec cannot frame
    /// (shorter than a WireGuard header, or longer than STUN's 16-bit DATA
    /// length) is an `InvalidInput` error, never a silent success.
    /// Validation keeps the tunnel's own messages under the limit.
    ///
    /// [`needs_initiation`]: Self::needs_initiation
    pub async fn send(&self, datagram: &[u8]) -> std::io::Result<usize> {
        let bound = self.socket.borrow().clone();
        let Some(layer) = &self.phobos else {
            return self.send_on(&bound, datagram).await;
        };
        let initiation = is_initiation(datagram);
        if !initiation && self.initiated_generation.load(Ordering::Acquire) < bound.generation {
            debug!(
                "Phobos: holding back a {}-byte datagram until the handshake \
                 initiation from the rebound socket",
                datagram.len()
            );
            return Ok(0);
        }
        let mut wire = self.wire_pool.lock().pop().unwrap_or_default();
        let result = match layer.wrap(datagram, &mut wire) {
            Ok(preamble) => {
                if let Some(request) = preamble
                    && let Err(e) = self.send_on(&bound, &request).await
                {
                    debug!("Phobos binding request send failed: {e}");
                }
                let sent = self.send_on(&bound, &wire).await;
                // The gate opens only once the initiation is on the
                // socket. Marked earlier, a sender passing it while this
                // send was still pending (behind the Binding Request, or an
                // ENOBUFS retry) could queue its datagram ahead of the
                // initiation, and a failed send would leave the gate open
                // with nothing sent (shoes#151 review).
                if initiation && sent.is_ok() {
                    self.initiated_generation
                        .fetch_max(bound.generation, Ordering::AcqRel);
                }
                sent
            }
            Err(e) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "Phobos cannot frame a {}-byte datagram: {e}",
                    datagram.len()
                ),
            )),
        };
        let mut pool = self.wire_pool.lock();
        if pool.len() < WIRE_POOL_MAX {
            pool.push(wire);
        }
        result
    }

    /// Send one datagram over the current socket, as given.
    async fn send_raw(&self, datagram: &[u8]) -> std::io::Result<usize> {
        let bound = self.socket.borrow().clone();
        self.send_on(&bound, datagram).await
    }

    /// Send one datagram on `bound`, as given.
    ///
    /// A failure that means the route is gone schedules a rebind, so a tunnel
    /// recovers even when the app never reports the network change itself.
    async fn send_on(&self, bound: &Bound, datagram: &[u8]) -> std::io::Result<usize> {
        let socket = &bound.socket;
        let mut result = socket.send(datagram).await;

        // ENOBUFS is the kernel's send queue momentarily full, not a lost
        // route: the datagram was never sent, and giving up here turns queue
        // pressure into loss that the virtual stack's congestion control
        // reads as a congested path. Waiting out the queue instead paces
        // this sender to the interface's drain rate -- backpressure, the
        // same thing a blocking sendto would have done. Bounded, so a
        // kernel that stays out of buffers for tens of milliseconds still
        // surfaces the error to the failure accounting.
        let mut retries = 0;
        while let Err(ref e) = result {
            if e.raw_os_error() != Some(crate::util::ENOBUFS_RAW) || retries >= 20 {
                break;
            }
            retries += 1;
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            result = socket.send(datagram).await;
        }

        if let Err(ref e) = result
            && is_route_gone(e)
        {
            debug!("AmneziaWG send failed with {e}; scheduling a rebind");
            self.request_rebind();
        }

        result
    }

    /// Receive one WireGuard datagram into the front of `buf`, following the
    /// socket across a rebind.
    ///
    /// With Phobos configured, control traffic is handled here and never
    /// returned: a STUN Binding Request from the server is answered, and
    /// anything else that unwraps to no WireGuard message is skipped, since
    /// its sender chose its contents.
    pub async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let Some(layer) = &self.phobos else {
            return self.recv_raw(buf).await;
        };
        loop {
            let n = self.recv_raw(buf).await?;
            let base = buf.as_ptr() as usize;
            // The message is decoded in place, somewhere inside `buf`; its
            // position is all that is needed past the borrow.
            let message = match layer.unwrap(&mut buf[..n], self.endpoint) {
                Unwrapped::WireGuard(message) => {
                    Some((message.as_ptr() as usize - base, message.len()))
                }
                Unwrapped::Reply(reply) => {
                    if let Err(e) = self.send_raw(&reply).await {
                        debug!("Phobos binding response send failed: {e}");
                    }
                    None
                }
                _ => None,
            };
            if let Some((start, len)) = message {
                buf.copy_within(start..start + len, 0);
                return Ok(len);
            }
        }
    }

    /// Receive one datagram as it arrived, following the socket across a
    /// rebind.
    async fn recv_raw(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut changes = self.socket.subscribe();
        loop {
            let bound = changes.borrow_and_update().clone();
            tokio::select! {
                result = bound.socket.recv(buf) => return result,
                // The socket was replaced. The pending recv belonged to an
                // address that no longer exists, so drop it and read from the
                // new one.
                _ = changes.changed() => continue,
            }
        }
    }

    /// Rebind whenever one is asked for. Runs for the life of the tunnel.
    ///
    /// `on_rebound` is called after each successful swap, for the state that
    /// belongs to the path rather than to the peer — the AmneziaWG 3.1
    /// trailer window, and the announcement that tells the server the new
    /// address (both in `tunnel.rs`). It only queues; the tunnel's own send
    /// path does the sending, so ordering and error handling stay in one
    /// place.
    pub async fn run_rebind_task(self: Arc<Self>, on_rebound: impl Fn() + Send + 'static) {
        /// First retry delay after a failed rebind, doubling to the cap.
        /// Failing is normal while the device is between networks -- but
        /// the request's Notify permit is consumed by then, so without a
        /// retry timer a tunnel whose app never re-notifies (and whose
        /// sends all vanish rather than error) stayed on the dead socket
        /// for good.
        const RETRY_INITIAL: std::time::Duration = std::time::Duration::from_secs(1);
        const RETRY_MAX: std::time::Duration = std::time::Duration::from_secs(30);

        /// The floor between bind attempts, whatever woke the task. The
        /// receive loop requests a rebind per route-gone error -- every
        /// ~50 ms during a persistent ENETDOWN -- and each request stores
        /// a Notify permit that completes the retry select's notified()
        /// arm instantly, so without this floor the exponential backoff
        /// above gated nothing: bind+protect+connect ran at request rate
        /// (on Android, protect is a VpnService IPC per attempt).
        const MIN_ATTEMPT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

        let mut last_attempt: Option<std::time::Instant> = None;
        let pace = async |last: &mut Option<std::time::Instant>| {
            if let Some(prev) = *last {
                let since = prev.elapsed();
                if since < MIN_ATTEMPT_INTERVAL {
                    tokio::time::sleep(MIN_ATTEMPT_INTERVAL - since).await;
                }
            }
            *last = Some(std::time::Instant::now());
        };

        loop {
            self.rebind_requested.notified().await;

            let mut backoff = RETRY_INITIAL;
            let mut attempt = 1u32;
            loop {
                pace(&mut last_attempt).await;
                match Self::bind(self.endpoint).await {
                    Ok(socket) => {
                        let local = socket
                            .local_addr()
                            .map(|a| a.to_string())
                            .unwrap_or_else(|_| "unknown".to_string());
                        // send_replace, not send: `send` fails and leaves the
                        // value untouched when no receiver happens to be parked,
                        // which is most of the time — the tunnel tasks subscribe
                        // only for the duration of a recv. Only this task
                        // swaps, so reading the generation first is not a
                        // race.
                        let generation = self.socket.borrow().generation + 1;
                        self.socket
                            .send_replace(Arc::new(Bound { socket, generation }));
                        on_rebound();
                        // Drain the stored permit: Notify holds at most one,
                        // but requests that piled up during this rebind --
                        // route-gone errors fire one per failed send -- were
                        // asking for the swap that just happened, and honoring
                        // the leftover would churn a fresh socket for nothing.
                        // A genuinely new signal re-fires: sends that still
                        // fail re-request, the app re-notifies, the liveness
                        // watchdog re-asks every 20 deaf seconds.
                        use futures::FutureExt;
                        let _ = self.rebind_requested.notified().now_or_never();
                        info!(
                            "AmneziaWG endpoint rebound to {} -> {}",
                            local, self.endpoint
                        );
                        break;
                    }
                    Err(e) => {
                        // Warn once per episode; the retries are routine and
                        // would otherwise write a line every backoff step for
                        // as long as the device is between networks.
                        if attempt == 1 {
                            warn!("AmneziaWG endpoint rebind failed, will retry: {e}");
                        } else {
                            debug!("AmneziaWG endpoint rebind retry {attempt} failed: {e}");
                        }
                        attempt += 1;
                        // A fresh request short-circuits the wait: the app's
                        // network-change callback knows before the timer does.
                        tokio::select! {
                            _ = tokio::time::sleep(backoff) => {}
                            _ = self.rebind_requested.notified() => {}
                        }
                        backoff = (backoff * 2).min(RETRY_MAX);
                    }
                }
            }
        }
    }

    /// The peer this socket is connected to.
    #[cfg(test)]
    pub fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    /// The address the current socket is bound to.
    #[cfg(test)]
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.borrow().socket.local_addr()
    }
}

/// Whether an error means the path this socket was bound to is gone.
///
/// `ECONNREFUSED` and `ECONNRESET` are deliberately absent: on a connected UDP
/// socket they are the peer's ICMP replies, which say nothing about our own
/// address and arrive routinely when a peer restarts.
///
/// pub(crate): the receive loop consults the same table, because on an
/// idle tunnel the recv side sees the dead route first -- the send path
/// only notices when something makes it transmit.
pub(crate) fn is_route_gone(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;

    // EINVAL from a connected UDP socket: the address it was bound to no
    // longer exists. The libc-vs-WinSock trap is documented at the
    // constant's definition.
    use crate::util::EINVAL_RAW;

    // PermissionDenied (EPERM/EACCES): what Android returns once a socket
    // has lost its VpnService.protect() exemption -- the send is refused
    // so it cannot loop into the tunnel. A rebind re-protects the fresh
    // socket, so there it is the same repair as a vanished route. Android
    // ONLY: on a desktop, EPERM is a firewall rejecting the tunnel's UDP,
    // which a rebind does not repair -- and since binding is not
    // firewalled, each rebind *succeeds*, re-sends, fails EPERM again,
    // and re-requests: a socket-churn hot loop with no error to back off.
    #[cfg(target_os = "android")]
    if e.kind() == ErrorKind::PermissionDenied {
        return true;
    }

    matches!(
        e.kind(),
        ErrorKind::NetworkUnreachable
            | ErrorKind::HostUnreachable
            | ErrorKind::NetworkDown
            | ErrorKind::AddrNotAvailable
    ) || e.raw_os_error() == Some(EINVAL_RAW)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn peer() -> (UdpSocket, SocketAddr) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        (socket, addr)
    }

    #[tokio::test]
    async fn a_rebind_moves_the_socket_and_keeps_the_peer() {
        let (peer_socket, peer_addr) = peer().await;
        let endpoint = EndpointSocket::connect(peer_addr, None).await.unwrap();
        let before = endpoint.local_addr().unwrap();

        tokio::spawn(endpoint.clone().run_rebind_task(|| {}));
        endpoint.request_rebind();

        // The rebind is asynchronous; wait for the address to actually move.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while endpoint.local_addr().unwrap() == before {
            assert!(
                std::time::Instant::now() < deadline,
                "rebind never happened"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        assert_eq!(endpoint.endpoint(), peer_addr, "the peer must not change");

        // And the new socket still reaches the peer, which is what makes a
        // rebind a recovery rather than just a different kind of broken.
        endpoint.send(b"after rebind").await.unwrap();
        let mut buf = [0u8; 32];
        let (n, from) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            peer_socket.recv_from(&mut buf),
        )
        .await
        .expect("peer never received the datagram")
        .unwrap();

        assert_eq!(&buf[..n], b"after rebind");
        // Against `before`, not against a fresh local_addr(). `from` was fixed
        // when the datagram left; reading the current address afterwards races
        // any later rebind, and comparing the two then fails for a reason the
        // test does not care about. What it does care about is that the
        // datagram no longer comes from the socket the rebind replaced.
        assert_ne!(from, before, "the datagram came from the pre-rebind socket");
    }

    #[tokio::test]
    async fn recv_follows_the_socket_across_a_rebind() {
        let (peer_socket, peer_addr) = peer().await;
        let endpoint = EndpointSocket::connect(peer_addr, None).await.unwrap();
        tokio::spawn(endpoint.clone().run_rebind_task(|| {}));

        // Park a receive on the pre-rebind socket, then move it. Without the
        // watch channel this future would wait on the old address forever.
        let receiver = {
            let endpoint = endpoint.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 32];
                let n = endpoint.recv(&mut buf).await.unwrap();
                buf[..n].to_vec()
            })
        };
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let before = endpoint.local_addr().unwrap();
        endpoint.request_rebind();

        // Wait for the swap rather than racing it: a `hello` sent from the old
        // socket would be answered on the old address, and the assertion below
        // would then be testing the race instead of the handover.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while endpoint.local_addr().unwrap() == before {
            assert!(
                std::time::Instant::now() < deadline,
                "rebind never happened"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        // Now make the peer answer the new socket.
        endpoint.send(b"hello").await.unwrap();
        let mut buf = [0u8; 32];
        let (_, from) = peer_socket.recv_from(&mut buf).await.unwrap();
        peer_socket.send_to(b"reply", from).await.unwrap();

        let received = tokio::time::timeout(std::time::Duration::from_secs(5), receiver)
            .await
            .expect("recv did not follow the rebind")
            .unwrap();
        assert_eq!(received, b"reply");
    }

    /// The rebind callback is what resets AmneziaWG 3.1's trailer window, and
    /// a silently-never-called callback would look exactly like a working
    /// tunnel until the trailer sizes were inspected on the wire.
    #[tokio::test]
    async fn a_successful_rebind_calls_back() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let (_peer_socket, peer_addr) = peer().await;
        let endpoint = EndpointSocket::connect(peer_addr, None).await.unwrap();

        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        tokio::spawn(endpoint.clone().run_rebind_task(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        }));

        assert_eq!(calls.load(Ordering::SeqCst), 0, "nothing rebound yet");
        endpoint.request_rebind();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while calls.load(Ordering::SeqCst) == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "the rebind callback never ran"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    /// The endpoint registers itself, and the listener rebinds it. Rung
    /// directly rather than through `network_change::notify`, which would
    /// reach every other test's tunnels too.
    #[tokio::test]
    async fn a_network_change_rebinds_a_registered_endpoint() {
        use crate::network_change::{NetworkChangeListener, is_registered};
        let (_peer_socket, peer_addr) = peer().await;
        let live = EndpointSocket::connect(peer_addr, None).await.unwrap();
        let listener: Arc<dyn NetworkChangeListener> = live.clone();
        assert!(is_registered(&listener));
        tokio::spawn(live.clone().run_rebind_task(|| {}));
        let before = live.local_addr().unwrap();

        live.network_changed();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while live.local_addr().unwrap() == before {
            assert!(
                std::time::Instant::now() < deadline,
                "the notification did not rebind the endpoint"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    /// Behind Phobos, a rebound socket sends nothing but an initiation until
    /// one has gone out on it. Driven at the socket, where the gate is, so a
    /// transport message sent straight after the swap is the case under
    /// test, with no scheduling to luck past it (shoes#151 review).
    #[tokio::test]
    async fn behind_phobos_a_rebound_socket_sends_an_initiation_first() {
        use awgtun::phobos::{PhobosCodec, PhobosConfig, Unwrapped};

        let (peer_socket, peer_addr) = peer().await;
        let config = PhobosConfig::new(b"synthetic-preset-key".to_vec()).unwrap();
        let layer = PhobosLayer::new(config.clone()).unwrap();
        let endpoint = EndpointSocket::connect(peer_addr, Some(layer))
            .await
            .unwrap();
        let mut server = PhobosCodec::new(config).unwrap();

        let message = |msg_type: u8| {
            let mut m = vec![msg_type, 0, 0, 0];
            m.extend(4..64u8);
            m
        };
        let mut buf = [0u8; 2048];
        let mut next_type = async |server: &mut PhobosCodec| {
            let (n, from) = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                peer_socket.recv_from(&mut buf),
            )
            .await
            .expect("the peer received nothing")
            .unwrap();
            match server.unwrap(&mut buf[..n], from) {
                Unwrapped::WireGuard(m) => (m[0], from),
                other => panic!("not a WireGuard message: {other:?}"),
            }
        };

        // The first socket is not gated: a tunnel's first message is an
        // initiation anyway.
        assert!(!endpoint.needs_initiation());
        endpoint.send(&message(4)).await.unwrap();
        let (first, before) = next_type(&mut server).await;
        assert_eq!(first, 4);

        let before_local = endpoint.local_addr().unwrap();
        tokio::spawn(endpoint.clone().run_rebind_task(|| {}));
        endpoint.request_rebind();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while endpoint.local_addr().unwrap() == before_local {
            assert!(
                std::time::Instant::now() < deadline,
                "rebind never happened"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        assert!(endpoint.needs_initiation());
        assert_eq!(endpoint.send(&message(4)).await.unwrap(), 0, "held back");
        endpoint.send(&message(1)).await.unwrap();
        assert!(!endpoint.needs_initiation());
        endpoint.send(&message(4)).await.unwrap();

        let (after, from) = next_type(&mut server).await;
        assert_ne!(from, before, "the datagram came from the old socket");
        assert_eq!(after, 1, "the first message from the new socket");
        assert_eq!(next_type(&mut server).await.0, 4);
    }

    /// An initiation that fails to go out does not open the gate: the
    /// generation still owes one, and transport stays held back. Marked
    /// before the send, as it first was, the failure left the gate open
    /// with nothing sent (shoes#151 review).
    #[tokio::test]
    async fn a_failed_initiation_keeps_the_rebound_socket_gated() {
        use awgtun::phobos::{Masking, PhobosConfig};

        let (_peer_socket, peer_addr) = peer().await;
        let mut config = PhobosConfig::new(b"synthetic-preset-key".to_vec()).unwrap();
        config.masking = Masking::Stun;
        let endpoint = EndpointSocket::connect(peer_addr, Some(PhobosLayer::new(config).unwrap()))
            .await
            .unwrap();

        let before_local = endpoint.local_addr().unwrap();
        tokio::spawn(endpoint.clone().run_rebind_task(|| {}));
        endpoint.request_rebind();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while endpoint.local_addr().unwrap() == before_local {
            assert!(
                std::time::Instant::now() < deadline,
                "rebind never happened"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        // Longer than STUN's 16-bit DATA length: the send fails for certain.
        let mut too_long = vec![1u8, 0, 0, 0];
        too_long.resize(65_536, 7);
        assert!(endpoint.send(&too_long).await.is_err());
        assert!(
            endpoint.needs_initiation(),
            "a failed initiation opened the gate"
        );
        assert_eq!(endpoint.send(&[4, 0, 0, 0, 1, 2, 3, 4]).await.unwrap(), 0);

        let mut initiation = vec![1u8, 0, 0, 0];
        initiation.resize(148, 7);
        endpoint.send(&initiation).await.unwrap();
        assert!(!endpoint.needs_initiation());
    }

    /// A datagram the codec cannot frame is an error, not `Ok(0)`: the
    /// caller's failure accounting has to see it.
    #[tokio::test]
    async fn a_datagram_phobos_cannot_frame_is_an_error() {
        use awgtun::phobos::{Masking, PhobosConfig};

        let (_peer_socket, peer_addr) = peer().await;
        let mut config = PhobosConfig::new(b"k".to_vec()).unwrap();
        config.masking = Masking::Stun;
        let endpoint = EndpointSocket::connect(peer_addr, Some(PhobosLayer::new(config).unwrap()))
            .await
            .unwrap();
        let err = endpoint.send(&[1, 0, 0]).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }
}
