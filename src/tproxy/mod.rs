//! Transparent proxying on Linux: inbounds with no protocol of their own,
//! where the kernel delivered the traffic and the only question is where it
//! was going. See docs/specs/2026-09-11-awg-manager-engine.md, "Slice 2".
//!
//! The `redirect` TCP inbound is `src/redirect_handler.rs`. The `tproxy` UDP
//! inbound is here: one transparent listener, and a demux task that hands
//! each datagram to the stream for its client address, creating the client
//! on first sight. Each client runs the per-destination `UdpRouter` every
//! other UDP inbound uses, so routing, sessions and expiry are shared code.
//! Replies go out through a per-client cache of sockets bound transparently
//! to the remote's address, so the client sees the remote it spoke to.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "predates the lint; see the [lints] note in Cargo.toml"
)]

pub mod sys;

#[cfg(target_os = "linux")]
mod linux {
    use std::mem::MaybeUninit;
    use std::net::SocketAddr;
    use std::num::NonZeroUsize;
    use std::os::fd::AsRawFd;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context, Poll};
    use std::time::Duration;

    use bytes::Bytes;
    use log::{debug, error, warn};
    use lru::LruCache;
    use tokio::io::ReadBuf;
    use tokio::io::unix::AsyncFd;
    use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
    use tokio::task::JoinHandle;
    use tokio::time::Instant;

    use super::sys;
    use crate::address::NetLocation;
    use crate::async_stream::{
        AsyncFlushMessage, AsyncPing, AsyncReadTargetedMessage, AsyncShutdownMessage,
        AsyncTargetedMessageStream, AsyncWriteSourcedMessage,
    };
    use crate::client_proxy_selector::ClientProxySelector;
    use crate::config::{BindLocation, ConfigSelection, ServerConfig, ServerProxyConfig};
    use crate::resolver::Resolver;
    use crate::routing::{RouterLimits, ServerStream, run_udp_routing_with_limits};

    /// Reply sockets one client keeps, keyed by the remote they speak as.
    /// The listener's total is bounded separately, by `udp_nat_max`.
    const REPLY_SOCKETS_PER_CLIENT: usize = 64;
    /// Datagrams queued for one client's router. Full means drop.
    const CLIENT_QUEUE: usize = 256;
    const MAX_DATAGRAM: usize = 65535;
    const SWEEP_INTERVAL: Duration = Duration::from_secs(5);

    /// A datagram's original destination and its payload.
    type Datagram = (SocketAddr, Bytes);

    /// How a reply socket is made. A function pointer so the tests can open
    /// an ordinary socket where production needs `CAP_NET_RAW`.
    type OpenReplySocket = fn(SocketAddr) -> std::io::Result<tokio::net::UdpSocket>;

    /// One client socket's view of the listener: reads are the datagrams the
    /// demux delivered for it, writes are replies to it, spoofed.
    pub struct TproxyClientStream {
        client: SocketAddr,
        rx: mpsc::Receiver<Datagram>,
        replies: LruCache<SocketAddr, ReplySocket>,
        /// Reply sockets across every client of this listener.
        reply_budget: Arc<Semaphore>,
        open_reply_socket: OpenReplySocket,
        /// Set on every reply, read and cleared by the demux's sweep: a
        /// client that only receives is still in use.
        replied: Arc<AtomicBool>,
        /// How long a reply socket may go unused: the listener's
        /// `udp_timeout`, after which the session it served has expired too.
        idle: Duration,
        /// Whether the budget refusal has been reported since this client
        /// last got a socket: one warning per stretch, not one per reply.
        budget_refusal_reported: bool,
    }

    /// A spoofed socket and its share of the listener's budget; evicting it
    /// returns the permit.
    struct ReplySocket {
        socket: tokio::net::UdpSocket,
        last_used: Instant,
        _permit: OwnedSemaphorePermit,
    }

    impl TproxyClientStream {
        fn new(
            client: SocketAddr,
            rx: mpsc::Receiver<Datagram>,
            reply_budget: Arc<Semaphore>,
            open_reply_socket: OpenReplySocket,
            replied: Arc<AtomicBool>,
            idle: Duration,
        ) -> Self {
            Self {
                client,
                rx,
                replies: LruCache::new(NonZeroUsize::new(REPLY_SOCKETS_PER_CLIENT).unwrap()),
                reply_budget,
                open_reply_socket,
                replied,
                idle,
                budget_refusal_reported: false,
            }
        }

        /// Close reply sockets unused for `idle`, returning their share of
        /// the listener's budget. They would otherwise live as long as the
        /// client does, which is as long as it sends anything: a few clients
        /// that once spoke to many remotes would hold the whole budget, and
        /// every reply to a newcomer would be dropped. The LRU's oldest entry
        /// is the least recently used, so this stops at the first fresh one.
        fn close_idle_reply_sockets(&mut self, now: Instant) {
            while let Some((_, oldest)) = self.replies.peek_lru() {
                if now.duration_since(oldest.last_used) < self.idle {
                    break;
                }
                self.replies.pop_lru();
            }
        }

        /// The cached socket speaking as `spoof`, opened on first use.
        fn reply_socket(&mut self, spoof: SocketAddr) -> std::io::Result<&tokio::net::UdpSocket> {
            let now = Instant::now();
            if self.reply_budget.available_permits() == 0 && !self.replies.contains(&spoof) {
                self.recycle_oldest_reply_socket(spoof, now)?;
            }
            let budget = &self.reply_budget;
            let open = self.open_reply_socket;
            // One lookup on a hit. On a miss the per-client cap evicts the
            // oldest socket, and its permit with it.
            let entry = self.replies.try_get_or_insert_mut(spoof, || {
                let permit = budget.clone().try_acquire_owned().map_err(|_| {
                    std::io::Error::other("the listener's reply sockets are all in use")
                })?;
                Ok::<_, std::io::Error>(ReplySocket {
                    socket: open(spoof)?,
                    last_used: now,
                    _permit: permit,
                })
            })?;
            entry.last_used = now;
            self.budget_refusal_reported = false;
            Ok(&entry.socket)
        }

        /// The listener's budget is spent: give up this client's own oldest
        /// socket for one speaking as `spoof`, so a busy client recycles
        /// rather than starves. The new socket is opened first, so a remote
        /// that cannot be spoofed costs no socket that works, and a client
        /// with nothing to give up opens nothing.
        fn recycle_oldest_reply_socket(
            &mut self,
            spoof: SocketAddr,
            now: Instant,
        ) -> std::io::Result<()> {
            if self.replies.is_empty() {
                if !self.budget_refusal_reported {
                    self.budget_refusal_reported = true;
                    warn!(
                        "tproxy: udp_nat_max reply sockets all in use; replies to {} are \
                         dropped until some go idle",
                        self.client
                    );
                }
                return Err(std::io::Error::other(
                    "the listener's reply sockets are all in use",
                ));
            }
            let socket = (self.open_reply_socket)(spoof)?;
            self.replies.pop_lru();
            // Another client may take the freed permit first; then this
            // reply is dropped like any other over the budget.
            let permit = self.reply_budget.clone().try_acquire_owned().map_err(|_| {
                std::io::Error::other("the listener's reply sockets are all in use")
            })?;
            self.replies.put(
                spoof,
                ReplySocket {
                    socket,
                    last_used: now,
                    _permit: permit,
                },
            );
            Ok(())
        }
    }

    impl AsyncReadTargetedMessage for TproxyClientStream {
        fn poll_read_targeted_message(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<NetLocation>> {
            let this = self.get_mut();
            match this.rx.poll_recv(cx) {
                Poll::Ready(Some((destination, payload))) => {
                    this.close_idle_reply_sockets(Instant::now());
                    // The router reads into a buffer of the largest UDP
                    // payload, so this never cuts; refuse rather than cut if
                    // that ever changes.
                    if payload.len() > buf.remaining() {
                        return Poll::Ready(Err(std::io::Error::other(
                            "tproxy datagram larger than the router's buffer",
                        )));
                    }
                    buf.put_slice(&payload);
                    Poll::Ready(Ok(NetLocation::from(destination)))
                }
                Poll::Ready(None) => Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "tproxy client expired",
                ))),
                Poll::Pending => Poll::Pending,
            }
        }
    }

    impl AsyncWriteSourcedMessage for TproxyClientStream {
        /// A reply that cannot be sent is dropped, never an error: the router
        /// takes a write error as the end of the client, which would end
        /// every other flow of this client over one refused remote.
        fn poll_write_sourced_message(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
            source: &SocketAddr,
        ) -> Poll<std::io::Result<()>> {
            let this = self.get_mut();
            this.replied.store(true, Ordering::Relaxed);
            this.close_idle_reply_sockets(Instant::now());
            let client = this.client;
            // The remote as the client addressed it: the router resolves the
            // destination the demux read, an address literal, so it reports
            // it back in the client's own family.
            let spoof = *source;
            let socket = match this.reply_socket(spoof) {
                Ok(socket) => socket,
                Err(e) => {
                    debug!("tproxy: no reply socket as {spoof} for {client}: {e}; dropped");
                    return Poll::Ready(Ok(()));
                }
            };
            match socket.poll_send_to(cx, buf, client) {
                Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
                Poll::Ready(Err(e)) => {
                    debug!("tproxy: reply as {spoof} to {client}: {e}; dropped");
                    Poll::Ready(Ok(()))
                }
                Poll::Pending => Poll::Pending,
            }
        }
    }

    impl AsyncFlushMessage for TproxyClientStream {
        fn poll_flush_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncShutdownMessage for TproxyClientStream {
        fn poll_shutdown_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncPing for TproxyClientStream {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncTargetedMessageStream for TproxyClientStream {}

    struct Client {
        tx: mpsc::Sender<Datagram>,
        last_seen: Instant,
        replied: Arc<AtomicBool>,
        /// Taken only by `cancel`.
        task: Option<JoinHandle<()>>,
    }

    impl Client {
        /// Stop the router, handing back its task so a successor can wait
        /// for it to be gone.
        fn cancel(mut self) -> JoinHandle<()> {
            let task = self.task.take().expect("a client's task is taken once");
            task.abort();
            task
        }
    }

    impl Drop for Client {
        /// A client is dropped when it expires or the listener stops; either
        /// way its router goes with it.
        fn drop(&mut self) {
            if let Some(task) = &self.task {
                task.abort();
            }
        }
    }

    #[derive(Debug, PartialEq)]
    enum Delivery {
        Delivered,
        /// A datagram no router may see; see `worth_routing`.
        Ignored,
        /// The client's queue is full.
        Dropped,
    }

    /// The listener's clients, keyed by source address, least recently heard
    /// from first in line for eviction.
    struct Clients<S> {
        /// The listener's own address, which no datagram may be routed to.
        listener: SocketAddr,
        /// Unbounded as a cache: `deliver` enforces `max_clients` itself, so
        /// it can say so when it evicts.
        clients: LruCache<SocketAddr, Client>,
        /// Every client holds at least one session, so more clients than
        /// `udp_nat_max` could never all be served.
        max_clients: usize,
        idle: Duration,
        /// Whether eviction at the cap has been reported since the listener
        /// was last below it: one warning per stretch, not one per client.
        eviction_reported: bool,
        /// Starts a client's router over its stream.
        spawn: S,
    }

    impl<S, F> Clients<S>
    where
        S: FnMut(SocketAddr, mpsc::Receiver<Datagram>, Arc<AtomicBool>) -> F,
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        fn new(listener: SocketAddr, max_clients: usize, idle: Duration, spawn: S) -> Self {
            Self {
                listener,
                clients: LruCache::unbounded(),
                max_clients,
                idle,
                eviction_reported: false,
                spawn,
            }
        }

        fn deliver(
            &mut self,
            source: SocketAddr,
            destination: SocketAddr,
            payload: Bytes,
            now: Instant,
        ) -> Delivery {
            if payload.is_empty() || !worth_routing(destination, self.listener) {
                return Delivery::Ignored;
            }
            let datagram = match self.clients.get_mut(&source) {
                Some(client) => {
                    client.last_seen = now;
                    // Bounded, and full means drop: what a full socket buffer
                    // does, and the only answer that cannot stall the
                    // listener for every other client.
                    match client.tx.try_send((destination, payload)) {
                        Ok(()) => return Delivery::Delivered,
                        Err(mpsc::error::TrySendError::Full(_)) => return Delivery::Dropped,
                        // The router has ended: start the client afresh
                        // rather than drop its traffic until the sweep.
                        Err(mpsc::error::TrySendError::Closed(datagram)) => {
                            let ended = self.clients.pop(&source).map(Client::cancel);
                            return self.admit(source, datagram, now, ended);
                        }
                    }
                }
                None => (destination, payload),
            };
            self.admit(source, datagram, now, None)
        }

        /// Start a client for `source` with `datagram` queued, evicting the
        /// least recently heard-from client at the cap: as sing-box's UDP NAT
        /// does, and unlike refusal, which fails every new flow (each DNS
        /// query from a fresh port is one) until the idle sweep runs.
        fn admit(
            &mut self,
            source: SocketAddr,
            datagram: Datagram,
            now: Instant,
            mut predecessor: Option<JoinHandle<()>>,
        ) -> Delivery {
            if self.clients.len() >= self.max_clients {
                if !self.eviction_reported {
                    self.eviction_reported = true;
                    warn!(
                        "tproxy: udp_nat_max {} clients reached; the least recently heard \
                         from are evicted for new ones",
                        self.max_clients
                    );
                }
                self.promote_replied_to(now);
                if let Some((evicted, client)) = self.clients.pop_lru() {
                    debug!("tproxy: client {evicted} evicted for {source}");
                    predecessor = Some(client.cancel());
                }
            }
            let (tx, rx) = mpsc::channel(CLIENT_QUEUE);
            let replied = Arc::new(AtomicBool::new(false));
            // A fresh queue cannot be full.
            let _ = tx.try_send(datagram);
            let router = (self.spawn)(source, rx, replied.clone());
            // A router cancelled to make room still holds its sessions' and
            // reply sockets' share of the budgets until its cancellation
            // lands, which on another worker can be after this one's first
            // datagram asks for a session. Its datagrams wait in the queue.
            // Into the listener's connection set (the demux runs in its
            // scope), so a reload can drain or cancel the flow.
            let task = Some(crate::connections::spawn(async move {
                if let Some(predecessor) = predecessor {
                    let _ = predecessor.await;
                }
                router.await
            }));
            self.clients.put(
                source,
                Client {
                    tx,
                    last_seen: now,
                    replied,
                    task,
                },
            );
            Delivery::Delivered
        }

        /// Move clients replied to since the last look off the eviction end,
        /// so the victim is idle both ways rather than only quiet. Each turn
        /// clears a flag, so this ends within one pass of the table.
        fn promote_replied_to(&mut self, now: Instant) {
            while let Some((&source, client)) = self.clients.peek_lru() {
                if !client.replied.swap(false, Ordering::Relaxed) {
                    break;
                }
                if let Some(client) = self.clients.get_mut(&source) {
                    client.last_seen = now;
                }
            }
        }

        /// Forget clients idle in both directions for `idle`, and clients
        /// whose router has ended. A client that only receives counts as
        /// heard from, for eviction as for expiry.
        fn sweep(&mut self, now: Instant) {
            let idle = self.idle;
            let mut expired = Vec::new();
            let mut replied = Vec::new();
            for (source, client) in self.clients.iter_mut() {
                if client.replied.swap(false, Ordering::Relaxed) {
                    client.last_seen = now;
                    replied.push(*source);
                }
                if now.duration_since(client.last_seen) >= idle
                    || client.task.as_ref().is_some_and(JoinHandle::is_finished)
                {
                    expired.push(*source);
                }
            }
            for source in replied {
                self.clients.promote(&source);
            }
            for source in expired {
                debug!("tproxy: client {source} expired");
                self.clients.pop(&source);
            }
            if self.clients.len() < self.max_clients {
                self.eviction_reported = false;
            }
        }
    }

    /// Whether a datagram for `destination` may reach a router.
    ///
    /// Not the listener's own address: that is shoes' own dial arriving back,
    /// because a datagram sent to the listener directly reports the listener
    /// as its original destination, and relaying it starts another client
    /// that does the same until `udp_nat_max` is spent. Loopback-only stops
    /// the LAN from reaching the listener directly; this stops the host.
    /// `redirect` refuses its own address for the same reason.
    ///
    /// Not broadcast, multicast, unspecified or port zero: none of them is a
    /// remote to relay a flow to and spoof replies from, and TPROXY delivers
    /// them only when the firewall rule is broader than it should be.
    /// Subnet-directed broadcast cannot be told from an address here; the
    /// rule's `addrtype` exclusion is what keeps it out.
    fn worth_routing(destination: SocketAddr, listener: SocketAddr) -> bool {
        if destination == listener || destination.port() == 0 {
            return false;
        }
        match destination.ip() {
            std::net::IpAddr::V4(ip) => {
                !(ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast())
            }
            std::net::IpAddr::V6(ip) => !(ip.is_unspecified() || ip.is_multicast()),
        }
    }

    /// Bind each address and start its demux.
    pub async fn start_tproxy_udp_server(
        config: ServerConfig,
        resolver: Arc<dyn Resolver>,
        connections: &crate::connections::ConnectionSet,
    ) -> std::io::Result<Vec<JoinHandle<()>>> {
        let ServerProxyConfig::Tproxy {
            udp_timeout,
            udp_nat_max,
        } = config.protocol
        else {
            unreachable!("validated: transport udp is tproxy");
        };
        let BindLocation::Address(addresses) = config.bind_location else {
            unreachable!("validated: tproxy binds an address");
        };
        // Every address resolved and bound before any demux starts, so a
        // failure part-way leaves nothing running behind the error.
        let binds = resolve_binds(addresses.into_vec())?;
        let open_files = raise_open_file_limit(udp_nat_max, binds.len());
        // IPv6 has no `src_valid_mark`.
        if binds.iter().any(SocketAddr::is_ipv4) {
            warn_about_source_validation();
        }
        let mut listeners = Vec::with_capacity(binds.len());
        for bind in binds {
            let listener = crate::socket_util::new_transparent_udp_listener(bind)
                .and_then(AsyncFd::new)
                .map_err(|e| {
                    std::io::Error::new(e.kind(), format!("tproxy listener at {bind}: {e}"))
                })?;
            listeners.push((bind, listener));
        }

        let rules = config.rules.map(ConfigSelection::unwrap_config).into_vec();
        let selector = Arc::new(
            crate::tcp::tcp_client_handler_factory::create_tcp_client_proxy_selector(
                rules,
                resolver.clone(),
            ),
        );
        let mut handles = Vec::with_capacity(listeners.len());
        for (bind, listener) in listeners {
            println!(
                "Starting TPROXY UDP server at {bind} (udp_nat_max {udp_nat_max}, \
                 open-file limit {open_files})"
            );
            // One budget of each kind per listener, shared by every client's
            // router and reply cache: `udp_nat_max` is a promise about the
            // listener's descriptors, not each client's.
            let limits = RouterLimits {
                session_timeout: Duration::from_secs(udp_timeout),
                max_sessions: udp_nat_max,
                shared_budget: Some(Arc::new(Semaphore::new(udp_nat_max))),
            };
            let reply_budget = Arc::new(Semaphore::new(udp_nat_max));
            handles.push(tokio::spawn(connections.scope(demux(
                listener,
                bind,
                selector.clone(),
                resolver.clone(),
                limits,
                reply_budget,
            ))));
        }
        Ok(handles)
    }

    /// Every address the listener binds, resolved, and each answer held to
    /// loopback again. Validation checked its own lookup, and a name can
    /// answer differently by now; a transparent socket anywhere else relays
    /// ordinary traffic to itself (`validate_tproxy_listener`).
    fn resolve_binds(
        addresses: Vec<crate::address::NetLocationPortRange>,
    ) -> std::io::Result<Vec<SocketAddr>> {
        let mut binds = Vec::new();
        for address in addresses {
            for bind in address.to_socket_addrs()? {
                if !bind.ip().is_loopback() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "tproxy listener {address} resolved to {bind}, which is not \
                             loopback; refusing to bind a transparent socket there"
                        ),
                    ));
                }
                binds.push(bind);
            }
        }
        Ok(binds)
    }

    async fn demux(
        listener: AsyncFd<socket2::Socket>,
        bind: SocketAddr,
        selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
        limits: RouterLimits,
        reply_budget: Arc<Semaphore>,
    ) {
        let spawn = {
            let limits = limits.clone();
            move |client: SocketAddr, rx, replied| {
                let stream = TproxyClientStream::new(
                    client,
                    rx,
                    reply_budget.clone(),
                    crate::socket_util::new_transparent_reply_socket,
                    replied,
                    limits.session_timeout,
                );
                let selector = selector.clone();
                let resolver = resolver.clone();
                let limits = limits.clone();
                async move {
                    let stream = ServerStream::Targeted(Box::new(stream));
                    if let Err(e) =
                        run_udp_routing_with_limits(stream, selector, resolver, false, limits).await
                    {
                        debug!("tproxy client {client} ended: {e}");
                    }
                }
            }
        };
        let mut clients = Clients::new(bind, limits.max_sessions, limits.session_timeout, spawn);
        let mut receiver = Receiver::new();
        let mut sweep = tokio::time::interval(SWEEP_INTERVAL);

        loop {
            tokio::select! {
                readable = listener.readable() => {
                    let mut guard = match readable {
                        Ok(guard) => guard,
                        Err(e) => {
                            error!("tproxy listener: {e}");
                            return;
                        }
                    };
                    let received =
                        guard.try_io(|inner| receiver.recv(inner.get_ref().as_raw_fd()));
                    let (payload, source, destination) = match received {
                        Ok(Ok(datagram)) => datagram,
                        Ok(Err(e)) => {
                            debug!("tproxy recvmsg: {e}");
                            continue;
                        }
                        Err(_would_block) => continue,
                    };
                    let Some(destination) = destination else {
                        debug!("tproxy: datagram from {source} without an original destination; dropped");
                        continue;
                    };
                    match clients.deliver(source, destination, payload, Instant::now()) {
                        Delivery::Delivered => {}
                        Delivery::Ignored => {
                            debug!("tproxy: datagram from {source} for {destination} ignored")
                        }
                        Delivery::Dropped => {
                            debug!("tproxy: client {source} queue full; datagram dropped")
                        }
                    }
                }
                _ = sweep.tick() => clients.sweep(Instant::now()),
            }
        }
    }

    /// Reads the listener's datagrams, each with its original destination.
    ///
    /// Into one reusable buffer, then copied out at its own size: one
    /// allocation per datagram, which the hand-off to a client's task needs
    /// anyway. Carving datagrams out of a large shared block saved that
    /// allocation but let each queued datagram keep its whole block alive,
    /// and a client whose router stalls holds a full queue of them.
    struct Receiver {
        scratch: Box<[MaybeUninit<u8>]>,
    }

    impl Receiver {
        fn new() -> Self {
            Self {
                scratch: vec![MaybeUninit::uninit(); MAX_DATAGRAM].into_boxed_slice(),
            }
        }

        fn recv(
            &mut self,
            fd: std::os::fd::RawFd,
        ) -> std::io::Result<(Bytes, SocketAddr, Option<SocketAddr>)> {
            let (n, source, destination) =
                sys::recv_with_original_destination(fd, &mut self.scratch)?;
            // SAFETY: the kernel initialised the first `n` bytes of the buffer
            // it was handed, and `n` is within it.
            let payload =
                unsafe { std::slice::from_raw_parts(self.scratch.as_ptr().cast::<u8>(), n) };
            Ok((Bytes::copy_from_slice(payload), source, destination))
        }
    }

    /// Raise the soft open-file limit to the hard one and return it, warning
    /// when full listeners could exceed it. A warning, not a refusal: the
    /// limit is the host's to change, and a listener over it degrades by
    /// dropping, not by failing. Entware's soft limit is 1024 on some
    /// routers, below the default `udp_nat_max`.
    fn raise_open_file_limit(udp_nat_max: usize, listeners: usize) -> u64 {
        // SAFETY: plain data the kernel fills in or reads.
        let limit = unsafe {
            let mut limit: libc::rlimit = std::mem::zeroed();
            if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) != 0 {
                return 0;
            }
            if limit.rlim_cur < limit.rlim_max {
                let raised = libc::rlimit {
                    rlim_cur: limit.rlim_max,
                    rlim_max: limit.rlim_max,
                };
                if libc::setrlimit(libc::RLIMIT_NOFILE, &raised) == 0 {
                    limit = raised;
                }
            }
            limit.rlim_cur as u64
        };
        let needed = open_files_needed(udp_nat_max, listeners);
        if limit < needed {
            println!(
                "WARNING: {listeners} tproxy listener(s) with udp_nat_max {udp_nat_max} need up \
                 to {needed} open files and the limit is {limit}; past it new UDP sessions are \
                 dropped. Raise the limit (ulimit -n) or lower udp_nat_max"
            );
        }
        limit
    }

    /// Each listener has budgets of its own: `udp_nat_max` sessions and as
    /// many reply sockets, plus the listener itself. Then room for everything
    /// else the process holds.
    fn open_files_needed(udp_nat_max: usize, listeners: usize) -> u64 {
        (listeners as u64) * (2 * udp_nat_max as u64 + 1) + 64
    }

    /// Interfaces on which the kernel drops what `TPROXY` marks, by name.
    ///
    /// With `src_valid_mark` on, the reverse-path check looks the client's
    /// address up with the datagram's mark, so it finds the policy route's
    /// `local` default and rejects the source as a martian: silently, with no
    /// counter. `accept_local` lets that pass unless `rp_filter` is strict.
    /// Each setting is in force on an interface if it is on there or under
    /// `all` (`rp_filter`: the larger of the two), as `IN_DEV_ORCONF` and
    /// `IN_DEV_MAXCONF` read them. `conf` is `/proc/sys/net/ipv4/conf`.
    fn interfaces_dropping_marked_datagrams(conf: &std::path::Path) -> Vec<String> {
        let read = |interface: &str, setting: &str| -> u8 {
            std::fs::read_to_string(conf.join(interface).join(setting))
                .ok()
                .and_then(|value| value.trim().parse().ok())
                .unwrap_or(0)
        };
        let Ok(entries) = std::fs::read_dir(conf) else {
            return Vec::new();
        };
        let mut at_risk: Vec<String> = entries
            .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
            // `default` is a template for interfaces yet to come, and `lo`
            // carries only the host's own traffic, whose route is chosen
            // on the way out.
            .filter(|name| !matches!(name.as_str(), "all" | "default" | "lo"))
            .filter(|name| {
                let on = |setting| read("all", setting) != 0 || read(name, setting) != 0;
                let strict = read("all", "rp_filter").max(read(name, "rp_filter")) == 1;
                on("src_valid_mark") && (!on("accept_local") || strict)
            })
            .collect();
        at_risk.sort();
        at_risk
    }

    /// Say so at startup when the host would drop what `TPROXY` delivers:
    /// the listener starts and binds either way, and a client behind one of
    /// these interfaces gets nothing, with no error anywhere. A warning, not
    /// a refusal, like the open-file limit: the settings are the host's, and
    /// clients on other interfaces are unaffected.
    fn warn_about_source_validation() {
        let at_risk =
            interfaces_dropping_marked_datagrams(std::path::Path::new("/proc/sys/net/ipv4/conf"));
        if !at_risk.is_empty() {
            println!(
                "WARNING: tproxy: src_valid_mark is on for {}, so the kernel drops the \
                 datagrams TPROXY marks on them as martians and their clients get no answer. \
                 Set net.ipv4.conf.all.src_valid_mark=0 (and per interface), or accept_local=1 \
                 on the LAN interface with rp_filter other than 1; see CONFIG.md, \"Tproxy\"",
                at_risk.join(", ")
            );
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const LISTENER: &str = "127.0.0.1:51271";
        const IDLE: Duration = Duration::from_secs(300);

        fn plain_socket(_spoof: SocketAddr) -> std::io::Result<tokio::net::UdpSocket> {
            let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
            socket.set_nonblocking(true)?;
            tokio::net::UdpSocket::from_std(socket)
        }

        fn refused_socket(_spoof: SocketAddr) -> std::io::Result<tokio::net::UdpSocket> {
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
        }

        fn stream(
            client: SocketAddr,
            budget: usize,
            open: OpenReplySocket,
        ) -> (mpsc::Sender<Datagram>, TproxyClientStream) {
            let (tx, rx) = mpsc::channel(CLIENT_QUEUE);
            let stream = TproxyClientStream::new(
                client,
                rx,
                Arc::new(Semaphore::new(budget)),
                open,
                Arc::new(AtomicBool::new(false)),
                IDLE,
            );
            (tx, stream)
        }

        async fn reply(stream: &mut TproxyClientStream, source: SocketAddr) -> std::io::Result<()> {
            std::future::poll_fn(|cx| {
                Pin::new(&mut *stream).poll_write_sourced_message(cx, b"reply", &source)
            })
            .await
        }

        #[tokio::test]
        async fn a_datagram_reads_with_its_original_destination() {
            let (tx, mut stream) = stream("10.0.0.5:4000".parse().unwrap(), 4, plain_socket);
            let destination: SocketAddr = "1.1.1.1:53".parse().unwrap();
            tx.send((destination, Bytes::from_static(b"query")))
                .await
                .unwrap();

            let mut buf = [0u8; 64];
            let mut read = ReadBuf::new(&mut buf);
            let target = std::future::poll_fn(|cx| {
                Pin::new(&mut stream).poll_read_targeted_message(cx, &mut read)
            })
            .await
            .unwrap();
            assert_eq!(target.to_socket_addr_nonblocking(), Some(destination));
            assert_eq!(read.filled(), b"query");
        }

        #[tokio::test]
        async fn a_client_whose_demux_is_gone_reads_end_of_stream() {
            let (tx, mut stream) = stream("10.0.0.5:4000".parse().unwrap(), 4, plain_socket);
            drop(tx);
            let mut buf = [0u8; 64];
            let mut read = ReadBuf::new(&mut buf);
            let err = std::future::poll_fn(|cx| {
                Pin::new(&mut stream).poll_read_targeted_message(cx, &mut read)
            })
            .await
            .unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
        }

        /// The write path end to end, with an ordinary socket standing in for
        /// the spoofed one: the reply reaches the client.
        #[tokio::test]
        async fn a_reply_reaches_the_client() {
            let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let (_tx, mut stream) = stream(client.local_addr().unwrap(), 4, plain_socket);
            reply(&mut stream, "1.1.1.1:53".parse().unwrap())
                .await
                .unwrap();
            let mut buf = [0u8; 64];
            let n = client.recv(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"reply");
            assert!(stream.replied.load(Ordering::Relaxed));
        }

        /// One remote that cannot be spoofed must not end the client's other
        /// flows, which an error from this write would do.
        #[tokio::test]
        async fn a_reply_that_cannot_be_sent_is_dropped_not_an_error() {
            let (_tx, mut stream) = stream("127.0.0.1:9".parse().unwrap(), 4, refused_socket);
            reply(&mut stream, "1.1.1.1:53".parse().unwrap())
                .await
                .unwrap();
        }

        /// The listener's budget is shared: when it is spent, a client
        /// recycles its own oldest socket rather than going without.
        #[tokio::test]
        async fn an_exhausted_budget_recycles_the_clients_oldest_socket() {
            let (_tx, mut stream) = stream("127.0.0.1:9".parse().unwrap(), 2, plain_socket);
            for port in [1, 2, 3] {
                reply(&mut stream, SocketAddr::from(([1, 1, 1, 1], port)))
                    .await
                    .unwrap();
            }
            let held: Vec<u16> = stream.replies.iter().map(|(addr, _)| addr.port()).collect();
            assert_eq!(held.len(), 2);
            assert!(!held.contains(&1), "the oldest socket went first: {held:?}");
            assert_eq!(stream.reply_budget.available_permits(), 0);
        }

        /// Over the per-client cap the oldest socket is evicted with its
        /// permit, so the listener's budget does not leak.
        #[tokio::test]
        async fn the_per_client_cap_returns_the_evicted_sockets_permit() {
            let budget = REPLY_SOCKETS_PER_CLIENT + 10;
            let (_tx, mut stream) = stream("127.0.0.1:9".parse().unwrap(), budget, plain_socket);
            for port in 1..=(REPLY_SOCKETS_PER_CLIENT as u16 + 5) {
                reply(&mut stream, SocketAddr::from(([1, 1, 1, 1], port)))
                    .await
                    .unwrap();
            }
            assert_eq!(stream.replies.len(), REPLY_SOCKETS_PER_CLIENT);
            assert_eq!(stream.reply_budget.available_permits(), 10);
        }

        fn refused_on_port_2(spoof: SocketAddr) -> std::io::Result<tokio::net::UdpSocket> {
            if spoof.port() == 2 {
                return refused_socket(spoof);
            }
            plain_socket(spoof)
        }

        /// With the budget spent, a remote that cannot be spoofed must not
        /// cost the client a socket that works: the old one is given up only
        /// once the new one is open.
        #[tokio::test]
        async fn a_reply_socket_that_cannot_open_costs_no_working_one() {
            let (_tx, mut stream) = stream("127.0.0.1:9".parse().unwrap(), 1, refused_on_port_2);
            let working = SocketAddr::from(([1, 1, 1, 1], 1));
            reply(&mut stream, working).await.unwrap();
            reply(&mut stream, SocketAddr::from(([1, 1, 1, 1], 2)))
                .await
                .unwrap();
            assert!(stream.replies.contains(&working));
            assert_eq!(stream.reply_budget.available_permits(), 0);
        }

        /// A queued datagram holds its own bytes and nothing more. A share
        /// of a larger receive block would keep the whole block alive for as
        /// long as it waits, and a client whose router stalls holds a full
        /// queue of them: 256 blocks of 1 MiB for a few bytes each.
        #[test]
        fn a_received_datagram_holds_only_its_own_bytes() {
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let addr = socket.local_addr().unwrap();
            sys::receive_original_destination(socket.as_raw_fd(), false).unwrap();
            let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            sender.send_to(b"first", addr).unwrap();
            sender.send_to(b"second", addr).unwrap();

            let mut receiver = Receiver::new();
            let (first, source, destination) = receiver.recv(socket.as_raw_fd()).unwrap();
            let (second, _, _) = receiver.recv(socket.as_raw_fd()).unwrap();
            assert_eq!((&first[..], &second[..]), (&b"first"[..], &b"second"[..]));
            assert_eq!(source, sender.local_addr().unwrap());
            assert_eq!(destination, Some(addr));
            assert!(
                first.is_unique(),
                "the first datagram shares its allocation"
            );
        }

        /// Budgets are per listener, so two addresses need twice the room.
        #[test]
        fn open_files_are_budgeted_for_every_listener() {
            assert_eq!(open_files_needed(4096, 1), 8193 + 64);
            assert_eq!(open_files_needed(4096, 2), 2 * 8193 + 64);
        }

        /// A fake `/proc/sys/net/ipv4/conf`: `all` and each interface,
        /// with the three settings that decide source validation.
        fn conf(interfaces: &[(&str, [u8; 3])]) -> tempfile::TempDir {
            let dir = tempfile::tempdir().unwrap();
            for (name, [src_valid_mark, accept_local, rp_filter]) in interfaces {
                let d = dir.path().join(name);
                std::fs::create_dir(&d).unwrap();
                for (file, value) in [
                    ("src_valid_mark", src_valid_mark),
                    ("accept_local", accept_local),
                    ("rp_filter", rp_filter),
                ] {
                    std::fs::write(d.join(file), format!("{value}\n")).unwrap();
                }
            }
            dir
        }

        /// The combinations `ip route get <dst> from <client> iif <lan> mark 1`
        /// answered with EINVAL on Linux 7.2, and the ones it routed.
        #[test]
        fn interfaces_that_drop_marked_datagrams_are_named() {
            let at_risk = |interfaces: &[(&str, [u8; 3])]| {
                let dir = conf(interfaces);
                interfaces_dropping_marked_datagrams(dir.path())
            };
            let defaults = [0, 0, 0];
            assert!(
                at_risk(&[("all", defaults), ("default", defaults), ("br0", defaults)]).is_empty()
            );
            // On under `all`, as wg-quick leaves it: every interface but `lo`.
            assert_eq!(
                at_risk(&[
                    ("all", [1, 0, 0]),
                    ("default", defaults),
                    ("lo", defaults),
                    ("br0", defaults),
                    ("eth0", defaults)
                ]),
                ["br0", "eth0"]
            );
            // On for one interface only.
            assert_eq!(
                at_risk(&[("all", defaults), ("br0", [1, 0, 2]), ("eth0", defaults)]),
                ["br0"]
            );
            // `accept_local` is the other remedy, under loose or no rp_filter
            // but not strict, wherever each is set.
            assert!(at_risk(&[("all", [1, 0, 2]), ("br0", [0, 1, 0])]).is_empty());
            assert!(at_risk(&[("all", [1, 1, 0]), ("br0", [0, 0, 0])]).is_empty());
            assert_eq!(at_risk(&[("all", [1, 0, 1]), ("br0", [0, 1, 0])]), ["br0"]);
            assert_eq!(at_risk(&[("all", [1, 1, 0]), ("br0", [0, 0, 1])]), ["br0"]);
        }

        /// Validation checked loopback on its own lookup; a name that
        /// answers differently at startup must not get a transparent socket
        /// on another address, where it relays ordinary traffic to itself.
        #[test]
        fn a_bind_that_resolves_off_loopback_at_startup_is_refused() {
            let at = |addr: &str| {
                let addr: SocketAddr = addr.parse().unwrap();
                vec![NetLocation::from(addr).into()]
            };
            assert_eq!(
                resolve_binds(at("127.0.0.1:51271")).unwrap(),
                ["127.0.0.1:51271".parse::<SocketAddr>().unwrap()]
            );
            let err = resolve_binds(at("192.168.1.1:51271")).unwrap_err();
            assert!(err.to_string().contains("loopback"), "{err}");
        }

        /// What the demux handed a client's router: its address, its
        /// datagrams, and its reply flag.
        type Spawned = (SocketAddr, mpsc::Receiver<Datagram>, Arc<AtomicBool>);
        type Recorded = Arc<std::sync::Mutex<Vec<Spawned>>>;
        type Router = Pin<Box<dyn std::future::Future<Output = ()> + Send>>;
        type Spawn =
            Box<dyn FnMut(SocketAddr, mpsc::Receiver<Datagram>, Arc<AtomicBool>) -> Router>;

        /// Clients whose receivers the test keeps, with routers that wait
        /// forever.
        fn clients(max: usize, idle: Duration) -> (Clients<Spawn>, Recorded) {
            let spawned = Arc::new(std::sync::Mutex::new(Vec::new()));
            let record = spawned.clone();
            let spawn: Spawn = Box::new(move |source, rx, replied| {
                record.lock().unwrap().push((source, rx, replied));
                Box::pin(std::future::pending())
            });
            let clients = Clients::new(LISTENER.parse().unwrap(), max, idle, spawn);
            (clients, spawned)
        }

        #[tokio::test]
        async fn datagrams_are_demultiplexed_by_client() {
            let (mut clients, spawned) = clients(8, Duration::from_secs(60));
            let a: SocketAddr = "10.0.0.5:4000".parse().unwrap();
            let b: SocketAddr = "10.0.0.6:4000".parse().unwrap();
            let dns: SocketAddr = "1.1.1.1:53".parse().unwrap();
            let now = Instant::now();
            for (source, payload) in [(a, "a1"), (b, "b1"), (a, "a2")] {
                assert_eq!(
                    clients.deliver(source, dns, Bytes::from(payload), now),
                    Delivery::Delivered
                );
            }
            let mut spawned = spawned.lock().unwrap();
            assert_eq!(spawned.len(), 2, "one router per client, not per datagram");
            let (source, rx, _) = &mut spawned[0];
            assert_eq!(*source, a);
            assert_eq!(rx.try_recv().unwrap(), (dns, Bytes::from("a1")));
            assert_eq!(rx.try_recv().unwrap(), (dns, Bytes::from("a2")));
            let (source, rx, _) = &mut spawned[1];
            assert_eq!(*source, b);
            assert_eq!(rx.try_recv().unwrap(), (dns, Bytes::from("b1")));
        }

        /// Datagrams no router may see. An empty one reads as end of stream
        /// to the router, which then never reads that client again. One
        /// addressed to the listener itself is shoes' own dial arriving back:
        /// each relay is a new client, until `udp_nat_max` is spent. The rest
        /// are not one remote's flow at all, and TPROXY receives them only
        /// when the firewall rule is too broad.
        #[tokio::test]
        async fn datagrams_no_router_may_see_never_make_a_client() {
            let (mut clients, spawned) = clients(8, Duration::from_secs(60));
            let a: SocketAddr = "10.0.0.5:4000".parse().unwrap();
            let dns: SocketAddr = "1.1.1.1:53".parse().unwrap();
            let now = Instant::now();
            assert_eq!(
                clients.deliver(a, dns, Bytes::new(), now),
                Delivery::Ignored
            );
            for destination in [
                LISTENER,
                "0.0.0.0:53",
                "255.255.255.255:67",
                "224.0.0.251:5353",
                "239.255.255.250:1900",
                "[ff02::fb]:5353",
                "[::]:53",
                "1.1.1.1:0",
            ] {
                let destination: SocketAddr = destination.parse().unwrap();
                assert_eq!(
                    clients.deliver(a, destination, Bytes::from_static(b"x"), now),
                    Delivery::Ignored,
                    "{destination}"
                );
            }
            assert!(spawned.lock().unwrap().is_empty());
            assert_eq!(
                clients.deliver(a, dns, Bytes::from_static(b"x"), now),
                Delivery::Delivered
            );
        }

        /// A client's reply sockets age out with its sessions: otherwise a
        /// few clients that once spoke to many remotes keep the listener's
        /// whole reply budget for as long as they keep sending anything, and
        /// every reply to a newcomer is dropped.
        #[tokio::test(start_paused = true)]
        async fn idle_reply_sockets_return_their_share_of_the_budget() {
            let (tx, mut stream) = stream("127.0.0.1:9".parse().unwrap(), 4, plain_socket);
            for port in [1, 2, 3] {
                reply(&mut stream, SocketAddr::from(([1, 1, 1, 1], port)))
                    .await
                    .unwrap();
            }
            assert_eq!(stream.reply_budget.available_permits(), 1);

            tokio::time::advance(IDLE + Duration::from_secs(1)).await;
            // Any datagram from the client is an occasion to prune.
            tx.send(("1.1.1.1:1".parse().unwrap(), Bytes::from_static(b"x")))
                .await
                .unwrap();
            let mut buf = [0u8; 64];
            let mut read = ReadBuf::new(&mut buf);
            std::future::poll_fn(|cx| {
                Pin::new(&mut stream).poll_read_targeted_message(cx, &mut read)
            })
            .await
            .unwrap();
            assert!(stream.replies.is_empty());
            assert_eq!(stream.reply_budget.available_permits(), 4);
        }

        /// At `udp_nat_max` clients a newcomer evicts the client heard from
        /// least recently, as sing-box's UDP NAT does, rather than being
        /// refused: every DNS query from a fresh source port is a client, and
        /// refusal would fail every new lookup until the idle sweep ran.
        #[tokio::test]
        async fn a_client_past_the_cap_evicts_the_least_recently_seen() {
            let (mut clients, spawned) = clients(2, Duration::from_secs(60));
            let dns: SocketAddr = "1.1.1.1:53".parse().unwrap();
            let now = Instant::now();
            let a: SocketAddr = "10.0.0.5:4000".parse().unwrap();
            let b: SocketAddr = "10.0.0.6:4000".parse().unwrap();
            let c: SocketAddr = "10.0.0.7:4000".parse().unwrap();
            for source in [a, b, a, c] {
                assert_eq!(
                    clients.deliver(source, dns, Bytes::from_static(b"x"), now),
                    Delivery::Delivered,
                    "{source}"
                );
            }
            let spawned = spawned.lock().unwrap();
            assert_eq!(spawned.len(), 3);
            assert!(spawned[1].1.is_closed(), "b, least recently seen, went");
            assert!(!spawned[0].1.is_closed(), "a was heard from after b");
            assert_eq!(clients.clients.len(), 2);
        }

        /// A client that only receives is in use: replies seen by the sweep
        /// keep it from being the one evicted.
        #[tokio::test]
        async fn a_client_receiving_replies_is_not_the_one_evicted() {
            let (mut clients, spawned) = clients(2, Duration::from_secs(60));
            let dns: SocketAddr = "1.1.1.1:53".parse().unwrap();
            let now = Instant::now();
            let a: SocketAddr = "10.0.0.5:4000".parse().unwrap();
            let b: SocketAddr = "10.0.0.6:4000".parse().unwrap();
            let c: SocketAddr = "10.0.0.7:4000".parse().unwrap();
            clients.deliver(a, dns, Bytes::from_static(b"x"), now);
            clients.deliver(b, dns, Bytes::from_static(b"x"), now);
            spawned.lock().unwrap()[0].2.store(true, Ordering::Relaxed);
            clients.sweep(now + Duration::from_secs(1));
            clients.deliver(c, dns, Bytes::from_static(b"x"), now);
            let spawned = spawned.lock().unwrap();
            assert!(!spawned[0].1.is_closed(), "a is receiving replies");
            assert!(spawned[1].1.is_closed(), "b went instead");
        }

        /// Replies since the last sweep count too: eviction must not wait
        /// for the sweep to learn that the oldest client is receiving.
        #[tokio::test]
        async fn a_client_replied_to_since_the_sweep_is_not_the_one_evicted() {
            let (mut clients, spawned) = clients(2, Duration::from_secs(60));
            let dns: SocketAddr = "1.1.1.1:53".parse().unwrap();
            let now = Instant::now();
            let a: SocketAddr = "10.0.0.5:4000".parse().unwrap();
            let b: SocketAddr = "10.0.0.6:4000".parse().unwrap();
            let c: SocketAddr = "10.0.0.7:4000".parse().unwrap();
            clients.deliver(a, dns, Bytes::from_static(b"x"), now);
            clients.deliver(b, dns, Bytes::from_static(b"x"), now);
            spawned.lock().unwrap()[0].2.store(true, Ordering::Relaxed);
            clients.deliver(c, dns, Bytes::from_static(b"x"), now);
            let spawned = spawned.lock().unwrap();
            assert!(!spawned[0].1.is_closed(), "a is receiving replies");
            assert!(spawned[1].1.is_closed(), "b went instead");
        }

        /// An evicted router keeps its sessions' share of the budget until
        /// its cancellation lands, which on another worker can be after the
        /// newcomer's first datagram asks for a session. The newcomer waits
        /// for it to be gone, so the capacity its eviction freed is there.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_newcomer_starts_once_the_evicted_router_is_gone() {
            /// Holds the evicted router's drop open, as a router with many
            /// sessions to close would.
            struct SlowDrop;
            impl Drop for SlowDrop {
                fn drop(&mut self) {
                    std::thread::sleep(Duration::from_millis(100));
                }
            }

            let budget = Arc::new(Semaphore::new(1));
            let admitted = Arc::new(std::sync::Mutex::new(Vec::new()));
            let spawn: Spawn = {
                let admitted = admitted.clone();
                Box::new(move |source, rx, _replied| {
                    let budget = budget.clone();
                    let admitted = admitted.clone();
                    Box::pin(async move {
                        let permit = budget.try_acquire_owned();
                        admitted.lock().unwrap().push((source, permit.is_ok()));
                        // Dropped before the permit: locals go in reverse.
                        let _slow = SlowDrop;
                        let _rx = rx;
                        std::future::pending::<()>().await;
                    })
                })
            };
            let mut clients =
                Clients::new(LISTENER.parse().unwrap(), 1, Duration::from_secs(60), spawn);
            let dns: SocketAddr = "1.1.1.1:53".parse().unwrap();
            let a: SocketAddr = "10.0.0.5:4000".parse().unwrap();
            let b: SocketAddr = "10.0.0.6:4000".parse().unwrap();
            clients.deliver(a, dns, Bytes::from_static(b"x"), Instant::now());
            while admitted.lock().unwrap().is_empty() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            clients.deliver(b, dns, Bytes::from_static(b"x"), Instant::now());
            for _ in 0..2000 {
                if admitted.lock().unwrap().len() == 2 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            assert_eq!(
                *admitted.lock().unwrap(),
                [(a, true), (b, true)],
                "b found the budget a held"
            );
        }

        /// A client whose router has ended is replaced by the next datagram
        /// from it, not reported as a full queue until the sweep finds it.
        #[tokio::test]
        async fn a_client_whose_router_ended_is_started_afresh() {
            let (mut clients, spawned) = clients(8, Duration::from_secs(60));
            let a: SocketAddr = "10.0.0.5:4000".parse().unwrap();
            let dns: SocketAddr = "1.1.1.1:53".parse().unwrap();
            let now = Instant::now();
            clients.deliver(a, dns, Bytes::from_static(b"1"), now);
            spawned.lock().unwrap()[0].1.close();
            assert_eq!(
                clients.deliver(a, dns, Bytes::from_static(b"2"), now),
                Delivery::Delivered
            );
            let mut spawned = spawned.lock().unwrap();
            assert_eq!(spawned.len(), 2, "a second router for the same client");
            assert_eq!(spawned[1].1.try_recv().unwrap(), (dns, Bytes::from("2")));
        }

        #[tokio::test]
        async fn a_full_client_queue_drops_rather_than_waits() {
            let (mut clients, _spawned) = clients(8, Duration::from_secs(60));
            let a: SocketAddr = "10.0.0.5:4000".parse().unwrap();
            let dns: SocketAddr = "1.1.1.1:53".parse().unwrap();
            let now = Instant::now();
            for _ in 0..CLIENT_QUEUE {
                assert_eq!(
                    clients.deliver(a, dns, Bytes::from_static(b"x"), now),
                    Delivery::Delivered
                );
            }
            assert_eq!(
                clients.deliver(a, dns, Bytes::from_static(b"x"), now),
                Delivery::Dropped
            );
        }

        /// Idle means idle both ways: a client that only receives, a download
        /// say, is kept while replies flow and expires once they stop.
        #[tokio::test]
        async fn a_client_expires_when_idle_both_ways() {
            let idle = Duration::from_secs(60);
            let (mut clients, spawned) = clients(8, idle);
            let a: SocketAddr = "10.0.0.5:4000".parse().unwrap();
            let dns: SocketAddr = "1.1.1.1:53".parse().unwrap();
            let start = Instant::now();
            clients.deliver(a, dns, Bytes::from_static(b"x"), start);

            let replied = spawned.lock().unwrap()[0].2.clone();
            replied.store(true, Ordering::Relaxed);
            clients.sweep(start + idle + Duration::from_secs(1));
            assert_eq!(clients.clients.len(), 1, "replies are activity");

            clients.sweep(start + 3 * idle);
            assert!(
                clients.clients.is_empty(),
                "silent both ways for longer than idle"
            );
            assert!(
                spawned.lock().unwrap()[0].1.is_closed(),
                "an expired client's stream reads end of stream once drained"
            );
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::start_tproxy_udp_server;
