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

pub mod sys;

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::num::NonZeroUsize;
    use std::os::fd::AsRawFd;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context, Poll};
    use std::time::Duration;

    use bytes::{Bytes, BytesMut};
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
    /// The receive buffer is carved into one `Bytes` per datagram, and a new
    /// block is allocated only when the last one cannot hold a full datagram:
    /// one allocation per many datagrams rather than one per datagram.
    const RECV_BLOCK: usize = 1 << 20;
    const SWEEP_INTERVAL: Duration = Duration::from_secs(5);

    /// A datagram's original destination and its payload.
    type Datagram = (SocketAddr, Bytes);

    /// How a reply socket is made. A function pointer so the tests can open
    /// an ordinary socket where production needs `CAP_NET_ADMIN`.
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
            if !self.replies.contains(&spoof) {
                // Out of budget: free this client's own oldest socket and try
                // once more, so a busy client recycles rather than starves.
                // If the listener is still full the caller drops the reply.
                let permit = match self.reply_budget.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        self.replies.pop_lru();
                        match self.reply_budget.clone().try_acquire_owned() {
                            Ok(permit) => permit,
                            Err(_) => {
                                if !self.budget_refusal_reported {
                                    self.budget_refusal_reported = true;
                                    warn!(
                                        "tproxy: udp_nat_max reply sockets all in use; replies \
                                         to {} are dropped until some go idle",
                                        self.client
                                    );
                                }
                                return Err(std::io::Error::other(
                                    "the listener's reply sockets are all in use",
                                ));
                            }
                        }
                    }
                };
                self.budget_refusal_reported = false;
                let socket = (self.open_reply_socket)(spoof)?;
                // At the per-client cap this evicts the oldest socket, and
                // its permit with it.
                self.replies.put(
                    spoof,
                    ReplySocket {
                        socket,
                        last_used: Instant::now(),
                        _permit: permit,
                    },
                );
            }
            let entry = self.replies.get_mut(&spoof).unwrap();
            entry.last_used = Instant::now();
            Ok(&entry.socket)
        }
    }

    /// The address a reply to `client` must come from: `remote`, in the
    /// client's address family. The router reports the remote as it resolved
    /// it, and an IPv4 remote seen through a dual-stack socket arrives
    /// IPv4-mapped; a socket of the wrong family cannot send to the client.
    fn reply_source(remote: SocketAddr, client: SocketAddr) -> SocketAddr {
        match (remote, client) {
            (SocketAddr::V6(v6), SocketAddr::V4(_)) => match v6.ip().to_ipv4_mapped() {
                Some(v4) => SocketAddr::new(v4.into(), v6.port()),
                None => remote,
            },
            (SocketAddr::V4(v4), SocketAddr::V6(_)) => {
                SocketAddr::new(v4.ip().to_ipv6_mapped().into(), v4.port())
            }
            _ => remote,
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
            let spoof = reply_source(*source, client);
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
        task: JoinHandle<()>,
    }

    impl Drop for Client {
        /// A client is dropped when it expires or the listener stops; either
        /// way its router goes with it.
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    #[derive(Debug, PartialEq)]
    enum Delivery {
        Delivered,
        /// A datagram no router may see; see `worth_routing`.
        Ignored,
        /// A new client, with the listener already at `udp_nat_max` clients.
        Refused,
        /// The client's queue is full.
        Dropped,
    }

    /// The listener's clients, keyed by source address.
    struct Clients<S> {
        /// The listener's own address, which no datagram may be routed to.
        listener: SocketAddr,
        clients: HashMap<SocketAddr, Client>,
        /// Every client holds at least one session, so more clients than
        /// `udp_nat_max` could never all be served.
        max_clients: usize,
        idle: Duration,
        /// Starts a client's router over its stream.
        spawn: S,
    }

    impl<S> Clients<S>
    where
        S: FnMut(SocketAddr, mpsc::Receiver<Datagram>, Arc<AtomicBool>) -> JoinHandle<()>,
    {
        fn new(listener: SocketAddr, max_clients: usize, idle: Duration, spawn: S) -> Self {
            Self {
                listener,
                clients: HashMap::new(),
                max_clients,
                idle,
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
            if !self.clients.contains_key(&source) {
                if self.clients.len() >= self.max_clients {
                    return Delivery::Refused;
                }
                let (tx, rx) = mpsc::channel(CLIENT_QUEUE);
                let replied = Arc::new(AtomicBool::new(false));
                let task = (self.spawn)(source, rx, replied.clone());
                self.clients.insert(
                    source,
                    Client {
                        tx,
                        last_seen: now,
                        replied,
                        task,
                    },
                );
            }
            let client = self.clients.get_mut(&source).unwrap();
            client.last_seen = now;
            // Bounded, and full means drop: what a full socket buffer does,
            // and the only answer that cannot stall the listener for every
            // other client.
            match client.tx.try_send((destination, payload)) {
                Ok(()) => Delivery::Delivered,
                Err(_) => Delivery::Dropped,
            }
        }

        /// Forget clients idle in both directions for `idle`, and clients
        /// whose router has ended.
        fn sweep(&mut self, now: Instant) {
            let idle = self.idle;
            self.clients.retain(|source, client| {
                if client.replied.swap(false, Ordering::Relaxed) {
                    client.last_seen = now;
                }
                let keep =
                    now.duration_since(client.last_seen) < idle && !client.task.is_finished();
                if !keep {
                    debug!("tproxy: client {source} expired");
                }
                keep
            });
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
        let open_files = raise_open_file_limit(udp_nat_max);
        let rules = config.rules.map(ConfigSelection::unwrap_config).into_vec();
        let selector = Arc::new(
            crate::tcp::tcp_client_handler_factory::create_tcp_client_proxy_selector(
                rules,
                resolver.clone(),
            ),
        );

        let mut handles: Vec<JoinHandle<()>> = Vec::new();
        for address in addresses.into_vec() {
            for bind in address.to_socket_addrs()? {
                println!(
                    "Starting TPROXY UDP server at {bind} (udp_nat_max {udp_nat_max}, \
                     open-file limit {open_files})"
                );
                let listener = match crate::socket_util::new_transparent_udp_listener(bind) {
                    Ok(listener) => AsyncFd::new(listener)?,
                    Err(e) => {
                        for handle in &handles {
                            handle.abort();
                        }
                        return Err(std::io::Error::new(
                            e.kind(),
                            format!("tproxy listener at {bind}: {e}"),
                        ));
                    }
                };
                // One budget of each kind per listener, shared by every
                // client's router and reply cache: `udp_nat_max` is a
                // promise about the listener's descriptors, not each client's.
                let limits = RouterLimits {
                    session_timeout: Duration::from_secs(udp_timeout),
                    max_sessions: udp_nat_max,
                    shared_budget: Some(Arc::new(Semaphore::new(udp_nat_max))),
                };
                let reply_budget = Arc::new(Semaphore::new(udp_nat_max));
                let label =
                    crate::tcp::tcp_server::inbound_label(&config.protocol, &bind.to_string());
                handles.push(tokio::spawn(demux(
                    listener,
                    bind,
                    selector.clone(),
                    resolver.clone(),
                    limits,
                    reply_budget,
                    label,
                )));
            }
        }
        Ok(handles)
    }

    async fn demux(
        listener: AsyncFd<socket2::Socket>,
        bind: SocketAddr,
        selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
        limits: RouterLimits,
        reply_budget: Arc<Semaphore>,
        label: &'static str,
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
                tokio::spawn(async move {
                    // One registry row per client source socket, not per
                    // destination: a row per destination would be a registry
                    // write on the session-create path (spec, "Decisions").
                    let _handle = crate::connection_registry::register(
                        client,
                        label,
                        crate::connection_registry::Network::Udp,
                    );
                    let stream = ServerStream::Targeted(Box::new(stream));
                    if let Err(e) =
                        run_udp_routing_with_limits(stream, selector, resolver, false, limits).await
                    {
                        debug!("tproxy client {client} ended: {e}");
                    }
                })
            }
        };
        let mut clients = Clients::new(bind, limits.max_sessions, limits.session_timeout, spawn);
        let mut buf = BytesMut::new();
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
                    if buf.capacity() - buf.len() < MAX_DATAGRAM {
                        buf.reserve(RECV_BLOCK);
                    }
                    let spare = &mut buf.spare_capacity_mut()[..MAX_DATAGRAM];
                    let received = guard.try_io(|inner| {
                        sys::recv_with_original_destination(inner.get_ref().as_raw_fd(), spare)
                    });
                    let (n, source, destination) = match received {
                        Ok(Ok(datagram)) => datagram,
                        Ok(Err(e)) => {
                            debug!("tproxy recvmsg: {e}");
                            continue;
                        }
                        Err(_would_block) => continue,
                    };
                    // SAFETY: the kernel initialised the first `n` bytes of
                    // the spare capacity it was handed.
                    unsafe { buf.set_len(n) };
                    let payload = buf.split().freeze();
                    let Some(destination) = destination else {
                        debug!("tproxy: datagram from {source} without an original destination; dropped");
                        continue;
                    };
                    match clients.deliver(source, destination, payload, Instant::now()) {
                        Delivery::Delivered => {}
                        Delivery::Ignored => {
                            debug!("tproxy: datagram from {source} for {destination} ignored")
                        }
                        Delivery::Refused => warn!(
                            "tproxy: udp_nat_max {} clients reached; datagram from {source} dropped",
                            clients.max_clients
                        ),
                        Delivery::Dropped => {
                            debug!("tproxy: client {source} queue full; datagram dropped")
                        }
                    }
                }
                _ = sweep.tick() => clients.sweep(Instant::now()),
            }
        }
    }

    /// Raise the soft open-file limit to the hard one and return it, warning
    /// when a full listener could exceed it: `udp_nat_max` sessions plus as
    /// many reply sockets, and room for everything else the process holds.
    /// A warning, not a refusal: the limit is the host's to change, and a
    /// listener over it degrades by dropping, not by failing. Entware's soft
    /// limit is 1024 on some routers, below the default `udp_nat_max`.
    fn raise_open_file_limit(udp_nat_max: usize) -> u64 {
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
        let needed = 2 * udp_nat_max as u64 + 64;
        if limit < needed {
            println!(
                "WARNING: tproxy udp_nat_max {udp_nat_max} needs up to {needed} open files and \
                 the limit is {limit}; past it new UDP sessions are dropped. Raise the limit \
                 (ulimit -n) or lower udp_nat_max"
            );
        }
        limit
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

        #[test]
        fn a_reply_speaks_in_the_clients_address_family() {
            let v4_client: SocketAddr = "192.168.1.5:4000".parse().unwrap();
            let v6_client: SocketAddr = "[fd00::5]:4000".parse().unwrap();
            let mapped: SocketAddr = "[::ffff:1.1.1.1]:53".parse().unwrap();
            let v4: SocketAddr = "1.1.1.1:53".parse().unwrap();
            let v6: SocketAddr = "[2606:4700::1111]:53".parse().unwrap();
            assert_eq!(reply_source(mapped, v4_client), v4);
            assert_eq!(reply_source(v4, v4_client), v4);
            assert_eq!(reply_source(v4, v6_client), mapped);
            assert_eq!(reply_source(v6, v6_client), v6);
        }

        /// What the demux handed a client's router: its address, its
        /// datagrams, and its reply flag.
        type Spawned = (SocketAddr, mpsc::Receiver<Datagram>, Arc<AtomicBool>);
        type Recorded = Arc<std::sync::Mutex<Vec<Spawned>>>;
        type Spawn =
            Box<dyn FnMut(SocketAddr, mpsc::Receiver<Datagram>, Arc<AtomicBool>) -> JoinHandle<()>>;

        /// Clients whose receivers the test keeps, with routers that wait
        /// forever.
        fn clients(max: usize, idle: Duration) -> (Clients<Spawn>, Recorded) {
            let spawned = Arc::new(std::sync::Mutex::new(Vec::new()));
            let record = spawned.clone();
            let spawn: Spawn = Box::new(move |source, rx, replied| {
                record.lock().unwrap().push((source, rx, replied));
                tokio::spawn(std::future::pending())
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

        #[tokio::test]
        async fn a_client_past_the_cap_is_refused_and_an_existing_one_is_not() {
            let (mut clients, _spawned) = clients(1, Duration::from_secs(60));
            let dns: SocketAddr = "1.1.1.1:53".parse().unwrap();
            let now = Instant::now();
            let a: SocketAddr = "10.0.0.5:4000".parse().unwrap();
            let b: SocketAddr = "10.0.0.6:4000".parse().unwrap();
            assert_eq!(
                clients.deliver(a, dns, Bytes::from_static(b"x"), now),
                Delivery::Delivered
            );
            assert_eq!(
                clients.deliver(b, dns, Bytes::from_static(b"x"), now),
                Delivery::Refused
            );
            assert_eq!(
                clients.deliver(a, dns, Bytes::from_static(b"x"), now),
                Delivery::Delivered
            );
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
