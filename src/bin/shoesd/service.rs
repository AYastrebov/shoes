//! The gRPC service.
//!
//! Handlers do no work of their own. Everything that touches the session goes
//! to the supervisor over a channel and comes back through a `oneshot`, and
//! the blocking wait for that happens on `spawn_blocking` -- a gRPC worker
//! that parks is one that stops serving every other client, and the calls it
//! waits on can take seconds by design.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use shoes::control::StopOutcome;
use shoes::control::logs::BroadcastLogWriter;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

pub mod proto {
    // The generated module, named for the proto package.
    tonic::include_proto!("shoes.daemon.v1");
}

use proto::daemon_server::{Daemon, DaemonServer};

use crate::auth::Authorizer;
use crate::supervisor::{StartError, State, StopReason, Supervisor};

/// The protocol version in `HelloReply`. A client that does not recognise it
/// must not proceed; that is the whole reason it is the first field of the
/// first call.
const PROTOCOL_VERSION: u32 = 1;

/// Floor on `WatchStats` polling. A client asking for 1 ms would spend the
/// daemon's CPU on its own frame rate.
const MIN_STATS_INTERVAL: Duration = Duration::from_millis(100);

/// How many messages a stream buffers before its sender waits.
const STREAM_BUFFER: usize = 32;

pub struct DaemonService {
    authorizer: Authorizer,
    supervisor: Supervisor,
    logs: Arc<BroadcastLogWriter>,
}

/// What this build can do to the host.
///
/// Reported rather than inferred: a client must not decide from the operating
/// system what the daemon is capable of, because a build can be missing an arm
/// the platform could in principle support.
fn capabilities() -> Vec<String> {
    if cfg!(target_os = "macos") {
        vec!["routes".to_string(), "dns".to_string()]
    } else {
        Vec::new()
    }
}

#[tonic::async_trait]
impl Daemon for DaemonService {
    async fn hello(
        &self,
        request: Request<proto::HelloRequest>,
    ) -> Result<Response<proto::HelloReply>, Status> {
        self.check_peer(&request)?;

        let client = request.get_ref();
        log::info!("hello from {:?} {:?}", client.client, client.client_version);

        Ok(Response::new(proto::HelloReply {
            protocol: PROTOCOL_VERSION,
            daemon_version: env!("CARGO_PKG_VERSION").to_string(),
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            capabilities: capabilities(),
        }))
    }

    async fn start(
        &self,
        request: Request<proto::StartRequest>,
    ) -> Result<Response<proto::StartReply>, Status> {
        self.check_peer(&request)?;
        let request = request.into_inner();

        // Parsed here rather than deeper in: these become arguments to `route`
        // as root, and the wire is the only place they are allowed to be text.
        // A name is refused rather than resolved -- that lookup's answer would
        // decide what bypasses the tunnel.
        let exclude = parse_addresses(&request.exclude, "exclude")?;
        let dns = parse_addresses(&request.dns, "dns")?;

        let supervisor = self.supervisor.clone();
        let result =
            tokio::task::spawn_blocking(move || supervisor.start(request.yaml, exclude, dns))
                .await
                .map_err(|e| Status::internal(format!("the start task failed: {e}")))?;

        match result {
            Ok(()) => Ok(Response::new(proto::StartReply {})),
            Err(e) => Err(start_error_to_status(e)),
        }
    }

    async fn stop(
        &self,
        request: Request<proto::StopRequest>,
    ) -> Result<Response<proto::StopReply>, Status> {
        self.check_peer(&request)?;

        let supervisor = self.supervisor.clone();
        let outcome = tokio::task::spawn_blocking(move || supervisor.stop())
            .await
            .map_err(|e| Status::internal(format!("the stop task failed: {e}")))?;

        // Not an error. `TimedOut` is a successful call reporting that the
        // engine did not confirm it released the device, and typing it as a
        // failure would invite a client to discard the distinction.
        let outcome = match outcome {
            StopOutcome::Released => proto::stop_reply::Outcome::Released,
            StopOutcome::TimedOut { .. } => proto::stop_reply::Outcome::TimedOut,
        };
        Ok(Response::new(proto::StopReply {
            outcome: outcome as i32,
        }))
    }

    async fn get_status(
        &self,
        request: Request<proto::StatusRequest>,
    ) -> Result<Response<proto::Status>, Status> {
        self.check_peer(&request)?;
        Ok(Response::new(self.current_status().await?))
    }

    type WatchStatusStream = ReceiverStream<Result<proto::Status, Status>>;
    type WatchStatsStream = ReceiverStream<Result<proto::Stats, Status>>;
    type WatchLogsStream = ReceiverStream<Result<proto::LogLine, Status>>;

    async fn watch_status(
        &self,
        request: Request<proto::StatusRequest>,
    ) -> Result<Response<Self::WatchStatusStream>, Status> {
        self.check_peer(&request)?;

        // Subscribed before the current status is read, so a transition that
        // lands between the two is delivered rather than lost. The client may
        // see a state twice; it may not miss one.
        let mut transitions = self.supervisor.watch();
        let current = self.current_status().await?;

        let (tx, rx) = mpsc::channel(STREAM_BUFFER);
        tokio::spawn(async move {
            if tx.send(Ok(current)).await.is_err() {
                return;
            }
            loop {
                match transitions.recv().await {
                    Ok(status) => {
                        if tx.send(Ok(to_proto_status(status))).await.is_err() {
                            return;
                        }
                    }
                    // Lagged: the client is slower than the session changes
                    // state. Its next message is still the truth, so the
                    // stream continues rather than ending.
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        log::warn!("a status watcher missed {n} transition(s)");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn watch_stats(
        &self,
        request: Request<proto::StatsRequest>,
    ) -> Result<Response<Self::WatchStatsStream>, Status> {
        self.check_peer(&request)?;

        let interval = Duration::from_millis(u64::from(request.into_inner().interval_ms))
            .max(MIN_STATS_INTERVAL);
        let supervisor = self.supervisor.clone();

        let (tx, rx) = mpsc::channel(STREAM_BUFFER);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;

                let supervisor = supervisor.clone();
                let Ok(status) = tokio::task::spawn_blocking(move || supervisor.status()).await
                else {
                    return;
                };

                // Only while running. Counters from a stopped session are the
                // last one's totals against no uptime, which a client would
                // draw as a flat line rather than as nothing.
                if status.state != State::Running {
                    continue;
                }

                let stats = proto::Stats {
                    upload_bytes: status.upload_bytes,
                    download_bytes: status.download_bytes,
                    active_connections: status.active_connections as u32,
                };
                if tx.send(Ok(stats)).await.is_err() {
                    return;
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn watch_logs(
        &self,
        request: Request<proto::LogsRequest>,
    ) -> Result<Response<Self::WatchLogsStream>, Status> {
        self.check_peer(&request)?;

        // The requested level filters what this subscriber is sent; it does
        // not raise the global one. A log stream must not be able to turn on
        // logging the daemon's own configuration left off -- these lines cross
        // a privilege boundary into a user session.
        let floor = shoes::logging::parse_log_level(&request.into_inner().level);

        let (backlog, mut live) = self.logs.subscribe();
        let (tx, rx) = mpsc::channel(STREAM_BUFFER);
        tokio::spawn(async move {
            for line in backlog {
                if passes(&line, floor) && tx.send(Ok(to_proto_log(line))).await.is_err() {
                    return;
                }
            }
            loop {
                match live.recv().await {
                    Ok(line) => {
                        if passes(&line, floor) && tx.send(Ok(to_proto_log(line))).await.is_err() {
                            return;
                        }
                    }
                    // A subscriber that falls behind loses lines rather than
                    // stalling the writer, which runs on the packet path.
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        log::debug!("a log watcher missed {n} line(s)");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

impl DaemonService {
    async fn current_status(&self) -> Result<proto::Status, Status> {
        let supervisor = self.supervisor.clone();
        let status = tokio::task::spawn_blocking(move || supervisor.status())
            .await
            .map_err(|e| Status::internal(format!("the status task failed: {e}")))?;
        Ok(to_proto_status(status))
    }

    /// Reject a caller who is neither root nor in the configured group.
    ///
    /// Per call rather than per connection. A connection is authorised once
    /// and then used for as long as the client likes, so putting the check at
    /// accept time makes the answer older with every request; and the cost
    /// here is reading two integers out of the request extensions.
    fn check_peer<T>(&self, request: &Request<T>) -> Result<(), Status> {
        let Some(info) = request
            .extensions()
            .get::<tonic::transport::server::UdsConnectInfo>()
        else {
            // No connect info means this did not arrive over the Unix socket
            // this daemon serves. There is no other transport, so this is a
            // programming error rather than an attack -- but it must not be
            // read as "no credentials, therefore allow".
            return Err(Status::permission_denied(
                "no peer credentials on this connection",
            ));
        };

        let Some(cred) = info.peer_cred else {
            return Err(Status::permission_denied(
                "the peer supplied no credentials",
            ));
        };

        let (uid, gid) = (cred.uid(), cred.gid());
        if self.authorizer.allows(uid, gid) {
            return Ok(());
        }

        // The uid is logged and not returned: the caller already knows who it
        // is, and the message stays the same for every refusal so it cannot
        // be used to probe which groups exist.
        log::warn!("refused a call from uid {uid} (gid {gid})");
        Err(Status::permission_denied(
            "not permitted; this daemon serves root and one configured group",
        ))
    }
}

/// The error mapping a client switches on.
fn start_error_to_status(error: StartError) -> Status {
    match error {
        StartError::AlreadyRunning => {
            Status::already_exists("a session is already running; stop it first")
        }
        // Forwarded verbatim: this is shoes' own message about the user's own
        // config, and rewording it would lose the field it names.
        StartError::Config(e) => Status::invalid_argument(e.to_string()),
        StartError::Device(message) => Status::failed_precondition(message),
        // The daemon has already undone whatever it applied, which is what
        // makes this a retryable condition rather than a broken machine.
        StartError::HostNetwork(e) => Status::unavailable(e.to_string()),
    }
}

/// Literal addresses only.
fn parse_addresses(values: &[String], field: &str) -> Result<Vec<IpAddr>, Status> {
    values
        .iter()
        .map(|value| {
            value.parse::<IpAddr>().map_err(|_| {
                Status::invalid_argument(format!(
                    "{field}: {value:?} is not an IP address. Resolve names before sending \
                     them -- that answer decides what bypasses the tunnel"
                ))
            })
        })
        .collect()
}

fn to_proto_status(status: crate::supervisor::Status) -> proto::Status {
    let (state, reason) = match &status.state {
        State::Stopped {
            reason: StopReason::Requested,
        } => (proto::status::State::Stopped, "requested".to_string()),
        State::Stopped {
            reason: StopReason::Failed(message),
        } => (proto::status::State::Stopped, message.clone()),
        State::Starting => (proto::status::State::Starting, String::new()),
        State::Running => (proto::status::State::Running, String::new()),
        State::Stopping => (proto::status::State::Stopping, String::new()),
    };

    proto::Status {
        state: state as i32,
        reason,
        uptime_ms: status.uptime.map(|d| d.as_millis() as u64).unwrap_or(0),
        upload_bytes: status.upload_bytes,
        download_bytes: status.download_bytes,
        interface: status.interface.unwrap_or_default(),
    }
}

fn to_proto_log(line: shoes::control::logs::LogLine) -> proto::LogLine {
    proto::LogLine {
        level: line.level.to_string(),
        target: line.target,
        message: line.message,
        at_ms: line
            .at
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0),
    }
}

/// Whether a line is at or above the level this subscriber asked for.
///
/// An unrecognised level means no extra filtering, which leaves the daemon's
/// own configuration in charge -- the direction that cannot hide a line the
/// operator wanted.
fn passes(line: &shoes::control::logs::LogLine, floor: Option<log::LevelFilter>) -> bool {
    floor.is_none_or(|floor| line.level <= floor)
}

/// Serve until `SIGTERM`.
pub async fn serve(
    socket_path: &std::path::Path,
    group: &str,
    supervisor: Supervisor,
    logs: Arc<BroadcastLogWriter>,
) -> std::io::Result<()> {
    let authorizer = Authorizer::for_group(group)?;
    let listener = crate::socket::bind(socket_path, authorizer.group_gid())?;

    log::info!(
        "shoesd listening on {} for root and group {} (gid {})",
        socket_path.display(),
        group,
        authorizer.group_gid()
    );

    let shutdown_supervisor = supervisor.clone();
    let service = DaemonService {
        authorizer,
        supervisor,
        logs,
    };
    let incoming = tokio_stream::wrappers::UnixListenerStream::new(listener);

    let result = tonic::transport::Server::builder()
        .add_service(DaemonServer::new(service))
        .serve_with_incoming_shutdown(incoming, shutdown_signal())
        .await;

    // A session outlives a client but not the process: SIGTERM means the
    // machine is going down or the daemon is being replaced, and either way
    // the routes and DNS come off before this process does.
    let _ = tokio::task::spawn_blocking(move || shutdown_supervisor.shutdown()).await;

    // The socket file outlives the listener, and launchd restarts the daemon.
    // Leaving it behind is survivable -- `bind` removes a stale one -- but it
    // means a client can connect to nothing and wait, so it goes.
    if let Err(e) = std::fs::remove_file(socket_path)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        log::warn!("could not remove {}: {e}", socket_path.display());
    }

    result.map_err(std::io::Error::other)
}

/// `SIGTERM` from launchd, or `SIGINT` from a terminal.
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut term = match signal(SignalKind::terminate()) {
        Ok(term) => term,
        Err(e) => {
            log::error!("could not listen for SIGTERM ({e}); serving until killed");
            std::future::pending::<()>().await;
            return;
        }
    };
    let mut interrupt = match signal(SignalKind::interrupt()) {
        Ok(interrupt) => interrupt,
        Err(e) => {
            log::error!("could not listen for SIGINT: {e}");
            term.recv().await;
            return;
        }
    };

    tokio::select! {
        _ = term.recv() => log::info!("SIGTERM; shutting down"),
        _ = interrupt.recv() => log::info!("SIGINT; shutting down"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::double::Recorder;

    fn service_with(authorizer: Authorizer) -> DaemonService {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("applied.json");
        // The directory has to outlive the supervisor thread, which holds the
        // path; these services live for the process.
        std::mem::forget(dir);

        let (supervisor, _thread) = Supervisor::spawn(|| Ok(Recorder::new()), path).unwrap();
        DaemonService {
            authorizer,
            supervisor,
            logs: Arc::new(BroadcastLogWriter::new(8)),
        }
    }

    /// A client asks what the daemon can do rather than inferring it from the
    /// operating system, so the answer has to be non-empty where the arms
    /// exist.
    #[test]
    fn macos_reports_the_host_capabilities_it_implements() {
        let caps = capabilities();
        if cfg!(target_os = "macos") {
            assert!(caps.contains(&"routes".to_string()), "{caps:?}");
            assert!(caps.contains(&"dns".to_string()), "{caps:?}");
        } else {
            assert!(
                caps.is_empty(),
                "a build with no host-network arms must promise nothing: {caps:?}"
            );
        }
    }

    /// The codes are the contract: the client switches on them, and each means
    /// something different about whether to retry, show the user their own
    /// mistake, or offer to stop the session that is in the way.
    #[test]
    fn each_start_failure_maps_to_the_code_a_client_switches_on() {
        assert_eq!(
            start_error_to_status(StartError::AlreadyRunning).code(),
            tonic::Code::AlreadyExists
        );
        assert_eq!(
            start_error_to_status(StartError::Config(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TUN on macOS requires 'address' and 'netmask'"
            )))
            .code(),
            tonic::Code::InvalidArgument
        );
        assert_eq!(
            start_error_to_status(StartError::Device("no TUN device appeared".into())).code(),
            tonic::Code::FailedPrecondition
        );
        assert_eq!(
            start_error_to_status(StartError::HostNetwork(std::io::Error::other("route add")))
                .code(),
            tonic::Code::Unavailable
        );
    }

    /// shoes' own message about the user's own config reaches them unchanged.
    /// Rewording it loses the field it names, which is the only part that
    /// tells them what to fix.
    #[test]
    fn a_config_error_reaches_the_client_verbatim() {
        let message = "TUN on macOS requires 'address' and 'netmask'";
        let status = start_error_to_status(StartError::Config(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            message,
        )));
        assert_eq!(status.message(), message);
    }

    /// A hostname is refused rather than resolved. That lookup's answer would
    /// decide what bypasses the tunnel, so it is the client's to make.
    #[test]
    fn an_exclusion_that_is_not_an_address_is_refused() {
        let status = parse_addresses(&["proxy.example.com".to_string()], "exclude")
            .expect_err("a name is not an address");
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
        assert!(
            status.message().contains("proxy.example.com"),
            "the message names it: {}",
            status.message()
        );
    }

    #[test]
    fn addresses_of_both_families_are_accepted() {
        let parsed = parse_addresses(
            &["203.0.113.7".to_string(), "2001:db8::1".to_string()],
            "exclude",
        )
        .expect("both families are addresses");
        assert_eq!(parsed.len(), 2);
    }

    /// `reason` is only meaningful with STOPPED, and the two kinds of stop
    /// stay distinguishable: a GUI shows a banner for one and nothing for the
    /// other.
    #[test]
    fn a_failure_and_a_requested_stop_are_different_on_the_wire() {
        let requested = to_proto_status(crate::supervisor::Status {
            state: State::Stopped {
                reason: StopReason::Requested,
            },
            uptime: None,
            upload_bytes: 0,
            download_bytes: 0,
            active_connections: 0,
            interface: None,
        });
        assert_eq!(requested.state, proto::status::State::Stopped as i32);
        assert_eq!(requested.reason, "requested");

        let failed = to_proto_status(crate::supervisor::Status {
            state: State::Stopped {
                reason: StopReason::Failed("bind: address in use".into()),
            },
            uptime: None,
            upload_bytes: 0,
            download_bytes: 0,
            active_connections: 0,
            interface: None,
        });
        assert_eq!(failed.reason, "bind: address in use");
    }

    #[test]
    fn a_running_status_carries_the_interface() {
        let running = to_proto_status(crate::supervisor::Status {
            state: State::Running,
            uptime: Some(Duration::from_millis(1500)),
            upload_bytes: 10,
            download_bytes: 20,
            active_connections: 3,
            interface: Some("utun4".into()),
        });
        assert_eq!(running.state, proto::status::State::Running as i32);
        assert_eq!(running.interface, "utun4");
        assert_eq!(running.uptime_ms, 1500);
        assert!(running.reason.is_empty(), "reason is for STOPPED only");
    }

    /// A client cannot spend the daemon's CPU on its own frame rate.
    #[test]
    fn the_stats_interval_has_a_floor() {
        assert_eq!(
            Duration::from_millis(1).max(MIN_STATS_INTERVAL),
            MIN_STATS_INTERVAL
        );
        assert_eq!(
            Duration::from_millis(1000).max(MIN_STATS_INTERVAL),
            Duration::from_millis(1000)
        );
    }

    /// A subscriber's level filters what it receives and nothing else. Raising
    /// the global level from here would let a user-session client turn on
    /// logging the operator's configuration left off.
    #[test]
    fn a_subscribers_level_filters_only_what_it_receives() {
        let error = shoes::control::logs::LogLine {
            level: log::Level::Error,
            target: "shoes".into(),
            message: "boom".into(),
            at: std::time::SystemTime::now(),
        };
        let debug = shoes::control::logs::LogLine {
            level: log::Level::Debug,
            target: "shoes".into(),
            message: "chatter".into(),
            at: std::time::SystemTime::now(),
        };

        let warn = shoes::logging::parse_log_level("warn");
        assert!(passes(&error, warn), "an error passes a warn filter");
        assert!(!passes(&debug, warn), "debug does not");

        // An unrecognised level leaves the daemon's own configuration in
        // charge rather than silently dropping everything.
        let nonsense = shoes::logging::parse_log_level("shouty");
        assert!(passes(&debug, nonsense));
    }

    /// Serve on a temporary socket for one test, and return a client and a
    /// shutdown handle.
    ///
    /// A real socket and a real connection, because that is the only way to
    /// exercise the peer check: `UCred` has no public constructor, so a fake
    /// request cannot carry credentials and the allow path is unreachable
    /// without the kernel filling them in.
    ///
    /// The socket's own group is separate from the authorizer's, because a
    /// non-root test process may only chgrp to a group it belongs to -- so the
    /// refusal case binds with the caller's group and authorizes against
    /// another. That split is a test artefact; in production both are the
    /// group `--group` named.
    async fn serve_for_test(
        authorizer: Authorizer,
        bind_gid: u32,
    ) -> (
        proto::daemon_client::DaemonClient<tonic::transport::Channel>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let path = std::env::temp_dir().join(format!(
            "shoesd-svc-{}-{:?}.sock",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_file(&path);

        let listener =
            crate::socket::bind(&path, bind_gid).expect("bind in the temp dir should succeed");
        let (tx, rx) = tokio::sync::oneshot::channel();

        let service = service_with(authorizer);
        tokio::spawn(async move {
            let _ = tonic::transport::Server::builder()
                .add_service(DaemonServer::new(service))
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::UnixListenerStream::new(listener),
                    async {
                        let _ = rx.await;
                    },
                )
                .await;
        });

        // The URI is ignored -- the connector below decides where this goes --
        // but tonic requires a syntactically valid one.
        let connect_path = path.clone();
        let channel = tonic::transport::Endpoint::try_from("http://[::1]:50051")
            .unwrap()
            .connect_with_connector(tower::service_fn(move |_: tonic::transport::Uri| {
                let connect_path = connect_path.clone();
                async move {
                    let stream = tokio::net::UnixStream::connect(connect_path).await?;
                    Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
                }
            }))
            .await
            .expect("the daemon should be accepting");

        (proto::daemon_client::DaemonClient::new(channel), tx)
    }

    /// The transport, the generated code and the allow path, end to end.
    ///
    /// The group is the caller's own primary gid, which is the one group the
    /// test can be sure it is in on any machine.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_member_of_the_group_gets_a_hello() {
        let gid = unsafe { libc::getgid() } as u32;
        let (mut client, shutdown) = serve_for_test(Authorizer::for_gid(gid), gid).await;

        let reply = client
            .hello(proto::HelloRequest {
                client: "shoesd-tests".into(),
                client_version: "0".into(),
            })
            .await
            .expect("a member of the group is allowed")
            .into_inner();

        assert_eq!(reply.protocol, PROTOCOL_VERSION);
        assert_eq!(reply.daemon_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(reply.capabilities, capabilities());

        let _ = shutdown.send(());
    }

    /// And the refusal path, over the same transport: a status the client can
    /// switch on, not a dropped connection. A dropped socket is
    /// indistinguishable from a daemon that is not running, and a client that
    /// cannot tell them apart offers to install one that is already there.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_non_member_is_refused_with_a_status() {
        if unsafe { libc::getuid() } == 0 {
            // Root is allowed by design, so there is nothing to refuse.
            return;
        }
        let uid = unsafe { libc::getuid() } as u32;
        let own_gid = unsafe { libc::getgid() } as u32;
        let outsider = (1..64u32)
            .find(|gid| !Authorizer::for_gid(*gid).allows(uid, own_gid))
            .expect("some low gid must not contain this user");

        let (mut client, shutdown) = serve_for_test(Authorizer::for_gid(outsider), own_gid).await;

        let status = client
            .hello(proto::HelloRequest {
                client: "shoesd-tests".into(),
                client_version: "0".into(),
            })
            .await
            .expect_err("a non-member must be refused");

        assert_eq!(status.code(), tonic::Code::PermissionDenied);
        let _ = shutdown.send(());
    }

    /// The session methods over the real transport, on a daemon with no
    /// session: a stop reports RELEASED rather than an error, and the status
    /// says stopped.
    #[tokio::test(flavor = "multi_thread")]
    async fn stopping_an_idle_daemon_is_released_not_an_error() {
        let gid = unsafe { libc::getgid() } as u32;
        let (mut client, shutdown) = serve_for_test(Authorizer::for_gid(gid), gid).await;

        let reply = client
            .stop(proto::StopRequest {})
            .await
            .expect("stopping nothing is not an error")
            .into_inner();
        assert_eq!(reply.outcome, proto::stop_reply::Outcome::Released as i32);

        let status = client
            .get_status(proto::StatusRequest {})
            .await
            .unwrap()
            .into_inner();
        assert_eq!(status.state, proto::status::State::Stopped as i32);

        let _ = shutdown.send(());
    }

    /// A config the engine cannot parse comes back as INVALID_ARGUMENT with
    /// shoes' own message, and leaves the daemon stopped rather than wedged in
    /// STARTING.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_bad_config_is_invalid_argument_over_the_wire() {
        let gid = unsafe { libc::getgid() } as u32;
        let (mut client, shutdown) = serve_for_test(Authorizer::for_gid(gid), gid).await;

        let status = client
            .start(proto::StartRequest {
                yaml: "this: is: not: a: config".into(),
                exclude: vec![],
                dns: vec![],
            })
            .await
            .expect_err("a bad config must be refused");
        assert_eq!(status.code(), tonic::Code::InvalidArgument);

        let after = client
            .get_status(proto::StatusRequest {})
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            after.state,
            proto::status::State::Stopped as i32,
            "a failed start must not leave the session STARTING"
        );

        let _ = shutdown.send(());
    }

    /// `WatchStatus` sends the current state before any transition, so a
    /// client that attaches to an idle daemon renders something immediately
    /// rather than waiting for the first change.
    #[tokio::test(flavor = "multi_thread")]
    async fn watch_status_leads_with_the_current_state() {
        use tokio_stream::StreamExt;

        let gid = unsafe { libc::getgid() } as u32;
        let (mut client, shutdown) = serve_for_test(Authorizer::for_gid(gid), gid).await;

        let mut stream = client
            .watch_status(proto::StatusRequest {})
            .await
            .expect("the stream opens")
            .into_inner();

        let first = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("the current state arrives without waiting for a transition")
            .expect("the stream is not empty")
            .expect("and carries a status");
        assert_eq!(first.state, proto::status::State::Stopped as i32);

        let _ = shutdown.send(());
    }
}
