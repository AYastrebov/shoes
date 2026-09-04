//! The gRPC service.
//!
//! Only `Hello` so far -- the session methods arrive with the supervisor, and
//! `Hello` is what proves the transport, the peer check and the generated code
//! all work before anything privileged is built on them.

use tonic::{Request, Response, Status};

pub mod proto {
    // The generated module, named for the proto package.
    tonic::include_proto!("shoes.daemon.v1");
}

use proto::daemon_server::{Daemon, DaemonServer};

use crate::auth::Authorizer;

/// The protocol version in `HelloReply`. A client that does not recognise it
/// must not proceed; that is the whole reason it is the first field of the
/// first call.
const PROTOCOL_VERSION: u32 = 1;

pub struct DaemonService {
    authorizer: Authorizer,
}

/// What this build can do to the host.
///
/// Reported rather than inferred: a client must not decide from the operating
/// system what the daemon is capable of, because a build can be missing an arm
/// the platform could in principle support. On anything but macOS both are
/// absent, and the session methods refuse rather than pretend.
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
        Err(Status::unimplemented("Start arrives with the supervisor"))
    }

    async fn stop(
        &self,
        request: Request<proto::StopRequest>,
    ) -> Result<Response<proto::StopReply>, Status> {
        self.check_peer(&request)?;
        Err(Status::unimplemented("Stop arrives with the supervisor"))
    }

    async fn get_status(
        &self,
        request: Request<proto::StatusRequest>,
    ) -> Result<Response<proto::Status>, Status> {
        self.check_peer(&request)?;
        Err(Status::unimplemented(
            "GetStatus arrives with the supervisor",
        ))
    }

    type WatchStatusStream = tokio_stream::wrappers::ReceiverStream<Result<proto::Status, Status>>;
    type WatchStatsStream = tokio_stream::wrappers::ReceiverStream<Result<proto::Stats, Status>>;
    type WatchLogsStream = tokio_stream::wrappers::ReceiverStream<Result<proto::LogLine, Status>>;

    async fn watch_status(
        &self,
        request: Request<proto::StatusRequest>,
    ) -> Result<Response<Self::WatchStatusStream>, Status> {
        self.check_peer(&request)?;
        Err(Status::unimplemented(
            "WatchStatus arrives with the supervisor",
        ))
    }

    async fn watch_stats(
        &self,
        request: Request<proto::StatsRequest>,
    ) -> Result<Response<Self::WatchStatsStream>, Status> {
        self.check_peer(&request)?;
        Err(Status::unimplemented(
            "WatchStats arrives with the supervisor",
        ))
    }

    async fn watch_logs(
        &self,
        request: Request<proto::LogsRequest>,
    ) -> Result<Response<Self::WatchLogsStream>, Status> {
        self.check_peer(&request)?;
        Err(Status::unimplemented(
            "WatchLogs arrives with the supervisor",
        ))
    }
}

impl DaemonService {
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

/// Serve until `SIGTERM`.
pub async fn serve(socket_path: &std::path::Path, group: &str) -> std::io::Result<()> {
    let authorizer = Authorizer::for_group(group)?;
    let listener = crate::socket::bind(socket_path, authorizer.group_gid())?;

    log::info!(
        "shoesd listening on {} for root and group {} (gid {})",
        socket_path.display(),
        group,
        authorizer.group_gid()
    );

    let service = DaemonService { authorizer };
    let incoming = tokio_stream::wrappers::UnixListenerStream::new(listener);

    let result = tonic::transport::Server::builder()
        .add_service(DaemonServer::new(service))
        .serve_with_incoming_shutdown(incoming, shutdown_signal())
        .await;

    // The socket file outlives the listener, and launchd restarts the daemon.
    // Leaving it behind is survivable -- `bind` removes a stale one -- but
    // leaving it means a client can connect to nothing and wait, so it goes.
    if let Err(e) = std::fs::remove_file(socket_path)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        log::warn!("could not remove {}: {e}", socket_path.display());
    }

    result.map_err(std::io::Error::other)
}

/// `SIGTERM` from launchd, or `SIGINT` from a terminal.
///
/// This is where the session teardown will hang once there is a session: the
/// future completes, `serve_with_incoming_shutdown` stops accepting, and the
/// supervisor reverts routes and DNS before the process exits.
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

        let service = DaemonService { authorizer };
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
    #[tokio::test]
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
    #[tokio::test]
    async fn a_non_member_is_refused_with_a_status() {
        if unsafe { libc::getuid() } == 0 {
            // Root is allowed by design, so there is nothing to refuse.
            return;
        }
        // A gid no ordinary user is in. `nogroup`-adjacent ids vary; this one
        // is checked rather than assumed.
        let outsider = (1..64u32)
            .find(|gid| {
                !Authorizer::for_gid(*gid)
                    .allows(unsafe { libc::getuid() } as u32, unsafe { libc::getgid() }
                        as u32)
            })
            .expect("some low gid must not contain this user");

        let own_gid = unsafe { libc::getgid() } as u32;
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

    /// The refusal must not name the group or the uid: a client that can
    /// enumerate which groups produce a different message can map the
    /// machine's accounts through an endpoint that exists to refuse it.
    #[test]
    fn a_refusal_says_nothing_about_the_machine() {
        let service = DaemonService {
            authorizer: Authorizer::for_group("wheel").unwrap(),
        };
        // A request built here carries no connect info, which is the first
        // refusal branch.
        let request = Request::new(proto::HelloRequest {
            client: "test".into(),
            client_version: "0".into(),
        });
        let status = service.check_peer(&request).expect_err("must refuse");
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
        assert!(
            !status.message().contains("wheel"),
            "got: {}",
            status.message()
        );
    }
}
