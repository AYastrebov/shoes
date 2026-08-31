//! Service lifecycle: prepare a config, run it, stop it.
//!
//! Extracted from `src/ffi/common.rs` so that non-mobile hosts — a macOS
//! Network Extension, a Windows service, a Linux daemon — can drive a tunnel
//! without going through the C or JNI boundary. The FFI keeps its global
//! singletons, because a C caller addresses its service by an integer, and
//! delegates the work here.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use log::{error, info, warn};
use tokio::sync::{oneshot, watch};
use tokio::task::JoinHandle;

mod device;
#[cfg(feature = "control-logs")]
pub mod logs;
#[cfg(feature = "control-stats")]
pub mod stats;
mod stop;

pub use device::DevicePolicy;
pub use stop::StopOutcome;

// Not on Android or iOS. This is not a feature a mobile host might want and
// currently declines -- it is API a mobile host structurally cannot use, since
// a C or JNI caller has no way to receive a StatusSnapshot and reads the same
// facts through shoes_is_running() and shoes_get_last_error() instead. Worth
// 1824 bytes of the arm64 .so, measured.
//
// macOS is deliberately on the near side of this: the desktop Network
// Extension provider is a target_os = "macos" build and does want it.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod status;

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub use status::{Status, StatusSnapshot, StopReason};

use crate::config::{Config, convert_cert_paths, create_server_configs, load_config_str};
use crate::dns::build_dns_registry;
use crate::tcp::tcp_server::start_servers;
#[cfg(any(unix, windows))]
use crate::tun::run_tun_from_config;

/// Handle to a running service.
///
/// # Do not drop this from async code
///
/// Prefer [`ServiceHandle::stop`], and call it from a blocking context —
/// `tokio::task::spawn_blocking` from a Tauri command or an async handler.
///
/// Two reasons, and they apply to a plain `drop` as much as to `stop`. The
/// handle owns a [`tokio::runtime::Runtime`], and dropping a runtime inside
/// another runtime's context panics with "Cannot drop a runtime in a context
/// where blocking is not allowed". And `stop` waits, by design, up to
/// [`STOP_TIMEOUT`] on the calling thread — on an async worker that stalls
/// every other task sharing it.
///
/// Dropping also skips the wait entirely, which is the wait that tells a host
/// whether it may close a descriptor it lent. That answer only comes back from
/// `stop`, as a [`StopOutcome`].
pub struct ServiceHandle {
    /// Tokio runtime running the service.
    runtime: tokio::runtime::Runtime,
    /// Channel to signal shutdown.
    shutdown_tx: Option<oneshot::Sender<()>>,
    /// Flag indicating if service is running.
    running: Arc<AtomicBool>,
    /// Set by `stop_handle` before the shutdown signal, so the exit guard
    /// can tell a stop the host asked for from one it must be told about.
    stop_requested: Arc<AtomicBool>,
    /// When `start` spawned the service, for `uptime`.
    started_at: std::time::Instant,
    /// Set if the service ended without being asked -- the error's message,
    /// or a fixed one for a clean but unrequested end -- so `status` can tell
    /// that from a stop the host asked for. The FFI gets the error through
    /// `on_exit`, because a C caller cannot receive an enum carrying a String.
    failure: Arc<parking_lot::Mutex<Option<String>>>,
}

/// How long `stop_handle` waits for the service task to finish.
pub const STOP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// How often it looks while waiting.
const STOP_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(5);

/// Stop a running service and wait for it to release the TUN descriptor.
///
/// Call this from a blocking context — see the warning on [`ServiceHandle`].
/// It sleeps the calling thread in a poll loop for up to [`STOP_TIMEOUT`], and
/// if the shutdown thread cannot be spawned it drops the runtime inline, which
/// panics inside an async context.
///
/// The wait is the part that cannot be skipped: it is what
/// guarantees the stack thread has released the TUN descriptor, so the app can
/// close its own copy without racing a thread that is still reading from it.
/// In practice it costs a few milliseconds — the old version polled in 100 ms
/// steps and so paid at least that much every time.
///
/// Dropping the runtime, on the other hand, waits on tasks that no longer hold
/// anything the app needs back, so it happens on a thread of its own and the
/// caller does not pay for it.
pub fn stop_handle(mut handle: ServiceHandle) -> StopOutcome {
    handle.stop_requested.store(true, Ordering::SeqCst);
    if let Some(tx) = handle.shutdown_tx.take() {
        let _ = tx.send(());
    }

    let started = std::time::Instant::now();
    let mut stopped = false;
    while started.elapsed() < STOP_TIMEOUT {
        if !handle.running.load(Ordering::SeqCst) {
            stopped = true;
            break;
        }
        std::thread::sleep(STOP_POLL_INTERVAL);
    }

    let waited = started.elapsed();
    let outcome = if stopped {
        info!("TUN service stopped after {}ms", waited.as_millis());
        StopOutcome::Released
    } else {
        error!(
            "TUN service did not stop within {}s; the TUN descriptor may still be in use",
            STOP_TIMEOUT.as_secs()
        );
        StopOutcome::TimedOut { waited }
    };

    // shutdown_timeout, not drop: a task wedged in a blocking call would
    // otherwise keep this thread — the app's main thread, in the sample code
    // both platforms ship — parked indefinitely.
    let runtime = Arc::new(parking_lot::Mutex::new(Some(handle.runtime)));
    let shutdown_runtime = runtime.clone();
    if let Err(e) = std::thread::Builder::new()
        .name("shoes-runtime-shutdown".to_owned())
        .spawn(move || {
            if let Some(runtime) = shutdown_runtime.lock().take() {
                runtime.shutdown_timeout(std::time::Duration::from_secs(5));
                info!("TUN runtime dropped");
            }
        })
    {
        warn!("Could not spawn the runtime shutdown thread ({e}); shutting down in place");
        // shutdown_background, not drop: this may be running on one of the
        // runtime's own workers -- a host is allowed to call shoes_stop from
        // the stopped callback -- and dropping a runtime from inside itself
        // panics, which under panic = "abort" ends the process.
        if let Some(runtime) = runtime.lock().take() {
            runtime.shutdown_background();
        }
    }

    outcome
}

impl ServiceHandle {
    /// Release a handle whose service has already ended, without waiting.
    /// The runtime shuts down in the background, so this is safe from any
    /// thread -- including one of that runtime's own workers, which is
    /// where a host's stopped callback runs.
    pub fn discard(self) {
        self.runtime.shutdown_background();
    }

    /// Whether the service task is still running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Stop this service and wait for it to release the device.
    ///
    /// Consumes the handle, because a stopped service has nothing left to
    /// answer and a second stop has no meaning.
    ///
    /// Call this from a blocking context — see the warning on this type.
    pub fn stop(self) -> StopOutcome {
        stop_handle(self)
    }

    /// A point-in-time reading of this service.
    ///
    /// Note that the byte counters are process-global — see the note on
    /// [`start`] about one service per process.
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    pub fn status(&self) -> StatusSnapshot {
        let running = self.is_running();

        let status = if running {
            Status::Running
        } else {
            Status::Stopped {
                reason: match self.failure.lock().clone() {
                    Some(msg) => StopReason::Failed(msg),
                    None => StopReason::Requested,
                },
            }
        };

        // The counters live with the TUN module, which exists on Unix and
        // Windows. On anything else there is no tunnel to count, and a host
        // still wants a snapshot.
        #[cfg(any(unix, windows))]
        let (upload_bytes, download_bytes) = crate::tun::traffic::get_traffic_counters();
        #[cfg(not(any(unix, windows)))]
        let (upload_bytes, download_bytes) = (0, 0);

        StatusSnapshot {
            status,
            uptime: running.then(|| self.started_at.elapsed()),
            upload_bytes,
            download_bytes,
        }
    }
}

/// Start a prepared service on `runtime`.
///
/// The runtime is the caller's rather than ours: iOS pins it to two worker
/// threads to stay inside a Network Extension's memory limit, while Android
/// takes `Runtime::new()` and all the cores it can get. That is a policy this
/// module has no business deciding.
///
/// `on_exit` runs once, from the service task, when the service ends for
/// any reason the host did not ask for: `Some(message)` when it failed,
/// `None` when it returned without an error. It is not called after
/// [`stop_handle`]. By the time it runs `running` is already false, so a
/// callback that stops the engine does not wait out [`STOP_TIMEOUT`].
///
/// A panic does not reach it: the crate builds with `panic = "abort"`. And a
/// handle that is dropped rather than stopped cancels the task, which
/// counts as an exit the host did not ask for -- prefer [`stop_handle`].
///
/// The task is running before this returns. A host that keeps the handle
/// somewhere `on_exit` can observe -- the FFI's process-global -- wants
/// [`start_and_install`] instead, which stores the handle first.
///
/// # One service per process
///
/// The traffic counters in `crate::tun::traffic` are process-global statics, so
/// a second concurrent `ServiceHandle` in one process would report the sum of
/// both services. Each privileged host runs exactly one tunnel, so this costs
/// nothing in practice -- but it is an invariant this API depends on rather
/// than an accident.
pub fn start(
    runtime: tokio::runtime::Runtime,
    prepared: PreparedService,
    on_exit: impl FnOnce(Option<String>) + Send + 'static,
) -> ServiceHandle {
    reset_counters();
    start_with(
        runtime,
        |shutdown_rx| run_prepared(prepared, shutdown_rx),
        on_exit,
    )
}

/// [`start`], with the handle given to `install` before the service task is
/// spawned. `on_exit` can fire in the service's first instant; a host whose
/// callback looks the handle up -- `shoes_stop` from inside it, say -- must
/// already find it there.
pub fn start_and_install(
    runtime: tokio::runtime::Runtime,
    prepared: PreparedService,
    on_exit: impl FnOnce(Option<String>) + Send + 'static,
    install: impl FnOnce(ServiceHandle),
) {
    reset_counters();
    let (handle, go) = spawn_service(
        runtime,
        |shutdown_rx| run_prepared(prepared, shutdown_rx),
        on_exit,
    );
    install(handle);
    go();
}

/// `start` with the service future injectable, so the exit contract can be
/// tested without a TUN device.
pub fn start_with<F, Fut>(
    runtime: tokio::runtime::Runtime,
    make_service: F,
    on_exit: impl FnOnce(Option<String>) + Send + 'static,
) -> ServiceHandle
where
    F: FnOnce(oneshot::Receiver<()>) -> Fut,
    Fut: std::future::Future<Output = std::io::Result<()>> + Send + 'static,
{
    let (handle, go) = spawn_service(runtime, make_service, on_exit);
    go();
    handle
}

fn reset_counters() {
    // From zero, so a second session does not report the first one's bytes
    // against a fresh uptime. Both FFI platforms already do this in their own
    // start path; a Rust host had no equivalent.
    #[cfg(any(unix, windows))]
    crate::tun::traffic::reset_traffic_counters();
}

/// Build the handle and the task, and hand back the task's spawn as a
/// closure, so a caller can put the handle where it belongs before the
/// task exists.
fn spawn_service<F, Fut>(
    runtime: tokio::runtime::Runtime,
    make_service: F,
    on_exit: impl FnOnce(Option<String>) + Send + 'static,
) -> (ServiceHandle, impl FnOnce())
where
    F: FnOnce(oneshot::Receiver<()>) -> Fut,
    Fut: std::future::Future<Output = std::io::Result<()>> + Send + 'static,
{
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let running = Arc::new(AtomicBool::new(true));
    let stop_requested = Arc::new(AtomicBool::new(false));
    let failure = Arc::new(parking_lot::Mutex::new(None));

    let service = make_service(shutdown_rx);
    let guard = ExitGuard {
        running: running.clone(),
        stop_requested: stop_requested.clone(),
        failure: failure.clone(),
        on_exit: Some(Box::new(on_exit)),
    };
    let spawner = runtime.handle().clone();
    let task = async move {
        let _guard = guard;
        info!("shoes service task started");
        match service.await {
            Ok(()) => info!("shoes service stopped normally"),
            Err(e) => {
                let msg = e.to_string();
                error!("shoes service error: {}", msg);
                // Written before the guard runs, so `running` never reads
                // false while the reason is still missing.
                *_guard.failure.lock() = Some(msg);
            }
        }
        // `_guard` drops here, at the end of the task.
    };

    let handle = ServiceHandle {
        runtime,
        shutdown_tx: Some(shutdown_tx),
        running,
        stop_requested,
        started_at: std::time::Instant::now(),
        failure,
    };
    (handle, move || {
        spawner.spawn(task);
    })
}

/// What `status` and `on_exit` say about a service that returned `Ok` on its
/// own. `run_prepared` does that only for the shutdown signal today, so this
/// is reserved rather than expected.
pub(crate) const ENDED_UNREQUESTED: &str = "service ended without being asked";

/// Runs at the end of the service task, however it ends. Order matters:
/// `running` goes false first, then the host is told -- so
/// `shoes_is_running()` is already false inside the callback and a host that
/// calls `shoes_stop` from it returns at once.
struct ExitGuard {
    running: Arc<AtomicBool>,
    stop_requested: Arc<AtomicBool>,
    failure: Arc<parking_lot::Mutex<Option<String>>>,
    on_exit: Option<Box<dyn FnOnce(Option<String>) + Send>>,
}

impl Drop for ExitGuard {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if self.stop_requested.load(Ordering::SeqCst) {
            return;
        }
        // An unrequested Ok gets the same sentence status() records: the
        // FFI hosts read only what on_exit carries, and a None here left
        // the iOS callback announcing a reasonless stop while
        // shoes_get_last_error answered with whatever an earlier failure
        // had written -- a stale message dressed as this stop's reason.
        let error = self
            .failure
            .lock()
            .clone()
            .or_else(|| Some(ENDED_UNREQUESTED.to_string()));
        *self.failure.lock() = error.clone();
        if let Some(on_exit) = self.on_exit.take() {
            on_exit(error);
        }
    }
}

/// A config that has been parsed, validated, and had its DNS resolvers built.
///
/// Preparing is separate from running so that the host can do it on the calling
/// thread and answer `start` with a real verdict. Everything that a bad config
/// can fail at — YAML syntax, a device the host cannot provide, an unusable
/// key, a resolver that will not build — fails here, in front of the caller,
/// instead of inside
/// a spawned task whose error the app only learns about by polling
/// `isRunning()` and finding it already false.
pub struct PreparedService {
    tun_config: crate::config::TunConfig,
    server_configs: Vec<crate::config::ServerConfig>,
    dns_registry: crate::dns::DnsRegistry,
    policy: DevicePolicy,
}

/// Start the service from a config YAML string.
///
/// This parses the config YAML and starts both TUN and any Server configs
/// (like mixed HTTP+SOCKS5 servers) that are defined in the config.
///
/// What the TUN section must contain depends on `policy`: under
/// [`DevicePolicy::BorrowedFd`] it needs a `device_fd` the host already owns,
/// and under [`DevicePolicy::Owned`] it must not have one, because the service
/// creates the device itself.
pub async fn start_from_config(
    config_yaml: &str,
    policy: DevicePolicy,
    shutdown_rx: oneshot::Receiver<()>,
) -> std::io::Result<()> {
    let prepared = prepare_from_config(config_yaml, policy).await?;
    run_prepared(prepared, shutdown_rx).await
}

/// Parse and validate a config, and build its resolvers. See [`PreparedService`].
pub async fn prepare_from_config(
    config_yaml: &str,
    policy: DevicePolicy,
) -> std::io::Result<PreparedService> {
    prepare_configs(config_yaml, policy, None).await
}

/// [`prepare_from_config`] under [`DevicePolicy::BorrowedFd`], with the
/// descriptor supplied by the caller rather than read from the document.
///
/// For the host that learns its descriptor last: an Apple packet tunnel
/// provider is handed the config by the app and the descriptor by
/// `packetFlow`, in that order, and has no YAML parser to marry them. The
/// parameter overrides a `device_fd` the document carries and fills one it
/// omits, so a generator may write `device_fd: 0` as a stand-in or leave the
/// field out.
pub async fn prepare_from_config_with_fd(
    config_yaml: &str,
    device_fd: i32,
) -> std::io::Result<PreparedService> {
    prepare_configs(config_yaml, DevicePolicy::BorrowedFd, Some(device_fd)).await
}

async fn prepare_configs(
    config_yaml: &str,
    policy: DevicePolicy,
    device_fd: Option<i32>,
) -> std::io::Result<PreparedService> {
    info!("Parsing config for TUN server");

    let configs: Vec<Config> = load_config_str(config_yaml)?;

    let (configs, pem_count) = convert_cert_paths(configs).await?;
    if pem_count > 0 {
        info!("Loaded {} PEM files", pem_count);
    }

    let crate::config::ValidatedConfigs {
        configs: validated_configs,
        dns_groups,
        outbounds,
    } = create_server_configs(configs)?;

    // Build DNS registry from expanded groups
    let dns_registry = build_dns_registry(dns_groups).await?;

    // Separate TUN config from server configs, and check the one TUN against
    // what this host can provide -- see DevicePolicy.
    let mut tun_config = None;
    let mut server_configs = Vec::new();

    for config in validated_configs {
        match config {
            Config::TunServer(mut tc) => {
                if tun_config.is_some() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Multiple TUN configs found - only one is allowed",
                    ));
                }
                // Before validate: under BorrowedFd a missing descriptor is
                // an error, and the parameter is how this host supplies it.
                if let Some(fd) = device_fd {
                    tc.device_fd = Some(fd);
                }
                device::validate(&tc, policy)?;
                // unwrap_or(-1) rather than {:?} on the Option: an Owned host
                // has no descriptor to report, and -1 says so without pulling
                // Option<i32>'s Debug impl into a mobile build.
                info!(
                    "TUN config: fd={}, mtu={}, tcp={}, udp={}, icmp={}",
                    tc.device_fd.unwrap_or(-1),
                    tc.mtu,
                    tc.tcp_enabled,
                    tc.udp_enabled,
                    tc.icmp_enabled
                );
                tun_config = Some(tc);
            }
            Config::Server(sc) => {
                server_configs.push(sc);
            }
            _ => {}
        }
    }

    let tun_config = tun_config.ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "No TUN config found")
    })?;

    // Last, once nothing above can still fail. Installing earlier would
    // publish a rejected config's outbounds -- and, if a service were already
    // running, drop its live counters out of the registry while its chains
    // went on holding them, so its traffic would vanish from every later
    // snapshot. Replace rather than merge: a reload must not carry the
    // previous config's servers into the new list.
    #[cfg(feature = "control-stats")]
    crate::outbound_stats::install(&outbounds);
    #[cfg(not(feature = "control-stats"))]
    let _ = outbounds;

    Ok(PreparedService {
        tun_config,
        server_configs,
        dns_registry,
        policy,
    })
}

/// Merge the two ways a service can be told to stop into the one oneshot
/// the TUN honours: the host's shutdown signal, or a fatal report from a
/// component with no handle to the service task (see `crate::fatal`).
///
/// Returns the fatal reason when that is what fired, `None` for a host
/// stop. Takes its receivers as parameters so tests can supply their own
/// channels instead of the process-global.
async fn shutdown_or_fatal(
    shutdown_rx: oneshot::Receiver<()>,
    mut fatal_rx: watch::Receiver<(u64, Option<String>)>,
    forward_tx: oneshot::Sender<()>,
) -> Option<String> {
    let reason = tokio::select! {
        _ = shutdown_rx => None,
        reason = async {
            // Cloned out in one expression so the watch's read guard --
            // which is not Send -- is gone before any await point.
            let reported = fatal_rx
                .wait_for(|slot| slot.1.is_some())
                .await
                .ok()
                .and_then(|slot| slot.1.clone());
            match reported {
                Some(reason) => reason,
                // The production sender is a static and cannot drop; a
                // closed channel means no fatal is ever coming.
                None => std::future::pending().await,
            }
        } => Some(reason),
    };
    let _ = forward_tx.send(());
    reason
}

/// Run a service that [`prepare_from_config`] has already validated.
///
/// Returns when the TUN stops, either because `shutdown_rx` fired, because
/// the stack died, or because a component reported a fatal condition
/// through [`crate::fatal`] -- which comes back as `Err` with its reason.
pub async fn run_prepared(
    prepared: PreparedService,
    shutdown_rx: oneshot::Receiver<()>,
) -> std::io::Result<()> {
    let PreparedService {
        tun_config,
        server_configs,
        mut dns_registry,
        policy,
    } = prepared;

    // A fatal from a previous session must not stop this one.
    crate::fatal::reset();

    // Start TCP servers (like mixed)
    let mut join_handles: Vec<JoinHandle<()>> = Vec::new();

    for server_config in server_configs {
        let resolver = dns_registry.get_for_server(server_config.dns.as_ref());
        join_handles.extend(start_servers(Config::Server(server_config), resolver).await?);
    }

    // The TUN honours one oneshot. Merge the host's shutdown and the
    // process-wide fatal signal into it, rather than selecting over the
    // TUN future itself -- dropping that future mid-poll would skip the
    // graceful teardown that releases the descriptor.
    let (tun_shutdown_tx, tun_shutdown_rx) = oneshot::channel();
    let stop_watcher = tokio::spawn(shutdown_or_fatal(
        shutdown_rx,
        crate::fatal::subscribe(),
        tun_shutdown_tx,
    ));

    // Runs until shutdown. Who closes the descriptor follows from the policy:
    // whoever created the device closes it, and nobody else.
    //
    // The resolver comes from the registry the config built: this is the
    // line that makes a TUN entry's `dns:` block real. Without the block,
    // get_for_server(None) answers the default system resolver, so
    // behaviour is unchanged for configs that never carried one.
    #[cfg(any(unix, windows))]
    let result = {
        let tun_resolver = dns_registry.get_for_server(tun_config.dns.as_ref());
        run_tun_from_config(
            tun_config,
            tun_resolver,
            tun_shutdown_rx,
            policy.close_fd_on_drop(),
        )
        .await
    };
    #[cfg(not(any(unix, windows)))]
    let result = {
        // Consumed only by the TUN branch, which this platform does not have.
        let _ = policy;
        let _ = tun_shutdown_rx;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "TUN is not supported on this platform",
        ))
    };

    // Cleanup any servers when TUN stops
    for handle in join_handles {
        handle.abort();
    }

    // The watcher either fired (and is finished -- a finished task
    // survives the abort and still yields its value) or the TUN ended on
    // its own (and the watcher is moot). A fatal reason overrides the
    // Ok(()) the TUN returns for what it saw as a requested shutdown; the
    // ExitGuard then reports it through on_exit like any other failure.
    stop_watcher.abort();
    match stop_watcher.await {
        Ok(Some(reason)) => {
            // The fatal is what the host must hear, but a teardown that
            // also failed -- a descriptor not released, say -- must not
            // vanish with it; the next start may fail because of it.
            if let Err(e) = &result {
                error!("TUN teardown also failed after the fatal: {e}");
            }
            Err(std::io::Error::other(reason))
        }
        _ => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn current_thread_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    /// `prepare_from_config` installs the config's outbounds into the
    /// process-global registry, so these tests write shared state even when
    /// they fail afterwards. Serialise them against everything else that
    /// touches it, the way `tun::traffic::COUNTER_TEST_LOCK` is used.
    fn prepare(yaml: &str) -> std::io::Result<PreparedService> {
        let _registry = crate::outbound_stats::REGISTRY_TEST_LOCK.lock().unwrap();
        current_thread_runtime().block_on(prepare_from_config(yaml, DevicePolicy::BorrowedFd))
    }

    /// A config with no TUN section must fail before anything is spawned, so
    /// the caller gets a verdict instead of a handle that dies moments later.
    #[test]
    fn test_prepare_rejects_a_config_with_no_tun() {
        let err = prepare("---\n[]\n").map(|_| ()).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("No TUN config found"));
    }

    /// A TUN section is recognised by device_name or device_fd, so this one is
    /// a TUN config that names no descriptor. The descriptor is the caller's,
    /// so that cannot be run and must be said here rather than inside a task.
    #[test]
    fn test_prepare_rejects_a_tun_without_a_descriptor() {
        // netmask included so the config passes per-platform validation on
        // Windows and the failure under test — the missing descriptor — is
        // the one that fires.
        let err =
            prepare("---\n- device_name: tun0\n  address: 10.0.0.2\n  netmask: 255.255.255.0\n")
                .map(|_| ())
                .unwrap_err();
        assert!(
            err.to_string().contains("device_fd"),
            "expected a device_fd complaint, got: {err}"
        );
    }

    /// Two TUN sections have no defined meaning, and silently taking the first
    /// would route a user's traffic somewhere they did not ask for.
    ///
    /// The shape and policy are per-platform because each platform accepts a
    /// different TUN shape; the duplicate-TUN complaint is the same on both.
    #[test]
    fn test_prepare_rejects_two_tun_configs() {
        #[cfg(not(windows))]
        let (yaml, policy) = (
            "---\n- device_fd: 3\n- device_fd: 4\n",
            DevicePolicy::BorrowedFd,
        );
        #[cfg(windows)]
        let (yaml, policy) = (
            "---\n- device_name: tun0\n  address: 10.0.0.2\n  netmask: 255.255.255.0\n\
             - device_name: tun1\n  address: 10.0.1.2\n  netmask: 255.255.255.0\n",
            DevicePolicy::Owned,
        );

        let _registry = crate::outbound_stats::REGISTRY_TEST_LOCK.lock().unwrap();
        let err = current_thread_runtime()
            .block_on(prepare_from_config(yaml, policy))
            .map(|_| ())
            .unwrap_err();
        assert!(
            err.to_string().contains("Multiple TUN configs"),
            "expected a multiple-TUN complaint, got: {err}"
        );
    }

    /// The Apple host learns its descriptor only inside the extension, after
    /// the document was generated somewhere else. So the fd arrives as a
    /// parameter and must win over whatever the document says -- the
    /// consumer's generator emits `device_fd: 0` as a stand-in.
    #[cfg(not(windows))]
    #[test]
    fn test_prepare_with_fd_overrides_the_documents_descriptor() {
        let _registry = crate::outbound_stats::REGISTRY_TEST_LOCK.lock().unwrap();
        let prepared = current_thread_runtime()
            .block_on(prepare_from_config_with_fd("---\n- device_fd: 0\n", 7))
            .unwrap();
        assert_eq!(prepared.tun_config.device_fd, Some(7));
    }

    /// And fills an absent one, so a generator can also omit the field.
    #[cfg(not(windows))]
    #[test]
    fn test_prepare_with_fd_fills_an_absent_descriptor() {
        let _registry = crate::outbound_stats::REGISTRY_TEST_LOCK.lock().unwrap();
        let prepared = current_thread_runtime()
            .block_on(prepare_from_config_with_fd(
                "---\n- device_name: utun9\n  address: 10.0.0.2\n  netmask: 255.255.255.0\n",
                7,
            ))
            .unwrap();
        assert_eq!(prepared.tun_config.device_fd, Some(7));
    }

    /// A config with no TUN section is still refused: the parameter names a
    /// descriptor for the TUN, it does not conjure one.
    #[test]
    fn test_prepare_with_fd_still_needs_a_tun_section() {
        let _registry = crate::outbound_stats::REGISTRY_TEST_LOCK.lock().unwrap();
        let err = current_thread_runtime()
            .block_on(prepare_from_config_with_fd("---\n[]\n", 7))
            .map(|_| ())
            .unwrap_err();
        assert!(err.to_string().contains("No TUN config found"));
    }

    use std::sync::mpsc;

    fn test_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .unwrap()
    }

    /// The watcher takes its receivers as parameters precisely so these
    /// tests can build their own channels and never touch the global.
    #[tokio::test]
    async fn a_fatal_report_forwards_shutdown_and_carries_its_reason() {
        let (fatal_tx, fatal_rx) = tokio::sync::watch::channel((0u64, None));
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let (forward_tx, forward_rx) = oneshot::channel::<()>();
        let watcher = tokio::spawn(shutdown_or_fatal(shutdown_rx, fatal_rx, forward_tx));

        fatal_tx.send_replace((0, Some("receive path died".to_string())));

        forward_rx.await.expect("the merged shutdown must fire");
        assert_eq!(watcher.await.unwrap().as_deref(), Some("receive path died"));
        drop(shutdown_tx);
    }

    #[tokio::test]
    async fn a_host_stop_forwards_shutdown_without_a_reason() {
        let (_fatal_tx, fatal_rx) = tokio::sync::watch::channel((0u64, None::<String>));
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let (forward_tx, forward_rx) = oneshot::channel::<()>();
        let watcher = tokio::spawn(shutdown_or_fatal(shutdown_rx, fatal_rx, forward_tx));

        shutdown_tx.send(()).unwrap();

        forward_rx.await.expect("the merged shutdown must fire");
        assert_eq!(watcher.await.unwrap(), None);
    }

    /// A failing service reports its message, and by then `running` is
    /// already false -- a callback that stops the engine must not wait out
    /// STOP_TIMEOUT for a flag the task was about to clear.
    #[test]
    fn on_exit_reports_a_failure_after_running_is_false() {
        let (tx, rx) = mpsc::channel();
        let handle = start_with(
            test_runtime(),
            |_shutdown| async { Err(std::io::Error::other("boom")) },
            move |reason| tx.send(reason).unwrap(),
        );
        let reason = rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
        assert_eq!(reason.as_deref(), Some("boom"));
        assert!(!handle.running.load(Ordering::SeqCst));
        let _ = stop_handle(handle);
    }

    /// A stop the host asked for is a stop the host knows about: no call.
    #[test]
    fn on_exit_is_silent_for_a_requested_stop() {
        let (tx, rx) = mpsc::channel();
        let handle = start_with(
            test_runtime(),
            |shutdown| async move {
                let _ = shutdown.await;
                Ok(())
            },
            move |reason| tx.send(reason).unwrap(),
        );
        assert!(matches!(stop_handle(handle), StopOutcome::Released));
        assert!(
            rx.recv_timeout(std::time::Duration::from_millis(200))
                .is_err()
        );
    }

    /// An Ok that nobody requested is still an exit the host must hear
    /// about; `None` is what it hears.
    #[test]
    fn on_exit_reports_an_unrequested_ok_with_the_recorded_sentence() {
        let (tx, rx) = mpsc::channel();
        let handle = start_with(
            test_runtime(),
            |_shutdown| async { Ok(()) },
            move |reason| tx.send(reason).unwrap(),
        );
        let reason = rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
        // The same sentence status() records: the FFI hosts read only what
        // on_exit carries, and None here meant a reasonless callback plus a
        // stale shoes_get_last_error.
        assert_eq!(reason.as_deref(), Some(ENDED_UNREQUESTED));
        assert_eq!(
            handle.failure.lock().as_deref(),
            Some(ENDED_UNREQUESTED),
            "status must not call this a requested stop"
        );
        let _ = stop_handle(handle);
    }

    /// The handle is where `install` put it before the service can end, so a
    /// callback that fires in the first instant finds it.
    #[test]
    fn start_and_install_stores_the_handle_before_the_task_runs() {
        let slot: Arc<parking_lot::Mutex<Option<ServiceHandle>>> =
            Arc::new(parking_lot::Mutex::new(None));
        let seen = Arc::new(AtomicBool::new(false));
        let (slot_cb, seen_cb) = (slot.clone(), seen.clone());
        let (handle, go) = spawn_service(
            test_runtime(),
            |_shutdown| async { Err(std::io::Error::other("instant")) },
            move |_| seen_cb.store(slot_cb.lock().is_some(), Ordering::SeqCst),
        );
        *slot.lock() = Some(handle);
        go();
        let started = std::time::Instant::now();
        while !seen.load(Ordering::SeqCst) && started.elapsed() < std::time::Duration::from_secs(2)
        {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(
            seen.load(Ordering::SeqCst),
            "the callback found no handle installed"
        );
        let handle = slot.lock().take().unwrap();
        let _ = stop_handle(handle);
    }
}

#[cfg(all(test, feature = "control-stats"))]
mod outbound_install_tests {
    use crate::outbound_stats::{REGISTRY_TEST_LOCK, reset_for_test, snapshot_all};

    /// Preparing a service is the commitment to running it, so this is where
    /// the registry is replaced — and where a host's list appears at zero.
    // The guard is held across awaits on purpose. `#[tokio::test]` runs a
    // current-thread runtime, so there is no other task on this thread to
    // starve, and no test takes this lock twice -- it exists precisely to stop
    // these tests interleaving on the process-global registry.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn preparing_a_service_installs_its_outbounds() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_for_test();

        // A TUN section is required. On the fd platforms BorrowedFd takes the
        // descriptor from the config; Windows has no descriptor and creates
        // its own device. Nothing opens anything here -- the device is
        // touched in run_prepared, not in prepare_from_config.
        #[cfg(not(windows))]
        let (tun_yaml, policy) = ("device_fd: 3", super::DevicePolicy::BorrowedFd);
        #[cfg(windows)]
        let (tun_yaml, policy) = (
            "device_name: tun0\n  address: 10.0.0.2\n  netmask: 255.255.255.0",
            super::DevicePolicy::Owned,
        );
        let yaml = format!(
            r#"
- {tun_yaml}
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        name: Frankfurt
        address: "fra1.example:443"
        protocol: {{type: socks}}
"#
        );
        let _prepared = super::prepare_from_config(&yaml, policy).await.unwrap();

        let names: Vec<String> = snapshot_all().into_iter().map(|o| o.name).collect();
        assert!(names.contains(&"Frankfurt".to_string()), "got {names:?}");
        assert!(names.contains(&"direct".to_string()), "got {names:?}");
    }

    /// A prepare that fails must leave the registry alone. Otherwise a
    /// rejected config's servers are published, and a service already running
    /// loses its counters from the registry while its chains go on holding
    /// them -- its traffic would disappear from every later snapshot.
    // Same as its neighbour: a current-thread runtime, and the lock exists to
    // stop these tests interleaving on the process-global registry.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn a_failed_prepare_does_not_touch_the_registry() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_for_test();

        // Valid config, valid outbound, but no TUN section: this fails after
        // create_server_configs has already produced the set.
        let yaml = r#"
- address: "127.0.0.1:0"
  protocol: {type: socks}
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        name: Rejected
        address: "rejected.example:443"
        protocol: {type: socks}
"#;
        let err = super::prepare_from_config(yaml, super::DevicePolicy::BorrowedFd)
            .await
            .map(|_| ())
            .unwrap_err();
        assert!(err.to_string().contains("No TUN config"), "got: {err}");

        assert!(
            snapshot_all().is_empty(),
            "a rejected config published {:?}",
            snapshot_all()
        );
    }
}
