//! The one owner of the session.
//!
//! A plain thread, not a task, and that is forced rather than chosen.
//! `ServiceHandle::stop` sleeps its caller for up to `STOP_TIMEOUT` in a poll
//! loop and may drop a tokio runtime inline; its own documentation says never
//! to do that from async code. A gRPC handler is the worst possible place to
//! call it from, so no gRPC handler ever holds the handle.
//!
//! Everything reaches the session through one channel, which makes the channel
//! the serialization point: a second `Start` while a session exists is refused
//! by a state machine one thread owns, rather than by a lock every caller has
//! to remember. The engine's own exit callback posts to the same channel, so a
//! session that dies on its own and one the user stopped converge on a single
//! revert path instead of two that can race.

use std::net::IpAddr;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use shoes::control::{self, DevicePolicy, ServiceHandle, StopOutcome};
use tokio::sync::{broadcast, oneshot};

use crate::host::{AppliedState, HostNetwork, Plan, Session};

/// How long to wait for the engine to create its device.
///
/// `control::start` returns once the service task is spawned, which is before
/// the TUN device exists -- and the interface name is what routes and DNS are
/// addressed to, so there is nothing to apply until it appears. Generous,
/// because the alternative to waiting is applying routes to an interface that
/// is not there yet.
const DEVICE_TIMEOUT: Duration = Duration::from_secs(10);

/// How often to look while waiting for it.
const DEVICE_POLL: Duration = Duration::from_millis(20);

/// What a client sees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    Stopped { reason: StopReason },
    Starting,
    Running,
    Stopping,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    /// Never started, or stopped because someone asked.
    Requested,
    /// The engine ended without being asked. Carries what to show.
    Failed(String),
}

/// A reading of the session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub state: State,
    pub uptime: Option<Duration>,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub active_connections: usize,
    pub interface: Option<String>,
}

/// Why a start did not happen. Maps onto a gRPC code; see `service.rs`.
#[derive(Debug)]
pub enum StartError {
    /// A session already exists. Never a silent replace.
    AlreadyRunning,
    /// The config did not parse or validate. Carries shoes' own message.
    Config(std::io::Error),
    /// The device could not be created, or never appeared.
    Device(String),
    /// Routes or DNS failed. Everything applied has been undone.
    HostNetwork(std::io::Error),
}

enum Command {
    Start {
        yaml: String,
        exclude: Vec<IpAddr>,
        dns: Vec<IpAddr>,
        reply: oneshot::Sender<Result<(), StartError>>,
    },
    Stop {
        reply: oneshot::Sender<StopOutcome>,
    },
    Status {
        reply: oneshot::Sender<Status>,
    },
    /// From the engine's exit callback.
    EngineExited(Option<String>),
    /// From the route monitor: something in the routing table moved.
    NetworkChanged,
    Shutdown,
}

/// The handle every gRPC handler holds.
#[derive(Clone)]
pub struct Supervisor {
    commands: mpsc::Sender<Command>,
    /// Transitions, for `WatchStatus`. Separate from the command channel so a
    /// watcher never blocks the session.
    transitions: broadcast::Sender<Status>,
}

impl Supervisor {
    /// Start the supervisor thread.
    ///
    /// The host is *built* on that thread rather than moved onto it, because
    /// the macOS one holds an `SCDynamicStore` -- a CoreFoundation object
    /// behind a raw pointer, and so not `Send`. Constructing it here also puts
    /// its one startup failure, "the configuration store would not open", on
    /// the thread that would have used it, and this call waits for that
    /// verdict rather than returning a supervisor that is about to die.
    pub fn spawn<N, F>(
        make_net: F,
        state_path: std::path::PathBuf,
    ) -> std::io::Result<(Self, std::thread::JoinHandle<()>)>
    where
        N: HostNetwork,
        F: FnOnce() -> std::io::Result<N> + Send + 'static,
    {
        let (commands, rx) = mpsc::channel();
        let (transitions, _) = broadcast::channel(64);
        let (ready, wait_ready) = mpsc::channel();

        let supervisor = Self {
            commands,
            transitions: transitions.clone(),
        };
        let exit_channel = supervisor.commands.clone();

        let thread = std::thread::Builder::new()
            .name("shoesd-supervisor".to_owned())
            .spawn(move || {
                let net = match make_net() {
                    Ok(net) => {
                        let _ = ready.send(Ok(()));
                        net
                    }
                    Err(e) => {
                        let _ = ready.send(Err(e));
                        return;
                    }
                };
                let mut inner = Inner {
                    net,
                    state_path,
                    exit_channel,
                    transitions,
                    handle: None,
                    applied: None,
                    state: State::Stopped {
                        reason: StopReason::Requested,
                    },
                    started_at: None,
                    interface: None,
                    exclude: Vec::new(),
                    dns: Vec::new(),
                    recovery_pending: false,
                };
                inner.run(rx);
            })?;

        match wait_ready.recv() {
            Ok(Ok(())) => Ok((supervisor, thread)),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(std::io::Error::other(
                "the supervisor thread ended before it reported",
            )),
        }
    }

    pub fn start(
        &self,
        yaml: String,
        exclude: Vec<IpAddr>,
        dns: Vec<IpAddr>,
    ) -> Result<(), StartError> {
        let (reply, wait) = oneshot::channel();
        self.send(Command::Start {
            yaml,
            exclude,
            dns,
            reply,
        });
        wait.blocking_recv()
            .unwrap_or(Err(StartError::Device("the supervisor is gone".into())))
    }

    pub fn stop(&self) -> StopOutcome {
        let (reply, wait) = oneshot::channel();
        self.send(Command::Stop { reply });
        wait.blocking_recv().unwrap_or(StopOutcome::Released)
    }

    pub fn status(&self) -> Status {
        let (reply, wait) = oneshot::channel();
        self.send(Command::Status { reply });
        wait.blocking_recv().unwrap_or_else(|_| Status {
            state: State::Stopped {
                reason: StopReason::Failed("the supervisor is gone".into()),
            },
            uptime: None,
            upload_bytes: 0,
            download_bytes: 0,
            active_connections: 0,
            interface: None,
        })
    }

    /// Every transition from now, for `WatchStatus`. The caller sends the
    /// current status first; this carries what comes after.
    pub fn watch(&self) -> broadcast::Receiver<Status> {
        self.transitions.subscribe()
    }

    /// Tell the supervisor the routing table moved.
    ///
    /// Cheap and idempotent, so the monitor can be liberal about what it
    /// reports: the handler re-reads the table and compares, rather than
    /// trying to work out what changed from the notification. Posted as a
    /// command so the re-apply is serialised with `Start` and `Stop` instead
    /// of racing them.
    pub fn network_changed(&self) {
        self.send(Command::NetworkChanged);
    }

    /// Stop the session and end the thread. For `SIGTERM`.
    pub fn shutdown(&self) {
        self.send(Command::Shutdown);
    }

    fn send(&self, command: Command) {
        // A closed channel means the supervisor thread is gone, which each
        // caller turns into its own answer -- there is nothing useful to do
        // about it here.
        let _ = self.commands.send(command);
    }
}

struct Inner<N: HostNetwork> {
    net: N,
    state_path: std::path::PathBuf,
    exit_channel: mpsc::Sender<Command>,
    transitions: broadcast::Sender<Status>,
    handle: Option<ServiceHandle>,
    applied: Option<AppliedState>,
    state: State,
    started_at: Option<Instant>,
    interface: Option<String>,
    /// What the running session asked to keep outside the tunnel, and which
    /// resolvers to advertise. Kept because a network change means recomputing
    /// the exclusion routes from the *new* gateway, which needs the addresses
    /// the plan named rather than the routes it produced.
    exclude: Vec<IpAddr>,
    dns: Vec<IpAddr>,
    /// A previous session's record is still on disk and could not be undone.
    ///
    /// Kept rather than forgotten, because `apply` writes a *fresh* record over
    /// the same path on its first route -- so starting anyway would erase the
    /// DNS backup that is the only way back to the host's own resolvers. The
    /// usual cause is transient (launchd restarts the daemon during early boot,
    /// before there is a primary network service to read DNS from), so the next
    /// start retries rather than refusing forever.
    recovery_pending: bool,
}

impl<N: HostNetwork> Inner<N> {
    fn run(&mut self, commands: mpsc::Receiver<Command>) {
        // Before anything else, and on every start rather than only after a
        // crash: a record on disk means the machine is not in the state this
        // process is about to assume.
        if let Err(e) = self.session().recover() {
            log::error!(
                "could not undo what a previous session left behind ({e}); \
                 refusing to start until it can be"
            );
            self.recovery_pending = true;
        }

        while let Ok(command) = commands.recv() {
            match command {
                Command::Start {
                    yaml,
                    exclude,
                    dns,
                    reply,
                } => {
                    let _ = reply.send(self.start(yaml, exclude, dns));
                }
                Command::Stop { reply } => {
                    let _ = reply.send(self.stop(StopReason::Requested));
                }
                Command::Status { reply } => {
                    let _ = reply.send(self.status());
                }
                Command::EngineExited(reason) => self.engine_exited(reason),
                Command::NetworkChanged => self.network_changed(),
                Command::Shutdown => {
                    let _ = self.stop(StopReason::Requested);
                    return;
                }
            }
        }
    }

    fn session(&self) -> Session<'_, N> {
        Session::new(&self.net, self.state_path.clone())
    }

    fn start(
        &mut self,
        yaml: String,
        exclude: Vec<IpAddr>,
        dns: Vec<IpAddr>,
    ) -> Result<(), StartError> {
        if !matches!(self.state, State::Stopped { .. }) {
            return Err(StartError::AlreadyRunning);
        }

        // Retried here rather than only at startup: the usual reason recovery
        // fails is that the machine had no network yet, and by the time
        // someone asks for a tunnel it does.
        if self.recovery_pending {
            match self.session().recover() {
                Ok(()) => self.recovery_pending = false,
                Err(e) => {
                    return Err(StartError::HostNetwork(std::io::Error::other(format!(
                        "a previous session's routes or DNS are still applied and could not \
                         be undone ({e}); starting now would overwrite the record of them"
                    ))));
                }
            }
        }

        self.transition(State::Starting);

        // The engine's runtime, built here so that `prepare` runs on it and
        // `start` takes it. The supervisor thread itself stays synchronous.
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|e| StartError::Device(format!("could not start a runtime: {e}")))?;

        // Every failure a bad config can produce happens here, in front of the
        // caller, with nothing started and nothing applied.
        let prepared = runtime
            .block_on(control::prepare_from_config(&yaml, DevicePolicy::Owned))
            .map_err(|e| {
                self.transition(State::Stopped {
                    reason: StopReason::Requested,
                });
                StartError::Config(e)
            })?;

        let exit_channel = self.exit_channel.clone();
        let handle = control::start(runtime, prepared, move |reason| {
            // Posted rather than acted on: this runs on one of the engine's
            // own threads, and reverting from there would race the supervisor.
            let _ = exit_channel.send(Command::EngineExited(reason));
        });

        let interface = match self.await_interface(&handle) {
            Ok(interface) => interface,
            Err(e) => {
                let _ = control::stop_handle(handle);
                self.transition(State::Stopped {
                    reason: StopReason::Requested,
                });
                return Err(StartError::Device(e));
            }
        };

        let plan = Plan {
            interface: interface.clone(),
            exclude: exclude.clone(),
            dns: dns.clone(),
        };
        let applied = match self.session().apply(&plan) {
            Ok(applied) => applied,
            Err(e) => {
                // `apply` has already undone whatever it managed, so the only
                // thing left holding the machine is the engine.
                let _ = control::stop_handle(handle);
                self.transition(State::Stopped {
                    reason: StopReason::Requested,
                });
                return Err(StartError::HostNetwork(e));
            }
        };

        self.handle = Some(handle);
        self.applied = Some(applied);
        self.started_at = Some(Instant::now());
        self.interface = Some(interface);
        self.exclude = exclude;
        self.dns = dns;
        self.transition(State::Running);
        Ok(())
    }

    /// Wait for the engine to create its device and report its name.
    ///
    /// Polled rather than signalled: the name is published by the stack thread
    /// deep inside the engine, and threading a channel out through
    /// `run_tun_from_config` to reach it would put a daemon's concern into
    /// code four other hosts share. The wait is bounded, and a device that
    /// never appears fails the start rather than leaving a session that looks
    /// running with no routes.
    fn await_interface(&self, handle: &ServiceHandle) -> Result<String, String> {
        let deadline = Instant::now() + DEVICE_TIMEOUT;
        loop {
            if let Some(interface) = shoes::tun::device_name() {
                return Ok(interface);
            }
            if !handle.is_running() {
                return Err("the engine stopped before it created a device".to_string());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "no TUN device appeared within {}s",
                    DEVICE_TIMEOUT.as_secs()
                ));
            }
            std::thread::sleep(DEVICE_POLL);
        }
    }

    fn stop(&mut self, reason: StopReason) -> StopOutcome {
        let Some(handle) = self.handle.take() else {
            // Nothing was running. Not an error: a client that reconnects and
            // stops a session that already ended wants to hear that it is
            // stopped, not that something went wrong.
            //
            // A recorded failure survives this. The engine's cause of death is
            // reported nowhere else, and a GUI that shows the banner and then
            // calls Stop -- or auto-stops on reconnect -- would otherwise erase
            // it from every later GetStatus.
            let reason = match &self.state {
                State::Stopped {
                    reason: failed @ StopReason::Failed(_),
                } => failed.clone(),
                _ => reason,
            };
            self.transition(State::Stopped { reason });
            return StopOutcome::Released;
        };

        self.transition(State::Stopping);
        let outcome = control::stop_handle(handle);
        self.revert(&outcome);
        self.transition(State::Stopped { reason });
        outcome
    }

    fn engine_exited(&mut self, reason: Option<String>) {
        if self.handle.is_none() {
            // A stop the user asked for already took the handle; the callback
            // is not called for those, but a race between the two is cheaper
            // to ignore than to reason about.
            return;
        }
        let message = reason.unwrap_or_else(|| "the tunnel ended unexpectedly".to_string());
        log::error!("the engine exited on its own: {message}");

        // The handle is spent -- the task is already gone -- so it is
        // discarded rather than stopped, which would wait out a timeout for a
        // flag that is already false.
        if let Some(handle) = self.handle.take() {
            handle.discard();
        }
        self.revert(&StopOutcome::Released);
        self.transition(State::Stopped {
            reason: StopReason::Failed(message),
        });
    }

    /// Undo the host changes and forget the record.
    fn revert(&mut self, outcome: &StopOutcome) {
        if let Some(applied) = self.applied.take()
            && let Err(e) = self.session().revert(&applied)
        {
            log::error!("could not fully undo the session's host configuration: {e}");
        }

        self.started_at = None;
        self.interface = None;
        self.exclude = Vec::new();
        self.dns = Vec::new();

        // A stop that timed out has not been confirmed to release the device,
        // so the record stays: a start after this one must still know there
        // may be something to undo. `StopOutcome` exists to force exactly this
        // decision rather than let it be discarded.
        if outcome.device_released()
            && let Err(e) = AppliedState::clear(&self.state_path)
        {
            log::warn!("could not remove {}: {e}", self.state_path.display());
        }
    }

    /// Re-point the exclusions at whatever the gateway is now.
    ///
    /// Only while running, and only with something applied: a change while
    /// stopped has nothing to re-apply, and one mid-start is followed by the
    /// apply itself reading the table.
    fn network_changed(&mut self) {
        if self.state != State::Running {
            return;
        }
        let Some(mut applied) = self.applied.take() else {
            return;
        };

        let session = Session::new(&self.net, self.state_path.clone());
        match session.reapply(&mut applied, &self.exclude, &self.dns) {
            Ok(true) => log::info!("re-applied the session's host configuration"),
            Ok(false) => log::debug!("a routing change left the session's routes correct"),
            // Logged rather than fatal: the session is still carrying traffic,
            // and tearing it down because one re-apply failed would be a worse
            // answer than a stale exclusion the next change may fix.
            Err(e) => log::error!("could not re-apply after a network change: {e}"),
        }
        self.applied = Some(applied);
    }

    fn status(&self) -> Status {
        let stats = shoes::control::stats::snapshot();
        Status {
            state: self.state.clone(),
            uptime: self.started_at.map(|at| at.elapsed()),
            upload_bytes: stats.upload_bytes,
            download_bytes: stats.download_bytes,
            active_connections: stats.active_connections,
            interface: self.interface.clone(),
        }
    }

    fn transition(&mut self, state: State) {
        self.state = state;
        // A watcher that has fallen behind, or none at all, must not hold up
        // the session -- so the result is dropped rather than checked.
        let _ = self.transitions.send(self.status());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::DnsBackup;
    use crate::host::double::Recorder;

    /// The supervisor over a double, with no engine: enough to pin the state
    /// machine and the refusals, which is what the gRPC layer switches on.
    fn supervisor(dir: &tempfile::TempDir) -> Supervisor {
        let (supervisor, _thread) =
            Supervisor::spawn(|| Ok(Recorder::new()), dir.path().join("applied.json"))
                .expect("the supervisor thread starts");
        supervisor
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_fresh_supervisor_is_stopped_and_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let supervisor = supervisor(&dir);

        let status = tokio::task::spawn_blocking(move || supervisor.status())
            .await
            .unwrap();
        assert_eq!(
            status.state,
            State::Stopped {
                reason: StopReason::Requested
            }
        );
        assert_eq!(status.interface, None);
        assert_eq!(status.uptime, None);
    }

    /// Stopping something that is not running is not an error. A client that
    /// reconnects after a crash and stops wants to hear "stopped", not a
    /// failure it has to explain to a user.
    #[tokio::test(flavor = "multi_thread")]
    async fn stopping_nothing_reports_released() {
        let dir = tempfile::tempdir().unwrap();
        let supervisor = supervisor(&dir);

        let outcome = tokio::task::spawn_blocking(move || supervisor.stop())
            .await
            .unwrap();
        assert!(matches!(outcome, StopOutcome::Released));
    }

    /// A config that will not parse fails in front of the caller, with
    /// nothing started and nothing applied to the host.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_bad_config_fails_before_anything_is_touched() {
        let dir = tempfile::tempdir().unwrap();
        let (supervisor, _thread) =
            Supervisor::spawn(|| Ok(Recorder::new()), dir.path().join("applied.json")).unwrap();

        let result = tokio::task::spawn_blocking({
            let supervisor = supervisor.clone();
            move || supervisor.start("this: is: not: a: config".into(), vec![], vec![])
        })
        .await
        .unwrap();

        assert!(
            matches!(result, Err(StartError::Config(_))),
            "got {result:?}"
        );

        let status = tokio::task::spawn_blocking(move || supervisor.status())
            .await
            .unwrap();
        assert_eq!(
            status.state,
            State::Stopped {
                reason: StopReason::Requested
            },
            "a failed start must not leave the session Starting"
        );
    }

    /// Transitions reach a watcher, which is what `WatchStatus` streams. The
    /// failed start above passes through `Starting` on its way back to
    /// `Stopped`, and a GUI showing a spinner needs both.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_watcher_sees_the_transitions() {
        let dir = tempfile::tempdir().unwrap();
        let (supervisor, _thread) =
            Supervisor::spawn(|| Ok(Recorder::new()), dir.path().join("applied.json")).unwrap();

        let mut watch = supervisor.watch();
        let _ = tokio::task::spawn_blocking({
            let supervisor = supervisor.clone();
            move || supervisor.start("this: is: not: a: config".into(), vec![], vec![])
        })
        .await
        .unwrap();

        let first = watch.recv().await.expect("a transition arrives");
        assert_eq!(first.state, State::Starting);
        let second = watch.recv().await.expect("and the one after it");
        assert_eq!(
            second.state,
            State::Stopped {
                reason: StopReason::Requested
            }
        );
    }

    /// `shutdown` must end the thread, because nothing else can.
    ///
    /// `Inner` holds a clone of its own command sender, so the receive loop
    /// never sees a closed channel however many `Supervisor` handles are
    /// dropped. `serve` has two `?` returns before it starts serving -- an
    /// unknown group, a socket it cannot bind -- and the caller joins this
    /// thread on every path out. Without this the daemon would hang there
    /// forever having printed nothing, and launchd would see a live process
    /// rather than a job to restart.
    #[tokio::test(flavor = "multi_thread")]
    async fn shutdown_ends_the_supervisor_thread() {
        let dir = tempfile::tempdir().unwrap();
        let (supervisor, thread) =
            Supervisor::spawn(|| Ok(Recorder::new()), dir.path().join("applied.json")).unwrap();

        supervisor.shutdown();
        // Dropping every handle is deliberately not enough on its own, and
        // this asserts the thread ends anyway.
        drop(supervisor);

        // The join is bounded rather than direct: without the fix this test
        // is checking, `join` blocks forever -- and a test that hangs is worse
        // in CI than one that fails, because it takes the whole run's timeout
        // with it and names nothing.
        let (done, wait) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = thread.join();
            let _ = done.send(());
        });
        wait.recv_timeout(Duration::from_secs(10))
            .expect("the supervisor thread should have ended after shutdown");
    }

    /// A recovery that could not finish blocks the next start rather than
    /// letting it overwrite the record.
    ///
    /// `apply` writes a fresh `AppliedState` over the same path on its first
    /// route, so starting anyway would erase the DNS backup -- the only way
    /// back to the host's own resolvers -- while those resolvers are still
    /// overridden. The usual cause is transient: launchd restarts the daemon
    /// during early boot, before there is a primary network service to write
    /// DNS to.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_start_is_refused_while_an_unrecovered_record_remains() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("applied.json");
        AppliedState {
            interface: Some("utun4".into()),
            routes: Vec::new(),
            dns: Some(DnsBackup {
                service: "primary".into(),
                servers: vec!["192.168.1.1".parse().unwrap()],
            }),
        }
        .save(&path)
        .unwrap();

        let (supervisor, _thread) =
            Supervisor::spawn(|| Ok(Recorder::new().failing_write_dns()), path.clone()).unwrap();

        let result = tokio::task::spawn_blocking({
            let supervisor = supervisor.clone();
            move || supervisor.start("---\n[]\n".into(), vec![], vec![])
        })
        .await
        .unwrap();

        assert!(
            matches!(result, Err(StartError::HostNetwork(_))),
            "got {result:?}"
        );
        assert!(
            path.exists(),
            "the record must survive, or the DNS backup in it is lost"
        );
    }

    /// A Stop must not erase why the engine died.
    ///
    /// The cause of death is reported nowhere else, and a GUI that shows the
    /// banner and then calls Stop -- or auto-stops on reconnect -- would
    /// otherwise lose it from every later GetStatus.
    ///
    /// Driven against `Inner` rather than through the channel, because getting
    /// there the long way needs an engine to die: `engine_exited` is a no-op
    /// without a live handle, which is correct and also means the state this
    /// tests cannot be reached from outside without a real session.
    #[test]
    fn stopping_after_a_failure_keeps_the_reason() {
        let dir = tempfile::tempdir().unwrap();
        let (commands, _rx) = mpsc::channel();
        let (transitions, _) = broadcast::channel(8);

        let mut inner = Inner {
            net: Recorder::new(),
            state_path: dir.path().join("applied.json"),
            exit_channel: commands,
            transitions,
            handle: None,
            applied: None,
            state: State::Stopped {
                reason: StopReason::Failed("the tunnel died".into()),
            },
            started_at: None,
            interface: None,
            exclude: Vec::new(),
            dns: Vec::new(),
            recovery_pending: false,
        };

        let outcome = inner.stop(StopReason::Requested);

        assert!(matches!(outcome, StopOutcome::Released));
        assert_eq!(
            inner.state,
            State::Stopped {
                reason: StopReason::Failed("the tunnel died".into())
            },
            "a stop must not overwrite the failure"
        );
    }

    /// And an ordinary stop still reports a requested one, so the rule above
    /// does not pin every later session to a stale failure.
    #[test]
    fn stopping_a_clean_session_reports_requested() {
        let dir = tempfile::tempdir().unwrap();
        let (commands, _rx) = mpsc::channel();
        let (transitions, _) = broadcast::channel(8);

        let mut inner = Inner {
            net: Recorder::new(),
            state_path: dir.path().join("applied.json"),
            exit_channel: commands,
            transitions,
            handle: None,
            applied: None,
            state: State::Running,
            started_at: None,
            interface: None,
            exclude: Vec::new(),
            dns: Vec::new(),
            recovery_pending: false,
        };

        let _ = inner.stop(StopReason::Requested);

        assert_eq!(
            inner.state,
            State::Stopped {
                reason: StopReason::Requested
            }
        );
    }

    /// And once the reason recovery failed has passed, the retry clears the
    /// block rather than leaving the daemon permanently unable to start.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_retried_recovery_unblocks_the_next_start() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("applied.json");
        AppliedState {
            interface: Some("utun4".into()),
            routes: Vec::new(),
            dns: Some(DnsBackup {
                service: "primary".into(),
                servers: vec!["192.168.1.1".parse().unwrap()],
            }),
        }
        .save(&path)
        .unwrap();

        // The double refuses DNS writes at startup, then stops refusing --
        // which is the shape of the real case: launchd restarts the daemon
        // before there is a primary network service, and a minute later there
        // is one.
        let net = Recorder::new().failing_write_dns();
        let allow = net.allow_handle();
        let (supervisor, _thread) = Supervisor::spawn(move || Ok(net), path.clone()).unwrap();

        let blocked = tokio::task::spawn_blocking({
            let supervisor = supervisor.clone();
            move || supervisor.start("---\n[]\n".into(), vec![], vec![])
        })
        .await
        .unwrap();
        assert!(matches!(blocked, Err(StartError::HostNetwork(_))));

        allow();

        let unblocked = tokio::task::spawn_blocking({
            let supervisor = supervisor.clone();
            move || supervisor.start("---\n[]\n".into(), vec![], vec![])
        })
        .await
        .unwrap();
        // Past the recovery gate, and now failing on the empty config -- which
        // is the point: the block is gone.
        assert!(
            matches!(unblocked, Err(StartError::Config(_))),
            "got {unblocked:?}"
        );
    }

    /// The record from a previous run is undone before the supervisor accepts
    /// anything, not on the first start. A daemon that crashed with routes
    /// installed is restarted by launchd within seconds, and the user cannot
    /// reach the network until this has run.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_record_left_by_a_crash_is_undone_at_startup() {
        use crate::host::{Route, Via};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("applied.json");
        AppliedState {
            interface: Some("utun4".into()),
            routes: vec![Route::net(
                "0.0.0.0".parse().unwrap(),
                1,
                Via::Interface("utun4".into()),
            )],
            dns: None,
        }
        .save(&path)
        .unwrap();

        let (supervisor, _thread) =
            Supervisor::spawn(|| Ok(Recorder::new()), path.clone()).unwrap();
        // Round-trip a command so the thread has certainly reached its loop.
        let _ = tokio::task::spawn_blocking(move || supervisor.status())
            .await
            .unwrap();

        assert!(
            !path.exists(),
            "the record is undone and forgotten before anything else"
        );
    }
}
