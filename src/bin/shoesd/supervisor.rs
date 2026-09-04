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
}

impl<N: HostNetwork> Inner<N> {
    fn run(&mut self, commands: mpsc::Receiver<Command>) {
        // Before anything else, and on every start rather than only after a
        // crash: a record on disk means the machine is not in the state this
        // process is about to assume.
        if let Err(e) = self.session().recover() {
            log::error!("could not undo what a previous session left behind: {e}");
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
            exclude,
            dns,
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
