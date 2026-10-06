//! Running under the Windows Service Control Manager.
//!
//! The daemon itself is unchanged: `shoesd service` runs exactly what
//! `shoesd run` runs, inside the handshake the SCM requires -- register a
//! control handler, report RUNNING, and report STOPPED with an exit code when
//! the daemon returns. A Stop or Shutdown from the SCM wakes the same
//! shutdown future `SIGTERM` drives on Unix, so the supervisor reverts the
//! session on the way out exactly as it does there.

use std::ffi::OsString;
use std::process::ExitCode;
use std::sync::OnceLock;
use std::time::Duration;

use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

/// The service's name. KVN tells users to run `sc.exe query shoesd` when the
/// daemon does not come up, so this is part of the contract with it.
pub const SERVICE_NAME: &str = "shoesd";

/// How long the SCM is told startup may take before the socket is bound.
const START_HINT: Duration = Duration::from_secs(30);

/// Woken by the SCM's Stop or Shutdown. `notify_one` stores a permit, so a
/// stop that arrives before anything is waiting is not lost.
static STOP: tokio::sync::Notify = tokio::sync::Notify::const_new();

/// What `shoesd service` was asked to run. Set once, before the dispatcher
/// starts: `define_windows_service!` takes a plain function, so the arguments
/// cannot be captured.
static RUN: OnceLock<crate::RunArgs> = OnceLock::new();

/// Resolves when the SCM asks the service to stop.
pub async fn stop_requested() {
    STOP.notified().await;
}

define_windows_service!(ffi_service_main, service_main);

/// Hand the process to the SCM. Returns once the service has stopped.
///
/// Fails at once when the process was not started by the SCM, which is what
/// running `shoesd service` from a console does -- `run` is the console mode.
pub fn run(args: crate::RunArgs) -> ExitCode {
    let _ = RUN.set(args);
    match service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!(
                "shoesd: could not connect to the Service Control Manager ({e}); \
                 `service` is what the SCM runs -- use `run` from a console"
            );
            ExitCode::FAILURE
        }
    }
}

fn service_main(_arguments: Vec<OsString>) {
    let handler = |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            STOP.notify_one();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status = match service_control_handler::register(SERVICE_NAME, handler) {
        Ok(status) => status,
        Err(e) => {
            eprintln!("shoesd: could not register with the Service Control Manager: {e}");
            return;
        }
    };

    let report = |state, accepted, exit_code, wait_hint| {
        let _ = status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accepted,
            exit_code,
            checkpoint: 0,
            wait_hint,
            process_id: None,
        });
    };

    // START_PENDING until the socket is bound, RUNNING only then: `install`
    // waits for RUNNING, so reporting it any earlier would let an install
    // succeed over a daemon that then failed to bind. The hint covers startup
    // -- probing the host and reverting a previous crash's record -- which
    // normally takes well under a second.
    report(
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
        ServiceExitCode::Win32(0),
        START_HINT,
    );
    let listening = || {
        report(
            ServiceState::Running,
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            ServiceExitCode::Win32(0),
            Duration::default(),
        );
    };

    let exit = match RUN.get() {
        Some(args) => crate::run_daemon(args.clone(), listening),
        None => ExitCode::FAILURE,
    };
    let exit_code = if exit == ExitCode::SUCCESS {
        ServiceExitCode::Win32(0)
    } else {
        ServiceExitCode::ServiceSpecific(1)
    };
    report(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        exit_code,
        Duration::default(),
    );
}
