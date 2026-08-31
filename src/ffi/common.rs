//! Common FFI utilities shared between iOS and Android.
//!
//! This module contains platform-independent code that both iOS and Android use.
//!
//! The service lifecycle itself lives in [`crate::control`]. What stays here is
//! the part that is genuinely about the C and JNI boundary: global singletons,
//! because a caller on the far side addresses its service by an integer rather
//! than by holding a value, and the log-file plumbing those callers configure.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::OnceLock;
use std::sync::atomic::AtomicBool;

use log::info;

// Only what ios.rs and android.rs actually name. `mod common` is private, so
// re-exporting more than that is an unused import rather than a public API --
// and the Android clippy job builds with -D warnings.
pub use crate::control::ServiceHandle as TunServiceHandle;

/// Parse and validate a config for a mobile host.
///
/// Always `BorrowedFd`: Android takes its descriptor from
/// `VpnService.Builder.establish()` and iOS from
/// `NEPacketTunnelProvider.packetFlow`, so neither ever creates a device or
/// closes one it did not open.
pub async fn prepare_from_config(
    config_yaml: &str,
    device_fd: Option<i32>,
) -> std::io::Result<crate::control::PreparedService> {
    match device_fd {
        Some(fd) => crate::control::prepare_from_config_with_fd(config_yaml, fd).await,
        None => {
            crate::control::prepare_from_config(
                config_yaml,
                crate::control::DevicePolicy::BorrowedFd,
            )
            .await
        }
    }
}

/// Global log file handle for file-based logging.
pub static LOG_FILE: OnceLock<parking_lot::Mutex<Option<File>>> = OnceLock::new();

/// Global flag to track if logger has been initialized.
pub static LOGGER_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Global state for the TUN service.
pub static TUN_SERVICE: OnceLock<parking_lot::Mutex<Option<TunServiceHandle>>> = OnceLock::new();

/// Global flag to track initialization.
pub static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Last error message from the service. Set when `start_from_config` fails
/// or the service stops with an error. Read via `shoes_get_last_error()`.
pub static LAST_ERROR: OnceLock<parking_lot::Mutex<Option<String>>> = OnceLock::new();

/// Serializes start/stop transitions across the FFI surface.
///
/// `stop_service` takes the handle out of `TUN_SERVICE` and then waits up
/// to five seconds for the engine to wind down. For that whole window the
/// slot is empty and `is_service_running()` answers false -- so a start
/// arriving on another thread would pass its already-running guard and put
/// a second engine on the same device descriptor. Every transition holds
/// this lock for its whole duration: the concurrent caller waits its turn
/// and sees the truth when it gets in.
///
/// A stopped callback that calls `shoes_stop` while a host-initiated stop
/// holds the lock waits here for at most that stop's five-second bound --
/// the holder never waits on the callback's thread past its timeout, so
/// this cannot deadlock, only queue.
///
/// The start paths are the other holders, and they are bounded too: the
/// one open-ended thing a start does is prepare the config, which is
/// capped at [`PREPARE_TIMEOUT`]. Without that cap a stop queued behind
/// a start stuck in DNS resolution would blow the very budgets --
/// Android's ANR window, iOS's stopTunnel deadline -- the five-second
/// stop bound exists to respect.
static TRANSITION: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

/// The most a start may spend preparing a config -- parsing, binding,
/// and any DNS resolution the config asks for. The OS resolver on a
/// captive portal or a mid-change network can hang for tens of seconds,
/// and the whole prepare runs under the transition lock (see
/// [`TRANSITION`]), so an unbounded prepare holds every later stop and
/// start hostage to it.
pub const PREPARE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Take the transition lock. Held across all of `stop_service` and all of
/// each platform's start path.
pub fn transition_guard() -> parking_lot::MutexGuard<'static, ()> {
    TRANSITION.lock()
}

/// Set up log file for file-based logging.
///
/// Returns 0 on success, -1 on error.
pub fn setup_log_file(path_str: &str) -> i32 {
    let file_mutex = LOG_FILE.get_or_init(|| parking_lot::Mutex::new(None));

    match OpenOptions::new().create(true).append(true).open(path_str) {
        Ok(file) => {
            *file_mutex.lock() = Some(file);
            info!("Log file set to: {}", path_str);
            0
        }
        Err(_) => -1,
    }
}

/// Write a log message to the log file if configured.
pub fn write_to_log_file(level: log::Level, target: &str, message: &str) {
    if let Some(file_mutex) = LOG_FILE.get() {
        let mut guard = file_mutex.lock();
        if let Some(ref mut writer) = *guard {
            let _ = writeln!(writer, "{} [{}] {}", level, target, message);
        }
    }
}

/// Flush the log file.
pub fn flush_log_file() {
    if let Some(file_mutex) = LOG_FILE.get() {
        let mut guard = file_mutex.lock();
        if let Some(ref mut writer) = *guard {
            let _ = writer.flush();
        }
    }
}

/// Stop the TUN service and wait for shutdown.
///
/// This is the common shutdown logic used by both iOS and Android.
///
/// Returns `true` if the service confirmed it stopped, `false` if the wait
/// timed out. See [`crate::control::stop_handle`] for what that distinction
/// costs the caller.
pub fn stop_service() -> bool {
    // Held to the end: a start that arrives mid-stop must wait until the
    // engine is gone, and a second stop must not clear the protector out
    // from under a teardown still in flight.
    let transition = transition_guard();
    stop_service_locked(&transition)
}

/// The body of [`stop_service`], for a caller that already holds the
/// transition lock -- the platform stop functions, which must clear their
/// callback slots inside the same locked scope. Clearing them after the
/// lock is released wiped the callbacks a queued start had just
/// installed, leaving its fresh engine with no socket protector.
pub fn stop_service_locked(_transition: &parking_lot::MutexGuard<'static, ()>) -> bool {
    info!("Stopping TUN service");

    let handle = if let Some(service) = TUN_SERVICE.get() {
        service.lock().take()
    } else {
        None
    };

    let Some(handle) = handle else {
        info!("TUN service was not running");
        crate::socket_protector::clear_global_socket_protector();
        return true;
    };

    // The C and JNI surfaces answer with an int, so the obligation the type
    // carries is flattened here rather than at the call sites.
    let stopped = crate::control::stop_handle(handle).device_released();

    // The protector holds a reference to the platform's VPN service object.
    // Released here rather than in the platform modules so that neither one can
    // forget.
    crate::socket_protector::clear_global_socket_protector();

    info!("TUN service stop completed");
    stopped
}

/// Store an error message.
pub fn set_last_error(error: String) {
    let err = LAST_ERROR.get_or_init(|| parking_lot::Mutex::new(None));
    *err.lock() = Some(error);
}

/// Clear the last error message (called on successful start).
pub fn clear_last_error() {
    if let Some(err) = LAST_ERROR.get() {
        *err.lock() = None;
    }
}

/// Get the last error message, if any.
pub fn get_last_error() -> Option<String> {
    LAST_ERROR.get().and_then(|m| m.lock().clone())
}

/// Check if the TUN service is running.
pub fn is_service_running() -> bool {
    if let Some(service) = TUN_SERVICE.get() {
        let guard = service.lock();
        if let Some(ref handle) = *guard {
            return handle.is_running();
        }
    }
    false
}

/// Serialize tests that mutate the shared LAST_ERROR state. pub(crate)
/// because two suites touch it -- these tests and `ffi::ios::tests`, which
/// asserts on the message a failed start leaves -- and cargo runs them on
/// different threads; two lock domains over one global is a flake.
#[cfg(test)]
pub(crate) static LAST_ERROR_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_and_get_last_error() {
        let _guard = LAST_ERROR_TEST_LOCK.lock().unwrap();
        clear_last_error();

        assert!(get_last_error().is_none());

        set_last_error("connection refused".to_string());
        assert_eq!(get_last_error().as_deref(), Some("connection refused"));
    }

    #[test]
    fn test_clear_last_error() {
        let _guard = LAST_ERROR_TEST_LOCK.lock().unwrap();

        set_last_error("some error".to_string());
        assert!(get_last_error().is_some());

        clear_last_error();
        assert!(get_last_error().is_none());
    }

    #[test]
    fn test_set_overwrites_previous_error() {
        let _guard = LAST_ERROR_TEST_LOCK.lock().unwrap();
        clear_last_error();

        set_last_error("first error".to_string());
        set_last_error("second error".to_string());
        assert_eq!(get_last_error().as_deref(), Some("second error"));
    }

    /// The property the transition lock buys: a stop queues behind a
    /// transition already in flight instead of interleaving with it.
    /// (The start paths take the same lock first thing, so this covers
    /// start-during-stop and stop-during-start alike.)
    #[test]
    fn a_stop_waits_for_the_transition_in_flight() {
        let held = transition_guard();

        let stopper = std::thread::spawn(stop_service);
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(
            !stopper.is_finished(),
            "stop_service must wait for the transition lock"
        );

        drop(held);
        // With no service installed, a stop that gets the lock reports
        // "was not running": device released.
        assert!(stopper.join().unwrap());
    }
}
