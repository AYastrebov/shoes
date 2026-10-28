//! Common FFI utilities shared between iOS and Android.
//!
//! This module contains platform-independent code that both iOS and Android use.
//!
//! The service lifecycle itself lives in [`crate::control`]. What stays here is
//! the part that is genuinely about the C and JNI boundary: global singletons,
//! because a caller on the far side addresses its service by an integer rather
//! than by holding a value, and the log-file plumbing those callers configure.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "predates the lint; see the [lints] note in Cargo.toml"
)]

use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use log::info;

use crate::control::ExitReason;

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

/// Global log file handle for file-based logging. Rotates at
/// [`crate::logging::LOG_FILE_MAX_BYTES`].
pub static LOG_FILE: OnceLock<parking_lot::Mutex<Option<crate::logging::RotatingFile>>> =
    OnceLock::new();

/// Global flag to track if logger has been initialized.
pub static LOGGER_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// What a host hands shoes to be told a session ended without being asked.
/// Called at most once, with the reason; never for a stop the host requested.
/// The host's one-shot callback for an end it did not ask for: the id of
/// the session that ended, and why.
pub type StoppedCallback = Box<dyn FnOnce(u64, &ExitReason) + Send>;

/// The running session: its handle, and the one-shot callback for its end.
///
/// One value in one slot, installed by [`start_session`] and taken whole by
/// [`stop_service_locked`], so nothing about a session can be cleared while
/// the rest of it stays -- the class of bug three earlier fixes were about,
/// when these were parallel statics and a slot could be emptied outside the
/// lock that guarded the others.
///
/// The two callbacks that are read on the engine's own paths -- the socket
/// protector, consulted whenever a socket is opened, and the traffic
/// callback, ticked once a second -- stay in the slots their readers look in
/// (`socket_protector`, `tun::traffic`), but are installed by
/// [`install_callbacks`] and cleared by the stop, both here, so neither
/// platform can forget one.
struct Session {
    /// Process-wide, from [`next_session_id`]: what `start` returns, what
    /// `stop` must be given, and what an exit names.
    id: u64,
    handle: TunServiceHandle,
    on_stop: Option<StoppedCallback>,
}

static SESSION: parking_lot::Mutex<Option<Session>> = parking_lot::Mutex::new(None);

/// Session ids start at 1, so the first session of a process is handed the
/// value every session was handed before ids existed, and 0 never names
/// one. A `u64` will not wrap in the life of a process.
static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);

fn next_session_id() -> u64 {
    NEXT_SESSION_ID.fetch_add(1, Ordering::SeqCst)
}

/// The id of the session a stop has taken out of the slot and is waiting
/// on, 0 when none. An exit for that id during the wait is the exit guard's
/// losing race -- a real failure that landed as the host reached for the
/// switch, or the stop's own unrequested-end echo -- and is recorded for
/// `get_last_error` so that [`written_by_the_stop`] can judge it, without
/// reaching a callback the stop has already taken.
static STOPPING: AtomicU64 = AtomicU64::new(0);

/// Last error message from the service. Set when `start_from_config` fails
/// or the service stops with an error. Read via `shoes_get_last_error()`.
static LAST_ERROR: OnceLock<parking_lot::Mutex<Option<LastError>>> = OnceLock::new();

/// The message, and whether it reports an [`ExitReason::EndedUnrequested`]
/// -- the one exit a stop can manufacture by racing the exit guard.
#[derive(Clone, PartialEq, Eq)]
struct LastError {
    message: String,
    ended_unrequested: bool,
}

/// Serializes start/stop transitions across the FFI surface.
///
/// `stop_service_locked` takes the session out of `SESSION` and then waits up
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

/// Proof of holding [`TRANSITION`], which every function that installs or
/// removes session state asks for.
pub type Transition = parking_lot::MutexGuard<'static, ()>;

/// Take the transition lock. Held across all of a stop and all of
/// each platform's start path.
pub fn transition_guard() -> Transition {
    TRANSITION.lock()
}

/// Install the callbacks the engine reads while it runs, from zeroed
/// counters. [`stop_service_locked`] removes them; a start that fails after
/// this calls [`clear_callbacks`].
pub fn install_callbacks(
    _transition: &Transition,
    protector: std::sync::Arc<dyn crate::socket_protector::SocketProtector>,
    traffic: std::sync::Arc<dyn Fn(u64, u64) + Send + Sync>,
) {
    crate::socket_protector::set_global_socket_protector(protector);
    crate::tun::traffic::reset_traffic_counters();
    crate::tun::traffic::set_traffic_callback(traffic);
}

/// Remove what [`install_callbacks`] installed.
pub fn clear_callbacks(_transition: &Transition) {
    crate::tun::traffic::clear_traffic_callback();
    crate::socket_protector::clear_global_socket_protector();
}

/// Start the prepared service as the session, with `on_stop` for an end the
/// host did not ask for. Returns the session's id: what the host passes
/// back to stop it, and what its exit is delivered under.
///
/// The session is in its slot before the task is spawned, so an exit in the
/// first instant finds its callback, and a callback that calls stop finds the
/// handle. The previous session's handle, if any, is taken out under the lock
/// and released after it, in the background: dropping its runtime in place
/// would wait for its workers, one of which may be inside that session's
/// callback and about to take this very lock.
pub fn start_session(
    _transition: &Transition,
    runtime: tokio::runtime::Runtime,
    prepared: crate::control::PreparedService,
    on_stop: Option<StoppedCallback>,
) -> u64 {
    let id = next_session_id();
    let mut previous = None;
    crate::control::start_and_install(
        runtime,
        prepared,
        move |reason| fire_stopped(id, reason),
        |handle| {
            previous = SESSION.lock().replace(Session {
                id,
                handle,
                on_stop,
            });
        },
    );
    if let Some(previous) = previous {
        previous.handle.discard();
    }
    id
}

/// Deliver an exit for session `id`. If that session is the one in the
/// slot, the reason is stored for `get_last_error` and the session's
/// callback, if it still has one, is taken and called with the slot's lock
/// released -- a callback that calls stop must not deadlock on it. Taken,
/// not read, so it fires at most once; a stop takes the whole session out
/// first, so a requested stop never reaches it.
///
/// If the id is the one a stop is waiting on, the reason is recorded and
/// nothing is called: the stop took the callback with the session, and
/// what it finds in the last error afterwards it judges with
/// [`written_by_the_stop`], keeping a failure and discarding its own echo.
///
/// If the slot holds another session, or none, and no stop is waiting on
/// this id, the exit is dropped: the exit guard marks a service stopped
/// before it delivers its exit, so a start on another thread can pass the
/// running guard and replace the slot in that window. Recording this exit
/// then would overwrite the error the new start just cleared, and taking
/// the slot's callback would hand the successor a death that is not its own.
fn fire_stopped(id: u64, reason: ExitReason) {
    let on_stop = {
        let mut slot = SESSION.lock();
        match slot.as_mut() {
            Some(session) if session.id == id => session.on_stop.take(),
            other => {
                if STOPPING.load(Ordering::SeqCst) == id {
                    set_last_exit(&reason);
                    return;
                }
                let running = other.as_ref().map(|s| s.id);
                log::warn!(
                    "an exit for session {id} arrived after it was replaced \
                     (running: {running:?}); dropped: {reason}"
                );
                return;
            }
        }
    };
    set_last_exit(&reason);
    if let Some(on_stop) = on_stop {
        on_stop(id, &reason);
    }
}

/// Set up log file for file-based logging.
///
/// Returns 0 on success, -1 on error.
pub fn setup_log_file(path_str: &str) -> i32 {
    let file_mutex = LOG_FILE.get_or_init(|| parking_lot::Mutex::new(None));

    match crate::logging::RotatingFile::open(
        std::path::Path::new(path_str),
        crate::logging::LOG_FILE_MAX_BYTES,
    ) {
        Ok(file) => {
            *file_mutex.lock() = Some(file);
            info!("Log file set to: {}", path_str);
            0
        }
        Err(_) => -1,
    }
}

/// The most verbose level this build can log at, spelled the way
/// `shoes_set_log_level` takes it.
///
/// Every artifact is built with `release_max_level_info`, so `debug!` and
/// `trace!` are compiled out and asking for them changes nothing. A host asks
/// this before offering a "debug logging" switch that would do nothing.
pub fn max_log_level_name() -> &'static std::ffi::CStr {
    match log::STATIC_MAX_LEVEL {
        log::LevelFilter::Off => c"off",
        log::LevelFilter::Error => c"error",
        log::LevelFilter::Warn => c"warn",
        log::LevelFilter::Info => c"info",
        log::LevelFilter::Debug => c"debug",
        log::LevelFilter::Trace => c"trace",
    }
}

/// End the session `handle` names and wait for shutdown, then remove its
/// callbacks -- all inside the caller's transition lock. Clearing them after
/// the lock was released once wiped the callbacks a queued start had just
/// installed, leaving its fresh engine with no socket protector.
///
/// A `handle` that is not the running session's id -- 0, a session already
/// gone, a value `start` never returned -- stops nothing and reports
/// released: nothing of the caller's is running, and the descriptor of the
/// session it named, if there ever was one, was let go when that session
/// ended. This is what lets a host release a session by identity, so a
/// late death handler cannot stop the session that replaced its own.
///
/// Returns `true` if the service confirmed it stopped, `false` if the wait
/// timed out. See [`crate::control::stop_handle`] for what that distinction
/// costs the caller.
pub fn stop_service_locked(transition: &Transition, handle: u64) -> bool {
    info!("Stopping TUN service");

    // The whole session at once, its stopped callback with it: the service
    // task exits during the wait below, and that exit is one the host asked
    // for, so it must find nothing to call.
    let taken = {
        let mut slot = SESSION.lock();
        match slot.as_ref() {
            Some(session) if session.id == handle => {
                // Under the slot's lock, so an exit for this id finds
                // either the session or the stopping mark, never neither.
                STOPPING.store(handle, Ordering::SeqCst);
                slot.take()
            }
            Some(session) => {
                log::warn!(
                    "stop({handle}): the running session is {}; nothing stopped",
                    session.id
                );
                return true;
            }
            None => None,
        }
    };
    let Some(Session { handle, .. }) = taken else {
        info!("TUN service was not running");
        clear_callbacks(transition);
        return true;
    };

    // A stop the host asked for must not manufacture an error: the exit
    // guard reads stop_requested in a race with our store of it, and the
    // losing interleaving reports EndedUnrequested -- for this very stop --
    // during the wait below. That exit appearing mid-stop is the race's
    // fingerprint and is discarded; the variant says so, not its sentence.
    // A failure written mid-stop is a genuine one that raced the stop -- an
    // engine that died of a real error as the host reached for the switch --
    // and it must survive: restoring unconditionally erased the only report
    // of a crash and dressed it as a clean user stop.
    let before = last_error();

    // The C and JNI surfaces answer with an int, so the obligation the type
    // carries is flattened here rather than at the call sites.
    let stopped = crate::control::stop_handle(handle).device_released();

    // The wait is over: an exit for this id from here on is late twice
    // over and is dropped like any other for a session no longer in the slot.
    STOPPING.store(0, Ordering::SeqCst);

    // One snapshot, compared and matched: two separate reads could see
    // two different values if a late writer lands between them.
    let after = last_error();
    if written_by_the_stop(&before, &after) {
        store_last_error(before);
    }

    // After the wait, not before: a socket the engine opens while it winds
    // down is still protected. The protector holds a reference to the
    // platform's VPN service object, released here rather than in the
    // platform modules so that neither one can forget.
    clear_callbacks(transition);

    info!("TUN service stop completed");
    stopped
}

/// A C string from an arbitrary message. An interior NUL is replaced
/// rather than allowed to fail the conversion: the messages are io::Error
/// text derived from config values and peer data, and a failure whose
/// message could not cross the boundary used to be delivered as a clean
/// stop -- NULL to the callback AND NULL from shoes_get_last_error, the
/// one state the contract reserves for "no reason". Shared here so every
/// C-string-producing sink uses the same rule; a file-private copy is how
/// the next symbol reintroduces the bug.
pub fn c_string_lossy(s: &str) -> std::ffi::CString {
    std::ffi::CString::new(s.replace('\0', "\u{fffd}")).expect("NULs were just replaced")
}

/// Refuse a start called from a thread inside a tokio runtime context.
///
/// The start paths run `block_on`, which panics there -- process death
/// under panic = "abort". The common way in is the stopped callback (it
/// runs on a worker of the dying session's runtime), but the check is by
/// context, not by caller, and it is broader than the panic it prevents:
/// a blocking-pool thread of an embedding host's runtime would be legal
/// ground for block_on, yet is refused too, because tokio exposes no way
/// to tell the two apart. The message names the context and the way out.
///
/// Returns true when the start must be refused; the reason is already in
/// last_error.
pub fn refuse_start_from_runtime_thread(who: &str) -> bool {
    if tokio::runtime::Handle::try_current().is_err() {
        return false;
    }
    log::error!("{who}: called on a thread with a tokio runtime context");
    set_last_error(
        "start called on a thread with a tokio runtime context (a shoes callback, or an \
         embedding runtime); call it from a plain thread instead"
            .to_string(),
    );
    true
}

fn store_last_error(error: Option<LastError>) {
    let err = LAST_ERROR.get_or_init(|| parking_lot::Mutex::new(None));
    *err.lock() = error;
}

fn last_error() -> Option<LastError> {
    LAST_ERROR.get().and_then(|m| m.lock().clone())
}

/// Whether what changed in the last error during a stop is the stop's own
/// echo -- an unrequested-end report -- rather than a failure that raced it.
fn written_by_the_stop(before: &Option<LastError>, after: &Option<LastError>) -> bool {
    after != before && after.as_ref().is_some_and(|e| e.ended_unrequested)
}

/// Store an error message.
pub fn set_last_error(error: String) {
    store_last_error(Some(LastError {
        message: error,
        ended_unrequested: false,
    }));
}

/// Store the reason a service ended without being asked.
pub fn set_last_exit(reason: &ExitReason) {
    store_last_error(Some(LastError {
        message: reason.message().to_string(),
        ended_unrequested: *reason == ExitReason::EndedUnrequested,
    }));
}

/// Clear the last error message (called on successful start).
pub fn clear_last_error() {
    if let Some(err) = LAST_ERROR.get() {
        *err.lock() = None;
    }
}

/// Get the last error message, if any.
pub fn get_last_error() -> Option<String> {
    last_error().map(|e| e.message)
}

/// Check if the TUN service is running.
pub fn is_service_running() -> bool {
    SESSION
        .lock()
        .as_ref()
        .is_some_and(|s| s.handle.is_running())
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

    fn exit(reason: ExitReason) -> Option<LastError> {
        Some(LastError {
            message: reason.message().to_string(),
            ended_unrequested: reason == ExitReason::EndedUnrequested,
        })
    }

    /// An unrequested end that lands during a stop is the stop's own echo and
    /// is discarded; a failure that lands then is real and is kept -- even one
    /// whose words match the unrequested sentence, which the string
    /// comparison this replaced would have thrown away.
    #[test]
    fn only_the_stops_own_echo_is_discarded() {
        let earlier = exit(ExitReason::Failed("an earlier failure".to_string()));
        assert!(written_by_the_stop(
            &earlier,
            &exit(ExitReason::EndedUnrequested)
        ));
        assert!(written_by_the_stop(
            &None,
            &exit(ExitReason::EndedUnrequested)
        ));

        let crash = exit(ExitReason::Failed("the stack died".to_string()));
        assert!(!written_by_the_stop(&None, &crash));

        let lookalike = exit(ExitReason::Failed(
            crate::control::ENDED_UNREQUESTED.to_string(),
        ));
        assert!(!written_by_the_stop(&None, &lookalike));

        // Nothing changed: nothing to restore.
        let unchanged = exit(ExitReason::EndedUnrequested);
        assert!(!written_by_the_stop(&unchanged, &unchanged));
    }

    /// The ceiling is reported in the spelling `shoes_set_log_level` takes,
    /// and names the level this build actually compiles in.
    #[test]
    fn the_log_ceiling_names_the_compiled_maximum() {
        let name = max_log_level_name().to_str().unwrap();
        assert_eq!(
            crate::logging::parse_log_level(name),
            Some(log::STATIC_MAX_LEVEL),
            "{name}"
        );
        assert_eq!(
            name,
            name.to_lowercase(),
            "spelled as set_log_level takes it"
        );
    }

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

    /// A session whose service runs until it is told to stop, installed the
    /// way `start_session` installs one: an id from the shared counter, and
    /// `fire_stopped` for that id as its exit. Returns the id.
    fn install_test_session(_transition: &Transition, on_stop: Option<StoppedCallback>) -> u64 {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let id = next_session_id();
        let handle = crate::control::start_with(
            runtime,
            |shutdown| async move {
                let _ = shutdown.await;
                Ok(())
            },
            move |reason| fire_stopped(id, reason),
        );
        *SESSION.lock() = Some(Session {
            id,
            handle,
            on_stop,
        });
        id
    }

    type Calls = std::sync::Arc<std::sync::Mutex<Vec<(u64, String)>>>;

    /// A callback that records every (id, reason) it is handed.
    fn counting() -> (StoppedCallback, Calls) {
        let calls: Calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let counted = calls.clone();
        let callback: StoppedCallback = Box::new(move |id, reason| {
            counted
                .lock()
                .unwrap()
                .push((id, reason.message().to_string()));
        });
        (callback, calls)
    }

    /// A stop takes the whole session, its callback with it, before it waits:
    /// the exit the stop causes is one the host asked for, and must not be
    /// reported to it as an end it did not.
    #[test]
    fn a_requested_stop_never_reaches_the_stopped_callback() {
        // Its exit guard clears the device name.
        let _names = crate::tun::device_name_test_lock();
        let _errors = LAST_ERROR_TEST_LOCK.lock().unwrap();
        let transition = transition_guard();
        let (callback, calls) = counting();
        let id = install_test_session(&transition, Some(callback));
        assert!(is_service_running());

        assert!(stop_service_locked(&transition, id));
        assert!(!is_service_running());
        assert!(calls.lock().unwrap().is_empty());
    }

    /// An end the host did not ask for records its reason for
    /// `get_last_error` and reaches the callback -- once, however many times
    /// it is delivered -- with the id the session was started with.
    #[test]
    fn an_unrequested_end_records_then_calls_once() {
        let _names = crate::tun::device_name_test_lock();
        let _errors = LAST_ERROR_TEST_LOCK.lock().unwrap();
        let transition = transition_guard();
        let (callback, calls) = counting();
        let id = install_test_session(&transition, Some(callback));

        for _ in 0..2 {
            fire_stopped(id, ExitReason::Failed("engine fell over".to_string()));
        }
        assert_eq!(
            calls.lock().unwrap().as_slice(),
            &[(id, "engine fell over".to_string())]
        );
        assert_eq!(get_last_error().as_deref(), Some("engine fell over"));

        assert!(stop_service_locked(&transition, id));
    }

    /// Each session of a process gets a larger id than the one before it.
    #[test]
    fn session_ids_increase() {
        let _names = crate::tun::device_name_test_lock();
        let _errors = LAST_ERROR_TEST_LOCK.lock().unwrap();
        let transition = transition_guard();
        let first = install_test_session(&transition, None);
        assert!(stop_service_locked(&transition, first));
        let second = install_test_session(&transition, None);
        assert!(second > first);
        assert!(stop_service_locked(&transition, second));
    }

    /// A stop names the session it is for. Any other value -- 0, a
    /// neighbour, a session long gone -- stops nothing, reports released
    /// (nothing of the caller's is running), and touches neither the
    /// callback nor the last error.
    #[test]
    fn a_stop_with_a_stale_id_leaves_the_session_running() {
        let _names = crate::tun::device_name_test_lock();
        let _errors = LAST_ERROR_TEST_LOCK.lock().unwrap();
        let transition = transition_guard();
        clear_last_error();
        let (callback, calls) = counting();
        let id = install_test_session(&transition, Some(callback));

        for stale in [0, id + 1, id.wrapping_sub(1)] {
            assert!(stop_service_locked(&transition, stale), "stale {stale}");
            assert!(is_service_running(), "stale {stale} stopped the session");
        }
        assert!(calls.lock().unwrap().is_empty());
        assert!(get_last_error().is_none());

        assert!(stop_service_locked(&transition, id));
        assert!(!is_service_running());
    }

    /// An exit and a start can cross: the exit guard marks the service
    /// stopped before the exit is delivered, so a start on another thread
    /// can replace the slot in between. The old session's exit must then
    /// reach neither the successor's callback nor the last error the
    /// successor's start just cleared.
    #[test]
    fn an_exit_for_a_replaced_session_is_dropped() {
        let _names = crate::tun::device_name_test_lock();
        let _errors = LAST_ERROR_TEST_LOCK.lock().unwrap();
        let transition = transition_guard();
        let (old_callback, old_calls) = counting();
        let old = install_test_session(&transition, Some(old_callback));
        let (new_callback, new_calls) = counting();
        // Replaces the slot as start_session does; the old handle is
        // dropped here, its runtime shut down in the background.
        let previous = SESSION.lock().take();
        let new = install_test_session(&transition, Some(new_callback));
        if let Some(previous) = previous {
            previous.handle.discard();
        }
        clear_last_error();

        fire_stopped(old, ExitReason::Failed("late".to_string()));
        assert!(old_calls.lock().unwrap().is_empty());
        assert!(new_calls.lock().unwrap().is_empty());
        assert!(get_last_error().is_none());

        assert!(stop_service_locked(&transition, new));
    }

    /// A session that, told to stop, reports a failure before it returns:
    /// the exit guard's losing race, where a real crash lands during the
    /// stop's wait. Installed the way `install_test_session` installs one.
    fn install_test_session_that_fails_on_stop(
        _transition: &Transition,
        on_stop: Option<StoppedCallback>,
        failure: ExitReason,
    ) -> u64 {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let id = next_session_id();
        let handle = crate::control::start_with(
            runtime,
            move |shutdown| async move {
                let _ = shutdown.await;
                fire_stopped(id, failure);
                Ok(())
            },
            move |reason| fire_stopped(id, reason),
        );
        *SESSION.lock() = Some(Session {
            id,
            handle,
            on_stop,
        });
        id
    }

    /// A failure that lands while the stop waits is a real crash that raced
    /// the host's hand on the switch: it must survive into `get_last_error`,
    /// and it must not reach the callback the stop already took.
    #[test]
    fn a_failure_racing_a_stop_is_recorded_but_not_delivered() {
        let _names = crate::tun::device_name_test_lock();
        let _errors = LAST_ERROR_TEST_LOCK.lock().unwrap();
        let transition = transition_guard();
        clear_last_error();
        let (callback, calls) = counting();
        let id = install_test_session_that_fails_on_stop(
            &transition,
            Some(callback),
            ExitReason::Failed("raced".to_string()),
        );

        assert!(stop_service_locked(&transition, id));
        assert_eq!(get_last_error().as_deref(), Some("raced"));
        assert!(calls.lock().unwrap().is_empty());
    }

    /// The stop's own echo -- an unrequested-end report for the exit the
    /// stop caused -- is still discarded, and an earlier failure survives it.
    #[test]
    fn the_stops_own_echo_is_still_discarded() {
        let _names = crate::tun::device_name_test_lock();
        let _errors = LAST_ERROR_TEST_LOCK.lock().unwrap();
        let transition = transition_guard();
        set_last_error("an earlier failure".to_string());
        let id = install_test_session_that_fails_on_stop(
            &transition,
            None,
            ExitReason::EndedUnrequested,
        );

        assert!(stop_service_locked(&transition, id));
        assert_eq!(get_last_error().as_deref(), Some("an earlier failure"));
    }

    /// The property the transition lock buys: a stop queues behind a
    /// transition already in flight instead of interleaving with it.
    /// (The start paths take the same lock first thing, so this covers
    /// start-during-stop and stop-during-start alike.)
    #[test]
    fn a_stop_waits_for_the_transition_in_flight() {
        let held = transition_guard();

        let stopper = std::thread::spawn(|| {
            let transition = transition_guard();
            stop_service_locked(&transition, 0)
        });
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(
            !stopper.is_finished(),
            "a stop must wait for the transition lock"
        );

        drop(held);
        // With no service installed, a stop that gets the lock reports
        // "was not running": device released.
        assert!(stopper.join().unwrap());
    }
}
