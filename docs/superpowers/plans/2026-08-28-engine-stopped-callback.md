# Engine-Stopped Callback Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The engine tells the provider the instant it stops on its own, through a C callback; the provider reports it at once, the 30 s health check goes away, `ShoesError` gains the host-side cases, and the app can ask the provider for its last error.

**Architecture:** `control::start` gets an `on_exit` hook run from a drop guard (running → false first). `src/ffi/ios.rs` stores a `ShoesStoppedCallback` in a slot shaped like the traffic one, cleared before `stop_service`. Swift `CallbackBridge` holds both C-callback slots; `ShoesEngine.start` gains `onStopped`; the provider maps it to `report(error:)` + `cancelTunnelWithError`. Core gains `ShoesError` cases, `Codable`, and the `.lastError` message/reply.

**Tech Stack:** Rust (tokio, parking_lot), cbindgen → `include/shoes.h`, Swift 6 / Swift Testing, `scripts/build-apple.sh` for the XCFramework.

**Spec:** `docs/superpowers/specs/2026-08-28-engine-stopped-callback-design.md`

## Global Constraints

- `cargo` is not on PATH (rustup shim dangling). Use `CARGO=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin/cargo`. `cbindgen` is at `$HOME/.cargo/bin/cbindgen`.
- `panic = "abort"` in release (`Cargo.toml:187`): no code or test may assume a drop guard runs on panic.
- `stop_handle` polls `handle.running` for up to `STOP_TIMEOUT` (5 s): `running` must be false **before** `on_exit` is called.
- `shoes_stop` clears the stopped slot **before** `common::stop_service()`; the traffic clear stays after, as today.
- `shoes_start` (no fd) is unchanged in signature; it installs an empty stopped slot.
- `include/shoes.h` is generated: edit the Rust doc comments, then run `cbindgen --config cbindgen.toml --output include/shoes.h`. Never hand-edit the header.
- Swift: after any Rust change, `bash scripts/build-apple.sh` rebuilds `output/apple/Shoes.xcframework`; every `swift build`/`swift test` needs `SHOES_LOCAL_XCFRAMEWORK=1`.
- Lint: `swift format lint --strict --recursive swift Package.swift`; Rust `$CARGO fmt` and `$CARGO clippy --all-targets` (clippy has pre-existing macOS failures — check only files you touched).
- Commits: imperative subject, body says why, author `Andrey Yastrebov <ayastrebov@gmail.com>`.
- Public Swift API: `ShoesEngine.start` gains a required `onStopped:`; `healthCheckInterval` is removed; `ShoesError` gains cases. All are documented in CHANGELOG as source-breaking where they are.

## File Structure

```
src/control/mod.rs                     on_exit hook, stop_requested, start_with, tests
src/ffi/ios.rs                         ShoesStoppedCallback, STOPPED_CALLBACK, fire_stopped, start_service param, shoes_stop order, tests
src/ffi/android.rs                     control::start call adapts to on_exit
include/shoes.h                        regenerated
swift/Sources/ShoesTunnelCore/ShoesError.swift        3 cases + Codable
swift/Sources/ShoesTunnelCore/ShoesAppMessage.swift   .lastError message + reply
swift/Sources/ShoesTunnelHost/ShoesTunnelManager.swift  throws .noSession / .providerNoReply
swift/Sources/ShoesTunnel/CallbackBridge.swift        renamed from TrafficCallbackBridge.swift, two slots
swift/Sources/ShoesTunnel/ShoesEngine.swift           onStopped parameter
swift/Sources/ShoesTunnel/ShoesPacketTunnelProvider.swift  engineStopped, lastError, health check removed
swift/Tests/ShoesTunnelCoreTests/ShoesErrorTests.swift     new
swift/Tests/ShoesTunnelCoreTests/ShoesAppMessageTests.swift lastError round-trips
swift/Tests/ShoesTunnelTests/ShoesEngineTests.swift        onStopped in calls; failed start never fires
swift/README.md, CHANGELOG.md
```

---

### Task 1: `control::start` reports every exit the host did not ask for

**Files:**
- Modify: `src/control/mod.rs:63-77` (struct), `:104-108` (stop_handle), `:222-267` (start), tests at `:457+`
- Modify: `src/ffi/ios.rs:295`, `src/ffi/android.rs:292` (call sites, to keep the build green)

**Interfaces:**
- Produces: `pub fn start(runtime, prepared, on_exit: impl FnOnce(Option<String>) + Send + 'static) -> ServiceHandle`; `pub fn start_with<F, Fut>(runtime, make_service: F, on_exit) -> ServiceHandle where F: FnOnce(oneshot::Receiver<()>) -> Fut, Fut: Future<Output = io::Result<()>> + Send + 'static`. `on_exit(Some(msg))` on `Err`, `on_exit(None)` on an `Ok` that was not requested, nothing after `stop_handle`; `running` is false when it runs.

- [ ] **Step 1: Write the failing tests**

Append to `mod tests` in `src/control/mod.rs`:

```rust
    use std::sync::mpsc;

    fn test_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .unwrap()
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
        assert!(rx.recv_timeout(std::time::Duration::from_millis(200)).is_err());
    }

    /// An Ok that nobody requested is still an exit the host must hear
    /// about; `None` is what it hears.
    #[test]
    fn on_exit_reports_an_unrequested_ok_as_none() {
        let (tx, rx) = mpsc::channel();
        let handle = start_with(
            test_runtime(),
            |_shutdown| async { Ok(()) },
            move |reason| tx.send(reason).unwrap(),
        );
        let reason = rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
        assert_eq!(reason, None);
        let _ = stop_handle(handle);
    }
```

- [ ] **Step 2: Run them to see them fail**

```bash
CARGO=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin/cargo
$CARGO test --lib control::tests::on_exit 2>&1 | tail -5
```
Expected: compile error, `start_with` not found.

- [ ] **Step 3: Implement**

In `ServiceHandle` (`src/control/mod.rs:63`), add after `running`:

```rust
    /// Set by `stop_handle` before the shutdown signal, so the exit guard
    /// can tell a stop the host asked for from one it must be told about.
    stop_requested: Arc<AtomicBool>,
```

In `stop_handle` (`:104`), before `if let Some(tx) = handle.shutdown_tx.take()`:

```rust
    handle.stop_requested.store(true, Ordering::SeqCst);
```

Replace `pub fn start(...)` (`:222-267`) with:

```rust
/// Start a prepared service on `runtime`.
///
/// `on_exit` runs once, from the service task, when the service ends for
/// any reason the host did not ask for: `Some(message)` when it failed,
/// `None` when it returned without an error. It is not called after
/// [`stop_handle`]. By the time it runs `running` is already false, so a
/// callback that stops the engine does not wait out [`STOP_TIMEOUT`].
///
/// A panic does not reach it: the crate builds with `panic = "abort"`.
pub fn start(
    runtime: tokio::runtime::Runtime,
    prepared: PreparedService,
    on_exit: impl FnOnce(Option<String>) + Send + 'static,
) -> ServiceHandle {
    // From zero, so a second session does not report the first one's bytes
    // against a fresh uptime. Both FFI platforms already do this in their own
    // start path; a Rust host had no equivalent.
    #[cfg(any(unix, windows))]
    crate::tun::traffic::reset_traffic_counters();

    start_with(runtime, |shutdown_rx| run_prepared(prepared, shutdown_rx), on_exit)
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
        outcome: None,
    };

    runtime.spawn(async move {
        let mut guard = guard;
        info!("shoes service task started");
        match service.await {
            Ok(()) => info!("shoes service stopped normally"),
            Err(e) => {
                let msg = e.to_string();
                error!("shoes service error: {}", msg);
                guard.outcome = Some(msg);
            }
        }
        // Dropped here, at the end of the task.
    });

    ServiceHandle {
        runtime,
        shutdown_tx: Some(shutdown_tx),
        running,
        stop_requested,
        started_at: std::time::Instant::now(),
        failure,
    }
}

/// Runs at the end of the service task. Order matters: `running` goes
/// false first, then the failure is recorded for `status`, then the host is
/// told -- so `shoes_is_running()` is already false inside the callback and
/// a host that calls `shoes_stop` from it returns at once.
struct ExitGuard {
    running: Arc<AtomicBool>,
    stop_requested: Arc<AtomicBool>,
    failure: Arc<parking_lot::Mutex<Option<String>>>,
    on_exit: Option<Box<dyn FnOnce(Option<String>) + Send>>,
    outcome: Option<String>,
}

impl Drop for ExitGuard {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(msg) = &self.outcome {
            // Recorded for status() as well as handed to the caller: a Rust
            // host wants StopReason::Failed, the FFI wants a string for
            // LAST_ERROR, and neither should have to read the other's channel.
            *self.failure.lock() = Some(msg.clone());
        }
        if self.stop_requested.load(Ordering::SeqCst) {
            return;
        }
        if let Some(on_exit) = self.on_exit.take() {
            on_exit(self.outcome.take());
        }
    }
}
```

Update the two FFI call sites so the crate builds (their real change is Task 2):

`src/ffi/ios.rs:295` and `src/ffi/android.rs:292`:
```rust
    let handle = crate::control::start(runtime, prepared, |reason| {
        if let Some(msg) = reason {
            common::set_last_error(msg);
        }
    });
```

Note on the spec's "Ok only on shutdown" property: `run_tun_server` already
turns a stack-thread death into `Err` (`src/tun/mod.rs:317-321`, "An error,
not a clean stop"), which is what keeps `None` reserved. Exercising that
path needs a live TUN device, so it is not unit-tested here; the
`start_with` tests above pin the control layer's half of the contract.

- [ ] **Step 4: Run the tests**

```bash
$CARGO test --lib control:: 2>&1 | grep -E "test result|FAILED|panicked" | head
$CARGO fmt && $CARGO clippy --lib 2>&1 | grep -A3 "src/control/mod.rs" | head -20
```
Expected: all `control::tests` pass; no clippy lines for `src/control/mod.rs`.

- [ ] **Step 5: Commit**

```bash
git add src/control/mod.rs src/ffi/ios.rs src/ffi/android.rs
git commit -m "control: report every service exit the host did not request

on_error fired only for Err and left an Ok exit, and a host that had
not asked for it, unreported. on_exit runs from a guard at the end of
the service task for both, after running has gone false so a callback
that stops the engine returns at once, and not at all after
stop_handle. start_with makes the contract testable without a device."
```

---

### Task 2: `ShoesStoppedCallback` on the C surface

**Files:**
- Modify: `src/ffi/ios.rs` (types at `:36-48`, `shoes_start` `:148-163`, `shoes_start_with_fd` `:165-210`, `start_service` `:212-303`, `shoes_stop` `:335-343`, tests `:545+`)
- Regenerate: `include/shoes.h`

**Interfaces:**
- Produces: `pub type ShoesStoppedCallback = Option<extern "C" fn(reason: *const c_char)>` (nullable); `shoes_start_with_fd(config, fd, protect, traffic, stopped)`; `shoes_start` unchanged.

- [ ] **Step 1: Write the failing tests**

Append to `mod tests` in `src/ffi/ios.rs`:

```rust
    use std::sync::atomic::{AtomicUsize, Ordering};

    static STOPPED_CALLS: AtomicUsize = AtomicUsize::new(0);
    extern "C" fn count_stopped(_reason: *const c_char) {
        STOPPED_CALLS.fetch_add(1, Ordering::SeqCst);
    }

    /// A start that never spawns the service leaves the slot empty and the
    /// callback uncalled: there is no exit to report.
    #[test]
    fn a_failed_start_never_calls_the_stopped_callback() {
        let _registry = crate::outbound_stats::REGISTRY_TEST_LOCK.lock().unwrap();
        let _errors = common::LAST_ERROR_TEST_LOCK.lock().unwrap();
        STOPPED_CALLS.store(0, Ordering::SeqCst);
        let yaml = CString::new("---\n[]\n").unwrap();
        let handle = unsafe { shoes_start_with_fd(yaml.as_ptr(), 7, protect, traffic, Some(count_stopped)) };
        assert_eq!(handle, -1);
        assert!(stopped_slot_is_empty());
        assert_eq!(STOPPED_CALLS.load(Ordering::SeqCst), 0);
    }

    /// shoes_stop empties the slot before it stops anything, so nothing
    /// that happens during the stop can reach the host.
    #[test]
    fn stop_clears_the_stopped_slot_first() {
        let _errors = common::LAST_ERROR_TEST_LOCK.lock().unwrap();
        install_stopped_callback(Some(count_stopped));
        assert!(!stopped_slot_is_empty());
        shoes_stop(1);
        assert!(stopped_slot_is_empty());
    }

    /// fire_stopped records the reason for shoes_get_last_error before it
    /// calls out, and calls exactly once.
    #[test]
    fn fire_stopped_records_then_calls() {
        let _errors = common::LAST_ERROR_TEST_LOCK.lock().unwrap();
        STOPPED_CALLS.store(0, Ordering::SeqCst);
        install_stopped_callback(Some(count_stopped));
        fire_stopped(Some("engine fell over".to_string()));
        assert_eq!(STOPPED_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(common::get_last_error().as_deref(), Some("engine fell over"));
        assert!(stopped_slot_is_empty(), "the slot is one-shot");
    }
```

- [ ] **Step 2: Run to see them fail**

```bash
$CARGO test --lib ffi::ios::tests 2>&1 | tail -5
```
Expected: compile errors — `shoes_start_with_fd` arity, `install_stopped_callback`, `stopped_slot_is_empty`, `fire_stopped` missing.

- [ ] **Step 3: Implement the type, slot and helpers**

After `ShoesTrafficCallback` (`src/ffi/ios.rs:47`):

```rust
/// Engine-stopped callback type.
///
/// Called once, from a shoes worker thread, when the engine stops without
/// `shoes_stop` having been called: a failure, or a task that ended on its
/// own. `reason` is the failure message, or NULL when there is none; it is
/// valid for the duration of the call only, and `shoes_get_last_error`
/// returns the same text afterwards. Never called for a stop the host
/// requested, never after `shoes_stop` has returned, and never for a start
/// that failed. `shoes_is_running()` is already false when it runs, and
/// calling `shoes_stop` from inside it is allowed. Do not block in it.
///
/// May be NULL, in which case nothing is called.
pub type ShoesStoppedCallback = Option<extern "C" fn(reason: *const c_char)>;

/// The stopped callback for the running session. One slot, like the traffic
/// callback: shoes runs one engine per process. Taken, not read, when it
/// fires, so it can call at most once per session.
static STOPPED_CALLBACK: OnceLock<Mutex<ShoesStoppedCallback>> = OnceLock::new();

fn install_stopped_callback(callback: ShoesStoppedCallback) {
    *STOPPED_CALLBACK.get_or_init(|| Mutex::new(None)).lock() = callback;
}

fn clear_stopped_callback() {
    install_stopped_callback(None);
}

#[cfg(test)]
fn stopped_slot_is_empty() -> bool {
    STOPPED_CALLBACK.get().is_none_or(|slot| slot.lock().is_none())
}

/// Deliver an exit to the host. The reason is stored for
/// `shoes_get_last_error` first, and the lock is released before the call
/// so a callback that calls `shoes_stop` cannot deadlock on this slot.
fn fire_stopped(reason: Option<String>) {
    if let Some(msg) = &reason {
        common::set_last_error(msg.clone());
    }
    let callback = STOPPED_CALLBACK.get_or_init(|| Mutex::new(None)).lock().take();
    let Some(callback) = callback else { return };
    match reason.and_then(|r| CString::new(r).ok()) {
        Some(c) => callback(c.as_ptr()),
        None => callback(std::ptr::null()),
    }
}
```

- [ ] **Step 4: Thread it through the start path**

`shoes_start` (`:148`): body passes `None` as the new last argument to `start_service`. Its doc comment gains: "Installs no stopped callback; use `shoes_start_with_fd` for one."

`shoes_start_with_fd` (`:192`): add the parameter and forward it:

```rust
pub unsafe extern "C" fn shoes_start_with_fd(
    config_yaml: *const c_char,
    device_fd: c_int,
    protect_callback: ProtectSocketCallback,
    traffic_callback: ShoesTrafficCallback,
    stopped_callback: ShoesStoppedCallback,
) -> c_long {
    // SAFETY: forwarded from the caller's guarantee on `config_yaml`.
    unsafe {
        start_service(
            "shoes_start_with_fd",
            config_yaml,
            Some(device_fd),
            protect_callback,
            traffic_callback,
            stopped_callback,
        )
    }
}
```
Its doc `# Arguments` gains `* \`stopped_callback\` - see \`ShoesStoppedCallback\`; may be NULL`.

`start_service` (`:212`): add `stopped_callback: ShoesStoppedCallback` as the last parameter. Immediately after the traffic callback is installed (`:254-256`):

```rust
    // Installed before control::start so an exit in the first instant is
    // not lost, and always (re)installed -- an empty slot for shoes_start --
    // so a callback from an earlier session can never fire for this one.
    install_stopped_callback(stopped_callback);
```
In the failed-prepare branch (`:284-288`), after `clear_traffic_callback()`:
```rust
            clear_stopped_callback();
```
Replace the `control::start` call (`:295`, as left by Task 1) with:
```rust
    let handle = crate::control::start(runtime, prepared, fire_stopped);
```

`shoes_stop` (`:335`):
```rust
pub extern "C" fn shoes_stop(_handle: c_long) {
    // Before stop_service, not after like the traffic callback: the service
    // task exits during the stop, and that exit is one the host asked for.
    // A late traffic tick is harmless; a stop event here is a lie.
    clear_stopped_callback();
    common::stop_service();
    crate::tun::traffic::clear_traffic_callback();
```

- [ ] **Step 5: Regenerate the header, run the tests**

```bash
$HOME/.cargo/bin/cbindgen --config cbindgen.toml --output include/shoes.h
grep -n "ShoesStoppedCallback" include/shoes.h        # typedef + shoes_start_with_fd parameter
$CARGO test --lib ffi::ios 2>&1 | grep -E "test result|FAILED|panicked"
$CARGO test --lib control:: 2>&1 | grep -E "test result"
$CARGO fmt && $CARGO clippy --lib 2>&1 | grep -A3 "src/ffi/ios.rs" | head
```
Expected: header shows `typedef void (*ShoesStoppedCallback)(const char *reason);` and the five-parameter prototype; all tests pass; no clippy lines for `ios.rs`. Update the existing two `shoes_start_with_fd` tests (`:565`, `:575`) to pass `None` as the fifth argument.

- [ ] **Step 6: Commit**

```bash
git add src/ffi/ios.rs include/shoes.h
git commit -m "ffi: shoes_start_with_fd takes a callback for an unrequested stop

The provider learned of an engine death from a 30-second poll of
shoes_is_running. The engine knows the instant it happens; now it says
so. The slot is cleared before stop_service, so a requested stop is
silent, and the reason lands in LAST_ERROR before the call so
shoes_get_last_error stays truthful. shoes_start is unchanged; the
_with_fd signature changes one release after it appeared, with the
Swift package its only consumer."
```

---

### Task 3: Core — `ShoesError` cases, `Codable`, `.lastError`

**Files:**
- Modify: `swift/Sources/ShoesTunnelCore/ShoesError.swift`, `swift/Sources/ShoesTunnelCore/ShoesAppMessage.swift`, `swift/Sources/ShoesTunnelHost/ShoesTunnelManager.swift:95-107`
- Create: `swift/Tests/ShoesTunnelCoreTests/ShoesErrorTests.swift`
- Modify: `swift/Tests/ShoesTunnelCoreTests/ShoesAppMessageTests.swift`

**Interfaces:**
- Produces: `ShoesError.noSession`, `.providerNoReply`, `.engineStopped(String?)`; `ShoesError: Codable`; `ShoesAppMessage.lastError`; `ShoesAppReply.lastError(ShoesError?)`.

- [ ] **Step 1: Write the failing tests**

`swift/Tests/ShoesTunnelCoreTests/ShoesErrorTests.swift`:

```swift
import Foundation
import Testing

@testable import ShoesTunnelCore

@Suite struct ShoesErrorTests {
    @Test func everyCaseRoundTrips() throws {
        let all: [ShoesError] = [
            .notInitialized, .alreadyRunning, .startFailed("no tun"), .tunnelDescriptorUnavailable,
            .timedOut(seconds: 14), .engine("shoes_set_log_level returned -1"),
            .noSession, .providerNoReply, .engineStopped("device gone"), .engineStopped(nil),
        ]
        for error in all {
            let data = try JSONEncoder().encode(error)
            #expect(try JSONDecoder().decode(ShoesError.self, from: data) == error)
        }
    }

    @Test func anUnknownKindThrows() {
        let data = Data("{\"kind\":\"meltdown\"}".utf8)
        #expect(throws: DecodingError.self) { try JSONDecoder().decode(ShoesError.self, from: data) }
    }

    @Test func descriptionsNameTheCondition() {
        #expect(ShoesError.noSession.localizedDescription == "no tunnel session")
        #expect(ShoesError.providerNoReply.localizedDescription == "provider gave no reply")
        #expect(ShoesError.engineStopped("x").localizedDescription == "shoes stopped: x")
        #expect(ShoesError.engineStopped(nil).localizedDescription == "shoes stopped")
    }
}
```

In `ShoesAppMessageTests.swift`, add `.lastError` to the `messagesRoundTrip` array and, to the `repliesRoundTrip` array, `.lastError(.engineStopped("x")), .lastError(nil)`.

- [ ] **Step 2: Run to see them fail**

```bash
export SHOES_LOCAL_XCFRAMEWORK=1
swift test --filter ShoesTunnelCoreTests 2>&1 | grep -E "error:|Test run" | head
```
Expected: compile errors for the missing cases.

- [ ] **Step 3: Implement `ShoesError`**

Replace `swift/Sources/ShoesTunnelCore/ShoesError.swift` with:

```swift
import Foundation

/// What can go wrong between a host and the engine.
///
/// Codable so the provider can answer `.lastError` with the case itself,
/// and an app maps on it rather than on a string.
public enum ShoesError: Error, Sendable, Equatable {
    /// `ShoesEngine.initialize` has not been called in this process.
    case notInitialized
    /// A session is already running; `stop()` it first.
    case alreadyRunning
    /// The engine refused to start; the string is `shoes_get_last_error`,
    /// or the return code when it had nothing to say.
    case startFailed(String)
    /// `packetFlow` did not yield a descriptor.
    case tunnelDescriptorUnavailable
    /// A step did not complete inside the platform's budget.
    case timedOut(seconds: Int)
    /// A call other than start returned failure; the string is the FFI
    /// function's name and code.
    case engine(String)
    /// `ShoesTunnelManager.send` with no tunnel session to send to.
    case noSession
    /// The provider returned no data for a message.
    case providerNoReply
    /// The engine stopped without being asked; the reason when it gave one.
    case engineStopped(String?)
}

extension ShoesError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .notInitialized: "shoes is not initialized"
        case .alreadyRunning: "shoes is already running"
        case .startFailed(let reason): "shoes failed to start: \(reason)"
        case .tunnelDescriptorUnavailable: "packetFlow has no file descriptor"
        case .timedOut(let seconds): "timed out after \(seconds)s"
        case .engine(let what): what
        case .noSession: "no tunnel session"
        case .providerNoReply: "provider gave no reply"
        case .engineStopped(let reason): reason.map { "shoes stopped: \($0)" } ?? "shoes stopped"
        }
    }
}

extension ShoesError: Codable {
    private enum CodingKeys: String, CodingKey { case kind, message, seconds }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .notInitialized: try c.encode("notInitialized", forKey: .kind)
        case .alreadyRunning: try c.encode("alreadyRunning", forKey: .kind)
        case .startFailed(let reason):
            try c.encode("startFailed", forKey: .kind)
            try c.encode(reason, forKey: .message)
        case .tunnelDescriptorUnavailable: try c.encode("tunnelDescriptorUnavailable", forKey: .kind)
        case .timedOut(let seconds):
            try c.encode("timedOut", forKey: .kind)
            try c.encode(seconds, forKey: .seconds)
        case .engine(let what):
            try c.encode("engine", forKey: .kind)
            try c.encode(what, forKey: .message)
        case .noSession: try c.encode("noSession", forKey: .kind)
        case .providerNoReply: try c.encode("providerNoReply", forKey: .kind)
        case .engineStopped(let reason):
            try c.encode("engineStopped", forKey: .kind)
            try c.encodeIfPresent(reason, forKey: .message)
        }
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        switch try c.decode(String.self, forKey: .kind) {
        case "notInitialized": self = .notInitialized
        case "alreadyRunning": self = .alreadyRunning
        case "startFailed": self = .startFailed(try c.decode(String.self, forKey: .message))
        case "tunnelDescriptorUnavailable": self = .tunnelDescriptorUnavailable
        case "timedOut": self = .timedOut(seconds: try c.decode(Int.self, forKey: .seconds))
        case "engine": self = .engine(try c.decode(String.self, forKey: .message))
        case "noSession": self = .noSession
        case "providerNoReply": self = .providerNoReply
        case "engineStopped": self = .engineStopped(try c.decodeIfPresent(String.self, forKey: .message))
        case let other:
            throw DecodingError.dataCorruptedError(forKey: .kind, in: c, debugDescription: "unknown error \(other)")
        }
    }
}
```

- [ ] **Step 4: Implement `.lastError`**

`ShoesAppMessage`: add `case lastError` after `case stats`; in `encode` add `case .lastError: try c.encode("lastError", forKey: .kind)`; in `init(from:)` add `case "lastError": self = .lastError`.

`ShoesAppReply`: add `case lastError(ShoesError?)` after `case stats(ShoesStats?)`; add `error` to `CodingKeys`; in `encode`:
```swift
        case .lastError(let error):
            try c.encode("lastError", forKey: .kind)
            try c.encodeIfPresent(error, forKey: .error)
```
in `init(from:)`: `case "lastError": self = .lastError(try c.decodeIfPresent(ShoesError.self, forKey: .error))`.

Update the doc comment on `ShoesAppReply.lastError`:
```swift
    /// The last error the provider reported, or nil. Answers while the
    /// extension is alive -- a failed rebind, a refused setLogLevel. After an
    /// engine death the provider cancels the tunnel and the process exits;
    /// the app then sees `.disconnected` and nobody is left to answer, so a
    /// host persists fatal reasons from `report(error:)` instead.
```

`ShoesTunnelManager.send`: replace `throw ShoesError.engine("no tunnel session")` with `throw ShoesError.noSession` and `throw ShoesError.engine("provider gave no reply")` with `throw ShoesError.providerNoReply`.

- [ ] **Step 5: Run Core tests and lint**

```bash
swift test --filter ShoesTunnelCoreTests 2>&1 | grep -E "Test run|failed"
swift build --target ShoesTunnelHost 2>&1 | tail -1
swift format lint --strict --recursive swift Package.swift && echo LINT-OK
```
Expected: all Core suites pass (now 4 suites), Host builds, lint clean.

- [ ] **Step 6: Commit**

```bash
git add swift/Sources/ShoesTunnelCore swift/Sources/ShoesTunnelHost swift/Tests/ShoesTunnelCoreTests
git commit -m "swift: host-side ShoesError cases, Codable, and a lastError message

ShoesTunnelManager.send threw .engine for conditions that were the
host's, so an app mapped errors by string. .noSession and
.providerNoReply name them; .engineStopped carries the callback's
reason. ShoesError is Codable so the new .lastError reply carries the
case, not a description."
```

---

### Task 4: `ShoesTunnel` — the callback reaches the provider; the health check goes

**Files:**
- Rename: `swift/Sources/ShoesTunnel/TrafficCallbackBridge.swift` → `CallbackBridge.swift`
- Modify: `swift/Sources/ShoesTunnel/ShoesEngine.swift:55-80`, `swift/Sources/ShoesTunnel/ShoesPacketTunnelProvider.swift`
- Modify: `swift/Tests/ShoesTunnelTests/ShoesEngineTests.swift`

**Interfaces:**
- Consumes: `shoes_start_with_fd(_, _, _, _, stopped)` from Task 2; `ShoesError.engineStopped` and `.lastError` from Task 3.
- Produces: `ShoesEngine.start(_:deviceFD:onTraffic:onStopped:)`.

- [ ] **Step 1: Rebuild the framework so Swift sees the new C signature**

```bash
bash scripts/build-apple.sh 2>&1 | tail -3
swift package reset
export SHOES_LOCAL_XCFRAMEWORK=1
swift build 2>&1 | grep -E "error:" | head -3
```
Expected: the build fails in `ShoesEngine.swift` — `shoes_start_with_fd` now wants five arguments. That is the failing state this task fixes.

- [ ] **Step 2: Update the engine tests first**

In `ShoesEngineTests.swift` change both `engine.start(config, deviceFD: 7) { _, _ in }` calls to `engine.start(config, deviceFD: 7, onTraffic: { _, _ in }, onStopped: { _ in })` (line 30 and, with `fresh`, line 63). Add:

```swift
    @Test func aFailedStartNeverReportsAStop() async throws {
        try engine.initialize(logLevel: .error)
        let fired = Fired()
        let config = ShoesConfiguration(yaml: "---\n[]\n")
        _ = await #expect(throws: ShoesError.self) {
            try await engine.start(config, deviceFD: 7, onTraffic: { _, _ in }, onStopped: { _ in fired.set() })
        }
        try await Task.sleep(for: .milliseconds(100))
        #expect(fired.isSet == false)
    }
}

/// A set-once flag readable from any thread, for the test above.
private final class Fired: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false
    var isSet: Bool { lock.withLock { value } }
    func set() { lock.withLock { value = true } }
}
```
(add `import Foundation` at the top of the test file for `NSLock`).

- [ ] **Step 3: `CallbackBridge`**

```bash
git mv swift/Sources/ShoesTunnel/TrafficCallbackBridge.swift swift/Sources/ShoesTunnel/CallbackBridge.swift
```
Replace its contents with:

```swift
import Foundation

/// Where the C callbacks deliver.
///
/// A C function pointer cannot capture context, so the closures a host
/// passes to `ShoesEngine.start` have to be reachable from a process-global.
/// shoes supports one running engine per process -- `shoes_is_running` is
/// process-wide and `shoes_stop` ignores its handle -- so one object with
/// one slot per callback is the right shape, not a registry. A third C
/// callback goes in here too, under the same lock.
///
/// One of the package's two `@unchecked Sendable`s -- the other is the
/// provider, whose state is actor-isolated. Here the lock is what makes it
/// true.
final class CallbackBridge: @unchecked Sendable {
    static let shared = CallbackBridge()

    private let lock = NSLock()
    private var traffic: (@Sendable (UInt64, UInt64) -> Void)?
    private var stopped: (@Sendable (String?) -> Void)?

    func install(
        traffic: @escaping @Sendable (UInt64, UInt64) -> Void,
        stopped: @escaping @Sendable (String?) -> Void
    ) {
        lock.withLock {
            self.traffic = traffic
            self.stopped = stopped
        }
    }

    func clear() {
        lock.withLock {
            traffic = nil
            stopped = nil
        }
    }

    /// Called from a shoes worker thread, about once a second while the
    /// counts change.
    func deliver(upload: UInt64, download: UInt64) {
        let handler = lock.withLock { traffic }
        handler?(upload, download)
    }

    /// Called from a shoes worker thread, once, when the engine stopped
    /// without being asked. The slot is taken, not read: the library calls
    /// at most once per session and so does this.
    func deliverStopped(reason: String?) {
        let handler = lock.withLock {
            defer { stopped = nil }
            return stopped
        }
        handler?(reason)
    }
}

/// The function pointers handed to `shoes_start_with_fd`.
let shoesTrafficCallback: @convention(c) (UInt64, UInt64) -> Void = { upload, download in
    CallbackBridge.shared.deliver(upload: upload, download: download)
}

let shoesStoppedCallback: @convention(c) (UnsafePointer<CChar>?) -> Void = { reason in
    CallbackBridge.shared.deliverStopped(reason: reason.map { String(cString: $0) })
}

/// The protect callback. On Apple platforms the system keeps a packet tunnel
/// provider's own sockets out of its tunnel, so there is nothing to do; the
/// engine still requires a callback. Verified on iOS by the consumer; on a
/// macOS system extension this is the behaviour expected and not yet shown.
let shoesProtectCallback: @convention(c) (Int32) -> Bool = { _ in true }
```

- [ ] **Step 4: `ShoesEngine.start`**

Replace the `start` method (`ShoesEngine.swift:60-75`) with:

```swift
    /// Start on a borrowed descriptor. `onTraffic` arrives about once a
    /// second while the counts change; `onStopped` arrives once if the engine
    /// stops without `stop()` having been called, with the reason when it
    /// gave one. Both run on a shoes worker thread; hop before touching an
    /// actor. A failed start calls neither.
    public func start(
        _ config: ShoesConfiguration,
        deviceFD: Int32,
        onTraffic: @escaping @Sendable (_ upload: UInt64, _ download: UInt64) -> Void,
        onStopped: @escaping @Sendable (_ reason: String?) -> Void
    ) async throws {
        guard initialized.isSet else { throw ShoesError.notInitialized }
        guard !isRunning else { throw ShoesError.alreadyRunning }

        CallbackBridge.shared.install(traffic: onTraffic, stopped: onStopped)
        let handle = await Task.detached(priority: .userInitiated) {
            shoes_start_with_fd(
                config.yaml, deviceFD, shoesProtectCallback, shoesTrafficCallback, shoesStoppedCallback)
        }.value
        guard handle > 0 else {
            CallbackBridge.shared.clear()
            throw ShoesError.startFailed(lastError() ?? "shoes_start_with_fd returned \(handle)")
        }
    }
```
In `stop()`, replace `TrafficCallbackBridge.shared.clear()` with `CallbackBridge.shared.clear()`. Update the doc comment above `start` that mentions the traffic callback only, and the class doc that says "`TrafficCallbackBridge`" (`ShoesPacketTunnelProvider.swift:26`) to `CallbackBridge`.

- [ ] **Step 5: The provider**

In `ShoesPacketTunnelProvider.swift`:

1. Class doc line 9: `engine, health check, path observation` → `engine, the engine's stop callback, path observation`.
2. `report(error:)` doc (line 51-53):
```swift
    /// An error the host should surface. Called for a failed start, a failed
    /// rebind, and an engine that stopped on its own. After that last one the
    /// provider cancels the tunnel and the extension process exits, so a host
    /// that needs the reason in the app must persist it from here; the
    /// `.lastError` message cannot answer once the process is gone, and a
    /// Rust panic aborts the process with no hook at all.
```
3. Delete `healthCheckInterval` (lines 65-66) and `private var healthCheck` (line 73). Add `private var lastError: ShoesError?` and `private var isStopping = false`.
4. In `start()`: after `try engine.initialize(...)` add `lastError = nil`; in the catch, after `report(error: shoesError)` add `lastError = shoesError` (before it, so `lastError` is set when `report` runs: put `lastError = shoesError` immediately before `report`). Replace `startHealthCheck()` / `startPathObservation()` at the end with just `startPathObservation()`.
5. In `stop(reason:)`: set `isStopping = true` first; delete the two `healthCheck` lines.
6. In `answer`: add `case .lastError: return .lastError(lastError)`.
7. In `startEngine`: replace the `engine.start` call with:
```swift
        let stopped: @MainActor @Sendable (String?) -> Void = { [weak self] reason in
            self?.engineStopped(reason: reason)
        }
        try await engine.start(
            config, deviceFD: fd,
            onTraffic: { upload, download in Task { @MainActor in deliver(upload, download) } },
            onStopped: { reason in Task { @MainActor in stopped(reason) } })
```
8. In `rebindTunnel`'s catch: `lastError = shoesError` before `report(error:)`.
9. Replace the whole `// MARK: Health` section with:
```swift
    // MARK: Engine exit

    /// The engine stopped and nobody asked it to. A rebind stops the engine
    /// on purpose and the library clears its slot before that stop, so this
    /// does not fire for one; the checks are for the window between a
    /// stopTunnel or rebind beginning on the actor and the C call landing.
    private func engineStopped(reason: String?) {
        if isRebinding || isStopping { return }
        let error = ShoesError.engineStopped(reason)
        log.error("\(error.localizedDescription, privacy: .public)")
        lastError = error
        report(error: error)
        cancelTunnelWithError(error)
    }
```

- [ ] **Step 6: Build, test, lint**

```bash
swift build 2>&1 | grep -E "error:|warning:.*ShoesTunnel/" | head
swift test 2>&1 | grep -E "Test run with|failed|error:"
swift format lint --strict --recursive swift Package.swift && echo LINT-OK
grep -rn "healthCheck\|TrafficCallbackBridge" swift/Sources swift/Tests   # expect none
```
Expected: clean build; all suites pass (Core 4 suites + `ShoesEngineTests` with the new test); lint clean; no stale identifiers.

- [ ] **Step 7: Commit**

```bash
git add -A swift/Sources/ShoesTunnel swift/Tests/ShoesTunnelTests
git commit -m "swift: report an engine death the instant it happens

ShoesEngine.start takes onStopped, delivered through the C callback the
FFI now provides; the provider reports it and cancels the tunnel at
once. The 30-second health check is removed -- it observed the same
event, the service task ending, thirty seconds later -- and with it
healthCheckInterval. The provider keeps lastError and answers the new
.lastError message with it."
```

---

### Task 5: Docs and changelog

**Files:**
- Modify: `swift/README.md:58-61`, `:75`; `CHANGELOG.md` under `## Unreleased`

- [ ] **Step 1: README**

Replace lines 58-61 with:
```markdown
Everything else is inherited: the start timeout, `shoes_stop` awaited before
`stopTunnel` completes, the engine's stop callback delivered to
`report(error:)` the moment the engine ends on its own, path observation
with the engine asked first and a full rebind only when it did not recover
in place, and typed app messages. The class is `@MainActor`; all four hooks
run there.
```
After `let reply = try await tunnel.send(.stats)` add:
```swift
if case .lastError(let error?) = try await tunnel.send(.lastError) { /* a non-fatal error */ }
```
and, after the code block, the paragraph:
```markdown
`.lastError` answers while the extension is alive. When the engine dies the
provider cancels the tunnel and the process exits; the app sees
`.disconnected` and nobody is left to ask, so persist fatal reasons from
`report(error:)` in the provider.
```

- [ ] **Step 2: CHANGELOG**

Under `## Unreleased`, after the `ShoesTunnelHost` section, add:
```markdown
### The engine says when it stops

`shoes_start_with_fd` takes a `ShoesStoppedCallback`, called once from a
worker thread when the engine stops without `shoes_stop` -- the failure
message, or NULL. Never for a requested stop, never after `shoes_stop`
returns; the reason is in `shoes_get_last_error` as well. `shoes_start` is
unchanged; the `_with_fd` signature changes one release after it appeared,
with the Swift package its only consumer. The surface count stays at 12.

In the package, `ShoesEngine.start` gains a required `onStopped:` and
`ShoesPacketTunnelProvider` reports an engine death at once instead of
noticing it on a 30-second health check, which is removed together with
`healthCheckInterval` (a subclass that overrode it no longer compiles; the
override did nothing). `ShoesError` gains `.noSession` and
`.providerNoReply` -- what `ShoesTunnelManager.send` now throws instead of
`.engine` -- and `.engineStopped(String?)`; it is `Codable`. An exhaustive
`switch` over `ShoesError` needs the new cases. `ShoesAppMessage.lastError`
asks the provider for the last error it reported, as the case; it answers
while the extension is alive, and after an engine death the process is gone
and the app sees only `.disconnected`.
```

- [ ] **Step 3: Commit**

```bash
git add swift/README.md CHANGELOG.md
git commit -m "docs: the stop callback, the removed health check, and lastError"
```

---

### Task 6: Verification and push

- [ ] **Step 1: Everything CI runs, locally**

```bash
CARGO=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin/cargo
$CARGO fmt --check && $CARGO test --lib 2>&1 | grep -E "test result"
$CARGO clippy --all-targets 2>&1 | grep -E "src/(control/mod|ffi/ios|ffi/android)\.rs" | head   # expect none
git diff --quiet include/shoes.h || echo "header changed after cbindgen?"   # expect silent
export SHOES_LOCAL_XCFRAMEWORK=1
swift format lint --strict --recursive swift Package.swift && swift build && swift test 2>&1 | grep -E "Test run with|failed"
rm -rf build/linkcheck
for s in HostLinkCheck ExtensionLinkCheck; do xcodebuild -scheme "$s" -configuration Release -destination 'generic/platform=iOS Simulator' ARCHS=arm64 CODE_SIGNING_ALLOWED=NO -derivedDataPath build/linkcheck build 2>&1 | grep BUILD; done
nm -U build/linkcheck/Build/Products/Release-iphonesimulator/HostLinkCheck | grep -c ' T _shoes_'        # 0
nm -U build/linkcheck/Build/Products/Release-iphonesimulator/ExtensionLinkCheck | grep -c ' T _shoes_'   # > 0
```

- [ ] **Step 2: Push and watch CI**

```bash
git push origin mobile
gh run list --branch mobile --limit 3
```
Report the Rust and Swift test counts, and the link-check numbers, verbatim. Release 0.2.16 is a separate step after CI is green.
