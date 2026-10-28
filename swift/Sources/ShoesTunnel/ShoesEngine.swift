import Foundation
import ShoesFFI

// Re-exported so `import ShoesTunnel` alone sees ShoesConfiguration and
// the rest of the wire types, as it did before the split.
@_exported import ShoesTunnelCore

/// The shoes engine, as a Swift host sees it.
///
/// One per process, because the library is: `shoes_is_running` is a
/// process-wide fact and there is one session at a time. `shoes_stop` acts
/// on the session whose id it is given and on no other, so this wrapper
/// keeps the id `shoes_start_with_fd` returned and passes it back; after a
/// stop, or before any start, it passes 0, which the library answers with
/// "released" since nothing of ours is running. A `stop()` that arrives
/// while `start` is still inside the native call waits for that call to
/// return, so it stops the session the start made rather than nothing. The
/// two rules the C surface states in prose are properties here:
///
/// - `stop()` is `async` and returns only when the engine has released the
///   descriptor. There is no synchronous stop; a host that wants
///   `shoes_stop` on its own thread can import `ShoesFFI` directly.
/// - `start(_:deviceFD:)` borrows the descriptor. The engine never closes it,
///   and it must stay open until `stop()` has returned.
public final class ShoesEngine: Sendable {
    public static let shared = ShoesEngine()

    /// `shoes_init` is idempotent, but `start` before it would fail inside
    /// the FFI with a less useful error than `.notInitialized`.
    private let initialized = LockedFlag()

    /// The id of the running session, 0 when there is none.
    private let session = LockedHandle()

    /// The native start in flight, so a `stop()` can wait for it.
    private let inFlight = LockedTask()

    /// The native stop in flight, so overlapping stops share it.
    private let stopping = LockedStop()

    /// The native calls, replaceable for tests of this wrapper's own
    /// choreography; the library's own behaviour is tested in Rust.
    private let startNative: @Sendable (String, Int32) -> Int
    private let stopNative: @Sendable (Int) -> Int32

    private init() {
        startNative = { yaml, fd in
            shoes_start_with_fd(
                yaml, fd, shoesProtectCallback, shoesTrafficCallback, shoesStoppedCallback)
        }
        stopNative = { handle in shoes_stop(handle) }
    }

    /// A second instance for tests of the pre-initialization path. The FFI
    /// state behind it is still process-global.
    convenience init(forTesting: Void) {
        self.init(
            forTesting: (),
            start: { yaml, fd in
                shoes_start_with_fd(
                    yaml, fd, shoesProtectCallback, shoesTrafficCallback, shoesStoppedCallback)
            },
            stop: { handle in shoes_stop(handle) })
    }

    /// An instance whose native start and stop are the closures given, for
    /// tests of how this wrapper sequences them.
    init(
        forTesting: Void,
        start: @escaping @Sendable (String, Int32) -> Int,
        stop: @escaping @Sendable (Int) -> Int32
    ) {
        startNative = start
        stopNative = stop
    }

    public var version: String {
        String(cString: shoes_get_version())
    }

    public var isRunning: Bool {
        shoes_is_running()
    }

    /// The most verbose level this build can log at. Release builds compile
    /// with `release_max_level_info`, so this is `.info` in every published
    /// artifact and `setLogLevel` cannot go past it: ask before offering a
    /// debug logging switch.
    public var maxLogLevel: ShoesLogLevel {
        ShoesLogLevel(rawValue: String(cString: shoes_max_log_level())) ?? .info
    }

    /// `shoes_init`. Safe to call repeatedly; only the first call's level is
    /// used, and `setLogLevel` changes it afterwards.
    public func initialize(logLevel: ShoesLogLevel) throws {
        let rc = shoes_init(logLevel.rawValue)
        guard rc == 0 else { throw ShoesError.engine("shoes_init returned \(rc)") }
        initialized.set()
    }

    /// Start on a borrowed descriptor. `onTraffic` arrives about once a
    /// second while the counts change; `onStopped` arrives once if the engine
    /// stops without `stop()` having been called, with the reason when it
    /// gave one. Both run on a shoes worker thread; hop before touching an
    /// actor. A failed start calls neither.
    ///
    /// `async`, and off the caller's executor: `shoes_start_with_fd` parses
    /// the config, loads PEM files and builds the DNS resolvers under a
    /// blocking `block_on` before it returns, which is work an extension must
    /// not do on its main thread.
    public func start(
        _ config: ShoesConfiguration,
        deviceFD: Int32,
        onTraffic: @escaping @Sendable (_ upload: UInt64, _ download: UInt64) -> Void,
        onStopped: @escaping @Sendable (_ reason: String?) -> Void
    ) async throws {
        guard initialized.isSet else { throw ShoesError.notInitialized }
        guard !isRunning else { throw ShoesError.alreadyRunning }

        // The task records the session itself, so a `stop()` that awaited
        // it finds the id set before it looks.
        let startNative = self.startNative
        let session = self.session
        let yaml = config.yaml
        // Handlers installed, task created and task registered under one
        // lock, the lock a `stop()` clears the handlers and reads the task
        // through: either the stop finds this start and its handlers and
        // clears them, or it finds nothing and this start installs after
        // it, as a start after a stop should. A second start while one is
        // registered is refused here, before it has touched anything.
        guard
            let task = inFlight.start(
                install: { CallbackBridge.shared.install(traffic: onTraffic, stopped: onStopped) },
                make: {
                    Task.detached(priority: .userInitiated) {
                        let handle = startNative(yaml, deviceFD)
                        if handle > 0 { session.set(handle) }
                        return handle
                    }
                })
        else { throw ShoesError.alreadyRunning }
        let handle = await task.value
        inFlight.clear(task)
        guard handle > 0 else {
            CallbackBridge.shared.clear()
            throw ShoesError.startFailed(lastError() ?? "shoes_start_with_fd returned \(handle)")
        }
    }

    /// Signal shutdown and wait until the engine has released the
    /// descriptor: milliseconds in practice, bounded at five seconds by the
    /// library. Runs `shoes_stop` off the caller's executor, so it is safe
    /// to await from a provider callback that has a deadline of its own.
    ///
    /// Returns whether the engine confirmed the release. `false` means the
    /// wait timed out and the engine may still be reading the descriptor --
    /// the answer `shoes_stop` has always computed and this wrapper used to
    /// discard. Discarding it still reproduces the old behavior.
    @discardableResult
    public func stop() async -> Bool {
        // The handlers are cleared under the registration lock, as the
        // library clears its own slot before it stops: a requested stop is
        // not an event, and a traffic tick during it is not worth
        // delivering. Under that lock, so a start in flight has either
        // installed its handlers already (cleared here, and the engine it
        // makes dies to nobody) or installs them after (a start after a
        // stop, whose handlers are its own to keep). A start still inside
        // the native call owns the session this stop is for; its id exists
        // only once that call returns.
        if let starting = inFlight.takeForStop(clearing: { CallbackBridge.shared.clear() }) {
            _ = await starting.value
        }
        // The session id is taken and the stop registered under one lock.
        // A stop that gets an id runs its own native stop, so a session
        // started while an earlier stop is returning is never left to that
        // earlier stop's answer; a stop that gets no id joins the stop in
        // flight, if any, so it cannot report "released" while the engine
        // still reads the descriptor.
        let stopNative = self.stopNative
        guard
            let task = stopping.share(
                take: session.take,
                make: { handle in
                    Task.detached(priority: .userInitiated) {
                        stopNative(handle) == 1
                    }
                })
        else { return true }
        let released = await task.value
        stopping.clear(task)
        return released
    }

    /// Tell the engine the network changed. Returns the number of tunnel
    /// endpoints that rebound in place; zero means nothing did, and a host
    /// that wants to recover must re-establish the tunnel itself.
    public func networkChanged() -> Int {
        Int(shoes_network_changed())
    }

    /// The runtime counters, or nil when the library produced no document.
    /// Nil is not a verdict on the build: poll again rather than latch it.
    public func stats() -> ShoesStats? {
        guard let ptr = shoes_get_stats() else { return nil }
        defer { shoes_free_string(ptr) }
        return try? ShoesStats.decode(String(cString: ptr))
    }

    /// `shoes_get_last_error`, freed. Empty is reported as nil.
    public func lastError() -> String? {
        guard let ptr = shoes_get_last_error() else { return nil }
        defer { shoes_free_string(ptr) }
        let message = String(cString: ptr)
        return message.isEmpty ? nil : message
    }

    /// `shoes_set_log_file`. Appends, and rotates at 4 MiB to `<path>.1`,
    /// keeping one previous file.
    public func setLogFile(_ path: String) throws {
        let rc = shoes_set_log_file(path)
        guard rc == 0 else { throw ShoesError.engine("shoes_set_log_file returned \(rc)") }
    }

    public func setLogLevel(_ level: ShoesLogLevel) throws {
        let rc = shoes_set_log_level(level.rawValue)
        guard rc == 0 else { throw ShoesError.engine("shoes_set_log_level returned \(rc)") }
    }
}

/// A set-once flag readable from any thread.
private final class LockedFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false
    var isSet: Bool { lock.withLock { value } }
    func set() { lock.withLock { value = true } }
}

/// The start task in flight, if any, readable from any thread.
private final class LockedTask: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Task<Int, Never>?
    /// Runs `install`, then creates the task with `make` and registers it,
    /// all under the lock, so a reader never sees a task running
    /// unregistered or without its handlers. Nil, and nothing done, while
    /// a start is already registered.
    func start(install: () -> Void, make: () -> Task<Int, Never>) -> Task<Int, Never>? {
        lock.withLock {
            if value != nil { return nil }
            install()
            let task = make()
            value = task
            return task
        }
    }
    /// The registered task, if any, after running `clearing` under the
    /// same lock `start` installs under.
    func takeForStop(clearing: () -> Void) -> Task<Int, Never>? {
        lock.withLock {
            clearing()
            return value
        }
    }
    /// Clears the slot if it still holds `task`; a newer start's task stays.
    func clear(_ task: Task<Int, Never>) {
        lock.withLock {
            if value == task { value = nil }
        }
    }
}

/// The stop task in flight, if any: a stop with no session of its own joins it.
private final class LockedStop: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Task<Bool, Never>?
    /// Under one lock: `take` the session id; with one, make and register a
    /// stop for it, replacing whatever was registered; without one, the stop
    /// in flight, or nil when there is none and nothing to stop.
    func share(take: () -> Int, make: (Int) -> Task<Bool, Never>) -> Task<Bool, Never>? {
        lock.withLock {
            let handle = take()
            if handle == 0 { return value }
            let task = make(handle)
            value = task
            return task
        }
    }
    func clear(_ task: Task<Bool, Never>) {
        lock.withLock {
            if value == task { value = nil }
        }
    }
}

/// A session id readable and clearable from any thread; 0 is "none".
private final class LockedHandle: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0
    func set(_ handle: Int) { lock.withLock { value = handle } }
    /// The id, and 0 from now on: a stop takes it, so a second stop
    /// passes nothing to stop.
    func take() -> Int {
        lock.withLock {
            let handle = value
            value = 0
            return handle
        }
    }
}
