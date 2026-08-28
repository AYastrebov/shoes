import Foundation
import ShoesFFI

/// The shoes engine, as a Swift host sees it.
///
/// One per process, because the library is: `shoes_is_running` is a
/// process-wide fact and `shoes_stop` ignores the handle it is given. The
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

    private init() {}

    /// A second instance for tests of the pre-initialization path. The FFI
    /// state behind it is still process-global.
    init(forTesting: Void) {}

    public var version: String {
        String(cString: shoes_get_version())
    }

    public var isRunning: Bool {
        shoes_is_running()
    }

    /// `shoes_init`. Safe to call repeatedly; only the first call's level is
    /// used, and `setLogLevel` changes it afterwards.
    public func initialize(logLevel: ShoesLogLevel) throws {
        let rc = shoes_init(logLevel.rawValue)
        guard rc == 0 else { throw ShoesError.engine("shoes_init returned \(rc)") }
        initialized.set()
    }

    /// Start a session. Returns once the config has been accepted; a thrown
    /// `.startFailed` carries what `shoes_get_last_error` had to say.
    ///
    /// - Parameter deviceFD: the TUN descriptor, borrowed. On an Apple
    ///   platform this is `packetFlow`'s `socket.fileDescriptor`. It must
    ///   stay open until `stop()` returns; the engine never closes it.
    /// - Parameter onTraffic: cumulative upload and download bytes, about
    ///   once a second while they change, from a shoes worker thread.
    public func start(
        _ config: ShoesConfiguration,
        deviceFD: Int32,
        onTraffic: @escaping @Sendable (_ upload: UInt64, _ download: UInt64) -> Void
    ) throws {
        guard initialized.isSet else { throw ShoesError.notInitialized }
        guard !isRunning else { throw ShoesError.alreadyRunning }

        TrafficCallbackBridge.shared.install(onTraffic)
        let handle = shoes_start_with_fd(config.yaml, deviceFD, shoesProtectCallback, shoesTrafficCallback)
        guard handle > 0 else {
            TrafficCallbackBridge.shared.clear()
            throw ShoesError.startFailed(lastError() ?? "shoes_start_with_fd returned \(handle)")
        }
    }

    /// Signal shutdown and wait until the engine has released the
    /// descriptor: milliseconds in practice, bounded at five seconds by the
    /// library. Runs `shoes_stop` off the caller's executor, so it is safe
    /// to await from a provider callback that has a deadline of its own.
    public func stop() async {
        await Task.detached(priority: .userInitiated) {
            shoes_stop(1)
        }.value
        TrafficCallbackBridge.shared.clear()
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
