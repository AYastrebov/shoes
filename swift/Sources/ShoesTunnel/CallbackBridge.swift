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
