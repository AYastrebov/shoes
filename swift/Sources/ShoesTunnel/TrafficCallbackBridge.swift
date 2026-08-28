import Foundation

/// Where the C traffic callback delivers its numbers.
///
/// `ShoesTrafficCallback` is a C function pointer and cannot capture context,
/// so the closure a host passes to `ShoesEngine.start` has to be reachable
/// from a process-global. shoes supports one running engine per process --
/// `shoes_is_running` is process-wide and `shoes_stop` ignores its handle --
/// so one slot is the right number, not a registry.
///
/// This is the only `@unchecked Sendable` in the package. The lock is what
/// makes it true; do not add a second global instead of reaching for this.
final class TrafficCallbackBridge: @unchecked Sendable {
    static let shared = TrafficCallbackBridge()

    private let lock = NSLock()
    private var handler: (@Sendable (UInt64, UInt64) -> Void)?

    func install(_ handler: @escaping @Sendable (UInt64, UInt64) -> Void) {
        lock.withLock { self.handler = handler }
    }

    func clear() {
        lock.withLock { handler = nil }
    }

    /// Called from a shoes worker thread, about once a second while the
    /// counts change.
    func deliver(upload: UInt64, download: UInt64) {
        let handler = lock.withLock { self.handler }
        handler?(upload, download)
    }
}

/// The function pointer handed to `shoes_start_with_fd`.
let shoesTrafficCallback: @convention(c) (UInt64, UInt64) -> Void = { upload, download in
    TrafficCallbackBridge.shared.deliver(upload: upload, download: download)
}

/// The protect callback. On Apple platforms the system keeps a packet tunnel
/// provider's own sockets out of its tunnel, so there is nothing to do; the
/// engine still requires a callback. Verified on iOS by the consumer; on a
/// macOS system extension this is the behaviour expected and not yet shown.
let shoesProtectCallback: @convention(c) (Int32) -> Bool = { _ in true }
