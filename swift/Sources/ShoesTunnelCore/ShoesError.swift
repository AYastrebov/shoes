import Foundation

/// What can go wrong between a host and the engine.
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
        }
    }
}
