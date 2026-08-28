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
