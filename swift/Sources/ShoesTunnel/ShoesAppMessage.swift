import Foundation

/// What a host asks the provider, over `sendProviderMessage`.
///
/// Typed on both sides so that the two processes do not have to spell a
/// string the same way. Encoded as JSON with a `kind` discriminator, and a
/// request the provider does not recognise -- a newer app against an older
/// extension -- is answered with `.error`, never dropped.
public enum ShoesAppMessage: Codable, Sendable, Equatable {
    case version
    case status
    case stats
    case setLogLevel(ShoesLogLevel)

    private enum CodingKeys: String, CodingKey { case kind, level }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .version: try c.encode("version", forKey: .kind)
        case .status: try c.encode("status", forKey: .kind)
        case .stats: try c.encode("stats", forKey: .kind)
        case .setLogLevel(let level):
            try c.encode("setLogLevel", forKey: .kind)
            try c.encode(level.rawValue, forKey: .level)
        }
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        switch try c.decode(String.self, forKey: .kind) {
        case "version": self = .version
        case "status": self = .status
        case "stats": self = .stats
        case "setLogLevel":
            let raw = try c.decode(String.self, forKey: .level)
            guard let level = ShoesLogLevel(rawValue: raw) else {
                throw DecodingError.dataCorruptedError(forKey: .level, in: c, debugDescription: "unknown level \(raw)")
            }
            self = .setLogLevel(level)
        case let other:
            throw DecodingError.dataCorruptedError(forKey: .kind, in: c, debugDescription: "unknown message \(other)")
        }
    }

    public func encoded() throws -> Data { try JSONEncoder().encode(self) }
    public static func decode(_ data: Data) throws -> ShoesAppMessage {
        try JSONDecoder().decode(ShoesAppMessage.self, from: data)
    }

    /// Decode a request and answer it, turning a request that does not decode
    /// into `.error` so the provider never fails a message it did not
    /// understand.
    public static func handle(_ data: Data, _ answer: (ShoesAppMessage) -> ShoesAppReply) -> ShoesAppReply {
        do {
            return answer(try decode(data))
        } catch {
            return .error("unrecognised request: \(error.localizedDescription)")
        }
    }
}

/// The provider's answer.
public enum ShoesAppReply: Codable, Sendable, Equatable {
    case version(String)
    case status(running: Bool)
    case stats(ShoesStats?)
    case ok
    case error(String)

    private enum CodingKeys: String, CodingKey { case kind, version, running, stats, message }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .version(let v):
            try c.encode("version", forKey: .kind)
            try c.encode(v, forKey: .version)
        case .status(let running):
            try c.encode("status", forKey: .kind)
            try c.encode(running, forKey: .running)
        case .stats(let stats):
            try c.encode("stats", forKey: .kind)
            try c.encodeIfPresent(stats, forKey: .stats)
        case .ok: try c.encode("ok", forKey: .kind)
        case .error(let message):
            try c.encode("error", forKey: .kind)
            try c.encode(message, forKey: .message)
        }
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        switch try c.decode(String.self, forKey: .kind) {
        case "version": self = .version(try c.decode(String.self, forKey: .version))
        case "status": self = .status(running: try c.decode(Bool.self, forKey: .running))
        case "stats": self = .stats(try c.decodeIfPresent(ShoesStats.self, forKey: .stats))
        case "ok": self = .ok
        case "error": self = .error(try c.decode(String.self, forKey: .message))
        case let other:
            throw DecodingError.dataCorruptedError(forKey: .kind, in: c, debugDescription: "unknown reply \(other)")
        }
    }

    public func encoded() throws -> Data { try JSONEncoder().encode(self) }
    public static func decode(_ data: Data) throws -> ShoesAppReply {
        try JSONDecoder().decode(ShoesAppReply.self, from: data)
    }
}
