import Foundation

/// The runtime counters, decoded from the JSON `shoes_get_stats` returns.
///
/// `uploadBytes` and `downloadBytes` are the two totals the traffic callback
/// also delivers, measured at the TUN edge; `activeConnections` is live TCP
/// connections through the tunnel. Each outbound is measured at the proxy
/// instead, so its figures do not agree with the top level to the byte and
/// are not meant to. Unknown keys are ignored: later releases may add them.
public struct ShoesStats: Codable, Sendable, Equatable {
    public struct Outbound: Codable, Sendable, Equatable {
        public let name: String
        public let uploadBytes: UInt64
        public let downloadBytes: UInt64
        public let activeConnections: UInt64

        public init(name: String, uploadBytes: UInt64, downloadBytes: UInt64, activeConnections: UInt64) {
            self.name = name
            self.uploadBytes = uploadBytes
            self.downloadBytes = downloadBytes
            self.activeConnections = activeConnections
        }
    }

    public let uploadBytes: UInt64
    public let downloadBytes: UInt64
    public let activeConnections: UInt64
    public let outbounds: [Outbound]

    public init(uploadBytes: UInt64, downloadBytes: UInt64, activeConnections: UInt64, outbounds: [Outbound]) {
        self.uploadBytes = uploadBytes
        self.downloadBytes = downloadBytes
        self.activeConnections = activeConnections
        self.outbounds = outbounds
    }

    /// Decode the document as `shoes_get_stats` produces it.
    public static func decode(_ json: String) throws -> ShoesStats {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try decoder.decode(ShoesStats.self, from: Data(json.utf8))
    }
}
