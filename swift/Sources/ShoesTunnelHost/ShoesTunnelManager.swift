import Foundation
@preconcurrency import NetworkExtension

// Re-exported so `import ShoesTunnelHost` alone sees ShoesAppMessage,
// ShoesError and the other wire types.
@_exported import ShoesTunnelCore

/// The app-process half: Apple's TN3120 sequence, status as a stream, and
/// typed messages to the provider.
///
/// The sequence is `loadAllFromPreferences`, find or create the manager for
/// this provider, configure, `saveToPreferences`, `loadFromPreferences`
/// *again*, then `startVPNTunnel`. The second load is the step everyone
/// omits, and without it the start silently does nothing. On macOS the
/// system extension is activated first; that is the one platform branch on
/// the app side, and it lives here rather than in each host.
@MainActor
public final class ShoesTunnelManager {
    public let providerBundleIdentifier: String
    private var manager: NETunnelProviderManager?

    public init(providerBundleIdentifier: String) {
        self.providerBundleIdentifier = providerBundleIdentifier
    }

    /// Find the saved configuration for this provider, or prepare a new one.
    @discardableResult
    public func load() async throws -> NETunnelProviderManager {
        let all = try await NETunnelProviderManager.loadAllFromPreferences()
        let found =
            all.first {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
                    == providerBundleIdentifier
            } ?? NETunnelProviderManager()
        manager = found
        return found
    }

    /// Configure, save, reload and start.
    ///
    /// - Parameter configure: the host's policy on the protocol object:
    ///   `serverAddress`, `includeAllNetworks`, the exclusion flags,
    ///   `disconnectOnSleep`. `providerBundleIdentifier` is set already.
    public func start(configure: (NETunnelProviderProtocol) -> Void) async throws {
        #if os(macOS)
            try await SystemExtensionInstaller.activate(bundleIdentifier: providerBundleIdentifier)
        #endif
        // load() always yields a manager; the binding makes that a
        // compile-time fact rather than a guard that silently returns.
        let manager: NETunnelProviderManager
        if let existing = self.manager {
            manager = existing
        } else {
            manager = try await load()
        }

        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = providerBundleIdentifier
        configure(proto)
        manager.protocolConfiguration = proto
        manager.isEnabled = true

        try await manager.saveToPreferences()
        try await manager.loadFromPreferences()
        try manager.connection.startVPNTunnel()
    }

    public func stop() {
        manager?.connection.stopVPNTunnel()
    }

    public var status: NEVPNStatus {
        manager?.connection.status ?? .invalid
    }

    /// Status changes for this connection, starting with the current value.
    public var statusUpdates: AsyncStream<NEVPNStatus> {
        AsyncStream { continuation in
            continuation.yield(status)
            let task = Task { @MainActor [weak self] in
                // Filtered here rather than by `object:`, whose parameter
                // wants a Sendable object and NEVPNConnection is not one.
                // Against the LIVE connection, read per notification: the
                // stream may be created before load(), and a connection
                // captured at creation would be nil and match nothing, ever.
                for await note in NotificationCenter.default.notifications(named: .NEVPNStatusDidChange) {
                    guard let self, let connection = self.manager?.connection,
                        note.object as AnyObject === connection
                    else { continue }
                    continuation.yield(self.status)
                }
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }

    /// Ask the running provider something. Throws if no session is
    /// connected or the provider gave no answer.
    public func send(_ message: ShoesAppMessage) async throws -> ShoesAppReply {
        guard let session = manager?.connection as? NETunnelProviderSession else {
            throw ShoesError.engine("no tunnel session")
        }
        let request = try message.encoded()
        let response: Data? = try await withCheckedThrowingContinuation { continuation in
            do {
                try session.sendProviderMessage(request) { continuation.resume(returning: $0) }
            } catch {
                continuation.resume(throwing: error)
            }
        }
        guard let response else { throw ShoesError.engine("provider gave no reply") }
        return try ShoesAppReply.decode(response)
    }
}
