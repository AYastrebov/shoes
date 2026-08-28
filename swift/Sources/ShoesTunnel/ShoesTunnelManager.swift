import Foundation
@preconcurrency import NetworkExtension

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
    public func load() async throws {
        let all = try await NETunnelProviderManager.loadAllFromPreferences()
        manager =
            all.first {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
                    == providerBundleIdentifier
            } ?? NETunnelProviderManager()
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
        if manager == nil { try await load() }
        guard let manager else { return }

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
        let connection = manager?.connection
        return AsyncStream { continuation in
            continuation.yield(status)
            let task = Task { @MainActor [weak self] in
                // Filtered here rather than by `object:`, whose parameter
                // wants a Sendable object and NEVPNConnection is not one.
                for await note in NotificationCenter.default.notifications(named: .NEVPNStatusDidChange)
                where note.object as AnyObject === connection {
                    continuation.yield(self?.status ?? .invalid)
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
