import Foundation
@preconcurrency import NetworkExtension

// Re-exported so `import ShoesTunnelHost` alone sees ShoesAppMessage,
// ShoesError and the other wire types.
@_exported import ShoesTunnelCore

/// Progress of a macOS system-extension activation that the app should
/// show rather than wait out. Defined outside the macOS-only installer so
/// `start(onActivationEvent:configure:)` has one signature on every
/// platform; on iOS the handler is simply never called.
public enum TunnelActivationEvent: Sendable {
    /// The user must approve the extension in System Settings > General >
    /// Login Items & Extensions. The activation -- and `start()` -- waits
    /// until they do, potentially forever: point them at the setting.
    case needsUserApproval
}

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
        try await start { _, proto in configure(proto) }
    }

    /// The two-parameter form without activation events.
    public func start(
        configure: (NETunnelProviderManager, NETunnelProviderProtocol) -> Void
    ) async throws {
        try await start(onActivationEvent: nil, configure: configure)
    }

    /// The two-parameter form, for policy that lives on the manager rather
    /// than the protocol object: on-demand rules (`onDemandRules`,
    /// `isOnDemandEnabled` -- always-on VPN), `localizedDescription`. The
    /// one-parameter form could not express these at all, which forced any
    /// app wanting always-on to bypass `start()` entirely.
    ///
    /// `onActivationEvent` is the macOS first-install story: without it the
    /// await sits silent for as long as the user takes to find System
    /// Settings, and the app has nothing to show. Delivered on the main
    /// queue; never called on iOS.
    public func start(
        onActivationEvent: (@Sendable (TunnelActivationEvent) -> Void)?,
        configure: (NETunnelProviderManager, NETunnelProviderProtocol) -> Void
    ) async throws {
        #if os(macOS)
            try await SystemExtensionInstaller.activate(
                bundleIdentifier: providerBundleIdentifier, onEvent: onActivationEvent)
        #else
            _ = onActivationEvent
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
        configure(manager, proto)
        manager.protocolConfiguration = proto
        manager.isEnabled = true

        do {
            try await manager.saveToPreferences()
        } catch let error as NEVPNError
            where error.code == .configurationStale || error.code == .configurationInvalid
        {
            // The cached manager can be stale: the user deleting the VPN
            // profile in Settings is routine, and saving the stale object
            // then fails. One reload-and-retry recreates the profile
            // instead of surfacing a configuration error for a state the
            // user considers clean. Scoped to the stale/invalid codes: any
            // other failure (a permission denial, say) must surface, not
            // be retried into a second identical failure.
            let fresh = try await load()
            let retryProto = NETunnelProviderProtocol()
            retryProto.providerBundleIdentifier = providerBundleIdentifier
            // configure runs again with the FRESH manager: the first run
            // put on-demand rules and descriptions on the stale object,
            // and carrying only the protocol forward silently shipped an
            // always-on app without always-on.
            configure(fresh, retryProto)
            fresh.protocolConfiguration = retryProto
            fresh.isEnabled = true
            try await fresh.saveToPreferences()
            try await fresh.loadFromPreferences()
            try fresh.connection.startVPNTunnel()
            return
        }
        try await manager.loadFromPreferences()
        try manager.connection.startVPNTunnel()
    }

    /// Fire-and-forget by design: the system delivers the outcome through
    /// `statusUpdates` (`.disconnecting`, then `.disconnected`), and the
    /// provider's own stop path is what guarantees teardown. An app that
    /// wants a "stopping…" state builds it from the stream.
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

    /// Ask the running provider something. Throws `.noSession` when no
    /// session is connected, `.providerNoReply` when the provider answered
    /// with nothing, and `.timedOut` when it answered with silence -- an
    /// extension that dies between the send and the reply never invokes
    /// the completion block at all, and without the deadline this call
    /// parked its caller forever (a stats refresh on a UI timer being the
    /// caller most exposed).
    public func send(
        _ message: ShoesAppMessage, timeout: Duration = .seconds(3)
    ) async throws -> ShoesAppReply {
        guard let session = manager?.connection as? NETunnelProviderSession else {
            throw ShoesError.noSession
        }
        let request = try message.encoded()
        let response: Data? = try await withCheckedThrowingContinuation { continuation in
            let claim = ClaimFlag()
            // Held so the winner can cancel it: an unstructured deadline
            // task otherwise sleeps out its full timeout retaining the
            // claim and continuation after every reply -- a 1 Hz stats
            // poll kept a rolling handful of dead racers alive for good.
            let deadline = Task {
                try? await Task.sleep(for: timeout)
                if await claim.claim() {
                    continuation.resume(
                        throwing: ShoesError.timedOut(seconds: wholeSeconds(timeout)))
                }
            }
            do {
                try session.sendProviderMessage(request) { data in
                    Task {
                        if await claim.claim() {
                            deadline.cancel()
                            continuation.resume(returning: data)
                        }
                    }
                }
            } catch {
                Task {
                    if await claim.claim() {
                        deadline.cancel()
                        continuation.resume(throwing: error)
                    }
                }
            }
        }
        guard let response else { throw ShoesError.providerNoReply }
        return try ShoesAppReply.decode(response)
    }
}
