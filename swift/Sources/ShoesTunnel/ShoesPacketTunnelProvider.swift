import Foundation
import Network
@preconcurrency import NetworkExtension
import os

/// An `NEPacketTunnelProvider` that runs shoes.
///
/// A template method: this class owns the sequence -- settings, descriptor,
/// engine, health check, path observation, and the ordering against
/// `shoes_stop` -- and a subclass supplies only what is its own through the
/// four `open` hooks below. Everything the subclass does not override is
/// inherited, so the rules cannot be got wrong by omission.
///
/// Identical on iOS (an app extension) and macOS (a system extension); the
/// two differ in the Xcode target that subclasses this, not in the code.
///
/// The class is `@MainActor`. The system calls the provider on its own
/// queues, so every override is `nonisolated` and hops onto the actor; the
/// state lives there and nothing else touches it. The provider's own API
/// (`setTunnelNetworkSettings`, `cancelTunnelWithError`, `packetFlow`) is
/// thread-safe and is called from the actor as from anywhere.
///
/// `@unchecked Sendable` is what lets a `nonisolated` override hand `self`
/// to the actor. It asserts only that the reference may cross a thread; every
/// stored property is actor-isolated and the compiler still checks each
/// access. This and `TrafficCallbackBridge` are the package's two escape
/// hatches, and each says why.
@MainActor
open class ShoesPacketTunnelProvider: NEPacketTunnelProvider, @unchecked Sendable {

    // MARK: Hooks

    /// The config to run. Called on every start and on every full rebind.
    /// Throw to fail the start with that error.
    open func loadConfiguration() throws -> ShoesConfiguration {
        throw ShoesError.startFailed("loadConfiguration() is not overridden")
    }

    /// The settings to apply before the engine starts. Addresses, routes,
    /// DNS and MTU are the host's policy; the engine only reads packets.
    open func makeNetworkSettings() -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "10.0.0.1")
        let ipv4 = NEIPv4Settings(addresses: ["10.0.0.2"], subnetMasks: ["255.255.255.0"])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = ipv4
        settings.mtu = 9000
        return settings
    }

    /// An error the host should surface. Called for a failed start, a failed
    /// rebind, and an engine that stopped on its own.
    open func report(error: ShoesError) {}

    /// Cumulative bytes, about once a second while they change. The engine
    /// produces them on a worker thread; they arrive here on the actor.
    open func report(upload: UInt64, download: UInt64) {}

    // MARK: Tunables

    /// How long `startTunnel` may take before it fails itself. The system's
    /// own limit is about a minute; failing earlier makes the reason ours.
    open var startTimeout: Duration { .seconds(14) }

    /// How often the engine is checked for having stopped on its own.
    open var healthCheckInterval: Duration { .seconds(30) }

    // MARK: State

    private let log = Logger(subsystem: "shoes", category: "ShoesPacketTunnelProvider")
    private let engine = ShoesEngine.shared
    private var configuration: ShoesConfiguration?
    private var healthCheck: Task<Void, Never>?
    private var pathObservation: Task<Void, Never>?
    private var rebind: Task<Void, Never>?

    // MARK: Overrides

    // `nonisolated` so they match the superclass and are callable from
    // whatever queue the system uses, each hopping onto the actor.
    //
    // startTunnel is the completion-handler form: an async override of an
    // ObjC method may not take a non-Sendable parameter, and `options` is
    // one. It is never read. The block is an ObjC completion handler, safe to
    // call from any thread by contract and not annotated as such.

    nonisolated open override func startTunnel(
        options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void
    ) {
        nonisolated(unsafe) let done = completionHandler
        Task { @MainActor in
            do {
                try await self.start()
                done(nil)
            } catch {
                done(error)
            }
        }
    }

    nonisolated open override func stopTunnel(with reason: NEProviderStopReason) async {
        await stop(reason: reason)
    }

    nonisolated open override func wake() {
        Task { @MainActor in
            self.log.info("wake")
            self.recoverFromNetworkChange()
        }
    }

    nonisolated open override func handleAppMessage(_ messageData: Data) async -> Data? {
        await answer(messageData)
    }

    // MARK: Lifecycle, on the actor

    private func start() async throws {
        log.info("startTunnel")
        // A previous session, if the system is reasserting after sleep.
        // Awaited, not blocked on: shoes_stop can take up to five seconds.
        if engine.isRunning { await engine.stop() }

        let config = try loadConfiguration()
        configuration = config
        try engine.initialize(logLevel: config.logLevel)

        do {
            // Raced against the timeout: the system's own limit is about a
            // minute, and failing earlier makes the reason ours.
            let limit = startTimeout
            try await withThrowingTaskGroup(of: Void.self) { group in
                group.addTask { try await self.applySettingsAndStartEngine(config) }
                group.addTask {
                    try await Task.sleep(for: limit)
                    throw ShoesError.timedOut(seconds: Int(limit.components.seconds))
                }
                try await group.next()
                group.cancelAll()
            }
        } catch {
            let shoesError = (error as? ShoesError) ?? .startFailed(error.localizedDescription)
            log.error("startTunnel failed: \(shoesError.localizedDescription, privacy: .public)")
            report(error: shoesError)
            throw shoesError
        }

        startHealthCheck()
        startPathObservation()
    }

    private func stop(reason: NEProviderStopReason) async {
        log.info("stopTunnel: \(reason.rawValue)")
        healthCheck?.cancel()
        healthCheck = nil
        rebind?.cancel()
        rebind = nil
        pathObservation?.cancel()
        pathObservation = nil
        // Awaited before the completion handler runs: the system may release
        // packetFlow's descriptor once it does, and the engine is reading it
        // until shoes_stop comes back. The five-second bound in the library
        // is what makes waiting here fit the platform's deadline.
        await engine.stop()
    }

    private func answer(_ messageData: Data) -> Data? {
        let reply = ShoesAppMessage.handle(messageData) { message in
            switch message {
            case .version: return .version(engine.version)
            case .status: return .status(running: engine.isRunning)
            case .stats: return .stats(engine.stats())
            case .setLogLevel(let level):
                do {
                    try engine.setLogLevel(level)
                    return .ok
                } catch {
                    return .error(error.localizedDescription)
                }
            }
        }
        return try? reply.encoded()
    }

    // MARK: Engine

    private func applySettingsAndStartEngine(_ config: ShoesConfiguration) async throws {
        try await setTunnelNetworkSettings(makeNetworkSettings())
        try startEngine(config)
    }

    private func startEngine(_ config: ShoesConfiguration) throws {
        guard let fd = packetFlow.value(forKeyPath: "socket.fileDescriptor") as? Int32, fd >= 0 else {
            throw ShoesError.tunnelDescriptorUnavailable
        }
        // The engine's callback is @Sendable and runs on a shoes worker
        // thread; the provider is actor-bound and not Sendable. A @MainActor
        // closure may capture it, and is itself Sendable, so that is what the
        // callback captures and hops through.
        let deliver: @MainActor @Sendable (UInt64, UInt64) -> Void = { [weak self] upload, download in
            self?.report(upload: upload, download: download)
        }
        try engine.start(config, deviceFD: fd) { upload, download in
            Task { @MainActor in deliver(upload, download) }
        }
        log.info("shoes \(self.engine.version, privacy: .public) started on fd \(fd)")
    }

    // MARK: Network changes

    /// `NEProvider.defaultPath` is deprecated from the OS versions this
    /// package requires, so the path comes from `NWPathMonitor` instead,
    /// delivered onto the actor through a stream.
    private func startPathObservation() {
        pathObservation?.cancel()
        let monitor = NWPathMonitor()
        let paths = AsyncStream<NWPath> { continuation in
            monitor.pathUpdateHandler = { continuation.yield($0) }
            continuation.onTermination = { _ in monitor.cancel() }
        }
        monitor.start(queue: DispatchQueue(label: "shoes.path-monitor"))
        pathObservation = Task { @MainActor [weak self] in
            // The first update is the current path, not a change.
            var first = true
            for await path in paths {
                if first {
                    first = false
                    continue
                }
                guard path.status == .satisfied else { continue }
                self?.recoverFromNetworkChange()
            }
        }
    }

    /// Ask the engine first. A UDP tunnel rebinds its endpoint in place and
    /// reports how many did; when that number is zero nothing recovered and
    /// the only recovery is a full rebind. The engine answers this, so the
    /// config is never inspected.
    private func recoverFromNetworkChange() {
        let rebound = engine.networkChanged()
        if rebound > 0 {
            log.info("engine rebound \(rebound) endpoint(s) in place")
            return
        }
        scheduleRebind()
    }

    /// Debounced: rapid path changes coalesce into one rebind.
    private func scheduleRebind() {
        rebind?.cancel()
        rebind = Task { @MainActor [weak self] in
            try? await Task.sleep(for: .milliseconds(500))
            guard !Task.isCancelled else { return }
            await self?.rebindTunnel()
        }
    }

    private func rebindTunnel() async {
        guard let config = configuration else { return }
        reasserting = true
        defer { reasserting = false }
        await engine.stop()
        do {
            // Nil then re-apply, so the system re-evaluates the default path.
            try await setTunnelNetworkSettings(nil)
            try await setTunnelNetworkSettings(makeNetworkSettings())
            try startEngine(config)
            log.info("rebind succeeded")
        } catch {
            let shoesError = (error as? ShoesError) ?? .startFailed(error.localizedDescription)
            log.error("rebind failed: \(shoesError.localizedDescription, privacy: .public)")
            report(error: shoesError)
            cancelTunnelWithError(shoesError)
        }
    }

    // MARK: Health

    private func startHealthCheck() {
        healthCheck?.cancel()
        let interval = healthCheckInterval
        healthCheck = Task { @MainActor [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: interval)
                guard let self, !Task.isCancelled else { return }
                if !self.engine.isRunning {
                    let reason = self.engine.lastError() ?? "engine stopped unexpectedly"
                    self.log.error("\(reason, privacy: .public)")
                    let error = ShoesError.engine(reason)
                    self.report(error: error)
                    self.cancelTunnelWithError(error)
                    return
                }
            }
        }
    }
}
