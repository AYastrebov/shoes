import Foundation
import Network
@preconcurrency import NetworkExtension
import os

/// An `NEPacketTunnelProvider` that runs shoes.
///
/// A template method: this class owns the sequence -- settings, descriptor,
/// engine, the engine's stop callback, path observation, and the ordering against
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
/// access. This and `CallbackBridge` are the package's two escape
/// hatches, and each says why.
@MainActor
open class ShoesPacketTunnelProvider: NEPacketTunnelProvider, @unchecked Sendable {

    // MARK: Hooks

    /// The config to run. Called on every start and on every full rebind.
    /// Throw to fail the start with that error. `async` so a slow source --
    /// a file, a keychain -- need not block the actor; a sync body is fine.
    open func loadConfiguration() async throws -> ShoesConfiguration {
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
    /// rebind, and an engine that stopped on its own. After that last one the
    /// provider cancels the tunnel and the extension process exits, so a host
    /// that needs the reason in the app must persist it from here; the
    /// `.lastError` message cannot answer once the process is gone, and a
    /// Rust panic aborts the process with no hook at all.
    open func report(error: ShoesError) {}

    /// Cumulative bytes, about once a second while they change. The engine
    /// produces them on a worker thread; they arrive here on the actor.
    open func report(upload: UInt64, download: UInt64) {}

    // MARK: Tunables

    /// How long `startTunnel` may take before it fails itself. The system's
    /// own limit is about a minute; failing earlier makes the reason ours.
    open var startTimeout: Duration { .seconds(14) }

    // MARK: State

    private let log = Logger(subsystem: "shoes", category: "ShoesPacketTunnelProvider")
    private let engine = ShoesEngine.shared
    private var configuration: ShoesConfiguration?
    /// What `report(error:)` last carried; answers `.lastError`.
    private var lastError: ShoesError?
    private var pathObservation: Task<Void, Never>?
    private var rebind: Task<Void, Never>?
    private var isRebinding = false
    private var isStopping = false

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

        let config = try await loadConfiguration()
        configuration = config
        try engine.initialize(logLevel: config.logLevel)
        lastError = nil
        isStopping = false

        do {
            // Raced against the timeout, first-wins: a task group would
            // await its children on exit, and the engine call cannot be
            // cancelled mid-C, so the race is by continuation instead --
            // the timeout genuinely bounds startTunnel. Work that finishes
            // after losing the race is cleaned up below, so a tunnel that
            // came up late does not linger behind a failed start.
            let limit = startTimeout
            let work = Task { @MainActor in
                try await self.applySettingsAndStartEngine(config)
            }
            let claim = ClaimFlag()
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, any Error>) in
                Task { @MainActor in
                    do {
                        try await work.value
                        if await claim.claim() { cont.resume() }
                    } catch {
                        if await claim.claim() { cont.resume(throwing: error) }
                    }
                }
                Task {
                    try? await Task.sleep(for: limit)
                    if await claim.claim() {
                        cont.resume(throwing: ShoesError.timedOut(seconds: Int(limit.components.seconds)))
                    }
                }
            }
        } catch {
            let shoesError = (error as? ShoesError) ?? .startFailed(error.localizedDescription)
            log.error("startTunnel failed: \(shoesError.localizedDescription, privacy: .public)")
            lastError = shoesError
            report(error: shoesError)
            if case .timedOut = shoesError {
                // The engine call may still be running and may yet succeed;
                // stop whatever it produces once it lands.
                Task { @MainActor in
                    if self.engine.isRunning { await self.engine.stop() }
                }
            }
            throw shoesError
        }

        startPathObservation()
    }

    private func stop(reason: NEProviderStopReason) async {
        log.info("stopTunnel: \(reason.rawValue)")
        isStopping = true
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
            case .lastError: return .lastError(lastError)
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
        try await startEngine(config)
    }

    private func startEngine(_ config: ShoesConfiguration) async throws {
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
        let stopped: @MainActor @Sendable (String?) -> Void = { [weak self] reason in
            self?.engineStopped(reason: reason)
        }
        try await engine.start(
            config, deviceFD: fd,
            onTraffic: { upload, download in Task { @MainActor in deliver(upload, download) } },
            onStopped: { reason in Task { @MainActor in stopped(reason) } })
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
        // One at a time. The actor is reentrant at every await below, so a
        // second debounced rebind could otherwise interleave with this one.
        guard !isRebinding else { return }
        isRebinding = true
        reasserting = true
        defer {
            isRebinding = false
            reasserting = false
        }
        await engine.stop()
        do {
            // Nil then re-apply, so the system re-evaluates the default path.
            try await setTunnelNetworkSettings(nil)
            try await setTunnelNetworkSettings(makeNetworkSettings())
            try await startEngine(config)
            log.info("rebind succeeded")
        } catch {
            let shoesError = (error as? ShoesError) ?? .startFailed(error.localizedDescription)
            log.error("rebind failed: \(shoesError.localizedDescription, privacy: .public)")
            lastError = shoesError
            report(error: shoesError)
            cancelTunnelWithError(shoesError)
        }
    }

    // MARK: Engine exit

    /// The engine stopped and nobody asked it to. A rebind stops the engine
    /// on purpose and the library clears its slot before that stop, so this
    /// does not fire for one; the checks are for the window between a
    /// stopTunnel or rebind beginning on the actor and the C call landing.
    private func engineStopped(reason: String?) {
        if isRebinding || isStopping { return }
        let error = ShoesError.engineStopped(reason)
        log.error("\(error.localizedDescription, privacy: .public)")
        lastError = error
        report(error: error)
        cancelTunnelWithError(error)
    }
}

/// First-wins for the start race: exactly one of the two racers resumes the
/// continuation. An actor rather than a lock, so it needs no unchecked
/// Sendable of its own.
private actor ClaimFlag {
    private var claimed = false
    func claim() -> Bool {
        if claimed { return false }
        claimed = true
        return true
    }
}
