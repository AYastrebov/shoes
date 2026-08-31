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
    /// that needs the reason in the app must persist it from here --
    /// **synchronously, before returning**: the process can be gone before a
    /// `Task` this hook spawns ever runs. `ShoesErrorStore` in
    /// `ShoesTunnelCore` is a ready-made synchronous store. The `.lastError`
    /// message cannot answer once the process is gone, and a Rust panic
    /// aborts the process with no hook at all.
    open func report(error: ShoesError) {}

    /// Why the system stopped the tunnel. Called at the top of `stopTunnel`,
    /// before teardown. The reason is otherwise discarded, and the app cannot
    /// reconstruct it: user-stop, engine-death, and a system kill all collapse
    /// to `.disconnected` on the app's side. Persist it here (synchronously,
    /// like `report(error:)`) if the app needs to tell them apart.
    open func report(stopReason: NEProviderStopReason) {}

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
    /// A rebind is scheduled or executing. Separate from `rebind` (the task
    /// handle, which lingers after completion) because `engineStopped` reads
    /// it to tell a death recovery is already underway.
    private var rebindPending = false
    /// A path change arrived while a rebind was executing; run another when
    /// it finishes rather than dropping the newer path on the floor.
    private var rebindAgain = false
    /// Which engine start the stopped callback belongs to. The callback's
    /// delivery hops through a Task, so an old session's death can land after
    /// the next session started; the stamp is what makes "cleared before the
    /// stop" actually hold at the point of delivery.
    private var session = 0

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

    /// Overridden as an immediate completion so the system treats this
    /// provider as sleep-aware: `wake()` is only delivered to providers
    /// that answered `sleep`, and wake-time recovery is where a tunnel
    /// suspended for hours gets its path back. There is nothing to do at
    /// sleep itself -- the engine's timers run on clocks that stop with
    /// the machine.
    nonisolated open override func sleep(completionHandler: @escaping () -> Void) {
        nonisolated(unsafe) let done = completionHandler
        Task { @MainActor in
            self.log.info("sleep")
            done()
        }
    }

    nonisolated open override func wake() {
        Task { @MainActor in
            self.log.info("wake")
            // Guarded: a wake on a provider that is stopping (or never
            // started) must not schedule a rebind that would restart the
            // engine into a tunnel on its way down.
            guard !self.isStopping, self.configuration != nil else { return }
            self.recoverFromNetworkChange()
        }
    }

    nonisolated open override func handleAppMessage(_ messageData: Data) async -> Data? {
        await answer(messageData)
    }

    // MARK: Lifecycle, on the actor

    private func start() async throws {
        log.info("startTunnel")
        // A rebind left over from a previous session must not survive into
        // this one: drained before the engine check below, so an engine it
        // was in the middle of starting is the one that check stops.
        let pendingRebind = rebind
        rebind = nil
        pendingRebind?.cancel()
        await pendingRebind?.value
        // A previous session, if the system is reasserting after sleep.
        // Awaited, not blocked on: shoes_stop can take up to five seconds.
        if engine.isRunning { await engine.stop() }

        lastError = nil
        isStopping = false
        rebindPending = false
        rebindAgain = false

        do {
            // Raced against the timeout, first-wins: a task group would
            // await its children on exit, and the engine call cannot be
            // cancelled mid-C, so the race is by continuation instead --
            // the timeout genuinely bounds startTunnel. Work that finishes
            // after losing the race is cleaned up below, so a tunnel that
            // came up late does not linger behind a failed start.
            //
            // loadConfiguration is inside the raced work: it is an open
            // hook whose doc invites a slow source, and outside the race a
            // hung keychain or network read kept startTunnel past this
            // timeout's whole point, until the system's own ~60 s kill.
            let limit = startTimeout
            let work = Task { @MainActor in
                let config = try await self.loadConfiguration()
                self.configuration = config
                try self.engine.initialize(logLevel: config.logLevel)
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
            fail(shoesError, prefix: "startTunnel failed")
            if case .timedOut = shoesError {
                // The engine call may still be running and may yet succeed;
                // stop whatever it produces once it lands. The session is
                // abandoned either way, so a death it reports before that
                // stop is not a second error.
                isStopping = true
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
        // Before teardown, while the process is certain to still be here:
        // the app cannot reconstruct this reason later.
        report(stopReason: reason)
        isStopping = true
        rebindPending = false
        rebindAgain = false
        let pendingRebind = rebind
        rebind = nil
        pendingRebind?.cancel()
        pathObservation?.cancel()
        pathObservation = nil
        // Awaited, not just cancelled: cancellation is cooperative, and a
        // rebind suspended inside the engine start observes nothing until
        // that call returns -- returning from here before it does would
        // let the engine come up on packetFlow's descriptor after the
        // system reclaimed it. rebindTunnel sees isStopping (set above,
        // before this suspension) at its next checkpoint and stops any
        // engine it started, so by the time this returns nothing runs.
        await pendingRebind?.value
        // The system may release packetFlow's descriptor once stopTunnel's
        // completion handler runs, and the engine reads it until
        // shoes_stop comes back. The five-second bound in the library is
        // what makes waiting here fit the platform's deadline.
        let released = await engine.stop()
        if !released {
            // Nothing good is left to do -- returning is what lets the
            // system proceed -- but the fact belongs in the log rather
            // than discarded: a descriptor torn down under a live reader
            // is the first suspect for the next session's mystery.
            log.error("engine stop timed out; the descriptor may still be held")
        }
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
                    let shoesError = (error as? ShoesError) ?? .engine(error.localizedDescription)
                    record(shoesError)
                    return .error(shoesError.localizedDescription)
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
        // Stamped per engine start: the delivery hops through a Task, so a
        // dying session's event can land after the next session started;
        // the stamp lets engineStopped ignore it.
        session += 1
        let thisSession = session
        let stopped: @MainActor @Sendable (String?) -> Void = { [weak self] reason in
            self?.engineStopped(reason: reason, session: thisSession)
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
        rebindPending = true
        rebind?.cancel()
        rebind = Task { @MainActor [weak self] in
            try? await Task.sleep(for: .milliseconds(500))
            guard !Task.isCancelled else { return }
            await self?.rebindTunnel()
        }
    }

    private func rebindTunnel() async {
        guard let config = configuration, !isStopping else {
            rebindPending = false
            return
        }
        // One at a time. The actor is reentrant at every await below, so a
        // second debounced rebind could otherwise interleave with this one.
        // A change that lands mid-rebind is remembered and run after --
        // Wi-Fi to cellular and back inside one rebind's span used to leave
        // the tunnel bound to the intermediate path with nothing left to
        // notice. And never against a stop: `stop()` cancels the debounce
        // task, but a rebind past that point used to run to completion
        // regardless -- restarting the engine after `stopTunnel`'s
        // completion handler had returned, on a descriptor the system was
        // free to reclaim.
        guard !isRebinding else {
            rebindAgain = true
            return
        }
        isRebinding = true
        reasserting = true
        defer {
            isRebinding = false
            reasserting = false
            if rebindAgain, !isStopping {
                rebindAgain = false
                scheduleRebind()
            } else {
                rebindPending = false
            }
        }
        await engine.stop()
        guard !isStopping else { return }
        do {
            // Nil then re-apply, so the system re-evaluates the default path.
            try await setTunnelNetworkSettings(nil)
            guard !isStopping else { return }
            try await setTunnelNetworkSettings(makeNetworkSettings())
            guard !isStopping else { return }
            try await startEngine(config)
            if isStopping {
                // stopTunnel ran while the engine was starting, so its own
                // stop saw nothing running. Undo the start it could not see.
                await engine.stop()
                return
            }
            log.info("rebind succeeded")
        } catch {
            // A stop tearing the tunnel down mid-rebind makes these calls
            // fail; that is the stop's outcome, not a rebind failure.
            guard !isStopping else { return }
            let shoesError = (error as? ShoesError) ?? .startFailed(error.localizedDescription)
            fail(shoesError, prefix: "rebind failed")
            cancelTunnelWithError(shoesError)
        }
    }

    // MARK: Engine exit

    /// The engine stopped and nobody asked it to.
    ///
    /// Three deaths are not the tunnel's end. A stale session's -- the
    /// stamp catches an event whose Task hop outlived its engine. A death
    /// while the host's own stop runs -- that stop's reason is known. And
    /// a death while a rebind is scheduled or executing: a path change
    /// that killed the engine is the event the rebind exists to recover
    /// from, and cancelling the tunnel here raced the recovery to the
    /// finish -- the most common mobile event tore the tunnel down when a
    /// half-second's patience would have carried it across.
    private func engineStopped(reason: String?, session: Int) {
        guard session == self.session else { return }
        if isStopping { return }
        if rebindPending {
            record(.engineStopped(reason))
            log.info("engine died with a rebind underway; letting the rebind recover")
            return
        }
        let error = ShoesError.engineStopped(reason)
        fail(error, prefix: "engine stopped")
        cancelTunnelWithError(error)
    }

    // MARK: Errors

    /// Remember an error for `.lastError` and log it.
    private func record(_ error: ShoesError) {
        log.error("\(error.localizedDescription, privacy: .public)")
        lastError = error
    }

    /// Remember, log, and hand to the host.
    private func fail(_ error: ShoesError, prefix: String) {
        log.error("\(prefix): \(error.localizedDescription, privacy: .public)")
        lastError = error
        report(error: error)
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
