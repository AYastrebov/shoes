import Foundation
import Testing

@testable import ShoesTunnel

/// Against the real library. shoes_init is process-global and idempotent,
/// so the suite is serialized and every test may initialize.
@Suite(.serialized) struct ShoesEngineTests {
    let engine = ShoesEngine.shared

    @Test func versionIsSemver() throws {
        try engine.initialize(logLevel: .error)
        let parts = engine.version.split(separator: ".")
        #expect(parts.count >= 2, "got \(engine.version)")
    }

    @Test func initializeIsIdempotent() throws {
        try engine.initialize(logLevel: .error)
        try engine.initialize(logLevel: .info)
    }

    @Test func isNotRunningBeforeStart() throws {
        try engine.initialize(logLevel: .error)
        #expect(engine.isRunning == false)
    }

    @Test func aConfigWithoutATunSectionIsRefusedWithAReason() async throws {
        try engine.initialize(logLevel: .error)
        let config = ShoesConfiguration(yaml: "---\n[]\n")
        let error = await #expect(throws: ShoesError.self) {
            try await engine.start(config, deviceFD: 7, onTraffic: { _, _ in }, onStopped: { _ in })
        }
        guard case .startFailed(let reason) = error else {
            Issue.record("expected .startFailed, got \(String(describing: error))")
            return
        }
        #expect(reason.contains("No TUN config found"), "got: \(reason)")
        #expect(engine.isRunning == false)
    }

    @Test func statsBeforeStartAreZero() throws {
        try engine.initialize(logLevel: .error)
        let stats = try #require(engine.stats())
        #expect(stats.uploadBytes == 0)
        #expect(stats.activeConnections == 0)
    }

    /// The tests link the release-mobile XCFramework, which compiles with
    /// `release_max_level_info`.
    @Test func maxLogLevelIsTheReleaseCeiling() throws {
        try engine.initialize(logLevel: .error)
        #expect(engine.maxLogLevel == .info)
    }

    @Test func networkChangedIsSafeWhenIdle() throws {
        try engine.initialize(logLevel: .error)
        #expect(engine.networkChanged() == 0)
    }

    /// With no session there is no id to pass; the wrapper passes 0 and
    /// the library reports released, since nothing of ours is running.
    @Test func stopIsSafeWhenNothingRuns() async throws {
        try engine.initialize(logLevel: .error)
        let released = await engine.stop()
        #expect(released == true)
        #expect(engine.isRunning == false)
    }

    @Test func startBeforeInitializeIsRefused() async {
        // `initialized` is an engine-side flag; the FFI itself would also
        // refuse, but this is the error a host should see first.
        let fresh = ShoesEngine(forTesting: ())
        await #expect(throws: ShoesError.notInitialized) {
            try await fresh.start(
                ShoesConfiguration(yaml: ""), deviceFD: 7, onTraffic: { _, _ in }, onStopped: { _ in })
        }
    }

    @Test func aFailedStartNeverReportsAStop() async throws {
        try engine.initialize(logLevel: .error)
        let fired = Fired()
        let config = ShoesConfiguration(yaml: "---\n[]\n")
        _ = await #expect(throws: ShoesError.self) {
            try await engine.start(config, deviceFD: 7, onTraffic: { _, _ in }, onStopped: { _ in fired.set() })
        }
        try await Task.sleep(for: .milliseconds(100))
        #expect(fired.isSet == false)
    }
}

/// A stop that lands while the native start is still running waits for it
/// and then stops the session that start made, rather than passing 0 and
/// stopping nothing: the user disconnecting while still connecting.
@Test func aStopDuringAStartWaitsForItAndStopsThatSession() async throws {
    let stops = Recorded()
    let engine = ShoesEngine(
        forTesting: (),
        start: { _, _ in
            Thread.sleep(forTimeInterval: 0.3)
            return 7
        },
        stop: { handle in
            stops.append(handle)
            return 1
        })
    try engine.initialize(logLevel: .error)
    let config = ShoesConfiguration(yaml: "tun:\n  device_fd: 7\n")
    async let started: Void = engine.start(
        config, deviceFD: 7, onTraffic: { _, _ in }, onStopped: { _ in })
    try await Task.sleep(for: .milliseconds(50))
    let released = await engine.stop()
    try await started
    #expect(released == true)
    #expect(stops.values == [7])
}

/// Two stops that overlap share one native stop: the second waits for the
/// first and reports its result, rather than taking a 0 handle and
/// reporting "released" while the engine still reads the descriptor.
@Test func overlappingStopsShareOneNativeStop() async throws {
    let stops = Recorded()
    let engine = ShoesEngine(
        forTesting: (),
        start: { _, _ in 7 },
        stop: { handle in
            stops.append(handle)
            Thread.sleep(forTimeInterval: 0.3)
            return 1
        })
    try engine.initialize(logLevel: .error)
    let config = ShoesConfiguration(yaml: "tun:\n  device_fd: 7\n")
    try await engine.start(config, deviceFD: 7, onTraffic: { _, _ in }, onStopped: { _ in })
    let began = ContinuousClock.now
    async let first = engine.stop()
    try await Task.sleep(for: .milliseconds(50))
    async let second = engine.stop()
    let (a, b) = await (first, second)
    let elapsed = ContinuousClock.now - began
    #expect(a == true)
    #expect(b == true)
    #expect(stops.values == [7])
    #expect(elapsed >= .milliseconds(300))
}

/// A second start while one is in flight is refused by the wrapper, before
/// it can replace the registered start a stop must wait for: the first
/// start's session is what a stop then stops.
@Test func aSecondStartWhileOneIsInFlightIsRefused() async throws {
    let starts = Recorded()
    let stops = Recorded()
    let engine = ShoesEngine(
        forTesting: (),
        start: { _, _ in
            starts.append(0)
            if starts.values.count == 1 {
                Thread.sleep(forTimeInterval: 0.3)
                return 7
            }
            return -1
        },
        stop: { handle in
            stops.append(handle)
            return 1
        })
    try engine.initialize(logLevel: .error)
    let config = ShoesConfiguration(yaml: "tun:\n  device_fd: 7\n")
    async let first: Void = engine.start(
        config, deviceFD: 7, onTraffic: { _, _ in }, onStopped: { _ in })
    try await Task.sleep(for: .milliseconds(50))
    await #expect(throws: ShoesError.alreadyRunning) {
        try await engine.start(config, deviceFD: 7, onTraffic: { _, _ in }, onStopped: { _ in })
    }
    let released = await engine.stop()
    try await first
    #expect(released == true)
    #expect(stops.values == [7])
}

/// A stop task is not reused once its session is gone: a session started
/// while the previous stop's native call is returning gets its own stop.
@Test func aStopAfterANewStartStopsTheNewSession() async throws {
    let stops = Recorded()
    let firstStopEntered = Fired()
    let engine = ShoesEngine(
        forTesting: (),
        start: { _, _ in stops.values.isEmpty ? 7 : 8 },
        stop: { handle in
            stops.append(handle)
            if handle == 7 {
                firstStopEntered.set()
                // The native stop has done its work; the wrapper's
                // continuation has not run yet.
                Thread.sleep(forTimeInterval: 0.3)
            }
            return 1
        })
    try engine.initialize(logLevel: .error)
    let config = ShoesConfiguration(yaml: "tun:\n  device_fd: 7\n")
    try await engine.start(config, deviceFD: 7, onTraffic: { _, _ in }, onStopped: { _ in })
    async let firstStop = engine.stop()
    while !firstStopEntered.isSet { try await Task.sleep(for: .milliseconds(10)) }
    try await engine.start(config, deviceFD: 7, onTraffic: { _, _ in }, onStopped: { _ in })
    let secondStop = await engine.stop()
    _ = await firstStop
    #expect(secondStop == true)
    #expect(stops.values == [7, 8])
}

/// Handles passed to a stop, readable from any thread.
private final class Recorded: @unchecked Sendable {
    private let lock = NSLock()
    private var handles: [Int] = []
    var values: [Int] { lock.withLock { handles } }
    func append(_ handle: Int) { lock.withLock { handles.append(handle) } }
}

/// A set-once flag readable from any thread, for the test above.
private final class Fired: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false
    var isSet: Bool { lock.withLock { value } }
    func set() { lock.withLock { value = true } }
}
