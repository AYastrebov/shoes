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

    @Test func networkChangedIsSafeWhenIdle() throws {
        try engine.initialize(logLevel: .error)
        #expect(engine.networkChanged() == 0)
    }

    @Test func stopIsSafeWhenNothingRuns() async throws {
        try engine.initialize(logLevel: .error)
        await engine.stop()
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

/// A set-once flag readable from any thread, for the test above.
private final class Fired: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false
    var isSet: Bool { lock.withLock { value } }
    func set() { lock.withLock { value = true } }
}
