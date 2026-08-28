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

    @Test func aConfigWithoutATunSectionIsRefusedWithAReason() throws {
        try engine.initialize(logLevel: .error)
        let config = ShoesConfiguration(yaml: "---\n[]\n")
        let error = #expect(throws: ShoesError.self) {
            try engine.start(config, deviceFD: 7) { _, _ in }
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

    @Test func startBeforeInitializeIsRefused() {
        // `initialized` is an engine-side flag; the FFI itself would also
        // refuse, but this is the error a host should see first.
        let fresh = ShoesEngine(forTesting: ())
        #expect(throws: ShoesError.notInitialized) {
            try fresh.start(ShoesConfiguration(yaml: ""), deviceFD: 7) { _, _ in }
        }
    }
}
