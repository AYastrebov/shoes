import Foundation
import Testing

@testable import ShoesTunnelCore

/// Against the directory initializer with a per-run temporary directory:
/// the App Group initializer only differs in how it resolves the
/// directory, and container resolution is a device-entitlement concern no
/// unit test can exercise honestly.
@Suite struct ShoesErrorStoreTests {

    private func freshStore() throws -> ShoesErrorStore {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("shoes-error-store-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return ShoesErrorStore(directory: dir)
    }

    @Test func aSavedErrorRoundTripsAndClears() throws {
        let store = try freshStore()
        #expect(store.load() == nil)

        #expect(store.save(.engineStopped("the peer vanished")))
        #expect(store.load() == .engineStopped("the peer vanished"))

        store.clear()
        #expect(store.load() == nil)
    }

    @Test func theNilReasonCaseSurvivesTheRoundTrip() throws {
        let store = try freshStore()
        store.save(.engineStopped(nil))
        #expect(store.load() == .engineStopped(nil))
    }

    @Test func aStopReasonIsStoredAsItsRawValue() throws {
        let store = try freshStore()
        #expect(store.loadStopReason() == nil)

        store.saveStopReason(2)  // NEProviderStopReason.userInitiated
        #expect(store.loadStopReason() == 2)

        store.clearStopReason()
        #expect(store.loadStopReason() == nil)
    }

    /// The write must survive the writing process: a second store over the
    /// same directory -- a stand-in for the app process reading after the
    /// extension died -- sees the error. This is the property UserDefaults
    /// could not promise (its set() is an in-process cache ahead of a
    /// deferred cfprefsd push) and the reason the store is file-backed.
    @Test func theErrorIsReadableThroughAFreshStoreOverTheSameDirectory() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("shoes-error-store-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

        ShoesErrorStore(directory: dir).save(.engineStopped("died"))
        #expect(ShoesErrorStore(directory: dir).load() == .engineStopped("died"))
    }
}
