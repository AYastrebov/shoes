import Foundation
import Testing

@testable import ShoesTunnelCore

/// Against a plain suite name rather than a real App Group: `UserDefaults`
/// treats any suite the same way outside the sandboxed-entitlement check,
/// which is a device-only concern. The suite is cleaned before and after.
@Suite(.serialized) struct ShoesErrorStoreTests {
    private static let suite = "shoes-error-store-tests"

    private func freshStore() -> ShoesErrorStore {
        UserDefaults(suiteName: Self.suite)?.removePersistentDomain(forName: Self.suite)
        return ShoesErrorStore(appGroup: Self.suite)!
    }

    @Test func aSavedErrorRoundTripsAndClears() {
        let store = freshStore()
        #expect(store.load() == nil)

        store.save(.engineStopped("the peer vanished"))
        #expect(store.load() == .engineStopped("the peer vanished"))

        store.clear()
        #expect(store.load() == nil)
    }

    @Test func theNilReasonCaseSurvivesTheRoundTrip() {
        let store = freshStore()
        store.save(.engineStopped(nil))
        #expect(store.load() == .engineStopped(nil))
    }

    @Test func aStopReasonIsStoredAsItsRawValue() {
        let store = freshStore()
        #expect(store.loadStopReason() == nil)

        store.saveStopReason(2)  // NEProviderStopReason.userInitiated
        #expect(store.loadStopReason() == 2)

        store.clearStopReason()
        #expect(store.loadStopReason() == nil)
    }
}
