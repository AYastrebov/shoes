import Foundation
import Testing

@testable import ShoesTunnelCore

@Suite struct ShoesErrorTests {
    @Test func everyCaseRoundTrips() throws {
        let all: [ShoesError] = [
            .notInitialized, .alreadyRunning, .startFailed("no tun"), .tunnelDescriptorUnavailable,
            .timedOut(seconds: 14), .engine("shoes_set_log_level returned -1"),
            .noSession, .providerNoReply, .engineStopped("device gone"), .engineStopped(nil),
        ]
        for error in all {
            let data = try JSONEncoder().encode(error)
            #expect(try JSONDecoder().decode(ShoesError.self, from: data) == error)
        }
    }

    @Test func anUnknownKindThrows() {
        let data = Data("{\"kind\":\"meltdown\"}".utf8)
        #expect(throws: DecodingError.self) { try JSONDecoder().decode(ShoesError.self, from: data) }
    }

    @Test func descriptionsNameTheCondition() {
        #expect(ShoesError.noSession.localizedDescription == "no tunnel session")
        #expect(ShoesError.providerNoReply.localizedDescription == "provider gave no reply")
        #expect(ShoesError.engineStopped("x").localizedDescription == "shoes stopped: x")
        #expect(ShoesError.engineStopped(nil).localizedDescription == "shoes stopped")
    }
}
