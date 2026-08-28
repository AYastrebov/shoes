import Foundation
import Testing

@testable import ShoesTunnelCore

@Suite struct ShoesAppMessageTests {
    @Test func messagesRoundTrip() throws {
        for message in [ShoesAppMessage.version, .status, .stats, .lastError, .setLogLevel(.debug)] {
            let data = try message.encoded()
            #expect(try ShoesAppMessage.decode(data) == message)
        }
    }

    @Test func repliesRoundTrip() throws {
        let stats = ShoesStats(uploadBytes: 1, downloadBytes: 2, activeConnections: 0, outbounds: [])
        for reply in [
            ShoesAppReply.version("0.2.15"), .status(running: true), .stats(stats), .stats(nil),
            .lastError(.engineStopped("x")), .lastError(nil), .ok, .error("x"),
        ] {
            let data = try reply.encoded()
            #expect(try ShoesAppReply.decode(data) == reply)
        }
    }

    @Test func anUnknownRequestBecomesAnErrorReplyNotACrash() {
        let garbage = Data("{\"kind\":\"reboot\"}".utf8)
        let reply = ShoesAppMessage.handle(garbage) { _ in .ok }
        guard case .error = reply else {
            Issue.record("expected .error, got \(reply)")
            return
        }
    }
}
