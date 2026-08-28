import Testing

@testable import ShoesTunnelCore

/// The document `shoes_get_stats` returns, as described on that function in
/// include/shoes.h. Later releases may add keys, and a host must ignore ones
/// it does not know.
@Suite struct ShoesStatsTests {
    @Test func decodesTheDocumentedShape() throws {
        let json = """
            {"upload_bytes":10,"download_bytes":20,"active_connections":3,
             "outbounds":[{"name":"Frankfurt","upload_bytes":1,"download_bytes":2,
                           "active_connections":1}]}
            """
        let stats = try ShoesStats.decode(json)
        #expect(stats.uploadBytes == 10)
        #expect(stats.downloadBytes == 20)
        #expect(stats.activeConnections == 3)
        #expect(
            stats.outbounds == [
                ShoesStats.Outbound(name: "Frankfurt", uploadBytes: 1, downloadBytes: 2, activeConnections: 1)
            ])
    }

    @Test func ignoresKeysItDoesNotKnow() throws {
        let json = """
            {"upload_bytes":0,"download_bytes":0,"active_connections":0,"outbounds":[],
             "uptime_seconds":12}
            """
        let stats = try ShoesStats.decode(json)
        #expect(stats.outbounds.isEmpty)
    }

    @Test func refusesAMalformedDocument() {
        #expect(throws: (any Error).self) {
            try ShoesStats.decode("{\"upload_bytes\":")
        }
    }
}
