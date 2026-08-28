// A link-check fixture, not an example. It is the smallest executable that
// links ShoesTunnelHost with the host surface live; mobile.yml builds it
// for the iOS Simulator in Release and asserts no shoes_* symbol survives.
import ShoesTunnelHost

@MainActor
func run() async {
    let tunnel = ShoesTunnelManager(providerBundleIdentifier: "com.example.linkcheck.tunnel")
    do {
        let reply = try await tunnel.send(.stats)
        print("reply: \(reply)")
    } catch {
        print("expected outside a VPN session: \(error)")
    }
}

await run()
