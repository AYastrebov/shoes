import Foundation
import Testing

@testable import ShoesTunnel

/// The bridge is the crux of the stopped-callback design: the C side may
/// misbehave, the take-slot is what guarantees the host sees at most one
/// stop per session. Each test builds its OWN bridge: the semantics under
/// test are per-instance, and `.shared` is process-global state that
/// ShoesEngineTests drives concurrently -- `.serialized` only orders a
/// suite internally, so touching the singleton here raced their
/// install/clear cycles and failed at random (AGENTS.md: scope the
/// effect, do not serialize around global state).
@Suite struct CallbackBridgeTests {

    @Test func aStopDeliversAtMostOncePerInstall() {
        let bridge = CallbackBridge()

        let deliveries = Counter()
        bridge.install(traffic: { _, _ in }, stopped: { _ in deliveries.increment() })

        bridge.deliverStopped(reason: "died")
        bridge.deliverStopped(reason: "died again")
        #expect(deliveries.value == 1, "the slot is taken, not read")
    }

    @Test func aClearedBridgeDeliversNothing() {
        let bridge = CallbackBridge()

        let deliveries = Counter()
        bridge.install(traffic: { _, _ in deliveries.increment() }, stopped: { _ in deliveries.increment() })
        bridge.clear()

        bridge.deliver(upload: 1, download: 2)
        bridge.deliverStopped(reason: nil)
        #expect(deliveries.value == 0)
    }

    @Test func aReinstallRearmsTheStoppedSlot() {
        let bridge = CallbackBridge()

        let reasons = Reasons()
        bridge.install(traffic: { _, _ in }, stopped: { reasons.append($0) })
        bridge.deliverStopped(reason: "first session")
        // A new session installs fresh handlers; its death must deliver
        // even though the previous session's slot was consumed.
        bridge.install(traffic: { _, _ in }, stopped: { reasons.append($0) })
        bridge.deliverStopped(reason: "second session")

        #expect(reasons.values == ["first session", "second session"])
    }

    @Test func trafficDeliversRepeatedlyAndInOrder() {
        let bridge = CallbackBridge()

        let totals = Counter()
        bridge.install(traffic: { up, down in totals.add(Int(up + down)) }, stopped: { _ in })
        bridge.deliver(upload: 1, download: 2)
        bridge.deliver(upload: 3, download: 4)
        #expect(totals.value == 10, "traffic is a stream, not a one-shot")
    }
}

/// Thread-safe accumulators: the bridge calls handlers on the caller's
/// thread here, but the closures must still be @Sendable.
private final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    var value: Int { lock.withLock { count } }
    func increment() { lock.withLock { count += 1 } }
    func add(_ n: Int) { lock.withLock { count += n } }
}

private final class Reasons: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: [String?] = []
    var values: [String?] { lock.withLock { stored } }
    func append(_ reason: String?) { lock.withLock { stored.append(reason) } }
}
