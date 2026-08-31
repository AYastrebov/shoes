import Foundation

/// First-wins between racers: exactly one caller claims the right to
/// resume a continuation. An actor rather than a lock, so it needs no
/// unchecked Sendable of its own.
///
/// Shared by the provider's start race and the host's `send()` deadline —
/// a `CheckedContinuation` diagnoses a double resume, not a never-resume,
/// and this is the piece that rules the double out.
package actor ClaimFlag {
    private var claimed = false
    package init() {}
    package func claim() -> Bool {
        if claimed { return false }
        claimed = true
        return true
    }
}

/// Whole seconds of a `Duration` for an error message, rounded up so a
/// sub-second timeout does not report "timed out after 0s".
package func wholeSeconds(_ duration: Duration) -> Int {
    let parts = duration.components
    return Int(parts.seconds) + (parts.attoseconds > 0 ? 1 : 0)
}
