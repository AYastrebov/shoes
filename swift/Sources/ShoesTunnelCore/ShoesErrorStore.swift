import Foundation

/// Synchronous persistence for the one error that must outlive the process.
///
/// The provider's docs tell every host to persist a fatal reason from
/// `report(error:)` -- the extension exits right after it, so nothing
/// asynchronous is guaranteed to run, and `.lastError` cannot answer once
/// the process is gone. This is the ready-made way to do it: an App Group
/// `UserDefaults` write, synchronous by nature, readable from the app
/// through the same suite.
///
/// ```swift
/// // In the provider subclass:
/// let store = ShoesErrorStore(appGroup: "group.example.shoes")
/// override func report(error: ShoesError) { store?.save(error) }
/// override func report(stopReason: NEProviderStopReason) {
///     store?.saveStopReason(stopReason.rawValue)
/// }
///
/// // In the app, when the session shows .disconnected:
/// let why = store?.load()
/// ```
///
/// `@unchecked Sendable`: `UserDefaults` is documented thread-safe; the
/// stored reference is immutable.
public final class ShoesErrorStore: @unchecked Sendable {
    private let defaults: UserDefaults
    private let errorKey: String
    private let stopReasonKey: String

    /// `nil` when the App Group suite cannot be opened -- a misspelled
    /// group, or an entitlement the target does not carry.
    public init?(
        appGroup: String,
        errorKey: String = "shoes.lastFatalError",
        stopReasonKey: String = "shoes.lastStopReason"
    ) {
        guard let defaults = UserDefaults(suiteName: appGroup) else { return nil }
        self.defaults = defaults
        self.errorKey = errorKey
        self.stopReasonKey = stopReasonKey
    }

    /// Persist a fatal error. Synchronous; safe to call from
    /// `report(error:)` right before the process exits.
    public func save(_ error: ShoesError) {
        guard let data = try? JSONEncoder().encode(error) else { return }
        defaults.set(data, forKey: errorKey)
    }

    /// The last persisted error, if any. Typically read by the app when the
    /// session goes `.disconnected` without the user asking.
    public func load() -> ShoesError? {
        guard let data = defaults.data(forKey: errorKey) else { return nil }
        return try? JSONDecoder().decode(ShoesError.self, from: data)
    }

    /// Forget the persisted error -- call once the app has shown it.
    public func clear() {
        defaults.removeObject(forKey: errorKey)
    }

    /// Persist why the system stopped the tunnel, as
    /// `NEProviderStopReason.rawValue`. An `Int` rather than the enum so
    /// this target needs no NetworkExtension dependency.
    public func saveStopReason(_ rawValue: Int) {
        defaults.set(rawValue, forKey: stopReasonKey)
    }

    /// The last persisted stop reason's `rawValue`, or `nil` when none was
    /// saved. Rebuild with `NEProviderStopReason(rawValue:)` on the app side.
    public func loadStopReason() -> Int? {
        defaults.object(forKey: stopReasonKey) as? Int
    }

    /// Forget the persisted stop reason.
    public func clearStopReason() {
        defaults.removeObject(forKey: stopReasonKey)
    }
}
