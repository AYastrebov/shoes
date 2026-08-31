import Foundation

/// Synchronous persistence for the one error that must outlive the process.
///
/// The provider's docs tell every host to persist a fatal reason from
/// `report(error:)` -- the extension exits right after it, so nothing
/// asynchronous is guaranteed to run, and `.lastError` cannot answer once
/// the process is gone.
///
/// Atomic file writes into the App Group container, not `UserDefaults`:
/// `set(_:forKey:)` only updates the in-process cache and pushes to
/// `cfprefsd` on a deferred, coalesced schedule -- an extension SIGKILLed
/// right after `stopTunnel` completes runs no exit flush, and the one
/// error this store exists to preserve was the write most likely to be
/// lost. `Data.write(to:options:.atomic)` has the durability the job
/// needs and the same synchronous shape.
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
/// `@unchecked Sendable`: the stored URLs are immutable, and the file
/// system serializes the atomic replace.
public final class ShoesErrorStore: @unchecked Sendable {
    private let errorURL: URL
    private let stopReasonURL: URL

    /// Store into the App Group container. `nil` when the container cannot
    /// be resolved -- a misspelled group, or an entitlement the target does
    /// not carry.
    public convenience init?(
        appGroup: String,
        errorKey: String = "shoes.lastFatalError",
        stopReasonKey: String = "shoes.lastStopReason"
    ) {
        guard
            let container = FileManager.default.containerURL(
                forSecurityApplicationGroupIdentifier: appGroup)
        else { return nil }
        self.init(directory: container, errorKey: errorKey, stopReasonKey: stopReasonKey)
    }

    /// Store into an explicit directory. The App Group initializer routes
    /// here; tests use it directly with a temporary directory.
    public init(
        directory: URL,
        errorKey: String = "shoes.lastFatalError",
        stopReasonKey: String = "shoes.lastStopReason"
    ) {
        errorURL = directory.appendingPathComponent(errorKey).appendingPathExtension("json")
        stopReasonURL = directory.appendingPathComponent(stopReasonKey).appendingPathExtension("json")
    }

    /// Persist a fatal error. Synchronous, and durable on a `true` return;
    /// safe to call from `report(error:)` right before the process exits.
    /// `false` means the write failed -- a full disk, a permissions problem
    /// -- and the error will NOT survive the process; a host with a second
    /// channel (os_log, an analytics queue) can fall back to it.
    @discardableResult
    public func save(_ error: ShoesError) -> Bool {
        guard let data = try? JSONEncoder().encode(error) else { return false }
        return (try? data.write(to: errorURL, options: .atomic)) != nil
    }

    /// The last persisted error, if any. Typically read by the app when the
    /// session goes `.disconnected` without the user asking.
    public func load() -> ShoesError? {
        guard let data = try? Data(contentsOf: errorURL) else { return nil }
        return try? JSONDecoder().decode(ShoesError.self, from: data)
    }

    /// Forget the persisted error -- call once the app has shown it.
    public func clear() {
        try? FileManager.default.removeItem(at: errorURL)
    }

    /// Persist why the system stopped the tunnel, as
    /// `NEProviderStopReason.rawValue`. An `Int` rather than the enum so
    /// this target needs no NetworkExtension dependency. Returns whether
    /// the write landed, like [`save(_:)`].
    @discardableResult
    public func saveStopReason(_ rawValue: Int) -> Bool {
        guard let data = try? JSONEncoder().encode(rawValue) else { return false }
        return (try? data.write(to: stopReasonURL, options: .atomic)) != nil
    }

    /// The last persisted stop reason's `rawValue`, or `nil` when none was
    /// saved. Rebuild with `NEProviderStopReason(rawValue:)` on the app side.
    public func loadStopReason() -> Int? {
        guard let data = try? Data(contentsOf: stopReasonURL) else { return nil }
        return try? JSONDecoder().decode(Int.self, from: data)
    }

    /// Forget the persisted stop reason.
    public func clearStopReason() {
        try? FileManager.default.removeItem(at: stopReasonURL)
    }
}
