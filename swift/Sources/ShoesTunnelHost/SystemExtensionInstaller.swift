#if os(macOS)
    import Foundation
    import SystemExtensions

    /// Activate the packet tunnel system extension embedded in this app.
    ///
    /// Developer ID distribution puts the provider in a `.systemextension` under
    /// `Contents/Library/SystemExtensions`, which the user approves once in
    /// System Settings. The app must be running from `/Applications` (or
    /// `systemextensionsctl developer on` must be set), and the extension must
    /// carry the `packet-tunnel-provider-systemextension` entitlement -- neither
    /// is something this code can check for you; both surface as the request
    /// failing.
    public enum SystemExtensionInstaller {
        /// A first install waits in `.needsApproval` until the user acts in
        /// System Settings -- potentially forever. `activate` reports it so
        /// the app can say so instead of hanging silently; it still waits,
        /// because the request genuinely completes once approval lands.
        public enum ActivationEvent: Sendable {
            /// The user must approve the extension in System Settings >
            /// General > Login Items & Extensions. Show them the way.
            case needsUserApproval
        }

        /// Thrown when activation reported `.willCompleteAfterReboot`: the
        /// extension is NOT active yet, and `startVPNTunnel` on top of it
        /// fails with an opaque error. Treating it as success was how the
        /// old code turned "reboot required" into a mystery.
        public struct RebootRequired: Error, Sendable {}

        /// Activate, reporting progress through `onEvent` (delivered on the
        /// main queue). Throws [`RebootRequired`] when the system defers the
        /// activation to the next boot.
        public static func activate(
            bundleIdentifier: String,
            onEvent: (@Sendable (ActivationEvent) -> Void)? = nil
        ) async throws {
            let request = OSSystemExtensionRequest.activationRequest(
                forExtensionWithIdentifier: bundleIdentifier, queue: .main)
            let delegate = Delegate(onEvent: onEvent)
            request.delegate = delegate
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
                delegate.continuation = continuation
                OSSystemExtensionManager.shared.submitRequest(request)
            }
            // Load-bearing: `request.delegate` is weak, and this line is what
            // keeps the delegate alive across the suspension above. Removing
            // a dead-looking statement here removes the delegate mid-request.
            withExtendedLifetime(delegate) {}
        }

        private final class Delegate: NSObject, OSSystemExtensionRequestDelegate {
            var continuation: CheckedContinuation<Void, any Error>?
            let onEvent: (@Sendable (ActivationEvent) -> Void)?

            init(onEvent: (@Sendable (ActivationEvent) -> Void)?) {
                self.onEvent = onEvent
            }

            func request(
                _ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties,
                withExtension ext: OSSystemExtensionProperties
            ) -> OSSystemExtensionRequest.ReplacementAction {
                .replace
            }

            func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
                // The request completes after the user approves it in System
                // Settings. The wait is right; waiting *silently* was the
                // bug -- the app's start() hung with nothing to show.
                onEvent?(.needsUserApproval)
            }

            func request(
                _ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result
            ) {
                switch result {
                case .completed:
                    continuation?.resume()
                case .willCompleteAfterReboot:
                    // Not active yet: proceeding to startVPNTunnel fails
                    // with an opaque error. Surface the actionable fact.
                    continuation?.resume(throwing: RebootRequired())
                @unknown default:
                    continuation?.resume()
                }
                continuation = nil
            }

            func request(_ request: OSSystemExtensionRequest, didFailWithError error: any Error) {
                continuation?.resume(throwing: error)
                continuation = nil
            }
        }
    }
#endif
