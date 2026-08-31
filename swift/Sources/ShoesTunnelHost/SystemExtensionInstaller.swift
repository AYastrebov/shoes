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
        /// Thrown when a FIRST install reported `.willCompleteAfterReboot`:
        /// no extension is active yet, and `startVPNTunnel` on top of it
        /// fails with an opaque error. Treating it as success was how the
        /// old code turned "reboot required" into a mystery. An UPGRADE
        /// deferred to reboot is different -- the already-approved older
        /// extension keeps serving -- and is treated as success.
        public struct RebootRequired: Error, Sendable {}

        /// Thrown for an `OSSystemExtensionRequest.Result` this code does
        /// not know. Unknown is not "completed": surfacing it beats
        /// starting a tunnel on an extension in an unmodeled state.
        public struct UnexpectedActivationResult: Error, Sendable {}

        /// Activate, reporting progress through `onEvent` (delivered on the
        /// main queue). Throws [`RebootRequired`] when a first install is
        /// deferred to the next boot.
        public static func activate(
            bundleIdentifier: String,
            onEvent: (@Sendable (TunnelActivationEvent) -> Void)? = nil
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
            let onEvent: (@Sendable (TunnelActivationEvent) -> Void)?
            /// Whether this activation replaces an installed extension --
            /// what makes `.willCompleteAfterReboot` survivable: the old,
            /// already-approved extension keeps serving until the reboot.
            var replacesExisting = false

            init(onEvent: (@Sendable (TunnelActivationEvent) -> Void)?) {
                self.onEvent = onEvent
            }

            func request(
                _ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties,
                withExtension ext: OSSystemExtensionProperties
            ) -> OSSystemExtensionRequest.ReplacementAction {
                replacesExisting = true
                return .replace
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
                    if replacesExisting {
                        // The older approved extension keeps serving; the
                        // reboot only upgrades it. Failing start() here
                        // would break a working tunnel over a pending
                        // version bump.
                        continuation?.resume()
                    } else {
                        continuation?.resume(throwing: RebootRequired())
                    }
                @unknown default:
                    continuation?.resume(throwing: UnexpectedActivationResult())
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
