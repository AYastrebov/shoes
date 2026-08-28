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
        public static func activate(bundleIdentifier: String) async throws {
            let request = OSSystemExtensionRequest.activationRequest(
                forExtensionWithIdentifier: bundleIdentifier, queue: .main)
            let delegate = Delegate()
            request.delegate = delegate
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
                delegate.continuation = continuation
                OSSystemExtensionManager.shared.submitRequest(request)
            }
            withExtendedLifetime(delegate) {}
        }

        private final class Delegate: NSObject, OSSystemExtensionRequestDelegate {
            var continuation: CheckedContinuation<Void, any Error>?

            func request(
                _ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties,
                withExtension ext: OSSystemExtensionProperties
            ) -> OSSystemExtensionRequest.ReplacementAction {
                .replace
            }

            func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
                // The request completes after the user approves it in System
                // Settings; nothing to do but wait.
            }

            func request(
                _ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result
            ) {
                continuation?.resume()
                continuation = nil
            }

            func request(_ request: OSSystemExtensionRequest, didFailWithError error: any Error) {
                continuation?.resume(throwing: error)
                continuation = nil
            }
        }
    }
#endif
