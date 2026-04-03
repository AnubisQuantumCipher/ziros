#if os(iOS)
import Foundation

@MainActor
final class WalletHelperWebKitBridge {
    static let shared = WalletHelperWebKitBridge()

    private let host = ZKFWalletWebViewHost()
    private var bootstrapTask: Task<URL, Error>?

    func compatibilityReport() async -> WalletHelperCompatibilityReport {
        do {
            _ = try await ensureBootstrapped()
            let payload = try await callAsyncJavaScriptString(
                "return JSON.stringify(await globalThis.__zirosWalletHelper.probeHostCompatibility());",
                arguments: [:]
            )
            let data = Data(payload.utf8)
            return try JSONDecoder.walletDecoder().decode(WalletHelperCompatibilityReport.self, from: data)
        } catch {
            return WalletHelperCompatibilityReport(
                mode: "webkit-bridge",
                bridgeLoaded: false,
                helperRootConfigured: false,
                hasWebCrypto: false,
                hasRandomUUID: false,
                hasWebSocket: false,
                runtimeAvailable: false,
                reason: error.localizedDescription
            )
        }
    }

    private func ensureBootstrapped() async throws -> URL {
        if let bootstrapTask {
            return try await bootstrapTask.value
        }

        let task = Task<URL, Error> { [weak self] in
            guard let self else {
                throw NSError(
                    domain: "WalletHelperWebKitBridge",
                    code: 90,
                    userInfo: [NSLocalizedDescriptionKey: "Wallet WebKit bridge was released before bootstrap completed."]
                )
            }

            let helperRoot = try self.resolveHelperRoot()
            try await self.loadBaseDocument(helperRoot: helperRoot)

            let bootstrapURL = helperRoot
                .appendingPathComponent("dist", isDirectory: true)
                .appendingPathComponent("src", isDirectory: true)
                .appendingPathComponent("main_webkit.js", isDirectory: false)

            guard FileManager.default.fileExists(atPath: bootstrapURL.path) else {
                throw NSError(
                    domain: "WalletHelperWebKitBridge",
                    code: 91,
                    userInfo: [NSLocalizedDescriptionKey: "Missing bundled WebKit helper bootstrap at \(bootstrapURL.path)."]
                )
            }

            let bootstrapScript = try String(contentsOf: bootstrapURL, encoding: .utf8)
            try await self.loadBaseDocument(helperRoot: helperRoot)
            try await self.evaluateJavaScriptVoid(bootstrapScript)
            _ = try await self.callAsyncJavaScriptString(
                "return JSON.stringify(await globalThis.__zirosWalletHelper.bootstrap(helperRootURL));",
                arguments: ["helperRootURL": helperRoot.absoluteString]
            )
            return helperRoot
        }

        bootstrapTask = task
        do {
            return try await task.value
        } catch {
            bootstrapTask = nil
            throw error
        }
    }

    private func resolveHelperRoot() throws -> URL {
        guard let root = Bundle.main.resourceURL?.appendingPathComponent("WalletHelper", isDirectory: true) else {
            throw NSError(
                domain: "WalletHelperWebKitBridge",
                code: 92,
                userInfo: [NSLocalizedDescriptionKey: "WalletHelper resources are missing from the app bundle."]
            )
        }
        return root
    }

    private func loadBaseDocument(helperRoot: URL) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            host.loadHelperRootURL(helperRoot) { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            }
        }
    }

    private func evaluateJavaScriptVoid(_ script: String) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            host.evaluateJavaScript(script) { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            }
        }
    }

    private func callAsyncJavaScriptString(
        _ body: String,
        arguments: [String: Any]
    ) async throws -> String {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<String, Error>) in
            host.callAsyncJavaScript(body, arguments: arguments) { result, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                guard let string = result as? String else {
                    continuation.resume(
                        throwing: NSError(
                            domain: "WalletHelperWebKitBridge",
                            code: 93,
                            userInfo: [NSLocalizedDescriptionKey: "WebKit helper returned a non-string payload."]
                        )
                    )
                    return
                }
                continuation.resume(returning: string)
            }
        }
    }
}
#endif
