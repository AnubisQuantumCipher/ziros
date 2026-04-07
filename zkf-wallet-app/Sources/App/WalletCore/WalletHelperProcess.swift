#if os(macOS)
import Foundation

struct HelperRpcEnvelope<Result: Decodable>: Decodable {
    struct RpcError: Decodable, Error {
        let code: Int
        let message: String
    }

    let result: Result?
    let error: RpcError?
}

struct HelperSessionRequest: Encodable {
    struct Seed: Encodable {
        let kind: String
        let value: String
    }

    struct Services: Encodable {
        let rpcUrl: String
        let indexerUrl: String
        let indexerWsUrl: String
        let explorerUrl: String
        let proofServerUrl: String
        let gatewayUrl: String
        let proveRoutes: [ProveRoute]
    }

    let network: String
    let seed: Seed
    let services: Services
}

actor WalletHelperProcess: WalletHelperRuntime {
    nonisolated let executionAvailability: WalletHelperExecutionAvailability = .available

    private struct HelperRuntime {
        let executableURL: URL
        let scriptURL: URL
        let workingDirectoryURL: URL
    }

    private var process: Process?
    private var stdinPipe: Pipe?
    private var stdoutHandle: FileHandle?
    private let decoder = JSONDecoder.walletDecoder()
    private let encoder = JSONEncoder.walletEncoder()

    deinit {
        process?.terminate()
    }

    func compatibilityReport() async -> WalletHelperCompatibilityReport {
        WalletHelperCompatibilityReport(
            mode: "node-process",
            bridgeLoaded: true,
            helperRootConfigured: true,
            hasWebCrypto: true,
            hasRandomUUID: true,
            hasWebSocket: true,
            runtimeAvailable: true,
            reason: nil
        )
    }

    func openSession(
        bundle: WalletHelperBundle,
        proveRoutes: [ProveRoute]
    ) async throws -> OpenWalletSessionResponse {
        try await ensureRunning()
        let request = HelperSessionRequest(
            network: bundle.services.network,
            seed: .init(kind: bundle.seed.kind, value: bundle.seed.value),
            services: .init(
                rpcUrl: bundle.services.rpcUrl,
                indexerUrl: bundle.services.indexerUrl,
                indexerWsUrl: bundle.services.indexerWsUrl,
                explorerUrl: bundle.services.explorerUrl,
                proofServerUrl: bundle.services.proofServerUrl,
                gatewayUrl: bundle.services.gatewayUrl,
                proveRoutes: proveRoutes
            )
        )
        return try await call(method: "openWalletSession", params: request)
    }

    func sync(sessionID: String) async throws -> WalletOverview {
        struct Params: Encodable { let sessionId: String }
        return try await call(method: "sync", params: Params(sessionId: sessionID))
    }

    func closeSession(sessionID: String) async throws {
        struct Params: Encodable { let sessionId: String }
        _ = try await call(method: "closeWalletSession", params: Params(sessionId: sessionID)) as [String: Bool]
    }

    func overview(sessionID: String) async throws -> WalletOverview {
        struct Params: Encodable { let sessionId: String }
        return try await call(method: "getOverview", params: Params(sessionId: sessionID))
    }

    func balances(sessionID: String) async throws -> WalletOverview.Balances {
        struct Params: Encodable { let sessionId: String }
        return try await call(method: "getBalances", params: Params(sessionId: sessionID))
    }

    func addresses(sessionID: String) async throws -> OpenWalletSessionResponse.Addresses {
        struct Params: Encodable { let sessionId: String }
        return try await call(method: "getAddresses", params: Params(sessionId: sessionID))
    }

    func configuration(sessionID: String) async throws -> OpenWalletSessionResponse.Configuration {
        struct Params: Encodable { let sessionId: String }
        return try await call(method: "getConfiguration", params: Params(sessionId: sessionID))
    }

    func activity(sessionID: String) async throws -> [WalletActivityEntry] {
        struct Params: Encodable { let sessionId: String }
        return try await call(method: "getActivity", params: Params(sessionId: sessionID))
    }

    func listDustCandidates(sessionID: String) async throws -> [DustUtxoCandidate] {
        struct Params: Encodable { let sessionId: String }
        return try await call(method: "listDustCandidates", params: Params(sessionId: sessionID))
    }

    func buildTransfer(sessionID: String, origin: String, recipient: String, tokenType: String, amountRaw: String) async throws -> PreparedTransactionHandle {
        try await buildTransfer(
            sessionID: sessionID,
            origin: origin,
            desiredOutputs: [
                BridgeDesiredOutput(
                    mode: "unshielded",
                    receiverAddress: recipient,
                    tokenType: tokenType,
                    amountRaw: amountRaw
                ),
            ],
            payFees: true
        )
    }

    func buildTransfer(
        sessionID: String,
        origin: String,
        desiredOutputs: [BridgeDesiredOutput],
        payFees: Bool
    ) async throws -> PreparedTransactionHandle {
        struct Params: Encodable {
            let sessionId: String
            let origin: String
            let desiredOutputs: [BridgeDesiredOutput]
            let payFees: Bool
        }

        return try await call(
            method: "buildTransfer",
            params: Params(sessionId: sessionID, origin: origin, desiredOutputs: desiredOutputs, payFees: payFees)
        )
    }

    func buildShield(sessionID: String, origin: String, tokenType: String, amountRaw: String) async throws -> PreparedTransactionHandle {
        struct Params: Encodable {
            let sessionId: String
            let origin: String
            let tokenType: String
            let amountRaw: String
            let payFees: Bool
        }

        return try await call(
            method: "buildShield",
            params: Params(sessionId: sessionID, origin: origin, tokenType: tokenType, amountRaw: amountRaw, payFees: true)
        )
    }

    func buildUnshield(sessionID: String, origin: String, tokenType: String, amountRaw: String) async throws -> PreparedTransactionHandle {
        struct Params: Encodable {
            let sessionId: String
            let origin: String
            let tokenType: String
            let amountRaw: String
            let payFees: Bool
        }

        return try await call(
            method: "buildUnshield",
            params: Params(sessionId: sessionID, origin: origin, tokenType: tokenType, amountRaw: amountRaw, payFees: true)
        )
    }

    func registerDust(
        sessionID: String,
        origin: String,
        utxoIndexes: [Int],
        dustReceiverAddress: String?
    ) async throws -> PreparedTransactionHandle {
        struct Params: Encodable {
            let sessionId: String
            let origin: String
            let utxoIndexes: [Int]
            let dustReceiverAddress: String?
        }

        return try await call(
            method: "registerDust",
            params: Params(
                sessionId: sessionID,
                origin: origin,
                utxoIndexes: utxoIndexes,
                dustReceiverAddress: dustReceiverAddress
            )
        )
    }

    func deregisterDust(
        sessionID: String,
        origin: String,
        utxoIndexes: [Int]
    ) async throws -> PreparedTransactionHandle {
        struct Params: Encodable {
            let sessionId: String
            let origin: String
            let utxoIndexes: [Int]
        }

        return try await call(
            method: "deregisterDust",
            params: Params(sessionId: sessionID, origin: origin, utxoIndexes: utxoIndexes)
        )
    }

    func redesignateDust(
        sessionID: String,
        origin: String,
        utxoIndexes: [Int],
        dustReceiverAddress: String
    ) async throws -> PreparedTransactionHandle {
        struct Params: Encodable {
            let sessionId: String
            let origin: String
            let utxoIndexes: [Int]
            let dustReceiverAddress: String
        }

        return try await call(
            method: "redesignateDust",
            params: Params(
                sessionId: sessionID,
                origin: origin,
                utxoIndexes: utxoIndexes,
                dustReceiverAddress: dustReceiverAddress
            )
        )
    }

    func buildIntent(
        sessionID: String,
        origin: String,
        desiredInputs: [BridgeDesiredInput],
        desiredOutputs: [BridgeDesiredOutput],
        payFees: Bool
    ) async throws -> PreparedTransactionHandle {
        struct Params: Encodable {
            let sessionId: String
            let origin: String
            let desiredInputs: [BridgeDesiredInput]
            let desiredOutputs: [BridgeDesiredOutput]
            let payFees: Bool
        }

        return try await call(
            method: "buildIntent",
            params: Params(
                sessionId: sessionID,
                origin: origin,
                desiredInputs: desiredInputs,
                desiredOutputs: desiredOutputs,
                payFees: payFees
            )
        )
    }

    func finalizeAndSubmit(sessionID: String, txDigest: String, grant: SubmissionGrant) async throws -> String {
        struct Params: Encodable {
            let sessionId: String
            let txDigest: String
            let submissionGrant: SubmissionGrant
        }

        struct Response: Decodable {
            let txId: String
        }

        let response: Response = try await call(
            method: "finalizeAndSubmit",
            params: Params(sessionId: sessionID, txDigest: txDigest, submissionGrant: grant)
        )
        return response.txId
    }

    func probeMailboxTransport(
        sessionID: String,
        contractAddress: String,
        manifestPath: String
    ) async throws -> MessagingTransportUpdate {
        struct Params: Encodable {
            let sessionId: String
            let contractAddress: String
            let manifestPath: String
        }

        return try await call(
            method: "probeMailboxTransport",
            params: Params(
                sessionId: sessionID,
                contractAddress: contractAddress,
                manifestPath: manifestPath
            )
        )
    }

    func postMailboxEnvelope(
        sessionID: String,
        contractAddress: String,
        manifestPath: String,
        preparedMessage: PreparedMessage
    ) async throws -> MailboxPostResponse {
        struct Params: Encodable {
            let sessionId: String
            let contractAddress: String
            let manifestPath: String
            let preparedMessage: PreparedMessage
        }

        return try await call(
            method: "postMailboxEnvelope",
            params: Params(
                sessionId: sessionID,
                contractAddress: contractAddress,
                manifestPath: manifestPath,
                preparedMessage: preparedMessage
            )
        )
    }

    func pollMailboxEnvelopes(
        sessionID: String,
        contractAddress: String,
        manifestPath: String,
        receiverPeerID: String,
        lastObservedCursor: String?
    ) async throws -> MailboxPollResponse {
        struct Params: Encodable {
            let sessionId: String
            let contractAddress: String
            let manifestPath: String
            let receiverPeerId: String
            let lastObservedCursor: String?
        }

        return try await call(
            method: "pollMailboxEnvelopes",
            params: Params(
                sessionId: sessionID,
                contractAddress: contractAddress,
                manifestPath: manifestPath,
                receiverPeerId: receiverPeerID,
                lastObservedCursor: lastObservedCursor
            )
        )
    }

    private func ensureRunning() async throws {
        if process?.isRunning == true {
            return
        }

        let runtime = try resolveHelperRuntime()

        let process = Process()
        process.executableURL = runtime.executableURL
        process.arguments = [runtime.scriptURL.path]
        process.currentDirectoryURL = runtime.workingDirectoryURL
        let stdin = Pipe()
        let stdout = Pipe()
        process.standardInput = stdin
        process.standardOutput = stdout
        process.standardError = Pipe()
        try process.run()
        self.process = process
        self.stdinPipe = stdin
        self.stdoutHandle = stdout.fileHandleForReading
    }

    private func resolveHelperRuntime() throws -> HelperRuntime {
        let fileManager = FileManager.default
        let bundledRoot = Bundle.main.resourceURL?.appendingPathComponent("WalletHelper", isDirectory: true)
        let bundledNode = bundledRoot?
            .appendingPathComponent("NodeRuntime", isDirectory: true)
            .appendingPathComponent("bin/node", isDirectory: false)
        let bundledScript = bundledRoot.flatMap { root in
            [
                root.appendingPathComponent("dist/src/main.js", isDirectory: false),
                root.appendingPathComponent("dist/main.js", isDirectory: false),
            ].first(where: { fileManager.fileExists(atPath: $0.path) })
        }

        if let bundledRoot,
           let bundledNode,
           let bundledScript,
           fileManager.isExecutableFile(atPath: bundledNode.path),
           fileManager.fileExists(atPath: bundledScript.path),
           runtimePassesSmokeCheck(executableURL: bundledNode) {
            return HelperRuntime(
                executableURL: bundledNode,
                scriptURL: bundledScript,
                workingDirectoryURL: bundledRoot
            )
        }

#if DEBUG
        if let repoHelperRoot = repoHelperOverrideRoot() {
            let repoNodeCandidates = [
                "/opt/homebrew/opt/node@22/bin/node",
                "/usr/local/bin/node",
                "/opt/homebrew/bin/node",
            ]
            let repoNodePath = repoNodeCandidates.first(where: { fileManager.isExecutableFile(atPath: $0) })

            let repoScriptCandidates = [
                repoHelperRoot.appendingPathComponent("dist/src/main.js", isDirectory: false),
                repoHelperRoot.appendingPathComponent("dist/main.js", isDirectory: false),
            ]
            let repoScript = repoScriptCandidates.first(where: { fileManager.fileExists(atPath: $0.path) })

            if let repoNodePath, let repoScript {
                return HelperRuntime(
                    executableURL: URL(fileURLWithPath: repoNodePath),
                    scriptURL: repoScript,
                    workingDirectoryURL: repoHelperRoot
                )
            }
        }
#endif

        throw NSError(
            domain: "WalletHelperProcess",
            code: 5,
            userInfo: [NSLocalizedDescriptionKey: "Wallet helper runtime bundle is unavailable or failed its smoke check."]
        )
    }

    private func runtimePassesSmokeCheck(executableURL: URL) -> Bool {
        let process = Process()
        let output = Pipe()
        process.executableURL = executableURL
        process.arguments = ["-v"]
        process.standardOutput = output
        process.standardError = output

        do {
            try process.run()
        } catch {
            return false
        }

        let deadline = Date().addingTimeInterval(2)
        while process.isRunning && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.05)
        }

        if process.isRunning {
            process.terminate()
            return false
        }

        let data = output.fileHandleForReading.readDataToEndOfFile()
        guard process.terminationStatus == 0,
              let value = String(data: data, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines),
              value.hasPrefix("v")
        else {
            return false
        }

        return true
    }

#if DEBUG
    private func repoHelperOverrideRoot() -> URL? {
        let environment = ProcessInfo.processInfo.environment
        guard environment["ZIROS_WALLET_ALLOW_REPO_FALLBACKS"] == "1" else {
            return nil
        }
        guard let repoRoot = environment["ZIROS_WALLET_REPO_ROOT"], repoRoot.isEmpty == false else {
            return nil
        }
        return URL(fileURLWithPath: repoRoot, isDirectory: true)
            .appendingPathComponent("zkf-wallet-helper", isDirectory: true)
    }
#endif

    private func call<Params: Encodable, Result: Decodable>(method: String, params: Params) async throws -> Result {
        try await ensureRunning()
        let request: [String: Any] = [
            "jsonrpc": "2.0",
            "id": UUID().uuidString,
            "method": method,
            "params": try jsonObject(for: params),
        ]
        let requestData = try JSONSerialization.data(withJSONObject: request)
        guard let stdinPipe else {
            throw NSError(domain: "WalletHelperProcess", code: 1, userInfo: [NSLocalizedDescriptionKey: "Helper stdin is unavailable"])
        }
        stdinPipe.fileHandleForWriting.write(requestData)
        stdinPipe.fileHandleForWriting.write(Data([0x0A]))

        guard let stdoutHandle else {
            throw NSError(domain: "WalletHelperProcess", code: 2, userInfo: [NSLocalizedDescriptionKey: "Helper stdout is unavailable"])
        }
        guard let line = try stdoutHandle.read(upToCount: 65_536), !line.isEmpty else {
            throw NSError(domain: "WalletHelperProcess", code: 3, userInfo: [NSLocalizedDescriptionKey: "Connecting to Midnight..."])
        }
        let trimmed: Data
        if let newlineIndex = line.firstIndex(of: 0x0A) {
            trimmed = line.prefix(upTo: newlineIndex)
        } else {
            trimmed = line
        }
        let envelope = try decoder.decode(HelperRpcEnvelope<Result>.self, from: trimmed)
        if let error = envelope.error {
            throw error
        }
        guard let result = envelope.result else {
            throw NSError(domain: "WalletHelperProcess", code: 4, userInfo: [NSLocalizedDescriptionKey: "Helper returned an empty result"])
        }
        return result
    }

    private func jsonObject<Params: Encodable>(for params: Params) throws -> Any {
        let data = try encoder.encode(params)
        return try JSONSerialization.jsonObject(with: data)
    }
}
#endif
