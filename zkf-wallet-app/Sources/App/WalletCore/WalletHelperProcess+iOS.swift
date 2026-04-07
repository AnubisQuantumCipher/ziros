#if os(iOS)
import Foundation

actor WalletHelperProcess: WalletHelperRuntime {
    nonisolated let executionAvailability: WalletHelperExecutionAvailability = .unavailable(
        "Midnight mobile execution remains fail-closed on iPhone. The app now bundles a real WebKit helper bootstrap and host probe, but the current Midnight wallet/testkit dependency graph is still not browser-safe end to end. The iPhone shell keeps Rust biometrics, seed import, permissions, messaging history, and settings live, while spend, sync, receive addresses, shield, unshield, DUST, and mailbox posting stay disabled until the WebKit lane clears that audit."
    )

    private func unavailable<T>() throws -> T {
        throw WalletHelperRuntimeError.executionUnavailable(
            executionAvailability.message ?? "Midnight mobile execution is unavailable."
        )
    }

    func compatibilityReport() async -> WalletHelperCompatibilityReport {
        await WalletHelperWebKitBridge.shared.compatibilityReport()
    }

    func openSession(
        bundle: WalletHelperBundle,
        proveRoutes: [ProveRoute]
    ) async throws -> OpenWalletSessionResponse {
        _ = bundle
        _ = proveRoutes
        return try unavailable()
    }

    func sync(sessionID: String) async throws -> WalletOverview {
        _ = sessionID
        return try unavailable()
    }

    func closeSession(sessionID: String) async throws {
        _ = sessionID
    }

    func overview(sessionID: String) async throws -> WalletOverview {
        _ = sessionID
        return try unavailable()
    }

    func balances(sessionID: String) async throws -> WalletOverview.Balances {
        _ = sessionID
        return try unavailable()
    }

    func addresses(sessionID: String) async throws -> OpenWalletSessionResponse.Addresses {
        _ = sessionID
        return try unavailable()
    }

    func configuration(sessionID: String) async throws -> OpenWalletSessionResponse.Configuration {
        _ = sessionID
        return try unavailable()
    }

    func activity(sessionID: String) async throws -> [WalletActivityEntry] {
        _ = sessionID
        return try unavailable()
    }

    func listDustCandidates(sessionID: String) async throws -> [DustUtxoCandidate] {
        _ = sessionID
        return try unavailable()
    }

    func buildTransfer(
        sessionID: String,
        origin: String,
        recipient: String,
        tokenType: String,
        amountRaw: String
    ) async throws -> PreparedTransactionHandle {
        _ = sessionID
        _ = origin
        _ = recipient
        _ = tokenType
        _ = amountRaw
        return try unavailable()
    }

    func buildTransfer(
        sessionID: String,
        origin: String,
        desiredOutputs: [BridgeDesiredOutput],
        payFees: Bool
    ) async throws -> PreparedTransactionHandle {
        _ = sessionID
        _ = origin
        _ = desiredOutputs
        _ = payFees
        return try unavailable()
    }

    func buildShield(
        sessionID: String,
        origin: String,
        tokenType: String,
        amountRaw: String
    ) async throws -> PreparedTransactionHandle {
        _ = sessionID
        _ = origin
        _ = tokenType
        _ = amountRaw
        return try unavailable()
    }

    func buildUnshield(
        sessionID: String,
        origin: String,
        tokenType: String,
        amountRaw: String
    ) async throws -> PreparedTransactionHandle {
        _ = sessionID
        _ = origin
        _ = tokenType
        _ = amountRaw
        return try unavailable()
    }

    func registerDust(
        sessionID: String,
        origin: String,
        utxoIndexes: [Int],
        dustReceiverAddress: String?
    ) async throws -> PreparedTransactionHandle {
        _ = sessionID
        _ = origin
        _ = utxoIndexes
        _ = dustReceiverAddress
        return try unavailable()
    }

    func deregisterDust(
        sessionID: String,
        origin: String,
        utxoIndexes: [Int]
    ) async throws -> PreparedTransactionHandle {
        _ = sessionID
        _ = origin
        _ = utxoIndexes
        return try unavailable()
    }

    func redesignateDust(
        sessionID: String,
        origin: String,
        utxoIndexes: [Int],
        dustReceiverAddress: String
    ) async throws -> PreparedTransactionHandle {
        _ = sessionID
        _ = origin
        _ = utxoIndexes
        _ = dustReceiverAddress
        return try unavailable()
    }

    func buildIntent(
        sessionID: String,
        origin: String,
        desiredInputs: [BridgeDesiredInput],
        desiredOutputs: [BridgeDesiredOutput],
        payFees: Bool
    ) async throws -> PreparedTransactionHandle {
        _ = sessionID
        _ = origin
        _ = desiredInputs
        _ = desiredOutputs
        _ = payFees
        return try unavailable()
    }

    func finalizeAndSubmit(
        sessionID: String,
        txDigest: String,
        grant: SubmissionGrant
    ) async throws -> String {
        _ = sessionID
        _ = txDigest
        _ = grant
        return try unavailable()
    }

    func probeMailboxTransport(
        sessionID: String,
        contractAddress: String,
        manifestPath: String
    ) async throws -> MessagingTransportUpdate {
        _ = sessionID
        _ = contractAddress
        _ = manifestPath
        return try unavailable()
    }

    func postMailboxEnvelope(
        sessionID: String,
        contractAddress: String,
        manifestPath: String,
        preparedMessage: PreparedMessage
    ) async throws -> MailboxPostResponse {
        _ = sessionID
        _ = contractAddress
        _ = manifestPath
        _ = preparedMessage
        return try unavailable()
    }

    func pollMailboxEnvelopes(
        sessionID: String,
        contractAddress: String,
        manifestPath: String,
        receiverPeerID: String,
        lastObservedCursor: String?
    ) async throws -> MailboxPollResponse {
        _ = sessionID
        _ = contractAddress
        _ = manifestPath
        _ = receiverPeerID
        _ = lastObservedCursor
        return try unavailable()
    }
}
#endif
