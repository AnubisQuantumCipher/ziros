import Foundation

enum WalletHelperExecutionAvailability: Equatable, Sendable {
    case available
    case unavailable(String)

    var isAvailable: Bool {
        if case .available = self {
            return true
        }
        return false
    }

    var message: String? {
        switch self {
        case .available:
            return nil
        case let .unavailable(message):
            return message
        }
    }
}

enum WalletHelperRuntimeError: LocalizedError {
    case executionUnavailable(String)

    var errorDescription: String? {
        switch self {
        case let .executionUnavailable(message):
            return message
        }
    }
}

protocol WalletHelperRuntime: Sendable {
    var executionAvailability: WalletHelperExecutionAvailability { get }

    func openSession(
        bundle: WalletHelperBundle,
        proveRoutes: [ProveRoute]
    ) async throws -> OpenWalletSessionResponse
    func sync(sessionID: String) async throws -> WalletOverview
    func closeSession(sessionID: String) async throws
    func overview(sessionID: String) async throws -> WalletOverview
    func balances(sessionID: String) async throws -> WalletOverview.Balances
    func addresses(sessionID: String) async throws -> OpenWalletSessionResponse.Addresses
    func configuration(sessionID: String) async throws -> OpenWalletSessionResponse.Configuration
    func activity(sessionID: String) async throws -> [WalletActivityEntry]
    func listDustCandidates(sessionID: String) async throws -> [DustUtxoCandidate]
    func buildTransfer(
        sessionID: String,
        origin: String,
        recipient: String,
        tokenType: String,
        amountRaw: String
    ) async throws -> PreparedTransactionHandle
    func buildTransfer(
        sessionID: String,
        origin: String,
        desiredOutputs: [BridgeDesiredOutput],
        payFees: Bool
    ) async throws -> PreparedTransactionHandle
    func buildShield(
        sessionID: String,
        origin: String,
        tokenType: String,
        amountRaw: String
    ) async throws -> PreparedTransactionHandle
    func buildUnshield(
        sessionID: String,
        origin: String,
        tokenType: String,
        amountRaw: String
    ) async throws -> PreparedTransactionHandle
    func registerDust(
        sessionID: String,
        origin: String,
        utxoIndexes: [Int],
        dustReceiverAddress: String?
    ) async throws -> PreparedTransactionHandle
    func deregisterDust(
        sessionID: String,
        origin: String,
        utxoIndexes: [Int]
    ) async throws -> PreparedTransactionHandle
    func redesignateDust(
        sessionID: String,
        origin: String,
        utxoIndexes: [Int],
        dustReceiverAddress: String
    ) async throws -> PreparedTransactionHandle
    func buildIntent(
        sessionID: String,
        origin: String,
        desiredInputs: [BridgeDesiredInput],
        desiredOutputs: [BridgeDesiredOutput],
        payFees: Bool
    ) async throws -> PreparedTransactionHandle
    func finalizeAndSubmit(
        sessionID: String,
        txDigest: String,
        grant: SubmissionGrant
    ) async throws -> String
    func probeMailboxTransport(
        sessionID: String,
        contractAddress: String,
        manifestPath: String
    ) async throws -> MessagingTransportUpdate
    func postMailboxEnvelope(
        sessionID: String,
        contractAddress: String,
        manifestPath: String,
        preparedMessage: PreparedMessage
    ) async throws -> MailboxPostResponse
    func pollMailboxEnvelopes(
        sessionID: String,
        contractAddress: String,
        manifestPath: String,
        receiverPeerID: String,
        lastObservedCursor: String?
    ) async throws -> MailboxPollResponse
}
