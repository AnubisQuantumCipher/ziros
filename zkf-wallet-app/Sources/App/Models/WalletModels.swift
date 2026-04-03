import Foundation

enum WalletSection: String, CaseIterable, Identifiable {
    case overview
    case transact
    case dust
    case messages
    case more

    var id: String { rawValue }

    var title: String {
        switch self {
        case .overview: "Overview"
        case .transact: "Transact"
        case .dust: "DUST"
        case .messages: "Messages"
        case .more: "More"
        }
    }

    var systemImage: String {
        switch self {
        case .overview: "house"
        case .transact: "arrow.left.arrow.right"
        case .dust: "flame"
        case .messages: "bubble.left.and.bubble.right"
        case .more: "ellipsis.circle"
        }
    }
}

enum TransactMode: String, CaseIterable, Identifiable {
    case send
    case receive
    case shield
    case unshield

    var id: String { rawValue }

    var title: String {
        rawValue.capitalized
    }

    var systemImage: String {
        switch self {
        case .send: "arrow.up"
        case .receive: "arrow.down"
        case .shield: "lock.fill"
        case .unshield: "lock.open.fill"
        }
    }
}

enum DustOperationKind: String, CaseIterable, Identifiable {
    case register
    case deregister
    case redesignate

    var id: String { rawValue }
}

struct WalletSnapshot: Codable {
    let schema: String?
    let walletId: String?
    let network: String
    let locked: Bool
    let hasImportedSeed: Bool
    let importedSeedKind: String?
    let importedSeedAt: Date?
    let helperSession: HelperSessionView?
    let services: WalletServiceSnapshot?
    let authPolicy: WalletAuthPolicy?
    let grants: [BridgeOriginGrantView]?
    let bridgeSessions: [BridgeSessionSnapshot]?
    let messagingStatus: MessagingTransportStatus?
    let history: [WalletHistoryEntry]
}

struct WalletAuthPolicy: Codable {
    let strictBiometricsOnly: Bool
    let relockTimeoutSeconds: Int
    let approvalTtlSeconds: Int
    let largeTransferThresholdRaw: String
}

struct WalletHistoryEntry: Codable, Identifiable {
    let at: Date
    let kind: String
    let detail: String

    var id: String { "\(at.timeIntervalSince1970)-\(kind)-\(detail)" }
}

struct HelperSessionView: Codable {
    let helperSessionId: String
    let network: String
    let seedKind: String
    let openedAt: Date
    let lastActivityAt: Date
}

struct SeedImportSummary: Codable {
    let network: String
    let kind: String
    let importedAt: Date
}

struct WalletHelperBundle: Codable {
    struct Session: Codable {
        let helperSessionId: String
        let network: String
        let seedKind: String
    }

    struct Seed: Codable {
        let kind: String
        let value: String
    }

    struct Services: Codable {
        let network: String
        let rpcUrl: String
        let indexerUrl: String
        let indexerWsUrl: String
        let explorerUrl: String
        let proofServerUrl: String
        let gatewayUrl: String
        let proveRoutes: [ProveRoute]?
    }

    let session: Session
    let seed: Seed
    let services: Services
}

struct WalletHelperCompatibilityReport: Codable, Equatable {
    let mode: String
    let bridgeLoaded: Bool
    let helperRootConfigured: Bool
    let hasWebCrypto: Bool
    let hasRandomUUID: Bool
    let hasWebSocket: Bool
    let runtimeAvailable: Bool
    let reason: String?
}

struct WalletServiceSnapshot: Codable {
    let network: String
    let rpcUrl: String
    let indexerUrl: String
    let indexerWsUrl: String
    let explorerUrl: String
    let proofServerUrl: String
    let gatewayUrl: String
    let mailboxContractAddress: String?
    let mailboxManifestPath: String?
    let proveRoutes: [ProveRoute]?
}

enum BridgeScope: String, Codable, CaseIterable {
    case readConfig = "read-config"
    case readBalances = "read-balances"
    case readAddresses = "read-addresses"
    case readHistory = "read-history"
    case transfer
    case intent
    case submit
}

struct BridgeOriginGrantView: Codable, Identifiable {
    let origin: String
    let scopes: [BridgeScope]
    let authorizedAt: Date?
    let note: String?

    var id: String { origin }
}

struct BridgeSessionSnapshot: Codable, Identifiable {
    let sessionId: String
    let origin: String
    let scopes: [BridgeScope]
    let createdAt: Date?
    let lastActivityAt: Date?

    var id: String { sessionId }
}

struct OpenWalletSessionResponse: Codable {
    struct Configuration: Codable {
        let indexerUri: String
        let indexerWsUri: String
        let proverServerUri: String?
        let substrateNodeUri: String
        let networkId: String
        let gatewayUrl: String?
        let proveRoutes: [ProveRoute]?
    }

    struct Addresses: Codable {
        let shieldedAddress: String
        let shieldedCoinPublicKey: String
        let shieldedEncryptionPublicKey: String
        let unshieldedAddress: String
        let dustAddress: String
    }

    let sessionId: String
    let configuration: Configuration
    let addresses: Addresses
}

struct WalletOverview: Codable {
    struct SyncStatus: Codable {
        let shieldedConnected: Bool
        let unshieldedConnected: Bool
        let dustConnected: Bool
        let synced: Bool
    }

    struct Balances: Codable {
        struct Dust: Codable {
            let spendableRaw: String
            let coinCount: Int
            let registeredNightUtxos: Int
        }

        let shielded: [String: String]
        let unshielded: [String: String]
        let dust: Dust
    }

    let network: String
    let sync: SyncStatus
    let balances: Balances
    let addresses: OpenWalletSessionResponse.Addresses
}

struct ProveRoute: Codable, Identifiable, Hashable {
    let label: String
    let kind: String
    let proofServerUrl: String
    let gatewayUrl: String?
    let priority: Int

    var id: String { proofServerUrl }
}

struct DustUtxoCandidate: Codable, Identifiable, Hashable {
    let index: Int
    let valueRaw: String
    let tokenType: String
    let owner: String
    let intentHash: String
    let outputNo: Int
    let ctime: Date
    let registeredForDustGeneration: Bool

    var id: Int { index }
}

struct WalletActivityEntry: Codable, Identifiable {
    let id: Int
    let hash: String
    let protocolVersion: Int
    let identifiers: [String]
    let timestamp: Date
    let feesRaw: String?
    let status: String
}

struct ReviewOutput: Codable, Identifiable {
    let recipient: String
    let tokenKind: String
    let amountRaw: String

    var id: String { "\(recipient)-\(tokenKind)-\(amountRaw)" }
}

struct TxReviewPayload: Codable {
    let origin: String
    let network: String
    let method: String
    let txDigest: String
    let outputs: [ReviewOutput]
    let nightTotalRaw: String
    let dustTotalRaw: String
    let feeRaw: String
    let dustImpact: String?
    let shielded: Bool
    let proverRoute: String?
    let warnings: [String]
    let humanSummary: String
}

struct ChannelOpenReviewPayload: Codable {
    let origin: String
    let network: String
    let method: String
    let txDigest: String
    let peerId: String
    let displayName: String?
    let humanSummary: String
    let warnings: [String]
}

struct MessageSendReviewPayload: Codable {
    let origin: String
    let network: String
    let method: String
    let txDigest: String
    let peerId: String
    let channelId: String
    let messageKind: String
    let dustCostRaw: String
    let messagePreview: String
    let humanSummary: String
    let warnings: [String]
}

struct ApprovalReviewPayload: Codable {
    let kind: String
    let transaction: TxReviewPayload?
    let channelOpen: ChannelOpenReviewPayload?
    let messageSend: MessageSendReviewPayload?

    var method: String {
        transaction?.method ?? channelOpen?.method ?? messageSend?.method ?? "transfer"
    }

    var txDigest: String {
        transaction?.txDigest ?? channelOpen?.txDigest ?? messageSend?.txDigest ?? ""
    }

    var humanSummary: String {
        transaction?.humanSummary ?? channelOpen?.humanSummary ?? messageSend?.humanSummary ?? ""
    }

    var warnings: [String] {
        transaction?.warnings ?? channelOpen?.warnings ?? messageSend?.warnings ?? []
    }
}

struct PendingApprovalView: Codable {
    let pendingId: String
    let origin: String
    let network: String
    let method: String
    let txDigest: String
    let createdAt: Date
    let expiresAt: Date
    let review: ApprovalReviewPayload
}

struct PreparedTransactionHandle: Codable {
    let sessionId: String
    let txDigest: String
    let review: TxReviewPayload
    let method: String
}

enum MessagingCommitKind: String, Codable {
    case openChannel = "open-channel"
    case sendMessage = "send-message"
}

struct ApprovalToken: Codable {
    let tokenId: String
    let pendingId: String
    let origin: String
    let network: String
    let method: String
    let txDigest: String
}

struct SubmissionGrant: Codable {
    let grantId: String
    let tokenId: String
    let origin: String
    let network: String
    let method: String
    let txDigest: String
    let issuedAt: Date
    let expiresAt: Date
}

struct BridgeOriginGrantInput: Codable {
    let origin: String
    let scopes: [BridgeScope]
    let authorizedAt: Date
    let note: String?
}

enum PendingActionKind: String, CaseIterable, Identifiable {
    case transfer
    case shield
    case unshield

    var id: String { rawValue }
}

struct BridgeRequestContext {
    let requestId: String
    let origin: String
    let sessionHandle: OpaquePointer
}

struct PendingApprovalFlow: Identifiable {
    let id = UUID()
    let handle: OpaquePointer
    let review: ApprovalReviewPayload
    let prepared: PreparedTransactionHandle?
    let messagingCommit: MessagingCommitKind?
    let bridgeRequest: BridgeRequestContext?
}

struct WalletPeerAdvertisement: Codable {
    let epochId: UInt64
    let x25519PublicKeyHex: String
    let mlKemPublicKeyHex: String
    let identityPublicKeyHex: String
}

struct WalletChannelInvite: Codable {
    let peerId: String
    let channelId: String
    let displayName: String?
    let advertisement: WalletPeerAdvertisement
    let invitationCode: String
}

struct WalletChannelOpenRequest: Codable {
    let peerId: String
    let displayName: String?
    let remoteInvite: WalletChannelInvite
}

struct ChannelStatus: Codable {
    let peerId: String
    let channelId: String
    let state: String
    let reason: String?
    let localInvite: WalletChannelInvite?
    let remoteInvite: WalletChannelInvite?
    let openedAt: Date?
    let lastRotatedAt: Date?
}

struct ConversationView: Codable, Identifiable {
    let peerId: String
    let displayName: String?
    let channelId: String
    let unreadCount: Int
    let lastMessagePreview: String?
    let lastMessageAt: Date?
    let dustSpentRaw: String
    let status: ChannelStatus

    var id: String { peerId }
}

struct MessagingTransportStatus: Codable {
    let mode: MessagingTransportMode?
    let available: Bool
    let mailboxContractAddress: String?
    let lastHealthyProbeAt: Date?
    let lastPollAt: Date?
    let lastObservedCursor: String?
    let reason: String?
}

enum MessagingTransportMode: String, Codable {
    case unavailable
    case helperAdapter = "helper-adapter"
    case disabledOnIos = "disabled-on-ios"
}

enum WalletMessageDirection: String, Codable {
    case inbound
    case outbound
}

enum WalletMessageStatus: String, Codable {
    case pending
    case posted
    case failed
    case received
}

enum WalletMessageKind: String, Codable {
    case text
    case transferReceipt = "transfer-receipt"
    case credentialRequest = "credential-request"
    case credentialResponse = "credential-response"
}

struct WalletTransferReceipt: Codable {
    let txHash: String
    let nightTotalRaw: String
    let dustTotalRaw: String
    let summary: String
}

struct WalletCredentialRequest: Codable {
    let requestId: String
    let claimSummary: String
}

struct WalletCredentialResponse: Codable {
    let requestId: String
    let disclosureSummary: String
    let proofReference: String?
}

enum WalletMessageContent: Codable {
    case text(String)
    case transferReceipt(WalletTransferReceipt)
    case credentialRequest(WalletCredentialRequest)
    case credentialResponse(WalletCredentialResponse)

    enum CodingKeys: String, CodingKey {
        case kind
        case text
        case txHash
        case nightTotalRaw
        case dustTotalRaw
        case summary
        case requestId
        case claimSummary
        case disclosureSummary
        case proofReference
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let kind = try container.decode(WalletMessageKind.self, forKey: .kind)
        switch kind {
        case .text:
            self = .text(try container.decode(String.self, forKey: .text))
        case .transferReceipt:
            self = .transferReceipt(
                WalletTransferReceipt(
                    txHash: try container.decode(String.self, forKey: .txHash),
                    nightTotalRaw: try container.decode(String.self, forKey: .nightTotalRaw),
                    dustTotalRaw: try container.decode(String.self, forKey: .dustTotalRaw),
                    summary: try container.decode(String.self, forKey: .summary)
                )
            )
        case .credentialRequest:
            self = .credentialRequest(
                WalletCredentialRequest(
                    requestId: try container.decode(String.self, forKey: .requestId),
                    claimSummary: try container.decode(String.self, forKey: .claimSummary)
                )
            )
        case .credentialResponse:
            self = .credentialResponse(
                WalletCredentialResponse(
                    requestId: try container.decode(String.self, forKey: .requestId),
                    disclosureSummary: try container.decode(String.self, forKey: .disclosureSummary),
                    proofReference: try container.decodeIfPresent(String.self, forKey: .proofReference)
                )
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case let .text(value):
            try container.encode(WalletMessageKind.text, forKey: .kind)
            try container.encode(value, forKey: .text)
        case let .transferReceipt(receipt):
            try container.encode(WalletMessageKind.transferReceipt, forKey: .kind)
            try container.encode(receipt.txHash, forKey: .txHash)
            try container.encode(receipt.nightTotalRaw, forKey: .nightTotalRaw)
            try container.encode(receipt.dustTotalRaw, forKey: .dustTotalRaw)
            try container.encode(receipt.summary, forKey: .summary)
        case let .credentialRequest(request):
            try container.encode(WalletMessageKind.credentialRequest, forKey: .kind)
            try container.encode(request.requestId, forKey: .requestId)
            try container.encode(request.claimSummary, forKey: .claimSummary)
        case let .credentialResponse(response):
            try container.encode(WalletMessageKind.credentialResponse, forKey: .kind)
            try container.encode(response.requestId, forKey: .requestId)
            try container.encode(response.disclosureSummary, forKey: .disclosureSummary)
            try container.encodeIfPresent(response.proofReference, forKey: .proofReference)
        }
    }

    var preview: String {
        switch self {
        case let .text(value):
            return value
        case let .transferReceipt(receipt):
            return receipt.summary
        case let .credentialRequest(request):
            return request.claimSummary
        case let .credentialResponse(response):
            return response.disclosureSummary
        }
    }
}

struct WalletMessage: Codable, Identifiable {
    let messageId: String
    let channelId: String
    let peerId: String
    let direction: WalletMessageDirection
    let status: WalletMessageStatus
    let kind: WalletMessageKind
    let sequence: UInt64
    let sentAt: Date
    let receivedAt: Date?
    let dustCostRaw: String
    let envelopeHash: String
    let content: WalletMessageContent

    var id: String { messageId }
}

struct MailboxEnvelope: Codable {
    let channelId: String
    let senderPeerId: String
    let receiverPeerId: String
    let messageKind: WalletMessageKind
    let sequence: UInt64
    let epochId: UInt64
    let senderAdvertisement: WalletPeerAdvertisement
    let nonceHex: String
    let ciphertextHex: String
    let mlKemCiphertextHex: String
    let payloadVersion: UInt32
    let senderSignatureHex: String
    let envelopeHash: String
    let postedAt: Date
}

struct PreparedMessage: Codable {
    let message: WalletMessage
    let envelope: MailboxEnvelope
    let submissionGrant: SubmissionGrant?
}

struct MessagingTransportUpdate: Codable {
    let mode: MessagingTransportMode
    let available: Bool
    let mailboxContractAddress: String?
    let lastHealthyProbeAt: Date?
    let lastPollAt: Date?
    let lastObservedCursor: String?
    let reason: String?
}

struct MailboxPostSuccess: Codable {
    let envelopeHash: String
    let txHash: String
    let postedAt: Date
    let cursor: String?
}

struct MailboxPostFailure: Codable {
    let envelopeHash: String
    let reason: String
}

struct MailboxTransportProbe: Codable {
    let sessionId: String
    let contractAddress: String
    let manifestPath: String
}

struct MailboxPostRequest: Codable {
    let sessionId: String
    let contractAddress: String
    let manifestPath: String
    let preparedMessage: PreparedMessage
}

struct MailboxPostResponse: Codable {
    let txHash: String
    let blockHeight: Int?
    let postedAt: Date
    let cursor: String?
}

struct MailboxPollRequest: Codable {
    let sessionId: String
    let contractAddress: String
    let manifestPath: String
    let receiverPeerId: String
    let lastObservedCursor: String?
}

struct MailboxPollResponse: Codable {
    let envelopes: [MailboxEnvelope]
    let transport: MessagingTransportUpdate
}

struct PendingSitePermissionRequest: Identifiable {
    let id: String
    let origin: String
    let networkId: String
}

extension JSONDecoder {
    static func walletDecoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }
}

extension JSONEncoder {
    static func walletEncoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }
}
