import Foundation
import Observation

enum SeedInputMode: String, CaseIterable, Identifiable {
    case mnemonic
    case masterSeed

    var id: String { rawValue }
}

@MainActor
@Observable
final class WalletCoordinator {
    struct VisualAuditConfig {
        enum State {
            case locked
            case unlocked
        }

        enum ApprovalMode: String {
            case transaction
            case message
        }

        let state: State
        let section: WalletSection
        let transactMode: TransactMode
        let approvalMode: ApprovalMode?

        static func fromProcessInfo() -> VisualAuditConfig? {
            let arguments = ProcessInfo.processInfo.arguments
            guard arguments.contains("-wallet-visual-audit") else {
                return nil
            }

            let state = arguments.value(after: "-wallet-audit-state")
                .flatMap(State.init(rawValue:))
                ?? .unlocked
            let section = arguments.value(after: "-wallet-audit-section")
                .flatMap(WalletSection.init(rawValue:))
                ?? .overview
            let transactMode = arguments.value(after: "-wallet-audit-transact-mode")
                .flatMap(TransactMode.init(rawValue:))
                ?? .send
            let approvalMode = arguments.value(after: "-wallet-audit-approval")
                .flatMap(ApprovalMode.init(rawValue:))

            return VisualAuditConfig(
                state: state,
                section: section,
                transactMode: transactMode,
                approvalMode: approvalMode
            )
        }
    }

    private struct MailboxTransportConfig {
        let contractAddress: String
        let manifestPath: String
    }

    let availableActions: [PendingActionKind] = [.transfer, .shield, .unshield]
    let isVisualAuditMode: Bool

    var selectedSection: WalletSection? = .overview
    var selectedTransactMode: TransactMode = .send
    var snapshot: WalletSnapshot?
    var configuration: OpenWalletSessionResponse.Configuration?
    var overview: WalletOverview?
    var conversations: [ConversationView] = []
    var selectedConversationPeerID: String?
    var activeConversationStatus: ChannelStatus?
    var activeMessages: [WalletMessage] = []
    var activity: [WalletActivityEntry] = []
    var dustCandidates: [DustUtxoCandidate] = []
    var helperCompatibilityReport: WalletHelperCompatibilityReport?
    var seedInputMode: SeedInputMode = .mnemonic
    var seedInput: String = ""
    var remoteInviteJSON: String = ""
    var messageComposerText: String = ""
    var sendRecipient: String = ""
    var sendAmountRaw: String = "1000000000000000"
    var sendAmountDisplay: String = WalletDisplay.editableNight(fromRaw: "1000000000000000")
    var sendShielded: Bool = false
    var shieldAmountRaw: String = "1000000000000000"
    var shieldAmountDisplay: String = WalletDisplay.editableNight(fromRaw: "1000000000000000")
    var unshieldAmountRaw: String = "1000000000000000"
    var unshieldAmountDisplay: String = WalletDisplay.editableNight(fromRaw: "1000000000000000")
    var selectedDustOperation: DustOperationKind = .register
    var selectedDustCandidateIndexes: Set<Int> = []
    var dustReceiverAddress: String = ""
    var primaryProverURL: String = "http://127.0.0.1:6300"
    var fallbackProverURL: String = ""
    var gatewayURL: String = "http://127.0.0.1:6311"
    var selectedAction: PendingActionKind = .transfer
    var pendingApproval: PendingApprovalFlow?
    var pendingSitePermission: PendingSitePermissionRequest?
    var statusMessage: String?
    var lastSubmittedTransactionID: String?
    var isBusy: Bool = false
    var helperExecutionAvailability: WalletHelperExecutionAvailability

    private let ffi: WalletFFIClient
    private let helper = WalletHelperProcess()
    private let bridgeStore = WalletBridgeStore()
    private let encoder = JSONEncoder.walletEncoder()
    private let decoder = JSONDecoder.walletDecoder()
    private let defaults = UserDefaults.standard
    private let visualAuditConfig: VisualAuditConfig?
    private var helperSession: OpenWalletSessionResponse?
    private var bridgePumpTask: Task<Void, Never>?
    private var messagingPollTask: Task<Void, Never>?

    init() {
        let baseRoot = WalletBridgeStore.sharedRootURL()
            .appendingPathComponent("WalletState", isDirectory: true)
        let persistentRoot = baseRoot.appendingPathComponent("persistent", isDirectory: true)
        let cacheRoot = baseRoot.appendingPathComponent("cache", isDirectory: true)
        ffi = try! WalletFFIClient(network: "preprod", persistentRoot: persistentRoot, cacheRoot: cacheRoot)
        visualAuditConfig = VisualAuditConfig.fromProcessInfo()
        isVisualAuditMode = visualAuditConfig != nil
        helperExecutionAvailability = helper.executionAvailability
        syncDisplayAmountsFromRaw()
        if let visualAuditConfig {
            applyVisualAudit(config: visualAuditConfig)
            return
        }
        refreshLocalSnapshot()
        loadSettings()
        syncSettingsFromSnapshotIfAvailable()
        publishBridgeStatus()
        startBridgePumpIfNeeded()
        if let message = helperExecutionAvailability.message {
            statusMessage = message
        }
        Task { [weak self] in
            await self?.refreshHelperCompatibilityReport()
        }
    }

    func importSeed() {
        guard !seedInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            statusMessage = "Enter a mnemonic or master seed first."
            return
        }
        do {
            switch seedInputMode {
            case .mnemonic:
                _ = try ffi.importMnemonic(seedInput)
            case .masterSeed:
                _ = try ffi.importMasterSeed(seedInput)
            }
            seedInput = ""
            statusMessage = "Seed imported into the native wallet."
            refreshLocalSnapshot()
            publishBridgeStatus()
        } catch {
            statusMessage = error.localizedDescription
        }
    }

    func unlock() async {
        await withBusyState { [self] in
            try self.ffi.unlock(prompt: "Unlock ZirOS Midnight Wallet")
            self.selectedSection = .overview
            try await self.refreshRemoteState()
            self.startMessagingPollIfNeeded()
            if self.helperExecutionAvailability.isAvailable {
                self.statusMessage = "Wallet unlocked with device biometrics."
            } else if let message = self.helperExecutionAvailability.message {
                self.statusMessage = message
            }
            await self.bridgePumpTick()
        }
    }

    func lock() async {
        await withBusyState { [self] in
            self.stopMessagingPoll()
            try await self.closeInteractiveState(reason: "Wallet locked.")
            try self.ffi.closeHelperSession()
            try self.ffi.lock()
            self.helperSession = nil
            self.configuration = nil
            self.overview = nil
            self.conversations = []
            self.selectedConversationPeerID = nil
            self.activeConversationStatus = nil
            self.activeMessages = []
            self.activity = []
            self.dustCandidates = []
            self.statusMessage = "Wallet locked."
            self.refreshLocalSnapshot()
            self.publishBridgeStatus()
        }
    }

    func appBackgrounded() async {
        await withBusyState { [self] in
            self.stopMessagingPoll()
            try await self.closeInteractiveState(reason: "Wallet locked after backgrounding.")
            try self.ffi.closeHelperSession()
            try self.ffi.appBackgrounded()
            self.helperSession = nil
            self.configuration = nil
            self.overview = nil
            self.conversations = []
            self.selectedConversationPeerID = nil
            self.activeConversationStatus = nil
            self.activeMessages = []
            self.activity = []
            self.dustCandidates = []
            self.statusMessage = "Wallet locked after backgrounding."
            self.refreshLocalSnapshot()
            self.publishBridgeStatus()
        }
    }

    func refresh() async {
        guard !isVisualAuditMode else {
            return
        }
        await withBusyState { [self] in
            try await self.refreshRemoteState()
        }
    }

    func handleIncomingBridgeURL(_ url: URL) {
        startBridgePumpIfNeeded()
        selectedSection = .more
        if let requestID = URLComponents(url: url, resolvingAgainstBaseURL: false)?
            .queryItems?
            .first(where: { $0.name == "id" })?
            .value
        {
            statusMessage = "Incoming DApp request \(requestID)."
        }
        Task { await bridgePumpTick() }
    }

    func openExplorerTransaction(txHash: String) {
        guard let baseURL = snapshot?.services?.explorerUrl,
              let url = URL(string: "\(baseURL)/transactions/\(txHash)")
        else {
            WalletPlatformSupport.copyToPasteboard(txHash)
            statusMessage = "Transaction hash copied for external verification."
            return
        }
        WalletPlatformSupport.openURL(url)
    }

    func beginSelectedAction() async {
        await withBusyState { [self] in
            guard self.helperExecutionAvailability.isAvailable else {
                throw WalletHelperRuntimeError.executionUnavailable(
                    self.helperExecutionAvailability.message ?? "Midnight execution is unavailable."
                )
            }
            guard let session = self.helperSession else {
                throw NSError(domain: "WalletCoordinator", code: 10, userInfo: [NSLocalizedDescriptionKey: "Unlock the wallet before creating transactions."])
            }
            let prepared: PreparedTransactionHandle
            switch self.selectedAction {
            case .transfer:
                prepared = try await self.helper.buildTransfer(
                    sessionID: session.sessionId,
                    origin: "native://wallet",
                    desiredOutputs: [
                        BridgeDesiredOutput(
                            mode: self.sendShielded ? "shielded" : "unshielded",
                            receiverAddress: self.sendRecipient,
                            tokenType: "NIGHT",
                            amountRaw: self.sendAmountRaw
                        ),
                    ],
                    payFees: true
                )
            case .shield:
                prepared = try await self.helper.buildShield(
                    sessionID: session.sessionId,
                    origin: "native://wallet",
                    tokenType: "NIGHT",
                    amountRaw: self.shieldAmountRaw
                )
            case .unshield:
                prepared = try await self.helper.buildUnshield(
                    sessionID: session.sessionId,
                    origin: "native://wallet",
                    tokenType: "NIGHT",
                    amountRaw: self.unshieldAmountRaw
                )
            }
            let pendingHandle = try self.ffi.beginNativeAction(review: prepared.review)
            let pendingReview = try self.ffi.pendingReview(pending: pendingHandle)
            self.pendingApproval = PendingApprovalFlow(
                handle: pendingHandle,
                review: pendingReview.review,
                prepared: prepared,
                messagingCommit: nil,
                bridgeRequest: nil
            )
        }
    }

    func beginSend() async {
        selectedSection = .transact
        selectedTransactMode = .send
        selectedAction = .transfer
        await beginSelectedAction()
    }

    func beginShield() async {
        selectedSection = .transact
        selectedTransactMode = .shield
        selectedAction = .shield
        await beginSelectedAction()
    }

    func beginUnshield() async {
        selectedSection = .transact
        selectedTransactMode = .unshield
        selectedAction = .unshield
        await beginSelectedAction()
    }

    func updateSendAmountDisplay(_ value: String) {
        updateNightAmountInput(value, rawValue: &sendAmountRaw, displayValue: &sendAmountDisplay)
    }

    func updateShieldAmountDisplay(_ value: String) {
        updateNightAmountInput(value, rawValue: &shieldAmountRaw, displayValue: &shieldAmountDisplay)
    }

    func updateUnshieldAmountDisplay(_ value: String) {
        updateNightAmountInput(value, rawValue: &unshieldAmountRaw, displayValue: &unshieldAmountDisplay)
    }

    func fillMaxSendAmount() {
        guard let rawAmount = WalletDisplay.rawNight(fromBalanceDisplay: overview?.balances.unshielded["NIGHT"]) else {
            return
        }
        sendAmountRaw = rawAmount
        sendAmountDisplay = WalletDisplay.editableNight(fromRaw: rawAmount)
    }

    func fillMaxShieldAmount() {
        guard let rawAmount = WalletDisplay.rawNight(fromBalanceDisplay: overview?.balances.unshielded["NIGHT"]) else {
            return
        }
        shieldAmountRaw = rawAmount
        shieldAmountDisplay = WalletDisplay.editableNight(fromRaw: rawAmount)
    }

    func fillMaxUnshieldAmount() {
        guard let rawAmount = WalletDisplay.rawNight(fromBalanceDisplay: overview?.balances.shielded["NIGHT"]) else {
            return
        }
        unshieldAmountRaw = rawAmount
        unshieldAmountDisplay = WalletDisplay.editableNight(fromRaw: rawAmount)
    }

    func beginDustOperation() async {
        await withBusyState { [self] in
            guard self.helperExecutionAvailability.isAvailable else {
                throw WalletHelperRuntimeError.executionUnavailable(
                    self.helperExecutionAvailability.message ?? "Midnight execution is unavailable."
                )
            }
            guard let session = self.helperSession else {
                throw NSError(domain: "WalletCoordinator", code: 13, userInfo: [NSLocalizedDescriptionKey: "Unlock the wallet before managing DUST."])
            }
            let prepared: PreparedTransactionHandle
            let indexes = self.selectedDustCandidateIndexes.sorted()
            switch self.selectedDustOperation {
            case .register:
                prepared = try await self.helper.registerDust(
                    sessionID: session.sessionId,
                    origin: "native://wallet",
                    utxoIndexes: indexes,
                    dustReceiverAddress: self.trimmedDustReceiverAddress
                )
            case .deregister:
                prepared = try await self.helper.deregisterDust(
                    sessionID: session.sessionId,
                    origin: "native://wallet",
                    utxoIndexes: indexes
                )
            case .redesignate:
                guard let dustReceiverAddress = self.trimmedDustReceiverAddress else {
                    throw NSError(domain: "WalletCoordinator", code: 14, userInfo: [NSLocalizedDescriptionKey: "Enter a DUST receiver address before redesignating."])
                }
                prepared = try await self.helper.redesignateDust(
                    sessionID: session.sessionId,
                    origin: "native://wallet",
                    utxoIndexes: indexes,
                    dustReceiverAddress: dustReceiverAddress
                )
            }
            let pendingHandle = try self.ffi.beginNativeAction(review: prepared.review)
            let pendingReview = try self.ffi.pendingReview(pending: pendingHandle)
            self.pendingApproval = PendingApprovalFlow(
                handle: pendingHandle,
                review: pendingReview.review,
                prepared: prepared,
                messagingCommit: nil,
                bridgeRequest: nil
            )
        }
    }

    func selectConversation(peerID: String) {
        selectedConversationPeerID = peerID
        do {
            activeConversationStatus = try ffi.messagingChannelStatus(peerID: peerID)
            activeMessages = try ffi.messagingConversation(peerID: peerID)
        } catch {
            statusMessage = error.localizedDescription
        }
    }

    func openMessagingChannel() async {
        await withBusyState { [self] in
            guard self.canComposeMessages else {
                throw NSError(
                    domain: "WalletCoordinator",
                    code: 39,
                    userInfo: [NSLocalizedDescriptionKey: self.snapshot?.messagingStatus?.reason ?? "Mailbox transport is unavailable on this device."]
                )
            }
            let payload = self.remoteInviteJSON.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !payload.isEmpty else {
                throw NSError(domain: "WalletCoordinator", code: 40, userInfo: [NSLocalizedDescriptionKey: "Paste a peer invite JSON blob first."])
            }
            let invite = try self.decoder.decode(WalletChannelInvite.self, from: Data(payload.utf8))
            let request = WalletChannelOpenRequest(
                peerId: invite.peerId,
                displayName: invite.displayName,
                remoteInvite: invite
            )
            let pendingHandle = try self.ffi.messagingPrepareOpenChannel(request)
            let pendingReview = try self.ffi.pendingReview(pending: pendingHandle)
            self.pendingApproval = PendingApprovalFlow(
                handle: pendingHandle,
                review: pendingReview.review,
                prepared: nil,
                messagingCommit: .openChannel,
                bridgeRequest: nil
            )
            self.statusMessage = "Review channel opening for \(invite.displayName ?? invite.peerId)."
        }
    }

    func sendMessage() async {
        await withBusyState { [self] in
            guard self.canComposeMessages else {
                throw NSError(
                    domain: "WalletCoordinator",
                    code: 44,
                    userInfo: [NSLocalizedDescriptionKey: self.snapshot?.messagingStatus?.reason ?? "Mailbox transport is unavailable on this device."]
                )
            }
            guard let peerID = self.selectedConversationPeerID else {
                throw NSError(domain: "WalletCoordinator", code: 41, userInfo: [NSLocalizedDescriptionKey: "Select a conversation before sending a message."])
            }
            let text = self.messageComposerText.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !text.isEmpty else {
                throw NSError(domain: "WalletCoordinator", code: 42, userInfo: [NSLocalizedDescriptionKey: "Enter a message before sending."])
            }
            let pendingHandle = try self.ffi.messagingPrepareText(peerID: peerID, text: text)
            let pendingReview = try self.ffi.pendingReview(pending: pendingHandle)
            self.pendingApproval = PendingApprovalFlow(
                handle: pendingHandle,
                review: pendingReview.review,
                prepared: nil,
                messagingCommit: .sendMessage,
                bridgeRequest: nil
            )
            self.statusMessage = "Review DUST-spending message send."
        }
    }

    func sendTransferReceipt(from entry: WalletActivityEntry) async {
        await withBusyState { [self] in
            guard self.canComposeMessages else {
                throw NSError(
                    domain: "WalletCoordinator",
                    code: 45,
                    userInfo: [NSLocalizedDescriptionKey: self.snapshot?.messagingStatus?.reason ?? "Mailbox transport is unavailable on this device."]
                )
            }
            guard let peerID = self.selectedConversationPeerID else {
                throw NSError(domain: "WalletCoordinator", code: 43, userInfo: [NSLocalizedDescriptionKey: "Select a conversation before sending a transfer receipt."])
            }
            let receipt = WalletTransferReceipt(
                txHash: entry.hash,
                nightTotalRaw: "0",
                dustTotalRaw: entry.feesRaw ?? "0",
                summary: "Receipt for \(entry.hash.prefix(12))…"
            )
            let pendingHandle = try self.ffi.messagingPrepareTransferReceipt(peerID: peerID, receipt: receipt)
            let pendingReview = try self.ffi.pendingReview(pending: pendingHandle)
            self.pendingApproval = PendingApprovalFlow(
                handle: pendingHandle,
                review: pendingReview.review,
                prepared: nil,
                messagingCommit: .sendMessage,
                bridgeRequest: nil
            )
            self.statusMessage = "Review transfer receipt send."
        }
    }

    func copyLocalInvite() {
        guard let invite = activeConversationStatus?.localInvite else {
            statusMessage = "Open or receive a channel before copying your invite."
            return
        }
        guard let data = try? encoder.encode(invite), let string = String(data: data, encoding: .utf8) else {
            statusMessage = "Unable to encode local invite."
            return
        }
        WalletPlatformSupport.copyToPasteboard(string)
        statusMessage = "Copied local invite JSON for \(invite.peerId)."
    }

    func closeSelectedConversation() {
        guard let peerID = selectedConversationPeerID else {
            return
        }
        do {
            _ = try ffi.messagingCloseChannel(peerID: peerID)
            try refreshMessagingState()
            statusMessage = "Closed messaging channel for \(peerID)."
        } catch {
            statusMessage = error.localizedDescription
        }
    }

    func approvePending() async {
        await withBusyState { [self] in
            guard let flow = self.pendingApproval else {
                throw NSError(domain: "WalletCoordinator", code: 11, userInfo: [NSLocalizedDescriptionKey: "No pending approval is available."])
            }
            defer {
                self.ffi.freePending(flow.handle)
                if let bridgeRequest = flow.bridgeRequest {
                    self.ffi.freeBridgeSession(bridgeRequest.sessionHandle)
                }
                self.pendingApproval = nil
            }

            let token = try self.ffi.approvePending(
                pending: flow.handle,
                prompt: self.biometricPrompt(for: flow.review.method),
                secondaryPrompt: "Confirm large NIGHT transfer"
            )

            if let bridgeRequest = flow.bridgeRequest {
                guard let session = self.helperSession else {
                    throw NSError(domain: "WalletCoordinator", code: 12, userInfo: [NSLocalizedDescriptionKey: "Unlock the wallet before approving requests."])
                }
                guard let prepared = flow.prepared else {
                    throw NSError(domain: "WalletCoordinator", code: 15, userInfo: [NSLocalizedDescriptionKey: "Bridge approval is missing prepared transaction state."])
                }
                let grant = try self.ffi.issueBridgeSubmissionGrant(
                    session: bridgeRequest.sessionHandle,
                    method: self.grantMethod(for: prepared.method),
                    txDigest: prepared.txDigest,
                    token: token
                )
                try self.ffi.consumeBridgeSubmissionGrant(
                    session: bridgeRequest.sessionHandle,
                    method: self.grantMethod(for: prepared.method),
                    txDigest: prepared.txDigest,
                    grant: grant
                )
                let txID = try await self.helper.finalizeAndSubmit(
                    sessionID: session.sessionId,
                    txDigest: prepared.txDigest,
                    grant: grant
                )
                let response = [
                    "txId": txID,
                    "txDigest": prepared.txDigest,
                    "networkId": self.snapshot?.network ?? "preprod",
                ]
                self.bridgeStore.complete(id: bridgeRequest.requestId, responseJSON: try self.jsonString(fromJSONObject: response))
                self.lastSubmittedTransactionID = txID
                self.statusMessage = "Approved \(prepared.method) for \(bridgeRequest.origin)."
            } else if let messagingCommit = flow.messagingCommit {
                switch messagingCommit {
                case .openChannel:
                    let conversation = try self.ffi.messagingCommitOpenChannel(token: token)
                    self.selectedSection = .messages
                    self.selectedConversationPeerID = conversation.peerId
                    await self.performMessagingPoll()
                    try self.refreshMessagingState()
                    self.statusMessage = "Opened encrypted channel with \(conversation.displayName ?? conversation.peerId)."
                case .sendMessage:
                    let preparedMessage = try self.ffi.messagingCommitSendMessage(token: token)
                    guard let session = self.helperSession else {
                        throw NSError(domain: "WalletCoordinator", code: 46, userInfo: [NSLocalizedDescriptionKey: "Unlock the macOS helper session before posting mailbox messages."])
                    }
                    guard let transportConfig = self.resolveMailboxTransportConfig() else {
                        throw NSError(domain: "WalletCoordinator", code: 47, userInfo: [NSLocalizedDescriptionKey: "Mailbox contract deployment is not configured."])
                    }
                    guard preparedMessage.submissionGrant != nil else {
                        throw NSError(domain: "WalletCoordinator", code: 48, userInfo: [NSLocalizedDescriptionKey: "Prepared mailbox post is missing a Rust-issued grant."])
                    }
                    do {
                        let post = try await self.helper.postMailboxEnvelope(
                            sessionID: session.sessionId,
                            contractAddress: transportConfig.contractAddress,
                            manifestPath: transportConfig.manifestPath,
                            preparedMessage: preparedMessage
                        )
                        _ = try self.ffi.messagingCompleteMailboxPost(
                            MailboxPostSuccess(
                                envelopeHash: preparedMessage.message.envelopeHash,
                                txHash: post.txHash,
                                postedAt: post.postedAt,
                                cursor: post.cursor
                            )
                        )
                    } catch {
                        _ = try? self.ffi.messagingFailMailboxPost(
                            MailboxPostFailure(
                                envelopeHash: preparedMessage.message.envelopeHash,
                                reason: error.localizedDescription
                            )
                        )
                        throw error
                    }
                    self.selectedSection = .messages
                    self.selectedConversationPeerID = preparedMessage.message.peerId
                    self.messageComposerText = ""
                    await self.performMessagingPoll()
                    try self.refreshMessagingState()
                    self.statusMessage = "Posted Midnight mailbox message for \(preparedMessage.message.peerId)."
                }
            } else {
                guard let session = self.helperSession else {
                    throw NSError(domain: "WalletCoordinator", code: 12, userInfo: [NSLocalizedDescriptionKey: "Unlock the wallet before approving requests."])
                }
                guard let prepared = flow.prepared else {
                    throw NSError(domain: "WalletCoordinator", code: 16, userInfo: [NSLocalizedDescriptionKey: "Native approval is missing prepared transaction state."])
                }
                let grant = try self.ffi.issueNativeSubmissionGrant(
                    method: self.grantMethod(for: prepared.method),
                    txDigest: prepared.txDigest,
                    token: token
                )
                try self.ffi.consumeNativeSubmissionGrant(
                    method: self.grantMethod(for: prepared.method),
                    txDigest: prepared.txDigest,
                    grant: grant
                )
                let txID = try await self.helper.finalizeAndSubmit(
                    sessionID: session.sessionId,
                    txDigest: prepared.txDigest,
                    grant: grant
                )
                self.lastSubmittedTransactionID = txID
                self.statusMessage = "Submitted Midnight transaction \(txID)."
            }

            try await self.refreshRemoteState()
        }
    }

    func rejectPending() {
        guard let flow = pendingApproval else {
            return
        }
        do {
            let reason: String
            if flow.messagingCommit != nil {
                reason = "User rejected the messaging request."
            } else {
                reason = "User rejected the transaction."
            }
            try ffi.rejectPending(pending: flow.handle, reason: reason)
            ffi.freePending(flow.handle)
            if let bridgeRequest = flow.bridgeRequest {
                bridgeStore.reject(id: bridgeRequest.requestId, error: "user_rejected: native app rejected the request.")
                ffi.freeBridgeSession(bridgeRequest.sessionHandle)
            }
            pendingApproval = nil
            statusMessage = flow.messagingCommit == nil ? "Transaction rejected." : "Messaging request rejected."
            publishBridgeStatus()
        } catch {
            statusMessage = error.localizedDescription
        }
    }

    func revokeOrigin(_ origin: String) {
        do {
            try ffi.revokeOrigin(origin)
            bridgeStore.revokeOrigin(origin)
            refreshLocalSnapshot()
            publishBridgeStatus()
            statusMessage = "Revoked \(origin)."
        } catch {
            statusMessage = error.localizedDescription
        }
    }

    func approveSitePermission() {
        guard let request = pendingSitePermission else {
            return
        }
        do {
            try ffi.grantOrigin(
                origin: request.origin,
                scopes: [.readConfig, .readBalances, .readAddresses, .readHistory, .transfer, .intent, .submit],
                note: "Authorized from Safari bridge"
            )
            bridgeStore.complete(
                id: request.id,
                responseJSON: try jsonString(fromJSONObject: [
                    "connected": true,
                    "networkId": request.networkId,
                    "origin": request.origin,
                ])
            )
            pendingSitePermission = nil
            refreshLocalSnapshot()
            publishBridgeStatus()
            statusMessage = "Authorized \(request.origin) for Midnight wallet access."
            Task { await bridgePumpTick() }
        } catch {
            bridgeStore.fail(id: request.id, error: error.localizedDescription)
            pendingSitePermission = nil
            statusMessage = error.localizedDescription
        }
    }

    func rejectSitePermission() {
        guard let request = pendingSitePermission else {
            return
        }
        bridgeStore.reject(id: request.id, error: "origin_unauthorized: site access was rejected in the native app.")
        pendingSitePermission = nil
        statusMessage = "Site permission rejected."
        publishBridgeStatus()
    }

    private func ensureHelperSession() async throws {
        guard !isVisualAuditMode else {
            return
        }
        helperExecutionAvailability = helper.executionAvailability
        guard helperExecutionAvailability.isAvailable else {
            throw WalletHelperRuntimeError.executionUnavailable(
                helperExecutionAvailability.message ?? "Midnight execution is unavailable."
            )
        }
        if helperSession != nil {
            return
        }
        let bundle = try ffi.openHelperBundle()
        helperSession = try await helper.openSession(
            bundle: bundle,
            proveRoutes: configuredProveRoutes(for: bundle)
        )
        configuration = helperSession?.configuration
    }

    private func refreshRemoteState() async throws {
        guard !isVisualAuditMode else {
            return
        }
        refreshLocalSnapshot()
        if snapshot?.locked == true {
            configuration = nil
            overview = nil
            conversations = []
            selectedConversationPeerID = nil
            activeConversationStatus = nil
            activeMessages = []
            activity = []
            dustCandidates = []
            publishBridgeStatus()
            return
        }
        try refreshMessagingState()
        helperExecutionAvailability = helper.executionAvailability
        await refreshHelperCompatibilityReport()
        if helperExecutionAvailability.isAvailable {
            try await ensureHelperSession()
        }
        try await refreshMessagingTransportStatus()
        if !helperExecutionAvailability.isAvailable {
            configuration = configurationFromServices(snapshot?.services)
            overview = nil
            activity = []
            dustCandidates = []
            publishBridgeStatus()
            return
        }
        guard let sessionID = helperSession?.sessionId else {
            publishBridgeStatus()
            return
        }
        overview = try await helper.sync(sessionID: sessionID)
        configuration = try await helper.configuration(sessionID: sessionID)
        activity = try await helper.activity(sessionID: sessionID)
        dustCandidates = try await helper.listDustCandidates(sessionID: sessionID)
        if selectedDustCandidateIndexes.isEmpty, let candidate = preferredDustCandidate {
            selectedDustCandidateIndexes = [candidate.index]
        }
        refreshLocalSnapshot()
        publishBridgeStatus()
    }

    private func refreshMessagingState() throws {
        conversations = try ffi.messagingListConversations()
        if selectedConversationPeerID == nil {
            selectedConversationPeerID = conversations.first?.peerId
        }
        guard let selectedConversationPeerID else {
            activeConversationStatus = nil
            activeMessages = []
            return
        }
        if conversations.contains(where: { $0.peerId == selectedConversationPeerID }) {
            activeConversationStatus = try ffi.messagingChannelStatus(peerID: selectedConversationPeerID)
            activeMessages = try ffi.messagingConversation(peerID: selectedConversationPeerID)
        } else {
            self.selectedConversationPeerID = conversations.first?.peerId
            activeConversationStatus = nil
            activeMessages = []
        }
    }

    private func refreshLocalSnapshot() {
        snapshot = try? ffi.snapshot()
        syncDisplayAmountsFromRaw()
    }

    private func updateNightAmountInput(
        _ value: String,
        rawValue: inout String,
        displayValue: inout String
    ) {
        let sanitized = WalletDisplay.sanitizedDecimalInput(value, maxFractionDigits: 3)
        displayValue = sanitized
        rawValue = WalletDisplay.rawNight(fromDisplay: sanitized) ?? ""
    }

    private func syncDisplayAmountsFromRaw() {
        sendAmountDisplay = WalletDisplay.editableNight(fromRaw: sendAmountRaw)
        shieldAmountDisplay = WalletDisplay.editableNight(fromRaw: shieldAmountRaw)
        unshieldAmountDisplay = WalletDisplay.editableNight(fromRaw: unshieldAmountRaw)
    }

    private func refreshHelperCompatibilityReport() async {
        guard !isVisualAuditMode else {
            return
        }
        helperCompatibilityReport = await helper.compatibilityReport()
        guard !helperExecutionAvailability.isAvailable,
              let reason = helperCompatibilityReport?.reason,
              statusMessage == nil || statusMessage == helperExecutionAvailability.message
        else {
            return
        }
        statusMessage = reason
    }

    private func startMessagingPollIfNeeded() {
        guard !isVisualAuditMode else {
            return
        }
        stopMessagingPoll()
        guard snapshot?.locked == false else {
            return
        }
        messagingPollTask = Task { [weak self] in
            await self?.performMessagingPoll()
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 10_000_000_000)
                await self?.performMessagingPoll()
            }
        }
    }

    private func performMessagingPoll() async {
        guard snapshot?.locked == false else {
            return
        }
        do {
            try await refreshMessagingTransportStatus()
            if helperExecutionAvailability.isAvailable,
               let session = helperSession,
               let transportConfig = resolveMailboxTransportConfig(),
               snapshot?.messagingStatus?.available == true
            {
                let response = try await helper.pollMailboxEnvelopes(
                    sessionID: session.sessionId,
                    contractAddress: transportConfig.contractAddress,
                    manifestPath: transportConfig.manifestPath,
                    receiverPeerID: localMessagingPeerID(),
                    lastObservedCursor: snapshot?.messagingStatus?.lastObservedCursor
                )
                _ = try ffi.messagingUpdateTransportStatus(response.transport)
                _ = try ffi.messagingPollMailbox()
                for envelope in response.envelopes {
                    _ = try ffi.messagingReceiveEnvelope(envelope)
                }
            } else {
                _ = try ffi.messagingPollMailbox()
            }
            refreshLocalSnapshot()
            try refreshMessagingState()
        } catch {
            statusMessage = error.localizedDescription
        }
    }

    private func stopMessagingPoll() {
        messagingPollTask?.cancel()
        messagingPollTask = nil
    }

    private func startBridgePumpIfNeeded() {
        guard !isVisualAuditMode else {
            return
        }
        guard bridgePumpTask == nil else {
            return
        }
        bridgePumpTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                await self.bridgePumpTick()
                try? await Task.sleep(nanoseconds: 1_000_000_000)
            }
        }
    }

    private func bridgePumpTick() async {
        publishBridgeStatus()
        guard snapshot?.locked == false else {
            return
        }
        guard !isBusy, pendingApproval == nil, pendingSitePermission == nil else {
            return
        }
        guard let request = bridgeStore.nextQueuedRequest() else {
            return
        }

        await withBusyState { [self] in
            switch request.method {
            case "connect":
                try self.prepareConnectRequest(request)
            case "makeTransfer":
                try await self.prepareBridgeTransfer(request)
            case "makeIntent":
                try await self.prepareBridgeIntent(request)
            default:
                self.bridgeStore.fail(
                    id: request.id,
                    error: "bridge_policy_violation: unsupported Safari bridge method '\(request.method)'."
                )
            }
        }
    }

    private func prepareConnectRequest(_ request: BridgeQueuedRequest) throws {
        let params = try decoder.decode(BridgeConnectParams.self, from: Data(request.paramsJSON.utf8))
        let currentNetwork = snapshot?.network ?? "preprod"
        guard params.networkId == nil || params.networkId == currentNetwork else {
            bridgeStore.fail(
                id: request.id,
                error: "network_mismatch: requested \(params.networkId ?? "unknown"), wallet is \(currentNetwork)."
            )
            return
        }
        if snapshot?.grants?.contains(where: { $0.origin == request.origin }) == true {
            bridgeStore.complete(
                id: request.id,
                responseJSON: try jsonString(fromJSONObject: [
                    "connected": true,
                    "networkId": currentNetwork,
                    "origin": request.origin,
                ])
            )
            publishBridgeStatus()
            return
        }
        bridgeStore.markProcessing(id: request.id)
        pendingSitePermission = PendingSitePermissionRequest(
            id: request.id,
            origin: request.origin,
            networkId: currentNetwork
        )
        statusMessage = "Review Safari DApp connection for \(request.origin)."
    }

    private func prepareBridgeTransfer(_ request: BridgeQueuedRequest) async throws {
        let params = try decoder.decode(BridgeMakeTransferParams.self, from: Data(request.paramsJSON.utf8))
        guard snapshot?.grants?.contains(where: { $0.origin == request.origin }) == true else {
            bridgeStore.reject(id: request.id, error: "origin_unauthorized: connect the DApp in the native app first.")
            return
        }
        guard helperExecutionAvailability.isAvailable else {
            bridgeStore.fail(
                id: request.id,
                error: helperExecutionAvailability.message ?? "Midnight execution is unavailable."
            )
            return
        }
        bridgeStore.markProcessing(id: request.id)
        try await ensureHelperSession()
        guard let session = helperSession else {
            throw NSError(domain: "WalletCoordinator", code: 20, userInfo: [NSLocalizedDescriptionKey: "Bridge helper session is unavailable."])
        }

        var bridgeSessionHandle: OpaquePointer?
        do {
            let handle = try ffi.openBridgeSession(origin: request.origin)
            bridgeSessionHandle = handle
            let prepared = try await helper.buildTransfer(
                sessionID: session.sessionId,
                origin: request.origin,
                desiredOutputs: params.desiredOutputs,
                payFees: params.options?.payFees ?? true
            )
            let pendingHandle = try ffi.beginBridgeTransfer(session: handle, review: prepared.review)
            let pendingReview = try ffi.pendingReview(pending: pendingHandle)
            pendingApproval = PendingApprovalFlow(
                handle: pendingHandle,
                review: pendingReview.review,
                prepared: prepared,
                messagingCommit: nil,
                bridgeRequest: BridgeRequestContext(requestId: request.id, origin: request.origin, sessionHandle: handle)
            )
            statusMessage = "Review Safari transfer for \(request.origin)."
        } catch {
            if let bridgeSessionHandle {
                ffi.freeBridgeSession(bridgeSessionHandle)
            }
            bridgeStore.fail(id: request.id, error: error.localizedDescription)
            throw error
        }
    }

    private func prepareBridgeIntent(_ request: BridgeQueuedRequest) async throws {
        let params = try decoder.decode(BridgeMakeIntentParams.self, from: Data(request.paramsJSON.utf8))
        guard snapshot?.grants?.contains(where: { $0.origin == request.origin }) == true else {
            bridgeStore.reject(id: request.id, error: "origin_unauthorized: connect the DApp in the native app first.")
            return
        }
        guard helperExecutionAvailability.isAvailable else {
            bridgeStore.fail(
                id: request.id,
                error: helperExecutionAvailability.message ?? "Midnight execution is unavailable."
            )
            return
        }
        bridgeStore.markProcessing(id: request.id)
        try await ensureHelperSession()
        guard let session = helperSession else {
            throw NSError(domain: "WalletCoordinator", code: 21, userInfo: [NSLocalizedDescriptionKey: "Bridge helper session is unavailable."])
        }

        var bridgeSessionHandle: OpaquePointer?
        do {
            let handle = try ffi.openBridgeSession(origin: request.origin)
            bridgeSessionHandle = handle
            let prepared = try await helper.buildIntent(
                sessionID: session.sessionId,
                origin: request.origin,
                desiredInputs: params.desiredInputs,
                desiredOutputs: params.desiredOutputs,
                payFees: params.options?.payFees ?? true
            )
            let pendingHandle = try ffi.beginBridgeIntent(session: handle, review: prepared.review)
            let pendingReview = try ffi.pendingReview(pending: pendingHandle)
            pendingApproval = PendingApprovalFlow(
                handle: pendingHandle,
                review: pendingReview.review,
                prepared: prepared,
                messagingCommit: nil,
                bridgeRequest: BridgeRequestContext(requestId: request.id, origin: request.origin, sessionHandle: handle)
            )
            statusMessage = "Review Safari intent for \(request.origin)."
        } catch {
            if let bridgeSessionHandle {
                ffi.freeBridgeSession(bridgeSessionHandle)
            }
            bridgeStore.fail(id: request.id, error: error.localizedDescription)
            throw error
        }
    }

    private func closeInteractiveState(reason: String) async throws {
        if let flow = pendingApproval {
            if let bridgeRequest = flow.bridgeRequest {
                bridgeStore.fail(id: bridgeRequest.requestId, error: "auth_required: wallet locked before approval completed.")
                ffi.freeBridgeSession(bridgeRequest.sessionHandle)
            }
            ffi.freePending(flow.handle)
            pendingApproval = nil
        }
        if let sitePermission = pendingSitePermission {
            bridgeStore.fail(id: sitePermission.id, error: "auth_required: wallet locked before site authorization completed.")
            pendingSitePermission = nil
        }
        if let sessionID = helperSession?.sessionId {
            try? await helper.closeSession(sessionID: sessionID)
        }
        configuration = nil
        dustCandidates = []
        statusMessage = reason
    }

    private func publishBridgeStatus() {
        let currentSnapshot = snapshot
        bridgeStore.updateRuntimeStatus { status in
            status.networkId = currentSnapshot?.network ?? "preprod"
            status.locked = currentSnapshot?.locked ?? true
            status.authorizedOrigins = currentSnapshot?.grants?.map(\.origin) ?? []
            status.activeOrigins = currentSnapshot?.bridgeSessions?.map(\.origin) ?? []
            status.configurationJSON = configurationJSON(
                helperConfiguration: configuration,
                services: currentSnapshot?.services
            )
            if currentSnapshot?.locked == false {
                status.overviewJSON = jsonStringIfPossible(overview)
                status.activityJSON = jsonStringIfPossible(activity)
            } else {
                status.overviewJSON = nil
                status.activityJSON = nil
            }
        }
    }

    private func applyVisualAudit(config: VisualAuditConfig) {
        let now = Date()
        let addresses = OpenWalletSessionResponse.Addresses(
            shieldedAddress: "midnight1shieldedziros0w2n6a8w5h9n2u0d9y3m4c7p5",
            shieldedCoinPublicKey: "zsw_shielded_coin_pk_visual_audit",
            shieldedEncryptionPublicKey: "zsw_shielded_encrypt_pk_visual_audit",
            unshieldedAddress: "midnight1unshieldedziros7q4k2t8j9v1n6d5s3y8x4m2p1",
            dustAddress: "midnight1dustziros4t7w5r3n1p9m6c2k8y0x5q4z2"
        )
        let proveRoutes = [
            ProveRoute(
                label: "Local Prover",
                kind: "local",
                proofServerUrl: primaryProverURL,
                gatewayUrl: gatewayURL,
                priority: 0
            ),
            ProveRoute(
                label: "Fallback Prover",
                kind: "upstream",
                proofServerUrl: "https://prover-fallback.preprod.midnight.network",
                gatewayUrl: "https://gateway.preprod.midnight.network",
                priority: 1
            ),
        ]
        let services = WalletServiceSnapshot(
            network: "preprod",
            rpcUrl: "https://rpc.preprod.midnight.network",
            indexerUrl: "https://indexer.preprod.midnight.network/api/v4/graphql",
            indexerWsUrl: "wss://indexer.preprod.midnight.network/api/v4/graphql/ws",
            explorerUrl: "https://explorer.preprod.midnight.network",
            proofServerUrl: primaryProverURL,
            gatewayUrl: gatewayURL,
            mailboxContractAddress: "midnight1mailboxpreprod2m7w8q1p6x4d9n3z5t0c8v1",
            mailboxManifestPath: "/Application Support/ZirOS/mailbox/preprod-mailbox.manifest.json",
            proveRoutes: proveRoutes
        )
        let helperConfiguration = OpenWalletSessionResponse.Configuration(
            indexerUri: services.indexerUrl,
            indexerWsUri: services.indexerWsUrl,
            proverServerUri: services.proofServerUrl,
            substrateNodeUri: services.rpcUrl,
            networkId: services.network,
            gatewayUrl: services.gatewayUrl,
            proveRoutes: services.proveRoutes
        )
        let overview = WalletOverview(
            network: "preprod",
            sync: .init(
                shieldedConnected: true,
                unshieldedConnected: true,
                dustConnected: true,
                synced: true
            ),
            balances: .init(
                shielded: ["NIGHT": "38,400"],
                unshielded: ["NIGHT": "11,600"],
                dust: .init(
                    spendableRaw: "94000000",
                    coinCount: 17,
                    registeredNightUtxos: 6
                )
            ),
            addresses: addresses
        )
        let localAdvertisement = WalletPeerAdvertisement(
            epochId: 412,
            x25519PublicKeyHex: "a4f87c02f6139a4ef6051a0b0a44ae1ee77ee1",
            mlKemPublicKeyHex: "10a872efab449dc72c991af4410c7208ef72f4",
            identityPublicKeyHex: "9e55c0ad18b6ff992b716d2fca3390bb7d41ab"
        )
        let remoteAdvertisement = WalletPeerAdvertisement(
            epochId: 413,
            x25519PublicKeyHex: "d0af73e51c77b5b82ad1ca3a2e5ea1350d16f2",
            mlKemPublicKeyHex: "00be78adff33ca65bd77f019ce903fcf6611a5",
            identityPublicKeyHex: "72ac1ee8f90b32ab1a7dc5f0a332cef4502ee8"
        )
        let localInvite = WalletChannelInvite(
            peerId: "peer-ziros-local",
            channelId: "ziros-channel-aurora",
            displayName: "ZirOS Alpha",
            advertisement: localAdvertisement,
            invitationCode: "ZIROS-LOCAL-AURORA"
        )
        let remoteInvite = WalletChannelInvite(
            peerId: "peer-midnight-labs",
            channelId: "ziros-channel-aurora",
            displayName: "Midnight Labs",
            advertisement: remoteAdvertisement,
            invitationCode: "MIDNIGHT-LABS-AURORA"
        )
        let activeStatus = ChannelStatus(
            peerId: remoteInvite.peerId,
            channelId: remoteInvite.channelId,
            state: "open",
            reason: nil,
            localInvite: localInvite,
            remoteInvite: remoteInvite,
            openedAt: now.addingTimeInterval(-86_400),
            lastRotatedAt: now.addingTimeInterval(-2_700)
        )
        let standbyStatus = ChannelStatus(
            peerId: "peer-ops",
            channelId: "ziros-channel-ops",
            state: "pending",
            reason: "Awaiting the other device to accept the invite.",
            localInvite: localInvite,
            remoteInvite: nil,
            openedAt: now.addingTimeInterval(-3_600),
            lastRotatedAt: now.addingTimeInterval(-3_600)
        )
        let messages: [WalletMessage] = [
            WalletMessage(
                messageId: "msg-001",
                channelId: remoteInvite.channelId,
                peerId: remoteInvite.peerId,
                direction: .inbound,
                status: .received,
                kind: .text,
                sequence: 14,
                sentAt: now.addingTimeInterval(-4_800),
                receivedAt: now.addingTimeInterval(-4_760),
                dustCostRaw: "1000000",
                envelopeHash: "env_14_aurora",
                content: .text("Proof route is healthy. I’m moving more NIGHT into the shielded side before the next sync.")
            ),
            WalletMessage(
                messageId: "msg-002",
                channelId: remoteInvite.channelId,
                peerId: remoteInvite.peerId,
                direction: .outbound,
                status: .posted,
                kind: .transferReceipt,
                sequence: 15,
                sentAt: now.addingTimeInterval(-2_800),
                receivedAt: nil,
                dustCostRaw: "1000000",
                envelopeHash: "env_15_aurora",
                content: .transferReceipt(
                    WalletTransferReceipt(
                        txHash: "0x9f41d18b8a2e7cc440b9f6d81a1d2fbc6d501ae4",
                        nightTotalRaw: "125000000000000000",
                        dustTotalRaw: "1000000",
                        summary: "Sent 125 NIGHT shielded with 1 DUST mailbox fee."
                    )
                )
            ),
            WalletMessage(
                messageId: "msg-003",
                channelId: remoteInvite.channelId,
                peerId: remoteInvite.peerId,
                direction: .outbound,
                status: .pending,
                kind: .text,
                sequence: 16,
                sentAt: now.addingTimeInterval(-240),
                receivedAt: nil,
                dustCostRaw: "1000000",
                envelopeHash: "env_16_aurora",
                content: .text("Fuel ring still looks strong. I can keep this channel active for roughly ninety-four more posts.")
            ),
        ]
        let conversations = [
            ConversationView(
                peerId: remoteInvite.peerId,
                displayName: remoteInvite.displayName,
                channelId: remoteInvite.channelId,
                unreadCount: 2,
                lastMessagePreview: messages.last?.content.preview,
                lastMessageAt: messages.last?.sentAt,
                dustSpentRaw: "3000000",
                status: activeStatus
            ),
            ConversationView(
                peerId: standbyStatus.peerId,
                displayName: "Operator Relay",
                channelId: standbyStatus.channelId,
                unreadCount: 0,
                lastMessagePreview: "Invite sent. Waiting for secure bind.",
                lastMessageAt: now.addingTimeInterval(-3_600),
                dustSpentRaw: "1000000",
                status: standbyStatus
            ),
        ]
        let activity = [
            WalletActivityEntry(
                id: 1,
                hash: "0x1f429bc9d99234da65ce443117018f4a8dbcc921",
                protocolVersion: 1,
                identifiers: ["shield", "night"],
                timestamp: now.addingTimeInterval(-7_200),
                feesRaw: "1000000",
                status: "finalized"
            ),
            WalletActivityEntry(
                id: 2,
                hash: "0xb6310ca91a4f24d44f985a34cfda113aa03f4772",
                protocolVersion: 1,
                identifiers: ["transfer", "night"],
                timestamp: now.addingTimeInterval(-25_200),
                feesRaw: "1000000",
                status: "finalized"
            ),
            WalletActivityEntry(
                id: 3,
                hash: "0xcf38d2bc1407d5513ea898778f4638ca4a0bcc98",
                protocolVersion: 1,
                identifiers: ["dust", "redesignate"],
                timestamp: now.addingTimeInterval(-52_000),
                feesRaw: "1000000",
                status: "submitted"
            ),
        ]
        let dustCandidates = [
            DustUtxoCandidate(
                index: 4,
                valueRaw: "45000000000000000",
                tokenType: "NIGHT",
                owner: addresses.unshieldedAddress,
                intentHash: "intent-004",
                outputNo: 0,
                ctime: now.addingTimeInterval(-7_200),
                registeredForDustGeneration: true
            ),
            DustUtxoCandidate(
                index: 5,
                valueRaw: "125000000000000000",
                tokenType: "NIGHT",
                owner: addresses.unshieldedAddress,
                intentHash: "intent-005",
                outputNo: 1,
                ctime: now.addingTimeInterval(-15_600),
                registeredForDustGeneration: false
            ),
            DustUtxoCandidate(
                index: 6,
                valueRaw: "90000000000000000",
                tokenType: "NIGHT",
                owner: addresses.unshieldedAddress,
                intentHash: "intent-006",
                outputNo: 0,
                ctime: now.addingTimeInterval(-28_800),
                registeredForDustGeneration: false
            ),
        ]
        let grants = [
            BridgeOriginGrantView(
                origin: "https://wallet-demo.midnight.network",
                scopes: [.readConfig, .readBalances, .readAddresses, .transfer],
                authorizedAt: now.addingTimeInterval(-14_400),
                note: "Audit fixture"
            ),
            BridgeOriginGrantView(
                origin: "https://launch.preprod.midnight.network",
                scopes: [.readConfig, .intent],
                authorizedAt: now.addingTimeInterval(-64_000),
                note: "Audit fixture"
            ),
        ]
        let bridgeSessions = [
            BridgeSessionSnapshot(
                sessionId: "bridge-audit-session-1",
                origin: grants[0].origin,
                scopes: grants[0].scopes,
                createdAt: now.addingTimeInterval(-14_000),
                lastActivityAt: now.addingTimeInterval(-600)
            ),
        ]
        let messagingStatus = MessagingTransportStatus(
            mode: .helperAdapter,
            available: true,
            mailboxContractAddress: services.mailboxContractAddress,
            lastHealthyProbeAt: now.addingTimeInterval(-90),
            lastPollAt: now.addingTimeInterval(-8),
            lastObservedCursor: "preprod:198445:7",
            reason: nil
        )

        helperExecutionAvailability = .available
        helperCompatibilityReport = WalletHelperCompatibilityReport(
            mode: "visual-audit",
            bridgeLoaded: true,
            helperRootConfigured: true,
            hasWebCrypto: true,
            hasRandomUUID: true,
            hasWebSocket: true,
            runtimeAvailable: true,
            reason: nil
        )
        helperSession = OpenWalletSessionResponse(
            sessionId: "visual-audit-session",
            configuration: helperConfiguration,
            addresses: addresses
        )
        configuration = helperConfiguration
        self.overview = overview
        self.conversations = conversations
        self.selectedConversationPeerID = conversations.first?.peerId
        self.activeConversationStatus = activeStatus
        self.activeMessages = messages
        self.activity = activity
        self.dustCandidates = dustCandidates
        self.selectedDustCandidateIndexes = [5]
        self.dustReceiverAddress = addresses.dustAddress
        self.sendRecipient = "midnight1auditreceiver9u2q7p4t5m8d1c6x3w0r9z2"
        self.sendAmountRaw = "125000000000000000"
        self.shieldAmountRaw = "11600000000000000000"
        self.unshieldAmountRaw = "38400000000000000000"
        self.messageComposerText = "Fuel ring looks strong. Posting one more encrypted update now."
        self.remoteInviteJSON = sampleInviteJSON(for: remoteInvite)
        self.snapshot = WalletSnapshot(
            schema: "wallet.snapshot.v1",
            walletId: "visual-audit-wallet",
            network: "preprod",
            locked: config.state == .locked,
            hasImportedSeed: true,
            importedSeedKind: "mnemonic",
            importedSeedAt: now.addingTimeInterval(-86400 * 19),
            helperSession: config.state == .locked ? nil : HelperSessionView(
                helperSessionId: "visual-audit-session",
                network: "preprod",
                seedKind: "mnemonic",
                openedAt: now.addingTimeInterval(-5_400),
                lastActivityAt: now.addingTimeInterval(-8)
            ),
            services: services,
            authPolicy: WalletAuthPolicy(
                strictBiometricsOnly: true,
                relockTimeoutSeconds: 300,
                approvalTtlSeconds: 120,
                largeTransferThresholdRaw: "100 NIGHT"
            ),
            grants: grants,
            bridgeSessions: bridgeSessions,
            messagingStatus: messagingStatus,
            history: [
                WalletHistoryEntry(
                    at: now.addingTimeInterval(-1_200),
                    kind: "message-posted",
                    detail: "Posted encrypted text to Midnight Labs."
                ),
                WalletHistoryEntry(
                    at: now.addingTimeInterval(-7_200),
                    kind: "shield",
                    detail: "Moved 125 NIGHT into the shielded pool."
                ),
            ]
        )
        if let approvalMode = config.approvalMode {
            switch approvalMode {
            case .transaction:
                let review = TxReviewPayload(
                    origin: "wallet-demo.midnight.network",
                    network: "preprod",
                    method: "transfer",
                    txDigest: "0x4e0f8b8bcfd4217e1de7c7cf4af77f76d293ce5a5f7c271aa8320f6dc6a1545e",
                    outputs: [
                        ReviewOutput(
                            recipient: "midnight1shieldedziros0w2n6a8w5h9n2u0d9y3m4c7p5",
                            tokenKind: "NIGHT",
                            amountRaw: "125000000000000000"
                        ),
                    ],
                    nightTotalRaw: "125000000000000000",
                    dustTotalRaw: "1000000",
                    feeRaw: "1000000",
                    dustImpact: "1 mailbox post",
                    shielded: true,
                    proverRoute: "Local Prover",
                    warnings: ["This action spends DUST and changes shielded balance."],
                    humanSummary: "Send 125 NIGHT shielded and spend 1 DUST for the transaction lane."
                )
                pendingApproval = PendingApprovalFlow(
                    handle: OpaquePointer(bitPattern: 1)!,
                    review: ApprovalReviewPayload(
                        kind: "transaction",
                        transaction: review,
                        channelOpen: nil,
                        messageSend: nil
                    ),
                    prepared: PreparedTransactionHandle(
                        sessionId: "visual-audit-session",
                        txDigest: review.txDigest,
                        review: review,
                        method: review.method
                    ),
                    messagingCommit: nil,
                    bridgeRequest: nil
                )
                selectedSection = .transact
                selectedTransactMode = .send
            case .message:
                let review = MessageSendReviewPayload(
                    origin: "wallet-demo.midnight.network",
                    network: "preprod",
                    method: "send-message",
                    txDigest: "0x9f41d18b8a2e7cc440b9f6d81a1d2fbc6d501ae4",
                    peerId: remoteInvite.peerId,
                    channelId: remoteInvite.channelId,
                    messageKind: "text",
                    dustCostRaw: "1000000",
                    messagePreview: "Fuel ring still looks strong. I can keep this channel active for roughly ninety-four more posts.",
                    humanSummary: "Review one DUST-spending Midnight message send before Face ID.",
                    warnings: ["Mailbox transport is live on macOS only in this tranche."],
                )
                pendingApproval = PendingApprovalFlow(
                    handle: OpaquePointer(bitPattern: 1)!,
                    review: ApprovalReviewPayload(
                        kind: "message-send",
                        transaction: nil,
                        channelOpen: nil,
                        messageSend: review
                    ),
                    prepared: nil,
                    messagingCommit: .sendMessage,
                    bridgeRequest: nil
                )
                selectedSection = .messages
                selectedTransactMode = config.transactMode
            }
        } else {
            selectedSection = config.section
            selectedTransactMode = config.transactMode
        }
        isBusy = false
        pendingSitePermission = nil
        lastSubmittedTransactionID = "0x9f41d18b8a2e7cc440b9f6d81a1d2fbc6d501ae4"
        statusMessage = nil
        syncDisplayAmountsFromRaw()
    }

    private func sampleInviteJSON(for invite: WalletChannelInvite) -> String {
        guard let data = try? encoder.encode(invite),
              let json = String(data: data, encoding: .utf8)
        else {
            return ""
        }
        return json
    }

    private func configurationJSON(
        helperConfiguration: OpenWalletSessionResponse.Configuration?,
        services: WalletServiceSnapshot?
    ) -> String {
        if let helperConfiguration {
            var configuration: [String: Any] = [
                "indexerUri": helperConfiguration.indexerUri,
                "indexerWsUri": helperConfiguration.indexerWsUri,
                "substrateNodeUri": helperConfiguration.substrateNodeUri,
                "networkId": helperConfiguration.networkId,
            ]
            if let proverServerUri = helperConfiguration.proverServerUri {
                configuration["proverServerUri"] = proverServerUri
            }
            if let gatewayUrl = helperConfiguration.gatewayUrl {
                configuration["gatewayUrl"] = gatewayUrl
            }
            if let proveRoutes = helperConfiguration.proveRoutes {
                configuration["proveRoutes"] = proveRoutes.map { route in
                    var routePayload: [String: Any] = [
                        "label": route.label,
                        "kind": route.kind,
                        "proofServerUrl": route.proofServerUrl,
                        "priority": route.priority,
                    ]
                    if let gatewayUrl = route.gatewayUrl {
                        routePayload["gatewayUrl"] = gatewayUrl
                    }
                    return routePayload
                }
            }
            return (try? jsonString(fromJSONObject: configuration)) ?? "{}"
        } else if let services {
            var configuration: [String: Any] = [
                "indexerUri": services.indexerUrl,
                "indexerWsUri": services.indexerWsUrl,
                "proverServerUri": services.proofServerUrl,
                "substrateNodeUri": services.rpcUrl,
                "networkId": services.network,
                "explorerUrl": services.explorerUrl,
                "gatewayUrl": services.gatewayUrl,
            ]
            if let proveRoutes = services.proveRoutes {
                configuration["proveRoutes"] = proveRoutes.map { route in
                    var routePayload: [String: Any] = [
                        "label": route.label,
                        "kind": route.kind,
                        "proofServerUrl": route.proofServerUrl,
                        "priority": route.priority,
                    ]
                    if let gatewayUrl = route.gatewayUrl {
                        routePayload["gatewayUrl"] = gatewayUrl
                    }
                    return routePayload
                }
            }
            return (try? jsonString(fromJSONObject: configuration)) ?? "{}"
        } else {
            return (try? jsonString(fromJSONObject: [
                "indexerUri": "https://indexer.preprod.midnight.network/api/v4/graphql",
                "indexerWsUri": "wss://indexer.preprod.midnight.network/api/v4/graphql/ws",
                "proverServerUri": "http://127.0.0.1:6300",
                "substrateNodeUri": "https://rpc.preprod.midnight.network",
                "networkId": "preprod",
                "explorerUrl": "https://explorer.preprod.midnight.network",
                "gatewayUrl": "http://127.0.0.1:6311",
            ])) ?? "{}"
        }
    }

    private func jsonStringIfPossible<T: Encodable>(_ value: T?) -> String? {
        guard let value, let data = try? encoder.encode(value) else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }

    private func jsonString(fromJSONObject value: Any) throws -> String {
        let data = try JSONSerialization.data(withJSONObject: value)
        guard let string = String(data: data, encoding: .utf8) else {
            throw NSError(domain: "WalletCoordinator", code: 30, userInfo: [NSLocalizedDescriptionKey: "Unable to encode bridge response."])
        }
        return string
    }

    private func withBusyState(_ operation: @escaping () async throws -> Void) async {
        guard !isBusy else {
            return
        }
        isBusy = true
        defer { isBusy = false }
        do {
            try await operation()
        } catch {
            statusMessage = error.localizedDescription
        }
        publishBridgeStatus()
    }

    private func biometricPrompt(for method: String) -> String {
        switch method {
        case "open-messaging-channel":
            return "Open encrypted messaging channel"
        case "send-message":
            return "Approve DUST-spending message send"
        case "shield":
            return "Approve shield transaction"
        case "unshield":
            return "Approve unshield transaction"
        case "dust-register":
            return "Approve DUST registration"
        case "dust-deregister":
            return "Approve DUST deregistration"
        case "dust-redesignate":
            return "Approve DUST receiver redesignation"
        case "intent":
            return "Approve Midnight intent"
        default:
            return "Approve NIGHT transfer"
        }
    }

    private func grantMethod(for preparedMethod: String) -> String {
        switch preparedMethod {
        case "shield":
            return "shield"
        case "unshield":
            return "unshield"
        case "dust-register":
            return "dust-register"
        case "dust-deregister":
            return "dust-deregister"
        case "dust-redesignate":
            return "dust-redesignate"
        case "intent":
            return "intent"
        default:
            return "transfer"
        }
    }

    private var trimmedDustReceiverAddress: String? {
        let value = dustReceiverAddress.trimmingCharacters(in: .whitespacesAndNewlines)
        return value.isEmpty ? nil : value
    }

    private var preferredDustCandidate: DustUtxoCandidate? {
        switch selectedDustOperation {
        case .register, .redesignate:
            return dustCandidates.first(where: { !$0.registeredForDustGeneration })
        case .deregister:
            return dustCandidates.first(where: \.registeredForDustGeneration)
        }
    }

    private func configuredProveRoutes(for bundle: WalletHelperBundle) -> [ProveRoute] {
        var routes = bundle.services.proveRoutes ?? [
            ProveRoute(
                label: "Local Midnight prover",
                kind: "local",
                proofServerUrl: bundle.services.proofServerUrl,
                gatewayUrl: bundle.services.gatewayUrl,
                priority: 0
            ),
        ]

        let primary = primaryProverURL.trimmingCharacters(in: .whitespacesAndNewlines)
        if !primary.isEmpty {
            routes.removeAll { $0.proofServerUrl == primary }
            routes.insert(
                ProveRoute(
                    label: primary.hasPrefix("http://127.0.0.1") ? "Local Midnight prover" : "Configured Midnight prover",
                    kind: primary.hasPrefix("http://127.0.0.1") ? "local" : "custom",
                    proofServerUrl: primary,
                    gatewayUrl: gatewayURL,
                    priority: -1
                ),
                at: 0
            )
        }

        let fallback = fallbackProverURL.trimmingCharacters(in: .whitespacesAndNewlines)
        if !fallback.isEmpty && !routes.contains(where: { $0.proofServerUrl == fallback }) {
            routes.append(
                ProveRoute(
                    label: "Fallback Midnight prover",
                    kind: "upstream",
                    proofServerUrl: fallback,
                    gatewayUrl: gatewayURL,
                    priority: 100
                )
            )
        }

        return routes
    }

    private var canComposeMessages: Bool {
        snapshot?.messagingStatus?.available == true
    }

    private func refreshMessagingTransportStatus() async throws {
        #if os(iOS)
        let disabled = MessagingTransportUpdate(
            mode: .disabledOnIos,
            available: false,
            mailboxContractAddress: snapshot?.messagingStatus?.mailboxContractAddress ?? snapshot?.services?.mailboxContractAddress,
            lastHealthyProbeAt: snapshot?.messagingStatus?.lastHealthyProbeAt,
            lastPollAt: snapshot?.messagingStatus?.lastPollAt,
            lastObservedCursor: snapshot?.messagingStatus?.lastObservedCursor,
            reason: "Midnight mailbox transport is macOS-only in this tranche. iPhone keeps Messages visible and history readable, but compose and channel-open stay disabled until a mobile-safe transport exists."
        )
        _ = try ffi.messagingUpdateTransportStatus(disabled)
        refreshLocalSnapshot()
        return
        #else
        guard let transportConfig = resolveMailboxTransportConfig() else {
            let unavailable = MessagingTransportUpdate(
                mode: .unavailable,
                available: false,
                mailboxContractAddress: snapshot?.services?.mailboxContractAddress,
                lastHealthyProbeAt: snapshot?.messagingStatus?.lastHealthyProbeAt,
                lastPollAt: snapshot?.messagingStatus?.lastPollAt,
                lastObservedCursor: snapshot?.messagingStatus?.lastObservedCursor,
                reason: "Messaging mailbox transport is unavailable until a bundled or configured deployment manifest with a contract address is present."
            )
            _ = try ffi.messagingUpdateTransportStatus(unavailable)
            refreshLocalSnapshot()
            return
        }
        guard let session = helperSession, helperExecutionAvailability.isAvailable else {
            let unavailable = MessagingTransportUpdate(
                mode: .helperAdapter,
                available: false,
                mailboxContractAddress: transportConfig.contractAddress,
                lastHealthyProbeAt: snapshot?.messagingStatus?.lastHealthyProbeAt,
                lastPollAt: snapshot?.messagingStatus?.lastPollAt,
                lastObservedCursor: snapshot?.messagingStatus?.lastObservedCursor,
                reason: helperExecutionAvailability.message ?? "Wallet helper execution is unavailable."
            )
            _ = try ffi.messagingUpdateTransportStatus(unavailable)
            refreshLocalSnapshot()
            return
        }
        let update = try await helper.probeMailboxTransport(
            sessionID: session.sessionId,
            contractAddress: transportConfig.contractAddress,
            manifestPath: transportConfig.manifestPath
        )
        _ = try ffi.messagingUpdateTransportStatus(update)
        refreshLocalSnapshot()
        #endif
    }

    private func resolveMailboxTransportConfig() -> MailboxTransportConfig? {
        if let services = snapshot?.services,
           let contractAddress = services.mailboxContractAddress,
           let manifestPath = services.mailboxManifestPath,
           FileManager.default.fileExists(atPath: manifestPath)
        {
            return MailboxTransportConfig(contractAddress: contractAddress, manifestPath: manifestPath)
        }

        #if os(macOS)
        guard let resourceRoot = Bundle.main.resourceURL?.appendingPathComponent("WalletHelper/Mailbox", isDirectory: true) else {
            #if DEBUG
            return debugMailboxTransportConfig()
            #else
            return nil
            #endif
        }
        let manifestCandidates = [
            resourceRoot.appendingPathComponent("deployment/mailbox.deployment.json", isDirectory: false),
            resourceRoot.appendingPathComponent("deployment/mailbox.deployment.template.json", isDirectory: false),
        ]
        guard let manifestURL = manifestCandidates.first(where: { FileManager.default.fileExists(atPath: $0.path) }),
              let contractAddress = mailboxContractAddress(fromManifestAt: manifestURL)
        else {
            #if DEBUG
            return debugMailboxTransportConfig()
            #else
            return nil
            #endif
        }
        return MailboxTransportConfig(contractAddress: contractAddress, manifestPath: manifestURL.path)
        #else
        return nil
        #endif
    }

    #if os(macOS) && DEBUG
    private func debugMailboxTransportConfig() -> MailboxTransportConfig? {
        guard let repoRoot = debugRepoRoot() else {
            return nil
        }
        let deploymentRoot = repoRoot.appendingPathComponent("zkf-wallet-mailbox/deployment", isDirectory: true)
        let manifestCandidates = [
            deploymentRoot.appendingPathComponent("mailbox.deployment.json", isDirectory: false),
            deploymentRoot.appendingPathComponent("mailbox.deployment.template.json", isDirectory: false),
        ]
        guard let manifestURL = manifestCandidates.first(where: { FileManager.default.fileExists(atPath: $0.path) }),
              let contractAddress = mailboxContractAddress(fromManifestAt: manifestURL)
        else {
            return nil
        }
        return MailboxTransportConfig(contractAddress: contractAddress, manifestPath: manifestURL.path)
    }

    private func debugRepoRoot() -> URL? {
        let environment = ProcessInfo.processInfo.environment
        guard environment["ZIROS_WALLET_ALLOW_REPO_FALLBACKS"] == "1" else {
            return nil
        }
        guard let repoRoot = environment["ZIROS_WALLET_REPO_ROOT"], repoRoot.isEmpty == false else {
            return nil
        }
        return URL(fileURLWithPath: repoRoot, isDirectory: true)
    }
    #endif

    private func mailboxContractAddress(fromManifestAt manifestURL: URL) -> String? {
        guard let data = try? Data(contentsOf: manifestURL),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let networks = object["networks"] as? [String: Any],
              let network = snapshot?.network,
              let deployment = networks[network] as? [String: Any]
        else {
            return nil
        }
        return deployment["contractAddress"] as? String
    }

    private func localMessagingPeerID() throws -> String {
        if let invite = activeConversationStatus?.localInvite {
            return invite.peerId
        }
        if let invite = conversations.compactMap(\.status.localInvite).first {
            return invite.peerId
        }
        guard conversations.isEmpty == false else {
            throw NSError(
                domain: "WalletCoordinator",
                code: 49,
                userInfo: [NSLocalizedDescriptionKey: "No local messaging channel is available for mailbox polling."]
            )
        }
        throw NSError(
            domain: "WalletCoordinator",
            code: 50,
            userInfo: [NSLocalizedDescriptionKey: "Messaging channels are missing their local invite metadata."]
        )
    }

    func saveSettings() {
        defaults.set(primaryProverURL, forKey: "wallet.primaryProverURL")
        defaults.set(fallbackProverURL, forKey: "wallet.fallbackProverURL")
        defaults.set(gatewayURL, forKey: "wallet.gatewayURL")
        statusMessage = "Wallet settings updated."
    }

    private func loadSettings() {
        primaryProverURL = defaults.string(forKey: "wallet.primaryProverURL") ?? primaryProverURL
        fallbackProverURL = defaults.string(forKey: "wallet.fallbackProverURL") ?? fallbackProverURL
        gatewayURL = defaults.string(forKey: "wallet.gatewayURL") ?? gatewayURL
    }

    private func syncSettingsFromSnapshotIfAvailable() {
        guard let services = snapshot?.services else {
            return
        }
        primaryProverURL = services.proofServerUrl
        gatewayURL = services.gatewayUrl
    }

    private func configurationFromServices(
        _ services: WalletServiceSnapshot?
    ) -> OpenWalletSessionResponse.Configuration? {
        guard let services else {
            return nil
        }
        return OpenWalletSessionResponse.Configuration(
            indexerUri: services.indexerUrl,
            indexerWsUri: services.indexerWsUrl,
            proverServerUri: services.proofServerUrl,
            substrateNodeUri: services.rpcUrl,
            networkId: services.network,
            gatewayUrl: services.gatewayUrl,
            proveRoutes: services.proveRoutes
        )
    }
}

private extension WalletCoordinator.VisualAuditConfig.State {
    init?(rawValue: String) {
        switch rawValue {
        case "locked":
            self = .locked
        case "unlocked":
            self = .unlocked
        default:
            return nil
        }
    }
}

private extension Array where Element == String {
    func value(after flag: String) -> String? {
        guard let index = firstIndex(of: flag), index + 1 < count else {
            return nil
        }
        return self[index + 1]
    }
}
