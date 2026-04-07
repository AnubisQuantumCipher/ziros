import Foundation

enum WalletFFIError: LocalizedError {
    case runtime(String)
    case invalidHandle

    var errorDescription: String? {
        switch self {
        case let .runtime(message):
            return message
        case .invalidHandle:
            return "Rust wallet handle is unavailable."
        }
    }
}

final class WalletFFIClient {
    private let decoder = JSONDecoder.walletDecoder()
    private let encoder = JSONEncoder.walletEncoder()
    private var handle: OpaquePointer?

    init(network: String, persistentRoot: URL, cacheRoot: URL) throws {
        persistentRoot.createDirectoryIfNeeded()
        cacheRoot.createDirectoryIfNeeded()
        handle = try network.withCString { networkPtr in
            try persistentRoot.path.withCString { persistentPtr in
                try cacheRoot.path.withCString { cachePtr in
                    let value = zkf_wallet_create_with_roots(networkPtr, persistentPtr, cachePtr)
                    guard let value else {
                        throw WalletFFIError.runtime(Self.lastErrorMessage())
                    }
                    return value
                }
            }
        }
    }

    deinit {
        if let handle {
            zkf_wallet_destroy(handle)
        }
    }

    func snapshot() throws -> WalletSnapshot {
        try decodeStringCall { zkf_wallet_snapshot_json(try requireHandle()) }
    }

    func importMasterSeed(_ seed: String) throws -> SeedImportSummary {
        try seed.withCString { seedPtr in
            try decodeStringCall { zkf_wallet_import_master_seed(try requireHandle(), seedPtr) }
        }
    }

    func importMnemonic(_ mnemonic: String) throws -> SeedImportSummary {
        try mnemonic.withCString { mnemonicPtr in
            try decodeStringCall { zkf_wallet_import_mnemonic(try requireHandle(), mnemonicPtr) }
        }
    }

    func unlock(prompt: String) throws {
        try prompt.withCString { promptPtr in
            let status = zkf_wallet_unlock(try requireHandle(), promptPtr)
            guard status == 0 else {
                throw WalletFFIError.runtime(Self.lastErrorMessage())
            }
        }
    }

    func lock() throws {
        let status = zkf_wallet_lock(try requireHandle())
        guard status == 0 else {
            throw WalletFFIError.runtime(Self.lastErrorMessage())
        }
    }

    func appBackgrounded() throws {
        let status = zkf_wallet_app_backgrounded(try requireHandle())
        guard status == 0 else {
            throw WalletFFIError.runtime(Self.lastErrorMessage())
        }
    }

    func openHelperBundle() throws -> WalletHelperBundle {
        try decodeStringCall { zkf_wallet_helper_open_session_json(try requireHandle()) }
    }

    func closeHelperSession() throws {
        let status = zkf_wallet_helper_close_session(try requireHandle())
        guard status == 0 else {
            throw WalletFFIError.runtime(Self.lastErrorMessage())
        }
    }

    func grantOrigin(origin: String, scopes: [BridgeScope], note: String?) throws {
        let grant = BridgeOriginGrantInput(
            origin: origin,
            scopes: scopes,
            authorizedAt: Date(),
            note: note
        )
        let json = try jsonString(for: grant, errorMessage: "Unable to encode bridge origin grant.")
        try json.withCString { grantPtr in
            let status = zkf_wallet_grant_origin(try requireHandle(), grantPtr)
            guard status == 0 else {
                throw WalletFFIError.runtime(Self.lastErrorMessage())
            }
        }
    }

    func revokeOrigin(_ origin: String) throws {
        try origin.withCString { originPtr in
            let status = zkf_wallet_revoke_origin(try requireHandle(), originPtr)
            guard status == 0 else {
                throw WalletFFIError.runtime(Self.lastErrorMessage())
            }
        }
    }

    func openBridgeSession(origin: String) throws -> OpaquePointer {
        try origin.withCString { originPtr in
            let session = zkf_wallet_bridge_open_session(try requireHandle(), originPtr)
            guard let session else {
                throw WalletFFIError.runtime(Self.lastErrorMessage())
            }
            return session
        }
    }

    func freeBridgeSession(_ session: OpaquePointer) {
        zkf_wallet_bridge_session_free(session)
    }

    func beginNativeAction(review: TxReviewPayload) throws -> OpaquePointer {
        let json = try jsonString(for: review, errorMessage: "Unable to encode review payload.")
        return try json.withCString { reviewPtr in
            let pending = zkf_wallet_begin_native_action(try requireHandle(), reviewPtr)
            guard let pending else {
                throw WalletFFIError.runtime(Self.lastErrorMessage())
            }
            return pending
        }
    }

    func messagingPrepareOpenChannel(_ request: WalletChannelOpenRequest) throws -> OpaquePointer {
        let json = try jsonString(for: request, errorMessage: "Unable to encode channel-open request.")
        return try json.withCString { requestPtr in
            let pending = zkf_wallet_messaging_prepare_open_channel(try requireHandle(), requestPtr)
            guard let pending else {
                throw WalletFFIError.runtime(Self.lastErrorMessage())
            }
            return pending
        }
    }

    func messagingPrepareText(peerID: String, text: String) throws -> OpaquePointer {
        try peerID.withCString { peerPtr in
            try text.withCString { textPtr in
                let pending = zkf_wallet_messaging_prepare_text(try requireHandle(), peerPtr, textPtr)
                guard let pending else {
                    throw WalletFFIError.runtime(Self.lastErrorMessage())
                }
                return pending
            }
        }
    }

    func messagingPrepareTransferReceipt(peerID: String, receipt: WalletTransferReceipt) throws -> OpaquePointer {
        let json = try jsonString(for: receipt, errorMessage: "Unable to encode transfer receipt.")
        return try peerID.withCString { peerPtr in
            try json.withCString { receiptPtr in
                let pending = zkf_wallet_messaging_prepare_transfer_receipt(
                    try requireHandle(),
                    peerPtr,
                    receiptPtr
                )
                guard let pending else {
                    throw WalletFFIError.runtime(Self.lastErrorMessage())
                }
                return pending
            }
        }
    }

    func messagingPrepareCredentialRequest(peerID: String, request: WalletCredentialRequest) throws -> OpaquePointer {
        let json = try jsonString(for: request, errorMessage: "Unable to encode credential request.")
        return try peerID.withCString { peerPtr in
            try json.withCString { requestPtr in
                let pending = zkf_wallet_messaging_prepare_credential_request(
                    try requireHandle(),
                    peerPtr,
                    requestPtr
                )
                guard let pending else {
                    throw WalletFFIError.runtime(Self.lastErrorMessage())
                }
                return pending
            }
        }
    }

    func messagingPrepareCredentialResponse(peerID: String, response: WalletCredentialResponse) throws -> OpaquePointer {
        let json = try jsonString(for: response, errorMessage: "Unable to encode credential response.")
        return try peerID.withCString { peerPtr in
            try json.withCString { responsePtr in
                let pending = zkf_wallet_messaging_prepare_credential_response(
                    try requireHandle(),
                    peerPtr,
                    responsePtr
                )
                guard let pending else {
                    throw WalletFFIError.runtime(Self.lastErrorMessage())
                }
                return pending
            }
        }
    }

    func messagingCommitOpenChannel(token: ApprovalToken) throws -> ConversationView {
        let json = try jsonString(for: token, errorMessage: "Unable to encode approval token.")
        return try json.withCString { tokenPtr in
            try decodeStringCall {
                zkf_wallet_messaging_commit_open_channel_json(try requireHandle(), tokenPtr)
            }
        }
    }

    func messagingCommitSendMessage(token: ApprovalToken) throws -> PreparedMessage {
        let json = try jsonString(for: token, errorMessage: "Unable to encode approval token.")
        return try json.withCString { tokenPtr in
            try decodeStringCall {
                zkf_wallet_messaging_commit_send_message_json(try requireHandle(), tokenPtr)
            }
        }
    }

    func messagingReceiveEnvelope(_ envelope: MailboxEnvelope) throws -> WalletMessage {
        let json = try jsonString(for: envelope, errorMessage: "Unable to encode mailbox envelope.")
        return try json.withCString { envelopePtr in
            try decodeStringCall {
                zkf_wallet_messaging_receive_envelope_json(try requireHandle(), envelopePtr)
            }
        }
    }

    func messagingPollMailbox() throws -> MessagingTransportStatus {
        try decodeStringCall { zkf_wallet_messaging_poll_mailbox_json(try requireHandle()) }
    }

    func messagingUpdateTransportStatus(_ update: MessagingTransportUpdate) throws -> MessagingTransportStatus {
        let json = try jsonString(for: update, errorMessage: "Unable to encode messaging transport update.")
        return try json.withCString { updatePtr in
            try decodeStringCall {
                zkf_wallet_messaging_update_transport_status_json(try requireHandle(), updatePtr)
            }
        }
    }

    func messagingCompleteMailboxPost(_ success: MailboxPostSuccess) throws -> WalletMessage {
        let json = try jsonString(for: success, errorMessage: "Unable to encode mailbox post success.")
        return try json.withCString { successPtr in
            try decodeStringCall {
                zkf_wallet_messaging_complete_mailbox_post_json(try requireHandle(), successPtr)
            }
        }
    }

    func messagingFailMailboxPost(_ failure: MailboxPostFailure) throws -> WalletMessage {
        let json = try jsonString(for: failure, errorMessage: "Unable to encode mailbox post failure.")
        return try json.withCString { failurePtr in
            try decodeStringCall {
                zkf_wallet_messaging_fail_mailbox_post_json(try requireHandle(), failurePtr)
            }
        }
    }

    func messagingListConversations() throws -> [ConversationView] {
        try decodeStringCall { zkf_wallet_messaging_list_conversations_json(try requireHandle()) }
    }

    func messagingConversation(peerID: String) throws -> [WalletMessage] {
        try peerID.withCString { peerPtr in
            try decodeStringCall {
                zkf_wallet_messaging_conversation_json(try requireHandle(), peerPtr)
            }
        }
    }

    func messagingChannelStatus(peerID: String) throws -> ChannelStatus {
        try peerID.withCString { peerPtr in
            try decodeStringCall {
                zkf_wallet_messaging_channel_status_json(try requireHandle(), peerPtr)
            }
        }
    }

    func messagingCloseChannel(peerID: String) throws -> ChannelStatus {
        try peerID.withCString { peerPtr in
            try decodeStringCall {
                zkf_wallet_messaging_close_channel_json(try requireHandle(), peerPtr)
            }
        }
    }

    func beginBridgeTransfer(session: OpaquePointer, review: TxReviewPayload) throws -> OpaquePointer {
        let json = try jsonString(for: review, errorMessage: "Unable to encode bridge review payload.")
        return try json.withCString { reviewPtr in
            let pending = zkf_wallet_bridge_make_transfer(session, reviewPtr)
            guard let pending else {
                throw WalletFFIError.runtime(Self.lastErrorMessage())
            }
            return pending
        }
    }

    func beginBridgeIntent(session: OpaquePointer, review: TxReviewPayload) throws -> OpaquePointer {
        let json = try jsonString(for: review, errorMessage: "Unable to encode bridge intent payload.")
        return try json.withCString { reviewPtr in
            let pending = zkf_wallet_bridge_make_intent(session, reviewPtr)
            guard let pending else {
                throw WalletFFIError.runtime(Self.lastErrorMessage())
            }
            return pending
        }
    }

    func approvePending(
        pending: OpaquePointer,
        prompt: String,
        secondaryPrompt: String?
    ) throws -> ApprovalToken {
        try prompt.withCString { promptPtr in
            try secondaryPrompt.withOptionalCString { secondaryPtr in
                try decodeStringCall {
                    zkf_wallet_pending_approve(pending, promptPtr, secondaryPtr)
                }
            }
        }
    }

    func pendingReview(pending: OpaquePointer) throws -> PendingApprovalView {
        try decodeStringCall { zkf_wallet_pending_review_json(pending) }
    }

    func rejectPending(
        pending: OpaquePointer,
        reason: String
    ) throws {
        try reason.withCString { reasonPtr in
            let status = zkf_wallet_pending_reject(pending, reasonPtr)
            guard status == 0 else {
                throw WalletFFIError.runtime(Self.lastErrorMessage())
            }
        }
    }

    func freePending(_ pending: OpaquePointer) {
        zkf_wallet_pending_approval_free(pending)
    }

    func issueNativeSubmissionGrant(
        method: String,
        txDigest: String,
        token: ApprovalToken
    ) throws -> SubmissionGrant {
        let tokenJSON = try jsonString(for: token, errorMessage: "Unable to encode approval token.")
        return try method.withCString { methodPtr in
            try txDigest.withCString { txDigestPtr in
                try tokenJSON.withCString { tokenPtr in
                    try decodeStringCall {
                        zkf_wallet_issue_native_submission_grant_json(
                            try requireHandle(),
                            methodPtr,
                            txDigestPtr,
                            tokenPtr
                        )
                    }
                }
            }
        }
    }

    func issueBridgeSubmissionGrant(
        session: OpaquePointer,
        method: String,
        txDigest: String,
        token: ApprovalToken
    ) throws -> SubmissionGrant {
        let tokenJSON = try jsonString(for: token, errorMessage: "Unable to encode approval token.")
        return try method.withCString { methodPtr in
            try txDigest.withCString { txDigestPtr in
                try tokenJSON.withCString { tokenPtr in
                    try decodeStringCall {
                        zkf_wallet_issue_bridge_submission_grant_json(
                            session,
                            methodPtr,
                            txDigestPtr,
                            tokenPtr
                        )
                    }
                }
            }
        }
    }

    func consumeNativeSubmissionGrant(
        method: String,
        txDigest: String,
        grant: SubmissionGrant
    ) throws {
        let grantJSON = try jsonString(for: grant, errorMessage: "Unable to encode submission grant.")
        try method.withCString { methodPtr in
            try txDigest.withCString { txDigestPtr in
                try grantJSON.withCString { grantPtr in
                    let status = zkf_wallet_consume_native_submission_grant(
                        try requireHandle(),
                        methodPtr,
                        txDigestPtr,
                        grantPtr
                    )
                    guard status == 0 else {
                        throw WalletFFIError.runtime(Self.lastErrorMessage())
                    }
                }
            }
        }
    }

    func consumeBridgeSubmissionGrant(
        session: OpaquePointer,
        method: String,
        txDigest: String,
        grant: SubmissionGrant
    ) throws {
        let grantJSON = try jsonString(for: grant, errorMessage: "Unable to encode submission grant.")
        try method.withCString { methodPtr in
            try txDigest.withCString { txDigestPtr in
                try grantJSON.withCString { grantPtr in
                    let status = zkf_wallet_consume_bridge_submission_grant(
                        session,
                        methodPtr,
                        txDigestPtr,
                        grantPtr
                    )
                    guard status == 0 else {
                        throw WalletFFIError.runtime(Self.lastErrorMessage())
                    }
                }
            }
        }
    }

    private func decodeStringCall<T: Decodable>(
        _ call: () throws -> UnsafeMutablePointer<CChar>?
    ) throws -> T {
        guard let pointer = try call() else {
            throw WalletFFIError.runtime(Self.lastErrorMessage())
        }
        defer { zkf_string_free(pointer) }
        let string = String(cString: pointer)
        guard let data = string.data(using: .utf8) else {
            throw WalletFFIError.runtime("Rust returned non-UTF8 JSON.")
        }
        return try decoder.decode(T.self, from: data)
    }

    private func requireHandle() throws -> OpaquePointer {
        guard let handle else {
            throw WalletFFIError.invalidHandle
        }
        return handle
    }

    private func jsonString<T: Encodable>(for value: T, errorMessage: String) throws -> String {
        let data = try encoder.encode(value)
        guard let string = String(data: data, encoding: .utf8) else {
            throw WalletFFIError.runtime(errorMessage)
        }
        return string
    }

    private static func lastErrorMessage() -> String {
        guard let pointer = zkf_last_error_message() else {
            return "Rust FFI returned an unknown error."
        }
        return String(cString: pointer)
    }
}

private extension URL {
    func createDirectoryIfNeeded() {
        try? FileManager.default.createDirectory(at: self, withIntermediateDirectories: true)
    }
}

private extension Optional where Wrapped == String {
    func withOptionalCString<Result>(
        _ body: (UnsafePointer<CChar>?) throws -> Result
    ) throws -> Result {
        switch self {
        case let .some(value):
            return try value.withCString(body)
        case .none:
            return try body(nil)
        }
    }
}
