import Foundation

enum BridgeRequestState: String, Codable {
    case queued
    case processing
    case approved
    case rejected
    case failed
}

struct BridgeRuntimeStatus: Codable {
    var networkId: String
    var locked: Bool
    var authorizedOrigins: [String]
    var activeOrigins: [String]
    var configurationJSON: String?
    var overviewJSON: String?
    var activityJSON: String?
    var updatedAt: Date

    static func empty(networkId: String = "preprod") -> Self {
        Self(
            networkId: networkId,
            locked: true,
            authorizedOrigins: [],
            activeOrigins: [],
            configurationJSON: nil,
            overviewJSON: nil,
            activityJSON: nil,
            updatedAt: Date()
        )
    }
}

struct BridgeQueuedRequest: Codable, Identifiable {
    let id: String
    let origin: String
    let method: String
    let networkId: String
    let paramsJSON: String
    var state: BridgeRequestState
    var responseJSON: String?
    var error: String?
    let createdAt: Date
    var updatedAt: Date
}

private struct BridgeStoreState: Codable {
    var runtimeStatus: BridgeRuntimeStatus
    var requests: [BridgeQueuedRequest]

    static func empty() -> Self {
        Self(runtimeStatus: .empty(), requests: [])
    }
}

struct BridgeRequestPollResponse {
    let request: BridgeQueuedRequest?

    var payload: [String: Any] {
        guard let request else {
            return ["state": BridgeRequestState.failed.rawValue, "error": "bridge request not found"]
        }
        var payload: [String: Any] = [
            "requestId": request.id,
            "state": request.state.rawValue,
            "method": request.method,
            "origin": request.origin,
            "networkId": request.networkId,
        ]
        if let responseJSON = request.responseJSON,
           let response = try? JSONSerialization.jsonObject(with: Data(responseJSON.utf8)) {
            payload["result"] = response
        }
        if let error = request.error {
            payload["error"] = error
        }
        return payload
    }
}

final class WalletBridgeStore {
    static let appGroupIdentifier = "group.com.ziros.wallet"

    private let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }()

    private let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return encoder
    }()

    private let fm = FileManager.default
    private let root: URL
    private let stateURL: URL

    init() {
        root = Self.sharedRootURL().appendingPathComponent("Bridge", isDirectory: true)
        stateURL = root.appendingPathComponent("bridge-state.json")
        try? fm.createDirectory(at: root, withIntermediateDirectories: true)
    }

    static func sharedRootURL() -> URL {
#if DEBUG
        // In debug builds, skip the app-group container call entirely to avoid
        // the macOS TCC "would like to access data from other apps" prompt that
        // fires on unsigned / locally-signed builds. The containerURL call
        // itself triggers the prompt before the nil-check can fall through.
        return FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".ziros-wallet-debug", isDirectory: true)
#else
        if let groupURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: appGroupIdentifier
        ) {
            return groupURL
        }
        preconditionFailure("App group '\(appGroupIdentifier)' is required for release builds.")
#endif
    }

    func runtimeStatus() -> BridgeRuntimeStatus {
        loadState().runtimeStatus
    }

    func updateRuntimeStatus(_ mutate: (inout BridgeRuntimeStatus) -> Void) {
        mutateState { state in
            mutate(&state.runtimeStatus)
            state.runtimeStatus.updatedAt = Date()
        }
    }

    @discardableResult
    func enqueueRequest(
        origin: String,
        method: String,
        networkId: String,
        paramsJSON: String
    ) -> BridgeQueuedRequest {
        mutateState { state in
            let now = Date()
            let request = BridgeQueuedRequest(
                id: UUID().uuidString,
                origin: origin,
                method: method,
                networkId: networkId,
                paramsJSON: paramsJSON,
                state: .queued,
                responseJSON: nil,
                error: nil,
                createdAt: now,
                updatedAt: now
            )
            state.requests.append(request)
            pruneResolvedRequests(state: &state)
            return request
        }
    }

    func request(id: String) -> BridgeQueuedRequest? {
        loadState().requests.first(where: { $0.id == id })
    }

    func nextQueuedRequest() -> BridgeQueuedRequest? {
        loadState()
            .requests
            .filter { $0.state == .queued }
            .sorted { $0.createdAt < $1.createdAt }
            .first
    }

    func markProcessing(id: String) {
        mutateRequest(id: id) { request in
            request.state = .processing
            request.updatedAt = Date()
        }
    }

    func complete(id: String, responseJSON: String) {
        mutateRequest(id: id) { request in
            request.state = .approved
            request.responseJSON = responseJSON
            request.error = nil
            request.updatedAt = Date()
        }
    }

    func reject(id: String, error: String) {
        mutateRequest(id: id) { request in
            request.state = .rejected
            request.error = error
            request.updatedAt = Date()
        }
    }

    func fail(id: String, error: String) {
        mutateRequest(id: id) { request in
            request.state = .failed
            request.error = error
            request.updatedAt = Date()
        }
    }

    func pollResponse(id: String) -> BridgeRequestPollResponse {
        BridgeRequestPollResponse(request: request(id: id))
    }

    func revokeOrigin(_ origin: String) {
        mutateState { state in
            state.runtimeStatus.authorizedOrigins.removeAll { $0 == origin }
            state.runtimeStatus.activeOrigins.removeAll { $0 == origin }
            let now = Date()
            for index in state.requests.indices {
                guard state.requests[index].origin == origin else {
                    continue
                }
                switch state.requests[index].state {
                case .queued, .processing:
                    state.requests[index].state = .rejected
                    state.requests[index].error = "origin_unauthorized: permission revoked in the native wallet."
                    state.requests[index].updatedAt = now
                case .approved, .rejected, .failed:
                    continue
                }
            }
            pruneResolvedRequests(state: &state)
        }
    }

    private func mutateRequest(id: String, mutate: (inout BridgeQueuedRequest) -> Void) {
        mutateState { state in
            guard let index = state.requests.firstIndex(where: { $0.id == id }) else {
                return
            }
            mutate(&state.requests[index])
            pruneResolvedRequests(state: &state)
        }
    }

    private func mutateState<T>(_ mutate: (inout BridgeStoreState) -> T) -> T {
        var state = loadState()
        let value = mutate(&state)
        saveState(state)
        return value
    }

    private func loadState() -> BridgeStoreState {
        guard
            let data = try? Data(contentsOf: stateURL),
            let state = try? decoder.decode(BridgeStoreState.self, from: data)
        else {
            return .empty()
        }
        return state
    }

    private func saveState(_ state: BridgeStoreState) {
        guard let data = try? encoder.encode(state) else {
            return
        }
        try? data.write(to: stateURL, options: .atomic)
    }

    private func pruneResolvedRequests(state: inout BridgeStoreState) {
        let cutoff = Date().addingTimeInterval(-(15 * 60))
        state.requests.removeAll {
            ($0.state == .approved || $0.state == .rejected || $0.state == .failed) && $0.updatedAt < cutoff
        }
    }
}
