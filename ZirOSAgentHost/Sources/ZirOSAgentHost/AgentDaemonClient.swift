import Darwin
import Foundation

enum AgentDaemonClientError: LocalizedError {
    case invalidSocketPath(String)
    case socketCreationFailed(Int32)
    case connectFailed(Int32)
    case daemonError(String)
    case emptyResponse

    var errorDescription: String? {
        switch self {
        case let .invalidSocketPath(path):
            return "Invalid Unix socket path: \(path)"
        case let .socketCreationFailed(code):
            return "Unable to open daemon socket (\(code))"
        case let .connectFailed(code):
            return "Unable to connect to daemon socket (\(code))"
        case let .daemonError(message):
            return message
        case .emptyResponse:
            return "The daemon returned an empty response"
        }
    }
}

struct AgentDaemonClient {
    var socketPath: String

    func status(limit: Int = 20) throws -> AgentStatusReport {
        try request(
            StatusRequest(limit: limit),
            responseType: AgentStatusReport.self
        )
    }

    func logs(sessionID: String) throws -> AgentLogsReport {
        try request(
            LogsRequest(sessionID: sessionID),
            responseType: AgentLogsReport.self
        )
    }

    func approve(
        sessionID: String?,
        pendingID: String,
        primaryPrompt: String,
        secondaryPrompt: String?
    ) throws {
        let _: ApprovalEnvelope = try request(
            ApproveRpcRequest(
                request: ApprovalRequest(
                    sessionID: sessionID,
                    walletNetwork: "preprod",
                    pendingID: pendingID,
                    primaryPrompt: primaryPrompt,
                    secondaryPrompt: secondaryPrompt?.nilIfEmpty,
                    persistentRoot: nil,
                    cacheRoot: nil
                )
            ),
            responseType: ApprovalEnvelope.self
        )
    }

    func reject(sessionID: String?, pendingID: String, reason: String) throws {
        let _: StatusOnlyEnvelope = try request(
            RejectRpcRequest(
                request: RejectRequest(
                    sessionID: sessionID,
                    walletNetwork: "preprod",
                    pendingID: pendingID,
                    reason: reason,
                    persistentRoot: nil,
                    cacheRoot: nil
                )
            ),
            responseType: StatusOnlyEnvelope.self
        )
    }

    private func request<Request: Encodable, Response: Decodable>(
        _ request: Request,
        responseType: Response.Type
    ) throws -> Response {
        let encoder = JSONEncoder()
        let payload = try encoder.encode(request) + [0x0a]
        let responseData = try send(payload: payload)
        let decoder = JSONDecoder()
        let envelope = try decoder.decode(AgentRpcResponse<Response>.self, from: responseData)
        if envelope.ok, let data = envelope.data {
            return data
        }
        throw AgentDaemonClientError.daemonError(envelope.error ?? "Unknown daemon error")
    }

    private func send(payload: Data) throws -> Data {
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let path = NSString(string: socketPath).expandingTildeInPath
        let utf8 = Array(path.utf8CString)
        guard utf8.count < MemoryLayout.size(ofValue: address.sun_path) else {
            throw AgentDaemonClientError.invalidSocketPath(path)
        }
        withUnsafeMutablePointer(to: &address.sun_path) { pointer in
            pointer.withMemoryRebound(to: CChar.self, capacity: utf8.count) { buffer in
                for index in 0..<utf8.count {
                    buffer[index] = utf8[index]
                }
            }
        }

        let socketFD = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard socketFD >= 0 else {
            throw AgentDaemonClientError.socketCreationFailed(errno)
        }

        let connectResult = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                Darwin.connect(
                    socketFD,
                    sockaddrPointer,
                    socklen_t(MemoryLayout<sockaddr_un>.stride)
                )
            }
        }
        guard connectResult == 0 else {
            let code = errno
            Darwin.close(socketFD)
            throw AgentDaemonClientError.connectFailed(code)
        }

        let handle = FileHandle(fileDescriptor: socketFD, closeOnDealloc: true)
        try handle.write(contentsOf: payload)
        try handle.synchronize()
        guard let response = try handle.readToEnd(), !response.isEmpty else {
            throw AgentDaemonClientError.emptyResponse
        }
        return response
    }
}

private struct StatusRequest: Encodable {
    let method = "status"
    let limit: Int
}

private struct LogsRequest: Encodable {
    let method = "logs"
    let sessionID: String

    private enum CodingKeys: String, CodingKey {
        case method
        case sessionID = "session_id"
    }
}

private struct ApproveRpcRequest: Encodable {
    let method = "approve"
    let request: ApprovalRequest
}

private struct ApprovalRequest: Encodable {
    let sessionID: String?
    let walletNetwork: String
    let pendingID: String
    let primaryPrompt: String
    let secondaryPrompt: String?
    let persistentRoot: String?
    let cacheRoot: String?

    private enum CodingKeys: String, CodingKey {
        case sessionID = "session_id"
        case walletNetwork = "wallet_network"
        case pendingID = "pending_id"
        case primaryPrompt = "primary_prompt"
        case secondaryPrompt = "secondary_prompt"
        case persistentRoot = "persistent_root"
        case cacheRoot = "cache_root"
    }
}

private struct RejectRpcRequest: Encodable {
    let method = "reject"
    let request: RejectRequest
}

private struct RejectRequest: Encodable {
    let sessionID: String?
    let walletNetwork: String
    let pendingID: String
    let reason: String
    let persistentRoot: String?
    let cacheRoot: String?

    private enum CodingKeys: String, CodingKey {
        case sessionID = "session_id"
        case walletNetwork = "wallet_network"
        case pendingID = "pending_id"
        case reason
        case persistentRoot = "persistent_root"
        case cacheRoot = "cache_root"
    }
}

private struct ApprovalEnvelope: Decodable {
    let schema: String
    let operationID: String

    private enum CodingKeys: String, CodingKey {
        case schema
        case operationID = "operation_id"
    }
}

private struct StatusOnlyEnvelope: Decodable {
    let status: String
}

private extension String {
    var nilIfEmpty: String? {
        trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? nil : self
    }
}
