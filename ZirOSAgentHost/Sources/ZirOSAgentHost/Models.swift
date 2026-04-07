import Foundation

struct AgentRpcResponse<Payload: Decodable>: Decodable {
    let ok: Bool
    let data: Payload?
    let error: String?
}

struct AgentStatusReport: Decodable {
    let schema: String
    let generatedAt: String
    let socketPath: String
    let socketPresent: Bool
    let sessions: [AgentSessionView]
    let projects: [ProjectRecord]

    private enum CodingKeys: String, CodingKey {
        case schema
        case generatedAt = "generated_at"
        case socketPath = "socket_path"
        case socketPresent = "socket_present"
        case sessions
        case projects
    }
}

struct AgentSessionView: Decodable, Hashable, Identifiable {
    let sessionID: String
    let status: String
    let workflowKind: String
    let goalSummary: String
    let createdAt: String
    let updatedAt: String
    let projectRoot: String?
    let workgraphID: String?
    let capabilitySnapshotID: String?

    var id: String { sessionID }

    private enum CodingKeys: String, CodingKey {
        case sessionID = "session_id"
        case status
        case workflowKind = "workflow_kind"
        case goalSummary = "goal_summary"
        case createdAt = "created_at"
        case updatedAt = "updated_at"
        case projectRoot = "project_root"
        case workgraphID = "workgraph_id"
        case capabilitySnapshotID = "capability_snapshot_id"
    }
}

struct ProjectRecord: Decodable, Hashable, Identifiable {
    let name: String
    let rootPath: String
    let createdAt: String

    var id: String { name + rootPath }

    private enum CodingKeys: String, CodingKey {
        case name
        case rootPath = "root_path"
        case createdAt = "created_at"
    }
}

struct AgentLogsReport: Decodable {
    let schema: String
    let generatedAt: String
    let sessionID: String
    let receipts: [ActionReceipt]

    private enum CodingKeys: String, CodingKey {
        case schema
        case generatedAt = "generated_at"
        case sessionID = "session_id"
        case receipts
    }
}

struct ActionReceipt: Decodable, Hashable, Identifiable {
    let schema: String
    let receiptID: String
    let sessionID: String
    let actionName: String
    let status: String
    let createdAt: String
    let payload: JSONValue

    var id: String { receiptID }

    private enum CodingKeys: String, CodingKey {
        case schema
        case receiptID = "receipt_id"
        case sessionID = "session_id"
        case actionName = "action_name"
        case status
        case createdAt = "created_at"
        case payload
    }
}

enum JSONValue: Decodable, Hashable {
    case string(String)
    case number(Double)
    case bool(Bool)
    case object([String: JSONValue])
    case array([JSONValue])
    case null

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let value = try? container.decode(Bool.self) {
            self = .bool(value)
        } else if let value = try? container.decode(Double.self) {
            self = .number(value)
        } else if let value = try? container.decode(String.self) {
            self = .string(value)
        } else if let value = try? container.decode([String: JSONValue].self) {
            self = .object(value)
        } else if let value = try? container.decode([JSONValue].self) {
            self = .array(value)
        } else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Unsupported JSON payload")
        }
    }

    func rawObject() -> Any {
        switch self {
        case let .string(value):
            return value
        case let .number(value):
            return value
        case let .bool(value):
            return value
        case let .object(value):
            return value.mapValues { $0.rawObject() }
        case let .array(value):
            return value.map { $0.rawObject() }
        case .null:
            return NSNull()
        }
    }

    var prettyPrinted: String {
        let object = rawObject()
        guard JSONSerialization.isValidJSONObject(object),
              let data = try? JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted]),
              let text = String(data: data, encoding: .utf8)
        else {
            switch self {
            case let .string(value):
                return value
            case let .number(value):
                return String(value)
            case let .bool(value):
                return String(value)
            case .null:
                return "null"
            case let .array(value):
                return value.map(\.prettyPrinted).joined(separator: "\n")
            case let .object(value):
                return value.map { "\($0.key): \($0.value.prettyPrinted)" }.joined(separator: "\n")
            }
        }
        return text
    }
}
