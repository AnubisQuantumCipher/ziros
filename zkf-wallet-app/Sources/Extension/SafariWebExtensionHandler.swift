import AppKit
import Foundation
import SafariServices
import os.log

final class SafariWebExtensionHandler: NSObject, NSExtensionRequestHandling {
    private let logger = Logger(subsystem: "com.ziros.wallet.extension", category: "bridge")
    private let bridgeStore = WalletBridgeStore()

    func beginRequest(with context: NSExtensionContext) {
        guard
            let item = context.inputItems.first as? NSExtensionItem,
            let message = item.userInfo?[SFExtensionMessageKey] as? [String: Any],
            let method = message["method"] as? String
        else {
            respond(context: context, payload: ["error": "Invalid extension request."])
            return
        }

        let params = message["params"] as? [String: Any] ?? [:]
        logger.log("Handling Safari bridge request: \(method, privacy: .public)")

        do {
            let payload = try handle(method: method, params: params)
            respond(context: context, payload: payload)
        } catch {
            respond(context: context, payload: ["error": error.localizedDescription])
        }
    }

    private func handle(method: String, params: [String: Any]) throws -> [String: Any] {
        let runtime = bridgeStore.runtimeStatus()
        switch method {
        case "connect":
            let origin = try requireString(params["origin"], label: "origin")
            if runtime.authorizedOrigins.contains(origin), runtime.locked == false {
                return [
                    "connected": true,
                    "networkId": runtime.networkId,
                    "origin": origin,
                ]
            }
            let queued = try queueRequest(method: method, params: params, runtime: runtime)
            openWalletForRequest(queued.id)
            return ["pendingRequestId": queued.id]
        case "getConfiguration":
            return configurationPayload(runtime: runtime)
        case "getProvingProvider":
            let configuration = configurationPayload(runtime: runtime)
            return [
                "kind": "http",
                "proverServerUri": configuration["proverServerUri"] as? String ?? "http://127.0.0.1:6300",
            ]
        case "getConnectionStatus":
            let origin = params["origin"] as? String
            return [
                "connected": origin.map { runtime.authorizedOrigins.contains($0) && runtime.locked == false } ?? (runtime.locked == false),
                "networkId": runtime.networkId,
                "locked": runtime.locked,
                "authorizedOrigins": runtime.authorizedOrigins,
            ]
        case "getBalances":
            return try overviewSubobject(runtime: runtime, key: "balances")
        case "getAddresses":
            return try overviewSubobject(runtime: runtime, key: "addresses")
        case "getActivity":
            guard runtime.locked == false else {
                throw NSError(domain: "SafariWebExtensionHandler", code: 20, userInfo: [NSLocalizedDescriptionKey: "auth_required: unlock the native wallet to read activity."])
            }
            return decodedJSONObject(from: runtime.activityJSON) as? [String: Any]
                ?? ["items": decodedJSONArray(from: runtime.activityJSON)]
        case "makeTransfer", "makeIntent":
            let queued = try queueRequest(method: method, params: params, runtime: runtime)
            openWalletForRequest(queued.id)
            return ["pendingRequestId": queued.id]
        case "getRequestStatus":
            let requestID = try requireString(params["requestId"], label: "requestId")
            return bridgeStore.pollResponse(id: requestID).payload
        default:
            return ["error": "Unsupported Safari bridge method '\(method)'"]
        }
    }

    private func queueRequest(
        method: String,
        params: [String: Any],
        runtime: BridgeRuntimeStatus
    ) throws -> BridgeQueuedRequest {
        let origin = try requireString(params["origin"], label: "origin")
        let data = try JSONSerialization.data(withJSONObject: params)
        guard let paramsJSON = String(data: data, encoding: .utf8) else {
            throw NSError(domain: "SafariWebExtensionHandler", code: 11, userInfo: [NSLocalizedDescriptionKey: "Failed to encode bridge request params."])
        }
        return bridgeStore.enqueueRequest(
            origin: origin,
            method: method,
            networkId: runtime.networkId,
            paramsJSON: paramsJSON
        )
    }

    private func openWalletForRequest(_ requestID: String) {
        guard let url = URL(string: "ziros-wallet://bridge/request?id=\(requestID)") else {
            return
        }
        NSWorkspace.shared.open(url)
    }

    private func configurationPayload(runtime: BridgeRuntimeStatus) -> [String: Any] {
        (decodedJSONObject(from: runtime.configurationJSON) as? [String: Any]) ?? [
            "indexerUri": "https://indexer.preprod.midnight.network/api/v4/graphql",
            "indexerWsUri": "wss://indexer.preprod.midnight.network/api/v4/graphql/ws",
            "proverServerUri": "http://127.0.0.1:6300",
            "substrateNodeUri": "https://rpc.preprod.midnight.network",
            "networkId": runtime.networkId,
            "explorerUrl": "https://explorer.preprod.midnight.network",
            "gatewayUrl": "http://127.0.0.1:6311",
        ]
    }

    private func overviewSubobject(runtime: BridgeRuntimeStatus, key: String) throws -> [String: Any] {
        guard runtime.locked == false else {
            throw NSError(domain: "SafariWebExtensionHandler", code: 21, userInfo: [NSLocalizedDescriptionKey: "auth_required: unlock the native wallet to read wallet state."])
        }
        guard let overview = decodedJSONObject(from: runtime.overviewJSON) as? [String: Any],
              let nested = overview[key] as? [String: Any]
        else {
            throw NSError(domain: "SafariWebExtensionHandler", code: 22, userInfo: [NSLocalizedDescriptionKey: "Wallet overview is unavailable."])
        }
        return nested
    }

    private func decodedJSONObject(from json: String?) -> Any? {
        guard let json, let data = json.data(using: .utf8) else {
            return nil
        }
        return try? JSONSerialization.jsonObject(with: data)
    }

    private func decodedJSONArray(from json: String?) -> [Any] {
        decodedJSONObject(from: json) as? [Any] ?? []
    }

    private func requireString(_ value: Any?, label: String) throws -> String {
        guard let value = value as? String, !value.isEmpty else {
            throw NSError(domain: "SafariWebExtensionHandler", code: 10, userInfo: [NSLocalizedDescriptionKey: "Missing \(label)."])
        }
        return value
    }

    private func respond(context: NSExtensionContext, payload: [String: Any]) {
        let item = NSExtensionItem()
        item.userInfo = [SFExtensionMessageKey: payload]
        context.completeRequest(returningItems: [item], completionHandler: nil)
    }
}
