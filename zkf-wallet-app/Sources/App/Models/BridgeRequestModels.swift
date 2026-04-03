import Foundation

struct BridgeDesiredOutput: Codable {
    let mode: String
    let receiverAddress: String
    let tokenType: String
    let amountRaw: String
}

struct BridgeDesiredInput: Codable {
    let mode: String
    let amountRaw: String
    let tokenType: String
}

struct BridgeWriteOptions: Codable {
    let payFees: Bool?
}

struct BridgeConnectParams: Codable {
    let networkId: String?
    let origin: String
}

struct BridgeMakeTransferParams: Codable {
    let desiredOutputs: [BridgeDesiredOutput]
    let options: BridgeWriteOptions?
    let origin: String
}

struct BridgeMakeIntentParams: Codable {
    let desiredInputs: [BridgeDesiredInput]
    let desiredOutputs: [BridgeDesiredOutput]
    let options: BridgeWriteOptions?
    let origin: String
}
