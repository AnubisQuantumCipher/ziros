#!/usr/bin/env swift

import CoreML
import Foundation

enum CliError: Error, CustomStringConvertible {
    case message(String)

    var description: String {
        switch self {
        case let .message(text):
            return text
        }
    }
}

func parseArguments(_ raw: [String]) throws -> [String: String] {
    var parsed: [String: String] = [:]
    var index = 0
    while index < raw.count {
        let key = raw[index]
        guard key.hasPrefix("--") else {
            throw CliError.message("unexpected argument: \(key)")
        }
        guard index + 1 < raw.count else {
            throw CliError.message("missing value for \(key)")
        }
        parsed[String(key.dropFirst(2))] = raw[index + 1]
        index += 2
    }
    return parsed
}

func parseComputeUnits(_ raw: String) throws -> MLComputeUnits {
    switch raw {
    case "all":
        return .all
    case "cpu-and-neural-engine":
        return .cpuAndNeuralEngine
    case "cpu-only":
        return .cpuOnly
    default:
        throw CliError.message(
            "invalid --compute-units value '\(raw)' (expected all, cpu-and-neural-engine, or cpu-only)"
        )
    }
}

func scalarArray(from jsonValue: Any) throws -> [Double] {
    if let dict = jsonValue as? [String: Any], let nested = dict["features"] {
        return try scalarArray(from: nested)
    }
    if let values = jsonValue as? [NSNumber] {
        return values.map(\.doubleValue)
    }
    if let values = jsonValue as? [Double] {
        return values
    }
    if let values = jsonValue as? [Float] {
        return values.map(Double.init)
    }
    throw CliError.message("features JSON must be an array of numbers or {\"features\": [...]}")
}

func makeInputArray(values: [Double]) throws -> MLMultiArray {
    let array = try MLMultiArray(shape: [1, NSNumber(value: values.count)], dataType: .float32)
    for (index, value) in values.enumerated() {
        array[index] = NSNumber(value: Float(value))
    }
    return array
}

func compileModelIfNeeded(url: URL) throws -> URL {
    if url.pathExtension == "mlmodelc" {
        return url
    }
    return try MLModel.compileModel(at: url)
}

func jsonValue(from featureValue: MLFeatureValue) -> Any {
    if let multiArray = featureValue.multiArrayValue {
        let values = (0 ..< multiArray.count).map { index in
            multiArray[index].doubleValue
        }
        if values.count == 1 {
            return values[0]
        }
        return values
    }
    if featureValue.type == .double {
        return featureValue.doubleValue
    }
    if featureValue.type == .int64 {
        return featureValue.int64Value
    }
    if featureValue.type == .string {
        return featureValue.stringValue
    }
    if featureValue.type == .dictionary {
        return featureValue.dictionaryValue
    }
    return NSNull()
}

func writeJSON(_ object: [String: Any]) throws {
    let data = try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write(Data("\n".utf8))
}

do {
    let args = try parseArguments(Array(CommandLine.arguments.dropFirst()))
    guard let modelPath = args["model"] else {
        throw CliError.message("missing --model")
    }
    guard let featureJSON = args["features"] else {
        throw CliError.message("missing --features")
    }
    let computeUnitsName = args["compute-units"] ?? "all"
    let computeUnits = try parseComputeUnits(computeUnitsName)

    let jsonObject = try JSONSerialization.jsonObject(with: Data(featureJSON.utf8))
    let features = try scalarArray(from: jsonObject)
    let inputArray = try makeInputArray(values: features)

    let originalURL = URL(fileURLWithPath: modelPath)
    let compiledURL = try compileModelIfNeeded(url: originalURL)
    let configuration = MLModelConfiguration()
    configuration.computeUnits = computeUnits
    let model = try MLModel(contentsOf: compiledURL, configuration: configuration)

    guard let inputName = model.modelDescription.inputDescriptionsByName.keys.sorted().first else {
        throw CliError.message("model has no inputs")
    }

    let provider = try MLDictionaryFeatureProvider(
        dictionary: [inputName: MLFeatureValue(multiArray: inputArray)]
    )
    let prediction = try model.prediction(from: provider)

    var outputs: [String: Any] = [:]
    for name in prediction.featureNames.sorted() {
        guard let value = prediction.featureValue(for: name) else {
            continue
        }
        outputs[name] = jsonValue(from: value)
    }

    let gpuLaneScore = outputs["gpu_lane_score"] as? Double
        ?? (outputs.values.first as? Double)

    try writeJSON(
        [
            "compiled_model_path": compiledURL.path,
            "compute_units": computeUnitsName,
            "feature_count": features.count,
            "gpu_lane_score": gpuLaneScore as Any,
            "input_name": inputName,
            "model_path": originalURL.path,
            "outputs": outputs,
        ]
    )
} catch {
    let message = String(describing: error)
    FileHandle.standardError.write(Data("error: \(message)\n".utf8))
    exit(1)
}
