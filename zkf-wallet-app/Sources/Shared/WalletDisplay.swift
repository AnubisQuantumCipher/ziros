import Foundation

struct WalletStatusCopy {
    let title: String
    let detail: String?
}

enum WalletDisplay {
    private static let posixLocale = Locale(identifier: "en_US_POSIX")
    private static let nightScale = Decimal(string: "1000000000000000", locale: posixLocale) ?? 1
    private static let defaultDustPerActionRaw = Decimal(string: "1000000", locale: posixLocale) ?? 1

    static func decimal(from value: String?) -> Decimal? {
        guard let value else { return nil }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        let normalized = trimmed.replacingOccurrences(of: ",", with: "")
        return Decimal(string: normalized, locale: posixLocale)
    }

    static func nightDecimal(fromRaw raw: String?) -> Decimal {
        let rawValue = decimal(from: raw) ?? .zero
        return rawValue / nightScale
    }

    static func rawNight(fromDisplay value: String) -> String? {
        let sanitized = sanitizedDecimalInput(value, maxFractionDigits: 3)
        guard let displayDecimal = decimal(from: sanitized) else {
            return nil
        }
        return wholeNumberString(displayDecimal * nightScale)
    }

    static func rawNight(fromBalanceDisplay value: String?) -> String? {
        guard let displayDecimal = decimal(from: value) else {
            return nil
        }
        return wholeNumberString(displayDecimal * nightScale)
    }

    static func editableNight(fromRaw raw: String?) -> String {
        formattedNight(nightDecimal(fromRaw: raw), minimumFractionDigits: 3, maximumFractionDigits: 3)
    }

    static func formattedNightPrimary(fromRaw raw: String?) -> String {
        formattedNight(nightDecimal(fromRaw: raw), minimumFractionDigits: 3, maximumFractionDigits: 3)
    }

    static func formattedNightPrimary(_ value: Decimal) -> String {
        formattedNight(value, minimumFractionDigits: 3, maximumFractionDigits: 3)
    }

    static func formattedNightCompact(fromRaw raw: String?) -> String {
        formattedNight(nightDecimal(fromRaw: raw), minimumFractionDigits: 0, maximumFractionDigits: 3)
    }

    static func formattedNightCompact(_ value: Decimal) -> String {
        formattedNight(value, minimumFractionDigits: 0, maximumFractionDigits: 3)
    }

    static func formattedNightMetric(_ value: Double) -> String {
        formattedNightCompact(Decimal(value))
    }

    static func formattedNightMetric(fromDisplay value: String?) -> String {
        guard let decimalValue = decimal(from: value) else {
            return "0.000"
        }
        return formattedNightPrimary(decimalValue)
    }

    static func formattedRawValue(_ raw: String?) -> String {
        let rawValue = raw?.trimmingCharacters(in: .whitespacesAndNewlines)
        return rawValue?.isEmpty == false ? rawValue! : "0"
    }

    static func rawCaption(_ raw: String?) -> String {
        "Raw: \(formattedRawValue(raw))"
    }

    static func formattedDustCompact(fromRaw raw: String?) -> String {
        "\(formattedDustCompactValue(fromRaw: raw)) DUST"
    }

    static func formattedDustCompactValue(fromRaw raw: String?) -> String {
        abbreviatedDust(decimal(from: raw) ?? .zero)
    }

    static func formattedDustPrecise(fromRaw raw: String?) -> String {
        let value = decimal(from: raw) ?? .zero
        return formattedNumber(value, minimumFractionDigits: 0, maximumFractionDigits: 0)
    }

    static func formattedDustFee(fromRaw raw: String?) -> String {
        "~\(formattedDustCompact(fromRaw: raw))"
    }

    static func estimatedTransactionCount(fromDustRaw raw: String?) -> Int {
        estimatedActionCount(fromDustRaw: raw, costRaw: formattedRawValue("1000000"))
    }

    static func estimatedActionCount(fromDustRaw raw: String?, costRaw: String?) -> Int {
        let available = decimal(from: raw) ?? .zero
        let actionCost = decimal(from: costRaw) ?? defaultDustPerActionRaw
        guard actionCost > .zero else { return 0 }
        var ratio = available / actionCost
        var flooredRatio = Decimal.zero
        NSDecimalRound(&flooredRatio, &ratio, 0, .down)
        return NSDecimalNumber(decimal: flooredRatio).intValue
    }

    static func estimatedTransactionText(fromDustRaw raw: String?) -> String {
        "~\(estimatedTransactionCount(fromDustRaw: raw)) txns"
    }

    static func estimatedPostText(fromDustRaw raw: String?, costRaw: String?) -> String {
        "~\(estimatedActionCount(fromDustRaw: raw, costRaw: costRaw)) posts"
    }

    static func formattedDustConversationTotal(fromRaw raw: String?) -> String {
        "\(formattedDustCompactValue(fromRaw: raw)) DUST"
    }

    static func userFacingError(_ message: String?) -> String? {
        guard let message else { return nil }
        let lowercased = message.lowercased()
        if lowercased.contains("the specified item could not be found in the keychain") {
            return "Wallet seed not found. Import your seed to get started."
        }
        if lowercased.contains("helper returned no response") {
            return "Connecting to Midnight..."
        }
        if lowercased.contains("prover unavailable") {
            return "Proof Server Offline"
        }
        if lowercased.contains("wallet helper runtime bundle is unavailable")
            || lowercased.contains("bridge helper session is unavailable")
            || lowercased.contains("midnight execution is unavailable")
            || lowercased.contains("wallet helper execution is unavailable")
        {
            return "Connecting to Midnight..."
        }
        return message
    }

    static func helperStatus(message: String?, networkName: String) -> WalletStatusCopy {
        let fallbackTitle = "Wallet is connecting to Midnight \(networkName.capitalized)..."
        guard let message else {
            return WalletStatusCopy(title: fallbackTitle, detail: helperStatusDetail)
        }
        let userFacing = userFacingError(message) ?? message
        if userFacing == "Connecting to Midnight..." || isConnectivityMessage(message) {
            return WalletStatusCopy(title: fallbackTitle, detail: helperStatusDetail)
        }
        return WalletStatusCopy(title: userFacing, detail: helperStatusDetail)
    }

    static func sanitizedDecimalInput(_ value: String, maxFractionDigits: Int = 3) -> String {
        var result = ""
        var hasDecimalSeparator = false
        var fractionDigits = 0

        for character in value {
            if character.isWholeNumber {
                if hasDecimalSeparator {
                    guard fractionDigits < maxFractionDigits else { continue }
                    fractionDigits += 1
                }
                result.append(character)
            } else if character == "." && !hasDecimalSeparator {
                hasDecimalSeparator = true
                result.append(character)
            } else if character == "," {
                continue
            }
        }

        return result
    }

    static func isPositiveRawNight(_ raw: String?) -> Bool {
        guard let value = decimal(from: raw) else { return false }
        return value > .zero
    }

    static var helperStatusDetail: String {
        "If this persists, check that the proof server is running on port 6300 and the network is reachable."
    }

    private static func formattedNight(
        _ value: Decimal,
        minimumFractionDigits: Int,
        maximumFractionDigits: Int
    ) -> String {
        formattedNumber(
            value,
            minimumFractionDigits: minimumFractionDigits,
            maximumFractionDigits: maximumFractionDigits
        )
    }

    private static func formattedNumber(
        _ value: Decimal,
        minimumFractionDigits: Int,
        maximumFractionDigits: Int
    ) -> String {
        let formatter = NumberFormatter()
        formatter.locale = posixLocale
        formatter.numberStyle = .decimal
        formatter.groupingSeparator = ","
        formatter.minimumFractionDigits = minimumFractionDigits
        formatter.maximumFractionDigits = maximumFractionDigits
        return formatter.string(from: NSDecimalNumber(decimal: value)) ?? "0"
    }

    private static func abbreviatedDust(_ value: Decimal) -> String {
        let numericValue = NSDecimalNumber(decimal: value).doubleValue
        switch numericValue {
        case 1_000_000_000...:
            return abbreviated(value: numericValue / 1_000_000_000, suffix: "B")
        case 1_000_000...:
            return abbreviated(value: numericValue / 1_000_000, suffix: "M")
        case 1_000...:
            return abbreviated(value: numericValue / 1_000, suffix: "K")
        default:
            return formattedDustPrecise(fromRaw: NSDecimalNumber(decimal: value).stringValue)
        }
    }

    private static func abbreviated(value: Double, suffix: String) -> String {
        let rounded = (value * 10).rounded() / 10
        if rounded.rounded() == rounded {
            return "\(Int(rounded))\(suffix)"
        }
        return "\(rounded.formatted(.number.precision(.fractionLength(1))))\(suffix)"
    }

    private static func wholeNumberString(_ value: Decimal) -> String {
        var workingValue = value
        var roundedValue = Decimal.zero
        NSDecimalRound(&roundedValue, &workingValue, 0, .down)
        return NSDecimalNumber(decimal: roundedValue).stringValue
    }

    private static func isConnectivityMessage(_ message: String) -> Bool {
        let lowercased = message.lowercased()
        return lowercased.contains("helper")
            || lowercased.contains("execution is unavailable")
            || lowercased.contains("runtime")
            || lowercased.contains("bundle is unavailable")
    }
}
