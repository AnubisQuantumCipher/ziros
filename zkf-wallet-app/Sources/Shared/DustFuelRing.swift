import SwiftUI
import Foundation
#if canImport(UIKit)
import UIKit
private typealias PlatformColor = UIColor
#elseif canImport(AppKit)
import AppKit
private typealias PlatformColor = NSColor
#endif

struct DustFuelRing: View {
    enum Style {
        case standard
        case hero
        case dashboard
    }

    let currentDust: Double
    let targetDustFor100Txns: Double
    let estimatedTransactionsRemaining: Int
    let style: Style

    @State private var pulse = false

    private var progress: Double {
        min(max(currentDust / max(targetDustFor100Txns, 1), 0), 1)
    }

    private var ringColor: Color {
        switch progress {
        case 0:
            return WalletBrandAssets.Color.critical
        case 0..<0.25:
            return WalletBrandAssets.Color.critical
        case 0.25..<0.5:
            return WalletBrandAssets.Color.warning
        default:
            return WalletBrandAssets.Color.dustAmber
        }
    }

    private var ringLineWidth: CGFloat {
        switch style {
        case .standard:
#if os(iOS)
            return 12
#else
            return 14
#endif
        case .hero:
#if os(iOS)
            return 12
#else
            return 14
#endif
        case .dashboard:
#if os(iOS)
            return 12
#else
            return 14
#endif
        }
    }

    private var numberFont: Font {
        switch style {
        case .standard:
#if os(iOS)
            return .system(size: 22, weight: .bold, design: .monospaced)
#else
            return .system(size: 26, weight: .bold, design: .monospaced)
#endif
        case .hero:
#if os(iOS)
            return .system(size: 22, weight: .bold, design: .monospaced)
#else
            return .system(size: 26, weight: .bold, design: .monospaced)
#endif
        case .dashboard:
#if os(iOS)
            return .system(size: 22, weight: .bold, design: .monospaced)
#else
            return .system(size: 26, weight: .bold, design: .monospaced)
#endif
        }
    }

    private var captionFont: Font {
#if os(iOS)
        return .system(size: 11, weight: .medium, design: .monospaced)
#else
        return .system(size: 11, weight: .medium, design: .monospaced)
#endif
    }

    private var ringFrame: CGFloat {
        switch style {
        case .standard:
#if os(iOS)
            return 120
#else
            return 140
#endif
        case .hero:
#if os(iOS)
            return 120
#else
            return 140
#endif
        case .dashboard:
#if os(iOS)
            return 120
#else
            return 140
#endif
        }
    }

    private var centerBoxSize: CGFloat {
        switch style {
        case .standard:
#if os(iOS)
            return 76
#else
            return 84
#endif
        case .hero:
#if os(iOS)
            return 76
#else
            return 84
#endif
        case .dashboard:
#if os(iOS)
            return 76
#else
            return 84
#endif
        }
    }

    private var abbreviatedDustValue: String {
        let value = max(currentDust, 0)
        switch value {
        case 1_000_000_000...:
            return abbreviated(value / 1_000_000_000, suffix: "B")
        case 1_000_000...:
            return abbreviated(value / 1_000_000, suffix: "M")
        case 1_000...:
            return abbreviated(value / 1_000, suffix: "K")
        default:
            return formatIntWithGroupingSeparator(Int(value.rounded(.down)))
        }
    }

    private var dustRawString: String {
        String(Int(max(currentDust, 0).rounded(.down)))
    }

    private var statusLine: String {
        "~\(estimatedTransactionsRemaining) txns"
    }

    private var ringGradient: LinearGradient {
        switch progress {
        case 0..<0.25:
            return LinearGradient(
                colors: [WalletBrandAssets.Color.critical.opacity(0.75), WalletBrandAssets.Color.critical, WalletBrandAssets.Color.warning],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
        case 0.25..<0.5:
            return LinearGradient(
                colors: [WalletBrandAssets.Color.warning.opacity(0.82), WalletBrandAssets.Color.warning, WalletBrandAssets.Color.dustAmber],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
        default:
            return LinearGradient(
                colors: [WalletBrandAssets.Color.dustAmber.opacity(0.82), WalletBrandAssets.Color.dustAmber, Color(red: 0.957, green: 0.773, blue: 0.259)],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
        }
    }

    init(currentDust: Double, targetDustFor100Txns: Double, estimatedTransactionsRemaining: Int? = nil, style: Style = .standard) {
        self.currentDust = currentDust
        self.targetDustFor100Txns = targetDustFor100Txns
        if let remaining = estimatedTransactionsRemaining {
            self.estimatedTransactionsRemaining = remaining
        } else {
            let ratio = targetDustFor100Txns > 0 ? currentDust / targetDustFor100Txns : 0
            self.estimatedTransactionsRemaining = Int((ratio * 100).rounded(.down))
        }
        self.style = style
    }

    var body: some View {
        let pulseAnimation = Animation.easeInOut(duration: 1).repeatForever(autoreverses: true)

        ZStack {
            Circle()
                .stroke(WalletBrandAssets.Color.cardBorder.opacity(0.75), lineWidth: ringLineWidth)
            Circle()
                .trim(from: 0, to: progress)
                .stroke(
                    ringGradient,
                    style: StrokeStyle(lineWidth: ringLineWidth, lineCap: .round)
                )
                .rotationEffect(.degrees(-90))
                .animation(.easeInOut(duration: 0.4), value: progress)
                .scaleEffect(progress < 0.25 && progress > 0 ? (pulse ? 1.02 : 1.0) : 1.0)
                .opacity(progress < 0.25 && progress > 0 ? (pulse ? 0.7 : 1.0) : 1.0)
                .animation(progress < 0.25 && progress > 0 ? pulseAnimation : .default, value: pulse)
                .onAppear {
                    if progress < 0.25 && progress > 0 {
                        pulse = true
                    }
                }
                .onChange(of: progress) { newValue in
                    if newValue < 0.25 && newValue > 0 {
                        pulse = true
                    } else {
                        pulse = false
                    }
                }

            VStack(spacing: 4) {
                Text(WalletDisplay.formattedDustCompactValue(fromRaw: dustRawString))
                    .font(numberFont)
                    .foregroundColor(ringColor)
                    .lineLimit(1)
                    .minimumScaleFactor(0.7)
                Text(statusLine)
                    .font(captionFont)
                    .foregroundColor(WalletBrandAssets.Color.textSecondary)
                    .lineLimit(1)
                    .minimumScaleFactor(0.8)
            }
            .frame(width: centerBoxSize, height: centerBoxSize)
            .multilineTextAlignment(.center)
            .padding(.horizontal, 4)
        }
        .frame(width: ringFrame, height: ringFrame)
    }

    private func formatIntWithGroupingSeparator(_ value: Int) -> String {
        let formatter = NumberFormatter()
        formatter.numberStyle = .decimal
        formatter.groupingSeparator = ","
        formatter.groupingSize = 3
        return formatter.string(from: NSNumber(value: value)) ?? "\(value)"
    }

    private func abbreviated(_ value: Double, suffix: String) -> String {
        let rounded = (value * 10).rounded() / 10
        if rounded.rounded() == rounded {
            return "\(Int(rounded))\(suffix)"
        }
        return "\(rounded.formatted(.number.precision(.fractionLength(1))))\(suffix)"
    }
}

private extension Color {
    func interpolate(to: Color, fraction: Double) -> Color {
        #if canImport(UIKit) || canImport(AppKit)
        let fromComponents = PlatformColor(self).cgColor.components ?? [0, 0, 0, 1]
        let toComponents = PlatformColor(to).cgColor.components ?? [0, 0, 0, 1]

        // UIColor components can have 2 or 4 components (grayscale or RGBA)
        // Normalize to RGBA 4 components
        let fromRGBA = fromComponents.count == 2 ? [fromComponents[0], fromComponents[0], fromComponents[0], fromComponents[1]] : fromComponents
        let toRGBA = toComponents.count == 2 ? [toComponents[0], toComponents[0], toComponents[0], toComponents[1]] : toComponents

        let r = fromRGBA[0] + (toRGBA[0] - fromRGBA[0]) * CGFloat(fraction)
        let g = fromRGBA[1] + (toRGBA[1] - fromRGBA[1]) * CGFloat(fraction)
        let b = fromRGBA[2] + (toRGBA[2] - fromRGBA[2]) * CGFloat(fraction)
        let a = fromRGBA[3] + (toRGBA[3] - fromRGBA[3]) * CGFloat(fraction)

        return Color(red: Double(r), green: Double(g), blue: Double(b), opacity: Double(a))
        #else
        return self
        #endif
    }
}

#Preview {
    VStack(spacing: 40) {
        DustFuelRing(currentDust: 0, targetDustFor100Txns: 100_000_000)
        DustFuelRing(currentDust: 10_000_000, targetDustFor100Txns: 100_000_000)
        DustFuelRing(currentDust: 30_000_000, targetDustFor100Txns: 100_000_000)
        DustFuelRing(currentDust: 50_000_000, targetDustFor100Txns: 100_000_000)
        DustFuelRing(currentDust: 80_000_000, targetDustFor100Txns: 100_000_000)
        DustFuelRing(currentDust: 100_000_000, targetDustFor100Txns: 100_000_000)
    }
    .padding()
    .background(Color.black)
    .previewLayout(.sizeThatFits)
}
