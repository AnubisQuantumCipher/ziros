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
    let currentDust: Double
    let targetDustFor100Txns: Double
    let estimatedTransactionsRemaining: Int

    @State private var pulse = false

    private var progress: Double {
        min(max(currentDust / max(targetDustFor100Txns, 1), 0), 1)
    }

    private var ringColor: Color {
        switch progress {
        case 0:
            return WalletBrandAssets.Color.critical
        case 0..<0.25:
            return WalletBrandAssets.Color.warning
        case 0.25...0.75:
            let amt = (progress - 0.25) / (0.75 - 0.25)
            return WalletBrandAssets.Color.warning.interpolate(to: WalletBrandAssets.Color.dustAmber, fraction: amt)
        default:
            return WalletBrandAssets.Color.dustAmber
        }
    }

    private var ringLineWidth: CGFloat {
#if os(iOS)
        16
#else
        18
#endif
    }

    private var numberFont: Font {
#if os(iOS)
        return .custom("Outfit-ExtraBold", size: 30)
#else
        return .custom("Outfit-ExtraBold", size: 34)
#endif
    }

    private var captionFont: Font {
#if os(iOS)
        return .custom("Outfit-Medium", size: 11)
#else
        return WalletBrandAssets.Typography.caption
#endif
    }

    private var ringFrame: CGFloat {
#if os(iOS)
        136
#else
        144
#endif
    }

    private var centerBoxSize: CGFloat {
#if os(iOS)
        78
#else
        84
#endif
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

    private var statusLine: String {
        if progress == 0 {
            return "Empty"
        }
        return "~\(estimatedTransactionsRemaining) transactions remaining"
    }

    init(currentDust: Double, targetDustFor100Txns: Double, estimatedTransactionsRemaining: Int? = nil) {
        self.currentDust = currentDust
        self.targetDustFor100Txns = targetDustFor100Txns
        if let remaining = estimatedTransactionsRemaining {
            self.estimatedTransactionsRemaining = remaining
        } else {
            let ratio = targetDustFor100Txns > 0 ? currentDust / targetDustFor100Txns : 0
            self.estimatedTransactionsRemaining = Int((ratio * 100).rounded(.down))
        }
    }

    var body: some View {
        let pulseAnimation = Animation.easeInOut(duration: 1).repeatForever(autoreverses: true)

        VStack(spacing: 10) {
            ZStack {
                Circle()
                    .stroke(Color.white.opacity(0.05), lineWidth: ringLineWidth)
                Circle()
                    .trim(from: 0, to: progress)
                    .stroke(
                        ringColor,
                        style: StrokeStyle(lineWidth: ringLineWidth, lineCap: .round)
                    )
                    .rotationEffect(.degrees(-90))
                    .animation(.easeInOut(duration: 0.4), value: progress)
                    .scaleEffect(progress < 0.25 && progress > 0 ? (pulse ? 1.04 : 1.0) : 1.0)
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
                    Text(abbreviatedDustValue)
                        .font(numberFont)
                        .foregroundColor(WalletBrandAssets.Color.textPrimary)
                        .lineLimit(1)
                        .minimumScaleFactor(0.7)
                    Text("DUST Fuel")
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

            Text(statusLine)
                .font(captionFont)
                .foregroundColor(WalletBrandAssets.Color.textSecondary)
                .lineLimit(1)
                .minimumScaleFactor(0.7)
        }
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
