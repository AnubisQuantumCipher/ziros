import SwiftUI
import Foundation

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

        ZStack {
            Circle()
                .stroke(Color.white.opacity(0.05), lineWidth: 20)
            Circle()
                .trim(from: 0, to: progress)
                .stroke(
                    ringColor,
                    style: StrokeStyle(lineWidth: 20, lineCap: .round)
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

            VStack(spacing: 2) {
                Text("DUST Fuel")
                    .font(WalletBrandAssets.Typography.caption)
                    .foregroundColor(WalletBrandAssets.Color.textSecondary)
                Text(formatIntWithGroupingSeparator(Int(currentDust)))
                    .font(WalletBrandAssets.Typography.monoMetric)
                    .foregroundColor(WalletBrandAssets.Color.textPrimary)
                if progress == 0 {
                    Text("Empty")
                        .font(WalletBrandAssets.Typography.caption)
                        .foregroundColor(WalletBrandAssets.Color.textSecondary)
                } else {
                    Text("~\(estimatedTransactionsRemaining) transactions remaining")
                        .font(WalletBrandAssets.Typography.caption)
                        .foregroundColor(WalletBrandAssets.Color.textSecondary)
                        .lineLimit(1)
                        .minimumScaleFactor(0.5)
                }
            }
            .padding(.horizontal, 6)
        }
        .frame(width: 140, height: 140)
    }

    private func formatIntWithGroupingSeparator(_ value: Int) -> String {
        let formatter = NumberFormatter()
        formatter.numberStyle = .decimal
        formatter.groupingSeparator = ","
        formatter.groupingSize = 3
        return formatter.string(from: NSNumber(value: value)) ?? "\(value)"
    }
}

private extension Color {
    func interpolate(to: Color, fraction: Double) -> Color {
        let fromComponents = UIColor(self).cgColor.components ?? [0,0,0,1]
        let toComponents = UIColor(to).cgColor.components ?? [0,0,0,1]

        // UIColor components can have 2 or 4 components (grayscale or RGBA)
        // Normalize to RGBA 4 components
        let fromRGBA = fromComponents.count == 2 ? [fromComponents[0], fromComponents[0], fromComponents[0], fromComponents[1]] : fromComponents
        let toRGBA = toComponents.count == 2 ? [toComponents[0], toComponents[0], toComponents[0], toComponents[1]] : toComponents

        let r = fromRGBA[0] + (toRGBA[0] - fromRGBA[0]) * CGFloat(fraction)
        let g = fromRGBA[1] + (toRGBA[1] - fromRGBA[1]) * CGFloat(fraction)
        let b = fromRGBA[2] + (toRGBA[2] - fromRGBA[2]) * CGFloat(fraction)
        let a = fromRGBA[3] + (toRGBA[3] - fromRGBA[3]) * CGFloat(fraction)

        return Color(red: Double(r), green: Double(g), blue: Double(b), opacity: Double(a))
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
