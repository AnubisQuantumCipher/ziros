import SwiftUI
import Foundation

struct PrivacyGauge: View {
    let shielded: Double
    let unshielded: Double
    
    private var total: Double {
        max(shielded + unshielded, 0.0001)
    }
    
    private var shieldedRatio: Double {
        shielded / total
    }
    
    private func formattedAmount(_ value: Double) -> String {
        let formatter = NumberFormatter()
        formatter.numberStyle = .decimal
        formatter.groupingSeparator = ","
        formatter.maximumFractionDigits = 0
        return formatter.string(from: NSNumber(value: value)) ?? "0"
    }
    
    var body: some View {
        VStack(spacing: 10) {
            GeometryReader { geo in
                ZStack(alignment: .leading) {
                    RoundedRectangle(cornerRadius: 10)
                        .fill(WalletBrandAssets.Color.cardBorder.opacity(0.1))
                        .frame(height: 18)
                    
                    RoundedRectangle(cornerRadius: 10)
                        .fill(WalletBrandAssets.Color.midnightBlue)
                        .frame(width: geo.size.width * CGFloat(shieldedRatio), height: 18)
                        .animation(.easeInOut(duration: 0.4), value: shieldedRatio)
                    
                    RoundedRectangle(cornerRadius: 10)
                        .fill(WalletBrandAssets.Color.neutralGray.opacity(0.5))
                        .frame(width: geo.size.width * CGFloat(1 - shieldedRatio), height: 18)
                        .offset(x: geo.size.width * CGFloat(shieldedRatio))
                        .animation(.easeInOut(duration: 0.4), value: shieldedRatio)
                }
            }
            .frame(height: 18)
            
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Shielded")
                        .font(.footnote)
                        .foregroundColor(WalletBrandAssets.Color.textSecondary)
                    Text("\(formattedAmount(shielded)) NIGHT")
                        .font(.system(.body, design: .monospaced))
                        .foregroundColor(WalletBrandAssets.Color.textPrimary)
                }
                
                Spacer()
                
                VStack(alignment: .trailing, spacing: 2) {
                    Text("Unshielded")
                        .font(.footnote)
                        .foregroundColor(WalletBrandAssets.Color.textSecondary)
                    Text("\(formattedAmount(unshielded)) NIGHT")
                        .font(.system(.body, design: .monospaced))
                        .foregroundColor(WalletBrandAssets.Color.textPrimary)
                }
            }
        }
    }
}

#Preview {
    PrivacyGauge(shielded: 38400, unshielded: 1600)
        .padding()
        .frame(width: 300)
}
