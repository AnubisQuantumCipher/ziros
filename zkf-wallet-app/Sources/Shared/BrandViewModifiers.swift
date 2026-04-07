import SwiftUI
import Foundation

public struct BrandPrimaryButtonStyle: ButtonStyle {
    public init() {}

    public func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .frame(maxWidth: .infinity, minHeight: 56)
            .background(WalletBrandAssets.Color.midnightBlue)
            .foregroundStyle(.white)
            .cornerRadius(14)
            .scaleEffect(configuration.isPressed ? 0.97 : 1)
            .onChange(of: configuration.isPressed) { pressed in
                if pressed {
                    WalletBrandAssets.Haptics.tapLight()
                }
            }
    }
}

public extension View {
    func brandBackground() -> some View {
        modifier(BrandBackgroundModifier())
    }

    func brandCard(cornerRadius: CGFloat = 16) -> some View {
        modifier(BrandCardModifier(cornerRadius: cornerRadius))
    }

    func brandPill() -> some View {
        modifier(BrandPillModifier())
    }

    func brandMono() -> some View {
        modifier(BrandMonoModifier())
    }
}

fileprivate struct BrandBackgroundModifier: ViewModifier {
    func body(content: Content) -> some View {
        content
            .background(WalletBrandAssets.Color.background)
            .ignoresSafeArea()
    }
}

fileprivate struct BrandCardModifier: ViewModifier {
    let cornerRadius: CGFloat

    func body(content: Content) -> some View {
        content
            .padding()
            .background(WalletBrandAssets.Color.card)
            .overlay(
                RoundedRectangle(cornerRadius: cornerRadius)
                    .stroke(WalletBrandAssets.Color.cardBorder, lineWidth: 1)
            )
            .cornerRadius(cornerRadius)
    }
}

fileprivate struct BrandPillModifier: ViewModifier {
    func body(content: Content) -> some View {
        content
            .padding(.horizontal, 16)
            .padding(.vertical, 6)
            .background(WalletBrandAssets.Color.card)
            .clipShape(Capsule())
    }
}

fileprivate struct BrandMonoModifier: ViewModifier {
    func body(content: Content) -> some View {
        content
            .font(WalletBrandAssets.Typography.monoInline)
            .monospacedDigit()
    }
}

#Preview {
    VStack(spacing: 20) {
        VStack(spacing: 12) {
            Text("Card Title")
                .font(.headline)
            Text("This is a card content area demonstrating the brand card style.")
                .font(.subheadline)
                .foregroundColor(WalletBrandAssets.Color.textSecondary)
            Button("Primary Action") {}
                .buttonStyle(BrandPrimaryButtonStyle())
        }
        .brandCard()

        Text("Pill Label")
            .brandPill()
            .font(.subheadline)

        Text("1234567890")
            .brandMono()
    }
    .padding()
    .brandBackground()
}
