import CoreText
import Foundation
import SwiftUI
#if canImport(UIKit)
import UIKit
#endif

@MainActor
enum WalletBrandAssets {
    enum Color {
        // Core surfaces
        static let background = SwiftUI.Color.black // #000000
        static let card = SwiftUI.Color(red: 0x11/255.0, green: 0x11/255.0, blue: 0x11/255.0) // #111111
        static let cardBorder = SwiftUI.Color(red: 0x1A/255.0, green: 0x1A/255.0, blue: 0x1A/255.0) // #1A1A1A

        // Accents
        static let midnightBlue = SwiftUI.Color(red: 0x00/255.0, green: 0x00/255.0, blue: 0xFE/255.0) // #0000FE
        static let dustAmber = SwiftUI.Color(red: 0xE5/255.0, green: 0xA9/255.0, blue: 0x13/255.0) // #E5A913

        // Status
        static let success = SwiftUI.Color(red: 0x00/255.0, green: 0xD4/255.0, blue: 0x7B/255.0) // #00D47B
        static let warning = SwiftUI.Color(red: 0xFF/255.0, green: 0x95/255.0, blue: 0x00/255.0) // #FF9500
        static let critical = SwiftUI.Color(red: 0xFF/255.0, green: 0x3B/255.0, blue: 0x30/255.0) // #FF3B30

        // Text opacities on white
        static let textPrimary = SwiftUI.Color.white.opacity(0.87)
        static let textSecondary = SwiftUI.Color.white.opacity(0.54)
        static let textTertiary = SwiftUI.Color.white.opacity(0.32)

        // Convenience neutrals
        static let neutralGray = SwiftUI.Color(red: 0x6E/255.0, green: 0x6E/255.0, blue: 0x6E/255.0)
    }

    @MainActor
    enum Haptics {
#if canImport(UIKit)
        static func tapLight() {
            let generator = UIImpactFeedbackGenerator(style: .light)
            generator.impactOccurred()
        }
        static func tapMedium() {
            let generator = UIImpactFeedbackGenerator(style: .medium)
            generator.impactOccurred()
        }
        static func success() {
            let generator = UINotificationFeedbackGenerator()
            generator.notificationOccurred(.success)
        }
        static func warning() {
            let generator = UINotificationFeedbackGenerator()
            generator.notificationOccurred(.warning)
        }
        static func error() {
            let generator = UINotificationFeedbackGenerator()
            generator.notificationOccurred(.error)
        }
#else
        static func tapLight() {}
        static func tapMedium() {}
        static func success() {}
        static func warning() {}
        static func error() {}
#endif
    }

    enum Typography {
        // Display (SF Pro Display) and Text (SF Pro Text) via system
        static func display(_ size: CGFloat, weight: Font.Weight = .bold) -> Font {
            .system(size: size, weight: weight, design: .default)
        }
        static func text(_ size: CGFloat, weight: Font.Weight = .regular) -> Font {
            .system(size: size, weight: weight, design: .default)
        }
        // Mono everywhere numbers matter
        static func mono(_ size: CGFloat, weight: Font.Weight = .regular) -> Font {
            .system(size: size, weight: weight, design: .monospaced)
        }

        // Named sizes per blueprint
        static var balanceHero: Font { mono(48, weight: .bold) }
        static var sectionTitle: Font { display(20, weight: .semibold) }
        static var cardTitle: Font { text(17, weight: .semibold) }
        static var body: Font { text(15) }
        static var caption: Font { text(13) }
        static var monoInline: Font { mono(15, weight: .medium) }
        static var monoMetric: Font { mono(28, weight: .bold) }
    }

    private static let fontNames = [
        "Outfit-Regular",
        "Outfit-Medium",
        "Outfit-SemiBold",
        "Outfit-Bold",
        "Outfit-ExtraBold",
    ]

    private static var didRegisterFonts = false
    // Call registerFontsIfNeeded early in app lifecycle to load custom fonts

    static func registerFontsIfNeeded() {
        guard !didRegisterFonts else { return }
        didRegisterFonts = true

        for fontName in fontNames {
            registerFont(named: fontName, extension: "ttf")
        }
    }

    private static func registerFont(named name: String, extension: String) {
        let url =
            Bundle.main.url(forResource: name, withExtension: `extension`, subdirectory: "Fonts")
            ?? Bundle.main.url(forResource: name, withExtension: `extension`)
        guard let url else {
            return
        }
        CTFontManagerRegisterFontsForURL(url as CFURL, .process, nil)
    }
}
