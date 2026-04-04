import CoreImage
import CoreImage.CIFilterBuiltins
import SwiftUI

#if os(macOS)
import AppKit
typealias WalletPlatformImage = NSImage
#elseif os(iOS)
import UIKit
typealias WalletPlatformImage = UIImage
#endif

enum WalletPlatformSupport {
    static var biometricLabel: String {
#if os(iOS)
        return "Face ID"
#else
        return "Touch ID"
#endif
    }

    static var biometricSymbol: String {
#if os(iOS)
        return "faceid"
#else
        return "touchid"
#endif
    }

    static func pastedString() -> String? {
#if os(iOS)
        return UIPasteboard.general.string
#else
        return NSPasteboard.general.string(forType: .string)
#endif
    }

    static func copyToPasteboard(_ value: String) {
#if os(iOS)
        UIPasteboard.general.string = value
#else
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(value, forType: .string)
#endif
    }

    static func openURL(_ url: URL) {
#if os(iOS)
        UIApplication.shared.open(url)
#else
        NSWorkspace.shared.open(url)
#endif
    }

    static func qrImage(value: String, context: CIContext) -> WalletPlatformImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(value.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 8, y: 8)),
              let cgImage = context.createCGImage(output, from: output.extent)
        else {
            return nil
        }

#if os(iOS)
        return UIImage(cgImage: cgImage)
#else
        return NSImage(
            cgImage: cgImage,
            size: NSSize(width: output.extent.width, height: output.extent.height)
        )
#endif
    }
}

extension Image {
    init(walletPlatformImage: WalletPlatformImage) {
#if os(iOS)
        self.init(uiImage: walletPlatformImage)
#else
        self.init(nsImage: walletPlatformImage)
#endif
    }
}
