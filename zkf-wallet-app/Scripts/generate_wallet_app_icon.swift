import AppKit
import Foundation
import ImageIO
import UniformTypeIdentifiers

enum Palette {
    static let background = NSColor(calibratedRed: 0.0, green: 0.0, blue: 0.0, alpha: 1.0)
    static let backgroundLift = NSColor(calibratedRed: 0.07, green: 0.07, blue: 0.09, alpha: 1.0)
    static let midnightBlue = NSColor(calibratedRed: 0.0, green: 0.0, blue: 254.0 / 255.0, alpha: 1.0)
    static let blueGlow = NSColor(calibratedRed: 0.15, green: 0.17, blue: 1.0, alpha: 1.0)
    static let dustAmber = NSColor(calibratedRed: 229.0 / 255.0, green: 169.0 / 255.0, blue: 19.0 / 255.0, alpha: 1.0)
    static let highlight = NSColor(calibratedWhite: 1.0, alpha: 0.94)
}

struct IconSize {
    let points: Int
    let scale: Int
    let filename: String

    var pixels: Int { points * scale }
}

let outputRoot = URL(fileURLWithPath: "/Users/sicarii/Desktop/ZirOS/zkf-wallet-app/Resources")
let appIconSet = outputRoot.appendingPathComponent("Assets.xcassets/AppIcon.appiconset", isDirectory: true)
let sourceRoot = outputRoot.appendingPathComponent("IconSource", isDirectory: true)

let fileManager = FileManager.default
try fileManager.createDirectory(at: appIconSet, withIntermediateDirectories: true)
try fileManager.createDirectory(at: sourceRoot, withIntermediateDirectories: true)

let sizes: [IconSize] = [
    .init(points: 20, scale: 2, filename: "AppIcon-20@2x.png"),
    .init(points: 20, scale: 3, filename: "AppIcon-20@3x.png"),
    .init(points: 29, scale: 2, filename: "AppIcon-29@2x.png"),
    .init(points: 29, scale: 3, filename: "AppIcon-29@3x.png"),
    .init(points: 40, scale: 2, filename: "AppIcon-40@2x.png"),
    .init(points: 40, scale: 3, filename: "AppIcon-40@3x.png"),
    .init(points: 60, scale: 2, filename: "AppIcon-60@2x.png"),
    .init(points: 60, scale: 3, filename: "AppIcon-60@3x.png"),
    .init(points: 1024, scale: 1, filename: "AppIcon-1024.png"),
]

func renderImage(size: Int) throws -> CGImage {
    guard
        let colorSpace = CGColorSpace(name: CGColorSpace.sRGB),
        let context = CGContext(
            data: nil,
            width: size,
            height: size,
            bitsPerComponent: 8,
            bytesPerRow: 0,
            space: colorSpace,
            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
        )
    else {
        throw NSError(domain: "ZirOSWalletIcon", code: 2, userInfo: [NSLocalizedDescriptionKey: "Unable to create bitmap"])
    }

    let rect = NSRect(x: 0, y: 0, width: CGFloat(size), height: CGFloat(size))
    let graphicsContext = NSGraphicsContext(cgContext: context, flipped: false)

    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = graphicsContext
    defer { NSGraphicsContext.restoreGraphicsState() }

    let size = CGFloat(size)

    context.setAllowsAntialiasing(true)
    context.setShouldAntialias(true)
    context.interpolationQuality = .high

    Palette.background.setFill()
    rect.fill()

    let baseGradient = NSGradient(
        colorsAndLocations:
            (Palette.backgroundLift, 0.0),
            (Palette.background, 0.55),
            (Palette.background, 1.0)
    )
    baseGradient?.draw(
        fromCenter: NSPoint(x: size * 0.42, y: size * 0.66),
        radius: 0,
        toCenter: NSPoint(x: size * 0.5, y: size * 0.5),
        radius: size * 0.9,
        options: []
    )

    let orbitCenter = NSPoint(x: size * 0.5, y: size * 0.54)
    let orbitRadius = size * 0.31
    let orbitLineWidth = size * 0.074

    let orbitPath = NSBezierPath()
    orbitPath.appendArc(
        withCenter: orbitCenter,
        radius: orbitRadius,
        startAngle: 135,
        endAngle: 402,
        clockwise: false
    )
    orbitPath.lineWidth = orbitLineWidth
    orbitPath.lineCapStyle = .round

    context.saveGState()
    context.setShadow(offset: .zero, blur: size * 0.04, color: Palette.blueGlow.withAlphaComponent(0.45).cgColor)
    Palette.midnightBlue.setStroke()
    orbitPath.stroke()
    context.restoreGState()

    let dustArc = NSBezierPath()
    dustArc.appendArc(
        withCenter: orbitCenter,
        radius: orbitRadius,
        startAngle: 26,
        endAngle: 74,
        clockwise: false
    )
    dustArc.lineWidth = orbitLineWidth * 0.92
    dustArc.lineCapStyle = .round
    context.saveGState()
    context.setShadow(offset: .zero, blur: size * 0.035, color: Palette.dustAmber.withAlphaComponent(0.4).cgColor)
    Palette.dustAmber.setStroke()
    dustArc.stroke()
    context.restoreGState()

    let highlightArc = NSBezierPath()
    highlightArc.appendArc(
        withCenter: orbitCenter,
        radius: orbitRadius - orbitLineWidth * 0.55,
        startAngle: 194,
        endAngle: 258,
        clockwise: false
    )
    highlightArc.lineWidth = size * 0.018
    highlightArc.lineCapStyle = .round
    Palette.highlight.withAlphaComponent(0.18).setStroke()
    highlightArc.stroke()

    let dustDots: [(CGFloat, CGFloat, CGFloat)] = [
        (0.77, 0.73, 0.046),
        (0.82, 0.67, 0.031),
        (0.855, 0.625, 0.020),
    ]
    for (x, y, scale) in dustDots {
        let diameter = size * scale
        let dotRect = NSRect(
            x: size * x - diameter / 2,
            y: size * y - diameter / 2,
            width: diameter,
            height: diameter
        )
        context.saveGState()
        context.setShadow(offset: .zero, blur: size * 0.02, color: Palette.dustAmber.withAlphaComponent(0.35).cgColor)
        Palette.dustAmber.setFill()
        NSBezierPath(ovalIn: dotRect).fill()
        context.restoreGState()
    }

    let monogram = NSBezierPath()
    monogram.lineWidth = size * 0.078
    monogram.lineCapStyle = .round
    monogram.lineJoinStyle = .round
    monogram.move(to: NSPoint(x: size * 0.31, y: size * 0.655))
    monogram.line(to: NSPoint(x: size * 0.69, y: size * 0.655))
    monogram.move(to: NSPoint(x: size * 0.675, y: size * 0.62))
    monogram.line(to: NSPoint(x: size * 0.34, y: size * 0.37))
    monogram.move(to: NSPoint(x: size * 0.31, y: size * 0.335))
    monogram.line(to: NSPoint(x: size * 0.69, y: size * 0.335))

    context.saveGState()
    context.setShadow(offset: CGSize(width: 0, height: -size * 0.01), blur: size * 0.05, color: Palette.midnightBlue.withAlphaComponent(0.38).cgColor)
    Palette.highlight.setStroke()
    monogram.stroke()
    context.restoreGState()

    let centerGlow = NSGradient(
        colorsAndLocations:
            (Palette.midnightBlue.withAlphaComponent(0.20), 0.0),
            (Palette.midnightBlue.withAlphaComponent(0.06), 0.45),
            (Palette.midnightBlue.withAlphaComponent(0.0), 1.0)
    )
    centerGlow?.draw(
        in: NSBezierPath(ovalIn: NSRect(
            x: size * 0.26,
            y: size * 0.22,
            width: size * 0.48,
            height: size * 0.48
        )),
        relativeCenterPosition: .zero
    )

    guard let image = context.makeImage() else {
        throw NSError(domain: "ZirOSWalletIcon", code: 4, userInfo: [NSLocalizedDescriptionKey: "Unable to create CGImage"])
    }

    return image
}

func writePNG(size: Int, to url: URL) throws {
    let image = try renderImage(size: size)
    guard
        let destination = CGImageDestinationCreateWithURL(
            url as CFURL,
            UTType.png.identifier as CFString,
            1,
            nil
        )
    else {
        throw NSError(domain: "ZirOSWalletIcon", code: 5, userInfo: [NSLocalizedDescriptionKey: "Unable to create image destination"])
    }

    CGImageDestinationAddImage(destination, image, nil)
    guard CGImageDestinationFinalize(destination) else {
        throw NSError(domain: "ZirOSWalletIcon", code: 6, userInfo: [NSLocalizedDescriptionKey: "Unable to finalize PNG"])
    }
}

for size in sizes {
    try writePNG(size: size.pixels, to: appIconSet.appendingPathComponent(size.filename))
}

try writePNG(size: 1024, to: sourceRoot.appendingPathComponent("ZirOSWallet-AppIcon-1024.png"))

print("Generated icon assets in \\(appIconSet.path)")
