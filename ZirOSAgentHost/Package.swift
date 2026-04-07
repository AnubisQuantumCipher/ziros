// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "ZirOSAgentHost",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .executable(
            name: "ZirOSAgentHost",
            targets: ["ZirOSAgentHost"]
        )
    ],
    targets: [
        .executableTarget(
            name: "ZirOSAgentHost",
            path: "Sources/ZirOSAgentHost"
        )
    ]
)
