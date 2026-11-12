// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "Fork",
    platforms: [.macOS(.v14)],
    products: [.executable(name: "Fork", targets: ["ForkApp"])],
    targets: [
        .target(name: "ForkCore"),
        .executableTarget(name: "ForkApp", dependencies: ["ForkCore"]),
        .testTarget(name: "ForkCoreTests", dependencies: ["ForkCore"]),
    ]
)
