// swift-tools-version:6.0
import PackageDescription

let cryptoDep: Target.Dependency = .product(
    name: "Crypto", package: "swift-crypto", condition: .when(platforms: [.linux]))

let package = Package(
    name: "AgentKey",
    platforms: [.macOS(.v14), .iOS(.v17)],
    products: [
        .library(name: "AgentKeyCore", targets: ["AgentKeyCore"]),
        .library(name: "AgentKeyIPC", targets: ["AgentKeyIPC"]),
        .executable(name: "agentkeyd", targets: ["agentkeyd"]),
        .executable(name: "agentkey", targets: ["agentkey"]),
        .executable(name: "agentkey-mcp", targets: ["agentkey-mcp"]),
    ],
    dependencies: [
        // Only linked on Linux (CI / dev boxes). Apple platforms use CryptoKit.
        .package(url: "https://github.com/apple/swift-crypto.git", "3.0.0"..<"5.0.0"),
    ],
    targets: [
        .target(name: "AgentKeyCore", dependencies: [cryptoDep],
                swiftSettings: [.swiftLanguageMode(.v5)]),
        .target(name: "AgentKeyIPC", dependencies: ["AgentKeyCore"],
                swiftSettings: [.swiftLanguageMode(.v5)]),
        .executableTarget(name: "agentkeyd", dependencies: ["AgentKeyCore", "AgentKeyIPC"],
                          swiftSettings: [.swiftLanguageMode(.v5)]),
        .executableTarget(name: "agentkey", dependencies: ["AgentKeyCore", "AgentKeyIPC"],
                          swiftSettings: [.swiftLanguageMode(.v5)]),
        .executableTarget(name: "agentkey-mcp", dependencies: ["AgentKeyCore", "AgentKeyIPC"],
                          swiftSettings: [.swiftLanguageMode(.v5)]),
        .testTarget(name: "AgentKeyCoreTests", dependencies: ["AgentKeyCore", "AgentKeyIPC"],
                    resources: [.copy("Fixtures")],
                    swiftSettings: [.swiftLanguageMode(.v5)]),
    ]
)
