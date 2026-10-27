// swift-tools-version: 6.0
import PackageDescription

let v5: [SwiftSetting] = [.swiftLanguageMode(.v5)]

// CryptoKit off Apple platforms: swift-crypto, the same API (Crypto.swift picks it when CryptoKit is missing)
#if os(Linux) || os(Windows)
let crypto: [Target.Dependency] = [.product(name: "Crypto", package: "swift-crypto")]
let dependencies: [Package.Dependency] = [.package(url: "https://github.com/apple/swift-crypto.git", "3.0.0" ..< "5.0.0")]
#else
let crypto: [Target.Dependency] = []
let dependencies: [Package.Dependency] = []
#endif

let package = Package(
  name: "HubServer",
  platforms: [.macOS(.v13), .iOS(.v16), .tvOS(.v16), .visionOS(.v1), .macCatalyst(.v16)],
  products: [
    .library(name: "HubServer", targets: ["HubServer"]),
    .library(name: "ChannelServer", targets: ["ChannelServer"]),
    .executable(name: "hub-server-swift", targets: ["hub-server-swift"]),
  ],
  dependencies: dependencies,
  targets: [
    // Server side of the channel protocol: JSON, WebSocket over a byte-stream transport, the symmetric peer
    .target(name: "ChannelServer", swiftSettings: v5),
    // The Hub server (Docs/Devices/protocol.md)
    .target(name: "HubServer", dependencies: ["ChannelServer"] + crypto, swiftSettings: v5),
    .executableTarget(name: "hub-server-swift", dependencies: ["HubServer"], swiftSettings: v5),
    // The routes of Channel/channel/tests/server.ts that Tests/interop/channel-interop.ts calls with the TS client
    .executableTarget(name: "channel-fixture", dependencies: ["ChannelServer"], swiftSettings: v5),
    .testTarget(name: "ChannelServerTests", dependencies: ["ChannelServer"], swiftSettings: v5),
    .testTarget(name: "HubServerTests", dependencies: ["HubServer"] + crypto, resources: [.copy("Fixtures")], swiftSettings: v5),
  ]
)
