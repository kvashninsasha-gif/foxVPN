// swift-tools-version: 5.9
import PackageDescription
let package = Package(name: "FoxVPNCore", platforms: [.macOS(.v13), .iOS(.v16)], products: [.library(name: "FoxVPNCore", targets: ["FoxVPNCore"])], targets: [.target(name: "FoxVPNCore", path: "Shared"), .testTarget(name: "FoxVPNCoreTests", dependencies: ["FoxVPNCore"], path: "Tests")])
