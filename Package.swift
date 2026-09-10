// swift-tools-version:5.9
import Foundation
import PackageDescription

// The manifest a consumer resolves. The core arrives as the XCFramework attached
// to each release, so there is no Zig and no build step; a checkout that built
// its own (tools/build-xcframework.sh, into zig-out) resolves that one instead.
let localKit = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
    .appendingPathComponent("zig-out/GossveilKit.xcframework").path
let kit: Target = FileManager.default.fileExists(atPath: localKit)
    ? .binaryTarget(name: "GossveilKit", path: "zig-out/GossveilKit.xcframework")
    : .binaryTarget(
        name: "GossveilKit",
        url: "https://github.com/myzonerocks/gossveil/releases/download/v0.1.0-alpha.2/GossveilKit.xcframework.zip",
        checksum: "11e839ab1f9110bff5835056a1a2f296968891d7a55ebeae7d95fca60efb7c60"
    )
let package = Package(
    name: "Gossveil",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [
        .library(name: "Gossveil", targets: ["Gossveil"]),
        .library(name: "GossveilKit", targets: ["GossveilKit"]),
    ],
    targets: [
        kit,
        .target(name: "Gossveil", dependencies: ["GossveilKit"], path: "sdk/swift/Sources/Gossveil"),
        .testTarget(name: "GossveilTests", dependencies: ["Gossveil"], path: "sdk/swift/Tests/GossveilTests"),
    ]
)
