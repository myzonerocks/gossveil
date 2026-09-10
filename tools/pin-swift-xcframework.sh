#!/usr/bin/env bash
# Rewrites the root Package.swift to a binaryTarget pinned to a release's
# XCFramework, so a SwiftPM consumer imports Gossveil with no Zig:
# pin-swift-xcframework.sh <tag> <checksum>. A checkout that built its own
# framework into zig-out resolves that one instead.
set -euo pipefail

tag="${1:?usage: pin-swift-xcframework.sh <tag> <checksum>}"
checksum="${2:?usage: pin-swift-xcframework.sh <tag> <checksum>}"
repo="${GITHUB_REPOSITORY:-myzonerocks/gossveil}"
server="${GITHUB_SERVER_URL:-https://github.com}"
url="${server}/${repo}/releases/download/${tag}/GossveilKit.xcframework.zip"

cat > Package.swift <<EOF
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
        url: "${url}",
        checksum: "${checksum}"
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
EOF
echo "pin-swift-xcframework: Package.swift pinned to ${tag}"
