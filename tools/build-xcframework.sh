#!/usr/bin/env bash
# Builds the Apple slices in release mode, merges the simulator and macOS
# architectures, wraps each platform as a static framework with the C header
# as its umbrella and a module map, and folds them into
# zig-out/GossveilKit.xcframework with a zip and a checksum for SwiftPM.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$PWD/.local/zig/current:$PATH"

zig build apple -Doptimize=ReleaseFast

out=zig-out
lib=libgossveil_ffi_static.a
stage="$out/apple-stage"
rm -rf "$stage" "$out/GossveilKit.xcframework" "$out/GossveilKit.xcframework.zip"
mkdir -p "$stage"

lipo -create "$out/ios-simulator/$lib" "$out/ios-simulator-x86_64/$lib" -output "$stage/sim.a"
lipo -create "$out/macos/$lib" "$out/macos-x86_64/$lib" -output "$stage/mac.a"

wrap() {
  local name="$1" archive="$2" dir="$stage/$1/GossveilKit.framework"
  mkdir -p "$dir/Headers" "$dir/Modules"
  cp "$archive" "$dir/GossveilKit"
  cp include/gossveil.h "$dir/Headers/gossveil.h"
  cat > "$dir/Modules/module.modulemap" <<'MAP'
framework module GossveilKit {
    umbrella header "gossveil.h"
    export *
}
MAP
  cat > "$dir/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.gossveil.kit</string>
<key>CFBundleName</key><string>GossveilKit</string>
<key>CFBundlePackageType</key><string>FMWK</string>
<key>CFBundleVersion</key><string>1</string>
<key>CFBundleShortVersionString</key><string>1.0</string>
</dict></plist>
PLIST
}
wrap ios "$out/ios/$lib"
wrap ios-simulator "$stage/sim.a"
wrap macos "$stage/mac.a"

xcodebuild -create-xcframework \
  -framework "$stage/ios/GossveilKit.framework" \
  -framework "$stage/ios-simulator/GossveilKit.framework" \
  -framework "$stage/macos/GossveilKit.framework" \
  -output "$out/GossveilKit.xcframework" >/dev/null

( cd "$out" && zip -qr GossveilKit.xcframework.zip GossveilKit.xcframework )
checksum=$(swift package compute-checksum "$out/GossveilKit.xcframework.zip")
echo "$checksum" > "$out/GossveilKit.checksum.txt"
rm -rf "$stage"
echo "build-xcframework: $out/GossveilKit.xcframework $(du -sh "$out/GossveilKit.xcframework" | cut -f1), checksum $checksum"
