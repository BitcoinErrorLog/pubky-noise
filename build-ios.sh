#!/bin/bash
set -e

echo "🔧 pubky-noise iOS Build Script v0.8.0"
echo "======================================="

# Check prerequisites
echo "Checking prerequisites..."

if ! command -v cargo &> /dev/null; then
    echo "❌ Error: cargo not found. Please install Rust from https://rustup.rs/"
    exit 1
fi
echo "✅ Rust/Cargo found: $(rustc --version)"

if ! command -v xcodebuild &> /dev/null; then
    echo "❌ Error: xcodebuild not found. Please install Xcode from the App Store."
    exit 1
fi
echo "✅ Xcode found"

# Check Xcode version
XCODE_VERSION=$(xcodebuild -version | head -n1 | awk '{print $2}')
echo "   Xcode version: $XCODE_VERSION"

# Setup
ROOT_DIR=$(pwd)
TARGET_DIR="$ROOT_DIR/target"
IOS_DIR="$ROOT_DIR/platforms/ios"
mkdir -p "$IOS_DIR"
mkdir -p "$IOS_DIR/Sources/PubkyNoise"

# Ensure targets are installed (including arm64 simulator for M1/M2 Macs)
echo ""
echo "Installing Rust targets for iOS..."
TARGETS="aarch64-apple-ios x86_64-apple-ios aarch64-apple-ios-sim"
for target in $TARGETS; do
    if rustup target list --installed | grep -q "$target"; then
        echo "✅ $target already installed"
    else
        echo "📦 Installing $target..."
        rustup target add "$target"
    fi
done

# Build libraries
echo ""
echo "Building for iOS targets..."
echo "⏳ This may take several minutes..."

# Build with all necessary features
FEATURES="uniffi_macros"
cargo build --release --features "$FEATURES" --target aarch64-apple-ios
cargo build --release --features "$FEATURES" --target x86_64-apple-ios
cargo build --release --features "$FEATURES" --target aarch64-apple-ios-sim

# Generate bindings
echo ""
echo "Generating Swift bindings..."
cargo run --features="$FEATURES" --bin uniffi-bindgen generate \
    --library "$TARGET_DIR/aarch64-apple-ios/release/libpubky_noise.a" \
    --language swift \
    --out-dir "$IOS_DIR/Sources/PubkyNoise" || {
    echo "⚠️  uniffi-bindgen not found as binary, using as library..."
    # If uniffi-bindgen binary isn't available, the scaffolding should be generated during build
}

# Create XCFramework
echo ""
echo "Creating XCFramework..."
rm -rf "$IOS_DIR/PubkyNoise.xcframework"

# Create a simulator universal library (x86_64 + arm64 simulator for M1/M2 support)
echo "Creating universal simulator library..."
mkdir -p "$TARGET_DIR/ios-sim-universal"
lipo -create \
    "$TARGET_DIR/x86_64-apple-ios/release/libpubky_noise.a" \
    "$TARGET_DIR/aarch64-apple-ios-sim/release/libpubky_noise.a" \
    -output "$TARGET_DIR/ios-sim-universal/libpubky_noise.a"

echo "Building XCFramework with all architectures..."
xcodebuild -create-xcframework \
    -library "$TARGET_DIR/aarch64-apple-ios/release/libpubky_noise.a" \
    -library "$TARGET_DIR/ios-sim-universal/libpubky_noise.a" \
    -output "$IOS_DIR/PubkyNoise.xcframework"

# Generate Swift Package manifest
echo "Generating Swift Package manifest..."
cat > "$IOS_DIR/Package.swift" << 'EOF'
// swift-tools-version:5.7
import PackageDescription

let package = Package(
    name: "PubkyNoise",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15)
    ],
    products: [
        .library(
            name: "PubkyNoise",
            targets: ["PubkyNoise", "PubkyNoiseFFI"]
        ),
    ],
    targets: [
        .target(
            name: "PubkyNoise",
            dependencies: ["PubkyNoiseFFI"],
            path: "Sources/PubkyNoise"
        ),
        .binaryTarget(
            name: "PubkyNoiseFFI",
            path: "PubkyNoise.xcframework"
        )
    ]
)
EOF

echo ""
echo "✅ iOS build complete!"
echo ""
echo "📦 XCFramework: platforms/ios/PubkyNoise.xcframework"
echo "📄 Swift bindings: platforms/ios/Sources/PubkyNoise/"
echo "📦 Package.swift: platforms/ios/Package.swift"
echo ""
echo "Supported architectures:"
echo "  - iOS Device: arm64"
echo "  - iOS Simulator: arm64 (M1/M2), x86_64 (Intel)"
echo ""
echo "Integration options:"
echo "  1. Swift Package Manager:"
echo "     Add platforms/ios as a local package dependency"
echo ""
echo "  2. Direct XCFramework:"
echo "     Drag PubkyNoise.xcframework into your Xcode project"
echo ""
echo "  3. CocoaPods (coming soon):"
echo "     pod 'PubkyNoise', :path => 'platforms/ios'"

