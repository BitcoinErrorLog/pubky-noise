#!/bin/bash
set -e

echo "🔧 pubky-noise iOS Build Script"
echo "================================"

# Check prerequisites
echo "Checking prerequisites..."

if ! command -v cargo &> /dev/null; then
    echo "❌ Error: cargo not found. Please install Rust from https://rustup.rs/"
    exit 1
fi
echo "✅ Rust/Cargo found"

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

# Ensure targets are installed
echo ""
echo "Installing Rust targets for iOS..."
for target in aarch64-apple-ios x86_64-apple-ios aarch64-apple-ios-sim; do
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
cargo build --release --features uniffi_macros --target aarch64-apple-ios
cargo build --release --features uniffi_macros --target x86_64-apple-ios
cargo build --release --features uniffi_macros --target aarch64-apple-ios-sim

# Generate bindings
echo ""
echo "Generating Swift bindings..."
cargo run --features "bindgen-cli,uniffi_macros" --bin uniffi-bindgen generate \
    --library "$TARGET_DIR/aarch64-apple-ios/release/libpubky_noise.a" \
    --language swift \
    --out-dir "$IOS_DIR/Sources"

if [ $? -ne 0 ]; then
    echo "❌ Error: Failed to generate Swift bindings"
    echo "   Make sure the 'bindgen-cli' feature is available in Cargo.toml"
    exit 1
fi
echo "✅ Swift bindings generated"

# Create XCFramework
echo ""
echo "Creating XCFramework..."
rm -rf "$IOS_DIR/PubkyNoise.xcframework"

# Create a simulator universal library (x86_64 + arm64 simulator)
# Note: Modern Xcode needs arm64 simulator support
echo "Creating universal simulator library..."
mkdir -p "$TARGET_DIR/sim-universal"
lipo -create \
    "$TARGET_DIR/x86_64-apple-ios/release/libpubky_noise.a" \
    "$TARGET_DIR/aarch64-apple-ios-sim/release/libpubky_noise.a" \
    -output "$TARGET_DIR/sim-universal/libpubky_noise.a"

echo "Building XCFramework..."
xcodebuild -create-xcframework \
    -library "$TARGET_DIR/aarch64-apple-ios/release/libpubky_noise.a" \
    -headers "$IOS_DIR/Sources" \
    -library "$TARGET_DIR/sim-universal/libpubky_noise.a" \
    -headers "$IOS_DIR/Sources" \
    -output "$IOS_DIR/PubkyNoise.xcframework"

# Organize files for SPM
mkdir -p "$IOS_DIR/Sources/PubkyNoise"
if [ -f "$IOS_DIR/Sources/pubky_noise.swift" ]; then
    mv "$IOS_DIR/Sources/pubky_noise.swift" "$IOS_DIR/Sources/PubkyNoise/PubkyNoise.swift"
fi

echo ""
echo "✅ iOS build complete!"
echo "📦 XCFramework: platforms/ios/PubkyNoise.xcframework"
echo "📄 Swift bindings: platforms/ios/Sources/PubkyNoise/PubkyNoise.swift"
echo ""
echo "Next steps:"
echo "  1. Add the XCFramework to your Xcode project"
echo "  2. Or use Swift Package Manager with platforms/ios/Package.swift"

