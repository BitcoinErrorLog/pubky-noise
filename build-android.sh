#!/bin/bash
set -e

echo "🔧 pubky-noise Android Build Script"
echo "==================================="

# Check prerequisites
echo "Checking prerequisites..."

if ! command -v cargo &> /dev/null; then
    echo "❌ Error: cargo not found. Please install Rust from https://rustup.rs/"
    exit 1
fi
echo "✅ Rust/Cargo found"

if [ -z "$ANDROID_NDK_HOME" ] && [ -z "$NDK_HOME" ]; then
    echo "⚠️  Warning: ANDROID_NDK_HOME not set. Android NDK is required for cross-compilation."
    echo "   Please install Android NDK and set ANDROID_NDK_HOME or NDK_HOME."
    echo "   Continuing anyway - cargo may fail if NDK is not configured..."
else
    echo "✅ Android NDK found"
    NDK_PATH="${ANDROID_NDK_HOME:-$NDK_HOME}"
    echo "   NDK path: $NDK_PATH"
fi

# Setup
ROOT_DIR=$(pwd)
TARGET_DIR="$ROOT_DIR/target"
ANDROID_DIR="$ROOT_DIR/platforms/android"
mkdir -p "$ANDROID_DIR/src/main/jniLibs"

# Ensure targets are installed
echo ""
echo "Installing Rust targets for Android..."
for target in aarch64-linux-android armv7-linux-androideabi x86_64-linux-android; do
    if rustup target list --installed | grep -q "$target"; then
        echo "✅ $target already installed"
    else
        echo "📦 Installing $target..."
        rustup target add "$target"
    fi
done

# Build libraries
echo ""
echo "Building for Android targets..."
echo "⏳ This may take several minutes..."
cargo build --release --features uniffi_macros --target aarch64-linux-android
cargo build --release --features uniffi_macros --target armv7-linux-androideabi
cargo build --release --features uniffi_macros --target x86_64-linux-android

# Generate bindings
echo ""
echo "Generating Kotlin bindings..."
cargo run --features "bindgen-cli,uniffi_macros" --bin uniffi-bindgen generate \
    --library "$TARGET_DIR/aarch64-linux-android/release/libpubky_noise.so" \
    --language kotlin \
    --out-dir "$ANDROID_DIR/src/main/java"

if [ $? -ne 0 ]; then
    echo "❌ Error: Failed to generate Kotlin bindings"
    echo "   Make sure the 'bindgen-cli' feature is available in Cargo.toml"
    exit 1
fi
echo "✅ Kotlin bindings generated"

# Copy libraries to jniLibs
echo ""
echo "Copying shared libraries to jniLibs..."
mkdir -p "$ANDROID_DIR/src/main/jniLibs/arm64-v8a"
mkdir -p "$ANDROID_DIR/src/main/jniLibs/armeabi-v7a"
mkdir -p "$ANDROID_DIR/src/main/jniLibs/x86_64"

cp "$TARGET_DIR/aarch64-linux-android/release/libpubky_noise.so" "$ANDROID_DIR/src/main/jniLibs/arm64-v8a/libpubky_noise.so"
cp "$TARGET_DIR/armv7-linux-androideabi/release/libpubky_noise.so" "$ANDROID_DIR/src/main/jniLibs/armeabi-v7a/libpubky_noise.so"
cp "$TARGET_DIR/x86_64-linux-android/release/libpubky_noise.so" "$ANDROID_DIR/src/main/jniLibs/x86_64/libpubky_noise.so"

echo ""
echo "✅ Android build complete!"
echo "📦 Native libraries: platforms/android/src/main/jniLibs/"
echo "📄 Kotlin bindings: platforms/android/src/main/java/uniffi/pubky_noise/"
echo ""
echo "Note: Kotlin bindings use package 'uniffi.pubky_noise' by default."
echo "      For Bitkit (com.pubky.noise), manually change the package declaration."
echo ""
echo "Next steps:"
echo "  1. Import the platforms/android directory as a Gradle module"
echo "  2. Or build the AAR with: cd platforms/android && ./gradlew assembleRelease"

