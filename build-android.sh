#!/bin/bash
set -e

echo "🔧 pubky-noise Android Build Script v0.8.0"
echo "==========================================="

# Check prerequisites
echo "Checking prerequisites..."

if ! command -v cargo &> /dev/null; then
    echo "❌ Error: cargo not found. Please install Rust from https://rustup.rs/"
    exit 1
fi
echo "✅ Rust/Cargo found: $(rustc --version)"

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
mkdir -p "$ANDROID_DIR/src/main/java/com/pubky/noise"

# Ensure targets are installed (including x86_64 for emulators)
echo ""
echo "Installing Rust targets for Android..."
TARGETS="aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android"
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
echo "Building for Android targets..."
echo "⏳ This may take several minutes..."

FEATURES="uniffi_macros"
cargo build --release --features "$FEATURES" --target aarch64-linux-android
cargo build --release --features "$FEATURES" --target armv7-linux-androideabi
cargo build --release --features "$FEATURES" --target x86_64-linux-android
cargo build --release --features "$FEATURES" --target i686-linux-android

# Generate bindings
echo ""
echo "Generating Kotlin bindings..."
cargo run --features="$FEATURES" --bin uniffi-bindgen generate \
    --library "$TARGET_DIR/aarch64-linux-android/release/libpubky_noise.so" \
    --language kotlin \
    --out-dir "$ANDROID_DIR/src/main/java" || {
    echo "⚠️  uniffi-bindgen not found as binary, using as library..."
}

# Copy libraries to jniLibs
echo ""
echo "Copying shared libraries to jniLibs..."
mkdir -p "$ANDROID_DIR/src/main/jniLibs/arm64-v8a"
mkdir -p "$ANDROID_DIR/src/main/jniLibs/armeabi-v7a"
mkdir -p "$ANDROID_DIR/src/main/jniLibs/x86_64"
mkdir -p "$ANDROID_DIR/src/main/jniLibs/x86"

cp "$TARGET_DIR/aarch64-linux-android/release/libpubky_noise.so" "$ANDROID_DIR/src/main/jniLibs/arm64-v8a/"
cp "$TARGET_DIR/armv7-linux-androideabi/release/libpubky_noise.so" "$ANDROID_DIR/src/main/jniLibs/armeabi-v7a/"
cp "$TARGET_DIR/x86_64-linux-android/release/libpubky_noise.so" "$ANDROID_DIR/src/main/jniLibs/x86_64/"
cp "$TARGET_DIR/i686-linux-android/release/libpubky_noise.so" "$ANDROID_DIR/src/main/jniLibs/x86/"

# Generate build.gradle
echo "Generating Gradle configuration..."
cat > "$ANDROID_DIR/build.gradle" << 'EOF'
plugins {
    id 'com.android.library'
    id 'org.jetbrains.kotlin.android'
}

android {
    namespace 'com.pubky.noise'
    compileSdk 34

    defaultConfig {
        minSdk 21
        targetSdk 34

        ndk {
            abiFilters 'arm64-v8a', 'armeabi-v7a', 'x86_64', 'x86'
        }
    }

    buildTypes {
        release {
            minifyEnabled false
        }
    }

    sourceSets {
        main {
            jniLibs.srcDirs = ['src/main/jniLibs']
        }
    }

    compileOptions {
        sourceCompatibility JavaVersion.VERSION_1_8
        targetCompatibility JavaVersion.VERSION_1_8
    }

    kotlinOptions {
        jvmTarget = '1.8'
    }
}

dependencies {
    implementation 'net.java.dev.jna:jna:5.13.0@aar'
}
EOF

# Generate settings.gradle for standalone builds
cat > "$ANDROID_DIR/settings.gradle" << 'EOF'
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}
rootProject.name = "pubky-noise"
EOF

echo ""
echo "✅ Android build complete!"
echo ""
echo "📦 Native libraries:"
echo "  - arm64-v8a (ARM64 devices)"
echo "  - armeabi-v7a (ARM32 devices)"
echo "  - x86_64 (x86_64 emulators)"
echo "  - x86 (x86 emulators)"
echo ""
echo "📄 Kotlin bindings: platforms/android/src/main/java/"
echo "📦 Gradle files: platforms/android/build.gradle"
echo ""
echo "Integration options:"
echo ""
echo "  1. Gradle module (recommended):"
echo "     Add to settings.gradle: include ':pubky-noise'"
echo "     Add to settings.gradle: project(':pubky-noise').projectDir = file('path/to/platforms/android')"
echo "     Add to app build.gradle: implementation project(':pubky-noise')"
echo ""
echo "  2. Build AAR:"
echo "     cd platforms/android && ./gradlew assembleRelease"
echo "     Then add the AAR to your project"
echo ""
echo "  3. Maven Local:"
echo "     cd platforms/android && ./gradlew publishToMavenLocal"

