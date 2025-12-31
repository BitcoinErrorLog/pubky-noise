# Pubky Noise - Build Instructions

**Crate**: `pubky-noise`  
**Description**: Noise protocol implementation with Pubky integration  
**Type**: Library with FFI bindings (UniFFI)  
**Version**: 1.1.0

---

## Prerequisites

### Required

- **Rust 1.70.0+** via Rustup
- **Cargo** (comes with Rust)
- **UniFFI tools** (for mobile bindings)

### Optional (for mobile builds)

- **Android NDK** (for Android)
- **Xcode** (for iOS)
- **Kotlin/Gradle** (for Android integration)
- **Swift** (for iOS integration)
- **Java 17+** (for Gradle/Android builds)

### Environment Variables (Android)

```bash
# Required for Android builds
export ANDROID_NDK_HOME="$HOME/Library/Android/sdk/ndk/<version>"

# Required for Gradle - use Android Studio's bundled JDK
export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
```

### Installation

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# Verify
rustc --version  # Should be 1.70.0 or higher
cargo --version

# Install UniFFI tools (for FFI)
cargo install uniffi-bindgen
```

---

## Quick Build

```bash
# Standard Rust build
cd pubky-noise
cargo build

# Run tests
cargo test --lib

# Generate FFI bindings
uniffi-bindgen generate src/pubky_noise.udl --language kotlin
uniffi-bindgen generate src/pubky_noise.udl --language swift
```

---

## Dependencies

### System Dependencies

#### macOS

```bash
# Most dependencies pre-installed
# For iOS builds, install Xcode
xcode-select --install
```

#### Linux (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install -y \
    build-essential \
    pkg-config \
    libssl-dev
```

### Rust Dependencies

All Rust dependencies are managed by Cargo:

- `pubky` (0.6.0-rc.6) - Pubky SDK
- `pkarr` - Keypair management
- `ed25519-dalek` - Ed25519 signatures
- `x25519-dalek` - X25519 key exchange
- `chacha20poly1305` - AEAD encryption
- `blake2` - Hashing
- `uniffi` - FFI scaffolding
- `tokio` - Async runtime
- `serde` - Serialization

---

## Building

### Rust Library

```bash
# Development build
cargo build

# Release build
cargo build --release

# With specific features
cargo build --features ffi
```

**Outputs**:
- `target/debug/libpubky_noise.rlib` (Debug)
- `target/release/libpubky_noise.rlib` (Release)

### Mobile Libraries

#### Android

```bash
# Build for all Android architectures
./build-android.sh

# Or manually for specific target
rustup target add aarch64-linux-android
rustup target add armv7-linux-androideabi
rustup target add i686-linux-android
rustup target add x86_64-linux-android

cargo build --target aarch64-linux-android --release
```

**Outputs**: `target/<arch>-linux-android/release/libpubky_noise.so`

#### iOS

```bash
# Build for all iOS architectures
./build-ios.sh

# Or manually for specific target
rustup target add aarch64-apple-ios
rustup target add aarch64-apple-ios-sim
rustup target add x86_64-apple-ios

cargo build --target aarch64-apple-ios --release
```

**Outputs**: `target/<arch>-apple-ios/release/libpubky_noise.a`

---

## Generate FFI Bindings

### Kotlin (Android)

```bash
# Generate Kotlin bindings
uniffi-bindgen generate src/pubky_noise.udl --language kotlin --out-dir platforms/android

# Outputs:
# - platforms/android/uniffi/pubky_noise/pubky_noise.kt
```

### Swift (iOS)

```bash
# Generate Swift bindings
uniffi-bindgen generate src/pubky_noise.udl --language swift --out-dir platforms/ios

# Outputs:
# - platforms/ios/pubky_noise.swift
# - platforms/ios/pubky_noiseFFI.h
# - platforms/ios/pubky_noiseFFI.modulemap
```

---

## Testing

### Run All Tests

```bash
cargo test --lib
```

**Test Suites**:
- Unit tests in `src/tests.rs`
- Integration tests in `tests/`

### Run Specific Tests

```bash
# Run adapter demo
cargo test --test adapter_demo

# Run FFI tests
cargo test --test ffi_comprehensive
cargo test --test ffi_smoke

# Run session tests
cargo test --test session_id
cargo test --test storage_queue

# Run mobile integration
cargo test --test mobile_integration

# Run with output
cargo test -- --nocapture
```

---

## Project Structure

```
pubky-noise/
├── Cargo.toml              # Package metadata
├── BUILD.md                # This file
├── README.md               # Project overview
├── build.rs                # Build script (UniFFI)
├── uniffi.toml             # UniFFI configuration
├── src/
│   ├── lib.rs             # Library entry point
│   ├── pubky_noise.udl    # UniFFI interface definition
│   ├── client.rs          # Noise client
│   ├── server.rs          # Noise server
│   ├── session_manager.rs # Session management
│   ├── mobile_manager.rs  # Mobile-friendly API
│   ├── transport.rs       # Transport layer
│   ├── errors.rs          # Error types
│   ├── tests.rs           # Unit tests
│   └── ffi/               # FFI-specific modules
│       ├── mod.rs
│       ├── manager.rs
│       ├── config.rs
│       ├── types.rs
│       └── errors.rs
├── tests/                 # Integration tests
│   ├── adapter_demo.rs
│   ├── ffi_comprehensive.rs
│   ├── ffi_smoke.rs
│   ├── mobile_integration.rs
│   └── ...
├── platforms/
│   ├── android/           # Android integration
│   │   ├── build.gradle.kts
│   │   └── example/
│   │       └── MainActivity.kt
│   └── ios/               # iOS integration
│       ├── Package.swift
│       └── example/
│           └── BasicExample.swift
├── build-android.sh       # Android build script
└── build-ios.sh           # iOS build script
```

---

## Key Features

### Noise Protocol

Implementation of Noise_IK_25519_ChaChaPoly_BLAKE2s:

```rust
use pubky_noise::{NoiseClient, NoiseServer};

// Create client
let client = NoiseClient::new(local_keypair, remote_pubkey)?;
let handshake_msg = client.create_handshake_message()?;

// Create server
let server = NoiseServer::new(local_keypair)?;
server.process_handshake_message(&handshake_msg)?;
```

### Session Management

Persistent session storage:

```rust
use pubky_noise::SessionManager;

let manager = SessionManager::new(storage_path)?;
manager.save_session(&session_id, &session_data)?;
let session = manager.load_session(&session_id)?;
```

### Mobile API

Simplified API for mobile platforms:

```rust
use pubky_noise::MobileNoiseManager;

// Available via FFI (Kotlin/Swift)
let manager = MobileNoiseManager::new()?;
manager.initialize_client(local_key, remote_key)?;
let encrypted = manager.encrypt_message(b"Hello")?;
let decrypted = manager.decrypt_message(&encrypted)?;
```

---

## Mobile Integration

### Android

See [docs/ANDROID_INTEGRATION.md](./docs/ANDROID_INTEGRATION.md) for complete guide.

**Quick Start**:

1. Build native library:
   ```bash
   ./build-android.sh
   ```

2. Copy to Android project:
   ```bash
   cp target/aarch64-linux-android/release/libpubky_noise.so \
      android-app/app/src/main/jniLibs/arm64-v8a/
   ```

3. Use in Kotlin:
   ```kotlin
   import uniffi.pubky_noise.*
   
   val manager = MobileNoiseManager()
   manager.initializeClient(localKey, remoteKey)
   ```

### iOS

See [docs/IOS_INTEGRATION.md](./docs/IOS_INTEGRATION.md) for complete guide.

**Quick Start**:

1. Build native library:
   ```bash
   ./build-ios.sh
   ```

2. Add to Xcode project via SPM or manual linking

3. Use in Swift:
   ```swift
   import pubky_noise
   
   let manager = MobileNoiseManager()
   try manager.initializeClient(localKey: localKey, remoteKey: remoteKey)
   ```

---

## Development

### Code Quality

```bash
# Format code
cargo fmt

# Lint code
cargo clippy --all-targets

# Check without building
cargo check
```

### Documentation

```bash
# Generate Rust docs
cargo doc --no-deps --open

# Generate FFI docs
uniffi-bindgen generate src/pubky_noise.udl --language kotlin --out-dir docs/kotlin
uniffi-bindgen generate src/pubky_noise.udl --language swift --out-dir docs/swift
```

### Build Scripts

The project includes convenience scripts:

```bash
# Android build (all architectures)
./build-android.sh

# iOS build (all architectures + create xcframework)
./build-ios.sh
```

---

## Troubleshooting

### Error: "uniffi-bindgen: command not found"

**Problem**: UniFFI tools not installed

**Solution**:
```bash
cargo install uniffi-bindgen
```

### Error: "linker `aarch64-linux-android-clang` not found"

**Problem**: Android NDK not configured

**Solution**:
```bash
# Install Android NDK via Android Studio

# Or download standalone:
# https://developer.android.com/ndk/downloads

# Set environment variables
export ANDROID_NDK_HOME="/path/to/ndk"
export PATH="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin:$PATH"
```

### Error: "xcrun: error: unable to find utility \"clang\""

**Problem**: Xcode command-line tools not installed

**Solution**:
```bash
xcode-select --install
```

---

## Performance

### Build Time

- **Debug build**: ~80-120 seconds (first build)
- **Release build**: ~120-240 seconds (first build)
- **Incremental**: ~10-20 seconds (after changes)
- **Mobile builds**: ~5-10 minutes (all architectures)

### Binary Size

- **Rust library (debug)**: ~1-2MB
- **Rust library (release)**: ~500KB
- **Android .so**: ~300-500KB per architecture
- **iOS .a**: ~400-600KB per architecture

### Runtime Performance

- **Handshake**: ~5-10ms
- **Encryption**: ~0.1-0.5ms per message
- **Decryption**: ~0.1-0.5ms per message

---

## UniFFI Configuration

The `uniffi.toml` file configures FFI generation:

```toml
[bindings.kotlin]
package_name = "com.pubky.noise"

[bindings.swift]
module_name = "PubkyNoise"
```

---

## API Stability

**Version**: 1.1.0  
**Status**: Stable for production use

### Compatibility

- ✅ FFI API: Stable (breaking changes in major versions only)
- ✅ Rust API: Stable
- ✅ Mobile platforms: Tested on Android 8+ and iOS 13+

---

## Related Documentation

- **FFI Guide**: [docs/FFI_GUIDE.md](./docs/FFI_GUIDE.md)
- **Android Integration**: [docs/ANDROID_INTEGRATION.md](./docs/ANDROID_INTEGRATION.md)
- **iOS Integration**: [docs/IOS_INTEGRATION.md](./docs/IOS_INTEGRATION.md)
- **Mobile Integration**: [docs/MOBILE_INTEGRATION.md](./docs/MOBILE_INTEGRATION.md)
- **Bitkit Integration**: [docs/BITKIT_INTEGRATION_CHECKLIST.md](./docs/BITKIT_INTEGRATION_CHECKLIST.md)

---

## Quick Reference

```bash
# Build Rust library
cargo build --release

# Run tests
cargo test --lib

# Generate bindings
uniffi-bindgen generate src/pubky_noise.udl --language kotlin
uniffi-bindgen generate src/pubky_noise.udl --language swift

# Build for Android
./build-android.sh

# Build for iOS
./build-ios.sh

# Format & Lint
cargo fmt
cargo clippy --all-targets

# Documentation
cargo doc --no-deps --open
```

---

## Additional Resources

- [UniFFI Book](https://mozilla.github.io/uniffi-rs/)
- [Noise Protocol Framework](https://noiseprotocol.org/)
- [Android NDK Guide](https://developer.android.com/ndk/guides)
- [Swift Package Manager](https://swift.org/package-manager/)

---

**For Paykit workspace build instructions, see the Paykit repository BUILD.md**

