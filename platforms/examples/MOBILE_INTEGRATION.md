# Mobile Integration Guide

This guide covers integrating pubky-noise v0.8.0 into iOS and Android applications.

## Overview

pubky-noise provides FFI bindings via UniFFI for:
- **iOS**: Swift via XCFramework
- **Android**: Kotlin via JNI libraries

## Cold Key Architecture

For Bitkit and similar wallets, we recommend the "cold key" architecture:

1. **Ed25519 Identity** - Your root identity key (kept cold/offline)
2. **X25519 Session Key** - Derived from Ed25519 (used for Noise)
3. **pkarr Publication** - X25519 public key published with Ed25519 signature

### Setup Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    ONE-TIME SETUP                           │
│                                                             │
│  Ed25519 Secret ─────┬─────► X25519 Keypair                │
│  (from seed phrase)  │       (via KDF)                     │
│                      │                                      │
│                      └─────► Sign X25519 binding           │
│                              (Ed25519 signature)           │
│                                                             │
│  Result: X25519 secret stored in Keychain/Keystore         │
│          X25519 pubkey + signature published to pkarr      │
│          Ed25519 key can be stored cold                    │
└─────────────────────────────────────────────────────────────┘
```

### Runtime Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    CONNECTION FLOW                          │
│                                                             │
│  1. Lookup recipient's X25519 key via pkarr                │
│  2. Load your X25519 secret from secure storage            │
│  3. Initiate IK-raw pattern handshake                      │
│  4. Complete handshake                                      │
│  5. Encrypt/decrypt messages                               │
└─────────────────────────────────────────────────────────────┘
```

## iOS Integration

### Prerequisites

- Xcode 14+
- iOS 13+ deployment target
- Rust toolchain with iOS targets

### Build

```bash
cd pubky-noise
./build-ios.sh
```

This creates:
- `platforms/ios/PubkyNoise.xcframework` - Universal framework
- `platforms/ios/Sources/PubkyNoise/` - Swift bindings
- `platforms/ios/Package.swift` - Swift Package manifest

### Integration Options

#### Swift Package Manager (Recommended)

1. Add `platforms/ios` as a local package:
   - File → Add Package Dependencies → Add Local...
   - Select the `platforms/ios` directory

2. Import and use:
   ```swift
   import PubkyNoise
   ```

#### XCFramework

1. Drag `PubkyNoise.xcframework` into your project
2. Add to "Frameworks, Libraries, and Embedded Content"
3. Copy the Swift bindings to your project

### Usage

See `platforms/examples/ios/PubkyNoiseExample.swift` for complete examples.

```swift
import PubkyNoise

// Initialize
let config = FfiMobileConfig(
    autoReconnect: true,
    maxReconnectAttempts: 3,
    reconnectDelayMs: 1000,
    batterySaver: true,
    chunkSize: 65535
)
let manager = FfiRawNoiseManager(config: config)

// Derive keys
let secretKey = try ffiDeriveX25519Static(seed: seed, context: deviceId.data)
let publicKey = try ffiX25519PublicKey(secretKey: secretKey)

// Connect with IK-raw pattern
let result = try manager.initiateIkRaw(localSk: secretKey, serverPk: recipientPk)

// Encrypt
let ciphertext = try manager.encrypt(sessionId: result.sessionId, plaintext: message)
```

## Android Integration

### Prerequisites

- Android Studio
- Android NDK
- Rust toolchain with Android targets
- `ANDROID_NDK_HOME` environment variable set

### Build

```bash
export ANDROID_NDK_HOME=/path/to/ndk
cd pubky-noise
./build-android.sh
```

This creates:
- `platforms/android/src/main/jniLibs/` - Native libraries
- `platforms/android/src/main/java/` - Kotlin bindings
- `platforms/android/build.gradle` - Gradle configuration

### Integration Options

#### Gradle Module (Recommended)

1. Add to `settings.gradle`:
   ```groovy
   include ':pubky-noise'
   project(':pubky-noise').projectDir = file('path/to/platforms/android')
   ```

2. Add to app `build.gradle`:
   ```groovy
   dependencies {
       implementation project(':pubky-noise')
   }
   ```

#### AAR

1. Build AAR:
   ```bash
   cd platforms/android
   ./gradlew assembleRelease
   ```

2. Add the AAR to your project

### Usage

See `platforms/examples/android/PubkyNoiseExample.kt` for complete examples.

```kotlin
import com.pubky.noise.*

// Initialize
val config = FfiMobileConfig(
    autoReconnect = true,
    maxReconnectAttempts = 3u,
    reconnectDelayMs = 1000u,
    batterySaver = true,
    chunkSize = 65535u
)
val manager = FfiRawNoiseManager(config)

// Derive keys
val secretKey = ffiDeriveX25519Static(seed.toList(), deviceId.toByteArray().toList())
val publicKey = ffiX25519PublicKey(secretKey)

// Connect with IK-raw pattern
val result = manager.initiateIkRaw(secretKey, recipientPk.toList())

// Encrypt
val ciphertext = manager.encrypt(result.sessionId, message.toList())
```

## Pattern Selection

| Pattern | Use Case | Identity |
|---------|----------|----------|
| IK-raw | Cold key, pkarr auth | Mutual (via pkarr) |
| N | Anonymous sender | Sender anonymous |
| NN | Ephemeral | Both anonymous |
| XX | Dynamic discovery | Mutual (in-band) |

### Recommendations

- **Payments (Bitkit)**: IK-raw with pkarr
- **Anonymous tips**: N pattern
- **Ephemeral chat**: NN pattern
- **First contact**: XX pattern

## Security Considerations

### Key Storage

- **iOS**: Use Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
- **Android**: Use Android Keystore with hardware backing

### Memory Safety

All secret keys are wrapped in `Zeroizing` on the Rust side. On mobile:
- Clear byte arrays after use
- Avoid logging key material
- Use secure memory if available

### Network

- Always use TLS for the underlying transport
- Verify pkarr records before connecting
- Implement connection timeouts

## Troubleshooting

### iOS

**Build fails with missing target**
```bash
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
```

**Simulator not working on M1/M2**
Ensure you have `aarch64-apple-ios-sim` target installed.

### Android

**NDK not found**
```bash
export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/25.2.9519653
```

**JNI loading fails**
Ensure your minSdk is at least 21.

## Version History

- **v0.8.0**: Added cold key patterns (IK-raw, N, NN), pkarr helpers, Snow 0.10
- **v0.7.0**: Initial FFI release with IK pattern

