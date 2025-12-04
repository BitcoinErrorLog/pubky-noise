# FFI Development Guide for pubky-noise

This guide explains how to work with the Foreign Function Interface (FFI) layer of `pubky-noise`. It uses Mozilla's [UniFFI](https://github.com/mozilla/uniffi-rs) to automatically generate safe bindings for Swift (iOS) and Kotlin (Android).

## Architecture

The FFI layer consists of:

1. **UDL Definition** (`src/pubky_noise.udl`): Defines the cross-language interface in a schema language.
2. **Rust Implementation** (`src/ffi/`): Implements the interface defined in UDL.
3. **Build Scripts** (`build.rs`, `build-ios.sh`, `build-android.sh`): Orchestrate compilation and binding generation.

## Adding New Features

When adding a new feature to the core library that needs to be exposed to mobile apps:

1. **Define the Interface**: Add types and functions to `src/pubky_noise.udl`.
2. **Implement the Logic**: Add Rust implementation in `src/ffi/`.
3. **Map Types**: Ensure types are convertible between Rust and FFI (implement `From`/`Into`).

### Example: Adding a new function

1. Edit `src/pubky_noise.udl`:
   ```idl
   interface FfiNoiseManager {
       // ...
       string my_new_function(u32 count);
   };
   ```

2. Edit `src/ffi/manager.rs`:
   ```rust
   impl FfiNoiseManager {
       pub fn my_new_function(&self, count: u32) -> String {
           format!("Count is {}", count)
       }
   }
   ```

## Building Bindings

### Prerequisites

- Rust toolchain (`rustup`, `cargo`)
- Xcode (for iOS)
- Android Studio / NDK (for Android)

### iOS Build

```bash
./build-ios.sh
```

This generates `platforms/ios/PubkyNoise.xcframework` and Swift bindings.

### Android Build

```bash
./build-android.sh
```

This generates `.so` libraries and Kotlin bindings in `platforms/android`.

## Testing FFI

Run the Rust smoke test to verify the FFI layer logic:

```bash
cargo test --test ffi_smoke
```

## Type Mapping

| UDL Type | Rust Type | Swift Type | Kotlin Type |
|----------|-----------|------------|-------------|
| `u32`    | `u32`     | `UInt32`   | `Int`       |
| `u64`    | `u64`     | `UInt64`   | `Long`      |
| `string` | `String`  | `String`   | `String`    |
| `bytes`  | `Vec<u8>` | `Data`     | `ByteArray` |
| `boolean`| `bool`    | `Bool`     | `Boolean`   |

## Error Handling

Errors defined in `FfiNoiseError` are automatically mapped to `NSError` in Swift and `Exception` in Kotlin.

```rust
// Rust
return Err(FfiNoiseError::Network { message: "Failed".into() });
```

```swift
// Swift
do {
    try manager.connectClient(...)
} catch let error as FfiNoiseError {
    print(error)
}
```

```kotlin
// Kotlin
try {
    manager.connectClient(...)
} catch (e: FfiNoiseError) {
    println(e.message)
}
```

## Pattern-Aware APIs

pubky-noise v0.8.0 supports multiple Noise patterns for different authentication scenarios:

| Pattern | Use Case | FFI Functions |
|---------|----------|---------------|
| IK | Hot keys, full auth | `connect_client` (default) |
| IK-raw | Cold keys + pkarr | `ffi_start_ik_raw`, `ffi_accept_ik_raw` |
| N | Anonymous client | `ffi_start_n`, `ffi_accept_n` |
| NN | Ephemeral (attestation) | `ffi_start_nn`, `ffi_accept_nn` |
| XX | Trust-on-first-use | `ffi_start_xx`, `ffi_accept_xx` |

### Cold Key Pattern (IK-raw)

For scenarios where Ed25519 keys are kept offline:

```rust
// Rust FFI - derive X25519 key from seed
let x25519_sk = ffi_derive_x25519_static(seed.to_vec(), b"device-id".to_vec())?;
let x25519_pk = ffi_x25519_public_key(x25519_sk.clone())?;

// Start IK-raw handshake (no Ed25519 signing required)
let (hs_state, first_msg) = ffi_start_ik_raw(x25519_sk, server_pk.to_vec())?;
```

```swift
// Swift
let x25519Sk = try ffiDeriveX25519Static(seed: seedData, context: "device-id".data(using: .utf8)!)
let firstMsg = try ffiStartIkRaw(localSk: x25519Sk, serverPk: serverPublicKey)
```

### Anonymous Pattern (N)

For donation boxes or anonymous requests:

```rust
// Rust FFI - anonymous client connecting to known server
let (hs_state, first_msg) = ffi_start_n(server_pk.to_vec())?;
// Note: N pattern is ONE-WAY (client → server only)
```

### Ephemeral Pattern (NN)

For connections requiring post-handshake attestation:

```rust
// Rust FFI
let (hs_state, first_msg) = ffi_start_nn()?;
// After handshake, perform attestation to verify identities
```

### Key Derivation for Cold Keys

```rust
// Derive X25519 key from Ed25519 seed (one-time cold operation)
let x25519_sk = ffi_derive_x25519_static(ed25519_seed.to_vec(), device_id.to_vec())?;

// Get public key for publishing to pkarr
let x25519_pk = ffi_x25519_public_key(x25519_sk.clone())?;

// Sign binding for pkarr publication
let signature = ffi_sign_pkarr_key_binding(ed25519_sk.to_vec(), x25519_pk.clone(), device_id.to_vec())?;
```

### Pattern Negotiation

When connecting to a pattern-aware server, send a pattern byte before the handshake:

```
Pattern Bytes:
  0x00 = IK
  0x01 = IK-raw
  0x02 = N
  0x03 = NN
  0x04 = XX
```

