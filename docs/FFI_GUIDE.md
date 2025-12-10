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

