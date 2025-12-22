# Migration Guide: pubky-noise 1.0.x → 1.1.0

This document describes breaking changes in version 1.1.0 and how to update consuming code.

## Breaking Changes Summary

1. **`derive_device_key` FFI function** now returns `Result<Vec<u8>, FfiNoiseError>`
2. **`FfiNoiseError::RateLimited`** changed from tuple to struct variant
3. **`StorageBackedMessaging::new()`** now returns `Result<Self, NoiseError>`

## Swift Updates (bitkit-ios, pubky-ring)

### deriveDeviceKey

**Before:**
```swift
let secretKey = deriveDeviceKey(seed: seed, deviceId: deviceId, epoch: epoch)
```

**After:**
```swift
do {
    let secretKey = try deriveDeviceKey(seed: seed, deviceId: deviceId, epoch: epoch)
    // ... use secretKey
} catch let error as FfiNoiseError {
    // Handle error
    print("Key derivation failed: \(error)")
}
```

### FfiNoiseError.RateLimited

**Before:**
```swift
case .RateLimited(let message):
    print("Rate limited: \(message)")
```

**After:**
```swift
case .RateLimited(let message, let retryAfterMs):
    print("Rate limited: \(message)")
    if let delay = retryAfterMs {
        print("Retry after: \(delay)ms")
    }
```

## Kotlin Updates (bitkit-android, pubky-ring)

### deriveDeviceKey

**Before:**
```kotlin
val secretKey = deriveDeviceKey(seed, deviceId, epoch.toUInt())
```

**After:**
```kotlin
try {
    val secretKey = deriveDeviceKey(seed, deviceId, epoch.toUInt())
    // ... use secretKey
} catch (e: FfiNoiseException) {
    // Handle error
    Log.e("PubkyNoise", "Key derivation failed: ${e.message}")
}
```

### FfiNoiseException.RateLimited

**Before:**
```kotlin
is FfiNoiseException.RateLimited -> {
    val message = e.msg
}
```

**After:**
```kotlin
is FfiNoiseException.RateLimited -> {
    val message = e.message
    val retryAfterMs = e.retryAfterMs  // Option<UInt64>
}
```

## Rust Updates (internal callers)

### derive_x25519_for_device_epoch

**Before:**
```rust
let key = derive_x25519_for_device_epoch(&seed, device_id, epoch);
```

**After:**
```rust
let key = derive_x25519_for_device_epoch(&seed, device_id, epoch)?;
// or
let key = derive_x25519_for_device_epoch(&seed, device_id, epoch)
    .expect("HKDF should not fail with valid inputs");
```

### NoiseError::RateLimited

**Before:**
```rust
NoiseError::RateLimited("Too many requests".to_string())
```

**After:**
```rust
NoiseError::RateLimited {
    message: "Too many requests".to_string(),
    retry_after_ms: Some(5000),  // or None
}
```

### StorageBackedMessaging::new

**Before:**
```rust
let messaging = StorageBackedMessaging::new(link, session, client, write_path, read_path);
```

**After:**
```rust
let messaging = StorageBackedMessaging::new(link, session, client, write_path, read_path)?;
```

## New Features

### Client-Side Expiry

Enable handshake replay protection by setting `now_unix`:

```rust
let client = NoiseClient::new_direct(kid, device_id, ring)
    .with_now_unix(current_timestamp_secs())  // enables expiry
    .with_expiry_secs(600);  // optional: 10 min instead of default 5 min
```

### Timeout Enforcement

Storage operations now enforce timeouts (non-WASM only):

```rust
let config = RetryConfig {
    operation_timeout_ms: 15000,  // 15 seconds instead of default 30
    ..RetryConfig::default()
};
```

## Binding Regeneration

After updating pubky-noise, regenerate the FFI bindings:

```bash
# iOS
cd pubky-noise && ./build-ios.sh

# Android
cd pubky-noise && ./build-android.sh
```

Then copy the generated files to:
- **bitkit-ios**: `Bitkit/PaykitIntegration/FFI/`
- **bitkit-android**: `app/src/main/java/com/pubky/noise/`
- **pubky-ring iOS**: `ios/pubkyring/`
- **pubky-ring Android**: `android/app/src/main/java/com/pubky/noise/`

