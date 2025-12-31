# Downstream Integration Impact Report (pubky-noise)

**Goal**: Identify *all* downstream break risks in this workspace caused by recent `pubky-noise` changes, and provide a concrete plan to upgrade Ring + Bitkit apps safely and quickly.

**pubky-noise version (current)**: `1.1.0` (`Cargo.toml`)

---

## Executive Summary

### Confirmed breaking change (FFI)

`public_key_from_secret` changed from returning bytes to returning `Result<bytes, FfiNoiseError>`.

This changes generated bindings:
- **Swift**: `publicKeyFromSecret(...)` now **throws**
- **Kotlin**: `publicKeyFromSecret(...)` now **throws** (via `@Throws(FfiNoiseException::class)`)

**Impact**:
- If any downstream project updates the native library (`.a` / `.so`) without also updating the generated bindings, it will fail at runtime with UniFFI **API checksum mismatch**.
- Swift call sites that used `publicKeyFromSecret(...)` without `try` will fail to compile after regenerating bindings.

### Confirmed behavior tightening (FFI)

- `derive_device_key` now rejects seeds not exactly 32 bytes (was previously truncating/zero-padding).
- `public_key_from_secret` now rejects secrets not exactly 32 bytes.

**Impact**:
- Any call site passing non-32-byte inputs will now fail (throw).

### Confirmed server-side policy tightening (behavioral)

- Handshake message size limit: **64 KiB**
- `server_hint` length limit: **256 chars**

**Impact**:
- Downstream clients passing overly-large `hint` values may now fail handshakes (throw).

---

## Workspace Inventory: Where pubky-noise is embedded

### iOS (XCFramework + Swift bindings)

| Project | Native lib | Swift bindings | Notes |
|--------|------------|----------------|------|
| `pubky-noise` | `pubky-noise/platforms/ios/PubkyNoise.xcframework/` | `pubky-noise/platforms/ios/Sources/pubky_noise.swift` | **Currently stale** vs Rust: `publicKeyFromSecret` is non-throwing here but **must throw** after recent changes. |
| `pubky-ring` | `pubky-ring/ios/PubkyNoise.xcframework/` | `pubky-ring/ios/pubkyring/PubkyNoise.swift` | `PubkyNoiseModule.swift` calls `publicKeyFromSecret` without `try`. |
| `bitkit-ios` | `bitkit-ios/Bitkit/PaykitIntegration/Frameworks/PubkyNoise.xcframework/` | `bitkit-ios/Bitkit/PaykitIntegration/FFI/PubkyNoise.swift` | Binding file currently has **non-throwing** `deriveDeviceKey`/`publicKeyFromSecret` (stale). |
| `paykit-rs` demo | `paykit-rs/paykit-mobile/ios-demo/.../PubkyNoise.xcframework/` | `paykit-rs/paykit-mobile/ios-demo/.../PubkyNoise.swift` | Demo bindings are stale; will break if native lib updated. |

### Android (JNI `.so` + Kotlin bindings)

| Project | Native lib(s) | Kotlin bindings | Notes |
|--------|----------------|----------------|------|
| `pubky-noise` | `pubky-noise/platforms/android/src/main/jniLibs/.../libpubky_noise.so` | `pubky-noise/platforms/android/src/main/java/uniffi/pubky_noise/pubky_noise.kt` | **Currently stale** vs Rust: `publicKeyFromSecret` is non-throwing here but **must throw** after recent changes. |
| `pubky-ring` | `pubky-ring/android/app/src/main/jniLibs/{arm64-v8a,x86_64}/libpubky_noise.so` | `pubky-ring/android/app/src/main/java/uniffi/pubky_noise/pubky_noise.kt` | Module calls are inside `try/catch`, so behavior change is handled. |
| `bitkit-android` | `bitkit-android/app/src/main/jniLibs/{arm64-v8a,x86_64}/libpubky_noise.so` | `bitkit-android/app/src/main/java/com/pubky/noise/pubky_noise.kt` | Bitkit uses `com.pubky.noise.*` imports. Generator output in `pubky-noise/platforms/android` currently uses `uniffi.pubky_noise` package. |
| `bitkit-core-fix` | `bitkit-core-fix/bindings/android/lib/src/main/jniLibs/{arm64-v8a,armeabi-v7a,x86,x86_64}/libpubky_noise.so` | (varies) | Ensure these artifacts are updated if Bitkit pulls from this module. |

---

## Binding Regeneration Reality Check (what *must* change)

Fresh UniFFI bindings generated from current `pubky-noise` show:

- Swift:
  - `deriveDeviceKey(...) throws -> Data`
  - `publicKeyFromSecret(...) throws -> Data`
- Kotlin:
  - `@Throws(FfiNoiseException::class) fun deriveDeviceKey(...): ByteArray`
  - `@Throws(FfiNoiseException::class) fun publicKeyFromSecret(...): ByteArray`

This is the authoritative “truth” for downstream after updating native libs.

---

## Downstream Break Risk Matrix

### High risk (will break at runtime if missed)

- **UniFFI checksum mismatch** if native libs are updated without updating generated bindings in:
  - `pubky-ring` (iOS + Android)
  - `bitkit-ios`
  - `bitkit-android`
  - `paykit-rs` demos

### High risk (Swift compile breaks)

- `pubky-ring/ios/pubkyring/PubkyNoiseModule.swift`
  - `publicKeyFromSecret(...)` must become `try publicKeyFromSecret(...)` with error handling.

### Medium risk (behavioral)

- Any caller passing non-32-byte seed/secret will now throw.
  - Ring Android already validates seed/secret length.
  - Ring iOS validates seed/secret length, but must handle `publicKeyFromSecret` throwing once bindings are regenerated.
  - Bitkit Android uses `X25519Keypair.secretKeyHex` (documented as 32-byte hex), so should remain OK.

- Any caller passing `hint` > 256 chars may now fail handshakes.
  - Ring passes `hint` from JS without length validation today; add a guard to produce a friendly error.

### Low risk (docs/scripts)

- `pubky-noise` build scripts currently invoke UniFFI bindgen incorrectly:
  - `build-ios.sh` / `build-android.sh` call `cargo run --features=uniffi_macros --bin uniffi-bindgen ...`
  - but the binary requires `bindgen-cli`, and the new bindings must be regenerated after API changes.

### Additional gotchas (easy to miss)

- **Generated artifacts inside `pubky-noise` are currently stale**:
  - `platforms/ios/Sources/pubky_noise.swift` and `platforms/android/src/main/java/**/pubky_noise.kt` currently expose **non-throwing** `publicKeyFromSecret`, but regenerated bindings show it must be **throwing**.
  - Any repo copying these stale files will break at runtime after updating native libs.

- **Kotlin package mismatch in the workspace**:
  - `pubky-ring` uses `uniffi.pubky_noise.*`
  - `bitkit-android` uses `com.pubky.noise.*`
  - Decide on one canonical package name for shipping, or explicitly generate two variants.

- **Potential build breaks if warnings are treated as errors**:
  - `pubky-noise` currently emits Rust warnings under `--features uniffi_macros` (unused variables in `src/ffi/manager.rs`).
  - If any downstream build sets `-D warnings`, fix these warnings before shipping.

---

## Upgrade Plan (ship-fast, don’t miss anything)

### Phase A — Fix generation + produce canonical artifacts (pubky-noise)

1. **Regenerate Swift/Kotlin bindings** from the current library and commit them into the canonical locations used for copying:
   - `platforms/ios/Sources/pubky_noise.swift` (+ headers/modulemap if applicable)
   - `platforms/android/src/main/java/.../pubky_noise.kt`

2. **Fix build scripts** to generate bindings with the right features:
   - Use `--features "bindgen-cli,uniffi_macros"`
   - Ensure the output paths match what downstream expects.

3. **Rebuild native libs** for shipping:
   - iOS: rebuild `platforms/ios/PubkyNoise.xcframework`
   - Android: rebuild `.so` for required ABIs (at minimum `arm64-v8a` + `x86_64`; optionally add `armeabi-v7a` + `x86` if you still ship 32-bit).

Deliverable: a “golden” set of artifacts under `pubky-noise/platforms/...` that downstream can copy verbatim.

### Phase B — Update Pubky Ring (highest leverage)

iOS (`pubky-ring`):
- Replace:
  - `ios/PubkyNoise.xcframework/`
  - `ios/pubkyring/PubkyNoise.swift`
- Update:
  - `ios/pubkyring/PubkyNoiseModule.swift` to handle `publicKeyFromSecret` throwing
  - Add `hint` length validation (<= 256) before calling `initiateConnection`/`connectClient`

Android (`pubky-ring`):
- Replace:
  - `android/app/src/main/jniLibs/**/libpubky_noise.so`
  - `android/app/src/main/java/**/pubky_noise.kt`
- Add `hint` length validation (<= 256) before passing to FFI.

### Phase C — Update Bitkit apps

Bitkit iOS (`bitkit-ios`):
- Replace:
  - `Bitkit/PaykitIntegration/Frameworks/PubkyNoise.xcframework/`
  - `Bitkit/PaykitIntegration/FFI/PubkyNoise.swift`
- Verify no local code is calling `publicKeyFromSecret` without `try` (current workspace grep shows only the generated file).

Bitkit Android (`bitkit-android`):
- Replace:
  - `app/src/main/jniLibs/**/libpubky_noise.so`
  - `app/src/main/java/**/pubky_noise.kt`
- Confirm `NoisePaymentService.kt` still compiles and catches exceptions around handshake calls (it does today).

### Phase D — Update demos and integration docs

`paykit-rs/paykit-mobile` demos:
- Replace embedded PubkyNoise artifacts (Swift + XCFramework, Kotlin + `.so`) to avoid checksum mismatch.

Docs:
- Update any “copy artifacts” or version compatibility sections to reflect:
  - `pubky-noise` is now `1.1.0`
  - `publicKeyFromSecret` now throws
  - `hint` length limit (<= 256)

---

## Test Plan (minimum confidence before shipping)

### pubky-noise
- `cargo test --all-features`
- `cargo clippy --all-targets --all-features`
- Regenerate bindings and sanity-check signatures in the generated output.

### pubky-ring
- Android: assemble/debug compile (verify JNI loads, no checksum mismatch at runtime)
- iOS: build target that links `PubkyNoise.xcframework` and compiles Swift module

### bitkit-android
- `./gradlew compileDevDebugKotlin`
- Smoke-run the Noise handshake path if you have an internal test endpoint.

### bitkit-ios
- Xcode build (or `xcodebuild`) ensuring updated `PubkyNoise.swift` compiles and links.

---

## Suggested sequencing for “ship ASAP”

1. **pubky-noise**: regenerate bindings + rebuild artifacts (golden outputs)
2. **pubky-ring**: update artifacts + fix Swift `try` sites + add `hint` guard
3. **bitkit-android** + **bitkit-ios**: update artifacts and compile
4. **paykit-rs demos/docs**: refresh artifacts + docs


