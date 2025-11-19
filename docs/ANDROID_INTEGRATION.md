# Android Integration Guide

This guide explains how to integrate `pubky-noise` into your Android application using Gradle and Kotlin.

## ⚠️ CRITICAL REQUIREMENTS

Before you start, understand these critical requirements:

### 1. **State Persistence is MANDATORY**
- **You MUST call `save_state()` in `onPause()` or before app termination**
- Failure to persist state will cause message loss and replay attacks
- State includes write/read counters that MUST be synchronized

### 2. **Seed Security**
- **Seeds MUST be stored in Android KeyStore, never in SharedPreferences or files**
- Seeds are zeroed in memory after use, but you must handle them securely
- Use `KeyGenParameterSpec` with `setUserAuthenticationRequired(true)` for sensitive apps

### 3. **Counter Synchronization**
- Write/read counters prevent replay attacks
- If counters desync between app instances, sessions become unusable
- Always restore from the most recent saved state

## Prerequisites

- Android Studio
- Android SDK 24+ (Android 7.0)

## Installation

1. **Build the Library**:
   Run the build script from the repository root:
   ```bash
   ./build-android.sh
   ```
   This generates `.so` files and Kotlin bindings in `platforms/android`.

2. **Import Module**:
   - In Android Studio, import the `platforms/android` folder as a new module.
   - Or copy the artifacts manually to your app's `libs` folder.

3. **Configure Gradle**:
   In your app's `build.gradle.kts`:
   ```kotlin
   dependencies {
       implementation(project(":pubky-noise"))
       // OR if using AAR
       // implementation(files("libs/pubky-noise.aar"))
   }
   ```

## Usage Example

```kotlin
import com.pubky.noise.*

// 1. Configure
val config = FfiMobileConfig(
    autoReconnect = true,
    maxReconnectAttempts = 5u,
    reconnectDelayMs = 1000u,
    batterySaver = false,
    chunkSize = 32768u
)

// 2. Create Manager
// Note: Manage keys securely using Android KeyStore
val clientSeed = ByteArray(32) // Replace with real seed
val deviceId = "device-123".toByteArray()

try {
    val manager = FfiNoiseManager(
        config,
        clientSeed,
        "my-key-id",
        deviceId
    )

    // 3. Connect
    val serverPk = ByteArray(32) // Replace with server static PK
    // Run on background thread (Coroutines)
    val sessionId = manager.connectClient(serverPk, 0u, null)
    
    println("Connected! Session ID: $sessionId")

    // 4. Encrypt/Decrypt
    val plaintext = "Hello World".toByteArray()
    val ciphertext = manager.encrypt(sessionId, plaintext)
    
    // 5. State Persistence (e.g., in ViewModel or onPause)
    val state = manager.saveState(sessionId)
    // Save state fields to SharedPreferences or Room
    
} catch (e: FfiNoiseError) {
    println("Noise error: ${e.message}")
}
```

## Threading

The `FfiNoiseManager` is thread-safe. However, operations like `connectClient` may take time. Use Kotlin Coroutines to avoid blocking the Main thread.

```kotlin
lifecycleScope.launch(Dispatchers.IO) {
    try {
        val sessionId = manager.connectClient(...)
        
        withContext(Dispatchers.Main) {
            // Update UI
        }
    } catch (e: Exception) {
        // Handle error
    }
}
```

## Error Handling

Errors are thrown as `FfiNoiseError` exceptions.

```kotlin
try {
    // ...
} catch (e: FfiNoiseError.Network) {
    // Handle network error
} catch (e: FfiNoiseError.Decryption) {
    // Handle decryption error
} catch (e: Exception) {
    // Generic error
}
```

