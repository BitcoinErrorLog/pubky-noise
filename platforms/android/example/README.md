# PubkyNoise Android Example

This directory contains a comprehensive Android example demonstrating how to integrate the PubkyNoise library into an Android application.

## Overview

The example demonstrates:
- Complete 3-step IK handshake
- State persistence across app lifecycle
- Encryption and decryption
- Connection status tracking
- Network transport integration
- Streaming/chunking for large messages
- Thread-safe operations
- Battery optimization
- Comprehensive error handling
- Multiple session management

## Quick Start

### 1. Add Dependency

Add the PubkyNoise library to your `build.gradle.kts`:

```kotlin
dependencies {
    implementation("com.pubky:pubky-noise:1.1.0")
}
```

### 2. Basic Setup

```kotlin
import com.pubky.noise.*

// Configure for mobile use
val config = FfiMobileConfig(
    autoReconnect = true,
    maxReconnectAttempts = 5u,
    reconnectDelayMs = 1000uL,
    batterySaver = false,
    chunkSize = 32768uL  // 32KB chunks for mobile networks
)

// Create manager
val manager = FfiNoiseManager.newClient(
    config = config,
    clientSeed = clientSeed.toList(),
    clientKid = "my-app-key-id",
    deviceId = deviceId.toList()
)
```

### 3. Complete Handshake

```kotlin
// Step 1: Initiate connection
val result = manager.initiateConnection(
    serverPk = serverPk.toList(),
    hint = null
)

// Step 2: Send first message to server (your network transport)
val serverResponse = sendToServer(result.firstMessage.toByteArray())

// Step 3: Complete connection
val sessionId = manager.completeConnection(
    sessionId = result.sessionId,
    serverResponse = serverResponse.toList()
)
```

## Features

### Network Transport Integration

The example includes a `sendToServer()` function demonstrating how to integrate with your network layer:

```kotlin
private suspend fun sendToServer(data: ByteArray): ByteArray = withContext(Dispatchers.IO) {
    val url = java.net.URL("https://your-server.com/api/noise/handshake")
    val connection = url.openConnection() as java.net.HttpURLConnection
    // ... send data and receive response
}
```

**Note**: Replace the placeholder URL with your actual server endpoint.

### State Persistence

**CRITICAL**: Always save and restore session state to survive app suspension:

```kotlin
override fun onPause() {
    super.onPause()
    sessionId?.let { 
        val state = manager.saveState(it)
        // Persist to SharedPreferences or database
    }
}

override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    // Restore state from storage
    val state = loadState()
    manager.restoreState(state)
}
```

### Streaming/Chunking

For large messages (files, images), use streaming:

```kotlin
// Encrypt large data
val chunks = encryptStreaming(largeData) { current, total ->
    val progress = (current * 100 / total)
    // Update progress UI
}

// Decrypt chunks
val decrypted = decryptStreaming(chunks)
```

### Thread Safety

The manager is thread-safe and can be used from any thread:

```kotlin
lifecycleScope.launch(Dispatchers.IO) {
    // Background thread operations
    val ciphertext = manager.encrypt(sessionId, data.toList())
    
    withContext(Dispatchers.Main) {
        // Update UI on main thread
    }
}
```

### Battery Optimization

Switch configurations based on battery level:

```kotlin
if (batteryLevel < 20) {
    // Use battery saver config
    val config = FfiMobileConfig(
        autoReconnect = false,
        batterySaver = true,
        chunkSize = 16384uL  // Smaller chunks
    )
}
```

## Code Structure

The example is organized into sections:

1. **Setup and Configuration** - Manager initialization
2. **Handshake Flow** - 3-step connection process
3. **Encryption/Decryption** - Message encryption
4. **State Persistence** - Save/restore for lifecycle
5. **Connection Status** - Status tracking
6. **Multiple Sessions** - Managing multiple connections
7. **Network Transport** - HTTP integration example
8. **Streaming** - Large message handling
9. **Thread Safety** - Background thread usage
10. **Battery Optimization** - Power management
11. **Error Handling** - Comprehensive error handling

## Integration Steps

1. **Add the library** to your project dependencies
2. **Initialize the manager** in your Application or Activity
3. **Implement network transport** (HTTP, WebSocket, etc.)
4. **Handle app lifecycle** (save/restore state)
5. **Configure for your use case** (battery, network conditions)
6. **Handle errors** appropriately

## Common Patterns

### Pattern 1: Basic Connection

```kotlin
// Initiate
val result = manager.initiateConnection(serverPk, null)
val response = sendToServer(result.firstMessage.toByteArray())
val sessionId = manager.completeConnection(result.sessionId, response.toList())

// Encrypt/Decrypt
val ciphertext = manager.encrypt(sessionId, data.toList())
val plaintext = manager.decrypt(sessionId, ciphertext)
```

### Pattern 2: With State Persistence

```kotlin
// Save before suspension
val state = manager.saveState(sessionId)
saveToStorage(state)

// Restore after resume
val state = loadFromStorage()
manager.restoreState(state)
```

### Pattern 3: Background Operations

```kotlin
lifecycleScope.launch(Dispatchers.IO) {
    val ciphertext = manager.encrypt(sessionId, data.toList())
    withContext(Dispatchers.Main) {
        // Update UI
    }
}
```

## Error Handling

The example includes comprehensive error handling for all error types:

```kotlin
try {
    val result = manager.initiateConnection(serverPk, null)
} catch (e: FfiNoiseError) {
    when (e) {
        is FfiNoiseError.Network -> {
            // Retry with backoff
        }
        is FfiNoiseError.InvalidPeerKey -> {
            // Security issue - alert user
        }
        // ... handle other errors
    }
}
```

## Troubleshooting

### Issue: Connection fails immediately

- Check that server public key is correct (32 bytes)
- Verify network connectivity
- Check error logs for specific error messages

### Issue: State not persisting

- Ensure you're calling `saveState()` in `onPause()`
- Verify SharedPreferences is working
- Check that state is being restored in `onCreate()`

### Issue: Encryption/decryption fails

- Verify session is established (check `getStatus()`)
- Ensure you're using the correct session ID
- Check that data hasn't been corrupted

### Issue: High battery consumption

- Enable `batterySaver` mode
- Reduce `chunkSize` for smaller operations
- Disable `autoReconnect` if not needed

## Best Practices

1. **Always persist state** - Critical for production apps
2. **Handle errors gracefully** - Provide user feedback
3. **Use appropriate chunk sizes** - Balance performance and battery
4. **Monitor connection status** - Update UI accordingly
5. **Use background threads** - Don't block main thread
6. **Optimize for battery** - Adjust config based on battery level

## See Also

- [iOS Example](../ios/example/BasicExample.swift)
- [Rust Examples](../../examples/)
- [Main README](../../README.md)
