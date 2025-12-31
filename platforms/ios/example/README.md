# PubkyNoise iOS Example

This directory contains a comprehensive iOS example demonstrating how to integrate the PubkyNoise library into an iOS application.

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

Add the PubkyNoise library to your `Package.swift` or Xcode project:

```swift
dependencies: [
    .package(url: "https://github.com/BitcoinErrorLog/pubky-noise", from: "1.1.0")
]
```

### 2. Basic Setup

```swift
import PubkyNoise

// Configure for mobile use
let config = FfiMobileConfig(
    autoReconnect: true,
    maxReconnectAttempts: 5,
    reconnectDelayMs: 1000,
    batterySaver: false,
    chunkSize: 32768  // 32KB chunks for mobile networks
)

// Create manager
let manager = try FfiNoiseManager.newClient(
    config: config,
    clientSeed: clientSeed,
    clientKid: "my-app-key-id",
    deviceId: deviceId
)
```

### 3. Complete Handshake

```swift
// Step 1: Initiate connection
let firstMessage = try manager.initiateConnection(
    serverPk: serverPk,
    hint: nil
)

// Step 2: Send first message to server (your network transport)
let serverResponse = try await sendToServer(data: firstMessage)

// Step 3: Complete connection
let sessionId = try manager.completeConnection(serverResponse: serverResponse)
```

## Features

### Network Transport Integration

The example includes a `sendToServer()` function demonstrating how to integrate with your network layer:

```swift
func sendToServer(data: Data) async throws -> Data {
    guard let url = URL(string: "https://your-server.com/api/noise/handshake") else {
        throw NoiseManagerError.configurationError("Invalid server URL")
    }
    
    var request = URLRequest(url: url)
    request.httpMethod = "POST"
    request.httpBody = data
    
    let (responseData, _) = try await URLSession.shared.data(for: request)
    return responseData
}
```

**Note**: Replace the placeholder URL with your actual server endpoint.

### State Persistence

**CRITICAL**: Always save and restore session state to survive app suspension:

```swift
func applicationWillResignActive() {
    if let sessionId = sessionId {
        let state = try? manager.saveState(sessionId: sessionId)
        // Persist to UserDefaults or Core Data
    }
}

func applicationDidBecomeActive() {
    // Restore state from storage
    if let state = loadState() {
        try? manager.restoreState(state: state)
    }
}
```

### Streaming/Chunking

For large messages (files, images), use streaming:

```swift
// Encrypt large data
let chunks = try encryptStreaming(data) { current, total in
    let progress = (current * 100 / total)
    // Update progress UI
}

// Decrypt chunks
let decrypted = try decryptStreaming(chunks: chunks)
```

### Thread Safety

The manager is thread-safe and can be used from any queue:

```swift
let backgroundQueue = DispatchQueue(label: "com.pubky.noise.background")
backgroundQueue.async {
    let ciphertext = try manager.encrypt(sessionId: sid, plaintext: data)
    DispatchQueue.main.async {
        // Update UI
    }
}
```

### Battery Optimization

Switch configurations based on battery level:

```swift
if batteryLevel < 20 {
    // Use battery saver config
    let config = FfiMobileConfig(
        autoReconnect: false,
        batterySaver: true,
        chunkSize: 16384  // Smaller chunks
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
9. **Thread Safety** - Background queue usage
10. **Battery Optimization** - Power management
11. **Error Handling** - Comprehensive error handling

## Integration Steps

1. **Add the library** to your project dependencies
2. **Initialize the manager** in your AppDelegate or SceneDelegate
3. **Implement network transport** (URLSession, Alamofire, etc.)
4. **Handle app lifecycle** (save/restore state)
5. **Configure for your use case** (battery, network conditions)
6. **Handle errors** appropriately

## Common Patterns

### Pattern 1: Basic Connection

```swift
// Initiate
let firstMessage = try manager.initiateConnection(serverPublicKey: serverPk)
let response = try await sendToServer(data: firstMessage)
let sessionId = try manager.completeConnection(serverResponse: response)

// Encrypt/Decrypt
let ciphertext = try manager.encrypt(sessionId: sessionId, plaintext: data)
let plaintext = try manager.decrypt(sessionId: sessionId, ciphertext: ciphertext)
```

### Pattern 2: With State Persistence

```swift
// Save before suspension
let state = try manager.saveState(sessionId: sessionId)
saveToStorage(state)

// Restore after resume
let state = loadFromStorage()
try manager.restoreState(state: state)
```

### Pattern 3: Background Operations

```swift
let backgroundQueue = DispatchQueue(label: "background")
backgroundQueue.async {
    let ciphertext = try manager.encrypt(sessionId: sid, plaintext: data)
    DispatchQueue.main.async {
        // Update UI
    }
}
```

## Error Handling

The example includes comprehensive error handling for all error types:

```swift
do {
    let result = try manager.initiateConnection(serverPublicKey: serverPk)
} catch let error as FfiNoiseError {
    switch error {
    case .network(let message):
        // Retry with backoff
    case .invalidPeerKey:
        // Security issue - alert user
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

- Ensure you're calling `saveState()` in `applicationWillResignActive`
- Verify UserDefaults is working
- Check that state is being restored in `applicationDidBecomeActive`

### Issue: Encryption/decryption fails

- Verify session is established (check `getConnectionStatus()`)
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
5. **Use background queues** - Don't block main queue
6. **Optimize for battery** - Adjust config based on battery level

## See Also

- [Android Example](../android/example/MainActivity.kt)
- [Rust Examples](../../examples/)
- [Main README](../../README.md)
