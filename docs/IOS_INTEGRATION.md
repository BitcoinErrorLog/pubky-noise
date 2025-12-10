# iOS Integration Guide

This guide explains how to integrate `pubky-noise` into your iOS application using Swift Package Manager (SPM).

## ⚠️ CRITICAL REQUIREMENTS

Before you start, understand these critical requirements:

### 1. **State Persistence is MANDATORY**
- **You MUST call `save_state()` before app suspension/termination**
- Failure to persist state will cause message loss and replay attacks
- State includes write/read counters that MUST be synchronized

### 2. **Seed Security**
- **Seeds MUST be stored in iOS Keychain, never in UserDefaults or files**
- Seeds are zeroed in memory after use, but you must handle them securely
- Use `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` or stricter

### 3. **Counter Synchronization**
- Write/read counters prevent replay attacks
- If counters desync between app instances, sessions become unusable
- Always restore from the most recent saved state

## Prerequisites

- Xcode 13.0+
- iOS 13.0+ target

## Installation

1. **Build the Framework**:
   Run the build script from the repository root:
   ```bash
   ./build-ios.sh
   ```
   This creates `platforms/ios/PubkyNoise.xcframework`.

2. **Add to Xcode Project**:
   - Open your project in Xcode.
   - Go to **File > Add Packages...**
   - Select **Add Local...** and navigate to `platforms/ios`.
   - Select the folder containing `Package.swift`.

3. **Link Framework**:
   - Select your app target.
   - Under **General > Frameworks, Libraries, and Embedded Content**, ensure `PubkyNoise` is added.

## Usage Example

```swift
import PubkyNoise

// 1. Configure
let config = FfiMobileConfig(
    autoReconnect: true,
    maxReconnectAttempts: 5,
    reconnectDelayMs: 1000,
    batterySaver: false,
    chunkSize: 32768
)

// 2. Create Manager
// Note: In a real app, manage keys securely (e.g. Keychain)
let clientSeed = Data(count: 32) // Replace with real seed
let deviceId = "device-123".data(using: .utf8)!

do {
    let manager = try FfiNoiseManager(
        config: config,
        clientSeed: clientSeed,
        clientKid: "my-key-id",
        deviceId: deviceId
    )

    // 3. Connect
    let serverPk = Data(count: 32) // Replace with server static PK
    let sessionId = try manager.connectClient(
        serverPk: serverPk,
        epoch: 0,
        hint: nil
    )
    
    print("Connected! Session ID: \(sessionId)")

    // 4. Encrypt/Decrypt
    let plaintext = "Hello World".data(using: .utf8)!
    let ciphertext = try manager.encrypt(sessionId: sessionId, plaintext: plaintext)
    
    // 5. State Persistence (e.g., in SceneDelegate)
    let state = try manager.saveState(sessionId: sessionId)
    // Save 'state' to UserDefaults or file
    
} catch {
    print("Noise error: \(error)")
}
```

## Threading

The `FfiNoiseManager` is thread-safe internally. You can call its methods from any queue. However, network operations (like `connectClient`) might block, so it's recommended to run them on a background queue.

```swift
DispatchQueue.global(qos: .userInitiated).async {
    do {
        let sessionId = try manager.connectClient(...)
        
        DispatchQueue.main.async {
            // Update UI
        }
    } catch {
        // Handle error
    }
}
```

## Error Handling

Errors are thrown as `FfiNoiseError` enum cases.

```swift
do {
    // ...
} catch FfiNoiseError.Network(let message) {
    // Handle network error
} catch FfiNoiseError.Decryption(let message) {
    // Handle decryption failure
} catch {
    // Generic error
}
```

