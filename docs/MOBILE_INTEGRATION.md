# Mobile Integration Guide for pubky-noise

This guide explains how to integrate `pubky-noise` into mobile applications (iOS, Android) with proper lifecycle management, state persistence, and network resilience.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Quick Start](#quick-start)
3. [State Persistence](#state-persistence)
4. [Thread Safety](#thread-safety)
5. [Network Resilience](#network-resilience)
6. [Memory Management](#memory-management)
7. [Error Handling](#error-handling)
8. [Platform-Specific Considerations](#platform-specific-considerations)
9. [Best Practices](#best-practices)

## Architecture Overview

### Components for Mobile Apps

```
┌─────────────────────────────────────────────────┐
│           Your Mobile Application               │
├─────────────────────────────────────────────────┤
│  NoiseManager (High-level lifecycle)            │
│    ├─ Session State Persistence                 │
│    ├─ Automatic Reconnection                    │
│    └─ Mobile Configuration                      │
├─────────────────────────────────────────────────┤
│  StorageBackedMessaging (Optional)              │
│    ├─ Async Queue Pattern                       │
│    ├─ Retry Logic                               │
│    └─ Counter Persistence                       │
├─────────────────────────────────────────────────┤
│  NoiseLink / StreamingNoiseLink                 │
│    ├─ Encryption/Decryption                     │
│    └─ Message Chunking                          │
├─────────────────────────────────────────────────┤
│  Snow (Noise Protocol)                          │
└─────────────────────────────────────────────────┘
```

### Integration Layers

1. **Direct Integration**: Use `NoiseClient`/`NoiseServer` + `NoiseLink` directly
2. **Session Management**: Add `NoiseSessionManager` or `ThreadSafeSessionManager` for multiple sessions
3. **Mobile Optimized**: Use `NoiseManager` for full lifecycle management
4. **Storage-Backed**: Add `StorageBackedMessaging` for asynchronous communication

## Quick Start

### Basic Session Setup

```rust
use pubky_noise::{
    NoiseClient, NoiseManager, DummyRing, MobileConfig,
    datalink_adapter::client_start_ik_direct
};
use std::sync::Arc;

// 1. Create ring key provider (replace DummyRing with your actual key management)
let ring = Arc::new(DummyRing::new([1u8; 32], "my-key-id"));

// 2. Create client
let client = Arc::new(NoiseClient::<_, ()>::new_direct(
    "my-key-id",
    b"device-unique-id",
    ring
));

// 3. Create mobile manager with configuration
let config = MobileConfig {
    auto_reconnect: true,
    max_reconnect_attempts: 5,
    reconnect_delay_ms: 1000,
    battery_saver: false,
    chunk_size: 32768, // 32KB for mobile networks
};

let mut manager = NoiseManager::new_client(client, config);

// 4. Connect to server (requires async runtime)
async {
    let server_pk = [0u8; 32]; // Get server's public key
    let session_id = manager.connect_client(&server_pk, 3, None).await?;
    
    // 5. Encrypt/decrypt messages
    let ciphertext = manager.encrypt(&session_id, b"Hello, server!")?;
    let plaintext = manager.decrypt(&session_id, &ciphertext)?;
    
    Ok::<(), pubky_noise::NoiseError>(())
};
```

## State Persistence

### Critical: Save State on App Suspend

Mobile apps can be terminated at any time. You **must** persist session state to avoid data loss.

```rust
use pubky_noise::{NoiseManager, SessionState};
use std::fs;

// Before app suspend (iOS: applicationWillResignActive, Android: onPause)
fn on_app_suspend(manager: &NoiseManager<impl RingKeyProvider>) {
    for session_id in manager.list_sessions() {
        if let Ok(state) = manager.save_state(&session_id) {
            // Serialize and save to disk
            let json = serde_json::to_string(&state).unwrap();
            fs::write(format!("session_{}.json", session_id), json).ok();
            
            // Also save counters if using storage-backed messaging
            // (see Storage-Backed Messaging section)
        }
    }
}

// After app resume (iOS: applicationDidBecomeActive, Android: onResume)
async fn on_app_resume(manager: &mut NoiseManager<impl RingKeyProvider>) {
    // Load persisted sessions
    for entry in fs::read_dir("./").unwrap() {
        let path = entry.unwrap().path();
        if path.to_str().unwrap().starts_with("session_") {
            let json = fs::read_to_string(&path).unwrap();
            let state: SessionState = serde_json::from_str(&json).unwrap();
            
            // Restore state metadata
            manager.restore_state(state.clone()).ok();
            
            // Reconnect if needed
            if manager.config().auto_reconnect {
                let _ = manager.connect_client(
                    &state.peer_static_pk,
                    state.epoch,
                    None
                ).await;
            }
        }
    }
}
```

### Storage-Backed Messaging Persistence

When using `StorageBackedMessaging`, counter persistence is **critical**:

```rust
use pubky_noise::{StorageBackedMessaging, RetryConfig};

async fn save_storage_queue_state(queue: &StorageBackedMessaging) -> std::io::Result<()> {
    let state = serde_json::json!({
        "write_counter": queue.write_counter(),
        "read_counter": queue.read_counter(),
    });
    fs::write("queue_state.json", serde_json::to_string(&state)?)?;
    Ok(())
}

async fn restore_storage_queue(
    manager: &mut NoiseManager<impl RingKeyProvider>,
    session_id: &SessionId,
    session: PubkySession,
    client: Pubky,
) -> Result<StorageBackedMessaging, NoiseError> {
    // Load saved counters
    let saved = fs::read_to_string("queue_state.json").ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok());
    
    let (write_counter, read_counter) = match saved {
        Some(state) => (
            state["write_counter"].as_u64().unwrap_or(0),
            state["read_counter"].as_u64().unwrap_or(0),
        ),
        None => (0, 0),
    };
    
    // Create messaging with restored counters
    let mut messaging = manager.create_storage_messaging(
        session_id,
        session,
        client,
        "/pub/me/outbox".to_string(),
        "pubky://peer/pub/peer/outbox".to_string(),
    )?;
    
    messaging = messaging.with_counters(write_counter, read_counter);
    
    Ok(messaging)
}
```

## Thread Safety

### Option 1: ThreadSafeSessionManager (Recommended for Mobile)

```rust
use pubky_noise::{ThreadSafeSessionManager, NoiseClient, DummyRing};
use std::sync::Arc;

let ring = Arc::new(DummyRing::new([1u8; 32], "kid"));
let client = Arc::new(NoiseClient::<_, ()>::new_direct("kid", b"device", ring));

// Thread-safe by default
let manager = ThreadSafeSessionManager::new_client(client);

// Clone and share across threads
let manager_clone = manager.clone();
std::thread::spawn(move || {
    // Encrypt in background thread
    let result = manager_clone.encrypt(&session_id, b"data");
});
```

### Option 2: Manual Mutex Wrapping

```rust
use pubky_noise::NoiseSessionManager;
use std::sync::{Arc, Mutex};

let manager = Arc::new(Mutex::new(NoiseSessionManager::new_client(client)));

// Use in multiple threads
let manager_clone = manager.clone();
std::thread::spawn(move || {
    let mut mgr = manager_clone.lock().unwrap();
    // Use manager...
});
```

### Mobile Threading Patterns

**iOS (Swift):**
```swift
// Background queue for Noise operations
let noiseQueue = DispatchQueue(label: "com.app.noise", qos: .userInitiated)

noiseQueue.async {
    // Call Rust FFI functions here
    rust_noise_encrypt(session_id, data)
}
```

**Android (Kotlin):**
```kotlin
// Coroutine for Noise operations
lifecycleScope.launch(Dispatchers.IO) {
    // Call Rust JNI functions here
    rustNoiseEncrypt(sessionId, data)
}
```

## Network Resilience

### Retry Configuration for Mobile

```rust
use pubky_noise::RetryConfig;

// Conservative (battery saver mode)
let conservative = RetryConfig {
    max_retries: 2,
    initial_backoff_ms: 500,
    max_backoff_ms: 3000,
    operation_timeout_ms: 20000,
};

// Aggressive (fast connection)
let aggressive = RetryConfig {
    max_retries: 5,
    initial_backoff_ms: 100,
    max_backoff_ms: 10000,
    operation_timeout_ms: 30000,
};

// Apply to storage messaging
let messaging = StorageBackedMessaging::new(/* ... */)
    .with_retry_config(conservative);
```

### Handling Network State Changes

```rust
// iOS: Monitor network reachability
// Android: Monitor ConnectivityManager

async fn on_network_available(manager: &mut NoiseManager<impl RingKeyProvider>) {
    // Attempt to reconnect disconnected sessions
    for session_id in manager.list_sessions() {
        if manager.get_status(&session_id) == Some(ConnectionStatus::Disconnected) {
            manager.set_status(&session_id, ConnectionStatus::Reconnecting);
            
            // Try to reconnect
            // (implement reconnection logic based on saved session state)
        }
    }
}

fn on_network_lost(manager: &mut NoiseManager<impl RingKeyProvider>) {
    // Mark all sessions as disconnected
    for session_id in manager.list_sessions() {
        manager.set_status(&session_id, ConnectionStatus::Disconnected);
    }
}
```

## Memory Management

### Best Practices

1. **Clean up sessions promptly**:
   ```rust
   // Remove session when done
   manager.remove_session(&session_id);
   ```

2. **Use streaming for large messages**:
   ```rust
   use pubky_noise::StreamingNoiseLink;
   
   let streaming = StreamingNoiseLink::new_with_default_chunk_size(link);
   let chunks = streaming.encrypt_streaming(large_data)?;
   ```

3. **Limit concurrent sessions**:
   ```rust
   const MAX_SESSIONS: usize = 10;
   
   if manager.list_sessions().len() >= MAX_SESSIONS {
       // Remove oldest or least used session
       if let Some(old_session) = manager.list_sessions().first() {
           manager.remove_session(old_session);
       }
   }
   ```

### Memory Warnings (iOS/Android)

```rust
fn on_memory_warning(manager: &mut NoiseManager<impl RingKeyProvider>) {
    // Save all session states
    for session_id in manager.list_sessions().clone() {
        if let Ok(state) = manager.save_state(&session_id) {
            // Persist to disk
            save_to_disk(&state);
            
            // Remove from memory (can be restored later)
            manager.remove_session(&session_id);
        }
    }
}
```

## Error Handling

### Structured Error Codes

```rust
use pubky_noise::{NoiseError, NoiseErrorCode};

match result {
    Err(NoiseError::Network(_)) => {
        // Retry or queue for later
        println!("Network error, will retry");
    }
    Err(NoiseError::Timeout(_)) => {
        // Adjust timeout or fail gracefully
        println!("Timeout, trying with longer timeout");
    }
    Err(NoiseError::Decryption(_)) => {
        // Critical: possible attack or corruption
        println!("Decryption failed - possible security issue");
    }
    Err(e) => {
        // Get numeric code for FFI
        let code = e.code() as i32;
        let message = e.message();
        // Report to error tracking
    }
    Ok(data) => { /* success */ }
}
```

### Mapping to Platform Errors

**iOS (Swift):**
```swift
enum NoiseError: Error {
    case ring(String)
    case network(String)
    case decryption(String)
    // ... map from Rust error codes
    
    init(rustCode: Int32, message: String) {
        switch rustCode {
        case 8000: self = .network(message)
        case 10000: self = .decryption(message)
        default: self = .ring(message)
        }
    }
}
```

**Android (Kotlin):**
```kotlin
sealed class NoiseError(message: String) : Exception(message) {
    class NetworkError(message: String) : NoiseError(message)
    class DecryptionError(message: String) : NoiseError(message)
    
    companion object {
        fun fromRust(code: Int, message: String): NoiseError {
            return when (code) {
                8000 -> NetworkError(message)
                10000 -> DecryptionError(message)
                else -> NoiseError(message)
            }
        }
    }
}
```

## Platform-Specific Considerations

### iOS

1. **App Lifecycle**:
   - Save state in `applicationWillResignActive`
   - Restore in `applicationDidBecomeActive`
   - Handle `applicationWillTerminate`

2. **Background Execution**:
   - Limited to specific use cases (VoIP, location, etc.)
   - Use background tasks for short operations
   - Consider local notifications for received messages

3. **Keychain Integration**:
   ```rust
   // Implement RingKeyProvider that uses iOS Keychain
   // via FFI to store/retrieve keys securely
   ```

### Android

1. **App Lifecycle**:
   - Save state in `onPause()`
   - Restore in `onResume()`
   - Handle `onDestroy()`

2. **Background Execution**:
   - Use `WorkManager` for deferred work
   - Use `Foreground Service` for ongoing operations
   - Respect Doze mode restrictions

3. **KeyStore Integration**:
   ```rust
   // Implement RingKeyProvider that uses Android KeyStore
   // via JNI to store/retrieve keys securely
   ```

### Battery Optimization

Both platforms support battery saver modes:

```rust
#[cfg(target_os = "ios")]
fn is_low_power_mode() -> bool {
    // Call iOS API via FFI
    // ProcessInfo.processInfo.isLowPowerModeEnabled
    false // placeholder
}

#[cfg(target_os = "android")]
fn is_battery_saver_enabled() -> bool {
    // Call Android API via JNI
    // PowerManager.isPowerSaveMode()
    false // placeholder
}

// Adjust configuration based on battery state
let config = MobileConfig {
    battery_saver: is_low_power_mode() || is_battery_saver_enabled(),
    ..Default::default()
};
```

## Best Practices

### 1. Always Persist State

```rust
// GOOD: Save before any suspension
manager.save_state(&session_id)?;

// BAD: Assuming state will survive
// (app can be terminated at any time)
```

### 2. Handle Network Transitions

```rust
// GOOD: Monitor network and adjust
network_monitor.on_change(|is_connected| {
    if is_connected {
        attempt_reconnect();
    } else {
        mark_disconnected();
    }
});

// BAD: Assuming persistent connection
```

### 3. Use Appropriate Chunk Sizes

```rust
// GOOD: Mobile-optimized chunk size
let streaming = StreamingNoiseLink::new(link, 32768); // 32KB

// BAD: Large chunks on mobile
let streaming = StreamingNoiseLink::new(link, 1048576); // 1MB - too large
```

### 4. Implement Timeout Handling

```rust
// GOOD: Reasonable timeouts for mobile
let config = RetryConfig {
    operation_timeout_ms: 30000, // 30 seconds
    ..Default::default()
};

// BAD: Infinite or very long timeouts
```

### 5. Clean Up Resources

```rust
// GOOD: Explicit cleanup
impl Drop for MyApp {
    fn drop(&mut self) {
        for session_id in self.manager.list_sessions() {
            self.manager.remove_session(&session_id);
        }
    }
}

// BAD: Letting resources leak
```

### 6. Test Offline Scenarios

```rust
#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn test_offline_queue() {
        // Simulate offline by using mock network
        let mut queue = create_queue_with_mock_offline();
        
        // Messages should be queued
        assert!(queue.send_message(b"test").await.is_err());
        
        // After reconnect, should retry
        mock_go_online();
        assert!(queue.send_message(b"test").await.is_ok());
    }
}
```

## Example: Complete Mobile Integration

See `examples/mobile_integration.rs` for a complete example showing:
- Session lifecycle management
- State persistence and restoration
- Network resilience
- Thread-safe operations
- Error handling

## Additional Resources

- [Noise Protocol Specification](http://www.noiseprotocol.org/)
- [Pubky Documentation](https://pubky.org/)
- [iOS Background Execution](https://developer.apple.com/documentation/uikit/app_and_environment/scenes/preparing_your_ui_to_run_in_the_background)
- [Android Background Work](https://developer.android.com/guide/background)

