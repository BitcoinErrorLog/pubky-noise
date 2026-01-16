# Bitkit Integration Checklist for pubky-noise v1.2.0

This checklist guides you through testing and integrating `pubky-noise` into your mobile applications.

## What's New in v1.2.0

### Security Fixes (Critical)

- **X25519 cryptographic fix**: Corrected scalar multiplication to use proper RFC 7748 operations
  - Previous code had incorrect math that could cause interoperability issues
  - Now uses `x25519_dalek::x25519()` for correct Montgomery ladder multiplication
- **Server-side remote static verification**: IK and XX patterns now verify that the handshake's remote static matches the claimed identity
- **XX pattern expiration validation**: Now validates `hint_expires_at` in XX pattern (previously only IK)
- **Stricter `is_sealed_blob()` check**: Now requires both version AND epk fields
- **`LockedBytes` heap allocation**: Fixed memory stability issue with mlock

### Breaking Changes in v1.2.0

- **Removed `seen_client_epochs` and related methods**: These were unused dead code
  - Remove any calls to `cleanup_seen_epochs()` or `seen_epochs_count()`
  - `MAX_SEEN_EPOCHS` constant no longer exists

## What Was New in v1.1.0

- **HKDF API hardening**: Key derivation returns `Result` instead of panicking
- **Client-side expiry support**: Optional handshake expiry timestamps
- **Timeouts and validation**: Storage-backed operations enforce timeouts (non-WASM) and validate paths
- **Docs and tooling**: Expanded operational docs and improved binding generation guidance

### Breaking Changes in v1.1.0

- **`publicKeyFromSecret` now throws**: Swift requires `try publicKeyFromSecret(...)`, Kotlin adds `@Throws(FfiNoiseException::class)`
- **`deriveDeviceKey` rejects non-32-byte seeds**: Previously silently truncated/padded; now throws
- **Server `hint` max length: 256 characters**: Larger hints are rejected during handshake
- **Handshake message max size: 64 KiB**: Oversized messages are rejected

---

## ✅ Phase 1: Initial Validation (15 minutes)

### 1.1 Environment Setup
- [ ] Clone/pull latest `pubky-noise` repository
- [ ] Ensure Rust toolchain is installed (`rustup --version`)
- [ ] Ensure Xcode is installed (iOS) or Android NDK (Android)

### 1.2 Run Unit Tests
```bash
cd pubky-noise
cargo test --features uniffi_macros --lib
```
**Expected**: All tests pass (6+ rate_limiter tests + FFI tests)  
**If fails**: Review error messages, check dependencies

### 1.3 Check Code Quality
```bash
cargo check --all-features
cargo clippy --all-features
```
**Expected**: No errors or warnings  
**If fails**: Contact pubky team

---

## ✅ Phase 2: iOS Integration (1-2 hours)

### 2.1 Build XCFramework
```bash
./build-ios.sh
```
**Expected**: `platforms/ios/PubkyNoise.xcframework` created  
**Troubleshooting**: Check prerequisites in script output

### 2.2 Add to Xcode Project
- [ ] Drag `PubkyNoise.xcframework` to project
- [ ] Ensure "Embed & Sign" in Framework settings
- [ ] Add to target dependencies

**Alternative - Swift Package Manager:**
```swift
// Package.swift
dependencies: [
    .package(path: "../pubky-noise/platforms/ios")
]
```

### 2.3 Basic iOS Test
Create `PubkyNoiseTest.swift`:

```swift
import XCTest
@testable import PubkyNoise

class PubkyNoiseTest: XCTestCase {
    func testManagerCreation() {
        let config = defaultConfig()
        let seed = Data(repeating: 1, count: 32)
        let kid = "test-client"
        let deviceId = "device-123".data(using: .utf8)!
        
        do {
            let manager = try FfiNoiseManager(
                config: config,
                clientSeed: seed,
                clientKid: kid,
                deviceId: deviceId
            )
            let sessions = manager.listSessions()
            XCTAssertEqual(sessions.count, 0)
        } catch {
            XCTFail("Failed to create manager: \(error)")
        }
    }
}
```

- [ ] Run test - should pass
- [ ] Check no memory leaks in Instruments

### 2.4 Keychain Integration Test
```swift
func testKeychainStorage() {
    // Generate seed
    var seed = Data(count: 32)
    _ = seed.withUnsafeMutableBytes {
        SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!)
    }
    
    // Store in Keychain
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: "pubky-noise-seed",
        kSecValueData as String: seed,
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    ]
    
    let status = SecItemAdd(query as CFDictionary, nil)
    XCTAssertEqual(status, errSecSuccess)
    
    // Retrieve and use
    // ... (implement retrieval)
}
```

- [ ] Test Keychain storage and retrieval
- [ ] Verify seed security (no plaintext files)

---

## ✅ Phase 3: Android Integration (1-2 hours)

### 3.1 Build AAR
```bash
./build-android.sh
```
**Expected**: Native libs in `platforms/android/src/main/jniLibs/`  
**Troubleshooting**: 
- Ensure `ANDROID_NDK_HOME` is set
- Ensure `JAVA_HOME` is set (required for Gradle). If using Android Studio's bundled JDK:
  ```bash
  export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
  ```

### 3.2 Add to Gradle Project
`settings.gradle.kts`:
```kotlin
include(":pubky_noise")
project(":pubky_noise").projectDir = File("../pubky-noise/platforms/android")
```

`app/build.gradle.kts`:
```kotlin
dependencies {
    implementation(project(":pubky_noise"))
}
```

### 3.3 Basic Android Test
Create `PubkyNoiseTest.kt`:

```kotlin
import org.junit.Test
import org.junit.Assert.*
import com.pubky.noise.*

class PubkyNoiseTest {
    @Test
    fun testManagerCreation() {
        val config = defaultConfig()
        val seed = ByteArray(32) { 1 }
        val kid = "test-client"
        val deviceId = "device-123".toByteArray()
        
        val manager = FfiNoiseManager(config, seed, kid, deviceId)
        val sessions = manager.listSessions()
        assertEquals(0, sessions.size)
    }
}
```

- [ ] Run test with `./gradlew test`
- [ ] Should pass without errors

### 3.4 KeyStore Integration Test
```kotlin
@Test
fun testKeyStoreStorage() {
    val keyStore = KeyStore.getInstance("AndroidKeyStore")
    keyStore.load(null)
    
    // Generate key
    val keyGenerator = KeyGenerator.getInstance(
        KeyProperties.KEY_ALGORITHM_AES,
        "AndroidKeyStore"
    )
    
    val keyGenSpec = KeyGenParameterSpec.Builder(
        "pubky-noise-seed",
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
    )
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setUserAuthenticationRequired(false)
        .build()
    
    keyGenerator.init(keyGenSpec)
    keyGenerator.generateKey()
    
    // Test encryption/decryption of seed
    // ... (implement encryption)
}
```

- [ ] Test KeyStore storage
- [ ] Verify seed security

---

## ✅ Phase 4: Functional Testing (2-3 hours)

### 4.1 State Persistence Test (CRITICAL)

**iOS:**
```swift
func testStatePersistence() {
    // Create manager and session
    let manager = // ... create manager
    // let sessionId = try manager.connectClient(...) // Would need server
    
    // Simulate app suspension
    NotificationCenter.default.post(
        name: UIApplication.willResignActiveNotification,
        object: nil
    )
    
    // Save state
    // let state = try manager.saveState(sessionId: sessionId)
    // let data = try JSONEncoder().encode(state)
    // UserDefaults.standard.set(data, forKey: "session_state")
    
    // Simulate app restart
    // let restoredData = UserDefaults.standard.data(forKey: "session_state")!
    // let restoredState = try JSONDecoder().decode(FfiSessionState.self, from: restoredData)
    // try manager.restoreState(state: restoredState)
    
    // Verify session still works
    // ... test encryption/decryption
}
```

**Android:**
```kotlin
@Test
fun testStatePersistence() {
    // In Activity lifecycle
    override fun onPause() {
        super.onPause()
        // Save all session states
        sessionStates.clear()
        for (sessionId in manager.listSessions()) {
            val state = manager.saveState(sessionId)
            sessionStates[sessionId] = state
            // Persist to SharedPreferences (encrypted)
        }
    }
    
    override fun onResume() {
        super.onResume()
        // Restore all session states
        for ((sessionId, state) in sessionStates) {
            manager.restoreState(state)
        }
    }
}
```

- [ ] Test app suspension and resume
- [ ] Test app termination and restart
- [ ] Verify counters are preserved
- [ ] Verify no message loss

### 4.2 Thread Safety Test

**iOS:**
```swift
func testThreadSafety() {
    let manager = // ... create manager
    let queue1 = DispatchQueue(label: "test1")
    let queue2 = DispatchQueue(label: "test2")
    
    var errors: [Error] = []
    let group = DispatchGroup()
    
    for _ in 0..<100 {
        group.enter()
        queue1.async {
            do {
                _ = manager.listSessions()
            } catch {
                errors.append(error)
            }
            group.leave()
        }
        
        group.enter()
        queue2.async {
            do {
                _ = manager.listSessions()
            } catch {
                errors.append(error)
            }
            group.leave()
        }
    }
    
    group.wait()
    XCTAssertTrue(errors.isEmpty)
}
```

**Android:**
```kotlin
@Test
fun testThreadSafety() {
    val manager = // ... create manager
    val errors = mutableListOf<Throwable>()
    
    val threads = (0..99).map { i ->
        Thread {
            try {
                repeat(10) {
                    manager.listSessions()
                }
            } catch (e: Throwable) {
                synchronized(errors) {
                    errors.add(e)
                }
            }
        }
    }
    
    threads.forEach { it.start() }
    threads.forEach { it.join() }
    
    assertTrue(errors.isEmpty())
}
```

- [ ] Test concurrent access
- [ ] Verify no crashes or deadlocks
- [ ] Check for race conditions

### 4.3 Error Handling Test

```swift
// iOS - v1.0.0 Error Handling
func testErrorHandling() {
    let config = defaultConfig()
    
    // Invalid seed length
    let shortSeed = Data(repeating: 1, count: 16)
    XCTAssertThrowsError(try FfiNoiseManager(config: config, clientSeed: shortSeed, ...))
    
    // Invalid session ID
    let manager = try FfiNoiseManager(...)
    let result = manager.getStatus(sessionId: "invalid-hex")
    XCTAssertNil(result)
    
    // Encrypt without session
    XCTAssertThrowsError(try manager.encrypt(sessionId: "0000...", plaintext: data))
}

// v1.0.0: Handle new error types
func handleNoiseError(_ error: NoiseError) {
    switch error {
    case .rateLimited(let msg):
        // New in v1.0.0: Rate limiting
        if let retryAfter = error.retryAfterMs() {
            // Wait and retry
        }
    case .sessionExpired(let msg):
        // New in v1.0.0: Session expired
        // Re-authenticate
    case .maxSessionsExceeded:
        // New in v1.0.0: Too many sessions
        // Close old sessions first
    case .connectionReset(let msg):
        // New in v1.0.0: Connection reset
        // Reconnect with backoff
    default:
        // Handle other errors
        if error.isRetryable() {
            // Can retry this error
        }
    }
}
```

- [ ] Test all error paths
- [ ] Verify error messages are helpful
- [ ] Ensure no crashes on invalid input
- [ ] Test new v1.0.0 error variants (RateLimited, SessionExpired, etc.)

---

## ✅ Phase 5: Integration Testing (1-2 days)

### 5.1 End-to-End Handshake (Requires Two Devices/Simulators)

**Setup:**
- Device A: Client mode
- Device B: Server mode

**Test Flow:**
1. [ ] Server creates manager in server mode
2. [ ] Client creates manager in client mode
3. [ ] Client initiates connection: `connectClient()`
4. [ ] Server accepts: `acceptServer()`
5. [ ] Client encrypts message
6. [ ] Server decrypts message
7. [ ] Server encrypts response
8. [ ] Client decrypts response

**Success Criteria:**
- [ ] Handshake completes without errors
- [ ] Messages decrypt correctly
- [ ] Session IDs match expectations

### 5.2 Network Resilience

- [ ] Test with airplane mode toggle
- [ ] Test with poor network (Network Link Conditioner)
- [ ] Test connection timeout handling
- [ ] Verify retry logic works

### 5.3 Battery Impact

**iOS:**
- [ ] Profile with Instruments (Energy Log)
- [ ] Check CPU usage during encryption
- [ ] Verify battery saver mode works

**Android:**
- [ ] Profile with Android Profiler
- [ ] Check wake locks
- [ ] Test doze mode compatibility

---

## ✅ Phase 6: Production Preparation (1 day)

### 6.1 Logging Configuration

**Development:**
```toml
# Cargo.toml
[features]
default = ["trace"]  # Enable for development
```

**Production:**
```toml
[features]
default = []  # Disable for production (or filter to errors only)
```

- [ ] Configure logging levels
- [ ] Set up crash reporting integration
- [ ] Add telemetry for key events

### 6.2 Security Audit

- [ ] Review seed storage implementation
- [ ] Verify state is encrypted at rest
- [ ] Check for memory leaks (Instruments/Profiler)
- [ ] Validate no sensitive data in logs

### 6.3 Performance Benchmarking

```swift
// iOS
func testEncryptionPerformance() {
    let manager = // ... create manager
    let data = Data(repeating: 0, count: 1024 * 10) // 10KB
    
    measure {
        for _ in 0..<100 {
            _ = try? manager.encrypt(sessionId: sessionId, plaintext: data)
        }
    }
}
```

- [ ] Measure encryption throughput
- [ ] Measure handshake time
- [ ] Verify acceptable for your use case

### 6.4 Documentation Review

- [ ] Read `docs/IOS_INTEGRATION.md`
- [ ] Read `docs/ANDROID_INTEGRATION.md`
- [ ] Read `docs/MOBILE_INTEGRATION.md`
- [ ] Understand critical requirements (state persistence!)

---

## ✅ Phase 7: Deployment (Ongoing)

### 7.1 Monitoring

- [ ] Track session creation rate
- [ ] Monitor error rates by type
- [ ] Alert on unusual patterns
- [ ] Log state persistence failures

### 7.2 Maintenance

- [ ] Subscribe to pubky-noise releases
- [ ] Test updates in staging first
- [ ] Have rollback plan
- [ ] Document any customizations

---

## 🚨 Critical Requirements (Don't Skip!)

### State Persistence is MANDATORY
- ❌ **DO NOT** skip `save_state()` calls
- ❌ Failure = message loss and replay attacks
- ✅ Call in `applicationWillResignActive` (iOS) or `onPause` (Android)
- ✅ Store encrypted in secure storage

### Seed Security
- ❌ **NEVER** store in UserDefaults/SharedPreferences
- ❌ **NEVER** log or transmit seeds
- ✅ Use Keychain (iOS) or KeyStore (Android)
- ✅ Use device-level encryption

### Counter Synchronization
- ❌ **NEVER** desync write/read counters between app instances
- ✅ Always restore from most recent state
- ✅ Persist counters with every state save

---

## 📞 Support & Issues

**Found a bug?**
1. Check `docs/FFI_EXPERT_REVIEW.md` for known issues
2. Enable `trace` feature and reproduce
3. File issue at https://github.com/BitcoinErrorLog/pubky-noise/issues
4. Include: platform, logs, steps to reproduce

**Need help?**
- Read integration docs: `docs/` directory
- Check examples: `platforms/ios/example/` and `platforms/android/example/`
- Contact Pubky team

---

## ✅ Sign-Off

Before considering integration complete:

- [ ] All Phase 1-7 tasks completed
- [ ] All critical requirements understood and implemented
- [ ] Team trained on state persistence requirements
- [ ] Monitoring and alerts configured
- [ ] Rollback plan in place

**Integration Lead Signature**: _______________  
**Date**: _______________  
**Notes**: _______________

---

*Checklist Version: 1.2*  
*Last Updated: 2025-12-31*  
*pubky-noise Version: 1.1.0*

