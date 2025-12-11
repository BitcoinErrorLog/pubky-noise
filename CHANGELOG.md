# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-12-11

### Production Readiness Release

This release marks the first stable production-ready version of pubky-noise.

### Added

#### Security
- **Rate Limiter**: Token bucket algorithm for DoS protection
  - Configurable limits (strict/lenient/disabled presets)
  - Per-IP tracking with automatic cleanup
  - Detailed rate limit results with retry timing
- **Enhanced Error Handling**: Structured error codes for FFI compatibility
  - `NoiseErrorCode` enum with numeric codes
  - `is_retryable()` and `retry_after_ms()` helpers
  - New error variants: `RateLimited`, `MaxSessionsExceeded`, `SessionExpired`, `ConnectionReset`

#### API Improvements
- **Prelude Module**: Convenient imports via `use pubky_noise::prelude::*`
- **NoiseResult Type Alias**: Standard result type for Noise operations

#### Documentation
- **Integration Guide**: Complete usage documentation
- **Production Deployment Guide**: Configuration, security, monitoring
- **Performance Benchmarks**: Expected latencies and tuning tips

### Changed
- Updated examples for new error variants
- Fixed borrow-after-move in server_example.rs

## [0.7.1] - 2025-12-10

### Added

#### Testing Infrastructure
- **Fuzz Targets**: Added 4 fuzz targets for security testing
  - `fuzz_identity_payload`: Tests binding message generation
  - `fuzz_kdf`: Tests key derivation functions
  - `fuzz_handshake`: Tests handshake with malformed messages
  - `fuzz_noise_link`: Tests encrypt/decrypt with arbitrary inputs
- **Loom Tests**: Added concurrency tests using `loom` crate
  - Thread-safe session manager operations
  - Concurrent encrypt/decrypt verification

### Changed

#### API Simplification
- Simplified `NoiseClient::new_direct()` - removed epoch parameter
- Simplified `NoiseServer::new_direct()` - removed epoch parameter  
- Simplified `client_start_ik_direct()` - removed epoch parameter
- Epoch is now internal (always `0`), key rotation via device_id/kid
- `make_binding_message()` now takes `BindingMessageParams` struct for clarity

#### FFI Updates
- `initiateConnection()` + `completeConnection()` replaces single-call connect
- `newServer()` simplified (no epoch parameter)
- `FfiSessionState` simplified (no epoch field)

### Fixed
- Clippy warnings for duplicate cfg attributes
- `DummyPkarr` now implements `Default` trait
- FFI smoke tests use proper 3-step handshake pattern

## [0.7.0] - 2025-01-19

### Added - Mobile Integration

#### Core Mobile Features
- **`NoiseManager`**: High-level mobile-optimized session manager with lifecycle management
  - Automatic session persistence and restoration
  - Connection status tracking (Connected, Reconnecting, Disconnected, Error)
  - Mobile configuration (battery saver, chunk sizes, reconnection policies)
  - Built-in cleanup on Drop
- **`ThreadSafeSessionManager`**: Thread-safe wrapper around `NoiseSessionManager`
  - Safe for concurrent access from multiple threads
  - Cloneable for sharing across iOS/Android background workers
  - Convenient `encrypt`/`decrypt` methods with automatic locking
- **`SessionState`**: Serializable session state for persistence
  - Contains session ID, peer info, epoch, and counters
  - Ready for JSON/binary serialization with serde

#### FFI Bindings (New)
- **`pubky_noise.udl`**: UniFFI interface definition for cross-language bindings
- **`FfiNoiseManager`**: Thread-safe FFI wrapper for `NoiseManager`
- **`FfiMobileConfig`**, **`FfiSessionState`**, **`FfiConnectionStatus`**: FFI-safe types
- **Platform Support**:
  - **iOS**: Swift Package Manager support, XCFramework generation
  - **Android**: Gradle support, AAR generation with JNI libs
- **Build Scripts**: `build-ios.sh` and `build-android.sh` for automated binding generation

#### Enhanced APIs
- **`SessionId`** improvements:
  - `to_bytes()` / `from_bytes()` for easy serialization
  - `as_bytes()` for zero-copy access
  - `serde::Serialize` / `serde::Deserialize` support (when `storage-queue` feature enabled)
- **`StorageBackedMessaging`** improvements:
  - `write_counter()` / `read_counter()` getters for state persistence
  - `with_retry_config()` for configuring network resilience
  - Automatic retry with exponential backoff for transient errors
  - Separate error types for network, timeout, storage, and decryption
- **Error handling** for mobile/FFI:
  - `NoiseErrorCode` enum with numeric codes (1000-99999 range)
  - `NoiseError::code()` returns structured error code
  - `NoiseError::message()` returns owned String for FFI
  - New error variants: `Network`, `Timeout`, `Storage`, `Decryption`

#### Network Resilience
- **`RetryConfig`**: Configurable retry behavior
  - `max_retries`: Maximum retry attempts
  - `initial_backoff_ms`: Initial backoff duration
  - `max_backoff_ms`: Maximum backoff cap
  - `operation_timeout_ms`: Per-operation timeout
  - Default: 3 retries, 100ms-5s backoff, 30s timeout
- Exponential backoff for failed operations
- Separate handling of transient (5xx) vs permanent (4xx) errors
- Automatic retry for network errors in `StorageBackedMessaging`

#### Documentation
- **`docs/MOBILE_INTEGRATION.md`**: Comprehensive 500+ line mobile integration guide
  - Architecture overview and component layers
  - State persistence patterns (critical for mobile)
  - Thread safety guidelines and patterns
  - Network resilience best practices
  - Memory management tips
  - Platform-specific considerations (iOS/Android)
  - Complete code examples for common scenarios
- Enhanced README with mobile integration section
- Thread safety documentation in `NoiseSessionManager`
- Extensive doc comments on all new public APIs

#### Testing
- **`tests/mobile_integration.rs`**: Comprehensive mobile scenario tests
  - Session lifecycle (creation, persistence, restoration)
  - Thread-safe operations
  - Error code mapping
  - Streaming with mobile-friendly chunk sizes
  - Multiple concurrent sessions
  - Connection status tracking
  - Configuration presets (battery saver vs performance)

### Changed - Breaking Changes

- Bumped version to 0.7.0 to signal breaking changes
- `NoiseError` now has additional variants (`Network`, `Timeout`, `Storage`, `Decryption`)
- Enhanced error messages with structured codes

### Fixed

- Removed `src/temp.md` from source tree
- Better error handling in `StorageBackedMessaging`
- Improved decryption error messages

### Internal Improvements

- Better module organization with `mobile_manager.rs`
- Consistent use of `Duration` for timeouts
- Platform-aware sleep implementation (tokio for native, placeholder for WASM)

## [0.6.0] - 2024-XX-XX

### Added

- `SessionId` for tracking individual sessions
- `NoiseSessionManager` for managing multiple concurrent sessions
- `StreamingNoiseLink` for automatic message chunking
- `StorageBackedMessaging` for asynchronous storage-backed communication
- `with_counters()` method for session resumption

## [0.5.0] and earlier

- Initial implementation of Noise Protocol wrapper
- Ring-based key management
- IK and XX handshake patterns
- PKARR integration (optional)
- Identity binding and payload verification

[0.7.0]: https://github.com/pubky/pubky-noise/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/pubky/pubky-noise/releases/tag/v0.6.0

