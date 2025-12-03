# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.0] - 2025-12-03

### Added - Cold Key Architecture Support

#### New Noise Patterns
- **IK-raw**: IK handshake without in-band identity binding
  - For cold key scenarios where identity is verified via pkarr
  - `NoiseSender::initiate_ik_raw()` and `NoiseReceiver::respond_ik_raw()`
- **N pattern**: Anonymous initiator, authenticated responder
  - One-message pattern for anonymous clients
  - `NoiseSender::initiate_n()` and `NoiseReceiver::respond_n()`
- **NN pattern**: Fully anonymous (ephemeral-only)
  - Two-message pattern with no static keys
  - `NoiseSender::initiate_nn()` and `NoiseReceiver::respond_nn()`
- **XX pattern improvements**: Better TOFU support
  - `NoiseSender::initiate_xx()` and `NoiseReceiver::respond_xx()`

#### Cold Key Infrastructure
- **`RawNoiseManager`**: Pattern-selectable session manager for cold keys
  - `initiate_connection_with_pattern()` and `accept_connection_with_pattern()`
  - Supports all patterns: IK, IKRaw, N, NN, XX
- **`NoisePattern` enum**: Pattern selection for managers
- **`docs/COLD_KEY_ARCHITECTURE.md`**: Comprehensive documentation

#### Datalink Adapter Helpers
- `start_ik_raw()` / `accept_ik_raw()`: IK-raw convenience functions
- `start_n()` / `accept_n()` / `complete_n()`: N pattern helpers
- `start_nn()` / `accept_nn()`: NN pattern helpers
- `complete_raw()`: Generic completion for raw patterns

### Changed - Breaking Changes

#### Snow 0.10 Upgrade
- Upgraded from `snow = "0.9"` to `snow = "0.10"`
- Builder methods now return `Result<Self, Error>` instead of `Self`
- All builder chains updated with proper error propagation

#### API Renames (with deprecated aliases)
- `NoiseTransport` → `NoiseSession` (alias retained)
- `StreamingNoiseLink` → `StreamingNoiseSession` (alias retained)
- `NoiseLink` → `NoiseSession` (alias retained)
- `derive_x25519_for_device_epoch()` → `derive_x25519_static()` (alias retained)

#### Identity Binding Changes
- Domain separator updated to `"pubky-noise-bind:v2"` (was v1)
- `epoch` parameter removed from identity binding
- `server_hint` removed entirely

### Removed

- **PKARR module**: Unused scaffolding removed
- **`server_hint`**: Half-baked feature removed from `IdentityPayload`
- **`epoch` from binding**: No longer part of handshake binding message
- **`PhantomData<P>`**: Removed from `NoiseClient` and `NoiseServer`

### Fixed

- **Weak key rejection**: `respond_ik_raw()` now validates peer keys
- **N pattern flow**: Fixed immediate transport transition
- **XX pattern flow**: Fixed 3-message handshake state management
- **Snow 0.10 API**: Fixed all builder method chains

### Security

- All raw patterns validate peer keys via `shared_secret_nonzero()`
- Constant-time zero check prevents timing attacks
- Cold key patterns document trust assumptions (pkarr verification required)

### Documentation

- Updated README with cold key architecture section
- Updated pattern selection guide
- Added `RawNoiseManager` usage examples
- Created `COLD_KEY_ARCHITECTURE.md`
- Created `PRODUCTION_READINESS_REPORT.md`

### Testing

- Added `tests/cold_key_patterns.rs` (13 new tests)
- Weak key rejection tests
- Session ID uniqueness tests
- `RawNoiseManager` integration tests
- All 140+ tests pass

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

[0.8.0]: https://github.com/pubky/pubky-noise/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/pubky/pubky-noise/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/pubky/pubky-noise/releases/tag/v0.6.0

