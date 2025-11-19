# FFI Bindings Changelog

This file documents changes specific to the mobile FFI bindings (`pubky-noise-ffi`).

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.7.0] - 2025-01-19

### Initial Release

- **`FfiNoiseManager`**: Main entry point for mobile apps
- **Platform Support**:
  - iOS (Swift Package Manager, XCFramework)
  - Android (Gradle, AAR, JNI)
- **API Surface**:
  - `connect_client`: Connect to a server (IK handshake)
  - `accept_server`: Accept a connection (IK handshake)
  - `encrypt`/`decrypt`: Message encryption
  - `save_state`/`restore_state`: Session persistence
  - `list_sessions`/`remove_session`: Session management
  - `get_status`/`set_status`: Connection monitoring
- **Configuration**:
  - `FfiMobileConfig`: Customize timeouts, retries, chunk sizes
  - Preset helpers: `default_config()`, `battery_saver_config()`, `performance_config()`
- **Error Handling**:
  - `FfiNoiseError`: Mapped to Swift `Error` and Kotlin `Exception`
  - Detailed error messages for debugging

### Known Limitations

- Async operations are currently exposed as blocking calls in the FFI layer. Mobile apps should run them on background threads (DispatchQueue/Coroutines).
- Custom `RingKeyProvider` implementation is not yet supported over FFI. Keys must be provided as raw bytes/seeds.

