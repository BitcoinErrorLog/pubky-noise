# PubkyNoise Rust Examples

This directory contains standalone Rust examples demonstrating various features of the `pubky-noise` library.

## Running Examples

All examples can be run with:

```bash
cargo run --example <example_name>
```

## Available Examples

### basic_handshake.rs

Complete IK pattern handshake between client and server with encrypted message exchange.

```bash
cargo run --example basic_handshake
```

**Demonstrates:**
- Client and server setup
- 3-step IK handshake
- Encryption/decryption
- Session ID verification

### server_example.rs

Server-side implementation handling multiple client connections.

```bash
cargo run --example server_example
```

**Demonstrates:**
- Server initialization
- Public key distribution
- Multiple client sessions with `NoiseSessionManager`
- Mobile-optimized server with `NoiseManager`
- Error handling for invalid messages and decryption failures
- Rate limiting patterns
- Client disconnection handling
- Connection timeout management
- Graceful shutdown procedures

### error_handling.rs

Comprehensive error handling patterns for all failure scenarios.

```bash
cargo run --example error_handling
```

**Demonstrates:**
- Invalid peer key detection
- Decryption failure handling
- Error codes for FFI integration
- Error recovery strategies

### streaming.rs

Large message handling with automatic chunking.

```bash
cargo run --example streaming
```

**Demonstrates:**
- `StreamingNoiseLink` usage
- Custom chunk sizes
- Automatic splitting and reassembly
- Mobile-friendly chunk size recommendations

### mobile_manager.rs

Mobile-optimized API with lifecycle management and state persistence.

```bash
cargo run --example mobile_manager
```

**Demonstrates:**
- `NoiseManager` API
- `MobileConfig` options
- State save/restore for app lifecycle
- Connection status tracking
- Multiple session management

### xx_pattern.rs

XX pattern (Trust On First Use) handshake demonstration.

```bash
cargo run --example xx_pattern
```

**Demonstrates:**
- XX pattern handshake flow (3 messages)
- Server key learning during handshake
- Key pinning for future IK connections
- Transition from XX to IK pattern
- Comparison of XX vs IK patterns
- Security considerations for TOFU

### storage_queue.rs

Storage-backed messaging with async operations and retry configuration.

```bash
cargo run --example storage_queue --features storage-queue
```

**Note**: Requires the `storage-queue` feature and Pubky infrastructure.

**Demonstrates:**
- `StorageBackedMessaging` setup
- `RetryConfig` configuration
- Counter persistence (critical for production)
- Async message sending and receiving
- Error handling for storage operations
- Best practices for production use

## Example Structure

Each example follows this pattern:

1. **Setup** - Initialize keys, clients, and servers
2. **Handshake** - Demonstrate the 3-step handshake
3. **Usage** - Show the specific feature
4. **Summary** - Key points and best practices

## Adding New Examples

When creating a new example:

1. Add the `.rs` file to this directory
2. The file must have a `fn main()` function
3. Use `println!` for output (no external dependencies needed)
4. Include comprehensive comments
5. Add documentation header with `//!` comments
6. Update this README

## Dependencies

Most examples use only the main `pubky-noise` crate. The `storage_queue.rs` example requires:
- The `storage-queue` feature to be enabled
- Pubky infrastructure (PubkySession, PublicStorage)

Run with feature:
```bash
cargo run --example storage_queue --features storage-queue
```

## See Also

- `tests/adapter_demo.rs` - Integration tests that double as examples
- `tests/mobile_integration.rs` - Comprehensive mobile feature tests
- Platform examples:
  - `platforms/android/example/MainActivity.kt`
  - `platforms/ios/example/BasicExample.swift`
