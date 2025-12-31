# Audit Report: pubky-noise

## Build Status
- [x] All workspace crates compile: **YES**
- [x] Tests pass: **YES** (6 unit tests, 88 integration/test cases, 9 doc-tests)
- [x] Clippy clean: **YES**
- [x] Cross-platform targets build (WASM/Mobile): **YES** (UniFFI bindings generate successfully)
- [x] Documentation compiles: **YES**

## Security Assessment
- [x] Nonces generated securely and never reused: **YES** (Noise protocol implementation via `snow` handles handshake/transport nonces; `StorageBackedMessaging` uses monotonic counters for replay protection).
- [x] Replay protection implemented: **YES** (`expires_at` in `IdentityPayload` enforced by server before signature verification; monotonic counters in storage-backed messaging; IP-based rate limiting).
- [x] Keys zeroized on drop: **YES** (`Zeroizing<[u8; 32]>` is used for all sensitive key material across the library and FFI layer).
- [x] Signature verification order correct (expiry first): **YES** (Handshake expiration is validated before cryptographic verification in `src/server.rs`).
- [x] No secrets in logs: **YES** (Production paths use `tracing` sparingly and never log keys/secrets).

## Financial Safety
- [x] Amount uses Decimal/fixed-point (not f64): **N/A** (Library handles encryption/handshakes, not monetary amounts).
- [x] Checked arithmetic used: **YES** (Saturating arithmetic is used for rate limiting windows and counter operations).
- [x] Spending limits enforced atomically: **N/A**

## Concurrency Safety
- [x] Lock poisoning handled: **YES** (Graceful recovery using `unwrap_or_else(|e| e.into_inner())` in `ThreadSafeSessionManager` and `RateLimiter`).
- [x] No deadlock potential identified: **YES** (Locks are granular, held briefly, and never nested across different resources).
- [x] Thread-safe where required: **YES** (FFI layer is fully thread-safe; `NoiseManager` and `RateLimiter` use `Mutex` protection).

## Critical Issues (blocks release)
*No critical issues found.*

## High Priority (fix before release)
*No high priority issues found.*

## Medium Priority (fix soon)
1. **Lock Poisoning Documentation**: While lock poisoning is handled by "failing open" (recovering the inner state), the rationale for this decision (e.g., preference for availability over crash-looping in mobile UI threads) should be explicitly documented in `src/session_manager.rs` and `src/rate_limiter.rs`.

## Low Priority (technical debt)
1. **Buffer Allocation in Transport**: `NoiseTransport` (src/transport.rs) allocates a new `Vec` for every `read` and `write`. While acceptable for mobile, buffer reuse or pooling could improve performance in high-throughput server scenarios.
2. **FFI SessionID Parsing DRY**: `FfiNoiseManager` (src/ffi/manager.rs) manually implements hex decoding for `SessionId`. This logic should be moved to a `FromStr` implementation in `src/session_id.rs` to avoid repetition.

## What's Actually Good
- **Mobile-First Design**: The `MobileConfig` allows for battery saver modes and adjustable chunk sizes, showing deep consideration for mobile platform constraints.
- **Cryptographic Guards**: The implementation includes a `shared_secret_nonzero` check before completing handshakes, protecting against small-group attacks and weak keys.
- **Testing Rigor**: The inclusion of `loom` concurrency tests, `cargo-fuzz` targets, and extensive property tests (`proptest`) for cryptographic primitives is excellent.
- **Robust FFI**: The `uniffi` implementation is very professional, with proper error mirroring and secure seed handling during manager initialization.

## Recommended Fix Order
1. **Document lock poisoning strategy**: Clarify the recovery mechanism in code comments.
2. **Refactor SessionId parsing**: Move hex decoding logic into the core `SessionId` struct.
3. **Optional**: Implement buffer reuse in `NoiseTransport` if server-side performance benchmarks identify it as a bottleneck.

---

## Plan for Addressing Issues

### 1. Documentation Update
- **File**: `src/session_manager.rs`, `src/rate_limiter.rs`
- **Action**: Add a standard doc block to every `unwrap_or_else(|e| e.into_inner())` call explaining that the library favors availability and that the internal state remains consistent even if a thread panics during a read/write operation.

### 2. Refactoring SessionId
- **File**: `src/session_id.rs`
- **Action**: Implement `std::str::FromStr` for `SessionId` to handle hex decoding.
- **File**: `src/ffi/manager.rs`
- **Action**: Update `parse_session_id` to use the new `FromStr` implementation.

### 3. Verification
- **Action**: Rerun `cargo test` and `cargo test --doc` to ensure refactoring didn't break existing session management logic.
- **Action**: Rerun UniFFI binding generation to verify the FFI layer remains compatible interface remains intact.

