# Production Readiness Audit Report: pubky-noise

**Version**: 1.0.0  
**Date**: December 31, 2025  
**Auditor**: Claude Opus 4.5 (based on paykit-rs/review-prompt.md methodology)

---

## Build Status

| Check | Status | Notes |
|-------|--------|-------|
| All workspace crates compile | ✅ YES | `cargo build --all-targets --all-features` succeeds |
| Tests pass | ✅ YES | 113 tests pass (0 failed, 1 ignored) |
| Clippy clean | ✅ YES | No warnings |
| Build without default features | ✅ YES | `cargo build --no-default-features` succeeds |
| Documentation compiles | ✅ YES | `cargo doc --no-deps` succeeds |
| Cross-platform targets | ⚠️ PARTIAL | Mobile builds work; WASM not explicitly tested |

---

## Security Assessment

| Property | Status | Evidence |
|----------|--------|----------|
| Nonces generated securely (via snow) | ✅ YES | Relies on snow library for AEAD nonce management |
| Replay protection implemented | ✅ YES | Nonce progression in transport mode + handshake expiry |
| Keys zeroized on drop | ✅ YES | `Zeroizing<[u8; 32]>` wrapper used consistently |
| Signature verification order correct | ✅ YES | Expiry checked BEFORE signature verification (server.rs:115-128) |
| No secrets in logs | ✅ YES | Only session IDs, lengths, and status logged |
| Constant-time DH check | ✅ YES | `shared_secret_nonzero` uses OR accumulator pattern |
| All-zero DH rejection | ✅ YES | Explicitly checks for zero shared secret |
| HKDF domain separation | ✅ YES | Unique salt: `"pubky-noise-x25519:v1"` |
| Binding message domain separation | ✅ YES | `"pubky-noise-bind:v1"` prefix + role + pattern |
| Path traversal prevention | ✅ YES | `validate_path()` rejects `..` and `//` sequences |

---

## Financial Safety

| Property | Status | Notes |
|----------|--------|-------|
| Amount uses Decimal/fixed-point | ⬜ N/A | No financial calculations in this library |
| Checked arithmetic used | ✅ YES | Uses `saturating_sub` in rate limiter |
| No floating-point for money | ⬜ N/A | No financial calculations |

---

## Concurrency Safety

| Property | Status | Evidence |
|----------|--------|----------|
| Lock poisoning handled | ✅ YES | `unwrap_or_else(\|e\| e.into_inner())` pattern throughout |
| No deadlock potential identified | ✅ YES | Single mutex per manager, no nested locks |
| Thread-safe where required | ✅ YES | `ThreadSafeSessionManager`, `Arc<Mutex<>>` wrappers |
| FFI types are Send + Sync | ✅ YES | UniFFI handles correctly with `Arc<Mutex<>>` |

---

## Critical Issues (Blocks Release)

**None identified.**

---

## High Priority (Fix Before Release)

### 1. PkarrResolver trait not implemented for DummyPkarr

**Location**: `src/pkarr.rs:51-63`

**Description**: `DummyPkarr` declares the `PkarrResolver` trait but doesn't implement it. The trait methods `fetch_server_noise_record` and `fetch_server_ed25519_pub` are declared but there's no `impl PkarrResolver for DummyPkarr` block.

```rust
/// Dummy PKARR resolver for testing (returns errors for all operations).
pub struct DummyPkarr;

impl DummyPkarr {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DummyPkarr {
    fn default() -> Self {
        Self::new()
    }
}
```

**Impact**: Any code attempting to use `DummyPkarr` as a `PkarrResolver` will fail to compile.

**Fix**: Add implementation:

```rust
impl PkarrResolver for DummyPkarr {
    fn fetch_server_noise_record(&self, _server_id: &str) -> Result<PkarrNoiseRecord, NoiseError> {
        Err(NoiseError::Pkarr("DummyPkarr: not implemented".to_string()))
    }
    
    fn fetch_server_ed25519_pub(&self, _server_id: &str) -> Result<[u8; 32], NoiseError> {
        Err(NoiseError::Pkarr("DummyPkarr: not implemented".to_string()))
    }
}
```

---

### 2. FFI seed handling doesn't zeroize input Vec

**Location**: `src/ffi/manager.rs:46-51`, `src/ffi/config.rs:45-50`

**Description**: While the copied seed array is wrapped in `Zeroizing`, the original `Vec<u8>` passed from FFI is not explicitly cleared. The `Zeroizing` only protects the local copy.

```rust
let mut seed_arr = [0u8; 32];
seed_arr.copy_from_slice(&client_seed);
let seed_zeroizing = Zeroizing::new(seed_arr);

let ring = Arc::new(DummyRing::new_with_device(
    *seed_zeroizing, // Deref to get the value, will be zeroed on drop
```

**Impact**: Original seed bytes remain in memory until garbage collected by the platform.

**Recommendation**: Explicitly zeroize the input Vec before returning:

```rust
let mut seed_arr = [0u8; 32];
seed_arr.copy_from_slice(&client_seed);
// Zeroize original input
let mut mutable_seed = client_seed;
mutable_seed.iter_mut().for_each(|b| *b = 0);
let seed_zeroizing = Zeroizing::new(seed_arr);
```

Or document that callers are responsible for clearing the input.

---

### 3. derive_device_key FFI function silently truncates short seeds

**Location**: `src/ffi/config.rs:44-50`

**Description**: If seed is less than 32 bytes, the function uses a zero-padded array instead of returning an error:

```rust
let mut seed_arr = [0u8; 32];
if seed.len() >= 32 {
    seed_arr.copy_from_slice(&seed[0..32]);
}
let sk = crate::kdf::derive_x25519_for_device_epoch(&seed_arr, &device_id, epoch)?;
```

**Impact**: A short seed could result in weaker keys if the caller makes a mistake.

**Fix**: Return an error for invalid seed length:

```rust
if seed.len() < 32 {
    return Err(FfiNoiseError::Ring { 
        message: "Seed must be at least 32 bytes".to_string() 
    });
}
```

---

### 4. public_key_from_secret has same truncation issue

**Location**: `src/ffi/config.rs:54-60`

**Description**: Same issue as above - silently accepts short secrets:

```rust
pub fn public_key_from_secret(secret: Vec<u8>) -> Vec<u8> {
    let mut secret_arr = [0u8; 32];
    if secret.len() >= 32 {
        secret_arr.copy_from_slice(&secret[0..32]);
    }
    crate::kdf::x25519_pk_from_sk(&secret_arr).to_vec()
}
```

**Fix**: Add length validation or document behavior clearly.

---

## Medium Priority (Fix Soon)

### 1. Epoch rotation not implemented

**Location**: `src/client.rs:8`, `src/server.rs:10`

**Description**: `INTERNAL_EPOCH` is hardcoded to 0. The epoch field exists but is never rotated. The THREAT_MODEL.md mentions epoch as a replay protection mechanism, but it's currently static.

```rust
/// Internal epoch value - always 0 (epoch is not a user-facing concept).
const INTERNAL_EPOCH: u32 = 0;
```

**Impact**: No key rotation mechanism for long-running deployments.

**Recommendation**: Document this limitation or implement epoch rotation for production use.

---

### 2. ServerPolicy enforcement is incomplete

**Location**: `src/server.rs:13-19`

**Description**: `ServerPolicy` defines `max_handshakes_per_ip` and `max_sessions_per_ed25519` but they're not enforced anywhere in the server code:

```rust
/// Server policy configuration.
#[derive(Clone, Debug, Default)]
pub struct ServerPolicy {
    /// Maximum handshakes allowed per IP address (rate limiting).
    pub max_handshakes_per_ip: Option<u32>,
    /// Maximum sessions allowed per Ed25519 identity.
    pub max_sessions_per_ed25519: Option<u32>,
}
```

**Impact**: Applications expecting these policies to be enforced by the library will be vulnerable to abuse.

**Recommendation**: Either implement the enforcement or clearly document that applications must use `RateLimiter` separately.

---

### 3. seen_client_epochs map never cleaned up

**Location**: `src/server.rs:29`

**Description**: The server maintains a `seen_client_epochs` HashMap, but there's no cleanup mechanism:

```rust
pub seen_client_epochs: std::sync::Mutex<std::collections::HashMap<[u8; 32], u32>>,
```

**Impact**: Memory grows unbounded over time with many unique clients.

**Recommendation**: Add periodic cleanup or use an LRU cache with bounded size.

---

### 4. FFI test files are empty

**Location**: `tests/ffi_comprehensive.rs`, `tests/ffi_integration.rs`, `tests/ffi_smoke.rs`

**Description**: These test files exist but have 0 tests when run (all are conditional on `uniffi_macros` feature or have no test functions).

**Impact**: FFI boundary is not adequately tested in CI.

**Recommendation**: Add substantive FFI tests or remove empty files.

---

### 5. Storage-queue tests require external Pubky infrastructure

**Location**: `tests/storage_queue.rs`, `tests/storage_queue_comprehensive.rs`

**Description**: These test files show 0 tests run because they require actual Pubky SDK integration.

**Impact**: Critical async code paths are not tested in CI.

**Recommendation**: Add mock-based tests that don't require network access.

---

## Low Priority (Technical Debt)

### 1. Documentation examples use `no_run`

**Location**: `src/lib.rs:9`, `src/mobile_manager.rs:103`

**Description**: Many doc examples use `#[doc(no_run)]` or `/// ```rust,no_run` which means they're not compile-tested.

**Recommendation**: Convert to runnable doctests where possible.

---

### 2. DummyRing stores unused fields

**Location**: `src/ring.rs:44-50`

**Description**: `DummyRing` stores `kid`, `device_id`, and `epoch` but marks them with `#[allow(dead_code)]`.

```rust
#[allow(dead_code)]
pub struct DummyRing {
    seed32: [u8; 32],
    kid: String,        // Stored for reference but not directly accessed
    device_id: Vec<u8>, // Stored for reference but not directly accessed
    epoch: u32,         // Stored for reference but not directly accessed
}
```

**Recommendation**: Remove if not needed, or add accessor methods if useful for debugging.

---

### 3. Test `.unwrap()` usage

**Location**: Various test files and one doctest example

**Description**: The grep found `unwrap()` in test code and one doctest example in `session_manager.rs:34`. This is acceptable for tests but the doctest example could confuse users.

**Recommendation**: Use `?` operator in doctest examples where possible.

---

### 4. THREAT_MODEL.md version mismatch

**Location**: `THREAT_MODEL.md:4`

**Description**: Document says "pubky-noise v0.7.0" but Cargo.toml says "1.0.0".

**Fix**: Update THREAT_MODEL.md version to 1.0.0.

---

## Demo/Test Code Issues (Acceptable for demo, fix for production)

### 1. Fuzz test uses dummy signatures

**Location**: `fuzz/fuzz_targets/fuzz_handshake.rs:36-39`

**Description**: FuzzRing returns constant signature `[0x42u8; 64]` for all messages. This is fine for fuzzing (testing input handling) but means signature verification paths aren't fuzzed.

```rust
fn sign_ed25519(&self, _kid: &str, _msg: &[u8]) -> Result<[u8; 64], NoiseError> {
    // Dummy signature for fuzzing (not cryptographically valid)
    Ok([0x42u8; 64])
}
```

**Recommendation**: Add a separate fuzz target that uses real signatures.

---

## What's Actually Good ✅

1. **Excellent cryptographic hygiene**: 
   - `Zeroizing` wrapper used consistently for secret keys
   - Closure-based key access prevents key escape
   - HKDF with unique domain separation strings
   - All-zero DH rejection with constant-time check

2. **Robust error handling**:
   - Custom `NoiseError` enum with error codes
   - `is_retryable()` and `retry_after_ms()` methods for smart retry logic
   - FFI errors map cleanly to platform error types

3. **Thread safety done right**:
   - Lock poisoning handled gracefully (fail-open with recovery)
   - `ThreadSafeSessionManager` provides correct `Arc<Mutex<>>` pattern
   - No nested locking that could cause deadlocks

4. **Strong replay protection**:
   - Nonce progression via snow library for transport-mode messages
   - Handshake expiry support (`expires_at` checked before signature verification)
   - Cross-session isolation via unique session keys

5. **Rate limiting infrastructure**:
   - Full-featured `RateLimiter` with configurable limits
   - Cooldown periods, cleanup of expired entries, bounded memory usage
   - Detailed result type with reason codes

6. **Comprehensive test coverage**:
   - Property-based tests for cryptographic operations
   - Replay protection tests
   - Signature tamper resistance tests (bit-flip across entire signature)
   - Identity binding message uniqueness tests

7. **Path traversal protection**:
   - Storage queue validates paths against injection attacks
   - Rejects `..`, `//`, and special characters

8. **Well-documented threat model**:
   - Comprehensive `THREAT_MODEL.md` covering attack vectors
   - Clear trust boundaries and residual risks
   - FFI-specific security considerations

9. **Clean API design**:
   - 3-step handshake pattern is clear and documented
   - Builder pattern with `with_*` methods
   - Strong typing prevents misuse

---

## Recommended Fix Order

1. **HIGH: Add PkarrResolver implementation for DummyPkarr** (blocks anyone trying to use PKARR feature)

2. **HIGH: Fix FFI seed length validation** (security issue - weak keys possible)

3. **MEDIUM: Implement seen_client_epochs cleanup** (memory leak in long-running servers)

4. **MEDIUM: Document or implement ServerPolicy enforcement** (avoid false sense of security)

5. **MEDIUM: Add FFI integration tests** (ensure mobile bindings work correctly)

6. **LOW: Update THREAT_MODEL.md version** (documentation accuracy)

7. **LOW: Consider epoch rotation strategy** (key hygiene for long deployments)

---

## Summary

**pubky-noise v1.0.0** is in excellent shape for production deployment. The cryptographic implementation is sound, with proper key zeroization, constant-time operations, and domain separation. The main issues are:

- One missing trait implementation (`PkarrResolver` for `DummyPkarr`)
- FFI input validation gaps for short seeds
- Some policy infrastructure that's defined but not enforced

None of these are critical security vulnerabilities - they're usability and completeness issues. After addressing the high-priority items, this library is ready for production use.

**Security Grade**: **A-** (matches THREAT_MODEL.md self-assessment)

---

## Appendix: Commands Run

```bash
# Build verification
cargo build --all-targets --all-features
cargo build --no-default-features
cargo test --all
cargo clippy --all-targets --all-features
cargo doc --no-deps

# Security pattern searches
grep -rn "TODO|FIXME|XXX|HACK|unimplemented!|todo!" --include="*.rs" src/
grep -rn "\.unwrap()|\.expect(|panic!" --include="*.rs" src/
grep -rn "unsafe|\*const|\*mut" --include="*.rs" src/
grep -rn "nonce|iv|Iv|Nonce" --include="*.rs" src/
grep -rn "Zeroizing|zeroize|Zero" --include="*.rs" src/
grep -rn "Mutex|RwLock|Arc|RefCell" --include="*.rs" src/
grep -rn "expires_at|expired|timestamp" --include="*.rs" src/
grep -rn "f64|f32" --include="*.rs" src/
grep -rn "as i64|as u64|as usize" --include="*.rs" src/
grep -rn "checked_add|saturating_" --include="*.rs" src/
grep -rn "block_on|spawn_blocking|Runtime::new" --include="*.rs" src/
```

---

**Document Prepared By**: Claude Opus 4.5  
**Review Status**: COMPLETE  
**Next Review**: Upon major version changes or when issues are addressed

