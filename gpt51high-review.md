# Audit Report: pubky-noise (GPT-5.1 high)

Hands-on production readiness audit of `pubky-noise` code and build outputs, following `paykit-rs/review-prompt.md`.

## Build Status

- [x] **All targets + all features compile**: YES
  - `cargo build --all-targets --all-features`
- [x] **All tests pass**: YES
  - `cargo test --all`
- [x] **Clippy clean (all targets + all features)**: YES
  - `cargo clippy --all-targets --all-features`
- [x] **Docs compile**: YES
  - `cargo doc --no-deps`
- [x] **Workspace build**: YES
  - `cargo build --workspace`
- [x] **No default features build**: YES
  - `cargo build --no-default-features`
- [x] **Feature combination spot-checks**: YES
  - `cargo build --lib --no-default-features --features storage-queue`
  - `cargo build --lib --no-default-features --features pubky-sdk`
  - `cargo build --lib --no-default-features --features pkarr`
  - `cargo build --lib --no-default-features --features uniffi_macros` (builds, but emits warnings; see below)
- [ ] **Cross-platform WASM build**: N/A in this environment
  - `wasm-pack` is not installed here (`wasm-pack: command not found`)
- [x] **UniFFI bindgen CLI**: YES (feature gated)
  - `cargo run --bin uniffi-bindgen --features bindgen-cli -- --help`

### Notable warnings

- Building with `--no-default-features --features uniffi_macros` emits `unused variable: e` warnings in `src/ffi/manager.rs`. This is not a functional error, but it indicates feature-combination hygiene issues.

## Security Assessment

- [x] **Signature verification order**: expiry check is done **before** signature verification in server IK handling (`src/server.rs`).
- [x] **Identity binding has domain separation**: `pubky-noise-bind:v1` is included in the binding hash (`src/identity_payload.rs`).
- [x] **Transport message replay protection**: relies on Noise transport nonce progression via `snow::TransportState`; tests explicitly verify replayed ciphertext fails (`tests/replay_protection.rs`).
- [ ] **Handshake replay protection**: not implemented as a “reject duplicate handshakes” mechanism; tests document that a repeated handshake produces a new session rather than being treated as replay (`tests/replay_protection.rs`). Optional expiry helps only when `expires_at` is used.
- [ ] **Secret handling / zeroization**: partial; some key material is wrapped in `Zeroizing` temporarily, but long-lived secrets are still stored as plain `[u8; 32]` in some paths.

## Concurrency Safety

- [x] **Lock poisoning**: handled gracefully in `RateLimiter` and `ThreadSafeSessionManager` via `unwrap_or_else(|e| e.into_inner())`.
- [ ] **Deadlock risk**: nothing obvious in the crate, but there are multiple mutexes (FFI manager, rate limiter, server fields) and callers could still create problematic lock ordering in integrations.

## DoS / Rate Limiting & Resource Exhaustion

- [x] **Rate limiter exists** with bounded tracked IPs and cleanup (`src/rate_limiter.rs`).
- [x] **Storage queue**:
  - validates Pubky paths against traversal/injection patterns (`src/storage_queue.rs`)
  - treats `404` as “empty queue” (not an error) (`src/storage_queue.rs`)
  - enforces timeouts on non-wasm targets and retries with exponential backoff (`src/storage_queue.rs`)
- [ ] **Input size caps** are generally missing for attacker-controlled inputs (handshake messages, JSON payload size, `server_hint` length, etc.).

## Code Quality Searches (high-signal results)

- No `TODO`/`FIXME`/`todo!`/`unimplemented!` found in `*.rs`.
- `unwrap/expect/panic` hits are dominated by `tests/` and `examples/` (acceptable); production `src/` code did not show these patterns in the earlier scan.
- No `unsafe` found in `src/`.
- Floating point: no `f32/f64` in `src/` (good).
- Integer casts: a small number of `as usize/u64` conversions exist (mostly config/FFI sizing).

## Critical Issues (blocks release)

### 1) `IdentityPayload` contains attacker-controlled fields that are not validated and are not integrity-protected

**Why it matters**

`IdentityPayload` is parsed from attacker-controlled JSON during handshake. In `NoiseServer::build_responder_read_ik`, signature verification binds only the server’s view of:
- pattern tag (`"IK"`)
- prologue (`pubky-noise-v1`)
- Ed25519 pubkey bytes
- local+remote Noise pubkeys
- role parameter (server hard-codes `Role::Client`)
- optional `server_hint`
- optional `expires_at`

But the decoded payload includes:
- `role`
- `epoch`

These are not validated in the server and are not included as “payload fields” in the signature. A MITM can tamper with them without breaking signature verification. That becomes a vulnerability if any downstream logic uses them.

**Evidence**

- `IdentityPayload` struct includes `role` and `epoch` (`src/identity_payload.rs`).
- The binding message uses a constant epoch (`INTERNAL_EPOCH = 0`) rather than `payload.epoch` (`src/identity_payload.rs`).
- Server verification always uses `role: Role::Client` as the binding parameter, rather than checking `payload.role` (`src/server.rs`).

**Fix plan**

- Minimal / non-breaking:
  - In `NoiseServer::build_responder_read_ik`, reject payloads where:
    - `payload.role != Role::Client`
    - `payload.epoch != 0`
  - Document explicitly that `epoch` is fixed and `role` is expected to match the handshake direction.
- Stronger / potentially breaking:
  - Bind `payload.epoch` and `payload.role` into the signed binding message; coordinate versioning and upgrade behavior.

### 2) “Policy” and “epoch tracking” are exposed but not enforced (public API risk)

**Why it matters**

`NoiseServer` publicly exposes fields like:
- `policy: ServerPolicy` (max handshakes per IP, max sessions per Ed25519)
- `current_epoch`, `seen_client_epochs`

But these are effectively unused in the handshake path (no references beyond initialization were found). This creates a “false sense of security” for integrators.

**Fix plan**

- Either:
  - wire policy enforcement into the server handshake API (requires passing IP/identity context into the server method), and add tests; or
  - remove these from the public API until they are real.

### 3) Missing size limits on attacker-controlled inputs (allocation/DoS surface)

**Why it matters**

Examples:
- `NoiseServer::build_responder_read_ik` allocates `Vec` sized by `first_msg.len() + 256` before any length cap.
- `IdentityPayload.server_hint: Option<String>` is unbounded.
- `kdf::derive_x25519_for_device_epoch` uses `device_id` length to size an `info` buffer.

**Fix plan**

Introduce and enforce constants (examples):
- `MAX_HANDSHAKE_MSG_LEN`
- `MAX_IDENTITY_JSON_LEN`
- `MAX_SERVER_HINT_LEN`
- `MAX_DEVICE_ID_LEN`
- `MAX_PLAINTEXT_LEN` / `MAX_CIPHERTEXT_LEN` (or an API that requires caller-provided buffers)

Reject early before allocation and before `serde_json::from_slice`.

## High Priority (fix before release)

### 1) Expiry validation is fail-open on system time errors

In `src/server.rs`, if `SystemTime` is before `UNIX_EPOCH`, the code currently falls back to `now = 0` (`unwrap_or(0)`), which can allow an expired payload to be accepted if the clock is invalid.

**Fix plan**

- If `expires_at` is present and system time cannot be computed reliably, fail closed.
- Consider bounding “too far in the future” `expires_at` values (skew window).

### 2) FFI exports accept short secrets by silently zero-padding

In `src/ffi/config.rs`:
- `derive_device_key(seed: Vec<u8>, ...)` uses a zeroed `[u8; 32]` if `seed.len() < 32`
- `public_key_from_secret(secret: Vec<u8>)` does the same

This is dangerous for integrators and can lead to predictable keys.

**Fix plan**

- Require exact lengths (`== 32`) and return a structured `FfiNoiseError` on invalid lengths.
- Avoid returning derived secrets unless that’s an explicit, documented API requirement.

### 3) Docs/API claim “automatic reconnection with exponential backoff” but it’s not implemented

`MobileConfig` contains reconnection settings, but `NoiseManager` does not implement reconnection logic; `restore_state()` explicitly says it only restores metadata and requires reconnect.

**Fix plan**

- Either implement explicit reconnection APIs (with a clear “caller provides transport” contract), or remove/rename settings and docs to match reality.

## Medium Priority (fix soon)

1. **Feature-combination hygiene**: eliminate `unused variable` warnings in the FFI manager under non-`trace` builds.
2. **Dependency surface**: `secrecy` and `x25519-dalek` are present in `[dependencies]` but not used in `src/` (supply chain + maintenance cost); either use them intentionally or remove.
3. **`secure-mem` feature**: feature exists but there’s no code path using `region`/mlock; either implement or remove to avoid misleading security posture.

## Demo/Test Code Issues (acceptable for demo, fix for production polish)

- `println!/unwrap/expect` are used in `examples/` and `tests/` (expected). Keep them out of runtime library paths.

## What’s Actually Good

- Strong build/test posture: builds and tests pass across multiple feature combinations.
- Domain-separated identity binding and expiry-first validation.
- Replay protection of transport ciphertext validated by tests.
- `StorageBackedMessaging` treats `404` as empty and validates Pubky paths against traversal and invalid characters.
- `RateLimiter` has bounded tracking (`max_tracked_ips`) and cleanup to avoid unbounded growth.

## Recommended Fix Order (action plan)

1. **Secure the handshake identity layer**
   - Validate `payload.role` and `payload.epoch` (and decide whether to bind them cryptographically vs enforce constants).
   - Add tests for tampering of those fields.
2. **Make policy real or remove it**
   - Either implement enforcement (requires new API inputs) or remove `ServerPolicy/current_epoch/seen_client_epochs` from the public API until implemented.
3. **Define and implement secret-handling posture**
   - Decide whether this crate guarantees in-memory key protections or pushes that responsibility to hosts.
   - Align FFI APIs accordingly; avoid long-lived raw seeds; add/enable `secure-mem` only if real.
4. **Add caps and fail-fast input validation**
   - Handshake message length, JSON payload length, hint length, device_id length, session limits, pending handshake limits.
5. **Harden FFI APIs**
   - Strict input length validation; no silent truncation/zero-padding.
   - Revisit which functions should export raw key material.
6. **Cleanup**
   - Remove unused deps/features or use them deliberately; fix feature-specific warnings; ensure clippy is clean for common feature combos too (not just all-features).


