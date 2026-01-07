# Pubky Cryptographic Specification

**Version**: 1.0  
**Date**: January 2026  
**Status**: Authoritative Reference

This specification defines the cryptographic primitives, key derivation schemes, transport protocols, and envelope formats used across the Pubky ecosystem (pubky-ring, pubky-noise, paykit, bitkit).

---

## Table of Contents

1. [Design Principles](#1-design-principles)
2. [Cryptographic Primitives](#2-cryptographic-primitives)
3. [Identity Model](#3-identity-model)
4. [Key Hierarchy and Derivation](#4-key-hierarchy-and-derivation)
5. [Device Authorization](#5-device-authorization)
6. [Live Transport (Noise Protocol)](#6-live-transport-noise-protocol)
7. [Async Messaging (Outbox Envelopes)](#7-async-messaging-outbox-envelopes)
8. [Session and Message Binding](#8-session-and-message-binding)
9. [Key Rotation](#9-key-rotation)
10. [Backup and Restore](#10-backup-and-restore)
11. [Security Considerations](#11-security-considerations)
12. [Implementation Reference](#12-implementation-reference)

---

## 1. Design Principles

### 1.1 Core Goals

1. **Deterministic identity**: A device can re-derive the same app-scoped keys after restart or restore from backup.

2. **Cold master secret**: The Ed25519 seed stays in Ring. Apps receive only derived material or perform derivation via Ring callbacks.

3. **No CipherState persistence**: Noise transport keys are never serialized or exported. Sessions re-handshake after disconnect.

4. **Offline async delivery**: Queued messages are decryptable without the sender being online.

5. **Clean separation of concerns**:
   - Ring: seed custody, authorization, derivation
   - pubky-noise: Noise handshake, transport encryption, envelope sealing
   - Apps (Bitkit, Paykit): message formats, outbox semantics, receipts

### 1.2 Threat Model

| Assumption | Description |
|------------|-------------|
| Device OS not actively malicious | We don't claim HSM-grade RAM protection |
| Homeserver untrusted | May delete, delay, reorder, replay stored blobs |
| Network adversary passive | Can observe timing/metadata; active MITM prevented by Noise |
| Traffic analysis out of scope | Timing attacks addressed in future work |

### 1.3 Required Properties

- Message confidentiality against homeserver and passive observers
- Message integrity and sender authenticity when signatures present
- Replay resistance and idempotency at application layer

---

## 2. Cryptographic Primitives

### 2.1 Algorithms

| Purpose | Algorithm | Library |
|---------|-----------|---------|
| Identity signing | Ed25519 | `ed25519-dalek` |
| Key exchange | X25519 | `x25519-dalek` |
| Key derivation | HKDF-SHA256 / HKDF-SHA512 | `hkdf` crate |
| Symmetric encryption (transport) | ChaCha20-Poly1305 | `chacha20poly1305` via `snow` |
| Symmetric encryption (envelopes) | XChaCha20-Poly1305 | `chacha20poly1305` crate |
| Hashing | BLAKE2s (Noise), BLAKE3 (tags), SHA-256 (HKDF) | Various |

### 2.2 Key Sizes

| Key Type | Size |
|----------|------|
| Ed25519 seed | 32 bytes |
| Ed25519 public key | 32 bytes |
| Ed25519 signature | 64 bytes |
| X25519 secret key | 32 bytes |
| X25519 public key | 32 bytes |
| Symmetric key | 32 bytes |
| ChaCha20-Poly1305 nonce | 12 bytes |
| XChaCha20-Poly1305 nonce | 24 bytes |
| Poly1305 tag | 16 bytes |

---

## 3. Identity Model

### 3.1 PKARR Identity

A PKARR identity is an Ed25519 keypair. The public key is the identity.

- **Encoding**: z-base-32 (52 characters)
- **URI format**: `pubky://{z32_public_key}`
- **One key = one identity**: No hierarchy within a single PKARR identity

### 3.2 Multiple Identities

A user may control multiple PKARR identities. Each is independent. Cross-identity linking is an application-layer concern.

### 3.3 Identity Publication

PKARR identities may publish signed DNS records via the DHT. Optional metadata includes:
- Homeserver endpoints
- Noise static public keys (per app, per epoch)
- Service capabilities

---

## 4. Key Hierarchy and Derivation

### 4.1 Master Seed

Ring maintains a master secret for each PKARR identity. This is typically the Ed25519 seed (32 bytes).

**Invariant**: The master seed MUST NOT be exported to apps. All derivation happens inside Ring or via Ring-controlled callbacks.

### 4.2 App Seed Derivation

Ring derives an app-scoped seed:

```
APP_SEED = HKDF-SHA256(
  ikm  = MASTER_SEED,
  salt = "pubky-ring/app-seed/v1",
  info = app_id || network_id,
  len  = 32
)
```

- `app_id`: ASCII string (e.g., `"bitkit"`, `"pubky-app"`)
- `network_id`: ASCII string (e.g., `"mainnet"`, `"testnet"`, `"regtest"`)

APP_SEED remains internal to Ring.

### 4.3 Noise Seed Derivation

For apps that need to derive epoch keys locally without calling Ring:

```
NOISE_SEED = HKDF-SHA256(
  ikm  = APP_SEED,
  salt = "pubky-ring/noise-seed/v1",
  info = device_id,
  len  = 32
)
```

NOISE_SEED may be handed off to the app (encrypted) to allow local epoch derivation.

### 4.4 Device Static X25519 Derivation

Per-device, per-epoch Noise static key:

```
raw = HKDF-SHA512(
  ikm  = NOISE_SEED,
  salt = "pubky-noise-x25519:v1",
  info = device_id || epoch_le32 || role,
  len  = 32
)

NOISE_STATIC_SK = X25519_CLAMP(raw)
NOISE_STATIC_PK = X25519_BASEPOINT_MULT(NOISE_STATIC_SK)
```

- `device_id`: 16 bytes, stable per authorized device
- `epoch`: 32-bit little-endian integer, starts at 0
- `role`: ASCII string (e.g., `"transport"`, `"handoff"`) — **optional, for future domain separation**

**Current implementation note**: The `role` parameter is not yet implemented. Current derivation uses `device_id || epoch` only.

### 4.5 X25519 Clamping

Per RFC 7748:
```
sk[0]  &= 248
sk[31] &= 127
sk[31] |= 64
```

### 4.6 Local Archive Key

For encrypting local message history and preferences:

```
LOCAL_ARCHIVE_KEY = HKDF-SHA256(
  ikm  = APP_SEED,
  salt = "pubky-ring/local-archive/v1",
  info = device_id,
  len  = 32
)
```

This key encrypts local data only. MUST NOT be used for outbox envelopes.

---

## 5. Device Authorization

### 5.1 Authorization Object

When an app requests authorization from Ring, Ring returns:

```json
{
  "pkarr_pub": "<32 bytes, hex>",
  "device_id": "<16 bytes, hex>",
  "app_id": "bitkit",
  "scopes": ["transport", "storage"],
  "epoch": 0,
  "expires_at": 1704153600,
  "signature": "<64 bytes, hex>"
}
```

The signature covers all fields using the PKARR identity key.

### 5.2 Derived Material Delivery

Two models:

**Model A: Encrypted Handoff**
- Ring encrypts `(NOISE_STATIC_SK, NOISE_SEED, session_secret)` to an app-generated ephemeral X25519 public key
- Stored on homeserver as Sealed Blob
- App fetches, decrypts, caches locally
- Used for same-device Ring→Bitkit handoff

**Model B: On-Demand Derivation**
- App calls Ring to derive keys when needed
- Ring returns via callback, app uses immediately and zeroizes
- Lower secret residency, higher runtime dependency on Ring

---

## 6. Live Transport (Noise Protocol)

### 6.1 Supported Patterns

| Pattern | Use Case |
|---------|----------|
| Noise_XX_25519_ChaChaPoly_BLAKE2s | First contact (TOFU) |
| Noise_IK_25519_ChaChaPoly_BLAKE2s | Subsequent contact (server static pinned) |
| Noise_NN_25519_ChaChaPoly_BLAKE2s | Anonymous/ephemeral (testing only) |

### 6.2 Handshake Flow (XX)

```
Initiator (Client)                    Responder (Server)
     |                                      |
     |  -> e                                |  Step 1: ephemeral
     |  <- e, ee, s, es                     |  Step 2: ephemeral, DH, static
     |  -> s, se [IdentityPayload]          |  Step 3: static, DH, identity
     |                                      |
     |  ====== TRANSPORT MODE ======        |
```

### 6.3 Identity Binding

During handshake, each party sends an `IdentityPayload`:

```rust
struct IdentityPayload {
    ed25519_pub: [u8; 32],      // PKARR identity
    noise_x25519_pub: [u8; 32], // Noise static for this session
    epoch: u32,                  // Key epoch (internal, always 0 for now)
    role: Role,                  // Client or Server
    server_hint: Option<String>, // Routing hint
    expires_at: Option<u64>,     // Unix seconds
    sig: [u8; 64],               // Ed25519 signature over binding message
}
```

### 6.4 Binding Message

```
binding = BLAKE2s(
  "pubky-noise-bind:v1" ||
  pattern_tag ||
  prologue ||
  ed25519_pub ||
  local_noise_pub ||
  remote_noise_pub? ||
  epoch_le32 ||
  role_string ||
  server_hint? ||
  expires_at?
)

sig = Ed25519_Sign(ed25519_sk, binding)
```

### 6.5 Session Identifier

Derived from the Noise handshake transcript hash:

```rust
let session_id = SessionId(hs.get_handshake_hash());
```

This is a 32-byte value unique to each completed handshake. It changes on every new handshake, even between the same parties.

**Important**: Do NOT use `DH(static_a, static_b)` as a session tag. That produces a peer-pair tag which is static across sessions.

### 6.6 Transport Encryption

Post-handshake messages use the Noise transport mode with ChaCha20-Poly1305. The library handles nonce management internally.

### 6.7 No State Persistence

Implementations MUST NOT:
- Export CipherState or transport keys from snow
- Serialize Noise session state for cross-device restore

Implementations MAY persist:
- Peer identity (Ed25519 public key)
- Pinned Noise static (for IK pattern)
- Last seen timestamp
- Session metadata (not secrets)

---

## 7. Async Messaging (Outbox Envelopes)

### 7.1 Purpose

When both parties are not online simultaneously, messages are stored encrypted on the homeserver. The recipient decrypts without the sender being online.

### 7.2 Sealed Blob v2 Envelope

Extension of Sealed Blob v1 with sender identity:

```json
{
  "v": 2,
  "epk": "<base64url: sender ephemeral X25519 public key, 32 bytes>",
  "sender": "<base64url: sender PKARR public key, 32 bytes, optional>",
  "nonce": "<base64url: 24 bytes for XChaCha20>",
  "ct": "<base64url: ciphertext + 16-byte Poly1305 tag>",
  "kid": "<hex: first 8 bytes of SHA256(recipient_pk), optional>",
  "kind": "<u16: message kind, optional>",
  "sig": "<base64url: Ed25519 signature, 64 bytes, optional>"
}
```

### 7.3 Key Derivation (Envelopes)

```
shared_secret = X25519(sender_ephemeral_sk, recipient_static_pk)

key = HKDF-SHA256(
  ikm  = shared_secret,
  salt = sender_ephemeral_pk || recipient_static_pk,
  info = "pubky-envelope/v2",
  len  = 32
)
```

### 7.4 Nonce Generation

For v2 envelopes: 24 bytes random (XChaCha20-Poly1305).

For v1 envelopes (legacy): 12 bytes random (ChaCha20-Poly1305).

### 7.5 AAD Construction

```
aad = purpose || ":" || owner_pkarr_z32 || ":" || storage_path || ":" || msg_id
```

Examples:
- `handoff:8um71us...xyz:/pub/paykit.app/v0/handoff/abc123:abc123`
- `outbox:8um71us...xyz:/pub/paykit.app/v0/outbox/peer123/msg456:msg456`

### 7.6 Optional Sender Signature

For messages requiring strong sender authenticity:

```
sig = Ed25519_Sign(
  sender_ed25519_sk,
  BLAKE3("pubky-envelope-sig/v2" || v || epk || sender || nonce || ct || kind)
)
```

### 7.7 Storage Layout

```
/pub/paykit.app/v0/outbox/{recipient_z32}/{msg_id}.pke
```

- `recipient_z32`: z-base-32 encoded recipient PKARR public key
- `msg_id`: 16 or 32 bytes random, hex or base32 encoded
- `.pke`: Pubky Encrypted Envelope

### 7.8 Message Kinds

| Range | Purpose |
|-------|---------|
| 0-99 | Core protocol (ACK, ERROR, PING) |
| 100-199 | Paykit (payment requests, receipts, subscriptions) |
| 200-299 | Pubky App (social, follows, posts) |
| 0xFF00-0xFFFF | Extensions |

Paykit-specific kinds:
| Kind | Name |
|------|------|
| 100 | PAYMENT_REQUEST |
| 101 | PAYMENT_RESPONSE |
| 102 | SUBSCRIPTION_PROPOSAL |
| 103 | SUBSCRIPTION_ACCEPT |
| 104 | SUBSCRIPTION_REJECT |
| 105 | RECEIPT |
| 106 | ACK |
| 199 | ERROR |

### 7.9 Replay and Idempotency

Recipients MUST:
- Treat `msg_id` as idempotency key
- Maintain set of seen `msg_id` per sender
- Ignore duplicates

Ordering is not guaranteed. Applications must handle out-of-order delivery.

---

## 8. Session and Message Binding

### 8.1 Live Session Binding

For messages over active Noise transport:
- Include `session_id` (handshake hash) in message payload
- Receiver verifies session_id matches current session
- Prevents message injection across sessions

### 8.2 Envelope Binding

For async envelopes:
- AAD binds ciphertext to storage path and owner
- `sender` field (when present) identifies originator
- `sig` field (when present) provides non-repudiation

### 8.3 Peer Identity

Live transport: Ed25519 public key from verified `IdentityPayload`
Async envelope: `sender` field (must be verified against signature if present)

---

## 9. Key Rotation

### 9.1 Epoch Increment

When rotating Noise static keys:
1. Increment `epoch` in Ring
2. Derive new `NOISE_STATIC_SK` using new epoch
3. Publish new public key to PKARR (optional)
4. Accept messages encrypted to old epoch during grace period

### 9.2 Epoch Fallback

When decrypting envelopes:
```
for epoch in [current, current-1, current-2]:
    sk = derive_noise_static(epoch)
    if decrypt(envelope, sk).is_ok():
        return plaintext
return DecryptionError
```

Grace window: 2-3 previous epochs.

### 9.3 PKARR Publication

Optional: publish current epoch and Noise static public key in PKARR DNS records for discovery.

---

## 10. Backup and Restore

### 10.1 Device Restore

1. Restore PKARR identity seed to Ring
2. Re-derive `APP_SEED`, `NOISE_SEED`, `NOISE_STATIC_SK` from Ring
3. Re-derive `LOCAL_ARCHIVE_KEY` to decrypt local history
4. Poll homeserver outbox folders for missed messages
5. No transport state is restored (re-handshake required)

### 10.2 Homeserver Backup

Only encrypted blobs are backed up. Restoring homeserver state does not expose plaintext.

### 10.3 Local Archive

Optional: encrypt full message history for backup using `LOCAL_ARCHIVE_KEY`. Store separately from outbox envelopes.

---

## 11. Security Considerations

### 11.1 Memory Hygiene

- Use `zeroize` crate for secret buffers
- Wrap secrets in `Zeroizing<[u8; 32]>`
- Minimize copies of key material
- Never log secrets or plaintext

### 11.2 Platform Limitations

iOS/Android do not provide true secure memory. Best-effort mitigations:
- Derive on demand, use immediately, zeroize
- Don't persist transport secrets
- Use platform keychain/keystore for long-term secrets

### 11.3 Invalid Peer Keys

Before performing X25519 DH, verify peer public key is not:
- All zeros
- Low-order point

```rust
fn shared_secret_nonzero(sk: &[u8; 32], pk: &[u8; 32]) -> bool {
    let shared = x25519(*sk, *pk);
    shared.iter().any(|&b| b != 0)
}
```

Reject handshakes with invalid peer keys.

### 11.4 Timing Attacks

ChaCha20-Poly1305 verification is constant-time. No additional measures required for AEAD.

Ed25519 signature verification uses constant-time comparison. No additional measures required.

### 11.5 Forward Secrecy

Live transport: provided by ephemeral X25519 keys in Noise handshake.
Async envelopes: provided by sender's ephemeral X25519 key per message.

### 11.6 Traffic Analysis

Out of scope for v1. Future mitigations:
- Padding messages to fixed sizes
- Randomized polling intervals
- Decoy traffic

---

## 12. Implementation Reference

### 12.1 Repositories

| Repository | Purpose |
|------------|---------|
| `pubky-ring` | Identity management, seed custody, authorization |
| `pubky-noise` | Noise handshake, transport, envelopes |
| `paykit-rs` | Payment protocols, receipts, subscriptions |
| `bitkit-android` / `bitkit-ios` | Wallet integration |
| `pubky-core` | Homeserver, SDK, storage |

### 12.2 Key Files

| File | Purpose |
|------|---------|
| `pubky-noise/src/kdf.rs` | Key derivation functions |
| `pubky-noise/src/ring.rs` | RingKeyProvider trait |
| `pubky-noise/src/sealed_blob.rs` | Envelope encryption |
| `pubky-noise/src/session_id.rs` | Session identifier |
| `pubky-noise/src/transport.rs` | Noise transport wrapper |
| `pubky-noise/src/identity_payload.rs` | Identity binding |

### 12.3 Test Vectors

Test vectors for interoperability testing are defined in `pubky-noise/tests/`.

---

## Appendix A: Domain Separation Strings

| Constant | Value |
|----------|-------|
| App seed salt | `"pubky-ring/app-seed/v1"` |
| Noise seed salt | `"pubky-ring/noise-seed/v1"` |
| X25519 derivation salt | `"pubky-noise-x25519:v1"` |
| Local archive salt | `"pubky-ring/local-archive/v1"` |
| Identity binding prefix | `"pubky-noise-bind:v1"` |
| Envelope key info (v1) | `"paykit-sealed-blob-v1"` |
| Envelope key info (v2) | `"pubky-envelope/v2"` |
| Envelope signature prefix | `"pubky-envelope-sig/v2"` |

---

## Appendix B: Encoding Reference

| Data | Encoding |
|------|----------|
| PKARR public key in URIs | z-base-32 |
| Keys in JSON envelopes | base64url (no padding) |
| Keys in handoff payloads | hex |
| Message IDs | hex or base32 |
| Paths | ASCII, alphanumeric + `/-_.` |

---

## Appendix C: Comparison with Current Implementation

This section documents gaps between the spec and current implementation.

### C.1 Implemented

| Feature | Status | Location |
|---------|--------|----------|
| X25519 derivation with device_id + epoch | ✅ Implemented | `pubky-noise/src/kdf.rs` |
| Session ID from handshake hash | ✅ Implemented | `pubky-noise/src/session_id.rs` |
| Sealed Blob v1 encryption | ✅ Implemented | `pubky-noise/src/sealed_blob.rs` |
| RingKeyProvider trait | ✅ Implemented | `pubky-noise/src/ring.rs` |
| Identity binding in handshake | ✅ Implemented | `pubky-noise/src/identity_payload.rs` |
| Secure handoff (Ring → Bitkit) | ✅ Implemented | `pubky-ring/src/utils/actions/paykitConnectAction.ts` |

### C.2 Not Yet Implemented

| Feature | Status | Notes |
|---------|--------|-------|
| APP_SEED derivation layer | ❌ Not implemented | Currently uses ed25519 seed directly |
| Role parameter in X25519 derivation | ❌ Not implemented | Info is `device_id \|\| epoch` only |
| LOCAL_ARCHIVE_KEY derivation | ❌ Not implemented | Needs new function in kdf.rs |
| Sealed Blob v2 (XChaCha20, sender field) | ❌ Not implemented | v1 uses ChaCha20-Poly1305 |
| Epoch fallback decryption | ❌ Not implemented | Single epoch only |
| Message kind field in envelopes | ❌ Not implemented | Purpose field exists but not typed |

---

*This specification is maintained in the Pubky ecosystem repositories.*

