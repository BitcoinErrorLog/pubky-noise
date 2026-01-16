---
name: Crypto Spec Update Final
overview: Complete update to PUBKY_CRYPTO_SPEC.md v2.4 and pubky-noise codebase incorporating Antoine's January 2026 review, secondary review corrections, and final specification artifacts. Includes Sealed Blob v2 header schema, AAD construction format, canonicalization rules, signature construction, and identity binding specification. All details self-contained.
todos:
  - id: header-schema
    content: Add Sealed Blob v2 header schema (field ids, types, CBOR rules, resource bounds) to Section 7.2
    status: completed
  - id: signature-construction
    content: Add signature construction subsection (header_no_sig, sig_input, verification) to Section 7.2
    status: completed
  - id: aad-format
    content: Add exact AAD byte construction format to Section 7.5
    status: completed
  - id: canonicalization
    content: Add complete canonicalization rules (PeerId, ContextId, path, CBOR) to Section 7.12
    status: completed
  - id: key-separation
    content: Add Section 4.8 InboxKey vs TransportKey separation rules
    status: completed
  - id: ack-encryption
    content: Add ACK encryption rules (Sealed Blob to sender InboxKey via PKARR only) to Section 7.9
    status: completed
  - id: ack-payload
    content: Update ACK payload to minimal format in Section 7.9
    status: completed
  - id: no-queued-noise
    content: Add normative MUST NOT for queued Noise ciphertext to Section 1.4
    status: completed
  - id: prologue-freeze
    content: Freeze prologue as fixed constant in Section 6.2 (with rationale note)
    status: completed
  - id: epoch-decision
    content: Freeze epoch encoding as LE32 or remove entirely (team decision)
    status: completed
  - id: nonce-handling
    content: Add transport nonce handling note (64-bit LE, no manual management) to Section 6.6
    status: completed
  - id: ring-bounds
    content: Add Ring state bounds (MUST bounded, recommended values) to Section 5.3
    status: completed
  - id: dos-kid-rule
    content: "Add rule: unknown inbox_kid = drop WITHOUT Ring call to Section 1.2"
    status: completed
  - id: cbor-resource-bounds
    content: Add CBOR resource bounds (header_len, msg_id length, depth limits) to Section 7.2
    status: completed
  - id: pinning-rules
    content: Add XX→IK upgrade and downgrade prevention rules to Section 6.8
    status: completed
  - id: identity-payload
    content: Update IdentityPayload wire format (remove epoch, document role) in Section 6.3
    status: completed
  - id: identity-binding-message
    content: Add IdentityPayload binding message bytes specification to Section 6.4
    status: completed
  - id: terminology
    content: Add Thread/Session/ContextId/PairContextId/InboxKey/TransportKey definitions to Section 7.7
    status: completed
  - id: sender-peerid
    content: Define sender_peerid explicitly in Section 7.6
    status: completed
  - id: server-hint
    content: Clarify server_hint as non-normative metadata in Section 6.3
    status: completed
  - id: secure-handoff
    content: Define Secure Handoff in Section 7.8
    status: completed
  - id: cross-refs
    content: Add ContextId vs PairContextId vs PeerPairFingerprint cross-reference with exact derivations
    status: completed
  - id: xchacha-note
    content: Add XChaCha20 non-standardization acknowledgment to Section 2.1
    status: completed
  - id: nonce-sizes
    content: Clarify Noise 64-bit counter vs Sealed Blob 24-byte nonce in Section 7.4
    status: completed
  - id: session-binding
    content: Correct session binding threat model in Section 8.1
    status: completed
  - id: grace-period
    content: Remove grace period as protocol concept in Section 9.1
    status: completed
  - id: aad-rationale
    content: Add AAD rationale (not SipHash, complementary to Noise, never parsed) to Section 7.5
    status: completed
  - id: ack-mitigations
    content: Add jitter, batching, polling guidance to Section 7.9
    status: completed
  - id: ack-tradeoff
    content: Add ACK round-trip trade-off note to Section 7.9
    status: completed
  - id: secure-element
    content: Add Section 5.4 Platform Keychain Integration (corrected for iOS limitations)
    status: completed
  - id: ring-isolation
    content: Strengthen Ring network isolation in Section 1.1
    status: completed
  - id: noise-relationship
    content: Add Section 1.5 Relationship to Noise Protocol
    status: completed
  - id: symmetry-section
    content: Add Section 6.9 Protocol Symmetry with decision point
    status: completed
  - id: clamping-entropy
    content: Add X25519 clamping entropy documentation to Section 4.5
    status: completed
  - id: dh-verification
    content: Add multi-step DH verification note to Section 6.2
    status: completed
  - id: wot-scope
    content: Add web-of-trust out-of-scope note to Section 7.6
    status: completed
  - id: code-epoch
    content: "CODE: Remove epoch from IdentityPayload in identity_payload.rs"
    status: completed
  - id: code-role
    content: "CODE: Document role field in identity_payload.rs"
    status: completed
  - id: code-dummyring
    content: "CODE: Add DummyRing test-only warning in pubky_ring.rs"
    status: completed
  - id: code-device-id
    content: "CODE: Add minimum device_id length check (16 bytes) in kdf.rs"
    status: completed
  - id: code-prologue
    content: "CODE: Change prologue to fixed constant in client.rs"
    status: completed
  - id: code-epoch-tracking
    content: "CODE: Remove seen_client_epoch mechanism from server.rs"
    status: completed
  - id: code-server-hint
    content: "CODE: Document server_hint as non-normative in client.rs"
    status: completed
  - id: code-inbox-kid
    content: "CODE: Verify inbox_kid derivation matches spec in sealed_blob.rs"
    status: completed
  - id: code-streaming
    content: "CODE: Document or integrate streaming.rs"
    status: completed
  - id: code-xx-tests
    content: "CODE: Add XX pattern interoperability tests"
    status: completed
  - id: code-error-docs
    content: "CODE: Document error classification in errors.rs"
    status: completed
  - id: code-mobile-manager
    content: "CODE: Address ConnectionStatus persistence and laddered backoff in mobile_manager.rs"
    status: completed
  - id: code-storage-queue
    content: "CODE: Refactor tokio::time::sleep to non-blocking in storage_queue.rs"
    status: completed
  - id: evaluate-split
    content: Evaluate splitting spec into crypto/messaging documents
    status: completed
---

# PUBKY_CRYPTO_SPEC Update Plan - Complete and Self-Contained

**Spec Version**: PUBKY_CRYPTO_SPEC.md v2.4 -> v2.5

**Code**: pubky-noise commit b8c0246be56c

**Target File**: [pubky-core/docs/PUBKY_CRYPTO_SPEC.md](pubky-core/docs/PUBKY_CRYPTO_SPEC.md)

This plan is self-contained. All context required to implement these changes is included below.

---

## Part A: Core Specification Artifacts

These three artifacts resolve the majority of interoperability ambiguity and should be implemented first.

### A.1 Sealed Blob v2 Header Schema

Add complete normative header schema to Section 7.2.

**Wire Format**:

```
magic: 0x53 0x42 0x32 ("SB2", 3 bytes)
version: u8 (value: 2)
header_len: u16 big-endian (MUST be <= 2048 bytes)
header_bytes: [u8; header_len] (deterministic CBOR)
ciphertext: [u8] (XChaCha20-Poly1305 output, includes 16-byte tag)
```

**Resource Bounds (DoS Prevention)**:

- `header_len` MUST be <= 2048 bytes
- `msg_id` length MUST be <= 128 characters
- Reject indefinite-length CBOR encodings
- Reject nested maps/arrays beyond depth 2
- Reject any CBOR with more than 16 top-level keys

**Header Fields (Deterministic CBOR map with integer keys)**:

| Key | Field Name | Type | Required | Description |

|-----|------------|------|----------|-------------|

| 0 | context_id | bytes(32) | REQUIRED (Paykit) | Thread identifier, raw bytes (see F.1) |

| 1 | created_at | uint | RECOMMENDED | Unix timestamp seconds |

| 2 | expires_at | uint | REQUIRED (Paykit) | Expiration timestamp |

| 3 | inbox_kid | bytes(16) | REQUIRED | Key identifier for recipient InboxKey |

| 4 | msg_id | text | REQUIRED (Paykit) | Idempotency key, ASCII, max 128 chars |

| 5 | nonce | bytes(24) | REQUIRED | XChaCha20-Poly1305 nonce, random |

| 6 | purpose | text | OPTIONAL | Hint: "request", "proposal", "ack" |

| 7 | recipient_peerid | bytes(32) | REQUIRED | Recipient Ed25519 public key |

| 8 | sender_ephemeral_pub | bytes(32) | REQUIRED | Sender ephemeral X25519 for DH |

| 9 | sender_peerid | bytes(32) | REQUIRED | Sender Ed25519 public key |

| 10 | sig | bytes(64) | REQUIRED (Paykit) | Ed25519 signature for authenticity |

**msg_id Type Decision**: `msg_id` is **text** (not bytes) with strict constraints:

- ASCII characters only (0x20-0x7E)
- Max length 128 characters
- When used in storage paths, use as-is (already path-safe if ASCII)
- This maintains compatibility with v2.4 and avoids encoding ambiguity

**sig Field Requirement**: For Paykit purposes (`purpose` in {"request", "proposal", "ack"}), the `sig` field is REQUIRED to prove sender identity. For non-Paykit or anonymous messaging use cases, `sig` MAY be omitted.

**Deterministic CBOR Rules** (per RFC 8949 Section 4.2):

- Map keys MUST be integers (not text)
- Keys MUST be sorted by numeric value (0, 1, 2, ...)
- All integers in shortest encoding (no leading zeros)
- All byte strings and text in definite-length encoding
- No indefinite-length maps or arrays
- No floats (forbidden)
- No duplicate keys
- No nested maps or arrays beyond depth 2

**Authentication Scope**: The ENTIRE `header_bytes` is authenticated via inclusion in AAD. All fields are cryptographically bound to the ciphertext.

**inbox_kid Derivation**:

```
inbox_kid = first_16_bytes(SHA256(recipient_inbox_x25519_pub))
```

The `inbox_kid` identifies the recipient's InboxKey (not TransportKey) for O(1) key selection. Unknown `inbox_kid` MUST be rejected immediately WITHOUT calling Ring derivation.

---

### A.1.1 Signature Construction

The `sig` field (key 10) is an Ed25519 signature that proves sender authenticity. Because the signature cannot include itself, the signing process uses a modified header.

**Signature Input Construction**:

```
header_no_sig = CBOR_encode(header_map with key 10 omitted)
sig_input = BLAKE3("pubky-envelope-sig/v2" || aad || header_no_sig || ciphertext)
sig = Ed25519_Sign(sender_peerid_sk, sig_input)
```

Where:

- `header_no_sig`: Deterministic CBOR encoding of header map WITHOUT key 10
- `aad`: The full AAD bytes computed using `header_no_sig` (see A.2)
- `ciphertext`: The encrypted payload bytes (after header in wire format)
- `sender_peerid_sk`: The sender's Ed25519 private key corresponding to `sender_peerid`

**Important**: When computing AAD for signature purposes, use `header_no_sig` (without signature), not the full header.

**Signature Verification**:

1. Extract `sig` (key 10) from received header
2. Re-encode header without key 10 to produce `header_no_sig`
3. Compute `aad` using `header_no_sig`: `aad = aad_prefix || owner || path || header_no_sig`
4. Compute `sig_input = BLAKE3("pubky-envelope-sig/v2" || aad || header_no_sig || ciphertext)`
5. Verify `sig` against `sender_peerid` (key 9) using Ed25519

**Trust Rule**: Without a valid signature, treat `sender_peerid` as routing metadata only, not proven identity. For Paykit purposes (request, proposal, ack), missing or invalid `sig` MUST cause message rejection.

---

### A.2 AAD Byte Construction Format

Add exact normative AAD format to Section 7.5.

**AAD Construction (Normative)**:

```
aad = aad_prefix || owner_peerid_bytes || canonical_path_bytes || header_bytes
```

Where:

- `aad_prefix`: ASCII bytes `"pubky-envelope/v2:"` (18 bytes, includes colon)
- `owner_peerid_bytes`: Raw 32-byte Ed25519 public key of storage owner
- `canonical_path_bytes`: UTF-8 bytes of canonical storage path (see A.3)
- `header_bytes`: Deterministic CBOR serialization of header (see A.1)

**No delimiters between components**. The fields are concatenated directly:

- aad_prefix: 18 bytes (fixed length)
- owner_peerid_bytes: 32 bytes (fixed length)
- canonical_path_bytes: variable length
- header_bytes: variable length (self-delimiting CBOR)

**AAD is never parsed.** Both sender and receiver compute the exact same byte concatenation from known values. The "self-delimiting" property of CBOR is not used for parsing; it merely means no explicit length prefix is needed.

**Storage Owner**: The peer who writes the object to their homeserver storage:

- Payment requests: sender is owner
- ACKs: receiver is owner (writes to their storage)
- Handoff: Ring user is owner

**Purpose-Specific AAD**: The `purpose` field (key 6) in header provides semantic disambiguation but is authenticated as part of header_bytes, not separately.

**ACK-Specific AAD**: ACK objects use purpose="ack" in the header. The path includes the acked message ID:

```
/pub/paykit.app/v0/acks/{object_type}/{context_id_z32}/{acked_msg_id}
```

---

### A.3 Canonicalization Rules

Add complete normative canonicalization rules to Section 7.12.

**PeerId Canonical Bytes**:

- In AAD, headers, and all cryptographic operations: raw 32-byte Ed25519 public key
- z-base-32 (52 chars, lowercase) is for URIs and display ONLY
- Implementations MUST use raw bytes for any crypto operation

**ContextId Canonical Bytes**:

- In headers and AAD: raw 32 bytes
- Hex (64 lowercase chars) and z-base-32 (52 chars) are display/path encoding ONLY
- Implementations MUST decode to 32 raw bytes before AAD computation
- ContextId is application-chosen, typically random (see F.1)

**inbox_kid Canonical Bytes**:

- In headers: raw 16 bytes (CBOR bstr)
- Hex (32 lowercase chars) is for JSON/display ONLY

**msg_id Encoding**:

- In headers: text (ASCII, max 128 chars)
- In paths: use as-is (ASCII is path-safe)
- In JSON: use as-is (already text)

**Path Canonicalization Rules**:

| Rule | Requirement |

|------|-------------|

| Encoding | UTF-8 bytes, no BOM |

| Leading slash | REQUIRED (must start with `/`) |

| Trailing slash | PROHIBITED (except root `/`) |

| Duplicate slashes | PROHIBITED (no `//`) |

| Dot segments | PROHIBITED (no `.` or `..`) |

| Percent encoding | PROHIBITED (paths are literal bytes) |

| Unicode normalization | PROHIBITED (treat bytes as-is) |

| Character set | ASCII alphanumeric + `/-_.` only |

| Max length | 1024 bytes |

**Path Canonicalization is NORMATIVE**: Implementations that produce different byte sequences for the same logical path will fail AAD verification.

**Valid path examples**:

```
/pub/paykit.app/v0/requests/abc123/req_001
/pub/paykit.app/v0/acks/request/abc123/req_001
```

**Invalid path examples**:

```
/pub/paykit.app/v0/requests/abc123/req_001/   (trailing slash)
/pub/paykit.app/v0//requests/abc123/req_001   (duplicate slash)
/pub/paykit.app/v0/./requests/abc123/req_001  (dot segment)
pub/paykit.app/v0/requests/abc123/req_001     (no leading slash)
```

---

## Part B: Key Separation and Encryption Rules

### B.1 InboxKey vs TransportKey Separation

Add new Section 4.8 "Key Role Separation".

**InboxKey**:

- X25519 key used ONLY for Sealed Blob stored delivery
- Published in PKARR KeyBinding for senders to encrypt to
- `inbox_kid` derived from this key

**TransportKey**:

- X25519 key used ONLY for Noise static key in live transport
- Used in XX and IK handshake patterns
- May be published in PKARR for IK pattern

**Reuse Rule (MVP)**:

- Reusing the same X25519 key for both InboxKey and TransportKey is PROHIBITED in MVP
- Domain separation via HKDF info strings provides safety if reuse is ever allowed
- Future versions MAY allow reuse with explicit configuration and domain separation labels

**Rationale**: Separating keys limits blast radius of key compromise and simplifies key rotation.

### B.2 ACK Encryption Rules

Add to Section 7.9 "Encrypted ACK Protocol".

**ACK objects are stored delivery messages and MUST be Sealed Blob v2 encrypted.**

**Encryption target**: ACKs are encrypted to the **original sender's InboxKey**. The InboxKey MUST be discovered from the sender's **PKARR KeyBinding** (which publishes InboxKeys). Do NOT use the Noise transport endpoint as an InboxKey source—that endpoint publishes TransportKeys, not InboxKeys.

**Key Discovery for ACKs**:

- Fetch sender's PKARR KeyBinding
- Extract the InboxKey entry (not TransportKey)
- Derive `inbox_kid` from that InboxKey
- Encrypt ACK to that InboxKey

**ACK Header Fields**:

- `purpose`: "ack"
- `context_id`: Same as original message (32 raw bytes)
- `inbox_kid`: Derived from original sender's InboxKey
- `sender_ephemeral_pub`: Fresh ephemeral X25519 for this ACK
- `sender_peerid`: ACK sender's Ed25519 public key
- `recipient_peerid`: Original message sender's Ed25519 public key
- `sig`: REQUIRED (ACK is a Paykit object)

**ACK Plaintext Payload** (inside ciphertext):

```json
{
  "acked_msg_id": "req_001",
  "error_code": 0,
  "error_text": null
}
```

| Field | Required | Description |

|-------|----------|-------------|

| acked_msg_id | REQUIRED | ID of message being acknowledged (text, matches original msg_id) |

| error_code | OPTIONAL | Machine-readable error (0 = success, nonzero = error) |

| error_text | OPTIONAL | Human-readable error description |

**Removed from normative spec**: `msg_id`, `status`, `created_at` for the plaintext payload. These are app-layer concerns. The header already contains `msg_id` for the ACK itself.

**Note on context_id in payload**: The authenticated header carries `context_id` as 32 raw bytes. If the plaintext payload includes `context_id` for app convenience, it is display encoding (hex) only and MUST match the header value when decoded.

**ACK Storage Path**:

```
/pub/paykit.app/v0/acks/{object_type}/{context_id_z32}/{acked_msg_id}
```

Where `context_id_z32` is z-base-32 encoding for path compatibility.

**Round-Trip Trade-off**: The ACK protocol requires multiple round-trips (sender polls receiver's storage). This overhead is an inherent trade-off for async stored delivery—there is no persistent connection to push acknowledgments. For latency-critical applications, use live Noise transport instead.

---

## Part C: Normative Protocol Rules

### C.1 No Queued Noise Ciphertext

Add explicit normative rule to Section 1.4.

"**MUST NOT** store Noise transport ciphertext for offline delivery. Noise session keys are not exported; if session state is lost, queued Noise ciphertext becomes permanently undecryptable. Stored delivery MUST use Sealed Blob only."

### C.2 Prologue Policy

Add to Section 6.2.

"The prologue MUST be a fixed constant per protocol version. For v1: `b\"pubky-noise-v1\"` (14 bytes). Arbitrary or caller-supplied prologues are PROHIBITED to prevent covert channels and interoperability failures."

**Rationale**: Antoine suggested making prologue a method parameter for flexibility. We chose a fixed constant instead because:

1. Covert channels: Arbitrary prologues could be used to leak information
2. Interoperability: All implementations must agree on prologue for handshake to succeed
3. Simplicity: One less parameter to configure incorrectly
4. Version binding: Prologue changes with protocol version, not per-call

### C.3 Epoch Encoding Decision

Add to Section 4.4. **Team decision required**:

**Option A (Freeze)**: "Epoch MUST be encoded as 32-bit little-endian bytes in all derivation contexts. This encoding is normative and MUST be consistent across all implementations regardless of implementation language."

**Option B (Remove)**: "Remove epoch from all cross-device derivation. Use key_version only. Epoch was Ring-internal and should not appear in any derivation info accessible to apps."

Recommend Option B for simplicity.

### C.4 Transport Nonce Handling

Add to Section 6.6.

"Noise uses a 64-bit little-endian counter as the nonce, encoded into a 96-bit (12-byte) nonce as per the Noise specification. The `snow` library manages this counter internally. Implementations MUST NOT manually manage Noise nonces. Attempting to set or export nonces breaks the security model."

### C.5 X25519 Clamping Entropy

Add to Section 4.5.

"X25519 key derivation applies clamping to the 32-byte scalar:

- Bits 0, 1, 2 are cleared (scalar is multiple of 8)
- Bit 255 is cleared
- Bit 254 is set

This clamping is mandatory per RFC 7748 and is applied automatically by the `x25519-dalek` crate. The clamping removes approximately 3 bits of entropy from the derived key, which is acceptable given the 252-bit security level of Curve25519. Implementations MUST NOT skip or modify clamping."

### C.6 Multi-Step DH Verification

Add to Section 6.2.

"The Noise XX pattern performs multiple Diffie-Hellman operations during the handshake. The `snow` library verifies the result of each DH step internally, rejecting low-order points that would produce all-zero shared secrets. Implementations using `snow` do not need to add additional verification; the library handles this. Implementations using other Noise libraries MUST verify that each DH result is not all-zeros before proceeding."

---

## Part D: Bounded State and DoS Hardening

### D.1 Ring State Bounds

Add to Section 5.3.

**Normative Requirements**:

- Ring state MUST be bounded (not unbounded growth)
- Caches keyed by remote/attacker-controlled inputs MUST have explicit size limits
- Caches MUST implement eviction policy (e.g., LRU)
- Ring MUST rate-limit derivation calls per app

**Recommended Defaults** (non-normative):

- MAX 16 active inbox keys per (identity, app_id)
- MAX 4 active transport keys per (identity, app_id, device_id)
- Rate limit: 10 derivation calls per second per app

### D.2 DoS Threat Model

Add to Section 1.2.

| Threat | Mitigation |

|--------|------------|

| Attacker floods with arbitrary inbox_kid | Bounded keyring. Unknown inbox_kid MUST be rejected immediately WITHOUT calling Ring derivation. |

| Attacker floods with arbitrary context_id | Apps MUST NOT create unbounded state keyed by context_id. Limit tracked contexts. |

| Attacker sends oversized CBOR headers | Reject header_len > 2048. Reject depth > 2. Reject > 16 keys. |

| Handshake rate exhaustion | Rate limit per IP (gameable). Defense in depth via homeserver rate limiting. |

| Epoch spoofing via UDP | Remove epoch from wire format entirely. Tracking becomes meaningless. |

**Critical Rule**: When `inbox_kid` in a Sealed Blob header does not match any known key, the receiver MUST drop the message WITHOUT calling any Ring derivation function. This prevents attackers from grinding the Ring API with random kid values.

---

## Part E: Identity Binding and Pinning

### E.1 Pinning Rules

Add to Section 6.8.

**What is Pinned**:

- Peer Ed25519 identity key (PeerId)
- Optionally: peer TransportKey X25519 static (if verified via PKARR KeyBinding)

**XX to IK Upgrade Rules**:

1. First contact MUST use XX pattern (TOFU)
2. After successful XX handshake, MAY pin the peer's TransportKey
3. Upgrade to IK pattern is allowed ONLY if:

   - A verified KeyBinding for the peer exists (from PKARR), AND
   - The TransportKey in KeyBinding matches the pinned key, AND
   - The upgrade is explicitly approved by app policy or user action

4. In MVP, automatic XX→IK upgrade for arbitrary peers is PROHIBITED

**Downgrade Prevention**:

- Once IK is established with a peer, downgrade to XX MUST require explicit user action or key rotation event
- If peer's PKARR KeyBinding rotates TransportKey, require re-verification before accepting new key

**PKARR Key Rotation**:

- When peer publishes new TransportKey via PKARR, the old pinned key becomes stale
- Receiver SHOULD fetch updated KeyBinding before next connection
- If new key differs from pinned key, treat as new TOFU event (XX pattern)

### E.2 IdentityPayload Wire Format

Update Section 6.3.

```rust
struct IdentityPayload {
    peerid: [u8; 32],              // Ed25519 public key (PKARR identity)
    role: Role,                     // Client or Server (see note)
    server_hint: Option<String>,    // Routing hint (non-normative, see below)
    hint_expires_at: Option<u64>,   // TTL for server_hint only
    sig: [u8; 64],                  // Ed25519 signature over binding message
}
```

**Removed from wire format**: `epoch`, `noise_x25519_pub` (Noise handshake already carries static keys).

**role Field**: The Noise state machine knows which side it is. The `role` field exists for application-layer disambiguation when needed (e.g., logging, debugging). It is not cryptographically significant.

**server_hint**: This is OPTIONAL, non-normative metadata:

- MAY be omitted from identity payloads
- MAY be rotated freely without affecting identity
- SHOULD NOT be considered part of core identity binding
- If present in signed payloads, authenticity is verified but semantics/reachability are not enforced

### E.3 IdentityPayload Binding Message

Add to Section 6.4.

The `sig` field in `IdentityPayload` is computed over a binding message that ties the Ed25519 identity to the Noise handshake.

**Binding Message Construction**:

```
binding_message = BLAKE3(
    "pubky-noise-binding/v1" ||
    peerid ||                    // 32 bytes: Ed25519 public key
    noise_static_pub ||          // 32 bytes: X25519 public key from handshake
    role_byte ||                 // 1 byte: 0x00=Client, 0x01=Server
    remote_static_pub            // 32 bytes: peer's X25519 public key
)

sig = Ed25519_Sign(peerid_sk, binding_message)
```

Where:

- `peerid`: The sender's Ed25519 public key
- `noise_static_pub`: The sender's X25519 static public key used in this handshake
- `role_byte`: `0x00` for Client, `0x01` for Server
- `remote_static_pub`: The peer's X25519 static public key from the handshake

**Verification**:

1. Extract `peerid` and `sig` from received IdentityPayload
2. Obtain `noise_static_pub` from Noise handshake state (peer's static key)
3. Compute `binding_message` using above formula
4. Verify `sig` against `peerid` using Ed25519

**Security Properties**:

- Binds Ed25519 identity to specific X25519 Noise static key
- Binds to specific handshake instance (includes remote key)
- Prevents identity payload replay across different sessions

---

## Part F: Terminology and Definitions

### F.1 Core Terminology

Add to Section 7.7.

| Term | Definition |

|------|------------|

| **Thread** | A logical conversation between two peers about a specific topic (e.g., payment negotiation). May span multiple messages and Noise sessions. |

| **Session** | A live Noise transport connection. Unique per handshake. Identified by `session_id` (handshake hash). |

| **ContextId** | Opaque 32-byte identifier chosen by the application for a specific thread. RECOMMENDED to be random. NOT derived from peer keys. Used for thread routing. |

| **PairContextId** | Optional deterministic identifier derived from peer public keys. For diagnostics, correlation, and rate-limiting. NOT for thread routing. |

| **InboxKey** | X25519 key used for Sealed Blob stored delivery. |

| **TransportKey** | X25519 key used for Noise static in live transport. |

| **inbox_kid** | 16-byte identifier derived from InboxKey public key for O(1) key lookup. |

**ContextId vs PairContextId Distinction**:

- **ContextId**: Application-chosen, typically random, identifies a specific thread. Used in storage paths and message routing. Different threads between the same peers have different ContextIds.
- **PairContextId**: Deterministic, derived from sorted peer public keys via `SHA256("paykit:v0:pair-context:" || first_z32 || ":" || second_z32)`. Same value for all threads between the same peer pair. Used ONLY for diagnostics, logging, rate-limiting, and cross-thread correlation. NEVER used for thread routing or storage paths.

**Important**: Thread routing uses `context_id`. Pair-level correlation uses `pair_context_id`. Never the other way around. Confusing these causes the ambiguity Antoine identified.

**Thread != Session**: A single thread may span multiple sessions (e.g., reconnections). A single session may carry messages for multiple threads.

### F.2 sender_peerid Definition

Add to Section 7.6.

"The `sender_peerid` is the PKARR Ed25519 public key of the sending identity. In Pubky's P2P model, this is the root identity (no external PKI hierarchy). The signature in key 10, when present, proves the sender controls the corresponding private key. For Paykit objects, signature is REQUIRED.

**Web-of-Trust / Identity Federation**: External trust models (PGP web-of-trust, X.509 hierarchies, DID verification) are out of scope for PUBKY_CRYPTO_SPEC v2.x. The Ed25519 key is self-certifying; trust establishment is an application-layer concern."

### F.3 Secure Handoff Definition

Add to Section 7.8.

"Secure Handoff is the process by which Ring transfers derived key material to an app (e.g., Bitkit) for local use. The handoff blob is Sealed Blob encrypted to an app-generated ephemeral key. Ring does not access the homeserver directly; the app writes the handoff blob to its storage path."

### F.4 ContextId vs PairContextId vs PeerPairFingerprint

Add cross-reference between Section 7.7.2 and Section 8.5.

| Identifier | Purpose | Derivation | User-Facing | Used in Paths |

|------------|---------|------------|-------------|---------------|

| ContextId | Thread routing, storage paths | App-chosen, random | No | Yes |

| PairContextId | Diagnostics, correlation, rate limits | See below | No | No |

| PeerPairFingerprint | TOFU verification, out-of-band comparison | See below | Yes (displayed) | No |

**PairContextId Derivation**:

```
sorted_keys = sort([local_peerid_z32, remote_peerid_z32])
pair_context_id = SHA256("paykit:v0:pair-context:" || sorted_keys[0] || ":" || sorted_keys[1])
```

Result is 32 bytes. Used internally for diagnostics.

**PeerPairFingerprint Derivation**:

```
sorted_keys = sort([local_peerid_bytes, remote_peerid_bytes])  // 32-byte raw keys
fingerprint_full = BLAKE3("pubky-fingerprint/v1:" || sorted_keys[0] || sorted_keys[1])
peer_pair_fingerprint = first_8_bytes(fingerprint_full)
```

Result is 8 bytes, displayed as 16 hex characters (e.g., `a1b2c3d4e5f67890`). Used for out-of-band verification between users.

These serve different purposes and MUST NOT be conflated.

---

## Part G: Clarifications and Corrections

### G.1 XChaCha20-Poly1305

Add to Section 2.1.

"XChaCha20-Poly1305 is based on IETF draft-irtf-cfrg-xchacha. While not RFC-standardized, it is widely implemented (libsodium, ring, chacha20poly1305 crate) and considered cryptographically sound for production use. The 192-bit nonce eliminates collision risk for random nonce generation."

### G.2 Nonce Sizes

Add to Section 7.4.

"Noise uses a 64-bit little-endian counter as the nonce, zero-padded to 96 bits (12 bytes) for ChaCha20-Poly1305 as per the Noise specification. Sealed Blob uses 192-bit (24-byte) random nonces for XChaCha20-Poly1305. These are different constructions with different nonce management. Do not conflate them."

### G.3 Session Binding Correction

Update Section 8.1.

"Session binding provides a unique session label via the Noise handshake hash. Cryptographic protection against message injection comes from AEAD authentication under session keys, not from the hash itself.

The handshake hash enables:

- Unique identification of a session instance
- Detection of handshake transcript tampering (when verified)

Replay protection for stored messages belongs in `msg_id` and app-layer idempotency, not session binding. The session hash is useful for logging and debugging, not security enforcement."

### G.4 Grace Period Removal

Update Section 9.1.

"Key rotation uses inbox_kid-based lookup. Receivers maintain a keyring of InboxKeys and retain old keys for decryption as needed. This is key retention policy, not a protocol-level 'grace period' mechanism.

**Recommendation**: Retain old InboxKeys for at least 7 days after rotation to handle in-flight messages encrypted to old keys."

### G.5 AAD Construction Rationale

Add to Section 7.5.

"AAD binds ciphertext to storage context and prevents relocation attacks. The construction uses cryptographic primitives (not SipHash or other non-cryptographic hashes). SipHash is designed for hash table collision resistance, not cryptographic binding.

This AAD construction is complementary to Noise's transport authentication. Noise AAD applies to live transport frames. Sealed Blob AAD applies to stored ciphertext and binds it to the storage owner and path. They serve different purposes and are not redundant.

AAD is never parsed by either party. Both sender and receiver compute the exact same byte concatenation from known values (owner, path, header). Mismatched AAD causes decryption failure."

---

## Part H: ACK Lifecycle and Mitigations

### H.1 ACK Lifecycle

Update Section 7.9.

1. Receiver decrypts and processes message (payment request, subscription proposal, etc.)
2. Receiver fetches sender's **InboxKey from their PKARR KeyBinding** (NOT from Noise transport endpoint)
3. Receiver creates ACK with fresh ephemeral X25519 key
4. Receiver encrypts ACK as Sealed Blob v2 to sender's InboxKey
5. Receiver writes encrypted ACK to their own storage:
   ```
   /pub/paykit.app/v0/acks/{object_type}/{context_id_z32}/{acked_msg_id}
   ```

6. Sender polls receiver's ACK directory until found or expires_at elapsed
7. Sender decrypts ACK with their InboxKey
8. Sender stops resending after ACK or expiration
9. ACKs are cleaned up after 7 days (configurable)

**Round-Trip Acknowledgment**: This polling-based approach requires multiple round-trips and introduces latency compared to push-based protocols. This is an inherent trade-off for async stored delivery without persistent connections. For latency-sensitive use cases, prefer live Noise transport with in-session acknowledgment.

### H.2 ACK Mitigations

Add to Section 7.9.

| Mitigation | Requirement |

|------------|-------------|

| Jitter | Apply +/- 20% random jitter to polling intervals |

| Batching | MAY batch multiple ACK writes into single storage operation |

| Polling cadence | Default: poll every 30 seconds, backoff to 5 minutes if idle |

| Retry caps | MAX 5 retries per message (6 total attempts) |

| Backoff | Exponential: 1m, 2m, 4m, 8m, 16m (per Section 7.13) |

---

## Part I: New Sections

### I.1 Platform Keychain Integration (Section 5.4)

Add new section.

**iOS Keychain**:

- Store NOISE_SEED, Ed25519 seeds, and derived secrets in Keychain
- Use access control: `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`
- This provides software-level protection with device binding

**iOS Secure Enclave Limitation**: The iOS Secure Enclave (via CryptoKit `SecureEnclave.P256`) only supports P-256 keys, not Ed25519 or X25519. Therefore:

- Ed25519 signing and X25519 key exchange CANNOT be performed directly in Secure Enclave
- Use Keychain with strong accessibility class for Ed25519/X25519 material
- If hardware-backed protection is critical, consider using Secure Enclave for wrapping keys (encrypt Ed25519 seed under a P-256 key stored in SE), but this adds complexity

**Android Keystore / TEE**:

- Store secrets in Android Keystore with hardware backing when available
- Use StrongBox if present
- Android Keystore does support Ed25519 on newer API levels (API 33+)

**Hot Memory Rule**: Keypairs and seeds MUST NOT reside in hot memory longer than necessary in production. Derive on demand, use immediately, zeroize.

**DummyRing**: The `DummyRing` implementation in pubky-noise is for testing only. Production deployments MUST use platform keychain/keystore integration.

### I.2 Ring Network Isolation (Section 1.1)

Strengthen Goal 5.

"Ring MUST NOT have network access. All network operations (homeserver communication, PKARR queries, DHT operations) are performed by the app layer. Ring is a local cryptographic component only."

### I.3 Relationship to Noise Protocol (Section 1.5)

Add new section.

**What Noise Provides** (we rely on):

- Transport confidentiality via ChaCha20-Poly1305
- Mutual authentication via static key verification
- Forward secrecy via ephemeral DH
- Replay protection via nonce counters (in-session)

**What We Add**:

- Sealed Blob for stored delivery (Noise is live-only)
- Identity binding (Ed25519 to X25519)
- Storage location binding via AAD
- Async message delivery via homeserver

**What Noise Provides That We Don't Use**:

- Noise PSK patterns (pre-shared keys)
- Noise fallback patterns
- Noise re-key for long sessions (we re-handshake instead)

### I.4 Protocol Symmetry Considerations (Section 6.9)

Add new section.

**Current Architecture**: pubky-noise uses client-server model (`client.rs`, `server.rs`). One peer initiates (client), one responds (server).

**Implication for P2P**: Two peers must decide out-of-band who initiates. For stored delivery, this is less relevant (either can write to their inbox, other polls).

**pubky-data Approach**: Fully symmetric `PubkyDataEncryptor`. Either peer can encrypt/decrypt without role assignment.

**Decision Point for Implementation**:

- **Option A**: Keep client-server architecture. Define convention for role selection (e.g., lexicographically smaller PeerId initiates).
- **Option B**: Refactor pubky-noise toward symmetric peer API. Either side can initiate, both poll inbox.

This decision should be made before significant new development on pubky-noise.

---

## Part J: Code Changes (pubky-noise)

### J.1 Critical Changes

| File | Change |

|------|--------|

| [identity_payload.rs](pubky-noise/src/identity_payload.rs) | Remove `epoch` field from wire format and binding message |

| [identity_payload.rs](pubky-noise/src/identity_payload.rs) | Document `role` field as application-layer disambiguation only |

| [pubky_ring.rs](pubky-noise/src/pubky_ring.rs) | Add prominent warning: "DummyRing is for testing only. Production MUST use platform keychain/keystore." |

### J.2 High Priority Changes

| File | Change |

|------|--------|

| [kdf.rs](pubky-noise/src/kdf.rs) | Add minimum device_id length check: `assert!(device_id.len() >= 16)` |

| [client.rs](pubky-noise/src/client.rs) | Change `prologue` from configurable field to fixed constant `b"pubky-noise-v1"` |

| [server.rs](pubky-noise/src/server.rs) | Remove `seen_client_epoch` tracking mechanism (meaningless without wire-visible epoch) |

### J.3 Medium Priority Changes

| File | Change |

|------|--------|

| [client.rs](pubky-noise/src/client.rs) | Document `server_hint` as non-normative routing metadata in docstrings |

| [streaming.rs](pubky-noise/src/streaming.rs) | Either integrate with mobile_manager or add documentation explaining standalone usage |

| [sealed_blob.rs](pubky-noise/src/sealed_blob.rs) | Verify inbox_kid derivation matches spec: `first_16_bytes(SHA256(pk))` |

| tests/ | Add XX pattern interoperability tests with known test vectors |

### J.4 Low Priority Changes

| File | Change |

|------|--------|

| [errors.rs](pubky-noise/src/errors.rs) | Add documentation explaining error classification: subsystem codes (1000, 2000...) and when to use each |

| [errors.rs](pubky-noise/src/errors.rs) | Consider adding `is_user_facing() -> bool` method for UI display decisions |

| [mobile_manager.rs](pubky-noise/src/mobile_manager.rs) | Address ConnectionStatus persistence across app restarts |

| [mobile_manager.rs](pubky-noise/src/mobile_manager.rs) | Consider laddered backoff instead of pure exponential for better UX |

| [storage_queue.rs](pubky-noise/src/storage_queue.rs) | Refactor `tokio::time::sleep` to non-blocking pattern |

### J.5 NOT Changing

| Original Suggestion | Reason |

|---------------------|--------|

| Rename InvalidPeerKey to InvalidSharedSecret | Incorrect. All-zeros ECDH result typically indicates low-order peer public key. `InvalidPeerKey` is the accurate name. The peer key is invalid. |

---

## Part K: Future Considerations

### K.1 Spec Splitting

Consider splitting into multiple documents:

- **PUBKY_CRYPTO_SPEC.md**: Sections 1-6, 9-11 (primitives, identity, derivation, transport)
- **PUBKY_MESSAGING_SPEC.md**: Sections 7-8 (stored delivery, ACK, binding)
- **PAYKIT_PROTOCOL_SPEC.md**: Payment-specific extensions

Benefits: Cleaner separation, easier to version independently.

### K.2 pubky-data Consolidation

pubky-noise and pubky-data have complementary strengths:

- pubky-noise: identity binding, mobile_manager, client-server structure
- pubky-data: symmetric API, more unit tests, decoupled from Ring

Future work should evaluate combining best aspects into unified library.

---

## Summary of All Changes

### Mistakes Corrected

| Issue | Correction |

|-------|------------|

| ACK encryption unspecified | ACKs are Sealed Blob v2 encrypted to sender InboxKey via PKARR |

| ACK key discovery contradicts key separation | Removed noise endpoint reference; InboxKey from PKARR only |

| ACK payload contradicts ContextId encoding | Header uses bytes; payload hex is display-only |

| Deterministic CBOR underspecified | Full schema with integer keys, types, forbidden floats, depth limits |

| kid scope ambiguous | Renamed to inbox_kid, tied to InboxKey only |

| Ring bounds too prescriptive | Bounds are MUST; specific values are recommended |

| DoS kid flood mitigation incomplete | Unknown kid = drop WITHOUT Ring call |

| Signature bytes not specified | Added A.1.1 with header_no_sig, sig_input, verification |

| msg_id type change unacknowledged | Kept as text with ASCII constraint for v2.4 compatibility |

| CBOR resource bounds missing | Added header_len, msg_id length, depth limits |

| iOS Secure Enclave incorrect | Corrected: SE is P-256 only, use Keychain for Ed25519 |

| AAD "self-delimiting" misleading | Clarified: AAD is never parsed, just recomputed |

| ContextId vs PairContextId muddled | Added clear definitions and usage rules |

| sig optional for Paykit | Made sig REQUIRED for Paykit purposes |

| IdentityPayload binding message unspecified | Added E.3 with exact binding message bytes |

| PeerPairFingerprint derivation incomplete | Added exact BLAKE3 formula in F.4 |

| X25519 clamping undocumented | Added C.5 with entropy implications |

| Multi-step DH verification unspecified | Added C.6 clarifying snow handles this |

| Prologue decision rationale missing | Added rationale in C.2 |

| ACK round-trip trade-off unacknowledged | Added note in B.2 and H.1 |

| Web-of-trust scope unclear | Added out-of-scope note in F.2 |

### Omissions Added

| Item | Addition |

|------|----------|

| InboxKey vs TransportKey | Explicit separation rule, reuse prohibited in MVP |

| Sealed Blob v2 header schema | Full table with field ids, types, required flags, resource bounds |

| Signature construction | Complete signing/verification algorithm |

| IdentityPayload binding message | Exact bytes and verification procedure |

| Path canonicalization rules | Complete rules frozen |

| AAD byte format | Exact construction with owner + path + header_bytes |

| Pinning rules | XX→IK upgrade, downgrade prevention, PKARR rotation |

| Transport nonce | 64-bit LE counter, do not manually manage |

| Client-server symmetry | Explicit decision point for architecture |

| ContextId vs PairContextId | Clear definitions and usage rules |

| PeerPairFingerprint derivation | Exact BLAKE3 formula with display format |

| X25519 clamping entropy | RFC 7748 clamping with entropy implications |

| Multi-step DH verification | Clarification that snow handles internally |

| mobile_manager cleanup | ConnectionStatus persistence, laddered backoff |

| storage_queue refactor | Non-blocking sleep pattern |

### Secondary Review Corrections

| Item | Original | Corrected |

|------|----------|-----------|

| server_hint | Core identity | Non-normative metadata |

| Session binding | Claims injection prevention | AEAD provides injection prevention |

| ACK payload | Keep status, created_at | Remove from normative spec |

| Grace period | Protocol concept | Key retention policy only |

| Epoch encoding | "LE is fine" | Freeze or remove |

| InvalidPeerKey | Rename | Keep (correct name) |

| SipHash | Mention as alternative | Explicitly forbidden |

| Prologue | Method parameter | Fixed constant only (with rationale) |

| seen_client_epoch | Document | Remove mechanism |