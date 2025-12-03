# Cold Key Architecture for pubky-noise

This document describes how pubky-noise supports cold Ed25519 key architectures where identity keys are kept offline and only used for infrequent operations.

## Overview

In the Pubky ecosystem:
- **Ed25519 keys** are the root identity (used for pkarr, homeserver auth)
- **X25519 keys** are derived for Noise sessions
- Ed25519 keys should be kept "cold" (offline, secure storage) when possible

The challenge: how to authenticate Noise sessions without requiring Ed25519 access at handshake time?

## Solution: pkarr-Based Identity Binding

```
┌─────────────────────────────────────────────────────────────────┐
│                    COLD KEY ARCHITECTURE                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐                                                │
│  │ Cold Ed25519│──signs once──▶ pkarr record:                   │
│  │   Identity  │               "My X25519 for Noise: [X]"       │
│  └─────────────┘                        │                       │
│                                         ▼                       │
│                              ┌──────────────────┐               │
│                              │      pkarr DHT   │               │
│                              └──────────────────┘               │
│                                         │                       │
│                              lookup by pubkey                   │
│                                         ▼                       │
│  ┌─────────────┐            ┌──────────────────┐               │
│  │  Hot X25519 │◀───────────│  Noise IK/N/NN   │               │
│  │  Session Key│            │   (no Ed25519)   │               │
│  └─────────────┘            └──────────────────┘               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### The Flow

1. **One-time setup (cold signing)**:
   - User's cold Ed25519 key signs a pkarr record
   - Record contains: "My Noise X25519 public key is [X]"
   - Record is published to the pkarr DHT
   - Ed25519 key goes back to cold storage

2. **Runtime connections (hot only)**:
   - Alice wants to connect to Bob
   - Alice looks up Bob's pkarr record
   - Gets Bob's X25519 key (already authenticated by Ed25519 in pkarr)
   - Alice initiates Noise IK-raw handshake
   - No Ed25519 signing needed at runtime!

## Pattern Selection

### IK Pattern (Hot Keys)

Use when Ed25519 is available at handshake time.

```rust
// Requires Ed25519 signing at handshake time
let (hs, msg) = sender.initiate_ik(
    &x25519_sk,
    &ed25519_pub,
    &server_pk,
    |binding| sign_with_ed25519(binding),
)?;
```

**Properties:**
- Identity binding in handshake
- Requires Ed25519 access
- Strongest authentication

### IK-raw Pattern (Cold Keys + pkarr)

Use when Ed25519 is cold but identity is pre-verified via pkarr.

```rust
// No Ed25519 signing needed - pkarr already authenticated
let server_pk = lookup_pkarr("server_pubkey")?;
let (hs, msg) = sender.initiate_ik_raw(&x25519_sk, &server_pk)?;
```

**Properties:**
- Identity binding via pkarr (pre-signed)
- No runtime Ed25519 access needed
- Caller must verify pkarr record

### N Pattern (Anonymous Client)

Use when client wants anonymity but server is known.

```rust
// Client is anonymous, server authenticated via pkarr
let server_pk = lookup_pkarr("server_pubkey")?;
let (hs, msg) = sender.initiate_n(&server_pk)?;
```

**Properties:**
- Client has no static key
- Server identity via pkarr
- One-way authentication

### NN Pattern (Both Anonymous)

Use with post-handshake attestation.

```rust
// Both parties anonymous
let (hs, msg) = sender.initiate_nn()?;

// After handshake, authenticate via application protocol
let session = NoiseSession::from_handshake(hs)?;
session.write(signed_attestation)?;
```

**Properties:**
- No static keys
- Forward secrecy via ephemeral keys
- Requires external authentication

## pkarr Record Format

Example pkarr record for Noise keys:

```
TXT noise.x25519 = "<base64-encoded-32-byte-key>"
TXT noise.created = "<unix-timestamp>"
```

The record is signed by the Ed25519 identity key, providing cryptographic binding.

## Key Rotation

When rotating X25519 keys:

1. Derive new X25519 key from seed with new context
2. Sign new pkarr record with cold Ed25519
3. Publish to DHT
4. Old sessions continue to work until they naturally expire

## Security Considerations

### Caller Responsibilities

When using IK-raw, N, or NN patterns:

1. **Verify pkarr records**: Ensure the X25519 key came from a valid, fresh pkarr record
2. **Check timestamps**: Reject stale pkarr records (application-defined policy)
3. **Handle rotation**: Have a strategy for when peer's pkarr record changes

### Attack Surface

| Pattern | MITM Possible? | Requires |
|---------|----------------|----------|
| IK | No | Ed25519 at handshake |
| IK-raw | Only if pkarr compromised | Valid pkarr lookup |
| N | Only server can be spoofed | Valid pkarr lookup |
| NN | Yes (without attestation) | Post-handshake auth |

### Recommendations

1. **Prefer IK when keys are hot** (e.g., homeserver sessions)
2. **Use IK-raw for cold key scenarios** with proper pkarr verification
3. **Use NN only with post-handshake attestation**
4. **Always verify pkarr record freshness**

## Example: Complete Cold Key Flow

```rust
use pubky_noise::{RawNoiseManager, NoisePattern, MobileConfig, kdf};
use zeroize::Zeroizing;

// === SETUP (one-time, cold) ===
// This happens offline with cold Ed25519 key

let cold_ed25519_seed = get_cold_seed(); // From secure storage
let x25519_key = kdf::derive_x25519_static(&cold_ed25519_seed, b"noise-2024");
let x25519_pub = kdf::x25519_pk_from_sk(&Zeroizing::new(x25519_key));

// Sign pkarr record with cold key
let pkarr_record = create_pkarr_record(&x25519_pub);
let signed_record = sign_pkarr(&cold_ed25519_seed, &pkarr_record);
publish_pkarr(signed_record);

// Cold key goes back to cold storage
zeroize_seed(cold_ed25519_seed);

// === RUNTIME (hot X25519 only) ===
// This happens frequently without cold key access

let mut manager = RawNoiseManager::new(MobileConfig::default());

// Derive X25519 from hot seed (could be in secure enclave)
let hot_seed = get_hot_seed();
let x25519_sk = Zeroizing::new(kdf::derive_x25519_static(&hot_seed, b"noise-2024"));

// Look up peer's X25519 from pkarr
let peer_pk = lookup_and_verify_pkarr("peer_pubkey")?;

// Connect with IK-raw (no Ed25519 needed!)
let (session_id, first_msg) = manager.initiate_connection_with_pattern(
    Some(&x25519_sk),
    Some(&peer_pk),
    NoisePattern::IKRaw,
)?;

// Send first_msg, receive response, complete connection...
```

## Comparison with Hot Key Flow

| Step | Hot Key (IK) | Cold Key (IK-raw) |
|------|--------------|-------------------|
| Setup | None needed | Sign pkarr once |
| Runtime signing | Yes (Ed25519) | No |
| Identity proof | In handshake | Via pkarr |
| Key access | Full Ed25519 | X25519 only |
| Suitable for | Servers, hot wallets | Mobile, cold storage |

## References

- [Noise Protocol Framework](https://noiseprotocol.org/noise.html)
- [pkarr Specification](https://github.com/pubky/pkarr)
- [X25519 RFC 7748](https://tools.ietf.org/html/rfc7748)

