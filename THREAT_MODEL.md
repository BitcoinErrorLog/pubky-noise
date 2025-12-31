# Threat Model & Security Architecture

**Project**: pubky-noise v1.1.0  
**Document Version**: 1.0  
**Last Updated**: November 20, 2025

---

## Executive Summary

`pubky-noise` implements the **Noise Protocol Framework** to provide authenticated, encrypted communication channels for the Pubky ecosystem. This document outlines the security assumptions, threat model, and mitigations.

**Security Objectives**:
1. ✅ **Confidentiality** - Encrypt all data in transit
2. ✅ **Authenticity** - Verify identity of communicating parties
3. ✅ **Forward Secrecy** - Protect past sessions if keys compromised
4. ✅ **Replay Protection** - Prevent message replay attacks
5. ✅ **Denial of Service Resistance** - Mitigate DoS vectors

---

## System Architecture

### Components

```
┌─────────────────────────────────────────────────┐
│                 Application Layer                │
│  (Paykit, Locks, or other Pubky applications)   │
├─────────────────────────────────────────────────┤
│              pubky-noise Layer                   │
│  ┌─────────────────────────────────────────┐   │
│  │  Identity Binding (Ed25519 signatures)  │   │
│  └─────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────┐   │
│  │   Noise Protocol (via snow library)     │   │
│  │   - IK pattern (known server)           │   │
│  │   - XX pattern (first contact/TOFU)     │   │
│  │   - NN pattern (ephemeral-only)*        │   │
│  └─────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────┐   │
│  │   Key Management (Ring/Pubky SDK)       │   │
│  └─────────────────────────────────────────┘   │
├─────────────────────────────────────────────────┤
│            Transport Layer (TCP/QUIC)            │
└─────────────────────────────────────────────────┘
```

---

## Trust Model

### Trusted Components
✅ **Local Cryptographic Libraries**:
- `snow` (Noise Protocol implementation)
- `ed25519-dalek`, `x25519-dalek` (ECC operations)
- `blake2`, `hkdf`, `sha2` (Hash/KDF)
- Rust standard library

✅ **Key Provider** (`Ring`):
- Application-provided key derivation
- Assumed to securely manage master seeds
- **Trust Boundary**: Application must protect Ring secrets

### Untrusted Components
❌ **Network**:
- All network traffic assumed hostile
- Active and passive attackers assumed
- Man-in-the-middle attacks possible

❌ **Peer Endpoints**:
- Until authenticated, all peers untrusted
- After authentication, trusted per session only

---

## Threat Actors

### 1. **Passive Network Attacker**
**Capabilities**:
- Observe all network traffic
- Record encrypted sessions

**Mitigations**:
- ✅ ChaCha20-Poly1305 AEAD encryption
- ✅ X25519 provides ~128-bit security
- ✅ No plaintext metadata exposed
- ✅ Forward secrecy (ephemeral keys)

**Residual Risk**: LOW

---

### 2. **Active Network Attacker (MITM)**
**Capabilities**:
- Intercept and modify packets
- Replay messages
- Connection hijacking attempts

**Mitigations**:
- ✅ Noise Protocol mutual authentication
- ✅ Ed25519 identity binding prevents impersonation
- ✅ Handshake hash prevents tampering
- ✅ AEAD prevents modification of encrypted data
- ✅ Nonce progression prevents replay

**Residual Risk**: LOW (requires compromise of long-term keys)

---

### 3. **Malicious Peer**
**Capabilities**:
- Send malformed messages
- Attempt protocol violations
- Resource exhaustion (send spam)

**Mitigations**:
- ✅ All inputs validated before processing
- ✅ `snow` library handles protocol state machine
- ✅ All-zero DH secret rejection
- ✅ Signature verification prevents impersonation
- ⚠️ Application must implement rate limiting

**Residual Risk**: MEDIUM (DoS possible without rate limits)

---

### 4. **Compromised Application**
**Capabilities**:
- Access to process memory
- Read plaintext messages
- Extract session keys

**Mitigations**:
- ✅ `Zeroizing` reduces key lifetime
- ✅ Closure-based key access (no long-lived keys)
- ✅ Optional `secure-mem` feature (page locking)
- ❌ Cannot protect against memory dumps if root/admin

**Residual Risk**: HIGH (if attacker has process access)

**Note**: Defense-in-depth assumes OS-level protections

---

### 5. **Cryptanalytic Attacker**
**Capabilities**:
- Large-scale cryptanalysis
- Quantum computers (future threat)

**Mitigations**:
- ✅ Modern, vetted algorithms (NIST, IETF standards)
- ✅ Constant-time implementations
- ✅ 256-bit security level (X25519, ChaCha20)
- ❌ Not quantum-resistant

**Residual Risk**: 
- **Classical attacks**: VERY LOW
- **Quantum attacks**: HIGH (post-quantum migration needed)

**Timeline**: Safe for 10-15 years against classical attacks

---

## Security Properties

### Confidentiality ✅

**Encryption**: ChaCha20-Poly1305
- **Key Size**: 256 bits
- **Nonce**: 96 bits (managed by Noise Protocol)
- **Authentication Tag**: 128 bits

**Protection Against**:
- ✅ Eavesdropping
- ✅ Traffic analysis (content hidden)
- ⚠️ Metadata analysis (packet sizes/timing visible)

**Guarantees**: IND-CCA2 security under standard assumptions

---

### Authenticity ✅

**Identity Binding**: Ed25519 signatures over BLAKE2s binding message

**Binding Message Includes**:
```
H = BLAKE2s-256(
    "pubky-noise-bind:v1" ||
    pattern_tag ||
    prologue ||
    ed25519_pubkey ||
    local_x25519_pubkey ||
    remote_x25519_pubkey ||
    epoch ||
    role ||
    server_hint
)
Signature = Ed25519.Sign(ed25519_secret, H)
```

**Protection Against**:
- ✅ Impersonation (requires Ed25519 private key)
- ✅ Man-in-the-middle (binds Ed25519 to X25519)
- ✅ Replay across contexts (includes epoch, role)

**Guarantee**: SUF-CMA security (existentially unforgeable)

---

### Forward Secrecy ✅

**Mechanism**: Ephemeral X25519 keys per session

**Property**: Compromise of long-term Ed25519 signing key does NOT compromise past session keys

**Implementation**:
- Each session derives fresh X25519 ephemeral
- HKDF ensures independent session keys
- Ephemeral X25519 zeroized after handshake

**Guarantee**: Full forward secrecy for past sessions

---

### Key Compromise Impersonation (KCI) ⚠️

**Scenario**: Attacker compromises client's Ed25519 key

**Impact**:
- ❌ Attacker can impersonate the client
- ✅ Attacker CANNOT impersonate other parties
- ✅ Attacker CANNOT decrypt past sessions (forward secrecy)

**Mitigation**: Use IK pattern when server identity is known (prevents some attacks)

**Status**: This is inherent to the Noise Protocol design

---

### Replay Protection ✅

**Mechanisms**:
1. **Handshake Replay**: Unique ephemeral keys prevent replay
2. **Message Replay**: AEAD nonce progression prevents replay
3. **Cross-Session Replay**: Session IDs + epoch prevents cross-session replay

**Epoch Mechanism**:
- Each epoch produces different X25519 keys
- Server can reject old epochs (policy-based)
- Prevents long-term replay of handshakes

**Guarantee**: Strong replay protection within protocol

---

## Attack Surfaces

### 1. Network Input (UNTRUSTED)
**Entry Points**:
- Handshake messages (XX/IK patterns)
- Transport messages (encrypted application data)
- PKARR metadata (optional feature)

**Validation**:
- ✅ All inputs parsed by `snow` library (battle-tested)
- ✅ Length checks before processing
- ✅ Signature verification on identity payloads
- ✅ All-zero DH rejection

**Risk**: LOW (robust input validation)

---

### 2. Key Material Management
**Sensitive Data**:
- Master seed (Ring provider)
- Derived X25519 keys
- Ed25519 signing keys
- Session keys

**Protection**:
- ✅ `Zeroizing` wrapper on all keys
- ✅ Closure-based access (no escaping)
- ✅ No serialization of keys
- ✅ No logging of keys
- ✅ Automatic cleanup on drop

**Risk**: LOW (excellent key hygiene)

---

### 3. Side-Channel Attacks
**Potential Vectors**:
- Timing attacks on crypto operations
- Power analysis (embedded/mobile)
- Cache timing attacks

**Mitigations**:
- ✅ Constant-time DH check (`shared_secret_nonzero`)
- ✅ `dalek` libraries use constant-time implementations
- ✅ `snow` designed for side-channel resistance
- ⚠️ Application code may introduce timing leaks

**Risk**: LOW (for core crypto), MEDIUM (for application)

---

### 4. Denial of Service
**Attack Vectors**:
- Handshake flooding
- Large message attacks
- Connection exhaustion

**Mitigations**:
- ⚠️ No rate limiting in library (application responsibility)
- ✅ Streaming support for large messages (chunking)
- ⚠️ Server policy (max sessions, epochs) partially implemented

**Risk**: MEDIUM (application must implement limits)

**Recommendation**: Applications SHOULD:
- Rate limit handshake attempts per IP
- Limit concurrent sessions
- Enforce maximum message sizes
- Implement connection timeouts

---

### 5. FFI Boundary (Mobile Applications)
**Entry Points**:
- UniFFI-generated bindings for iOS (Swift) and Android (Kotlin/Java)
- Cross-language function calls
- Memory ownership transfers

**Threats**:
- **Memory Safety**: Incorrect memory management across language boundaries
- **Type Confusion**: Mismatched types between Rust and target language
- **Resource Leaks**: Unclosed handles or sessions
- **Panic Propagation**: Rust panics crossing FFI boundary

**Mitigations**:
- ✅ UniFFI handles memory management automatically (Arc refcounting)
- ✅ Structured error codes (`NoiseErrorCode` as `i32`) prevent type confusion
- ✅ No raw pointers exposed to generated bindings
- ✅ Thread-safe wrappers (`ThreadSafeSessionManager`) for concurrent access
- ✅ Error codes mapped to platform-specific error types

**Risk**: LOW (UniFFI provides safe abstractions)

**Mobile-Specific Considerations**:
- **App Suspension**: Sessions must be persisted before app backgrounding
- **Memory Dumps**: Keys in memory vulnerable if device is compromised
- **Jailbreak/Root**: Elevated privileges can access process memory
- **Debugging**: Debuggers can inspect memory (mitigated by release builds)

**Recommendation**: Applications SHOULD:
- Persist session state before app suspension (use `NoiseManager::save_state()`)
- Use secure storage for master seeds (iOS Keychain, Android Keystore)
- Enable `secure-mem` feature on servers (page locking)
- Clear sensitive data on app termination

---

### 6. Mobile-Specific Threats

#### 6.1 App Lifecycle Attacks
**Threat**: App suspension/resume can cause session state loss or corruption

**Mitigations**:
- ✅ `NoiseManager` provides `save_state()` and `restore_state()` methods
- ✅ Session state is serializable for persistence
- ✅ Connection status tracking for reconnection logic

**Risk**: LOW (if state is properly persisted)

#### 6.2 Memory Dump Attacks
**Threat**: Compromised device can dump process memory containing keys

**Mitigations**:
- ✅ `Zeroizing` reduces key lifetime in memory
- ✅ Closure-based key access (keys don't escape function scope)
- ✅ Optional `secure-mem` feature (page locking on supported OSes)
- ❌ Cannot fully protect against root/admin access

**Risk**: MEDIUM (requires device compromise)

**Recommendation**: Use secure hardware storage (HSM, TEE) for master seeds in high-security deployments

#### 6.3 Platform-Specific Threats

**iOS**:
- **Jailbreak Detection**: Jailbroken devices have elevated attack surface
- **Keychain Access**: Secure storage via iOS Keychain (recommended)
- **App Sandbox**: Provides isolation but keys still in process memory

**Android**:
- **Root Detection**: Rooted devices can access all app memory
- **Keystore**: Hardware-backed key storage available on modern devices
- **Debugging**: Release builds obfuscate but don't fully protect

**Risk**: MEDIUM (platform-dependent)

---

## Cryptographic Assumptions

### Standard Assumptions (Accepted)
1. **DLOG**: Discrete log problem is hard in Curve25519
2. **CDH**: Computational Diffie-Hellman is hard in Curve25519
3. **PRF**: ChaCha20 is a pseudorandom function
4. **UF-CMA**: Ed25519 is unforgeable under chosen message attack
5. **Collision Resistance**: BLAKE2s is collision-resistant

**Justification**: These are industry-standard assumptions, widely accepted

---

### Non-Standard Assumptions (NONE)
✅ No custom crypto
✅ No non-standard parameter choices
✅ No unproven constructions

---

## FFI Boundary Security

### Trust Model
The FFI layer (UniFFI) is considered **TRUSTED** for memory safety but **UNTRUSTED** for application logic:
- ✅ UniFFI-generated code is safe (no manual memory management)
- ⚠️ Application code calling FFI must handle errors correctly
- ⚠️ Platform-specific code (Swift/Kotlin) must validate inputs

### Error Handling
FFI errors are mapped to structured error codes:
- `NoiseErrorCode` enum provides platform-agnostic error types
- Errors are serialized as `i32` for cross-language compatibility
- Platform bindings should map these to native error types

### Memory Safety
- **Ownership**: UniFFI uses `Arc` for shared ownership (automatic refcounting)
- **Lifetimes**: No manual lifetime management required
- **Leaks**: Automatic cleanup when objects are dropped

### Thread Safety
- `ThreadSafeSessionManager` uses `Arc<Mutex<>>` for concurrent access
- FFI layer is thread-safe if internal types are thread-safe
- Mobile apps should use thread-safe wrappers for background workers

### Security Best Practices for FFI
1. **Input Validation**: Validate all inputs from platform code
2. **Error Handling**: Never ignore FFI errors
3. **Resource Management**: Ensure sessions are properly closed
4. **State Persistence**: Save state before app suspension
5. **Secure Storage**: Use platform secure storage for master seeds

---

## Known Limitations

### 1. No Post-Quantum Cryptography
**Status**: Vulnerable to future quantum computers

**Timeline**: Safe for 10-15 years (NIST estimates)

**Mitigation Path**: Future upgrade to PQ-Noise or hybrid schemes

---

### 2. Metadata Leakage
**Leaked Information**:
- Packet sizes (approximate message length)
- Timing of messages
- Connection patterns

**Mitigation**: Application-level padding (not in library)

---

### 3. No Anonymous Communication
**Property**: Parties learn each other's Ed25519 public keys

**Implication**: Not suitable for anonymous routing

**By Design**: Pubky requires identity binding

---

### 4. Trust-On-First-Use (TOFU) Risk
**XX Pattern**: First contact requires out-of-band verification

**Risk**: MITM possible on first connection if no verification

**Mitigation**: 
- Use IK pattern when server key known
- PIN server keys after first contact
- Optional PKARR for automated discovery

---

### 5. NN Pattern (Ephemeral-Only) ⚠️ HIGH RISK

**CRITICAL WARNING**: The NN pattern provides **ZERO AUTHENTICATION**.

**Security Properties**:
- ✅ Forward secrecy (ephemeral keys)
- ❌ NO identity binding
- ❌ NO impersonation protection
- ❌ Trivial MITM attacks possible

**Attack Scenario**:
```
Client ←→ [Active Attacker] ←→ Server
```
An active attacker can:
1. Intercept client's ephemeral key
2. Complete handshake with client using attacker's ephemeral
3. Complete separate handshake with server using attacker's ephemeral
4. Decrypt all traffic, re-encrypt for the other party

**Valid Use Cases**:
- Transport layer already provides authentication (TLS with pinned certs)
- Building higher-level authenticated protocol on top
- Testing/development environments
- Explicit acceptance of MITM risk for specific use case

**NEVER Use For**:
- Production systems without external authentication
- Any system requiring identity verification
- Financial or sensitive data transfer

**Recommendation**: Use IK (known peer) or XX (TOFU) patterns instead. NN is included only for completeness and specific transport-layer integration scenarios.

---

## Security Checklist for Applications

### ✅ MUST Implement
- [ ] Verify server Ed25519 keys on first contact (XX pattern)
- [ ] PIN server keys after verification (use IK pattern)
- [ ] Implement rate limiting on handshakes
- [ ] Limit concurrent sessions per identity
- [ ] Enforce maximum message sizes
- [ ] Handle connection timeouts
- [ ] Protect Ring master seed (secure storage)

### ⭐ SHOULD Implement
- [ ] Enable `secure-mem` feature on servers
- [ ] Implement connection attempt limits per IP
- [ ] Log security events (auth failures, policy violations)
- [ ] Monitor for unusual patterns
- [ ] Implement graceful degradation under load

### 💡 MAY Implement
- [ ] Application-level message padding
- [ ] Traffic shaping for metadata protection
- [ ] Multiple epoch support for key rotation
- [ ] Custom server policies (max handshakes, rate limits)

---

## Incident Response

### Key Compromise Scenarios

#### Ed25519 Signing Key Compromised
**Impact**: HIGH - Attacker can impersonate identity

**Immediate Actions**:
1. Revoke compromised key (via PKARR or app-specific mechanism)
2. Generate new Ed25519 keypair
3. Notify all peers of key rotation
4. Audit recent connections for suspicious activity

**Forward Secrecy**: Past sessions remain secure ✅

---

#### Ring Master Seed Compromised
**Impact**: CRITICAL - All derived keys compromised

**Immediate Actions**:
1. Generate new master seed
2. Rotate all derived keys
3. Invalidate all active sessions
4. Re-establish trust with peers
5. Full security audit of system

**Recovery**: Full key rotation required

---

#### Session Key Compromised
**Impact**: MEDIUM - Single session decryptable

**Immediate Actions**:
1. Terminate affected session
2. Establish new session
3. Investigate how key was leaked

**Isolation**: Only affects one session ✅

---

## Compliance & Standards

**Noise Protocol**: Revision 34 ✅  
**NIST FIPS 140-2**: Compatible (pending certification)  
**GDPR**: Provides encryption in transit  
**HIPAA**: Suitable for healthcare (with proper key management)  

---

## Conclusion

`pubky-noise` provides **strong security properties** based on the battle-tested Noise Protocol Framework and modern cryptography. The threat model assumes:

- **Hostile network** ✅ Protected
- **Malicious peers** ✅ Authenticated
- **Passive eavesdropping** ✅ Encrypted
- **Active MITM** ✅ Detected via identity binding

**Residual Risks** (Application Responsibility):
- Denial of Service mitigation
- Metadata protection
- Key storage security
- Rate limiting

**Future Considerations**:
- Post-quantum migration (10-15 year timeline)
- Enhanced DoS protections
- Formal verification of implementation

**Security Grade**: **A-** (Strong, with well-understood limitations)

---

**Document Prepared By**: Security Audit Team  
**Review Status**: COMPLETE  
**Next Review**: Upon major version changes or cryptographic developments

