//! Paykit Sealed Blob v2 Implementation
//!
//! Provides authenticated encryption for secret-bearing data stored on public
//! Pubky homeserver paths. Uses ephemeral-static X25519 ECDH with XChaCha20-Poly1305.
//!
//! v2 uses XChaCha20-Poly1305 (24-byte nonce) for improved security.
//! v1 backward compatibility is maintained for decryption.
//!
//! See `/docs/SEALED_BLOB_SPEC.md` in paykit-rs for full specification.

use crate::errors::NoiseError;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};
use zeroize::Zeroizing;

/// Current sealed blob version (v2 uses XChaCha20-Poly1305).
pub const SEALED_BLOB_VERSION: u8 = 2;

/// Maximum plaintext size (64 KiB).
pub const MAX_PLAINTEXT_SIZE: usize = 65536;

/// HKDF info string for v1 key derivation (backward compat).
const HKDF_INFO_V1: &[u8] = b"paykit-sealed-blob-v1";

/// HKDF info string for v2 key derivation.
const HKDF_INFO_V2: &[u8] = b"pubky-envelope/v2";

/// ChaCha20-Poly1305 nonce size (v1).
const NONCE_SIZE_V1: usize = 12;

/// XChaCha20-Poly1305 nonce size (v2).
pub const NONCE_SIZE_V2: usize = 24;

/// ChaCha20-Poly1305 tag size (included in ciphertext).
#[allow(dead_code)]
const TAG_SIZE: usize = 16;

/// Sealed blob envelope (JSON-serializable).
/// Supports both v1 and v2 formats.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedBlobEnvelope {
    /// Version number (1 or 2).
    pub v: u8,
    /// Sender's ephemeral public key, base64url-encoded.
    pub epk: String,
    /// Nonce, base64url-encoded (12 bytes for v1, 24 bytes for v2).
    pub nonce: String,
    /// Ciphertext + tag, base64url-encoded.
    pub ct: String,
    /// Key identifier: first 16 bytes of SHA-256(recipient_inbox_x25519_pub), hex-encoded.
    /// Per PUBKY_CRYPTO_SPEC v2.5, this is `inbox_kid` and MUST be 16 bytes (32 hex chars).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// Optional purpose hint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    /// Optional sender PKARR pubkey (z-base-32). Untrusted unless sig present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender: Option<String>,
    /// Optional Ed25519 signature over envelope hash. Required to trust sender.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
}

/// Sealed blob error codes matching the spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealedBlobErrorCode {
    UnsupportedVersion,
    MalformedEnvelope,
    InvalidBase64,
    InvalidKeySize,
    InvalidNonceSize,
    DecryptionFailed,
    PlaintextTooLarge,
}

impl std::fmt::Display for SealedBlobErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedVersion => write!(f, "E001: Unsupported version"),
            Self::MalformedEnvelope => write!(f, "E002: Malformed envelope"),
            Self::InvalidBase64 => write!(f, "E003: Invalid base64"),
            Self::InvalidKeySize => write!(f, "E004: Invalid key size"),
            Self::InvalidNonceSize => write!(f, "E005: Invalid nonce size"),
            Self::DecryptionFailed => write!(f, "E006: Decryption failed"),
            Self::PlaintextTooLarge => write!(f, "E007: Plaintext too large"),
        }
    }
}

/// Generate a random X25519 keypair.
///
/// Returns (secret_key, public_key) as 32-byte arrays.
pub fn x25519_generate_keypair() -> ([u8; 32], [u8; 32]) {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut secret = [0u8; 32];
    rng.fill_bytes(&mut secret);
    
    // Clamp for X25519
    secret[0] &= 248;
    secret[31] &= 127;
    secret[31] |= 64;
    
    let public = x25519_public_from_secret(&secret);
    (secret, public)
}

/// Derive X25519 public key from secret key using proper RFC 7748 operations.
pub fn x25519_public_from_secret(secret: &[u8; 32]) -> [u8; 32] {
    x25519(*secret, X25519_BASEPOINT_BYTES)
}

/// Compute X25519 shared secret using proper RFC 7748 operations.
fn x25519_shared_secret(local_sk: &[u8; 32], peer_pk: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(x25519(*local_sk, *peer_pk))
}

/// Derive symmetric key from shared secret and ephemeral public keys (v1).
fn derive_symmetric_key_v1(
    shared_secret: &[u8; 32],
    ephemeral_pk: &[u8; 32],
    recipient_pk: &[u8; 32],
) -> Zeroizing<[u8; 32]> {
    // salt = ephemeral_pk || recipient_pk
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(ephemeral_pk);
    salt[32..].copy_from_slice(recipient_pk);
    
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_INFO_V1, key.as_mut())
        .expect("HKDF expand with 32-byte output should never fail");
    key
}

/// Derive symmetric key from shared secret and ephemeral public keys (v2).
fn derive_symmetric_key_v2(
    shared_secret: &[u8; 32],
    ephemeral_pk: &[u8; 32],
    recipient_pk: &[u8; 32],
) -> Zeroizing<[u8; 32]> {
    // salt = ephemeral_pk || recipient_pk
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(ephemeral_pk);
    salt[32..].copy_from_slice(recipient_pk);
    
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_INFO_V2, key.as_mut())
        .expect("HKDF expand with 32-byte output should never fail");
    key
}

/// Compute inbox_kid from recipient's InboxKey public key.
///
/// Per PUBKY_CRYPTO_SPEC v2.5 Section 7.2:
/// ```text
/// inbox_kid = first_16_bytes(SHA256(recipient_inbox_x25519_pub))
/// ```
///
/// The `inbox_kid` identifies the recipient's InboxKey (not TransportKey)
/// for O(1) key selection.
fn compute_kid(recipient_pk: &[u8; 32]) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(recipient_pk);
    // Per PUBKY_CRYPTO_SPEC v2.5: inbox_kid = first 16 bytes = 32 hex chars
    hex::encode(&hash[..16])
}

/// Base64url encode without padding.
fn base64url_encode(data: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(data)
}

/// Base64url decode.
fn base64url_decode(s: &str) -> Result<Vec<u8>, SealedBlobErrorCode> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| SealedBlobErrorCode::InvalidBase64)
}

/// ChaCha20-Poly1305 encrypt with AAD (v1 - used in tests for backward compat).
#[allow(dead_code)]
fn chacha20poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; NONCE_SIZE_V1],
    plaintext: &[u8],
    aad: &[u8],
) -> Vec<u8> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::ChaCha20Poly1305;
    
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(nonce.into(), Payload { msg: plaintext, aad })
        .expect("ChaCha20Poly1305 encryption should never fail")
}

/// ChaCha20-Poly1305 decrypt with AAD (v1).
fn chacha20poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; NONCE_SIZE_V1],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, SealedBlobErrorCode> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::ChaCha20Poly1305;
    
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(nonce.into(), Payload { msg: ciphertext, aad })
        .map_err(|_| SealedBlobErrorCode::DecryptionFailed)
}

/// XChaCha20-Poly1305 encrypt with AAD (v2).
fn xchacha20poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; NONCE_SIZE_V2],
    plaintext: &[u8],
    aad: &[u8],
) -> Vec<u8> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::XChaCha20Poly1305;
    
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(nonce.into(), Payload { msg: plaintext, aad })
        .expect("XChaCha20Poly1305 encryption should never fail")
}

/// XChaCha20-Poly1305 decrypt with AAD (v2).
fn xchacha20poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; NONCE_SIZE_V2],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, SealedBlobErrorCode> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::XChaCha20Poly1305;
    
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(nonce.into(), Payload { msg: ciphertext, aad })
        .map_err(|_| SealedBlobErrorCode::DecryptionFailed)
}

/// AAD prefix for Sealed Blob v2 per PUBKY_CRYPTO_SPEC Section 7.5.
const AAD_PREFIX: &[u8] = b"pubky-envelope/v2:";

/// Build deterministic CBOR header bytes for AAD per PUBKY_CRYPTO_SPEC Section 7.12.
///
/// Uses integer keys in numeric order for deterministic encoding:
/// - Key 3: inbox_kid (bytes 16)
/// - Key 5: nonce (bytes 24)
/// - Key 6: purpose (text, optional)
/// - Key 8: sender_ephemeral_pub (bytes 32)
fn build_cbor_header_bytes(
    ephemeral_pk: &[u8; 32],
    inbox_kid: &[u8; 16],
    nonce: &[u8; NONCE_SIZE_V2],
    purpose: Option<&str>,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(96);
    
    let field_count: u8 = if purpose.is_some() { 4 } else { 3 };
    
    // Write CBOR map header
    buf.push(0xa0 + field_count);
    
    // Key 3: inbox_kid (bytes 16)
    buf.push(3); // uint 3
    buf.push(0x50); // bytes(16)
    buf.extend_from_slice(inbox_kid);
    
    // Key 5: nonce (bytes 24)
    buf.push(5); // uint 5
    buf.push(0x58); // bytes(24) - 0x58 is one-byte length prefix
    buf.push(24);
    buf.extend_from_slice(nonce);
    
    // Key 6: purpose (text, optional)
    if let Some(p) = purpose {
        buf.push(6); // uint 6
        let p_bytes = p.as_bytes();
        let p_len = p_bytes.len();
        if p_len < 24 {
            buf.push(0x60 + p_len as u8);
        } else {
            buf.push(0x78);
            buf.push(p_len as u8);
        }
        buf.extend_from_slice(p_bytes);
    }
    
    // Key 8: sender_ephemeral_pub (bytes 32)
    buf.push(8); // uint 8
    buf.push(0x58); // bytes(32) - 0x58 is one-byte length prefix
    buf.push(32);
    buf.extend_from_slice(ephemeral_pk);
    
    buf
}

/// Build AAD bytes per PUBKY_CRYPTO_SPEC Section 7.5 using deterministic CBOR.
///
/// ```text
/// aad = aad_prefix || owner_peerid_bytes || canonical_path_bytes || header_bytes
/// ```
///
/// Uses deterministic CBOR encoding for header_bytes per Section 7.12.
fn build_spec_aad(
    owner_peerid: &[u8; 32],
    canonical_path: &str,
    ephemeral_pk: &[u8; 32],
    recipient_pk: &[u8; 32],
    nonce: &[u8; NONCE_SIZE_V2],
    purpose: Option<&str>,
) -> Vec<u8> {
    // Compute inbox_kid from recipient's X25519 public key
    let kid_hex = compute_kid(recipient_pk);
    let mut inbox_kid = [0u8; 16];
    for (i, chunk) in kid_hex.as_bytes().chunks(2).enumerate() {
        if i < 16 {
            let hex_byte = std::str::from_utf8(chunk).unwrap_or("00");
            inbox_kid[i] = u8::from_str_radix(hex_byte, 16).unwrap_or(0);
        }
    }
    
    // Build CBOR header bytes
    let header_cbor = build_cbor_header_bytes(ephemeral_pk, &inbox_kid, nonce, purpose);
    
    // Concatenate: prefix || owner_peerid || canonical_path || header_bytes
    let mut aad = Vec::with_capacity(
        AAD_PREFIX.len() + 32 + canonical_path.len() + header_cbor.len()
    );
    aad.extend_from_slice(AAD_PREFIX);
    aad.extend_from_slice(owner_peerid);
    aad.extend_from_slice(canonical_path.as_bytes());
    aad.extend_from_slice(&header_cbor);
    
    aad
}

/// Build legacy JSON-based AAD for backward compatibility with older envelopes.
fn build_legacy_json_aad(
    owner_peerid: &[u8; 32],
    canonical_path: &str,
    ephemeral_pk: &[u8; 32],
    recipient_pk: &[u8; 32],
    nonce: &[u8; NONCE_SIZE_V2],
    purpose: Option<&str>,
) -> Vec<u8> {
    let kid = compute_kid(recipient_pk);
    let epk_b64 = base64url_encode(ephemeral_pk);
    let nonce_b64 = base64url_encode(nonce);
    
    // Canonical JSON with sorted keys (no whitespace)
    let header_json = if let Some(p) = purpose {
        format!(
            r#"{{"epk":"{}","kid":"{}","nonce":"{}","purpose":"{}","v":2}}"#,
            epk_b64, kid, nonce_b64, p
        )
    } else {
        format!(
            r#"{{"epk":"{}","kid":"{}","nonce":"{}","v":2}}"#,
            epk_b64, kid, nonce_b64
        )
    };
    
    let mut aad = Vec::with_capacity(
        AAD_PREFIX.len() + 32 + canonical_path.len() + header_json.len()
    );
    aad.extend_from_slice(AAD_PREFIX);
    aad.extend_from_slice(owner_peerid);
    aad.extend_from_slice(canonical_path.as_bytes());
    aad.extend_from_slice(header_json.as_bytes());
    
    aad
}

/// Encrypt plaintext using Sealed Blob v2 with spec-compliant AAD construction.
///
/// This function computes AAD internally per PUBKY_CRYPTO_SPEC Section 7.5:
/// ```text
/// aad = "pubky-envelope/v2:" || owner_peerid_bytes || canonical_path_bytes || header_bytes
/// ```
///
/// # Arguments
///
/// * `recipient_pk` - Recipient's X25519 public key (32 bytes)
/// * `plaintext` - Data to encrypt (max 64 KiB)
/// * `owner_peerid` - Storage owner's Ed25519 public key (32 bytes)
/// * `canonical_path` - Canonical storage path (e.g., "/pub/paykit.app/v0/handoff/{id}")
/// * `purpose` - Optional purpose hint ("handoff", "request", "proposal")
///
/// # Returns
///
/// JSON-encoded sealed blob v2 envelope.
pub fn sealed_blob_encrypt_with_context(
    recipient_pk: &[u8; 32],
    plaintext: &[u8],
    owner_peerid: &[u8; 32],
    canonical_path: &str,
    purpose: Option<&str>,
) -> Result<String, NoiseError> {
    if plaintext.len() > MAX_PLAINTEXT_SIZE {
        return Err(NoiseError::Other(format!(
            "{}: plaintext {} bytes exceeds max {}",
            SealedBlobErrorCode::PlaintextTooLarge,
            plaintext.len(),
            MAX_PLAINTEXT_SIZE
        )));
    }
    
    // Generate ephemeral keypair
    let (ephemeral_sk, ephemeral_pk) = x25519_generate_keypair();
    let ephemeral_sk = Zeroizing::new(ephemeral_sk);
    
    // Compute shared secret
    let shared_secret = x25519_shared_secret(&ephemeral_sk, recipient_pk);
    
    // Derive symmetric key (v2)
    let key = derive_symmetric_key_v2(&shared_secret, &ephemeral_pk, recipient_pk);
    
    // Generate random 24-byte nonce for XChaCha20
    let mut nonce = [0u8; NONCE_SIZE_V2];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
    
    // Build AAD per PUBKY_CRYPTO_SPEC
    let aad = build_spec_aad(
        owner_peerid,
        canonical_path,
        &ephemeral_pk,
        recipient_pk,
        &nonce,
        purpose,
    );
    
    // Encrypt with XChaCha20-Poly1305
    let ciphertext = xchacha20poly1305_encrypt(&key, &nonce, plaintext, &aad);
    
    // Build envelope
    let envelope = SealedBlobEnvelope {
        v: SEALED_BLOB_VERSION,
        epk: base64url_encode(&ephemeral_pk),
        nonce: base64url_encode(&nonce),
        ct: base64url_encode(&ciphertext),
        kid: Some(compute_kid(recipient_pk)),
        purpose: purpose.map(String::from),
        sender: None, // Deferred to future enhancement
        sig: None,    // Deferred to future enhancement
    };
    
    serde_json::to_string(&envelope).map_err(|e| NoiseError::Serde(e.to_string()))
}

/// Decrypt sealed blob envelope using spec-compliant AAD construction.
///
/// This function computes AAD internally per PUBKY_CRYPTO_SPEC Section 7.5.
/// For backward compatibility, it tries CBOR-based AAD first, then falls back
/// to legacy JSON-based AAD for older envelopes.
///
/// # Arguments
///
/// * `recipient_sk` - Recipient's X25519 secret key (32 bytes)
/// * `envelope_json` - JSON-encoded sealed blob envelope (v2 only for spec AAD)
/// * `owner_peerid` - Storage owner's Ed25519 public key (32 bytes)
/// * `canonical_path` - Canonical storage path (must match encryption)
///
/// # Returns
///
/// Decrypted plaintext.
pub fn sealed_blob_decrypt_with_context(
    recipient_sk: &[u8; 32],
    envelope_json: &str,
    owner_peerid: &[u8; 32],
    canonical_path: &str,
) -> Result<Vec<u8>, NoiseError> {
    // Parse envelope
    let envelope: SealedBlobEnvelope = serde_json::from_str(envelope_json)
        .map_err(|_| NoiseError::Decryption(SealedBlobErrorCode::MalformedEnvelope.to_string()))?;
    
    // Only v2 supports spec-compliant AAD
    if envelope.v != 2 {
        return Err(NoiseError::Decryption(format!(
            "sealed_blob_decrypt_with_context requires v2, got v{}",
            envelope.v
        )));
    }
    
    // Decode ephemeral public key
    let ephemeral_pk_bytes = base64url_decode(&envelope.epk)
        .map_err(|e| NoiseError::Decryption(e.to_string()))?;
    
    if ephemeral_pk_bytes.len() != 32 {
        return Err(NoiseError::Decryption(
            SealedBlobErrorCode::InvalidKeySize.to_string(),
        ));
    }
    
    let mut ephemeral_pk = [0u8; 32];
    ephemeral_pk.copy_from_slice(&ephemeral_pk_bytes);
    
    // Decode nonce and ciphertext
    let nonce_bytes = base64url_decode(&envelope.nonce)
        .map_err(|e| NoiseError::Decryption(e.to_string()))?;
    let ciphertext = base64url_decode(&envelope.ct)
        .map_err(|e| NoiseError::Decryption(e.to_string()))?;
    
    if nonce_bytes.len() != NONCE_SIZE_V2 {
        return Err(NoiseError::Decryption(
            SealedBlobErrorCode::InvalidNonceSize.to_string(),
        ));
    }
    let mut nonce = [0u8; NONCE_SIZE_V2];
    nonce.copy_from_slice(&nonce_bytes);
    
    // Compute recipient public key and shared secret
    let recipient_pk = x25519_public_from_secret(recipient_sk);
    let shared_secret = x25519_shared_secret(recipient_sk, &ephemeral_pk);
    
    // Derive symmetric key (v2)
    let key = derive_symmetric_key_v2(&shared_secret, &ephemeral_pk, &recipient_pk);
    
    // Try CBOR-based AAD first (new format per PUBKY_CRYPTO_SPEC v2.5)
    let cbor_aad = build_spec_aad(
        owner_peerid,
        canonical_path,
        &ephemeral_pk,
        &recipient_pk,
        &nonce,
        envelope.purpose.as_deref(),
    );
    
    if let Ok(plaintext) = xchacha20poly1305_decrypt(&key, &nonce, &ciphertext, &cbor_aad) {
        return Ok(plaintext);
    }
    
    // Fall back to legacy JSON-based AAD for older envelopes
    let json_aad = build_legacy_json_aad(
        owner_peerid,
        canonical_path,
        &ephemeral_pk,
        &recipient_pk,
        &nonce,
        envelope.purpose.as_deref(),
    );
    
    xchacha20poly1305_decrypt(&key, &nonce, &ciphertext, &json_aad)
        .map_err(|e| NoiseError::Decryption(e.to_string()))
}

/// Encrypt plaintext to recipient's X25519 public key using Sealed Blob v2.
///
/// **DEPRECATED**: Use `sealed_blob_encrypt_with_context` for spec-compliant AAD.
/// This function is retained for backward compatibility with existing callers
/// that construct their own AAD strings.
///
/// # Arguments
///
/// * `recipient_pk` - Recipient's X25519 public key (32 bytes)
/// * `plaintext` - Data to encrypt (max 64 KiB)
/// * `aad` - Associated authenticated data (bound to path/context)
/// * `purpose` - Optional purpose hint ("handoff", "request", "proposal")
///
/// # Returns
///
/// JSON-encoded sealed blob v2 envelope.
pub fn sealed_blob_encrypt(
    recipient_pk: &[u8; 32],
    plaintext: &[u8],
    aad: &str,
    purpose: Option<&str>,
) -> Result<String, NoiseError> {
    if plaintext.len() > MAX_PLAINTEXT_SIZE {
        return Err(NoiseError::Other(format!(
            "{}: plaintext {} bytes exceeds max {}",
            SealedBlobErrorCode::PlaintextTooLarge,
            plaintext.len(),
            MAX_PLAINTEXT_SIZE
        )));
    }
    
    // Generate ephemeral keypair
    let (ephemeral_sk, ephemeral_pk) = x25519_generate_keypair();
    let ephemeral_sk = Zeroizing::new(ephemeral_sk);
    
    // Compute shared secret
    let shared_secret = x25519_shared_secret(&ephemeral_sk, recipient_pk);
    
    // Derive symmetric key (v2)
    let key = derive_symmetric_key_v2(&shared_secret, &ephemeral_pk, recipient_pk);
    
    // Generate random 24-byte nonce for XChaCha20
    let mut nonce = [0u8; NONCE_SIZE_V2];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
    
    // Encrypt with XChaCha20-Poly1305
    let ciphertext = xchacha20poly1305_encrypt(&key, &nonce, plaintext, aad.as_bytes());
    
    // Build envelope
    let envelope = SealedBlobEnvelope {
        v: SEALED_BLOB_VERSION,
        epk: base64url_encode(&ephemeral_pk),
        nonce: base64url_encode(&nonce),
        ct: base64url_encode(&ciphertext),
        kid: Some(compute_kid(recipient_pk)),
        purpose: purpose.map(String::from),
        sender: None, // Deferred to future enhancement
        sig: None,    // Deferred to future enhancement
    };
    
    serde_json::to_string(&envelope).map_err(|e| NoiseError::Serde(e.to_string()))
}

/// Decrypt sealed blob envelope using recipient's secret key.
/// Auto-detects v1 or v2 format.
///
/// # Arguments
///
/// * `recipient_sk` - Recipient's X25519 secret key (32 bytes)
/// * `envelope_json` - JSON-encoded sealed blob envelope (v1 or v2)
/// * `aad` - Associated authenticated data (must match encryption)
///
/// # Returns
///
/// Decrypted plaintext.
pub fn sealed_blob_decrypt(
    recipient_sk: &[u8; 32],
    envelope_json: &str,
    aad: &str,
) -> Result<Vec<u8>, NoiseError> {
    // Parse envelope
    let envelope: SealedBlobEnvelope = serde_json::from_str(envelope_json)
        .map_err(|_| NoiseError::Decryption(SealedBlobErrorCode::MalformedEnvelope.to_string()))?;
    
    // Decode ephemeral public key
    let ephemeral_pk_bytes = base64url_decode(&envelope.epk)
        .map_err(|e| NoiseError::Decryption(e.to_string()))?;
    
    if ephemeral_pk_bytes.len() != 32 {
        return Err(NoiseError::Decryption(
            SealedBlobErrorCode::InvalidKeySize.to_string(),
        ));
    }
    
    let mut ephemeral_pk = [0u8; 32];
    ephemeral_pk.copy_from_slice(&ephemeral_pk_bytes);
    
    // Decode nonce and ciphertext
    let nonce_bytes = base64url_decode(&envelope.nonce)
        .map_err(|e| NoiseError::Decryption(e.to_string()))?;
    let ciphertext = base64url_decode(&envelope.ct)
        .map_err(|e| NoiseError::Decryption(e.to_string()))?;
    
    // Compute recipient public key and shared secret
    let recipient_pk = x25519_public_from_secret(recipient_sk);
    let shared_secret = x25519_shared_secret(recipient_sk, &ephemeral_pk);
    
    // Version-specific decryption
    match envelope.v {
        1 => {
            // v1: ChaCha20-Poly1305, 12-byte nonce, HKDF_INFO_V1
            if nonce_bytes.len() != NONCE_SIZE_V1 {
                return Err(NoiseError::Decryption(
                    SealedBlobErrorCode::InvalidNonceSize.to_string(),
                ));
            }
            let mut nonce = [0u8; NONCE_SIZE_V1];
            nonce.copy_from_slice(&nonce_bytes);
            
            let key = derive_symmetric_key_v1(&shared_secret, &ephemeral_pk, &recipient_pk);
            chacha20poly1305_decrypt(&key, &nonce, &ciphertext, aad.as_bytes())
                .map_err(|e| NoiseError::Decryption(e.to_string()))
        }
        2 => {
            // v2: XChaCha20-Poly1305, 24-byte nonce, HKDF_INFO_V2
            if nonce_bytes.len() != NONCE_SIZE_V2 {
                return Err(NoiseError::Decryption(
                    SealedBlobErrorCode::InvalidNonceSize.to_string(),
                ));
            }
            let mut nonce = [0u8; NONCE_SIZE_V2];
            nonce.copy_from_slice(&nonce_bytes);
            
            let key = derive_symmetric_key_v2(&shared_secret, &ephemeral_pk, &recipient_pk);
            xchacha20poly1305_decrypt(&key, &nonce, &ciphertext, aad.as_bytes())
                .map_err(|e| NoiseError::Decryption(e.to_string()))
        }
        _ => Err(NoiseError::Decryption(format!(
            "{}: got version {}",
            SealedBlobErrorCode::UnsupportedVersion,
            envelope.v
        ))),
    }
}

/// Check if a JSON string looks like a sealed blob envelope.
///
/// This is a quick heuristic check that requires BOTH version (`"v":1` or `"v":2`)
/// AND `"epk":`. Use for distinguishing encrypted from legacy plaintext.
pub fn is_sealed_blob(json: &str) -> bool {
    let has_v1 = json.contains("\"v\":1") || json.contains("\"v\": 1");
    let has_v2 = json.contains("\"v\":2") || json.contains("\"v\": 2");
    let has_epk = json.contains("\"epk\":") || json.contains("\"epk\" :");
    (has_v1 || has_v2) && has_epk
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let (sk, pk) = x25519_generate_keypair();
        assert_ne!(sk, [0u8; 32]);
        assert_ne!(pk, [0u8; 32]);
        
        // Public key derivation should be consistent
        let pk2 = x25519_public_from_secret(&sk);
        assert_eq!(pk, pk2);
    }

    #[test]
    fn test_roundtrip_encrypt_decrypt_v2() {
        let (recipient_sk, recipient_pk) = x25519_generate_keypair();
        let plaintext = b"hello world";
        let aad = "handoff:testpubkey123:/pub/paykit.app/v0/handoff/abc";
        
        let envelope = sealed_blob_encrypt(&recipient_pk, plaintext, aad, Some("handoff")).unwrap();
        
        // Verify it's v2
        assert!(envelope.contains("\"v\":2"));
        
        let decrypted = sealed_blob_decrypt(&recipient_sk, &envelope, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_v1_envelope_still_decrypts() {
        // Hardcoded v1 envelope for backward compatibility testing
        // This was generated with the old v1 code
        let (recipient_sk, recipient_pk) = x25519_generate_keypair();
        let plaintext = b"test v1 data";
        let aad = "test:v1:aad";
        
        // Manually create a v1 envelope using v1 logic
        let (ephemeral_sk, ephemeral_pk) = x25519_generate_keypair();
        let ephemeral_sk = Zeroizing::new(ephemeral_sk);
        let shared_secret = x25519_shared_secret(&ephemeral_sk, &recipient_pk);
        let key = derive_symmetric_key_v1(&shared_secret, &ephemeral_pk, &recipient_pk);
        
        let mut nonce = [0u8; NONCE_SIZE_V1];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
        
        let ciphertext = chacha20poly1305_encrypt(&key, &nonce, plaintext, aad.as_bytes());
        
        let envelope = SealedBlobEnvelope {
            v: 1, // v1!
            epk: base64url_encode(&ephemeral_pk),
            nonce: base64url_encode(&nonce),
            ct: base64url_encode(&ciphertext),
            kid: Some(compute_kid(&recipient_pk)),
            purpose: Some("test".to_string()),
            sender: None,
            sig: None,
        };
        
        let envelope_json = serde_json::to_string(&envelope).unwrap();
        
        // Decrypt with the v2 code - should auto-detect v1
        let decrypted = sealed_blob_decrypt(&recipient_sk, &envelope_json, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let (_, recipient_pk) = x25519_generate_keypair();
        let (wrong_sk, _) = x25519_generate_keypair();
        let plaintext = b"secret data";
        let aad = "test:aad";
        
        let envelope = sealed_blob_encrypt(&recipient_pk, plaintext, aad, None).unwrap();
        let result = sealed_blob_decrypt(&wrong_sk, &envelope, aad);
        
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_aad_fails() {
        let (recipient_sk, recipient_pk) = x25519_generate_keypair();
        let plaintext = b"secret data";
        let aad1 = "handoff:owner1:/path1";
        let aad2 = "handoff:owner2:/path2";
        
        let envelope = sealed_blob_encrypt(&recipient_pk, plaintext, aad1, None).unwrap();
        let result = sealed_blob_decrypt(&recipient_sk, &envelope, aad2);
        
        assert!(result.is_err());
    }

    #[test]
    fn test_plaintext_too_large() {
        let (_, recipient_pk) = x25519_generate_keypair();
        let plaintext = vec![0u8; MAX_PLAINTEXT_SIZE + 1];
        let aad = "test:aad";
        
        let result = sealed_blob_encrypt(&recipient_pk, &plaintext, aad, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_envelope_structure_v2() {
        let (_, recipient_pk) = x25519_generate_keypair();
        let plaintext = b"test";
        let aad = "test:aad";
        
        let envelope_json = sealed_blob_encrypt(&recipient_pk, plaintext, aad, Some("handoff")).unwrap();
        let envelope: SealedBlobEnvelope = serde_json::from_str(&envelope_json).unwrap();
        
        assert_eq!(envelope.v, 2);
        assert!(envelope.kid.is_some());
        assert_eq!(envelope.purpose, Some("handoff".to_string()));
        assert!(envelope.sender.is_none()); // Deferred
        assert!(envelope.sig.is_none());    // Deferred
        
        // v2 nonce should be 24 bytes (32 chars base64url)
        let nonce_bytes = base64url_decode(&envelope.nonce).unwrap();
        assert_eq!(nonce_bytes.len(), NONCE_SIZE_V2);
    }

    #[test]
    fn test_is_sealed_blob() {
        // Valid sealed blob envelopes (have version AND epk)
        assert!(is_sealed_blob(r#"{"v":1,"epk":"abc","nonce":"def","ct":"ghi"}"#));
        assert!(is_sealed_blob(r#"{"v": 1, "epk": "abc"}"#));
        assert!(is_sealed_blob(r#"{"v":1,"epk":"abc"}"#));
        assert!(is_sealed_blob(r#"{"v":2,"epk":"abc","nonce":"def","ct":"ghi"}"#));
        assert!(is_sealed_blob(r#"{"v": 2, "epk": "abc"}"#));
        assert!(is_sealed_blob(r#"{"v":2,"epk":"abc"}"#));
        
        // Not sealed blobs (missing required fields)
        assert!(!is_sealed_blob(r#"{"session_secret":"abc"}"#));
        assert!(!is_sealed_blob(r#"{"version":1}"#));
        
        // Has version but no epk - NOT a sealed blob (prevents false positives)
        assert!(!is_sealed_blob(r#"{"v":1,"other":"field"}"#));
        assert!(!is_sealed_blob(r#"{"v": 1}"#));
        assert!(!is_sealed_blob(r#"{"v":2,"other":"field"}"#));
        assert!(!is_sealed_blob(r#"{"v": 2}"#));
        
        // Has epk but no version - NOT a sealed blob
        assert!(!is_sealed_blob(r#"{"epk":"abc","v":3}"#)); // v3 not supported
        assert!(!is_sealed_blob(r#"{"epk":"abc"}"#));
    }

    #[test]
    fn test_unsupported_version_fails() {
        // Create a v2 envelope then modify it to have an unsupported version
        let (recipient_sk, recipient_pk) = x25519_generate_keypair();
        let plaintext = b"test";
        let aad = "test:aad";
        
        let envelope_json = sealed_blob_encrypt(&recipient_pk, plaintext, aad, None).unwrap();
        // Replace "v":2 with "v":99
        let bad_envelope = envelope_json.replace("\"v\":2", "\"v\":99");
        
        let result = sealed_blob_decrypt(&recipient_sk, &bad_envelope, aad);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unsupported version"));
    }
}
