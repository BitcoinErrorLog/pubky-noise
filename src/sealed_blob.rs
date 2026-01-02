//! Paykit Sealed Blob v1 Implementation
//!
//! Provides authenticated encryption for secret-bearing data stored on public
//! Pubky homeserver paths. Uses ephemeral-static X25519 ECDH with ChaCha20-Poly1305.
//!
//! See `/docs/SEALED_BLOB_V1_SPEC.md` in paykit-rs for full specification.

use crate::errors::NoiseError;
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

/// Current sealed blob version.
pub const SEALED_BLOB_VERSION: u8 = 1;

/// Maximum plaintext size (64 KiB).
pub const MAX_PLAINTEXT_SIZE: usize = 65536;

/// HKDF info string for key derivation.
const HKDF_INFO: &[u8] = b"paykit-sealed-blob-v1";

/// ChaCha20-Poly1305 nonce size.
const NONCE_SIZE: usize = 12;

/// ChaCha20-Poly1305 tag size (included in ciphertext).
#[allow(dead_code)]
const TAG_SIZE: usize = 16;

/// Sealed blob envelope (JSON-serializable).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedBlobEnvelope {
    /// Version number (must be 1).
    pub v: u8,
    /// Sender's ephemeral public key, base64url-encoded.
    pub epk: String,
    /// Nonce, base64url-encoded.
    pub nonce: String,
    /// Ciphertext + tag, base64url-encoded.
    pub ct: String,
    /// Optional key identifier (first 8 bytes of SHA-256(recipient_pk), hex).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// Optional purpose hint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
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

/// Derive X25519 public key from secret key.
pub fn x25519_public_from_secret(secret: &[u8; 32]) -> [u8; 32] {
    let scalar = Scalar::from_bytes_mod_order(*secret);
    let point = &scalar * ED25519_BASEPOINT_TABLE;
    point.to_montgomery().to_bytes()
}

/// Compute X25519 shared secret.
fn x25519_shared_secret(local_sk: &[u8; 32], peer_pk: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let scalar = Scalar::from_bytes_mod_order(*local_sk);
    let peer_point = MontgomeryPoint(*peer_pk);
    Zeroizing::new((scalar * peer_point).to_bytes())
}

/// Derive symmetric key from shared secret and ephemeral public keys.
fn derive_symmetric_key(
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
    hk.expand(HKDF_INFO, key.as_mut())
        .expect("HKDF expand with 32-byte output should never fail");
    key
}

/// Compute key identifier from recipient public key.
fn compute_kid(recipient_pk: &[u8; 32]) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(recipient_pk);
    hex::encode(&hash[..8])
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

/// ChaCha20-Poly1305 encrypt with AAD.
fn chacha20poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; NONCE_SIZE],
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

/// ChaCha20-Poly1305 decrypt with AAD.
fn chacha20poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; NONCE_SIZE],
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

/// Encrypt plaintext to recipient's X25519 public key.
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
/// JSON-encoded sealed blob envelope.
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
    
    // Derive symmetric key
    let key = derive_symmetric_key(&shared_secret, &ephemeral_pk, recipient_pk);
    
    // Generate random nonce
    let mut nonce = [0u8; NONCE_SIZE];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
    
    // Encrypt
    let ciphertext = chacha20poly1305_encrypt(&key, &nonce, plaintext, aad.as_bytes());
    
    // Build envelope
    let envelope = SealedBlobEnvelope {
        v: SEALED_BLOB_VERSION,
        epk: base64url_encode(&ephemeral_pk),
        nonce: base64url_encode(&nonce),
        ct: base64url_encode(&ciphertext),
        kid: Some(compute_kid(recipient_pk)),
        purpose: purpose.map(String::from),
    };
    
    serde_json::to_string(&envelope).map_err(|e| NoiseError::Serde(e.to_string()))
}

/// Decrypt sealed blob envelope using recipient's secret key.
///
/// # Arguments
///
/// * `recipient_sk` - Recipient's X25519 secret key (32 bytes)
/// * `envelope_json` - JSON-encoded sealed blob envelope
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
    
    // Verify version
    if envelope.v != SEALED_BLOB_VERSION {
        return Err(NoiseError::Decryption(format!(
            "{}: got version {}",
            SealedBlobErrorCode::UnsupportedVersion,
            envelope.v
        )));
    }
    
    // Decode fields
    let ephemeral_pk_bytes = base64url_decode(&envelope.epk)
        .map_err(|e| NoiseError::Decryption(e.to_string()))?;
    let nonce_bytes = base64url_decode(&envelope.nonce)
        .map_err(|e| NoiseError::Decryption(e.to_string()))?;
    let ciphertext = base64url_decode(&envelope.ct)
        .map_err(|e| NoiseError::Decryption(e.to_string()))?;
    
    // Validate sizes
    if ephemeral_pk_bytes.len() != 32 {
        return Err(NoiseError::Decryption(
            SealedBlobErrorCode::InvalidKeySize.to_string(),
        ));
    }
    if nonce_bytes.len() != NONCE_SIZE {
        return Err(NoiseError::Decryption(
            SealedBlobErrorCode::InvalidNonceSize.to_string(),
        ));
    }
    
    let mut ephemeral_pk = [0u8; 32];
    ephemeral_pk.copy_from_slice(&ephemeral_pk_bytes);
    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(&nonce_bytes);
    
    // Compute recipient public key and shared secret
    let recipient_pk = x25519_public_from_secret(recipient_sk);
    let shared_secret = x25519_shared_secret(recipient_sk, &ephemeral_pk);
    
    // Derive symmetric key
    let key = derive_symmetric_key(&shared_secret, &ephemeral_pk, &recipient_pk);
    
    // Decrypt
    chacha20poly1305_decrypt(&key, &nonce, &ciphertext, aad.as_bytes())
        .map_err(|e| NoiseError::Decryption(e.to_string()))
}

/// Check if a JSON string looks like a sealed blob envelope.
///
/// This is a quick heuristic check (looks for `"v":1` and `"epk":`).
/// Use for distinguishing encrypted from legacy plaintext.
pub fn is_sealed_blob(json: &str) -> bool {
    json.contains("\"v\":1") || json.contains("\"v\": 1")
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
    fn test_roundtrip_encrypt_decrypt() {
        let (recipient_sk, recipient_pk) = x25519_generate_keypair();
        let plaintext = b"hello world";
        let aad = "handoff:testpubkey123:/pub/paykit.app/v0/handoff/abc";
        
        let envelope = sealed_blob_encrypt(&recipient_pk, plaintext, aad, Some("handoff")).unwrap();
        let decrypted = sealed_blob_decrypt(&recipient_sk, &envelope, aad).unwrap();
        
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
    fn test_envelope_structure() {
        let (_, recipient_pk) = x25519_generate_keypair();
        let plaintext = b"test";
        let aad = "test:aad";
        
        let envelope_json = sealed_blob_encrypt(&recipient_pk, plaintext, aad, Some("handoff")).unwrap();
        let envelope: SealedBlobEnvelope = serde_json::from_str(&envelope_json).unwrap();
        
        assert_eq!(envelope.v, 1);
        assert!(envelope.kid.is_some());
        assert_eq!(envelope.purpose, Some("handoff".to_string()));
    }

    #[test]
    fn test_is_sealed_blob() {
        assert!(is_sealed_blob(r#"{"v":1,"epk":"abc","nonce":"def","ct":"ghi"}"#));
        assert!(is_sealed_blob(r#"{"v": 1, "epk": "abc"}"#));
        assert!(!is_sealed_blob(r#"{"session_secret":"abc"}"#));
        assert!(!is_sealed_blob(r#"{"version":1}"#));
    }
}

