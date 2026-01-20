//! Unified Key Delegation (UKD) implementation per PUBKY_UNIFIED_KEY_DELEGATION_SPEC_v0.2.
//!
//! This module provides AppCert creation, cert_id derivation, and typed signing
//! for proof-of-authorship without exposing generic "sign-anything" APIs.

use crate::errors::NoiseError;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// Length of cert_id in bytes (first 16 bytes of SHA256(cert_body)).
pub const CERT_ID_LEN: usize = 16;

/// AppCert version number (v1).
pub const APP_CERT_VERSION: u8 = 1;

/// Maximum app_id length in bytes.
pub const MAX_APP_ID_LEN: usize = 64;

/// Maximum device_id length in bytes.
pub const MAX_DEVICE_ID_LEN: usize = 64;

/// Maximum number of scopes.
pub const MAX_SCOPES: usize = 16;

/// Maximum scope string length.
pub const MAX_SCOPE_LEN: usize = 128;

/// AppCert fields for creating a delegated application certificate.
#[derive(Debug, Clone)]
pub struct AppCertInput {
    /// Root PKARR Ed25519 public key (32 bytes)
    pub issuer_peerid: [u8; 32],
    /// Application identifier (e.g., "pubky.app", "paykit", "bitkit")
    pub app_id: String,
    /// Optional device identifier
    pub device_id: Option<Vec<u8>>,
    /// Delegated signing key (Ed25519 public key, 32 bytes)
    pub app_ed25519_pub: [u8; 32],
    /// Delegated Noise static key (X25519 public key, 32 bytes)
    pub transport_x25519_pub: [u8; 32],
    /// Delegated inbox encryption key (X25519 public key, 32 bytes)
    pub inbox_x25519_pub: [u8; 32],
    /// Optional capability scopes
    pub scopes: Option<Vec<String>>,
    /// Optional not-before timestamp (Unix seconds)
    pub not_before: Option<u64>,
    /// Optional expiration timestamp (Unix seconds)
    pub expires_at: Option<u64>,
    /// Optional flags bitfield (reserved)
    pub flags: Option<u64>,
}

/// Signed AppCert with signature and cert_id.
#[derive(Debug, Clone)]
pub struct AppCert {
    /// Raw cert_body bytes (deterministic CBOR encoding of all fields except sig)
    pub cert_body: Vec<u8>,
    /// Ed25519 signature over SHA256(cert_body)
    pub sig: [u8; 64],
    /// First 16 bytes of SHA256(cert_body)
    pub cert_id: [u8; CERT_ID_LEN],
}

/// Encode a u64 as minimal unsigned CBOR.
fn cbor_encode_uint(n: u64) -> Vec<u8> {
    if n < 24 {
        vec![n as u8]
    } else if n <= 0xff {
        vec![0x18, n as u8]
    } else if n <= 0xffff {
        vec![0x19, (n >> 8) as u8, n as u8]
    } else if n <= 0xffff_ffff {
        vec![0x1a, (n >> 24) as u8, (n >> 16) as u8, (n >> 8) as u8, n as u8]
    } else {
        vec![
            0x1b,
            (n >> 56) as u8,
            (n >> 48) as u8,
            (n >> 40) as u8,
            (n >> 32) as u8,
            (n >> 24) as u8,
            (n >> 16) as u8,
            (n >> 8) as u8,
            n as u8,
        ]
    }
}

/// Encode a byte slice as CBOR bstr.
fn cbor_encode_bytes(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 8 + b.len());
    let len = b.len() as u64;
    if len < 24 {
        out.push(0x40 | len as u8);
    } else if len <= 0xff {
        out.push(0x58);
        out.push(len as u8);
    } else if len <= 0xffff {
        out.push(0x59);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    } else {
        out.push(0x5a);
        out.push((len >> 24) as u8);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
    out.extend_from_slice(b);
    out
}

/// Encode a string as CBOR tstr.
fn cbor_encode_text(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(1 + 8 + b.len());
    let len = b.len() as u64;
    if len < 24 {
        out.push(0x60 | len as u8);
    } else if len <= 0xff {
        out.push(0x78);
        out.push(len as u8);
    } else if len <= 0xffff {
        out.push(0x79);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    } else {
        out.push(0x7a);
        out.push((len >> 24) as u8);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
    out.extend_from_slice(b);
    out
}

/// Encode an array of strings as CBOR array.
fn cbor_encode_text_array(arr: &[String]) -> Vec<u8> {
    let len = arr.len() as u64;
    let mut out = Vec::new();
    if len < 24 {
        out.push(0x80 | len as u8);
    } else if len <= 0xff {
        out.push(0x98);
        out.push(len as u8);
    } else {
        out.push(0x99);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
    for s in arr {
        out.extend(cbor_encode_text(s));
    }
    out
}

/// Encode cert_body as deterministic CBOR map (keys sorted by numeric value).
fn encode_cert_body(input: &AppCertInput) -> Result<Vec<u8>, NoiseError> {
    // Validate inputs
    if input.app_id.is_empty() || input.app_id.len() > MAX_APP_ID_LEN {
        return Err(NoiseError::Other(format!(
            "app_id must be 1-{} bytes, got {}",
            MAX_APP_ID_LEN,
            input.app_id.len()
        )));
    }
    
    if let Some(ref device_id) = input.device_id {
        if device_id.len() > MAX_DEVICE_ID_LEN {
            return Err(NoiseError::Other(format!(
                "device_id must be <= {} bytes, got {}",
                MAX_DEVICE_ID_LEN,
                device_id.len()
            )));
        }
    }
    
    if let Some(ref scopes) = input.scopes {
        if scopes.len() > MAX_SCOPES {
            return Err(NoiseError::Other(format!(
                "scopes count must be <= {}, got {}",
                MAX_SCOPES,
                scopes.len()
            )));
        }
        for s in scopes {
            if s.len() > MAX_SCOPE_LEN {
                return Err(NoiseError::Other(format!(
                    "scope string must be <= {} bytes, got {}",
                    MAX_SCOPE_LEN,
                    s.len()
                )));
            }
        }
    }
    
    // Count map entries (keys 0-10, excluding 11 which is sig)
    let mut entry_count = 6; // v, issuer_peerid, app_id, app_ed25519_pub, transport_x25519_pub, inbox_x25519_pub
    if input.device_id.is_some() { entry_count += 1; }
    if input.scopes.is_some() { entry_count += 1; }
    if input.not_before.is_some() { entry_count += 1; }
    if input.expires_at.is_some() { entry_count += 1; }
    if input.flags.is_some() { entry_count += 1; }
    
    let mut out = Vec::with_capacity(512);
    
    // CBOR map header
    if entry_count < 24 {
        out.push(0xa0 | entry_count);
    } else {
        out.push(0xb8);
        out.push(entry_count);
    }
    
    // Keys must be in numeric order: 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10
    
    // 0: v = 1
    out.extend(cbor_encode_uint(0));
    out.extend(cbor_encode_uint(APP_CERT_VERSION as u64));
    
    // 1: issuer_peerid
    out.extend(cbor_encode_uint(1));
    out.extend(cbor_encode_bytes(&input.issuer_peerid));
    
    // 2: app_id
    out.extend(cbor_encode_uint(2));
    out.extend(cbor_encode_text(&input.app_id));
    
    // 3: device_id (optional)
    if let Some(ref device_id) = input.device_id {
        out.extend(cbor_encode_uint(3));
        out.extend(cbor_encode_bytes(device_id));
    }
    
    // 4: app_ed25519_pub
    out.extend(cbor_encode_uint(4));
    out.extend(cbor_encode_bytes(&input.app_ed25519_pub));
    
    // 5: transport_x25519_pub
    out.extend(cbor_encode_uint(5));
    out.extend(cbor_encode_bytes(&input.transport_x25519_pub));
    
    // 6: inbox_x25519_pub
    out.extend(cbor_encode_uint(6));
    out.extend(cbor_encode_bytes(&input.inbox_x25519_pub));
    
    // 7: scopes (optional)
    if let Some(ref scopes) = input.scopes {
        out.extend(cbor_encode_uint(7));
        out.extend(cbor_encode_text_array(scopes));
    }
    
    // 8: not_before (optional)
    if let Some(not_before) = input.not_before {
        out.extend(cbor_encode_uint(8));
        out.extend(cbor_encode_uint(not_before));
    }
    
    // 9: expires_at (optional)
    if let Some(expires_at) = input.expires_at {
        out.extend(cbor_encode_uint(9));
        out.extend(cbor_encode_uint(expires_at));
    }
    
    // 10: flags (optional)
    if let Some(flags) = input.flags {
        out.extend(cbor_encode_uint(10));
        out.extend(cbor_encode_uint(flags));
    }
    
    Ok(out)
}

/// Issue an AppCert by signing with the root Ed25519 secret key.
///
/// # Arguments
///
/// * `root_sk` - Root PKARR Ed25519 secret key (32 bytes seed)
/// * `input` - AppCert fields to include in the certificate
///
/// # Returns
///
/// A signed AppCert containing cert_body, sig, and cert_id.
pub fn issue_app_cert(
    root_sk: &[u8; 32],
    input: &AppCertInput,
) -> Result<AppCert, NoiseError> {
    // Verify issuer_peerid matches root_sk
    let signing_key = SigningKey::from_bytes(root_sk);
    let expected_pk = signing_key.verifying_key();
    if expected_pk.as_bytes() != &input.issuer_peerid {
        return Err(NoiseError::Other(
            "issuer_peerid does not match root secret key".to_string(),
        ));
    }
    
    // Encode cert_body
    let cert_body = encode_cert_body(input)?;
    
    // Compute SHA256(cert_body) for signing
    let mut hasher = Sha256::new();
    hasher.update(&cert_body);
    let hash = hasher.finalize();
    
    // Sign
    let signature: ed25519_dalek::Signature = signing_key.sign(&hash);
    let sig = signature.to_bytes();
    
    // Compute cert_id = first 16 bytes of SHA256(cert_body)
    let mut cert_id = [0u8; CERT_ID_LEN];
    cert_id.copy_from_slice(&hash[..CERT_ID_LEN]);
    
    Ok(AppCert {
        cert_body,
        sig,
        cert_id,
    })
}

/// Verify an AppCert signature.
///
/// # Arguments
///
/// * `issuer_peerid` - Root PKARR Ed25519 public key (32 bytes)
/// * `cert_body` - Raw cert_body bytes
/// * `sig` - Ed25519 signature (64 bytes)
///
/// # Returns
///
/// Ok(cert_id) if valid, Err otherwise.
pub fn verify_app_cert(
    issuer_peerid: &[u8; 32],
    cert_body: &[u8],
    sig: &[u8; 64],
) -> Result<[u8; CERT_ID_LEN], NoiseError> {
    let verifying_key = VerifyingKey::from_bytes(issuer_peerid)
        .map_err(|_| NoiseError::Other("Invalid issuer public key".to_string()))?;
    
    let signature = ed25519_dalek::Signature::from_bytes(sig);
    
    // Compute SHA256(cert_body)
    let mut hasher = Sha256::new();
    hasher.update(cert_body);
    let hash = hasher.finalize();
    
    // Verify signature
    verifying_key
        .verify_strict(&hash, &signature)
        .map_err(|_| NoiseError::Other("AppCert signature verification failed".to_string()))?;
    
    // Return cert_id
    let mut cert_id = [0u8; CERT_ID_LEN];
    cert_id.copy_from_slice(&hash[..CERT_ID_LEN]);
    Ok(cert_id)
}

/// Derive cert_id from cert_body bytes.
///
/// cert_id = first 16 bytes of SHA256(cert_body)
pub fn derive_cert_id(cert_body: &[u8]) -> [u8; CERT_ID_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(cert_body);
    let hash = hasher.finalize();
    let mut cert_id = [0u8; CERT_ID_LEN];
    cert_id.copy_from_slice(&hash[..CERT_ID_LEN]);
    cert_id
}

/// Prefix for SignedContent signing input per UKD spec Section 7.2.
const SIGNED_CONTENT_PREFIX: &[u8] = b"pubky-content-sig/v1:";

/// Sign typed content with an AppKey per UKD spec Section 7.2.
///
/// This is a TYPED signing function, not a generic "sign anything" API.
/// The content_type parameter constrains what is being signed.
///
/// # Arguments
///
/// * `app_sk` - AppKey Ed25519 secret key (32 bytes seed)
/// * `issuer_peerid` - Root PKARR Ed25519 public key (32 bytes)
/// * `cert_id` - AppCert identifier (16 bytes)
/// * `content_type` - ASCII label describing what is being signed (e.g., "pubky.post", "paykit.receipt")
/// * `payload` - The content payload bytes
///
/// # Returns
///
/// 64-byte Ed25519 signature.
pub fn sign_typed_content(
    app_sk: &[u8; 32],
    issuer_peerid: &[u8; 32],
    cert_id: &[u8; CERT_ID_LEN],
    content_type: &str,
    payload: &[u8],
) -> Result<[u8; 64], NoiseError> {
    // Validate content_type is ASCII and reasonable length
    if !content_type.is_ascii() || content_type.is_empty() || content_type.len() > 64 {
        return Err(NoiseError::Other(
            "content_type must be non-empty ASCII, max 64 bytes".to_string(),
        ));
    }
    
    // Compute payload_hash = SHA256(payload)
    let mut hasher = Sha256::new();
    hasher.update(payload);
    let payload_hash = hasher.finalize();
    
    // sign_input = prefix || issuer_peerid || cert_id || content_type || payload_hash
    let mut sign_input = Vec::with_capacity(
        SIGNED_CONTENT_PREFIX.len() + 32 + CERT_ID_LEN + content_type.len() + 32,
    );
    sign_input.extend_from_slice(SIGNED_CONTENT_PREFIX);
    sign_input.extend_from_slice(issuer_peerid);
    sign_input.extend_from_slice(cert_id);
    sign_input.extend_from_slice(content_type.as_bytes());
    sign_input.extend_from_slice(&payload_hash);
    
    // Sign
    let signing_key = SigningKey::from_bytes(app_sk);
    let signature: ed25519_dalek::Signature = signing_key.sign(&sign_input);
    
    Ok(signature.to_bytes())
}

/// Verify typed content signature.
///
/// # Arguments
///
/// * `app_ed25519_pub` - AppKey Ed25519 public key (32 bytes)
/// * `issuer_peerid` - Root PKARR Ed25519 public key (32 bytes)
/// * `cert_id` - AppCert identifier (16 bytes)
/// * `content_type` - ASCII label describing what is being signed
/// * `payload` - The content payload bytes
/// * `sig` - Signature to verify (64 bytes)
///
/// # Returns
///
/// Ok(()) if valid, Err otherwise.
pub fn verify_typed_content(
    app_ed25519_pub: &[u8; 32],
    issuer_peerid: &[u8; 32],
    cert_id: &[u8; CERT_ID_LEN],
    content_type: &str,
    payload: &[u8],
    sig: &[u8; 64],
) -> Result<(), NoiseError> {
    // Validate content_type
    if !content_type.is_ascii() || content_type.is_empty() || content_type.len() > 64 {
        return Err(NoiseError::Other(
            "content_type must be non-empty ASCII, max 64 bytes".to_string(),
        ));
    }
    
    // Compute payload_hash
    let mut hasher = Sha256::new();
    hasher.update(payload);
    let payload_hash = hasher.finalize();
    
    // Reconstruct sign_input
    let mut sign_input = Vec::with_capacity(
        SIGNED_CONTENT_PREFIX.len() + 32 + CERT_ID_LEN + content_type.len() + 32,
    );
    sign_input.extend_from_slice(SIGNED_CONTENT_PREFIX);
    sign_input.extend_from_slice(issuer_peerid);
    sign_input.extend_from_slice(cert_id);
    sign_input.extend_from_slice(content_type.as_bytes());
    sign_input.extend_from_slice(&payload_hash);
    
    // Verify
    let verifying_key = VerifyingKey::from_bytes(app_ed25519_pub)
        .map_err(|_| NoiseError::Other("Invalid AppKey public key".to_string()))?;
    let signature = ed25519_dalek::Signature::from_bytes(sig);
    
    verifying_key
        .verify_strict(&sign_input, &signature)
        .map_err(|_| NoiseError::Other("Typed content signature verification failed".to_string()))
}

/// Generate a new Ed25519 keypair for use as an AppKey.
///
/// # Returns
///
/// (secret_key, public_key) tuple, each 32 bytes.
pub fn generate_app_keypair() -> ([u8; 32], [u8; 32]) {
    let mut rng = rand::thread_rng();
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rng, &mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let secret = *signing_key.as_bytes();
    let public = *signing_key.verifying_key().as_bytes();
    (secret, public)
}

// ============================================================================
// KeyBinding per PUBKY_CRYPTO_SPEC v2.5 Section 7.3
// ============================================================================

/// KeyBinding structure for publishing keys via PKARR.
///
/// Per PUBKY_CRYPTO_SPEC v2.5 Section 7.3, a KeyBinding contains:
/// - inbox_keys: List of InboxKey public keys with their inbox_kid identifiers
/// - transport_keys: List of TransportKey public keys
/// - app_keys: Optional list of delegated AppKey public keys with cert_id
///
/// The KeyBinding is CBOR-encoded and published at a well-known PKARR path.
#[derive(Debug, Clone, Default)]
pub struct KeyBinding {
    /// InboxKey entries (inbox_kid, X25519 public key)
    pub inbox_keys: Vec<InboxKeyEntry>,
    /// TransportKey entries (X25519 public key)
    pub transport_keys: Vec<TransportKeyEntry>,
    /// Optional AppKey entries (cert_id, Ed25519 public key)
    pub app_keys: Option<Vec<AppKeyEntry>>,
}

/// Entry in the inbox_keys list.
#[derive(Debug, Clone)]
pub struct InboxKeyEntry {
    /// 16-byte inbox_kid identifier
    pub inbox_kid: [u8; CERT_ID_LEN],
    /// 32-byte X25519 public key
    pub x25519_pub: [u8; 32],
}

/// Entry in the transport_keys list.
#[derive(Debug, Clone)]
pub struct TransportKeyEntry {
    /// 32-byte X25519 public key
    pub x25519_pub: [u8; 32],
}

/// Entry in the app_keys list.
#[derive(Debug, Clone)]
pub struct AppKeyEntry {
    /// 16-byte cert_id from the AppCert
    pub cert_id: [u8; CERT_ID_LEN],
    /// 32-byte Ed25519 public key
    pub ed25519_pub: [u8; 32],
}

impl KeyBinding {
    /// Create a new empty KeyBinding.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an InboxKey entry.
    pub fn add_inbox_key(&mut self, x25519_pub: [u8; 32]) {
        // Compute inbox_kid from public key
        let hash = Sha256::digest(&x25519_pub);
        let mut inbox_kid = [0u8; CERT_ID_LEN];
        inbox_kid.copy_from_slice(&hash[..CERT_ID_LEN]);

        self.inbox_keys.push(InboxKeyEntry {
            inbox_kid,
            x25519_pub,
        });
    }

    /// Add a TransportKey entry.
    pub fn add_transport_key(&mut self, x25519_pub: [u8; 32]) {
        self.transport_keys.push(TransportKeyEntry { x25519_pub });
    }

    /// Add an AppKey entry.
    pub fn add_app_key(&mut self, cert_id: [u8; CERT_ID_LEN], ed25519_pub: [u8; 32]) {
        if self.app_keys.is_none() {
            self.app_keys = Some(Vec::new());
        }
        self.app_keys
            .as_mut()
            .unwrap()
            .push(AppKeyEntry { cert_id, ed25519_pub });
    }

    /// Encode as deterministic CBOR.
    ///
    /// Returns CBOR bytes suitable for publishing via PKARR.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);

        // Count map entries
        let mut entry_count: u8 = 2; // inbox_keys, transport_keys
        if self.app_keys.is_some() {
            entry_count += 1;
        }

        // Map header
        out.push(0xa0 | entry_count);

        // Key 0: inbox_keys (array of [inbox_kid, x25519_pub])
        out.extend(cbor_encode_uint(0));
        out.push(0x80 | (self.inbox_keys.len() as u8).min(23));
        if self.inbox_keys.len() > 23 {
            // For larger arrays, use proper CBOR encoding
            out.pop();
            out.push(0x98);
            out.push(self.inbox_keys.len() as u8);
        }
        for entry in &self.inbox_keys {
            // Each entry is a 2-element array: [inbox_kid, x25519_pub]
            out.push(0x82);
            out.extend(cbor_encode_bytes(&entry.inbox_kid));
            out.extend(cbor_encode_bytes(&entry.x25519_pub));
        }

        // Key 1: transport_keys (array of x25519_pub)
        out.extend(cbor_encode_uint(1));
        out.push(0x80 | (self.transport_keys.len() as u8).min(23));
        if self.transport_keys.len() > 23 {
            out.pop();
            out.push(0x98);
            out.push(self.transport_keys.len() as u8);
        }
        for entry in &self.transport_keys {
            out.extend(cbor_encode_bytes(&entry.x25519_pub));
        }

        // Key 2: app_keys (optional, array of [cert_id, ed25519_pub])
        if let Some(ref app_keys) = self.app_keys {
            out.extend(cbor_encode_uint(2));
            out.push(0x80 | (app_keys.len() as u8).min(23));
            if app_keys.len() > 23 {
                out.pop();
                out.push(0x98);
                out.push(app_keys.len() as u8);
            }
            for entry in app_keys {
                out.push(0x82);
                out.extend(cbor_encode_bytes(&entry.cert_id));
                out.extend(cbor_encode_bytes(&entry.ed25519_pub));
            }
        }

        out
    }

    /// Decode from CBOR bytes.
    pub fn decode(data: &[u8]) -> Result<Self, NoiseError> {
        // Simple CBOR decoder for KeyBinding format
        let mut pos = 0;

        if data.is_empty() {
            return Err(NoiseError::Decryption("Empty KeyBinding data".into()));
        }

        // Read map header
        let first = data[pos];
        pos += 1;
        let major = first >> 5;
        if major != 5 {
            return Err(NoiseError::Decryption(format!(
                "KeyBinding: expected map, got major type {}",
                major
            )));
        }

        let map_len = (first & 0x1f) as usize;
        if map_len > 16 {
            return Err(NoiseError::Decryption("KeyBinding: too many keys".into()));
        }

        let mut binding = KeyBinding::new();

        for _ in 0..map_len {
            if pos >= data.len() {
                return Err(NoiseError::Decryption("KeyBinding: truncated".into()));
            }

            // Read key (uint)
            let key = data[pos] as u64;
            pos += 1;

            match key {
                0 => {
                    // inbox_keys
                    let (keys, consumed) = decode_inbox_keys_array(&data[pos..])?;
                    binding.inbox_keys = keys;
                    pos += consumed;
                }
                1 => {
                    // transport_keys
                    let (keys, consumed) = decode_transport_keys_array(&data[pos..])?;
                    binding.transport_keys = keys;
                    pos += consumed;
                }
                2 => {
                    // app_keys
                    let (keys, consumed) = decode_app_keys_array(&data[pos..])?;
                    binding.app_keys = Some(keys);
                    pos += consumed;
                }
                _ => {
                    // Skip unknown key
                    return Err(NoiseError::Decryption(format!(
                        "KeyBinding: unknown key {}",
                        key
                    )));
                }
            }
        }

        Ok(binding)
    }

    /// Find an InboxKey by inbox_kid.
    pub fn find_inbox_key(&self, inbox_kid: &[u8; CERT_ID_LEN]) -> Option<&[u8; 32]> {
        self.inbox_keys
            .iter()
            .find(|e| &e.inbox_kid == inbox_kid)
            .map(|e| &e.x25519_pub)
    }

    /// Find an AppKey by cert_id.
    pub fn find_app_key(&self, cert_id: &[u8; CERT_ID_LEN]) -> Option<&[u8; 32]> {
        self.app_keys.as_ref().and_then(|keys| {
            keys.iter()
                .find(|e| &e.cert_id == cert_id)
                .map(|e| &e.ed25519_pub)
        })
    }
}

/// Decode a CBOR byte string from data, returning (bytes, consumed_bytes).
fn cbor_decode_bytes(data: &[u8]) -> Result<(Vec<u8>, usize), NoiseError> {
    if data.is_empty() {
        return Err(NoiseError::Decryption("cbor_decode_bytes: empty input".into()));
    }
    let first = data[0];
    let major = first >> 5;
    if major != 2 {
        return Err(NoiseError::Decryption(format!(
            "cbor_decode_bytes: expected bstr (major 2), got major {}",
            major
        )));
    }
    let additional = first & 0x1f;
    let (byte_len, header_size): (usize, usize) = if additional < 24 {
        (additional as usize, 1)
    } else if additional == 24 {
        if data.len() < 2 {
            return Err(NoiseError::Decryption("cbor_decode_bytes: truncated length".into()));
        }
        (data[1] as usize, 2)
    } else if additional == 25 {
        if data.len() < 3 {
            return Err(NoiseError::Decryption("cbor_decode_bytes: truncated length".into()));
        }
        (((data[1] as usize) << 8) | (data[2] as usize), 3)
    } else if additional == 26 {
        if data.len() < 5 {
            return Err(NoiseError::Decryption("cbor_decode_bytes: truncated length".into()));
        }
        (
            ((data[1] as usize) << 24)
                | ((data[2] as usize) << 16)
                | ((data[3] as usize) << 8)
                | (data[4] as usize),
            5,
        )
    } else {
        return Err(NoiseError::Decryption(format!(
            "cbor_decode_bytes: unsupported additional info {}",
            additional
        )));
    };
    let total = header_size + byte_len;
    if data.len() < total {
        return Err(NoiseError::Decryption("cbor_decode_bytes: truncated data".into()));
    }
    Ok((data[header_size..total].to_vec(), total))
}

/// Decode CBOR array header, returning (array_length, consumed_bytes).
fn cbor_decode_array_header(data: &[u8]) -> Result<(usize, usize), NoiseError> {
    if data.is_empty() {
        return Err(NoiseError::Decryption("cbor_decode_array_header: empty input".into()));
    }
    let first = data[0];
    let major = first >> 5;
    if major != 4 {
        return Err(NoiseError::Decryption(format!(
            "cbor_decode_array_header: expected array (major 4), got major {}",
            major
        )));
    }
    let additional = first & 0x1f;
    if additional < 24 {
        Ok((additional as usize, 1))
    } else if additional == 24 {
        if data.len() < 2 {
            return Err(NoiseError::Decryption(
                "cbor_decode_array_header: truncated length".into(),
            ));
        }
        Ok((data[1] as usize, 2))
    } else {
        Err(NoiseError::Decryption(format!(
            "cbor_decode_array_header: unsupported additional info {}",
            additional
        )))
    }
}

/// Decode inbox_keys CBOR array: array of [inbox_kid(16 bytes), x25519_pub(32 bytes)]
fn decode_inbox_keys_array(data: &[u8]) -> Result<(Vec<InboxKeyEntry>, usize), NoiseError> {
    let (arr_len, mut pos) = cbor_decode_array_header(data)?;
    let mut entries = Vec::with_capacity(arr_len);

    for _ in 0..arr_len {
        if pos >= data.len() {
            return Err(NoiseError::Decryption("decode_inbox_keys_array: truncated".into()));
        }
        let first = data[pos];
        if first != 0x82 {
            return Err(NoiseError::Decryption(format!(
                "decode_inbox_keys_array: expected 2-element array (0x82), got 0x{:02x}",
                first
            )));
        }
        pos += 1;

        let (kid_vec, kid_consumed) = cbor_decode_bytes(&data[pos..])?;
        if kid_vec.len() != CERT_ID_LEN {
            return Err(NoiseError::Decryption(format!(
                "decode_inbox_keys_array: inbox_kid expected {} bytes, got {}",
                CERT_ID_LEN,
                kid_vec.len()
            )));
        }
        pos += kid_consumed;

        let (pk_vec, pk_consumed) = cbor_decode_bytes(&data[pos..])?;
        if pk_vec.len() != 32 {
            return Err(NoiseError::Decryption(format!(
                "decode_inbox_keys_array: x25519_pub expected 32 bytes, got {}",
                pk_vec.len()
            )));
        }
        pos += pk_consumed;

        let mut inbox_kid = [0u8; CERT_ID_LEN];
        inbox_kid.copy_from_slice(&kid_vec);
        let mut x25519_pub = [0u8; 32];
        x25519_pub.copy_from_slice(&pk_vec);
        entries.push(InboxKeyEntry { inbox_kid, x25519_pub });
    }
    Ok((entries, pos))
}

/// Decode transport_keys CBOR array: array of x25519_pub(32 bytes)
fn decode_transport_keys_array(data: &[u8]) -> Result<(Vec<TransportKeyEntry>, usize), NoiseError> {
    let (arr_len, mut pos) = cbor_decode_array_header(data)?;
    let mut entries = Vec::with_capacity(arr_len);

    for _ in 0..arr_len {
        let (pk_vec, pk_consumed) = cbor_decode_bytes(&data[pos..])?;
        if pk_vec.len() != 32 {
            return Err(NoiseError::Decryption(format!(
                "decode_transport_keys_array: x25519_pub expected 32 bytes, got {}",
                pk_vec.len()
            )));
        }
        pos += pk_consumed;

        let mut x25519_pub = [0u8; 32];
        x25519_pub.copy_from_slice(&pk_vec);
        entries.push(TransportKeyEntry { x25519_pub });
    }
    Ok((entries, pos))
}

/// Decode app_keys CBOR array: array of [cert_id(16 bytes), ed25519_pub(32 bytes)]
fn decode_app_keys_array(data: &[u8]) -> Result<(Vec<AppKeyEntry>, usize), NoiseError> {
    let (arr_len, mut pos) = cbor_decode_array_header(data)?;
    let mut entries = Vec::with_capacity(arr_len);

    for _ in 0..arr_len {
        if pos >= data.len() {
            return Err(NoiseError::Decryption("decode_app_keys_array: truncated".into()));
        }
        let first = data[pos];
        if first != 0x82 {
            return Err(NoiseError::Decryption(format!(
                "decode_app_keys_array: expected 2-element array (0x82), got 0x{:02x}",
                first
            )));
        }
        pos += 1;

        let (cid_vec, cid_consumed) = cbor_decode_bytes(&data[pos..])?;
        if cid_vec.len() != CERT_ID_LEN {
            return Err(NoiseError::Decryption(format!(
                "decode_app_keys_array: cert_id expected {} bytes, got {}",
                CERT_ID_LEN,
                cid_vec.len()
            )));
        }
        pos += cid_consumed;

        let (pk_vec, pk_consumed) = cbor_decode_bytes(&data[pos..])?;
        if pk_vec.len() != 32 {
            return Err(NoiseError::Decryption(format!(
                "decode_app_keys_array: ed25519_pub expected 32 bytes, got {}",
                pk_vec.len()
            )));
        }
        pos += pk_consumed;

        let mut cert_id = [0u8; CERT_ID_LEN];
        cert_id.copy_from_slice(&cid_vec);
        let mut ed25519_pub = [0u8; 32];
        ed25519_pub.copy_from_slice(&pk_vec);
        entries.push(AppKeyEntry { cert_id, ed25519_pub });
    }
    Ok((entries, pos))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sealed_blob::x25519_generate_keypair;

    fn generate_test_signing_key() -> SigningKey {
        let mut rng = rand::thread_rng();
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rng, &mut seed);
        SigningKey::from_bytes(&seed)
    }

    #[test]
    fn test_issue_and_verify_app_cert() {
        // Generate root keypair
        let root_sk = generate_test_signing_key();
        let root_pk = *root_sk.verifying_key().as_bytes();
        
        // Generate delegated keys
        let (app_sk, app_pk) = generate_app_keypair();
        let (_, transport_pk) = x25519_generate_keypair();
        let (_, inbox_pk) = x25519_generate_keypair();
        
        let input = AppCertInput {
            issuer_peerid: root_pk,
            app_id: "test.app".to_string(),
            device_id: Some(b"test-device-123".to_vec()),
            app_ed25519_pub: app_pk,
            transport_x25519_pub: transport_pk,
            inbox_x25519_pub: inbox_pk,
            scopes: Some(vec!["post.sign".to_string(), "message.sign".to_string()]),
            not_before: Some(1700000000),
            expires_at: Some(1800000000),
            flags: None,
        };
        
        // Issue cert
        let cert = issue_app_cert(root_sk.as_bytes(), &input).unwrap();
        
        // Verify cert
        let verified_cert_id = verify_app_cert(&root_pk, &cert.cert_body, &cert.sig).unwrap();
        assert_eq!(verified_cert_id, cert.cert_id);
    }
    
    #[test]
    fn test_sign_and_verify_typed_content() {
        // Generate keys
        let root_sk = generate_test_signing_key();
        let root_pk = *root_sk.verifying_key().as_bytes();
        let (app_sk, app_pk) = generate_app_keypair();
        let (_, transport_pk) = x25519_generate_keypair();
        let (_, inbox_pk) = x25519_generate_keypair();
        
        // Issue cert
        let input = AppCertInput {
            issuer_peerid: root_pk,
            app_id: "test.app".to_string(),
            device_id: None,
            app_ed25519_pub: app_pk,
            transport_x25519_pub: transport_pk,
            inbox_x25519_pub: inbox_pk,
            scopes: None,
            not_before: None,
            expires_at: None,
            flags: None,
        };
        let cert = issue_app_cert(root_sk.as_bytes(), &input).unwrap();
        
        // Sign content
        let content = b"Hello, World!";
        let sig = sign_typed_content(
            &app_sk,
            &root_pk,
            &cert.cert_id,
            "pubky.post",
            content,
        ).unwrap();
        
        // Verify
        verify_typed_content(
            &app_pk,
            &root_pk,
            &cert.cert_id,
            "pubky.post",
            content,
            &sig,
        ).unwrap();
    }
    
    #[test]
    fn test_keybinding_encode() {
        let mut kb = KeyBinding::new();

        // Add an inbox key
        let inbox_pk = [1u8; 32];
        kb.add_inbox_key(inbox_pk);

        // Add a transport key
        let transport_pk = [2u8; 32];
        kb.add_transport_key(transport_pk);

        // Encode
        let encoded = kb.encode();
        assert!(!encoded.is_empty());

        // Verify it's valid CBOR (starts with map)
        assert_eq!(encoded[0] >> 5, 5); // major type 5 = map

        // Verify inbox_kid was computed
        assert_eq!(kb.inbox_keys.len(), 1);
        assert_eq!(kb.inbox_keys[0].inbox_kid.len(), CERT_ID_LEN);
    }

    #[test]
    fn test_keybinding_find_keys() {
        let mut kb = KeyBinding::new();

        let inbox_pk = [42u8; 32];
        kb.add_inbox_key(inbox_pk);

        // Compute expected inbox_kid
        let hash = Sha256::digest(&inbox_pk);
        let mut expected_kid = [0u8; CERT_ID_LEN];
        expected_kid.copy_from_slice(&hash[..CERT_ID_LEN]);

        // Find by inbox_kid
        let found = kb.find_inbox_key(&expected_kid);
        assert!(found.is_some());
        assert_eq!(found.unwrap(), &inbox_pk);

        // Add app key
        let cert_id = [3u8; CERT_ID_LEN];
        let app_pk = [4u8; 32];
        kb.add_app_key(cert_id, app_pk);

        let found_app = kb.find_app_key(&cert_id);
        assert!(found_app.is_some());
        assert_eq!(found_app.unwrap(), &app_pk);
    }

    #[test]
    fn test_wrong_content_type_fails() {
        let root_sk = generate_test_signing_key();
        let root_pk = *root_sk.verifying_key().as_bytes();
        let (app_sk, app_pk) = generate_app_keypair();
        let (_, transport_pk) = x25519_generate_keypair();
        let (_, inbox_pk) = x25519_generate_keypair();
        
        let input = AppCertInput {
            issuer_peerid: root_pk,
            app_id: "test.app".to_string(),
            device_id: None,
            app_ed25519_pub: app_pk,
            transport_x25519_pub: transport_pk,
            inbox_x25519_pub: inbox_pk,
            scopes: None,
            not_before: None,
            expires_at: None,
            flags: None,
        };
        let cert = issue_app_cert(root_sk.as_bytes(), &input).unwrap();
        
        let content = b"Hello";
        let sig = sign_typed_content(
            &app_sk,
            &root_pk,
            &cert.cert_id,
            "pubky.post",
            content,
        ).unwrap();
        
        // Verify with wrong content_type should fail
        let result = verify_typed_content(
            &app_pk,
            &root_pk,
            &cert.cert_id,
            "paykit.receipt", // Wrong type
            content,
            &sig,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_keybinding_encode_decode_roundtrip_empty() {
        let kb = KeyBinding::new();
        let encoded = kb.encode();
        let decoded = KeyBinding::decode(&encoded).expect("decode should succeed");
        assert!(decoded.inbox_keys.is_empty());
        assert!(decoded.transport_keys.is_empty());
        assert!(decoded.app_keys.is_none());
    }

    #[test]
    fn test_keybinding_encode_decode_roundtrip_inbox_only() {
        let mut kb = KeyBinding::new();
        let inbox_pk1 = [1u8; 32];
        let inbox_pk2 = [2u8; 32];
        kb.add_inbox_key(inbox_pk1);
        kb.add_inbox_key(inbox_pk2);

        let encoded = kb.encode();
        let decoded = KeyBinding::decode(&encoded).expect("decode should succeed");

        assert_eq!(decoded.inbox_keys.len(), 2);
        assert_eq!(decoded.inbox_keys[0].x25519_pub, inbox_pk1);
        assert_eq!(decoded.inbox_keys[1].x25519_pub, inbox_pk2);
        assert!(decoded.transport_keys.is_empty());
        assert!(decoded.app_keys.is_none());
    }

    #[test]
    fn test_keybinding_encode_decode_roundtrip_transport_only() {
        let mut kb = KeyBinding::new();
        let transport_pk = [3u8; 32];
        kb.add_transport_key(transport_pk);

        let encoded = kb.encode();
        let decoded = KeyBinding::decode(&encoded).expect("decode should succeed");

        assert!(decoded.inbox_keys.is_empty());
        assert_eq!(decoded.transport_keys.len(), 1);
        assert_eq!(decoded.transport_keys[0].x25519_pub, transport_pk);
        assert!(decoded.app_keys.is_none());
    }

    #[test]
    fn test_keybinding_encode_decode_roundtrip_full() {
        let mut kb = KeyBinding::new();

        let inbox_pk = [10u8; 32];
        kb.add_inbox_key(inbox_pk);

        let transport_pk = [20u8; 32];
        kb.add_transport_key(transport_pk);

        let cert_id = [30u8; CERT_ID_LEN];
        let app_pk = [40u8; 32];
        kb.add_app_key(cert_id, app_pk);

        let encoded = kb.encode();
        let decoded = KeyBinding::decode(&encoded).expect("decode should succeed");

        assert_eq!(decoded.inbox_keys.len(), 1);
        assert_eq!(decoded.inbox_keys[0].x25519_pub, inbox_pk);

        assert_eq!(decoded.transport_keys.len(), 1);
        assert_eq!(decoded.transport_keys[0].x25519_pub, transport_pk);

        let app_keys = decoded.app_keys.expect("app_keys should be Some");
        assert_eq!(app_keys.len(), 1);
        assert_eq!(app_keys[0].cert_id, cert_id);
        assert_eq!(app_keys[0].ed25519_pub, app_pk);
    }

    #[test]
    fn test_keybinding_encode_decode_roundtrip_multiple_entries() {
        let mut kb = KeyBinding::new();

        for i in 0..5u8 {
            kb.add_inbox_key([i; 32]);
        }
        for i in 10..13u8 {
            kb.add_transport_key([i; 32]);
        }
        for i in 20..22u8 {
            let cert_id = [i; CERT_ID_LEN];
            kb.add_app_key(cert_id, [i + 100; 32]);
        }

        let encoded = kb.encode();
        let decoded = KeyBinding::decode(&encoded).expect("decode should succeed");

        assert_eq!(decoded.inbox_keys.len(), 5);
        for (idx, entry) in decoded.inbox_keys.iter().enumerate() {
            assert_eq!(entry.x25519_pub, [idx as u8; 32]);
        }

        assert_eq!(decoded.transport_keys.len(), 3);
        for (idx, entry) in decoded.transport_keys.iter().enumerate() {
            assert_eq!(entry.x25519_pub, [(10 + idx) as u8; 32]);
        }

        let app_keys = decoded.app_keys.expect("app_keys should be Some");
        assert_eq!(app_keys.len(), 2);
        assert_eq!(app_keys[0].cert_id, [20u8; CERT_ID_LEN]);
        assert_eq!(app_keys[0].ed25519_pub, [120u8; 32]);
        assert_eq!(app_keys[1].cert_id, [21u8; CERT_ID_LEN]);
        assert_eq!(app_keys[1].ed25519_pub, [121u8; 32]);
    }

    #[test]
    fn test_keybinding_decode_empty_data() {
        let result = KeyBinding::decode(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_keybinding_decode_not_a_map() {
        let result = KeyBinding::decode(&[0x82]); // 2-element array, not a map
        assert!(result.is_err());
    }

    #[test]
    fn test_keybinding_decode_truncated_inbox_key() {
        let mut kb = KeyBinding::new();
        kb.add_inbox_key([1u8; 32]);
        let mut encoded = kb.encode();
        encoded.truncate(encoded.len() - 10);
        let result = KeyBinding::decode(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn test_keybinding_decode_wrong_inbox_kid_length() {
        let mut data = Vec::new();
        data.push(0xa2);
        data.push(0x00);
        data.push(0x81);
        data.push(0x82);
        data.push(0x48);
        data.extend([0u8; 8]);
        data.push(0x58);
        data.push(32);
        data.extend([0u8; 32]);
        data.push(0x01);
        data.push(0x80);
        let result = KeyBinding::decode(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_keybinding_decode_unknown_key() {
        let mut data = Vec::new();
        data.push(0xa3);
        data.push(0x00);
        data.push(0x80);
        data.push(0x01);
        data.push(0x80);
        data.push(0x05);
        data.push(0x80);
        let result = KeyBinding::decode(&data);
        assert!(result.is_err());
    }
}
