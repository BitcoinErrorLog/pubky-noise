//! pkarr integration helpers for X25519 key discovery.
//!
//! This module provides utilities for working with pkarr (Public Key Addressable
//! Resource Records) in the context of Noise protocol key discovery.
//!
//! # Architecture
//!
//! In the Pubky ecosystem, identity is based on Ed25519 keys stored in pkarr.
//! For Noise sessions, we need X25519 keys. This module helps with:
//!
//! 1. **Publishing**: Formatting X25519 keys for pkarr TXT records
//! 2. **Discovery**: Parsing X25519 keys from pkarr responses
//! 3. **Binding**: Verifying Ed25519 -> X25519 key binding signatures
//!
//! # Cold Key Pattern
//!
//! When Ed25519 keys are kept cold:
//! 1. Derive X25519 key from Ed25519 (one-time, offline)
//! 2. Sign binding message (Ed25519 signs X25519 pubkey)
//! 3. Publish to pkarr: `_noise.{device}` TXT record
//! 4. Noise peers lookup X25519 key via pkarr before connecting
//!
//! # TXT Record Format
//!
//! ```text
//! _noise.{device_id}.{pubky}  IN TXT "v=1;k={base64_x25519_pk};sig={base64_signature}"
//! ```

use crate::NoiseError;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

/// pkarr TXT record version
pub const PKARR_NOISE_VERSION: &str = "1";

/// Prefix for Noise key TXT records
pub const PKARR_NOISE_PREFIX: &str = "_noise";

/// Parse X25519 public key from a pkarr TXT record value.
///
/// Expects format: `v=1;k={base64_x25519_pk};sig={base64_signature}`
///
/// # Arguments
/// * `txt_record` - The TXT record value string
///
/// # Returns
/// The 32-byte X25519 public key
///
/// # Example
/// ```
/// use pubky_noise::pkarr_helpers::parse_x25519_from_pkarr;
///
/// let txt = "v=1;k=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=;sig=AAAA...";
/// // Would parse the base64-encoded key
/// ```
pub fn parse_x25519_from_pkarr(txt_record: &str) -> Result<[u8; 32], NoiseError> {
    let parts: std::collections::HashMap<&str, &str> = txt_record
        .split(';')
        .filter_map(|part| {
            let mut kv = part.splitn(2, '=');
            Some((kv.next()?, kv.next()?))
        })
        .collect();

    // Verify version
    let version = parts
        .get("v")
        .ok_or_else(|| NoiseError::Other("Missing version in pkarr record".to_string()))?;
    if *version != PKARR_NOISE_VERSION {
        return Err(NoiseError::Other(format!(
            "Unsupported pkarr version: {}",
            version
        )));
    }

    // Extract key
    let key_b64 = parts
        .get("k")
        .ok_or_else(|| NoiseError::Other("Missing key in pkarr record".to_string()))?;

    let key_bytes = BASE64
        .decode(key_b64)
        .map_err(|e| NoiseError::Other(format!("Invalid base64 key: {}", e)))?;

    if key_bytes.len() != 32 {
        return Err(NoiseError::Other(format!(
            "Invalid key length: {} (expected 32)",
            key_bytes.len()
        )));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);
    Ok(key)
}

/// Format X25519 public key for pkarr publication.
///
/// Creates a TXT record value with the X25519 public key and optional
/// Ed25519 signature binding.
///
/// # Arguments
/// * `x25519_pk` - 32-byte X25519 public key
/// * `signature` - Optional 64-byte Ed25519 signature over the binding message
///
/// # Returns
/// Formatted TXT record value
///
/// # Example
/// ```
/// use pubky_noise::pkarr_helpers::format_x25519_for_pkarr;
///
/// let x25519_pk = [0u8; 32];
/// let txt = format_x25519_for_pkarr(&x25519_pk, None);
/// assert!(txt.starts_with("v=1;k="));
/// ```
pub fn format_x25519_for_pkarr(x25519_pk: &[u8; 32], signature: Option<&[u8; 64]>) -> String {
    let key_b64 = BASE64.encode(x25519_pk);

    match signature {
        Some(sig) => {
            let sig_b64 = BASE64.encode(sig);
            format!("v={};k={};sig={}", PKARR_NOISE_VERSION, key_b64, sig_b64)
        }
        None => format!("v={};k={}", PKARR_NOISE_VERSION, key_b64),
    }
}

/// Generate the pkarr subdomain for a device's Noise key.
///
/// # Arguments
/// * `device_id` - Device identifier string
///
/// # Returns
/// Subdomain string like `_noise.device123`
pub fn pkarr_noise_subdomain(device_id: &str) -> String {
    format!("{}.{}", PKARR_NOISE_PREFIX, device_id)
}

/// Create the binding message that ties an X25519 key to an Ed25519 identity.
///
/// This message is signed by the Ed25519 key to prove ownership of the X25519 key.
///
/// # Arguments
/// * `ed25519_pk` - 32-byte Ed25519 public key (identity)
/// * `x25519_pk` - 32-byte X25519 public key (session key)
/// * `device_id` - Device identifier for scoping
///
/// # Returns
/// 32-byte binding message suitable for Ed25519 signing
pub fn create_pkarr_binding_message(
    ed25519_pk: &[u8; 32],
    x25519_pk: &[u8; 32],
    device_id: &str,
) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(b"pubky-noise-pkarr-binding-v1:");
    hasher.update(ed25519_pk);
    hasher.update(x25519_pk);
    hasher.update(device_id.as_bytes());

    let result = hasher.finalize();
    let mut binding = [0u8; 32];
    binding.copy_from_slice(&result);
    binding
}

/// Verify that an X25519 key is properly bound to an Ed25519 identity.
///
/// # Arguments
/// * `ed25519_pk` - 32-byte Ed25519 public key (identity)
/// * `x25519_pk` - 32-byte X25519 public key (from pkarr)
/// * `signature` - 64-byte Ed25519 signature
/// * `device_id` - Device identifier used in binding
///
/// # Returns
/// `true` if the signature is valid
pub fn verify_pkarr_key_binding(
    ed25519_pk: &[u8; 32],
    x25519_pk: &[u8; 32],
    signature: &[u8; 64],
    device_id: &str,
) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let binding_msg = create_pkarr_binding_message(ed25519_pk, x25519_pk, device_id);

    let Ok(verifying_key) = VerifyingKey::from_bytes(ed25519_pk) else {
        return false;
    };

    let sig = Signature::from_bytes(signature);

    verifying_key.verify(&binding_msg, &sig).is_ok()
}

/// Sign an X25519 key binding with an Ed25519 secret key.
///
/// Creates a signature that proves the Ed25519 identity owns the X25519 key.
///
/// # Arguments
/// * `ed25519_sk` - 32-byte Ed25519 secret key
/// * `x25519_pk` - 32-byte X25519 public key to bind
/// * `device_id` - Device identifier for scoping
///
/// # Returns
/// 64-byte Ed25519 signature
pub fn sign_pkarr_key_binding(
    ed25519_sk: &[u8; 32],
    x25519_pk: &[u8; 32],
    device_id: &str,
) -> [u8; 64] {
    use ed25519_dalek::{Signer, SigningKey};

    let signing_key = SigningKey::from_bytes(ed25519_sk);
    let ed25519_pk = signing_key.verifying_key().to_bytes();
    let binding_msg = create_pkarr_binding_message(&ed25519_pk, x25519_pk, device_id);

    let signature = signing_key.sign(&binding_msg);
    signature.to_bytes()
}

/// Parse a pkarr TXT record and verify its key binding.
///
/// This is the complete validation flow for cold key scenarios:
/// 1. Parse the TXT record to extract X25519 key and signature
/// 2. Verify the signature binds the key to the Ed25519 identity
///
/// # Arguments
/// * `txt_record` - The TXT record value string
/// * `ed25519_pk` - The expected Ed25519 identity public key
/// * `device_id` - Device identifier used in binding
///
/// # Returns
/// The verified 32-byte X25519 public key
pub fn parse_and_verify_pkarr_key(
    txt_record: &str,
    ed25519_pk: &[u8; 32],
    device_id: &str,
) -> Result<[u8; 32], NoiseError> {
    // Parse parts
    let parts: std::collections::HashMap<&str, &str> = txt_record
        .split(';')
        .filter_map(|part| {
            let mut kv = part.splitn(2, '=');
            Some((kv.next()?, kv.next()?))
        })
        .collect();

    // Get key
    let x25519_pk = parse_x25519_from_pkarr(txt_record)?;

    // Get and verify signature
    let sig_b64 = parts
        .get("sig")
        .ok_or_else(|| NoiseError::Other("Missing signature in pkarr record".to_string()))?;

    let sig_bytes = BASE64
        .decode(sig_b64)
        .map_err(|e| NoiseError::Other(format!("Invalid base64 signature: {}", e)))?;

    if sig_bytes.len() != 64 {
        return Err(NoiseError::Other(format!(
            "Invalid signature length: {} (expected 64)",
            sig_bytes.len()
        )));
    }

    let mut signature = [0u8; 64];
    signature.copy_from_slice(&sig_bytes);

    if !verify_pkarr_key_binding(ed25519_pk, &x25519_pk, &signature, device_id) {
        return Err(NoiseError::Other(
            "Invalid pkarr key binding signature".to_string(),
        ));
    }

    Ok(x25519_pk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_and_parse_roundtrip() {
        let x25519_pk = [42u8; 32];
        let txt = format_x25519_for_pkarr(&x25519_pk, None);

        let parsed = parse_x25519_from_pkarr(&txt).unwrap();
        assert_eq!(parsed, x25519_pk);
    }

    #[test]
    fn test_sign_and_verify_binding() {
        // Generate Ed25519 keypair
        use ed25519_dalek::SigningKey;
        use rand::RngCore;

        let mut ed25519_sk_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut ed25519_sk_bytes);
        let signing_key = SigningKey::from_bytes(&ed25519_sk_bytes);
        let ed25519_sk = signing_key.to_bytes();
        let ed25519_pk = signing_key.verifying_key().to_bytes();

        // Generate X25519 keypair  
        let x25519_pk_bytes = [99u8; 32];

        let device_id = "device-123";

        // Sign binding
        let signature = sign_pkarr_key_binding(&ed25519_sk, &x25519_pk_bytes, device_id);

        // Verify binding
        assert!(verify_pkarr_key_binding(
            &ed25519_pk,
            &x25519_pk_bytes,
            &signature,
            device_id
        ));

        // Wrong device_id should fail
        assert!(!verify_pkarr_key_binding(
            &ed25519_pk,
            &x25519_pk_bytes,
            &signature,
            "wrong-device"
        ));
    }

    #[test]
    fn test_full_pkarr_flow() {
        use ed25519_dalek::SigningKey;
        use rand::RngCore;

        // Setup keys
        let mut ed25519_sk_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut ed25519_sk_bytes);
        let signing_key = SigningKey::from_bytes(&ed25519_sk_bytes);
        let ed25519_sk = signing_key.to_bytes();
        let ed25519_pk = signing_key.verifying_key().to_bytes();

        let x25519_pk = [99u8; 32];
        let device_id = "my-phone";

        // Sign and format for publication
        let signature = sign_pkarr_key_binding(&ed25519_sk, &x25519_pk, device_id);
        let txt = format_x25519_for_pkarr(&x25519_pk, Some(&signature));

        // Simulate pkarr lookup and verification
        let verified_key = parse_and_verify_pkarr_key(&txt, &ed25519_pk, device_id).unwrap();
        assert_eq!(verified_key, x25519_pk);
    }

    #[test]
    fn test_subdomain_format() {
        assert_eq!(pkarr_noise_subdomain("phone1"), "_noise.phone1");
        assert_eq!(
            pkarr_noise_subdomain("laptop-main"),
            "_noise.laptop-main"
        );
    }

    #[test]
    fn test_parse_errors() {
        // Missing version
        assert!(parse_x25519_from_pkarr("k=AAAA").is_err());

        // Wrong version
        assert!(parse_x25519_from_pkarr("v=99;k=AAAA").is_err());

        // Missing key
        assert!(parse_x25519_from_pkarr("v=1").is_err());

        // Invalid base64
        assert!(parse_x25519_from_pkarr("v=1;k=!!!invalid!!!").is_err());
    }
}

