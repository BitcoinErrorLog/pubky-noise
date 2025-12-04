//! FFI wrappers for pkarr-related functions.
//!
//! These functions enable mobile apps to:
//! - Sign X25519 key bindings with Ed25519 identity keys (cold signing)
//! - Format keys for pkarr publication
//! - Parse and verify keys from pkarr records

use crate::ffi::errors::FfiNoiseError;

/// Sign an X25519 key binding with an Ed25519 secret key.
///
/// This creates a signature proving that the Ed25519 identity owns the X25519 key.
/// Use this during cold key setup - the Ed25519 key can be stored cold afterward.
///
/// # Arguments
/// * `ed25519_sk` - 32-byte Ed25519 secret key
/// * `x25519_pk` - 32-byte X25519 public key to bind
/// * `device_id` - Device identifier for scoping
///
/// # Returns
/// 64-byte Ed25519 signature
#[uniffi::export]
pub fn ffi_sign_pkarr_key_binding(
    ed25519_sk: Vec<u8>,
    x25519_pk: Vec<u8>,
    device_id: String,
) -> Result<Vec<u8>, FfiNoiseError> {
    let ed25519_sk = parse_key_32(&ed25519_sk, "Ed25519 secret key")?;
    let x25519_pk = parse_key_32(&x25519_pk, "X25519 public key")?;

    let signature =
        crate::pkarr_helpers::sign_pkarr_key_binding(&ed25519_sk, &x25519_pk, &device_id);

    Ok(signature.to_vec())
}

/// Format an X25519 public key for pkarr publication.
///
/// Creates a TXT record value with the X25519 public key and optional signature.
///
/// # Arguments
/// * `x25519_pk` - 32-byte X25519 public key
/// * `signature` - Optional 64-byte Ed25519 signature over the binding message
///
/// # Returns
/// Formatted TXT record value string (e.g., "v=1;k=...;sig=...")
#[uniffi::export]
pub fn ffi_format_x25519_for_pkarr(
    x25519_pk: Vec<u8>,
    signature: Option<Vec<u8>>,
) -> Result<String, FfiNoiseError> {
    let x25519_pk = parse_key_32(&x25519_pk, "X25519 public key")?;

    let sig_arr = match signature {
        Some(sig) => {
            if sig.len() != 64 {
                return Err(FfiNoiseError::Ring {
                    message: format!("Signature must be 64 bytes, got {}", sig.len()),
                });
            }
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&sig);
            Some(arr)
        }
        None => None,
    };

    Ok(crate::pkarr_helpers::format_x25519_for_pkarr(
        &x25519_pk,
        sig_arr.as_ref(),
    ))
}

/// Format an X25519 public key for pkarr publication with timestamp.
///
/// Creates a TXT record value including a Unix timestamp for freshness validation.
/// Recommended for production use.
///
/// # Arguments
/// * `x25519_pk` - 32-byte X25519 public key
/// * `signature` - Optional 64-byte Ed25519 signature
/// * `timestamp` - Unix timestamp (seconds since epoch)
///
/// # Returns
/// Formatted TXT record value string (e.g., "v=1;k=...;sig=...;ts=...")
#[uniffi::export]
pub fn ffi_format_x25519_for_pkarr_with_timestamp(
    x25519_pk: Vec<u8>,
    signature: Option<Vec<u8>>,
    timestamp: u64,
) -> Result<String, FfiNoiseError> {
    let x25519_pk = parse_key_32(&x25519_pk, "X25519 public key")?;

    let sig_arr = match signature {
        Some(sig) => {
            if sig.len() != 64 {
                return Err(FfiNoiseError::Ring {
                    message: format!("Signature must be 64 bytes, got {}", sig.len()),
                });
            }
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&sig);
            Some(arr)
        }
        None => None,
    };

    Ok(crate::pkarr_helpers::format_x25519_for_pkarr_with_timestamp(
        &x25519_pk,
        sig_arr.as_ref(),
        timestamp,
    ))
}

/// Parse an X25519 public key from a pkarr TXT record value.
///
/// Extracts the X25519 key without signature verification.
/// Use `ffi_parse_and_verify_pkarr_key` for verified parsing.
///
/// # Arguments
/// * `txt_record` - TXT record value string (e.g., "v=1;k=...;sig=...")
///
/// # Returns
/// 32-byte X25519 public key
#[uniffi::export]
pub fn ffi_parse_x25519_from_pkarr(txt_record: String) -> Result<Vec<u8>, FfiNoiseError> {
    let key = crate::pkarr_helpers::parse_x25519_from_pkarr(&txt_record)
        .map_err(|e| FfiNoiseError::Pkarr {
            message: format!("Failed to parse pkarr record: {}", e),
        })?;

    Ok(key.to_vec())
}

/// Parse and verify an X25519 public key from a pkarr TXT record.
///
/// This is the secure method that verifies the Ed25519 signature binding
/// the X25519 key to the identity.
///
/// # Arguments
/// * `txt_record` - TXT record value string
/// * `ed25519_pk` - 32-byte Ed25519 public key of the identity
/// * `device_id` - Device identifier used in the binding
///
/// # Returns
/// 32-byte X25519 public key (only if signature is valid)
#[uniffi::export]
pub fn ffi_parse_and_verify_pkarr_key(
    txt_record: String,
    ed25519_pk: Vec<u8>,
    device_id: String,
) -> Result<Vec<u8>, FfiNoiseError> {
    let ed25519_pk = parse_key_32(&ed25519_pk, "Ed25519 public key")?;

    let key = crate::pkarr_helpers::parse_and_verify_pkarr_key(&txt_record, &ed25519_pk, &device_id)
        .map_err(|e| FfiNoiseError::Pkarr {
            message: format!("Failed to verify pkarr key: {}", e),
        })?;

    Ok(key.to_vec())
}

/// Parse and verify an X25519 key with timestamp expiry check.
///
/// This is the recommended secure method for production use.
/// Verifies both the Ed25519 signature and the key freshness.
///
/// # Arguments
/// * `txt_record` - TXT record value string
/// * `ed25519_pk` - 32-byte Ed25519 public key
/// * `device_id` - Device identifier
/// * `max_age_seconds` - Maximum acceptable key age
///
/// # Returns
/// 32-byte X25519 public key if all checks pass
#[uniffi::export]
pub fn ffi_parse_and_verify_with_expiry(
    txt_record: String,
    ed25519_pk: Vec<u8>,
    device_id: String,
    max_age_seconds: u64,
) -> Result<Vec<u8>, FfiNoiseError> {
    let ed25519_pk = parse_key_32(&ed25519_pk, "Ed25519 public key")?;

    let key = crate::pkarr_helpers::parse_and_verify_with_expiry(
        &txt_record,
        &ed25519_pk,
        &device_id,
        max_age_seconds,
    )
    .map_err(|e| FfiNoiseError::Pkarr {
        message: format!("Failed to verify pkarr key with expiry: {}", e),
    })?;

    Ok(key.to_vec())
}

/// Extract timestamp from a pkarr TXT record.
///
/// # Arguments
/// * `txt_record` - TXT record value string
///
/// # Returns
/// Timestamp in Unix seconds, or None if not present
#[uniffi::export]
pub fn ffi_extract_timestamp_from_pkarr(txt_record: String) -> Option<u64> {
    crate::pkarr_helpers::extract_timestamp_from_pkarr(&txt_record)
}

/// Verify a pkarr key binding signature.
///
/// # Arguments
/// * `ed25519_pk` - 32-byte Ed25519 public key
/// * `x25519_pk` - 32-byte X25519 public key
/// * `signature` - 64-byte Ed25519 signature
/// * `device_id` - Device identifier used in the binding
///
/// # Returns
/// true if the signature is valid
#[uniffi::export]
pub fn ffi_verify_pkarr_key_binding(
    ed25519_pk: Vec<u8>,
    x25519_pk: Vec<u8>,
    signature: Vec<u8>,
    device_id: String,
) -> Result<bool, FfiNoiseError> {
    let ed25519_pk = parse_key_32(&ed25519_pk, "Ed25519 public key")?;
    let x25519_pk = parse_key_32(&x25519_pk, "X25519 public key")?;

    if signature.len() != 64 {
        return Err(FfiNoiseError::Ring {
            message: format!("Signature must be 64 bytes, got {}", signature.len()),
        });
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&signature);

    Ok(crate::pkarr_helpers::verify_pkarr_key_binding(
        &ed25519_pk,
        &x25519_pk,
        &sig_arr,
        &device_id,
    ))
}

/// Get the pkarr subdomain for a device's noise key.
///
/// # Arguments
/// * `device_id` - Device identifier string
///
/// # Returns
/// Subdomain string like "_noise.device123"
#[uniffi::export]
pub fn ffi_pkarr_noise_subdomain(device_id: String) -> String {
    crate::pkarr_helpers::pkarr_noise_subdomain(&device_id)
}

/// Create the binding message that ties an X25519 key to an Ed25519 identity.
///
/// This is the message that gets signed during cold key setup.
///
/// # Arguments
/// * `ed25519_pk` - 32-byte Ed25519 public key
/// * `x25519_pk` - 32-byte X25519 public key
/// * `device_id` - Device identifier
///
/// # Returns
/// 32-byte binding message
#[uniffi::export]
pub fn ffi_create_pkarr_binding_message(
    ed25519_pk: Vec<u8>,
    x25519_pk: Vec<u8>,
    device_id: String,
) -> Result<Vec<u8>, FfiNoiseError> {
    let ed25519_pk = parse_key_32(&ed25519_pk, "Ed25519 public key")?;
    let x25519_pk = parse_key_32(&x25519_pk, "X25519 public key")?;

    let binding =
        crate::pkarr_helpers::create_pkarr_binding_message(&ed25519_pk, &x25519_pk, &device_id);

    Ok(binding.to_vec())
}

// Helper function
fn parse_key_32(bytes: &[u8], name: &str) -> Result<[u8; 32], FfiNoiseError> {
    if bytes.len() != 32 {
        return Err(FfiNoiseError::Ring {
            message: format!("{} must be 32 bytes, got {}", name, bytes.len()),
        });
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_and_parse_roundtrip() {
        let x25519_pk = vec![42u8; 32];
        let txt = ffi_format_x25519_for_pkarr(x25519_pk.clone(), None).unwrap();

        let parsed = ffi_parse_x25519_from_pkarr(txt).unwrap();
        assert_eq!(parsed, x25519_pk);
    }

    #[test]
    fn test_sign_and_verify_roundtrip() {
        // Generate Ed25519 keypair
        use ed25519_dalek::SigningKey;
        use rand::RngCore;

        let mut ed25519_sk_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut ed25519_sk_bytes);
        let signing_key = SigningKey::from_bytes(&ed25519_sk_bytes);
        let ed25519_pk = signing_key.verifying_key().to_bytes();

        let x25519_pk = vec![99u8; 32];
        let device_id = "test-device".to_string();

        // Sign
        let signature =
            ffi_sign_pkarr_key_binding(ed25519_sk_bytes.to_vec(), x25519_pk.clone(), device_id.clone())
                .unwrap();

        // Verify
        let valid = ffi_verify_pkarr_key_binding(
            ed25519_pk.to_vec(),
            x25519_pk,
            signature,
            device_id,
        )
        .unwrap();

        assert!(valid);
    }

    #[test]
    fn test_subdomain_format() {
        let subdomain = ffi_pkarr_noise_subdomain("phone1".to_string());
        assert_eq!(subdomain, "_noise.phone1");
    }

    #[test]
    fn test_invalid_key_lengths() {
        assert!(ffi_sign_pkarr_key_binding(vec![0u8; 16], vec![0u8; 32], "".to_string()).is_err());
        assert!(ffi_sign_pkarr_key_binding(vec![0u8; 32], vec![0u8; 16], "".to_string()).is_err());
        assert!(ffi_format_x25519_for_pkarr(vec![0u8; 16], None).is_err());
    }
}

