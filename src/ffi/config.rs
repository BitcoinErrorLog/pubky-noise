use crate::ffi::errors::FfiNoiseError;
use crate::ffi::types::{FfiMobileConfig, FfiX25519Keypair};
use crate::mobile_manager::MobileConfig;

#[uniffi::export]
pub fn default_config() -> FfiMobileConfig {
    MobileConfig::default().into()
}

#[uniffi::export]
pub fn battery_saver_config() -> FfiMobileConfig {
    MobileConfig {
        auto_reconnect: false,
        max_reconnect_attempts: 2,
        reconnect_delay_ms: 2000,
        battery_saver: true,
        chunk_size: 16384,
    }
    .into()
}

#[uniffi::export]
pub fn performance_config() -> FfiMobileConfig {
    MobileConfig {
        auto_reconnect: true,
        max_reconnect_attempts: 10,
        reconnect_delay_ms: 100,
        battery_saver: false,
        chunk_size: 65536,
    }
    .into()
}

/// Derive an X25519 device key from seed, device ID, and epoch.
///
/// # Errors
///
/// Returns `FfiNoiseError::Ring` if seed is less than 32 bytes.
/// Returns `FfiNoiseError::Other` if key derivation fails (extremely rare).
#[uniffi::export]
pub fn derive_device_key(
    seed: Vec<u8>,
    device_id: Vec<u8>,
    epoch: u32,
) -> Result<Vec<u8>, FfiNoiseError> {
    if seed.len() < 32 {
        return Err(FfiNoiseError::Ring {
            msg: "Seed must be at least 32 bytes".to_string(),
        });
    }
    let mut seed_arr = [0u8; 32];
    seed_arr.copy_from_slice(&seed[0..32]);
    let sk = crate::kdf::derive_x25519_for_device_epoch(&seed_arr, &device_id, epoch)?;
    Ok(sk.to_vec())
}

/// Derive a public key from a 32-byte secret.
///
/// # Errors
///
/// Returns `FfiNoiseError::Ring` if secret is less than 32 bytes.
#[uniffi::export]
pub fn public_key_from_secret(secret: Vec<u8>) -> Result<Vec<u8>, FfiNoiseError> {
    if secret.len() < 32 {
        return Err(FfiNoiseError::Ring {
            msg: "Secret must be at least 32 bytes".to_string(),
        });
    }
    let mut secret_arr = [0u8; 32];
    secret_arr.copy_from_slice(&secret[0..32]);
    Ok(crate::kdf::x25519_pk_from_sk(&secret_arr).to_vec())
}

/// Derive a full X25519 keypair from seed, device ID, and epoch.
///
/// This is a convenience function that combines `derive_device_key` and
/// `public_key_from_secret` to return both the secret and public keys.
///
/// # Errors
///
/// Returns `FfiNoiseError::Ring` if seed is less than 32 bytes.
/// Returns `FfiNoiseError::Other` if key derivation fails.
#[uniffi::export]
pub fn derive_device_keypair(
    seed: Vec<u8>,
    device_id: Vec<u8>,
    epoch: u32,
) -> Result<FfiX25519Keypair, FfiNoiseError> {
    if seed.len() < 32 {
        return Err(FfiNoiseError::Ring {
            msg: "Seed must be at least 32 bytes".to_string(),
        });
    }
    let mut seed_arr = [0u8; 32];
    seed_arr.copy_from_slice(&seed[0..32]);
    let sk = crate::kdf::derive_x25519_for_device_epoch(&seed_arr, &device_id, epoch)?;
    let pk = crate::kdf::x25519_pk_from_sk(&sk);
    Ok(FfiX25519Keypair {
        secret_key: sk.to_vec(),
        public_key: pk.to_vec(),
    })
}

// ============================================================================
// Sealed Blob v1 FFI Exports
// ============================================================================

/// Generate a new X25519 keypair for sealed blob encryption.
///
/// Returns a record containing secret_key and public_key, each 32 bytes.
/// The secret_key should be zeroized after use.
#[uniffi::export]
pub fn x25519_generate_keypair() -> FfiX25519Keypair {
    let (sk, pk) = crate::sealed_blob::x25519_generate_keypair();
    FfiX25519Keypair {
        secret_key: sk.to_vec(),
        public_key: pk.to_vec(),
    }
}

/// Derive X25519 public key from a 32-byte secret key.
///
/// # Errors
///
/// Returns `FfiNoiseError::Ring` if secret is not 32 bytes.
#[uniffi::export]
pub fn x25519_public_from_secret(secret: Vec<u8>) -> Result<Vec<u8>, FfiNoiseError> {
    if secret.len() != 32 {
        return Err(FfiNoiseError::Ring {
            msg: format!("Secret must be exactly 32 bytes, got {}", secret.len()),
        });
    }
    let mut secret_arr = [0u8; 32];
    secret_arr.copy_from_slice(&secret);
    Ok(crate::sealed_blob::x25519_public_from_secret(&secret_arr).to_vec())
}

/// Encrypt plaintext using Paykit Sealed Blob v1 format.
///
/// # Arguments
///
/// * `recipient_pk` - Recipient's X25519 public key (32 bytes)
/// * `plaintext` - Data to encrypt (max 64 KiB)
/// * `aad` - Associated authenticated data (e.g., "handoff:pubkey:/path")
/// * `purpose` - Optional purpose hint ("handoff", "request", "proposal")
///
/// # Returns
///
/// JSON-encoded sealed blob envelope.
///
/// # Errors
///
/// Returns `FfiNoiseError::Ring` if recipient_pk is not 32 bytes.
/// Returns `FfiNoiseError::Other` if plaintext exceeds 64 KiB.
#[uniffi::export]
pub fn sealed_blob_encrypt(
    recipient_pk: Vec<u8>,
    plaintext: Vec<u8>,
    aad: String,
    purpose: Option<String>,
) -> Result<String, FfiNoiseError> {
    if recipient_pk.len() != 32 {
        return Err(FfiNoiseError::Ring {
            msg: format!(
                "Recipient public key must be 32 bytes, got {}",
                recipient_pk.len()
            ),
        });
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&recipient_pk);
    crate::sealed_blob::sealed_blob_encrypt(
        &pk_arr,
        &plaintext,
        &aad,
        purpose.as_deref(),
    )
    .map_err(FfiNoiseError::from)
}

/// Decrypt a Paykit Sealed Blob v1 envelope.
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
///
/// # Errors
///
/// Returns `FfiNoiseError::Ring` if recipient_sk is not 32 bytes.
/// Returns `FfiNoiseError::Decryption` if decryption fails (wrong key, wrong AAD, or tampered).
#[uniffi::export]
pub fn sealed_blob_decrypt(
    recipient_sk: Vec<u8>,
    envelope_json: String,
    aad: String,
) -> Result<Vec<u8>, FfiNoiseError> {
    if recipient_sk.len() != 32 {
        return Err(FfiNoiseError::Ring {
            msg: format!(
                "Recipient secret key must be 32 bytes, got {}",
                recipient_sk.len()
            ),
        });
    }
    let mut sk_arr = [0u8; 32];
    sk_arr.copy_from_slice(&recipient_sk);
    crate::sealed_blob::sealed_blob_decrypt(&sk_arr, &envelope_json, &aad)
        .map_err(FfiNoiseError::from)
}

/// Check if a JSON string looks like a sealed blob envelope.
///
/// This is a quick heuristic check for distinguishing encrypted from legacy plaintext.
#[uniffi::export]
pub fn is_sealed_blob(json: String) -> bool {
    crate::sealed_blob::is_sealed_blob(&json)
}
