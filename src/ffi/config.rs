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
// Sealed Blob v2 FFI Exports (v1 backward compatible for decryption)
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

/// Encrypt plaintext using Paykit Sealed Blob v2 format (XChaCha20-Poly1305).
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
/// JSON-encoded sealed blob v2 envelope.
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

/// Decrypt a Paykit Sealed Blob v1 or v2 envelope (auto-detects version).
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

/// Check if a JSON string looks like a sealed blob envelope (v1 or v2).
///
/// Requires both version field (`"v":1` or `"v":2`) AND ephemeral public key (`"epk":`).
/// This is a quick heuristic check for distinguishing encrypted from legacy plaintext.
#[uniffi::export]
pub fn is_sealed_blob(json: String) -> bool {
    crate::sealed_blob::is_sealed_blob(&json)
}

/// Derive noise seed from Ed25519 secret key using HKDF-SHA256.
///
/// This is used to derive future X25519 epoch keys locally without
/// needing to call Ring again. The seed is domain-separated and
/// cannot be used for signing.
///
/// HKDF parameters:
/// - salt: "paykit-noise-seed-v1"
/// - ikm: Ed25519 secret key (32 bytes)
/// - info: device ID
/// - output: 32 bytes
///
/// # Arguments
///
/// * `ed25519_secret_hex` - Ed25519 secret key as 64-char hex string (32 bytes)
/// * `device_id_hex` - Device ID as hex string
///
/// # Returns
///
/// 64-character hex string of the 32-byte noise seed.
///
/// # Errors
///
/// Returns `FfiNoiseError::Ring` if input is invalid.
#[uniffi::export]
pub fn derive_noise_seed(
    ed25519_secret_hex: String,
    device_id_hex: String,
) -> Result<String, FfiNoiseError> {
    let secret_bytes = hex::decode(&ed25519_secret_hex).map_err(|e| FfiNoiseError::Ring {
        msg: format!("Invalid hex for Ed25519 secret key: {}", e),
    })?;

    if secret_bytes.len() != 32 {
        return Err(FfiNoiseError::Ring {
            msg: format!(
                "Ed25519 secret key must be 32 bytes, got {}",
                secret_bytes.len()
            ),
        });
    }

    let device_id = hex::decode(&device_id_hex).map_err(|e| FfiNoiseError::Ring {
        msg: format!("Invalid hex for device ID: {}", e),
    })?;

    let mut sk_arr = [0u8; 32];
    sk_arr.copy_from_slice(&secret_bytes);

    let seed = crate::kdf::derive_noise_seed(&sk_arr, &device_id).map_err(FfiNoiseError::from)?;
    Ok(hex::encode(seed))
}

/// Sign an arbitrary message with an Ed25519 secret key.
///
/// # Arguments
///
/// * `ed25519_secret_hex` - 64-character hex string of the 32-byte Ed25519 secret key
/// * `message_hex` - Hex-encoded message bytes to sign
///
/// # Returns
///
/// 128-character hex string of the 64-byte Ed25519 signature.
#[uniffi::export]
pub fn ed25519_sign(
    ed25519_secret_hex: String,
    message_hex: String,
) -> Result<String, FfiNoiseError> {
    let secret_bytes = hex::decode(&ed25519_secret_hex).map_err(|e| FfiNoiseError::Ring {
        msg: format!("Invalid hex for secret key: {}", e),
    })?;

    if secret_bytes.len() != 32 {
        return Err(FfiNoiseError::Ring {
            msg: format!(
                "Ed25519 secret key must be 32 bytes, got {}",
                secret_bytes.len()
            ),
        });
    }

    let message_bytes = hex::decode(&message_hex).map_err(|e| FfiNoiseError::Ring {
        msg: format!("Invalid hex for message: {}", e),
    })?;

    let mut sk_arr = [0u8; 32];
    sk_arr.copy_from_slice(&secret_bytes);

    let signature = crate::identity_payload::ed25519_sign(&sk_arr, &message_bytes)
        .map_err(FfiNoiseError::from)?;

    Ok(hex::encode(signature))
}

/// Verify an Ed25519 signature.
///
/// # Arguments
///
/// * `ed25519_public_hex` - 64-character hex string of the 32-byte Ed25519 public key
/// * `message_hex` - Hex-encoded message bytes that were signed
/// * `signature_hex` - 128-character hex string of the 64-byte signature
///
/// # Returns
///
/// `true` if the signature is valid, `false` otherwise.
#[uniffi::export]
pub fn ed25519_verify(
    ed25519_public_hex: String,
    message_hex: String,
    signature_hex: String,
) -> Result<bool, FfiNoiseError> {
    let public_bytes = hex::decode(&ed25519_public_hex).map_err(|e| FfiNoiseError::Ring {
        msg: format!("Invalid hex for public key: {}", e),
    })?;

    if public_bytes.len() != 32 {
        return Err(FfiNoiseError::Ring {
            msg: format!(
                "Ed25519 public key must be 32 bytes, got {}",
                public_bytes.len()
            ),
        });
    }

    let message_bytes = hex::decode(&message_hex).map_err(|e| FfiNoiseError::Ring {
        msg: format!("Invalid hex for message: {}", e),
    })?;

    let signature_bytes = hex::decode(&signature_hex).map_err(|e| FfiNoiseError::Ring {
        msg: format!("Invalid hex for signature: {}", e),
    })?;

    if signature_bytes.len() != 64 {
        return Err(FfiNoiseError::Ring {
            msg: format!(
                "Ed25519 signature must be 64 bytes, got {}",
                signature_bytes.len()
            ),
        });
    }

    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&public_bytes);

    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&signature_bytes);

    Ok(crate::identity_payload::ed25519_verify(
        &pk_arr,
        &message_bytes,
        &sig_arr,
    ))
}
