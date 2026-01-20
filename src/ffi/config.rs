use crate::ffi::errors::FfiNoiseError;
use crate::ffi::types::{FfiMobileConfig, FfiX25519Keypair, FfiEd25519Keypair, FfiAppCertResult};
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

/// Encrypt using Sealed Blob v2 with spec-compliant AAD construction.
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
#[uniffi::export]
pub fn sealed_blob_encrypt_with_context(
    recipient_pk: Vec<u8>,
    plaintext: Vec<u8>,
    owner_peerid: Vec<u8>,
    canonical_path: String,
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
    if owner_peerid.len() != 32 {
        return Err(FfiNoiseError::Ring {
            msg: format!(
                "Owner peerid must be 32 bytes, got {}",
                owner_peerid.len()
            ),
        });
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&recipient_pk);
    let mut owner_arr = [0u8; 32];
    owner_arr.copy_from_slice(&owner_peerid);
    
    crate::sealed_blob::sealed_blob_encrypt_with_context(
        &pk_arr,
        &plaintext,
        &owner_arr,
        &canonical_path,
        purpose.as_deref(),
    )
    .map_err(FfiNoiseError::from)
}

/// Decrypt Sealed Blob v2 with spec-compliant AAD construction.
///
/// This function computes AAD internally per PUBKY_CRYPTO_SPEC Section 7.5.
///
/// # Arguments
///
/// * `recipient_sk` - Recipient's X25519 secret key (32 bytes)
/// * `envelope_json` - JSON-encoded sealed blob v2 envelope
/// * `owner_peerid` - Storage owner's Ed25519 public key (32 bytes)
/// * `canonical_path` - Canonical storage path (must match encryption)
///
/// # Returns
///
/// Decrypted plaintext.
#[uniffi::export]
pub fn sealed_blob_decrypt_with_context(
    recipient_sk: Vec<u8>,
    envelope_json: String,
    owner_peerid: Vec<u8>,
    canonical_path: String,
) -> Result<Vec<u8>, FfiNoiseError> {
    if recipient_sk.len() != 32 {
        return Err(FfiNoiseError::Ring {
            msg: format!(
                "Recipient secret key must be 32 bytes, got {}",
                recipient_sk.len()
            ),
        });
    }
    if owner_peerid.len() != 32 {
        return Err(FfiNoiseError::Ring {
            msg: format!(
                "Owner peerid must be 32 bytes, got {}",
                owner_peerid.len()
            ),
        });
    }
    let mut sk_arr = [0u8; 32];
    sk_arr.copy_from_slice(&recipient_sk);
    let mut owner_arr = [0u8; 32];
    owner_arr.copy_from_slice(&owner_peerid);
    
    crate::sealed_blob::sealed_blob_decrypt_with_context(
        &sk_arr,
        &envelope_json,
        &owner_arr,
        &canonical_path,
    )
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

/// Derive Ed25519 public key from secret key.
///
/// # Arguments
///
/// * `ed25519_secret_hex` - Ed25519 secret key (seed) as 64-char hex string (32 bytes)
///
/// # Returns
///
/// Ed25519 public key as 64-char hex string (32 bytes).
#[uniffi::export]
pub fn ed25519_public_from_secret(ed25519_secret_hex: String) -> Result<String, FfiNoiseError> {
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

    let mut sk_arr = [0u8; 32];
    sk_arr.copy_from_slice(&secret_bytes);

    use ed25519_dalek::SigningKey;
    let signing_key = SigningKey::from_bytes(&sk_arr);
    let public_key = signing_key.verifying_key();
    
    Ok(hex::encode(public_key.as_bytes()))
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

// ============================================================================
// UKD (Unified Key Delegation) Functions
// ============================================================================

/// Generate a new Ed25519 keypair for use as an AppKey.
///
/// # Returns
///
/// FfiEd25519Keypair with secret_key_hex and public_key_hex, each 64 chars (32 bytes).
#[uniffi::export]
pub fn generate_app_keypair() -> FfiEd25519Keypair {
    let (sk, pk) = crate::ukd::generate_app_keypair();
    FfiEd25519Keypair {
        secret_key_hex: hex::encode(sk),
        public_key_hex: hex::encode(pk),
    }
}

/// Issue an AppCert by signing with the root Ed25519 secret key.
///
/// # Arguments
///
/// * `root_sk_hex` - Root PKARR Ed25519 secret key as hex (64 chars)
/// * `app_id` - Application identifier (e.g., "pubky.app", "paykit")
/// * `app_ed25519_pub_hex` - Delegated signing key as hex (64 chars)
/// * `transport_x25519_pub_hex` - Delegated Noise static key as hex (64 chars)
/// * `inbox_x25519_pub_hex` - Delegated inbox encryption key as hex (64 chars)
/// * `device_id_hex` - Optional device ID as hex
/// * `scopes` - Optional capability scopes
/// * `expires_at` - Optional expiration timestamp (Unix seconds)
///
/// # Returns
///
/// FfiAppCertResult with cert_body_hex, sig_hex, and cert_id_hex.
#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn issue_app_cert(
    root_sk_hex: String,
    app_id: String,
    app_ed25519_pub_hex: String,
    transport_x25519_pub_hex: String,
    inbox_x25519_pub_hex: String,
    device_id_hex: Option<String>,
    scopes: Option<Vec<String>>,
    expires_at: Option<u64>,
) -> Result<FfiAppCertResult, FfiNoiseError> {
    // Parse root secret key
    let root_sk_bytes = hex::decode(&root_sk_hex).map_err(|e| FfiNoiseError::Ring {
        msg: format!("Invalid hex for root secret key: {}", e),
    })?;
    if root_sk_bytes.len() != 32 {
        return Err(FfiNoiseError::Ring {
            msg: format!("Root secret key must be 32 bytes, got {}", root_sk_bytes.len()),
        });
    }
    let mut root_sk = [0u8; 32];
    root_sk.copy_from_slice(&root_sk_bytes);
    
    // Derive issuer_peerid from root_sk
    use ed25519_dalek::SigningKey;
    let signing_key = SigningKey::from_bytes(&root_sk);
    let issuer_peerid = *signing_key.verifying_key().as_bytes();
    
    // Parse app public key
    let app_pk_bytes = hex::decode(&app_ed25519_pub_hex).map_err(|e| FfiNoiseError::Ring {
        msg: format!("Invalid hex for app public key: {}", e),
    })?;
    if app_pk_bytes.len() != 32 {
        return Err(FfiNoiseError::Ring {
            msg: format!("App public key must be 32 bytes, got {}", app_pk_bytes.len()),
        });
    }
    let mut app_ed25519_pub = [0u8; 32];
    app_ed25519_pub.copy_from_slice(&app_pk_bytes);
    
    // Parse transport public key
    let transport_pk_bytes = hex::decode(&transport_x25519_pub_hex).map_err(|e| FfiNoiseError::Ring {
        msg: format!("Invalid hex for transport public key: {}", e),
    })?;
    if transport_pk_bytes.len() != 32 {
        return Err(FfiNoiseError::Ring {
            msg: format!("Transport public key must be 32 bytes, got {}", transport_pk_bytes.len()),
        });
    }
    let mut transport_x25519_pub = [0u8; 32];
    transport_x25519_pub.copy_from_slice(&transport_pk_bytes);
    
    // Parse inbox public key
    let inbox_pk_bytes = hex::decode(&inbox_x25519_pub_hex).map_err(|e| FfiNoiseError::Ring {
        msg: format!("Invalid hex for inbox public key: {}", e),
    })?;
    if inbox_pk_bytes.len() != 32 {
        return Err(FfiNoiseError::Ring {
            msg: format!("Inbox public key must be 32 bytes, got {}", inbox_pk_bytes.len()),
        });
    }
    let mut inbox_x25519_pub = [0u8; 32];
    inbox_x25519_pub.copy_from_slice(&inbox_pk_bytes);
    
    // Parse optional device_id
    let device_id = if let Some(ref did_hex) = device_id_hex {
        Some(hex::decode(did_hex).map_err(|e| FfiNoiseError::Ring {
            msg: format!("Invalid hex for device ID: {}", e),
        })?)
    } else {
        None
    };
    
    let input = crate::ukd::AppCertInput {
        issuer_peerid,
        app_id,
        device_id,
        app_ed25519_pub,
        transport_x25519_pub,
        inbox_x25519_pub,
        scopes,
        not_before: None,
        expires_at,
        flags: None,
    };
    
    let cert = crate::ukd::issue_app_cert(&root_sk, &input).map_err(FfiNoiseError::from)?;
    
    Ok(FfiAppCertResult {
        cert_body_hex: hex::encode(&cert.cert_body),
        sig_hex: hex::encode(cert.sig),
        cert_id_hex: hex::encode(cert.cert_id),
    })
}

/// Verify an AppCert signature.
///
/// # Arguments
///
/// * `issuer_peerid_hex` - Root PKARR Ed25519 public key as hex (64 chars)
/// * `cert_body_hex` - Raw cert_body bytes as hex
/// * `sig_hex` - Ed25519 signature as hex (128 chars)
///
/// # Returns
///
/// cert_id as hex (32 chars) if valid.
#[uniffi::export]
pub fn verify_app_cert(
    issuer_peerid_hex: String,
    cert_body_hex: String,
    sig_hex: String,
) -> Result<String, FfiNoiseError> {
    let issuer_bytes = hex::decode(&issuer_peerid_hex).map_err(|e| FfiNoiseError::Ring {
        msg: format!("Invalid hex for issuer peerid: {}", e),
    })?;
    if issuer_bytes.len() != 32 {
        return Err(FfiNoiseError::Ring {
            msg: format!("Issuer peerid must be 32 bytes, got {}", issuer_bytes.len()),
        });
    }
    let mut issuer_peerid = [0u8; 32];
    issuer_peerid.copy_from_slice(&issuer_bytes);
    
    let cert_body = hex::decode(&cert_body_hex).map_err(|e| FfiNoiseError::Ring {
        msg: format!("Invalid hex for cert body: {}", e),
    })?;
    
    let sig_bytes = hex::decode(&sig_hex).map_err(|e| FfiNoiseError::Ring {
        msg: format!("Invalid hex for signature: {}", e),
    })?;
    if sig_bytes.len() != 64 {
        return Err(FfiNoiseError::Ring {
            msg: format!("Signature must be 64 bytes, got {}", sig_bytes.len()),
        });
    }
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&sig_bytes);
    
    let cert_id = crate::ukd::verify_app_cert(&issuer_peerid, &cert_body, &sig)
        .map_err(FfiNoiseError::from)?;
    
    Ok(hex::encode(cert_id))
}

/// Sign typed content with an AppKey per UKD spec.
///
/// This is a TYPED signing function, not a generic "sign anything" API.
/// The content_type parameter constrains what is being signed.
///
/// # Arguments
///
/// * `app_sk_hex` - AppKey Ed25519 secret key as hex (64 chars)
/// * `issuer_peerid_hex` - Root PKARR Ed25519 public key as hex (64 chars)
/// * `cert_id_hex` - AppCert identifier as hex (32 chars)
/// * `content_type` - ASCII label describing what is signed (e.g., "pubky.post")
/// * `payload_hex` - Content payload as hex
///
/// # Returns
///
/// 64-byte Ed25519 signature as hex (128 chars).
#[uniffi::export]
pub fn sign_typed_content(
    app_sk_hex: String,
    issuer_peerid_hex: String,
    cert_id_hex: String,
    content_type: String,
    payload_hex: String,
) -> Result<String, FfiNoiseError> {
    let app_sk_bytes = hex::decode(&app_sk_hex).map_err(|e| FfiNoiseError::Ring {
        msg: format!("Invalid hex for app secret key: {}", e),
    })?;
    if app_sk_bytes.len() != 32 {
        return Err(FfiNoiseError::Ring {
            msg: format!("App secret key must be 32 bytes, got {}", app_sk_bytes.len()),
        });
    }
    let mut app_sk = [0u8; 32];
    app_sk.copy_from_slice(&app_sk_bytes);
    
    let issuer_bytes = hex::decode(&issuer_peerid_hex).map_err(|e| FfiNoiseError::Ring {
        msg: format!("Invalid hex for issuer peerid: {}", e),
    })?;
    if issuer_bytes.len() != 32 {
        return Err(FfiNoiseError::Ring {
            msg: format!("Issuer peerid must be 32 bytes, got {}", issuer_bytes.len()),
        });
    }
    let mut issuer_peerid = [0u8; 32];
    issuer_peerid.copy_from_slice(&issuer_bytes);
    
    let cert_id_bytes = hex::decode(&cert_id_hex).map_err(|e| FfiNoiseError::Ring {
        msg: format!("Invalid hex for cert ID: {}", e),
    })?;
    if cert_id_bytes.len() != 16 {
        return Err(FfiNoiseError::Ring {
            msg: format!("Cert ID must be 16 bytes, got {}", cert_id_bytes.len()),
        });
    }
    let mut cert_id = [0u8; 16];
    cert_id.copy_from_slice(&cert_id_bytes);
    
    let payload = hex::decode(&payload_hex).map_err(|e| FfiNoiseError::Ring {
        msg: format!("Invalid hex for payload: {}", e),
    })?;
    
    let sig = crate::ukd::sign_typed_content(
        &app_sk,
        &issuer_peerid,
        &cert_id,
        &content_type,
        &payload,
    ).map_err(FfiNoiseError::from)?;
    
    Ok(hex::encode(sig))
}

/// Verify typed content signature.
///
/// # Arguments
///
/// * `app_ed25519_pub_hex` - AppKey Ed25519 public key as hex (64 chars)
/// * `issuer_peerid_hex` - Root PKARR Ed25519 public key as hex (64 chars)
/// * `cert_id_hex` - AppCert identifier as hex (32 chars)
/// * `content_type` - ASCII label describing what is signed
/// * `payload_hex` - Content payload as hex
/// * `sig_hex` - Signature to verify as hex (128 chars)
///
/// # Returns
///
/// true if valid.
#[uniffi::export]
pub fn verify_typed_content(
    app_ed25519_pub_hex: String,
    issuer_peerid_hex: String,
    cert_id_hex: String,
    content_type: String,
    payload_hex: String,
    sig_hex: String,
) -> Result<bool, FfiNoiseError> {
    let app_pk_bytes = hex::decode(&app_ed25519_pub_hex).map_err(|e| FfiNoiseError::Ring {
        msg: format!("Invalid hex for app public key: {}", e),
    })?;
    if app_pk_bytes.len() != 32 {
        return Err(FfiNoiseError::Ring {
            msg: format!("App public key must be 32 bytes, got {}", app_pk_bytes.len()),
        });
    }
    let mut app_ed25519_pub = [0u8; 32];
    app_ed25519_pub.copy_from_slice(&app_pk_bytes);
    
    let issuer_bytes = hex::decode(&issuer_peerid_hex).map_err(|e| FfiNoiseError::Ring {
        msg: format!("Invalid hex for issuer peerid: {}", e),
    })?;
    if issuer_bytes.len() != 32 {
        return Err(FfiNoiseError::Ring {
            msg: format!("Issuer peerid must be 32 bytes, got {}", issuer_bytes.len()),
        });
    }
    let mut issuer_peerid = [0u8; 32];
    issuer_peerid.copy_from_slice(&issuer_bytes);
    
    let cert_id_bytes = hex::decode(&cert_id_hex).map_err(|e| FfiNoiseError::Ring {
        msg: format!("Invalid hex for cert ID: {}", e),
    })?;
    if cert_id_bytes.len() != 16 {
        return Err(FfiNoiseError::Ring {
            msg: format!("Cert ID must be 16 bytes, got {}", cert_id_bytes.len()),
        });
    }
    let mut cert_id = [0u8; 16];
    cert_id.copy_from_slice(&cert_id_bytes);
    
    let payload = hex::decode(&payload_hex).map_err(|e| FfiNoiseError::Ring {
        msg: format!("Invalid hex for payload: {}", e),
    })?;
    
    let sig_bytes = hex::decode(&sig_hex).map_err(|e| FfiNoiseError::Ring {
        msg: format!("Invalid hex for signature: {}", e),
    })?;
    if sig_bytes.len() != 64 {
        return Err(FfiNoiseError::Ring {
            msg: format!("Signature must be 64 bytes, got {}", sig_bytes.len()),
        });
    }
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&sig_bytes);
    
    crate::ukd::verify_typed_content(
        &app_ed25519_pub,
        &issuer_peerid,
        &cert_id,
        &content_type,
        &payload,
        &sig,
    ).map_err(FfiNoiseError::from)?;
    
    Ok(true)
}
