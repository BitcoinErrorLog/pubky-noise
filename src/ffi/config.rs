use crate::ffi::errors::FfiNoiseError;
use crate::ffi::types::FfiMobileConfig;
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
            message: "Seed must be at least 32 bytes".to_string(),
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
            message: "Secret must be at least 32 bytes".to_string(),
        });
    }
    let mut secret_arr = [0u8; 32];
    secret_arr.copy_from_slice(&secret[0..32]);
    Ok(crate::kdf::x25519_pk_from_sk(&secret_arr).to_vec())
}
