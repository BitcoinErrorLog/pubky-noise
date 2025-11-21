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

#[uniffi::export]
pub fn derive_device_key(seed: Vec<u8>, device_id: Vec<u8>, epoch: u32) -> Vec<u8> {
    let mut seed_arr = [0u8; 32];
    if seed.len() >= 32 {
        seed_arr.copy_from_slice(&seed[0..32]);
    }
    crate::kdf::derive_x25519_for_device_epoch(&seed_arr, &device_id, epoch).to_vec()
}

#[uniffi::export]
pub fn public_key_from_secret(secret: Vec<u8>) -> Vec<u8> {
    let mut secret_arr = [0u8; 32];
    if secret.len() >= 32 {
        secret_arr.copy_from_slice(&secret[0..32]);
    }
    crate::kdf::x25519_pk_from_sk(&secret_arr).to_vec()
}
