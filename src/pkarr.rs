//! PKARR integration for server static key discovery (optional feature).

use crate::errors::NoiseError;
use serde::{Deserialize, Serialize};

/// PKARR noise record containing server's static key and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PkarrNoiseRecord {
    pub suite: String,
    #[serde(with = "serde_bytes")]
    pub static_x25519_pub: [u8; 32],
    #[serde(with = "serde_big_array")]
    pub ed25519_sig: [u8; 64],
    pub expires_at: Option<u64>,
}

mod serde_big_array {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(arr: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_bytes::serialize(arr.as_slice(), serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde_bytes::deserialize(deserializer)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom(format!(
                "expected 64 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

/// Trait for resolving server noise records via PKARR.
pub trait PkarrResolver: Send + Sync {
    fn fetch_server_noise_record(&self, server_id: &str) -> Result<PkarrNoiseRecord, NoiseError>;
    fn fetch_server_ed25519_pub(&self, server_id: &str) -> Result<[u8; 32], NoiseError>;
}

/// Dummy PKARR resolver for testing (returns errors for all operations).
pub struct DummyPkarr;

impl DummyPkarr {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DummyPkarr {
    fn default() -> Self {
        Self::new()
    }
}

impl PkarrResolver for DummyPkarr {
    fn fetch_server_noise_record(&self, _server_id: &str) -> Result<PkarrNoiseRecord, NoiseError> {
        Err(NoiseError::Pkarr("DummyPkarr: not implemented".to_string()))
    }

    fn fetch_server_ed25519_pub(&self, _server_id: &str) -> Result<[u8; 32], NoiseError> {
        Err(NoiseError::Pkarr("DummyPkarr: not implemented".to_string()))
    }
}
