#![cfg(feature = "pkarr")]
use crate::errors::NoiseError;
use serde::{Deserialize, Serialize};

// Helper for serializing [u8; 64]
mod signature_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom("signature must be 64 bytes"));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PkarrNoiseRecord {
    pub suite: String,
    pub epoch: u32,
    pub static_x25519_pub: [u8; 32],
    #[serde(with = "signature_serde")]
    pub ed25519_sig: [u8; 64],
    pub expires_at: Option<u64>,
}
pub trait PkarrResolver: Send + Sync {
    fn fetch_server_noise_record(&self, server_id: &str) -> Result<PkarrNoiseRecord, NoiseError>;
    fn fetch_server_ed25519_pub(&self, server_id: &str) -> Result<[u8; 32], NoiseError>;
}
pub struct DummyPkarr;
impl DummyPkarr {
    pub fn new() -> Self {
        Self
    }
}
