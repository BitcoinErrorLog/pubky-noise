#![cfg(feature="pkarr")]
use serde::{Serialize, Deserialize};
use crate::errors::NoiseError;
use ed25519_dalek::{VerifyingKey, Signature, Verifier};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PkarrNoiseRecord {
    pub suite: String,
    pub epoch: u32,
    pub static_x25519_pub: [u8; 32],
    pub ed25519_sig: [u8; 64],
    pub expires_at: Option<u64>,
}
pub trait PkarrResolver: Send + Sync {
    fn fetch_server_noise_record(&self, server_id: &str) -> Result<PkarrNoiseRecord, NoiseError>;
    fn fetch_server_ed25519_pub(&self, server_id: &str) -> Result<[u8; 32], NoiseError>;
}
pub struct DummyPkarr;
impl DummyPkarr { pub fn new() -> Self { Self } }
