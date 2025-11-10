use serde::{Serialize, Deserialize};
use crate::errors::NoiseError;
use ed25519_dalek::{VerifyingKey, Signature, Verifier};

/// PKARR record that binds the advertised Noise static to the Pubky Ed25519 identity and a rotation epoch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PkarrNoiseRecord {
    pub suite: String, // e.g., "Noise_IK_25519_ChaChaPoly_BLAKE2s"
    pub epoch: u32,
    pub static_x25519_pub: [u8; 32],
    pub ed25519_sig: [u8; 64], // Sign_ed25519("pubky-noise-v1" || suite || epoch_le || static_x25519_pub)
    pub expires_at: Option<u64>,
}

pub trait PkarrResolver: Send + Sync {
    fn fetch_server_noise_record(&self, server_id: &str) -> Result<PkarrNoiseRecord, NoiseError>;
    fn fetch_server_ed25519_pub(&self, server_id: &str) -> Result<[u8; 32], NoiseError>;
    fn client_epoch(&self, _ed25519_pub: &[u8; 32]) -> Result<u32, NoiseError> { Err(NoiseError::Pkarr("client epoch lookup not implemented".into())) }
    fn verify_server_binding(&self, server_id: &str) -> Result<PkarrNoiseRecord, NoiseError> {
        let rec = self.fetch_server_noise_record(server_id)?;
        let ed25519_pub = self.fetch_server_ed25519_pub(server_id)?;
        verify_pkarr_binding(&ed25519_pub, &rec)?;
        Ok(rec)
    }
}

pub fn verify_pkarr_binding(ed25519_pub: &[u8; 32], rec: &PkarrNoiseRecord) -> Result<(), NoiseError> {
    let vk = VerifyingKey::from_bytes(ed25519_pub).map_err(|e| NoiseError::Pkarr(e.to_string()))?;
    let mut msg = b"pubky-noise-v1".to_vec();
    msg.extend_from_slice(rec.suite.as_bytes());
    msg.extend_from_slice(&rec.epoch.to_le_bytes());
    msg.extend_from_slice(&rec.static_x25519_pub);
    let sig = Signature::from_bytes(&rec.ed25519_sig);
    vk.verify(&msg, &sig).map_err(|_| NoiseError::IdentityVerify)
}

pub fn verify_pkarr_binding_with_time(ed25519_pub: &[u8; 32], rec: &PkarrNoiseRecord, now_unix: Option<u64>) -> Result<(), NoiseError> {
    if let (Some(now), Some(exp)) = (now_unix, rec.expires_at) {
        if now > exp {
            return Err(NoiseError::Policy("pkarr record expired".to_string()));
        }
    }
    verify_pkarr_binding(ed25519_pub, rec)
}

/// DummyPkarr keeps maps for server records and expected client epochs.
pub struct DummyPkarr {
    pub map: std::collections::HashMap<String, ([u8; 32], PkarrNoiseRecord)>,
    pub client_epochs: std::collections::HashMap<[u8;32], u32>,
}
impl DummyPkarr {
    pub fn new() -> Self { Self { map: Default::default(), client_epochs: Default::default() } }
    pub fn insert(&mut self, server_id: &str, ed25519_pub: [u8; 32], rec: PkarrNoiseRecord) {
        self.map.insert(server_id.into(), (ed25519_pub, rec));
    }
    pub fn set_client_epoch(&mut self, ed25519_pub: [u8;32], epoch: u32) {
        self.client_epochs.insert(ed25519_pub, epoch);
    }
}
impl crate::pkarr::PkarrResolver for DummyPkarr {
    fn fetch_server_noise_record(&self, server_id: &str) -> Result<PkarrNoiseRecord, NoiseError> {
        self.map.get(server_id).map(|(_, r)| r.clone()).ok_or_else(|| NoiseError::Pkarr("not found".into()))
    }
    fn fetch_server_ed25519_pub(&self, server_id: &str) -> Result<[u8; 32], NoiseError> {
        self.map.get(server_id).map(|(p, _)| *p).ok_or_else(|| NoiseError::Pkarr("not found".into()))
    }
    fn client_epoch(&self, ed25519_pub: &[u8; 32]) -> Result<u32, NoiseError> {
        self.client_epochs.get(ed25519_pub).cloned().ok_or_else(|| NoiseError::Pkarr("client epoch not found".into()))
    }
}
