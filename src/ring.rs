use crate::errors::NoiseError;

/// RingKeyProvider is implemented by Pubky Ring or a local cached device store.
/// Abstraction over Pubky Ring or a local delegated devicestore for cold operation.
pub trait RingKeyProvider: Send + Sync {
    /// Return a device+epoch-scoped X25519 static secret.
    fn derive_device_x25519(&self, kid: &str, device_id: &[u8], epoch: u32) -> Result<[u8; 32], NoiseError>;

    /// Return the Ed25519 verifying key bytes (public) for identity binding.
    fn ed25519_pubkey(&self, kid: &str) -> Result<[u8; 32], NoiseError>;

    /// Sign with Ed25519. In production, Ring signs; a cached device-delegated key may sign when Ring is cold.
    fn sign_ed25519(&self, kid: &str, msg: &[u8]) -> Result<[u8; 64], NoiseError>;
}

/// DummyRing is for tests only. It holds a seed and signs locally.
pub struct DummyRing {
    seed32: [u8; 32],
    kid: String,
    device_id: Vec<u8>,
    epoch: u32,
}

impl DummyRing {
    pub fn new_with_device(seed32: [u8; 32], kid: impl Into<String>, device_id: impl AsRef<[u8]>, epoch: u32) -> Self {
        Self { seed32, kid: kid.into(), device_id: device_id.as_ref().to_vec(), epoch }
    }
    pub fn new(seed32: [u8; 32], kid: impl Into<String>) -> Self {
        Self { seed32, kid: kid.into(), device_id: b"default".to_vec(), epoch: 0 }
    }
    pub fn set_epoch(&mut self, epoch: u32) { self.epoch = epoch; }
    pub fn device_id(&self) -> &[u8] { &self.device_id }
    pub fn epoch(&self) -> u32 { self.epoch }
}

impl RingKeyProvider for DummyRing {
    fn derive_device_x25519(&self, _kid: &str, device_id: &[u8], epoch: u32) -> Result<[u8; 32], NoiseError> {
        let mut seed = self.seed32;
        let sk = crate::kdf::derive_x25519_for_device_epoch(&seed, device_id, epoch);
        Ok(sk)
    }
    fn ed25519_pubkey(&self, _kid: &str) -> Result<[u8; 32], NoiseError> {
        use ed25519_dalek::{SigningKey, VerifyingKey};
        let signing = SigningKey::from_bytes(&self.seed32);
        let vk: VerifyingKey = signing.verifying_key();
        Ok(vk.to_bytes())
    }
    fn sign_ed25519(&self, _kid: &str, msg: &[u8]) -> Result<[u8; 64], NoiseError> {
        use ed25519_dalek::{SigningKey, Signer};
        let s = SigningKey::from_bytes(&self.seed32);
        Ok(s.sign(msg).to_bytes())
    }
}
