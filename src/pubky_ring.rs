//! Pubky SDK integration for RingKeyProvider (optional feature).

use crate::errors::NoiseError;
use crate::ring::RingKeyProvider;
use pubky::Keypair;

pub struct PubkyRingProvider {
    keypair: Keypair,
    #[allow(dead_code)]
    device_id: Vec<u8>,
}

impl PubkyRingProvider {
    pub fn new(keypair: Keypair, device_id: impl AsRef<[u8]>) -> Self {
        Self {
            keypair,
            device_id: device_id.as_ref().to_vec(),
        }
    }
}

impl RingKeyProvider for PubkyRingProvider {
    fn derive_device_x25519(
        &self,
        _kid: &str,
        device_id: &[u8],
        epoch: u32,
    ) -> Result<[u8; 32], NoiseError> {
        let seed = self.keypair.secret_key();
        let sk = crate::kdf::derive_x25519_for_device_epoch(&seed, device_id, epoch);
        Ok(sk)
    }

    fn ed25519_pubkey(&self, _kid: &str) -> Result<[u8; 32], NoiseError> {
        Ok(self.keypair.public_key().to_bytes())
    }

    fn sign_ed25519(&self, _kid: &str, msg: &[u8]) -> Result<[u8; 64], NoiseError> {
        Ok(self.keypair.sign(msg).to_bytes())
    }
}
