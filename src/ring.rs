use crate::errors::NoiseError;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use zeroize::Zeroizing;

pub trait RingKeyProvider: Send + Sync {
    fn derive_device_x25519(
        &self,
        kid: &str,
        device_id: &[u8],
        epoch: u32,
    ) -> Result<[u8; 32], NoiseError>;
    fn ed25519_pubkey(&self, kid: &str) -> Result<[u8; 32], NoiseError>;
    fn sign_ed25519(&self, kid: &str, msg: &[u8]) -> Result<[u8; 64], NoiseError>;
}

pub trait RingKeyFiller: Send + Sync {
    fn with_device_x25519<F, T>(
        &self,
        kid: &str,
        device_id: &[u8],
        epoch: u32,
        f: F,
    ) -> Result<T, NoiseError>
    where
        F: FnOnce(&Zeroizing<[u8; 32]>) -> T;
}
impl<T: RingKeyProvider + ?Sized> RingKeyFiller for T {
    fn with_device_x25519<F, U>(
        &self,
        kid: &str,
        device_id: &[u8],
        epoch: u32,
        f: F,
    ) -> Result<U, NoiseError>
    where
        F: FnOnce(&Zeroizing<[u8; 32]>) -> U,
    {
        let sk = self.derive_device_x25519(kid, device_id, epoch)?;
        let z = Zeroizing::new(sk);
        Ok(f(&z))
    }
}

#[allow(dead_code)]
pub struct DummyRing {
    seed32: [u8; 32],
    kid: String,        // Stored for reference but not directly accessed
    device_id: Vec<u8>, // Stored for reference but not directly accessed
    epoch: u32,         // Stored for reference but not directly accessed
}
impl DummyRing {
    pub fn new_with_device(
        seed32: [u8; 32],
        kid: impl Into<String>,
        device_id: impl AsRef<[u8]>,
        epoch: u32,
    ) -> Self {
        Self {
            seed32,
            kid: kid.into(),
            device_id: device_id.as_ref().to_vec(),
            epoch,
        }
    }
    pub fn new(seed32: [u8; 32], kid: impl Into<String>) -> Self {
        Self {
            seed32,
            kid: kid.into(),
            device_id: b"default".to_vec(),
            epoch: 0,
        }
    }
}
impl RingKeyProvider for DummyRing {
    fn derive_device_x25519(
        &self,
        _kid: &str,
        device_id: &[u8],
        epoch: u32,
    ) -> Result<[u8; 32], NoiseError> {
        let sk = crate::kdf::derive_x25519_for_device_epoch(&self.seed32, device_id, epoch);
        Ok(sk)
    }
    fn ed25519_pubkey(&self, _kid: &str) -> Result<[u8; 32], NoiseError> {
        let signing = SigningKey::from_bytes(&self.seed32);
        let vk: VerifyingKey = signing.verifying_key();
        Ok(vk.to_bytes())
    }
    fn sign_ed25519(&self, _kid: &str, msg: &[u8]) -> Result<[u8; 64], NoiseError> {
        let s = SigningKey::from_bytes(&self.seed32);
        Ok(s.sign(msg).to_bytes())
    }
}
