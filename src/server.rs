use crate::errors::NoiseError;
use crate::ring::{RingKeyProvider, RingKeyFiller};
use crate::identity_payload::{IdentityPayload, Role, make_binding_message, verify_identity_payload};
use secrecy::Zeroizing;

#[derive(Clone, Debug, Default)]
pub struct ServerPolicy {
    pub max_handshakes_per_ip: Option<u32>,
    pub max_sessions_per_ed25519: Option<u32>,
    pub min_client_epoch: Option<u32>,
}

pub struct NoiseServer<R: RingKeyProvider, P> {
    pub kid: String,
    pub device_id: Vec<u8>,
    pub ring: std::sync::Arc<R>,
    #[cfg(feature="pkarr")] pub pkarr: std::sync::Arc<P>,
    pub prologue: Vec<u8>,
    pub suite: String,
    pub current_epoch: u32,
    pub seen_client_epochs: std::sync::Mutex<std::collections::HashMap<[u8;32], u32>>,
    pub policy: ServerPolicy,
}

impl<R: RingKeyProvider, P> NoiseServer<R, P> {
    pub fn new_direct(kid: impl Into<String>, device_id: impl AsRef<[u8]>, ring: std::sync::Arc<R>, current_epoch: u32) -> Self {
        Self {
            kid: kid.into(),
            device_id: device_id.as_ref().to_vec(),
            ring,
            #[cfg(feature="pkarr")] pkarr: std::sync::Arc::new(crate::pkarr::DummyPkarr::new()),
            prologue: b"pubky-noise-v1".to_vec(),
            suite: "Noise_IK_25519_ChaChaPoly_BLAKE2s".into(),
            current_epoch,
            seen_client_epochs: std::sync::Mutex::new(Default::default()),
            policy: ServerPolicy::default(),
        }
    }

    pub fn build_responder_read_ik(&self, first_msg: &[u8]) -> Result<(snow::HandshakeState, IdentityPayload), NoiseError> {
        let suite = self.suite.parse().map_err(|e| NoiseError::Other(e.to_string()))?;
        let mut builder = snow::Builder::new(suite);

        let hs = self.ring.with_device_x25519(&self.kid, &self.device_id, self.current_epoch, |x_sk: &Zeroizing<[u8;32]>| {
            builder.local_private_key(x_sk);
            builder.prologue(&self.prologue);
            builder.build_responder().map_err(NoiseError::from)
        })?;
        let mut hs = hs?;

        let x_pk = hs.get_local_static().expect("local static").to_vec();
        let mut x_pk_arr = [0u8;32]; x_pk_arr.copy_from_slice(&x_pk[..32]);

        let mut buf = vec![0u8; first_msg.len() + 256];
        let n = hs.read_message(first_msg, &mut buf)?;
        let payload: IdentityPayload = serde_json::from_slice(&buf[..n])?;

        // Reject all-zero shared secret with client static
        let ok = self.ring.with_device_x25519(&self.kid, &self.device_id, self.current_epoch, |x_sk: &Zeroizing<[u8;32]>| {
            crate::kdf::shared_secret_nonzero(x_sk, &payload.noise_x25519_pub)
        })?;
        if !ok { return Err(NoiseError::InvalidPeerKey) }

        let tag = "IK";
        let msg32 = make_binding_message(tag, &self.prologue, &payload.ed25519_pub, &payload.noise_x25519_pub, Some(&x_pk_arr), payload.epoch, Role::Client, payload.server_hint.as_deref());
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&payload.ed25519_pub).map_err(|e| NoiseError::Other(e.to_string()))?;
        let ok = verify_identity_payload(&vk, &msg32, &payload.sig);
        if !ok { return Err(NoiseError::IdentityVerify) }

        Ok((hs, payload))
    }
}
