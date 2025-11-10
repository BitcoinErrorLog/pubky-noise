use crate::errors::NoiseError;
use crate::ring::RingKeyProvider;
use crate::identity_payload::{IdentityPayload, Role, make_binding_message, verify_identity_payload};
use crate::kdf::{x25519_pk_from_sk};
use zeroize::Zeroize;

#[derive(Clone, Debug, Default)]
pub struct ServerPolicy {
    pub max_handshakes_per_ip: Option<u32>,
    pub max_sessions_per_ed25519: Option<u32>,
    pub min_client_epoch: Option<u32>,
}

/// Server-side Noise responder that enforces epoch policy and verifies the client identity payload.
pub struct NoiseServer<R: RingKeyProvider, P: crate::pkarr::PkarrResolver> {
    pub kid: String,
    pub device_id: Vec<u8>,
    pub ring: std::sync::Arc<R>,
    pub pkarr: std::sync::Arc<P>,
    pub prologue: Vec<u8>,
    pub suite: String,
    pub current_epoch: u32,
    pub seen_client_epochs: std::sync::Mutex<std::collections::HashMap<[u8;32], u32>>,
    pub policy: ServerPolicy,
}

impl<R: RingKeyProvider, P: crate::pkarr::PkarrResolver> NoiseServer<R, P> {
    pub fn new(kid: impl Into<String>, device_id: impl AsRef<[u8]>, ring: std::sync::Arc<R>, pkarr: std::sync::Arc<P>, current_epoch: u32) -> Self {
        Self {
            kid: kid.into(),
            device_id: device_id.as_ref().to_vec(),
            ring,
            pkarr,
            prologue: b"pubky-noise-v1".to_vec(),
            suite: "Noise_IK_25519_ChaChaPoly_BLAKE2s".into(),
            current_epoch,
            seen_client_epochs: std::sync::Mutex::new(Default::default()),
            policy: ServerPolicy::default(),
        }
    }

    pub fn build_responder_and_read(&self, first_msg: &[u8]) -> Result<(snow::HandshakeState, IdentityPayload), NoiseError> {
        let mut x_sk = self.ring.derive_device_x25519(&self.kid, &self.device_id, self.current_epoch)?;
        let x_pk = x25519_pk_from_sk(&x_sk);

        let params: snow::params::NoiseParams = self.suite.parse().map_err(|e| NoiseError::Other(e.to_string()))?;
        let mut builder = snow::Builder::new(params);
        let mut hs = builder
            .local_private_key(&x_sk)
            .prologue(&self.prologue)
            .build_responder()?;

        x_sk.zeroize();

        let mut buf = vec![0u8; first_msg.len() + 256];
        let n = hs.read_message(first_msg, &mut buf)?;
        let payload: IdentityPayload = serde_json::from_slice(&buf[..n])?;

        let expected = self.pkarr.client_epoch(&payload.ed25519_pub).map_err(|_| NoiseError::Policy("client epoch unknown".into()))?;
        if payload.epoch != expected {
            return Err(NoiseError::Policy(format!("client epoch {} not accepted (expected {})", payload.epoch, expected)));
        }

        if let Ok(mut map) = self.seen_client_epochs.lock() {
            if let Some(prev) = map.get(&payload.ed25519_pub) {
                if payload.epoch < *prev {
                    return Err(NoiseError::Policy(format!("client epoch regression {} -> {}", payload.epoch, prev)));
                }
            }
            map.insert(payload.ed25519_pub, payload.epoch);
        }

        let tag = "IK";
        let msg32 = make_binding_message(
            tag,
            &self.prologue,
            &payload.ed25519_pub,
            &payload.noise_x25519_pub,
            Some(&x_pk),
            payload.epoch,
            Role::Client,
            payload.server_hint.as_deref(),
        );
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&payload.ed25519_pub).map_err(|e| NoiseError::Other(e.to_string()))?;
        let ok = verify_identity_payload(&vk, &msg32, &payload.sig);
        if !ok { return Err(NoiseError::IdentityVerify) }

        Ok((hs, payload))
    }
}
