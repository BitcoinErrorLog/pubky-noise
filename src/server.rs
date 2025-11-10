use crate::errors::NoiseError;
use crate::ring::RingKeyProvider;
use crate::identity_payload::{IdentityPayload, Role, make_binding_message, verify_identity_payload};
use crate::kdf::{x25519_pk_from_sk};
use zeroize::Zeroize;

/// NoiseServer handles IK as a responder. It enforces a local epoch policy and payload signature.
/// Server-side Noise responder that enforces epoch policy and verifies the client identity payload.
pub struct NoiseServer<R: RingKeyProvider> {
    pub kid: String,       // server identity id
    pub device_id: Vec<u8>,
    pub ring: std::sync::Arc<R>,
    pub prologue: Vec<u8>,
    pub suite: String,
    pub current_epoch: u32,
}

impl<R: RingKeyProvider> NoiseServer<R> {
    pub fn new(kid: impl Into<String>, device_id: impl AsRef<[u8]>, ring: std::sync::Arc<R>, current_epoch: u32) -> Self {
        Self {
            kid: kid.into(),
            device_id: device_id.as_ref().to_vec(),
            ring,
            prologue: b"pubky-data-v1:role=server".to_vec(),
            suite: "Noise_IK_25519_ChaChaPoly_BLAKE2s".into(),
            current_epoch: current_epoch,
        }
    }

    /// Build responder
        #[cfg(feature="trace")] tracing::debug!(suite=%self.suite, "build responder"); and process the first IK message. Verifies client's identity payload signature
    /// and enforces that client's declared epoch matches server policy (configurable per deployment).
    pub fn build_responder_and_read(&self, first_msg: &[u8]) -> Result<(snow::HandshakeState, IdentityPayload), NoiseError> {
        // Derive server static for its current epoch
        #[cfg(feature="trace")] tracing::debug!(epoch=self.current_epoch, kid=%self.kid, device_id=%hex::encode(&self.device_id), "derive server x25519");
        let x_sk = self.ring.derive_device_x25519(&self.kid, &self.device_id, self.current_epoch)?;
        let x_pk = x25519_pk_from_sk(&x_sk);

        // Build responder
        #[cfg(feature="trace")] tracing::debug!(suite=%self.suite, "build responder");
        let params: snow::params::NoiseParams = self.suite.parse().map_err(|e| NoiseError::Other(e.to_string()))?;
        let mut builder = snow::Builder::new(params);
        let mut hs = builder
            .local_private_key(&x_sk)
            .prologue(&self.prologue)
            .build_responder()?;

        let mut tmp = x_sk;
        tmp.zeroize();

        // Read first handshake message
        #[cfg(feature="trace")] tracing::debug!("reading first handshake message");
        let mut buf = vec![0u8; 2048];
        let n = hs.read_message(first_msg, &mut buf)?;
        let payload: IdentityPayload = serde_json::from_slice(&buf[..n])?;

        // Policy: enforce that client epoch equals our current epoch (or customize policy)
        #[cfg(feature="trace")] tracing::debug!(client_epoch=payload.epoch, server_epoch=self.current_epoch, "check epoch policy");
        if payload.epoch != self.current_epoch {
            return Err(NoiseError::Policy(format!("client epoch {} not accepted (server expects {})", payload.epoch, self.current_epoch)));
        }

        // Verify binding signature
        #[cfg(feature="trace")] tracing::debug!("verify identity binding signature");
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
