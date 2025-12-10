use crate::errors::NoiseError;
use crate::identity_payload::{
    make_binding_message, verify_identity_payload, BindingMessageParams, IdentityPayload, Role,
};
use crate::ring::{RingKeyFiller, RingKeyProvider};
use std::marker::PhantomData;
use zeroize::Zeroizing;

/// Internal epoch value - always 0 (epoch is not a user-facing concept).
const INTERNAL_EPOCH: u32 = 0;

/// Server policy configuration.
#[derive(Clone, Debug, Default)]
pub struct ServerPolicy {
    /// Maximum handshakes allowed per IP address (rate limiting).
    pub max_handshakes_per_ip: Option<u32>,
    /// Maximum sessions allowed per Ed25519 identity.
    pub max_sessions_per_ed25519: Option<u32>,
}

pub struct NoiseServer<R: RingKeyProvider, P = ()> {
    pub kid: String,
    pub device_id: Vec<u8>,
    pub ring: std::sync::Arc<R>,
    _phantom: PhantomData<P>,
    pub prologue: Vec<u8>,
    pub suite: String,
    pub current_epoch: u32,
    pub seen_client_epochs: std::sync::Mutex<std::collections::HashMap<[u8; 32], u32>>,
    pub policy: ServerPolicy,
}

impl<R: RingKeyProvider, P> NoiseServer<R, P> {
    /// Create a new Noise server for direct connections.
    ///
    /// # Arguments
    ///
    /// * `kid` - Key identifier.
    /// * `device_id` - Device identifier for key derivation.
    /// * `ring` - Key provider for cryptographic operations.
    pub fn new_direct(
        kid: impl Into<String>,
        device_id: impl AsRef<[u8]>,
        ring: std::sync::Arc<R>,
    ) -> Self {
        Self {
            kid: kid.into(),
            device_id: device_id.as_ref().to_vec(),
            ring,
            _phantom: PhantomData,
            prologue: b"pubky-noise-v1".to_vec(),
            suite: "Noise_IK_25519_ChaChaPoly_BLAKE2s".into(),
            current_epoch: INTERNAL_EPOCH,
            seen_client_epochs: std::sync::Mutex::new(Default::default()),
            policy: ServerPolicy::default(),
        }
    }

    /// Build a responder for IK pattern handshake.
    ///
    /// # Arguments
    ///
    /// * `first_msg` - The first handshake message from the client.
    ///
    /// # Returns
    ///
    /// A tuple of (HandshakeState, client IdentityPayload).
    pub fn build_responder_read_ik(
        &self,
        first_msg: &[u8],
    ) -> Result<(snow::HandshakeState, IdentityPayload), NoiseError> {
        let suite = self
            .suite
            .parse::<snow::params::NoiseParams>()
            .map_err(|e: snow::Error| NoiseError::Other(e.to_string()))?;
        let builder = snow::Builder::new(suite);

        let (hs, x_pk_arr) = self.ring.with_device_x25519(
            &self.kid,
            &self.device_id,
            INTERNAL_EPOCH,
            |x_sk: &Zeroizing<[u8; 32]>| -> Result<(snow::HandshakeState, [u8; 32]), NoiseError> {
                // Derive public key from private key before passing to builder
                let x_pk_arr = crate::kdf::x25519_pk_from_sk(x_sk);

                // Chain builder calls since each method consumes and returns self
                let hs = builder
                    .local_private_key(&**x_sk) // Deref Zeroizing to &[u8; 32] to &[u8]
                    .prologue(&self.prologue)
                    .build_responder()
                    .map_err(NoiseError::from)?;
                Ok((hs, x_pk_arr))
            },
        )??;

        let mut hs = hs;

        let mut buf = vec![0u8; first_msg.len() + 256];
        let n = hs.read_message(first_msg, &mut buf)?;
        let payload: IdentityPayload = serde_json::from_slice(&buf[..n])?;

        // Reject all-zero shared secret with client static
        let ok = self.ring.with_device_x25519(
            &self.kid,
            &self.device_id,
            INTERNAL_EPOCH,
            |x_sk: &Zeroizing<[u8; 32]>| {
                crate::kdf::shared_secret_nonzero(x_sk, &payload.noise_x25519_pub)
            },
        )?;
        if !ok {
            return Err(NoiseError::InvalidPeerKey);
        }

        let msg32 = make_binding_message(&BindingMessageParams {
            pattern_tag: "IK",
            prologue: &self.prologue,
            ed25519_pub: &payload.ed25519_pub,
            local_noise_pub: &payload.noise_x25519_pub,
            remote_noise_pub: Some(&x_pk_arr),
            role: Role::Client,
            server_hint: payload.server_hint.as_deref(),
        });
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&payload.ed25519_pub)
            .map_err(|e| NoiseError::Other(e.to_string()))?;
        let ok = verify_identity_payload(&vk, &msg32, &payload.sig);
        if !ok {
            return Err(NoiseError::IdentityVerify);
        }

        Ok((hs, payload))
    }
}
