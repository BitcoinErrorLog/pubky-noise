use crate::errors::NoiseError;
use crate::identity_payload::{make_binding_message, BindingMessageParams, IdentityPayload, Role};
use crate::ring::{RingKeyFiller, RingKeyProvider};
use std::marker::PhantomData;
use zeroize::Zeroizing;

/// Internal epoch value - always 0 (epoch is not a user-facing concept).
const INTERNAL_EPOCH: u32 = 0;

pub struct NoiseClient<R: RingKeyProvider, P = ()> {
    pub kid: String,
    pub device_id: Vec<u8>,
    pub ring: std::sync::Arc<R>,
    _phantom: PhantomData<P>,
    pub prologue: Vec<u8>,
    pub suite: String,
    pub now_unix: Option<u64>,
}

impl<R: RingKeyProvider, P> NoiseClient<R, P> {
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
            now_unix: None,
        }
    }

    /// Build an IK pattern initiator handshake.
    ///
    /// # Arguments
    ///
    /// * `server_static_pub` - The server's static X25519 public key.
    /// * `server_hint` - Optional hint for server routing.
    ///
    /// # Returns
    ///
    /// A tuple of (HandshakeState, first_message_bytes).
    pub fn build_initiator_ik_direct(
        &self,
        server_static_pub: &[u8; 32],
        server_hint: Option<&str>,
    ) -> Result<(snow::HandshakeState, Vec<u8>), NoiseError> {
        let builder = snow::Builder::new(
            self.suite
                .parse::<snow::params::NoiseParams>()
                .map_err(|e: snow::Error| NoiseError::Other(e.to_string()))?,
        );

        let (mut hs, x_pk_arr) = self.ring.with_device_x25519(
            &self.kid,
            &self.device_id,
            INTERNAL_EPOCH,
            |x_sk: &Zeroizing<[u8; 32]>| {
                if !crate::kdf::shared_secret_nonzero(x_sk, server_static_pub) {
                    return Err(NoiseError::InvalidPeerKey);
                }
                // Derive public key from private key before passing to builder
                let x_pk_arr = crate::kdf::x25519_pk_from_sk(x_sk);

                // Chain builder calls since each method consumes and returns self
                let hs = builder
                    .local_private_key(&**x_sk) // Deref Zeroizing to &[u8; 32] to &[u8]
                    .remote_public_key(server_static_pub)
                    .prologue(&self.prologue)
                    .build_initiator()
                    .map_err(NoiseError::from)?;
                Ok((hs, x_pk_arr))
            },
        )??;
        let ed_pub = self.ring.ed25519_pubkey(&self.kid)?;

        let msg32 = make_binding_message(&BindingMessageParams {
            pattern_tag: "IK",
            prologue: &self.prologue,
            ed25519_pub: &ed_pub,
            local_noise_pub: &x_pk_arr,
            remote_noise_pub: Some(server_static_pub),
            role: Role::Client,
            server_hint,
        });
        let sig64 = self.ring.sign_ed25519(&self.kid, &msg32)?;

        let payload = IdentityPayload {
            ed25519_pub: ed_pub,
            noise_x25519_pub: x_pk_arr,
            epoch: INTERNAL_EPOCH, // Always 0 for wire format compatibility
            role: Role::Client,
            server_hint: server_hint.map(|s| s.to_string()),
            sig: sig64,
        };

        let payload_bytes = serde_json::to_vec(&payload)?;
        let mut out = vec![0u8; payload_bytes.len() + 128];
        let n = hs.write_message(&payload_bytes, &mut out)?;
        out.truncate(n);
        Ok((hs, out))
    }

    /// Build an XX pattern initiator handshake (Trust On First Use).
    ///
    /// # Arguments
    ///
    /// * `_server_hint` - Optional hint for server routing (currently unused).
    ///
    /// # Returns
    ///
    /// A tuple of (HandshakeState, first_message_bytes).
    pub fn build_initiator_xx_tofu(
        &self,
        _server_hint: Option<&str>,
    ) -> Result<(snow::HandshakeState, Vec<u8>), NoiseError> {
        let suite = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
        let builder = snow::Builder::new(
            suite
                .parse::<snow::params::NoiseParams>()
                .map_err(|e: snow::Error| NoiseError::Other(e.to_string()))?,
        );
        let hs =
            self.ring
                .with_device_x25519(&self.kid, &self.device_id, INTERNAL_EPOCH, |x_sk| {
                    // Chain builder calls since each method consumes and returns self
                    builder
                        .local_private_key(&**x_sk) // Deref Zeroizing to &[u8; 32] to &[u8]
                        .prologue(&self.prologue)
                        .build_initiator()
                        .map_err(NoiseError::from)
                })?;
        let mut hs = hs?;

        let mut out = vec![0u8; 128];
        let n = hs.write_message(&[], &mut out)?;
        out.truncate(n);
        Ok((hs, out))
    }
}
