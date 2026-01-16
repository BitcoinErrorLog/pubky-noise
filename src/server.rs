use crate::errors::NoiseError;
use crate::identity_payload::{
    make_binding_message, verify_identity_payload, BindingMessageParams, IdentityPayload, Role,
};
use crate::ring::{RingKeyFiller, RingKeyProvider};
use std::marker::PhantomData;
use zeroize::Zeroizing;

/// Internal epoch value for Ring derivation (always 0).
/// Key rotation is managed via key_version, not epoch.
const INTERNAL_EPOCH: u32 = 0;

/// Fixed prologue for the Noise protocol handshake.
/// Per PUBKY_CRYPTO_SPEC v2.5 Section 6.2, this MUST be a fixed constant.
const PROLOGUE: &[u8] = b"pubky-noise-v1";

/// Maximum allowed handshake message length in bytes.
pub const MAX_HANDSHAKE_MSG_LEN: usize = 65536;

/// Maximum allowed server_hint length in IdentityPayload.
pub const MAX_SERVER_HINT_LEN: usize = 256;

/// Server policy configuration.
///
/// **Note**: These fields are reserved for future use. Rate limiting should currently
/// be implemented using the [`RateLimiter`](crate::rate_limiter::RateLimiter) type
/// at the application layer, which provides comprehensive per-IP rate limiting.
///
/// Future versions may integrate these policies directly into the handshake flow.
#[derive(Clone, Debug, Default)]
pub struct ServerPolicy {
    /// Maximum handshakes allowed per IP address (rate limiting).
    /// **Reserved for future use** - not currently enforced.
    pub max_handshakes_per_ip: Option<u32>,
    /// Maximum sessions allowed per Ed25519 identity.
    /// **Reserved for future use** - not currently enforced.
    pub max_sessions_per_ed25519: Option<u32>,
}

pub struct NoiseServer<R: RingKeyProvider, P = ()> {
    pub kid: String,
    pub device_id: Vec<u8>,
    pub ring: std::sync::Arc<R>,
    _phantom: PhantomData<P>,
    pub suite: String,
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
            suite: "Noise_IK_25519_ChaChaPoly_BLAKE2s".into(),
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
    ///
    /// # Errors
    ///
    /// Returns `NoiseError::Policy` if the message exceeds `MAX_HANDSHAKE_MSG_LEN`.
    pub fn build_responder_read_ik(
        &self,
        first_msg: &[u8],
    ) -> Result<(snow::HandshakeState, IdentityPayload), NoiseError> {
        if first_msg.len() > MAX_HANDSHAKE_MSG_LEN {
            return Err(NoiseError::Policy(format!(
                "Handshake message too large: {} bytes (max {})",
                first_msg.len(),
                MAX_HANDSHAKE_MSG_LEN
            )));
        }

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
                let x_pk_arr = crate::kdf::x25519_pk_from_sk(x_sk);
                let hs = builder
                    .local_private_key(&**x_sk)
                    .prologue(PROLOGUE)
                    .build_responder()
                    .map_err(NoiseError::from)?;
                Ok((hs, x_pk_arr))
            },
        )??;

        let mut hs = hs;

        let mut buf = vec![0u8; first_msg.len() + 256];
        let n = hs.read_message(first_msg, &mut buf)?;
        let payload: IdentityPayload = serde_json::from_slice(&buf[..n])?;

        // Get client's static key from Noise handshake state (per spec v2.5)
        let client_static_pk: [u8; 32] = hs
            .get_remote_static()
            .ok_or(NoiseError::RemoteStaticMissing)?
            .try_into()
            .map_err(|_| NoiseError::Other("Remote static key wrong length".to_string()))?;

        // Validate server_hint length to prevent abuse
        if let Some(ref hint) = payload.server_hint {
            if hint.len() > MAX_SERVER_HINT_LEN {
                return Err(NoiseError::Policy(format!(
                    "server_hint too long: {} chars (max {})",
                    hint.len(),
                    MAX_SERVER_HINT_LEN
                )));
            }
        }

        // Reject all-zero shared secret with client static
        let ok = self.ring.with_device_x25519(
            &self.kid,
            &self.device_id,
            INTERNAL_EPOCH,
            |x_sk: &Zeroizing<[u8; 32]>| {
                crate::kdf::shared_secret_nonzero(x_sk, &client_static_pk)
            },
        )?;
        if !ok {
            return Err(NoiseError::InvalidPeerKey);
        }

        // Validate hint_expires_at timestamp (scoped to server_hint only)
        if let Some(hint_expires_at) = payload.hint_expires_at {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .map_err(|_| {
                    NoiseError::Other(
                        "System clock before UNIX epoch; cannot validate expiration".to_string(),
                    )
                })?;
            if now > hint_expires_at {
                return Err(NoiseError::SessionExpired(format!(
                    "Identity payload hint expired at {} (current time: {})",
                    hint_expires_at, now
                )));
            }
        }

        // Verify identity binding signature
        // Client's binding: client_ed25519, client_static, Client role, server_static
        let msg32 = make_binding_message(&BindingMessageParams {
            ed25519_pub: &payload.ed25519_pub,
            local_noise_pub: &client_static_pk,
            remote_noise_pub: Some(&x_pk_arr),
            role: Role::Client,
        });
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&payload.ed25519_pub)
            .map_err(|e| NoiseError::Other(e.to_string()))?;
        let ok = verify_identity_payload(&vk, &msg32, &payload.sig);
        if !ok {
            return Err(NoiseError::IdentityVerify);
        }

        Ok((hs, payload))
    }

    // =========================================================================
    // XX Pattern (Trust On First Use)
    // =========================================================================

    /// Build a responder for XX pattern handshake (step 2).
    pub fn build_responder_xx(
        &self,
        first_msg: &[u8],
    ) -> Result<(snow::HandshakeState, Vec<u8>, [u8; 32]), NoiseError> {
        if first_msg.len() > MAX_HANDSHAKE_MSG_LEN {
            return Err(NoiseError::Policy(format!(
                "Handshake message too large: {} bytes (max {})",
                first_msg.len(),
                MAX_HANDSHAKE_MSG_LEN
            )));
        }

        let suite = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
        let params: snow::params::NoiseParams = suite
            .parse()
            .map_err(|e: snow::Error| NoiseError::Other(e.to_string()))?;
        let builder = snow::Builder::new(params);

        let (mut hs, x_pk_arr) = self.ring.with_device_x25519(
            &self.kid,
            &self.device_id,
            INTERNAL_EPOCH,
            |x_sk: &Zeroizing<[u8; 32]>| -> Result<(snow::HandshakeState, [u8; 32]), NoiseError> {
                let x_pk_arr = crate::kdf::x25519_pk_from_sk(x_sk);
                let hs = builder
                    .local_private_key(&**x_sk)
                    .prologue(PROLOGUE)
                    .build_responder()
                    .map_err(NoiseError::from)?;
                Ok((hs, x_pk_arr))
            },
        )??;

        // Read client's first message
        let mut buf = vec![0u8; first_msg.len() + 256];
        let _n = hs.read_message(first_msg, &mut buf)?;

        // Build server's identity payload
        let ed_pub = self.ring.ed25519_pubkey(&self.kid)?;
        let hint_expires_at: Option<u64> = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|d| d.as_secs() + 300);

        // Server's binding: server_ed25519, server_static, Server role
        // In XX step 2, client's static is not yet known, so remote_noise_pub is None
        let msg32 = make_binding_message(&BindingMessageParams {
            ed25519_pub: &ed_pub,
            local_noise_pub: &x_pk_arr,
            remote_noise_pub: None,
            role: Role::Server,
        });
        let sig64 = self.ring.sign_ed25519(&self.kid, &msg32)?;

        let payload = IdentityPayload {
            ed25519_pub: ed_pub,
            role: Role::Server,
            server_hint: None,
            hint_expires_at,
            sig: sig64,
        };

        let payload_bytes = serde_json::to_vec(&payload)?;
        let mut response = vec![0u8; payload_bytes.len() + 256];
        let n = hs.write_message(&payload_bytes, &mut response)?;
        response.truncate(n);

        Ok((hs, response, x_pk_arr))
    }

    /// Complete XX pattern handshake after receiving client's final message (step 3).
    pub fn complete_responder_xx(
        &self,
        mut hs: snow::HandshakeState,
        client_final_msg: &[u8],
        server_static_pk: &[u8; 32],
    ) -> Result<(snow::HandshakeState, IdentityPayload), NoiseError> {
        if client_final_msg.len() > MAX_HANDSHAKE_MSG_LEN {
            return Err(NoiseError::Policy(format!(
                "Handshake message too large: {} bytes (max {})",
                client_final_msg.len(),
                MAX_HANDSHAKE_MSG_LEN
            )));
        }

        let mut buf = vec![0u8; client_final_msg.len() + 256];
        let n = hs.read_message(client_final_msg, &mut buf)?;
        let payload: IdentityPayload = serde_json::from_slice(&buf[..n])?;

        // Get client's static key from Noise handshake state (per spec v2.5)
        let client_static_pk: [u8; 32] = hs
            .get_remote_static()
            .ok_or(NoiseError::RemoteStaticMissing)?
            .try_into()
            .map_err(|_| NoiseError::Other("Remote static key wrong length".to_string()))?;

        if let Some(ref hint) = payload.server_hint {
            if hint.len() > MAX_SERVER_HINT_LEN {
                return Err(NoiseError::Policy(format!(
                    "server_hint too long: {} chars (max {})",
                    hint.len(),
                    MAX_SERVER_HINT_LEN
                )));
            }
        }

        // Reject all-zero shared secret
        let ok = self.ring.with_device_x25519(
            &self.kid,
            &self.device_id,
            INTERNAL_EPOCH,
            |x_sk: &Zeroizing<[u8; 32]>| {
                crate::kdf::shared_secret_nonzero(x_sk, &client_static_pk)
            },
        )?;
        if !ok {
            return Err(NoiseError::InvalidPeerKey);
        }

        // Validate hint_expires_at timestamp (scoped to server_hint only)
        if let Some(hint_expires_at) = payload.hint_expires_at {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .map_err(|_| {
                    NoiseError::Other(
                        "System clock before UNIX epoch; cannot validate expiration".to_string(),
                    )
                })?;
            if now > hint_expires_at {
                return Err(NoiseError::SessionExpired(format!(
                    "Identity payload hint expired at {} (current time: {})",
                    hint_expires_at, now
                )));
            }
        }

        // Verify identity binding signature
        // Client's binding: client_ed25519, client_static, Client role, server_static
        let msg32 = make_binding_message(&BindingMessageParams {
            ed25519_pub: &payload.ed25519_pub,
            local_noise_pub: &client_static_pk,
            remote_noise_pub: Some(server_static_pk),
            role: Role::Client,
        });
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&payload.ed25519_pub)
            .map_err(|e| NoiseError::Other(e.to_string()))?;
        let ok = verify_identity_payload(&vk, &msg32, &payload.sig);
        if !ok {
            return Err(NoiseError::IdentityVerify);
        }

        Ok((hs, payload))
    }

    // =========================================================================
    // NN Pattern (Ephemeral-only, NO AUTHENTICATION)
    // =========================================================================

    /// Build a responder for NN pattern handshake (ephemeral-only, NO AUTHENTICATION).
    ///
    /// # Security Warning: No Authentication
    ///
    /// The NN pattern provides **forward secrecy only** with NO identity binding.
    /// An active attacker can trivially MITM this connection.
    pub fn build_responder_nn(
        &self,
        first_msg: &[u8],
    ) -> Result<(snow::HandshakeState, Vec<u8>), NoiseError> {
        if first_msg.len() > MAX_HANDSHAKE_MSG_LEN {
            return Err(NoiseError::Policy(format!(
                "Handshake message too large: {} bytes (max {})",
                first_msg.len(),
                MAX_HANDSHAKE_MSG_LEN
            )));
        }

        let suite = "Noise_NN_25519_ChaChaPoly_BLAKE2s";
        let params: snow::params::NoiseParams = suite
            .parse()
            .map_err(|e: snow::Error| NoiseError::Other(e.to_string()))?;

        let mut hs = snow::Builder::new(params)
            .prologue(PROLOGUE)
            .build_responder()
            .map_err(NoiseError::from)?;

        let mut buf = vec![0u8; first_msg.len() + 256];
        let _n = hs.read_message(first_msg, &mut buf)?;

        let mut response = vec![0u8; 128];
        let n = hs.write_message(&[], &mut response)?;
        response.truncate(n);

        Ok((hs, response))
    }
}
