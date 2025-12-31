use crate::errors::NoiseError;
use crate::identity_payload::{
    make_binding_message, verify_identity_payload, BindingMessageParams, IdentityPayload, Role,
};
use crate::ring::{RingKeyFiller, RingKeyProvider};
use std::marker::PhantomData;
use zeroize::Zeroizing;

/// Internal epoch value - always 0.
///
/// **Note**: Key epoch rotation is not currently implemented. The epoch field
/// exists in the wire format for future compatibility, but is always set to 0.
/// For key rotation needs, applications should use fresh device IDs or manage
/// key versioning at a higher layer.
const INTERNAL_EPOCH: u32 = 0;

/// Maximum allowed handshake message length in bytes.
/// This prevents memory exhaustion from maliciously large messages.
pub const MAX_HANDSHAKE_MSG_LEN: usize = 65536;

/// Maximum allowed server_hint length in IdentityPayload.
pub const MAX_SERVER_HINT_LEN: usize = 256;

/// Maximum number of client epochs to track before cleanup.
pub const MAX_SEEN_EPOCHS: usize = 10_000;

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
    ///
    /// # Errors
    ///
    /// Returns `NoiseError::Policy` if the message exceeds `MAX_HANDSHAKE_MSG_LEN`.
    pub fn build_responder_read_ik(
        &self,
        first_msg: &[u8],
    ) -> Result<(snow::HandshakeState, IdentityPayload), NoiseError> {
        // Validate input size to prevent memory exhaustion attacks
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
                crate::kdf::shared_secret_nonzero(x_sk, &payload.noise_x25519_pub)
            },
        )?;
        if !ok {
            return Err(NoiseError::InvalidPeerKey);
        }

        // Validate expiration timestamp BEFORE signature verification (fail-fast)
        // This is defense-in-depth: if a payload has an expiration, enforce it
        // We fail closed if system time is unreliable when expiration is present
        if let Some(expires_at) = payload.expires_at {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .map_err(|_| {
                    NoiseError::Other(
                        "System clock before UNIX epoch; cannot validate expiration".to_string(),
                    )
                })?;
            if now > expires_at {
                return Err(NoiseError::SessionExpired(format!(
                    "Identity payload expired at {} (current time: {})",
                    expires_at, now
                )));
            }
        }

        let msg32 = make_binding_message(&BindingMessageParams {
            pattern_tag: "IK",
            prologue: &self.prologue,
            ed25519_pub: &payload.ed25519_pub,
            local_noise_pub: &payload.noise_x25519_pub,
            remote_noise_pub: Some(&x_pk_arr),
            role: Role::Client,
            server_hint: payload.server_hint.as_deref(),
            expires_at: payload.expires_at,
        });
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&payload.ed25519_pub)
            .map_err(|e| NoiseError::Other(e.to_string()))?;
        let ok = verify_identity_payload(&vk, &msg32, &payload.sig);
        if !ok {
            return Err(NoiseError::IdentityVerify);
        }

        Ok((hs, payload))
    }

    /// Clean up the seen_client_epochs map if it exceeds the maximum size.
    ///
    /// This prevents unbounded memory growth in long-running servers.
    /// Removes all entries when the map exceeds `MAX_SEEN_EPOCHS`.
    ///
    /// # Lock Poisoning
    ///
    /// Uses `unwrap_or_else(|e| e.into_inner())` to recover gracefully from
    /// lock poisoning. This prioritizes availability over crash-looping: if
    /// another thread panicked while holding the lock, we recover the inner
    /// data and continue. The epoch tracking data remains consistent because
    /// all mutations are simple HashMap operations.
    pub fn cleanup_seen_epochs(&self) {
        let mut epochs = self
            .seen_client_epochs
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if epochs.len() > MAX_SEEN_EPOCHS {
            epochs.clear();
        }
    }

    /// Get the current number of tracked client epochs.
    ///
    /// # Lock Poisoning
    ///
    /// Uses `unwrap_or_else(|e| e.into_inner())` to recover gracefully from
    /// lock poisoning rather than panicking.
    pub fn seen_epochs_count(&self) -> usize {
        self.seen_client_epochs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }
}
