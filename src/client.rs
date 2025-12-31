use crate::errors::NoiseError;
use crate::identity_payload::{make_binding_message, BindingMessageParams, IdentityPayload, Role};
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

/// Default handshake expiry duration in seconds (5 minutes).
///
/// When `now_unix` is set on the client, this value is added to compute `expires_at`.
/// Servers MUST reject payloads with timestamps in the past, which provides
/// replay protection for handshake initiation.
const DEFAULT_HANDSHAKE_EXPIRY_SECS: u64 = 300;

pub struct NoiseClient<R: RingKeyProvider, P = ()> {
    pub kid: String,
    pub device_id: Vec<u8>,
    pub ring: std::sync::Arc<R>,
    _phantom: PhantomData<P>,
    pub prologue: Vec<u8>,
    pub suite: String,
    /// Current Unix timestamp in seconds. When set, enables handshake expiry.
    ///
    /// Setting this causes the client to include `expires_at = now_unix + 300` in the
    /// identity payload, providing replay protection for handshake messages.
    pub now_unix: Option<u64>,
    /// Custom expiry duration in seconds. Defaults to 300 (5 minutes).
    pub expiry_secs: u64,
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
            expiry_secs: DEFAULT_HANDSHAKE_EXPIRY_SECS,
        }
    }

    /// Set the current Unix timestamp to enable handshake expiry.
    ///
    /// When set, the handshake payload will include `expires_at = now_unix + expiry_secs`,
    /// which servers can use to reject replayed handshake messages.
    pub fn with_now_unix(mut self, now_unix: u64) -> Self {
        self.now_unix = Some(now_unix);
        self
    }

    /// Set a custom expiry duration (default is 300 seconds / 5 minutes).
    pub fn with_expiry_secs(mut self, secs: u64) -> Self {
        self.expiry_secs = secs;
        self
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

        // Compute expiration if now_unix is set (enables replay protection)
        // When now_unix is None, expires_at is None for backward compatibility
        let expires_at: Option<u64> = self.now_unix.map(|now| now + self.expiry_secs);

        let msg32 = make_binding_message(&BindingMessageParams {
            pattern_tag: "IK",
            prologue: &self.prologue,
            ed25519_pub: &ed_pub,
            local_noise_pub: &x_pk_arr,
            remote_noise_pub: Some(server_static_pub),
            role: Role::Client,
            server_hint,
            expires_at,
        });
        let sig64 = self.ring.sign_ed25519(&self.kid, &msg32)?;

        let payload = IdentityPayload {
            ed25519_pub: ed_pub,
            noise_x25519_pub: x_pk_arr,
            epoch: INTERNAL_EPOCH, // Always 0 for wire format compatibility
            role: Role::Client,
            server_hint: server_hint.map(|s| s.to_string()),
            expires_at,
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
    /// * `server_hint` - Optional hint for server routing.
    ///
    /// # Returns
    ///
    /// A tuple of (HandshakeState, first_message_bytes, server_hint).
    pub fn build_initiator_xx_tofu(
        &self,
        server_hint: Option<&str>,
    ) -> Result<(snow::HandshakeState, Vec<u8>, Option<String>), NoiseError> {
        let suite = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
        let builder = snow::Builder::new(
            suite
                .parse::<snow::params::NoiseParams>()
                .map_err(|e: snow::Error| NoiseError::Other(e.to_string()))?,
        );
        let hs =
            self.ring
                .with_device_x25519(&self.kid, &self.device_id, INTERNAL_EPOCH, |x_sk| {
                    builder
                        .local_private_key(&**x_sk)
                        .prologue(&self.prologue)
                        .build_initiator()
                        .map_err(NoiseError::from)
                })?;
        let mut hs = hs?;

        let mut out = vec![0u8; 128];
        let n = hs.write_message(&[], &mut out)?;
        out.truncate(n);
        Ok((hs, out, server_hint.map(|s| s.to_string())))
    }

    /// Complete XX pattern handshake after receiving server response.
    pub fn complete_initiator_xx(
        &self,
        mut hs: snow::HandshakeState,
        server_response: &[u8],
        server_hint: Option<&str>,
    ) -> Result<(snow::HandshakeState, Vec<u8>, IdentityPayload, [u8; 32]), NoiseError> {
        use crate::identity_payload::verify_identity_payload;

        // Read server's response
        let mut buf = vec![0u8; server_response.len() + 256];
        let n = hs.read_message(server_response, &mut buf)?;
        let server_payload: IdentityPayload = serde_json::from_slice(&buf[..n])?;

        // Extract server's static public key
        let server_static_pk: [u8; 32] = hs
            .get_remote_static()
            .ok_or(NoiseError::RemoteStaticMissing)?
            .try_into()
            .map_err(|_| NoiseError::Other("Server static key wrong length".to_string()))?;

        // Validate server's static key matches identity payload
        if server_static_pk != server_payload.noise_x25519_pub {
            return Err(NoiseError::IdentityVerify);
        }

        // Reject all-zero shared secret
        let ok = self.ring.with_device_x25519(
            &self.kid,
            &self.device_id,
            INTERNAL_EPOCH,
            |x_sk: &Zeroizing<[u8; 32]>| crate::kdf::shared_secret_nonzero(x_sk, &server_static_pk),
        )?;
        if !ok {
            return Err(NoiseError::InvalidPeerKey);
        }

        // Verify server's identity binding signature
        let msg32 = make_binding_message(&BindingMessageParams {
            pattern_tag: "XX",
            prologue: &self.prologue,
            ed25519_pub: &server_payload.ed25519_pub,
            local_noise_pub: &server_payload.noise_x25519_pub,
            remote_noise_pub: None,
            role: Role::Server,
            server_hint: server_payload.server_hint.as_deref(),
            expires_at: server_payload.expires_at,
        });
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&server_payload.ed25519_pub)
            .map_err(|e| NoiseError::Other(e.to_string()))?;
        let ok = verify_identity_payload(&vk, &msg32, &server_payload.sig);
        if !ok {
            return Err(NoiseError::IdentityVerify);
        }

        // Build client's identity payload
        let ed_pub = self.ring.ed25519_pubkey(&self.kid)?;
        let x_pk_arr = self.ring.with_device_x25519(
            &self.kid,
            &self.device_id,
            INTERNAL_EPOCH,
            |x_sk: &Zeroizing<[u8; 32]>| crate::kdf::x25519_pk_from_sk(x_sk),
        )?;

        let expires_at: Option<u64> = self.now_unix.map(|now| now + self.expiry_secs);

        let client_msg32 = make_binding_message(&BindingMessageParams {
            pattern_tag: "XX",
            prologue: &self.prologue,
            ed25519_pub: &ed_pub,
            local_noise_pub: &x_pk_arr,
            remote_noise_pub: Some(&server_static_pk),
            role: Role::Client,
            server_hint,
            expires_at,
        });
        let sig64 = self.ring.sign_ed25519(&self.kid, &client_msg32)?;

        let client_payload = IdentityPayload {
            ed25519_pub: ed_pub,
            noise_x25519_pub: x_pk_arr,
            epoch: INTERNAL_EPOCH,
            role: Role::Client,
            server_hint: server_hint.map(|s| s.to_string()),
            expires_at,
            sig: sig64,
        };

        let payload_bytes = serde_json::to_vec(&client_payload)?;
        let mut final_msg = vec![0u8; payload_bytes.len() + 256];
        let n = hs.write_message(&payload_bytes, &mut final_msg)?;
        final_msg.truncate(n);

        Ok((hs, final_msg, server_payload, server_static_pk))
    }

    // =========================================================================
    // NN Pattern (Ephemeral-only, NO AUTHENTICATION)
    // =========================================================================

    /// Build an NN pattern initiator handshake (ephemeral-only, NO AUTHENTICATION).
    ///
    /// # Security Warning: No Authentication
    ///
    /// The NN pattern provides **forward secrecy only** with NO identity binding.
    /// An active attacker can trivially MITM this connection.
    pub fn build_initiator_nn(&self) -> Result<(snow::HandshakeState, Vec<u8>), NoiseError> {
        let suite = "Noise_NN_25519_ChaChaPoly_BLAKE2s";
        let builder = snow::Builder::new(
            suite
                .parse::<snow::params::NoiseParams>()
                .map_err(|e: snow::Error| NoiseError::Other(e.to_string()))?,
        );

        let mut hs = builder
            .prologue(&self.prologue)
            .build_initiator()
            .map_err(NoiseError::from)?;

        let mut out = vec![0u8; 128];
        let n = hs.write_message(&[], &mut out)?;
        out.truncate(n);
        Ok((hs, out))
    }

    /// Complete NN pattern handshake after receiving server response.
    ///
    /// # Security Warning: No Authentication
    ///
    /// The NN pattern provides **forward secrecy only** with NO identity binding.
    pub fn complete_initiator_nn(
        &self,
        mut hs: snow::HandshakeState,
        server_response: &[u8],
    ) -> Result<snow::HandshakeState, NoiseError> {
        let mut buf = vec![0u8; server_response.len() + 256];
        let _n = hs.read_message(server_response, &mut buf)?;
        Ok(hs)
    }
}
