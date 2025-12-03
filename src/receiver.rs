//! Raw-key Noise receiver (server/responder).
//!
//! `NoiseReceiver` provides a simpler API for responding to Noise handshakes when
//! the caller already has derived X25519/Ed25519 keys. This avoids the need for
//! `RingKeyProvider` and gives applications full control over key management.
//!
//! # Example
//!
//! ```no_run
//! use pubky_noise::{NoiseReceiver, kdf};
//! use zeroize::Zeroizing;
//!
//! # fn main() -> Result<(), pubky_noise::NoiseError> {
//! // Derive keys at the application layer
//! let seed = [0u8; 32]; // Your Ed25519 seed
//! let x25519_sk = Zeroizing::new(kdf::derive_x25519_static(&seed, b"server-device"));
//!
//! // Create receiver with raw key
//! let receiver = NoiseReceiver::new();
//!
//! // Respond to IK handshake (with identity binding)
//! let first_msg: Vec<u8> = vec![]; // From client
//! let (hs, client_identity, response) = receiver.respond_ik(&x25519_sk, &first_msg)?;
//! // Send response back to client...
//! # Ok(())
//! # }
//! ```

use crate::errors::NoiseError;
use crate::identity_payload::{
    make_binding_message, verify_identity_payload, IdentityPayload, Role,
};
use zeroize::Zeroizing;

/// Default Noise suite for pubky-noise.
pub const DEFAULT_NOISE_SUITE: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
/// Default prologue for pubky-noise.
pub const DEFAULT_PROLOGUE: &[u8] = b"pubky-noise-v1";

/// Raw-key Noise receiver for accepting encrypted sessions.
///
/// Unlike `NoiseServer`, `NoiseReceiver` accepts pre-derived keys directly rather
/// than requiring a `RingKeyProvider`. This gives applications full control over
/// key derivation while still benefiting from the Noise protocol implementation.
///
/// # Key Management
///
/// The caller is responsible for:
/// - Deriving X25519 keys from Ed25519 seeds (use `kdf::derive_x25519_static`)
/// - Validating client identities
/// - Zeroizing keys after use
///
/// # Thread Safety
///
/// `NoiseReceiver` is stateless and can be shared across threads. Each handshake
/// response creates independent state.
#[derive(Debug, Clone)]
pub struct NoiseReceiver {
    /// Noise pattern suite (defaults to IK with X25519/ChaChaPoly/BLAKE2s)
    pub suite: String,
    /// Prologue for channel binding (defaults to "pubky-noise-v1")
    pub prologue: Vec<u8>,
}

impl Default for NoiseReceiver {
    fn default() -> Self {
        Self::new()
    }
}

impl NoiseReceiver {
    /// Create a new `NoiseReceiver` with default settings.
    ///
    /// - Suite: `Noise_IK_25519_ChaChaPoly_BLAKE2s`
    /// - Prologue: `"pubky-noise-v1"`
    pub fn new() -> Self {
        Self {
            suite: DEFAULT_NOISE_SUITE.to_string(),
            prologue: DEFAULT_PROLOGUE.to_vec(),
        }
    }

    /// Create a `NoiseReceiver` with custom suite and prologue.
    pub fn with_params(suite: impl Into<String>, prologue: impl Into<Vec<u8>>) -> Self {
        Self {
            suite: suite.into(),
            prologue: prologue.into(),
        }
    }

    /// Respond to an IK pattern handshake.
    ///
    /// Processes the client's first handshake message, validates their identity
    /// binding, and generates the response message to complete the handshake.
    ///
    /// # Arguments
    ///
    /// * `local_x25519_sk` - Your X25519 secret key for this session (32 bytes, zeroizing).
    ///   Use `kdf::derive_x25519_static` to derive from Ed25519 seed.
    ///
    /// * `first_msg` - The first handshake message received from the client.
    ///
    /// # Returns
    ///
    /// Returns `Ok((handshake_state, client_identity, response_message))` on success:
    /// - `handshake_state` - Snow handshake state for transitioning to transport mode
    /// - `client_identity` - Parsed and validated client identity payload containing:
    ///   - `ed25519_pub`: Client's long-term Ed25519 public key
    ///   - `noise_x25519_pub`: Client's ephemeral X25519 public key
    ///   - `role`: Should be `Role::Client`
    ///   - `sig`: Ed25519 signature (already verified)
    /// - `response_message` - The response to send back to the client
    ///
    /// # Errors
    ///
    /// Returns `Err(NoiseError)` if:
    /// - `Snow(...)` - Noise protocol validation failed
    /// - `InvalidPeerKey` - Client's key would result in all-zero shared secret
    /// - `IdentityVerify` - Client's Ed25519 signature verification failed
    /// - `Serde(...)` - Identity payload deserialization failed
    ///
    /// # Security Checks
    ///
    /// 1. **Noise Protocol Validation**: Verifies the Noise handshake message format
    /// 2. **DH Validation**: Ensures the shared secret with client is non-zero
    /// 3. **Identity Binding**: Validates Ed25519 signature over binding message
    ///
    /// # Example
    ///
    /// ```no_run
    /// use pubky_noise::{NoiseReceiver, kdf};
    /// use zeroize::Zeroizing;
    ///
    /// # fn main() -> Result<(), pubky_noise::NoiseError> {
    /// let x25519_sk = Zeroizing::new(kdf::derive_x25519_static(&[0u8; 32], b"server"));
    /// let receiver = NoiseReceiver::new();
    ///
    /// let first_msg: Vec<u8> = vec![]; // From client
    /// let (hs, client_identity, response) = receiver.respond_ik(&x25519_sk, &first_msg)?;
    ///
    /// println!("Client Ed25519: {:?}", client_identity.ed25519_pub);
    /// // Send response back to client...
    /// # Ok(())
    /// # }
    /// ```
    pub fn respond_ik(
        &self,
        local_x25519_sk: &Zeroizing<[u8; 32]>,
        first_msg: &[u8],
    ) -> Result<(snow::HandshakeState, IdentityPayload, Vec<u8>), NoiseError> {
        // Derive local X25519 public key
        let local_x25519_pub = crate::kdf::x25519_pk_from_sk(local_x25519_sk);

        // Build Noise handshake state
        let builder = snow::Builder::new(
            self.suite
                .parse::<snow::params::NoiseParams>()
                .map_err(|e: snow::Error| NoiseError::Other(e.to_string()))?,
        );

        let mut hs = builder
            .local_private_key(&**local_x25519_sk)?
            .prologue(&self.prologue)?
            .build_responder()
            .map_err(NoiseError::from)?;

        // Read and decrypt first message
        let mut buf = vec![0u8; first_msg.len() + 256];
        let n = hs.read_message(first_msg, &mut buf)?;
        let payload: IdentityPayload = serde_json::from_slice(&buf[..n])?;

        // Reject all-zero shared secret with client static key
        if !crate::kdf::shared_secret_nonzero(local_x25519_sk, &payload.noise_x25519_pub) {
            return Err(NoiseError::InvalidPeerKey);
        }

        // Verify identity binding signature
        let tag = "IK";
        let msg32 = make_binding_message(
            tag,
            &self.prologue,
            &payload.ed25519_pub,
            &payload.noise_x25519_pub,
            Some(&local_x25519_pub),
            Role::Client,
        );

        let vk = ed25519_dalek::VerifyingKey::from_bytes(&payload.ed25519_pub)
            .map_err(|e| NoiseError::Other(e.to_string()))?;

        if !verify_identity_payload(&vk, &msg32, &payload.sig) {
            return Err(NoiseError::IdentityVerify);
        }

        // Generate response message
        let mut response = vec![0u8; 128];
        let n = hs.write_message(&[], &mut response)?;
        response.truncate(n);

        Ok((hs, payload, response))
    }

    // ========== COLD KEY PATTERNS (pkarr-based authentication) ==========

    /// Respond to an IK pattern handshake without identity verification.
    ///
    /// Use when identity binding is provided externally (e.g., via pkarr).
    /// The client's identity should be verified through pkarr lookup before
    /// or after the handshake.
    ///
    /// # Cold Key Architecture
    ///
    /// This method is designed for scenarios where Ed25519 keys are kept cold:
    /// 1. Client publishes X25519 key via pkarr (one-time cold signing)
    /// 2. Server can verify client identity via pkarr lookup
    /// 3. Handshake proceeds without in-band identity binding
    ///
    /// # Arguments
    ///
    /// * `local_x25519_sk` - Your X25519 secret key (32 bytes, zeroizing).
    /// * `first_msg` - The first handshake message from the client.
    ///
    /// # Returns
    ///
    /// Returns `Ok((handshake_state, response_message))` on success.
    ///
    /// # Security Notes
    ///
    /// - **No In-Handshake Authentication**: Identity must be verified via pkarr
    /// - **Caller Responsibility**: Verify client identity through external means
    ///
    /// # Example
    ///
    /// ```no_run
    /// use pubky_noise::{NoiseReceiver, kdf};
    /// use zeroize::Zeroizing;
    ///
    /// # fn main() -> Result<(), pubky_noise::NoiseError> {
    /// let x25519_sk = Zeroizing::new(kdf::derive_x25519_static(&[0u8; 32], b"server"));
    /// let receiver = NoiseReceiver::new();
    ///
    /// let first_msg: Vec<u8> = vec![]; // From client
    /// let (hs, response) = receiver.respond_ik_raw(&x25519_sk, &first_msg)?;
    ///
    /// // Verify client identity via pkarr lookup separately
    /// # Ok(())
    /// # }
    /// ```
    pub fn respond_ik_raw(
        &self,
        local_x25519_sk: &Zeroizing<[u8; 32]>,
        first_msg: &[u8],
    ) -> Result<(snow::HandshakeState, Vec<u8>), NoiseError> {
        // Build Noise handshake state
        let builder = snow::Builder::new(
            self.suite
                .parse::<snow::params::NoiseParams>()
                .map_err(|e: snow::Error| NoiseError::Other(e.to_string()))?,
        );

        let mut hs = builder
            .local_private_key(&**local_x25519_sk)?
            .prologue(&self.prologue)?
            .build_responder()
            .map_err(NoiseError::from)?;

        // Read first message (ignore payload - no identity binding)
        let mut buf = vec![0u8; first_msg.len() + 256];
        let _n = hs.read_message(first_msg, &mut buf)?;

        // Validate client's static key is not weak (all-zero DH result)
        if let Some(remote_static) = hs.get_remote_static() {
            let remote_pk: [u8; 32] = remote_static
                .try_into()
                .map_err(|_| NoiseError::Other("Invalid remote static key length".to_string()))?;
            if !crate::kdf::shared_secret_nonzero(local_x25519_sk, &remote_pk) {
                return Err(NoiseError::InvalidPeerKey);
            }
        }

        // Generate response message
        let mut response = vec![0u8; 128];
        let n = hs.write_message(&[], &mut response)?;
        response.truncate(n);

        Ok((hs, response))
    }

    /// Respond to an N pattern handshake (anonymous initiator).
    ///
    /// The initiator is anonymous (no static key), responder has a static key.
    ///
    /// # Arguments
    ///
    /// * `local_x25519_sk` - Your X25519 secret key (32 bytes, zeroizing).
    /// * `first_msg` - The first handshake message from the client.
    ///
    /// # Returns
    ///
    /// Returns `Ok(handshake_state)` on success. The N pattern is a one-message
    /// pattern, so the handshake completes after reading the first message.
    ///
    /// # Security Notes
    ///
    /// - **Anonymous Initiator**: Client identity is not authenticated
    /// - **Authenticated Responder**: Your identity via pkarr
    ///
    /// # Example
    ///
    /// ```no_run
    /// use pubky_noise::{NoiseReceiver, kdf};
    /// use zeroize::Zeroizing;
    ///
    /// # fn main() -> Result<(), pubky_noise::NoiseError> {
    /// let x25519_sk = Zeroizing::new(kdf::derive_x25519_static(&[0u8; 32], b"server"));
    /// let receiver = NoiseReceiver::new();
    ///
    /// let first_msg: Vec<u8> = vec![]; // From anonymous client
    /// let hs = receiver.respond_n(&x25519_sk, &first_msg)?;
    ///
    /// // Handshake complete - transition to transport mode
    /// # Ok(())
    /// # }
    /// ```
    pub fn respond_n(
        &self,
        local_x25519_sk: &Zeroizing<[u8; 32]>,
        first_msg: &[u8],
    ) -> Result<snow::HandshakeState, NoiseError> {
        let suite = "Noise_N_25519_ChaChaPoly_BLAKE2s";
        let builder = snow::Builder::new(
            suite
                .parse::<snow::params::NoiseParams>()
                .map_err(|e: snow::Error| NoiseError::Other(e.to_string()))?,
        );

        let mut hs = builder
            .local_private_key(&**local_x25519_sk)?
            .prologue(&self.prologue)?
            .build_responder()
            .map_err(NoiseError::from)?;

        // Read the single N pattern message
        let mut buf = vec![0u8; first_msg.len() + 256];
        let _n = hs.read_message(first_msg, &mut buf)?;

        // N pattern completes after one message
        Ok(hs)
    }

    /// Respond to an NN pattern handshake (both parties anonymous).
    ///
    /// No static keys on either side - purely ephemeral key exchange.
    ///
    /// # Arguments
    ///
    /// * `first_msg` - The first handshake message from the client.
    ///
    /// # Returns
    ///
    /// Returns `Ok((handshake_state, response_message))` on success.
    ///
    /// # Security Notes
    ///
    /// - **No Authentication**: Neither party is authenticated
    /// - **MITM Vulnerable**: Without external authentication
    ///
    /// # Example
    ///
    /// ```no_run
    /// use pubky_noise::NoiseReceiver;
    ///
    /// # fn main() -> Result<(), pubky_noise::NoiseError> {
    /// let receiver = NoiseReceiver::new();
    ///
    /// let first_msg: Vec<u8> = vec![]; // From client
    /// let (hs, response) = receiver.respond_nn(&first_msg)?;
    ///
    /// // After handshake, authenticate via application-layer protocol
    /// # Ok(())
    /// # }
    /// ```
    pub fn respond_nn(
        &self,
        first_msg: &[u8],
    ) -> Result<(snow::HandshakeState, Vec<u8>), NoiseError> {
        let suite = "Noise_NN_25519_ChaChaPoly_BLAKE2s";
        let builder = snow::Builder::new(
            suite
                .parse::<snow::params::NoiseParams>()
                .map_err(|e: snow::Error| NoiseError::Other(e.to_string()))?,
        );

        let mut hs = builder
            .prologue(&self.prologue)?
            .build_responder()
            .map_err(NoiseError::from)?;

        // Read first message
        let mut buf = vec![0u8; first_msg.len() + 256];
        let _n = hs.read_message(first_msg, &mut buf)?;

        // Generate response message
        let mut response = vec![0u8; 128];
        let n = hs.write_message(&[], &mut response)?;
        response.truncate(n);

        Ok((hs, response))
    }

    /// Respond to an XX pattern handshake (Trust On First Use).
    ///
    /// XX pattern exchanges static keys during the handshake. Neither party
    /// knows the other's static key in advance.
    ///
    /// # Arguments
    ///
    /// * `local_x25519_sk` - Your X25519 secret key (32 bytes, zeroizing).
    /// * `first_msg` - The first handshake message from the client.
    ///
    /// # Returns
    ///
    /// Returns `Ok((handshake_state, response_message))` on success.
    /// Note: XX is a 3-message pattern. After this response, the initiator
    /// sends one more message before the handshake completes.
    ///
    /// # Security Notes
    ///
    /// - **Trust On First Use**: Neither party authenticated on first connection
    /// - **Pin After First Use**: Extract and store peer's static key
    ///
    /// # Example
    ///
    /// ```no_run
    /// use pubky_noise::{NoiseReceiver, kdf};
    /// use zeroize::Zeroizing;
    ///
    /// # fn main() -> Result<(), pubky_noise::NoiseError> {
    /// let x25519_sk = Zeroizing::new(kdf::derive_x25519_static(&[0u8; 32], b"server"));
    /// let receiver = NoiseReceiver::new();
    ///
    /// let first_msg: Vec<u8> = vec![]; // From client
    /// let (hs, response) = receiver.respond_xx(&x25519_sk, &first_msg)?;
    ///
    /// // Send response to client, then await third message
    /// // let third_msg = receive_from_client();
    /// // let mut buf = vec![0u8; 256];
    /// // hs.read_message(&third_msg, &mut buf)?;
    /// // let session = NoiseSession::from_handshake(hs)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn respond_xx(
        &self,
        local_x25519_sk: &Zeroizing<[u8; 32]>,
        first_msg: &[u8],
    ) -> Result<(snow::HandshakeState, Vec<u8>), NoiseError> {
        let suite = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
        let builder = snow::Builder::new(
            suite
                .parse::<snow::params::NoiseParams>()
                .map_err(|e: snow::Error| NoiseError::Other(e.to_string()))?,
        );

        let mut hs = builder
            .local_private_key(&**local_x25519_sk)?
            .prologue(&self.prologue)?
            .build_responder()
            .map_err(NoiseError::from)?;

        // Read first message (initiator's ephemeral key)
        let mut buf = vec![0u8; first_msg.len() + 256];
        let _n = hs.read_message(first_msg, &mut buf)?;

        // Generate response message (our ephemeral + DH + static + DH)
        let mut response = vec![0u8; 128];
        let n = hs.write_message(&[], &mut response)?;
        response.truncate(n);

        Ok((hs, response))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_receiver_default() {
        let receiver = NoiseReceiver::new();
        assert_eq!(receiver.suite, DEFAULT_NOISE_SUITE);
        assert_eq!(receiver.prologue, DEFAULT_PROLOGUE);
    }

    #[test]
    fn test_receiver_custom_params() {
        let receiver = NoiseReceiver::with_params("Noise_XX_25519_ChaChaPoly_BLAKE2s", b"custom");
        assert_eq!(receiver.suite, "Noise_XX_25519_ChaChaPoly_BLAKE2s");
        assert_eq!(receiver.prologue, b"custom".to_vec());
    }
}
