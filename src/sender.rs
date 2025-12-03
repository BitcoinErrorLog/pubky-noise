//! Raw-key Noise sender (client/initiator).
//!
//! `NoiseSender` provides a simpler API for initiating Noise handshakes when the
//! caller already has derived X25519/Ed25519 keys. This avoids the need for
//! `RingKeyProvider` and gives applications full control over key management.
//!
//! # Example
//!
//! ```no_run
//! use pubky_noise::{NoiseSender, kdf};
//! use zeroize::Zeroizing;
//!
//! # fn main() -> Result<(), pubky_noise::NoiseError> {
//! // Derive keys at the application layer
//! let seed = [0u8; 32]; // Your Ed25519 seed
//! let x25519_sk = Zeroizing::new(kdf::derive_x25519_static(&seed, b"device-id"));
//! let ed25519_pub = [0u8; 32]; // Your Ed25519 public key
//!
//! // Create sender with raw keys
//! let sender = NoiseSender::new();
//! let server_pk = [0u8; 32]; // Server's X25519 public key
//!
//! // Initiate IK handshake with a signing callback
//! let (hs, first_msg) = sender.initiate_ik(
//!     &x25519_sk,
//!     &ed25519_pub,
//!     &server_pk,
//!     |binding_msg| {
//!         // Sign the binding message with your Ed25519 key
//!         // Return [u8; 64] signature
//!         [0u8; 64] // placeholder
//!     },
//! )?;
//! # Ok(())
//! # }
//! ```

use crate::errors::NoiseError;
use crate::identity_payload::{make_binding_message, IdentityPayload, Role};
use zeroize::Zeroizing;

/// Default Noise suite for pubky-noise.
pub const DEFAULT_NOISE_SUITE: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
/// Default prologue for pubky-noise.
pub const DEFAULT_PROLOGUE: &[u8] = b"pubky-noise-v1";

/// Raw-key Noise sender for initiating encrypted sessions.
///
/// Unlike `NoiseClient`, `NoiseSender` accepts pre-derived keys directly rather
/// than requiring a `RingKeyProvider`. This gives applications full control over
/// key derivation while still benefiting from the Noise protocol implementation.
///
/// # Key Management
///
/// The caller is responsible for:
/// - Deriving X25519 keys from Ed25519 seeds (use `kdf::derive_x25519_static`)
/// - Providing a signing callback for Ed25519 signatures
/// - Zeroizing keys after use
///
/// # Thread Safety
///
/// `NoiseSender` is stateless and can be shared across threads. Each handshake
/// initiation creates independent state.
#[derive(Debug, Clone)]
pub struct NoiseSender {
    /// Noise pattern suite (defaults to IK with X25519/ChaChaPoly/BLAKE2s)
    pub suite: String,
    /// Prologue for channel binding (defaults to "pubky-noise-v1")
    pub prologue: Vec<u8>,
}

impl Default for NoiseSender {
    fn default() -> Self {
        Self::new()
    }
}

impl NoiseSender {
    /// Create a new `NoiseSender` with default settings.
    ///
    /// - Suite: `Noise_IK_25519_ChaChaPoly_BLAKE2s`
    /// - Prologue: `"pubky-noise-v1"`
    pub fn new() -> Self {
        Self {
            suite: DEFAULT_NOISE_SUITE.to_string(),
            prologue: DEFAULT_PROLOGUE.to_vec(),
        }
    }

    /// Create a `NoiseSender` with custom suite and prologue.
    pub fn with_params(suite: impl Into<String>, prologue: impl Into<Vec<u8>>) -> Self {
        Self {
            suite: suite.into(),
            prologue: prologue.into(),
        }
    }

    /// Initiate an IK pattern handshake.
    ///
    /// Creates a Noise IK handshake state and generates the first message to send
    /// to the server. The IK pattern is used when the server's static public key
    /// is known in advance.
    ///
    /// # Arguments
    ///
    /// * `local_x25519_sk` - Your X25519 secret key for this session (32 bytes, zeroizing).
    ///   Use `kdf::derive_x25519_static` to derive from Ed25519 seed.
    ///
    /// * `local_ed25519_pub` - Your long-term Ed25519 public key (32 bytes).
    ///
    /// * `server_static_pub` - The server's static X25519 public key (32 bytes).
    ///   **Security**: Verify this through a trusted channel.
    ///
    /// * `sign_binding` - Callback to sign the binding message with your Ed25519 key.
    ///   Receives a 32-byte binding message, returns 64-byte Ed25519 signature.
    ///
    /// # Returns
    ///
    /// Returns `Ok((handshake_state, first_message))` on success:
    /// - `handshake_state` - Snow handshake state for completing the handshake
    /// - `first_message` - Encrypted handshake message to send to server
    ///
    /// # Errors
    ///
    /// Returns `Err(NoiseError)` if:
    /// - `InvalidPeerKey` - Server's static key would result in all-zero shared secret
    /// - `Snow(...)` - Noise protocol error
    /// - `Serde(...)` - Identity payload serialization failed
    ///
    /// # Security
    ///
    /// - **All-Zero DH Check**: Automatically rejects weak peer keys
    /// - **Identity Binding**: Binds Ed25519 identity to X25519 session key
    /// - **Key Zeroization**: Uses `Zeroizing<[u8; 32]>` for secret keys
    ///
    /// # Example
    ///
    /// ```no_run
    /// use pubky_noise::{NoiseSender, kdf};
    /// use zeroize::Zeroizing;
    ///
    /// # fn sign_with_ed25519(msg: &[u8; 32]) -> [u8; 64] { [0u8; 64] }
    /// # fn main() -> Result<(), pubky_noise::NoiseError> {
    /// let x25519_sk = Zeroizing::new(kdf::derive_x25519_static(&[0u8; 32], b"dev"));
    /// let ed25519_pub = [0u8; 32];
    /// let server_pk = [0u8; 32];
    ///
    /// let sender = NoiseSender::new();
    /// let (hs, first_msg) = sender.initiate_ik(
    ///     &x25519_sk,
    ///     &ed25519_pub,
    ///     &server_pk,
    ///     |msg| sign_with_ed25519(msg),
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn initiate_ik<F>(
        &self,
        local_x25519_sk: &Zeroizing<[u8; 32]>,
        local_ed25519_pub: &[u8; 32],
        server_static_pub: &[u8; 32],
        sign_binding: F,
    ) -> Result<(snow::HandshakeState, Vec<u8>), NoiseError>
    where
        F: FnOnce(&[u8; 32]) -> [u8; 64],
    {
        // Check for weak keys (all-zero DH result)
        if !crate::kdf::shared_secret_nonzero(local_x25519_sk, server_static_pub) {
            return Err(NoiseError::InvalidPeerKey);
        }

        // Derive X25519 public key from secret
        let local_x25519_pub = crate::kdf::x25519_pk_from_sk(local_x25519_sk);

        // Build Noise handshake state
        let builder = snow::Builder::new(
            self.suite
                .parse::<snow::params::NoiseParams>()
                .map_err(|e: snow::Error| NoiseError::Other(e.to_string()))?,
        );

        let mut hs = builder
            .local_private_key(&**local_x25519_sk)?
            .remote_public_key(server_static_pub)?
            .prologue(&self.prologue)?
            .build_initiator()
            .map_err(NoiseError::from)?;

        // Create identity binding
        let tag = "IK";
        let msg32 = make_binding_message(
            tag,
            &self.prologue,
            local_ed25519_pub,
            &local_x25519_pub,
            Some(server_static_pub),
            Role::Client,
        );

        // Sign the binding
        let sig64 = sign_binding(&msg32);

        // Build identity payload
        let payload = IdentityPayload {
            ed25519_pub: *local_ed25519_pub,
            noise_x25519_pub: local_x25519_pub,
            role: Role::Client,
            sig: sig64,
        };

        // Encrypt and send identity payload in first message
        let payload_bytes = serde_json::to_vec(&payload)?;
        let mut out = vec![0u8; payload_bytes.len() + 128];
        let n = hs.write_message(&payload_bytes, &mut out)?;
        out.truncate(n);

        Ok((hs, out))
    }

    /// Initiate an XX pattern handshake (Trust On First Use).
    ///
    /// Creates a Noise XX handshake for first-contact scenarios where the server's
    /// static key is not known in advance. Both client and server exchange static
    /// keys during the handshake.
    ///
    /// **Use Case**: Initial connection before the server's key is pinned.
    /// After the first successful XX handshake, extract and pin the server's
    /// static key, then use `initiate_ik` for subsequent connections.
    ///
    /// # Arguments
    ///
    /// * `local_x25519_sk` - Your X25519 secret key for this session (32 bytes, zeroizing).
    ///
    /// # Returns
    ///
    /// Returns `Ok((handshake_state, first_message))` on success.
    ///
    /// # Security Notes
    ///
    /// - **Trust On First Use**: No server authentication on first connection.
    /// - **Pin After First Use**: Extract and store the server's static key.
    pub fn initiate_xx(
        &self,
        local_x25519_sk: &Zeroizing<[u8; 32]>,
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
            .build_initiator()
            .map_err(NoiseError::from)?;

        let mut out = vec![0u8; 128];
        let n = hs.write_message(&[], &mut out)?;
        out.truncate(n);

        Ok((hs, out))
    }

    // ========== COLD KEY PATTERNS (pkarr-based authentication) ==========

    /// Initiate an IK pattern handshake without identity binding.
    ///
    /// Use when identity binding is provided externally (e.g., via pkarr).
    /// The server's X25519 key should be retrieved from a pkarr record
    /// signed by their Ed25519 identity.
    ///
    /// # Cold Key Architecture
    ///
    /// This method is designed for scenarios where Ed25519 keys are kept cold:
    /// 1. Server publishes X25519 key via pkarr (one-time cold signing)
    /// 2. Client looks up server's X25519 from pkarr (already authenticated)
    /// 3. Client calls `initiate_ik_raw` - no Ed25519 signing needed
    ///
    /// # Arguments
    ///
    /// * `local_x25519_sk` - Your X25519 secret key for this session (32 bytes, zeroizing).
    /// * `server_static_pub` - The server's static X25519 public key (from pkarr lookup).
    ///
    /// # Returns
    ///
    /// Returns `Ok((handshake_state, first_message))` on success.
    ///
    /// # Security Notes
    ///
    /// - **No In-Handshake Authentication**: Identity must be verified via pkarr
    /// - **Caller Responsibility**: Ensure server_static_pub came from a valid pkarr record
    /// - **All-Zero DH Check**: Automatically rejects weak peer keys
    ///
    /// # Example
    ///
    /// ```no_run
    /// use pubky_noise::{NoiseSender, kdf};
    /// use zeroize::Zeroizing;
    ///
    /// # fn main() -> Result<(), pubky_noise::NoiseError> {
    /// // 1. Look up server's X25519 key from pkarr (already Ed25519-signed)
    /// let server_pk = [0u8; 32]; // From pkarr lookup
    ///
    /// // 2. Derive local X25519 key
    /// let x25519_sk = Zeroizing::new(kdf::derive_x25519_static(&[0u8; 32], b"device"));
    ///
    /// // 3. Initiate without Ed25519 signing (pkarr already authenticated server)
    /// let sender = NoiseSender::new();
    /// let (hs, first_msg) = sender.initiate_ik_raw(&x25519_sk, &server_pk)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn initiate_ik_raw(
        &self,
        local_x25519_sk: &Zeroizing<[u8; 32]>,
        server_static_pub: &[u8; 32],
    ) -> Result<(snow::HandshakeState, Vec<u8>), NoiseError> {
        // Check for weak keys (all-zero DH result)
        if !crate::kdf::shared_secret_nonzero(local_x25519_sk, server_static_pub) {
            return Err(NoiseError::InvalidPeerKey);
        }

        // Build Noise handshake state
        let builder = snow::Builder::new(
            self.suite
                .parse::<snow::params::NoiseParams>()
                .map_err(|e: snow::Error| NoiseError::Other(e.to_string()))?,
        );

        let mut hs = builder
            .local_private_key(&**local_x25519_sk)?
            .remote_public_key(server_static_pub)?
            .prologue(&self.prologue)?
            .build_initiator()
            .map_err(NoiseError::from)?;

        // Send empty payload (no identity binding)
        let mut out = vec![0u8; 128];
        let n = hs.write_message(&[], &mut out)?;
        out.truncate(n);

        Ok((hs, out))
    }

    /// Initiate an N pattern handshake (anonymous initiator, known responder).
    ///
    /// The initiator has no static key (anonymous), while the responder's
    /// static key is known in advance (typically from pkarr).
    ///
    /// # Use Cases
    ///
    /// - Cold client keys connecting to a known server
    /// - Anonymous clients with authenticated servers
    /// - One-way authentication (server only)
    ///
    /// # Arguments
    ///
    /// * `server_static_pub` - The server's static X25519 public key (from pkarr).
    ///
    /// # Returns
    ///
    /// Returns `Ok((handshake_state, first_message))` on success.
    ///
    /// # Security Notes
    ///
    /// - **Anonymous Initiator**: Client identity is not authenticated
    /// - **Authenticated Responder**: Server identity via pkarr
    /// - **Forward Secrecy**: Provided by ephemeral keys
    ///
    /// # Example
    ///
    /// ```no_run
    /// use pubky_noise::NoiseSender;
    ///
    /// # fn main() -> Result<(), pubky_noise::NoiseError> {
    /// let server_pk = [0u8; 32]; // From pkarr lookup
    ///
    /// let sender = NoiseSender::new();
    /// let (hs, first_msg) = sender.initiate_n(&server_pk)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn initiate_n(
        &self,
        server_static_pub: &[u8; 32],
    ) -> Result<(snow::HandshakeState, Vec<u8>), NoiseError> {
        let suite = "Noise_N_25519_ChaChaPoly_BLAKE2s";
        let builder = snow::Builder::new(
            suite
                .parse::<snow::params::NoiseParams>()
                .map_err(|e: snow::Error| NoiseError::Other(e.to_string()))?,
        );

        let mut hs = builder
            .remote_public_key(server_static_pub)?
            .prologue(&self.prologue)?
            .build_initiator()
            .map_err(NoiseError::from)?;

        let mut out = vec![0u8; 64];
        let n = hs.write_message(&[], &mut out)?;
        out.truncate(n);

        Ok((hs, out))
    }

    /// Initiate an NN pattern handshake (both parties anonymous).
    ///
    /// No static keys on either side - purely ephemeral key exchange.
    ///
    /// # Use Cases
    ///
    /// - Post-handshake attestation will provide identity
    /// - Truly anonymous connections
    /// - External authentication mechanism exists
    ///
    /// # Returns
    ///
    /// Returns `Ok((handshake_state, first_message))` on success.
    ///
    /// # Security Notes
    ///
    /// - **No Authentication**: Neither party is authenticated
    /// - **Forward Secrecy**: Yes (ephemeral keys)
    /// - **MITM Vulnerable**: Without external authentication
    ///
    /// # Example
    ///
    /// ```no_run
    /// use pubky_noise::NoiseSender;
    ///
    /// # fn main() -> Result<(), pubky_noise::NoiseError> {
    /// let sender = NoiseSender::new();
    /// let (hs, first_msg) = sender.initiate_nn()?;
    ///
    /// // After handshake, send identity attestation over encrypted channel
    /// # Ok(())
    /// # }
    /// ```
    pub fn initiate_nn(&self) -> Result<(snow::HandshakeState, Vec<u8>), NoiseError> {
        let suite = "Noise_NN_25519_ChaChaPoly_BLAKE2s";
        let builder = snow::Builder::new(
            suite
                .parse::<snow::params::NoiseParams>()
                .map_err(|e: snow::Error| NoiseError::Other(e.to_string()))?,
        );

        let mut hs = builder
            .prologue(&self.prologue)?
            .build_initiator()
            .map_err(NoiseError::from)?;

        let mut out = vec![0u8; 64];
        let n = hs.write_message(&[], &mut out)?;
        out.truncate(n);

        Ok((hs, out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sender_default() {
        let sender = NoiseSender::new();
        assert_eq!(sender.suite, DEFAULT_NOISE_SUITE);
        assert_eq!(sender.prologue, DEFAULT_PROLOGUE);
    }

    #[test]
    fn test_sender_custom_params() {
        let sender = NoiseSender::with_params("Noise_XX_25519_ChaChaPoly_BLAKE2s", b"custom");
        assert_eq!(sender.suite, "Noise_XX_25519_ChaChaPoly_BLAKE2s");
        assert_eq!(sender.prologue, b"custom".to_vec());
    }
}
