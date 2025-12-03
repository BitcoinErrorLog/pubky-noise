use crate::errors::NoiseError;
use crate::identity_payload::{make_binding_message, IdentityPayload, Role};
use crate::ring::{RingKeyFiller, RingKeyProvider};
use zeroize::Zeroizing;

/// Noise Protocol client for initiating encrypted sessions.
///
/// `NoiseClient` manages the client side of Noise Protocol handshakes, supporting
/// both IK (Interactive, Known responder) and XX (eXchange, eXchange) patterns.
/// The client initiates connections, derives ephemeral keys, and creates identity
/// bindings to authenticate the session.
///
/// # Type Parameters
///
/// * `R: RingKeyProvider` - Key provider for device-specific X25519 and Ed25519 keys.
///   Keys are derived on-demand and never stored in application memory.
///
/// # Key Features
///
/// - **Secure Key Management**: Keys are derived in closures and passed directly
///   to the Noise library without lingering in application memory.
///
/// - **Identity Binding**: Each session binds the long-term Ed25519 identity to
///   the ephemeral X25519 session key, preventing identity substitution.
///
/// - **All-Zero DH Rejection**: Automatically rejects invalid peer keys that would
///   result in weak/trivial shared secrets.
///
/// # Noise Patterns
///
/// ## IK Pattern (Recommended)
///
/// Used when the server's static public key is known in advance (pinned or delivered
/// out-of-band). Provides:
/// - Forward secrecy
/// - Mutual authentication
/// - Hidden initiator identity (from passive observers)
///
/// ## XX Pattern (TOFU - Trust On First Use)
///
/// Used for first contact when server key is not known. Provides:
/// - Forward secrecy
/// - Mutual authentication (after first exchange)
/// - Both identities transmitted during handshake
///
/// # Examples
///
/// ## Basic Direct Connection (IK Pattern)
///
/// ```no_run
/// use pubky_noise::{NoiseClient, DummyRing};
/// use std::sync::Arc;
///
/// # fn main() -> Result<(), pubky_noise::NoiseError> {
/// // Create a key provider (use PubkyRingProvider in production)
/// let seed = [0u8; 32]; // Use secure random seed in production
/// let ring = Arc::new(DummyRing::new(seed, "my-key-id"));
///
/// // Create client
/// let client = NoiseClient::new_direct(
///     "my-key-id",      // Key identifier
///     b"device-001",    // Device identifier
///     ring,             // Key provider
/// );
///
/// // Initiate IK handshake with known server
/// let server_static_pk = [0u8; 32]; // Server's public key
/// let (handshake_state, first_message) =
///     client.build_initiator_ik_direct(&server_static_pk)?;
///
/// // Send first_message to server...
/// # Ok(())
/// # }
/// ```
///
/// # Security Considerations
///
/// - **Key Provider Security**: The security of the client depends entirely on
///   the `RingKeyProvider` implementation. Ensure your provider properly protects
///   key material.
///
/// - **Server Key Validation**: Always verify the server's static public key
///   through a trusted channel before using IK pattern.
///
/// - **Weak DH Detection**: The client automatically rejects peer keys that would
///   result in all-zero shared secrets, preventing weak DH attacks.
///
/// # Thread Safety
///
/// `NoiseClient` is `Send` and `Sync` if its generic parameters are. The key
/// provider `R` must implement `Send + Sync` as enforced by the trait bounds.
pub struct NoiseClient<R: RingKeyProvider> {
    pub kid: String,
    pub device_id: Vec<u8>,
    pub ring: std::sync::Arc<R>,
    pub prologue: Vec<u8>,
    pub suite: String,
    pub now_unix: Option<u64>,
}

impl<R: RingKeyProvider> NoiseClient<R> {
    /// Create a new Noise client for direct connections.
    ///
    /// # Arguments
    ///
    /// * `kid` - Key identifier used to look up keys from the ring provider.
    ///   This should uniquely identify the keypair for this client.
    ///
    /// * `device_id` - Device identifier used for key derivation. Each device
    ///   should have a unique identifier.
    ///
    /// * `ring` - Arc-wrapped key provider implementing `RingKeyProvider`.
    ///   The provider will be called to derive keys on-demand.
    ///
    /// # Returns
    ///
    /// A new `NoiseClient` configured with:
    /// - Prologue: `"pubky-noise-v1"`
    /// - Suite: `Noise_IK_25519_ChaChaPoly_BLAKE2s`
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use pubky_noise::{NoiseClient, DummyRing};
    /// use std::sync::Arc;
    ///
    /// let ring = Arc::new(DummyRing::new([0u8; 32], "key-id"));
    /// let client = NoiseClient::new_direct("key-id", b"device-001", ring);
    /// ```
    pub fn new_direct(
        kid: impl Into<String>,
        device_id: impl AsRef<[u8]>,
        ring: std::sync::Arc<R>,
    ) -> Self {
        Self {
            kid: kid.into(),
            device_id: device_id.as_ref().to_vec(),
            ring,
            prologue: b"pubky-noise-v1".to_vec(),
            suite: "Noise_IK_25519_ChaChaPoly_BLAKE2s".into(),
            now_unix: None,
        }
    }

    /// Build an IK pattern handshake initiator with identity binding.
    ///
    /// This method creates a Noise IK handshake state and generates the first
    /// handshake message to send to the server. The message includes:
    /// - Ephemeral X25519 public key
    /// - Ed25519 identity signature binding
    /// - Encrypted identity payload
    ///
    /// # Arguments
    ///
    /// * `server_static_pub` - The server's static X25519 public key (32 bytes).
    ///   This must be known in advance (pinned or delivered out-of-band).
    ///   **Security**: Verify this key through a trusted channel.
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
    /// - `Ring(...)` - Key derivation failed
    /// - `Snow(...)` - Noise protocol error
    /// - `Serde(...)` - Identity payload serialization failed
    ///
    /// # Security
    ///
    /// - **All-Zero DH Check**: Automatically rejects weak peer keys
    /// - **Identity Binding**: Binds Ed25519 identity to X25519 session key
    /// - **Key Zeroization**: Ephemeral secret keys are zeroized after use
    /// - **Domain Separation**: Uses "pubky-noise-bind:v2" prefix
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use pubky_noise::{NoiseClient, DummyRing};
    /// use std::sync::Arc;
    ///
    /// # fn main() -> Result<(), pubky_noise::NoiseError> {
    /// let ring = Arc::new(DummyRing::new([0u8; 32], "key-id"));
    /// let client = NoiseClient::new_direct("key-id", b"device-001", ring);
    ///
    /// let server_pk = [0u8; 32]; // Server's static public key
    ///
    /// let (hs, first_msg) = client
    ///     .build_initiator_ik_direct(&server_pk)?;
    ///
    /// // Send first_msg to server over your transport...
    /// // Then complete handshake with server's response
    /// # Ok(())
    /// # }
    /// ```
    pub fn build_initiator_ik_direct(
        &self,
        server_static_pub: &[u8; 32],
    ) -> Result<(snow::HandshakeState, Vec<u8>), NoiseError> {
        let builder = snow::Builder::new(
            self.suite
                .parse::<snow::params::NoiseParams>()
                .map_err(|e: snow::Error| NoiseError::Other(e.to_string()))?,
        );

        let (mut hs, x_pk_arr) = self.ring.with_device_x25519(
            &self.kid,
            &self.device_id,
            |x_sk: &Zeroizing<[u8; 32]>| {
                if !crate::kdf::shared_secret_nonzero(x_sk, server_static_pub) {
                    return Err(NoiseError::InvalidPeerKey);
                }
                // Derive public key from private key before passing to builder
                let x_pk_arr = crate::kdf::x25519_pk_from_sk(x_sk);

                // Chain builder calls since each method consumes and returns self
                let hs = builder
                    .local_private_key(&**x_sk)?
                    .remote_public_key(server_static_pub)?
                    .prologue(&self.prologue)?
                    .build_initiator()
                    .map_err(NoiseError::from)?;
                Ok((hs, x_pk_arr))
            },
        )??;
        let ed_pub = self.ring.ed25519_pubkey(&self.kid)?;

        let tag = "IK";
        let msg32 = make_binding_message(
            tag,
            &self.prologue,
            &ed_pub,
            &x_pk_arr,
            Some(server_static_pub),
            Role::Client,
        );
        let sig64 = self.ring.sign_ed25519(&self.kid, &msg32)?;

        let payload = IdentityPayload {
            ed25519_pub: ed_pub,
            noise_x25519_pub: x_pk_arr,
            role: Role::Client,
            sig: sig64,
        };

        let payload_bytes = serde_json::to_vec(&payload)?;
        let mut out = vec![0u8; payload_bytes.len() + 128];
        let n = hs.write_message(&payload_bytes, &mut out)?;
        out.truncate(n);
        Ok((hs, out))
    }

    /// Build an XX pattern handshake initiator (Trust On First Use).
    ///
    /// This method creates a Noise XX handshake for first-contact scenarios where
    /// the server's static key is not known in advance. Both client and server
    /// exchange static keys during the handshake.
    ///
    /// **Use Case**: Initial connection before the server's key is pinned.
    /// After the first successful XX handshake, switch to IK pattern with the
    /// now-known server key for better performance and stronger guarantees.
    ///
    /// # Returns
    ///
    /// Returns `Ok((handshake_state, first_message))` on success:
    /// - `handshake_state` - Snow handshake state for completing the handshake
    /// - `first_message` - First XX handshake message to send to server
    ///
    /// # Errors
    ///
    /// Returns `Err(NoiseError)` if:
    /// - `Ring(...)` - Key derivation failed
    /// - `Snow(...)` - Noise protocol error
    ///
    /// # Security Notes
    ///
    /// - **No Forward Secrecy on First Message**: The first XX message doesn't
    ///   provide forward secrecy yet. It's established after the handshake completes.
    ///
    /// - **Trust On First Use**: No authentication on first connection. The
    ///   application must validate the server's identity through other means.
    ///
    /// - **Pin After First Use**: After a successful XX handshake, pin the
    ///   server's static key and use IK pattern for subsequent connections.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use pubky_noise::{NoiseClient, DummyRing};
    /// use std::sync::Arc;
    ///
    /// # fn main() -> Result<(), pubky_noise::NoiseError> {
    /// let ring = Arc::new(DummyRing::new([0u8; 32], "key-id"));
    /// let client = NoiseClient::new_direct("key-id", b"device-001", ring);
    ///
    /// // First contact - server key unknown
    /// let (hs, first_msg) = client.build_initiator_xx_tofu()?;
    ///
    /// // Send first_msg to server...
    /// // After handshake completes, extract and pin server's static key
    /// // Use IK pattern for all future connections
    /// # Ok(())
    /// # }
    /// ```
    pub fn build_initiator_xx_tofu(&self) -> Result<(snow::HandshakeState, Vec<u8>), NoiseError> {
        let suite = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
        let builder = snow::Builder::new(
            suite
                .parse::<snow::params::NoiseParams>()
                .map_err(|e: snow::Error| NoiseError::Other(e.to_string()))?,
        );
        let hs = self
            .ring
            .with_device_x25519(&self.kid, &self.device_id, |x_sk| {
                // Chain builder calls since each method consumes and returns self
                builder
                    .local_private_key(&**x_sk)?
                    .prologue(&self.prologue)?
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
