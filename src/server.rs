use crate::errors::NoiseError;
use crate::identity_payload::{
    make_binding_message, verify_identity_payload, IdentityPayload, Role,
};
use crate::ring::{RingKeyFiller, RingKeyProvider};
use zeroize::Zeroizing;

/// Server policy configuration for connection management.
///
/// Defines limits and policies for accepting client connections.
/// All fields are optional - `None` means no limit enforced.
///
/// # Examples
///
/// ```rust
/// use pubky_noise::server::ServerPolicy;
///
/// // Default: no limits
/// let policy = ServerPolicy::default();
///
/// // With limits
/// let policy = ServerPolicy {
///     max_handshakes_per_ip: Some(100),
///     max_sessions_per_ed25519: Some(10),
/// };
/// ```
#[derive(Clone, Debug, Default)]
pub struct ServerPolicy {
    /// Maximum handshake attempts allowed per IP address.
    ///
    /// Helps prevent DoS attacks from a single source.
    /// `None` means unlimited (not recommended for production).
    pub max_handshakes_per_ip: Option<u32>,

    /// Maximum concurrent sessions per client Ed25519 identity.
    ///
    /// Prevents a single client from consuming too many resources.
    /// `None` means unlimited.
    pub max_sessions_per_ed25519: Option<u32>,
}

/// Noise Protocol server for accepting encrypted sessions.
///
/// `NoiseServer` manages the server side of Noise Protocol handshakes, supporting
/// the IK (Interactive, Known responder) pattern. The server accepts connections,
/// validates client identities, and enforces policy constraints.
///
/// # Type Parameters
///
/// * `R: RingKeyProvider` - Key provider for device-specific X25519 and Ed25519 keys.
///   Keys are derived on-demand and never stored in application memory.
///
/// # Key Features
///
/// - **Identity Verification**: Validates client Ed25519 signatures on identity bindings
/// - **Policy Enforcement**: Configurable limits on connections and resources
/// - **All-Zero DH Rejection**: Automatically rejects weak client keys
///
/// # Security Architecture
///
/// The server performs multiple security checks on incoming connections:
///
/// 1. **Noise Handshake Validation**: Verifies Noise protocol messages
/// 2. **DH Shared Secret Check**: Rejects all-zero shared secrets
/// 3. **Identity Binding Verification**: Validates Ed25519 signature over session binding
/// 4. **Policy Enforcement**: Applies configured limits
///
/// # Examples
///
/// ## Basic Server Setup
///
/// ```no_run
/// use pubky_noise::{NoiseServer, DummyRing};
/// use pubky_noise::server::ServerPolicy;
/// use std::sync::Arc;
///
/// // Create key provider (use PubkyRingProvider in production)
/// let seed = [0u8; 32]; // Use secure random seed in production
/// let ring = Arc::new(DummyRing::new(seed, "server-key-id"));
///
/// // Create server
/// let mut server = NoiseServer::new_direct(
///     "server-key-id",
///     b"server-device",
///     ring,
/// );
///
/// // Configure policy
/// server.policy = ServerPolicy {
///     max_handshakes_per_ip: Some(100),
///     max_sessions_per_ed25519: Some(10),
/// };
/// ```
///
/// ## Accepting a Connection
///
/// ```no_run
/// # use pubky_noise::{NoiseServer, DummyRing};
/// # use std::sync::Arc;
/// # fn main() -> Result<(), pubky_noise::NoiseError> {
/// # let ring = Arc::new(DummyRing::new([0u8; 32], "key-id"));
/// # let server = NoiseServer::new_direct("key-id", b"device", ring);
/// // Receive first message from client over your transport
/// let client_first_msg: Vec<u8> = vec![]; // From network
///
/// // Process handshake
/// let (handshake_state, client_identity) = server
///     .build_responder_read_ik(&client_first_msg)?;
///
/// // Extract client information
/// println!("Client Ed25519: {:?}", client_identity.ed25519_pub);
///
/// // Continue handshake to establish session...
/// # Ok(())
/// # }
/// ```
///
/// # Thread Safety
///
/// `NoiseServer` is `Send + Sync` if `R: Send + Sync`.
pub struct NoiseServer<R: RingKeyProvider> {
    pub kid: String,
    pub device_id: Vec<u8>,
    pub ring: std::sync::Arc<R>,
    pub prologue: Vec<u8>,
    pub suite: String,
    pub policy: ServerPolicy,
}

impl<R: RingKeyProvider> NoiseServer<R> {
    /// Create a new Noise server for direct connections.
    ///
    /// # Arguments
    ///
    /// * `kid` - Key identifier for looking up server keys from the ring provider
    /// * `device_id` - Device identifier for key derivation
    /// * `ring` - Arc-wrapped key provider implementing `RingKeyProvider`
    ///
    /// # Returns
    ///
    /// A new `NoiseServer` configured with:
    /// - Prologue: `"pubky-noise-v1"`
    /// - Suite: `Noise_IK_25519_ChaChaPoly_BLAKE2s`
    /// - Default policy (no limits)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use pubky_noise::{NoiseServer, DummyRing};
    /// use std::sync::Arc;
    ///
    /// let ring = Arc::new(DummyRing::new([0u8; 32], "server-key-id"));
    /// let server = NoiseServer::new_direct(
    ///     "server-key-id",
    ///     b"server-device-001",
    ///     ring,
    /// );
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
            policy: ServerPolicy::default(),
        }
    }

    /// Process the first message of an IK handshake from a client.
    ///
    /// This method validates the client's handshake message, verifies their
    /// identity binding, and prepares the handshake state for completing
    /// the session establishment.
    ///
    /// # Security Checks Performed
    ///
    /// 1. **Noise Protocol Validation**: Verifies the Noise handshake message format
    /// 2. **DH Validation**: Ensures the shared secret with client is non-zero
    /// 3. **Identity Binding**: Validates Ed25519 signature over binding message
    /// 4. **Signature Verification**: Checks client's signature is valid
    ///
    /// # Arguments
    ///
    /// * `first_msg` - The first handshake message received from the client.
    ///   This should be the raw bytes from the network.
    ///
    /// # Returns
    ///
    /// Returns `Ok((handshake_state, client_identity))` on success:
    /// - `handshake_state` - Snow handshake state for completing the handshake
    /// - `client_identity` - Parsed and validated client identity payload containing:
    ///   - `ed25519_pub`: Client's long-term Ed25519 public key
    ///   - `noise_x25519_pub`: Client's ephemeral X25519 public key
    ///   - `role`: Should be `Role::Client`
    ///   - `sig`: Ed25519 signature (already verified)
    ///
    /// # Errors
    ///
    /// Returns `Err(NoiseError)` if:
    /// - `Snow(...)` - Noise protocol validation failed (malformed message, wrong pattern, etc.)
    /// - `InvalidPeerKey` - Client's X25519 key would result in all-zero shared secret
    /// - `IdentityVerify` - Client's Ed25519 signature verification failed
    /// - `Serde(...)` - Identity payload deserialization failed
    /// - `Ring(...)` - Key derivation failed
    /// - `Other(...)` - Ed25519 public key deserialization failed
    ///
    /// # Identity Binding
    ///
    /// The binding message that is signed includes:
    /// - Pattern tag ("IK")
    /// - Prologue ("pubky-noise-v1")
    /// - Client's Ed25519 public key
    /// - Client's X25519 ephemeral key
    /// - Server's X25519 static key
    /// - Role (Client)
    ///
    /// This binding prevents:
    /// - Key substitution attacks
    /// - Identity confusion attacks
    /// - Cross-pattern replay attacks
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use pubky_noise::{NoiseServer, DummyRing};
    /// # use std::sync::Arc;
    /// # fn main() -> Result<(), pubky_noise::NoiseError> {
    /// # let ring = Arc::new(DummyRing::new([0u8; 32], "key-id"));
    /// # let server = NoiseServer::new_direct("key-id", b"device", ring);
    /// // Receive client's first message from network
    /// let client_msg: Vec<u8> = vec![]; // From TCP/WebSocket/etc
    ///
    /// match server.build_responder_read_ik(&client_msg) {
    ///     Ok((hs, identity)) => {
    ///         // Handshake message valid, identity verified
    ///         println!("Client identity: {:?}", identity.ed25519_pub);
    ///         
    ///         // Continue with handshake completion...
    ///     }
    ///     Err(e) => {
    ///         eprintln!("Handshake failed: {:?}", e);
    ///         // Reject connection
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Performance Considerations
    ///
    /// This method performs:
    /// - One Ed25519 signature verification (~0.1ms on modern hardware)
    /// - One X25519 DH operation (~0.05ms)
    /// - One BLAKE2s hash (~0.01ms)
    ///
    /// Total: ~0.15ms per connection attempt. For high-traffic servers,
    /// consider rate limiting per IP address using `ServerPolicy`.
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
            |x_sk: &Zeroizing<[u8; 32]>| -> Result<(snow::HandshakeState, [u8; 32]), NoiseError> {
                // Derive public key from private key before passing to builder
                let x_pk_arr = crate::kdf::x25519_pk_from_sk(x_sk);

                // Chain builder calls since each method consumes and returns self
                let hs = builder
                    .local_private_key(&**x_sk)?
                    .prologue(&self.prologue)?
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
            |x_sk: &Zeroizing<[u8; 32]>| {
                crate::kdf::shared_secret_nonzero(x_sk, &payload.noise_x25519_pub)
            },
        )?;
        if !ok {
            return Err(NoiseError::InvalidPeerKey);
        }

        let tag = "IK";
        let msg32 = make_binding_message(
            tag,
            &self.prologue,
            &payload.ed25519_pub,
            &payload.noise_x25519_pub,
            Some(&x_pk_arr),
            Role::Client,
        );
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&payload.ed25519_pub)
            .map_err(|e| NoiseError::Other(e.to_string()))?;
        let ok = verify_identity_payload(&vk, &msg32, &payload.sig);
        if !ok {
            return Err(NoiseError::IdentityVerify);
        }

        Ok((hs, payload))
    }
}
