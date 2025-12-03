use crate::errors::NoiseError;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use zeroize::Zeroizing;

/// Key provider trait for deriving device-specific cryptographic keys.
///
/// `RingKeyProvider` is the core abstraction for secure key management in pubky-noise.
/// It provides methods to derive X25519 keys for Noise Protocol handshakes and
/// Ed25519 keys for identity binding, all while keeping keys out of application memory.
///
/// # Security Model
///
/// The trait enforces a security-by-design approach:
///
/// 1. **No Long-Lived Keys**: Keys are derived on-demand, used immediately, and
///    zeroized after use. No keys persist in application memory.
///
/// 2. **Hierarchical Derivation**: Device-specific keys are derived from a root
///    seed using HKDF, with device ID providing key isolation.
///
/// 3. **Memory Safety**: The companion `RingKeyFiller` trait ensures derived keys
///    are wrapped in `Zeroizing` and passed through closures, preventing leakage.
///
/// # Thread Safety
///
/// Implementors must be `Send + Sync` to allow safe sharing across threads.
/// This is enforced by trait bounds and enables concurrent session management.
///
/// # Implementation Requirements
///
/// Implementations must:
/// - Protect the root seed material
/// - Use proper key derivation (HKDF with domain separation)
/// - Apply X25519 clamping (clear bits 0-2 of first byte, set bit 254, clear bit 255)
/// - Use deterministic Ed25519 (RFC 8032)
/// - Zero sensitive material after use
///
/// # Examples
///
/// ## Using the Dummy Provider (Testing Only)
///
/// ```rust
/// use pubky_noise::DummyRing;
/// use pubky_noise::ring::RingKeyProvider;
///
/// // Create a dummy ring with a test seed
/// let seed = [42u8; 32];
/// let ring = DummyRing::new(seed, "test-key-id");
///
/// // Derive X25519 key
/// let x25519_key = ring.derive_device_x25519(
///     "test-key-id",
///     b"device-001",
/// )?;
///
/// // Get Ed25519 public key
/// let ed25519_pub = ring.ed25519_pubkey("test-key-id")?;
///
/// // Sign a message
/// let message = b"test message";
/// let signature = ring.sign_ed25519("test-key-id", message)?;
/// # Ok::<(), pubky_noise::NoiseError>(())
/// ```
///
/// ## Implementing for Production (Conceptual)
///
/// ```rust,no_run
/// # use pubky_noise::ring::RingKeyProvider;
/// # use pubky_noise::NoiseError;
/// # use ed25519_dalek::{Signer, SigningKey};
/// struct SecureKeyProvider {
///     // Encrypted seed stored in secure enclave/keychain
///     encrypted_seed: Vec<u8>,
/// }
///
/// impl RingKeyProvider for SecureKeyProvider {
///     fn derive_device_x25519(
///         &self,
///         kid: &str,
///         device_id: &[u8],
///     ) -> Result<[u8; 32], NoiseError> {
///         // 1. Decrypt seed from secure storage
///         // 2. Derive key using HKDF with device_id as context
///         // 3. Apply X25519 clamping
///         // 4. Zero temporary buffers
///         // 5. Return derived key
///         # unimplemented!()
///     }
///     
///     fn ed25519_pubkey(&self, kid: &str) -> Result<[u8; 32], NoiseError> {
///         // 1. Decrypt seed
///         // 2. Derive Ed25519 keypair
///         // 3. Extract public key
///         // 4. Zero temporary buffers
///         # unimplemented!()
///     }
///     
///     fn sign_ed25519(&self, kid: &str, msg: &[u8]) -> Result<[u8; 64], NoiseError> {
///         // 1. Decrypt seed
///         // 2. Create signing key
///         // 3. Sign message
///         // 4. Zero signing key
///         # unimplemented!()
///     }
/// }
/// ```
///
/// # See Also
///
/// - [`RingKeyFiller`] - Companion trait that wraps keys in `Zeroizing`
/// - [`DummyRing`] - Testing implementation
/// - `PubkyRingProvider` - Production implementation using Pubky SDK (requires `pubky-sdk` feature)
pub trait RingKeyProvider: Send + Sync {
    /// Derive a device-specific X25519 secret key.
    ///
    /// This method derives an ephemeral X25519 secret key for Noise Protocol
    /// handshakes. The key is specific to the device ID, allowing
    /// per-device isolation.
    ///
    /// # Key Derivation
    ///
    /// The implementation should:
    /// 1. Use HKDF-SHA512 with domain separation salt
    /// 2. Bind to `device_id` in the HKDF info parameter
    /// 3. Apply X25519 scalar clamping per RFC 7748
    ///
    /// # Arguments
    ///
    /// * `kid` - Key identifier for looking up the root seed
    /// * `device_id` - Device identifier for key isolation
    ///
    /// # Returns
    ///
    /// Returns the derived X25519 secret key (32 bytes, clamped).
    ///
    /// # Security
    ///
    /// **Important**: The returned key will be wrapped in `Zeroizing` by
    /// `RingKeyFiller::with_device_x25519()`. Never store or log this key.
    fn derive_device_x25519(&self, kid: &str, device_id: &[u8]) -> Result<[u8; 32], NoiseError>;

    /// Get the Ed25519 public key for identity binding.
    ///
    /// Returns the Ed25519 public key corresponding to the root seed
    /// identified by `kid`. This public key is used in identity payloads
    /// to bind the long-term identity to ephemeral session keys.
    ///
    /// # Arguments
    ///
    /// * `kid` - Key identifier for looking up the Ed25519 keypair
    ///
    /// # Returns
    ///
    /// Returns the Ed25519 public key (32 bytes).
    ///
    /// # Note
    ///
    /// Unlike X25519 keys, Ed25519 public keys are not secret and can
    /// be freely shared.
    fn ed25519_pubkey(&self, kid: &str) -> Result<[u8; 32], NoiseError>;

    /// Sign a message with Ed25519 for identity binding.
    ///
    /// Creates a deterministic Ed25519 signature over the provided message
    /// using the secret key identified by `kid`. This is used to sign
    /// binding messages that authenticate the session.
    ///
    /// # Arguments
    ///
    /// * `kid` - Key identifier for the Ed25519 signing key
    /// * `msg` - Message to sign (typically a binding message hash)
    ///
    /// # Returns
    ///
    /// Returns the Ed25519 signature (64 bytes).
    ///
    /// # Security
    ///
    /// - Uses deterministic Ed25519 (RFC 8032) - no randomness required
    /// - Signing key should be zeroized immediately after signing
    /// - Signature is safe to transmit (does not reveal secret key)
    fn sign_ed25519(&self, kid: &str, msg: &[u8]) -> Result<[u8; 64], NoiseError>;
}

/// Extension trait that wraps X25519 keys in `Zeroizing` for automatic cleanup.
///
/// `RingKeyFiller` provides a higher-level interface over `RingKeyProvider`
/// that ensures derived secret keys are automatically zeroized when they go
/// out of scope. This prevents keys from lingering in memory.
///
/// # Security Pattern
///
/// The trait uses a closure-based API that:
/// 1. Derives the secret key
/// 2. Wraps it in `Zeroizing<[u8; 32]>`
/// 3. Passes it to a user closure
/// 4. Automatically zeros the memory when the closure returns
///
/// This pattern ensures keys never escape their intended scope and are
/// always cleaned up, even if the closure panics.
///
/// # Automatic Implementation
///
/// This trait is automatically implemented for all `RingKeyProvider`
/// implementations, so you never need to implement it manually.
///
/// # Examples
///
/// ```rust
/// use pubky_noise::{DummyRing, NoiseClient};
/// use pubky_noise::ring::{RingKeyProvider, RingKeyFiller};
/// use std::sync::Arc;
/// use zeroize::Zeroizing;
///
/// let ring = Arc::new(DummyRing::new([42u8; 32], "key-id"));
///
/// // Use the key within a closure - it's automatically zeroized after
/// let result = ring.with_device_x25519(
///     "key-id",
///     b"device-001",
///     |secret_key: &Zeroizing<[u8; 32]>| {
///         // Use secret_key here
///         // It will be zeroized when this closure returns
///         println!("Key length: {}", secret_key.len());
///         42 // Return any value
///     },
/// )?;
///
/// assert_eq!(result, 42);
/// // secret_key has been zeroized by this point
/// # Ok::<(), pubky_noise::NoiseError>(())
/// ```
pub trait RingKeyFiller: Send + Sync {
    /// Execute a closure with a zeroizing-wrapped X25519 secret key.
    ///
    /// This method derives an X25519 secret key, wraps it in `Zeroizing`
    /// to ensure automatic memory cleanup, and passes it to the provided
    /// closure. The key is automatically zeroized when the closure returns.
    ///
    /// # Arguments
    ///
    /// * `kid` - Key identifier
    /// * `device_id` - Device identifier
    /// * `f` - Closure that receives the zeroizing-wrapped key
    ///
    /// # Returns
    ///
    /// Returns the value produced by the closure.
    ///
    /// # Security
    ///
    /// - Key is automatically zeroized even if closure panics
    /// - Key never escapes the closure scope
    /// - Prevents accidental key storage or logging
    ///
    /// # Examples
    ///
    /// ```rust
    /// use pubky_noise::{DummyRing};
    /// use pubky_noise::ring::RingKeyFiller;
    /// use std::sync::Arc;
    ///
    /// let ring = Arc::new(DummyRing::new([42u8; 32], "key-id"));
    ///
    /// // Derive and use key in one operation
    /// ring.with_device_x25519("key-id", b"device", |sk| {
    ///     // sk is &Zeroizing<[u8; 32]>
    ///     // Use sk here, it will be zeroized automatically
    /// })?;
    /// # Ok::<(), pubky_noise::NoiseError>(())
    /// ```
    fn with_device_x25519<F, T>(&self, kid: &str, device_id: &[u8], f: F) -> Result<T, NoiseError>
    where
        F: FnOnce(&Zeroizing<[u8; 32]>) -> T;
}
impl<T: RingKeyProvider + ?Sized> RingKeyFiller for T {
    fn with_device_x25519<F, U>(&self, kid: &str, device_id: &[u8], f: F) -> Result<U, NoiseError>
    where
        F: FnOnce(&Zeroizing<[u8; 32]>) -> U,
    {
        let sk = self.derive_device_x25519(kid, device_id)?;
        let z = Zeroizing::new(sk);
        Ok(f(&z))
    }
}

/// Dummy key provider for testing and examples.
///
/// **⚠️ WARNING: NOT FOR PRODUCTION USE**
///
/// `DummyRing` is a simple implementation of `RingKeyProvider` intended only
/// for testing, examples, and development. It stores the seed directly in memory
/// without any protection.
///
/// # Production Alternative
///
/// For production use, implement a secure `RingKeyProvider` that:
/// - Stores seeds in secure enclaves (iOS Keychain, Android Keystore)
/// - Uses hardware-backed key storage when available
/// - Implements proper access controls
/// - Logs security events
///
/// Alternatively, use `PubkyRingProvider` (requires `pubky-sdk` feature).
///
/// # Examples
///
/// ```rust
/// use pubky_noise::DummyRing;
/// use pubky_noise::ring::RingKeyProvider;
///
/// // For testing only!
/// let seed = [42u8; 32]; // Use secure random in any real scenario
/// let ring = DummyRing::new(seed, "test-key-id");
///
/// // Derive keys
/// let x25519_key = ring.derive_device_x25519("test-key-id", b"device-001")?;
/// let ed25519_pub = ring.ed25519_pubkey("test-key-id")?;
/// # Ok::<(), pubky_noise::NoiseError>(())
/// ```
#[allow(dead_code)]
pub struct DummyRing {
    seed32: [u8; 32],
    kid: String,        // Stored for reference but not directly accessed
    device_id: Vec<u8>, // Stored for reference but not directly accessed
}
impl DummyRing {
    /// Create a new dummy ring with full device parameters.
    ///
    /// # Arguments
    ///
    /// * `seed32` - 32-byte seed for key derivation
    /// * `kid` - Key identifier
    /// * `device_id` - Device identifier
    ///
    /// # Examples
    ///
    /// ```rust
    /// use pubky_noise::DummyRing;
    ///
    /// let ring = DummyRing::new_with_device(
    ///     [42u8; 32],
    ///     "key-id",
    ///     b"device-001",
    /// );
    /// ```
    pub fn new_with_device(
        seed32: [u8; 32],
        kid: impl Into<String>,
        device_id: impl AsRef<[u8]>,
    ) -> Self {
        Self {
            seed32,
            kid: kid.into(),
            device_id: device_id.as_ref().to_vec(),
        }
    }
    /// Create a new dummy ring with minimal parameters.
    ///
    /// Uses default device ID ("default").
    ///
    /// # Arguments
    ///
    /// * `seed32` - 32-byte seed for key derivation
    /// * `kid` - Key identifier
    ///
    /// # Examples
    ///
    /// ```rust
    /// use pubky_noise::DummyRing;
    ///
    /// let ring = DummyRing::new([42u8; 32], "key-id");
    /// ```
    pub fn new(seed32: [u8; 32], kid: impl Into<String>) -> Self {
        Self {
            seed32,
            kid: kid.into(),
            device_id: b"default".to_vec(),
        }
    }
}
impl RingKeyProvider for DummyRing {
    fn derive_device_x25519(&self, _kid: &str, device_id: &[u8]) -> Result<[u8; 32], NoiseError> {
        let sk = crate::kdf::derive_x25519_static(&self.seed32, device_id);
        Ok(sk)
    }
    fn ed25519_pubkey(&self, _kid: &str) -> Result<[u8; 32], NoiseError> {
        let signing = SigningKey::from_bytes(&self.seed32);
        let vk: VerifyingKey = signing.verifying_key();
        Ok(vk.to_bytes())
    }
    fn sign_ed25519(&self, _kid: &str, msg: &[u8]) -> Result<[u8; 64], NoiseError> {
        let s = SigningKey::from_bytes(&self.seed32);
        Ok(s.sign(msg).to_bytes())
    }
}
