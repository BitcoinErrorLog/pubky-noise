use thiserror::Error;

/// Error codes for FFI/mobile integration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum NoiseErrorCode {
    /// Ring/key management error
    Ring = 1000,
    /// PKARR error
    Pkarr = 2000,
    /// Snow protocol error
    Snow = 3000,
    /// Serialization error
    Serde = 4000,
    /// Identity verification failed
    IdentityVerify = 5000,
    /// Remote static not available
    RemoteStaticMissing = 5001,
    /// Policy violation
    Policy = 6000,
    /// Invalid peer key
    InvalidPeerKey = 7000,
    /// Network error
    Network = 8000,
    /// Timeout error
    Timeout = 8001,
    /// Storage error
    Storage = 9000,
    /// Decryption error
    Decryption = 10000,
    /// Other/unknown error
    Other = 99999,
}

/// Error type for all pubky-noise operations.
///
/// `NoiseError` provides comprehensive error information for all failure modes
/// in the library, from key management to network operations. Each variant
/// includes contextual information to aid debugging.
///
/// # Error Categories
///
/// ## Cryptographic Errors
/// - [`Ring`](Self::Ring) - Key derivation or management failures
/// - [`IdentityVerify`](Self::IdentityVerify) - Ed25519 signature verification failed
/// - [`InvalidPeerKey`](Self::InvalidPeerKey) - Weak or invalid peer keys
/// - [`Decryption`](Self::Decryption) - AEAD decryption failures
///
/// ## Protocol Errors
/// - [`Snow`](Self::Snow) - Noise protocol violations
/// - [`Pkarr`](Self::Pkarr) - PKARR metadata issues
/// - [`RemoteStaticMissing`](Self::RemoteStaticMissing) - Missing required keys
///
/// ## Network Errors
/// - [`Network`](Self::Network) - Network communication failures
/// - [`Timeout`](Self::Timeout) - Operation timeouts
/// - [`Storage`](Self::Storage) - Storage backend issues
///
/// ## Application Errors
/// - [`Serde`](Self::Serde) - Serialization/deserialization failures
/// - [`Policy`](Self::Policy) - Server policy violations
/// - [`Other`](Self::Other) - Miscellaneous errors
///
/// # FFI Integration
///
/// Each error variant maps to a unique integer error code (see [`NoiseErrorCode`])
/// for use across language boundaries. Access the code via [`code()`](Self::code)
/// and message via [`message()`](Self::message).
///
/// # Examples
///
/// ```rust
/// use pubky_noise::{NoiseError, NoiseErrorCode};
///
/// let error = NoiseError::IdentityVerify;
///
/// // Get error code for FFI
/// assert_eq!(error.code() as i32, 5000);
///
/// // Get human-readable message
/// let msg = error.message();
/// assert!(msg.contains("verification"));
/// ```
///
/// ## Error Handling Patterns
///
/// ```rust,no_run
/// use pubky_noise::{NoiseClient, NoiseError, DummyRing};
/// use std::sync::Arc;
///
/// fn handle_connection() -> Result<(), NoiseError> {
///     let ring = Arc::new(DummyRing::new([0u8; 32], "key-id"));
///     let client = NoiseClient::new_direct("key-id", b"device", ring);
///     
///     match client.build_initiator_ik_direct(&[0u8; 32], 0, None) {
///         Ok((hs, msg, epoch)) => {
///             // Success - proceed with handshake
///             Ok(())
///         }
///         Err(NoiseError::InvalidPeerKey) => {
///             // Specific handling for weak keys
///             eprintln!("Server key is invalid or weak");
///             Err(NoiseError::InvalidPeerKey)
///         }
///         Err(NoiseError::Ring(msg)) => {
///             // Key management issue
///             eprintln!("Key error: {}", msg);
///             Err(NoiseError::Ring(msg))
///         }
///         Err(e) => {
///             // Generic error handling
///             eprintln!("Connection failed: {}", e);
///             Err(e)
///         }
///     }
/// }
/// ```
#[derive(Debug, Error)]
pub enum NoiseError {
    /// Key management or derivation error.
    ///
    /// Indicates that the key provider (`RingKeyProvider`) failed to derive
    /// or access cryptographic keys. This can occur due to:
    /// - Missing or corrupted key material
    /// - Secure enclave access denial
    /// - Key derivation failures
    /// - Invalid key identifiers
    ///
    /// **Recovery**: Check key storage, verify key IDs, ensure secure storage
    /// permissions are granted.
    #[error("ring error: {0}")]
    Ring(String),

    /// PKARR protocol or metadata error.
    ///
    /// Indicates issues with PKARR out-of-band metadata operations:
    /// - Failed to fetch PKARR records
    /// - Invalid PKARR record format
    /// - Signature verification failure on PKARR data
    /// - DNS resolution issues
    ///
    /// **Note**: Only occurs when `pkarr` feature is enabled.
    ///
    /// **Recovery**: Verify PKARR resolver configuration, check network
    /// connectivity, validate PKARR record format.
    #[error("pkarr error: {0}")]
    Pkarr(String),

    /// Noise Protocol error from the underlying `snow` library.
    ///
    /// Indicates Noise Protocol Framework violations:
    /// - Invalid handshake message format
    /// - Wrong pattern or cipher suite
    /// - Handshake state machine violations
    /// - Message authentication failures
    /// - Prologue mismatches
    ///
    /// **Recovery**: Usually indicates protocol incompatibility or corrupted
    /// messages. Verify both sides use compatible versions and parameters.
    #[error("snow error: {0}")]
    Snow(String),

    /// Serialization or deserialization error.
    ///
    /// Indicates JSON or binary serialization failures:
    /// - Invalid identity payload format
    /// - Corrupted session state
    /// - Incompatible data versions
    ///
    /// **Recovery**: Check data format compatibility, verify no data corruption.
    #[error("serialization error: {0}")]
    Serde(String),

    /// Ed25519 identity signature verification failed.
    ///
    /// The client's Ed25519 signature over the identity binding message
    /// did not verify. This indicates:
    /// - Wrong signing key used by client
    /// - Tampered identity payload
    /// - Man-in-the-middle attack attempt
    /// - Protocol version mismatch
    ///
    /// **Security**: This is a **critical security error**. The connection
    /// should be rejected immediately.
    ///
    /// **Recovery**: None - reject the connection. Verify client is using
    /// correct keys and protocol version.
    #[error("identity verification failed")]
    IdentityVerify,

    /// Remote static public key not available when required.
    ///
    /// The handshake requires the peer's static public key but it's not
    /// available. This can occur:
    /// - IK pattern used without known server key
    /// - Handshake state accessed incorrectly
    /// - Pattern mismatch between client and server
    ///
    /// **Recovery**: For IK, ensure server key is pinned. For first contact,
    /// use XX pattern instead.
    #[error("remote static not available")]
    RemoteStaticMissing,

    /// Server policy violation.
    ///
    /// The connection was rejected due to policy constraints:
    /// - Too many connections from this IP
    /// - Too many sessions for this identity
    /// - Client epoch below minimum
    /// - Rate limiting triggered
    ///
    /// **Recovery**: Back off and retry later, or contact server administrator.
    #[error("policy violation: {0}")]
    Policy(String),

    /// Invalid or weak peer public key.
    ///
    /// The peer's X25519 static key would result in an all-zero shared secret,
    /// indicating:
    /// - Low-order point attack attempt
    /// - Invalid key generation by peer
    /// - Corrupted key material
    ///
    /// **Security**: This is a **critical security error**. The library
    /// automatically rejects such keys to prevent weak DH attacks.
    ///
    /// **Recovery**: None - reject the connection. The peer needs to generate
    /// valid keys.
    #[error("invalid peer static or shared secret")]
    InvalidPeerKey,

    #[error("network error: {0}")]
    Network(String),

    #[error("timeout: {0}")]
    Timeout(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("decryption error: {0}")]
    Decryption(String),

    #[error("other: {0}")]
    Other(String),
}

impl NoiseError {
    /// Get the error code for FFI/mobile integration
    pub fn code(&self) -> NoiseErrorCode {
        match self {
            Self::Ring(_) => NoiseErrorCode::Ring,
            Self::Pkarr(_) => NoiseErrorCode::Pkarr,
            Self::Snow(_) => NoiseErrorCode::Snow,
            Self::Serde(_) => NoiseErrorCode::Serde,
            Self::IdentityVerify => NoiseErrorCode::IdentityVerify,
            Self::RemoteStaticMissing => NoiseErrorCode::RemoteStaticMissing,
            Self::Policy(_) => NoiseErrorCode::Policy,
            Self::InvalidPeerKey => NoiseErrorCode::InvalidPeerKey,
            Self::Network(_) => NoiseErrorCode::Network,
            Self::Timeout(_) => NoiseErrorCode::Timeout,
            Self::Storage(_) => NoiseErrorCode::Storage,
            Self::Decryption(_) => NoiseErrorCode::Decryption,
            Self::Other(_) => NoiseErrorCode::Other,
        }
    }

    /// Get the error message as an owned String (useful for FFI)
    pub fn message(&self) -> String {
        self.to_string()
    }
}

impl From<snow::Error> for NoiseError {
    fn from(e: snow::Error) -> Self {
        Self::Snow(e.to_string())
    }
}

impl From<serde_json::Error> for NoiseError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serde(e.to_string())
    }
}
