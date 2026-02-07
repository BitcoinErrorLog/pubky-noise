//! Error types for pubky-noise.
//!
//! ## Error Classification
//!
//! Errors are organized into subsystem ranges for FFI/mobile integration:
//!
//! | Range | Subsystem | Examples |
//! |-------|-----------|----------|
//! | 1000-1999 | Ring/key management | Key derivation failures |
//! | 2000-2999 | PKARR | DHT/DNS lookup failures |
//! | 3000-3999 | Snow protocol | Handshake failures, decrypt errors |
//! | 4000-4999 | Serialization | JSON/CBOR parse errors |
//! | 5000-5999 | Identity | Signature verification, missing keys |
//! | 6000-6999 | Policy | Rate limits, session limits |
//! | 7000-7999 | Cryptographic | Invalid keys, low-order points |
//! | 8000-8999 | Network | Timeouts, connection resets |
//! | 9000-9999 | Storage | File I/O, database errors |
//! | 10000+ | Other | Decryption failures, misc |
//!
//! ## Error Handling Guidelines
//!
//! - Use `is_retryable()` to check if an error is transient
//! - Use `retry_after_ms()` to get suggested retry delay
//! - Use `code()` to get FFI-compatible error code
//!
//! ## User-Facing Errors
//!
//! Not all errors should be shown to users. Use `is_user_facing()` to determine
//! if an error message is appropriate for UI display.

use thiserror::Error;

/// Common result type for Noise operations.
pub type NoiseResult<T> = Result<T, NoiseError>;

/// Error codes for FFI/mobile integration.
///
/// These codes are organized into subsystem ranges:
/// - 1000-1999: Ring/key management
/// - 2000-2999: PKARR
/// - 3000-3999: Snow protocol
/// - 4000-4999: Serialization
/// - 5000-5999: Identity
/// - 6000-6999: Policy
/// - 7000-7999: Cryptographic
/// - 8000-8999: Network
/// - 9000-9999: Storage
/// - 10000+: Other
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum NoiseErrorCode {
    /// Ring/key management error (1000)
    Ring = 1000,
    /// PKARR error (2000)
    Pkarr = 2000,
    /// Snow protocol error (3000)
    Snow = 3000,
    /// Serialization error (4000)
    Serde = 4000,
    /// Identity verification failed (5000)
    IdentityVerify = 5000,
    /// Remote static not available (5001)
    RemoteStaticMissing = 5001,
    /// Policy violation (6000)
    Policy = 6000,
    /// Rate limited (6001)
    RateLimited = 6001,
    /// Maximum sessions exceeded (6002)
    MaxSessionsExceeded = 6002,
    /// Session expired or not found (6003)
    SessionExpired = 6003,
    /// Invalid peer key (low-order point or all-zeros DH result) (7000)
    InvalidPeerKey = 7000,
    /// Network error (8000)
    Network = 8000,
    /// Timeout error (8001)
    Timeout = 8001,
    /// Connection reset (8002)
    ConnectionReset = 8002,
    /// Storage error (9000)
    Storage = 9000,
    /// Decryption error (10000)
    Decryption = 10000,
    /// Other/unknown error (99999)
    Other = 99999,
}

#[derive(Debug, Error)]
pub enum NoiseError {
    #[error("ring error: {0}")]
    Ring(String),

    #[error("pkarr error: {0}")]
    Pkarr(String),

    #[error("snow error: {0}")]
    Snow(String),

    #[error("serialization error: {0}")]
    Serde(String),

    #[error("identity verification failed")]
    IdentityVerify,

    #[error("remote static not available")]
    RemoteStaticMissing,

    #[error("policy violation: {0}")]
    Policy(String),

    #[error("rate limited: {message}")]
    RateLimited {
        message: String,
        /// Optional retry delay in milliseconds.
        /// When present, the client should wait at least this long before retrying.
        retry_after_ms: Option<u64>,
    },

    #[error("maximum sessions exceeded for this identity")]
    MaxSessionsExceeded,

    #[error("session expired or not found: {0}")]
    SessionExpired(String),

    /// Invalid peer key or shared secret.
    ///
    /// This occurs when:
    /// - The peer's X25519 public key is a low-order point
    /// - The ECDH result is all-zeros (indicates attacker-controlled key)
    /// - The peer's key fails validation
    ///
    /// This error is NOT retryable - the peer must use a different key.
    #[error("invalid peer static or shared secret")]
    InvalidPeerKey,

    #[error("network error: {0}")]
    Network(String),

    #[error("timeout: {0}")]
    Timeout(String),

    #[error("connection reset: {0}")]
    ConnectionReset(String),

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
            Self::RateLimited { .. } => NoiseErrorCode::RateLimited,
            Self::MaxSessionsExceeded => NoiseErrorCode::MaxSessionsExceeded,
            Self::SessionExpired(_) => NoiseErrorCode::SessionExpired,
            Self::InvalidPeerKey => NoiseErrorCode::InvalidPeerKey,
            Self::Network(_) => NoiseErrorCode::Network,
            Self::Timeout(_) => NoiseErrorCode::Timeout,
            Self::ConnectionReset(_) => NoiseErrorCode::ConnectionReset,
            Self::Storage(_) => NoiseErrorCode::Storage,
            Self::Decryption(_) => NoiseErrorCode::Decryption,
            Self::Other(_) => NoiseErrorCode::Other,
        }
    }

    /// Get the error message as an owned String (useful for FFI)
    pub fn message(&self) -> String {
        self.to_string()
    }

    /// Returns true if this error is potentially recoverable by retrying.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Network(_)
                | Self::Timeout(_)
                | Self::ConnectionReset(_)
                | Self::RateLimited { .. }
                | Self::Storage(_)
        )
    }

    /// Returns a suggested retry delay in milliseconds, if applicable.
    pub fn retry_after_ms(&self) -> Option<u64> {
        match self {
            Self::RateLimited { retry_after_ms, .. } => *retry_after_ms,
            Self::Network(_) | Self::Timeout(_) | Self::ConnectionReset(_) => Some(1000),
            Self::Storage(_) => Some(500),
            _ => None,
        }
    }

    /// Returns true if this error is appropriate for user-facing UI.
    ///
    /// Some errors (like internal serialization failures) should be logged
    /// but not displayed to users. This method helps distinguish between
    /// user-actionable errors and internal errors.
    pub fn is_user_facing(&self) -> bool {
        matches!(
            self,
            Self::Network(_)
                | Self::Timeout(_)
                | Self::RateLimited { .. }
                | Self::IdentityVerify
                | Self::SessionExpired(_)
        )
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

impl From<pubky_crypto::CryptoError> for NoiseError {
    fn from(e: pubky_crypto::CryptoError) -> Self {
        match e {
            pubky_crypto::CryptoError::KeyDerivation(msg) => Self::Ring(msg),
            pubky_crypto::CryptoError::Serde(msg) => Self::Serde(msg),
            pubky_crypto::CryptoError::InvalidPeerKey => Self::InvalidPeerKey,
            pubky_crypto::CryptoError::Decryption(msg) => Self::Decryption(msg),
            pubky_crypto::CryptoError::InvalidSignature => {
                Self::Other("invalid signature".to_string())
            }
            pubky_crypto::CryptoError::Other(msg) => Self::Other(msg),
        }
    }
}
