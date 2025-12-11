use thiserror::Error;

/// Common result type for Noise operations.
pub type NoiseResult<T> = Result<T, NoiseError>;

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
    /// Rate limited
    RateLimited = 6001,
    /// Maximum sessions exceeded
    MaxSessionsExceeded = 6002,
    /// Session expired or not found
    SessionExpired = 6003,
    /// Invalid peer key
    InvalidPeerKey = 7000,
    /// Network error
    Network = 8000,
    /// Timeout error
    Timeout = 8001,
    /// Connection reset
    ConnectionReset = 8002,
    /// Storage error
    Storage = 9000,
    /// Decryption error
    Decryption = 10000,
    /// Other/unknown error
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

    #[error("rate limited: {0}")]
    RateLimited(String),

    #[error("maximum sessions exceeded for this identity")]
    MaxSessionsExceeded,

    #[error("session expired or not found: {0}")]
    SessionExpired(String),

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
            Self::RateLimited(_) => NoiseErrorCode::RateLimited,
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
                | Self::RateLimited(_)
                | Self::Storage(_)
        )
    }

    /// Returns a suggested retry delay in milliseconds, if applicable.
    pub fn retry_after_ms(&self) -> Option<u64> {
        match self {
            Self::RateLimited(msg) => {
                // Try to parse retry-after from message if encoded
                msg.parse().ok()
            }
            Self::Network(_) | Self::Timeout(_) | Self::ConnectionReset(_) => Some(1000),
            Self::Storage(_) => Some(500),
            _ => None,
        }
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
