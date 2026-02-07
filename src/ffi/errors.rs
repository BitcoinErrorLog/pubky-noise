use crate::NoiseError;

/// FFI-exported error type for noise operations.
///
/// Note: Field names use `msg` instead of `message` to avoid conflicts with
/// Kotlin's `Exception.message` property in generated bindings.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiNoiseError {
    #[error("Ring error: {msg}")]
    Ring { msg: String },

    #[error("Pkarr error: {msg}")]
    Pkarr { msg: String },

    #[error("Snow error: {msg}")]
    Snow { msg: String },

    #[error("Serialization error: {msg}")]
    Serde { msg: String },

    #[error("Identity verification failed")]
    IdentityVerify,

    #[error("Remote static not available")]
    RemoteStaticMissing,

    #[error("Policy violation: {msg}")]
    Policy { msg: String },

    #[error("Invalid peer static or shared secret")]
    InvalidPeerKey,

    #[error("Network error: {msg}")]
    Network { msg: String },

    #[error("Timeout error: {msg}")]
    Timeout { msg: String },

    #[error("Storage error: {msg}")]
    Storage { msg: String },

    #[error("Decryption error: {msg}")]
    Decryption { msg: String },

    #[error("Rate limited: {msg}")]
    RateLimited {
        msg: String,
        /// Optional retry delay in milliseconds.
        retry_after_ms: Option<u64>,
    },

    #[error("Maximum sessions exceeded")]
    MaxSessionsExceeded,

    #[error("Session expired: {msg}")]
    SessionExpired { msg: String },

    #[error("Connection reset: {msg}")]
    ConnectionReset { msg: String },

    #[error("Other error: {msg}")]
    Other { msg: String },
}

impl From<pubky_crypto::CryptoError> for FfiNoiseError {
    fn from(err: pubky_crypto::CryptoError) -> Self {
        FfiNoiseError::from(NoiseError::from(err))
    }
}

impl From<NoiseError> for FfiNoiseError {
    fn from(err: NoiseError) -> Self {
        match err {
            NoiseError::Ring(m) => FfiNoiseError::Ring { msg: m },
            NoiseError::Pkarr(m) => FfiNoiseError::Pkarr { msg: m },
            NoiseError::Snow(m) => FfiNoiseError::Snow { msg: m },
            NoiseError::Serde(m) => FfiNoiseError::Serde { msg: m },
            NoiseError::IdentityVerify => FfiNoiseError::IdentityVerify,
            NoiseError::RemoteStaticMissing => FfiNoiseError::RemoteStaticMissing,
            NoiseError::Policy(m) => FfiNoiseError::Policy { msg: m },
            NoiseError::InvalidPeerKey => FfiNoiseError::InvalidPeerKey,
            NoiseError::Network(m) => FfiNoiseError::Network { msg: m },
            NoiseError::Timeout(m) => FfiNoiseError::Timeout { msg: m },
            NoiseError::Storage(m) => FfiNoiseError::Storage { msg: m },
            NoiseError::Decryption(m) => FfiNoiseError::Decryption { msg: m },
            NoiseError::RateLimited {
                message,
                retry_after_ms,
            } => FfiNoiseError::RateLimited {
                msg: message,
                retry_after_ms,
            },
            NoiseError::MaxSessionsExceeded => FfiNoiseError::MaxSessionsExceeded,
            NoiseError::SessionExpired(m) => FfiNoiseError::SessionExpired { msg: m },
            NoiseError::ConnectionReset(m) => FfiNoiseError::ConnectionReset { msg: m },
            NoiseError::Other(m) => FfiNoiseError::Other { msg: m },
        }
    }
}
