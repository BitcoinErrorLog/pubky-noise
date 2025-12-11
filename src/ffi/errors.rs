use crate::NoiseError;

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiNoiseError {
    #[error("Ring error: {message}")]
    Ring { message: String },

    #[error("Pkarr error: {message}")]
    Pkarr { message: String },

    #[error("Snow error: {message}")]
    Snow { message: String },

    #[error("Serialization error: {message}")]
    Serde { message: String },

    #[error("Identity verification failed")]
    IdentityVerify,

    #[error("Remote static not available")]
    RemoteStaticMissing,

    #[error("Policy violation: {message}")]
    Policy { message: String },

    #[error("Invalid peer static or shared secret")]
    InvalidPeerKey,

    #[error("Network error: {message}")]
    Network { message: String },

    #[error("Timeout error: {message}")]
    Timeout { message: String },

    #[error("Storage error: {message}")]
    Storage { message: String },

    #[error("Decryption error: {message}")]
    Decryption { message: String },

    #[error("Rate limited: {message}")]
    RateLimited { message: String },

    #[error("Maximum sessions exceeded")]
    MaxSessionsExceeded,

    #[error("Session expired: {message}")]
    SessionExpired { message: String },

    #[error("Connection reset: {message}")]
    ConnectionReset { message: String },

    #[error("Other error: {message}")]
    Other { message: String },
}

impl From<NoiseError> for FfiNoiseError {
    fn from(err: NoiseError) -> Self {
        match err {
            NoiseError::Ring(msg) => FfiNoiseError::Ring { message: msg },
            NoiseError::Pkarr(msg) => FfiNoiseError::Pkarr { message: msg },
            NoiseError::Snow(msg) => FfiNoiseError::Snow { message: msg },
            NoiseError::Serde(msg) => FfiNoiseError::Serde { message: msg },
            NoiseError::IdentityVerify => FfiNoiseError::IdentityVerify,
            NoiseError::RemoteStaticMissing => FfiNoiseError::RemoteStaticMissing,
            NoiseError::Policy(msg) => FfiNoiseError::Policy { message: msg },
            NoiseError::InvalidPeerKey => FfiNoiseError::InvalidPeerKey,
            NoiseError::Network(msg) => FfiNoiseError::Network { message: msg },
            NoiseError::Timeout(msg) => FfiNoiseError::Timeout { message: msg },
            NoiseError::Storage(msg) => FfiNoiseError::Storage { message: msg },
            NoiseError::Decryption(msg) => FfiNoiseError::Decryption { message: msg },
            NoiseError::RateLimited(msg) => FfiNoiseError::RateLimited { message: msg },
            NoiseError::MaxSessionsExceeded => FfiNoiseError::MaxSessionsExceeded,
            NoiseError::SessionExpired(msg) => FfiNoiseError::SessionExpired { message: msg },
            NoiseError::ConnectionReset(msg) => FfiNoiseError::ConnectionReset { message: msg },
            NoiseError::Other(msg) => FfiNoiseError::Other { message: msg },
        }
    }
}
