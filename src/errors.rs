use thiserror::Error;

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
    #[error("other: {0}")]
    Other(String),
}

impl From<snow::Error> for NoiseError {
    fn from(e: snow::Error) -> Self { Self::Snow(e.to_string()) }
}
impl From<serde_json::Error> for NoiseError {
    fn from(e: serde_json::Error) -> Self { Self::Serde(e.to_string()) }
}
