use crate::errors::NoiseError;
use std::fmt;

#[cfg_attr(feature = "storage-queue", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SessionId(pub [u8; 32]);

impl SessionId {
    pub fn from_handshake(hs: &snow::HandshakeState) -> Result<Self, NoiseError> {
        let mut out = [0u8; 32];
        hs.export_keying_material(b"pubky-session-id:v1", &mut out)
            .map_err(|e| NoiseError::Snow(e.to_string()))?;
        Ok(Self(out))
    }

    /// Convert SessionId to bytes for serialization
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Create SessionId from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Convert SessionId to a byte vector
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SessionId({})", self)
    }
}

