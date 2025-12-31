//! Session identifier type for Noise protocol sessions.

use crate::errors::NoiseError;
use std::fmt;
use std::str::FromStr;

/// A unique identifier for a Noise session, derived from the handshake hash.
///
/// The SessionId is a 32-byte value that uniquely identifies a completed
/// handshake. It can be serialized to/from hex strings for storage and
/// transmission.
///
/// ## Parsing from hex strings
///
/// ```rust
/// use pubky_noise::SessionId;
/// use std::str::FromStr;
///
/// let hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
/// let session_id = SessionId::from_str(hex).unwrap();
/// assert_eq!(session_id.to_string(), hex);
/// ```
#[cfg_attr(
    feature = "storage-queue",
    derive(serde::Serialize, serde::Deserialize)
)]
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SessionId(pub [u8; 32]);

impl SessionId {
    pub fn from_handshake(hs: &snow::HandshakeState) -> Result<Self, NoiseError> {
        // Use handshake hash as session ID (available in Snow 0.9)
        // This is cryptographically unique per handshake
        let hash = hs.get_handshake_hash();
        let mut out = [0u8; 32];
        out.copy_from_slice(hash);
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

impl FromStr for SessionId {
    type Err = NoiseError;

    /// Parse a SessionId from a 64-character hex string.
    ///
    /// # Errors
    ///
    /// Returns `NoiseError::Other` if the string is not valid hex or not 64 characters.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s).map_err(|e| NoiseError::Other(format!("Invalid hex: {}", e)))?;
        if bytes.len() != 32 {
            return Err(NoiseError::Other(format!(
                "SessionId must be 32 bytes (64 hex chars), got {} bytes",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}
