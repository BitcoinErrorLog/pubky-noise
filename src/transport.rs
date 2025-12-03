//! Noise transport session for encrypted communication.
//!
//! This module provides `NoiseSession`, the transport-mode wrapper around
//! Snow's `TransportState` for encrypting/decrypting messages after a
//! Noise handshake completes.

use crate::errors::NoiseError;
use crate::session_id::SessionId;

/// A completed Noise session for encrypting/decrypting messages.
///
/// `NoiseSession` wraps Snow's `TransportState` and provides a simplified
/// API for message encryption and decryption. Create one by calling
/// `from_handshake()` after completing a Noise handshake.
///
/// # Thread Safety
///
/// `NoiseSession` is **not** thread-safe. The underlying Snow transport
/// maintains internal counters that would be corrupted by concurrent access.
/// Use `Arc<Mutex<NoiseSession>>` if you need to share across threads.
///
/// # Example
///
/// ```no_run
/// use pubky_noise::NoiseSession;
///
/// # fn example(hs: snow::HandshakeState) -> Result<(), pubky_noise::NoiseError> {
/// // After completing handshake
/// let mut session = NoiseSession::from_handshake(hs)?;
///
/// // Encrypt a message
/// let plaintext = b"Hello, world!";
/// let ciphertext = session.write(plaintext)?;
///
/// // Decrypt a message
/// // let received = session.read(&incoming_ciphertext)?;
/// # Ok(())
/// # }
/// ```
pub struct NoiseSession {
    inner: snow::TransportState,
    session_id: SessionId,
}

impl NoiseSession {
    /// Create a `NoiseSession` from a completed handshake.
    ///
    /// Transitions the handshake state into transport mode and extracts
    /// the session ID from the handshake hash.
    ///
    /// # Errors
    ///
    /// Returns `Err(NoiseError)` if the handshake is not yet complete.
    pub fn from_handshake(hs: snow::HandshakeState) -> Result<Self, NoiseError> {
        let session_id = SessionId::from_handshake(&hs)?;
        Ok(Self {
            inner: hs.into_transport_mode()?,
            session_id,
        })
    }

    /// Get the session ID.
    ///
    /// The session ID is derived from the Noise handshake hash and uniquely
    /// identifies this session. Both peers will derive the same session ID.
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Encrypt a message.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The message to encrypt
    ///
    /// # Returns
    ///
    /// Returns the ciphertext (plaintext + 16 bytes AEAD tag + padding).
    pub fn write(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let mut out = vec![0u8; plaintext.len() + 64];
        let n = self.inner.write_message(plaintext, &mut out)?;
        out.truncate(n);
        Ok(out)
    }

    /// Decrypt a message.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The ciphertext to decrypt
    ///
    /// # Returns
    ///
    /// Returns the decrypted plaintext.
    ///
    /// # Errors
    ///
    /// Returns `Err(NoiseError)` if decryption fails (authentication tag invalid).
    pub fn read(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let mut out = vec![0u8; ciphertext.len() + 64];
        let n = self.inner.read_message(ciphertext, &mut out)?;
        out.truncate(n);
        Ok(out)
    }

    /// Encrypt a message (alias for `write`).
    ///
    /// This is an alias for `write()` that provides a more intuitive name.
    #[inline]
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        self.write(plaintext)
    }

    /// Decrypt a message (alias for `read`).
    ///
    /// This is an alias for `read()` that provides a more intuitive name.
    #[inline]
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        self.read(ciphertext)
    }

    /// Export a session tag from a handshake (before transition to transport mode).
    ///
    /// This is useful for deriving additional keys or identifiers from the
    /// handshake hash.
    pub fn export_session_tag(hs: &snow::HandshakeState) -> Result<[u8; 32], NoiseError> {
        let hash = hs.get_handshake_hash();
        let mut out = [0u8; 32];
        out.copy_from_slice(hash);
        Ok(out)
    }
}

/// Deprecated alias for `NoiseSession`.
///
/// Use `NoiseSession` instead. This alias exists for backward compatibility
/// and will be removed in a future release.
#[deprecated(since = "0.3.0", note = "Use NoiseSession instead")]
pub type NoiseTransport = NoiseSession;
