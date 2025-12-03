//! Streaming support for large message encryption.
//!
//! This module provides `StreamingNoiseSession` for encrypting large messages
//! that need to be split into chunks. It supports two modes:
//!
//! - **Legacy mode** (`encrypt_streaming`/`decrypt_streaming`): Returns/accepts
//!   separate chunks that the caller must frame for transport.
//!
//! - **Framed mode** (`encrypt_framed`/`decrypt_framed`): Handles length-prefix
//!   framing internally, producing/consuming a single byte stream.

use crate::errors::NoiseError;
use crate::transport::NoiseSession;

/// Streaming wrapper for encrypting large messages in chunks.
///
/// `StreamingNoiseSession` wraps a `NoiseSession` and provides methods for
/// encrypting/decrypting messages larger than a single Noise frame.
///
/// # Chunk Size
///
/// The chunk size should be chosen based on:
/// - Network MTU (avoid IP fragmentation)
/// - Memory constraints (especially on mobile)
/// - Latency requirements (smaller = lower latency per chunk)
///
/// Default is 65536 bytes (64KB).
///
/// # Example
///
/// ```no_run
/// use pubky_noise::{StreamingNoiseSession, NoiseSession};
///
/// # fn example(session: NoiseSession) -> Result<(), pubky_noise::NoiseError> {
/// let mut stream = StreamingNoiseSession::new(session, 32768);
///
/// // Framed mode (recommended for transport)
/// let data = vec![0u8; 100_000]; // Large message
/// let framed = stream.encrypt_framed(&data)?;
/// // Send framed bytes over transport...
///
/// // Receive and decrypt
/// // let plaintext = stream.decrypt_framed(&received)?;
/// # Ok(())
/// # }
/// ```
pub struct StreamingNoiseSession {
    inner: NoiseSession,
    chunk_size: usize,
}

impl StreamingNoiseSession {
    /// Create a new `StreamingNoiseSession` with specified chunk size.
    pub fn new(session: NoiseSession, chunk_size: usize) -> Self {
        Self {
            inner: session,
            chunk_size,
        }
    }

    /// Create a new `StreamingNoiseSession` with default chunk size (64KB).
    pub fn new_with_default_chunk_size(session: NoiseSession) -> Self {
        Self::new(session, 65536)
    }

    /// Get the configured chunk size.
    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    // ========== FRAMED MODE (recommended) ==========

    /// Encrypt a message with length-prefix framing.
    ///
    /// This method splits the plaintext into chunks, encrypts each chunk,
    /// and prepends a 4-byte big-endian length prefix to each encrypted chunk.
    /// The result is a single contiguous byte stream ready for transport.
    ///
    /// # Format
    ///
    /// ```text
    /// [4-byte len1][encrypted_chunk1][4-byte len2][encrypted_chunk2]...
    /// ```
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The message to encrypt (any size)
    ///
    /// # Returns
    ///
    /// A framed byte stream containing all encrypted chunks with length prefixes.
    pub fn encrypt_framed(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let mut output = Vec::new();

        for chunk in plaintext.chunks(self.chunk_size) {
            let encrypted = self.inner.encrypt(chunk)?;

            // 4-byte big-endian length prefix
            let len = encrypted.len() as u32;
            output.extend_from_slice(&len.to_be_bytes());
            output.extend_from_slice(&encrypted);
        }

        Ok(output)
    }

    /// Decrypt a framed message.
    ///
    /// This method parses a framed byte stream (produced by `encrypt_framed`),
    /// extracts each length-prefixed chunk, decrypts it, and reassembles the
    /// original plaintext.
    ///
    /// # Arguments
    ///
    /// * `data` - Framed byte stream from `encrypt_framed`
    ///
    /// # Returns
    ///
    /// The decrypted plaintext.
    ///
    /// # Errors
    ///
    /// Returns `Err(NoiseError)` if:
    /// - The framing is invalid (truncated length prefix)
    /// - A chunk length exceeds available data
    /// - Decryption fails (authentication tag invalid)
    pub fn decrypt_framed(&mut self, data: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let mut plaintext = Vec::new();
        let mut offset = 0;

        while offset < data.len() {
            // Read 4-byte length prefix
            if offset + 4 > data.len() {
                return Err(NoiseError::Other(
                    "Framed data truncated: missing length prefix".to_string(),
                ));
            }
            let len = u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]) as usize;
            offset += 4;

            // Read encrypted chunk
            if offset + len > data.len() {
                return Err(NoiseError::Other(format!(
                    "Framed data truncated: expected {} bytes at offset {}, got {}",
                    len,
                    offset,
                    data.len() - offset
                )));
            }
            let chunk = &data[offset..offset + len];
            offset += len;

            // Decrypt chunk
            plaintext.extend(self.inner.decrypt(chunk)?);
        }

        Ok(plaintext)
    }

    // ========== LEGACY MODE (backward compatibility) ==========

    /// Encrypt a message into separate chunks (legacy mode).
    ///
    /// **Deprecated**: Use `encrypt_framed` for new code. This method returns
    /// separate chunks that the caller must frame for transport.
    #[deprecated(since = "0.3.0", note = "Use encrypt_framed for automatic framing")]
    pub fn encrypt_streaming(&mut self, plaintext: &[u8]) -> Result<Vec<Vec<u8>>, NoiseError> {
        let mut chunks = Vec::new();
        for chunk in plaintext.chunks(self.chunk_size) {
            chunks.push(self.inner.encrypt(chunk)?);
        }
        Ok(chunks)
    }

    /// Decrypt separate chunks (legacy mode).
    ///
    /// **Deprecated**: Use `decrypt_framed` for new code.
    #[deprecated(since = "0.3.0", note = "Use decrypt_framed for automatic framing")]
    pub fn decrypt_streaming(&mut self, chunks: &[Vec<u8>]) -> Result<Vec<u8>, NoiseError> {
        let mut plaintext = Vec::new();
        for chunk in chunks {
            plaintext.extend(self.inner.decrypt(chunk)?);
        }
        Ok(plaintext)
    }

    /// Encrypt a single chunk.
    pub fn encrypt_chunk(&mut self, chunk: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if chunk.len() > self.chunk_size {
            return Err(NoiseError::Other(format!(
                "Chunk size {} exceeds limit {}",
                chunk.len(),
                self.chunk_size
            )));
        }
        self.inner.encrypt(chunk)
    }

    /// Decrypt a single chunk.
    pub fn decrypt_chunk(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        self.inner.decrypt(ciphertext)
    }

    /// Get a reference to the inner `NoiseSession`.
    pub fn inner(&self) -> &NoiseSession {
        &self.inner
    }

    /// Get a mutable reference to the inner `NoiseSession`.
    pub fn inner_mut(&mut self) -> &mut NoiseSession {
        &mut self.inner
    }
}

/// Deprecated alias for `StreamingNoiseSession`.
#[deprecated(since = "0.8.0", note = "Use StreamingNoiseSession instead")]
pub type StreamingNoiseLink = StreamingNoiseSession;
