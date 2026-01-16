//! Streaming wrapper for Noise protocol transport.
//!
//! This module provides a streaming interface for sending large data over
//! a Noise-encrypted channel by chunking the plaintext and encrypting each
//! chunk separately.
//!
//! ## Usage
//!
//! `StreamingNoiseLink` wraps a `NoiseLink` and provides chunk-based
//! encryption/decryption:
//!
//! - Use `encrypt_streaming()` to encrypt large plaintext into multiple chunks
//! - Use `decrypt_streaming()` to decrypt chunks back to plaintext
//! - Default chunk size is 64 KiB
//!
//! ## Relationship to mobile_manager
//!
//! This module provides low-level streaming primitives. For mobile applications,
//! use `NoiseManager` instead (in `mobile_manager.rs`), which provides higher-level
//! connection management with state tracking. Note: auto-reconnection is not
//! provided; applications must handle connection lifecycle explicitly.

use crate::datalink_adapter::NoiseLink;
use crate::errors::NoiseError;

/// Streaming wrapper for NoiseLink that handles chunking large messages.
///
/// Encrypts/decrypts data in configurable chunk sizes for efficient
/// transmission of large payloads over Noise-encrypted channels.
pub struct StreamingNoiseLink {
    inner: NoiseLink,
    chunk_size: usize,
}

impl StreamingNoiseLink {
    pub fn new(link: NoiseLink, chunk_size: usize) -> Self {
        Self {
            inner: link,
            chunk_size,
        }
    }

    pub fn new_with_default_chunk_size(link: NoiseLink) -> Self {
        Self::new(link, 65536)
    }

    pub fn encrypt_streaming(&mut self, plaintext: &[u8]) -> Result<Vec<Vec<u8>>, NoiseError> {
        let mut chunks = Vec::new();
        for chunk in plaintext.chunks(self.chunk_size) {
            chunks.push(self.inner.encrypt(chunk)?);
        }
        Ok(chunks)
    }

    pub fn decrypt_streaming(&mut self, chunks: &[Vec<u8>]) -> Result<Vec<u8>, NoiseError> {
        let mut plaintext = Vec::new();
        for chunk in chunks {
            plaintext.extend(self.inner.decrypt(chunk)?);
        }
        Ok(plaintext)
    }

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

    pub fn decrypt_chunk(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        self.inner.decrypt(ciphertext)
    }

    pub fn inner(&self) -> &NoiseLink {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut NoiseLink {
        &mut self.inner
    }
}
