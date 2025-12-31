//! Async handshake exchange over Pubky storage.
//!
//! This module provides the [`HandshakeQueue`] type for performing Noise protocol
//! handshakes asynchronously via Pubky storage, enabling handshake exchange between
//! parties that are not online simultaneously.
//!
//! ## Use Case
//!
//! When direct TCP/WebSocket connections aren't possible (e.g., mobile apps in
//! background, offline-first scenarios), parties can exchange handshake messages
//! through Pubky storage:
//!
//! 1. Client writes handshake message 0 to storage
//! 2. Server polls, finds message, writes response (message 1)
//! 3. Client polls, finds response, writes final message (message 2) for XX pattern
//! 4. Both sides transition to [`StorageBackedMessaging`] for encrypted communication
//!
//! ## Path Structure
//!
//! Handshake messages are stored at:
//! - `/pub/noise/handshake/{session_id}/msg_{index}`
//!
//! Where `session_id` is a unique identifier for the handshake session (e.g.,
//! derived from the initiator's public key), and `index` is 0, 1, or 2.
//!
//! ## Security Considerations
//!
//! - Handshake messages are not encrypted; they contain Noise protocol data
//! - The storage layer should provide integrity (Pubky does via signatures)
//! - Implement expiration/cleanup for abandoned handshakes
//! - Consider rate limiting handshake initiation per identity

use crate::datalink_adapter::NoiseLink;
use crate::errors::NoiseError;
use crate::storage_queue::{RetryConfig, StorageBackedMessaging};
use pubky::{PubkySession, PublicStorage};
use std::time::Duration;

/// Maximum allowed handshake path length in characters.
const MAX_PATH_LENGTH: usize = 1024;

/// Async handshake exchange over Pubky storage (IK or XX patterns).
///
/// Enables Noise handshakes between parties that are not online simultaneously
/// by storing handshake messages in Pubky storage.
///
/// ## Example (Client-side XX handshake)
///
/// ```rust,ignore
/// // Step 1: Initiate handshake
/// let mut queue = HandshakeQueue::new(session, public, handshake_path)?;
/// let (hs, first_msg, _) = client.build_initiator_xx_tofu(None)?;
/// queue.send_handshake_msg(0, &first_msg).await?;
///
/// // Step 2: Wait for server response
/// let response = queue.await_handshake_msg(1, Duration::from_secs(60)).await?;
/// let (hs, final_msg, server_id, server_pk) = client.complete_initiator_xx(hs, &response, None)?;
/// queue.send_handshake_msg(2, &final_msg).await?;
///
/// // Step 3: Transition to encrypted messaging
/// let link = NoiseLink::new_from_hs(hs)?;
/// let messaging = queue.complete_to_messaging(link, write_path, read_path)?;
/// ```
pub struct HandshakeQueue {
    session: PubkySession,
    public_client: PublicStorage,
    handshake_path: String,
    retry_config: RetryConfig,
}

impl HandshakeQueue {
    fn normalize_base_path(mut path: String) -> String {
        while path.len() > 1 && path.ends_with('/') {
            path.pop();
        }
        path
    }

    /// Validate that a storage path is safe for use.
    fn validate_path(path: &str) -> Result<(), NoiseError> {
        if path.is_empty() {
            return Err(NoiseError::Storage("Path cannot be empty".to_string()));
        }
        if !path.starts_with('/') {
            return Err(NoiseError::Storage("Path must start with /".to_string()));
        }
        if path.len() > MAX_PATH_LENGTH {
            return Err(NoiseError::Storage(format!(
                "Path exceeds maximum length of {} characters",
                MAX_PATH_LENGTH
            )));
        }
        if path.contains("..") {
            return Err(NoiseError::Storage(
                "Path cannot contain .. sequences (path traversal)".to_string(),
            ));
        }
        if path.contains("//") {
            return Err(NoiseError::Storage(
                "Path cannot contain // sequences".to_string(),
            ));
        }

        // Check for invalid characters
        for c in path.chars() {
            if !c.is_alphanumeric() && !matches!(c, '/' | '-' | '_' | '.') {
                return Err(NoiseError::Storage(format!(
                    "Path contains invalid character: '{}'",
                    c
                )));
            }
        }

        Ok(())
    }

    /// Create a new HandshakeQueue.
    ///
    /// # Arguments
    ///
    /// * `session` - Authenticated Pubky session for writes
    /// * `public_client` - Public storage client for reads
    /// * `handshake_path` - Base path for handshake messages (e.g., `/pub/noise/handshake/{session_id}`)
    ///
    /// # Errors
    ///
    /// Returns `NoiseError::Storage` if the path is invalid.
    pub fn new(
        session: PubkySession,
        public_client: PublicStorage,
        handshake_path: String,
    ) -> Result<Self, NoiseError> {
        Self::validate_path(&handshake_path)?;

        Ok(Self {
            session,
            public_client,
            handshake_path: Self::normalize_base_path(handshake_path),
            retry_config: RetryConfig::default(),
        })
    }

    /// Configure retry behavior for network operations.
    pub fn with_retry_config(mut self, config: RetryConfig) -> Self {
        self.retry_config = config;
        self
    }

    /// Get the handshake path.
    pub fn handshake_path(&self) -> &str {
        &self.handshake_path
    }

    /// Send a handshake message to storage.
    ///
    /// # Arguments
    ///
    /// * `msg_index` - Message index (0 for initiator's first, 1 for responder's, 2 for initiator's final in XX)
    /// * `data` - Raw handshake message bytes
    ///
    /// # Errors
    ///
    /// Returns `NoiseError::Storage` on write failure, `NoiseError::Timeout` if operation times out.
    pub async fn send_handshake_msg(&self, msg_index: u8, data: &[u8]) -> Result<(), NoiseError> {
        let path = format!("{}/msg_{}", self.handshake_path, msg_index);

        let mut attempt = 0;
        let mut backoff_ms = self.retry_config.initial_backoff_ms;

        #[cfg(not(target_arch = "wasm32"))]
        let timeout_duration = Duration::from_millis(self.retry_config.operation_timeout_ms);

        loop {
            #[cfg(not(target_arch = "wasm32"))]
            let result = tokio::time::timeout(
                timeout_duration,
                self.session.storage().put(&path, data.to_vec()),
            )
            .await;

            #[cfg(target_arch = "wasm32")]
            let result = Ok(self.session.storage().put(&path, data.to_vec()).await);

            match result {
                #[cfg(not(target_arch = "wasm32"))]
                Err(_elapsed) => {
                    attempt += 1;
                    if attempt >= self.retry_config.max_retries {
                        return Err(NoiseError::Timeout(format!(
                            "Handshake send timed out after {}ms ({} attempts)",
                            self.retry_config.operation_timeout_ms, attempt
                        )));
                    }
                }
                Ok(Ok(_)) => return Ok(()),
                Ok(Err(e)) => {
                    attempt += 1;
                    if attempt >= self.retry_config.max_retries {
                        return Err(NoiseError::Storage(format!(
                            "Failed to send handshake message after {} attempts: {:?}",
                            attempt, e
                        )));
                    }
                }
            }

            #[cfg(not(target_arch = "wasm32"))]
            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;

            backoff_ms = (backoff_ms * 2).min(self.retry_config.max_backoff_ms);
        }
    }

    /// Poll for a handshake message (non-blocking).
    ///
    /// # Arguments
    ///
    /// * `msg_index` - Message index to poll for
    ///
    /// # Returns
    ///
    /// `Ok(Some(data))` if message exists, `Ok(None)` if not found yet.
    ///
    /// # Errors
    ///
    /// Returns `NoiseError::Network` on read failure.
    pub async fn poll_handshake_msg(&self, msg_index: u8) -> Result<Option<Vec<u8>>, NoiseError> {
        let path = format!("{}/msg_{}", self.handshake_path, msg_index);

        #[cfg(not(target_arch = "wasm32"))]
        let timeout_duration = Duration::from_millis(self.retry_config.operation_timeout_ms);

        #[cfg(not(target_arch = "wasm32"))]
        let result = tokio::time::timeout(timeout_duration, self.public_client.get(&path)).await;

        #[cfg(target_arch = "wasm32")]
        let result = Ok(self.public_client.get(&path).await);

        match result {
            #[cfg(not(target_arch = "wasm32"))]
            Err(_elapsed) => Err(NoiseError::Timeout(format!(
                "Handshake poll timed out after {}ms",
                self.retry_config.operation_timeout_ms
            ))),
            Ok(Ok(response)) => {
                if response.status().is_success() {
                    #[cfg(not(target_arch = "wasm32"))]
                    let bytes_result =
                        tokio::time::timeout(timeout_duration, response.bytes()).await;

                    #[cfg(target_arch = "wasm32")]
                    let bytes_result = Ok(response.bytes().await);

                    match bytes_result {
                        #[cfg(not(target_arch = "wasm32"))]
                        Err(_) => Err(NoiseError::Timeout(
                            "Reading handshake bytes timed out".to_string(),
                        )),
                        Ok(Ok(bytes)) => Ok(Some(bytes.to_vec())),
                        Ok(Err(e)) => Err(NoiseError::Network(format!(
                            "Failed to read handshake bytes: {:?}",
                            e
                        ))),
                    }
                } else if response.status().as_u16() == 404 {
                    Ok(None) // Not found yet
                } else {
                    Err(NoiseError::Storage(format!(
                        "Unexpected status polling handshake: {}",
                        response.status()
                    )))
                }
            }
            Ok(Err(e)) => Err(NoiseError::Network(format!(
                "Network error polling handshake: {:?}",
                e
            ))),
        }
    }

    /// Wait for a handshake message with timeout and polling.
    ///
    /// Polls repeatedly until the message appears or timeout expires.
    ///
    /// # Arguments
    ///
    /// * `msg_index` - Message index to wait for
    /// * `timeout` - Maximum time to wait
    ///
    /// # Errors
    ///
    /// Returns `NoiseError::Timeout` if message doesn't appear within timeout.
    pub async fn await_handshake_msg(
        &self,
        msg_index: u8,
        timeout: Duration,
    ) -> Result<Vec<u8>, NoiseError> {
        let start = std::time::Instant::now();
        let poll_interval = Duration::from_millis(500); // Poll every 500ms

        loop {
            if start.elapsed() > timeout {
                return Err(NoiseError::Timeout(format!(
                    "Handshake message {} not received within {:?}",
                    msg_index, timeout
                )));
            }

            match self.poll_handshake_msg(msg_index).await? {
                Some(data) => return Ok(data),
                None => {
                    #[cfg(not(target_arch = "wasm32"))]
                    tokio::time::sleep(poll_interval).await;

                    // On WASM, we can't sleep easily, so just return timeout immediately
                    #[cfg(target_arch = "wasm32")]
                    return Err(NoiseError::Timeout(
                        "WASM: await_handshake_msg requires polling manually".to_string(),
                    ));
                }
            }
        }
    }

    /// Transition from handshake to encrypted messaging.
    ///
    /// After handshake completes, use this to create a [`StorageBackedMessaging`]
    /// instance for encrypted communication.
    ///
    /// # Arguments
    ///
    /// * `link` - Completed NoiseLink from handshake
    /// * `write_path` - Path for outgoing encrypted messages
    /// * `read_path` - Path for incoming encrypted messages
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let messaging = queue.complete_to_messaging(
    ///     link,
    ///     "/pub/myapp/messages/outbox".to_string(),
    ///     "/pub/peer/messages/outbox".to_string(),
    /// )?;
    /// ```
    pub fn complete_to_messaging(
        self,
        link: NoiseLink,
        write_path: String,
        read_path: String,
    ) -> Result<StorageBackedMessaging, NoiseError> {
        StorageBackedMessaging::new(
            link,
            self.session,
            self.public_client,
            write_path,
            read_path,
        )
    }

    /// Clean up handshake messages from storage.
    ///
    /// Call this after handshake completes or fails to remove temporary messages.
    /// Cleaning up helps prevent storage bloat and hides handshake artifacts.
    ///
    /// # Arguments
    ///
    /// * `msg_count` - Number of messages to delete (typically 2 for IK, 3 for XX)
    pub async fn cleanup(&self, msg_count: u8) -> Result<(), NoiseError> {
        for i in 0..msg_count {
            let path = format!("{}/msg_{}", self.handshake_path, i);

            // Best-effort deletion - ignore errors
            let _ = self.session.storage().delete(&path).await;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_path_valid() {
        assert!(HandshakeQueue::validate_path("/pub/noise/handshake/abc123").is_ok());
        assert!(HandshakeQueue::validate_path("/pub/noise/hs/peer-key-hex").is_ok());
        assert!(HandshakeQueue::validate_path("/a").is_ok());
    }

    #[test]
    fn test_validate_path_empty() {
        let result = HandshakeQueue::validate_path("");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn test_validate_path_no_leading_slash() {
        let result = HandshakeQueue::validate_path("pub/noise/hs");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("start with /"));
    }

    #[test]
    fn test_validate_path_no_traversal() {
        let result = HandshakeQueue::validate_path("/pub/../etc");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains(".."));
    }

    #[test]
    fn test_validate_path_no_double_slash() {
        let result = HandshakeQueue::validate_path("/pub//noise");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("//"));
    }

    #[test]
    fn test_validate_path_no_special_chars() {
        assert!(HandshakeQueue::validate_path("/pub/noise?query").is_err());
        assert!(HandshakeQueue::validate_path("/pub/noise#frag").is_err());
        assert!(HandshakeQueue::validate_path("/pub/noise key").is_err());
    }

    #[test]
    fn test_normalize_base_path_trailing_slash() {
        // Single trailing slash should be removed
        assert_eq!(
            HandshakeQueue::normalize_base_path("/pub/noise/hs/".to_string()),
            "/pub/noise/hs"
        );

        // Multiple trailing slashes should be removed
        assert_eq!(
            HandshakeQueue::normalize_base_path("/pub/noise/hs///".to_string()),
            "/pub/noise/hs"
        );

        // No trailing slash should remain unchanged
        assert_eq!(
            HandshakeQueue::normalize_base_path("/pub/noise/hs".to_string()),
            "/pub/noise/hs"
        );

        // Root path should remain as single slash
        assert_eq!(HandshakeQueue::normalize_base_path("/".to_string()), "/");
    }

    #[test]
    fn test_normalize_prevents_double_slash_in_handshake_path() {
        // This test verifies the fix for the path construction bug
        // where trailing slashes could cause "/pub/hs//msg_0" paths

        let base_with_trailing = "/pub/noise/handshake/session123/";
        let normalized = HandshakeQueue::normalize_base_path(base_with_trailing.to_string());
        let msg_path = format!("{}/msg_0", normalized);

        assert!(
            !msg_path.contains("//"),
            "Path should not contain double slashes: {}",
            msg_path
        );
        assert_eq!(msg_path, "/pub/noise/handshake/session123/msg_0");
    }
}
