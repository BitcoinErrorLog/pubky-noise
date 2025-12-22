//! Storage-backed messaging queue using Pubky storage (optional feature).
//!
//! ## Path Requirements
//!
//! Storage paths must meet the following criteria:
//! - Must start with `/` (absolute Pubky path)
//! - Maximum length: 1024 characters
//! - Allowed characters: alphanumeric, `/`, `-`, `_`, `.`
//! - Cannot contain `..` (path traversal)
//! - Cannot contain `//` (double slashes)
//!
//! Example valid paths:
//! - `/pub/my-app/messages/outbox`
//! - `/pub/paykit.app/v0/noise/inbox`
//!
//! ## WASM Limitations
//!
//! On WASM targets, operation timeouts are not enforced because `tokio::time::timeout`
//! is not available. Operations may block indefinitely on slow networks.

use crate::datalink_adapter::NoiseLink;
use crate::errors::NoiseError;
use pubky::{PubkySession, PublicStorage};
use std::time::Duration;

/// Maximum allowed path length in characters.
const MAX_PATH_LENGTH: usize = 1024;

/// Configuration for retry behavior
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_retries: u32,
    /// Initial backoff duration in milliseconds
    pub initial_backoff_ms: u64,
    /// Maximum backoff duration in milliseconds
    pub max_backoff_ms: u64,
    /// Timeout for individual operations in milliseconds
    pub operation_timeout_ms: u64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_backoff_ms: 100,
            max_backoff_ms: 5000,
            operation_timeout_ms: 30000,
        }
    }
}

/// Storage-backed messaging with Noise encryption
///
/// This implementation follows the Outbox Pattern: senders write to their own
/// repository (authenticated write), and receivers poll the sender's repository
/// (public read).
///
/// **Important**: You must persist `write_counter` and `read_counter` values
/// across application restarts to avoid data loss or message replay.
pub struct StorageBackedMessaging {
    noise_link: NoiseLink,
    session: PubkySession,
    public_client: PublicStorage,
    write_path: String,
    read_path: String,
    write_counter: u64,
    read_counter: u64,
    retry_config: RetryConfig,
}

#[cfg_attr(feature = "storage-queue", async_trait::async_trait)]
pub trait MessageQueue {
    async fn enqueue(&mut self, data: &[u8]) -> Result<(), NoiseError>;
    async fn dequeue(&mut self) -> Result<Option<Vec<u8>>, NoiseError>;
}

impl StorageBackedMessaging {
    /// Validate that a storage path is safe for use with Pubky.
    ///
    /// # Path Requirements
    ///
    /// - Must start with `/` (absolute Pubky path)
    /// - Maximum length: 1024 characters
    /// - Allowed characters: alphanumeric, `/`, `-`, `_`, `.`
    /// - Cannot contain `..` (path traversal prevention)
    /// - Cannot contain `//` (no double slashes)
    ///
    /// # Errors
    ///
    /// Returns `NoiseError::Storage` if the path is invalid.
    fn validate_path(path: &str) -> Result<(), NoiseError> {
        if path.is_empty() {
            return Err(NoiseError::Storage("Path cannot be empty".to_string()));
        }
        if !path.starts_with('/') {
            return Err(NoiseError::Storage(
                "Path must start with /".to_string(),
            ));
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

    /// Create a new StorageBackedMessaging instance with default retry configuration.
    ///
    /// # Errors
    ///
    /// Returns `NoiseError::Storage` if either `write_path` or `read_path` is invalid.
    /// See module documentation for path requirements.
    pub fn new(
        link: NoiseLink,
        session: PubkySession,
        public_client: PublicStorage,
        write_path: String,
        read_path: String,
    ) -> Result<Self, NoiseError> {
        Self::validate_path(&write_path)?;
        Self::validate_path(&read_path)?;

        Ok(Self {
            noise_link: link,
            session,
            public_client,
            write_path,
            read_path,
            write_counter: 0,
            read_counter: 0,
            retry_config: RetryConfig::default(),
        })
    }

    /// Set the initial counters (useful for resuming sessions from persisted state)
    ///
    /// **Critical for production**: Always persist and restore these counters
    /// to avoid data loss or message replay across app restarts.
    pub fn with_counters(mut self, write: u64, read: u64) -> Self {
        self.write_counter = write;
        self.read_counter = read;
        self
    }

    /// Configure retry behavior for network operations
    pub fn with_retry_config(mut self, config: RetryConfig) -> Self {
        self.retry_config = config;
        self
    }

    pub fn write_path(&self) -> &str {
        &self.write_path
    }

    pub fn read_path(&self) -> &str {
        &self.read_path
    }

    /// Get the current write counter value for persistence
    pub fn write_counter(&self) -> u64 {
        self.write_counter
    }

    /// Get the current read counter value for persistence
    pub fn read_counter(&self) -> u64 {
        self.read_counter
    }

    /// Send a message with retry logic and exponential backoff
    pub async fn send_message(&mut self, plaintext: &[u8]) -> Result<(), NoiseError> {
        let ciphertext = self.noise_link.encrypt(plaintext)?;
        let path = format!("{}/msg_{}", self.write_path, self.write_counter);

        // Retry with exponential backoff
        let mut attempt = 0;
        let mut backoff_ms = self.retry_config.initial_backoff_ms;

        loop {
            match self.session.storage().put(&path, ciphertext.clone()).await {
                Ok(_) => {
                    self.write_counter += 1;
                    return Ok(());
                }
                Err(e) => {
                    attempt += 1;
                    if attempt >= self.retry_config.max_retries {
                        return Err(NoiseError::Storage(format!(
                            "Failed to put after {} attempts: {:?}",
                            attempt, e
                        )));
                    }

                    // Exponential backoff with cap
                    // Note: For WASM targets, consider using gloo-timers or similar
                    #[cfg(not(target_arch = "wasm32"))]
                    tokio::time::sleep(Duration::from_millis(backoff_ms)).await;

                    backoff_ms = (backoff_ms * 2).min(self.retry_config.max_backoff_ms);
                }
            }
        }
    }

    /// Receive messages with retry logic for transient errors
    pub async fn receive_messages(
        &mut self,
        max_messages: Option<usize>,
    ) -> Result<Vec<Vec<u8>>, NoiseError> {
        let mut messages = Vec::new();
        let limit = max_messages.unwrap_or(10); // Default limit to avoid infinite loops
        let mut attempts = 0;

        while attempts < limit {
            let path = format!("{}/msg_{}", self.read_path, self.read_counter);

            // Retry logic for transient errors
            let mut retry_attempt = 0;
            let mut backoff_ms = self.retry_config.initial_backoff_ms;

            loop {
                match self.public_client.get(&path).await {
                    Ok(response) => {
                        if response.status().is_success() {
                            let ciphertext = response.bytes().await.map_err(|e| {
                                NoiseError::Network(format!("Failed to read bytes: {:?}", e))
                            })?;

                            let plaintext = self.noise_link.decrypt(&ciphertext).map_err(|e| {
                                NoiseError::Decryption(format!("Failed to decrypt: {:?}", e))
                            })?;

                            messages.push(plaintext);
                            self.read_counter += 1;
                            attempts += 1;
                            break; // Success, move to next message
                        } else if response.status().as_u16() == 404 {
                            // No more messages - this is expected, not an error
                            return Ok(messages);
                        } else if response.status().as_u16() >= 500
                            && retry_attempt < self.retry_config.max_retries
                        {
                            // Server error - retry
                            retry_attempt += 1;

                            #[cfg(not(target_arch = "wasm32"))]
                            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;

                            backoff_ms = (backoff_ms * 2).min(self.retry_config.max_backoff_ms);
                            continue;
                        } else {
                            // Other error (client error or exhausted retries)
                            return Err(NoiseError::Storage(format!(
                                "Failed to get message: status {}",
                                response.status()
                            )));
                        }
                    }
                    Err(_e) if retry_attempt < self.retry_config.max_retries => {
                        // Network error - retry
                        retry_attempt += 1;

                        #[cfg(not(target_arch = "wasm32"))]
                        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;

                        backoff_ms = (backoff_ms * 2).min(self.retry_config.max_backoff_ms);
                        continue;
                    }
                    Err(e) => {
                        // Exhausted retries
                        return Err(NoiseError::Network(format!(
                            "Network error after {} retries: {:?}",
                            retry_attempt, e
                        )));
                    }
                }
            }
        }

        Ok(messages)
    }

    pub async fn peek_message_count(&self) -> Result<usize, NoiseError> {
        // Estimate by checking if next message exists
        // This is just a peek, doesn't guarantee total count without scanning
        let path = format!("{}/msg_{}", self.read_path, self.read_counter);
        match self.public_client.get(&path).await {
            Ok(r) if r.status().is_success() => Ok(1), // At least 1
            _ => Ok(0),
        }
    }
}

#[cfg_attr(feature = "storage-queue", async_trait::async_trait)]
impl MessageQueue for StorageBackedMessaging {
    async fn enqueue(&mut self, data: &[u8]) -> Result<(), NoiseError> {
        self.send_message(data).await
    }

    async fn dequeue(&mut self) -> Result<Option<Vec<u8>>, NoiseError> {
        let mut msgs = self.receive_messages(Some(1)).await?;
        Ok(msgs.pop())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_path_valid_paths() {
        // Valid paths should pass
        assert!(StorageBackedMessaging::validate_path("/pub/app/messages").is_ok());
        assert!(StorageBackedMessaging::validate_path("/pub/paykit.app/v0/noise").is_ok());
        assert!(StorageBackedMessaging::validate_path("/pub/my-app/outbox").is_ok());
        assert!(StorageBackedMessaging::validate_path("/pub/user_123/inbox").is_ok());
        assert!(StorageBackedMessaging::validate_path("/a").is_ok());
    }

    #[test]
    fn test_validate_path_empty() {
        let result = StorageBackedMessaging::validate_path("");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn test_validate_path_must_start_with_slash() {
        let result = StorageBackedMessaging::validate_path("pub/app/messages");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("start with /"));
    }

    #[test]
    fn test_validate_path_no_path_traversal() {
        let result = StorageBackedMessaging::validate_path("/pub/../etc/passwd");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains(".."));

        let result = StorageBackedMessaging::validate_path("/pub/app/../../secret");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_path_no_double_slashes() {
        let result = StorageBackedMessaging::validate_path("/pub//app/messages");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("//"));
    }

    #[test]
    fn test_validate_path_max_length() {
        // Create a path that exceeds MAX_PATH_LENGTH
        let long_path = format!("/{}", "a".repeat(MAX_PATH_LENGTH));
        let result = StorageBackedMessaging::validate_path(&long_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("maximum length"));
    }

    #[test]
    fn test_validate_path_invalid_characters() {
        // Space is invalid
        let result = StorageBackedMessaging::validate_path("/pub/my app/messages");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid character"));

        // Special characters are invalid
        assert!(StorageBackedMessaging::validate_path("/pub/app@domain").is_err());
        assert!(StorageBackedMessaging::validate_path("/pub/app#tag").is_err());
        assert!(StorageBackedMessaging::validate_path("/pub/app?query").is_err());
        assert!(StorageBackedMessaging::validate_path("/pub/app&more").is_err());
        assert!(StorageBackedMessaging::validate_path("/pub/app=value").is_err());
    }

    #[test]
    fn test_validate_path_allowed_special_characters() {
        // Dash, underscore, and dot are allowed
        assert!(StorageBackedMessaging::validate_path("/pub/my-app").is_ok());
        assert!(StorageBackedMessaging::validate_path("/pub/my_app").is_ok());
        assert!(StorageBackedMessaging::validate_path("/pub/my.app").is_ok());
        assert!(StorageBackedMessaging::validate_path("/pub/my-app_v2.0").is_ok());
    }
}
