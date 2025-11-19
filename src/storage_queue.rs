#![cfg(feature = "storage-queue")]

use crate::datalink_adapter::NoiseLink;
use crate::errors::NoiseError;
use pubky::{Pubky, PubkySession};
use std::time::Duration;

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
    public_client: Pubky,
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
    /// Create a new StorageBackedMessaging instance with default retry configuration
    pub fn new(
        link: NoiseLink,
        session: PubkySession,
        public_client: Pubky,
        write_path: String,
        read_path: String,
    ) -> Self {
        Self {
            noise_link: link,
            session,
            public_client,
            write_path,
            read_path,
            write_counter: 0,
            read_counter: 0,
            retry_config: RetryConfig::default(),
        }
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
    pub async fn receive_messages(&mut self, max_messages: Option<usize>) -> Result<Vec<Vec<u8>>, NoiseError> {
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
                            let ciphertext = response.bytes().await
                                .map_err(|e| NoiseError::Network(format!("Failed to read bytes: {:?}", e)))?;
                            
                            let plaintext = self.noise_link.decrypt(&ciphertext)
                                .map_err(|e| NoiseError::Decryption(format!("Failed to decrypt: {:?}", e)))?;
                            
                            messages.push(plaintext);
                            self.read_counter += 1;
                            attempts += 1;
                            break; // Success, move to next message
                        } else if response.status().as_u16() == 404 {
                            // No more messages - this is expected, not an error
                            return Ok(messages);
                        } else if response.status().as_u16() >= 500 && retry_attempt < self.retry_config.max_retries {
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
                    },
                    Err(e) if retry_attempt < self.retry_config.max_retries => {
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
            _ => Ok(0)
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
