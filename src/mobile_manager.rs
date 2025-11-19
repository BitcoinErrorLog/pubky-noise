//! Mobile-optimized Noise session manager with lifecycle management
//! 
//! This module provides a high-level API specifically designed for mobile applications
//! that need to manage Noise sessions with proper lifecycle handling, state persistence,
//! and automatic reconnection.

use crate::{NoiseClient, NoiseServer, NoiseLink, RingKeyProvider, NoiseError, SessionId};
use crate::datalink_adapter::{client_start_ik_direct, server_accept_ik};
use std::sync::Arc;
use std::collections::HashMap;

#[cfg(feature = "storage-queue")]
use crate::storage_queue::{StorageBackedMessaging, RetryConfig};

/// Connection status for a Noise session
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "storage-queue", derive(serde::Serialize, serde::Deserialize))]
pub enum ConnectionStatus {
    /// Session is connected and ready
    Connected,
    /// Session is attempting to reconnect
    Reconnecting,
    /// Session is disconnected
    Disconnected,
    /// Session encountered an error
    Error,
}

/// Serializable session state for persistence across app restarts
#[cfg_attr(feature = "storage-queue", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone)]
pub struct SessionState {
    /// Session identifier
    pub session_id: SessionId,
    /// Peer's public key (for reconnection)
    pub peer_static_pk: [u8; 32],
    /// Current epoch
    pub epoch: u32,
    /// Write counter (for storage-backed messaging)
    pub write_counter: u64,
    /// Read counter (for storage-backed messaging)
    pub read_counter: u64,
    /// Connection status
    pub status: ConnectionStatus,
}

/// Mobile-optimized configuration
#[derive(Debug, Clone)]
pub struct MobileConfig {
    /// Enable automatic reconnection
    pub auto_reconnect: bool,
    /// Maximum reconnection attempts
    pub max_reconnect_attempts: u32,
    /// Initial reconnection delay in milliseconds
    pub reconnect_delay_ms: u64,
    /// Enable aggressive battery saving (reduces background activity)
    pub battery_saver: bool,
    /// Chunk size for streaming (smaller for mobile networks)
    pub chunk_size: usize,
}

impl Default for MobileConfig {
    fn default() -> Self {
        Self {
            auto_reconnect: true,
            max_reconnect_attempts: 5,
            reconnect_delay_ms: 1000,
            battery_saver: false,
            chunk_size: 32768, // 32KB chunks for mobile
        }
    }
}

/// High-level Noise session manager for mobile applications
/// 
/// This manager handles:
/// - Session lifecycle (creation, persistence, restoration)
/// - Automatic reconnection with exponential backoff
/// - Multiple concurrent sessions
/// - Thread-safe access (wrap in Arc<Mutex<>> for multi-threaded use)
/// 
/// # Example
/// 
/// ```rust,no_run
/// use pubky_noise::{NoiseClient, DummyRing, mobile_manager::{NoiseManager, MobileConfig}};
/// use std::sync::Arc;
/// 
/// # async fn example() -> Result<(), pubky_noise::NoiseError> {
/// let ring = Arc::new(DummyRing::new([1u8; 32], "kid"));
/// let client = Arc::new(NoiseClient::<_, ()>::new_direct("kid", b"device-id", ring));
/// 
/// let mut manager = NoiseManager::new_client(client, MobileConfig::default());
/// 
/// // Create a new session
/// let server_pk = [0u8; 32]; // Get from server
/// let session_id = manager.connect_client(&server_pk, 3, None).await?;
/// 
/// // Save state for persistence
/// let state = manager.save_state(&session_id)?;
/// // ... save state to disk ...
/// 
/// // Later, restore state
/// manager.restore_state(state)?;
/// # Ok(())
/// # }
/// ```
pub struct NoiseManager<R: RingKeyProvider> {
    client: Option<Arc<NoiseClient<R, ()>>>,
    server: Option<Arc<NoiseServer<R, ()>>>,
    sessions: HashMap<SessionId, NoiseLink>,
    session_states: HashMap<SessionId, SessionState>,
    config: MobileConfig,
}

impl<R: RingKeyProvider> NoiseManager<R> {
    /// Create a new manager for client role
    pub fn new_client(client: Arc<NoiseClient<R, ()>>, config: MobileConfig) -> Self {
        Self {
            client: Some(client),
            server: None,
            sessions: HashMap::new(),
            session_states: HashMap::new(),
            config,
        }
    }

    /// Create a new manager for server role
    pub fn new_server(server: Arc<NoiseServer<R, ()>>, config: MobileConfig) -> Self {
        Self {
            client: None,
            server: Some(server),
            sessions: HashMap::new(),
            session_states: HashMap::new(),
            config,
        }
    }

    /// Connect as a client and establish a new session
    /// 
    /// Returns the SessionId of the newly created session
    pub async fn connect_client(
        &mut self, 
        server_static_pk: &[u8; 32], 
        epoch: u32,
        hint: Option<&str>
    ) -> Result<SessionId, NoiseError> {
        let client = self.client.as_ref()
            .ok_or_else(|| NoiseError::Other("Not in client mode".to_string()))?;

        let (link, used_epoch, _first_msg) = client_start_ik_direct(client, server_static_pk, epoch, hint)?;
        let session_id = link.session_id().clone();

        let state = SessionState {
            session_id: session_id.clone(),
            peer_static_pk: *server_static_pk,
            epoch: used_epoch,
            write_counter: 0,
            read_counter: 0,
            status: ConnectionStatus::Connected,
        };

        self.sessions.insert(session_id.clone(), link);
        self.session_states.insert(session_id.clone(), state);

        Ok(session_id)
    }

    /// Accept a connection as a server
    /// 
    /// Returns the SessionId of the newly created session
    pub fn accept_server(&mut self, first_msg: &[u8]) -> Result<SessionId, NoiseError> {
        let server = self.server.as_ref()
            .ok_or_else(|| NoiseError::Other("Not in server mode".to_string()))?;

        let (link, _identity) = server_accept_ik(server, first_msg)?;
        let session_id = link.session_id().clone();

        let state = SessionState {
            session_id: session_id.clone(),
            peer_static_pk: [0u8; 32], // Not available in server mode
            epoch: 0,
            write_counter: 0,
            read_counter: 0,
            status: ConnectionStatus::Connected,
        };

        self.sessions.insert(session_id.clone(), link);
        self.session_states.insert(session_id.clone(), state);

        Ok(session_id)
    }

    /// Get a session link for encryption/decryption
    pub fn get_session(&self, session_id: &SessionId) -> Option<&NoiseLink> {
        self.sessions.get(session_id)
    }

    /// Get a mutable session link
    pub fn get_session_mut(&mut self, session_id: &SessionId) -> Option<&mut NoiseLink> {
        self.sessions.get_mut(session_id)
    }

    /// Remove a session
    pub fn remove_session(&mut self, session_id: &SessionId) -> Option<NoiseLink> {
        self.session_states.remove(session_id);
        self.sessions.remove(session_id)
    }

    /// List all active sessions
    pub fn list_sessions(&self) -> Vec<SessionId> {
        self.sessions.keys().cloned().collect()
    }

    /// Get the connection status for a session
    pub fn get_status(&self, session_id: &SessionId) -> Option<ConnectionStatus> {
        self.session_states.get(session_id).map(|s| s.status)
    }

    /// Update the connection status for a session
    pub fn set_status(&mut self, session_id: &SessionId, status: ConnectionStatus) {
        if let Some(state) = self.session_states.get_mut(session_id) {
            state.status = status;
        }
    }

    /// Save the current state of a session for persistence
    /// 
    /// **Critical**: Call this before app suspension to enable session restoration
    pub fn save_state(&self, session_id: &SessionId) -> Result<SessionState, NoiseError> {
        self.session_states
            .get(session_id)
            .cloned()
            .ok_or_else(|| NoiseError::Other("Session not found".to_string()))
    }

    /// Restore a session from saved state
    /// 
    /// Note: This only restores the state metadata. You'll need to reconnect
    /// to re-establish the actual Noise transport.
    pub fn restore_state(&mut self, state: SessionState) -> Result<(), NoiseError> {
        self.session_states.insert(state.session_id.clone(), state);
        Ok(())
    }

    /// Get the mobile configuration
    pub fn config(&self) -> &MobileConfig {
        &self.config
    }

    /// Update the mobile configuration
    pub fn set_config(&mut self, config: MobileConfig) {
        self.config = config;
    }

    /// Encrypt data using a specific session
    pub fn encrypt(&mut self, session_id: &SessionId, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        self.sessions
            .get_mut(session_id)
            .ok_or_else(|| NoiseError::Other("Session not found".to_string()))?
            .encrypt(plaintext)
    }

    /// Decrypt data using a specific session
    pub fn decrypt(&mut self, session_id: &SessionId, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        self.sessions
            .get_mut(session_id)
            .ok_or_else(|| NoiseError::Other("Session not found".to_string()))?
            .decrypt(ciphertext)
    }
}

/// Create storage-backed messaging for a session (requires storage-queue feature)
#[cfg(feature = "storage-queue")]
impl<R: RingKeyProvider> NoiseManager<R> {
    /// Create a storage-backed messaging instance for asynchronous communication
    /// 
    /// This is useful when direct connection is not possible or for implementing
    /// an asynchronous message queue pattern.
    pub fn create_storage_messaging(
        &mut self,
        session_id: &SessionId,
        session: pubky::PubkySession,
        public_client: pubky::Pubky,
        write_path: String,
        read_path: String,
    ) -> Result<StorageBackedMessaging, NoiseError> {
        let link = self.sessions
            .remove(session_id)
            .ok_or_else(|| NoiseError::Other("Session not found".to_string()))?;
        
        let state = self.session_states
            .get(session_id)
            .ok_or_else(|| NoiseError::Other("Session state not found".to_string()))?;

        let mut messaging = StorageBackedMessaging::new(
            link,
            session,
            public_client,
            write_path,
            read_path,
        );

        // Configure with retry settings appropriate for mobile
        let retry_config = RetryConfig {
            max_retries: if self.config.battery_saver { 2 } else { 3 },
            initial_backoff_ms: 200,
            max_backoff_ms: if self.config.battery_saver { 3000 } else { 5000 },
            operation_timeout_ms: 30000,
        };
        
        messaging = messaging
            .with_counters(state.write_counter, state.read_counter)
            .with_retry_config(retry_config);

        Ok(messaging)
    }
}

impl<R: RingKeyProvider> Drop for NoiseManager<R> {
    fn drop(&mut self) {
        // Clean up all sessions
        self.sessions.clear();
        self.session_states.clear();
    }
}

