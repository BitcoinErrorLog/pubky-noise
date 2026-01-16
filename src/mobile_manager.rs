//! Mobile-optimized Noise session manager with lifecycle management.
//!
//! This module provides a high-level API specifically designed for mobile applications
//! that need to manage Noise sessions with proper lifecycle handling and state persistence.
//!
//! ## Reconnection
//!
//! Reconnection logic must be implemented by the application. The `MobileConfig` provides
//! configuration hints (`auto_reconnect`, `max_reconnect_attempts`, `reconnect_delay_ms`)
//! that applications can use to configure their own reconnection behavior. Use
//! `save_state()` to persist session metadata before app suspension, and `restore_state()`
//! followed by a new `initiate_connection()` to reconnect after resuming.
//!
//! ## 3-Step Handshake Flow
//!
//! **Client:**
//! 1. Call `initiate_connection()` - returns first message to send to server
//! 2. Send message over your transport (TCP, WebSocket, etc.)
//! 3. Receive server response
//! 4. Call `complete_connection()` with response - establishes session
//!
//! **Server:**
//! 1. Receive client's first message
//! 2. Call `accept_connection()` - processes message and returns response + SessionId
//! 3. Send response back to client over your transport
//! 4. Session established

use crate::datalink_adapter::{client_complete_ik, client_start_ik_direct};
use crate::{NoiseClient, NoiseError, NoiseLink, NoiseServer, RingKeyProvider, SessionId};
use snow::HandshakeState;
use std::collections::HashMap;
use std::sync::Arc;

#[cfg(feature = "storage-queue")]
use crate::storage_queue::{RetryConfig, StorageBackedMessaging};

/// Connection status for a Noise session.
///
/// ## Persistence
///
/// When the `storage-queue` feature is enabled, this enum derives `Serialize`/`Deserialize`
/// to support state persistence across app restarts. Applications should:
///
/// 1. Persist `SessionState` (which includes `ConnectionStatus`) before app suspension
/// 2. Restore on resume using `NoiseManager::restore_state()`
/// 3. Check status and initiate reconnection if needed
///
/// ## Reconnection Strategy
///
/// Applications should implement **laddered backoff** for reconnection:
///
/// ```text
/// Attempt 1: wait 1s
/// Attempt 2: wait 2s
/// Attempt 3: wait 4s
/// Attempt 4: wait 8s
/// Attempt 5: wait 16s (capped)
/// ```
///
/// Use `MobileConfig::reconnect_delay_ms` as the initial delay, then double
/// for each subsequent attempt up to a reasonable maximum (e.g., 30s).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    feature = "storage-queue",
    derive(serde::Serialize, serde::Deserialize)
)]
pub enum ConnectionStatus {
    /// Session is connected and ready for encryption/decryption.
    Connected,
    /// Session is attempting to reconnect (application-managed).
    /// Track reconnection attempts externally and use laddered backoff.
    Reconnecting,
    /// Session is disconnected. Call `initiate_connection()` to reconnect.
    Disconnected,
    /// Session encountered an error. Check logs and potentially retry.
    Error,
}

/// Serializable session state for persistence across app restarts.
#[cfg_attr(
    feature = "storage-queue",
    derive(serde::Serialize, serde::Deserialize)
)]
#[derive(Debug, Clone)]
pub struct SessionState {
    /// Session identifier.
    pub session_id: SessionId,
    /// Peer's public key (for reconnection).
    pub peer_static_pk: [u8; 32],
    /// Write counter (for storage-backed messaging).
    pub write_counter: u64,
    /// Read counter (for storage-backed messaging).
    pub read_counter: u64,
    /// Connection status.
    pub status: ConnectionStatus,
}

/// Mobile-optimized configuration for Noise sessions.
///
/// ## Reconnection Settings
///
/// The `auto_reconnect`, `max_reconnect_attempts`, and `reconnect_delay_ms` fields
/// are **configuration hints** for application-level reconnection logic. The
/// `NoiseManager` does not implement automatic reconnection internally; applications
/// must implement their own reconnection handling using `restore_state()` and
/// `initiate_connection()`.
///
/// These fields are exposed in the configuration to provide a standard way for
/// applications to configure their reconnection behavior.
#[derive(Debug, Clone)]
pub struct MobileConfig {
    /// Hint: Whether the application should attempt reconnection on disconnect.
    /// Applications must implement their own reconnection logic.
    pub auto_reconnect: bool,
    /// Hint: Maximum number of reconnection attempts before giving up.
    /// Applications must implement their own retry counter.
    pub max_reconnect_attempts: u32,
    /// Hint: Initial delay in milliseconds between reconnection attempts.
    /// Applications should use exponential backoff (e.g., delay * 2^attempt).
    pub reconnect_delay_ms: u64,
    /// Enable aggressive battery saving (reduces background activity).
    pub battery_saver: bool,
    /// Chunk size for streaming (smaller for mobile networks).
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
/// - Reconnection hints and state persistence for application-managed reconnects
/// - Multiple concurrent sessions
/// - Thread-safe access (wrap in Arc<Mutex<>> for multi-threaded use)
///
/// # Example
///
/// ```rust
/// use pubky_noise::{NoiseClient, DummyRing, mobile_manager::{NoiseManager, MobileConfig}};
/// use std::sync::Arc;
///
/// let ring = Arc::new(DummyRing::new([1u8; 32], "kid"));
/// let client = Arc::new(NoiseClient::<_, ()>::new_direct("kid", b"device-id", ring));
///
/// let manager = NoiseManager::new_client(client, MobileConfig::default());
/// // Manager is ready for use
/// ```
///
/// ## Full Handshake Flow
///
/// ```rust,ignore
/// // Step 1: Initiate connection
/// let server_pk = [0u8; 32]; // Get from server
/// let (temp_id, first_msg) = manager.initiate_connection(&server_pk, None)?;
///
/// // Step 2: Send first_msg to server, receive response (app's responsibility)
/// let response = send_to_server(&first_msg)?;
///
/// // Step 3: Complete handshake
/// let session_id = manager.complete_connection(&temp_id, &response)?;
///
/// // Save state for persistence
/// let state = manager.save_state(&session_id)?;
///
/// // Later, restore state
/// manager.restore_state(state)?;
/// ```
pub struct NoiseManager<R: RingKeyProvider> {
    client: Option<Arc<NoiseClient<R, ()>>>,
    server: Option<Arc<NoiseServer<R, ()>>>,
    sessions: HashMap<SessionId, NoiseLink>,
    session_states: HashMap<SessionId, SessionState>,
    /// Pending client handshakes (temporary SessionId -> HandshakeState + server_pk)
    pending_handshakes: HashMap<SessionId, (HandshakeState, [u8; 32])>,
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
            pending_handshakes: HashMap::new(),
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
            pending_handshakes: HashMap::new(),
            config,
        }
    }

    /// Initiate a client connection (Step 1 of 3-step handshake).
    ///
    /// This starts the handshake and returns the first message to send to the server.
    ///
    /// # Arguments
    ///
    /// * `server_static_pk` - The server's static X25519 public key.
    /// * `hint` - Optional server hint for routing.
    ///
    /// # Returns
    ///
    /// A tuple of (temporary SessionId, first handshake message).
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use pubky_noise::{NoiseClient, DummyRing, mobile_manager::{NoiseManager, MobileConfig}};
    /// # use std::sync::Arc;
    /// # fn example() -> Result<(), pubky_noise::NoiseError> {
    /// # let ring = Arc::new(DummyRing::new([1u8; 32], "kid"));
    /// # let client = Arc::new(NoiseClient::<_, ()>::new_direct("kid", b"device-id", ring));
    /// let mut manager = NoiseManager::new_client(client, MobileConfig::default());
    ///
    /// let server_pk = [0u8; 32]; // Server's public key
    /// let (session_id, first_msg) = manager.initiate_connection(&server_pk, None)?;
    ///
    /// // Send first_msg to server over your transport...
    /// // Then receive server response and call complete_connection()
    /// # Ok(())
    /// # }
    /// ```
    pub fn initiate_connection(
        &mut self,
        server_static_pk: &[u8; 32],
        hint: Option<&str>,
    ) -> Result<(SessionId, Vec<u8>), NoiseError> {
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| NoiseError::Other("Not in client mode".to_string()))?;

        // Step 1: Start handshake
        let (hs, first_msg) = client_start_ik_direct(client, server_static_pk, hint)?;

        // Generate temporary session ID for tracking
        let temp_session_id = SessionId::from_handshake(&hs)?;

        // Store pending handshake
        self.pending_handshakes
            .insert(temp_session_id.clone(), (hs, *server_static_pk));

        Ok((temp_session_id, first_msg))
    }

    /// Complete a client connection (Step 3 of 3-step handshake).
    ///
    /// Call this after receiving the server's response to complete the handshake.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The temporary SessionId returned from `initiate_connection()`.
    /// * `server_response` - The handshake response message from the server.
    ///
    /// # Returns
    ///
    /// The final `SessionId` for the established session.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use pubky_noise::{NoiseClient, DummyRing, mobile_manager::{NoiseManager, MobileConfig}, SessionId};
    /// # use std::sync::Arc;
    /// # fn example(temp_id: SessionId, response: Vec<u8>) -> Result<(), pubky_noise::NoiseError> {
    /// # let ring = Arc::new(DummyRing::new([1u8; 32], "kid"));
    /// # let client = Arc::new(NoiseClient::<_, ()>::new_direct("kid", b"device-id", ring));
    /// # let mut manager = NoiseManager::new_client(client, MobileConfig::default());
    /// // After receiving server response...
    /// let final_session_id = manager.complete_connection(&temp_id, &response)?;
    ///
    /// // Now you can use the session
    /// let session = manager.get_session(&final_session_id);
    /// # Ok(())
    /// # }
    /// ```
    pub fn complete_connection(
        &mut self,
        session_id: &SessionId,
        server_response: &[u8],
    ) -> Result<SessionId, NoiseError> {
        // Get pending handshake
        let (hs, server_static_pk) = self
            .pending_handshakes
            .remove(session_id)
            .ok_or_else(|| NoiseError::Other("No pending handshake found".to_string()))?;

        // Step 3: Complete handshake
        let link = client_complete_ik(hs, server_response)?;
        let final_session_id = link.session_id().clone();

        // Store session and state
        let state = SessionState {
            session_id: final_session_id.clone(),
            peer_static_pk: server_static_pk,
            write_counter: 0,
            read_counter: 0,
            status: ConnectionStatus::Connected,
        };

        self.sessions.insert(final_session_id.clone(), link);
        self.session_states.insert(final_session_id.clone(), state);

        Ok(final_session_id)
    }

    /// Accept a connection as a server (completes 3-step handshake).
    ///
    /// This processes the client's first message, completes the handshake,
    /// and returns both the response message to send back and the SessionId.
    ///
    /// # Arguments
    ///
    /// * `first_msg` - The first handshake message from the client.
    ///
    /// # Returns
    ///
    /// A tuple of (SessionId, response message to send back to client).
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use pubky_noise::{NoiseServer, DummyRing, mobile_manager::{NoiseManager, MobileConfig}};
    /// # use std::sync::Arc;
    /// # fn example(client_msg: Vec<u8>) -> Result<(), pubky_noise::NoiseError> {
    /// # let ring = Arc::new(DummyRing::new([2u8; 32], "kid"));
    /// # let server = Arc::new(NoiseServer::<_, ()>::new_direct("kid", b"device-id", ring));
    /// let mut manager = NoiseManager::new_server(server, MobileConfig::default());
    ///
    /// // Receive client's first handshake message
    /// let (session_id, response) = manager.accept_connection(&client_msg)?;
    ///
    /// // Send response back to client over your transport
    /// // Session is now established and ready to use
    /// # Ok(())
    /// # }
    /// ```
    pub fn accept_connection(
        &mut self,
        first_msg: &[u8],
    ) -> Result<(SessionId, Vec<u8>), NoiseError> {
        let server = self
            .server
            .as_ref()
            .ok_or_else(|| NoiseError::Other("Not in server mode".to_string()))?;

        // Step 2: Accept client's message and prepare response
        let (hs, _identity, response) =
            crate::datalink_adapter::server_accept_ik(server, first_msg)?;

        // Step 3: Complete handshake to get NoiseLink
        let link = crate::datalink_adapter::server_complete_ik(hs)?;
        let session_id = link.session_id().clone();

        // Store session and state
        let state = SessionState {
            session_id: session_id.clone(),
            peer_static_pk: [0u8; 32], // Not available in server mode
            write_counter: 0,
            read_counter: 0,
            status: ConnectionStatus::Connected,
        };

        self.sessions.insert(session_id.clone(), link);
        self.session_states.insert(session_id.clone(), state);

        Ok((session_id, response))
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
    pub fn encrypt(
        &mut self,
        session_id: &SessionId,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, NoiseError> {
        self.sessions
            .get_mut(session_id)
            .ok_or_else(|| NoiseError::Other("Session not found".to_string()))?
            .encrypt(plaintext)
    }

    /// Decrypt data using a specific session
    pub fn decrypt(
        &mut self,
        session_id: &SessionId,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, NoiseError> {
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
        public_client: pubky::PublicStorage,
        write_path: String,
        read_path: String,
    ) -> Result<StorageBackedMessaging, NoiseError> {
        let link = self
            .sessions
            .remove(session_id)
            .ok_or_else(|| NoiseError::Other("Session not found".to_string()))?;

        let state = self
            .session_states
            .get(session_id)
            .ok_or_else(|| NoiseError::Other("Session state not found".to_string()))?;

        let messaging =
            StorageBackedMessaging::new(link, session, public_client, write_path, read_path)?;

        // Configure with retry settings appropriate for mobile
        let retry_config = RetryConfig {
            max_retries: if self.config.battery_saver { 2 } else { 3 },
            initial_backoff_ms: 200,
            max_backoff_ms: if self.config.battery_saver {
                3000
            } else {
                5000
            },
            operation_timeout_ms: 30000,
        };

        let messaging = messaging
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
