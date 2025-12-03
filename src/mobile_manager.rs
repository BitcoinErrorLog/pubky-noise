//! Mobile-optimized Noise session manager with lifecycle management
//!
//! This module provides a high-level API specifically designed for mobile applications
//! that need to manage Noise sessions with proper lifecycle handling, state persistence,
//! and automatic reconnection.
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
use crate::{NoiseClient, NoiseError, NoiseServer, NoiseSession, RingKeyProvider, SessionId};
use crate::{NoiseReceiver, NoiseSender};
use snow::HandshakeState;
use std::collections::HashMap;
use std::sync::Arc;
use zeroize::Zeroizing;

#[cfg(feature = "storage-queue")]
use crate::storage_queue::{RetryConfig, StorageBackedMessaging};

/// Noise handshake pattern selection for different authentication scenarios.
///
/// # Pattern Guide
///
/// | Pattern | Use Case | Identity Binding |
/// |---------|----------|------------------|
/// | `IK` | Hot keys, real-time sessions | In handshake (Ed25519 signature) |
/// | `IKRaw` | Cold keys + pkarr | Via pkarr (pre-signed) |
/// | `N` | Anonymous client, known server | Server only (via pkarr) |
/// | `NN` | Post-handshake auth | External (application layer) |
/// | `XX` | Trust-on-first-use | Both parties during handshake |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoisePattern {
    /// IK pattern with identity binding in handshake.
    /// Requires Ed25519 signing at handshake time.
    IK,
    /// IK pattern without identity binding.
    /// Use when identity is verified via pkarr.
    IKRaw,
    /// N pattern: anonymous initiator, authenticated responder.
    /// Server identity verified via pkarr.
    N,
    /// NN pattern: both parties anonymous.
    /// Use post-handshake attestation for identity.
    NN,
    /// XX pattern: Trust-On-First-Use.
    /// Both parties exchange static keys during handshake.
    XX,
}

/// Connection status for a Noise session
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    feature = "storage-queue",
    derive(serde::Serialize, serde::Deserialize)
)]
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
#[cfg_attr(
    feature = "storage-queue",
    derive(serde::Serialize, serde::Deserialize)
)]
#[derive(Debug, Clone)]
pub struct SessionState {
    /// Session identifier
    pub session_id: SessionId,
    /// Peer's public key (for reconnection)
    pub peer_static_pk: [u8; 32],
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
/// # fn example() -> Result<(), pubky_noise::NoiseError> {
/// let ring = Arc::new(DummyRing::new([1u8; 32], "kid"));
/// let client = Arc::new(NoiseClient::<_>::new_direct("kid", b"device-id", ring));
///
/// let mut manager = NoiseManager::new_client(client, MobileConfig::default());
///
/// // Step 1: Initiate connection
/// let server_pk = [0u8; 32]; // Get from server
/// let (temp_id, first_msg) = manager.initiate_connection(&server_pk)?;
///
/// // Step 2: Send first_msg to server, receive response (app's responsibility)
/// // let response = send_to_server(&first_msg)?;
///
/// // Step 3: Complete handshake
/// // let session_id = manager.complete_connection(&temp_id, &response)?;
///
/// // Save state for persistence
/// // let state = manager.save_state(&session_id)?;
/// // ... save state to disk ...
///
/// // Later, restore state
/// // manager.restore_state(state)?;
/// # Ok(())
/// # }
/// ```
pub struct NoiseManager<R: RingKeyProvider> {
    client: Option<Arc<NoiseClient<R>>>,
    server: Option<Arc<NoiseServer<R>>>,
    sessions: HashMap<SessionId, NoiseSession>,
    session_states: HashMap<SessionId, SessionState>,
    /// Pending client handshakes (temporary SessionId -> HandshakeState + server_pk)
    pending_handshakes: HashMap<SessionId, (HandshakeState, [u8; 32])>,
    config: MobileConfig,
}

impl<R: RingKeyProvider> NoiseManager<R> {
    /// Create a new manager for client role
    pub fn new_client(client: Arc<NoiseClient<R>>, config: MobileConfig) -> Self {
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
    pub fn new_server(server: Arc<NoiseServer<R>>, config: MobileConfig) -> Self {
        Self {
            client: None,
            server: Some(server),
            sessions: HashMap::new(),
            session_states: HashMap::new(),
            pending_handshakes: HashMap::new(),
            config,
        }
    }

    /// Initiate a client connection (Step 1 of 3-step handshake)
    ///
    /// This starts the handshake and returns the first message to send to the server.
    ///
    /// # Returns
    /// - `SessionId`: Temporary ID for tracking this pending handshake
    /// - `Vec<u8>`: First handshake message to send to server
    ///
    /// # Example
    /// ```no_run
    /// # use pubky_noise::{NoiseClient, DummyRing, mobile_manager::{NoiseManager, MobileConfig}};
    /// # use std::sync::Arc;
    /// # fn example() -> Result<(), pubky_noise::NoiseError> {
    /// # let ring = Arc::new(DummyRing::new([1u8; 32], "kid"));
    /// # let client = Arc::new(NoiseClient::<_>::new_direct("kid", b"device-id", ring));
    /// let mut manager = NoiseManager::new_client(client, MobileConfig::default());
    ///
    /// let server_pk = [0u8; 32]; // Server's public key
    /// let (session_id, first_msg) = manager.initiate_connection(&server_pk)?;
    ///
    /// // Send first_msg to server over your transport...
    /// // Then receive server response and call complete_connection()
    /// # Ok(())
    /// # }
    /// ```
    pub fn initiate_connection(
        &mut self,
        server_static_pk: &[u8; 32],
    ) -> Result<(SessionId, Vec<u8>), NoiseError> {
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| NoiseError::Other("Not in client mode".to_string()))?;

        // Step 1: Start handshake
        let (hs, first_msg) = client_start_ik_direct(client, server_static_pk)?;

        // Generate temporary session ID for tracking
        let temp_session_id = SessionId::from_handshake(&hs)?;

        // Store pending handshake
        self.pending_handshakes
            .insert(temp_session_id.clone(), (hs, *server_static_pk));

        Ok((temp_session_id, first_msg))
    }

    /// Complete a client connection (Step 3 of 3-step handshake)
    ///
    /// Call this after receiving the server's response to complete the handshake.
    ///
    /// # Arguments
    /// - `session_id`: The temporary SessionId returned from `initiate_connection()`
    /// - `server_response`: The handshake response message from the server
    ///
    /// # Returns
    /// The final `SessionId` for the established session
    ///
    /// # Example
    /// ```no_run
    /// # use pubky_noise::{NoiseClient, DummyRing, mobile_manager::{NoiseManager, MobileConfig}, SessionId};
    /// # use std::sync::Arc;
    /// # fn example(temp_id: SessionId, response: Vec<u8>) -> Result<(), pubky_noise::NoiseError> {
    /// # let ring = Arc::new(DummyRing::new([1u8; 32], "kid"));
    /// # let client = Arc::new(NoiseClient::<_>::new_direct("kid", b"device-id", ring));
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

    /// Accept a connection as a server (completes 3-step handshake)
    ///
    /// This processes the client's first message, completes the handshake,
    /// and returns both the response message to send back and the SessionId.
    ///
    /// # Returns
    /// - `SessionId`: ID for the newly established session
    /// - `Vec<u8>`: Response message to send back to client
    ///
    /// # Example
    /// ```no_run
    /// # use pubky_noise::{NoiseServer, DummyRing, mobile_manager::{NoiseManager, MobileConfig}};
    /// # use std::sync::Arc;
    /// # fn example(client_msg: Vec<u8>) -> Result<(), pubky_noise::NoiseError> {
    /// # let ring = Arc::new(DummyRing::new([2u8; 32], "kid"));
    /// # let server = Arc::new(NoiseServer::<_>::new_direct("kid", b"device-id", ring));
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
        #[allow(deprecated)]
        let (hs, _identity, response) =
            crate::datalink_adapter::server_accept_ik(server, first_msg)?;

        // Step 3: Complete handshake to get NoiseSession
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
    pub fn get_session(&self, session_id: &SessionId) -> Option<&NoiseSession> {
        self.sessions.get(session_id)
    }

    /// Get a mutable session link
    pub fn get_session_mut(&mut self, session_id: &SessionId) -> Option<&mut NoiseSession> {
        self.sessions.get_mut(session_id)
    }

    /// Remove a session
    pub fn remove_session(&mut self, session_id: &SessionId) -> Option<NoiseSession> {
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

// ========== RAW KEY / COLD KEY PATTERN SUPPORT ==========

/// Raw-key Noise manager for cold key scenarios.
///
/// This manager uses `NoiseSender` and `NoiseReceiver` directly with raw X25519 keys,
/// supporting cold Ed25519 key architectures where identity binding is provided via pkarr.
pub struct RawNoiseManager {
    sender: NoiseSender,
    receiver: NoiseReceiver,
    sessions: HashMap<SessionId, NoiseSession>,
    session_states: HashMap<SessionId, SessionState>,
    pending_handshakes: HashMap<SessionId, (HandshakeState, Option<[u8; 32]>)>,
    /// Configuration for mobile-optimized behavior (reserved for future use)
    #[allow(dead_code)]
    config: MobileConfig,
}

impl RawNoiseManager {
    /// Create a new raw-key manager with default settings.
    pub fn new(config: MobileConfig) -> Self {
        Self {
            sender: NoiseSender::new(),
            receiver: NoiseReceiver::new(),
            sessions: HashMap::new(),
            session_states: HashMap::new(),
            pending_handshakes: HashMap::new(),
            config,
        }
    }

    /// Initiate a connection with pattern selection.
    ///
    /// # Arguments
    ///
    /// * `local_x25519_sk` - Your X25519 secret key (required for IKRaw, XX patterns).
    /// * `server_static_pk` - Server's static X25519 key (required for IKRaw, N patterns).
    /// * `pattern` - The Noise pattern to use.
    ///
    /// # Returns
    ///
    /// Returns `Ok((session_id, first_message))` on success.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use pubky_noise::mobile_manager::{RawNoiseManager, NoisePattern, MobileConfig};
    /// use pubky_noise::kdf;
    /// use zeroize::Zeroizing;
    ///
    /// # fn main() -> Result<(), pubky_noise::NoiseError> {
    /// let mut manager = RawNoiseManager::new(MobileConfig::default());
    ///
    /// // Cold key scenario: use IKRaw with pkarr-authenticated server key
    /// let server_pk = [0u8; 32]; // From pkarr lookup
    /// let x25519_sk = Zeroizing::new(kdf::derive_x25519_static(&[0u8; 32], b"device"));
    ///
    /// let (session_id, first_msg) = manager.initiate_connection_with_pattern(
    ///     Some(&x25519_sk),
    ///     Some(&server_pk),
    ///     NoisePattern::IKRaw,
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn initiate_connection_with_pattern(
        &mut self,
        local_x25519_sk: Option<&Zeroizing<[u8; 32]>>,
        server_static_pk: Option<&[u8; 32]>,
        pattern: NoisePattern,
    ) -> Result<(SessionId, Vec<u8>), NoiseError> {
        let (hs, first_msg) = match pattern {
            NoisePattern::IK => {
                return Err(NoiseError::Other(
                    "IK pattern requires identity binding - use NoiseManager with Ring instead"
                        .to_string(),
                ));
            }
            NoisePattern::IKRaw => {
                let sk = local_x25519_sk.ok_or_else(|| {
                    NoiseError::Other("IKRaw pattern requires local_x25519_sk".to_string())
                })?;
                let server_pk = server_static_pk.ok_or_else(|| {
                    NoiseError::Other("IKRaw pattern requires server_static_pk".to_string())
                })?;
                self.sender.initiate_ik_raw(sk, server_pk)?
            }
            NoisePattern::N => {
                // N pattern is one-way: initiator sends, handshake complete immediately
                let server_pk = server_static_pk.ok_or_else(|| {
                    NoiseError::Other("N pattern requires server_static_pk".to_string())
                })?;
                let (hs, first_msg) = self.sender.initiate_n(server_pk)?;

                // N pattern completes immediately - transition to transport
                let session = NoiseSession::from_handshake(hs)?;
                let session_id = session.session_id().clone();

                let state = SessionState {
                    session_id: session_id.clone(),
                    peer_static_pk: *server_pk,
                    write_counter: 0,
                    read_counter: 0,
                    status: ConnectionStatus::Connected,
                };

                self.sessions.insert(session_id.clone(), session);
                self.session_states.insert(session_id.clone(), state);

                // Return immediately - no need to call complete_connection
                return Ok((session_id, first_msg));
            }
            NoisePattern::NN => self.sender.initiate_nn()?,
            NoisePattern::XX => {
                let sk = local_x25519_sk.ok_or_else(|| {
                    NoiseError::Other("XX pattern requires local_x25519_sk".to_string())
                })?;
                self.sender.initiate_xx(sk)?
            }
        };

        let temp_session_id = SessionId::from_handshake(&hs)?;

        self.pending_handshakes
            .insert(temp_session_id.clone(), (hs, server_static_pk.copied()));

        Ok((temp_session_id, first_msg))
    }

    /// Complete a client connection after receiving server response (2-message patterns).
    ///
    /// For IKRaw and NN patterns. For XX pattern, use `complete_connection_xx` instead.
    pub fn complete_connection(
        &mut self,
        session_id: &SessionId,
        server_response: &[u8],
    ) -> Result<SessionId, NoiseError> {
        let (hs, server_pk) = self
            .pending_handshakes
            .remove(session_id)
            .ok_or_else(|| NoiseError::Other("No pending handshake found".to_string()))?;

        let session = client_complete_ik(hs, server_response)?;
        let final_session_id = session.session_id().clone();

        let state = SessionState {
            session_id: final_session_id.clone(),
            peer_static_pk: server_pk.unwrap_or([0u8; 32]),
            write_counter: 0,
            read_counter: 0,
            status: ConnectionStatus::Connected,
        };

        self.sessions.insert(final_session_id.clone(), session);
        self.session_states.insert(final_session_id.clone(), state);

        Ok(final_session_id)
    }

    /// Complete an XX pattern client connection (3-message pattern).
    ///
    /// For XX pattern, after receiving the server's response:
    /// 1. Call this method with the response
    /// 2. Send the returned third message to the server
    /// 3. Session is now ready for use
    ///
    /// # Returns
    ///
    /// Returns `(session_id, third_message)` on success.
    pub fn complete_connection_xx(
        &mut self,
        session_id: &SessionId,
        server_response: &[u8],
    ) -> Result<(SessionId, Vec<u8>), NoiseError> {
        let (mut hs, server_pk) = self
            .pending_handshakes
            .remove(session_id)
            .ok_or_else(|| NoiseError::Other("No pending XX handshake found".to_string()))?;

        // Read server's response (ephemeral + static + DH)
        let mut buf = vec![0u8; server_response.len() + 256];
        let _n = hs.read_message(server_response, &mut buf)?;

        // Write third message (our static + DH)
        let mut third_msg = vec![0u8; 128];
        let n = hs.write_message(&[], &mut third_msg)?;
        third_msg.truncate(n);

        let session = NoiseSession::from_handshake(hs)?;
        let final_session_id = session.session_id().clone();

        let state = SessionState {
            session_id: final_session_id.clone(),
            peer_static_pk: server_pk.unwrap_or([0u8; 32]),
            write_counter: 0,
            read_counter: 0,
            status: ConnectionStatus::Connected,
        };

        self.sessions.insert(final_session_id.clone(), session);
        self.session_states.insert(final_session_id.clone(), state);

        Ok((final_session_id, third_msg))
    }

    /// Accept a connection with pattern selection (server role).
    ///
    /// # Arguments
    ///
    /// * `local_x25519_sk` - Your X25519 secret key (required for IKRaw, N patterns).
    /// * `first_msg` - The first handshake message from the client.
    /// * `pattern` - The Noise pattern to use.
    pub fn accept_connection_with_pattern(
        &mut self,
        local_x25519_sk: Option<&Zeroizing<[u8; 32]>>,
        first_msg: &[u8],
        pattern: NoisePattern,
    ) -> Result<(SessionId, Vec<u8>), NoiseError> {
        match pattern {
            NoisePattern::IK => Err(NoiseError::Other(
                "IK pattern requires identity verification - use NoiseManager with Ring"
                    .to_string(),
            )),
            NoisePattern::IKRaw => {
                let sk = local_x25519_sk.ok_or_else(|| {
                    NoiseError::Other("IKRaw pattern requires local_x25519_sk".to_string())
                })?;
                let (hs, response) = self.receiver.respond_ik_raw(sk, first_msg)?;
                self.finalize_accept(hs, response)
            }
            NoisePattern::N => {
                let sk = local_x25519_sk.ok_or_else(|| {
                    NoiseError::Other("N pattern requires local_x25519_sk".to_string())
                })?;
                let hs = self.receiver.respond_n(sk, first_msg)?;
                // N pattern completes in one message, no response needed
                self.finalize_accept(hs, vec![])
            }
            NoisePattern::NN => {
                let (hs, response) = self.receiver.respond_nn(first_msg)?;
                self.finalize_accept(hs, response)
            }
            NoisePattern::XX => {
                // XX is a 3-message pattern. After this, caller must:
                // 1. Send the response to client
                // 2. Receive third message from client
                // 3. Call complete_accept() with that message
                let sk = local_x25519_sk.ok_or_else(|| {
                    NoiseError::Other("XX pattern requires local_x25519_sk".to_string())
                })?;
                let (hs, response) = self.receiver.respond_xx(sk, first_msg)?;

                // Store pending handshake for XX 3rd message
                let temp_session_id = SessionId::from_handshake(&hs)?;
                self.pending_handshakes
                    .insert(temp_session_id.clone(), (hs, None));

                Ok((temp_session_id, response))
            }
        }
    }

    /// Finalize an accepted connection (for 2-message patterns).
    fn finalize_accept(
        &mut self,
        hs: HandshakeState,
        response: Vec<u8>,
    ) -> Result<(SessionId, Vec<u8>), NoiseError> {
        let session = NoiseSession::from_handshake(hs)?;
        let session_id = session.session_id().clone();

        let state = SessionState {
            session_id: session_id.clone(),
            peer_static_pk: [0u8; 32],
            write_counter: 0,
            read_counter: 0,
            status: ConnectionStatus::Connected,
        };

        self.sessions.insert(session_id.clone(), session);
        self.session_states.insert(session_id.clone(), state);

        Ok((session_id, response))
    }

    /// Complete an XX pattern accept (read third message).
    ///
    /// For XX pattern, after `accept_connection_with_pattern` returns,
    /// you must:
    /// 1. Send the response to the client
    /// 2. Receive the third handshake message from client
    /// 3. Call this method with that message
    pub fn complete_accept(
        &mut self,
        session_id: &SessionId,
        third_msg: &[u8],
    ) -> Result<SessionId, NoiseError> {
        let (mut hs, _) = self
            .pending_handshakes
            .remove(session_id)
            .ok_or_else(|| NoiseError::Other("No pending XX handshake found".to_string()))?;

        // Read third message (initiator's static key + DH)
        let mut buf = vec![0u8; third_msg.len() + 256];
        let _n = hs.read_message(third_msg, &mut buf)?;

        let session = NoiseSession::from_handshake(hs)?;
        let final_session_id = session.session_id().clone();

        let state = SessionState {
            session_id: final_session_id.clone(),
            peer_static_pk: [0u8; 32], // Could extract from handshake if needed
            write_counter: 0,
            read_counter: 0,
            status: ConnectionStatus::Connected,
        };

        self.sessions.insert(final_session_id.clone(), session);
        self.session_states.insert(final_session_id.clone(), state);

        Ok(final_session_id)
    }

    /// Get a session for encryption/decryption.
    pub fn get_session(&self, session_id: &SessionId) -> Option<&NoiseSession> {
        self.sessions.get(session_id)
    }

    /// Get a mutable session.
    pub fn get_session_mut(&mut self, session_id: &SessionId) -> Option<&mut NoiseSession> {
        self.sessions.get_mut(session_id)
    }

    /// Remove a session.
    pub fn remove_session(&mut self, session_id: &SessionId) -> Option<NoiseSession> {
        self.session_states.remove(session_id);
        self.sessions.remove(session_id)
    }

    /// List all active sessions.
    pub fn list_sessions(&self) -> Vec<SessionId> {
        self.sessions.keys().cloned().collect()
    }

    /// Encrypt data using a specific session.
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

    /// Decrypt data using a specific session.
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
        public_client: pubky::Pubky,
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

        let mut messaging =
            StorageBackedMessaging::new(link, session, public_client, write_path, read_path);

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
