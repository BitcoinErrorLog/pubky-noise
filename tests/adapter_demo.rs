//! Adapter and Streaming Tests / Examples
//!
//! This file demonstrates comprehensive usage of the pubky-noise library,
//! serving both as integration tests and as example code.
//!
//! ## Features Demonstrated
//!
//! - Basic client/server setup
//! - Complete 3-step IK handshake
//! - XX pattern handshake (Trust On First Use)
//! - Streaming/chunking for large messages
//! - Session management
//! - Error handling patterns
//! - State persistence patterns
//! - Multiple session management
//!
//! ## Usage
//!
//! Run all tests: `cargo test --test adapter_demo`
//! Run specific test: `cargo test --test adapter_demo test_streaming_link`

use pubky_noise::datalink_adapter::{
    client_complete_ik, client_start_ik_direct, server_accept_ik, server_complete_ik,
};
use pubky_noise::*;
use std::sync::Arc;

// =============================================================================
// Basic Setup Tests
// =============================================================================

/// Test that basic client and server setup compiles correctly.
///
/// This demonstrates the minimal setup required to create Noise endpoints.
#[test]
fn adapter_smoke_compiles() {
    // Create ring providers with unique seeds for client and server
    // In production, these seeds come from secure key storage
    let ring_client = Arc::new(DummyRing::new([1u8; 32], "client-key-id"));
    let ring_server = Arc::new(DummyRing::new([2u8; 32], "server-key-id"));

    // Create client and server instances
    // The type parameters are:
    // - R: RingKeyProvider implementation
    // - P: Optional phantom type for PKARR (usually ())
    let _client = NoiseClient::<_, ()>::new_direct("client-key-id", b"device-client", ring_client);
    let _server = NoiseServer::<_, ()>::new_direct("server-key-id", b"device-server", ring_server);
}

// =============================================================================
// IK Pattern Handshake Tests
// =============================================================================

/// Test complete IK pattern handshake with encryption/decryption.
///
/// The IK pattern is used when the client knows the server's static key
/// in advance (e.g., from configuration or previous exchange).
///
/// Flow:
/// 1. Client initiates with server's static public key
/// 2. Server processes and responds
/// 3. Both complete handshake and establish transport
#[test]
fn test_ik_handshake_complete() {
    // Setup
    let ring_client = Arc::new(DummyRing::new([1u8; 32], "kid"));
    let ring_server = Arc::new(DummyRing::new([2u8; 32], "kid"));

    let client = NoiseClient::<_, ()>::new_direct("kid", b"dev-client", ring_client);
    let server = NoiseServer::<_, ()>::new_direct("kid", b"dev-server", ring_server.clone());

    // Get server's static public key
    // In production, this would be obtained through secure configuration
    let server_sk = ring_server
        .derive_device_x25519("kid", b"dev-server", 0)
        .unwrap();
    let server_static_pk = pubky_noise::kdf::x25519_pk_from_sk(&server_sk);

    // === 3-Step Handshake ===

    // Step 1: Client initiates
    // This creates the first handshake message containing encrypted identity
    let (c_hs, first_msg) = client_start_ik_direct(&client, &server_static_pk, None)
        .expect("Client should initiate successfully");

    // Step 2: Server accepts and responds
    // Server decrypts client identity and creates response
    let (s_hs, client_identity, response) =
        server_accept_ik(&server, &first_msg).expect("Server should accept successfully");

    // Verify client identity was received
    assert_eq!(client_identity.role, identity_payload::Role::Client);

    // Step 3: Both complete to get NoiseLink
    let mut c_link =
        client_complete_ik(c_hs, &response).expect("Client should complete successfully");
    let mut s_link = server_complete_ik(s_hs).expect("Server should complete successfully");

    // Verify session IDs match
    assert_eq!(c_link.session_id(), s_link.session_id());

    // === Test Encryption/Decryption ===

    // Client sends encrypted message to server
    let plaintext = b"Hello from client!";
    let ciphertext = c_link
        .encrypt(plaintext)
        .expect("Encryption should succeed");

    // Server decrypts
    let decrypted = s_link
        .decrypt(&ciphertext)
        .expect("Decryption should succeed");
    assert_eq!(plaintext.to_vec(), decrypted);

    // Server sends encrypted response to client
    let response_text = b"Hello from server!";
    let response_ct = s_link
        .encrypt(response_text)
        .expect("Encryption should succeed");
    let response_pt = c_link
        .decrypt(&response_ct)
        .expect("Decryption should succeed");
    assert_eq!(response_text.to_vec(), response_pt);
}

/// Test IK handshake with optional server hint.
///
/// Server hints can be used for routing or identification purposes.
#[test]
fn test_ik_handshake_with_hint() {
    let ring_client = Arc::new(DummyRing::new([1u8; 32], "kid"));
    let ring_server = Arc::new(DummyRing::new([2u8; 32], "kid"));

    let client = NoiseClient::<_, ()>::new_direct("kid", b"dev-client", ring_client);
    let server = NoiseServer::<_, ()>::new_direct("kid", b"dev-server", ring_server.clone());

    let server_sk = ring_server
        .derive_device_x25519("kid", b"dev-server", 0)
        .unwrap();
    let server_static_pk = pubky_noise::kdf::x25519_pk_from_sk(&server_sk);

    // Include a server hint for routing
    let server_hint = Some("production-server-01");

    let (c_hs, first_msg) = client_start_ik_direct(&client, &server_static_pk, server_hint)
        .expect("Should initiate with hint");

    let (s_hs, identity, response) = server_accept_ik(&server, &first_msg).unwrap();

    // Verify hint was received
    assert_eq!(identity.server_hint.as_deref(), server_hint);

    // Complete handshake
    let _c_link = client_complete_ik(c_hs, &response).unwrap();
    let _s_link = server_complete_ik(s_hs).unwrap();
}

// =============================================================================
// XX Pattern Handshake Tests (Trust On First Use)
// =============================================================================

/// Test XX pattern handshake (Trust On First Use).
///
/// The XX pattern is used when the client doesn't know the server's
/// static key in advance. The server's key is learned during handshake.
///
/// Use case: First-time connection to a new server
#[test]
fn test_xx_pattern_tofu() {
    let ring_client = Arc::new(DummyRing::new([1u8; 32], "kid"));
    let ring_server = Arc::new(DummyRing::new([2u8; 32], "kid"));

    let client = NoiseClient::<_, ()>::new_direct("kid", b"dev-client", ring_client);
    let _server = NoiseServer::<_, ()>::new_direct("kid", b"dev-server", ring_server);

    // XX pattern doesn't require server's static key upfront
    let result = client.build_initiator_xx_tofu(None);

    // Should succeed in creating the initial message
    assert!(result.is_ok(), "XX pattern initiation should succeed");

    let (hs, first_msg, _hint) = result.unwrap();

    // First message in XX is just an ephemeral key
    assert!(!first_msg.is_empty(), "First message should not be empty");

    // After handshake completes (not shown here), client would:
    // 1. Learn server's static public key
    // 2. Pin it for future IK connections
    // 3. Use IK pattern for subsequent connections

    // The handshake state can be used to extract the server's key later
    drop(hs);
}

// =============================================================================
// Streaming Tests
// =============================================================================

/// Test streaming/chunking for large messages.
///
/// The Noise protocol has a per-message size limit. StreamingNoiseLink
/// automatically splits large messages into chunks.
#[test]
fn test_streaming_link() {
    let ring_client = Arc::new(DummyRing::new([1u8; 32], "kid"));
    let ring_server = Arc::new(DummyRing::new([2u8; 32], "kid"));

    let client = NoiseClient::<_, ()>::new_direct("kid", b"dev-client", ring_client);
    let server = NoiseServer::<_, ()>::new_direct("kid", b"dev-server", ring_server.clone());

    let server_sk = ring_server
        .derive_device_x25519("kid", b"dev-server", 0)
        .unwrap();
    let server_static_pk = pubky_noise::kdf::x25519_pk_from_sk(&server_sk);

    // Complete handshake
    let (c_hs, first_msg) = client_start_ik_direct(&client, &server_static_pk, None).unwrap();
    let (s_hs, _, response) = server_accept_ik(&server, &first_msg).unwrap();
    let c_link = client_complete_ik(c_hs, &response).unwrap();
    let s_link = server_complete_ik(s_hs).unwrap();

    // Create streaming links with small chunk size for testing
    // In production, use larger chunks (e.g., 32KB for mobile)
    let mut c_stream = StreamingNoiseLink::new(c_link, 10);
    let mut s_stream = StreamingNoiseLink::new(s_link, 10);

    let data = b"This is a long message that should be split into chunks";

    // Encrypt - automatically splits into chunks
    let chunks = c_stream.encrypt_streaming(data).unwrap();
    assert!(chunks.len() > 1, "Should be split into multiple chunks");

    // Decrypt - automatically reassembles chunks
    let decrypted = s_stream.decrypt_streaming(&chunks).unwrap();
    assert_eq!(data.to_vec(), decrypted);
}

/// Test streaming with default mobile-friendly chunk size.
#[test]
fn test_streaming_default_chunk_size() {
    let ring_client = Arc::new(DummyRing::new([1u8; 32], "kid"));
    let ring_server = Arc::new(DummyRing::new([2u8; 32], "kid"));

    let client = NoiseClient::<_, ()>::new_direct("kid", b"dev-client", ring_client);
    let server = NoiseServer::<_, ()>::new_direct("kid", b"dev-server", ring_server.clone());

    let server_sk = ring_server
        .derive_device_x25519("kid", b"dev-server", 0)
        .unwrap();
    let server_static_pk = pubky_noise::kdf::x25519_pk_from_sk(&server_sk);

    let (c_hs, first_msg) = client_start_ik_direct(&client, &server_static_pk, None).unwrap();
    let (s_hs, _, response) = server_accept_ik(&server, &first_msg).unwrap();
    let c_link = client_complete_ik(c_hs, &response).unwrap();
    let s_link = server_complete_ik(s_hs).unwrap();

    // Use default chunk size (65536 bytes)
    let mut c_stream = StreamingNoiseLink::new_with_default_chunk_size(c_link);
    let mut s_stream = StreamingNoiseLink::new_with_default_chunk_size(s_link);

    // Test with a message smaller than chunk size
    let small_message = b"Small message that fits in one chunk";
    let chunks = c_stream.encrypt_streaming(small_message).unwrap();
    assert_eq!(chunks.len(), 1, "Small message should be one chunk");

    let decrypted = s_stream.decrypt_streaming(&chunks).unwrap();
    assert_eq!(small_message.to_vec(), decrypted);
}

// =============================================================================
// Session Management Tests
// =============================================================================

/// Test basic session manager functionality.
///
/// NoiseSessionManager allows managing multiple concurrent sessions.
#[test]
fn test_session_manager() {
    let ring_client = Arc::new(DummyRing::new([1u8; 32], "kid"));
    let ring_server = Arc::new(DummyRing::new([2u8; 32], "kid"));

    let client = Arc::new(NoiseClient::<_, ()>::new_direct(
        "kid",
        b"dev-client",
        ring_client,
    ));
    let server = Arc::new(NoiseServer::<_, ()>::new_direct(
        "kid",
        b"dev-server",
        ring_server.clone(),
    ));

    let mut client_manager = NoiseSessionManager::new_client(client.clone());
    let mut server_manager = NoiseSessionManager::new_server(server.clone());

    let server_sk = ring_server
        .derive_device_x25519("kid", b"dev-server", 0)
        .unwrap();
    let server_static_pk = pubky_noise::kdf::x25519_pk_from_sk(&server_sk);

    // Complete handshake
    let (c_hs, first_msg) = client_start_ik_direct(&client, &server_static_pk, None).unwrap();
    let (s_hs, _, response) = server_accept_ik(&server, &first_msg).unwrap();
    let c_link = client_complete_ik(c_hs, &response).unwrap();
    let s_link = server_complete_ik(s_hs).unwrap();

    let c_sid = c_link.session_id().clone();
    let s_sid = s_link.session_id().clone();

    // Session IDs should match on both sides
    assert_eq!(c_sid, s_sid);

    // Add sessions to managers
    client_manager.add_session(c_sid.clone(), c_link);
    server_manager.add_session(s_sid.clone(), s_link);

    // Verify sessions are tracked
    assert!(client_manager.get_session(&c_sid).is_some());
    assert!(server_manager.get_session(&s_sid).is_some());

    // List sessions
    assert_eq!(client_manager.list_sessions().len(), 1);
    assert_eq!(server_manager.list_sessions().len(), 1);

    // Remove session
    client_manager.remove_session(&c_sid);
    assert!(client_manager.get_session(&c_sid).is_none());
    assert_eq!(client_manager.list_sessions().len(), 0);
}

/// Test thread-safe session manager.
///
/// ThreadSafeSessionManager provides built-in thread safety using Mutex.
#[test]
fn test_thread_safe_session_manager() {
    let ring_client = Arc::new(DummyRing::new([1u8; 32], "kid"));
    let ring_server = Arc::new(DummyRing::new([2u8; 32], "kid"));

    let client = Arc::new(NoiseClient::<_, ()>::new_direct(
        "kid",
        b"dev-client",
        ring_client,
    ));
    let server = Arc::new(NoiseServer::<_, ()>::new_direct(
        "kid",
        b"dev-server",
        ring_server.clone(),
    ));

    // Use thread-safe manager
    let manager = ThreadSafeSessionManager::new_client(client.clone());

    let server_sk = ring_server
        .derive_device_x25519("kid", b"dev-server", 0)
        .unwrap();
    let server_static_pk = pubky_noise::kdf::x25519_pk_from_sk(&server_sk);

    // Complete handshake
    let (c_hs, first_msg) = client_start_ik_direct(&client, &server_static_pk, None).unwrap();
    let (s_hs, _, response) = server_accept_ik(&server, &first_msg).unwrap();
    let c_link = client_complete_ik(c_hs, &response).unwrap();
    let _s_link = server_complete_ik(s_hs).unwrap();

    let session_id = c_link.session_id().clone();
    manager.add_session(session_id.clone(), c_link);

    // Clone manager for use in another thread
    let manager_clone = manager.clone();
    let sid_clone = session_id.clone();

    // Access from another thread
    let handle = std::thread::spawn(move || {
        // Thread-safe access
        assert!(manager_clone.has_session(&sid_clone));

        // Encrypt from background thread
        manager_clone.encrypt(&sid_clone, b"background data")
    });

    // Access from main thread
    assert!(manager.has_session(&session_id));

    // Wait for background thread
    let result = handle.join().unwrap();
    assert!(
        result.is_ok(),
        "Encryption from background thread should succeed"
    );
}

// =============================================================================
// Error Handling Tests
// =============================================================================

/// Test error handling for invalid peer key.
///
/// An all-zero public key would result in an all-zero shared secret,
/// which is a security vulnerability. The library rejects such keys.
#[test]
fn test_error_invalid_peer_key() {
    let ring_client = Arc::new(DummyRing::new([1u8; 32], "kid"));
    let client = NoiseClient::<_, ()>::new_direct("kid", b"dev-client", ring_client);

    // All-zero key is invalid (would produce zero shared secret)
    let invalid_server_pk = [0u8; 32];

    let result = client_start_ik_direct(&client, &invalid_server_pk, None);

    // Should fail with InvalidPeerKey error
    assert!(result.is_err());
    match result {
        Err(NoiseError::InvalidPeerKey) => {
            // Expected error
        }
        Err(e) => panic!("Expected InvalidPeerKey, got: {:?}", e),
        Ok(_) => panic!("Should have failed with invalid peer key"),
    }
}

/// Test error handling patterns.
///
/// Demonstrates proper error handling for various failure scenarios.
#[test]
fn test_error_handling_patterns() {
    let ring_client = Arc::new(DummyRing::new([1u8; 32], "kid"));
    let ring_server = Arc::new(DummyRing::new([2u8; 32], "kid"));

    let client = NoiseClient::<_, ()>::new_direct("kid", b"dev-client", ring_client);
    let server = NoiseServer::<_, ()>::new_direct("kid", b"dev-server", ring_server.clone());

    let server_sk = ring_server
        .derive_device_x25519("kid", b"dev-server", 0)
        .unwrap();
    let server_static_pk = pubky_noise::kdf::x25519_pk_from_sk(&server_sk);

    // Successful handshake
    let (c_hs, first_msg) = client_start_ik_direct(&client, &server_static_pk, None).unwrap();
    let (s_hs, _, response) = server_accept_ik(&server, &first_msg).unwrap();
    let c_link = client_complete_ik(c_hs, &response).unwrap();
    let mut s_link = server_complete_ik(s_hs).unwrap();

    // Test decryption with corrupted data
    let corrupted_data = vec![0u8; 64]; // Random bytes, not valid ciphertext
    let decrypt_result = s_link.decrypt(&corrupted_data);

    // Should fail with decryption error
    assert!(decrypt_result.is_err());
    if let Err(e) = decrypt_result {
        // Use error code for FFI/mobile integration
        let code = e.code();
        assert_eq!(code, NoiseErrorCode::Snow); // Decryption errors come from Snow

        // Use error message for logging
        let message = e.message();
        assert!(!message.is_empty());
    }

    // Clean usage with Result handling
    let _c_link = c_link; // Keep for demonstration
}

/// Test NoiseError code mapping.
///
/// Error codes are designed for FFI/mobile integration where
/// you need stable numeric codes for error handling.
#[test]
fn test_error_codes() {
    // Test all error variants have correct codes
    assert_eq!(NoiseError::Ring("test".into()).code(), NoiseErrorCode::Ring);
    assert_eq!(
        NoiseError::Pkarr("test".into()).code(),
        NoiseErrorCode::Pkarr
    );
    assert_eq!(NoiseError::Snow("test".into()).code(), NoiseErrorCode::Snow);
    assert_eq!(
        NoiseError::Serde("test".into()).code(),
        NoiseErrorCode::Serde
    );
    assert_eq!(
        NoiseError::IdentityVerify.code(),
        NoiseErrorCode::IdentityVerify
    );
    assert_eq!(
        NoiseError::RemoteStaticMissing.code(),
        NoiseErrorCode::RemoteStaticMissing
    );
    assert_eq!(
        NoiseError::Policy("test".into()).code(),
        NoiseErrorCode::Policy
    );
    assert_eq!(
        NoiseError::InvalidPeerKey.code(),
        NoiseErrorCode::InvalidPeerKey
    );
    assert_eq!(
        NoiseError::Network("test".into()).code(),
        NoiseErrorCode::Network
    );
    assert_eq!(
        NoiseError::Timeout("test".into()).code(),
        NoiseErrorCode::Timeout
    );
    assert_eq!(
        NoiseError::Storage("test".into()).code(),
        NoiseErrorCode::Storage
    );
    assert_eq!(
        NoiseError::Decryption("test".into()).code(),
        NoiseErrorCode::Decryption
    );
    assert_eq!(
        NoiseError::Other("test".into()).code(),
        NoiseErrorCode::Other
    );

    // Test error message extraction
    let err = NoiseError::Network("connection refused".into());
    let msg = err.message();
    assert!(msg.contains("network error"));
    assert!(msg.contains("connection refused"));
}

// =============================================================================
// Mobile Manager Tests
// =============================================================================

/// Test mobile-optimized NoiseManager.
///
/// NoiseManager provides a high-level API specifically designed for
/// mobile applications with lifecycle management and state persistence.
#[test]
fn test_mobile_manager_basic() {
    let ring_client = Arc::new(DummyRing::new([1u8; 32], "kid"));
    let ring_server = Arc::new(DummyRing::new([2u8; 32], "kid"));

    let client = Arc::new(NoiseClient::<_, ()>::new_direct(
        "kid",
        b"dev-client",
        ring_client,
    ));
    let server = Arc::new(NoiseServer::<_, ()>::new_direct(
        "kid",
        b"dev-server",
        ring_server.clone(),
    ));

    // Configure for mobile use
    let config = MobileConfig {
        auto_reconnect: true,
        max_reconnect_attempts: 3,
        reconnect_delay_ms: 500,
        battery_saver: false,
        chunk_size: 32768, // 32KB for mobile
    };

    let mut client_manager = NoiseManager::new_client(client, config.clone());
    let mut server_manager = NoiseManager::new_server(server, config);

    let server_sk = ring_server
        .derive_device_x25519("kid", b"dev-server", 0)
        .unwrap();
    let server_static_pk = pubky_noise::kdf::x25519_pk_from_sk(&server_sk);

    // 3-step handshake using NoiseManager API
    // Step 1: Client initiates
    let (temp_id, first_msg) = client_manager
        .initiate_connection(&server_static_pk, None)
        .expect("Initiation should succeed");

    // Step 2: Server accepts
    let (_server_sid, response) = server_manager
        .accept_connection(&first_msg)
        .expect("Accept should succeed");

    // Step 3: Client completes
    let session_id = client_manager
        .complete_connection(&temp_id, &response)
        .expect("Completion should succeed");

    // Verify session is active
    assert!(client_manager.get_session(&session_id).is_some());
    assert_eq!(
        client_manager.get_status(&session_id),
        Some(ConnectionStatus::Connected)
    );
}

/// Test state persistence with NoiseManager.
///
/// State can be saved before app suspension and restored on resume.
#[test]
fn test_mobile_manager_state_persistence() {
    let ring_client = Arc::new(DummyRing::new([1u8; 32], "kid"));
    let ring_server = Arc::new(DummyRing::new([2u8; 32], "kid"));

    let client = Arc::new(NoiseClient::<_, ()>::new_direct(
        "kid",
        b"dev-client",
        ring_client.clone(),
    ));
    let server = Arc::new(NoiseServer::<_, ()>::new_direct(
        "kid",
        b"dev-server",
        ring_server.clone(),
    ));

    let config = MobileConfig::default();
    let mut client_manager = NoiseManager::new_client(client, config.clone());
    let mut server_manager = NoiseManager::new_server(server, config.clone());

    let server_sk = ring_server
        .derive_device_x25519("kid", b"dev-server", 0)
        .unwrap();
    let server_static_pk = pubky_noise::kdf::x25519_pk_from_sk(&server_sk);

    // Establish session
    let (temp_id, first_msg) = client_manager
        .initiate_connection(&server_static_pk, None)
        .unwrap();
    let (_, response) = server_manager.accept_connection(&first_msg).unwrap();
    let session_id = client_manager
        .complete_connection(&temp_id, &response)
        .unwrap();

    // === Save State (before app suspension) ===
    let saved_state = client_manager
        .save_state(&session_id)
        .expect("State save should succeed");

    // Verify saved state
    assert_eq!(saved_state.session_id, session_id);
    assert_eq!(saved_state.status, ConnectionStatus::Connected);
    assert_eq!(saved_state.write_counter, 0);
    assert_eq!(saved_state.read_counter, 0);

    // === Restore State (after app resume) ===
    // Simulate creating a new manager instance after app restart
    let client2 = Arc::new(NoiseClient::<_, ()>::new_direct(
        "kid",
        b"dev-client",
        ring_client,
    ));
    let mut new_manager = NoiseManager::new_client(client2, config);

    // Restore the saved state
    new_manager
        .restore_state(saved_state)
        .expect("State restore should succeed");

    // Verify state was restored
    assert_eq!(
        new_manager.get_status(&session_id),
        Some(ConnectionStatus::Connected)
    );
}

/// Test connection status tracking.
#[test]
fn test_connection_status_tracking() {
    let ring_client = Arc::new(DummyRing::new([1u8; 32], "kid"));
    let ring_server = Arc::new(DummyRing::new([2u8; 32], "kid"));

    let client = Arc::new(NoiseClient::<_, ()>::new_direct(
        "kid",
        b"dev-client",
        ring_client,
    ));
    let server = Arc::new(NoiseServer::<_, ()>::new_direct(
        "kid",
        b"dev-server",
        ring_server.clone(),
    ));

    let config = MobileConfig::default();
    let mut client_manager = NoiseManager::new_client(client, config.clone());
    let mut server_manager = NoiseManager::new_server(server, config);

    let server_sk = ring_server
        .derive_device_x25519("kid", b"dev-server", 0)
        .unwrap();
    let server_static_pk = pubky_noise::kdf::x25519_pk_from_sk(&server_sk);

    // Establish session
    let (temp_id, first_msg) = client_manager
        .initiate_connection(&server_static_pk, None)
        .unwrap();
    let (_, response) = server_manager.accept_connection(&first_msg).unwrap();
    let session_id = client_manager
        .complete_connection(&temp_id, &response)
        .unwrap();

    // Initial status should be Connected
    assert_eq!(
        client_manager.get_status(&session_id),
        Some(ConnectionStatus::Connected)
    );

    // Simulate network disconnection
    client_manager.set_status(&session_id, ConnectionStatus::Disconnected);
    assert_eq!(
        client_manager.get_status(&session_id),
        Some(ConnectionStatus::Disconnected)
    );

    // Simulate reconnection attempt
    client_manager.set_status(&session_id, ConnectionStatus::Reconnecting);
    assert_eq!(
        client_manager.get_status(&session_id),
        Some(ConnectionStatus::Reconnecting)
    );

    // Simulate reconnection success
    client_manager.set_status(&session_id, ConnectionStatus::Connected);
    assert_eq!(
        client_manager.get_status(&session_id),
        Some(ConnectionStatus::Connected)
    );
}

// =============================================================================
// Multiple Sessions Test
// =============================================================================

/// Test managing multiple concurrent sessions.
#[test]
fn test_multiple_sessions() {
    let ring_client = Arc::new(DummyRing::new([1u8; 32], "kid"));
    let ring_server1 = Arc::new(DummyRing::new([2u8; 32], "server1"));
    let ring_server2 = Arc::new(DummyRing::new([3u8; 32], "server2"));

    let client = Arc::new(NoiseClient::<_, ()>::new_direct(
        "kid",
        b"dev-client",
        ring_client,
    ));
    let server1 = Arc::new(NoiseServer::<_, ()>::new_direct(
        "server1",
        b"server1",
        ring_server1.clone(),
    ));
    let server2 = Arc::new(NoiseServer::<_, ()>::new_direct(
        "server2",
        b"server2",
        ring_server2.clone(),
    ));

    let config = MobileConfig::default();
    let mut client_manager = NoiseManager::new_client(client.clone(), config.clone());
    let mut server1_manager = NoiseManager::new_server(server1, config.clone());
    let mut server2_manager = NoiseManager::new_server(server2, config);

    // Get server public keys
    let server1_sk = ring_server1
        .derive_device_x25519("server1", b"server1", 0)
        .unwrap();
    let server1_pk = pubky_noise::kdf::x25519_pk_from_sk(&server1_sk);

    let server2_sk = ring_server2
        .derive_device_x25519("server2", b"server2", 0)
        .unwrap();
    let server2_pk = pubky_noise::kdf::x25519_pk_from_sk(&server2_sk);

    // Establish session with server1
    let (temp1, msg1) = client_manager
        .initiate_connection(&server1_pk, None)
        .unwrap();
    let (_, resp1) = server1_manager.accept_connection(&msg1).unwrap();
    let sid1 = client_manager.complete_connection(&temp1, &resp1).unwrap();

    // Establish session with server2
    let (temp2, msg2) = client_manager
        .initiate_connection(&server2_pk, None)
        .unwrap();
    let (_, resp2) = server2_manager.accept_connection(&msg2).unwrap();
    let sid2 = client_manager.complete_connection(&temp2, &resp2).unwrap();

    // Both sessions should be active
    let sessions = client_manager.list_sessions();
    assert_eq!(sessions.len(), 2);
    assert!(sessions.contains(&sid1));
    assert!(sessions.contains(&sid2));

    // Encrypt with different sessions produces different ciphertexts
    let data = b"test message";
    let ct1 = client_manager.encrypt(&sid1, data).unwrap();
    let ct2 = client_manager.encrypt(&sid2, data).unwrap();
    assert_ne!(
        ct1, ct2,
        "Different sessions should produce different ciphertexts"
    );

    // Remove one session
    client_manager.remove_session(&sid1);
    let remaining = client_manager.list_sessions();
    assert_eq!(remaining.len(), 1);
    assert!(!remaining.contains(&sid1));
    assert!(remaining.contains(&sid2));
}

// =============================================================================
// Configuration Tests
// =============================================================================

/// Test different mobile configuration presets.
#[test]
fn test_mobile_config_presets() {
    // Default config
    let default = MobileConfig::default();
    assert!(default.auto_reconnect);
    assert_eq!(default.chunk_size, 32768);

    // Battery saver config
    let battery_saver = MobileConfig {
        auto_reconnect: false, // Reduce background activity
        max_reconnect_attempts: 1,
        reconnect_delay_ms: 2000, // Longer delay
        battery_saver: true,
        chunk_size: 16384, // Smaller chunks
    };
    assert!(battery_saver.battery_saver);

    // Performance config
    let performance = MobileConfig {
        auto_reconnect: true,
        max_reconnect_attempts: 10,
        reconnect_delay_ms: 100, // Quick retry
        battery_saver: false,
        chunk_size: 65536, // Larger chunks
    };
    assert!(!performance.battery_saver);
    assert_eq!(performance.chunk_size, 65536);
}
