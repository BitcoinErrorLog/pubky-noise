//! Mobile integration tests and examples
//!
//! These tests verify the mobile-optimized session management features,
//! including state persistence, thread-safety, and configuration options.

use pubky_noise::datalink_adapter::{
    client_complete_ik, client_start_ik_direct, server_accept_ik, server_complete_ik,
};
use pubky_noise::*;
use std::sync::Arc;

#[test]
fn test_mobile_lifecycle() {
    // Setup: Create client and server with ring providers
    let ring_client = Arc::new(DummyRing::new([1u8; 32], "client-kid"));
    let ring_server = Arc::new(DummyRing::new([2u8; 32], "server-kid"));

    let client = Arc::new(NoiseClient::<_>::new_direct(
        "client-kid",
        b"mobile-device-123",
        ring_client,
    ));

    let server = Arc::new(NoiseServer::<_>::new_direct(
        "server-kid",
        b"server-device",
        ring_server.clone(),
    ));

    // Create mobile manager
    let config = MobileConfig {
        auto_reconnect: true,
        max_reconnect_attempts: 3,
        reconnect_delay_ms: 500,
        battery_saver: false,
        chunk_size: 32768,
    };

    let mut client_manager = NoiseManager::new_client(client, config.clone());
    let mut server_manager = NoiseManager::new_server(server, config);

    // Get server's public key
    let server_sk = ring_server
        .derive_device_x25519("server-kid", b"server-device")
        .unwrap();
    let server_static_pk = pubky_noise::kdf::x25519_pk_from_sk(&server_sk);

    // 3-step handshake using mobile_manager API
    // Step 1: Client initiates
    let (session_id, first_msg) = client_manager
        .initiate_connection(&server_static_pk)
        .unwrap();

    // Step 2: Server accepts and responds
    let (_server_session_id, response_msg) = server_manager.accept_connection(&first_msg).unwrap();

    // Step 3: Client completes
    let session_id = client_manager
        .complete_connection(&session_id, &response_msg)
        .unwrap();

    // Save state (simulate app suspension)
    let saved_state = client_manager.save_state(&session_id).unwrap();
    assert_eq!(saved_state.session_id, session_id);
    assert_eq!(saved_state.status, ConnectionStatus::Connected);

    // Serialize state (for persistence)
    #[cfg(feature = "storage-queue")]
    {
        let json = serde_json::to_string(&saved_state).unwrap();
        let restored_state: SessionState = serde_json::from_str(&json).unwrap();
        assert_eq!(restored_state.session_id, session_id);
    }

    // Simulate app resume - restore state
    let ring_client2 = Arc::new(DummyRing::new([1u8; 32], "client-kid"));
    let client2 = Arc::new(NoiseClient::<_>::new_direct(
        "client-kid",
        b"mobile-device-123",
        ring_client2,
    ));
    let mut new_manager = NoiseManager::new_client(client2, MobileConfig::default());

    new_manager.restore_state(saved_state).unwrap();

    // Verify state was restored
    assert_eq!(
        new_manager.get_status(&session_id),
        Some(ConnectionStatus::Connected)
    );
}

#[test]
fn test_session_id_serialization() {
    let ring_client = Arc::new(DummyRing::new([1u8; 32], "kid"));
    let ring_server = Arc::new(DummyRing::new([2u8; 32], "kid"));

    let client = Arc::new(NoiseClient::<_>::new_direct(
        "kid",
        b"dev-client",
        ring_client,
    ));
    let server = Arc::new(NoiseServer::<_>::new_direct(
        "kid",
        b"dev-server",
        ring_server.clone(),
    ));

    // Perform 3-step handshake
    let server_sk = ring_server
        .derive_device_x25519("kid", b"dev-server")
        .unwrap();
    let server_static_pk = pubky_noise::kdf::x25519_pk_from_sk(&server_sk);

    // Step 1: Client initiates
    let (c_hs, first_msg) = client_start_ik_direct(&client, &server_static_pk).unwrap();

    // Step 2: Server accepts and responds
    let (s_hs, _identity, response) = server_accept_ik(&server, &first_msg).unwrap();

    // Step 3: Both complete
    let c_link = pubky_noise::datalink_adapter::client_complete_ik(c_hs, &response).unwrap();
    let _s_link = pubky_noise::datalink_adapter::server_complete_ik(s_hs).unwrap();

    // Test SessionId serialization
    let session_id = c_link.session_id();

    // to_bytes/from_bytes
    let bytes = session_id.to_bytes();
    let restored = SessionId::from_bytes(bytes);
    assert_eq!(session_id, &restored);

    // Display format (hex string)
    let hex_str = format!("{}", session_id);
    assert_eq!(hex_str.len(), 64); // 32 bytes = 64 hex chars

    // as_bytes reference
    let byte_ref = session_id.as_bytes();
    assert_eq!(byte_ref, &bytes);
}

#[test]
fn test_thread_safe_manager() {
    let ring = Arc::new(DummyRing::new([1u8; 32], "kid"));
    let client = Arc::new(NoiseClient::<_>::new_direct("kid", b"device", ring.clone()));

    // Create thread-safe manager
    let manager = ThreadSafeSessionManager::new_client(client.clone());

    // Setup a session with 3-step handshake
    let server_ring = Arc::new(DummyRing::new([2u8; 32], "server"));
    let server = Arc::new(NoiseServer::<_>::new_direct(
        "server",
        b"server",
        server_ring.clone(),
    ));
    let server_sk = server_ring
        .derive_device_x25519("server", b"server")
        .unwrap();
    let server_static_pk = pubky_noise::kdf::x25519_pk_from_sk(&server_sk);

    // Step 1: Client initiates
    let (c_hs, first_msg) = client_start_ik_direct(&client, &server_static_pk).unwrap();
    // Step 2: Server accepts
    let (_, _identity, response) = server_accept_ik(&server, &first_msg).unwrap();
    // Step 3: Client completes
    let link = client_complete_ik(c_hs, &response).unwrap();
    let session_id = link.session_id().clone();

    manager.add_session(session_id.clone(), link);

    // Clone manager for another thread
    let manager_clone = manager.clone();
    let sid_clone = session_id.clone();

    let handle = std::thread::spawn(move || {
        // Access from another thread
        assert!(manager_clone.has_session(&sid_clone));

        // Encrypt in background thread
        manager_clone.encrypt(&sid_clone, b"background data")
    });

    // Also access from main thread
    assert!(manager.has_session(&session_id));

    // Wait for background thread
    let result = handle.join().unwrap();
    assert!(result.is_ok());
}

#[test]
fn test_error_codes() {
    // Test that error codes are properly assigned
    use NoiseError::*;

    assert_eq!(Ring("test".to_string()).code(), NoiseErrorCode::Ring);
    assert_eq!(Network("test".to_string()).code(), NoiseErrorCode::Network);
    assert_eq!(Timeout("test".to_string()).code(), NoiseErrorCode::Timeout);
    assert_eq!(Storage("test".to_string()).code(), NoiseErrorCode::Storage);
    assert_eq!(
        Decryption("test".to_string()).code(),
        NoiseErrorCode::Decryption
    );
    assert_eq!(InvalidPeerKey.code(), NoiseErrorCode::InvalidPeerKey);

    // Test message() method for FFI
    let err = Network("connection failed".to_string());
    let msg = err.message();
    assert!(msg.contains("network error"));
    assert!(msg.contains("connection failed"));
}

#[test]
#[allow(deprecated)]
fn test_streaming_for_mobile() {
    let ring_client = Arc::new(DummyRing::new([1u8; 32], "kid"));
    let ring_server = Arc::new(DummyRing::new([2u8; 32], "kid"));

    let client = NoiseClient::<_>::new_direct("kid", b"dev-client", ring_client);
    let server = NoiseServer::<_>::new_direct("kid", b"dev-server", ring_server.clone());

    // 3-step handshake
    let server_sk = ring_server
        .derive_device_x25519("kid", b"dev-server")
        .unwrap();
    let server_static_pk = pubky_noise::kdf::x25519_pk_from_sk(&server_sk);

    // Step 1: Client initiates
    let (c_hs, first_msg) = client_start_ik_direct(&client, &server_static_pk).unwrap();
    // Step 2: Server accepts and responds
    let (s_hs, _identity, response) = server_accept_ik(&server, &first_msg).unwrap();
    // Step 3: Both complete
    let c_link = client_complete_ik(c_hs, &response).unwrap();
    let s_link = server_complete_ik(s_hs).unwrap();

    // Use mobile-friendly chunk size (32KB)
    let chunk_size = 32768;
    let mut c_stream = StreamingNoiseLink::new(c_link, chunk_size);
    let mut s_stream = StreamingNoiseLink::new(s_link, chunk_size);

    // Simulate large message (100KB)
    let large_message = vec![0x42u8; 100_000];

    // Encrypt into chunks
    let chunks = c_stream.encrypt_streaming(&large_message).unwrap();
    assert!(chunks.len() > 1, "Should be split into multiple chunks");

    // Each chunk should be approximately chunk_size + overhead
    for chunk in &chunks {
        assert!(chunk.len() <= chunk_size + 64); // Noise overhead
    }

    // Decrypt chunks
    let decrypted = s_stream.decrypt_streaming(&chunks).unwrap();
    assert_eq!(decrypted, large_message);
}

#[test]
fn test_mobile_config_presets() {
    // Battery saver mode
    let battery_saver = MobileConfig {
        auto_reconnect: false,
        max_reconnect_attempts: 1,
        reconnect_delay_ms: 2000,
        battery_saver: true,
        chunk_size: 16384, // Smaller chunks
    };

    assert!(battery_saver.battery_saver);
    assert_eq!(battery_saver.chunk_size, 16384);

    // Performance mode
    let performance = MobileConfig {
        auto_reconnect: true,
        max_reconnect_attempts: 10,
        reconnect_delay_ms: 100,
        battery_saver: false,
        chunk_size: 65536, // Larger chunks
    };

    assert!(!performance.battery_saver);
    assert_eq!(performance.chunk_size, 65536);

    // Default should be balanced
    let default = MobileConfig::default();
    assert!(default.auto_reconnect);
    assert_eq!(default.chunk_size, 32768);
}

#[test]
fn test_multiple_session_management() {
    let ring = Arc::new(DummyRing::new([1u8; 32], "kid"));
    let client = Arc::new(NoiseClient::<_>::new_direct("kid", b"device", ring.clone()));

    let mut manager = NoiseManager::new_client(client.clone(), MobileConfig::default());

    // Create multiple sessions with different servers
    let ring_server1 = Arc::new(DummyRing::new([2u8; 32], "server1"));
    let ring_server2 = Arc::new(DummyRing::new([3u8; 32], "server2"));

    let server1 = Arc::new(NoiseServer::<_>::new_direct(
        "server1",
        b"server1",
        ring_server1.clone(),
    ));
    let server2 = Arc::new(NoiseServer::<_>::new_direct(
        "server2",
        b"server2",
        ring_server2.clone(),
    ));

    let server1_sk = ring_server1
        .derive_device_x25519("server1", b"server1")
        .unwrap();
    let server1_pk = pubky_noise::kdf::x25519_pk_from_sk(&server1_sk);

    let server2_sk = ring_server2
        .derive_device_x25519("server2", b"server2")
        .unwrap();
    let server2_pk = pubky_noise::kdf::x25519_pk_from_sk(&server2_sk);

    // Create server managers for the handshakes
    let mut server_manager1 = NoiseManager::new_server(server1, MobileConfig::default());
    let mut server_manager2 = NoiseManager::new_server(server2, MobileConfig::default());

    // Session 1: Complete 3-step handshake using manager API
    let (sid1_temp, first_msg1) = manager.initiate_connection(&server1_pk).unwrap();
    let (_, response1) = server_manager1.accept_connection(&first_msg1).unwrap();
    let sid1 = manager.complete_connection(&sid1_temp, &response1).unwrap();

    // Session 2: Complete 3-step handshake using manager API
    let (sid2_temp, first_msg2) = manager.initiate_connection(&server2_pk).unwrap();
    let (_, response2) = server_manager2.accept_connection(&first_msg2).unwrap();
    let sid2 = manager.complete_connection(&sid2_temp, &response2).unwrap();

    // List sessions
    let sessions = manager.list_sessions();
    assert_eq!(sessions.len(), 2);
    assert!(sessions.contains(&sid1));
    assert!(sessions.contains(&sid2));

    // Encrypt with each session
    let data = b"test message";
    let ct1 = manager.encrypt(&sid1, data).unwrap();
    let ct2 = manager.encrypt(&sid2, data).unwrap();

    // Ciphertexts should be different (different session keys)
    assert_ne!(ct1, ct2);

    // Remove one session
    manager.remove_session(&sid1);
    assert_eq!(manager.list_sessions().len(), 1);
    assert!(!manager.list_sessions().contains(&sid1));
}

#[cfg(feature = "storage-queue")]
#[test]
fn test_retry_config_mobile() {
    use RetryConfig;

    // Test default config
    let default = RetryConfig::default();
    assert_eq!(default.max_retries, 3);
    assert_eq!(default.initial_backoff_ms, 100);
    assert_eq!(default.max_backoff_ms, 5000);
    assert_eq!(default.operation_timeout_ms, 30000);

    // Test custom config for mobile
    let mobile = RetryConfig {
        max_retries: 2,
        initial_backoff_ms: 200,
        max_backoff_ms: 3000,
        operation_timeout_ms: 20000,
    };

    assert_eq!(mobile.max_retries, 2);
}

#[test]
fn test_connection_status_tracking() {
    // Setup client
    let ring_client = Arc::new(DummyRing::new([1u8; 32], "client_kid"));
    let client = Arc::new(NoiseClient::<_>::new_direct(
        "client_kid",
        b"client_device",
        ring_client.clone(),
    ));
    let mut client_manager = NoiseManager::new_client(client.clone(), MobileConfig::default());

    // Setup server
    let ring_server = Arc::new(DummyRing::new([2u8; 32], "server_kid"));
    let server = Arc::new(NoiseServer::<_>::new_direct(
        "server_kid",
        b"server_device",
        ring_server.clone(),
    ));
    let mut server_manager = NoiseManager::new_server(server.clone(), MobileConfig::default());

    // Get server's static public key
    let server_sk = ring_server
        .derive_device_x25519("server_kid", b"server_device")
        .unwrap();
    let server_pk = pubky_noise::kdf::x25519_pk_from_sk(&server_sk);

    // 3-step handshake
    // Step 1: Client initiates
    let (temp_id, first_msg) = client_manager.initiate_connection(&server_pk).unwrap();

    // Step 2: Server accepts and generates response
    let (server_session_id, response) = server_manager.accept_connection(&first_msg).unwrap();

    // Step 3: Client completes
    let client_session_id = client_manager
        .complete_connection(&temp_id, &response)
        .unwrap();

    // Verify session IDs match
    assert_eq!(client_session_id, server_session_id);

    // Initial status should be Connected
    assert_eq!(
        client_manager.get_status(&client_session_id),
        Some(ConnectionStatus::Connected)
    );

    // Update status (simulate network change)
    client_manager.set_status(&client_session_id, ConnectionStatus::Disconnected);
    assert_eq!(
        client_manager.get_status(&client_session_id),
        Some(ConnectionStatus::Disconnected)
    );

    client_manager.set_status(&client_session_id, ConnectionStatus::Reconnecting);
    assert_eq!(
        client_manager.get_status(&client_session_id),
        Some(ConnectionStatus::Reconnecting)
    );

    client_manager.set_status(&client_session_id, ConnectionStatus::Error);
    assert_eq!(
        client_manager.get_status(&client_session_id),
        Some(ConnectionStatus::Error)
    );
}
