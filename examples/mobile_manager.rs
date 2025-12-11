//! Mobile Manager Example
//!
//! This example demonstrates the NoiseManager API designed specifically
//! for mobile applications with lifecycle management and state persistence.
//!
//! ## Running
//!
//! ```bash
//! cargo run --example mobile_manager
//! ```
//!
//! ## Overview
//!
//! NoiseManager provides:
//! - Simplified 3-step handshake API
//! - Session state persistence (save/restore)
//! - Connection status tracking
//! - Multiple session management
//! - Mobile-friendly configuration

use pubky_noise::{
    ConnectionStatus, DummyRing, MobileConfig, NoiseClient, NoiseManager, NoiseServer,
    RingKeyProvider,
};
use std::sync::Arc;

fn main() {
    println!("=== PubkyNoise Mobile Manager Example ===\n");

    // =========================================================================
    // Configuration
    // =========================================================================

    println!("1. Configuring for mobile use...");

    // Default configuration
    let default_config = MobileConfig::default();
    println!("   Default config:");
    println!("     auto_reconnect: {}", default_config.auto_reconnect);
    println!(
        "     max_reconnect_attempts: {}",
        default_config.max_reconnect_attempts
    );
    println!("     reconnect_delay_ms: {}", default_config.reconnect_delay_ms);
    println!("     battery_saver: {}", default_config.battery_saver);
    println!("     chunk_size: {} bytes", default_config.chunk_size);

    // Custom battery-saver configuration
    let _battery_config = MobileConfig {
        auto_reconnect: false, // Don't auto-reconnect to save battery
        max_reconnect_attempts: 1,
        reconnect_delay_ms: 2000,
        battery_saver: true,
        chunk_size: 16384, // Smaller chunks for less memory
    };

    // Performance configuration
    let _perf_config = MobileConfig {
        auto_reconnect: true,
        max_reconnect_attempts: 10,
        reconnect_delay_ms: 100, // Quick retry
        battery_saver: false,
        chunk_size: 65536, // Larger chunks for throughput
    };

    println!("\n   Battery-saver config: smaller chunks, no auto-reconnect");
    println!("   Performance config: larger chunks, aggressive retry");

    // =========================================================================
    // Setup Client and Server
    // =========================================================================

    println!("\n2. Setting up client and server managers...");

    let ring_client = Arc::new(DummyRing::new([1u8; 32], "client"));
    let ring_server = Arc::new(DummyRing::new([2u8; 32], "server"));

    let client = Arc::new(NoiseClient::<_, ()>::new_direct(
        "client",
        b"mobile-device",
        ring_client,
    ));

    let server = Arc::new(NoiseServer::<_, ()>::new_direct(
        "server",
        b"server-device",
        ring_server.clone(),
    ));

    // Create managers
    let mut client_manager = NoiseManager::new_client(client.clone(), default_config.clone());
    let mut server_manager = NoiseManager::new_server(server.clone(), default_config);

    // Get server's public key
    let server_sk = ring_server
        .derive_device_x25519("server", b"server-device", 0)
        .unwrap();
    let server_pk = pubky_noise::kdf::x25519_pk_from_sk(&server_sk);

    println!("   Client manager created");
    println!("   Server manager created");

    // =========================================================================
    // 3-Step Handshake with NoiseManager
    // =========================================================================

    println!("\n3. Performing 3-step handshake...");

    // Step 1: Client initiates
    println!("   Step 1: Client initiates connection");
    let (temp_session_id, first_message) = client_manager
        .initiate_connection(&server_pk, None)
        .expect("Initiation failed");

    println!("   Temporary session ID: {}", temp_session_id);
    println!("   First message: {} bytes", first_message.len());

    // In a real app, you would send first_message over the network here
    // let response = network.send_and_receive(first_message);

    // Step 2: Server accepts (simulating server receiving the message)
    println!("   Step 2: Server accepts and responds");
    let (server_session_id, response_message) = server_manager
        .accept_connection(&first_message)
        .expect("Accept failed");

    println!("   Server session ID: {}", server_session_id);
    println!("   Response message: {} bytes", response_message.len());

    // Step 3: Client completes (simulating client receiving response)
    println!("   Step 3: Client completes handshake");
    let client_session_id = client_manager
        .complete_connection(&temp_session_id, &response_message)
        .expect("Completion failed");

    println!("   Client session ID: {}", client_session_id);

    // Verify session IDs match
    assert_eq!(client_session_id, server_session_id);
    println!("   Session IDs match!");

    // =========================================================================
    // Connection Status
    // =========================================================================

    println!("\n4. Connection status tracking...");

    // Check initial status
    let status = client_manager.get_status(&client_session_id);
    println!("   Initial status: {:?}", status);
    assert_eq!(status, Some(ConnectionStatus::Connected));

    // Simulate status changes (e.g., from network events)
    println!("   Simulating network disconnect...");
    client_manager.set_status(&client_session_id, ConnectionStatus::Disconnected);
    println!("   Status: {:?}", client_manager.get_status(&client_session_id));

    println!("   Simulating reconnection attempt...");
    client_manager.set_status(&client_session_id, ConnectionStatus::Reconnecting);
    println!("   Status: {:?}", client_manager.get_status(&client_session_id));

    println!("   Simulating reconnection success...");
    client_manager.set_status(&client_session_id, ConnectionStatus::Connected);
    println!("   Status: {:?}", client_manager.get_status(&client_session_id));

    // =========================================================================
    // Encryption and Decryption
    // =========================================================================

    println!("\n5. Encrypted communication...");

    let message = b"Hello from mobile client!";
    let ciphertext = client_manager
        .encrypt(&client_session_id, message)
        .expect("Encryption failed");

    println!(
        "   Encrypted: {} bytes -> {} bytes",
        message.len(),
        ciphertext.len()
    );

    let plaintext = server_manager
        .decrypt(&server_session_id, &ciphertext)
        .expect("Decryption failed");

    println!(
        "   Decrypted: {:?}",
        String::from_utf8_lossy(&plaintext)
    );

    // =========================================================================
    // State Persistence
    // =========================================================================

    println!("\n6. State persistence (for app lifecycle)...");

    // Save state before app suspension
    println!("   Saving state (app going to background)...");
    let saved_state = client_manager
        .save_state(&client_session_id)
        .expect("Save state failed");

    println!("   Saved state:");
    println!("     session_id: {}", saved_state.session_id);
    println!("     write_counter: {}", saved_state.write_counter);
    println!("     read_counter: {}", saved_state.read_counter);
    println!("     status: {:?}", saved_state.status);

    // In a real app, you would serialize this to disk here
    // For example: serde_json::to_string(&saved_state)

    // Simulate app restart - create new manager and restore state
    println!("\n   Simulating app restart...");

    let ring_client2 = Arc::new(DummyRing::new([1u8; 32], "client"));
    let client2 = Arc::new(NoiseClient::<_, ()>::new_direct(
        "client",
        b"mobile-device",
        ring_client2,
    ));

    let mut new_manager = NoiseManager::new_client(client2, MobileConfig::default());

    // Restore state from saved
    new_manager
        .restore_state(saved_state)
        .expect("Restore state failed");

    println!("   State restored!");
    println!(
        "   Restored status: {:?}",
        new_manager.get_status(&client_session_id)
    );

    // Note: The actual Noise transport state cannot be serialized.
    // You'll need to re-establish the connection for actual message exchange.
    // The saved state preserves metadata like counters and status.

    // =========================================================================
    // Multiple Sessions
    // =========================================================================

    println!("\n7. Managing multiple sessions...");

    // Create another server to connect to
    let ring_server2 = Arc::new(DummyRing::new([3u8; 32], "server2"));
    let server2 = Arc::new(NoiseServer::<_, ()>::new_direct(
        "server2",
        b"server2-device",
        ring_server2.clone(),
    ));

    let mut server2_manager = NoiseManager::new_server(server2, MobileConfig::default());

    let server2_sk = ring_server2
        .derive_device_x25519("server2", b"server2-device", 0)
        .unwrap();
    let server2_pk = pubky_noise::kdf::x25519_pk_from_sk(&server2_sk);

    // Reset client manager for this demo
    let ring_client3 = Arc::new(DummyRing::new([1u8; 32], "client"));
    let client3 = Arc::new(NoiseClient::<_, ()>::new_direct(
        "client",
        b"mobile-device",
        ring_client3,
    ));
    let mut multi_client = NoiseManager::new_client(client3, MobileConfig::default());

    // Connect to server 1
    let (temp1, msg1) = multi_client.initiate_connection(&server_pk, None).unwrap();
    let (_, resp1) = server_manager.accept_connection(&msg1).unwrap();
    let sid1 = multi_client.complete_connection(&temp1, &resp1).unwrap();

    // Connect to server 2
    let (temp2, msg2) = multi_client.initiate_connection(&server2_pk, None).unwrap();
    let (_, resp2) = server2_manager.accept_connection(&msg2).unwrap();
    let _sid2 = multi_client.complete_connection(&temp2, &resp2).unwrap();

    // List sessions
    let sessions = multi_client.list_sessions();
    println!("   Active sessions: {}", sessions.len());
    for (i, sid) in sessions.iter().enumerate() {
        let status = multi_client.get_status(sid);
        println!("     Session {}: {} ({:?})", i + 1, sid, status);
    }

    // Remove a session
    println!("   Removing session 1...");
    multi_client.remove_session(&sid1);

    let remaining = multi_client.list_sessions();
    println!("   Remaining sessions: {}", remaining.len());

    // =========================================================================
    // Summary
    // =========================================================================

    println!("\n=== Mobile Manager example complete! ===");
    println!("\nKey points:");
    println!("- NoiseManager provides a high-level API for mobile apps");
    println!("- 3-step handshake: initiate -> accept -> complete");
    println!("- State can be saved before app suspension");
    println!("- State can be restored after app resume");
    println!("- Connection status is tracked automatically");
    println!("- Multiple sessions can be managed simultaneously");
    println!("\nMobile best practices:");
    println!("- Always save state in onPause/applicationWillResignActive");
    println!("- Restore state in onCreate/applicationDidBecomeActive");
    println!("- Track connection status for UI updates");
    println!("- Use battery_saver config when low on battery");
}
