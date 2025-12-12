//! Server-Side Implementation Example
//!
//! This example demonstrates how to implement a Noise protocol server
//! that can accept connections from multiple clients.
//!
//! ## Running
//!
//! ```bash
//! cargo run --example server_example
//! ```
//!
//! ## Overview
//!
//! A Noise server:
//! 1. Initializes with its own key pair
//! 2. Publishes its public key for clients
//! 3. Accepts incoming handshake messages
//! 4. Manages multiple client sessions

use pubky_noise::datalink_adapter::{
    client_complete_ik, client_start_ik_direct, server_accept_ik, server_complete_ik,
};
use pubky_noise::{
    DummyRing, MobileConfig, NoiseClient, NoiseError, NoiseManager, NoiseServer,
    NoiseSessionManager, RingKeyProvider,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn main() {
    println!("=== PubkyNoise Server Example ===\n");

    // =========================================================================
    // Server Setup
    // =========================================================================

    println!("1. Setting up server...");

    // Server's master seed - in production, load from secure storage
    let server_seed = [0xABu8; 32];
    let ring_server = Arc::new(DummyRing::new(server_seed, "server-main"));

    // Create server instance
    let server = Arc::new(NoiseServer::<_, ()>::new_direct(
        "server-main",
        b"production-server",
        ring_server.clone(),
    ));

    // Get server's public key to distribute to clients
    let server_sk = ring_server
        .derive_device_x25519("server-main", b"production-server", 0)
        .expect("Failed to derive server key");
    let server_public_key = pubky_noise::kdf::x25519_pk_from_sk(&server_sk);

    println!("   Server initialized");
    println!(
        "   Public key (share with clients): {}",
        hex::encode(server_public_key)
    );

    // =========================================================================
    // Using NoiseSessionManager for Multiple Clients
    // =========================================================================

    println!("\n2. Setting up session manager for multiple clients...");

    let mut server_manager = NoiseSessionManager::new_server(server.clone());

    // Simulate multiple clients connecting
    let num_clients = 3;
    let mut client_sessions = Vec::new();

    for i in 0..num_clients {
        println!("\n   --- Client {} connecting ---", i + 1);

        // Create a client
        let client_seed = [(i + 1) as u8; 32];
        let ring_client = Arc::new(DummyRing::new(client_seed, format!("client-{}", i)));
        let client = NoiseClient::<_, ()>::new_direct(
            format!("client-{}", i),
            format!("device-{}", i).as_bytes(),
            ring_client,
        );

        // Client initiates handshake
        let (client_hs, first_msg) =
            client_start_ik_direct(&client, &server_public_key, None).expect("Client init failed");

        // Server accepts and responds
        let (server_hs, client_identity, response) =
            server_accept_ik(&server, &first_msg).expect("Server accept failed");

        println!(
            "   Client {} identity: {}...",
            i + 1,
            hex::encode(&client_identity.ed25519_pub[..8])
        );

        // Both complete
        let client_link = client_complete_ik(client_hs, &response).expect("Client complete failed");
        let server_link = server_complete_ik(server_hs).expect("Server complete failed");

        let session_id = server_link.session_id().clone();

        // Server adds session to manager
        server_manager.add_session(session_id.clone(), server_link);

        println!("   Session: {}", session_id);

        client_sessions.push((client_link, session_id));
    }

    // =========================================================================
    // Managing Client Sessions
    // =========================================================================

    println!(
        "\n3. Managing {} active sessions...",
        server_manager.list_sessions().len()
    );

    // List all sessions
    for (i, session_id) in server_manager.list_sessions().iter().enumerate() {
        println!("   Session {}: {}", i + 1, session_id);
    }

    // Process messages from clients
    println!("\n4. Processing messages from clients...");

    // Save first session ID for later use in error handling demos
    let first_session_id = client_sessions.first().map(|(_, id)| id.clone());

    for (i, (mut client_link, session_id)) in client_sessions.into_iter().enumerate() {
        // Client sends a message
        let message = format!("Hello from client {}!", i + 1);
        let ciphertext = client_link
            .encrypt(message.as_bytes())
            .expect("Encrypt failed");

        // Server receives and decrypts
        if let Some(server_link) = server_manager.get_session_mut(&session_id) {
            let plaintext = server_link.decrypt(&ciphertext).expect("Decrypt failed");
            println!(
                "   Received from client {}: {:?}",
                i + 1,
                String::from_utf8_lossy(&plaintext)
            );

            // Server sends response
            let response = format!("Welcome, client {}!", i + 1);
            let response_ct = server_link
                .encrypt(response.as_bytes())
                .expect("Encrypt failed");

            // Client receives
            let response_pt = client_link.decrypt(&response_ct).expect("Decrypt failed");
            println!(
                "   Sent to client {}: {:?}",
                i + 1,
                String::from_utf8_lossy(&response_pt)
            );
        }
    }

    // =========================================================================
    // Using NoiseManager for Mobile-Optimized Server
    // =========================================================================

    println!("\n5. Mobile-optimized server with NoiseManager...");

    let ring_server2 = Arc::new(DummyRing::new([0xCDu8; 32], "mobile-server"));
    let server2 = Arc::new(NoiseServer::<_, ()>::new_direct(
        "mobile-server",
        b"mobile-optimized",
        ring_server2.clone(),
    ));

    let config = MobileConfig {
        auto_reconnect: true,
        max_reconnect_attempts: 5,
        reconnect_delay_ms: 1000,
        battery_saver: false,
        chunk_size: 32768,
    };

    let mut mobile_server = NoiseManager::new_server(server2, config);

    // Accept a connection using the higher-level API
    let ring_client = Arc::new(DummyRing::new([0xEFu8; 32], "mobile-client"));
    let client = Arc::new(NoiseClient::<_, ()>::new_direct(
        "mobile-client",
        b"phone",
        ring_client,
    ));

    let server2_sk = ring_server2
        .derive_device_x25519("mobile-server", b"mobile-optimized", 0)
        .unwrap();
    let server2_pk = pubky_noise::kdf::x25519_pk_from_sk(&server2_sk);

    let mut mobile_client = NoiseManager::new_client(client, MobileConfig::default());

    // 3-step handshake with NoiseManager
    let (temp_id, first_msg) = mobile_client
        .initiate_connection(&server2_pk, None)
        .expect("Init failed");

    let (server_session_id, response) = mobile_server
        .accept_connection(&first_msg)
        .expect("Accept failed");

    let client_session_id = mobile_client
        .complete_connection(&temp_id, &response)
        .expect("Complete failed");

    println!("   Mobile server session: {}", server_session_id);
    println!("   Mobile client session: {}", client_session_id);

    // Encrypt/decrypt using NoiseManager
    let message = b"Mobile-optimized communication!";
    let ct = mobile_client
        .encrypt(&client_session_id, message)
        .expect("Encrypt failed");
    let pt = mobile_server
        .decrypt(&server_session_id, &ct)
        .expect("Decrypt failed");

    println!("   Message received: {:?}", String::from_utf8_lossy(&pt));

    // =========================================================================
    // Error Handling Examples
    // =========================================================================

    println!("\n6. Error handling examples...");

    // Example: Handle invalid handshake message
    let invalid_message = vec![0u8; 64]; // Random bytes, not a valid handshake
    match server_accept_ik(&server, &invalid_message) {
        Ok(_) => println!("   Unexpected success with invalid message"),
        Err(e) => {
            println!("   Correctly rejected invalid message: {:?}", e);
            match e {
                NoiseError::Snow(_) => println!("   Error type: Protocol error (expected)"),
                NoiseError::Serde(_) => println!("   Error type: Serialization error (expected)"),
                _ => println!("   Error type: {:?}", e),
            }
        }
    }

    // Example: Handle decryption failure (corrupted data)
    if let Some(first_id) = &first_session_id {
        if let Some(server_link) = server_manager.get_session_mut(first_id) {
            let corrupted_data = vec![0xDE, 0xAD, 0xBE, 0xEF];
            match server_link.decrypt(&corrupted_data) {
                Ok(_) => println!("   Unexpected success with corrupted data"),
                Err(e) => {
                    println!("   Correctly rejected corrupted data: {:?}", e);
                    println!("   Error code: {:?}", e.code());
                }
            }
        }
    }

    // =========================================================================
    // Rate Limiting Example
    // =========================================================================

    println!("\n7. Rate limiting example...");

    // Simple rate limiter: track handshake attempts per client identity
    let mut rate_limiter: HashMap<String, (u32, Instant)> = HashMap::new();
    let max_attempts_per_minute = 5;

    // Simulate rate limiting check
    let client_identity_str = "client-1";
    let now = Instant::now();

    if let Some((count, last_reset)) = rate_limiter.get_mut(client_identity_str) {
        if now.duration_since(*last_reset) > Duration::from_secs(60) {
            // Reset counter after 1 minute
            *count = 1;
            *last_reset = now;
            println!("   Rate limit reset for {}", client_identity_str);
        } else if *count >= max_attempts_per_minute {
            println!(
                "   Rate limit exceeded for {}: {} attempts in last minute",
                client_identity_str, count
            );
            println!("   Would reject handshake attempt");
        } else {
            *count += 1;
            println!(
                "   Rate limit check passed: {}/{} attempts",
                count, max_attempts_per_minute
            );
        }
    } else {
        rate_limiter.insert(client_identity_str.to_string(), (1, now));
        println!("   First handshake attempt from {}", client_identity_str);
    }

    // =========================================================================
    // Client Disconnection Handling
    // =========================================================================

    println!("\n8. Client disconnection handling...");

    // Simulate client disconnection
    let disconnected_session = server_manager.list_sessions()[0].clone();
    println!(
        "   Simulating disconnection for session: {}",
        disconnected_session
    );

    // Remove disconnected session
    server_manager.remove_session(&disconnected_session);
    println!(
        "   Session removed. Active sessions: {}",
        server_manager.list_sessions().len()
    );

    // Example: Cleanup stale sessions (sessions inactive for > 5 minutes)
    println!("\n   Example: Cleanup stale sessions");
    let mut session_activity: HashMap<String, Instant> = HashMap::new();

    // Track activity
    for session_id in server_manager.list_sessions() {
        session_activity.insert(session_id.to_string(), Instant::now());
    }

    // Simulate time passing
    println!("   Would check for sessions inactive > 5 minutes");
    println!("   Would remove stale sessions automatically");

    // Example: Graceful shutdown
    println!("\n9. Graceful shutdown example...");

    println!("   Before shutdown:");
    println!(
        "     Active sessions: {}",
        server_manager.list_sessions().len()
    );

    // In production, you would:
    // 1. Stop accepting new connections
    // 2. Notify active clients of shutdown
    // 3. Wait for in-flight operations to complete
    // 4. Close all sessions

    println!("   Steps for graceful shutdown:");
    println!("   1. Stop accepting new handshakes");
    println!("   2. Notify clients of impending shutdown");
    println!("   3. Wait for active operations to complete");
    println!("   4. Close all sessions");
    println!("   5. Clean up resources");

    // Clean up all sessions
    let sessions_to_close: Vec<_> = server_manager.list_sessions().to_vec();
    for session_id in sessions_to_close {
        server_manager.remove_session(&session_id);
        println!("     Closed session: {}", session_id);
    }

    println!("   After shutdown:");
    println!(
        "     Active sessions: {}",
        server_manager.list_sessions().len()
    );

    // =========================================================================
    // Connection Timeout Handling
    // =========================================================================

    println!("\n10. Connection timeout handling...");

    // Example: Track connection start time
    let connection_start = Instant::now();
    let timeout_duration = Duration::from_secs(30);

    // Check for timeout
    if connection_start.elapsed() > timeout_duration {
        println!("   Connection timeout detected");
        println!("   Would close timed-out connection");
    } else {
        println!(
            "   Connection still active: {}s elapsed",
            connection_start.elapsed().as_secs()
        );
    }

    // =========================================================================
    // Summary
    // =========================================================================

    println!("\n=== Server example complete! ===");
    println!("\nKey points:");
    println!("- Server publishes its public key for clients to use");
    println!("- Use NoiseSessionManager for basic multi-client support");
    println!("- Use NoiseManager for mobile-optimized server");
    println!("- Each client gets a unique session with its own keys");
    println!("- Sessions can be managed independently");
    println!("\nProduction considerations:");
    println!("- Implement rate limiting to prevent abuse");
    println!("- Handle client disconnections gracefully");
    println!("- Monitor session activity and cleanup stale sessions");
    println!("- Implement connection timeouts");
    println!("- Handle errors appropriately (invalid messages, decryption failures)");
    println!("- Plan for graceful shutdown");
}
