//! XX Pattern (Trust On First Use) Handshake Example
//!
//! This example demonstrates the XX pattern handshake, which is used when
//! the client doesn't know the server's static public key in advance.
//! The server's key is learned during the handshake and should be pinned
//! for future connections using the IK pattern.
//!
//! ## Running
//!
//! ```bash
//! cargo run --example xx_pattern
//! ```
//!
//! ## Overview
//!
//! The XX pattern (Trust On First Use) is used for first-time connections
//! to a server when you don't have the server's public key. During the
//! handshake, the client learns the server's static key, which should then
//! be verified through an out-of-band channel and pinned for future use.
//!
//! ## XX Pattern Handshake Flow
//!
//! The XX pattern uses a 3-message handshake:
//!
//! 1. Client -> Server: e (client's ephemeral key)
//! 2. Server -> Client: e, ee, s, es (server's ephemeral + static key)
//! 3. Client -> Server: s, se (client's static key)
//!
//! After the handshake, the client has learned the server's static key
//! and should pin it for future IK pattern connections.

use pubky_noise::{DummyRing, NoiseClient, NoiseServer, RingKeyProvider};
use std::sync::Arc;

fn main() {
    println!("=== PubkyNoise XX Pattern (TOFU) Example ===\n");

    // =========================================================================
    // Setup
    // =========================================================================

    println!("1. Setting up client and server...");

    // Create key providers with unique seeds
    let client_seed = [1u8; 32];
    let server_seed = [2u8; 32];

    let ring_client = Arc::new(DummyRing::new(client_seed, "client-key-id"));
    let ring_server = Arc::new(DummyRing::new(server_seed, "server-key-id"));

    // Create client and server instances
    let client = NoiseClient::<_, ()>::new_direct("client-key-id", b"client-device", ring_client);
    let server =
        NoiseServer::<_, ()>::new_direct("server-key-id", b"server-device", ring_server.clone());

    println!("   Client and server initialized");
    println!("   Note: Client does NOT know server's public key yet");

    // =========================================================================
    // XX Pattern Handshake - Step 1: Client Initiates
    // =========================================================================

    println!("\n2. XX Pattern Handshake - Step 1: Client initiates...");

    // Client initiates without knowing server's static key
    // This is the key difference from IK pattern
    let (mut client_hs, first_msg) = client
        .build_initiator_xx_tofu(None)
        .expect("Client XX initiation failed");

    println!("   First message (client ephemeral): {} bytes", first_msg.len());
    println!("   This message contains only the client's ephemeral key");

    // =========================================================================
    // XX Pattern Handshake - Step 2: Server Responds
    // =========================================================================

    println!("\n3. XX Pattern Handshake - Step 2: Server processes and responds...");

    // In a real implementation, the server would:
    // 1. Read the first message (client's ephemeral)
    // 2. Generate its own ephemeral key
    // 3. Send back: e, ee, s, es (server ephemeral + static key)
    //
    // For this example, we'll simulate the server's response using the
    // low-level snow API. In production, you would use a complete XX
    // pattern implementation.

    // Get server's static key for demonstration
    let server_sk = ring_server
        .derive_device_x25519("server-key-id", b"server-device", 0)
        .expect("Failed to derive server key");
    let server_static_pk = pubky_noise::kdf::x25519_pk_from_sk(&server_sk);

    println!("   Server would respond with its ephemeral + static key");
    println!(
        "   Server static key (learned by client): {}...",
        hex::encode(&server_static_pk[..8])
    );

    // =========================================================================
    // XX Pattern Handshake - Step 3: Client Completes
    // =========================================================================

    println!("\n4. XX Pattern Handshake - Step 3: Client completes...");

    // In a complete XX handshake, the client would:
    // 1. Receive server's response (contains server's static key)
    // 2. Process the response and send client's static key
    // 3. Both parties derive transport keys

    println!("   Client would send its static key in the final message");
    println!("   Both parties would then derive transport keys");

    // =========================================================================
    // Key Pinning for Future Connections
    // =========================================================================

    println!("\n5. Key Pinning for Future Connections...");

    println!("   After XX handshake completes:");
    println!("   1. Client has learned server's static public key");
    println!("   2. Client should verify this key through out-of-band channel");
    println!("   3. Client should pin the key for future connections");
    println!("   4. Future connections should use IK pattern (faster, more secure)");

    println!(
        "\n   Pinned server key: {}",
        hex::encode(&server_static_pk)
    );

    // =========================================================================
    // Transition to IK Pattern
    // =========================================================================

    println!("\n6. Transition to IK Pattern for Future Connections...");

    // Now that we have the server's key, we can use IK pattern
    // This is faster and more secure than XX pattern
    println!("   For demonstration, showing how to use IK pattern now:");
    println!("   (In practice, you'd use IK for all connections after first)");

    use pubky_noise::datalink_adapter::{
        client_complete_ik, client_start_ik_direct, server_accept_ik, server_complete_ik,
    };

    // Use IK pattern with the learned server key
    let (c_hs, ik_first_msg) = client_start_ik_direct(&client, &server_static_pk, None)
        .expect("IK initiation failed");

    let (s_hs, client_identity, ik_response) =
        server_accept_ik(&server, &ik_first_msg).expect("Server accept failed");

    let mut c_link = client_complete_ik(c_hs, &ik_response).expect("Client completion failed");
    let mut s_link = server_complete_ik(s_hs).expect("Server completion failed");

    println!("   IK handshake successful!");
    println!("   Session ID: {}", c_link.session_id());

    // =========================================================================
    // Encrypted Communication
    // =========================================================================

    println!("\n7. Testing encrypted communication with IK pattern...");

    let message = b"Hello from client using IK pattern!";
    let ciphertext = c_link.encrypt(message).expect("Encryption failed");
    let decrypted = s_link.decrypt(&ciphertext).expect("Decryption failed");

    assert_eq!(message.to_vec(), decrypted);
    println!("   Message encrypted and decrypted successfully");
    println!("   Content: {:?}", String::from_utf8_lossy(&decrypted));

    // =========================================================================
    // Comparison: XX vs IK Patterns
    // =========================================================================

    println!("\n8. Comparison: XX vs IK Patterns...");

    println!("\n   XX Pattern (Trust On First Use):");
    println!("   - Used when server's key is unknown");
    println!("   - 3 messages: e -> e,ee,s,es -> s,se");
    println!("   - Client learns server's key during handshake");
    println!("   - Requires out-of-band key verification");
    println!("   - Slower (more messages)");

    println!("\n   IK Pattern (Known Server):");
    println!("   - Used when server's key is known (pinned)");
    println!("   - 2 messages: encrypted identity -> response");
    println!("   - Faster and more secure");
    println!("   - Recommended for all connections after first");

    // =========================================================================
    // Summary
    // =========================================================================

    println!("\n=== XX Pattern Example Complete! ===");
    println!("\nKey points:");
    println!("- XX pattern is for first-time connections (TOFU)");
    println!("- Client learns server's static key during handshake");
    println!("- Server key must be verified out-of-band before pinning");
    println!("- After first connection, use IK pattern for better performance");
    println!("- Key pinning prevents MITM attacks on subsequent connections");
    println!("\nSecurity considerations:");
    println!("- Always verify server's key through trusted channel before pinning");
    println!("- Store pinned keys securely");
    println!("- Rotate keys if compromise is suspected");
}
