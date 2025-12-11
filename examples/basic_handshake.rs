//! Basic IK Handshake Example
//!
//! This example demonstrates a complete IK pattern handshake between
//! a client and server, followed by encrypted message exchange.
//!
//! ## Running
//!
//! ```bash
//! cargo run --example basic_handshake
//! ```
//!
//! ## Overview
//!
//! The IK pattern is used when the client knows the server's static
//! public key in advance. This is the most common pattern for
//! connecting to a known server.
//!
//! ## 3-Step Handshake Flow
//!
//! 1. Client: Create first message with encrypted identity
//! 2. Server: Process and create response
//! 3. Client: Process response, both now have transport keys

use pubky_noise::datalink_adapter::{
    client_complete_ik, client_start_ik_direct, server_accept_ik, server_complete_ik,
};
use pubky_noise::{DummyRing, NoiseClient, NoiseServer, RingKeyProvider};
use std::sync::Arc;

fn main() {
    println!("=== PubkyNoise Basic Handshake Example ===\n");

    // =========================================================================
    // Setup
    // =========================================================================

    println!("1. Setting up client and server...");

    // Create key providers with unique seeds
    // In production, use secure random seeds from key storage
    let client_seed = [1u8; 32];
    let server_seed = [2u8; 32];

    let ring_client = Arc::new(DummyRing::new(client_seed, "client-key-id"));
    let ring_server = Arc::new(DummyRing::new(server_seed, "server-key-id"));

    // Create client and server instances
    let client = NoiseClient::<_, ()>::new_direct("client-key-id", b"client-device", ring_client);
    let server =
        NoiseServer::<_, ()>::new_direct("server-key-id", b"server-device", ring_server.clone());

    // Get server's static public key
    // In production, this would be distributed securely
    let server_sk = ring_server
        .derive_device_x25519("server-key-id", b"server-device", 0)
        .expect("Failed to derive server key");
    let server_static_pk = pubky_noise::kdf::x25519_pk_from_sk(&server_sk);

    println!("   Client and server initialized");
    println!(
        "   Server public key: {}...",
        hex::encode(&server_static_pk[..8])
    );

    // =========================================================================
    // 3-Step Handshake
    // =========================================================================

    println!("\n2. Performing 3-step handshake...");

    // Step 1: Client initiates
    println!("   Step 1: Client creates first message");
    let (client_hs, first_msg) =
        client_start_ik_direct(&client, &server_static_pk, None).expect("Client initiation failed");
    println!("   First message: {} bytes", first_msg.len());

    // Step 2: Server processes and responds
    println!("   Step 2: Server processes and responds");
    let (server_hs, client_identity, response) =
        server_accept_ik(&server, &first_msg).expect("Server accept failed");
    println!(
        "   Client identity: {:?}",
        hex::encode(&client_identity.ed25519_pub[..8])
    );
    println!("   Response: {} bytes", response.len());

    // Step 3: Both complete handshake
    println!("   Step 3: Both complete handshake");
    let mut client_link =
        client_complete_ik(client_hs, &response).expect("Client completion failed");
    let mut server_link = server_complete_ik(server_hs).expect("Server completion failed");

    // Verify session IDs match
    assert_eq!(client_link.session_id(), server_link.session_id());
    println!("   Session established: {}", client_link.session_id());

    // =========================================================================
    // Encrypted Communication
    // =========================================================================

    println!("\n3. Testing encrypted communication...");

    // Client sends message to server
    let client_message = b"Hello, server! This is encrypted.";
    let ciphertext = client_link
        .encrypt(client_message)
        .expect("Encryption failed");
    println!(
        "   Client encrypted: {} bytes -> {} bytes",
        client_message.len(),
        ciphertext.len()
    );

    // Server decrypts
    let decrypted = server_link.decrypt(&ciphertext).expect("Decryption failed");
    assert_eq!(client_message.to_vec(), decrypted);
    println!(
        "   Server decrypted: {:?}",
        String::from_utf8_lossy(&decrypted)
    );

    // Server sends response
    let server_response = b"Hello, client! Message received.";
    let response_ct = server_link
        .encrypt(server_response)
        .expect("Encryption failed");
    let response_pt = client_link
        .decrypt(&response_ct)
        .expect("Decryption failed");
    assert_eq!(server_response.to_vec(), response_pt);
    println!(
        "   Client received: {:?}",
        String::from_utf8_lossy(&response_pt)
    );

    // =========================================================================
    // Summary
    // =========================================================================

    println!("\n=== Handshake and communication successful! ===");
    println!("\nKey points:");
    println!("- IK pattern requires knowing server's public key upfront");
    println!("- 3-step handshake: initiate -> accept -> complete");
    println!("- After handshake, both parties can encrypt/decrypt");
    println!("- Session ID is derived from handshake hash (unique per session)");
}
