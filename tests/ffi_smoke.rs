//! Smoke test for FFI layer
//!
//! This test verifies that the FFI manager and types work correctly from Rust.
//! It simulates how the generated bindings would interact with the FFI layer.

#![cfg(feature = "uniffi_macros")]

use pubky_noise::ffi::config::performance_config;
use pubky_noise::ffi::manager::FfiNoiseManager;
use pubky_noise::kdf::derive_x25519_for_device_epoch;
use pubky_noise::kdf::x25519_pk_from_sk;

#[test]
fn test_ffi_smoke() {
    // Setup keys
    let client_seed = [1u8; 32];
    let client_kid = "client_kid".to_string();
    let device_id = b"device_id".to_vec();
    let server_seed = [2u8; 32];
    let server_device_id = b"server_device".to_vec();

    // Server setup (manual for now as FFI doesn't expose server)
    let server_sk = derive_x25519_for_device_epoch(&server_seed, &server_device_id, 0).unwrap();
    let server_pk = x25519_pk_from_sk(&server_sk);

    // Create manager
    let config = performance_config();
    let manager = FfiNoiseManager::new_client(config, client_seed.to_vec(), client_kid, device_id)
        .expect("Failed to create manager");

    // Initiate connection (step 1 of 3-step handshake)
    // Note: This only initiates the handshake; we need a server to complete it
    let result = manager
        .initiate_connection(server_pk.to_vec(), None)
        .expect("Failed to initiate connection");

    let session_id = result.session_id;
    let first_msg = result.first_message;

    println!("Initiated connection with session ID: {}", session_id);
    println!("First message length: {} bytes", first_msg.len());

    // Verify first message was generated
    assert!(!first_msg.is_empty(), "First message should not be empty");
    assert!(
        first_msg.len() > 32,
        "First message should contain handshake data (at least 32 bytes)"
    );

    // Note: The handshake is not completed in this test, so sessions will be empty
    // until the handshake is completed. This is expected behavior.
    let sessions = manager.list_sessions();
    assert_eq!(
        sessions.len(),
        0,
        "Sessions should be empty until handshake is completed"
    );

    // Cleanup: remove the pending session
    manager.remove_session(session_id.clone());

    println!("FFI smoke test passed!");
}

#[test]
fn test_ffi_server_client_handshake() {
    // This test verifies the full 3-step handshake via FFI

    // Setup keys
    let client_seed = [1u8; 32];
    let server_seed = [2u8; 32];
    let server_device_id = b"server_device".to_vec();

    // Get server's public key (derived the same way the server will derive it)
    let server_sk = derive_x25519_for_device_epoch(&server_seed, &server_device_id, 0).unwrap();
    let server_pk = x25519_pk_from_sk(&server_sk);

    // Create client manager
    let client_config = performance_config();
    let client_manager = FfiNoiseManager::new_client(
        client_config,
        client_seed.to_vec(),
        "client_kid".to_string(),
        b"client_device".to_vec(),
    )
    .expect("Failed to create client manager");

    // Create server manager
    let server_config = performance_config();
    let server_manager = FfiNoiseManager::new_server(
        server_config,
        server_seed.to_vec(),
        "server_kid".to_string(),
        server_device_id.clone(),
    )
    .expect("Failed to create server manager");

    // Step 1: Client initiates connection
    let initiate_result = client_manager
        .initiate_connection(server_pk.to_vec(), None)
        .expect("Failed to initiate connection");

    let temp_session_id = initiate_result.session_id.clone();
    let first_msg = initiate_result.first_message;

    println!("Client initiated: session_id={}", temp_session_id);

    // Step 2: Server accepts connection
    let accept_result = server_manager
        .accept_connection(first_msg)
        .expect("Failed to accept connection");

    let server_session_id = accept_result.session_id.clone();
    let response_msg = accept_result.response_message;

    println!("Server accepted: session_id={}", server_session_id);

    // Step 3: Client completes connection
    let final_session_id = client_manager
        .complete_connection(temp_session_id, response_msg)
        .expect("Failed to complete connection");

    println!("Client completed: session_id={}", final_session_id);

    // Now both sides should have established sessions
    let client_sessions = client_manager.list_sessions();
    let server_sessions = server_manager.list_sessions();

    assert_eq!(client_sessions.len(), 1, "Client should have 1 session");
    assert_eq!(server_sessions.len(), 1, "Server should have 1 session");

    // Test encryption/decryption
    let plaintext = b"Hello, secure world!";
    let ciphertext = client_manager
        .encrypt(final_session_id.clone(), plaintext.to_vec())
        .expect("Failed to encrypt");

    let decrypted = server_manager
        .decrypt(server_session_id.clone(), ciphertext)
        .expect("Failed to decrypt");

    assert_eq!(
        decrypted,
        plaintext.to_vec(),
        "Decrypted message should match"
    );

    println!("Full handshake test passed!");
}
