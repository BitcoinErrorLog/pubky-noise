//! Smoke test for FFI layer
//!
//! This test verifies that the FFI manager and types work correctly from Rust.
//! It simulates how the generated bindings would interact with the FFI layer.

use pubky_noise::ffi::manager::FfiNoiseManager;
use pubky_noise::ffi::config::{default_config, performance_config};
use pubky_noise::ffi::types::{FfiMobileConfig, FfiConnectionStatus};
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
    let server_sk = derive_x25519_for_device_epoch(&server_seed, &server_device_id, 0);
    let server_pk = x25519_pk_from_sk(&server_sk);

    // Create manager
    let config = performance_config();
    let manager = FfiNoiseManager::new_client(
        config,
        client_seed.to_vec(),
        client_kid,
        device_id
    ).expect("Failed to create manager");

    // Connect
    let session_id = manager.connect_client(server_pk.to_vec(), 0, None)
        .expect("Failed to connect");
    
    println!("Connected with session ID: {}", session_id);
    
    // Check status
    let status = manager.get_status(session_id.clone())
        .expect("Failed to get status");
        
    assert!(matches!(status, FfiConnectionStatus::Connected));
    
    // Save state
    let state = manager.save_state(session_id.clone())
        .expect("Failed to save state");
        
    assert_eq!(state.session_id, session_id);
    
    // Encrypt (will fail without real server response, but validates API)
    // Note: In a real test we'd need a server to complete the handshake
    // But connect_client only initiates the handshake for IK
    
    // List sessions
    let sessions = manager.list_sessions();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0], session_id);
    
    // Remove session
    manager.remove_session(session_id);
    let sessions = manager.list_sessions();
    assert_eq!(sessions.len(), 0);
}

