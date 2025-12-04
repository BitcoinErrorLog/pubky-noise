//! Tests for FfiRawNoiseManager and pkarr FFI helpers.
//!
//! This module tests the cold-key FFI layer including:
//! - Raw key management without Ring dependency
//! - All Noise patterns (IK-raw, N, NN, XX)
//! - pkarr helper functions for key binding
//! - Error handling for invalid inputs

#![cfg(feature = "uniffi_macros")]

use pubky_noise::ffi::{
    ffi_create_pkarr_binding_message, ffi_derive_x25519_static, ffi_format_x25519_for_pkarr,
    ffi_parse_and_verify_pkarr_key, ffi_parse_x25519_from_pkarr, ffi_pkarr_noise_subdomain,
    ffi_sign_pkarr_key_binding, ffi_verify_pkarr_key_binding, ffi_x25519_public_key,
    FfiMobileConfig, FfiRawNoiseManager,
};

// ============================================================================
// Key Derivation Tests
// ============================================================================

#[test]
fn test_ffi_derive_x25519_deterministic() {
    let seed = vec![42u8; 32];
    let context = b"test-context".to_vec();

    let key1 = ffi_derive_x25519_static(seed.clone(), context.clone()).unwrap();
    let key2 = ffi_derive_x25519_static(seed, context).unwrap();

    assert_eq!(key1, key2, "Same inputs should produce same output");
    assert_eq!(key1.len(), 32);
}

#[test]
fn test_ffi_derive_x25519_different_contexts_differ() {
    let seed = vec![42u8; 32];

    let key1 = ffi_derive_x25519_static(seed.clone(), b"context-a".to_vec()).unwrap();
    let key2 = ffi_derive_x25519_static(seed, b"context-b".to_vec()).unwrap();

    assert_ne!(key1, key2, "Different contexts should produce different keys");
}

#[test]
fn test_ffi_derive_x25519_invalid_seed_length() {
    let short_seed = vec![0u8; 16];
    assert!(ffi_derive_x25519_static(short_seed, vec![]).is_err());

    let long_seed = vec![0u8; 64];
    assert!(ffi_derive_x25519_static(long_seed, vec![]).is_err());
}

#[test]
fn test_ffi_x25519_public_key_derivation() {
    let seed = vec![1u8; 32];
    let sk = ffi_derive_x25519_static(seed, b"test".to_vec()).unwrap();

    let pk = ffi_x25519_public_key(sk.clone()).unwrap();
    assert_eq!(pk.len(), 32);

    // Same secret key produces same public key
    let pk2 = ffi_x25519_public_key(sk).unwrap();
    assert_eq!(pk, pk2);
}

#[test]
fn test_ffi_x25519_public_key_invalid_length() {
    assert!(ffi_x25519_public_key(vec![0u8; 16]).is_err());
}

// ============================================================================
// pkarr Helper Tests
// ============================================================================

#[test]
fn test_ffi_pkarr_format_and_parse_roundtrip() {
    let x25519_pk = vec![42u8; 32];
    let txt = ffi_format_x25519_for_pkarr(x25519_pk.clone(), None).unwrap();

    assert!(txt.starts_with("v=1;k="));

    let parsed = ffi_parse_x25519_from_pkarr(txt).unwrap();
    assert_eq!(parsed, x25519_pk);
}

#[test]
fn test_ffi_pkarr_sign_and_verify_roundtrip() {
    use ed25519_dalek::SigningKey;
    use rand::RngCore;

    // Generate Ed25519 keypair
    let mut ed25519_sk_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut ed25519_sk_bytes);
    let signing_key = SigningKey::from_bytes(&ed25519_sk_bytes);
    let ed25519_pk = signing_key.verifying_key().to_bytes();

    let x25519_pk = vec![99u8; 32];
    let device_id = "test-device".to_string();

    // Sign
    let signature = ffi_sign_pkarr_key_binding(
        ed25519_sk_bytes.to_vec(),
        x25519_pk.clone(),
        device_id.clone(),
    )
    .unwrap();

    assert_eq!(signature.len(), 64);

    // Verify
    let valid = ffi_verify_pkarr_key_binding(
        ed25519_pk.to_vec(),
        x25519_pk,
        signature,
        device_id,
    )
    .unwrap();

    assert!(valid);
}

#[test]
fn test_ffi_pkarr_verify_fails_with_wrong_device() {
    use ed25519_dalek::SigningKey;
    use rand::RngCore;

    let mut ed25519_sk_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut ed25519_sk_bytes);
    let signing_key = SigningKey::from_bytes(&ed25519_sk_bytes);
    let ed25519_pk = signing_key.verifying_key().to_bytes();

    let x25519_pk = vec![99u8; 32];

    let signature = ffi_sign_pkarr_key_binding(
        ed25519_sk_bytes.to_vec(),
        x25519_pk.clone(),
        "correct-device".to_string(),
    )
    .unwrap();

    // Verify with wrong device should fail
    let valid = ffi_verify_pkarr_key_binding(
        ed25519_pk.to_vec(),
        x25519_pk,
        signature,
        "wrong-device".to_string(),
    )
    .unwrap();

    assert!(!valid);
}

#[test]
fn test_ffi_pkarr_parse_and_verify_full_flow() {
    use ed25519_dalek::SigningKey;
    use rand::RngCore;

    let mut ed25519_sk_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut ed25519_sk_bytes);
    let signing_key = SigningKey::from_bytes(&ed25519_sk_bytes);
    let ed25519_pk = signing_key.verifying_key().to_bytes();

    let x25519_pk = vec![99u8; 32];
    let device_id = "my-phone".to_string();

    // Sign
    let signature = ffi_sign_pkarr_key_binding(
        ed25519_sk_bytes.to_vec(),
        x25519_pk.clone(),
        device_id.clone(),
    )
    .unwrap();

    // Format for publication
    let txt = ffi_format_x25519_for_pkarr(x25519_pk.clone(), Some(signature)).unwrap();

    // Parse and verify (simulates lookup from pkarr)
    let verified_key =
        ffi_parse_and_verify_pkarr_key(txt, ed25519_pk.to_vec(), device_id).unwrap();

    assert_eq!(verified_key, x25519_pk);
}

#[test]
fn test_ffi_pkarr_subdomain_format() {
    assert_eq!(ffi_pkarr_noise_subdomain("phone1".to_string()), "_noise.phone1");
    assert_eq!(
        ffi_pkarr_noise_subdomain("laptop-main".to_string()),
        "_noise.laptop-main"
    );
}

#[test]
fn test_ffi_pkarr_binding_message_deterministic() {
    let ed25519_pk = vec![1u8; 32];
    let x25519_pk = vec![2u8; 32];
    let device_id = "device".to_string();

    let msg1 = ffi_create_pkarr_binding_message(
        ed25519_pk.clone(),
        x25519_pk.clone(),
        device_id.clone(),
    )
    .unwrap();

    let msg2 = ffi_create_pkarr_binding_message(ed25519_pk, x25519_pk, device_id).unwrap();

    assert_eq!(msg1, msg2);
    assert_eq!(msg1.len(), 32);
}

// ============================================================================
// FfiRawNoiseManager Tests
// ============================================================================

fn default_config() -> FfiMobileConfig {
    FfiMobileConfig {
        auto_reconnect: true,
        max_reconnect_attempts: 3,
        reconnect_delay_ms: 1000,
        battery_saver: false,
        chunk_size: 65535,
    }
}

#[test]
fn test_ffi_raw_manager_creation() {
    let manager = FfiRawNoiseManager::new(default_config());
    assert!(manager.list_sessions().is_empty());
}

#[test]
fn test_ffi_raw_manager_ik_raw_handshake() {
    // Derive keys for client and server
    let client_seed = vec![1u8; 32];
    let server_seed = vec![2u8; 32];

    let client_sk = ffi_derive_x25519_static(client_seed, b"client".to_vec()).unwrap();
    let server_sk = ffi_derive_x25519_static(server_seed, b"server".to_vec()).unwrap();
    let server_pk = ffi_x25519_public_key(server_sk.clone()).unwrap();

    // Create managers
    let client_mgr = FfiRawNoiseManager::new(default_config());
    let server_mgr = FfiRawNoiseManager::new(default_config());

    // Client initiates IK-raw
    let init_result = client_mgr
        .initiate_ik_raw(client_sk.clone(), server_pk)
        .unwrap();

    assert!(!init_result.session_id.is_empty());
    assert!(!init_result.message.is_empty());

    // Server accepts
    let accept_result = server_mgr
        .accept_ik_raw(server_sk, init_result.message)
        .unwrap();

    assert!(!accept_result.session_id.is_empty());
    assert!(!accept_result.response.is_empty());

    // Client completes handshake
    let _final_msg = client_mgr
        .complete_handshake(init_result.session_id.clone(), accept_result.response)
        .unwrap();

    // Both should have active sessions
    assert_eq!(client_mgr.list_sessions().len(), 1);
    assert_eq!(server_mgr.list_sessions().len(), 1);

    // Test encryption
    let plaintext = b"Hello from client!".to_vec();
    let ciphertext = client_mgr
        .encrypt(init_result.session_id.clone(), plaintext.clone())
        .unwrap();

    let decrypted = server_mgr
        .decrypt(accept_result.session_id.clone(), ciphertext)
        .unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_ffi_raw_manager_anonymous_pattern() {
    let server_seed = vec![3u8; 32];
    let server_sk = ffi_derive_x25519_static(server_seed, b"server".to_vec()).unwrap();
    let server_pk = ffi_x25519_public_key(server_sk.clone()).unwrap();

    let client_mgr = FfiRawNoiseManager::new(default_config());
    let server_mgr = FfiRawNoiseManager::new(default_config());

    // Client initiates N pattern (anonymous)
    let init_result = client_mgr.initiate_anonymous(server_pk).unwrap();

    // Server accepts anonymous connection
    let accept_result = server_mgr
        .accept_anonymous(server_sk, init_result.message)
        .unwrap();

    // N pattern has no client static key
    assert!(accept_result.client_static_pk.is_none());

    // N pattern is one-round, client should be in transport mode immediately
    assert_eq!(client_mgr.list_sessions().len(), 1);
    assert_eq!(server_mgr.list_sessions().len(), 1);
}

#[test]
fn test_ffi_raw_manager_ephemeral_pattern() {
    let client_mgr = FfiRawNoiseManager::new(default_config());
    let server_mgr = FfiRawNoiseManager::new(default_config());

    // Client initiates NN pattern (both anonymous)
    let init_result = client_mgr.initiate_ephemeral().unwrap();

    // Server accepts ephemeral connection
    let accept_result = server_mgr
        .accept_ephemeral(init_result.message)
        .unwrap();

    // Complete handshake
    let _ = client_mgr
        .complete_handshake(init_result.session_id.clone(), accept_result.response)
        .unwrap();

    // Both should have sessions
    assert_eq!(client_mgr.list_sessions().len(), 1);
    assert_eq!(server_mgr.list_sessions().len(), 1);
}

#[test]
fn test_ffi_raw_manager_session_lifecycle() {
    let manager = FfiRawNoiseManager::new(default_config());

    assert!(manager.list_sessions().is_empty());

    // Create a session via ephemeral pattern (simplest)
    let init_result = manager.initiate_ephemeral().unwrap();
    
    // Session should be in pending state (not yet complete)
    // But session_id should be trackable
    assert!(!init_result.session_id.is_empty());

    // Remove the session
    manager.remove_session(init_result.session_id.clone());
}

#[test]
fn test_ffi_raw_manager_invalid_key_lengths() {
    let manager = FfiRawNoiseManager::new(default_config());

    // Invalid local key length
    let result = manager.initiate_ik_raw(vec![0u8; 16], vec![0u8; 32]);
    assert!(result.is_err());

    // Invalid server key length
    let result = manager.initiate_ik_raw(vec![0u8; 32], vec![0u8; 16]);
    assert!(result.is_err());
}

#[test]
fn test_ffi_raw_manager_session_operations() {
    let manager = FfiRawNoiseManager::new(default_config());

    // Initiate a session
    let init_result = manager.initiate_ephemeral().unwrap();
    
    // Session should be listed (in pending state)
    // Note: Pending sessions might not be in the main list until complete
    // This test verifies the API doesn't panic
    let _ = manager.list_sessions();
    
    // Remove session
    manager.remove_session(init_result.session_id);
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[test]
fn test_ffi_pkarr_invalid_signature_length() {
    let result = ffi_format_x25519_for_pkarr(vec![0u8; 32], Some(vec![0u8; 32])); // 32 instead of 64
    assert!(result.is_err());
}

#[test]
fn test_ffi_pkarr_invalid_key_length() {
    assert!(ffi_sign_pkarr_key_binding(vec![0u8; 16], vec![0u8; 32], "".to_string()).is_err());
    assert!(ffi_sign_pkarr_key_binding(vec![0u8; 32], vec![0u8; 16], "".to_string()).is_err());
}

#[test]
fn test_ffi_pkarr_malformed_txt_record() {
    let result = ffi_parse_x25519_from_pkarr("invalid".to_string());
    assert!(result.is_err());

    let result = ffi_parse_x25519_from_pkarr("v=2;k=invalid".to_string());
    assert!(result.is_err());
}

