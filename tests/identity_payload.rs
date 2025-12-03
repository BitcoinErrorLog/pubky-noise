//! Comprehensive tests for identity payload signature operations
//!
//! This module tests the critical authentication functions that bind
//! Ed25519 identities to Noise X25519 session keys.

use ed25519_dalek::{SigningKey, VerifyingKey};
use pubky_noise::identity_payload::{
    make_binding_message, sign_identity_payload, verify_identity_payload, Role,
};

#[test]
fn test_binding_message_consistency() {
    // Test that the same inputs always produce the same binding message
    let pattern = "IK";
    let prologue = b"test-prologue";
    let ed25519_pub = [1u8; 32];
    let local_x25519 = [2u8; 32];
    let remote_x25519 = [3u8; 32];
    let role = Role::Client;

    let msg1 = make_binding_message(
        pattern,
        prologue,
        &ed25519_pub,
        &local_x25519,
        Some(&remote_x25519),
        role,
    );

    let msg2 = make_binding_message(
        pattern,
        prologue,
        &ed25519_pub,
        &local_x25519,
        Some(&remote_x25519),
        role,
    );

    assert_eq!(msg1, msg2, "Binding message should be deterministic");
}

#[test]
fn test_binding_message_uniqueness() {
    // Test that different inputs produce different binding messages
    let pattern = "IK";
    let prologue = b"test-prologue";
    let ed25519_pub = [1u8; 32];
    let local_x25519 = [2u8; 32];
    let remote_x25519 = [3u8; 32];
    let role = Role::Client;

    let baseline = make_binding_message(
        pattern,
        prologue,
        &ed25519_pub,
        &local_x25519,
        Some(&remote_x25519),
        role,
    );

    // Different pattern
    let msg_xx = make_binding_message(
        "XX",
        prologue,
        &ed25519_pub,
        &local_x25519,
        Some(&remote_x25519),
        role,
    );
    assert_ne!(baseline, msg_xx, "Different pattern should change message");

    // Different prologue
    let msg_prologue = make_binding_message(
        pattern,
        b"different",
        &ed25519_pub,
        &local_x25519,
        Some(&remote_x25519),
        role,
    );
    assert_ne!(
        baseline, msg_prologue,
        "Different prologue should change message"
    );

    // Different ed25519 key
    let mut diff_ed = ed25519_pub;
    diff_ed[0] ^= 1;
    let msg_ed = make_binding_message(
        pattern,
        prologue,
        &diff_ed,
        &local_x25519,
        Some(&remote_x25519),
        role,
    );
    assert_ne!(
        baseline, msg_ed,
        "Different ed25519 key should change message"
    );

    // Different local key
    let mut diff_local = local_x25519;
    diff_local[0] ^= 1;
    let msg_local = make_binding_message(
        pattern,
        prologue,
        &ed25519_pub,
        &diff_local,
        Some(&remote_x25519),
        role,
    );
    assert_ne!(
        baseline, msg_local,
        "Different local key should change message"
    );

    // Different remote key
    let mut diff_remote = remote_x25519;
    diff_remote[0] ^= 1;
    let msg_remote = make_binding_message(
        pattern,
        prologue,
        &ed25519_pub,
        &local_x25519,
        Some(&diff_remote),
        role,
    );
    assert_ne!(
        baseline, msg_remote,
        "Different remote key should change message"
    );

    // Different role
    let msg_role = make_binding_message(
        pattern,
        prologue,
        &ed25519_pub,
        &local_x25519,
        Some(&remote_x25519),
        Role::Server,
    );
    assert_ne!(baseline, msg_role, "Different role should change message");
}

#[test]
fn test_binding_without_remote_key() {
    // XX pattern initial messages don't know remote static
    let pattern = "XX";
    let prologue = b"test";
    let ed25519_pub = [1u8; 32];
    let local_x25519 = [2u8; 32];

    let msg_none = make_binding_message(
        pattern,
        prologue,
        &ed25519_pub,
        &local_x25519,
        None,
        Role::Client,
    );

    let msg_some = make_binding_message(
        pattern,
        prologue,
        &ed25519_pub,
        &local_x25519,
        Some(&[3u8; 32]),
        Role::Client,
    );

    assert_ne!(
        msg_none, msg_some,
        "Remote key presence should change binding"
    );
}

#[test]
fn test_signature_roundtrip() {
    let seed = [42u8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    let binding_msg = make_binding_message(
        "IK",
        b"test",
        &[1u8; 32],
        &[2u8; 32],
        Some(&[3u8; 32]),
        Role::Client,
    );

    let sig = sign_identity_payload(&signing_key, &binding_msg);
    let valid = verify_identity_payload(&verifying_key, &binding_msg, &sig);

    assert!(valid, "Valid signature should verify");
}

#[test]
fn test_signature_wrong_key() {
    let seed1 = [42u8; 32];
    let seed2 = [99u8; 32];
    let signing_key = SigningKey::from_bytes(&seed1);
    let wrong_key = SigningKey::from_bytes(&seed2).verifying_key();

    let binding_msg = [1u8; 32];
    let sig = sign_identity_payload(&signing_key, &binding_msg);

    let valid = verify_identity_payload(&wrong_key, &binding_msg, &sig);
    assert!(!valid, "Wrong key should fail verification");
}

#[test]
fn test_signature_modified_message() {
    let seed = [42u8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    let binding_msg = [1u8; 32];
    let sig = sign_identity_payload(&signing_key, &binding_msg);

    let mut modified = binding_msg;
    modified[0] ^= 1;

    let valid = verify_identity_payload(&verifying_key, &modified, &sig);
    assert!(!valid, "Modified message should fail verification");
}

#[test]
fn test_client_server_role_separation() {
    let pattern = "IK";
    let prologue = b"test";
    let ed25519_pub = [1u8; 32];
    let local = [2u8; 32];
    let remote = [3u8; 32];

    let client_msg = make_binding_message(
        pattern,
        prologue,
        &ed25519_pub,
        &local,
        Some(&remote),
        Role::Client,
    );

    let server_msg = make_binding_message(
        pattern,
        prologue,
        &ed25519_pub,
        &local,
        Some(&remote),
        Role::Server,
    );

    assert_ne!(
        client_msg, server_msg,
        "Client and server bindings must differ"
    );
}

#[test]
fn test_binding_message_length() {
    let msg = make_binding_message(
        "IK",
        b"test",
        &[1u8; 32],
        &[2u8; 32],
        Some(&[3u8; 32]),
        Role::Client,
    );

    assert_eq!(
        msg.len(),
        32,
        "Binding message should be 32 bytes (BLAKE2s output)"
    );
}

#[test]
fn test_binding_message_not_all_zeros() {
    let msg = make_binding_message(
        "IK",
        b"test",
        &[0u8; 32],
        &[0u8; 32],
        Some(&[0u8; 32]),
        Role::Client,
    );

    assert_ne!(
        msg, [0u8; 32],
        "Binding message should not be all zeros even with zero keys"
    );
}
