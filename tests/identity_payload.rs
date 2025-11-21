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
    let epoch = 42;
    let role = Role::Client;
    let hint = Some("test-server");

    let msg1 = make_binding_message(
        pattern,
        prologue,
        &ed25519_pub,
        &local_x25519,
        Some(&remote_x25519),
        epoch,
        role,
        hint,
    );

    let msg2 = make_binding_message(
        pattern,
        prologue,
        &ed25519_pub,
        &local_x25519,
        Some(&remote_x25519),
        epoch,
        role,
        hint,
    );

    assert_eq!(msg1, msg2, "Binding message should be deterministic");
}

#[test]
fn test_binding_message_uniqueness() {
    // Test that different inputs produce different binding messages
    let base_params = (
        "IK",
        b"prologue",
        [1u8; 32],
        [2u8; 32],
        Some([3u8; 32]),
        42u32,
        Role::Client,
        Some("hint"),
    );

    let base_msg = make_binding_message(
        base_params.0,
        base_params.1,
        &base_params.2,
        &base_params.3,
        Some(&base_params.4.unwrap()),
        base_params.5,
        base_params.6,
        base_params.7,
    );

    // Change pattern
    let msg_diff_pattern = make_binding_message(
        "XX",
        base_params.1,
        &base_params.2,
        &base_params.3,
        Some(&base_params.4.unwrap()),
        base_params.5,
        base_params.6,
        base_params.7,
    );
    assert_ne!(
        base_msg, msg_diff_pattern,
        "Different pattern should change message"
    );

    // Change epoch
    let msg_diff_epoch = make_binding_message(
        base_params.0,
        base_params.1,
        &base_params.2,
        &base_params.3,
        Some(&base_params.4.unwrap()),
        99,
        base_params.6,
        base_params.7,
    );
    assert_ne!(
        base_msg, msg_diff_epoch,
        "Different epoch should change message"
    );

    // Change role
    let msg_diff_role = make_binding_message(
        base_params.0,
        base_params.1,
        &base_params.2,
        &base_params.3,
        Some(&base_params.4.unwrap()),
        base_params.5,
        Role::Server,
        base_params.7,
    );
    assert_ne!(
        base_msg, msg_diff_role,
        "Different role should change message"
    );

    // Change ed25519 key
    let mut different_ed25519 = base_params.2;
    different_ed25519[0] ^= 1;
    let msg_diff_ed25519 = make_binding_message(
        base_params.0,
        base_params.1,
        &different_ed25519,
        &base_params.3,
        Some(&base_params.4.unwrap()),
        base_params.5,
        base_params.6,
        base_params.7,
    );
    assert_ne!(
        base_msg, msg_diff_ed25519,
        "Different Ed25519 key should change message"
    );
}

#[test]
fn test_valid_signature_round_trip() {
    // Test that a valid signature can be created and verified
    let signing_key = SigningKey::from_bytes(&[42u8; 32]);
    let verifying_key = signing_key.verifying_key();

    let binding_msg = make_binding_message(
        "IK",
        b"test-prologue",
        &verifying_key.to_bytes(),
        &[1u8; 32],
        Some(&[2u8; 32]),
        1,
        Role::Client,
        None,
    );

    let signature = sign_identity_payload(&signing_key, &binding_msg);
    assert_eq!(signature.len(), 64, "Signature should be 64 bytes");

    let verified = verify_identity_payload(&verifying_key, &binding_msg, &signature);
    assert!(verified, "Valid signature should verify successfully");
}

#[test]
fn test_invalid_signature_rejection() {
    // Test that an invalid signature is rejected
    let signing_key = SigningKey::from_bytes(&[42u8; 32]);
    let verifying_key = signing_key.verifying_key();

    let binding_msg = make_binding_message(
        "IK",
        b"test-prologue",
        &verifying_key.to_bytes(),
        &[1u8; 32],
        None,
        1,
        Role::Client,
        None,
    );

    let signature = sign_identity_payload(&signing_key, &binding_msg);

    // Corrupt the signature
    let mut corrupted_sig = signature;
    corrupted_sig[0] ^= 1;

    let verified = verify_identity_payload(&verifying_key, &binding_msg, &corrupted_sig);
    assert!(!verified, "Corrupted signature should fail verification");
}

#[test]
fn test_wrong_key_signature_rejection() {
    // Test that a signature from a different key is rejected
    let signing_key1 = SigningKey::from_bytes(&[1u8; 32]);
    let signing_key2 = SigningKey::from_bytes(&[2u8; 32]);
    let verifying_key2 = signing_key2.verifying_key();

    let binding_msg = make_binding_message(
        "IK",
        b"test-prologue",
        &verifying_key2.to_bytes(),
        &[1u8; 32],
        None,
        1,
        Role::Server,
        None,
    );

    // Sign with key1
    let signature = sign_identity_payload(&signing_key1, &binding_msg);

    // Try to verify with key2
    let verified = verify_identity_payload(&verifying_key2, &binding_msg, &signature);
    assert!(
        !verified,
        "Signature from wrong key should fail verification"
    );
}

#[test]
fn test_modified_message_signature_rejection() {
    // Test that modifying the message after signing causes verification failure
    let signing_key = SigningKey::from_bytes(&[42u8; 32]);
    let verifying_key = signing_key.verifying_key();

    let binding_msg = make_binding_message(
        "IK",
        b"original-prologue",
        &verifying_key.to_bytes(),
        &[1u8; 32],
        None,
        1,
        Role::Client,
        None,
    );

    let signature = sign_identity_payload(&signing_key, &binding_msg);

    // Create a different message
    let different_msg = make_binding_message(
        "IK",
        b"modified-prologue",
        &verifying_key.to_bytes(),
        &[1u8; 32],
        None,
        1,
        Role::Client,
        None,
    );

    let verified = verify_identity_payload(&verifying_key, &different_msg, &signature);
    assert!(!verified, "Signature should fail for modified message");
}

#[test]
fn test_signature_with_all_parameters() {
    // Test signature with all optional parameters present
    let signing_key = SigningKey::from_bytes(&[99u8; 32]);
    let verifying_key = signing_key.verifying_key();

    let binding_msg = make_binding_message(
        "IK",
        b"full-prologue",
        &verifying_key.to_bytes(),
        &[10u8; 32],
        Some(&[20u8; 32]),
        42,
        Role::Server,
        Some("server-hint"),
    );

    let signature = sign_identity_payload(&signing_key, &binding_msg);
    let verified = verify_identity_payload(&verifying_key, &binding_msg, &signature);
    assert!(verified, "Signature with all parameters should verify");
}

#[test]
fn test_signature_without_optional_parameters() {
    // Test signature with optional parameters omitted
    let signing_key = SigningKey::from_bytes(&[55u8; 32]);
    let verifying_key = signing_key.verifying_key();

    let binding_msg = make_binding_message(
        "XX",
        b"minimal-prologue",
        &verifying_key.to_bytes(),
        &[5u8; 32],
        None, // No remote key (XX pattern)
        1,
        Role::Client,
        None, // No hint
    );

    let signature = sign_identity_payload(&signing_key, &binding_msg);
    let verified = verify_identity_payload(&verifying_key, &binding_msg, &signature);
    assert!(
        verified,
        "Signature without optional parameters should verify"
    );
}

#[test]
fn test_malformed_signature_rejection() {
    // Test that malformed signatures are rejected
    let signing_key = SigningKey::from_bytes(&[77u8; 32]);
    let verifying_key = signing_key.verifying_key();

    let binding_msg = make_binding_message(
        "IK",
        b"test",
        &verifying_key.to_bytes(),
        &[1u8; 32],
        None,
        1,
        Role::Client,
        None,
    );

    // All-zero signature (clearly invalid)
    let zero_sig = [0u8; 64];
    let verified = verify_identity_payload(&verifying_key, &binding_msg, &zero_sig);
    assert!(!verified, "All-zero signature should be rejected");

    // All-ones signature (clearly invalid)
    let ones_sig = [0xFFu8; 64];
    let verified = verify_identity_payload(&verifying_key, &binding_msg, &ones_sig);
    assert!(!verified, "All-ones signature should be rejected");
}

#[test]
fn test_role_binding_integrity() {
    // Test that client and server roles produce different binding messages
    let ed25519_pub = [1u8; 32];
    let local_x25519 = [2u8; 32];
    let remote_x25519 = [3u8; 32];

    let client_msg = make_binding_message(
        "IK",
        b"test",
        &ed25519_pub,
        &local_x25519,
        Some(&remote_x25519),
        1,
        Role::Client,
        None,
    );

    let server_msg = make_binding_message(
        "IK",
        b"test",
        &ed25519_pub,
        &local_x25519,
        Some(&remote_x25519),
        1,
        Role::Server,
        None,
    );

    assert_ne!(
        client_msg, server_msg,
        "Client and server roles must produce different binding messages"
    );
}

#[test]
fn test_epoch_binding_integrity() {
    // Test that different epochs produce different binding messages
    let ed25519_pub = [1u8; 32];
    let x25519_pub = [2u8; 32];

    let msg_epoch_1 = make_binding_message(
        "IK",
        b"test",
        &ed25519_pub,
        &x25519_pub,
        None,
        1,
        Role::Client,
        None,
    );

    let msg_epoch_2 = make_binding_message(
        "IK",
        b"test",
        &ed25519_pub,
        &x25519_pub,
        None,
        2,
        Role::Client,
        None,
    );

    assert_ne!(
        msg_epoch_1, msg_epoch_2,
        "Different epochs must produce different binding messages"
    );
}

#[test]
fn test_cross_pattern_binding() {
    // Test that different Noise patterns produce different bindings
    let ed25519_pub = [1u8; 32];
    let x25519_pub = [2u8; 32];

    let msg_xx = make_binding_message(
        "XX",
        b"test",
        &ed25519_pub,
        &x25519_pub,
        None,
        1,
        Role::Client,
        None,
    );

    let msg_ik = make_binding_message(
        "IK",
        b"test",
        &ed25519_pub,
        &x25519_pub,
        None,
        1,
        Role::Client,
        None,
    );

    assert_ne!(
        msg_xx, msg_ik,
        "Different patterns must produce different binding messages"
    );
}

#[test]
fn test_multiple_signatures_same_key() {
    // Test that multiple signatures with the same key all verify correctly
    let signing_key = SigningKey::from_bytes(&[123u8; 32]);
    let verifying_key = signing_key.verifying_key();

    for i in 0..10 {
        let binding_msg = make_binding_message(
            "IK",
            b"test",
            &verifying_key.to_bytes(),
            &[i as u8; 32],
            None,
            i,
            Role::Client,
            None,
        );

        let signature = sign_identity_payload(&signing_key, &binding_msg);
        let verified = verify_identity_payload(&verifying_key, &binding_msg, &signature);
        assert!(verified, "Signature {} should verify successfully", i);
    }
}

#[test]
fn test_signature_independence() {
    // Test that signatures for different messages are independent
    let signing_key = SigningKey::from_bytes(&[200u8; 32]);
    let verifying_key = signing_key.verifying_key();

    let msg1 = make_binding_message(
        "IK",
        b"message1",
        &verifying_key.to_bytes(),
        &[1u8; 32],
        None,
        1,
        Role::Client,
        None,
    );

    let msg2 = make_binding_message(
        "IK",
        b"message2",
        &verifying_key.to_bytes(),
        &[2u8; 32],
        None,
        2,
        Role::Client,
        None,
    );

    let sig1 = sign_identity_payload(&signing_key, &msg1);
    let sig2 = sign_identity_payload(&signing_key, &msg2);

    // Each signature should verify its own message
    assert!(verify_identity_payload(&verifying_key, &msg1, &sig1));
    assert!(verify_identity_payload(&verifying_key, &msg2, &sig2));

    // But not the other message
    assert!(!verify_identity_payload(&verifying_key, &msg1, &sig2));
    assert!(!verify_identity_payload(&verifying_key, &msg2, &sig1));
}
