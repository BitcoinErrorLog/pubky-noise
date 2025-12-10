//! Comprehensive tests for identity payload signature operations.
//!
//! This module tests the critical authentication functions that bind
//! Ed25519 identities to Noise X25519 session keys.

use ed25519_dalek::{SigningKey, VerifyingKey};
use pubky_noise::identity_payload::{
    make_binding_message, sign_identity_payload, verify_identity_payload, BindingMessageParams,
    Role,
};

#[test]
fn test_binding_message_consistency() {
    // Test that the same inputs always produce the same binding message
    let ed25519_pub = [1u8; 32];
    let local_x25519 = [2u8; 32];
    let remote_x25519 = [3u8; 32];

    let msg1 = make_binding_message(&BindingMessageParams {
        pattern_tag: "IK",
        prologue: b"test-prologue",
        ed25519_pub: &ed25519_pub,
        local_noise_pub: &local_x25519,
        remote_noise_pub: Some(&remote_x25519),
        role: Role::Client,
        server_hint: Some("test-server"),
    });

    let msg2 = make_binding_message(&BindingMessageParams {
        pattern_tag: "IK",
        prologue: b"test-prologue",
        ed25519_pub: &ed25519_pub,
        local_noise_pub: &local_x25519,
        remote_noise_pub: Some(&remote_x25519),
        role: Role::Client,
        server_hint: Some("test-server"),
    });

    assert_eq!(msg1, msg2, "Binding message should be deterministic");
}

#[test]
fn test_binding_message_uniqueness() {
    let ed25519_pub = [1u8; 32];
    let local_x25519 = [2u8; 32];
    let remote_x25519 = [3u8; 32];

    let base_msg = make_binding_message(&BindingMessageParams {
        pattern_tag: "IK",
        prologue: b"prologue",
        ed25519_pub: &ed25519_pub,
        local_noise_pub: &local_x25519,
        remote_noise_pub: Some(&remote_x25519),
        role: Role::Client,
        server_hint: Some("hint"),
    });

    // Change pattern
    let msg_diff_pattern = make_binding_message(&BindingMessageParams {
        pattern_tag: "XX",
        prologue: b"prologue",
        ed25519_pub: &ed25519_pub,
        local_noise_pub: &local_x25519,
        remote_noise_pub: Some(&remote_x25519),
        role: Role::Client,
        server_hint: Some("hint"),
    });
    assert_ne!(
        base_msg, msg_diff_pattern,
        "Different pattern should change message"
    );

    // Change role
    let msg_diff_role = make_binding_message(&BindingMessageParams {
        pattern_tag: "IK",
        prologue: b"prologue",
        ed25519_pub: &ed25519_pub,
        local_noise_pub: &local_x25519,
        remote_noise_pub: Some(&remote_x25519),
        role: Role::Server,
        server_hint: Some("hint"),
    });
    assert_ne!(
        base_msg, msg_diff_role,
        "Different role should change message"
    );

    // Change ed25519 key
    let mut different_ed = ed25519_pub;
    different_ed[0] ^= 0xff;
    let msg_diff_ed25519 = make_binding_message(&BindingMessageParams {
        pattern_tag: "IK",
        prologue: b"prologue",
        ed25519_pub: &different_ed,
        local_noise_pub: &local_x25519,
        remote_noise_pub: Some(&remote_x25519),
        role: Role::Client,
        server_hint: Some("hint"),
    });
    assert_ne!(
        base_msg, msg_diff_ed25519,
        "Different ed25519 key should change message"
    );
}

#[test]
fn test_signature_roundtrip() {
    let secret_bytes = [42u8; 32];
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key = VerifyingKey::from(&signing_key);

    let ed25519_pub = [1u8; 32];
    let local_x25519 = [2u8; 32];

    let binding_msg = make_binding_message(&BindingMessageParams {
        pattern_tag: "IK",
        prologue: b"test",
        ed25519_pub: &ed25519_pub,
        local_noise_pub: &local_x25519,
        remote_noise_pub: None,
        role: Role::Client,
        server_hint: None,
    });

    let signature = sign_identity_payload(&signing_key, &binding_msg);
    let is_valid = verify_identity_payload(&verifying_key, &binding_msg, &signature);

    assert!(is_valid, "Valid signature should verify");
}

#[test]
fn test_signature_wrong_key() {
    let secret1 = [42u8; 32];
    let secret2 = [43u8; 32];
    let signing_key = SigningKey::from_bytes(&secret1);
    let wrong_verifying_key = VerifyingKey::from(&SigningKey::from_bytes(&secret2));

    let ed25519_pub = [1u8; 32];
    let local_x25519 = [2u8; 32];

    let binding_msg = make_binding_message(&BindingMessageParams {
        pattern_tag: "IK",
        prologue: b"test",
        ed25519_pub: &ed25519_pub,
        local_noise_pub: &local_x25519,
        remote_noise_pub: None,
        role: Role::Client,
        server_hint: None,
    });

    let signature = sign_identity_payload(&signing_key, &binding_msg);
    let is_valid = verify_identity_payload(&wrong_verifying_key, &binding_msg, &signature);

    assert!(!is_valid, "Wrong key should fail verification");
}

#[test]
fn test_signature_tampered_message() {
    let secret_bytes = [42u8; 32];
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key = VerifyingKey::from(&signing_key);

    let ed25519_pub = [1u8; 32];
    let local_x25519 = [2u8; 32];

    let binding_msg = make_binding_message(&BindingMessageParams {
        pattern_tag: "IK",
        prologue: b"test",
        ed25519_pub: &ed25519_pub,
        local_noise_pub: &local_x25519,
        remote_noise_pub: None,
        role: Role::Client,
        server_hint: None,
    });

    let signature = sign_identity_payload(&signing_key, &binding_msg);

    // Different message should fail
    let different_msg = make_binding_message(&BindingMessageParams {
        pattern_tag: "XX",
        prologue: b"test",
        ed25519_pub: &ed25519_pub,
        local_noise_pub: &local_x25519,
        remote_noise_pub: None,
        role: Role::Client,
        server_hint: None,
    });

    let is_valid = verify_identity_payload(&verifying_key, &different_msg, &signature);
    assert!(!is_valid, "Tampered message should fail verification");
}

#[test]
fn test_signature_invalid_format() {
    let secret_bytes = [42u8; 32];
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key = VerifyingKey::from(&signing_key);

    let ed25519_pub = [1u8; 32];
    let local_x25519 = [2u8; 32];

    let binding_msg = make_binding_message(&BindingMessageParams {
        pattern_tag: "IK",
        prologue: b"test",
        ed25519_pub: &ed25519_pub,
        local_noise_pub: &local_x25519,
        remote_noise_pub: None,
        role: Role::Client,
        server_hint: None,
    });

    // Invalid signature (all zeros)
    let invalid_sig = [0u8; 64];
    let is_valid = verify_identity_payload(&verifying_key, &binding_msg, &invalid_sig);
    assert!(!is_valid, "Invalid signature should fail verification");
}

#[test]
fn test_role_differentiation() {
    let ed25519_pub = [1u8; 32];
    let local_x25519 = [2u8; 32];

    let client_msg = make_binding_message(&BindingMessageParams {
        pattern_tag: "IK",
        prologue: b"test",
        ed25519_pub: &ed25519_pub,
        local_noise_pub: &local_x25519,
        remote_noise_pub: None,
        role: Role::Client,
        server_hint: None,
    });

    let server_msg = make_binding_message(&BindingMessageParams {
        pattern_tag: "IK",
        prologue: b"test",
        ed25519_pub: &ed25519_pub,
        local_noise_pub: &local_x25519,
        remote_noise_pub: None,
        role: Role::Server,
        server_hint: None,
    });

    assert_ne!(
        client_msg, server_msg,
        "Different roles should produce different bindings"
    );
}

#[test]
fn test_pattern_differentiation() {
    let ed25519_pub = [1u8; 32];
    let local_x25519 = [2u8; 32];

    let msg_xx = make_binding_message(&BindingMessageParams {
        pattern_tag: "XX",
        prologue: b"test",
        ed25519_pub: &ed25519_pub,
        local_noise_pub: &local_x25519,
        remote_noise_pub: None,
        role: Role::Client,
        server_hint: None,
    });

    let msg_ik = make_binding_message(&BindingMessageParams {
        pattern_tag: "IK",
        prologue: b"test",
        ed25519_pub: &ed25519_pub,
        local_noise_pub: &local_x25519,
        remote_noise_pub: None,
        role: Role::Client,
        server_hint: None,
    });

    assert_ne!(
        msg_xx, msg_ik,
        "Different patterns should produce different bindings"
    );
}

#[test]
fn test_multiple_signatures_same_message() {
    let secret_bytes = [42u8; 32];
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key = VerifyingKey::from(&signing_key);

    let ed25519_pub = [1u8; 32];
    let local_x25519 = [2u8; 32];

    let binding_msg = make_binding_message(&BindingMessageParams {
        pattern_tag: "IK",
        prologue: b"test",
        ed25519_pub: &ed25519_pub,
        local_noise_pub: &local_x25519,
        remote_noise_pub: None,
        role: Role::Client,
        server_hint: None,
    });

    // Create two signatures for the same message
    let sig1 = sign_identity_payload(&signing_key, &binding_msg);
    let sig2 = sign_identity_payload(&signing_key, &binding_msg);

    // Ed25519 is deterministic, so signatures should be identical
    assert_eq!(
        sig1, sig2,
        "Deterministic signing should produce identical signatures"
    );

    // Both should verify
    assert!(verify_identity_payload(&verifying_key, &binding_msg, &sig1));
    assert!(verify_identity_payload(&verifying_key, &binding_msg, &sig2));
}

#[test]
fn test_binding_message_32_bytes() {
    let ed25519_pub = [1u8; 32];
    let local_x25519 = [2u8; 32];

    let msg1 = make_binding_message(&BindingMessageParams {
        pattern_tag: "IK",
        prologue: b"test",
        ed25519_pub: &ed25519_pub,
        local_noise_pub: &local_x25519,
        remote_noise_pub: None,
        role: Role::Client,
        server_hint: None,
    });

    let msg2 = make_binding_message(&BindingMessageParams {
        pattern_tag: "XX",
        prologue: b"very-long-prologue-that-is-different",
        ed25519_pub: &ed25519_pub,
        local_noise_pub: &local_x25519,
        remote_noise_pub: Some(&[99u8; 32]),
        role: Role::Server,
        server_hint: Some("long-server-hint.example.com"),
    });

    assert_eq!(msg1.len(), 32, "Binding message should always be 32 bytes");
    assert_eq!(msg2.len(), 32, "Binding message should always be 32 bytes");
}
