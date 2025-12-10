//! Tests for identity payload binding and signature verification.

use ed25519_dalek::{SigningKey, VerifyingKey, SECRET_KEY_LENGTH};
use pubky_noise::identity_payload::{
    make_binding_message, sign_identity_payload, verify_identity_payload, BindingMessageParams,
    Role,
};

/// Test that binding message generation is deterministic
#[test]
fn test_binding_message_deterministic() {
    let ed_pub = [1u8; 32];
    let local_noise = [2u8; 32];
    let remote_noise = [3u8; 32];

    // Generate binding message twice with same inputs
    let msg1 = make_binding_message(&BindingMessageParams {
        pattern_tag: "IK",
        prologue: b"pubky-noise-v1",
        ed25519_pub: &ed_pub,
        local_noise_pub: &local_noise,
        remote_noise_pub: Some(&remote_noise),
        role: Role::Client,
        server_hint: Some("example.com"),
    });

    let msg2 = make_binding_message(&BindingMessageParams {
        pattern_tag: "IK",
        prologue: b"pubky-noise-v1",
        ed25519_pub: &ed_pub,
        local_noise_pub: &local_noise,
        remote_noise_pub: Some(&remote_noise),
        role: Role::Client,
        server_hint: Some("example.com"),
    });

    assert_eq!(msg1, msg2, "Binding message should be deterministic");
}

/// Test that different inputs produce different binding messages
#[test]
fn test_binding_message_uniqueness() {
    let ed_pub = [1u8; 32];
    let local_noise = [2u8; 32];
    let remote_noise = [3u8; 32];

    let msg_baseline = make_binding_message(&BindingMessageParams {
        pattern_tag: "IK",
        prologue: b"pubky-noise-v1",
        ed25519_pub: &ed_pub,
        local_noise_pub: &local_noise,
        remote_noise_pub: Some(&remote_noise),
        role: Role::Client,
        server_hint: None,
    });

    // Change pattern
    let msg_diff_pattern = make_binding_message(&BindingMessageParams {
        pattern_tag: "XX",
        prologue: b"pubky-noise-v1",
        ed25519_pub: &ed_pub,
        local_noise_pub: &local_noise,
        remote_noise_pub: Some(&remote_noise),
        role: Role::Client,
        server_hint: None,
    });
    assert_ne!(
        msg_baseline, msg_diff_pattern,
        "Different patterns should produce different bindings"
    );

    // Change prologue
    let msg_diff_prologue = make_binding_message(&BindingMessageParams {
        pattern_tag: "IK",
        prologue: b"different-prologue",
        ed25519_pub: &ed_pub,
        local_noise_pub: &local_noise,
        remote_noise_pub: Some(&remote_noise),
        role: Role::Client,
        server_hint: None,
    });
    assert_ne!(
        msg_baseline, msg_diff_prologue,
        "Different prologues should produce different bindings"
    );

    // Change ed25519 key
    let mut different_ed = ed_pub;
    different_ed[0] ^= 1;
    let msg_diff_ed = make_binding_message(&BindingMessageParams {
        pattern_tag: "IK",
        prologue: b"pubky-noise-v1",
        ed25519_pub: &different_ed,
        local_noise_pub: &local_noise,
        remote_noise_pub: Some(&remote_noise),
        role: Role::Client,
        server_hint: None,
    });
    assert_ne!(
        msg_baseline, msg_diff_ed,
        "Different ed25519 keys should produce different bindings"
    );

    // Change local noise key
    let mut different_local = local_noise;
    different_local[0] ^= 1;
    let msg_diff_local = make_binding_message(&BindingMessageParams {
        pattern_tag: "IK",
        prologue: b"pubky-noise-v1",
        ed25519_pub: &ed_pub,
        local_noise_pub: &different_local,
        remote_noise_pub: Some(&remote_noise),
        role: Role::Client,
        server_hint: None,
    });
    assert_ne!(
        msg_baseline, msg_diff_local,
        "Different local noise keys should produce different bindings"
    );

    // Change role
    let msg_diff_role = make_binding_message(&BindingMessageParams {
        pattern_tag: "IK",
        prologue: b"pubky-noise-v1",
        ed25519_pub: &ed_pub,
        local_noise_pub: &local_noise,
        remote_noise_pub: Some(&remote_noise),
        role: Role::Server,
        server_hint: None,
    });
    assert_ne!(
        msg_baseline, msg_diff_role,
        "Different roles should produce different bindings"
    );
}

/// Test signature generation and verification
#[test]
fn test_signature_roundtrip() {
    // Generate a keypair
    let secret_bytes = [42u8; SECRET_KEY_LENGTH];
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key = VerifyingKey::from(&signing_key);

    let ed_pub = [1u8; 32];
    let local_noise = [2u8; 32];

    // Create binding message
    let msg = make_binding_message(&BindingMessageParams {
        pattern_tag: "IK",
        prologue: b"pubky-noise-v1",
        ed25519_pub: &ed_pub,
        local_noise_pub: &local_noise,
        remote_noise_pub: None,
        role: Role::Client,
        server_hint: None,
    });

    // Sign and verify
    let sig = sign_identity_payload(&signing_key, &msg);
    assert!(
        verify_identity_payload(&verifying_key, &msg, &sig),
        "Signature should verify"
    );
}

/// Test that signature fails with wrong key
#[test]
fn test_signature_wrong_key() {
    // Generate two keypairs
    let secret1 = [42u8; SECRET_KEY_LENGTH];
    let secret2 = [43u8; SECRET_KEY_LENGTH];
    let signing_key = SigningKey::from_bytes(&secret1);
    let wrong_verifying_key = VerifyingKey::from(&SigningKey::from_bytes(&secret2));

    let ed_pub = [1u8; 32];
    let local_noise = [2u8; 32];

    // Create binding message
    let msg = make_binding_message(&BindingMessageParams {
        pattern_tag: "IK",
        prologue: b"pubky-noise-v1",
        ed25519_pub: &ed_pub,
        local_noise_pub: &local_noise,
        remote_noise_pub: None,
        role: Role::Client,
        server_hint: None,
    });

    // Sign with one key, verify with another
    let sig = sign_identity_payload(&signing_key, &msg);
    assert!(
        !verify_identity_payload(&wrong_verifying_key, &msg, &sig),
        "Signature should not verify with wrong key"
    );
}

/// Test that signature fails with tampered message
#[test]
fn test_signature_tampered_message() {
    let secret_bytes = [42u8; SECRET_KEY_LENGTH];
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key = VerifyingKey::from(&signing_key);

    let ed_pub = [1u8; 32];
    let local_noise = [2u8; 32];

    let msg = make_binding_message(&BindingMessageParams {
        pattern_tag: "IK",
        prologue: b"pubky-noise-v1",
        ed25519_pub: &ed_pub,
        local_noise_pub: &local_noise,
        remote_noise_pub: None,
        role: Role::Client,
        server_hint: None,
    });

    let sig = sign_identity_payload(&signing_key, &msg);

    // Tamper with message
    let mut tampered_msg = msg;
    tampered_msg[0] ^= 1;

    assert!(
        !verify_identity_payload(&verifying_key, &tampered_msg, &sig),
        "Signature should not verify with tampered message"
    );
}

/// Test role differentiation
#[test]
fn test_role_differentiation() {
    let ed_pub = [1u8; 32];
    let local_noise = [2u8; 32];

    let client_msg = make_binding_message(&BindingMessageParams {
        pattern_tag: "IK",
        prologue: b"pubky-noise-v1",
        ed25519_pub: &ed_pub,
        local_noise_pub: &local_noise,
        remote_noise_pub: None,
        role: Role::Client,
        server_hint: None,
    });

    let server_msg = make_binding_message(&BindingMessageParams {
        pattern_tag: "IK",
        prologue: b"pubky-noise-v1",
        ed25519_pub: &ed_pub,
        local_noise_pub: &local_noise,
        remote_noise_pub: None,
        role: Role::Server,
        server_hint: None,
    });

    assert_ne!(
        client_msg, server_msg,
        "Client and server roles should produce different bindings"
    );
}

/// Test remote noise key differentiation
#[test]
fn test_remote_noise_key_differentiation() {
    let ed_pub = [1u8; 32];
    let local_noise = [2u8; 32];
    let remote_noise = [3u8; 32];

    let msg_with_remote = make_binding_message(&BindingMessageParams {
        pattern_tag: "IK",
        prologue: b"pubky-noise-v1",
        ed25519_pub: &ed_pub,
        local_noise_pub: &local_noise,
        remote_noise_pub: Some(&remote_noise),
        role: Role::Client,
        server_hint: None,
    });

    let msg_without_remote = make_binding_message(&BindingMessageParams {
        pattern_tag: "IK",
        prologue: b"pubky-noise-v1",
        ed25519_pub: &ed_pub,
        local_noise_pub: &local_noise,
        remote_noise_pub: None,
        role: Role::Client,
        server_hint: None,
    });

    assert_ne!(
        msg_with_remote, msg_without_remote,
        "With/without remote noise should produce different bindings"
    );
}

/// Test server hint differentiation
#[test]
fn test_server_hint_differentiation() {
    let ed_pub = [1u8; 32];
    let local_noise = [2u8; 32];

    let msg_with_hint = make_binding_message(&BindingMessageParams {
        pattern_tag: "IK",
        prologue: b"pubky-noise-v1",
        ed25519_pub: &ed_pub,
        local_noise_pub: &local_noise,
        remote_noise_pub: None,
        role: Role::Client,
        server_hint: Some("example.com"),
    });

    let msg_without_hint = make_binding_message(&BindingMessageParams {
        pattern_tag: "IK",
        prologue: b"pubky-noise-v1",
        ed25519_pub: &ed_pub,
        local_noise_pub: &local_noise,
        remote_noise_pub: None,
        role: Role::Client,
        server_hint: None,
    });

    let msg_different_hint = make_binding_message(&BindingMessageParams {
        pattern_tag: "IK",
        prologue: b"pubky-noise-v1",
        ed25519_pub: &ed_pub,
        local_noise_pub: &local_noise,
        remote_noise_pub: None,
        role: Role::Client,
        server_hint: Some("other.com"),
    });

    assert_ne!(
        msg_with_hint, msg_without_hint,
        "With/without hint should produce different bindings"
    );
    assert_ne!(
        msg_with_hint, msg_different_hint,
        "Different hints should produce different bindings"
    );
}

/// Test IK vs XX pattern differentiation
#[test]
fn test_pattern_differentiation() {
    let ed_pub = [1u8; 32];
    let local_noise = [2u8; 32];

    let msg_ik = make_binding_message(&BindingMessageParams {
        pattern_tag: "IK",
        prologue: b"pubky-noise-v1",
        ed25519_pub: &ed_pub,
        local_noise_pub: &local_noise,
        remote_noise_pub: None,
        role: Role::Client,
        server_hint: None,
    });

    let msg_xx = make_binding_message(&BindingMessageParams {
        pattern_tag: "XX",
        prologue: b"pubky-noise-v1",
        ed25519_pub: &ed_pub,
        local_noise_pub: &local_noise,
        remote_noise_pub: None,
        role: Role::Client,
        server_hint: None,
    });

    assert_ne!(
        msg_ik, msg_xx,
        "IK and XX patterns should produce different bindings"
    );
}

/// Test binding message is 32 bytes (BLAKE2s output)
#[test]
fn test_binding_message_length() {
    let ed_pub = [1u8; 32];
    let local_noise = [2u8; 32];

    let msg = make_binding_message(&BindingMessageParams {
        pattern_tag: "IK",
        prologue: b"pubky-noise-v1",
        ed25519_pub: &ed_pub,
        local_noise_pub: &local_noise,
        remote_noise_pub: None,
        role: Role::Client,
        server_hint: None,
    });

    assert_eq!(msg.len(), 32, "Binding message should be 32 bytes");
}
