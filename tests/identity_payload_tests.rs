//! Tests for identity payload binding and signature verification.
//!
//! ## Wire Format (PUBKY_CRYPTO_SPEC v2.5 Section 6.4)
//!
//! Binding message uses BLAKE3 with:
//! - "pubky-noise-binding/v1" prefix
//! - ed25519_pub (32 bytes)
//! - local_noise_pub (32 bytes)
//! - role_byte (0x00=Client, 0x01=Server)
//! - remote_noise_pub (32 bytes)

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

    let msg1 = make_binding_message(&BindingMessageParams {
        ed25519_pub: &ed_pub,
        local_noise_pub: &local_noise,
        remote_noise_pub: Some(&remote_noise,
        ),
        role: Role::Client,
    });

    let msg2 = make_binding_message(&BindingMessageParams {
        ed25519_pub: &ed_pub,
        local_noise_pub: &local_noise,
        remote_noise_pub: Some(&remote_noise,
        ),
        role: Role::Client,
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
        ed25519_pub: &ed_pub,
        local_noise_pub: &local_noise,
        remote_noise_pub: Some(&remote_noise,
        ),
        role: Role::Client,
    });

    // Change ed25519 key
    let mut different_ed = ed_pub;
    different_ed[0] ^= 1;
    let msg_diff_ed = make_binding_message(&BindingMessageParams {
        ed25519_pub: &different_ed,
        local_noise_pub: &local_noise,
        remote_noise_pub: Some(&remote_noise,
        ),
        role: Role::Client,
    });
    assert_ne!(
        msg_baseline, msg_diff_ed,
        "Different ed25519 keys should produce different bindings"
    );

    // Change local noise key
    let mut different_local = local_noise;
    different_local[0] ^= 1;
    let msg_diff_local = make_binding_message(&BindingMessageParams {
        ed25519_pub: &ed_pub,
        local_noise_pub: &different_local,
        remote_noise_pub: Some(&remote_noise,
        ),
        role: Role::Client,
    });
    assert_ne!(
        msg_baseline, msg_diff_local,
        "Different local noise keys should produce different bindings"
    );

    // Change remote noise key
    let mut different_remote = remote_noise;
    different_remote[0] ^= 1;
    let msg_diff_remote = make_binding_message(&BindingMessageParams {
        ed25519_pub: &ed_pub,
        local_noise_pub: &local_noise,
        remote_noise_pub: Some(&different_remote,
        ),
        role: Role::Client,
    });
    assert_ne!(
        msg_baseline, msg_diff_remote,
        "Different remote noise keys should produce different bindings"
    );

    // Change role
    let msg_diff_role = make_binding_message(&BindingMessageParams {
        ed25519_pub: &ed_pub,
        local_noise_pub: &local_noise,
        remote_noise_pub: Some(&remote_noise,
        ),
        role: Role::Server,
    });
    assert_ne!(
        msg_baseline, msg_diff_role,
        "Different roles should produce different bindings"
    );
}

/// Test signature generation and verification
#[test]
fn test_signature_roundtrip() {
    let secret_bytes = [42u8; SECRET_KEY_LENGTH];
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key = VerifyingKey::from(&signing_key);

    let ed_pub = [1u8; 32];
    let local_noise = [2u8; 32];
    let remote_noise = [3u8; 32];

    let msg = make_binding_message(&BindingMessageParams {
        ed25519_pub: &ed_pub,
        local_noise_pub: &local_noise,
        remote_noise_pub: Some(&remote_noise,
        ),
        role: Role::Client,
    });

    let sig = sign_identity_payload(&signing_key, &msg);
    assert!(
        verify_identity_payload(&verifying_key, &msg, &sig),
        "Signature should verify"
    );
}

/// Test that signature fails with wrong key
#[test]
fn test_signature_wrong_key() {
    let secret1 = [42u8; SECRET_KEY_LENGTH];
    let secret2 = [43u8; SECRET_KEY_LENGTH];
    let signing_key = SigningKey::from_bytes(&secret1);
    let wrong_verifying_key = VerifyingKey::from(&SigningKey::from_bytes(&secret2));

    let ed_pub = [1u8; 32];
    let local_noise = [2u8; 32];
    let remote_noise = [3u8; 32];

    let msg = make_binding_message(&BindingMessageParams {
        ed25519_pub: &ed_pub,
        local_noise_pub: &local_noise,
        remote_noise_pub: Some(&remote_noise,
        ),
        role: Role::Client,
    });

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
    let remote_noise = [3u8; 32];

    let msg = make_binding_message(&BindingMessageParams {
        ed25519_pub: &ed_pub,
        local_noise_pub: &local_noise,
        remote_noise_pub: Some(&remote_noise,
        ),
        role: Role::Client,
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
    let remote_noise = [3u8; 32];

    let client_msg = make_binding_message(&BindingMessageParams {
        ed25519_pub: &ed_pub,
        local_noise_pub: &local_noise,
        remote_noise_pub: Some(&remote_noise,
        ),
        role: Role::Client,
    });

    let server_msg = make_binding_message(&BindingMessageParams {
        ed25519_pub: &ed_pub,
        local_noise_pub: &local_noise,
        remote_noise_pub: Some(&remote_noise,
        ),
        role: Role::Server,
    });

    assert_ne!(
        client_msg, server_msg,
        "Client and server roles should produce different bindings"
    );
}

/// Test binding message is 32 bytes (BLAKE3 output)
#[test]
fn test_binding_message_length() {
    let ed_pub = [1u8; 32];
    let local_noise = [2u8; 32];
    let remote_noise = [3u8; 32];

    let msg = make_binding_message(&BindingMessageParams {
        ed25519_pub: &ed_pub,
        local_noise_pub: &local_noise,
        remote_noise_pub: Some(&remote_noise,
        ),
        role: Role::Client,
    });

    assert_eq!(msg.len(), 32, "Binding message should be 32 bytes");
}
