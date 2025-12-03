use ed25519_dalek::{SigningKey, VerifyingKey, SECRET_KEY_LENGTH};
use pubky_noise::identity_payload::{
    make_binding_message, sign_identity_payload, verify_identity_payload, Role,
};

/// Test that binding message generation is deterministic
#[test]
fn test_binding_message_deterministic() {
    let pattern = "IK";
    let prologue = b"pubky-noise-v1";
    let ed_pub = [1u8; 32];
    let local_noise = [2u8; 32];
    let remote_noise = [3u8; 32];
    let role = Role::Client;

    // Generate binding message twice with same inputs
    let msg1 = make_binding_message(
        pattern,
        prologue,
        &ed_pub,
        &local_noise,
        Some(&remote_noise),
        role,
    );

    let msg2 = make_binding_message(
        pattern,
        prologue,
        &ed_pub,
        &local_noise,
        Some(&remote_noise),
        role,
    );

    assert_eq!(msg1, msg2, "Binding message should be deterministic");
}

/// Test that different inputs produce different binding messages
#[test]
fn test_binding_message_uniqueness() {
    let pattern = "IK";
    let prologue = b"pubky-noise-v1";
    let ed_pub = [1u8; 32];
    let local_noise = [2u8; 32];
    let remote_noise = [3u8; 32];
    let role = Role::Client;

    let msg_baseline = make_binding_message(
        pattern,
        prologue,
        &ed_pub,
        &local_noise,
        Some(&remote_noise),
        role,
    );

    // Change pattern
    let msg_diff_pattern = make_binding_message(
        "XX",
        prologue,
        &ed_pub,
        &local_noise,
        Some(&remote_noise),
        role,
    );
    assert_ne!(
        msg_baseline, msg_diff_pattern,
        "Different patterns should produce different bindings"
    );

    // Change prologue
    let msg_diff_prologue = make_binding_message(
        pattern,
        b"different-prologue",
        &ed_pub,
        &local_noise,
        Some(&remote_noise),
        role,
    );
    assert_ne!(
        msg_baseline, msg_diff_prologue,
        "Different prologues should produce different bindings"
    );

    // Change ed25519 key
    let mut different_ed = ed_pub;
    different_ed[0] ^= 1;
    let msg_diff_ed = make_binding_message(
        pattern,
        prologue,
        &different_ed,
        &local_noise,
        Some(&remote_noise),
        role,
    );
    assert_ne!(
        msg_baseline, msg_diff_ed,
        "Different ed25519 keys should produce different bindings"
    );

    // Change local noise key
    let mut different_local = local_noise;
    different_local[0] ^= 1;
    let msg_diff_local = make_binding_message(
        pattern,
        prologue,
        &ed_pub,
        &different_local,
        Some(&remote_noise),
        role,
    );
    assert_ne!(
        msg_baseline, msg_diff_local,
        "Different local keys should produce different bindings"
    );

    // Change remote noise key
    let mut different_remote = remote_noise;
    different_remote[0] ^= 1;
    let msg_diff_remote = make_binding_message(
        pattern,
        prologue,
        &ed_pub,
        &local_noise,
        Some(&different_remote),
        role,
    );
    assert_ne!(
        msg_baseline, msg_diff_remote,
        "Different remote keys should produce different bindings"
    );

    // Change role
    let msg_diff_role = make_binding_message(
        pattern,
        prologue,
        &ed_pub,
        &local_noise,
        Some(&remote_noise),
        Role::Server,
    );
    assert_ne!(
        msg_baseline, msg_diff_role,
        "Different roles should produce different bindings"
    );
}

/// Test binding message with and without remote key
#[test]
fn test_binding_message_optional_remote() {
    let pattern = "XX";
    let prologue = b"pubky-noise-v1";
    let ed_pub = [1u8; 32];
    let local_noise = [2u8; 32];
    let remote_noise = [3u8; 32];
    let role = Role::Client;

    let msg_with_remote = make_binding_message(
        pattern,
        prologue,
        &ed_pub,
        &local_noise,
        Some(&remote_noise),
        role,
    );

    let msg_without_remote =
        make_binding_message(pattern, prologue, &ed_pub, &local_noise, None, role);

    assert_ne!(
        msg_with_remote, msg_without_remote,
        "Presence of remote key should affect binding message"
    );
}

/// Test signature creation and verification
#[test]
fn test_signature_roundtrip() {
    let seed = [42u8; SECRET_KEY_LENGTH];
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    let binding_msg = [1u8; 32];

    // Sign the binding message
    let signature = sign_identity_payload(&signing_key, &binding_msg);

    // Verify the signature
    let is_valid = verify_identity_payload(&verifying_key, &binding_msg, &signature);

    assert!(is_valid, "Valid signature should verify successfully");
}

/// Test that modified message fails verification
#[test]
fn test_signature_detects_modification() {
    let seed = [42u8; SECRET_KEY_LENGTH];
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    let binding_msg = [1u8; 32];
    let signature = sign_identity_payload(&signing_key, &binding_msg);

    // Modify the message
    let mut modified_msg = binding_msg;
    modified_msg[0] ^= 1;

    let is_valid = verify_identity_payload(&verifying_key, &modified_msg, &signature);

    assert!(!is_valid, "Modified message should fail verification");
}

/// Test that wrong key fails verification
#[test]
fn test_signature_wrong_key_fails() {
    let seed1 = [42u8; SECRET_KEY_LENGTH];
    let seed2 = [43u8; SECRET_KEY_LENGTH];
    let signing_key = SigningKey::from_bytes(&seed1);
    let wrong_verifying_key = SigningKey::from_bytes(&seed2).verifying_key();

    let binding_msg = [1u8; 32];
    let signature = sign_identity_payload(&signing_key, &binding_msg);

    let is_valid = verify_identity_payload(&wrong_verifying_key, &binding_msg, &signature);

    assert!(!is_valid, "Wrong verifying key should fail verification");
}

/// Test both roles produce different bindings
#[test]
fn test_role_binding_separation() {
    let pattern = "IK";
    let prologue = b"pubky-noise-v1";
    let ed_pub = [1u8; 32];
    let local_noise = [2u8; 32];
    let remote_noise = [3u8; 32];

    let msg_client = make_binding_message(
        pattern,
        prologue,
        &ed_pub,
        &local_noise,
        Some(&remote_noise),
        Role::Client,
    );

    let msg_server = make_binding_message(
        pattern,
        prologue,
        &ed_pub,
        &local_noise,
        Some(&remote_noise),
        Role::Server,
    );

    assert_ne!(
        msg_client, msg_server,
        "Different roles must produce different bindings"
    );
}

/// Test binding with XX pattern (no prior server knowledge)
#[test]
fn test_xx_pattern_binding() {
    let pattern = "XX";
    let prologue = b"pubky-noise-v1";
    let ed_pub = [1u8; 32];
    let local_noise = [2u8; 32];

    // XX pattern typically doesn't have remote key initially
    let msg = make_binding_message(pattern, prologue, &ed_pub, &local_noise, None, Role::Client);

    // Should produce a valid 32-byte hash
    assert_eq!(msg.len(), 32);
    assert_ne!(msg, [0u8; 32], "Binding message should not be all zeros");
}

/// Test binding with IK pattern
#[test]
fn test_ik_pattern_binding() {
    let pattern = "IK";
    let prologue = b"pubky-noise-v1";
    let ed_pub = [1u8; 32];
    let local_noise = [2u8; 32];
    let remote_noise = [3u8; 32];

    // IK pattern has remote key from pinning
    let msg = make_binding_message(
        pattern,
        prologue,
        &ed_pub,
        &local_noise,
        Some(&remote_noise),
        Role::Client,
    );

    assert_eq!(msg.len(), 32);
    assert_ne!(msg, [0u8; 32], "Binding message should not be all zeros");
}

/// Test various seed lengths for signature
#[test]
fn test_signature_with_various_keys() {
    let seeds = vec![
        [0u8; SECRET_KEY_LENGTH],
        [1u8; SECRET_KEY_LENGTH],
        [0xFFu8; SECRET_KEY_LENGTH],
        [0x42u8; SECRET_KEY_LENGTH],
    ];

    for seed in seeds {
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();

        let binding_msg = [42u8; 32];
        let signature = sign_identity_payload(&signing_key, &binding_msg);

        let is_valid = verify_identity_payload(&verifying_key, &binding_msg, &signature);
        assert!(
            is_valid,
            "Signature should verify with seed {:?}",
            &seed[..4]
        );
    }
}
