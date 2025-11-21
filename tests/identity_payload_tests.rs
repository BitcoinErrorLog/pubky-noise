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
    let epoch = 42;
    let role = Role::Client;
    let hint = Some("example.com");

    // Generate binding message twice with same inputs
    let msg1 = make_binding_message(
        pattern,
        prologue,
        &ed_pub,
        &local_noise,
        Some(&remote_noise),
        epoch,
        role,
        hint,
    );

    let msg2 = make_binding_message(
        pattern,
        prologue,
        &ed_pub,
        &local_noise,
        Some(&remote_noise),
        epoch,
        role,
        hint,
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
    let epoch = 42;
    let role = Role::Client;

    let msg_baseline = make_binding_message(
        pattern,
        prologue,
        &ed_pub,
        &local_noise,
        Some(&remote_noise),
        epoch,
        role,
        None,
    );

    // Change pattern
    let msg_diff_pattern = make_binding_message(
        "XX",
        prologue,
        &ed_pub,
        &local_noise,
        Some(&remote_noise),
        epoch,
        role,
        None,
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
        epoch,
        role,
        None,
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
        epoch,
        role,
        None,
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
        epoch,
        role,
        None,
    );
    assert_ne!(
        msg_baseline, msg_diff_local,
        "Different local noise keys should produce different bindings"
    );

    // Change epoch
    let msg_diff_epoch = make_binding_message(
        pattern,
        prologue,
        &ed_pub,
        &local_noise,
        Some(&remote_noise),
        epoch + 1,
        role,
        None,
    );
    assert_ne!(
        msg_baseline, msg_diff_epoch,
        "Different epochs should produce different bindings"
    );

    // Change role
    let msg_diff_role = make_binding_message(
        pattern,
        prologue,
        &ed_pub,
        &local_noise,
        Some(&remote_noise),
        epoch,
        Role::Server,
        None,
    );
    assert_ne!(
        msg_baseline, msg_diff_role,
        "Different roles should produce different bindings"
    );
}

/// Test valid signature generation and verification
#[test]
fn test_signature_valid_roundtrip() {
    // Generate a keypair
    let signing_key = SigningKey::from_bytes(&[1u8; SECRET_KEY_LENGTH]);
    let verifying_key = signing_key.verifying_key();

    // Create a binding message
    let msg = make_binding_message(
        "IK",
        b"pubky-noise-v1",
        &verifying_key.to_bytes(),
        &[2u8; 32],
        Some(&[3u8; 32]),
        42,
        Role::Client,
        None,
    );

    // Sign the message
    let signature = sign_identity_payload(&signing_key, &msg);

    // Verify the signature
    assert!(
        verify_identity_payload(&verifying_key, &msg, &signature),
        "Valid signature should verify successfully"
    );
}

/// Test that modified message fails verification
#[test]
fn test_signature_modified_message_fails() {
    // Generate a keypair
    let signing_key = SigningKey::from_bytes(&[2u8; SECRET_KEY_LENGTH]);
    let verifying_key = signing_key.verifying_key();

    // Create and sign a binding message
    let msg = make_binding_message(
        "IK",
        b"pubky-noise-v1",
        &verifying_key.to_bytes(),
        &[2u8; 32],
        Some(&[3u8; 32]),
        42,
        Role::Client,
        None,
    );
    let signature = sign_identity_payload(&signing_key, &msg);

    // Modify the message
    let mut modified_msg = msg;
    modified_msg[0] ^= 1;

    // Verification should fail
    assert!(
        !verify_identity_payload(&verifying_key, &modified_msg, &signature),
        "Modified message should fail verification"
    );
}

/// Test that wrong public key fails verification
#[test]
fn test_signature_wrong_key_fails() {
    // Generate two keypairs
    let signing_key = SigningKey::from_bytes(&[3u8; SECRET_KEY_LENGTH]);
    let verifying_key = signing_key.verifying_key();

    let wrong_signing_key = SigningKey::from_bytes(&[4u8; SECRET_KEY_LENGTH]);
    let wrong_verifying_key = wrong_signing_key.verifying_key();

    // Create and sign a binding message with first key
    let msg = make_binding_message(
        "IK",
        b"pubky-noise-v1",
        &verifying_key.to_bytes(),
        &[2u8; 32],
        Some(&[3u8; 32]),
        42,
        Role::Client,
        None,
    );
    let signature = sign_identity_payload(&signing_key, &msg);

    // Try to verify with wrong key
    assert!(
        !verify_identity_payload(&wrong_verifying_key, &msg, &signature),
        "Wrong public key should fail verification"
    );
}

/// Test that malformed signature fails verification
#[test]
fn test_signature_malformed_fails() {
    // Generate a keypair
    let signing_key = SigningKey::from_bytes(&[5u8; SECRET_KEY_LENGTH]);
    let verifying_key = signing_key.verifying_key();

    // Create a binding message
    let msg = make_binding_message(
        "IK",
        b"pubky-noise-v1",
        &verifying_key.to_bytes(),
        &[2u8; 32],
        Some(&[3u8; 32]),
        42,
        Role::Client,
        None,
    );

    // Create malformed signatures
    let all_zeros = [0u8; 64];
    assert!(
        !verify_identity_payload(&verifying_key, &msg, &all_zeros),
        "All-zeros signature should fail verification"
    );

    let all_ones = [0xFFu8; 64];
    assert!(
        !verify_identity_payload(&verifying_key, &msg, &all_ones),
        "All-ones signature should fail verification"
    );

    let random_bytes = [42u8; 64];
    assert!(
        !verify_identity_payload(&verifying_key, &msg, &random_bytes),
        "Random bytes should fail verification"
    );
}

/// Test that modified signature fails verification
#[test]
fn test_signature_modified_signature_fails() {
    // Generate a keypair
    let signing_key = SigningKey::from_bytes(&[6u8; SECRET_KEY_LENGTH]);
    let verifying_key = signing_key.verifying_key();

    // Create and sign a binding message
    let msg = make_binding_message(
        "IK",
        b"pubky-noise-v1",
        &verifying_key.to_bytes(),
        &[2u8; 32],
        Some(&[3u8; 32]),
        42,
        Role::Client,
        None,
    );
    let signature = sign_identity_payload(&signing_key, &msg);

    // Modify the signature
    let mut modified_sig = signature;
    modified_sig[0] ^= 1;

    // Verification should fail
    assert!(
        !verify_identity_payload(&verifying_key, &msg, &modified_sig),
        "Modified signature should fail verification"
    );
}

/// Test role binding - client and server produce different bindings
#[test]
fn test_binding_role_separation() {
    let ed_pub = [1u8; 32];
    let local_noise = [2u8; 32];
    let remote_noise = [3u8; 32];
    let epoch = 42;

    let client_msg = make_binding_message(
        "IK",
        b"pubky-noise-v1",
        &ed_pub,
        &local_noise,
        Some(&remote_noise),
        epoch,
        Role::Client,
        None,
    );

    let server_msg = make_binding_message(
        "IK",
        b"pubky-noise-v1",
        &ed_pub,
        &local_noise,
        Some(&remote_noise),
        epoch,
        Role::Server,
        None,
    );

    assert_ne!(
        client_msg, server_msg,
        "Client and server roles should produce different bindings"
    );
}

/// Test epoch binding - different epochs produce different bindings
#[test]
fn test_binding_epoch_separation() {
    let ed_pub = [1u8; 32];
    let local_noise = [2u8; 32];
    let remote_noise = [3u8; 32];

    let msg_epoch_1 = make_binding_message(
        "IK",
        b"pubky-noise-v1",
        &ed_pub,
        &local_noise,
        Some(&remote_noise),
        1,
        Role::Client,
        None,
    );

    let msg_epoch_2 = make_binding_message(
        "IK",
        b"pubky-noise-v1",
        &ed_pub,
        &local_noise,
        Some(&remote_noise),
        2,
        Role::Client,
        None,
    );

    assert_ne!(
        msg_epoch_1, msg_epoch_2,
        "Different epochs should produce different bindings"
    );
}

/// Test remote noise key binding - with and without remote key
#[test]
fn test_binding_remote_noise_key() {
    let ed_pub = [1u8; 32];
    let local_noise = [2u8; 32];
    let remote_noise = [3u8; 32];
    let epoch = 42;

    let msg_with_remote = make_binding_message(
        "IK",
        b"pubky-noise-v1",
        &ed_pub,
        &local_noise,
        Some(&remote_noise),
        epoch,
        Role::Client,
        None,
    );

    let msg_without_remote = make_binding_message(
        "IK",
        b"pubky-noise-v1",
        &ed_pub,
        &local_noise,
        None,
        epoch,
        Role::Client,
        None,
    );

    assert_ne!(
        msg_with_remote, msg_without_remote,
        "Presence of remote noise key should affect binding"
    );
}

/// Test server hint binding - with and without hint
#[test]
fn test_binding_server_hint() {
    let ed_pub = [1u8; 32];
    let local_noise = [2u8; 32];
    let epoch = 42;

    let msg_with_hint = make_binding_message(
        "IK",
        b"pubky-noise-v1",
        &ed_pub,
        &local_noise,
        None,
        epoch,
        Role::Client,
        Some("server.example.com"),
    );

    let msg_without_hint = make_binding_message(
        "IK",
        b"pubky-noise-v1",
        &ed_pub,
        &local_noise,
        None,
        epoch,
        Role::Client,
        None,
    );

    assert_ne!(
        msg_with_hint, msg_without_hint,
        "Presence of server hint should affect binding"
    );

    // Different hints should produce different bindings
    let msg_different_hint = make_binding_message(
        "IK",
        b"pubky-noise-v1",
        &ed_pub,
        &local_noise,
        None,
        epoch,
        Role::Client,
        Some("other.example.com"),
    );

    assert_ne!(
        msg_with_hint, msg_different_hint,
        "Different server hints should produce different bindings"
    );
}

/// Test cross-pattern binding - IK and XX patterns
#[test]
fn test_binding_cross_pattern() {
    let ed_pub = [1u8; 32];
    let local_noise = [2u8; 32];
    let epoch = 42;

    let msg_ik = make_binding_message(
        "IK",
        b"pubky-noise-v1",
        &ed_pub,
        &local_noise,
        None,
        epoch,
        Role::Client,
        None,
    );

    let msg_xx = make_binding_message(
        "XX",
        b"pubky-noise-v1",
        &ed_pub,
        &local_noise,
        None,
        epoch,
        Role::Client,
        None,
    );

    assert_ne!(
        msg_ik, msg_xx,
        "IK and XX patterns should produce different bindings"
    );
}

/// Test that signatures from different messages are independent
#[test]
fn test_signature_independence() {
    // Generate a keypair
    let signing_key = SigningKey::from_bytes(&[7u8; SECRET_KEY_LENGTH]);
    let verifying_key = signing_key.verifying_key();

    // Create two different binding messages
    let msg1 = make_binding_message(
        "IK",
        b"pubky-noise-v1",
        &verifying_key.to_bytes(),
        &[2u8; 32],
        Some(&[3u8; 32]),
        42,
        Role::Client,
        None,
    );

    let msg2 = make_binding_message(
        "IK",
        b"pubky-noise-v1",
        &verifying_key.to_bytes(),
        &[2u8; 32],
        Some(&[3u8; 32]),
        43, // Different epoch
        Role::Client,
        None,
    );

    // Sign both messages
    let sig1 = sign_identity_payload(&signing_key, &msg1);
    let sig2 = sign_identity_payload(&signing_key, &msg2);

    // Signatures should be different
    assert_ne!(
        sig1, sig2,
        "Different messages should produce different signatures"
    );

    // Each signature should only verify its own message
    assert!(verify_identity_payload(&verifying_key, &msg1, &sig1));
    assert!(verify_identity_payload(&verifying_key, &msg2, &sig2));
    assert!(!verify_identity_payload(&verifying_key, &msg1, &sig2));
    assert!(!verify_identity_payload(&verifying_key, &msg2, &sig1));
}

/// Test signature with multiple different keypairs
#[test]
fn test_signature_multiple_keypairs() {
    // Generate three different keypairs
    let keys: Vec<(SigningKey, VerifyingKey)> = (0..3)
        .map(|i| {
            let mut seed = [0u8; SECRET_KEY_LENGTH];
            seed[0] = (i + 8) as u8; // Different seeds for each key
            let sk = SigningKey::from_bytes(&seed);
            let vk = sk.verifying_key();
            (sk, vk)
        })
        .collect();

    // Create a message
    let msg = make_binding_message(
        "IK",
        b"pubky-noise-v1",
        &keys[0].1.to_bytes(),
        &[2u8; 32],
        Some(&[3u8; 32]),
        42,
        Role::Client,
        None,
    );

    // Sign with each key
    let signatures: Vec<[u8; 64]> = keys
        .iter()
        .map(|(sk, _)| sign_identity_payload(sk, &msg))
        .collect();

    // Each signature should verify only with its corresponding key
    for (i, (_, vk)) in keys.iter().enumerate() {
        for (j, sig) in signatures.iter().enumerate() {
            if i == j {
                assert!(
                    verify_identity_payload(vk, &msg, sig),
                    "Signature {} should verify with key {}",
                    j,
                    i
                );
            } else {
                assert!(
                    !verify_identity_payload(vk, &msg, sig),
                    "Signature {} should NOT verify with key {}",
                    j,
                    i
                );
            }
        }
    }
}
