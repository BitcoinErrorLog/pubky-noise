use ed25519_dalek::{SigningKey, VerifyingKey, SECRET_KEY_LENGTH};
use pubky_noise::identity_payload::{
    make_binding_message, sign_identity_payload, verify_identity_payload, Role,
};
use pubky_noise::kdf::{derive_x25519_static, shared_secret_nonzero, x25519_pk_from_sk};
use zeroize::Zeroizing;

/// Property: KDF should be deterministic - same inputs produce same outputs
#[test]
fn property_kdf_deterministic() {
    let test_cases = vec![
        ([0u8; 32], b"device1".as_slice()),
        ([1u8; 32], b"device2"),
        ([42u8; 32], b"device3"),
        ([0xFFu8; 32], b"device4"),
    ];

    for (seed, device_id) in test_cases {
        let key1 = derive_x25519_static(&seed, device_id);
        let key2 = derive_x25519_static(&seed, device_id);

        assert_eq!(
            key1, key2,
            "KDF should produce same output for same inputs (seed, device_id={:?})",
            device_id
        );
    }
}

/// Property: Different device IDs should produce different keys
#[test]
fn property_kdf_device_separation() {
    let seed = [42u8; 32];

    let devices = vec![
        b"device_a".as_slice(),
        b"device_b",
        b"device_c",
        b"device_d",
    ];

    let keys: Vec<[u8; 32]> = devices
        .iter()
        .map(|device_id| derive_x25519_static(&seed, device_id))
        .collect();

    // All keys should be unique
    for i in 0..keys.len() {
        for j in (i + 1)..keys.len() {
            assert_ne!(
                keys[i], keys[j],
                "Different device IDs should produce different keys (device {} vs {})",
                i, j
            );
        }
    }
}

/// Property: Different contexts should produce different keys
#[test]
fn property_kdf_context_separation() {
    let seed = [42u8; 32];

    let contexts: Vec<&[u8]> = vec![
        b"context_a",
        b"context_b",
        b"context_c",
        b"",
        b"longer_context_string",
    ];

    let keys: Vec<[u8; 32]> = contexts
        .iter()
        .map(|ctx| derive_x25519_static(&seed, ctx))
        .collect();

    // All keys should be unique
    for i in 0..keys.len() {
        for j in (i + 1)..keys.len() {
            assert_ne!(
                keys[i], keys[j],
                "Different contexts should produce different keys (context {} vs {})",
                i, j
            );
        }
    }
}

/// Property: X25519 keys should have proper clamping
#[test]
fn property_x25519_clamping() {
    let test_seeds = vec![[0u8; 32], [1u8; 32], [42u8; 32], [0xFFu8; 32], [0x77u8; 32]];

    for seed in test_seeds {
        let sk = derive_x25519_static(&seed, b"device");

        // Check clamping: sk[0] should have bottom 3 bits clear
        assert_eq!(
            sk[0] & 0b00000111,
            0,
            "X25519 secret key should have bottom 3 bits of first byte cleared"
        );

        // Check clamping: sk[31] should have top bit clear and bit 254 set
        assert_eq!(
            sk[31] & 0b10000000,
            0,
            "X25519 secret key should have top bit of last byte cleared"
        );
        assert_ne!(
            sk[31] & 0b01000000,
            0,
            "X25519 secret key should have bit 254 set"
        );
    }
}

/// Property: X25519 public key derivation should be deterministic
#[test]
fn property_public_key_derivation_deterministic() {
    let test_sks = vec![
        derive_x25519_static(&[1u8; 32], b"dev1"),
        derive_x25519_static(&[2u8; 32], b"dev2"),
        derive_x25519_static(&[42u8; 32], b"dev3"),
    ];

    for sk in test_sks {
        let pk1 = x25519_pk_from_sk(&sk);
        let pk2 = x25519_pk_from_sk(&sk);

        assert_eq!(
            pk1, pk2,
            "Public key derivation should be deterministic for same secret key"
        );
    }
}

/// Property: Different secret keys should produce different public keys
#[test]
fn property_public_key_uniqueness() {
    let sks = vec![
        derive_x25519_static(&[1u8; 32], b"dev"),
        derive_x25519_static(&[2u8; 32], b"dev"),
        derive_x25519_static(&[3u8; 32], b"dev"),
        derive_x25519_static(&[42u8; 32], b"dev"),
    ];

    let pks: Vec<[u8; 32]> = sks.iter().map(|sk| x25519_pk_from_sk(sk)).collect();

    for i in 0..pks.len() {
        for j in (i + 1)..pks.len() {
            assert_ne!(
                pks[i], pks[j],
                "Different secret keys should produce different public keys"
            );
        }
    }
}

/// Property: Binding message should be deterministic
#[test]
fn property_binding_message_deterministic() {
    let test_cases = vec![
        (
            "IK",
            b"prologue1".as_slice(),
            [1u8; 32],
            [2u8; 32],
            Some([3u8; 32]),
            Role::Client,
        ),
        ("XX", b"prologue2", [4u8; 32], [5u8; 32], None, Role::Server),
        (
            "IK",
            b"prologue3",
            [6u8; 32],
            [7u8; 32],
            Some([8u8; 32]),
            Role::Client,
        ),
    ];

    for (pattern, prologue, ed_pub, local, remote_opt, role) in test_cases {
        let remote = remote_opt.as_ref();
        let msg1 = make_binding_message(pattern, prologue, &ed_pub, &local, remote, role);
        let msg2 = make_binding_message(pattern, prologue, &ed_pub, &local, remote, role);

        assert_eq!(
            msg1, msg2,
            "Binding message should be deterministic for same inputs"
        );
    }
}

/// Property: Changing any binding parameter should change the message
#[test]
fn property_binding_message_sensitivity() {
    let base_pattern = "IK";
    let base_prologue = b"prologue";
    let base_ed = [1u8; 32];
    let base_local = [2u8; 32];
    let base_remote = [3u8; 32];
    let base_role = Role::Client;

    let base_msg = make_binding_message(
        base_pattern,
        base_prologue,
        &base_ed,
        &base_local,
        Some(&base_remote),
        base_role,
    );

    // Change pattern
    let msg = make_binding_message(
        "XX",
        base_prologue,
        &base_ed,
        &base_local,
        Some(&base_remote),
        base_role,
    );
    assert_ne!(
        base_msg, msg,
        "Changing pattern should change binding message"
    );

    // Change prologue
    let msg = make_binding_message(
        base_pattern,
        b"different",
        &base_ed,
        &base_local,
        Some(&base_remote),
        base_role,
    );
    assert_ne!(
        base_msg, msg,
        "Changing prologue should change binding message"
    );

    // Change ed25519 key
    let mut different_ed = base_ed;
    different_ed[0] ^= 1;
    let msg = make_binding_message(
        base_pattern,
        base_prologue,
        &different_ed,
        &base_local,
        Some(&base_remote),
        base_role,
    );
    assert_ne!(
        base_msg, msg,
        "Changing ed25519 key should change binding message"
    );

    // Change local key
    let mut different_local = base_local;
    different_local[0] ^= 1;
    let msg = make_binding_message(
        base_pattern,
        base_prologue,
        &base_ed,
        &different_local,
        Some(&base_remote),
        base_role,
    );
    assert_ne!(
        base_msg, msg,
        "Changing local key should change binding message"
    );

    // Change remote key
    let mut different_remote = base_remote;
    different_remote[0] ^= 1;
    let msg = make_binding_message(
        base_pattern,
        base_prologue,
        &base_ed,
        &base_local,
        Some(&different_remote),
        base_role,
    );
    assert_ne!(
        base_msg, msg,
        "Changing remote key should change binding message"
    );

    // Change role
    let msg = make_binding_message(
        base_pattern,
        base_prologue,
        &base_ed,
        &base_local,
        Some(&base_remote),
        Role::Server,
    );
    assert_ne!(base_msg, msg, "Changing role should change binding message");
}

/// Property: Signature verification should be symmetric (sign then verify succeeds)
#[test]
fn property_signature_roundtrip() {
    let test_keys = vec![
        [1u8; SECRET_KEY_LENGTH],
        [2u8; SECRET_KEY_LENGTH],
        [42u8; SECRET_KEY_LENGTH],
        [0x77u8; SECRET_KEY_LENGTH],
    ];

    for seed in test_keys {
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();

        // Create multiple test messages
        let messages = vec![[0u8; 32], [1u8; 32], [42u8; 32], [0xFFu8; 32]];

        for msg in messages {
            let sig = sign_identity_payload(&signing_key, &msg);
            let result = verify_identity_payload(&verifying_key, &msg, &sig);

            assert!(
                result,
                "Signature verification should succeed for valid signature"
            );
        }
    }
}

/// Property: Signature verification should fail for wrong key
#[test]
fn property_signature_wrong_key_fails() {
    let signing_key = SigningKey::from_bytes(&[1u8; SECRET_KEY_LENGTH]);
    let wrong_verifying_key = SigningKey::from_bytes(&[2u8; SECRET_KEY_LENGTH]).verifying_key();

    let msg = [42u8; 32];
    let sig = sign_identity_payload(&signing_key, &msg);

    // Verify with wrong key should fail
    let result = verify_identity_payload(&wrong_verifying_key, &msg, &sig);
    assert!(!result, "Signature verification should fail with wrong key");
}

/// Property: Signature verification should fail for modified message
#[test]
fn property_signature_modified_message_fails() {
    let signing_key = SigningKey::from_bytes(&[1u8; SECRET_KEY_LENGTH]);
    let verifying_key = signing_key.verifying_key();

    let msg = [42u8; 32];
    let sig = sign_identity_payload(&signing_key, &msg);

    // Modify message
    let mut modified_msg = msg;
    modified_msg[0] ^= 1;

    let result = verify_identity_payload(&verifying_key, &modified_msg, &sig);
    assert!(
        !result,
        "Signature verification should fail for modified message"
    );
}

/// Property: Shared secret should be non-zero for valid keypairs
#[test]
fn property_shared_secret_nonzero() {
    let test_pairs = vec![
        (
            derive_x25519_static(&[1u8; 32], b"alice"),
            derive_x25519_static(&[2u8; 32], b"bob"),
        ),
        (
            derive_x25519_static(&[42u8; 32], b"device1"),
            derive_x25519_static(&[43u8; 32], b"device2"),
        ),
    ];

    for (sk_a, sk_b) in test_pairs {
        let pk_a = x25519_pk_from_sk(&sk_a);
        let pk_b = x25519_pk_from_sk(&sk_b);

        // A computing shared secret with B's public key should be non-zero
        assert!(
            shared_secret_nonzero(&Zeroizing::new(sk_a), &pk_b),
            "Shared secret should be non-zero for valid keypairs"
        );

        // B computing shared secret with A's public key should be non-zero
        assert!(
            shared_secret_nonzero(&Zeroizing::new(sk_b), &pk_a),
            "Shared secret should be non-zero for valid keypairs"
        );
    }
}
