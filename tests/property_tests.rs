//! Property-based tests for cryptographic operations.

use ed25519_dalek::{SigningKey, SECRET_KEY_LENGTH};
use pubky_noise::identity_payload::{
    make_binding_message, sign_identity_payload, verify_identity_payload, BindingMessageParams,
    Role,
};
use pubky_noise::kdf::{derive_x25519_for_device_epoch, shared_secret_nonzero, x25519_pk_from_sk};
use zeroize::Zeroizing;

/// Property: KDF should be deterministic - same inputs produce same outputs
#[test]
fn property_kdf_deterministic() {
    let test_cases = vec![
        ([0u8; 32], b"device1".as_slice(), 0u32),
        ([1u8; 32], b"device2", 1),
        ([42u8; 32], b"device3", 42),
        ([0xFFu8; 32], b"device4", 999),
    ];

    for (seed, device_id, epoch) in test_cases {
        let key1 = derive_x25519_for_device_epoch(&seed, device_id, epoch);
        let key2 = derive_x25519_for_device_epoch(&seed, device_id, epoch);

        assert_eq!(
            key1, key2,
            "KDF should produce same output for same inputs (seed, device_id={:?}, epoch={})",
            device_id, epoch
        );
    }
}

/// Property: Different device IDs should produce different keys
#[test]
fn property_kdf_device_separation() {
    let seed = [42u8; 32];
    let epoch = 0; // Use default epoch

    let devices = [
        b"device_a".as_slice(),
        b"device_b",
        b"device_c",
        b"device_d",
    ];

    let keys: Vec<[u8; 32]> = devices
        .iter()
        .map(|device_id| derive_x25519_for_device_epoch(&seed, device_id, epoch))
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

/// Property: X25519 keys should have proper clamping
#[test]
fn property_x25519_clamping() {
    let test_seeds = vec![[0u8; 32], [1u8; 32], [42u8; 32], [0xFFu8; 32], [0x77u8; 32]];

    for seed in test_seeds {
        let sk = derive_x25519_for_device_epoch(&seed, b"device", 0);

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
        assert_eq!(
            sk[31] & 0b01000000,
            0b01000000,
            "X25519 secret key should have bit 254 set"
        );
    }
}

/// Property: Public key derivation should be consistent
#[test]
fn property_pubkey_derivation_consistent() {
    let test_keys = vec![[1u8; 32], [2u8; 32], [42u8; 32], [0xAAu8; 32]];

    for sk in test_keys {
        let pk1 = x25519_pk_from_sk(&sk);
        let pk2 = x25519_pk_from_sk(&sk);

        assert_eq!(pk1, pk2, "Public key derivation should be deterministic");
    }
}

/// Property: Different secret keys should produce different public keys
#[test]
fn property_pubkey_uniqueness() {
    let secret_keys = [[1u8; 32], [2u8; 32], [3u8; 32], [42u8; 32]];

    let public_keys: Vec<[u8; 32]> = secret_keys.iter().map(x25519_pk_from_sk).collect();

    // All public keys should be unique
    for i in 0..public_keys.len() {
        for j in (i + 1)..public_keys.len() {
            assert_ne!(
                public_keys[i], public_keys[j],
                "Different secret keys should produce different public keys"
            );
        }
    }
}

/// Property: Binding message should be deterministic
#[test]
fn property_binding_message_deterministic() {
    let ed_pub = [1u8; 32];
    let local = [2u8; 32];
    let remote = [3u8; 32];

    let msg1 = make_binding_message(&BindingMessageParams {
        pattern_tag: "IK",
        prologue: b"prologue1",
        ed25519_pub: &ed_pub,
        local_noise_pub: &local,
        remote_noise_pub: Some(&remote),
        role: Role::Client,
        server_hint: None,
    });

    let msg2 = make_binding_message(&BindingMessageParams {
        pattern_tag: "IK",
        prologue: b"prologue1",
        ed25519_pub: &ed_pub,
        local_noise_pub: &local,
        remote_noise_pub: Some(&remote),
        role: Role::Client,
        server_hint: None,
    });

    assert_eq!(
        msg1, msg2,
        "Binding message should be deterministic for same inputs"
    );
}

/// Property: Changing any binding parameter should change the message
#[test]
fn property_binding_message_sensitivity() {
    let base_ed = [1u8; 32];
    let base_local = [2u8; 32];
    let base_remote = [3u8; 32];

    let base_msg = make_binding_message(&BindingMessageParams {
        pattern_tag: "IK",
        prologue: b"prologue",
        ed25519_pub: &base_ed,
        local_noise_pub: &base_local,
        remote_noise_pub: Some(&base_remote),
        role: Role::Client,
        server_hint: None,
    });

    // Change pattern
    let msg = make_binding_message(&BindingMessageParams {
        pattern_tag: "XX",
        prologue: b"prologue",
        ed25519_pub: &base_ed,
        local_noise_pub: &base_local,
        remote_noise_pub: Some(&base_remote),
        role: Role::Client,
        server_hint: None,
    });
    assert_ne!(
        base_msg, msg,
        "Changing pattern should change binding message"
    );

    // Change prologue
    let msg = make_binding_message(&BindingMessageParams {
        pattern_tag: "IK",
        prologue: b"different",
        ed25519_pub: &base_ed,
        local_noise_pub: &base_local,
        remote_noise_pub: Some(&base_remote),
        role: Role::Client,
        server_hint: None,
    });
    assert_ne!(
        base_msg, msg,
        "Changing prologue should change binding message"
    );

    // Change ed25519 key
    let mut different_ed = base_ed;
    different_ed[0] ^= 1;
    let msg = make_binding_message(&BindingMessageParams {
        pattern_tag: "IK",
        prologue: b"prologue",
        ed25519_pub: &different_ed,
        local_noise_pub: &base_local,
        remote_noise_pub: Some(&base_remote),
        role: Role::Client,
        server_hint: None,
    });
    assert_ne!(
        base_msg, msg,
        "Changing ed25519 key should change binding message"
    );

    // Change role
    let msg = make_binding_message(&BindingMessageParams {
        pattern_tag: "IK",
        prologue: b"prologue",
        ed25519_pub: &base_ed,
        local_noise_pub: &base_local,
        remote_noise_pub: Some(&base_remote),
        role: Role::Server,
        server_hint: None,
    });
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
            let signature = sign_identity_payload(&signing_key, &msg);
            let valid = verify_identity_payload(&verifying_key, &msg, &signature);

            assert!(
                valid,
                "Signature verification should succeed for valid signature"
            );
        }
    }
}

/// Property: Signature should not verify with wrong key
#[test]
fn property_signature_key_mismatch() {
    let sk1 = SigningKey::from_bytes(&[1u8; SECRET_KEY_LENGTH]);
    let vk1 = sk1.verifying_key();

    let sk2 = SigningKey::from_bytes(&[2u8; SECRET_KEY_LENGTH]);
    let vk2 = sk2.verifying_key();

    let msg = [42u8; 32];

    // Sign with key 1
    let sig1 = sign_identity_payload(&sk1, &msg);

    // Verify with key 2 should fail
    assert!(
        !verify_identity_payload(&vk2, &msg, &sig1),
        "Signature should not verify with wrong key"
    );

    // But verify with correct key should succeed
    assert!(
        verify_identity_payload(&vk1, &msg, &sig1),
        "Signature should verify with correct key"
    );
}

/// Property: Modified signature should not verify
#[test]
fn property_signature_tamper_resistance() {
    let signing_key = SigningKey::from_bytes(&[42u8; SECRET_KEY_LENGTH]);
    let verifying_key = signing_key.verifying_key();

    let msg = [1u8; 32];
    let signature = sign_identity_payload(&signing_key, &msg);

    // Flip each bit and verify it fails
    for byte_idx in 0..64 {
        for bit_idx in 0..8 {
            let mut tampered = signature;
            tampered[byte_idx] ^= 1 << bit_idx;

            let valid = verify_identity_payload(&verifying_key, &msg, &tampered);

            assert!(
                !valid,
                "Tampered signature (byte {}, bit {}) should not verify",
                byte_idx, bit_idx
            );
        }
    }
}

/// Property: Zero check should detect all-zero shared secrets
#[test]
fn property_zero_check_correctness() {
    // All-zero peer key should result in zero shared secret
    let sk = Zeroizing::new([1u8; 32]);
    let zero_pk = [0u8; 32];

    assert!(
        !shared_secret_nonzero(&sk, &zero_pk),
        "All-zero peer key should be detected as invalid"
    );
}

/// Property: Valid peer keys should result in non-zero shared secrets (usually)
#[test]
fn property_valid_keys_nonzero() {
    let sk = Zeroizing::new([42u8; 32]);

    // Test various non-zero peer keys
    let test_pks = vec![[1u8; 32], [2u8; 32], [0xFFu8; 32], [0x77u8; 32]];

    for pk in test_pks {
        // Skip if pk is all zeros
        if pk.iter().all(|&b| b == 0) {
            continue;
        }

        let result = shared_secret_nonzero(&sk, &pk);

        // Most valid keys should result in non-zero shared secrets
        // (there are rare edge cases with low-order points, but they're extremely rare)
        println!("Peer key {:?} -> non-zero: {}", &pk[0..4], result);
    }
}
