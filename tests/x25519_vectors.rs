//! RFC 7748 Known-Vector Tests for X25519 Operations
//!
//! These tests verify that our X25519 implementation produces correct results
//! by comparing against the test vectors specified in RFC 7748 Section 6.1.
//!
//! Test vectors from: https://www.rfc-editor.org/rfc/rfc7748#section-6.1

use pubky_noise::kdf::{shared_secret_nonzero, x25519_pk_from_sk};
use zeroize::Zeroizing;

/// RFC 7748 Section 6.1 - Test Vector 1
/// Alice's private key (clamped) and expected public key
#[test]
fn test_rfc7748_alice_keypair() {
    // Alice's private key (already clamped per RFC 7748)
    let alice_private: [u8; 32] = [
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66,
        0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9,
        0x2c, 0x2a,
    ];

    // Expected Alice's public key from RFC 7748
    let expected_alice_public: [u8; 32] = [
        0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7,
        0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b,
        0x4e, 0x6a,
    ];

    let computed_public = x25519_pk_from_sk(&alice_private);
    assert_eq!(
        computed_public, expected_alice_public,
        "Alice's public key doesn't match RFC 7748 test vector"
    );
}

/// RFC 7748 Section 6.1 - Test Vector 2
/// Bob's private key (clamped) and expected public key
#[test]
fn test_rfc7748_bob_keypair() {
    // Bob's private key (already clamped per RFC 7748)
    let bob_private: [u8; 32] = [
        0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e,
        0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88,
        0xe0, 0xeb,
    ];

    // Expected Bob's public key from RFC 7748
    let expected_bob_public: [u8; 32] = [
        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35,
        0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88,
        0x2b, 0x4f,
    ];

    let computed_public = x25519_pk_from_sk(&bob_private);
    assert_eq!(
        computed_public, expected_bob_public,
        "Bob's public key doesn't match RFC 7748 test vector"
    );
}

/// RFC 7748 Section 6.1 - Shared Secret Test
/// Verify that Alice and Bob compute the same shared secret
#[test]
fn test_rfc7748_shared_secret() {
    // Alice's private key
    let alice_private: [u8; 32] = [
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66,
        0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9,
        0x2c, 0x2a,
    ];

    // Bob's public key
    let bob_public: [u8; 32] = [
        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35,
        0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88,
        0x2b, 0x4f,
    ];

    // Expected shared secret from RFC 7748
    let expected_shared: [u8; 32] = [
        0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f,
        0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16,
        0x17, 0x42,
    ];

    // Compute shared secret using x25519 function directly for verification
    use x25519_dalek::x25519;
    let computed_shared = x25519(alice_private, bob_public);

    assert_eq!(
        computed_shared, expected_shared,
        "Shared secret doesn't match RFC 7748 test vector"
    );

    // Also verify our shared_secret_nonzero returns true
    let alice_sk = Zeroizing::new(alice_private);
    assert!(
        shared_secret_nonzero(&alice_sk, &bob_public),
        "shared_secret_nonzero should return true for valid keys"
    );
}

/// Test that all-zero peer public key results in all-zero shared secret
/// and is correctly rejected by shared_secret_nonzero
#[test]
fn test_zero_public_key_rejected() {
    let private_key: [u8; 32] = [
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66,
        0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9,
        0x2c, 0x2a,
    ];
    let zero_public: [u8; 32] = [0u8; 32];

    let sk = Zeroizing::new(private_key);
    assert!(
        !shared_secret_nonzero(&sk, &zero_public),
        "shared_secret_nonzero should return false for all-zero peer key"
    );
}

/// Test interoperability with snow by verifying that our public key
/// derivation works correctly with snow's handshake
#[test]
fn test_snow_interop_keypair() {
    use snow::Builder;

    // Use a known seed
    let seed: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];

    // Derive X25519 key using our HKDF approach (which does clamping)
    let derived_sk = pubky_noise::kdf::derive_x25519_for_device_epoch(&seed, b"test", 0).unwrap();
    let our_public = x25519_pk_from_sk(&derived_sk);

    // Use XX pattern which doesn't require remote public key
    let params: snow::params::NoiseParams = "Noise_XX_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
    let builder = Builder::new(params);
    let mut initiator = builder
        .local_private_key(&derived_sk)
        .build_initiator()
        .unwrap();

    // Verify our public key is non-zero
    assert_ne!(our_public, [0u8; 32], "Public key should not be all zeros");

    // Verify deterministic derivation
    let our_public_2 = x25519_pk_from_sk(&derived_sk);
    assert_eq!(our_public, our_public_2, "Public key derivation should be deterministic");

    // Create a responder with a different key to verify the handshake works
    let responder_sk: [u8; 32] = [0x42u8; 32];
    let _responder_pk = x25519_pk_from_sk(&responder_sk);

    let params2: snow::params::NoiseParams = "Noise_XX_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
    let mut responder = Builder::new(params2)
        .local_private_key(&responder_sk)
        .build_responder()
        .unwrap();

    // Perform handshake to verify interop
    let mut msg = [0u8; 128];
    let len = initiator.write_message(&[], &mut msg).unwrap();

    let mut buf = [0u8; 128];
    responder.read_message(&msg[..len], &mut buf).unwrap();
    let len = responder.write_message(&[], &mut msg).unwrap();

    initiator.read_message(&msg[..len], &mut buf).unwrap();
    let len = initiator.write_message(&[], &mut msg).unwrap();

    responder.read_message(&msg[..len], &mut buf).unwrap();

    // Verify handshake completed
    assert!(initiator.is_handshake_finished());
    assert!(responder.is_handshake_finished());

    // Verify the responder sees our public key correctly
    let remote_static = responder.get_remote_static().unwrap();
    assert_eq!(remote_static, our_public.as_slice(), "Snow should see our public key correctly");
}

/// Test that public key derivation is deterministic
#[test]
fn test_deterministic_pk_derivation() {
    let private_key: [u8; 32] = [0x42u8; 32];

    let pk1 = x25519_pk_from_sk(&private_key);
    let pk2 = x25519_pk_from_sk(&private_key);
    let pk3 = x25519_pk_from_sk(&private_key);

    assert_eq!(pk1, pk2);
    assert_eq!(pk2, pk3);
}

/// Test that different private keys produce different public keys
#[test]
fn test_different_keys_different_outputs() {
    let sk1: [u8; 32] = [0x01u8; 32];
    let sk2: [u8; 32] = [0x02u8; 32];
    let sk3: [u8; 32] = [0x03u8; 32];

    let pk1 = x25519_pk_from_sk(&sk1);
    let pk2 = x25519_pk_from_sk(&sk2);
    let pk3 = x25519_pk_from_sk(&sk3);

    assert_ne!(pk1, pk2);
    assert_ne!(pk2, pk3);
    assert_ne!(pk1, pk3);
}

