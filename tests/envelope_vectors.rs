//! Test vectors for Sealed Blob v2 format
//!
//! These tests verify deterministic behavior and cross-platform compatibility.

use pubky_noise::sealed_blob::{is_sealed_blob, sealed_blob_decrypt, sealed_blob_encrypt};

/// Test that v2 envelopes have correct structure
#[test]
fn test_v2_envelope_structure() {
    // Use known keypair for reproducibility
    let recipient_sk: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x40, // Clamped for X25519
    ];

    // Derive public key
    let recipient_pk = pubky_noise::sealed_blob::x25519_public_from_secret(&recipient_sk);

    let plaintext = b"Hello, World!";
    let aad = "test:v2:envelope";

    // Encrypt
    let envelope_json =
        sealed_blob_encrypt(&recipient_pk, plaintext, aad, Some("test")).unwrap();

    // Parse envelope
    let envelope: serde_json::Value = serde_json::from_str(&envelope_json).unwrap();

    // Verify v2 structure
    assert_eq!(envelope["v"].as_u64().unwrap(), 2, "Version should be 2");
    assert!(envelope["epk"].is_string(), "epk should be a string");
    assert!(envelope["nonce"].is_string(), "nonce should be a string");
    assert!(envelope["ct"].is_string(), "ct should be a string");
    assert!(envelope["kid"].is_string(), "kid should be a string");
    assert_eq!(
        envelope["purpose"].as_str(),
        Some("test"),
        "purpose should be 'test'"
    );

    // v2 nonce should be 24 bytes (32 chars in base64url)
    let nonce = envelope["nonce"].as_str().unwrap();
    assert!(
        nonce.len() >= 32,
        "v2 nonce should be at least 32 base64url chars (24 bytes)"
    );

    // Verify decryption
    let decrypted = sealed_blob_decrypt(&recipient_sk, &envelope_json, aad).unwrap();
    assert_eq!(decrypted, plaintext);
}

/// Test v1 backward compatibility using manually constructed v1 envelope
#[test]
fn test_v1_backward_compatibility() {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::ChaCha20Poly1305;
    use hkdf::Hkdf;
    use sha2::Sha256;
    use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};
    use zeroize::Zeroizing;

    // Known recipient keypair
    let mut recipient_sk: [u8; 32] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff, 0x00,
    ];
    // Clamp for X25519
    recipient_sk[0] &= 248;
    recipient_sk[31] &= 127;
    recipient_sk[31] |= 64;

    let recipient_pk = x25519(recipient_sk, X25519_BASEPOINT_BYTES);

    // Known ephemeral keypair
    let mut ephemeral_sk: [u8; 32] = [
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99,
    ];
    // Clamp
    ephemeral_sk[0] &= 248;
    ephemeral_sk[31] &= 127;
    ephemeral_sk[31] |= 64;

    let ephemeral_pk = x25519(ephemeral_sk, X25519_BASEPOINT_BYTES);

    // Compute shared secret
    let shared_secret = Zeroizing::new(x25519(ephemeral_sk, recipient_pk));

    // Derive v1 symmetric key
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(&ephemeral_pk);
    salt[32..].copy_from_slice(&recipient_pk);

    let hk = Hkdf::<Sha256>::new(Some(&salt), &*shared_secret);
    let mut key = [0u8; 32];
    hk.expand(b"paykit-sealed-blob-v1", &mut key)
        .expect("HKDF expand should succeed");

    // Known nonce (12 bytes for v1)
    let nonce: [u8; 12] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c];

    // Plaintext and AAD
    let plaintext = b"v1 test data";
    let aad = "test:v1:compat";

    // Encrypt with v1 algorithm
    let cipher = ChaCha20Poly1305::new(&key.into());
    let ciphertext = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: plaintext,
                aad: aad.as_bytes(),
            },
        )
        .expect("Encryption should succeed");

    // Build v1 envelope
    let envelope = serde_json::json!({
        "v": 1,
        "epk": URL_SAFE_NO_PAD.encode(&ephemeral_pk),
        "nonce": URL_SAFE_NO_PAD.encode(&nonce),
        "ct": URL_SAFE_NO_PAD.encode(&ciphertext),
    });
    let envelope_json = serde_json::to_string(&envelope).unwrap();

    // Verify is_sealed_blob detects it
    assert!(is_sealed_blob(&envelope_json), "Should detect v1 envelope");

    // Decrypt with v2 code (should auto-detect v1)
    let decrypted = sealed_blob_decrypt(&recipient_sk, &envelope_json, aad)
        .expect("v1 decryption should succeed");

    assert_eq!(decrypted, plaintext);
}

/// Test that is_sealed_blob correctly distinguishes v1, v2, and invalid envelopes
#[test]
fn test_is_sealed_blob_detection() {
    // Valid v1
    assert!(is_sealed_blob(r#"{"v":1,"epk":"abc"}"#));
    assert!(is_sealed_blob(r#"{"v": 1, "epk": "xyz"}"#));

    // Valid v2
    assert!(is_sealed_blob(r#"{"v":2,"epk":"abc"}"#));
    assert!(is_sealed_blob(r#"{"v": 2, "epk": "xyz"}"#));

    // Invalid - no epk
    assert!(!is_sealed_blob(r#"{"v":1}"#));
    assert!(!is_sealed_blob(r#"{"v":2}"#));

    // Invalid - unsupported version
    assert!(!is_sealed_blob(r#"{"v":0,"epk":"abc"}"#));
    assert!(!is_sealed_blob(r#"{"v":3,"epk":"abc"}"#));
    assert!(!is_sealed_blob(r#"{"v":99,"epk":"abc"}"#));

    // Invalid - no version
    assert!(!is_sealed_blob(r#"{"epk":"abc"}"#));

    // Not JSON
    assert!(!is_sealed_blob("not json at all"));
    assert!(!is_sealed_blob(""));
}

/// Test round-trip encryption/decryption with various data sizes
#[test]
fn test_various_plaintext_sizes() {
    let (recipient_sk, recipient_pk) = pubky_noise::sealed_blob::x25519_generate_keypair();
    let aad = "test:size:variations";

    // Test sizes: empty, small, medium, large (just under 64KB limit)
    let test_sizes = [0, 1, 16, 256, 4096, 65536 - 1];

    for size in test_sizes {
        let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

        let envelope = sealed_blob_encrypt(&recipient_pk, &plaintext, aad, None)
            .expect(&format!("Encryption should succeed for size {}", size));

        let decrypted = sealed_blob_decrypt(&recipient_sk, &envelope, aad)
            .expect(&format!("Decryption should succeed for size {}", size));

        assert_eq!(
            decrypted, plaintext,
            "Round-trip should preserve data for size {}",
            size
        );
    }
}

