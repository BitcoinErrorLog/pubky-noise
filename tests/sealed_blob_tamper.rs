//! Sealed Blob Tamper Detection Tests
//!
//! These tests verify that the SealedBlob implementation correctly detects
//! and rejects tampered or malformed envelopes.

use pubky_noise::sealed_blob::{
    sealed_blob_decrypt, sealed_blob_encrypt, x25519_generate_keypair, SealedBlobEnvelope,
};

/// Helper to create a valid encrypted blob for testing
fn create_test_blob() -> (String, [u8; 32], String) {
    let (recipient_sk, recipient_pk) = x25519_generate_keypair();
    let plaintext = b"test secret data";
    let aad = "test:context:/pub/test/path";

    let envelope_json = sealed_blob_encrypt(&recipient_pk, plaintext, aad, Some("test")).unwrap();
    (envelope_json, recipient_sk, aad.to_string())
}

/// Test that flipping a single bit in the ciphertext causes decryption to fail
#[test]
fn test_ciphertext_bit_flip_fails() {
    let (envelope_json, recipient_sk, aad) = create_test_blob();

    // Parse the envelope to modify the ciphertext
    let mut envelope: SealedBlobEnvelope = serde_json::from_str(&envelope_json).unwrap();

    // Decode, flip a bit, and re-encode the ciphertext
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let mut ct_bytes = URL_SAFE_NO_PAD.decode(&envelope.ct).unwrap();
    ct_bytes[0] ^= 0x01; // Flip first bit
    envelope.ct = URL_SAFE_NO_PAD.encode(&ct_bytes);

    let tampered_json = serde_json::to_string(&envelope).unwrap();

    // Decryption should fail
    let result = sealed_blob_decrypt(&recipient_sk, &tampered_json, &aad);
    assert!(
        result.is_err(),
        "Decryption should fail with tampered ciphertext"
    );
}

/// Test that flipping a single bit in the ephemeral public key causes decryption to fail
#[test]
fn test_epk_bit_flip_fails() {
    let (envelope_json, recipient_sk, aad) = create_test_blob();

    // Parse the envelope to modify the ephemeral public key
    let mut envelope: SealedBlobEnvelope = serde_json::from_str(&envelope_json).unwrap();

    // Decode, flip a bit, and re-encode the ephemeral public key
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let mut epk_bytes = URL_SAFE_NO_PAD.decode(&envelope.epk).unwrap();
    epk_bytes[0] ^= 0x01; // Flip first bit
    envelope.epk = URL_SAFE_NO_PAD.encode(&epk_bytes);

    let tampered_json = serde_json::to_string(&envelope).unwrap();

    // Decryption should fail
    let result = sealed_blob_decrypt(&recipient_sk, &tampered_json, &aad);
    assert!(
        result.is_err(),
        "Decryption should fail with tampered ephemeral public key"
    );
}

/// Test that flipping a single bit in the nonce causes decryption to fail
#[test]
fn test_nonce_bit_flip_fails() {
    let (envelope_json, recipient_sk, aad) = create_test_blob();

    // Parse the envelope to modify the nonce
    let mut envelope: SealedBlobEnvelope = serde_json::from_str(&envelope_json).unwrap();

    // Decode, flip a bit, and re-encode the nonce
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let mut nonce_bytes = URL_SAFE_NO_PAD.decode(&envelope.nonce).unwrap();
    nonce_bytes[0] ^= 0x01; // Flip first bit
    envelope.nonce = URL_SAFE_NO_PAD.encode(&nonce_bytes);

    let tampered_json = serde_json::to_string(&envelope).unwrap();

    // Decryption should fail
    let result = sealed_blob_decrypt(&recipient_sk, &tampered_json, &aad);
    assert!(
        result.is_err(),
        "Decryption should fail with tampered nonce"
    );
}

/// Test that truncated ciphertext causes decryption to fail
#[test]
fn test_truncated_ciphertext_fails() {
    let (envelope_json, recipient_sk, aad) = create_test_blob();

    // Parse the envelope to truncate the ciphertext
    let mut envelope: SealedBlobEnvelope = serde_json::from_str(&envelope_json).unwrap();

    // Decode, truncate, and re-encode the ciphertext
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let mut ct_bytes = URL_SAFE_NO_PAD.decode(&envelope.ct).unwrap();
    ct_bytes.truncate(ct_bytes.len() / 2); // Remove half the ciphertext
    envelope.ct = URL_SAFE_NO_PAD.encode(&ct_bytes);

    let tampered_json = serde_json::to_string(&envelope).unwrap();

    // Decryption should fail
    let result = sealed_blob_decrypt(&recipient_sk, &tampered_json, &aad);
    assert!(
        result.is_err(),
        "Decryption should fail with truncated ciphertext"
    );
}

/// Test that wrong AAD causes decryption to fail (authentication check)
#[test]
fn test_wrong_aad_fails() {
    let (envelope_json, recipient_sk, _aad) = create_test_blob();

    // Use different AAD for decryption
    let wrong_aad = "different:context:/pub/different/path";

    // Decryption should fail due to AAD mismatch
    let result = sealed_blob_decrypt(&recipient_sk, &envelope_json, wrong_aad);
    assert!(
        result.is_err(),
        "Decryption should fail with wrong AAD"
    );
}

/// Test that unsupported version is rejected
#[test]
fn test_unsupported_version_rejected() {
    let (envelope_json, recipient_sk, aad) = create_test_blob();

    // Parse and change version to unsupported
    let mut envelope: SealedBlobEnvelope = serde_json::from_str(&envelope_json).unwrap();
    envelope.v = 99; // Unsupported version

    let tampered_json = serde_json::to_string(&envelope).unwrap();

    // Decryption should fail due to unsupported version
    let result = sealed_blob_decrypt(&recipient_sk, &tampered_json, &aad);
    assert!(
        result.is_err(),
        "Decryption should fail with unsupported version"
    );
}

/// Test that kid is optional and doesn't affect decryption
/// (kid is just a hint for key selection, not authenticated)
#[test]
fn test_kid_is_optional_hint() {
    let (envelope_json, recipient_sk, aad) = create_test_blob();

    // Parse and remove or modify kid
    let mut envelope: SealedBlobEnvelope = serde_json::from_str(&envelope_json).unwrap();

    // Remove kid entirely
    envelope.kid = None;
    let modified_json = serde_json::to_string(&envelope).unwrap();
    let result = sealed_blob_decrypt(&recipient_sk, &modified_json, &aad);
    assert!(
        result.is_ok(),
        "Decryption should succeed without kid"
    );

    // Change kid to wrong value
    envelope.kid = Some("wrongkidvalue".to_string());
    let modified_json = serde_json::to_string(&envelope).unwrap();
    let result = sealed_blob_decrypt(&recipient_sk, &modified_json, &aad);
    assert!(
        result.is_ok(),
        "Decryption should succeed with wrong kid (it's just a hint)"
    );
}

/// Test that malformed JSON is rejected
#[test]
fn test_malformed_json_rejected() {
    let (_, recipient_sk, _) = create_test_blob();
    let aad = "test:context";

    // Try various malformed inputs
    let malformed_inputs = [
        "not json at all",
        "{incomplete json",
        r#"{"v":1}"#, // Missing required fields
        r#"{"v":1,"epk":"invalid!base64","nonce":"abc","ct":"def"}"#, // Invalid base64
        "",
        "null",
        "[]",
    ];

    for input in malformed_inputs {
        let result = sealed_blob_decrypt(&recipient_sk, input, aad);
        assert!(
            result.is_err(),
            "Decryption should fail for malformed input: {}",
            input
        );
    }
}

/// Test that invalid key sizes are rejected
#[test]
fn test_invalid_key_size_rejected() {
    let (envelope_json, recipient_sk, aad) = create_test_blob();

    // Parse and modify ephemeral public key to wrong size
    let mut envelope: SealedBlobEnvelope = serde_json::from_str(&envelope_json).unwrap();

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    // Too short
    envelope.epk = URL_SAFE_NO_PAD.encode([0u8; 16]);
    let tampered_json = serde_json::to_string(&envelope).unwrap();
    let result = sealed_blob_decrypt(&recipient_sk, &tampered_json, &aad);
    assert!(
        result.is_err(),
        "Decryption should fail with too-short ephemeral key"
    );

    // Too long
    envelope.epk = URL_SAFE_NO_PAD.encode([0u8; 64]);
    let tampered_json = serde_json::to_string(&envelope).unwrap();
    let result = sealed_blob_decrypt(&recipient_sk, &tampered_json, &aad);
    assert!(
        result.is_err(),
        "Decryption should fail with too-long ephemeral key"
    );
}

/// Test that invalid nonce sizes are rejected
#[test]
fn test_invalid_nonce_size_rejected() {
    let (envelope_json, recipient_sk, aad) = create_test_blob();

    // Parse and modify nonce to wrong size
    let mut envelope: SealedBlobEnvelope = serde_json::from_str(&envelope_json).unwrap();

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    // Too short (v2 expects 24 bytes)
    envelope.nonce = URL_SAFE_NO_PAD.encode([0u8; 8]);
    let tampered_json = serde_json::to_string(&envelope).unwrap();
    let result = sealed_blob_decrypt(&recipient_sk, &tampered_json, &aad);
    assert!(
        result.is_err(),
        "Decryption should fail with too-short nonce"
    );

    // Too long (v2 expects 24 bytes, not 32)
    envelope.nonce = URL_SAFE_NO_PAD.encode([0u8; 32]);
    let tampered_json = serde_json::to_string(&envelope).unwrap();
    let result = sealed_blob_decrypt(&recipient_sk, &tampered_json, &aad);
    assert!(
        result.is_err(),
        "Decryption should fail with too-long nonce"
    );
}

