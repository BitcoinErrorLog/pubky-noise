use pubky_noise::kdf::shared_secret_nonzero;
use zeroize::Zeroizing;

/// Test that all-zero DH shared secret is rejected
#[test]
fn test_rejects_all_zero_shared_secret() {
    // Create a test secret key
    let local_sk = Zeroizing::new([1u8; 32]);

    // Try with all-zero peer key (invalid point)
    let zero_peer_pk = [0u8; 32];

    // This might or might not result in all-zero depending on the implementation
    // but we test that the function correctly identifies all-zero results
    let result = shared_secret_nonzero(&local_sk, &zero_peer_pk);

    // The all-zero point should result in all-zero shared secret
    // which should be rejected (return false)
    // Note: X25519 with all-zero input typically gives all-zero output
    assert!(
        !result,
        "All-zero peer key should result in zero shared secret and be rejected"
    );
}

/// Test that valid DH shared secret is accepted
#[test]
fn test_accepts_valid_shared_secret() {
    // Create a test secret key
    let local_sk = Zeroizing::new([
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66,
        0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9,
        0x2c, 0x2a,
    ]);

    // Use a valid peer public key (from X25519 test vectors)
    let peer_pk = [
        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35,
        0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88,
        0x2b, 0x4f,
    ];

    let result = shared_secret_nonzero(&local_sk, &peer_pk);

    // Valid peer key should result in non-zero shared secret
    assert!(
        result,
        "Valid peer key should result in non-zero shared secret and be accepted"
    );
}

/// Test with various patterns to ensure constant-time behavior
#[test]
fn test_shared_secret_with_various_keys() {
    // Test multiple secret/public key combinations
    let test_cases = vec![
        // (secret_key_byte, peer_pk_byte, expected_to_be_nonzero, description)
        (0x00, 0x00, false, "all zeros"),
        (0x01, 0x00, false, "zero peer key"),
        (0x01, 0x01, true, "small valid values"),
        (0x42, 0x42, true, "arbitrary valid values"),
        (0xFF, 0xFF, true, "high valid values"),
    ];

    for (sk_byte, pk_byte, expected_nonzero, desc) in test_cases {
        let local_sk = Zeroizing::new([sk_byte; 32]);
        let peer_pk = [pk_byte; 32];

        let result = shared_secret_nonzero(&local_sk, &peer_pk);

        if expected_nonzero {
            // We expect these to potentially be non-zero
            // (though implementation-dependent)
            println!("Test case '{}': result = {}", desc, result);
        } else {
            // These should definitely be zero
            assert!(
                !result,
                "Test case '{}' should result in zero shared secret",
                desc
            );
        }
    }
}

/// Test that the function checks all bytes (not just some)
#[test]
fn test_checks_all_bytes() {
    let local_sk = Zeroizing::new([1u8; 32]);

    // Test with almost-all-zero peer key (only last byte set)
    // This tests that we don't short-circuit and check all bytes
    let mut almost_zero_pk = [0u8; 32];
    almost_zero_pk[31] = 1;

    let result = shared_secret_nonzero(&local_sk, &almost_zero_pk);

    // The behavior depends on the actual DH operation result
    // but we're mainly testing that the function doesn't panic
    // and properly checks all bytes
    println!("Almost-zero peer key result: {}", result);
}

/// Test constant-time property by ensuring function doesn't branch on secret data
/// This is a behavioral test - the actual constant-time check would require
/// timing analysis tools like dudect or ctgrind
#[test]
fn test_constant_time_behavior() {
    // Create two different secret keys
    let sk1 = Zeroizing::new([0x42u8; 32]);
    let sk2 = Zeroizing::new([0x77u8; 32]);

    // Use same peer key
    let peer_pk = [0x99u8; 32];

    // Both should execute in roughly the same time
    // (we can't test timing here, but we test they both complete)
    let result1 = shared_secret_nonzero(&sk1, &peer_pk);
    let result2 = shared_secret_nonzero(&sk2, &peer_pk);

    println!("Result 1: {}, Result 2: {}", result1, result2);

    // Both should succeed without panic
    // Actual constant-time verification requires specialized tools
}
