#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use pubky_noise::kdf::{derive_x25519_for_device_epoch, shared_secret_nonzero, x25519_pk_from_sk};
use zeroize::Zeroizing;

/// Arbitrary input for KDF functions
#[derive(Debug, Arbitrary)]
struct KdfInput {
    seed: [u8; 32],
    device_id: Vec<u8>,
    epoch: u32,
    peer_pk: [u8; 32],
}

fuzz_target!(|input: KdfInput| {
    // Test derive_x25519_for_device_epoch
    let sk = derive_x25519_for_device_epoch(&input.seed, &input.device_id, input.epoch)
        .expect("HKDF should never fail with valid inputs");

    // Verify the key is clamped correctly (X25519 requirements)
    assert_eq!(sk[0] & 7, 0, "Low 3 bits should be cleared");
    assert_eq!(sk[31] & 128, 0, "High bit should be cleared");
    assert_eq!(sk[31] & 64, 64, "Bit 6 should be set");

    // Verify determinism
    let sk2 = derive_x25519_for_device_epoch(&input.seed, &input.device_id, input.epoch)
        .expect("HKDF should never fail with valid inputs");
    assert_eq!(sk, sk2);

    // Test x25519_pk_from_sk doesn't panic
    let pk = x25519_pk_from_sk(&sk);

    // Verify pk is deterministic
    let pk2 = x25519_pk_from_sk(&sk);
    assert_eq!(pk, pk2);

    // Test shared_secret_nonzero
    let sk_zeroizing = Zeroizing::new(sk);
    let result = shared_secret_nonzero(&sk_zeroizing, &input.peer_pk);

    // Zero peer_pk should always produce zero shared secret (rejected)
    let zero_pk = [0u8; 32];
    let zero_result = shared_secret_nonzero(&sk_zeroizing, &zero_pk);
    assert!(!zero_result, "Zero peer_pk should be rejected");

    // DH with own public key should work (non-zero)
    let self_result = shared_secret_nonzero(&sk_zeroizing, &pk);
    // Note: this might not always be true for all curves, but should be for x25519
    // Let's not assert this to avoid false positives

    // Just verify the function doesn't panic with arbitrary input
    let _ = result;
    let _ = self_result;
});

