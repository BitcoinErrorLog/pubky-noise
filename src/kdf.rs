use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroizing;

/// Derive an X25519 secret key for a specific device and epoch using HKDF-SHA512.
///
/// This function uses HKDF (HMAC-based Key Derivation Function) with SHA-512 to derive
/// device-specific X25519 keys from a root seed. The derivation includes:
///
/// - Domain separation via salt: `"pubky-noise-x25519:v1"`
/// - Context binding: device ID and epoch
/// - X25519 scalar clamping per RFC 7748
///
/// # Arguments
///
/// * `seed` - 32-byte root seed material
/// * `device_id` - Device identifier (arbitrary length)
/// * `epoch` - Key rotation epoch
///
/// # Returns
///
/// A 32-byte X25519 secret key with proper clamping applied.
///
/// # Note
///
/// This function cannot fail - HKDF-SHA512 supports output lengths up to 16,320 bytes,
/// and we only request 32 bytes. The function signature returns `[u8; 32]` directly
/// rather than `Result` because failure is mathematically impossible.
pub fn derive_x25519_for_device_epoch(seed: &[u8; 32], device_id: &[u8], epoch: u32) -> [u8; 32] {
    let salt = b"pubky-noise-x25519:v1";
    let hk = Hkdf::<Sha512>::new(Some(salt), seed);
    let mut info = Vec::with_capacity(device_id.len() + 4);
    info.extend_from_slice(device_id);
    info.extend_from_slice(&epoch.to_le_bytes());
    let mut sk = [0u8; 32];

    // HKDF expand cannot fail for 32-byte output
    // (maximum for SHA-512 is 255 * 64 = 16,320 bytes per RFC 5869)
    // Using unwrap() here is safe and documented above
    hk.expand(&info, &mut sk).unwrap();

    // X25519 scalar clamping per RFC 7748
    sk[0] &= 248; // Clear bottom 3 bits
    sk[31] &= 127; // Clear top bit
    sk[31] |= 64; // Set bit 254

    sk
}

/// Compute X25519 public key from secret key.
///
/// Converts a 32-byte X25519 secret key to its corresponding public key
/// by performing scalar multiplication with the Curve25519 basepoint.
///
/// # Arguments
///
/// * `sk` - 32-byte X25519 secret key (should be clamped)
///
/// # Returns
///
/// A 32-byte X25519 public key (Montgomery form).
pub fn x25519_pk_from_sk(sk: &[u8; 32]) -> [u8; 32] {
    // x25519-dalek v2: compute public key from secret key
    // Use curve25519-dalek directly for scalar operations
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::scalar::Scalar;

    let scalar = Scalar::from_bytes_mod_order(*sk);
    let point = &scalar * ED25519_BASEPOINT_TABLE;
    point.to_montgomery().to_bytes()
}

/// Check if Diffie-Hellman shared secret is non-zero (constant-time).
///
/// This function performs X25519 ECDH and checks whether the resulting
/// shared secret is all-zero. An all-zero shared secret indicates that
/// the peer's public key was invalid or a low-order point, which would
/// result in a trivial/predictable shared secret.
///
/// The zero-check is performed in constant time to prevent timing attacks.
///
/// # Arguments
///
/// * `local_sk` - Local X25519 secret key (wrapped in Zeroizing)
/// * `peer_pk` - Peer's X25519 public key
///
/// # Returns
///
/// `true` if the shared secret is non-zero (valid), `false` if all-zero (invalid).
///
/// # Security
///
/// This function is crucial for preventing acceptance of invalid public keys
/// that would result in weak/trivial shared secrets. Always check the return
/// value and reject the handshake if it returns `false`.
pub fn shared_secret_nonzero(local_sk: &Zeroizing<[u8; 32]>, peer_pk: &[u8; 32]) -> bool {
    // x25519-dalek v2: perform DH operation using curve25519-dalek primitives
    use curve25519_dalek::montgomery::MontgomeryPoint;
    use curve25519_dalek::scalar::Scalar;

    let scalar = Scalar::from_bytes_mod_order(**local_sk);
    let peer_point = MontgomeryPoint(*peer_pk);
    let shared = (scalar * peer_point).to_bytes();

    let mut acc: u8 = 0;
    for b in shared {
        acc |= b;
    }
    acc != 0
}
