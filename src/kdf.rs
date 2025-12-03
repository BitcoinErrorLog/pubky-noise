use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroizing;

/// Derive an X25519 secret key for a specific context using HKDF-SHA512.
///
/// This function uses HKDF (HMAC-based Key Derivation Function) with SHA-512 to derive
/// context-specific X25519 keys from a root seed. The derivation includes:
///
/// - Domain separation via salt: `"pubky-noise-x25519:v2"`
/// - Context binding: arbitrary context bytes (device ID, purpose, etc.)
/// - X25519 scalar clamping per RFC 7748
///
/// # Arguments
///
/// * `seed` - 32-byte root seed material
/// * `context` - Context bytes for derivation (device ID, purpose, etc.)
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
///
/// # Example
///
/// ```rust
/// use pubky_noise::kdf;
///
/// let seed = [0u8; 32]; // Root seed
/// let x25519_sk = kdf::derive_x25519_static(&seed, b"device-001");
/// ```
pub fn derive_x25519_static(seed: &[u8; 32], context: &[u8]) -> [u8; 32] {
    let salt = b"pubky-noise-x25519:v2";
    let hk = Hkdf::<Sha512>::new(Some(salt), seed);
    let mut sk = [0u8; 32];

    // HKDF expand cannot fail for 32-byte output
    // (maximum for SHA-512 is 255 * 64 = 16,320 bytes per RFC 5869)
    hk.expand(context, &mut sk)
        .expect("HKDF-SHA512 cannot fail for 32-byte output per RFC 5869");

    // X25519 scalar clamping per RFC 7748
    sk[0] &= 248; // Clear bottom 3 bits
    sk[31] &= 127; // Clear top bit
    sk[31] |= 64; // Set bit 254

    sk
}

/// Deprecated: Use `derive_x25519_static` instead.
///
/// This function derives an X25519 key using device ID and epoch as context.
/// The epoch was previously used for key rotation, but is no longer part of
/// the Noise protocol binding. It's now just part of the derivation context.
#[deprecated(since = "0.8.0", note = "Use derive_x25519_static instead")]
pub fn derive_x25519_for_device_epoch(seed: &[u8; 32], device_id: &[u8], epoch: u32) -> [u8; 32] {
    let salt = b"pubky-noise-x25519:v1";
    let hk = Hkdf::<Sha512>::new(Some(salt), seed);
    let mut info = Vec::with_capacity(device_id.len() + 4);
    info.extend_from_slice(device_id);
    info.extend_from_slice(&epoch.to_le_bytes());
    let mut sk = [0u8; 32];

    hk.expand(&info, &mut sk)
        .expect("HKDF-SHA512 cannot fail for 32-byte output per RFC 5869");

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

/// Derive Ed25519 secret key bytes from a seed.
///
/// This function simply returns the seed as the Ed25519 secret key.
/// Ed25519 uses a 32-byte seed as the secret key material.
///
/// # Arguments
///
/// * `seed` - 32-byte seed
///
/// # Returns
///
/// 32-byte Ed25519 secret key (same as seed).
pub fn derive_ed25519_secret(seed: &[u8; 32]) -> [u8; 32] {
    *seed
}

/// Derive Ed25519 public key from a seed.
///
/// Computes the Ed25519 public key from a 32-byte seed.
///
/// # Arguments
///
/// * `seed` - 32-byte seed
///
/// # Returns
///
/// 32-byte Ed25519 public key.
pub fn derive_ed25519_public(seed: &[u8; 32]) -> [u8; 32] {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(seed);
    signing_key.verifying_key().to_bytes()
}
