use crate::errors::NoiseError;
use hkdf::Hkdf;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

/// Derive an X25519 secret key from a seed, device ID, and epoch.
///
/// Uses HKDF-SHA512 with a fixed salt to derive keys deterministically.
/// The resulting key is clamped for X25519 compatibility.
///
/// # Errors
///
/// Returns `NoiseError::Other` if HKDF expansion fails (should never happen
/// with valid 32-byte output, but we handle it explicitly for robustness).
pub fn derive_x25519_for_device_epoch(
    seed: &[u8; 32],
    device_id: &[u8],
    epoch: u32,
) -> Result<[u8; 32], NoiseError> {
    let salt = b"pubky-noise-x25519:v1";
    let hk = Hkdf::<Sha512>::new(Some(salt), seed);
    let mut info = Vec::with_capacity(device_id.len() + 4);
    info.extend_from_slice(device_id);
    info.extend_from_slice(&epoch.to_le_bytes());
    let mut sk = [0u8; 32];
    hk.expand(&info, &mut sk)
        .map_err(|e| NoiseError::Other(format!("HKDF expand failed: {:?}", e)))?;
    sk[0] &= 248;
    sk[31] &= 127;
    sk[31] |= 64;
    Ok(sk)
}

/// Derive X25519 public key from secret key using proper RFC 7748 operations.
///
/// Uses x25519-dalek's bare `x25519` function which implements the Montgomery
/// ladder multiplication exactly as specified in RFC 7748, ensuring
/// interoperability with snow and other RFC 7748-compliant implementations.
pub fn x25519_pk_from_sk(sk: &[u8; 32]) -> [u8; 32] {
    use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

    x25519(*sk, X25519_BASEPOINT_BYTES)
}

/// Check if X25519 DH shared secret is non-zero using proper RFC 7748 operations.
///
/// Returns `false` if the shared secret is all zeros (indicating an invalid
/// peer public key such as a low-order point), `true` otherwise.
///
/// Uses x25519-dalek's bare `x25519` function which implements the Montgomery
/// ladder multiplication exactly as specified in RFC 7748, ensuring
/// interoperability with snow and other RFC 7748-compliant implementations.
pub fn shared_secret_nonzero(local_sk: &Zeroizing<[u8; 32]>, peer_pk: &[u8; 32]) -> bool {
    use x25519_dalek::x25519;

    let shared = x25519(**local_sk, *peer_pk);

    shared.iter().any(|&b| b != 0)
}

/// Derive a noise seed from an Ed25519 secret key and device ID.
///
/// This produces a 32-byte seed that can be used for local X25519 epoch key
/// derivation without needing to call Ring again. The seed is domain-separated
/// and cannot be used for Ed25519 signing.
///
/// Uses HKDF-SHA256 with:
/// - salt: "paykit-noise-seed-v1"
/// - ikm: Ed25519 secret key (32 bytes)
/// - info: device ID
/// - output: 32 bytes
///
/// # Errors
///
/// Returns `NoiseError::Other` if HKDF expansion fails (should never happen
/// with valid 32-byte output, but we handle it explicitly for robustness).
pub fn derive_noise_seed(ed25519_secret: &[u8; 32], device_id: &[u8]) -> Result<[u8; 32], NoiseError> {
    let salt = b"paykit-noise-seed-v1";
    let hk = Hkdf::<Sha256>::new(Some(salt), ed25519_secret);
    let mut seed = [0u8; 32];
    hk.expand(device_id, &mut seed)
        .map_err(|e| NoiseError::Other(format!("HKDF expand failed: {:?}", e)))?;
    Ok(seed)
}
