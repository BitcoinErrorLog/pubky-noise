use crate::errors::NoiseError;
use hkdf::Hkdf;
use sha2::Sha512;
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

pub fn x25519_pk_from_sk(sk: &[u8; 32]) -> [u8; 32] {
    // x25519-dalek v2: compute public key from secret key
    // Use curve25519-dalek directly for scalar operations
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::scalar::Scalar;

    let scalar = Scalar::from_bytes_mod_order(*sk);
    let point = &scalar * ED25519_BASEPOINT_TABLE;
    point.to_montgomery().to_bytes()
}

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
