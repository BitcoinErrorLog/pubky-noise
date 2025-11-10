use sha2::{Sha512, Digest};

/// Derive a deterministic X25519 static secret from a 32 byte Ed25519 seed,
/// domain-separated, per-device, per-epoch. Use this for cold-Ring operation.
/// Deterministic per-device, per-epoch X25519 private key derivation.
/// Do not log or persist the returned secret; feed it directly to `snow::Builder::local_private_key`.
pub fn derive_x25519_for_device_epoch(
    ed25519_seed: &[u8; 32],
    device_id: &[u8],
    epoch: u32,
) -> [u8; 32] {
    let mut h = Sha512::new();
    h.update(b"pubky-noise-x25519:v1");
    h.update(device_id);
    h.update(&epoch.to_le_bytes());
    h.update(ed25519_seed);
    let digest = h.finalize();
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&digest[..32]);
    // X25519 clamp
    sk[0]  &= 248;
    sk[31] &= 127;
    sk[31] |= 64;
    sk
}

/// Back-compat simple derivation (no device/epoch). Prefer derive_x25519_for_device_epoch.
pub fn ed25519_seed_to_x25519_sk(seed32: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha512::new();
    h.update(b"pubky-noise-x25519:v1");
    h.update(seed32);
    let digest = h.finalize();
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&digest[..32]);
    // X25519 clamp
    sk[0]  &= 248;
    sk[31] &= 127;
    sk[31] |= 64;
    sk
}

pub fn x25519_pk_from_sk(sk: &[u8; 32]) -> [u8; 32] {
    use x25519_dalek::{PublicKey, StaticSecret};
    let sec = StaticSecret::from(*sk);
    let pubk = PublicKey::from(&sec);
    pubk.to_bytes()
}
