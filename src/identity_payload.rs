use blake2::{Blake2s256, Digest};
use ed25519_dalek::{Signature, VerifyingKey, Signer, SigningKey, Verifier};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Role { Client, Server }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityPayload {
    pub ed25519_pub: [u8; 32],
    pub noise_x25519_pub: [u8; 32],
    pub epoch: u32,
    pub role: Role,
    pub server_hint: Option<String>,
    pub sig: [u8; 64],
}

/// Transcript/Context binding digest (32 bytes) for identity payload signing.
pub fn make_binding_message(
    pattern_tag: &str,
    prologue: &[u8],
    ed25519_pub: &[u8; 32],
    local_noise_pub: &[u8; 32],
    remote_noise_pub: Option<&[u8; 32]>,
    epoch: u32,
    role: Role,
    server_hint: Option<&str>,
) -> [u8; 32] {
    let mut h = Blake2s256::new();
    h.update(b"pubky-noise-bind:v1");
    h.update(pattern_tag.as_bytes());
    h.update(prologue);
    h.update(ed25519_pub);
    h.update(local_noise_pub);
    if let Some(r) = remote_noise_pub { h.update(r); }
    h.update(&epoch.to_le_bytes());
    h.update(match role { Role::Client => b"client", Role::Server => b"server" });
    if let Some(hint) = server_hint { h.update(hint.as_bytes()); }
    let out = h.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&out[..32]);
    digest
}

pub fn sign_identity_payload(
    ed25519_sk: &SigningKey,
    msg32: &[u8; 32],
) -> [u8; 64] {
    let sig: Signature = ed25519_sk.sign(msg32);
    sig.to_bytes()
}

pub fn verify_identity_payload(
    ed25519_pub: &VerifyingKey,
    msg32: &[u8; 32],
    sig64: &[u8; 64],
) -> bool {
    let sig = Signature::from_bytes(sig64);
    ed25519_pub.verify(msg32, &sig).is_ok()
}
