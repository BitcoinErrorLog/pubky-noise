use blake2::{Blake2s256, Digest};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

// Helper for serializing [u8; 64]
mod signature_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom("signature must be 64 bytes"));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityPayload {
    pub ed25519_pub: [u8; 32],
    pub noise_x25519_pub: [u8; 32],
    pub epoch: u32,
    pub role: Role,
    pub server_hint: Option<String>,
    #[serde(with = "signature_serde")]
    pub sig: [u8; 64],
}

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
    if let Some(r) = remote_noise_pub {
        h.update(r);
    }
    h.update(epoch.to_le_bytes()); // Fixed: removed redundant & borrow
    h.update(match role {
        Role::Client => b"client",
        Role::Server => b"server",
    });
    if let Some(hint) = server_hint {
        h.update(hint.as_bytes());
    }
    let out = h.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&out[..32]);
    digest
}

pub fn sign_identity_payload(ed25519_sk: &SigningKey, msg32: &[u8; 32]) -> [u8; 64] {
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
