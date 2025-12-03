//! Identity payload for binding Ed25519 identities to X25519 Noise sessions.
//!
//! This module provides the `IdentityPayload` structure and binding message functions
//! used to cryptographically bind a long-term Ed25519 identity to ephemeral X25519
//! session keys during Noise Protocol handshakes.

use blake2::{Blake2s256, Digest};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Role in the Noise handshake.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Role {
    /// Client/initiator role
    Client,
    /// Server/responder role
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

/// Identity payload transmitted during Noise handshakes.
///
/// Binds a long-term Ed25519 identity to the ephemeral X25519 session key,
/// preventing identity substitution attacks.
///
/// # Fields
///
/// - `ed25519_pub`: The sender's long-term Ed25519 public key (32 bytes)
/// - `noise_x25519_pub`: The sender's X25519 key for this session (32 bytes)
/// - `role`: Whether sender is Client or Server
/// - `sig`: Ed25519 signature over the binding message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityPayload {
    /// Long-term Ed25519 public key
    pub ed25519_pub: [u8; 32],
    /// X25519 session key (derived from Ed25519 seed via HKDF)
    pub noise_x25519_pub: [u8; 32],
    /// Handshake role
    pub role: Role,
    /// Ed25519 signature over binding message
    #[serde(with = "signature_serde")]
    pub sig: [u8; 64],
}

/// Create a binding message hash for identity binding.
///
/// The binding message is a BLAKE2s hash of:
/// - Domain separator: `"pubky-noise-bind:v2"` (v2 removes epoch)
/// - Pattern tag (e.g., "IK", "XX")
/// - Prologue
/// - Ed25519 public key
/// - Local X25519 public key
/// - Remote X25519 public key (if known)
/// - Role ("client" or "server")
///
/// This hash is signed by the Ed25519 key to prove ownership and bind
/// the long-term identity to the session keys.
pub fn make_binding_message(
    pattern_tag: &str,
    prologue: &[u8],
    ed25519_pub: &[u8; 32],
    local_noise_pub: &[u8; 32],
    remote_noise_pub: Option<&[u8; 32]>,
    role: Role,
) -> [u8; 32] {
    let mut h = Blake2s256::new();
    h.update(b"pubky-noise-bind:v2"); // v2: epoch removed
    h.update(pattern_tag.as_bytes());
    h.update(prologue);
    h.update(ed25519_pub);
    h.update(local_noise_pub);
    if let Some(r) = remote_noise_pub {
        h.update(r);
    }
    h.update(match role {
        Role::Client => b"client",
        Role::Server => b"server",
    });
    let out = h.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&out[..32]);
    digest
}

/// Sign a binding message with an Ed25519 signing key.
pub fn sign_identity_payload(ed25519_sk: &SigningKey, msg32: &[u8; 32]) -> [u8; 64] {
    let sig: Signature = ed25519_sk.sign(msg32);
    sig.to_bytes()
}

/// Verify a binding message signature.
///
/// Returns `true` if the signature is valid for the given message and public key.
pub fn verify_identity_payload(
    ed25519_pub: &VerifyingKey,
    msg32: &[u8; 32],
    sig64: &[u8; 64],
) -> bool {
    let sig = Signature::from_bytes(sig64);
    ed25519_pub.verify(msg32, &sig).is_ok()
}
