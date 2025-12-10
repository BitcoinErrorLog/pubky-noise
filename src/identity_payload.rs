//! Identity payload for Noise protocol authentication.
//!
//! This module provides the identity binding mechanism that links Ed25519 identities
//! to Noise X25519 ephemeral keys, preventing man-in-the-middle attacks.

use blake2::{Blake2s256, Digest};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Role in the Noise protocol handshake.
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

/// Identity payload transmitted during Noise handshake.
///
/// Contains the Ed25519 identity, the X25519 ephemeral key used in the handshake,
/// and a signature binding them together.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityPayload {
    pub ed25519_pub: [u8; 32],
    pub noise_x25519_pub: [u8; 32],
    /// Internal epoch field (always 0, kept for wire format compatibility).
    pub epoch: u32,
    pub role: Role,
    pub server_hint: Option<String>,
    #[serde(with = "signature_serde")]
    pub sig: [u8; 64],
}

/// Parameters for constructing a binding message.
///
/// This struct groups all the parameters needed to create a cryptographic
/// binding between an Ed25519 identity and a Noise X25519 ephemeral key.
pub struct BindingMessageParams<'a> {
    /// Pattern identifier (e.g., "IK" or "XX").
    pub pattern_tag: &'a str,
    /// Protocol prologue bytes.
    pub prologue: &'a [u8],
    /// Ed25519 public key being bound.
    pub ed25519_pub: &'a [u8; 32],
    /// Local X25519 public key.
    pub local_noise_pub: &'a [u8; 32],
    /// Remote X25519 public key (if known).
    pub remote_noise_pub: Option<&'a [u8; 32]>,
    /// Role in the handshake.
    pub role: Role,
    /// Optional server hint for routing.
    pub server_hint: Option<&'a str>,
}

/// Create a binding message hash for identity payload signing.
///
/// The binding message cryptographically links the Ed25519 identity to the
/// Noise X25519 ephemeral keys, preventing man-in-the-middle attacks.
///
/// # Arguments
///
/// * `params` - Parameters for the binding message.
///
/// # Returns
///
/// A 32-byte BLAKE2s hash suitable for Ed25519 signing.
pub fn make_binding_message(params: &BindingMessageParams<'_>) -> [u8; 32] {
    // Internal epoch value - always 0 (kept for wire format compatibility)
    const INTERNAL_EPOCH: u32 = 0;

    let mut h = Blake2s256::new();
    h.update(b"pubky-noise-bind:v1");
    h.update(params.pattern_tag.as_bytes());
    h.update(params.prologue);
    h.update(params.ed25519_pub);
    h.update(params.local_noise_pub);
    if let Some(r) = params.remote_noise_pub {
        h.update(r);
    }
    h.update(INTERNAL_EPOCH.to_le_bytes());
    h.update(match params.role {
        Role::Client => b"client",
        Role::Server => b"server",
    });
    if let Some(hint) = params.server_hint {
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
