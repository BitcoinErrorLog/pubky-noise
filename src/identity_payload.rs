//! Identity payload for Noise protocol authentication.
//!
//! This module provides the identity binding mechanism that links Ed25519 identities
//! to Noise X25519 ephemeral keys, preventing man-in-the-middle attacks.
//!
//! ## Wire Format (PUBKY_CRYPTO_SPEC v2.5)
//!
//! The binding message uses BLAKE3 with a specific input format per spec Section 6.4.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Role in the Noise protocol handshake.
///
/// **Note**: The Noise state machine knows which side it is. The `role` field
/// exists for application-layer disambiguation when needed (e.g., logging,
/// debugging). It is not cryptographically significant.
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
/// Contains the Ed25519 identity and a signature binding it to the Noise handshake.
///
/// ## Wire Format (PUBKY_CRYPTO_SPEC v2.5 Section 6.3)
///
/// - **ed25519_pub**: The sender's Ed25519 public key (PKARR identity)
/// - **role**: Application-layer disambiguation (Client or Server). Not cryptographically significant.
/// - **server_hint**: Optional, non-normative routing metadata. May be rotated freely.
/// - **hint_expires_at**: Optional TTL scoped to server_hint only (not key validity)
/// - **sig**: Ed25519 signature over binding message (see Section 6.4)
///
/// **Removed in v2.5**: `epoch` and `noise_x25519_pub` (Noise handshake already carries static keys)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityPayload {
    /// Sender's Ed25519 public key (PKARR identity)
    pub ed25519_pub: [u8; 32],
    /// Application-layer disambiguation only. Not cryptographically significant.
    pub role: Role,
    /// Optional, non-normative routing metadata. May be rotated freely without affecting identity.
    pub server_hint: Option<String>,
    /// Optional expiration timestamp (Unix seconds) scoped to `server_hint` only.
    ///
    /// When set, the receiver should validate that the current time is before
    /// this timestamp before accepting the server_hint routing metadata.
    /// This does NOT affect key validity or session lifetime.
    ///
    /// If `None`, no expiration check is performed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint_expires_at: Option<u64>,
    /// Ed25519 signature over binding message (see make_binding_message)
    #[serde(with = "signature_serde")]
    pub sig: [u8; 64],
}

/// Parameters for constructing a binding message per PUBKY_CRYPTO_SPEC v2.5 Section 6.4.
///
/// This struct groups all the parameters needed to create a cryptographic
/// binding between an Ed25519 identity and a Noise X25519 static key.
pub struct BindingMessageParams<'a> {
    /// Ed25519 public key being bound (peerid).
    pub ed25519_pub: &'a [u8; 32],
    /// Local X25519 static public key from the Noise handshake.
    pub local_noise_pub: &'a [u8; 32],
    /// Remote X25519 static public key from the Noise handshake.
    /// Optional because in XX pattern step 2, server doesn't yet know client's static.
    pub remote_noise_pub: Option<&'a [u8; 32]>,
    /// Role in the handshake (Client or Server).
    pub role: Role,
}

/// Create a binding message hash for identity payload signing.
///
/// The binding message cryptographically links the Ed25519 identity to the
/// Noise X25519 static keys, preventing man-in-the-middle attacks.
///
/// ## Binding Message Construction (PUBKY_CRYPTO_SPEC v2.5 Section 6.4)
///
/// ```text
/// binding_message = BLAKE3(
///     "pubky-noise-binding/v1" ||
///     peerid ||                    // 32 bytes: Ed25519 public key
///     noise_static_pub ||          // 32 bytes: local X25519 static key
///     role_byte ||                 // 1 byte: 0x00=Client, 0x01=Server
///     [remote_static_pub]          // 32 bytes: peer's X25519 static key (if known)
/// )
/// ```
///
/// Note: `remote_static_pub` is optional because in XX pattern step 2, the
/// server doesn't yet know the client's static key.
///
/// # Arguments
///
/// * `params` - Parameters for the binding message.
///
/// # Returns
///
/// A 32-byte BLAKE3 hash suitable for Ed25519 signing.
pub fn make_binding_message(params: &BindingMessageParams<'_>) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"pubky-noise-binding/v1");
    h.update(params.ed25519_pub);
    h.update(params.local_noise_pub);
    h.update(&[match params.role {
        Role::Client => 0x00,
        Role::Server => 0x01,
    }]);
    if let Some(remote) = params.remote_noise_pub {
        h.update(remote);
    }
    *h.finalize().as_bytes()
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
