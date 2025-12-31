//! Tests for XX pattern (Trust On First Use) handshake
//!
//! The XX pattern is used for first contact when the server's static key
//! is not known in advance. The client learns the server's key during
//! the handshake and should pin it for future use (IK pattern).

use pubky_noise::{
    datalink_adapter::client_start_ik_direct, NoiseClient, NoiseServer, RingKeyProvider,
};
use std::sync::Arc;

struct TestRing {
    seed: [u8; 32],
}

impl RingKeyProvider for TestRing {
    fn derive_device_x25519(
        &self,
        _kid: &str,
        device_id: &[u8],
        epoch: u32,
    ) -> Result<[u8; 32], pubky_noise::NoiseError> {
        pubky_noise::kdf::derive_x25519_for_device_epoch(&self.seed, device_id, epoch)
    }

    fn ed25519_pubkey(&self, _kid: &str) -> Result<[u8; 32], pubky_noise::NoiseError> {
        use ed25519_dalek::SigningKey;
        let signing_key = SigningKey::from_bytes(&self.seed);
        Ok(signing_key.verifying_key().to_bytes())
    }

    fn sign_ed25519(&self, _kid: &str, msg: &[u8]) -> Result<[u8; 64], pubky_noise::NoiseError> {
        use ed25519_dalek::{Signer, SigningKey};
        let signing_key = SigningKey::from_bytes(&self.seed);
        Ok(signing_key.sign(msg).to_bytes())
    }
}

/// Test XX pattern handshake (first contact, no server key known)
#[test]
fn test_xx_pattern_first_contact() {
    let client_ring = Arc::new(TestRing { seed: [1u8; 32] });
    let server_ring = Arc::new(TestRing { seed: [2u8; 32] });

    let client = NoiseClient::<_, ()>::new_direct("kid", b"client", client_ring);
    let _server = NoiseServer::<_, ()>::new_direct("kid", b"server", server_ring);

    // XX pattern: Client initiates without knowing server's static key
    let (hs, first_msg, _hint) = client.build_initiator_xx_tofu(None).unwrap();

    assert!(
        !first_msg.is_empty(),
        "XX pattern first message should not be empty"
    );

    drop(hs);
}

/// Test that XX and IK patterns produce different handshake messages
#[test]
fn test_xx_vs_ik_different_messages() {
    let client_ring = Arc::new(TestRing { seed: [1u8; 32] });
    let server_ring = Arc::new(TestRing { seed: [2u8; 32] });

    let client = NoiseClient::<_, ()>::new_direct("kid", b"client", client_ring.clone());
    let server_ring_clone = server_ring.clone();

    // XX pattern: No server key needed
    let (_, xx_msg, _) = client.build_initiator_xx_tofu(None).unwrap();

    // IK pattern: Requires server key
    let server_sk = server_ring_clone
        .derive_device_x25519("kid", b"server", 0)
        .unwrap();
    let server_pk = pubky_noise::kdf::x25519_pk_from_sk(&server_sk);
    let (_, ik_msg) = client_start_ik_direct(&client, &server_pk, None).unwrap();

    assert_ne!(
        xx_msg, ik_msg,
        "XX and IK patterns should produce different handshake messages"
    );
}

/// Test XX pattern use case: first contact scenario
#[test]
fn test_xx_pattern_first_contact_scenario() {
    let client_ring = Arc::new(TestRing { seed: [1u8; 32] });
    let server_ring = Arc::new(TestRing { seed: [2u8; 32] });

    let client = NoiseClient::<_, ()>::new_direct("kid", b"client", client_ring);
    let _server = NoiseServer::<_, ()>::new_direct("kid", b"server", server_ring);

    let (hs, first_msg, _hint) = client.build_initiator_xx_tofu(None).unwrap();

    assert!(!first_msg.is_empty());
    drop(hs);
}
