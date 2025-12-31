//! Tests for NN pattern (ephemeral-only, NO AUTHENTICATION).
//!
//! # Security Warning
//!
//! The NN pattern provides **forward secrecy only** with NO identity binding.
//! An active attacker can trivially MITM this connection.
//!
//! These tests exist to verify the implementation works correctly, NOT to
//! encourage use of NN pattern. For authenticated connections, use IK or XX.

use pubky_noise::datalink_adapter::{
    client_complete_nn, client_start_nn, complete_nn_handshake_for_test, server_accept_nn,
    server_complete_nn,
};
use pubky_noise::{NoiseClient, NoiseError, NoiseServer, RingKeyProvider};
use std::sync::Arc;

/// Test ring implementation
struct TestRing {
    seed: [u8; 32],
}

impl RingKeyProvider for TestRing {
    fn derive_device_x25519(
        &self,
        _kid: &str,
        device_id: &[u8],
        epoch: u32,
    ) -> Result<[u8; 32], NoiseError> {
        pubky_noise::kdf::derive_x25519_for_device_epoch(&self.seed, device_id, epoch)
    }

    fn ed25519_pubkey(&self, _kid: &str) -> Result<[u8; 32], NoiseError> {
        use ed25519_dalek::SigningKey;
        let signing_key = SigningKey::from_bytes(&self.seed);
        Ok(signing_key.verifying_key().to_bytes())
    }

    fn sign_ed25519(&self, _kid: &str, msg: &[u8]) -> Result<[u8; 64], NoiseError> {
        use ed25519_dalek::{Signer, SigningKey};
        let signing_key = SigningKey::from_bytes(&self.seed);
        Ok(signing_key.sign(msg).to_bytes())
    }
}

/// Test complete NN handshake with encryption.
///
/// WARNING: NN provides NO authentication! This test is for implementation
/// verification only. Do NOT use NN pattern unless you have external
/// authentication (e.g., TLS with pinned certificates).
#[test]
fn test_nn_full_handshake() {
    let client_ring = Arc::new(TestRing { seed: [1u8; 32] });
    let server_ring = Arc::new(TestRing { seed: [2u8; 32] });

    let client = NoiseClient::<_, ()>::new_direct("kid", b"client", client_ring);
    let server = NoiseServer::<_, ()>::new_direct("kid", b"server", server_ring);

    // Step 1: Client initiates (ephemeral only)
    let (c_hs, first_msg) = client_start_nn(&client).expect("NN init should succeed");

    assert!(!first_msg.is_empty(), "First message should not be empty");

    // Step 2: Server accepts and responds (ephemeral + ee)
    let (s_hs, response) =
        server_accept_nn(&server, &first_msg).expect("Server accept should succeed");

    assert!(!response.is_empty(), "Server response should not be empty");

    // Step 3: Both complete
    let mut c_link =
        client_complete_nn(&client, c_hs, &response).expect("Client complete should succeed");
    let mut s_link = server_complete_nn(s_hs).expect("Server complete should succeed");

    // Session IDs should match
    assert_eq!(c_link.session_id(), s_link.session_id());

    // Test bidirectional encryption
    let msg1 = b"Hello from client (UNAUTHENTICATED!)";
    let ct1 = c_link.encrypt(msg1).expect("Encrypt should succeed");
    let pt1 = s_link.decrypt(&ct1).expect("Decrypt should succeed");
    assert_eq!(msg1.to_vec(), pt1);

    let msg2 = b"Hello from server (UNAUTHENTICATED!)";
    let ct2 = s_link.encrypt(msg2).expect("Encrypt should succeed");
    let pt2 = c_link.decrypt(&ct2).expect("Decrypt should succeed");
    assert_eq!(msg2.to_vec(), pt2);
}

/// Test test helper function.
#[test]
fn test_nn_test_helper() {
    let client_ring = Arc::new(TestRing { seed: [10u8; 32] });
    let server_ring = Arc::new(TestRing { seed: [20u8; 32] });

    let client = NoiseClient::<_, ()>::new_direct("kid", b"client", client_ring);
    let server = NoiseServer::<_, ()>::new_direct("kid", b"server", server_ring);

    let (mut c_link, mut s_link) =
        complete_nn_handshake_for_test(&client, &server).expect("Helper should work");

    // Verify encryption works
    let msg = b"Test via helper";
    let ct = c_link.encrypt(msg).unwrap();
    let pt = s_link.decrypt(&ct).unwrap();
    assert_eq!(msg.to_vec(), pt);
}

/// Test that NN messages are incompatible with IK pattern.
#[test]
fn test_nn_ik_incompatible() {
    let client_ring = Arc::new(TestRing { seed: [1u8; 32] });
    let server_ring = Arc::new(TestRing { seed: [2u8; 32] });

    let client = NoiseClient::<_, ()>::new_direct("kid", b"client", client_ring);
    let server = NoiseServer::<_, ()>::new_direct("kid", b"server", server_ring);

    // Client sends NN first message
    let (_, first_msg) = client_start_nn(&client).unwrap();

    // Server tries to process as IK (should fail)
    let ik_result = pubky_noise::datalink_adapter::server_accept_ik(&server, &first_msg);

    // Should fail because NN message doesn't have identity payload
    assert!(
        ik_result.is_err(),
        "IK server should reject NN client message"
    );
}

/// Verify that NoiseError types are available for NN error handling.
#[test]
fn test_nn_error_types_available() {
    // NN doesn't have identity-specific errors, but general Noise errors apply
    let snow_err = NoiseError::Snow("test".into());
    assert!(format!("{:?}", snow_err).contains("Snow"));

    let policy_err = NoiseError::Policy("message too large".into());
    assert!(format!("{:?}", policy_err).contains("Policy"));
}

/// Document that NN has NO identity verification (this is a "test" that documents behavior).
#[test]
fn test_nn_no_identity_verification() {
    // This test documents that NN provides NO identity guarantees.
    //
    // Unlike IK and XX patterns which include identity payloads with:
    // - Ed25519 public key
    // - Noise X25519 public key
    // - Ed25519 signature binding the two
    //
    // NN pattern exchanges ONLY ephemeral keys. There is:
    // - No static key exchange
    // - No identity payload
    // - No signature verification
    //
    // An active MITM can:
    // 1. Intercept client's ephemeral key
    // 2. Complete handshake with client using their own ephemeral
    // 3. Complete separate handshake with server using their own ephemeral
    // 4. Decrypt all traffic from client, re-encrypt for server (and vice versa)
    //
    // NN is ONLY safe when:
    // - Transport layer provides authentication (e.g., TLS with pinned certs)
    // - Higher-level protocol provides authentication after Noise handshake
    // - MITM attacks are explicitly accepted as a risk

    // This test passes to document this behavior.
}
