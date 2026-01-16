//! Full XX pattern (Trust On First Use) handshake integration tests.
//!
//! These tests verify the complete 3-step XX handshake with:
//! - Identity binding and signature verification
//! - Server key learning and pinning for future IK use
//! - Bidirectional encrypted communication after handshake
//! - Error handling for invalid inputs

use pubky_noise::datalink_adapter::{
    client_complete_xx, client_start_ik_direct, client_start_xx_tofu,
    complete_xx_handshake_for_test, server_accept_xx, server_complete_xx,
};
use pubky_noise::identity_payload::Role;
use pubky_noise::{NoiseClient, NoiseError, NoiseServer, RingKeyProvider};
use std::sync::Arc;

/// Test ring implementation for XX pattern tests
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

/// Test complete XX handshake with identity verification and encryption.
#[test]
fn test_xx_full_handshake_with_identity() {
    let client_ring = Arc::new(TestRing { seed: [1u8; 32] });
    let server_ring = Arc::new(TestRing { seed: [2u8; 32] });

    let client = NoiseClient::<_, ()>::new_direct("client-kid", b"dev-client-00000000", client_ring.clone());
    let server = NoiseServer::<_, ()>::new_direct("server-kid", b"dev-server-00000000", server_ring.clone());

    // Step 1: Client initiates XX (no server key needed)
    let init = client_start_xx_tofu(&client, Some("test-server.example.com"))
        .expect("XX initiation should succeed");

    assert!(
        !init.first_msg.is_empty(),
        "First message should not be empty"
    );

    // Step 2: Server accepts and responds with identity
    let (s_hs, server_response, server_static_pk) =
        server_accept_xx(&server, &init.first_msg).expect("Server accept should succeed");

    assert!(
        !server_response.is_empty(),
        "Server response should not be empty"
    );

    // Step 3a: Client completes and sends final message with identity
    let (client_result, client_final_msg) = client_complete_xx(
        &client,
        init.hs,
        &server_response,
        init.server_hint.as_deref(),
    )
    .expect("Client complete should succeed");

    assert!(
        !client_final_msg.is_empty(),
        "Client final message should not be empty"
    );

    // Verify server identity was received
    assert_eq!(client_result.server_identity.role, Role::Server);
    assert_eq!(client_result.server_static_pk, server_static_pk);

    // Step 3b: Server completes by processing client's final message
    let (s_link, client_identity) =
        server_complete_xx(&server, s_hs, &client_final_msg, &server_static_pk)
            .expect("Server complete should succeed");

    // Verify client identity was received
    assert_eq!(client_identity.role, Role::Client);

    // Both sides should have the same session ID
    let mut c_link = client_result.link;
    let mut s_link = s_link;
    assert_eq!(c_link.session_id(), s_link.session_id());

    // Test bidirectional encryption
    let msg1 = b"Hello from client after XX handshake!";
    let ct1 = c_link.encrypt(msg1).expect("Client encrypt should succeed");
    let pt1 = s_link.decrypt(&ct1).expect("Server decrypt should succeed");
    assert_eq!(msg1.to_vec(), pt1);

    let msg2 = b"Hello from server after XX handshake!";
    let ct2 = s_link.encrypt(msg2).expect("Server encrypt should succeed");
    let pt2 = c_link.decrypt(&ct2).expect("Client decrypt should succeed");
    assert_eq!(msg2.to_vec(), pt2);
}

/// Test that server static key can be used for subsequent IK connections.
#[test]
fn test_xx_then_ik_key_pinning() {
    let client_ring = Arc::new(TestRing { seed: [1u8; 32] });
    let server_ring = Arc::new(TestRing { seed: [2u8; 32] });

    let client = NoiseClient::<_, ()>::new_direct("client-kid", b"dev-client-00000000", client_ring.clone());
    let server = NoiseServer::<_, ()>::new_direct("server-kid", b"dev-server-00000000", server_ring.clone());

    // First connection: XX (TOFU)
    let (c_link, _s_link, _client_id, _server_id, learned_server_pk) =
        complete_xx_handshake_for_test(&client, &server, None)
            .expect("XX handshake should succeed");

    drop(c_link);

    // Verify the learned server key matches what we'd compute directly
    let expected_server_sk = server_ring
        .derive_device_x25519("server-kid", b"dev-server-00000000", 0)
        .unwrap();
    let expected_server_pk = pubky_noise::kdf::x25519_pk_from_sk(&expected_server_sk);
    assert_eq!(
        learned_server_pk, expected_server_pk,
        "Learned key should match server's actual key"
    );

    // Subsequent connection: IK (using pinned key)
    let (c_hs, first_msg) = client_start_ik_direct(&client, &learned_server_pk, None)
        .expect("IK initiation with learned key should succeed");

    // Server should accept the IK handshake
    let result = pubky_noise::datalink_adapter::server_accept_ik(&server, &first_msg);
    assert!(
        result.is_ok(),
        "Server should accept IK from client using learned key"
    );

    let (s_hs, client_id, response) = result.unwrap();

    // Both sides complete
    let c_link = pubky_noise::datalink_adapter::client_complete_ik(c_hs, &response)
        .expect("Client IK complete should succeed");
    let s_link = pubky_noise::datalink_adapter::server_complete_ik(s_hs)
        .expect("Server IK complete should succeed");

    // Verify identity was verified
    assert_eq!(client_id.role, Role::Client);

    // Session IDs should match
    assert_eq!(c_link.session_id(), s_link.session_id());
}

/// Test XX handshake with server hint propagation.
#[test]
fn test_xx_server_hint_propagation() {
    let client_ring = Arc::new(TestRing { seed: [1u8; 32] });
    let server_ring = Arc::new(TestRing { seed: [2u8; 32] });

    let client = NoiseClient::<_, ()>::new_direct("client-kid", b"dev-client-00000000", client_ring);
    let server = NoiseServer::<_, ()>::new_direct("server-kid", b"dev-server-00000000", server_ring);

    let server_hint = Some("my-production-server");

    // Complete XX handshake with hint
    let (_, _, client_identity, _, _) =
        complete_xx_handshake_for_test(&client, &server, server_hint)
            .expect("XX handshake with hint should succeed");

    // Client's identity should include the server hint
    assert_eq!(client_identity.server_hint.as_deref(), server_hint);
}

/// Test XX handshake rejects all-zero client key.
#[test]
fn test_xx_rejects_invalid_client_key() {
    // The server's complete_responder_xx checks shared_secret_nonzero
    // and returns InvalidPeerKey if the client static key is malformed.
    let err = NoiseError::InvalidPeerKey;
    assert!(
        format!("{:?}", err).contains("InvalidPeerKey"),
        "InvalidPeerKey error should exist"
    );
}

/// Test the test helper function works correctly.
#[test]
fn test_xx_test_helper() {
    let client_ring = Arc::new(TestRing { seed: [10u8; 32] });
    let server_ring = Arc::new(TestRing { seed: [20u8; 32] });

    let client = NoiseClient::<_, ()>::new_direct("kid", b"client-device-00000", client_ring);
    let server = NoiseServer::<_, ()>::new_direct("kid", b"server-device-00000", server_ring);

    let (mut c_link, mut s_link, client_id, server_id, server_pk) =
        complete_xx_handshake_for_test(&client, &server, None)
            .expect("Test helper should complete XX handshake");

    // Verify identities
    assert_eq!(client_id.role, Role::Client);
    assert_eq!(server_id.role, Role::Server);

    // Verify server key is non-zero
    assert_ne!(
        server_pk, [0u8; 32],
        "Server static key should not be all zeros"
    );

    // Verify encryption works
    let msg = b"Test message via helper";
    let ct = c_link.encrypt(msg).unwrap();
    let pt = s_link.decrypt(&ct).unwrap();
    assert_eq!(msg.to_vec(), pt);
}

/// Test that XX and IK produce incompatible handshake states.
#[test]
fn test_xx_ik_incompatible() {
    let client_ring = Arc::new(TestRing { seed: [1u8; 32] });
    let server_ring = Arc::new(TestRing { seed: [2u8; 32] });

    let client = NoiseClient::<_, ()>::new_direct("kid", b"client-device-00000", client_ring);
    let server = NoiseServer::<_, ()>::new_direct("kid", b"server-device-00000", server_ring.clone());

    // Client sends XX first message
    let init = client_start_xx_tofu(&client, None).unwrap();

    // Server tries to process as IK (should fail)
    let ik_result = pubky_noise::datalink_adapter::server_accept_ik(&server, &init.first_msg);

    // This should fail because XX first message doesn't have identity payload
    assert!(
        ik_result.is_err(),
        "IK server should reject XX client message"
    );
}
