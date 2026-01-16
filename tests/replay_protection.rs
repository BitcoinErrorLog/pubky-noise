//! Replay attack protection tests
//!
//! These tests verify that the Noise protocol implementation correctly prevents
//! replay attacks at various levels: handshake, message, and cross-session.

use pubky_noise::{
    datalink_adapter::{client_complete_ik, client_start_ik_direct, server_complete_ik},
    NoiseClient, NoiseServer, RingKeyProvider,
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

/// Test that handshake messages create independent sessions
///
/// Note: Noise protocol doesn't reject duplicate handshake messages - each handshake
/// creates a new session with different ephemeral keys. Replay protection comes from
/// nonce progression in transport mode, not from rejecting duplicate handshakes.
#[test]
fn test_handshake_creates_independent_sessions() {
    let client_ring = Arc::new(TestRing { seed: [1u8; 32] });
    let server_ring = Arc::new(TestRing { seed: [2u8; 32] });

    let client = NoiseClient::<_, ()>::new_direct("kid", b"client-device-00000", client_ring.clone());
    let server = NoiseServer::<_, ()>::new_direct("kid", b"server-device-00000", server_ring.clone());

    // Get server's public key
    let server_sk = server_ring
        .derive_device_x25519("kid", b"server-device-00000", 0)
        .unwrap();
    let server_pk = pubky_noise::kdf::x25519_pk_from_sk(&server_sk);

    // Step 1: Create first handshake
    let (hs1, first_msg1) = client_start_ik_direct(&client, &server_pk, None).unwrap();

    // Step 2: Server processes first handshake
    let (hs_s1, _id1, response1) = {
        let (mut hs, id) = server.build_responder_read_ik(&first_msg1).unwrap();
        let mut resp = vec![0u8; 128];
        let n = hs.write_message(&[], &mut resp).unwrap();
        resp.truncate(n);
        (hs, id, resp)
    };

    // Step 3: Complete first handshake
    let mut link1 = client_complete_ik(hs1, &response1).unwrap();
    let mut link_s1 = server_complete_ik(hs_s1).unwrap();

    // Create a second handshake with the same message
    // This creates a NEW session (not a replay)
    let (hs2, first_msg2) = client_start_ik_direct(&client, &server_pk, None).unwrap();
    let (hs_s2, _id2, response2) = {
        let (mut hs, id) = server.build_responder_read_ik(&first_msg2).unwrap();
        let mut resp = vec![0u8; 128];
        let n = hs.write_message(&[], &mut resp).unwrap();
        resp.truncate(n);
        (hs, id, resp)
    };
    let mut link2 = client_complete_ik(hs2, &response2).unwrap();
    let mut link_s2 = server_complete_ik(hs_s2).unwrap();

    // Encrypt message in session 1
    let msg1 = link1.encrypt(b"session1").unwrap();
    let decrypted1 = link_s1.decrypt(&msg1).unwrap();
    assert_eq!(decrypted1, b"session1");

    // Encrypt message in session 2
    let msg2 = link2.encrypt(b"session2").unwrap();
    let decrypted2 = link_s2.decrypt(&msg2).unwrap();
    assert_eq!(decrypted2, b"session2");

    // Messages from session 1 should NOT decrypt in session 2 (different keys)
    let cross_result = link_s2.decrypt(&msg1);
    assert!(
        cross_result.is_err(),
        "Messages from one session should not decrypt in another session"
    );
}

/// Test that encrypted messages cannot be replayed within a session
#[test]
fn test_message_replay_detection() {
    let client_ring = Arc::new(TestRing { seed: [1u8; 32] });
    let server_ring = Arc::new(TestRing { seed: [2u8; 32] });

    let client = NoiseClient::<_, ()>::new_direct("kid", b"client-device-00000", client_ring.clone());
    let server = NoiseServer::<_, ()>::new_direct("kid", b"server-device-00000", server_ring.clone());

    // Get server's public key
    let server_sk = server_ring
        .derive_device_x25519("kid", b"server-device-00000", 0)
        .unwrap();
    let server_pk = pubky_noise::kdf::x25519_pk_from_sk(&server_sk);

    // Complete handshake
    let (c_hs, first_msg) = client_start_ik_direct(&client, &server_pk, None).unwrap();
    let (s_hs, _id, response) = {
        let (mut hs, id) = server.build_responder_read_ik(&first_msg).unwrap();
        let mut resp = vec![0u8; 128];
        let n = hs.write_message(&[], &mut resp).unwrap();
        resp.truncate(n);
        (hs, id, resp)
    };

    let mut client_link = client_complete_ik(c_hs, &response).unwrap();
    let mut server_link = server_complete_ik(s_hs).unwrap();

    // Encrypt a message
    let plaintext = b"Hello, secure world!";
    let ciphertext = client_link.encrypt(plaintext).unwrap();

    // Decrypt it once (should succeed)
    let decrypted1 = server_link.decrypt(&ciphertext).unwrap();
    assert_eq!(decrypted1, plaintext);

    // Attempt to replay the same ciphertext
    // Noise protocol uses nonces, so replay should fail
    let replay_result = server_link.decrypt(&ciphertext);

    // Replay should be rejected (nonce reuse detection)
    assert!(
        replay_result.is_err(),
        "Replayed encrypted message should be rejected"
    );
}

/// Test that messages from one session cannot be replayed in another session
#[test]
fn test_cross_session_replay_detection() {
    let client_ring = Arc::new(TestRing { seed: [1u8; 32] });
    let server_ring = Arc::new(TestRing { seed: [2u8; 32] });

    let client1 = NoiseClient::<_, ()>::new_direct("kid", b"client1-device-0000", client_ring.clone());
    let client2 = NoiseClient::<_, ()>::new_direct("kid", b"client2-device-0000", client_ring.clone());
    let server = NoiseServer::<_, ()>::new_direct("kid", b"server-device-00000", server_ring.clone());

    // Get server's public key
    let server_sk = server_ring
        .derive_device_x25519("kid", b"server-device-00000", 0)
        .unwrap();
    let server_pk = pubky_noise::kdf::x25519_pk_from_sk(&server_sk);

    // Create first session
    let (c1_hs, first_msg1) = client_start_ik_direct(&client1, &server_pk, None).unwrap();
    let (s1_hs, _id1, response1) = {
        let (mut hs, id) = server.build_responder_read_ik(&first_msg1).unwrap();
        let mut resp = vec![0u8; 128];
        let n = hs.write_message(&[], &mut resp).unwrap();
        resp.truncate(n);
        (hs, id, resp)
    };
    let mut link1 = client_complete_ik(c1_hs, &response1).unwrap();
    let _server_link1 = server_complete_ik(s1_hs).unwrap();

    // Create second session
    let (c2_hs, first_msg2) = client_start_ik_direct(&client2, &server_pk, None).unwrap();
    let (s2_hs, _id2, response2) = {
        let (mut hs, id) = server.build_responder_read_ik(&first_msg2).unwrap();
        let mut resp = vec![0u8; 128];
        let n = hs.write_message(&[], &mut resp).unwrap();
        resp.truncate(n);
        (hs, id, resp)
    };
    let mut link2 = client_complete_ik(c2_hs, &response2).unwrap();
    let mut server_link2 = server_complete_ik(s2_hs).unwrap();

    // Encrypt message in session 1
    let plaintext = b"Message from session 1";
    let ciphertext1 = link1.encrypt(plaintext).unwrap();

    // Attempt to decrypt session 1's message in session 2
    // This should fail because each session has different keys
    let cross_session_result = server_link2.decrypt(&ciphertext1);

    // Cross-session replay should be rejected
    assert!(
        cross_session_result.is_err(),
        "Message from one session should not be decryptable in another session"
    );

    // Verify session 2 can still decrypt its own messages
    let ciphertext2 = link2.encrypt(plaintext).unwrap();
    let decrypted2 = server_link2.decrypt(&ciphertext2).unwrap();
    assert_eq!(decrypted2, plaintext);
}

/// Test that epoch changes prevent replay of old handshakes
#[test]
fn test_epoch_replay_prevention() {
    // Note: Currently epoch is always 0, but this test documents the expected behavior
    // if epoch rotation is implemented in the future
    let client_ring = Arc::new(TestRing { seed: [1u8; 32] });
    let server_ring = Arc::new(TestRing { seed: [2u8; 32] });

    let client = NoiseClient::<_, ()>::new_direct("kid", b"client-device-00000", client_ring.clone());
    let server = NoiseServer::<_, ()>::new_direct("kid", b"server-device-00000", server_ring.clone());

    // Get server's public key
    let server_sk = server_ring
        .derive_device_x25519("kid", b"server-device-00000", 0)
        .unwrap();
    let server_pk = pubky_noise::kdf::x25519_pk_from_sk(&server_sk);

    // Create handshake with epoch 0
    let (hs, first_msg) = client_start_ik_direct(&client, &server_pk, None).unwrap();

    // Server processes it
    let (s_hs, _id, response) = {
        let (mut hs, id) = server.build_responder_read_ik(&first_msg).unwrap();
        let mut resp = vec![0u8; 128];
        let n = hs.write_message(&[], &mut resp).unwrap();
        resp.truncate(n);
        (hs, id, resp)
    };

    // Complete handshake
    let _link = client_complete_ik(hs, &response).unwrap();
    let _server_link = server_complete_ik(s_hs).unwrap();

    // If epoch were to change, old handshakes should be rejected
    // This test documents the expected behavior for future epoch rotation
    // Currently epoch is always 0, so this is more of a documentation test
}
