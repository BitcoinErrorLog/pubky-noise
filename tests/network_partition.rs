//! Network partition simulation tests
//!
//! These tests simulate network partitions and verify that the protocol
//! handles connection failures gracefully.

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

/// Simulate network partition during handshake
///
/// This test verifies that partial handshakes don't leave the system
/// in an inconsistent state.
#[test]
fn test_partition_during_handshake() {
    let client_ring = Arc::new(TestRing { seed: [1u8; 32] });
    let server_ring = Arc::new(TestRing { seed: [2u8; 32] });

    let client = NoiseClient::<_, ()>::new_direct("kid", b"client-device-00000", client_ring.clone());
    let _server = NoiseServer::<_, ()>::new_direct("kid", b"server-device-00000", server_ring.clone());

    // Get server's public key
    let server_sk = server_ring
        .derive_device_x25519("kid", b"server-device-00000", 0)
        .unwrap();
    let server_pk = pubky_noise::kdf::x25519_pk_from_sk(&server_sk);

    // Step 1: Client initiates handshake
    let (hs, first_msg) = client_start_ik_direct(&client, &server_pk, None).unwrap();

    // Simulate network partition: message is sent but response never arrives
    // Client's handshake state is left incomplete

    // After partition heals, client can retry with a new handshake
    let (new_hs, new_first_msg) = client_start_ik_direct(&client, &server_pk, None).unwrap();

    // New handshake should be independent (different ephemeral keys)
    assert_ne!(
        first_msg, new_first_msg,
        "New handshake after partition should use different ephemeral keys"
    );

    // Old handshake state can be discarded
    drop(hs);
    drop(new_hs);
}

/// Simulate network partition during message exchange
#[test]
fn test_partition_during_message_exchange() {
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

    // Exchange some messages
    let msg1 = client_link.encrypt(b"message1").unwrap();
    let _decrypted1 = server_link.decrypt(&msg1).unwrap();

    // Simulate network partition: connection drops
    // Both sides still have their link state

    // After partition heals, need to establish new session
    // Old session cannot be resumed (Noise doesn't support session resumption)
    let (new_c_hs, new_first_msg) = client_start_ik_direct(&client, &server_pk, None).unwrap();
    let (new_s_hs, _new_id, new_response) = {
        let (mut hs, id) = server.build_responder_read_ik(&new_first_msg).unwrap();
        let mut resp = vec![0u8; 128];
        let n = hs.write_message(&[], &mut resp).unwrap();
        resp.truncate(n);
        (hs, id, resp)
    };

    let mut new_client_link = client_complete_ik(new_c_hs, &new_response).unwrap();
    let mut new_server_link = server_complete_ik(new_s_hs).unwrap();

    // New session should work independently
    let new_msg = new_client_link.encrypt(b"message after partition").unwrap();
    let new_decrypted = new_server_link.decrypt(&new_msg).unwrap();
    assert_eq!(new_decrypted, b"message after partition");

    // Old session's messages should not work with new session
    let old_msg_result = new_server_link.decrypt(&msg1);
    assert!(
        old_msg_result.is_err(),
        "Messages from old session should not decrypt in new session"
    );
}

/// Test that multiple partition/reconnect cycles work correctly
#[test]
fn test_multiple_partition_cycles() {
    let client_ring = Arc::new(TestRing { seed: [1u8; 32] });
    let server_ring = Arc::new(TestRing { seed: [2u8; 32] });

    let client = NoiseClient::<_, ()>::new_direct("kid", b"client-device-00000", client_ring.clone());
    let server = NoiseServer::<_, ()>::new_direct("kid", b"server-device-00000", server_ring.clone());

    // Get server's public key
    let server_sk = server_ring
        .derive_device_x25519("kid", b"server-device-00000", 0)
        .unwrap();
    let server_pk = pubky_noise::kdf::x25519_pk_from_sk(&server_sk);

    // Simulate multiple partition/reconnect cycles
    for cycle in 0..3 {
        // Establish new session
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

        // Exchange message
        let msg = format!("cycle {}", cycle);
        let ciphertext = client_link.encrypt(msg.as_bytes()).unwrap();
        let decrypted = server_link.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, msg.as_bytes());

        // Partition occurs (simulated by dropping the links)
        // Next iteration will create a new session
    }
}
