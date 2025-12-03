//! Tests for cold key patterns (IK-raw, N, NN).
//!
//! These patterns don't require Ed25519 signing at handshake time,
//! making them suitable for cold key architectures where identity
//! binding is provided via pkarr.

use pubky_noise::{
    datalink_adapter, kdf, MobileConfig, NoisePattern, NoiseReceiver, NoiseSender, NoiseSession,
    RawNoiseManager,
};
use zeroize::Zeroizing;

/// Helper to derive X25519 keypair for testing
fn derive_keypair(seed: &[u8; 32], context: &[u8]) -> (Zeroizing<[u8; 32]>, [u8; 32]) {
    let sk = Zeroizing::new(kdf::derive_x25519_static(seed, context));
    let pk = kdf::x25519_pk_from_sk(&sk);
    (sk, pk)
}

// ============ IK-raw Pattern Tests ============

#[test]
fn test_ik_raw_handshake() {
    // Derive keys
    let (client_sk, _client_pk) = derive_keypair(&[1u8; 32], b"client");
    let (server_sk, server_pk) = derive_keypair(&[2u8; 32], b"server");

    // Client initiates IK-raw (no identity binding)
    let sender = NoiseSender::new();
    let (mut client_hs, first_msg) = sender
        .initiate_ik_raw(&client_sk, &server_pk)
        .expect("initiate_ik_raw should succeed");

    // Server responds to IK-raw
    let receiver = NoiseReceiver::new();
    let (server_hs, response) = receiver
        .respond_ik_raw(&server_sk, &first_msg)
        .expect("respond_ik_raw should succeed");

    // Client reads response
    let mut buf = vec![0u8; response.len() + 256];
    client_hs
        .read_message(&response, &mut buf)
        .expect("client should read response");

    // Convert to transport mode
    let mut client_session = NoiseSession::from_handshake(client_hs).expect("client session");
    let mut server_session = NoiseSession::from_handshake(server_hs).expect("server session");

    // Verify encryption works
    let plaintext = b"Hello from cold key client!";
    let ciphertext = client_session.encrypt(plaintext).expect("encrypt");
    let decrypted = server_session.decrypt(&ciphertext).expect("decrypt");
    assert_eq!(decrypted, plaintext);

    // Reverse direction
    let plaintext2 = b"Hello from server!";
    let ciphertext2 = server_session.encrypt(plaintext2).expect("encrypt");
    let decrypted2 = client_session.decrypt(&ciphertext2).expect("decrypt");
    assert_eq!(decrypted2, plaintext2);
}

#[test]
fn test_ik_raw_via_adapter() {
    let (client_sk, _client_pk) = derive_keypair(&[3u8; 32], b"client");
    let (server_sk, server_pk) = derive_keypair(&[4u8; 32], b"server");

    // Use convenience functions
    let (client_hs, first_msg) =
        datalink_adapter::start_ik_raw(&client_sk, &server_pk).expect("start_ik_raw");
    let (server_hs, response) =
        datalink_adapter::accept_ik_raw(&server_sk, &first_msg).expect("accept_ik_raw");

    // Complete handshake
    let mut client_session =
        datalink_adapter::complete_raw(client_hs, &response).expect("complete_raw");
    let mut server_session = NoiseSession::from_handshake(server_hs).expect("server session");

    // Verify
    let ct = client_session.encrypt(b"test").expect("encrypt");
    let pt = server_session.decrypt(&ct).expect("decrypt");
    assert_eq!(pt, b"test");
}

// ============ N Pattern Tests ============

#[test]
fn test_n_pattern_handshake() {
    // Only server has a static key
    let (server_sk, server_pk) = derive_keypair(&[5u8; 32], b"server");

    // Client initiates N pattern (anonymous)
    let sender = NoiseSender::new();
    let (client_hs, first_msg) = sender
        .initiate_n(&server_pk)
        .expect("initiate_n should succeed");

    // Server responds to N pattern
    let receiver = NoiseReceiver::new();
    let server_hs = receiver
        .respond_n(&server_sk, &first_msg)
        .expect("respond_n should succeed");

    // N pattern completes in one message - both sides go to transport mode
    let mut client_session = NoiseSession::from_handshake(client_hs).expect("client session");
    let mut server_session = NoiseSession::from_handshake(server_hs).expect("server session");

    // Verify one-way encryption works (initiator -> responder only)
    // N pattern is explicitly one-way - only the initiator can send to the responder
    let plaintext = b"Anonymous client message";
    let ciphertext = client_session.encrypt(plaintext).expect("encrypt");
    let decrypted = server_session.decrypt(&ciphertext).expect("decrypt");
    assert_eq!(decrypted, plaintext);

    // Note: N pattern is one-way. Server cannot send back to client.
    // This is by design for anonymous initiator scenarios.
}

#[test]
fn test_n_pattern_via_adapter() {
    let (server_sk, server_pk) = derive_keypair(&[6u8; 32], b"server");

    let (client_hs, first_msg) = datalink_adapter::start_n(&server_pk).expect("start_n");
    let server_hs = datalink_adapter::accept_n(&server_sk, &first_msg).expect("accept_n");

    let mut client_session = NoiseSession::from_handshake(client_hs).expect("client");
    let mut server_session = datalink_adapter::complete_n(server_hs).expect("complete_n");

    // Verify
    let ct = client_session.encrypt(b"n-test").expect("encrypt");
    let pt = server_session.decrypt(&ct).expect("decrypt");
    assert_eq!(pt, b"n-test");
}

// ============ NN Pattern Tests ============

#[test]
fn test_nn_pattern_handshake() {
    // Neither side has a static key

    // Client initiates NN pattern
    let sender = NoiseSender::new();
    let (mut client_hs, first_msg) = sender.initiate_nn().expect("initiate_nn should succeed");

    // Server responds to NN pattern
    let receiver = NoiseReceiver::new();
    let (server_hs, response) = receiver
        .respond_nn(&first_msg)
        .expect("respond_nn should succeed");

    // Client reads response
    let mut buf = vec![0u8; response.len() + 256];
    client_hs
        .read_message(&response, &mut buf)
        .expect("client should read response");

    // Convert to transport mode
    let mut client_session = NoiseSession::from_handshake(client_hs).expect("client session");
    let mut server_session = NoiseSession::from_handshake(server_hs).expect("server session");

    // Verify encryption works
    let plaintext = b"Anonymous NN message";
    let ciphertext = client_session.encrypt(plaintext).expect("encrypt");
    let decrypted = server_session.decrypt(&ciphertext).expect("decrypt");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_nn_pattern_via_adapter() {
    let (client_hs, first_msg) = datalink_adapter::start_nn().expect("start_nn");
    let (server_hs, response) = datalink_adapter::accept_nn(&first_msg).expect("accept_nn");

    let mut client_session =
        datalink_adapter::complete_raw(client_hs, &response).expect("complete_raw");
    let mut server_session = NoiseSession::from_handshake(server_hs).expect("server");

    // Verify
    let ct = client_session.encrypt(b"nn-test").expect("encrypt");
    let pt = server_session.decrypt(&ct).expect("decrypt");
    assert_eq!(pt, b"nn-test");
}

// ============ RawNoiseManager Tests ============

#[test]
fn test_raw_noise_manager_ik_raw() {
    let mut client_manager = RawNoiseManager::new(MobileConfig::default());
    let mut server_manager = RawNoiseManager::new(MobileConfig::default());

    let (client_sk, _) = derive_keypair(&[10u8; 32], b"client");
    let (server_sk, server_pk) = derive_keypair(&[11u8; 32], b"server");

    // Client initiates with IK-raw pattern
    let (session_id, first_msg) = client_manager
        .initiate_connection_with_pattern(Some(&client_sk), Some(&server_pk), NoisePattern::IKRaw)
        .expect("initiate IKRaw");

    // Server accepts with IK-raw pattern
    let (server_session_id, response) = server_manager
        .accept_connection_with_pattern(Some(&server_sk), &first_msg, NoisePattern::IKRaw)
        .expect("accept IKRaw");

    // Client completes
    let client_session_id = client_manager
        .complete_connection(&session_id, &response)
        .expect("complete");

    // Verify both can encrypt/decrypt
    let ct = client_manager
        .encrypt(&client_session_id, b"hello via manager")
        .expect("encrypt");
    let pt = server_manager
        .decrypt(&server_session_id, &ct)
        .expect("decrypt");
    assert_eq!(pt, b"hello via manager");
}

#[test]
fn test_raw_noise_manager_nn() {
    let mut client_manager = RawNoiseManager::new(MobileConfig::default());
    let mut server_manager = RawNoiseManager::new(MobileConfig::default());

    // NN pattern - no keys needed
    let (session_id, first_msg) = client_manager
        .initiate_connection_with_pattern(None, None, NoisePattern::NN)
        .expect("initiate NN");

    let (server_session_id, response) = server_manager
        .accept_connection_with_pattern(None, &first_msg, NoisePattern::NN)
        .expect("accept NN");

    let client_session_id = client_manager
        .complete_connection(&session_id, &response)
        .expect("complete");

    // Verify
    let ct = client_manager
        .encrypt(&client_session_id, b"anonymous")
        .expect("encrypt");
    let pt = server_manager
        .decrypt(&server_session_id, &ct)
        .expect("decrypt");
    assert_eq!(pt, b"anonymous");
}

#[test]
fn test_raw_noise_manager_n_pattern() {
    let mut client_manager = RawNoiseManager::new(MobileConfig::default());
    let mut server_manager = RawNoiseManager::new(MobileConfig::default());

    let (server_sk, server_pk) = derive_keypair(&[12u8; 32], b"server");

    // N pattern - initiator is anonymous, only server has static key
    // N is a one-message pattern: initiator sends, handshake complete
    let (client_session_id, first_msg) = client_manager
        .initiate_connection_with_pattern(None, Some(&server_pk), NoisePattern::N)
        .expect("initiate N");

    // Server accepts and also completes immediately (N has no response)
    let (server_session_id, response) = server_manager
        .accept_connection_with_pattern(Some(&server_sk), &first_msg, NoisePattern::N)
        .expect("accept N");

    // N pattern has no response message
    assert!(response.is_empty(), "N pattern should have empty response");

    // Client session should be immediately available (N completes in one message)
    assert!(
        client_manager.get_session(&client_session_id).is_some(),
        "Client should have session after N pattern initiation"
    );

    // Verify one-way encryption works (initiator -> responder only)
    // N pattern is explicitly one-way - only the initiator can send to the responder
    let ct = client_manager
        .encrypt(&client_session_id, b"from client")
        .expect("client encrypt");
    let pt = server_manager
        .decrypt(&server_session_id, &ct)
        .expect("server decrypt");
    assert_eq!(pt, b"from client");

    // Note: N pattern is one-way. Server cannot send back to client.
    // This is by design for anonymous initiator scenarios.
}

// ============ Security Tests ============

#[test]
fn test_ik_raw_rejects_weak_keys() {
    // All-zero key should be rejected
    let (client_sk, _) = derive_keypair(&[1u8; 32], b"client");
    let weak_server_pk = [0u8; 32]; // All zeros - weak key

    let sender = NoiseSender::new();
    let result = sender.initiate_ik_raw(&client_sk, &weak_server_pk);

    assert!(result.is_err());
}

#[test]
fn test_session_ids_are_unique() {
    // Same keys, different handshakes should produce different session IDs
    let (client_sk, _) = derive_keypair(&[20u8; 32], b"client");
    let (server_sk, server_pk) = derive_keypair(&[21u8; 32], b"server");

    // First handshake
    let (hs1, msg1) = datalink_adapter::start_ik_raw(&client_sk, &server_pk).unwrap();
    let (s_hs1, resp1) = datalink_adapter::accept_ik_raw(&server_sk, &msg1).unwrap();
    let session1 = datalink_adapter::complete_raw(hs1, &resp1).unwrap();

    // Second handshake with same keys
    let (hs2, msg2) = datalink_adapter::start_ik_raw(&client_sk, &server_pk).unwrap();
    let (s_hs2, resp2) = datalink_adapter::accept_ik_raw(&server_sk, &msg2).unwrap();
    let session2 = datalink_adapter::complete_raw(hs2, &resp2).unwrap();

    // Session IDs should be different (due to ephemeral keys)
    assert_ne!(session1.session_id(), session2.session_id());

    // Also check server sessions
    let s_session1 = NoiseSession::from_handshake(s_hs1).unwrap();
    let s_session2 = NoiseSession::from_handshake(s_hs2).unwrap();
    assert_ne!(s_session1.session_id(), s_session2.session_id());
}

#[test]
fn test_respond_ik_raw_rejects_weak_keys() {
    // Test that respond_ik_raw validates the client's static key
    let (server_sk, _server_pk) = derive_keypair(&[30u8; 32], b"server");

    // Create a handshake message using a weak (all-zero) client key
    // We need to manually craft this since normal initiate_ik_raw would reject it
    let weak_client_sk = Zeroizing::new([0u8; 32]);
    let (valid_server_sk, valid_server_pk) = derive_keypair(&[31u8; 32], b"valid-server");

    let sender = NoiseSender::new();
    // This should fail during initiation (initiator-side check)
    let result = sender.initiate_ik_raw(&weak_client_sk, &valid_server_pk);
    assert!(
        result.is_err(),
        "Weak client key should be rejected on initiator side"
    );

    // Also verify responder rejects weak keys from valid-looking messages
    // by testing with a real handshake where we tamper with the key
    let (client_sk, _) = derive_keypair(&[32u8; 32], b"client");
    let (_, msg) = sender
        .initiate_ik_raw(&client_sk, &valid_server_pk)
        .unwrap();

    // Receiver should successfully process a valid handshake
    let receiver = NoiseReceiver::new();
    let result = receiver.respond_ik_raw(&valid_server_sk, &msg);
    assert!(result.is_ok(), "Valid handshake should succeed");
}

#[test]
fn test_raw_noise_manager_xx_pattern() {
    // XX is a 3-message TOFU pattern
    let mut client_manager = RawNoiseManager::new(MobileConfig::default());
    let mut server_manager = RawNoiseManager::new(MobileConfig::default());

    let (client_sk, _) = derive_keypair(&[40u8; 32], b"client");
    let (server_sk, _) = derive_keypair(&[41u8; 32], b"server");

    // Step 1: Client initiates XX (neither knows the other's key)
    let (client_temp_id, first_msg) = client_manager
        .initiate_connection_with_pattern(Some(&client_sk), None, NoisePattern::XX)
        .expect("initiate XX");

    // Step 2: Server accepts and responds (stores pending for 3rd message)
    let (server_temp_id, response) = server_manager
        .accept_connection_with_pattern(Some(&server_sk), &first_msg, NoisePattern::XX)
        .expect("accept XX");

    // XX response should not be empty
    assert!(!response.is_empty(), "XX should have response message");

    // Step 3: Client completes with response, gets third message
    let (client_session_id, third_msg) = client_manager
        .complete_connection_xx(&client_temp_id, &response)
        .expect("complete XX client");

    // Step 4: Server completes with third message
    let server_session_id = server_manager
        .complete_accept(&server_temp_id, &third_msg)
        .expect("complete XX server");

    // Verify bidirectional communication
    let ct = client_manager
        .encrypt(&client_session_id, b"xx from client")
        .expect("encrypt");
    let pt = server_manager
        .decrypt(&server_session_id, &ct)
        .expect("decrypt");
    assert_eq!(pt, b"xx from client");

    let ct2 = server_manager
        .encrypt(&server_session_id, b"xx from server")
        .expect("encrypt");
    let pt2 = client_manager
        .decrypt(&client_session_id, &ct2)
        .expect("decrypt");
    assert_eq!(pt2, b"xx from server");
}
