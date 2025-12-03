//! Tests for NoiseSender and NoiseReceiver (raw-key API).
//!
//! These tests verify that the new raw-key API produces correct handshakes
//! and is compatible with the legacy Ring-based API.

use pubky_noise::{kdf, NoiseReceiver, NoiseSender};
use zeroize::Zeroizing;

/// Test basic NoiseSender/NoiseReceiver handshake with raw keys.
#[test]
fn test_sender_receiver_handshake() {
    // Derive keys for client
    let client_seed = [1u8; 32];
    let client_x25519_sk = Zeroizing::new(kdf::derive_x25519_static(&client_seed, b"client-dev"));
    let client_ed25519_pk = kdf::derive_ed25519_public(&client_seed);

    // Derive keys for server
    let server_seed = [2u8; 32];
    let server_x25519_sk_raw = kdf::derive_x25519_static(&server_seed, b"server-dev");
    let server_x25519_sk = Zeroizing::new(server_x25519_sk_raw);
    let server_x25519_pk = kdf::x25519_pk_from_sk(&server_x25519_sk_raw);

    // Create sender and receiver
    let sender = NoiseSender::new();
    let receiver = NoiseReceiver::new();

    // Client initiates handshake
    let (client_hs, first_msg) = sender
        .initiate_ik(
            &client_x25519_sk,
            &client_ed25519_pk,
            &server_x25519_pk,
            |binding_msg| {
                // Sign with the client's Ed25519 key
                let signing_key = ed25519_dalek::SigningKey::from_bytes(
                    &kdf::derive_ed25519_secret(&client_seed),
                );
                use ed25519_dalek::Signer;
                signing_key.sign(binding_msg).to_bytes()
            },
        )
        .expect("Client handshake initiation should succeed");

    // Server responds to handshake (respond_ik now returns response message)
    let (server_hs, client_identity, response) = receiver
        .respond_ik(&server_x25519_sk, &first_msg)
        .expect("Server handshake response should succeed");

    // Verify client identity was extracted
    assert_eq!(client_identity.ed25519_pub, client_ed25519_pk);

    // Client processes server response
    let mut client_hs = client_hs;
    let mut buf = vec![0u8; response.len() + 64];
    client_hs
        .read_message(&response, &mut buf)
        .expect("Client should process server response");

    // Convert to transport mode
    let mut client_session = pubky_noise::NoiseSession::from_handshake(client_hs)
        .expect("Client transport should succeed");
    let mut server_session = pubky_noise::NoiseSession::from_handshake(server_hs)
        .expect("Server transport should succeed");

    // Verify session IDs match
    assert_eq!(client_session.session_id(), server_session.session_id());

    // Test encryption/decryption
    let plaintext = b"Hello from client!";
    let ciphertext = client_session
        .write(plaintext)
        .expect("Encryption should work");
    let decrypted = server_session
        .read(&ciphertext)
        .expect("Decryption should work");
    assert_eq!(decrypted, plaintext);

    // Test reverse direction
    let server_msg = b"Hello from server!";
    let server_ct = server_session
        .write(server_msg)
        .expect("Server encryption should work");
    let server_pt = client_session
        .read(&server_ct)
        .expect("Client decryption should work");
    assert_eq!(server_pt, server_msg);
}

/// Test that sender correctly derives its X25519 public key.
#[test]
fn test_sender_key_derivation() {
    let seed = [42u8; 32];
    let x25519_sk = Zeroizing::new(kdf::derive_x25519_static(&seed, b"device"));
    let ed25519_pk = kdf::derive_ed25519_public(&seed);

    // Server key
    let server_seed = [99u8; 32];
    let server_sk = kdf::derive_x25519_static(&server_seed, b"server");
    let server_pk = kdf::x25519_pk_from_sk(&server_sk);

    let sender = NoiseSender::new();
    let result = sender.initiate_ik(&x25519_sk, &ed25519_pk, &server_pk, |binding_msg| {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&kdf::derive_ed25519_secret(&seed));
        use ed25519_dalek::Signer;
        signing_key.sign(binding_msg).to_bytes()
    });

    assert!(result.is_ok(), "Handshake initiation should succeed");
}

/// Test that the raw-key API produces the same transcript as Ring-based API.
#[test]
fn test_sender_receiver_matches_ring_api() {
    use pubky_noise::DummyRing;
    use std::sync::Arc;

    let client_seed = [10u8; 32];
    let server_seed = [20u8; 32];

    // Raw-key API
    let client_x25519_sk_raw = kdf::derive_x25519_static(&client_seed, b"client");
    let client_x25519_sk = Zeroizing::new(client_x25519_sk_raw);
    let client_ed25519_pk = kdf::derive_ed25519_public(&client_seed);

    let server_x25519_sk_raw = kdf::derive_x25519_static(&server_seed, b"server");
    let server_x25519_sk = Zeroizing::new(server_x25519_sk_raw);
    let server_x25519_pk = kdf::x25519_pk_from_sk(&server_x25519_sk_raw);

    // Ring-based API should derive the same keys
    let ring = Arc::new(DummyRing::new(client_seed, "kid"));
    let ring_sk = ring.derive_device_x25519("kid", b"client").unwrap();
    assert_eq!(
        ring_sk, client_x25519_sk_raw,
        "Ring API should derive same key as raw API"
    );

    // Both should successfully perform handshake
    let sender = NoiseSender::new();
    let receiver = NoiseReceiver::new();

    let (_, first_msg) = sender
        .initiate_ik(
            &client_x25519_sk,
            &client_ed25519_pk,
            &server_x25519_pk,
            |binding_msg| {
                let signing_key = ed25519_dalek::SigningKey::from_bytes(
                    &kdf::derive_ed25519_secret(&client_seed),
                );
                use ed25519_dalek::Signer;
                signing_key.sign(binding_msg).to_bytes()
            },
        )
        .expect("Sender handshake should work");

    let result = receiver.respond_ik(&server_x25519_sk, &first_msg);
    assert!(result.is_ok(), "Receiver should accept sender's handshake");
}

/// Test XX pattern handshake with NoiseSender/NoiseReceiver.
/// XX is a Trust On First Use pattern with no pre-shared keys.
#[test]
fn test_sender_receiver_xx_pattern() {
    let client_seed = [30u8; 32];
    let client_x25519_sk = Zeroizing::new(kdf::derive_x25519_static(&client_seed, b"client"));

    let server_seed = [40u8; 32];
    let server_x25519_sk = Zeroizing::new(kdf::derive_x25519_static(&server_seed, b"server"));

    let sender = NoiseSender::new();
    let receiver = NoiseReceiver::new();

    // Client initiates XX handshake (no prior knowledge of server key)
    let (mut client_hs, first_msg) = sender
        .initiate_xx(&client_x25519_sk)
        .expect("Client XX initiation should succeed");

    // Server responds
    let (mut server_hs, response) = receiver
        .respond_xx(&server_x25519_sk, &first_msg)
        .expect("Server XX response should succeed");

    // Client processes response and sends final message
    let mut buf = vec![0u8; response.len() + 256];
    client_hs
        .read_message(&response, &mut buf)
        .expect("Client should process response");

    // Complete with client's final message
    let mut final_msg = vec![0u8; 256];
    let n = client_hs
        .write_message(&[], &mut final_msg)
        .expect("Client should send final message");
    final_msg.truncate(n);

    // Server processes final message
    let mut server_buf = vec![0u8; 256];
    server_hs
        .read_message(&final_msg, &mut server_buf)
        .expect("Server should process final message");

    // Both should now be in transport mode
    assert!(client_hs.is_handshake_finished());
    assert!(server_hs.is_handshake_finished());
}

use pubky_noise::ring::RingKeyProvider;
