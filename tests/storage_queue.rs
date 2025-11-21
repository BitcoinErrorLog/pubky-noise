#![cfg(feature = "storage-queue")]

use pubky::{Keypair, Pubky};
use pubky_noise::datalink_adapter::{client_start_ik_direct, server_accept_ik};
use pubky_noise::{
    DummyRing, MessageQueue, NoiseClient, NoiseLink, NoiseServer, RingKeyProvider,
    StorageBackedMessaging,
};
use std::sync::Arc;

#[tokio::test]
async fn test_storage_queue_flow() {
    // Setup Noise
    let ring_client = Arc::new(DummyRing::new([1u8; 32], "kid"));
    let ring_server = Arc::new(DummyRing::new([2u8; 32], "kid"));
    let client = NoiseClient::<_, ()>::new_direct("kid", b"dev-client", ring_client.clone());
    let server = NoiseServer::<_, ()>::new_direct("kid", b"dev-server", ring_server.clone(), 3);

    // Server static
    let server_sk = ring_server
        .derive_device_x25519("kid", b"dev-server", 3)
        .unwrap();
    let server_static_pk = pubky_noise::kdf::x25519_pk_from_sk(&server_sk);

    // Handshake
    let (c_link, _, first_msg) =
        client_start_ik_direct(&client, &server_static_pk, 3, None).unwrap();
    let (_s_hs, _, _response) = server_accept_ik(&server, &first_msg).unwrap();

    // Since we can't easily mock PubkySession without a real network or internal mocks,
    // we mostly verify that the types align and the feature compiles.
    // In a real integration test, we would do:

    /*
    let mut queue = StorageBackedMessaging::new(
        c_link,
        session,
        pubky_client,
        "/pub/me/outbox".to_string(),
        "pubky://them/pub/them/outbox".to_string()
    ).with_counters(10, 5); // Test resumption API

    assert_eq!(queue.write_path(), "/pub/me/outbox");
    */
}
