use pubky_noise::{NoiseClient, NoiseServer, DummyRing, RingKeyProvider};
use pubky_noise::datalink_adapter::{client_start_ik_direct, server_accept_ik};
use std::sync::Arc;

#[test]
fn test_session_id_derivation() {
    let ring_client = Arc::new(DummyRing::new([1u8;32], "kid"));
    let ring_server = Arc::new(DummyRing::new([2u8;32], "kid"));

    let client = NoiseClient::<_, ()>::new_direct("kid", b"dev-client", ring_client.clone());
    let server = NoiseServer::<_, ()>::new_direct("kid", b"dev-server", ring_server.clone(), 3);

    // Get server static pub key
    let server_sk = ring_server.derive_device_x25519("kid", b"dev-server", 3).unwrap();
    let server_static_pk = pubky_noise::kdf::x25519_pk_from_sk(&server_sk);

    let (c_link, _epoch, first_msg) = client_start_ik_direct(&client, &server_static_pk, 3, None).unwrap();
    let (s_link, _id) = server_accept_ik(&server, &first_msg).unwrap();

    println!("Client Session ID: {}", c_link.session_id());
    println!("Server Session ID: {}", s_link.session_id());

    assert_eq!(c_link.session_id(), s_link.session_id(), "Session IDs must match on both sides");
}

