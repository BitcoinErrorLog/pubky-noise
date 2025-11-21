use pubky_noise::datalink_adapter::{
    client_complete_ik, client_start_ik_direct, server_accept_ik, server_complete_ik,
};
use pubky_noise::{DummyRing, NoiseClient, NoiseServer, RingKeyProvider};
use std::sync::Arc;

#[test]
fn test_session_id_derivation() {
    let ring_client = Arc::new(DummyRing::new([1u8; 32], "kid"));
    let ring_server = Arc::new(DummyRing::new([2u8; 32], "kid"));

    let client = NoiseClient::<_, ()>::new_direct("kid", b"dev-client", ring_client.clone());
    let server = NoiseServer::<_, ()>::new_direct("kid", b"dev-server", ring_server.clone(), 3);

    // Get server static pub key
    let server_sk = ring_server
        .derive_device_x25519("kid", b"dev-server", 3)
        .unwrap();
    let server_static_pk = pubky_noise::kdf::x25519_pk_from_sk(&server_sk);

    // Step 1: Client initiates handshake
    let (c_hs, _epoch, first_msg) =
        client_start_ik_direct(&client, &server_static_pk, 3, None).unwrap();

    // Step 2: Server responds
    let (s_hs, _id, response) = server_accept_ik(&server, &first_msg).unwrap();

    // Step 3: Client completes handshake
    let c_link = client_complete_ik(c_hs, &response).unwrap();

    // Server completes handshake
    let s_link = server_complete_ik(s_hs).unwrap();

    println!("Client Session ID: {}", c_link.session_id());
    println!("Server Session ID: {}", s_link.session_id());

    assert_eq!(
        c_link.session_id(),
        s_link.session_id(),
        "Session IDs must match on both sides"
    );
}
