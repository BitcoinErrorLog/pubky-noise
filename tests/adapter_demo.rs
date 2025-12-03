use pubky_noise::datalink_adapter::{
    client_complete_ik, client_start_ik_direct, server_accept_ik, server_complete_ik, NoiseLink,
};
use pubky_noise::*;
use std::sync::Arc;

#[test]
fn adapter_smoke_compiles() {
    let ring_client = std::sync::Arc::new(pubky_noise::DummyRing::new([1u8; 32], "kid"));
    let ring_server = std::sync::Arc::new(pubky_noise::DummyRing::new([2u8; 32], "kid"));
    let _client = pubky_noise::NoiseClient::<_>::new_direct("kid", b"devC", ring_client);
    let _server = pubky_noise::NoiseServer::<_>::new_direct("kid", b"devS", ring_server);
    assert!(true);
}

#[test]
#[allow(deprecated)]
fn test_streaming_link_legacy() {
    let ring_client = Arc::new(DummyRing::new([1u8; 32], "kid"));
    let ring_server = Arc::new(DummyRing::new([2u8; 32], "kid"));

    let client = NoiseClient::<_>::new_direct("kid", b"dev-client", ring_client);
    let server = NoiseServer::<_>::new_direct("kid", b"dev-server", ring_server.clone());

    // Server static
    let server_sk = ring_server
        .derive_device_x25519("kid", b"dev-server")
        .unwrap();
    let server_static_pk = pubky_noise::kdf::x25519_pk_from_sk(&server_sk);

    // Handshake (3-step process)
    // Step 1: Client initiates
    let (c_hs, first_msg) = client_start_ik_direct(&client, &server_static_pk).unwrap();

    // Step 2: Server accepts and responds
    let (s_hs, _identity, response) = server_accept_ik(&server, &first_msg).unwrap();

    // Step 3: Both complete
    let c_link = client_complete_ik(c_hs, &response).unwrap();
    let s_link = server_complete_ik(s_hs).unwrap();

    // Create streaming links with small chunk size
    let mut c_stream = StreamingNoiseLink::new(c_link, 10);
    let mut s_stream = StreamingNoiseLink::new(s_link, 10);

    let data = b"This is a long message that should be split into chunks";

    // Encrypt (legacy mode)
    let chunks = c_stream.encrypt_streaming(data).unwrap();
    assert!(chunks.len() > 1, "Should be split into multiple chunks");

    // Decrypt (legacy mode)
    let decrypted = s_stream.decrypt_streaming(&chunks).unwrap();
    assert_eq!(data.to_vec(), decrypted);
}

#[test]
fn test_streaming_link_framed() {
    let ring_client = Arc::new(DummyRing::new([1u8; 32], "kid"));
    let ring_server = Arc::new(DummyRing::new([2u8; 32], "kid"));

    let client = NoiseClient::<_>::new_direct("kid", b"dev-client", ring_client);
    let server = NoiseServer::<_>::new_direct("kid", b"dev-server", ring_server.clone());

    // Server static
    let server_sk = ring_server
        .derive_device_x25519("kid", b"dev-server")
        .unwrap();
    let server_static_pk = pubky_noise::kdf::x25519_pk_from_sk(&server_sk);

    // Handshake
    let (c_hs, first_msg) = client_start_ik_direct(&client, &server_static_pk).unwrap();
    let (s_hs, _identity, response) = server_accept_ik(&server, &first_msg).unwrap();
    let c_link = client_complete_ik(c_hs, &response).unwrap();
    let s_link = server_complete_ik(s_hs).unwrap();

    // Create streaming links with small chunk size
    let mut c_stream = StreamingNoiseLink::new(c_link, 10);
    let mut s_stream = StreamingNoiseLink::new(s_link, 10);

    let data = b"This is a long message that should be split into chunks and framed";

    // Encrypt with framing
    let framed = c_stream.encrypt_framed(data).unwrap();

    // Framed output should be larger than raw data (includes length prefixes + AEAD overhead)
    assert!(framed.len() > data.len());

    // Decrypt framed data
    let decrypted = s_stream.decrypt_framed(&framed).unwrap();
    assert_eq!(data.to_vec(), decrypted);
}

#[test]
fn test_streaming_framed_roundtrip_large() {
    let ring_client = Arc::new(DummyRing::new([3u8; 32], "kid"));
    let ring_server = Arc::new(DummyRing::new([4u8; 32], "kid"));

    let client = NoiseClient::<_>::new_direct("kid", b"dev-client", ring_client);
    let server = NoiseServer::<_>::new_direct("kid", b"dev-server", ring_server.clone());

    let server_sk = ring_server
        .derive_device_x25519("kid", b"dev-server")
        .unwrap();
    let server_static_pk = pubky_noise::kdf::x25519_pk_from_sk(&server_sk);

    let (c_hs, first_msg) = client_start_ik_direct(&client, &server_static_pk).unwrap();
    let (s_hs, _identity, response) = server_accept_ik(&server, &first_msg).unwrap();
    let c_link = client_complete_ik(c_hs, &response).unwrap();
    let s_link = server_complete_ik(s_hs).unwrap();

    // 32KB chunks
    let mut c_stream = StreamingNoiseLink::new(c_link, 32768);
    let mut s_stream = StreamingNoiseLink::new(s_link, 32768);

    // 100KB message
    let large_data = vec![0x42u8; 100_000];

    let framed = c_stream.encrypt_framed(&large_data).unwrap();
    let decrypted = s_stream.decrypt_framed(&framed).unwrap();

    assert_eq!(large_data, decrypted);
}

#[test]
fn test_session_manager() {
    let ring_client = Arc::new(DummyRing::new([1u8; 32], "kid"));
    let ring_server = Arc::new(DummyRing::new([2u8; 32], "kid"));

    let client = Arc::new(NoiseClient::<_>::new_direct(
        "kid",
        b"dev-client",
        ring_client,
    ));
    let server = Arc::new(NoiseServer::<_>::new_direct(
        "kid",
        b"dev-server",
        ring_server.clone(),
    ));

    let mut client_manager = NoiseSessionManager::new_client(client.clone());
    let mut server_manager = NoiseSessionManager::new_server(server.clone());

    // Server static
    let server_sk = ring_server
        .derive_device_x25519("kid", b"dev-server")
        .unwrap();
    let server_static_pk = pubky_noise::kdf::x25519_pk_from_sk(&server_sk);

    // Handshake (3-step process)
    // Step 1: Client initiates
    let (c_hs, first_msg) = client_start_ik_direct(&client, &server_static_pk).unwrap();

    // Step 2: Server accepts and responds
    let (s_hs, _identity, response) = server_accept_ik(&server, &first_msg).unwrap();

    // Step 3: Both complete
    let c_link = client_complete_ik(c_hs, &response).unwrap();
    let s_link = server_complete_ik(s_hs).unwrap();

    let c_sid = c_link.session_id().clone();
    let s_sid = s_link.session_id().clone();

    assert_eq!(c_sid, s_sid);

    // Add to managers
    client_manager.add_session(c_sid.clone(), c_link);
    server_manager.add_session(s_sid.clone(), s_link);

    assert!(client_manager.get_session(&c_sid).is_some());
    assert!(server_manager.get_session(&s_sid).is_some());

    // List sessions
    assert_eq!(client_manager.list_sessions().len(), 1);
    assert_eq!(server_manager.list_sessions().len(), 1);

    // Remove session
    client_manager.remove_session(&c_sid);
    assert!(client_manager.get_session(&c_sid).is_none());
}
