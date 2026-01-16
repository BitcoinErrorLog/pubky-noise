//! Session ID derivation tests.

use pubky_noise::datalink_adapter::{
    client_complete_ik, client_start_ik_direct, server_accept_ik, server_complete_ik,
};
use pubky_noise::{DummyRing, NoiseClient, NoiseServer, RingKeyProvider, SessionId};
use std::str::FromStr;
use std::sync::Arc;

#[test]
fn test_session_id_derivation() {
    let ring_client = Arc::new(DummyRing::new([1u8; 32], "kid"));
    let ring_server = Arc::new(DummyRing::new([2u8; 32], "kid"));

    let client = NoiseClient::<_, ()>::new_direct("kid", b"dev-client-00000000", ring_client.clone());
    let server = NoiseServer::<_, ()>::new_direct("kid", b"dev-server-00000000", ring_server.clone());

    // Get server static pub key (using internal epoch 0)
    let server_sk = ring_server
        .derive_device_x25519("kid", b"dev-server-00000000", 0)
        .unwrap();
    let server_static_pk = pubky_noise::kdf::x25519_pk_from_sk(&server_sk);

    // Step 1: Client initiates handshake
    let (c_hs, first_msg) = client_start_ik_direct(&client, &server_static_pk, None).unwrap();

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

#[test]
fn test_session_id_from_str() {
    let hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let session_id = SessionId::from_str(hex).expect("Should parse valid hex");
    assert_eq!(session_id.to_string(), hex);
}

#[test]
fn test_session_id_from_str_uppercase() {
    let hex_upper = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    let hex_lower = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let session_id = SessionId::from_str(hex_upper).expect("Should parse uppercase hex");
    assert_eq!(session_id.to_string(), hex_lower);
}

#[test]
fn test_session_id_from_str_invalid_hex() {
    let invalid = "not_valid_hex_string_at_all_here";
    let result = SessionId::from_str(invalid);
    assert!(result.is_err(), "Should reject invalid hex");
}

#[test]
fn test_session_id_from_str_wrong_length() {
    // Too short
    let short = "0123456789abcdef";
    let result = SessionId::from_str(short);
    assert!(result.is_err(), "Should reject short hex");

    // Too long
    let long = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0000";
    let result = SessionId::from_str(long);
    assert!(result.is_err(), "Should reject long hex");
}

#[test]
fn test_session_id_roundtrip() {
    let original = SessionId::from_bytes([42u8; 32]);
    let hex = original.to_string();
    let parsed = SessionId::from_str(&hex).expect("Should parse back");
    assert_eq!(original, parsed);
}
