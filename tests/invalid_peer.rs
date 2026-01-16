#[test]
fn rejects_zero_shared_secret_on_client() {
    let ring = std::sync::Arc::new(pubky_noise::DummyRing::new([7u8; 32], "kid"));
    let client: pubky_noise::NoiseClient<_, ()> =
        pubky_noise::NoiseClient::new_direct("kid", b"device-minimum-16b", ring.clone());
    let zero_pk = [0u8; 32];
    let res = client.build_initiator_ik_direct(&zero_pk, None);
    assert!(matches!(res, Err(pubky_noise::NoiseError::InvalidPeerKey)));
}
