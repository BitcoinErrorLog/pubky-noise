use pubky_noise::*;
#[test]
fn adapter_smoke_compiles() {
    let ring_client = std::sync::Arc::new(pubky_noise::DummyRing::new([1u8;32], "kid"));
    let ring_server = std::sync::Arc::new(pubky_noise::DummyRing::new([2u8;32], "kid"));
    let _client = pubky_noise::NoiseClient::<_, ()>::new_direct("kid", b"devC", ring_client);
    let _server = pubky_noise::NoiseServer::<_, ()>::new_direct("kid", b"devS", ring_server, 3);
    assert!(true);
}
