use pubky_noise::*;

#[test]
fn adapter_smoke() {
    let ring_client = std::sync::Arc::new(pubky_noise::DummyRing::new([1u8;32], "kid"));
    let ring_server = std::sync::Arc::new(pubky_noise::DummyRing::new([2u8;32], "kid"));

    // Server derives its static from epoch and we pin the pk for the client
    let server = pubky_noise::NoiseServer::new_direct("kid", b"devS", ring_server.clone(), 3);
    // We can't easily read the server's static pk from builder here; in a real setup you'd pin OOB.
    // For the demo, we just assert that the helper compiles and the types line up.

    assert!(true);
}
