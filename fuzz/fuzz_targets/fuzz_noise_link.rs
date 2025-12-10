#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use pubky_noise::{NoiseClient, NoiseServer, RingKeyProvider, NoiseError};
use pubky_noise::datalink_adapter::{
    client_start_ik_direct, client_complete_ik, server_accept_ik, server_complete_ik,
};
use std::sync::Arc;

/// A simple key provider for fuzzing
struct FuzzRing {
    seed: [u8; 32],
}

impl RingKeyProvider for FuzzRing {
    fn derive_device_x25519(
        &self,
        _kid: &str,
        device_id: &[u8],
        epoch: u32,
    ) -> Result<[u8; 32], NoiseError> {
        Ok(pubky_noise::kdf::derive_x25519_for_device_epoch(
            &self.seed, device_id, epoch,
        ))
    }

    fn ed25519_pubkey(&self, _kid: &str) -> Result<[u8; 32], NoiseError> {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&self.seed);
        hasher.update(b"ed25519_pubkey");
        let result = hasher.finalize();
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&result[..32]);
        Ok(pk)
    }

    fn sign_ed25519(&self, _kid: &str, _msg: &[u8]) -> Result<[u8; 64], NoiseError> {
        Ok([0x42u8; 64])
    }
}

/// Arbitrary input for NoiseLink fuzzing
#[derive(Debug, Arbitrary)]
struct NoiseLinkInput {
    seed: [u8; 32],
    plaintext: Vec<u8>,
    malformed_ciphertext: Vec<u8>,
}

fuzz_target!(|input: NoiseLinkInput| {
    // Skip very large inputs to avoid OOM
    if input.plaintext.len() > 65536 || input.malformed_ciphertext.len() > 65536 {
        return;
    }

    // Create a pair of links using the complete handshake helper
    let ring = Arc::new(FuzzRing { seed: input.seed });

    let client = NoiseClient::<_, ()>::new_direct("client", b"client_dev", ring.clone());
    let server = NoiseServer::<_, ()>::new_direct("server", b"server_dev", ring.clone());

    // Get server's public key
    let server_sk = match ring.derive_device_x25519("server", b"server_dev", 0) {
        Ok(sk) => sk,
        Err(_) => return,
    };
    let server_pk = pubky_noise::kdf::x25519_pk_from_sk(&server_sk);

    // Complete handshake
    let (c_hs, first_msg) = match client_start_ik_direct(&client, &server_pk, None) {
        Ok(result) => result,
        Err(_) => return,
    };

    let (s_hs, _identity, response) = match server_accept_ik(&server, &first_msg) {
        Ok(result) => result,
        Err(_) => return,
    };

    let mut client_link = match client_complete_ik(c_hs, &response) {
        Ok(link) => link,
        Err(_) => return,
    };

    let mut server_link = match server_complete_ik(s_hs) {
        Ok(link) => link,
        Err(_) => return,
    };

    // Test 1: Encrypt/decrypt roundtrip
    let ciphertext = match client_link.encrypt(&input.plaintext) {
        Ok(ct) => ct,
        Err(_) => return,
    };

    let decrypted = match server_link.decrypt(&ciphertext) {
        Ok(pt) => pt,
        Err(_) => {
            // This shouldn't happen for valid ciphertext
            panic!("Failed to decrypt valid ciphertext");
        }
    };

    assert_eq!(
        input.plaintext, decrypted,
        "Decrypted plaintext should match original"
    );

    // Test 2: Decrypt malformed ciphertext (should error, not panic)
    let malformed_result = server_link.decrypt(&input.malformed_ciphertext);
    
    // We expect an error for malformed ciphertext
    // The important thing is it doesn't panic
    match malformed_result {
        Ok(_) => {
            // Very unlikely - random bytes happen to be valid ciphertext
            // This could indicate a security issue if it happens frequently
        }
        Err(_) => {
            // Expected - authentication should fail
        }
    }

    // Test 3: Multiple messages
    for i in 0..3 {
        let msg = format!("message {}", i);
        let ct = client_link.encrypt(msg.as_bytes()).expect("Encrypt should work");
        let pt = server_link.decrypt(&ct).expect("Decrypt should work");
        assert_eq!(msg.as_bytes(), &pt[..]);
    }

    // Test 4: Bidirectional
    let server_msg = b"response from server";
    let server_ct = server_link.encrypt(server_msg).expect("Server encrypt");
    let server_pt = client_link.decrypt(&server_ct).expect("Client decrypt");
    assert_eq!(server_msg, &server_pt[..]);
});

