#![no_main]

//! Fuzz target for NN pattern handshake message parsing.
//!
//! Tests that the server gracefully handles malformed NN handshake messages
//! without panicking.
//!
//! # Security Note
//!
//! The NN pattern provides NO authentication. This fuzz target tests
//! implementation robustness, not security properties.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use pubky_noise::{NoiseClient, NoiseError, NoiseServer, RingKeyProvider};
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
        pubky_noise::kdf::derive_x25519_for_device_epoch(&self.seed, device_id, epoch)
    }

    fn ed25519_pubkey(&self, _kid: &str) -> Result<[u8; 32], NoiseError> {
        use sha2::{Digest, Sha256};
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

/// Arbitrary input for NN handshake fuzzing
#[derive(Debug, Arbitrary)]
struct NnInput {
    client_seed: [u8; 32],
    server_seed: [u8; 32],
    /// Fuzzed first message (should be ephemeral key only)
    malformed_first_msg: Vec<u8>,
    /// Fuzzed response (should be server ephemeral + ee)
    malformed_response: Vec<u8>,
}

fuzz_target!(|input: NnInput| {
    // Skip very large messages to avoid OOM
    if input.malformed_first_msg.len() > 65536 || input.malformed_response.len() > 65536 {
        return;
    }

    let client_ring = Arc::new(FuzzRing {
        seed: input.client_seed,
    });
    let server_ring = Arc::new(FuzzRing {
        seed: input.server_seed,
    });

    let client = NoiseClient::<_, ()>::new_direct("fuzz_client", b"client", client_ring);
    let server = NoiseServer::<_, ()>::new_direct("fuzz_server", b"server", server_ring);

    // Test 1: Server handling malformed NN first message
    // This should NOT panic, just return an error
    let nn_result = server.build_responder_nn(&input.malformed_first_msg);
    match nn_result {
        Ok((_hs, _response)) => {
            // If somehow valid, that's fine - NN is lenient
        }
        Err(_) => {
            // Expected - malformed messages should be rejected gracefully
        }
    }

    // Test 2: Valid NN initiation followed by malformed response handling
    let init_result = client.build_initiator_nn();
    if let Ok((hs, first_msg)) = init_result {
        // Server processes valid first message
        if let Ok((_server_hs, response)) = server.build_responder_nn(&first_msg) {
            // Client tries to complete with fuzzed data instead of valid response
            let complete_result = client.complete_initiator_nn(hs, &input.malformed_response);
            // Should not panic
            let _ = complete_result;
        }
    }

    // Test 3: Test with random first message, valid response flow
    if let Ok((hs, _)) = client.build_initiator_nn() {
        // Pass malformed data as first message to server
        if let Ok((_, valid_response)) = server.build_responder_nn(&input.malformed_first_msg) {
            // Client completes with this response (may fail, but shouldn't panic)
            let _ = client.complete_initiator_nn(hs, &valid_response);
        }
    }
});

