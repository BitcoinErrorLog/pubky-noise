#![no_main]

//! Fuzz target for XX pattern handshake message parsing.
//!
//! Tests that the server gracefully handles malformed XX handshake messages
//! without panicking.

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
        // Dummy signature for fuzzing
        Ok([0x42u8; 64])
    }
}

/// Arbitrary input for XX handshake fuzzing
#[derive(Debug, Arbitrary)]
struct XxInput {
    client_seed: [u8; 32],
    server_seed: [u8; 32],
    /// Fuzzed first message (should be ephemeral key only)
    malformed_first_msg: Vec<u8>,
    /// Fuzzed final message (should be client static + identity)
    malformed_final_msg: Vec<u8>,
}

fuzz_target!(|input: XxInput| {
    // Skip very large messages to avoid OOM
    if input.malformed_first_msg.len() > 65536 || input.malformed_final_msg.len() > 65536 {
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

    // Test 1: Server handling malformed XX first message
    // This should NOT panic, just return an error
    let xx_result = server.build_responder_xx(&input.malformed_first_msg);
    match xx_result {
        Ok((hs, _response, server_pk)) => {
            // If somehow valid, test malformed final message
            let complete_result =
                server.complete_responder_xx(hs, &input.malformed_final_msg, &server_pk);
            // Should not panic
            let _ = complete_result;
        }
        Err(_) => {
            // Expected - malformed messages should be rejected gracefully
        }
    }

    // Test 2: Valid XX initiation followed by malformed response handling
    let init_result = client.build_initiator_xx_tofu(None);
    if let Ok((hs, first_msg, hint)) = init_result {
        // Server processes valid first message
        if let Ok((server_hs, response, server_pk)) = server.build_responder_xx(&first_msg) {
            // Client tries to complete with fuzzed data instead of valid response
            let complete_result =
                client.complete_initiator_xx(hs, &input.malformed_first_msg, hint.as_deref());
            // Should not panic
            let _ = complete_result;

            // Server completes with fuzzed final message
            let server_complete =
                server.complete_responder_xx(server_hs, &input.malformed_final_msg, &server_pk);
            // Should not panic
            let _ = server_complete;
        }
    }
});

