#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use pubky_noise::{NoiseClient, NoiseServer, RingKeyProvider, NoiseError};
use std::sync::Arc;
use zeroize::Zeroizing;

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
        // Deterministic public key from seed
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
        // Dummy signature for fuzzing (not cryptographically valid)
        Ok([0x42u8; 64])
    }
}

/// Arbitrary input for handshake fuzzing
#[derive(Debug, Arbitrary)]
struct HandshakeInput {
    client_seed: [u8; 32],
    server_seed: [u8; 32],
    client_device_id: Vec<u8>,
    server_device_id: Vec<u8>,
    malformed_message: Vec<u8>,
}

fuzz_target!(|input: HandshakeInput| {
    // Skip very large device IDs to avoid OOM
    if input.client_device_id.len() > 1024 || input.server_device_id.len() > 1024 {
        return;
    }
    if input.malformed_message.len() > 65536 {
        return;
    }

    let client_ring = Arc::new(FuzzRing {
        seed: input.client_seed,
    });
    let server_ring = Arc::new(FuzzRing {
        seed: input.server_seed,
    });

    let client = NoiseClient::<_, ()>::new_direct(
        "fuzz_client",
        &input.client_device_id,
        client_ring,
    );

    let server = NoiseServer::<_, ()>::new_direct(
        "fuzz_server",
        &input.server_device_id,
        server_ring.clone(),
    );

    // Get server's public key for handshake
    let server_pk = match server_ring.derive_device_x25519("fuzz_server", &input.server_device_id, 0) {
        Ok(sk) => pubky_noise::kdf::x25519_pk_from_sk(&sk),
        Err(_) => return,
    };

    // Test 1: Valid handshake initiation
    let handshake_result = pubky_noise::datalink_adapter::client_start_ik_direct(
        &client,
        &server_pk,
        None,
    );

    // Should succeed with valid inputs
    if let Ok((_hs_state, first_msg)) = handshake_result {
        // Test server processing valid message using 3-step handshake
        let server_result = server.build_responder_read_ik(&first_msg);
        // Server should be able to process a properly formed message
        // (though verification may fail due to dummy signatures)
        if let Ok((mut hs, _identity)) = server_result {
            // Generate response
            let mut response = vec![0u8; 128];
            if let Ok(n) = hs.write_message(&[], &mut response) {
                response.truncate(n);
                let _ = pubky_noise::datalink_adapter::server_complete_ik(hs);
            }
        }
    }

    // Test 2: Server handling malformed/arbitrary message
    // This should NOT panic, just return an error
    let malformed_result = server.build_responder_read_ik(&input.malformed_message);
    
    // We expect an error for malformed messages, but no panic
    match malformed_result {
        Ok(_) => {
            // Unlikely but possible if input happens to be valid
        }
        Err(_) => {
            // Expected - malformed messages should be rejected gracefully
        }
    }
});

