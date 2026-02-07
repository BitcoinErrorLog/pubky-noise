//! Tests for ServerPolicy enforcement
//!
//! These tests verify server policy configuration and enforcement behavior.
//! Note: ServerPolicy rate limiting fields are reserved for future use.
//! Use the RateLimiter type for current rate limiting needs.

use pubky_noise::server::{ServerPolicy, MAX_HANDSHAKE_MSG_LEN, MAX_SERVER_HINT_LEN};
use pubky_noise::{NoiseServer, RingKeyProvider};
use std::sync::Arc;

struct TestRing {
    seed: [u8; 32],
}

impl RingKeyProvider for TestRing {
    fn derive_device_x25519(
        &self,
        _kid: &str,
        device_id: &[u8],
        epoch: u32,
    ) -> Result<[u8; 32], pubky_noise::NoiseError> {
        Ok(pubky_noise::kdf::derive_x25519_for_device_epoch(&self.seed, device_id, epoch)?)
    }

    fn ed25519_pubkey(&self, _kid: &str) -> Result<[u8; 32], pubky_noise::NoiseError> {
        use ed25519_dalek::SigningKey;
        let signing_key = SigningKey::from_bytes(&self.seed);
        Ok(signing_key.verifying_key().to_bytes())
    }

    fn sign_ed25519(&self, _kid: &str, msg: &[u8]) -> Result<[u8; 64], pubky_noise::NoiseError> {
        use ed25519_dalek::{Signer, SigningKey};
        let signing_key = SigningKey::from_bytes(&self.seed);
        Ok(signing_key.sign(msg).to_bytes())
    }
}

/// Test that ServerPolicy can be configured
#[test]
fn test_server_policy_configuration() {
    let ring = Arc::new(TestRing { seed: [1u8; 32] });

    // Create server with default policy
    let server = NoiseServer::<_, ()>::new_direct("kid", b"server", ring.clone());
    assert_eq!(server.policy.max_handshakes_per_ip, None);
    assert_eq!(server.policy.max_sessions_per_ed25519, None);

    // Create server with custom policy (would need builder pattern or setter)
    // For now, we can manually set after creation (if fields are public)
    // This test documents the expected API
}

/// Test ServerPolicy default values
#[test]
fn test_server_policy_default() {
    let policy = ServerPolicy::default();
    assert_eq!(policy.max_handshakes_per_ip, None);
    assert_eq!(policy.max_sessions_per_ed25519, None);
}

/// Test ServerPolicy clone
#[test]
fn test_server_policy_clone() {
    let policy = ServerPolicy {
        max_handshakes_per_ip: Some(10),
        max_sessions_per_ed25519: Some(5),
    };

    let cloned = policy.clone();
    assert_eq!(cloned.max_handshakes_per_ip, Some(10));
    assert_eq!(cloned.max_sessions_per_ed25519, Some(5));
}

/// Test ServerPolicy debug formatting
#[test]
fn test_server_policy_debug() {
    let policy = ServerPolicy::default();
    let debug_str = format!("{:?}", policy);
    assert!(debug_str.contains("ServerPolicy"));
}

/// Document expected behavior for max_handshakes_per_ip
///
/// When implemented, this should:
/// 1. Track handshake attempts per IP address
/// 2. Reject handshakes exceeding the limit
/// 3. Reset counters after a time window
#[test]
fn test_max_handshakes_per_ip_expected_behavior() {
    // This test documents expected behavior when enforcement is implemented
    let policy = ServerPolicy {
        max_handshakes_per_ip: Some(5),
        max_sessions_per_ed25519: None,
    };

    // When implemented:
    // - First 5 handshakes from same IP should succeed
    // - 6th handshake should be rejected with Policy error
    // - Counter should reset after time window

    assert_eq!(policy.max_handshakes_per_ip, Some(5));
}

/// Document expected behavior for max_sessions_per_ed25519
///
/// When implemented, this should:
/// 1. Track active sessions per Ed25519 identity
/// 2. Reject new handshakes if limit exceeded
/// 3. Allow new sessions when old ones are closed
#[test]
fn test_max_sessions_per_ed25519_expected_behavior() {
    // This test documents expected behavior when enforcement is implemented
    let policy = ServerPolicy {
        max_handshakes_per_ip: None,
        max_sessions_per_ed25519: Some(3),
    };

    // When implemented:
    // - First 3 sessions from same Ed25519 identity should succeed
    // - 4th session should be rejected with Policy error
    // - Closing a session should allow a new one

    assert_eq!(policy.max_sessions_per_ed25519, Some(3));
}

/// Test that handshake size constants are reasonable
#[test]
fn test_size_limit_constants() {
    // Verify constants are defined and have reasonable values
    assert_eq!(MAX_HANDSHAKE_MSG_LEN, 65536);
    assert_eq!(MAX_SERVER_HINT_LEN, 256);
}

/// Test that handshake message size is validated
#[test]
fn test_handshake_rejects_oversized_message() {
    let ring = Arc::new(TestRing { seed: [1u8; 32] });
    let server = NoiseServer::<_, ()>::new_direct("kid", b"server", ring);

    // Create a message larger than MAX_HANDSHAKE_MSG_LEN
    let oversized_msg = vec![0u8; MAX_HANDSHAKE_MSG_LEN + 1];

    let result = server.build_responder_read_ik(&oversized_msg);
    assert!(result.is_err());

    // Should be a Policy error
    let err = result.unwrap_err();
    assert!(
        matches!(err, pubky_noise::NoiseError::Policy(_)),
        "Expected Policy error, got {:?}",
        err
    );
}

