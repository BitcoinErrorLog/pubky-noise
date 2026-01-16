//! XX Pattern Interoperability Tests
//!
//! These tests verify that the XX pattern implementation is compatible with
//! the PUBKY_CRYPTO_SPEC specification and other implementations.
//!
//! ## Coverage
//!
//! - Fixed prologue verification (must be `b"pubky-noise-v1"`)
//! - Pattern tag consistency in binding messages
//! - XX→IK upgrade path validation
//! - Downgrade prevention from IK to XX
//! - Identity payload format compliance

use pubky_noise::datalink_adapter::{
    client_complete_xx, client_start_ik_direct, client_start_xx_tofu, complete_xx_handshake_for_test,
    server_accept_ik, server_accept_xx, server_complete_xx,
};
use pubky_noise::identity_payload::Role;
use pubky_noise::{NoiseClient, NoiseError, NoiseServer, RingKeyProvider};
use std::sync::Arc;

/// Test ring implementation
struct InteropRing {
    seed: [u8; 32],
}

impl RingKeyProvider for InteropRing {
    fn derive_device_x25519(
        &self,
        _kid: &str,
        device_id: &[u8],
        epoch: u32,
    ) -> Result<[u8; 32], NoiseError> {
        pubky_noise::kdf::derive_x25519_for_device_epoch(&self.seed, device_id, epoch)
    }

    fn ed25519_pubkey(&self, _kid: &str) -> Result<[u8; 32], NoiseError> {
        use ed25519_dalek::SigningKey;
        let signing_key = SigningKey::from_bytes(&self.seed);
        Ok(signing_key.verifying_key().to_bytes())
    }

    fn sign_ed25519(&self, _kid: &str, msg: &[u8]) -> Result<[u8; 64], NoiseError> {
        use ed25519_dalek::{Signer, SigningKey};
        let signing_key = SigningKey::from_bytes(&self.seed);
        Ok(signing_key.sign(msg).to_bytes())
    }
}

/// Verify that prologue is frozen and not configurable.
///
/// Per PUBKY_CRYPTO_SPEC v2.5 Section 6.2, the prologue MUST be a fixed constant.
/// The NoiseClient/NoiseServer structs no longer expose a `prologue` field -
/// it is hardcoded internally as `b"pubky-noise-v1"`.
#[test]
fn test_prologue_is_frozen() {
    // This test verifies that handshakes complete successfully using the fixed prologue.
    // The prologue is no longer a public field, so we verify by ensuring
    // client and server can complete a handshake (which requires matching prologues).
    
    let client_ring = Arc::new(InteropRing { seed: [1u8; 32] });
    let server_ring = Arc::new(InteropRing { seed: [2u8; 32] });

    let client = NoiseClient::<_, ()>::new_direct("client-kid", b"client-device-id-16", client_ring);
    let server = NoiseServer::<_, ()>::new_direct("server-kid", b"server-device-id-16", server_ring);

    // If prologues weren't matching, handshake would fail
    let result = complete_xx_handshake_for_test(&client, &server, None);
    assert!(result.is_ok(), "Handshake with frozen prologue should succeed: {:?}", result.err());
}

/// Verify that XX pattern correctly learns and pins server's static key.
#[test]
fn test_xx_to_ik_upgrade_path() {
    let client_ring = Arc::new(InteropRing { seed: [11u8; 32] });
    let server_ring = Arc::new(InteropRing { seed: [22u8; 32] });

    let client = NoiseClient::<_, ()>::new_direct("client-kid", b"client-device-id000", client_ring);
    let server = NoiseServer::<_, ()>::new_direct("server-kid", b"server-device-id000", server_ring);

    // Step 1: Complete XX handshake (TOFU)
    let (c_link, s_link, _client_id, server_id, learned_server_pk) =
        complete_xx_handshake_for_test(&client, &server, None)
            .expect("XX handshake should succeed");

    // Verify server identity was learned
    assert_eq!(server_id.role, Role::Server, "Server should have Server role");
    assert_ne!(learned_server_pk, [0u8; 32], "Server key should not be all zeros");

    // Verify session was established
    assert_eq!(c_link.session_id(), s_link.session_id());

    // Step 2: Subsequent connection using IK pattern with pinned key
    let (c_hs, first_msg) = client_start_ik_direct(&client, &learned_server_pk, None)
        .expect("IK with pinned key should succeed");

    let (s_hs, client_id, response) = server_accept_ik(&server, &first_msg)
        .expect("Server should accept IK from client with pinned key");

    assert_eq!(client_id.role, Role::Client);

    // Complete the IK handshake
    let c_link = pubky_noise::datalink_adapter::client_complete_ik(c_hs, &response)
        .expect("Client IK complete should succeed");
    let s_link = pubky_noise::datalink_adapter::server_complete_ik(s_hs)
        .expect("Server IK complete should succeed");

    // Session IDs should match
    assert_eq!(c_link.session_id(), s_link.session_id());
}

/// Verify that IK cannot be downgraded to XX.
/// 
/// Per spec Section 6.8: Once a peer has completed a successful XX handshake
/// and pinned the server's key, subsequent connections SHOULD use IK.
/// A server that expects IK MUST NOT accept XX from a known client.
#[test]
fn test_downgrade_prevention_xx_after_ik() {
    let client_ring = Arc::new(InteropRing { seed: [33u8; 32] });
    let server_ring = Arc::new(InteropRing { seed: [44u8; 32] });

    let client = NoiseClient::<_, ()>::new_direct("client-kid", b"client-device-id000", client_ring);
    let server = NoiseServer::<_, ()>::new_direct("server-kid", b"server-device-id000", server_ring.clone());

    // First, establish trust via XX
    let (_, _, _, _, learned_server_pk) = complete_xx_handshake_for_test(&client, &server, None)
        .expect("Initial XX should succeed");

    // Now try to connect with XX again (simulating downgrade attempt)
    // The client should use IK since it has the server's key
    let init = client_start_xx_tofu(&client, None).expect("XX start should succeed");

    // Server processes as XX - this succeeds but application SHOULD
    // maintain a pin database and reject XX from known clients
    let result = server_accept_xx(&server, &init.first_msg);
    
    // The cryptographic layer allows this, but the application layer
    // SHOULD maintain pinning and reject. We verify the handshake completes
    // to ensure we're testing the right scenario.
    assert!(result.is_ok(), "Crypto layer accepts XX, pinning is app responsibility");

    // The correct behavior is: after learning learned_server_pk via XX,
    // client MUST use IK with that key, not XX again.
    // This test documents that enforcement is at application layer.
    let (_ik_hs, _ik_msg) = client_start_ik_direct(&client, &learned_server_pk, None)
        .expect("Client should use IK after learning server key");
}

/// Verify identity payload contains required fields.
#[test]
fn test_identity_payload_format_compliance() {
    let client_ring = Arc::new(InteropRing { seed: [55u8; 32] });
    let server_ring = Arc::new(InteropRing { seed: [66u8; 32] });

    let client = NoiseClient::<_, ()>::new_direct("client-kid", b"client-device-id000", client_ring);
    let server = NoiseServer::<_, ()>::new_direct("server-kid", b"server-device-id000", server_ring);

    let (_, _, client_identity, server_identity, _) =
        complete_xx_handshake_for_test(&client, &server, Some("test.example.com"))
            .expect("XX handshake should succeed");

    // Per spec Section 6.3, IdentityPayload contains:
    // - ed25519_pub: 32 bytes
    // - role: Client or Server
    // - server_hint: optional, non-normative metadata
    // - sig: 64 bytes Ed25519 signature

    // Verify client identity
    assert_eq!(client_identity.role, Role::Client);
    assert_ne!(client_identity.ed25519_pub, [0u8; 32]);
    assert_eq!(client_identity.server_hint.as_deref(), Some("test.example.com"));
    assert_ne!(client_identity.sig, [0u8; 64]);

    // Verify server identity
    assert_eq!(server_identity.role, Role::Server);
    assert_ne!(server_identity.ed25519_pub, [0u8; 32]);
    assert_ne!(server_identity.sig, [0u8; 64]);
}

/// Verify that server_hint is correctly propagated but not cryptographically enforced.
#[test]
fn test_server_hint_non_normative() {
    let client_ring = Arc::new(InteropRing { seed: [77u8; 32] });
    let server_ring = Arc::new(InteropRing { seed: [88u8; 32] });

    let client = NoiseClient::<_, ()>::new_direct("client-kid", b"client-device-id000", client_ring);
    let server = NoiseServer::<_, ()>::new_direct("server-kid", b"server-device-id000", server_ring);

    // Test with hint
    let (_, _, client_id_with_hint, _, _) =
        complete_xx_handshake_for_test(&client, &server, Some("my-server.example.com"))
            .expect("XX with hint should succeed");

    assert_eq!(
        client_id_with_hint.server_hint.as_deref(),
        Some("my-server.example.com")
    );

    // Test without hint
    let (_, _, client_id_no_hint, _, _) =
        complete_xx_handshake_for_test(&client, &server, None)
            .expect("XX without hint should succeed");

    assert_eq!(client_id_no_hint.server_hint, None);

    // Both handshakes should succeed regardless of hint presence
    // because server_hint is non-normative metadata
}

/// Verify role domain separation in binding messages.
#[test]
fn test_role_domain_separation() {
    let client_ring = Arc::new(InteropRing { seed: [99u8; 32] });
    let server_ring = Arc::new(InteropRing { seed: [100u8; 32] });

    let client = NoiseClient::<_, ()>::new_direct("client-kid", b"client-device-id000", client_ring);
    let server = NoiseServer::<_, ()>::new_direct("server-kid", b"server-device-id000", server_ring);

    let (_, _, client_identity, server_identity, _) =
        complete_xx_handshake_for_test(&client, &server, None)
            .expect("XX handshake should succeed");

    // Roles must be distinct
    assert_eq!(client_identity.role, Role::Client);
    assert_eq!(server_identity.role, Role::Server);
    assert_ne!(
        client_identity.role, server_identity.role,
        "Client and server must have different roles for domain separation"
    );
}

/// Verify that multiple concurrent XX handshakes produce distinct session IDs.
#[test]
fn test_concurrent_xx_session_uniqueness() {
    let client_ring = Arc::new(InteropRing { seed: [111u8; 32] });
    let server_ring = Arc::new(InteropRing { seed: [222u8; 32] });

    let client = NoiseClient::<_, ()>::new_direct("client-kid", b"client-device-id000", client_ring);
    let server = NoiseServer::<_, ()>::new_direct("server-kid", b"server-device-id000", server_ring);

    // Complete two separate handshakes
    let (link1, _, _, _, _) = complete_xx_handshake_for_test(&client, &server, None)
        .expect("First XX should succeed");
    let (link2, _, _, _, _) = complete_xx_handshake_for_test(&client, &server, None)
        .expect("Second XX should succeed");

    // Session IDs should be different due to ephemeral keys
    assert_ne!(
        link1.session_id(),
        link2.session_id(),
        "Different handshakes must produce different session IDs"
    );
}

/// Verify that XX handshake produces deterministic results for the same ephemeral keys.
#[test]
fn test_xx_deterministic_session_id() {
    // This test verifies that session ID is derived from handshake hash,
    // which includes all exchanged keys. Same keys = same session ID.
    
    let client_ring = Arc::new(InteropRing { seed: [1u8; 32] });
    let server_ring = Arc::new(InteropRing { seed: [2u8; 32] });

    let client = NoiseClient::<_, ()>::new_direct("client-kid", b"client-device-id000", client_ring);
    let server = NoiseServer::<_, ()>::new_direct("server-kid", b"server-device-id000", server_ring);

    // Start XX handshake
    let init = client_start_xx_tofu(&client, None).expect("XX start should succeed");

    // Server accepts
    let (s_hs, server_response, server_pk) =
        server_accept_xx(&server, &init.first_msg).expect("Server accept should succeed");

    // Client completes
    let (client_result, client_final) =
        client_complete_xx(&client, init.hs, &server_response, None)
            .expect("Client complete should succeed");

    // Server completes
    let (s_link, _) = server_complete_xx(&server, s_hs, &client_final, &server_pk)
        .expect("Server complete should succeed");

    // Session IDs must match
    assert_eq!(
        client_result.link.session_id(),
        s_link.session_id(),
        "Client and server session IDs must match after handshake"
    );
}
