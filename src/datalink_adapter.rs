//! Datalink adapter helpers for completing Noise handshakes.
//!
//! This module provides helper functions for the 3-step handshake process.

use crate::{
    identity_payload::IdentityPayload, NoiseClient, NoiseError, NoiseServer, NoiseSession,
    RingKeyProvider,
};

/// Start IK handshake as client (step 1 of 3)
/// Returns HandshakeState for later completion
pub fn client_start_ik_direct<R: RingKeyProvider>(
    client: &NoiseClient<R>,
    server_static_pub: &[u8; 32],
) -> Result<(snow::HandshakeState, Vec<u8>), NoiseError> {
    #[cfg(feature = "trace")]
    tracing::debug!("starting client_start_ik_direct");
    let (hs, first_msg) = client.build_initiator_ik_direct(server_static_pub)?;
    // Return HandshakeState, NOT NoiseSession - handshake not complete yet
    Ok((hs, first_msg))
}

/// Server completes IK handshake (step 3 for server)
/// Transitions HandshakeState to transport mode (NoiseSession)
pub fn server_complete_ik(hs: snow::HandshakeState) -> Result<NoiseSession, NoiseError> {
    #[cfg(feature = "trace")]
    tracing::debug!("completing server handshake");
    // Handshake is already complete after server sent response in step 2
    // Now convert to transport mode
    NoiseSession::from_handshake(hs)
}

/// Client completes IK handshake (step 3 of 3)
/// After this, both client and server can use NoiseSession
pub fn client_complete_ik(
    mut hs: snow::HandshakeState,
    response: &[u8],
) -> Result<NoiseSession, NoiseError> {
    #[cfg(feature = "trace")]
    tracing::debug!("completing client handshake");
    let mut buf = vec![0u8; response.len()];
    hs.read_message(response, &mut buf)?;
    // Now handshake is complete on both sides
    NoiseSession::from_handshake(hs)
}

/// INTERNAL TEST HELPER: Complete full IK handshake in one call
/// This is for testing only - production code should use the 3-step process
/// Returns (client_session, server_session, first_msg, identity) for testing
#[doc(hidden)]
#[allow(deprecated)]
pub fn complete_ik_handshake_for_test<R: RingKeyProvider>(
    client: &NoiseClient<R>,
    server: &NoiseServer<R>,
    server_static_pk: &[u8; 32],
) -> Result<(NoiseSession, NoiseSession, Vec<u8>, IdentityPayload), NoiseError> {
    // Step 1: Client initiates
    let (c_hs, first_msg) = client_start_ik_direct(client, server_static_pk)?;

    // Step 2: Server accepts and prepares response
    let (s_hs, id, response) = server_accept_ik(server, &first_msg)?;

    // Step 3: Both sides complete to get NoiseSessions
    let c_session = client_complete_ik(c_hs, &response)?;
    let s_session = server_complete_ik(s_hs)?;

    Ok((c_session, s_session, first_msg, id))
}

/// Server accepts IK handshake (step 2 of 3 for server)
/// Reads client's first message and prepares response
/// Returns (HandshakeState, client identity, response message to send back)
pub fn server_accept_ik<R: RingKeyProvider>(
    server: &NoiseServer<R>,
    first_msg: &[u8],
) -> Result<(snow::HandshakeState, IdentityPayload, Vec<u8>), NoiseError> {
    #[cfg(feature = "trace")]
    tracing::debug!("starting server_accept_ik");
    let (mut hs, id) = server.build_responder_read_ik(first_msg)?;

    // Send response message to complete handshake
    let mut response = vec![0u8; 128];
    let n = hs.write_message(&[], &mut response)?;
    response.truncate(n);

    Ok((hs, id, response))
}

/// Deprecated alias for `NoiseSession`.
///
/// Use `NoiseSession` directly. This type exists for backward compatibility.
#[deprecated(since = "0.8.0", note = "Use NoiseSession directly")]
pub type NoiseLink = NoiseSession;

// ========== RAW KEY / COLD KEY PATTERN HELPERS ==========

use crate::{NoiseReceiver, NoiseSender};
use zeroize::Zeroizing;

/// Start IK-raw handshake (no identity binding).
///
/// Use when identity is verified externally via pkarr.
///
/// # Example
///
/// ```no_run
/// use pubky_noise::{datalink_adapter, kdf};
/// use zeroize::Zeroizing;
///
/// # fn main() -> Result<(), pubky_noise::NoiseError> {
/// let x25519_sk = Zeroizing::new(kdf::derive_x25519_static(&[0u8; 32], b"device"));
/// let server_pk = [0u8; 32]; // From pkarr lookup
///
/// let (hs, first_msg) = datalink_adapter::start_ik_raw(&x25519_sk, &server_pk)?;
/// # Ok(())
/// # }
/// ```
pub fn start_ik_raw(
    local_x25519_sk: &Zeroizing<[u8; 32]>,
    server_static_pub: &[u8; 32],
) -> Result<(snow::HandshakeState, Vec<u8>), NoiseError> {
    let sender = NoiseSender::new();
    sender.initiate_ik_raw(local_x25519_sk, server_static_pub)
}

/// Accept IK-raw handshake (no identity verification).
///
/// Use when identity is verified externally via pkarr.
pub fn accept_ik_raw(
    local_x25519_sk: &Zeroizing<[u8; 32]>,
    first_msg: &[u8],
) -> Result<(snow::HandshakeState, Vec<u8>), NoiseError> {
    let receiver = NoiseReceiver::new();
    receiver.respond_ik_raw(local_x25519_sk, first_msg)
}

/// Start N pattern handshake (anonymous initiator).
///
/// # Example
///
/// ```no_run
/// use pubky_noise::datalink_adapter;
///
/// # fn main() -> Result<(), pubky_noise::NoiseError> {
/// let server_pk = [0u8; 32]; // From pkarr lookup
/// let (hs, first_msg) = datalink_adapter::start_n(&server_pk)?;
/// # Ok(())
/// # }
/// ```
pub fn start_n(
    server_static_pub: &[u8; 32],
) -> Result<(snow::HandshakeState, Vec<u8>), NoiseError> {
    let sender = NoiseSender::new();
    sender.initiate_n(server_static_pub)
}

/// Accept N pattern handshake (responder side).
///
/// N pattern completes in one message, so this returns a ready-to-use HandshakeState.
pub fn accept_n(
    local_x25519_sk: &Zeroizing<[u8; 32]>,
    first_msg: &[u8],
) -> Result<snow::HandshakeState, NoiseError> {
    let receiver = NoiseReceiver::new();
    receiver.respond_n(local_x25519_sk, first_msg)
}

/// Start NN pattern handshake (both parties anonymous).
///
/// # Example
///
/// ```no_run
/// use pubky_noise::datalink_adapter;
///
/// # fn main() -> Result<(), pubky_noise::NoiseError> {
/// let (hs, first_msg) = datalink_adapter::start_nn()?;
/// # Ok(())
/// # }
/// ```
pub fn start_nn() -> Result<(snow::HandshakeState, Vec<u8>), NoiseError> {
    let sender = NoiseSender::new();
    sender.initiate_nn()
}

/// Accept NN pattern handshake.
pub fn accept_nn(first_msg: &[u8]) -> Result<(snow::HandshakeState, Vec<u8>), NoiseError> {
    let receiver = NoiseReceiver::new();
    receiver.respond_nn(first_msg)
}

/// Complete a raw-key handshake for initiator after receiving response.
///
/// Works for IK-raw and NN patterns.
pub fn complete_raw(
    mut hs: snow::HandshakeState,
    response: &[u8],
) -> Result<NoiseSession, NoiseError> {
    if !response.is_empty() {
        let mut buf = vec![0u8; response.len() + 256];
        hs.read_message(response, &mut buf)?;
    }
    NoiseSession::from_handshake(hs)
}

/// Complete N pattern on responder side (already complete after accept_n).
pub fn complete_n(hs: snow::HandshakeState) -> Result<NoiseSession, NoiseError> {
    NoiseSession::from_handshake(hs)
}
