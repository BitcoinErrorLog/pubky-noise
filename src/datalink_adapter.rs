//! DataLink-style adapter for Noise protocol encryption.
//!
//! This module provides a simple encrypt/decrypt interface over Noise sessions.

use crate::session_id::SessionId;
use crate::{
    identity_payload::IdentityPayload, NoiseClient, NoiseError, NoiseServer, NoiseTransport,
    RingKeyProvider,
};

/// Simple adapter for Noise-encrypted communication.
///
/// Provides `encrypt` and `decrypt` methods for application-layer messages
/// after a Noise handshake has been completed.
pub struct NoiseLink {
    inner: NoiseTransport,
}

impl NoiseLink {
    /// Create a NoiseLink from a completed handshake state.
    pub fn new_from_hs(hs: snow::HandshakeState) -> Result<Self, NoiseError> {
        Ok(Self {
            inner: NoiseTransport::from_handshake(hs)?,
        })
    }

    /// Encrypt plaintext for sending to the peer.
    #[cfg_attr(feature = "trace", tracing::instrument(skip(self, plaintext)))]
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        self.inner.write(plaintext)
    }

    /// Decrypt ciphertext received from the peer.
    #[cfg_attr(feature = "trace", tracing::instrument(skip(self, ciphertext)))]
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        self.inner.read(ciphertext)
    }

    /// Get the session identifier for this link.
    pub fn session_id(&self) -> &SessionId {
        self.inner.session_id()
    }
}

/// Start IK handshake as client (step 1 of 3).
///
/// # Arguments
///
/// * `client` - The NoiseClient instance.
/// * `server_static_pub` - The server's static X25519 public key.
/// * `hint` - Optional server hint for routing.
///
/// # Returns
///
/// A tuple of (HandshakeState, first_message_bytes).
pub fn client_start_ik_direct<R: RingKeyProvider>(
    client: &NoiseClient<R, ()>,
    server_static_pub: &[u8; 32],
    hint: Option<&str>,
) -> Result<(snow::HandshakeState, Vec<u8>), NoiseError> {
    #[cfg(feature = "trace")]
    tracing::debug!("starting client_start_ik_direct");
    let (hs, first_msg) = client.build_initiator_ik_direct(server_static_pub, hint)?;
    // Return HandshakeState, NOT NoiseLink - handshake not complete yet
    Ok((hs, first_msg))
}

/// Server completes IK handshake (step 3 for server).
///
/// Transitions HandshakeState to transport mode (NoiseLink).
pub fn server_complete_ik(hs: snow::HandshakeState) -> Result<NoiseLink, NoiseError> {
    #[cfg(feature = "trace")]
    tracing::debug!("completing server handshake");
    // Handshake is already complete after server sent response in step 2
    // Now convert to transport mode
    NoiseLink::new_from_hs(hs)
}

/// Client completes IK handshake (step 3 of 3).
///
/// After this, both client and server can create NoiseLink.
pub fn client_complete_ik(
    mut hs: snow::HandshakeState,
    response: &[u8],
) -> Result<NoiseLink, NoiseError> {
    #[cfg(feature = "trace")]
    tracing::debug!("completing client handshake");
    let mut buf = vec![0u8; response.len()];
    hs.read_message(response, &mut buf)?;
    // Now handshake is complete on both sides
    NoiseLink::new_from_hs(hs)
}

/// Server accepts IK handshake (step 2 of 3 for server).
///
/// This is a convenience function that wraps `server.build_responder_read_ik()`
/// and generates the response message in one call. For more control, use
/// the individual steps directly.
///
/// # Arguments
///
/// * `server` - The NoiseServer instance.
/// * `first_msg` - The first handshake message from the client.
///
/// # Returns
///
/// A tuple of (HandshakeState, client IdentityPayload, response message).
pub fn server_accept_ik<R: RingKeyProvider>(
    server: &NoiseServer<R, ()>,
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

/// INTERNAL TEST HELPER: Complete full IK handshake in one call.
///
/// This is for testing only - production code should use the 3-step process.
///
/// # Returns
///
/// A tuple of (client_link, server_link, first_msg, client_identity).
#[doc(hidden)]
pub fn complete_ik_handshake_for_test<R: RingKeyProvider>(
    client: &NoiseClient<R, ()>,
    server: &NoiseServer<R, ()>,
    server_static_pk: &[u8; 32],
    hint: Option<&str>,
) -> Result<(NoiseLink, NoiseLink, Vec<u8>, IdentityPayload), NoiseError> {
    // Step 1: Client initiates
    let (c_hs, first_msg) = client_start_ik_direct(client, server_static_pk, hint)?;

    // Step 2: Server accepts and prepares response
    let (s_hs, id, response) = server_accept_ik(server, &first_msg)?;

    // Step 3: Both sides complete to get NoiseLinks
    let c_link = client_complete_ik(c_hs, &response)?;
    let s_link = server_complete_ik(s_hs)?;

    Ok((c_link, s_link, first_msg, id))
}

// =============================================================================
// XX Pattern (Trust On First Use)
// =============================================================================

/// Result type for XX handshake initiation.
pub struct XxInitResult {
    pub hs: snow::HandshakeState,
    pub first_msg: Vec<u8>,
    pub server_hint: Option<String>,
}

/// Result type for XX handshake completion on client side.
pub struct XxClientCompleteResult {
    pub link: NoiseLink,
    pub server_identity: IdentityPayload,
    pub server_static_pk: [u8; 32],
}

/// Start XX handshake as client (step 1 of 3, Trust On First Use).
pub fn client_start_xx_tofu<R: RingKeyProvider>(
    client: &NoiseClient<R, ()>,
    server_hint: Option<&str>,
) -> Result<XxInitResult, NoiseError> {
    let (hs, first_msg, hint) = client.build_initiator_xx_tofu(server_hint)?;
    Ok(XxInitResult {
        hs,
        first_msg,
        server_hint: hint,
    })
}

/// Server accepts XX handshake (step 2 of 3).
pub fn server_accept_xx<R: RingKeyProvider>(
    server: &NoiseServer<R, ()>,
    first_msg: &[u8],
) -> Result<(snow::HandshakeState, Vec<u8>, [u8; 32]), NoiseError> {
    server.build_responder_xx(first_msg)
}

/// Server completes XX handshake after receiving client's final message (step 3).
pub fn server_complete_xx<R: RingKeyProvider>(
    server: &NoiseServer<R, ()>,
    hs: snow::HandshakeState,
    client_final_msg: &[u8],
    server_static_pk: &[u8; 32],
) -> Result<(NoiseLink, IdentityPayload), NoiseError> {
    let (hs, client_identity) =
        server.complete_responder_xx(hs, client_final_msg, server_static_pk)?;
    let link = NoiseLink::new_from_hs(hs)?;
    Ok((link, client_identity))
}

/// Client completes XX handshake (step 3 of 3).
pub fn client_complete_xx<R: RingKeyProvider>(
    client: &NoiseClient<R, ()>,
    hs: snow::HandshakeState,
    server_response: &[u8],
    server_hint: Option<&str>,
) -> Result<(XxClientCompleteResult, Vec<u8>), NoiseError> {
    let (hs, final_msg, server_identity, server_static_pk) =
        client.complete_initiator_xx(hs, server_response, server_hint)?;
    let link = NoiseLink::new_from_hs(hs)?;
    Ok((
        XxClientCompleteResult {
            link,
            server_identity,
            server_static_pk,
        },
        final_msg,
    ))
}

/// INTERNAL TEST HELPER: Complete full XX handshake in one call.
#[doc(hidden)]
pub fn complete_xx_handshake_for_test<R: RingKeyProvider>(
    client: &NoiseClient<R, ()>,
    server: &NoiseServer<R, ()>,
    server_hint: Option<&str>,
) -> Result<
    (
        NoiseLink,
        NoiseLink,
        IdentityPayload,
        IdentityPayload,
        [u8; 32],
    ),
    NoiseError,
> {
    let init = client_start_xx_tofu(client, server_hint)?;
    let (s_hs, server_response, server_static_pk) = server_accept_xx(server, &init.first_msg)?;
    let (client_result, client_final_msg) = client_complete_xx(
        client,
        init.hs,
        &server_response,
        init.server_hint.as_deref(),
    )?;
    let (s_link, client_identity) =
        server_complete_xx(server, s_hs, &client_final_msg, &server_static_pk)?;

    Ok((
        client_result.link,
        s_link,
        client_identity,
        client_result.server_identity,
        server_static_pk,
    ))
}

// =============================================================================
// NN Pattern (Ephemeral-only, NO AUTHENTICATION)
// =============================================================================

/// Start NN handshake as client (ephemeral-only, NO AUTHENTICATION).
///
/// # Security Warning: No Authentication
///
/// The NN pattern provides **forward secrecy only** with NO identity binding.
/// An active attacker can trivially MITM this connection.
pub fn client_start_nn<R: RingKeyProvider>(
    client: &NoiseClient<R, ()>,
) -> Result<(snow::HandshakeState, Vec<u8>), NoiseError> {
    client.build_initiator_nn()
}

/// Server accepts NN handshake (ephemeral-only, NO AUTHENTICATION).
///
/// # Security Warning: No Authentication
///
/// The NN pattern provides **forward secrecy only** with NO identity binding.
pub fn server_accept_nn<R: RingKeyProvider>(
    server: &NoiseServer<R, ()>,
    first_msg: &[u8],
) -> Result<(snow::HandshakeState, Vec<u8>), NoiseError> {
    server.build_responder_nn(first_msg)
}

/// Client completes NN handshake (ephemeral-only, NO AUTHENTICATION).
///
/// # Security Warning: No Authentication
///
/// The NN pattern provides **forward secrecy only** with NO identity binding.
pub fn client_complete_nn<R: RingKeyProvider>(
    client: &NoiseClient<R, ()>,
    hs: snow::HandshakeState,
    server_response: &[u8],
) -> Result<NoiseLink, NoiseError> {
    let hs = client.complete_initiator_nn(hs, server_response)?;
    NoiseLink::new_from_hs(hs)
}

/// Server completes NN handshake to get NoiseLink (ephemeral-only, NO AUTHENTICATION).
///
/// # Security Warning: No Authentication
///
/// The NN pattern provides **forward secrecy only** with NO identity binding.
pub fn server_complete_nn(hs: snow::HandshakeState) -> Result<NoiseLink, NoiseError> {
    NoiseLink::new_from_hs(hs)
}

/// INTERNAL TEST HELPER: Complete full NN handshake in one call.
#[doc(hidden)]
pub fn complete_nn_handshake_for_test<R: RingKeyProvider>(
    client: &NoiseClient<R, ()>,
    server: &NoiseServer<R, ()>,
) -> Result<(NoiseLink, NoiseLink), NoiseError> {
    let (c_hs, first_msg) = client_start_nn(client)?;
    let (s_hs, response) = server_accept_nn(server, &first_msg)?;
    let c_link = client_complete_nn(client, c_hs, &response)?;
    let s_link = server_complete_nn(s_hs)?;
    Ok((c_link, s_link))
}
