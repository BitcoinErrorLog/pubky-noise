use crate::session_id::SessionId;
use crate::{
    identity_payload::IdentityPayload, NoiseClient, NoiseError, NoiseServer, NoiseTransport,
    RingKeyProvider,
};

/// Tiny adapter similar to DataLinkEncryptor.
pub struct NoiseLink {
    inner: NoiseTransport,
}
impl NoiseLink {
    pub fn new_from_hs(hs: snow::HandshakeState) -> Result<Self, NoiseError> {
        Ok(Self {
            inner: NoiseTransport::from_handshake(hs)?,
        })
    }

    #[cfg_attr(feature = "trace", tracing::instrument(skip(self, plaintext)))]
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        self.inner.write(plaintext)
    }

    #[cfg_attr(feature = "trace", tracing::instrument(skip(self, ciphertext)))]
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        self.inner.read(ciphertext)
    }

    pub fn session_id(&self) -> &SessionId {
        self.inner.session_id()
    }
}
/// Start IK handshake as client (step 1 of 3)
/// Returns HandshakeState for later completion
pub fn client_start_ik_direct<R: RingKeyProvider>(
    client: &NoiseClient<R, ()>,
    server_static_pub: &[u8; 32],
    epoch: u32,
    hint: Option<&str>,
) -> Result<(snow::HandshakeState, u32, Vec<u8>), NoiseError> {
    #[cfg(feature = "trace")]
    tracing::debug!("starting client_start_ik_direct");
    let (hs, first_msg, used_epoch) =
        client.build_initiator_ik_direct(server_static_pub, epoch, hint)?;
    // Return HandshakeState, NOT NoiseLink - handshake not complete yet
    Ok((hs, used_epoch, first_msg))
}

/// Server completes IK handshake (step 3 for server)
/// Transitions HandshakeState to transport mode (NoiseLink)
pub fn server_complete_ik(hs: snow::HandshakeState) -> Result<NoiseLink, NoiseError> {
    #[cfg(feature = "trace")]
    tracing::debug!("completing server handshake");
    // Handshake is already complete after server sent response in step 2
    // Now convert to transport mode
    NoiseLink::new_from_hs(hs)
}

/// Client completes IK handshake (step 3 of 3)
/// After this, both client and server can create NoiseLink
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

/// INTERNAL TEST HELPER: Complete full IK handshake in one call
/// This is for testing only - production code should use the 3-step process
/// Returns (client_link, server_link, epoch, first_msg) for testing
#[doc(hidden)]
#[allow(deprecated)]
pub fn complete_ik_handshake_for_test<R: RingKeyProvider>(
    client: &NoiseClient<R, ()>,
    server: &NoiseServer<R, ()>,
    server_static_pk: &[u8; 32],
    epoch: u32,
    hint: Option<&str>,
) -> Result<(NoiseLink, NoiseLink, u32, Vec<u8>, IdentityPayload), NoiseError> {
    // Step 1: Client initiates
    let (c_hs, used_epoch, first_msg) =
        client_start_ik_direct(client, server_static_pk, epoch, hint)?;

    // Step 2: Server accepts and prepares response
    let (s_hs, id, response) = server_accept_ik(server, &first_msg)?;

    // Step 3: Both sides complete to get NoiseLinks
    let c_link = client_complete_ik(c_hs, &response)?;
    let s_link = server_complete_ik(s_hs)?;

    Ok((c_link, s_link, used_epoch, first_msg, id))
}

/// Deprecated: Use client_start_ik_direct + server_complete_ik + client_complete_ik instead
/// This function tries to create NoiseLink before handshake is complete
#[deprecated(note = "Use 3-step handshake functions instead")]
/// Server accepts IK handshake (step 2 of 3 for server)
/// Reads client's first message and prepares response
/// Returns (HandshakeState, client identity, response message to send back)
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
