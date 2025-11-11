use crate::{NoiseError, NoiseClient, NoiseServer, NoiseTransport, RingKeyProvider, identity_payload::IdentityPayload};
/// Tiny adapter similar to DataLinkEncryptor.
pub struct NoiseLink { inner: NoiseTransport }
impl NoiseLink {
    pub fn new_from_hs(hs: snow::HandshakeState) -> Result<Self, NoiseError> { Ok(Self { inner: NoiseTransport::from_handshake(hs)? }) }
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> { self.inner.write(plaintext) }
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> { self.inner.read(ciphertext) }
}
pub fn client_start_ik_direct<R: RingKeyProvider>(
    client: &NoiseClient<R, ()>,
    server_static_pub: &[u8;32],
    epoch: u32,
    hint: Option<&str>,
) -> Result<(NoiseLink, u32, Vec<u8>), NoiseError> {
    let (hs, first_msg, used_epoch) = client.build_initiator_ik_direct(server_static_pub, epoch, hint)?;
    let link = NoiseLink::new_from_hs(hs)?;
    Ok((link, used_epoch, first_msg))
}
pub fn server_accept_ik<R: RingKeyProvider>(
    server: &NoiseServer<R, ()>,
    first_msg: &[u8],
) -> Result<(NoiseLink, IdentityPayload), NoiseError> {
    let (hs, id) = server.build_responder_read_ik(first_msg)?;
    let link = NoiseLink::new_from_hs(hs)?;
    Ok((link, id))
}
