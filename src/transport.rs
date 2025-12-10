use crate::errors::NoiseError;
use crate::session_id::SessionId;

pub struct NoiseTransport {
    inner: snow::TransportState,
    session_id: SessionId,
}

impl NoiseTransport {
    pub fn from_handshake(hs: snow::HandshakeState) -> Result<Self, NoiseError> {
        let session_id = SessionId::from_handshake(&hs)?;
        Ok(Self {
            inner: hs.into_transport_mode()?,
            session_id,
        })
    }
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }
    pub fn write(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let mut out = vec![0u8; plaintext.len() + 64];
        let n = self.inner.write_message(plaintext, &mut out)?;
        out.truncate(n);
        Ok(out)
    }
    pub fn read(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let mut out = vec![0u8; ciphertext.len() + 64];
        let n = self.inner.read_message(ciphertext, &mut out)?;
        out.truncate(n);
        Ok(out)
    }
    pub fn export_session_tag(hs: &snow::HandshakeState) -> Result<[u8; 32], NoiseError> {
        // Use handshake hash as session tag (available in Snow 0.9)
        let hash = hs.get_handshake_hash();
        let mut out = [0u8; 32];
        out.copy_from_slice(hash);
        Ok(out)
    }
}
