use crate::errors::NoiseError;

pub struct NoiseTransport {
    inner: snow::TransportState,
}

impl NoiseTransport {
    pub fn from_handshake(hs: snow::HandshakeState) -> Result<Self, NoiseError> {
        let ts = hs.into_transport_mode()?;
        Ok(Self { inner: ts })
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
}
