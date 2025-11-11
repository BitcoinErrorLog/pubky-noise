use crate::errors::NoiseError;
use crate::ring::{RingKeyProvider, RingKeyFiller};
#[cfg(feature="pkarr")] use crate::pkarr::{PkarrResolver, PkarrNoiseRecord, verify_pkarr_binding, verify_pkarr_binding_with_time};
use crate::identity_payload::{IdentityPayload, Role, make_binding_message};
use crate::kdf::{shared_secret_nonzero};
use secrecy::Zeroizing;

pub struct NoiseClient<R: RingKeyProvider, P: crate::pkarr::PkarrResolver> {
    pub kid: String,
    pub device_id: Vec<u8>,
    pub ring: std::sync::Arc<R>,
    #[cfg(feature="pkarr")] pub pkarr: std::sync::Arc<P>,
    pub prologue: Vec<u8>,
    pub suite: String,
    pub now_unix: Option<u64>,
}

impl<R: RingKeyProvider, P: crate::pkarr::PkarrResolver> NoiseClient<R, P> {
    pub fn new_direct(kid: impl Into<String>, device_id: impl AsRef<[u8]>, ring: std::sync::Arc<R>) -> Self {
        Self {
            kid: kid.into(),
            device_id: device_id.as_ref().to_vec(),
            ring,
            #[cfg(feature="pkarr")] pkarr: std::sync::Arc::new(crate::pkarr::DummyPkarr::new()),
            prologue: b"pubky-noise-v1".to_vec(),
            suite: "Noise_IK_25519_ChaChaPoly_BLAKE2s".into(),
            now_unix: None,
        }
    }

    #[cfg(feature="pkarr")]
    pub fn new_with_pkarr(kid: impl Into<String>, device_id: impl AsRef<[u8]>, ring: std::sync::Arc<R>, pkarr: std::sync::Arc<P>) -> Self {
        Self {
            kid: kid.into(),
            device_id: device_id.as_ref().to_vec(),
            ring,
            pkarr,
            prologue: b"pubky-noise-v1".to_vec(),
            suite: "Noise_IK_25519_ChaChaPoly_BLAKE2s".into(),
            now_unix: None,
        }
    }

    pub fn build_initiator_ik_direct(&self, server_static_pub: &[u8;32], epoch: u32, server_hint: Option<&str>)
        -> Result<(snow::HandshakeState, Vec<u8>, u32), NoiseError>
    {
        let mut builder = snow::Builder::new(self.suite.parse().map_err(|e| NoiseError::Other(e.to_string()))?);
        let hs = self.ring.with_device_x25519(&self.kid, &self.device_id, epoch, |x_sk: &Zeroizing<[u8;32]>| {
            if !crate::kdf::shared_secret_nonzero(x_sk, server_static_pub) {
                return Err(NoiseError::InvalidPeerKey);
            }
            builder.local_private_key(x_sk);
            builder.remote_public_key(server_static_pub);
            builder.prologue(&self.prologue);
            builder.build_initiator().map_err(NoiseError::from)
        })?;
        let mut hs = hs?;

        let x_pk = hs.get_local_static().expect("local static").to_vec();
        let mut x_pk_arr = [0u8;32]; x_pk_arr.copy_from_slice(&x_pk[..32]);
        let ed_pub = self.ring.ed25519_pubkey(&self.kid)?;

        let tag = "IK";
        let msg32 = make_binding_message(tag, &self.prologue, &ed_pub, &x_pk_arr, Some(server_static_pub), epoch, Role::Client, server_hint);
        let sig64 = self.ring.sign_ed25519(&self.kid, &msg32)?;

        let payload = IdentityPayload { ed25519_pub: ed_pub, noise_x25519_pub: x_pk_arr, epoch, role: Role::Client, server_hint: server_hint.map(|s| s.to_string()), sig: sig64 };
        let payload_bytes = serde_json::to_vec(&payload)?;
        let mut out = vec![0u8; payload_bytes.len() + 128];
        let n = hs.write_message(&payload_bytes, &mut out)?;
        out.truncate(n);
        Ok((hs, out, epoch))
    }

    #[cfg(feature="pkarr")]
    pub fn build_initiator_ik(&self, server_id: &str, server_hint: Option<&str>) -> Result<(snow::HandshakeState, Vec<u8>, u32), NoiseError> {
        let rec: PkarrNoiseRecord = self.pkarr.fetch_server_noise_record(server_id)?;
        let server_ed = self.pkarr.fetch_server_ed25519_pub(server_id)?;
        if let Some(now) = self.now_unix { verify_pkarr_binding_with_time(&server_ed, &rec, Some(now))?; }
        else { verify_pkarr_binding(&server_ed, &rec)?; }
        self.build_initiator_ik_direct(&rec.static_x25519_pub, rec.epoch, server_hint)
    }

    pub fn build_initiator_xx_tofu(&self, _server_hint: Option<&str>) -> Result<(snow::HandshakeState, Vec<u8>), NoiseError> {
        let suite = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
        let mut builder = snow::Builder::new(suite.parse().map_err(|e| NoiseError::Other(e.to_string()))?);
        let epoch = 0u32;
        let hs = self.ring.with_device_x25519(&self.kid, &self.device_id, epoch, |x_sk| {
            builder.local_private_key(x_sk);
            builder.prologue(&self.prologue);
            builder.build_initiator().map_err(NoiseError::from)
        })?;
        let mut hs = hs?;

        let mut out = vec![0u8; 128];
        let n = hs.write_message(&[], &mut out)?;
        out.truncate(n);
        Ok((hs, out))
    }
}
