use crate::errors::NoiseError;
use crate::ring::RingKeyProvider;
use crate::pkarr::{PkarrResolver, PkarrNoiseRecord, verify_pkarr_binding, verify_pkarr_binding_with_time};
use crate::identity_payload::{IdentityPayload, Role, make_binding_message};
use crate::kdf::{x25519_pk_from_sk};
use zeroize::Zeroize;

/// Client-side Noise initiator that verifies PKARR, binds identity, and produces the first IK message.
pub struct NoiseClient<R: RingKeyProvider, P: PkarrResolver> {
    pub kid: String,
    pub device_id: Vec<u8>,
    pub ring: std::sync::Arc<R>,
    pub pkarr: std::sync::Arc<P>,
    pub prologue: Vec<u8>,
    pub suite: String,
    pub now_unix: Option<u64>,
}

impl<R: RingKeyProvider, P: PkarrResolver> NoiseClient<R, P> {
    pub fn new(kid: impl Into<String>, device_id: impl AsRef<[u8]>, ring: std::sync::Arc<R>, pkarr: std::sync::Arc<P>) -> Self {
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

    pub fn build_initiator_ik(&self, server_id: &str, server_hint: Option<&str>) -> Result<(snow::HandshakeState, Vec<u8>, u32), NoiseError> {
        let rec: PkarrNoiseRecord = self.pkarr.fetch_server_noise_record(server_id)?;
        let server_ed = self.pkarr.fetch_server_ed25519_pub(server_id)?;
        if let Some(now) = self.now_unix {
            verify_pkarr_binding_with_time(&server_ed, &rec, Some(now))?;
        } else {
            verify_pkarr_binding(&server_ed, &rec)?;
        }
        let server_epoch = rec.epoch;

        let mut x_sk = self.ring.derive_device_x25519(&self.kid, &self.device_id, server_epoch)?;
        let x_pk = x25519_pk_from_sk(&x_sk);

        let ed_pub = self.ring.ed25519_pubkey(&self.kid)?;

        let params: snow::params::NoiseParams = self.suite.parse().map_err(|e| NoiseError::Other(e.to_string()))?;
        let mut builder = snow::Builder::new(params);
        let mut hs = builder
            .local_private_key(&x_sk)
            .remote_public_key(&rec.static_x25519_pub)
            .prologue(&self.prologue)
            .build_initiator()?;

        x_sk.zeroize();

        let tag = "IK";
        let msg32 = make_binding_message(
            tag,
            &self.prologue,
            &ed_pub,
            &x_pk,
            Some(&rec.static_x25519_pub),
            server_epoch,
            Role::Client,
            server_hint,
        );

        let sig64 = self.ring.sign_ed25519(&self.kid, &msg32)?;

        let payload = IdentityPayload {
            ed25519_pub: ed_pub,
            noise_x25519_pub: x_pk,
            epoch: server_epoch,
            role: Role::Client,
            server_hint: server_hint.map(|s| s.to_string() ),
            sig: sig64,
        };

        let payload_bytes = serde_json::to_vec(&payload)?;
        let mut out = vec![0u8; payload_bytes.len() + 128];
        let n = hs.write_message(&payload_bytes, &mut out)?;
        out.truncate(n);
        Ok((hs, out, server_epoch))
    }
}
