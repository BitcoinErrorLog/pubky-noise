#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;

    #[test]
    fn client_server_ik_epoch_roundtrip() {
        // dummy seeds and ids
        let seed_client = [1u8; 32];
        let seed_server = [2u8; 32];
        let device_client = b"iphone-15-pro";
        let device_server = b"homeserver-01";
        let epoch = 7u32;

        let ring_client = std::sync::Arc::new(ring::DummyRing::new_with_device(seed_client, "client-kid", device_client, epoch));
        let ring_server = std::sync::Arc::new(ring::DummyRing::new_with_device(seed_server, "server-kid", device_server, epoch));

        // Prepare PKARR with server record
        let x_sk_srv = kdf::derive_x25519_for_device_epoch(&seed_server, device_server, epoch);
        let x_pk_srv = kdf::x25519_pk_from_sk(&x_sk_srv);
        let ed_pub_server = ring_server.ed25519_pubkey("server-kid").unwrap();
        let mut msg = b"pubky-noise-v1".to_vec();
        msg.extend_from_slice(&epoch.to_le_bytes());
        msg.extend_from_slice(&x_pk_srv);
        let sig = ring_server.sign_ed25519("server-kid", &msg).unwrap();
        let rec = pkarr::PkarrNoiseRecord {
            suite: "Noise_IK_25519_ChaChaPoly_BLAKE2s".into(),
            epoch,
            static_x25519_pub: x_pk_srv,
            ed25519_sig: sig,
            expires_at: None,
        
    #[test]
    fn epoch_mismatch_is_rejected() {
        let seed_client = [1u8; 32];
        let seed_server = [2u8; 32];
        let device_client = b"iphone-15-pro";
        let device_server = b"homeserver-01";
        let epoch_client_view = 7u32;
        let epoch_server_policy = 8u32; // server rotated

        let ring_client = std::sync::Arc::new(ring::DummyRing::new_with_device(seed_client, "client-kid", device_client, epoch_client_view));
        let ring_server = std::sync::Arc::new(ring::DummyRing::new_with_device(seed_server, "server-kid", device_server, epoch_server_policy));

        // PKARR says epoch 7
        let x_sk_srv = kdf::derive_x25519_for_device_epoch(&seed_server, device_server, epoch_client_view);
        let x_pk_srv = kdf::x25519_pk_from_sk(&x_sk_srv);
        let ed_pub_server = ring_server.ed25519_pubkey("server-kid").unwrap();
        let mut msg = b"pubky-noise-v1".to_vec();
        msg.extend_from_slice(&epoch_client_view.to_le_bytes());
        msg.extend_from_slice(&x_pk_srv);
        let sig = ring_server.sign_ed25519("server-kid", &msg).unwrap();
        let rec = pkarr::PkarrNoiseRecord {
            suite: "Noise_IK_25519_ChaChaPoly_BLAKE2s".into(),
            epoch: epoch_client_view,
            static_x25519_pub: x_pk_srv,
            ed25519_sig: sig,
            expires_at: None,
        };
        let mut pkarr = pkarr::DummyPkarr::new();
        pkarr.insert("server-id", ed_pub_server, rec);
        let pkarr = std::sync::Arc::new(pkarr);

        let client = client::NoiseClient::new("client-kid", device_client.as_ref(), ring_client.clone(), pkarr.clone());
        let ( _hs_cli, first_msg, _ ) = client.build_initiator_ik("server-id", Some("example.com")).unwrap();

        let server = server::NoiseServer::new("server-kid", device_server.as_ref(), ring_server.clone(), epoch_server_policy);
        let e = server.build_responder_and_read(&first_msg).unwrap_err();
        match e {
            errors::NoiseError::Policy(s) => assert!(s.contains("not accepted")),
            _ => panic!("expected policy error"),
        }
    }

    #[test]
    fn pkarr_signature_invalid_is_caught() {
        let seed_client = [1u8; 32];
        let seed_server = [2u8; 32];
        let device_client = b"iphone-15-pro";
        let device_server = b"homeserver-01";
        let epoch = 7u32;

        let ring_client = std::sync::Arc::new(ring::DummyRing::new_with_device(seed_client, "client-kid", device_client, epoch));
        let ring_server = std::sync::Arc::new(ring::DummyRing::new_with_device(seed_server, "server-kid", device_server, epoch));

        // PKARR record with WRONG signature
        let x_sk_srv = kdf::derive_x25519_for_device_epoch(&seed_server, device_server, epoch);
        let x_pk_srv = kdf::x25519_pk_from_sk(&x_sk_srv);
        let ed_pub_server = ring_server.ed25519_pubkey("server-kid").unwrap();
        let rec = pkarr::PkarrNoiseRecord {
            suite: "Noise_IK_25519_ChaChaPoly_BLAKE2s".into(),
            epoch,
            static_x25519_pub: x_pk_srv,
            ed25519_sig: [0u8; 64], // invalid
            expires_at: None,
        };
        let mut pkarr = pkarr::DummyPkarr::new();
        pkarr.insert("server-id", ed_pub_server, rec);
        let pkarr = std::sync::Arc::new(pkarr);

        let client = client::NoiseClient::new("client-kid", device_client.as_ref(), ring_client.clone(), pkarr.clone());
        let err = client.build_initiator_ik("server-id", Some("example.com")).unwrap_err();
        match err {
            errors::NoiseError::IdentityVerify => (),
            _ => panic!("expected IdentityVerify due to bad PKARR signature"),
        }
    }

    struct BadSignRing {
        good: ring::DummyRing,
        bad_seed: [u8; 32],
    }
    impl BadSignRing {
        fn new(good_seed: [u8;32], bad_seed: [u8;32], kid: &str, device_id: &[u8], epoch: u32) -> Self {
            Self { good: ring::DummyRing::new_with_device(good_seed, kid.to_string(), device_id, epoch), bad_seed }
        }
    }
    impl ring::RingKeyProvider for BadSignRing {
        fn derive_device_x25519(&self, kid: &str, device_id: &[u8], epoch: u32) -> Result<[u8; 32], errors::NoiseError> {
            self.good.derive_device_x25519(kid, device_id, epoch)
        }
        fn ed25519_pubkey(&self, kid: &str) -> Result<[u8; 32], errors::NoiseError> {
            self.good.ed25519_pubkey(kid)
        }
        fn sign_ed25519(&self, _kid: &str, msg: &[u8]) -> Result<[u8; 64], errors::NoiseError> {
            use ed25519_dalek::{SigningKey, Signer};
            let s = SigningKey::from_bytes(&self.bad_seed);
            Ok(s.sign(msg).to_bytes())
        }
    }

    #[test]
    fn payload_signature_invalid_is_caught() {
        let good_seed_client = [1u8; 32];
        let bad_seed_client = [9u8; 32];
        let seed_server = [2u8; 32];
        let device_client = b"iphone-15-pro";
        let device_server = b"homeserver-01";
        let epoch = 7u32;

        let ring_client = std::sync::Arc::new(BadSignRing::new(good_seed_client, bad_seed_client, "client-kid", device_client, epoch));
        let ring_server = std::sync::Arc::new(ring::DummyRing::new_with_device(seed_server, "server-kid", device_server, epoch));

        // PKARR proper
        let x_sk_srv = kdf::derive_x25519_for_device_epoch(&seed_server, device_server, epoch);
        let x_pk_srv = kdf::x25519_pk_from_sk(&x_sk_srv);
        let ed_pub_server = ring_server.ed25519_pubkey("server-kid").unwrap();
        let mut msg = b"pubky-noise-v1".to_vec();
        msg.extend_from_slice(&epoch.to_le_bytes());
        msg.extend_from_slice(&x_pk_srv);
        let sig = ring_server.sign_ed25519("server-kid", &msg).unwrap();
        let rec = pkarr::PkarrNoiseRecord {
            suite: "Noise_IK_25519_ChaChaPoly_BLAKE2s".into(),
            epoch,
            static_x25519_pub: x_pk_srv,
            ed25519_sig: sig,
            expires_at: None,
        };
        let mut pkarr = pkarr::DummyPkarr::new();
        pkarr.insert("server-id", ed_pub_server, rec);
        let pkarr = std::sync::Arc::new(pkarr);

        let client = client::NoiseClient::new("client-kid", device_client.as_ref(), ring_client.clone(), pkarr.clone());
        let (_hs_cli, first_msg, _) = client.build_initiator_ik("server-id", Some("example.com")).unwrap();

        let server = server::NoiseServer::new("server-kid", device_server.as_ref(), ring_server.clone(), epoch);
        let err = server.build_responder_and_read(&first_msg).unwrap_err();
        match err {
            errors::NoiseError::IdentityVerify => (),
            _ => panic!("expected IdentityVerify due to mismatched payload signature"),
        }
    }

};
        let mut pkarr = pkarr::DummyPkarr::new();
        pkarr.insert("server-id", ed_pub_server, rec);
        let pkarr = std::sync::Arc::new(pkarr);

        // Client builds initiator IK
        let client = client::NoiseClient::new("client-kid", device_client.as_ref(), ring_client.clone(), pkarr.clone());
        let (mut hs_cli, first_msg, used_epoch) = client.build_initiator_ik("server-id", Some("example.com")).unwrap();
        assert_eq!(used_epoch, epoch);

        // Server builds responder and processes first msg
        let server = server::NoiseServer::new("server-kid", device_server.as_ref(), ring_server.clone(), epoch);
        let (mut hs_srv, _payload) = server.build_responder_and_read(&first_msg).unwrap();

        // Server sends second handshake
        let mut out_srv = vec![0u8; 1024];
        let n2 = hs_srv.write_message(&[], &mut out_srv).unwrap();
        out_srv.truncate(n2);

        // Client completes handshake
        let mut out_cli_read = vec![0u8; 1024];
        let _ = hs_cli.read_message(&out_srv, &mut out_cli_read).unwrap();

        // Transport exchange
        let mut t_cli = transport::NoiseTransport::from_handshake(hs_cli).unwrap();
        let mut t_srv = transport::NoiseTransport::from_handshake(hs_srv).unwrap();

        let ct = t_cli.write(b"hello epoch").unwrap();
        let pt = t_srv.read(&ct).unwrap();
        assert_eq!(pt, b"hello epoch");
    
    #[test]
    fn epoch_mismatch_is_rejected() {
        let seed_client = [1u8; 32];
        let seed_server = [2u8; 32];
        let device_client = b"iphone-15-pro";
        let device_server = b"homeserver-01";
        let epoch_client_view = 7u32;
        let epoch_server_policy = 8u32; // server rotated

        let ring_client = std::sync::Arc::new(ring::DummyRing::new_with_device(seed_client, "client-kid", device_client, epoch_client_view));
        let ring_server = std::sync::Arc::new(ring::DummyRing::new_with_device(seed_server, "server-kid", device_server, epoch_server_policy));

        // PKARR says epoch 7
        let x_sk_srv = kdf::derive_x25519_for_device_epoch(&seed_server, device_server, epoch_client_view);
        let x_pk_srv = kdf::x25519_pk_from_sk(&x_sk_srv);
        let ed_pub_server = ring_server.ed25519_pubkey("server-kid").unwrap();
        let mut msg = b"pubky-noise-v1".to_vec();
        msg.extend_from_slice(&epoch_client_view.to_le_bytes());
        msg.extend_from_slice(&x_pk_srv);
        let sig = ring_server.sign_ed25519("server-kid", &msg).unwrap();
        let rec = pkarr::PkarrNoiseRecord {
            suite: "Noise_IK_25519_ChaChaPoly_BLAKE2s".into(),
            epoch: epoch_client_view,
            static_x25519_pub: x_pk_srv,
            ed25519_sig: sig,
            expires_at: None,
        };
        let mut pkarr = pkarr::DummyPkarr::new();
        pkarr.insert("server-id", ed_pub_server, rec);
        let pkarr = std::sync::Arc::new(pkarr);

        let client = client::NoiseClient::new("client-kid", device_client.as_ref(), ring_client.clone(), pkarr.clone());
        let ( _hs_cli, first_msg, _ ) = client.build_initiator_ik("server-id", Some("example.com")).unwrap();

        let server = server::NoiseServer::new("server-kid", device_server.as_ref(), ring_server.clone(), epoch_server_policy);
        let e = server.build_responder_and_read(&first_msg).unwrap_err();
        match e {
            errors::NoiseError::Policy(s) => assert!(s.contains("not accepted")),
            _ => panic!("expected policy error"),
        }
    }

    #[test]
    fn pkarr_signature_invalid_is_caught() {
        let seed_client = [1u8; 32];
        let seed_server = [2u8; 32];
        let device_client = b"iphone-15-pro";
        let device_server = b"homeserver-01";
        let epoch = 7u32;

        let ring_client = std::sync::Arc::new(ring::DummyRing::new_with_device(seed_client, "client-kid", device_client, epoch));
        let ring_server = std::sync::Arc::new(ring::DummyRing::new_with_device(seed_server, "server-kid", device_server, epoch));

        // PKARR record with WRONG signature
        let x_sk_srv = kdf::derive_x25519_for_device_epoch(&seed_server, device_server, epoch);
        let x_pk_srv = kdf::x25519_pk_from_sk(&x_sk_srv);
        let ed_pub_server = ring_server.ed25519_pubkey("server-kid").unwrap();
        let rec = pkarr::PkarrNoiseRecord {
            suite: "Noise_IK_25519_ChaChaPoly_BLAKE2s".into(),
            epoch,
            static_x25519_pub: x_pk_srv,
            ed25519_sig: [0u8; 64], // invalid
            expires_at: None,
        };
        let mut pkarr = pkarr::DummyPkarr::new();
        pkarr.insert("server-id", ed_pub_server, rec);
        let pkarr = std::sync::Arc::new(pkarr);

        let client = client::NoiseClient::new("client-kid", device_client.as_ref(), ring_client.clone(), pkarr.clone());
        let err = client.build_initiator_ik("server-id", Some("example.com")).unwrap_err();
        match err {
            errors::NoiseError::IdentityVerify => (),
            _ => panic!("expected IdentityVerify due to bad PKARR signature"),
        }
    }

    struct BadSignRing {
        good: ring::DummyRing,
        bad_seed: [u8; 32],
    }
    impl BadSignRing {
        fn new(good_seed: [u8;32], bad_seed: [u8;32], kid: &str, device_id: &[u8], epoch: u32) -> Self {
            Self { good: ring::DummyRing::new_with_device(good_seed, kid.to_string(), device_id, epoch), bad_seed }
        }
    }
    impl ring::RingKeyProvider for BadSignRing {
        fn derive_device_x25519(&self, kid: &str, device_id: &[u8], epoch: u32) -> Result<[u8; 32], errors::NoiseError> {
            self.good.derive_device_x25519(kid, device_id, epoch)
        }
        fn ed25519_pubkey(&self, kid: &str) -> Result<[u8; 32], errors::NoiseError> {
            self.good.ed25519_pubkey(kid)
        }
        fn sign_ed25519(&self, _kid: &str, msg: &[u8]) -> Result<[u8; 64], errors::NoiseError> {
            use ed25519_dalek::{SigningKey, Signer};
            let s = SigningKey::from_bytes(&self.bad_seed);
            Ok(s.sign(msg).to_bytes())
        }
    }

    #[test]
    fn payload_signature_invalid_is_caught() {
        let good_seed_client = [1u8; 32];
        let bad_seed_client = [9u8; 32];
        let seed_server = [2u8; 32];
        let device_client = b"iphone-15-pro";
        let device_server = b"homeserver-01";
        let epoch = 7u32;

        let ring_client = std::sync::Arc::new(BadSignRing::new(good_seed_client, bad_seed_client, "client-kid", device_client, epoch));
        let ring_server = std::sync::Arc::new(ring::DummyRing::new_with_device(seed_server, "server-kid", device_server, epoch));

        // PKARR proper
        let x_sk_srv = kdf::derive_x25519_for_device_epoch(&seed_server, device_server, epoch);
        let x_pk_srv = kdf::x25519_pk_from_sk(&x_sk_srv);
        let ed_pub_server = ring_server.ed25519_pubkey("server-kid").unwrap();
        let mut msg = b"pubky-noise-v1".to_vec();
        msg.extend_from_slice(&epoch.to_le_bytes());
        msg.extend_from_slice(&x_pk_srv);
        let sig = ring_server.sign_ed25519("server-kid", &msg).unwrap();
        let rec = pkarr::PkarrNoiseRecord {
            suite: "Noise_IK_25519_ChaChaPoly_BLAKE2s".into(),
            epoch,
            static_x25519_pub: x_pk_srv,
            ed25519_sig: sig,
            expires_at: None,
        };
        let mut pkarr = pkarr::DummyPkarr::new();
        pkarr.insert("server-id", ed_pub_server, rec);
        let pkarr = std::sync::Arc::new(pkarr);

        let client = client::NoiseClient::new("client-kid", device_client.as_ref(), ring_client.clone(), pkarr.clone());
        let (_hs_cli, first_msg, _) = client.build_initiator_ik("server-id", Some("example.com")).unwrap();

        let server = server::NoiseServer::new("server-kid", device_server.as_ref(), ring_server.clone(), epoch);
        let err = server.build_responder_and_read(&first_msg).unwrap_err();
        match err {
            errors::NoiseError::IdentityVerify => (),
            _ => panic!("expected IdentityVerify due to mismatched payload signature"),
        }
    }

}

    #[test]
    fn epoch_mismatch_is_rejected() {
        let seed_client = [1u8; 32];
        let seed_server = [2u8; 32];
        let device_client = b"iphone-15-pro";
        let device_server = b"homeserver-01";
        let epoch_client_view = 7u32;
        let epoch_server_policy = 8u32; // server rotated

        let ring_client = std::sync::Arc::new(ring::DummyRing::new_with_device(seed_client, "client-kid", device_client, epoch_client_view));
        let ring_server = std::sync::Arc::new(ring::DummyRing::new_with_device(seed_server, "server-kid", device_server, epoch_server_policy));

        // PKARR says epoch 7
        let x_sk_srv = kdf::derive_x25519_for_device_epoch(&seed_server, device_server, epoch_client_view);
        let x_pk_srv = kdf::x25519_pk_from_sk(&x_sk_srv);
        let ed_pub_server = ring_server.ed25519_pubkey("server-kid").unwrap();
        let mut msg = b"pubky-noise-v1".to_vec();
        msg.extend_from_slice(&epoch_client_view.to_le_bytes());
        msg.extend_from_slice(&x_pk_srv);
        let sig = ring_server.sign_ed25519("server-kid", &msg).unwrap();
        let rec = pkarr::PkarrNoiseRecord {
            suite: "Noise_IK_25519_ChaChaPoly_BLAKE2s".into(),
            epoch: epoch_client_view,
            static_x25519_pub: x_pk_srv,
            ed25519_sig: sig,
            expires_at: None,
        };
        let mut pkarr = pkarr::DummyPkarr::new();
        pkarr.insert("server-id", ed_pub_server, rec);
        let pkarr = std::sync::Arc::new(pkarr);

        let client = client::NoiseClient::new("client-kid", device_client.as_ref(), ring_client.clone(), pkarr.clone());
        let ( _hs_cli, first_msg, _ ) = client.build_initiator_ik("server-id", Some("example.com")).unwrap();

        let server = server::NoiseServer::new("server-kid", device_server.as_ref(), ring_server.clone(), epoch_server_policy);
        let e = server.build_responder_and_read(&first_msg).unwrap_err();
        match e {
            errors::NoiseError::Policy(s) => assert!(s.contains("not accepted")),
            _ => panic!("expected policy error"),
        }
    }

    #[test]
    fn pkarr_signature_invalid_is_caught() {
        let seed_client = [1u8; 32];
        let seed_server = [2u8; 32];
        let device_client = b"iphone-15-pro";
        let device_server = b"homeserver-01";
        let epoch = 7u32;

        let ring_client = std::sync::Arc::new(ring::DummyRing::new_with_device(seed_client, "client-kid", device_client, epoch));
        let ring_server = std::sync::Arc::new(ring::DummyRing::new_with_device(seed_server, "server-kid", device_server, epoch));

        // PKARR record with WRONG signature
        let x_sk_srv = kdf::derive_x25519_for_device_epoch(&seed_server, device_server, epoch);
        let x_pk_srv = kdf::x25519_pk_from_sk(&x_sk_srv);
        let ed_pub_server = ring_server.ed25519_pubkey("server-kid").unwrap();
        let rec = pkarr::PkarrNoiseRecord {
            suite: "Noise_IK_25519_ChaChaPoly_BLAKE2s".into(),
            epoch,
            static_x25519_pub: x_pk_srv,
            ed25519_sig: [0u8; 64], // invalid
            expires_at: None,
        };
        let mut pkarr = pkarr::DummyPkarr::new();
        pkarr.insert("server-id", ed_pub_server, rec);
        let pkarr = std::sync::Arc::new(pkarr);

        let client = client::NoiseClient::new("client-kid", device_client.as_ref(), ring_client.clone(), pkarr.clone());
        let err = client.build_initiator_ik("server-id", Some("example.com")).unwrap_err();
        match err {
            errors::NoiseError::IdentityVerify => (),
            _ => panic!("expected IdentityVerify due to bad PKARR signature"),
        }
    }

    struct BadSignRing {
        good: ring::DummyRing,
        bad_seed: [u8; 32],
    }
    impl BadSignRing {
        fn new(good_seed: [u8;32], bad_seed: [u8;32], kid: &str, device_id: &[u8], epoch: u32) -> Self {
            Self { good: ring::DummyRing::new_with_device(good_seed, kid.to_string(), device_id, epoch), bad_seed }
        }
    }
    impl ring::RingKeyProvider for BadSignRing {
        fn derive_device_x25519(&self, kid: &str, device_id: &[u8], epoch: u32) -> Result<[u8; 32], errors::NoiseError> {
            self.good.derive_device_x25519(kid, device_id, epoch)
        }
        fn ed25519_pubkey(&self, kid: &str) -> Result<[u8; 32], errors::NoiseError> {
            self.good.ed25519_pubkey(kid)
        }
        fn sign_ed25519(&self, _kid: &str, msg: &[u8]) -> Result<[u8; 64], errors::NoiseError> {
            use ed25519_dalek::{SigningKey, Signer};
            let s = SigningKey::from_bytes(&self.bad_seed);
            Ok(s.sign(msg).to_bytes())
        }
    }

    #[test]
    fn payload_signature_invalid_is_caught() {
        let good_seed_client = [1u8; 32];
        let bad_seed_client = [9u8; 32];
        let seed_server = [2u8; 32];
        let device_client = b"iphone-15-pro";
        let device_server = b"homeserver-01";
        let epoch = 7u32;

        let ring_client = std::sync::Arc::new(BadSignRing::new(good_seed_client, bad_seed_client, "client-kid", device_client, epoch));
        let ring_server = std::sync::Arc::new(ring::DummyRing::new_with_device(seed_server, "server-kid", device_server, epoch));

        // PKARR proper
        let x_sk_srv = kdf::derive_x25519_for_device_epoch(&seed_server, device_server, epoch);
        let x_pk_srv = kdf::x25519_pk_from_sk(&x_sk_srv);
        let ed_pub_server = ring_server.ed25519_pubkey("server-kid").unwrap();
        let mut msg = b"pubky-noise-v1".to_vec();
        msg.extend_from_slice(&epoch.to_le_bytes());
        msg.extend_from_slice(&x_pk_srv);
        let sig = ring_server.sign_ed25519("server-kid", &msg).unwrap();
        let rec = pkarr::PkarrNoiseRecord {
            suite: "Noise_IK_25519_ChaChaPoly_BLAKE2s".into(),
            epoch,
            static_x25519_pub: x_pk_srv,
            ed25519_sig: sig,
            expires_at: None,
        };
        let mut pkarr = pkarr::DummyPkarr::new();
        pkarr.insert("server-id", ed_pub_server, rec);
        let pkarr = std::sync::Arc::new(pkarr);

        let client = client::NoiseClient::new("client-kid", device_client.as_ref(), ring_client.clone(), pkarr.clone());
        let (_hs_cli, first_msg, _) = client.build_initiator_ik("server-id", Some("example.com")).unwrap();

        let server = server::NoiseServer::new("server-kid", device_server.as_ref(), ring_server.clone(), epoch);
        let err = server.build_responder_and_read(&first_msg).unwrap_err();
        match err {
            errors::NoiseError::IdentityVerify => (),
            _ => panic!("expected IdentityVerify due to mismatched payload signature"),
        }
    }

}
