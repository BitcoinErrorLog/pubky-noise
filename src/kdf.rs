use sha2::{Sha512, Digest};
use hkdf::Hkdf;
use x25519_dalek::{PublicKey, StaticSecret};
use secrecy::Zeroizing;

pub fn derive_x25519_for_device_epoch(seed: &[u8; 32], device_id: &[u8], epoch: u32) -> [u8; 32] {
    let salt = b"pubky-noise-x25519:v1";
    let hk = Hkdf::<Sha512>::new(Some(salt), seed);
    let mut info = Vec::with_capacity(device_id.len() + 4);
    info.extend_from_slice(device_id);
    info.extend_from_slice(&epoch.to_le_bytes());
    let mut sk = [0u8; 32];
    hk.expand(&info, &mut sk).expect("hkdf expand");
    sk[0] &= 248; sk[31] &= 127; sk[31] |= 64;
    sk
}
pub fn x25519_pk_from_sk(sk: &[u8; 32]) -> [u8; 32] {
    let sec = StaticSecret::from(*sk);
    let pubk = PublicKey::from(&sec);
    pubk.to_bytes()
}
pub fn shared_secret_nonzero(local_sk:&Zeroizing<[u8;32]>, peer_pk:&[u8;32]) -> bool {
    let sec = StaticSecret::from(**local_sk);
    let pk = PublicKey::from(*peer_pk);
    let shared = sec.diffie_hellman(&pk).to_bytes();
    let mut acc: u8 = 0;
    for b in shared { acc |= b; }
    acc != 0
}
