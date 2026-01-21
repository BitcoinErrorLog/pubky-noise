//! Sealed Blob v2 (SB2) Binary Wire Format
//!
//! Implements the binary wire format per PUBKY_CRYPTO_SPEC v2.5 Section 7.2.
//!
//! Wire Format:
//! ```text
//! magic: 0x53 0x42 0x32 ("SB2", 3 bytes)
//! version: u8 (2)
//! header_len: u16 (big-endian, MUST be <= 2048 bytes)
//! header_bytes: [u8; header_len] (deterministic CBOR, see 7.12)
//! ciphertext: [u8] (remainder, includes 16-byte Poly1305 tag)
//! ```

use crate::errors::NoiseError;
use crate::sealed_blob::{
    x25519_generate_keypair, x25519_public_from_secret, MAX_PLAINTEXT_SIZE,
};
use blake3::Hasher;
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::x25519;
use zeroize::Zeroizing;

/// SB2 magic bytes: "SB2"
pub const SB2_MAGIC: &[u8; 3] = b"SB2";

/// SB2 version number
pub const SB2_VERSION: u8 = 2;

/// Maximum header length per PUBKY_CRYPTO_SPEC (DoS prevention)
pub const MAX_HEADER_LEN: usize = 2048;

/// Maximum CBOR nesting depth
pub const MAX_CBOR_DEPTH: usize = 2;

/// Maximum CBOR top-level keys
pub const MAX_CBOR_KEYS: usize = 16;

/// Maximum msg_id length (characters)
pub const MAX_MSG_ID_LEN: usize = 128;

/// HKDF info string for v2 key derivation
const HKDF_INFO_V2: &[u8] = b"pubky-envelope/v2";

/// AAD prefix per PUBKY_CRYPTO_SPEC Section 7.5
pub const AAD_PREFIX: &[u8] = b"pubky-envelope/v2:";

/// Signature input prefix per PUBKY_CRYPTO_SPEC Section 7.2.1
pub const SIG_PREFIX: &[u8] = b"pubky-envelope-sig/v2";

/// SB2 Header using deterministic CBOR with integer keys.
///
/// Per PUBKY_CRYPTO_SPEC v2.5 Section 7.2:
/// | Key | Field Name | Type | Required |
/// |-----|------------|------|----------|
/// | 0 | context_id | bytes(32) | REQUIRED (Paykit) |
/// | 1 | created_at | uint | RECOMMENDED |
/// | 2 | expires_at | uint | REQUIRED (Paykit) |
/// | 3 | inbox_kid | bytes(16) | REQUIRED |
/// | 4 | msg_id | text | REQUIRED (Paykit) |
/// | 5 | nonce | bytes(24) | REQUIRED |
/// | 6 | purpose | text | Optional |
/// | 7 | recipient_peerid | bytes(32) | REQUIRED |
/// | 8 | sender_ephemeral_pub | bytes(32) | REQUIRED |
/// | 9 | sender_peerid | bytes(32) | REQUIRED |
/// | 10 | sig | bytes(64) | REQUIRED (Paykit) |
/// | 11 | cert_id | bytes(16) | Optional (for AppKey) |
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sb2Header {
    /// Thread identifier (32 random bytes)
    pub context_id: [u8; 32],
    /// Unix timestamp (seconds) when created
    pub created_at: Option<u64>,
    /// Unix timestamp (seconds) when expires
    pub expires_at: Option<u64>,
    /// Key identifier for recipient InboxKey (16 bytes)
    pub inbox_kid: [u8; 16],
    /// Idempotency key (ASCII, max 128 chars)
    pub msg_id: Option<String>,
    /// XChaCha20-Poly1305 nonce (24 bytes)
    pub nonce: [u8; 24],
    /// Purpose hint (e.g., "request", "proposal", "ack")
    pub purpose: Option<String>,
    /// Recipient's Ed25519 public key (32 bytes)
    pub recipient_peerid: [u8; 32],
    /// Sender's ephemeral X25519 public key (32 bytes)
    pub sender_ephemeral_pub: [u8; 32],
    /// Sender's Ed25519 public key (32 bytes)
    pub sender_peerid: [u8; 32],
    /// Ed25519 signature (64 bytes) - optional during construction
    pub sig: Option<[u8; 64]>,
    /// AppCert identifier (16 bytes) - for delegated signing
    pub cert_id: Option<[u8; 16]>,
}

impl Sb2Header {
    /// Compute inbox_kid from recipient's InboxKey public key.
    ///
    /// Per PUBKY_CRYPTO_SPEC v2.5 Section 7.2:
    /// ```text
    /// inbox_kid = first_16_bytes(SHA256(recipient_inbox_x25519_pub))
    /// ```
    pub fn compute_inbox_kid(recipient_inbox_pk: &[u8; 32]) -> [u8; 16] {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(recipient_inbox_pk);
        let mut kid = [0u8; 16];
        kid.copy_from_slice(&hash[..16]);
        kid
    }

    /// Encode header to deterministic CBOR bytes (without signature).
    ///
    /// This produces `header_no_sig` used for signature input and AAD.
    pub fn encode_no_sig(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        encode_header_no_sig(&mut buf, self);
        buf
    }

    /// Encode header to deterministic CBOR bytes (with signature if present).
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(320);
        encode_header_full(&mut buf, self);
        buf
    }

    /// Decode header from CBOR bytes.
    pub fn decode(data: &[u8]) -> Result<Self, NoiseError> {
        decode_header(data)
    }
}

/// CBOR encoder helper - writes to a Vec<u8>
struct CborWriter<'a> {
    buf: &'a mut Vec<u8>,
}

impl<'a> CborWriter<'a> {
    fn new(buf: &'a mut Vec<u8>) -> Self {
        Self { buf }
    }

    fn write_map(&mut self, len: u64) {
        if len < 24 {
            self.buf.push(0xa0 + len as u8);
        } else if len < 256 {
            self.buf.push(0xb8);
            self.buf.push(len as u8);
        } else {
            self.buf.push(0xb9);
            self.buf.extend_from_slice(&(len as u16).to_be_bytes());
        }
    }

    fn write_uint(&mut self, val: u64) {
        if val < 24 {
            self.buf.push(val as u8);
        } else if val < 256 {
            self.buf.push(0x18);
            self.buf.push(val as u8);
        } else if val < 65536 {
            self.buf.push(0x19);
            self.buf.extend_from_slice(&(val as u16).to_be_bytes());
        } else if val < 0x100000000 {
            self.buf.push(0x1a);
            self.buf.extend_from_slice(&(val as u32).to_be_bytes());
        } else {
            self.buf.push(0x1b);
            self.buf.extend_from_slice(&val.to_be_bytes());
        }
    }

    fn write_bytes(&mut self, data: &[u8]) {
        let len = data.len();
        if len < 24 {
            self.buf.push(0x40 + len as u8);
        } else if len < 256 {
            self.buf.push(0x58);
            self.buf.push(len as u8);
        } else {
            self.buf.push(0x59);
            self.buf.extend_from_slice(&(len as u16).to_be_bytes());
        }
        self.buf.extend_from_slice(data);
    }

    fn write_str(&mut self, s: &str) {
        let data = s.as_bytes();
        let len = data.len();
        if len < 24 {
            self.buf.push(0x60 + len as u8);
        } else if len < 256 {
            self.buf.push(0x78);
            self.buf.push(len as u8);
        } else {
            self.buf.push(0x79);
            self.buf.extend_from_slice(&(len as u16).to_be_bytes());
        }
        self.buf.extend_from_slice(data);
    }
}

/// Encode header without signature (for AAD and signature input).
fn encode_header_no_sig(buf: &mut Vec<u8>, header: &Sb2Header) {
    let mut w = CborWriter::new(buf);

    let field_count = count_fields_no_sig(header);
    w.write_map(field_count);

    // Fields MUST be in numeric key order per deterministic CBOR
    // Key 0: context_id
    w.write_uint(0);
    w.write_bytes(&header.context_id);

    // Key 1: created_at (optional)
    if let Some(created_at) = header.created_at {
        w.write_uint(1);
        w.write_uint(created_at);
    }

    // Key 2: expires_at (optional)
    if let Some(expires_at) = header.expires_at {
        w.write_uint(2);
        w.write_uint(expires_at);
    }

    // Key 3: inbox_kid
    w.write_uint(3);
    w.write_bytes(&header.inbox_kid);

    // Key 4: msg_id (optional)
    if let Some(ref msg_id) = header.msg_id {
        w.write_uint(4);
        w.write_str(msg_id);
    }

    // Key 5: nonce
    w.write_uint(5);
    w.write_bytes(&header.nonce);

    // Key 6: purpose (optional)
    if let Some(ref purpose) = header.purpose {
        w.write_uint(6);
        w.write_str(purpose);
    }

    // Key 7: recipient_peerid
    w.write_uint(7);
    w.write_bytes(&header.recipient_peerid);

    // Key 8: sender_ephemeral_pub
    w.write_uint(8);
    w.write_bytes(&header.sender_ephemeral_pub);

    // Key 9: sender_peerid
    w.write_uint(9);
    w.write_bytes(&header.sender_peerid);

    // Key 10: sig - EXCLUDED for header_no_sig

    // Key 11: cert_id (optional)
    if let Some(ref cert_id) = header.cert_id {
        w.write_uint(11);
        w.write_bytes(cert_id);
    }
}

/// Encode header with signature.
fn encode_header_full(buf: &mut Vec<u8>, header: &Sb2Header) {
    let mut w = CborWriter::new(buf);

    let field_count = count_fields_full(header);
    w.write_map(field_count);

    // Fields MUST be in numeric key order
    w.write_uint(0);
    w.write_bytes(&header.context_id);

    if let Some(created_at) = header.created_at {
        w.write_uint(1);
        w.write_uint(created_at);
    }

    if let Some(expires_at) = header.expires_at {
        w.write_uint(2);
        w.write_uint(expires_at);
    }

    w.write_uint(3);
    w.write_bytes(&header.inbox_kid);

    if let Some(ref msg_id) = header.msg_id {
        w.write_uint(4);
        w.write_str(msg_id);
    }

    w.write_uint(5);
    w.write_bytes(&header.nonce);

    if let Some(ref purpose) = header.purpose {
        w.write_uint(6);
        w.write_str(purpose);
    }

    w.write_uint(7);
    w.write_bytes(&header.recipient_peerid);

    w.write_uint(8);
    w.write_bytes(&header.sender_ephemeral_pub);

    w.write_uint(9);
    w.write_bytes(&header.sender_peerid);

    // Key 10: sig (if present)
    if let Some(ref sig) = header.sig {
        w.write_uint(10);
        w.write_bytes(sig);
    }

    if let Some(ref cert_id) = header.cert_id {
        w.write_uint(11);
        w.write_bytes(cert_id);
    }
}

fn count_fields_no_sig(header: &Sb2Header) -> u64 {
    let mut count: u64 = 6; // Required: context_id, inbox_kid, nonce, recipient_peerid, sender_ephemeral_pub, sender_peerid
    if header.created_at.is_some() { count += 1; }
    if header.expires_at.is_some() { count += 1; }
    if header.msg_id.is_some() { count += 1; }
    if header.purpose.is_some() { count += 1; }
    if header.cert_id.is_some() { count += 1; }
    count
}

fn count_fields_full(header: &Sb2Header) -> u64 {
    let mut count = count_fields_no_sig(header);
    if header.sig.is_some() { count += 1; }
    count
}

/// CBOR decoder helper
struct CborReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> CborReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    #[allow(dead_code)]
    fn peek(&self) -> Result<u8, NoiseError> {
        if self.pos >= self.data.len() {
            return Err(NoiseError::Decryption("CBOR: unexpected end of data".into()));
        }
        Ok(self.data[self.pos])
    }

    fn read_u8(&mut self) -> Result<u8, NoiseError> {
        if self.pos >= self.data.len() {
            return Err(NoiseError::Decryption("CBOR: unexpected end of data".into()));
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn read_argument(&mut self, additional: u8) -> Result<u64, NoiseError> {
        if additional < 24 {
            Ok(additional as u64)
        } else if additional == 24 {
            Ok(self.read_u8()? as u64)
        } else if additional == 25 {
            if self.remaining() < 2 {
                return Err(NoiseError::Decryption("CBOR: truncated u16".into()));
            }
            let val = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
            self.pos += 2;
            Ok(val as u64)
        } else if additional == 26 {
            if self.remaining() < 4 {
                return Err(NoiseError::Decryption("CBOR: truncated u32".into()));
            }
            let val = u32::from_be_bytes([
                self.data[self.pos],
                self.data[self.pos + 1],
                self.data[self.pos + 2],
                self.data[self.pos + 3],
            ]);
            self.pos += 4;
            Ok(val as u64)
        } else if additional == 27 {
            if self.remaining() < 8 {
                return Err(NoiseError::Decryption("CBOR: truncated u64".into()));
            }
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&self.data[self.pos..self.pos + 8]);
            self.pos += 8;
            Ok(u64::from_be_bytes(bytes))
        } else {
            Err(NoiseError::Decryption(format!("CBOR: invalid additional info {}", additional)))
        }
    }

    fn read_uint(&mut self) -> Result<u64, NoiseError> {
        let byte = self.read_u8()?;
        let major = byte >> 5;
        let additional = byte & 0x1f;
        if major != 0 {
            return Err(NoiseError::Decryption(format!("CBOR: expected uint, got major type {}", major)));
        }
        self.read_argument(additional)
    }

    fn read_map_len(&mut self) -> Result<u64, NoiseError> {
        let byte = self.read_u8()?;
        let major = byte >> 5;
        let additional = byte & 0x1f;
        if major != 5 {
            return Err(NoiseError::Decryption(format!("CBOR: expected map, got major type {}", major)));
        }
        if additional == 31 {
            return Err(NoiseError::Decryption("CBOR: indefinite-length map not allowed".into()));
        }
        self.read_argument(additional)
    }

    fn read_bytes(&mut self) -> Result<&'a [u8], NoiseError> {
        let byte = self.read_u8()?;
        let major = byte >> 5;
        let additional = byte & 0x1f;
        if major != 2 {
            return Err(NoiseError::Decryption(format!("CBOR: expected bytes, got major type {}", major)));
        }
        let len = self.read_argument(additional)? as usize;
        if self.remaining() < len {
            return Err(NoiseError::Decryption("CBOR: truncated bytes".into()));
        }
        let bytes = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(bytes)
    }

    fn read_str(&mut self) -> Result<&'a str, NoiseError> {
        let byte = self.read_u8()?;
        let major = byte >> 5;
        let additional = byte & 0x1f;
        if major != 3 {
            return Err(NoiseError::Decryption(format!("CBOR: expected text, got major type {}", major)));
        }
        let len = self.read_argument(additional)? as usize;
        if self.remaining() < len {
            return Err(NoiseError::Decryption("CBOR: truncated text".into()));
        }
        let bytes = &self.data[self.pos..self.pos + len];
        self.pos += len;
        std::str::from_utf8(bytes).map_err(|_| NoiseError::Decryption("CBOR: invalid UTF-8 in text".into()))
    }

    fn skip_value(&mut self) -> Result<(), NoiseError> {
        let byte = self.read_u8()?;
        let major = byte >> 5;
        let additional = byte & 0x1f;

        match major {
            0 | 1 => {
                // unsigned/negative integer
                let _ = self.read_argument(additional)?;
            }
            2 | 3 => {
                // bytes or text
                let len = self.read_argument(additional)? as usize;
                if self.remaining() < len {
                    return Err(NoiseError::Decryption("CBOR: truncated during skip".into()));
                }
                self.pos += len;
            }
            4 => {
                // array
                let len = self.read_argument(additional)?;
                for _ in 0..len {
                    self.skip_value()?;
                }
            }
            5 => {
                // map
                let len = self.read_argument(additional)?;
                for _ in 0..len {
                    self.skip_value()?;
                    self.skip_value()?;
                }
            }
            7 => {
                // simple/float
                let _ = self.read_argument(additional)?;
            }
            _ => {
                return Err(NoiseError::Decryption(format!("CBOR: unsupported major type {}", major)));
            }
        }
        Ok(())
    }
}

/// Decode header from CBOR bytes.
fn decode_header(data: &[u8]) -> Result<Sb2Header, NoiseError> {
    let mut r = CborReader::new(data);

    let map_len = r.read_map_len()?;
    if map_len > MAX_CBOR_KEYS as u64 {
        return Err(NoiseError::Decryption(format!("CBOR map has {} keys, max is {}", map_len, MAX_CBOR_KEYS)));
    }

    let mut header = Sb2Header {
        context_id: [0u8; 32],
        created_at: None,
        expires_at: None,
        inbox_kid: [0u8; 16],
        msg_id: None,
        nonce: [0u8; 24],
        purpose: None,
        recipient_peerid: [0u8; 32],
        sender_ephemeral_pub: [0u8; 32],
        sender_peerid: [0u8; 32],
        sig: None,
        cert_id: None,
    };

    let mut seen_required: u8 = 0;
    const REQUIRED_MASK: u8 = 0b00111111; // context_id, inbox_kid, nonce, recipient, sender_eph, sender_peerid

    for _ in 0..map_len {
        let key = r.read_uint()? as u8;

        match key {
            0 => {
                let bytes = r.read_bytes()?;
                if bytes.len() != 32 {
                    return Err(NoiseError::Decryption(format!("context_id must be 32 bytes, got {}", bytes.len())));
                }
                header.context_id.copy_from_slice(bytes);
                seen_required |= 0b000001;
            }
            1 => {
                header.created_at = Some(r.read_uint()?);
            }
            2 => {
                header.expires_at = Some(r.read_uint()?);
            }
            3 => {
                let bytes = r.read_bytes()?;
                if bytes.len() != 16 {
                    return Err(NoiseError::Decryption(format!("inbox_kid must be 16 bytes, got {}", bytes.len())));
                }
                header.inbox_kid.copy_from_slice(bytes);
                seen_required |= 0b000010;
            }
            4 => {
                let s = r.read_str()?;
                if s.len() > MAX_MSG_ID_LEN {
                    return Err(NoiseError::Decryption(format!("msg_id exceeds {} chars", MAX_MSG_ID_LEN)));
                }
                if !s.is_ascii() {
                    return Err(NoiseError::Decryption("msg_id must be ASCII".into()));
                }
                header.msg_id = Some(s.to_string());
            }
            5 => {
                let bytes = r.read_bytes()?;
                if bytes.len() != 24 {
                    return Err(NoiseError::Decryption(format!("nonce must be 24 bytes, got {}", bytes.len())));
                }
                header.nonce.copy_from_slice(bytes);
                seen_required |= 0b000100;
            }
            6 => {
                let s = r.read_str()?;
                header.purpose = Some(s.to_string());
            }
            7 => {
                let bytes = r.read_bytes()?;
                if bytes.len() != 32 {
                    return Err(NoiseError::Decryption(format!("recipient_peerid must be 32 bytes, got {}", bytes.len())));
                }
                header.recipient_peerid.copy_from_slice(bytes);
                seen_required |= 0b001000;
            }
            8 => {
                let bytes = r.read_bytes()?;
                if bytes.len() != 32 {
                    return Err(NoiseError::Decryption(format!("sender_ephemeral_pub must be 32 bytes, got {}", bytes.len())));
                }
                header.sender_ephemeral_pub.copy_from_slice(bytes);
                seen_required |= 0b010000;
            }
            9 => {
                let bytes = r.read_bytes()?;
                if bytes.len() != 32 {
                    return Err(NoiseError::Decryption(format!("sender_peerid must be 32 bytes, got {}", bytes.len())));
                }
                header.sender_peerid.copy_from_slice(bytes);
                seen_required |= 0b100000;
            }
            10 => {
                let bytes = r.read_bytes()?;
                if bytes.len() != 64 {
                    return Err(NoiseError::Decryption(format!("sig must be 64 bytes, got {}", bytes.len())));
                }
                let mut sig = [0u8; 64];
                sig.copy_from_slice(bytes);
                header.sig = Some(sig);
            }
            11 => {
                let bytes = r.read_bytes()?;
                if bytes.len() != 16 {
                    return Err(NoiseError::Decryption(format!("cert_id must be 16 bytes, got {}", bytes.len())));
                }
                let mut cert_id = [0u8; 16];
                cert_id.copy_from_slice(bytes);
                header.cert_id = Some(cert_id);
            }
            _ => {
                // Skip unknown keys (forward compatibility)
                r.skip_value()?;
            }
        }
    }

    if seen_required != REQUIRED_MASK {
        return Err(NoiseError::Decryption("Missing required header fields".into()));
    }

    Ok(header)
}

/// Build AAD bytes per PUBKY_CRYPTO_SPEC Section 7.5.
///
/// ```text
/// aad = aad_prefix || owner_peerid_bytes || canonical_path_bytes || header_bytes
/// ```
///
/// Where `header_bytes` is `header_no_sig` (without signature field).
pub fn build_aad(
    owner_peerid: &[u8; 32],
    canonical_path: &str,
    header_no_sig: &[u8],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        AAD_PREFIX.len() + 32 + canonical_path.len() + header_no_sig.len()
    );
    aad.extend_from_slice(AAD_PREFIX);
    aad.extend_from_slice(owner_peerid);
    aad.extend_from_slice(canonical_path.as_bytes());
    aad.extend_from_slice(header_no_sig);
    aad
}

/// Compute signature input per PUBKY_CRYPTO_SPEC Section 7.2.1.
///
/// ```text
/// sig_input = BLAKE3("pubky-envelope-sig/v2" || aad || header_no_sig || ciphertext)
/// ```
pub fn compute_sig_input(aad: &[u8], header_no_sig: &[u8], ciphertext: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(SIG_PREFIX);
    hasher.update(aad);
    hasher.update(header_no_sig);
    hasher.update(ciphertext);
    *hasher.finalize().as_bytes()
}

/// Derive symmetric key from shared secret (v2).
fn derive_symmetric_key(
    shared_secret: &[u8; 32],
    ephemeral_pk: &[u8; 32],
    recipient_pk: &[u8; 32],
) -> Zeroizing<[u8; 32]> {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(ephemeral_pk);
    salt[32..].copy_from_slice(recipient_pk);

    let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_INFO_V2, key.as_mut())
        .expect("HKDF expand with 32-byte output should never fail");
    key
}

/// XChaCha20-Poly1305 encrypt with AAD.
fn xchacha_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    plaintext: &[u8],
    aad: &[u8],
) -> Vec<u8> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::XChaCha20Poly1305;

    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(nonce.into(), Payload { msg: plaintext, aad })
        .expect("XChaCha20Poly1305 encryption should never fail")
}

/// XChaCha20-Poly1305 decrypt with AAD.
fn xchacha_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, NoiseError> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::XChaCha20Poly1305;

    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(nonce.into(), Payload { msg: ciphertext, aad })
        .map_err(|_| NoiseError::Decryption("XChaCha20Poly1305 decryption failed".into()))
}

/// SB2 Sealed Blob binary format.
#[derive(Debug, Clone)]
pub struct Sb2 {
    /// Header (includes all metadata)
    pub header: Sb2Header,
    /// Encrypted ciphertext (includes Poly1305 tag)
    pub ciphertext: Vec<u8>,
}

impl Sb2 {
    /// Check if bytes start with SB2 magic.
    pub fn is_sb2(data: &[u8]) -> bool {
        data.len() >= 3 && &data[..3] == SB2_MAGIC
    }

    /// Encode to binary wire format.
    ///
    /// Returns: magic (3) + version (1) + header_len (2) + header + ciphertext
    pub fn encode(&self) -> Vec<u8> {
        let header_bytes = self.header.encode();
        let header_len = header_bytes.len();

        let mut output = Vec::with_capacity(6 + header_len + self.ciphertext.len());
        output.extend_from_slice(SB2_MAGIC);
        output.push(SB2_VERSION);
        output.extend_from_slice(&(header_len as u16).to_be_bytes());
        output.extend_from_slice(&header_bytes);
        output.extend_from_slice(&self.ciphertext);
        output
    }

    /// Decode from binary wire format.
    pub fn decode(data: &[u8]) -> Result<Self, NoiseError> {
        if data.len() < 6 {
            return Err(NoiseError::Decryption("SB2 too short".into()));
        }

        // Check magic
        if &data[..3] != SB2_MAGIC {
            return Err(NoiseError::Decryption("Invalid SB2 magic".into()));
        }

        // Check version
        let version = data[3];
        if version != SB2_VERSION {
            return Err(NoiseError::Decryption(format!("Unsupported SB2 version: {}", version)));
        }

        // Read header length (big-endian u16)
        let header_len = u16::from_be_bytes([data[4], data[5]]) as usize;
        if header_len > MAX_HEADER_LEN {
            return Err(NoiseError::Decryption(format!("SB2 header_len {} exceeds max {}", header_len, MAX_HEADER_LEN)));
        }

        if data.len() < 6 + header_len {
            return Err(NoiseError::Decryption("SB2 truncated: header incomplete".into()));
        }

        let header_bytes = &data[6..6 + header_len];
        let ciphertext = data[6 + header_len..].to_vec();

        let header = Sb2Header::decode(header_bytes)?;

        Ok(Sb2 { header, ciphertext })
    }

    /// Encrypt plaintext to SB2 binary format (without signature).
    ///
    /// For messages requiring sender authentication, call `sign()` after encryption.
    pub fn encrypt(
        recipient_inbox_pk: &[u8; 32],
        plaintext: &[u8],
        context_id: [u8; 32],
        msg_id: Option<String>,
        purpose: Option<String>,
        owner_peerid: &[u8; 32],
        sender_peerid: &[u8; 32],
        recipient_peerid: &[u8; 32],
        canonical_path: &str,
        created_at: Option<u64>,
        expires_at: Option<u64>,
    ) -> Result<Self, NoiseError> {
        Self::encrypt_with_cert_id(
            recipient_inbox_pk,
            plaintext,
            context_id,
            msg_id,
            purpose,
            owner_peerid,
            sender_peerid,
            recipient_peerid,
            canonical_path,
            created_at,
            expires_at,
            None,
        )
    }

    /// Encrypt with optional cert_id for delegated signing.
    ///
    /// Same as `encrypt`, but allows specifying a `cert_id` for AppKey-based signing.
    /// The `cert_id` is included in the AAD, so it must be set before encryption
    /// if the message will be signed with an AppKey.
    pub fn encrypt_with_cert_id(
        recipient_inbox_pk: &[u8; 32],
        plaintext: &[u8],
        context_id: [u8; 32],
        msg_id: Option<String>,
        purpose: Option<String>,
        owner_peerid: &[u8; 32],
        sender_peerid: &[u8; 32],
        recipient_peerid: &[u8; 32],
        canonical_path: &str,
        created_at: Option<u64>,
        expires_at: Option<u64>,
        cert_id: Option<[u8; 16]>,
    ) -> Result<Self, NoiseError> {
        if plaintext.len() > MAX_PLAINTEXT_SIZE {
            return Err(NoiseError::Other(format!(
                "Plaintext {} bytes exceeds max {}",
                plaintext.len(),
                MAX_PLAINTEXT_SIZE
            )));
        }

        // Validate msg_id if present
        if let Some(ref id) = msg_id {
            if id.len() > MAX_MSG_ID_LEN {
                return Err(NoiseError::Other(format!("msg_id exceeds {} chars", MAX_MSG_ID_LEN)));
            }
            if !id.is_ascii() {
                return Err(NoiseError::Other("msg_id must be ASCII".into()));
            }
        }

        // Generate ephemeral keypair
        let (ephemeral_sk, ephemeral_pk) = x25519_generate_keypair();
        let ephemeral_sk = Zeroizing::new(ephemeral_sk);

        // Compute shared secret
        let shared_secret = Zeroizing::new(x25519(*ephemeral_sk, *recipient_inbox_pk));

        // Derive symmetric key
        let key = derive_symmetric_key(&shared_secret, &ephemeral_pk, recipient_inbox_pk);

        // Generate random nonce
        let mut nonce = [0u8; 24];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);

        // Compute inbox_kid
        let inbox_kid = Sb2Header::compute_inbox_kid(recipient_inbox_pk);

        // Build header (without signature)
        let header = Sb2Header {
            context_id,
            created_at,
            expires_at,
            inbox_kid,
            msg_id,
            nonce,
            purpose,
            recipient_peerid: *recipient_peerid,
            sender_ephemeral_pub: ephemeral_pk,
            sender_peerid: *sender_peerid,
            sig: None,
            cert_id,
        };

        // Encode header_no_sig for AAD
        let header_no_sig = header.encode_no_sig();

        // Build AAD
        let aad = build_aad(owner_peerid, canonical_path, &header_no_sig);

        // Encrypt
        let ciphertext = xchacha_encrypt(&key, &nonce, plaintext, &aad);

        Ok(Sb2 { header, ciphertext })
    }

    /// Sign the SB2 with sender's Ed25519 private key.
    ///
    /// Per PUBKY_CRYPTO_SPEC Section 7.2.1:
    /// ```text
    /// sig_input = BLAKE3("pubky-envelope-sig/v2" || aad || header_no_sig || ciphertext)
    /// ```
    pub fn sign(
        &mut self,
        sender_sk: &ed25519_dalek::SigningKey,
        owner_peerid: &[u8; 32],
        canonical_path: &str,
    ) {
        use ed25519_dalek::Signer;

        let header_no_sig = self.header.encode_no_sig();
        let aad = build_aad(owner_peerid, canonical_path, &header_no_sig);
        let sig_input = compute_sig_input(&aad, &header_no_sig, &self.ciphertext);

        let sig = sender_sk.sign(&sig_input);
        self.header.sig = Some(sig.to_bytes());
    }

    /// Decrypt SB2 binary format.
    pub fn decrypt(
        &self,
        recipient_inbox_sk: &[u8; 32],
        owner_peerid: &[u8; 32],
        canonical_path: &str,
    ) -> Result<Vec<u8>, NoiseError> {
        // Compute recipient public key
        let recipient_inbox_pk = x25519_public_from_secret(recipient_inbox_sk);

        // Verify inbox_kid matches
        let expected_kid = Sb2Header::compute_inbox_kid(&recipient_inbox_pk);
        if self.header.inbox_kid != expected_kid {
            return Err(NoiseError::Decryption("inbox_kid mismatch - key not found".into()));
        }

        // Compute shared secret
        let shared_secret = Zeroizing::new(x25519(*recipient_inbox_sk, self.header.sender_ephemeral_pub));

        // Derive symmetric key
        let key = derive_symmetric_key(&shared_secret, &self.header.sender_ephemeral_pub, &recipient_inbox_pk);

        // Build AAD using header_no_sig
        let header_no_sig = self.header.encode_no_sig();
        let aad = build_aad(owner_peerid, canonical_path, &header_no_sig);

        // Decrypt
        xchacha_decrypt(&key, &self.header.nonce, &self.ciphertext, &aad)
    }

    /// Verify signature if present.
    ///
    /// Returns Ok(true) if signature valid, Ok(false) if no signature, Err on invalid signature.
    pub fn verify_signature(
        &self,
        owner_peerid: &[u8; 32],
        canonical_path: &str,
    ) -> Result<bool, NoiseError> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let sig_bytes = match &self.header.sig {
            Some(s) => s,
            None => return Ok(false),
        };

        let header_no_sig = self.header.encode_no_sig();
        let aad = build_aad(owner_peerid, canonical_path, &header_no_sig);
        let sig_input = compute_sig_input(&aad, &header_no_sig, &self.ciphertext);

        let verifying_key = VerifyingKey::from_bytes(&self.header.sender_peerid)
            .map_err(|e| NoiseError::Decryption(format!("Invalid sender_peerid: {}", e)))?;

        let signature = Signature::from_bytes(sig_bytes);

        verifying_key
            .verify(&sig_input, &signature)
            .map_err(|_| NoiseError::Decryption("Signature verification failed".into()))?;

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use rand::RngCore;

    fn random_context_id() -> [u8; 32] {
        let mut id = [0u8; 32];
        rand::RngCore::fill_bytes(&mut OsRng, &mut id);
        id
    }

    fn random_peerid() -> [u8; 32] {
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        let signing_key = SigningKey::from_bytes(&secret);
        signing_key.verifying_key().to_bytes()
    }

    #[test]
    fn test_sb2_magic_detection() {
        assert!(Sb2::is_sb2(b"SB2\x02\x00\x10"));
        assert!(!Sb2::is_sb2(b"JSON"));
        assert!(!Sb2::is_sb2(b"SB"));
    }

    #[test]
    fn test_inbox_kid_derivation() {
        let (_, pk) = x25519_generate_keypair();
        let kid = Sb2Header::compute_inbox_kid(&pk);
        assert_eq!(kid.len(), 16);

        // Should be deterministic
        let kid2 = Sb2Header::compute_inbox_kid(&pk);
        assert_eq!(kid, kid2);
    }

    #[test]
    fn test_sb2_roundtrip() {
        let (recipient_sk, recipient_pk) = x25519_generate_keypair();
        let context_id = random_context_id();
        let owner_peerid = random_peerid();
        let sender_peerid = random_peerid();
        let recipient_peerid = random_peerid();
        let path = "/pub/paykit.app/v0/requests/abc/req_001";
        let plaintext = b"Hello, SB2!";

        let sb2 = Sb2::encrypt(
            &recipient_pk,
            plaintext,
            context_id,
            Some("req_001".into()),
            Some("request".into()),
            &owner_peerid,
            &sender_peerid,
            &recipient_peerid,
            path,
            Some(1704067200),
            Some(1704153600),
        ).unwrap();

        // Encode to binary
        let encoded = sb2.encode();
        assert!(Sb2::is_sb2(&encoded));

        // Decode from binary
        let decoded = Sb2::decode(&encoded).unwrap();
        assert_eq!(decoded.header.context_id, context_id);
        assert_eq!(decoded.header.msg_id, Some("req_001".into()));
        assert_eq!(decoded.header.purpose, Some("request".into()));

        // Decrypt
        let decrypted = decoded.decrypt(&recipient_sk, &owner_peerid, path).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_sb2_with_signature() {
        let (recipient_sk, recipient_pk) = x25519_generate_keypair();
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        let sender_signing_key = SigningKey::from_bytes(&secret);
        let sender_peerid = sender_signing_key.verifying_key().to_bytes();
        let context_id = random_context_id();
        let owner_peerid = sender_peerid; // Sender owns the storage
        let recipient_peerid = random_peerid();
        let path = "/pub/paykit.app/v0/requests/abc/req_002";
        let plaintext = b"Signed message";

        let mut sb2 = Sb2::encrypt(
            &recipient_pk,
            plaintext,
            context_id,
            Some("req_002".into()),
            Some("request".into()),
            &owner_peerid,
            &sender_peerid,
            &recipient_peerid,
            path,
            None,
            None,
        ).unwrap();

        // Sign
        sb2.sign(&sender_signing_key, &owner_peerid, path);
        assert!(sb2.header.sig.is_some());

        // Encode/decode
        let encoded = sb2.encode();
        let decoded = Sb2::decode(&encoded).unwrap();

        // Verify signature
        let verified = decoded.verify_signature(&owner_peerid, path).unwrap();
        assert!(verified);

        // Decrypt
        let decrypted = decoded.decrypt(&recipient_sk, &owner_peerid, path).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_sb2_wrong_key_fails() {
        let (_, recipient_pk) = x25519_generate_keypair();
        let (wrong_sk, _) = x25519_generate_keypair();
        let context_id = random_context_id();
        let owner_peerid = random_peerid();
        let sender_peerid = random_peerid();
        let recipient_peerid = random_peerid();
        let path = "/pub/paykit.app/v0/requests/abc/req_003";

        let sb2 = Sb2::encrypt(
            &recipient_pk,
            b"secret",
            context_id,
            None,
            None,
            &owner_peerid,
            &sender_peerid,
            &recipient_peerid,
            path,
            None,
            None,
        ).unwrap();

        let result = sb2.decrypt(&wrong_sk, &owner_peerid, path);
        assert!(result.is_err());
    }

    #[test]
    fn test_sb2_wrong_aad_fails() {
        let (recipient_sk, recipient_pk) = x25519_generate_keypair();
        let context_id = random_context_id();
        let owner_peerid = random_peerid();
        let sender_peerid = random_peerid();
        let recipient_peerid = random_peerid();
        let path1 = "/pub/paykit.app/v0/requests/abc/req_004";
        let path2 = "/pub/paykit.app/v0/requests/xyz/req_004";

        let sb2 = Sb2::encrypt(
            &recipient_pk,
            b"secret",
            context_id,
            None,
            None,
            &owner_peerid,
            &sender_peerid,
            &recipient_peerid,
            path1,
            None,
            None,
        ).unwrap();

        let result = sb2.decrypt(&recipient_sk, &owner_peerid, path2);
        assert!(result.is_err());
    }

    #[test]
    fn test_sb2_msg_id_validation() {
        let (_, recipient_pk) = x25519_generate_keypair();
        let context_id = random_context_id();
        let owner_peerid = random_peerid();
        let sender_peerid = random_peerid();
        let recipient_peerid = random_peerid();
        let path = "/pub/paykit.app/v0/requests/abc/req_005";

        // Too long msg_id should fail
        let long_id = "x".repeat(MAX_MSG_ID_LEN + 1);
        let result = Sb2::encrypt(
            &recipient_pk,
            b"test",
            context_id,
            Some(long_id),
            None,
            &owner_peerid,
            &sender_peerid,
            &recipient_peerid,
            path,
            None,
            None,
        );
        assert!(result.is_err());

        // Non-ASCII msg_id should fail
        let non_ascii = "hello\u{00A0}world".to_string();
        let result = Sb2::encrypt(
            &recipient_pk,
            b"test",
            context_id,
            Some(non_ascii),
            None,
            &owner_peerid,
            &sender_peerid,
            &recipient_peerid,
            path,
            None,
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_header_cbor_determinism() {
        let header = Sb2Header {
            context_id: [1u8; 32],
            created_at: Some(1704067200),
            expires_at: Some(1704153600),
            inbox_kid: [2u8; 16],
            msg_id: Some("test_id".into()),
            nonce: [3u8; 24],
            purpose: Some("request".into()),
            recipient_peerid: [4u8; 32],
            sender_ephemeral_pub: [5u8; 32],
            sender_peerid: [6u8; 32],
            sig: None,
            cert_id: None,
        };

        // Encode twice - should be identical
        let encoded1 = header.encode();
        let encoded2 = header.encode();
        assert_eq!(encoded1, encoded2);

        // Decode and re-encode - should be identical
        let decoded = Sb2Header::decode(&encoded1).unwrap();
        let encoded3 = decoded.encode();
        assert_eq!(encoded1, encoded3);
    }
}
