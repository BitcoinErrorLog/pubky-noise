use crate::mobile_manager::{ConnectionStatus, MobileConfig, SessionState};
use crate::session_id::SessionId;

/// FFI-safe connection status wrapper
#[derive(uniffi::Enum)]
pub enum FfiConnectionStatus {
    Connected,
    Reconnecting,
    Disconnected,
    Error,
}

impl From<ConnectionStatus> for FfiConnectionStatus {
    fn from(status: ConnectionStatus) -> Self {
        match status {
            ConnectionStatus::Connected => FfiConnectionStatus::Connected,
            ConnectionStatus::Reconnecting => FfiConnectionStatus::Reconnecting,
            ConnectionStatus::Disconnected => FfiConnectionStatus::Disconnected,
            ConnectionStatus::Error => FfiConnectionStatus::Error,
        }
    }
}

impl From<FfiConnectionStatus> for ConnectionStatus {
    fn from(status: FfiConnectionStatus) -> Self {
        match status {
            FfiConnectionStatus::Connected => ConnectionStatus::Connected,
            FfiConnectionStatus::Reconnecting => ConnectionStatus::Reconnecting,
            FfiConnectionStatus::Disconnected => ConnectionStatus::Disconnected,
            FfiConnectionStatus::Error => ConnectionStatus::Error,
        }
    }
}

/// FFI-safe mobile configuration wrapper
#[derive(uniffi::Record, Clone)]
pub struct FfiMobileConfig {
    pub auto_reconnect: bool,
    pub max_reconnect_attempts: u32,
    pub reconnect_delay_ms: u64,
    pub battery_saver: bool,
    pub chunk_size: u64,
}

impl From<MobileConfig> for FfiMobileConfig {
    fn from(config: MobileConfig) -> Self {
        Self {
            auto_reconnect: config.auto_reconnect,
            max_reconnect_attempts: config.max_reconnect_attempts,
            reconnect_delay_ms: config.reconnect_delay_ms,
            battery_saver: config.battery_saver,
            chunk_size: config.chunk_size as u64,
        }
    }
}

impl From<FfiMobileConfig> for MobileConfig {
    fn from(config: FfiMobileConfig) -> Self {
        Self {
            auto_reconnect: config.auto_reconnect,
            max_reconnect_attempts: config.max_reconnect_attempts,
            reconnect_delay_ms: config.reconnect_delay_ms,
            battery_saver: config.battery_saver,
            chunk_size: config.chunk_size as usize,
        }
    }
}

/// FFI-safe session state wrapper.
#[derive(uniffi::Record)]
pub struct FfiSessionState {
    pub session_id: String,
    pub peer_static_pk: Vec<u8>,
    pub write_counter: u64,
    pub read_counter: u64,
    pub status: FfiConnectionStatus,
}

impl From<SessionState> for FfiSessionState {
    fn from(state: SessionState) -> Self {
        Self {
            session_id: state.session_id.to_string(),
            peer_static_pk: state.peer_static_pk.to_vec(),
            write_counter: state.write_counter,
            read_counter: state.read_counter,
            status: state.status.into(),
        }
    }
}

/// FFI-safe result for initiate_connection
#[derive(uniffi::Record)]
pub struct FfiInitiateResult {
    pub session_id: String,
    pub first_message: Vec<u8>,
}

/// FFI-safe result for accept_connection
#[derive(uniffi::Record)]
pub struct FfiAcceptResult {
    pub session_id: String,
    pub response_message: Vec<u8>,
}

impl TryFrom<FfiSessionState> for SessionState {
    type Error = crate::NoiseError;

    fn try_from(state: FfiSessionState) -> Result<Self, Self::Error> {
        let session_id_bytes = hex::decode(&state.session_id)
            .map_err(|_| crate::NoiseError::Other("Invalid session ID hex string".to_string()))?;

        let mut sid = [0u8; 32];
        if session_id_bytes.len() != 32 {
            return Err(crate::NoiseError::Other(
                "Invalid session ID length".to_string(),
            ));
        }
        sid.copy_from_slice(&session_id_bytes);

        let mut peer_pk = [0u8; 32];
        if state.peer_static_pk.len() != 32 {
            return Err(crate::NoiseError::Other(
                "Invalid peer public key length".to_string(),
            ));
        }
        peer_pk.copy_from_slice(&state.peer_static_pk);

        Ok(Self {
            session_id: SessionId(sid),
            peer_static_pk: peer_pk,
            write_counter: state.write_counter,
            read_counter: state.read_counter,
            status: state.status.into(),
        })
    }
}

/// FFI-safe X25519 keypair for sealed blob operations.
#[derive(uniffi::Record)]
pub struct FfiX25519Keypair {
    /// Secret key (32 bytes). Zeroize after use.
    pub secret_key: Vec<u8>,
    /// Public key (32 bytes).
    pub public_key: Vec<u8>,
}

/// FFI-safe Ed25519 keypair for UKD AppKey generation.
#[derive(uniffi::Record)]
pub struct FfiEd25519Keypair {
    /// Secret key as hex (64 chars / 32 bytes). Zeroize after use.
    pub secret_key_hex: String,
    /// Public key as hex (64 chars / 32 bytes).
    pub public_key_hex: String,
}

/// FFI-safe result for AppCert issuance.
#[derive(uniffi::Record)]
pub struct FfiAppCertResult {
    /// Raw cert_body bytes as hex.
    pub cert_body_hex: String,
    /// Ed25519 signature as hex (128 chars / 64 bytes).
    pub sig_hex: String,
    /// cert_id as hex (32 chars / 16 bytes).
    pub cert_id_hex: String,
}

// ============================================================================
// KeyBinding FFI Types (per PUBKY_CRYPTO_SPEC v2.5 Section 7.3)
// ============================================================================

/// FFI-safe InboxKey entry from KeyBinding.
#[derive(uniffi::Record, Clone)]
pub struct FfiInboxKeyEntry {
    /// 16-byte inbox_kid as hex (32 chars).
    pub inbox_kid_hex: String,
    /// 32-byte X25519 public key as hex (64 chars).
    pub x25519_pub_hex: String,
}

/// FFI-safe TransportKey entry from KeyBinding.
#[derive(uniffi::Record, Clone)]
pub struct FfiTransportKeyEntry {
    /// 32-byte X25519 public key as hex (64 chars).
    pub x25519_pub_hex: String,
}

/// FFI-safe AppKey entry from KeyBinding.
#[derive(uniffi::Record, Clone)]
pub struct FfiAppKeyEntry {
    /// 16-byte cert_id as hex (32 chars).
    pub cert_id_hex: String,
    /// 32-byte Ed25519 public key as hex (64 chars).
    pub ed25519_pub_hex: String,
}

/// FFI-safe KeyBinding structure.
///
/// Contains lists of InboxKeys (for stored delivery), TransportKeys (for Noise),
/// and optional AppKeys (for delegated signing).
#[derive(uniffi::Record, Clone)]
pub struct FfiKeyBinding {
    /// List of InboxKey entries (inbox_kid + X25519 public key).
    pub inbox_keys: Vec<FfiInboxKeyEntry>,
    /// List of TransportKey entries (X25519 public key).
    pub transport_keys: Vec<FfiTransportKeyEntry>,
    /// Optional list of AppKey entries (cert_id + Ed25519 public key).
    pub app_keys: Option<Vec<FfiAppKeyEntry>>,
}

impl From<crate::ukd::KeyBinding> for FfiKeyBinding {
    fn from(kb: crate::ukd::KeyBinding) -> Self {
        Self {
            inbox_keys: kb
                .inbox_keys
                .into_iter()
                .map(|e| FfiInboxKeyEntry {
                    inbox_kid_hex: hex::encode(e.inbox_kid),
                    x25519_pub_hex: hex::encode(e.x25519_pub),
                })
                .collect(),
            transport_keys: kb
                .transport_keys
                .into_iter()
                .map(|e| FfiTransportKeyEntry {
                    x25519_pub_hex: hex::encode(e.x25519_pub),
                })
                .collect(),
            app_keys: kb.app_keys.map(|keys| {
                keys.into_iter()
                    .map(|e| FfiAppKeyEntry {
                        cert_id_hex: hex::encode(e.cert_id),
                        ed25519_pub_hex: hex::encode(e.ed25519_pub),
                    })
                    .collect()
            }),
        }
    }
}

// ============================================================================
// SB2 Binary Wire Format FFI Types (per PUBKY_CRYPTO_SPEC v2.5 Section 7.2)
// ============================================================================

/// FFI-safe SB2 header structure.
///
/// Contains all metadata from the SB2 binary envelope header.
#[derive(uniffi::Record, Clone)]
pub struct FfiSb2Header {
    /// Thread identifier (32 bytes as hex, 64 chars).
    pub context_id_hex: String,
    /// Unix timestamp (seconds) when created. Optional.
    pub created_at: Option<u64>,
    /// Unix timestamp (seconds) when expires. Optional.
    pub expires_at: Option<u64>,
    /// Key identifier for recipient InboxKey (16 bytes as hex, 32 chars).
    pub inbox_kid_hex: String,
    /// Idempotency key (ASCII, max 128 chars). Optional.
    pub msg_id: Option<String>,
    /// XChaCha20-Poly1305 nonce (24 bytes as hex, 48 chars).
    pub nonce_hex: String,
    /// Purpose hint (e.g., "request", "proposal", "ack"). Optional.
    pub purpose: Option<String>,
    /// Recipient's Ed25519 public key (32 bytes as hex, 64 chars).
    pub recipient_peerid_hex: String,
    /// Sender's ephemeral X25519 public key (32 bytes as hex, 64 chars).
    pub sender_ephemeral_pub_hex: String,
    /// Sender's Ed25519 public key (32 bytes as hex, 64 chars).
    pub sender_peerid_hex: String,
    /// Ed25519 signature (64 bytes as hex, 128 chars). Optional.
    pub sig_hex: Option<String>,
    /// AppCert identifier (16 bytes as hex, 32 chars). Optional.
    pub cert_id_hex: Option<String>,
}

impl From<crate::sealed_blob_v2::Sb2Header> for FfiSb2Header {
    fn from(h: crate::sealed_blob_v2::Sb2Header) -> Self {
        Self {
            context_id_hex: hex::encode(h.context_id),
            created_at: h.created_at,
            expires_at: h.expires_at,
            inbox_kid_hex: hex::encode(h.inbox_kid),
            msg_id: h.msg_id,
            nonce_hex: hex::encode(h.nonce),
            purpose: h.purpose,
            recipient_peerid_hex: hex::encode(h.recipient_peerid),
            sender_ephemeral_pub_hex: hex::encode(h.sender_ephemeral_pub),
            sender_peerid_hex: hex::encode(h.sender_peerid),
            sig_hex: h.sig.map(hex::encode),
            cert_id_hex: h.cert_id.map(hex::encode),
        }
    }
}

/// FFI-safe SB2 decrypt result containing header and plaintext.
#[derive(uniffi::Record)]
pub struct FfiSb2DecryptResult {
    /// Decoded header with all metadata.
    pub header: FfiSb2Header,
    /// Decrypted plaintext bytes.
    pub plaintext: Vec<u8>,
}
