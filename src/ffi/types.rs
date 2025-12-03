use crate::mobile_manager::{ConnectionStatus, MobileConfig, NoisePattern, SessionState};
use crate::session_id::SessionId;

/// FFI-safe Noise pattern enum for cold key scenarios.
///
/// Allows mobile apps to select the appropriate Noise pattern:
/// - IK: Full mutual authentication with Ring-based key derivation
/// - IKRaw: IK with raw X25519 keys (for pkarr-based identity)
/// - N: Anonymous sender to known receiver
/// - NN: Fully anonymous (ephemeral both sides)
/// - XX: Mutual authentication with deferred identity
#[derive(uniffi::Enum, Clone, Copy)]
pub enum FfiNoisePattern {
    /// IK pattern with Ring-based key derivation
    IK,
    /// IK pattern with raw X25519 keys (cold key scenario)
    IKRaw,
    /// N pattern: anonymous sender to known receiver
    N,
    /// NN pattern: fully anonymous ephemeral connection
    NN,
    /// XX pattern: mutual auth with deferred identity
    XX,
}

impl From<FfiNoisePattern> for NoisePattern {
    fn from(pattern: FfiNoisePattern) -> Self {
        match pattern {
            FfiNoisePattern::IK => NoisePattern::IK,
            FfiNoisePattern::IKRaw => NoisePattern::IKRaw,
            FfiNoisePattern::N => NoisePattern::N,
            FfiNoisePattern::NN => NoisePattern::NN,
            FfiNoisePattern::XX => NoisePattern::XX,
        }
    }
}

impl From<NoisePattern> for FfiNoisePattern {
    fn from(pattern: NoisePattern) -> Self {
        match pattern {
            NoisePattern::IK => FfiNoisePattern::IK,
            NoisePattern::IKRaw => FfiNoisePattern::IKRaw,
            NoisePattern::N => FfiNoisePattern::N,
            NoisePattern::NN => FfiNoisePattern::NN,
            NoisePattern::XX => FfiNoisePattern::XX,
        }
    }
}

/// Result of initiating a Noise handshake.
#[derive(uniffi::Record)]
pub struct FfiHandshakeResult {
    /// Session ID for tracking this connection
    pub session_id: String,
    /// First handshake message to send to peer
    pub message: Vec<u8>,
}

/// Result of accepting a Noise handshake.
#[derive(uniffi::Record)]
pub struct FfiAcceptResult {
    /// Session ID for tracking this connection
    pub session_id: String,
    /// Response message to send back to initiator
    pub response: Vec<u8>,
    /// Remote peer's static public key (if pattern provides it)
    pub client_static_pk: Option<Vec<u8>>,
}

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

/// FFI-safe session state wrapper
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
