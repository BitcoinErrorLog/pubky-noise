//! FFI wrapper for RawNoiseManager supporting cold key patterns.
//!
//! This module provides FFI-safe access to Noise patterns that use raw X25519 keys
//! instead of Ring-based key derivation. This is essential for:
//!
//! - Cold key scenarios where Ed25519 identity keys are kept offline
//! - pkarr-based identity binding where X25519 keys are published separately
//! - Anonymous and ephemeral connection patterns (N, NN)

use crate::ffi::errors::FfiNoiseError;
use crate::ffi::types::{
    FfiAcceptResult, FfiConnectionStatus, FfiHandshakeResult, FfiMobileConfig, FfiNoisePattern,
    FfiSessionState,
};
use crate::mobile_manager::{MobileConfig, NoisePattern, RawNoiseManager};
use crate::session_id::SessionId;
use std::sync::{Arc, Mutex};

/// FFI wrapper for RawNoiseManager.
///
/// Provides cold-key pattern support for mobile platforms where Ed25519
/// identity keys are kept cold and X25519 session keys are derived separately.
#[derive(uniffi::Object)]
pub struct FfiRawNoiseManager {
    inner: Arc<Mutex<RawNoiseManager>>,
}

#[uniffi::export]
impl FfiRawNoiseManager {
    /// Create a new raw noise manager with the given configuration.
    #[uniffi::constructor]
    pub fn new(config: FfiMobileConfig) -> Arc<Self> {
        let mobile_config: MobileConfig = config.into();
        Arc::new(Self {
            inner: Arc::new(Mutex::new(RawNoiseManager::new(mobile_config))),
        })
    }

    /// Initiate an IK-raw handshake with a known recipient.
    ///
    /// Use this when you have pre-shared the recipient's X25519 public key
    /// (e.g., via pkarr lookup) and want identity hiding.
    ///
    /// # Arguments
    /// * `local_sk` - Your X25519 secret key (32 bytes)
    /// * `server_pk` - Recipient's X25519 public key (32 bytes)
    ///
    /// # Returns
    /// Handshake result with session ID and first message to send
    pub fn initiate_ik_raw(
        &self,
        local_sk: Vec<u8>,
        server_pk: Vec<u8>,
    ) -> Result<FfiHandshakeResult, FfiNoiseError> {
        let local_sk = parse_key_32(&local_sk, "local secret key")?;
        let server_pk = parse_key_32(&server_pk, "server public key")?;

        let zeroizing_sk = zeroize::Zeroizing::new(local_sk);

        let mut manager = lock_manager(&self.inner)?;
        let (session_id, message) = manager
            .initiate_connection_with_pattern(
                NoisePattern::IKRaw,
                Some(&zeroizing_sk),
                Some(&server_pk),
            )
            .map_err(FfiNoiseError::from)?;

        Ok(FfiHandshakeResult {
            session_id: session_id.to_string(),
            message,
        })
    }

    /// Initiate an anonymous (N pattern) connection to a known recipient.
    ///
    /// The sender is anonymous (ephemeral key only), but the recipient is
    /// authenticated by their static public key.
    ///
    /// # Arguments
    /// * `server_pk` - Recipient's X25519 public key (32 bytes)
    pub fn initiate_anonymous(
        &self,
        server_pk: Vec<u8>,
    ) -> Result<FfiHandshakeResult, FfiNoiseError> {
        let server_pk = parse_key_32(&server_pk, "server public key")?;

        let mut manager = lock_manager(&self.inner)?;
        let (session_id, message) = manager
            .initiate_connection_with_pattern(NoisePattern::N, None, Some(&server_pk))
            .map_err(FfiNoiseError::from)?;

        Ok(FfiHandshakeResult {
            session_id: session_id.to_string(),
            message,
        })
    }

    /// Initiate a fully ephemeral (NN pattern) connection.
    ///
    /// Neither party is authenticated - both use ephemeral keys.
    /// Only use when you have an out-of-band authentication mechanism.
    pub fn initiate_ephemeral(&self) -> Result<FfiHandshakeResult, FfiNoiseError> {
        let mut manager = lock_manager(&self.inner)?;
        let (session_id, message) = manager
            .initiate_connection_with_pattern(NoisePattern::NN, None, None)
            .map_err(FfiNoiseError::from)?;

        Ok(FfiHandshakeResult {
            session_id: session_id.to_string(),
            message,
        })
    }

    /// Initiate an XX pattern handshake for mutual authentication.
    ///
    /// Both parties authenticate but identities are revealed later in the handshake.
    /// Use when you want mutual auth but don't have the recipient's key upfront.
    ///
    /// # Arguments
    /// * `local_sk` - Your X25519 secret key (32 bytes)
    pub fn initiate_xx(&self, local_sk: Vec<u8>) -> Result<FfiHandshakeResult, FfiNoiseError> {
        let local_sk = parse_key_32(&local_sk, "local secret key")?;
        let zeroizing_sk = zeroize::Zeroizing::new(local_sk);

        let mut manager = lock_manager(&self.inner)?;
        let (session_id, message) = manager
            .initiate_connection_with_pattern(NoisePattern::XX, Some(&zeroizing_sk), None)
            .map_err(FfiNoiseError::from)?;

        Ok(FfiHandshakeResult {
            session_id: session_id.to_string(),
            message,
        })
    }

    /// Accept an IK-raw handshake from an initiator.
    ///
    /// # Arguments
    /// * `local_sk` - Your X25519 secret key (32 bytes)
    /// * `first_msg` - First handshake message from initiator
    pub fn accept_ik_raw(
        &self,
        local_sk: Vec<u8>,
        first_msg: Vec<u8>,
    ) -> Result<FfiAcceptResult, FfiNoiseError> {
        let local_sk = parse_key_32(&local_sk, "local secret key")?;
        let zeroizing_sk = zeroize::Zeroizing::new(local_sk);

        let mut manager = lock_manager(&self.inner)?;
        let (session_id, response, client_pk) = manager
            .accept_connection_with_pattern(NoisePattern::IKRaw, Some(&zeroizing_sk), &first_msg)
            .map_err(FfiNoiseError::from)?;

        Ok(FfiAcceptResult {
            session_id: session_id.to_string(),
            response,
            client_static_pk: client_pk.map(|pk| pk.to_vec()),
        })
    }

    /// Accept an anonymous (N pattern) connection.
    ///
    /// The sender is anonymous; you are authenticated by your static key.
    ///
    /// # Arguments
    /// * `local_sk` - Your X25519 secret key (32 bytes)
    /// * `first_msg` - First handshake message from initiator
    pub fn accept_anonymous(
        &self,
        local_sk: Vec<u8>,
        first_msg: Vec<u8>,
    ) -> Result<FfiAcceptResult, FfiNoiseError> {
        let local_sk = parse_key_32(&local_sk, "local secret key")?;
        let zeroizing_sk = zeroize::Zeroizing::new(local_sk);

        let mut manager = lock_manager(&self.inner)?;
        let (session_id, response, _) = manager
            .accept_connection_with_pattern(NoisePattern::N, Some(&zeroizing_sk), &first_msg)
            .map_err(FfiNoiseError::from)?;

        Ok(FfiAcceptResult {
            session_id: session_id.to_string(),
            response,
            client_static_pk: None, // N pattern: sender is anonymous
        })
    }

    /// Accept a fully ephemeral (NN pattern) connection.
    ///
    /// Neither party is authenticated.
    ///
    /// # Arguments
    /// * `first_msg` - First handshake message from initiator
    pub fn accept_ephemeral(&self, first_msg: Vec<u8>) -> Result<FfiAcceptResult, FfiNoiseError> {
        let mut manager = lock_manager(&self.inner)?;
        let (session_id, response, _) = manager
            .accept_connection_with_pattern(NoisePattern::NN, None, &first_msg)
            .map_err(FfiNoiseError::from)?;

        Ok(FfiAcceptResult {
            session_id: session_id.to_string(),
            response,
            client_static_pk: None, // NN pattern: sender is anonymous
        })
    }

    /// Accept an XX pattern handshake.
    ///
    /// Returns the client's static public key after the handshake completes.
    ///
    /// # Arguments
    /// * `local_sk` - Your X25519 secret key (32 bytes)
    /// * `first_msg` - First handshake message from initiator
    pub fn accept_xx(
        &self,
        local_sk: Vec<u8>,
        first_msg: Vec<u8>,
    ) -> Result<FfiAcceptResult, FfiNoiseError> {
        let local_sk = parse_key_32(&local_sk, "local secret key")?;
        let zeroizing_sk = zeroize::Zeroizing::new(local_sk);

        let mut manager = lock_manager(&self.inner)?;
        let (session_id, response, client_pk) = manager
            .accept_connection_with_pattern(NoisePattern::XX, Some(&zeroizing_sk), &first_msg)
            .map_err(FfiNoiseError::from)?;

        Ok(FfiAcceptResult {
            session_id: session_id.to_string(),
            response,
            client_static_pk: client_pk.map(|pk| pk.to_vec()),
        })
    }

    /// Complete handshake for patterns requiring multiple round-trips (XX).
    ///
    /// Call this after receiving the server's response to complete the handshake.
    ///
    /// # Arguments
    /// * `session_id` - Session ID from initiate call
    /// * `response` - Response message from server
    pub fn complete_handshake(
        &self,
        session_id: String,
        response: Vec<u8>,
    ) -> Result<Vec<u8>, FfiNoiseError> {
        let sid = parse_session_id(&session_id)?;

        let mut manager = lock_manager(&self.inner)?;
        let final_msg = manager
            .complete_connection(&sid, &response)
            .map_err(FfiNoiseError::from)?;

        Ok(final_msg)
    }

    /// Encrypt a message for the given session.
    pub fn encrypt(
        &self,
        session_id: String,
        plaintext: Vec<u8>,
    ) -> Result<Vec<u8>, FfiNoiseError> {
        let sid = parse_session_id(&session_id)?;
        let mut manager = lock_manager(&self.inner)?;
        manager
            .encrypt(&sid, &plaintext)
            .map_err(FfiNoiseError::from)
    }

    /// Decrypt a message for the given session.
    pub fn decrypt(
        &self,
        session_id: String,
        ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, FfiNoiseError> {
        let sid = parse_session_id(&session_id)?;
        let mut manager = lock_manager(&self.inner)?;
        manager
            .decrypt(&sid, &ciphertext)
            .map_err(FfiNoiseError::from)
    }

    /// Save session state for persistence.
    pub fn save_state(&self, session_id: String) -> Result<FfiSessionState, FfiNoiseError> {
        let sid = parse_session_id(&session_id)?;
        let manager = lock_manager(&self.inner)?;
        let state = manager.save_state(&sid).map_err(FfiNoiseError::from)?;
        Ok(state.into())
    }

    /// Restore a saved session state.
    pub fn restore_state(&self, state: FfiSessionState) -> Result<(), FfiNoiseError> {
        let session_state: crate::mobile_manager::SessionState =
            state.try_into().map_err(FfiNoiseError::from)?;
        let mut manager = lock_manager(&self.inner)?;
        manager
            .restore_state(session_state)
            .map_err(FfiNoiseError::from)
    }

    /// List all active session IDs.
    pub fn list_sessions(&self) -> Vec<String> {
        match self.inner.lock() {
            Ok(manager) => manager
                .list_sessions()
                .into_iter()
                .map(|sid| sid.to_string())
                .collect(),
            Err(_) => vec![],
        }
    }

    /// Remove a session.
    pub fn remove_session(&self, session_id: String) {
        if let Ok(sid) = parse_session_id(&session_id) {
            if let Ok(mut manager) = self.inner.lock() {
                manager.remove_session(&sid);
            }
        }
    }

    /// Get connection status for a session.
    pub fn get_status(&self, session_id: String) -> Option<FfiConnectionStatus> {
        let sid = parse_session_id(&session_id).ok()?;
        let manager = self.inner.lock().ok()?;
        manager.get_status(&sid).map(|s| s.into())
    }

    /// Set connection status for a session.
    pub fn set_status(&self, session_id: String, status: FfiConnectionStatus) {
        if let Ok(sid) = parse_session_id(&session_id) {
            if let Ok(mut manager) = self.inner.lock() {
                manager.set_status(&sid, status.into());
            }
        }
    }
}

// ============================================================================
// FFI Key Derivation Functions
// ============================================================================

/// Derive an X25519 key pair from a seed and context.
///
/// Use this to derive session keys from a master seed without exposing
/// the seed to the Noise layer.
///
/// # Arguments
/// * `seed` - 32-byte seed (typically from Ed25519 secret key)
/// * `context` - Application-specific context bytes (e.g., device ID)
///
/// # Returns
/// 32-byte X25519 secret key
#[uniffi::export]
pub fn ffi_derive_x25519_static(seed: Vec<u8>, context: Vec<u8>) -> Result<Vec<u8>, FfiNoiseError> {
    if seed.len() != 32 {
        return Err(FfiNoiseError::Ring {
            message: "Seed must be 32 bytes".to_string(),
        });
    }

    let mut seed_arr = [0u8; 32];
    seed_arr.copy_from_slice(&seed);

    let derived = crate::kdf::derive_x25519_static(&seed_arr, &context);
    Ok(derived.to_vec())
}

/// Compute the X25519 public key from a secret key.
///
/// # Arguments
/// * `secret_key` - 32-byte X25519 secret key
///
/// # Returns
/// 32-byte X25519 public key
#[uniffi::export]
pub fn ffi_x25519_public_key(secret_key: Vec<u8>) -> Result<Vec<u8>, FfiNoiseError> {
    if secret_key.len() != 32 {
        return Err(FfiNoiseError::Ring {
            message: "Secret key must be 32 bytes".to_string(),
        });
    }

    let mut sk_arr = [0u8; 32];
    sk_arr.copy_from_slice(&secret_key);

    // Use x25519_dalek to compute public key
    use x25519_dalek::{PublicKey, StaticSecret};
    let secret = StaticSecret::from(sk_arr);
    let public = PublicKey::from(&secret);

    Ok(public.as_bytes().to_vec())
}

// ============================================================================
// Helper Functions
// ============================================================================

fn parse_key_32(bytes: &[u8], name: &str) -> Result<[u8; 32], FfiNoiseError> {
    if bytes.len() != 32 {
        return Err(FfiNoiseError::Ring {
            message: format!("{} must be 32 bytes, got {}", name, bytes.len()),
        });
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Ok(arr)
}

fn parse_session_id(session_id: &str) -> Result<SessionId, FfiNoiseError> {
    let bytes = hex::decode(session_id).map_err(|_| FfiNoiseError::Other {
        message: "Invalid session ID hex".to_string(),
    })?;

    if bytes.len() != 32 {
        return Err(FfiNoiseError::Other {
            message: "Session ID must be 32 bytes".to_string(),
        });
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(SessionId(arr))
}

fn lock_manager(
    inner: &Arc<Mutex<RawNoiseManager>>,
) -> Result<std::sync::MutexGuard<RawNoiseManager>, FfiNoiseError> {
    inner.lock().map_err(|_| FfiNoiseError::Other {
        message: "Mutex poisoned".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation() {
        let seed = vec![0u8; 32];
        let context = b"test-context".to_vec();

        let derived = ffi_derive_x25519_static(seed.clone(), context.clone()).unwrap();
        assert_eq!(derived.len(), 32);

        // Same inputs produce same output
        let derived2 = ffi_derive_x25519_static(seed, context).unwrap();
        assert_eq!(derived, derived2);
    }

    #[test]
    fn test_public_key_derivation() {
        let sk = vec![1u8; 32];
        let pk = ffi_x25519_public_key(sk.clone()).unwrap();
        assert_eq!(pk.len(), 32);

        // Same input produces same output
        let pk2 = ffi_x25519_public_key(sk).unwrap();
        assert_eq!(pk, pk2);
    }

    #[test]
    fn test_invalid_key_length() {
        let short = vec![0u8; 16];
        assert!(ffi_derive_x25519_static(short.clone(), vec![]).is_err());
        assert!(ffi_x25519_public_key(short).is_err());
    }
}

