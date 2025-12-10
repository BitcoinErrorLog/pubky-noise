use crate::ffi::errors::FfiNoiseError;
use crate::ffi::types::{
    FfiAcceptResult, FfiConnectionStatus, FfiInitiateResult, FfiMobileConfig, FfiSessionState,
};
use crate::mobile_manager::{MobileConfig, NoiseManager};
use crate::session_id::SessionId;
use crate::{DummyRing, NoiseClient, NoiseServer};
use std::sync::{Arc, Mutex};

/// FFI wrapper around NoiseManager
///
/// Uses internal Mutex for thread safety across FFI boundary.
#[derive(uniffi::Object)]
pub struct FfiNoiseManager {
    inner: Arc<Mutex<NoiseManager<DummyRing>>>,
}

#[uniffi::export]
impl FfiNoiseManager {
    #[uniffi::constructor]
    pub fn new_client(
        config: FfiMobileConfig,
        client_seed: Vec<u8>,
        client_kid: String,
        device_id: Vec<u8>,
    ) -> Result<Arc<Self>, FfiNoiseError> {
        #[cfg(feature = "trace")]
        tracing::info!(
            "Creating FfiNoiseManager in client mode: kid={}, device_id_len={}",
            client_kid,
            device_id.len()
        );

        // Create dummy ring provider with provided seed
        // Use Zeroizing to securely erase seed from memory after use
        use zeroize::Zeroizing;

        if client_seed.len() != 32 {
            #[cfg(feature = "trace")]
            tracing::error!("Invalid seed length: {} (expected 32)", client_seed.len());
            return Err(FfiNoiseError::Ring {
                message: "Seed must be 32 bytes".to_string(),
            });
        }

        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(&client_seed);
        let seed_zeroizing = Zeroizing::new(seed_arr);

        let ring = Arc::new(DummyRing::new_with_device(
            *seed_zeroizing, // Deref to get the value, will be zeroed on drop
            client_kid.clone(),
            device_id.clone(),
            0, // initial epoch
        ));

        let client = Arc::new(NoiseClient::<_, ()>::new_direct(
            client_kid, device_id, ring,
        ));

        let mobile_config: MobileConfig = config.into();
        let manager = NoiseManager::new_client(client, mobile_config);

        #[cfg(feature = "trace")]
        tracing::info!("FfiNoiseManager created successfully in client mode");

        Ok(Arc::new(Self {
            inner: Arc::new(Mutex::new(manager)),
        }))
    }

    /// Initiate a client connection (step 1 of 3-step handshake).
    ///
    /// Returns the temporary session ID and the first handshake message to send.
    /// After sending the message and receiving a response, call `complete_connection`.
    pub fn connect_client(
        &self,
        server_pk: Vec<u8>,
        hint: Option<String>,
    ) -> Result<String, FfiNoiseError> {
        let mut pk_arr = [0u8; 32];
        if server_pk.len() != 32 {
            return Err(FfiNoiseError::Ring {
                message: "Server public key must be 32 bytes".to_string(),
            });
        }
        pk_arr.copy_from_slice(&server_pk);

        let mut manager = self.inner.lock().map_err(|e| {
            #[cfg(feature = "trace")]
            tracing::error!("Mutex poisoned in connect_client: {}", e);
            FfiNoiseError::Other {
                message: "Mutex poisoned".to_string(),
            }
        })?;

        let (session_id, _first_msg) = manager
            .initiate_connection(&pk_arr, hint.as_deref())
            .map_err(FfiNoiseError::from)?;

        #[cfg(feature = "trace")]
        tracing::info!("Client connection initiated: session_id={}", session_id);

        Ok(session_id.to_string())
    }

    /// Initiate a client connection and get the handshake message.
    ///
    /// Returns FfiInitiateResult with session_id and first_message to send to server.
    pub fn initiate_connection(
        &self,
        server_pk: Vec<u8>,
        hint: Option<String>,
    ) -> Result<FfiInitiateResult, FfiNoiseError> {
        let mut pk_arr = [0u8; 32];
        if server_pk.len() != 32 {
            return Err(FfiNoiseError::Ring {
                message: "Server public key must be 32 bytes".to_string(),
            });
        }
        pk_arr.copy_from_slice(&server_pk);

        let mut manager = self.inner.lock().map_err(|e| {
            #[cfg(feature = "trace")]
            tracing::error!("Mutex poisoned in initiate_connection: {}", e);
            FfiNoiseError::Other {
                message: "Mutex poisoned".to_string(),
            }
        })?;

        let (session_id, first_msg) = manager
            .initiate_connection(&pk_arr, hint.as_deref())
            .map_err(FfiNoiseError::from)?;

        #[cfg(feature = "trace")]
        tracing::info!("Client connection initiated: session_id={}", session_id);

        Ok(FfiInitiateResult {
            session_id: session_id.to_string(),
            first_message: first_msg,
        })
    }

    /// Complete a client connection after receiving server response.
    pub fn complete_connection(
        &self,
        session_id: String,
        server_response: Vec<u8>,
    ) -> Result<String, FfiNoiseError> {
        let sid = self.parse_session_id(&session_id)?;

        let mut manager = self.inner.lock().map_err(|e| {
            #[cfg(feature = "trace")]
            tracing::error!("Mutex poisoned in complete_connection: {}", e);
            FfiNoiseError::Other {
                message: "Mutex poisoned".to_string(),
            }
        })?;

        let final_session_id = manager
            .complete_connection(&sid, &server_response)
            .map_err(FfiNoiseError::from)?;

        #[cfg(feature = "trace")]
        tracing::info!(
            "Client connection completed: session_id={}",
            final_session_id
        );

        Ok(final_session_id.to_string())
    }

    #[uniffi::constructor]
    pub fn new_server(
        config: FfiMobileConfig,
        server_seed: Vec<u8>,
        server_kid: String,
        device_id: Vec<u8>,
    ) -> Result<Arc<Self>, FfiNoiseError> {
        #[cfg(feature = "trace")]
        tracing::info!(
            "Creating FfiNoiseManager in server mode: kid={}, device_id_len={}",
            server_kid,
            device_id.len()
        );

        // Create dummy ring provider with provided seed
        use zeroize::Zeroizing;

        if server_seed.len() != 32 {
            #[cfg(feature = "trace")]
            tracing::error!("Invalid seed length: {} (expected 32)", server_seed.len());
            return Err(FfiNoiseError::Ring {
                message: "Seed must be 32 bytes".to_string(),
            });
        }

        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(&server_seed);
        let seed_zeroizing = Zeroizing::new(seed_arr);

        let ring = Arc::new(DummyRing::new_with_device(
            *seed_zeroizing,
            server_kid.clone(),
            device_id.clone(),
            0, // internal epoch
        ));

        let server = Arc::new(NoiseServer::<_, ()>::new_direct(
            server_kid, device_id, ring,
        ));

        let mobile_config: MobileConfig = config.into();
        let manager = NoiseManager::new_server(server, mobile_config);

        Ok(Arc::new(Self {
            inner: Arc::new(Mutex::new(manager)),
        }))
    }

    /// Accept a client connection (server-side handshake).
    ///
    /// Returns FfiAcceptResult with session_id and response_message to send to client.
    pub fn accept_connection(&self, first_msg: Vec<u8>) -> Result<FfiAcceptResult, FfiNoiseError> {
        #[cfg(feature = "trace")]
        tracing::debug!("accept_connection called: msg_len={}", first_msg.len());

        let mut manager = self.inner.lock().map_err(|e| {
            #[cfg(feature = "trace")]
            tracing::error!("Mutex poisoned in accept_connection: {}", e);
            FfiNoiseError::Other {
                message: "Mutex poisoned".to_string(),
            }
        })?;
        let (session_id, response) = manager
            .accept_connection(&first_msg)
            .map_err(FfiNoiseError::from)?;

        #[cfg(feature = "trace")]
        tracing::info!("Server accepted connection: session_id={}", session_id);

        Ok(FfiAcceptResult {
            session_id: session_id.to_string(),
            response_message: response,
        })
    }

    pub fn encrypt(
        &self,
        session_id: String,
        plaintext: Vec<u8>,
    ) -> Result<Vec<u8>, FfiNoiseError> {
        #[cfg(feature = "trace")]
        tracing::trace!(
            "encrypt called: session_id={}, plaintext_len={}",
            session_id,
            plaintext.len()
        );
        let sid = self.parse_session_id(&session_id)?;
        let mut manager = self.inner.lock().map_err(|e| {
            #[cfg(feature = "trace")]
            tracing::error!("Mutex poisoned in encrypt: {}", e);
            FfiNoiseError::Other {
                message: "Mutex poisoned".to_string(),
            }
        })?;
        manager
            .encrypt(&sid, &plaintext)
            .map_err(FfiNoiseError::from)
    }

    pub fn decrypt(
        &self,
        session_id: String,
        ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, FfiNoiseError> {
        #[cfg(feature = "trace")]
        tracing::trace!(
            "decrypt called: session_id={}, ciphertext_len={}",
            session_id,
            ciphertext.len()
        );

        let sid = self.parse_session_id(&session_id)?;
        let mut manager = self.inner.lock().map_err(|e| {
            #[cfg(feature = "trace")]
            tracing::error!("Mutex poisoned in decrypt: {}", e);
            FfiNoiseError::Other {
                message: "Mutex poisoned".to_string(),
            }
        })?;
        manager
            .decrypt(&sid, &ciphertext)
            .map_err(FfiNoiseError::from)
    }

    pub fn save_state(&self, session_id: String) -> Result<FfiSessionState, FfiNoiseError> {
        #[cfg(feature = "trace")]
        tracing::debug!("save_state called: session_id={}", session_id);

        let sid = self.parse_session_id(&session_id)?;
        let manager = self.inner.lock().map_err(|e| {
            #[cfg(feature = "trace")]
            tracing::error!("Mutex poisoned in save_state: {}", e);
            FfiNoiseError::Other {
                message: "Mutex poisoned".to_string(),
            }
        })?;
        let state = manager.save_state(&sid).map_err(FfiNoiseError::from)?;
        Ok(state.into())
    }

    pub fn restore_state(&self, state: FfiSessionState) -> Result<(), FfiNoiseError> {
        #[cfg(feature = "trace")]
        tracing::debug!("restore_state called: session_id={}", state.session_id);

        let session_state: crate::mobile_manager::SessionState =
            state.try_into().map_err(FfiNoiseError::from)?;

        let mut manager = self.inner.lock().map_err(|e| {
            #[cfg(feature = "trace")]
            tracing::error!("Mutex poisoned in restore_state: {}", e);
            FfiNoiseError::Other {
                message: "Mutex poisoned".to_string(),
            }
        })?;
        manager
            .restore_state(session_state)
            .map_err(FfiNoiseError::from)
    }

    pub fn list_sessions(&self) -> Vec<String> {
        let manager = match self.inner.lock() {
            Ok(m) => m,
            Err(e) => {
                #[cfg(feature = "trace")]
                tracing::warn!("Mutex poisoned in list_sessions: {}", e);
                return vec![];
            }
        };

        manager
            .list_sessions()
            .into_iter()
            .map(|sid| sid.to_string())
            .collect()
    }

    pub fn remove_session(&self, session_id: String) {
        if let Ok(sid) = self.parse_session_id(&session_id) {
            match self.inner.lock() {
                Ok(mut manager) => {
                    manager.remove_session(&sid);
                }
                Err(e) => {
                    #[cfg(feature = "trace")]
                    tracing::warn!("Mutex poisoned in remove_session: {}", e);
                }
            }
        }
    }

    pub fn get_status(&self, session_id: String) -> Option<FfiConnectionStatus> {
        let sid = self.parse_session_id(&session_id).ok()?;
        let manager = match self.inner.lock() {
            Ok(m) => m,
            Err(e) => {
                #[cfg(feature = "trace")]
                tracing::warn!("Mutex poisoned in get_status: {}", e);
                return None;
            }
        };
        manager.get_status(&sid).map(|s| s.into())
    }

    pub fn set_status(&self, session_id: String, status: FfiConnectionStatus) {
        if let Ok(sid) = self.parse_session_id(&session_id) {
            match self.inner.lock() {
                Ok(mut manager) => {
                    manager.set_status(&sid, status.into());
                }
                Err(e) => {
                    #[cfg(feature = "trace")]
                    tracing::warn!("Mutex poisoned in set_status: {}", e);
                }
            }
        }
    }
}

impl FfiNoiseManager {
    fn parse_session_id(&self, session_id: &str) -> Result<SessionId, FfiNoiseError> {
        let bytes = hex::decode(session_id).map_err(|_| FfiNoiseError::Other {
            message: "Invalid session ID hex".to_string(),
        })?;

        if bytes.len() != 32 {
            return Err(FfiNoiseError::Other {
                message: "Invalid session ID length".to_string(),
            });
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(SessionId(arr))
    }
}
