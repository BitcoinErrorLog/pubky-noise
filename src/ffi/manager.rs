use std::sync::{Arc, Mutex};
use crate::{NoiseClient, NoiseServer, DummyRing};
use crate::mobile_manager::{NoiseManager, MobileConfig};
use crate::session_id::SessionId;
use crate::ffi::types::{FfiMobileConfig, FfiSessionState, FfiConnectionStatus};
use crate::ffi::errors::FfiNoiseError;

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
        device_id: Vec<u8>
    ) -> Result<Self, FfiNoiseError> {
        #[cfg(feature = "trace")]
        tracing::info!("Creating FfiNoiseManager in client mode: kid={}, device_id_len={}", client_kid, device_id.len());
        
        // Create dummy ring provider with provided seed
        // Use Zeroizing to securely erase seed from memory after use
        use secrecy::Zeroizing;
        
        if client_seed.len() != 32 {
            #[cfg(feature = "trace")]
            tracing::error!("Invalid seed length: {} (expected 32)", client_seed.len());
            return Err(FfiNoiseError::Ring { message: "Seed must be 32 bytes".to_string() });
        }
        
        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(&client_seed);
        let seed_zeroizing = Zeroizing::new(seed_arr);
        
        let ring = Arc::new(DummyRing::new_with_device(
            *seed_zeroizing,  // Deref to get the value, will be zeroed on drop
            client_kid.clone(), 
            device_id.clone(),
            0 // initial epoch
        ));

        let client = Arc::new(NoiseClient::<_, ()>::new_direct(
            client_kid,
            device_id,
            ring
        ));

        let mobile_config: MobileConfig = config.into();
        let manager = NoiseManager::new_client(client, mobile_config);

        #[cfg(feature = "trace")]
        tracing::info!("FfiNoiseManager created successfully in client mode");

        Ok(Self {
            inner: Arc::new(Mutex::new(manager)),
        })
    }

    pub fn connect_client(&self, server_pk: Vec<u8>, epoch: u32, hint: Option<String>) -> Result<String, FfiNoiseError> {
        let mut pk_arr = [0u8; 32];
        if server_pk.len() != 32 {
            return Err(FfiNoiseError::Ring { message: "Server public key must be 32 bytes".to_string() });
        }
        pk_arr.copy_from_slice(&server_pk);

        let mut manager = self.inner.lock().map_err(|e| {
            #[cfg(feature = "trace")]
            tracing::error!("Mutex poisoned in connect_client: {}", e);
            FfiNoiseError::Other { message: "Mutex poisoned".to_string() }
        })?;
        
        // Use tokio runtime to block on async operation
        // This is acceptable for FFI as mobile platforms will call from background threads
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| {
                #[cfg(feature = "trace")]
                tracing::error!("Failed to create tokio runtime: {}", e);
                FfiNoiseError::Other { message: format!("Runtime error: {}", e) }
            })?;
            
        let session_id = rt.block_on(manager.connect_client(&pk_arr, epoch, hint.as_deref()))
            .map_err(FfiNoiseError::from)?;
        
        #[cfg(feature = "trace")]
        tracing::info!("Client connected successfully: session_id={}", session_id);
            
        Ok(session_id.to_string())
    }
    
    #[uniffi::constructor(name = "new_server")]
    pub fn new_server_constructor(
        config: FfiMobileConfig, 
        server_seed: Vec<u8>, 
        server_kid: String, 
        device_id: Vec<u8>
    ) -> Result<Self, FfiNoiseError> {
        #[cfg(feature = "trace")]
        tracing::info!("Creating FfiNoiseManager in server mode: kid={}, device_id_len={}", server_kid, device_id.len());
        
        // Create dummy ring provider with provided seed
        use secrecy::Zeroizing;
        
        if server_seed.len() != 32 {
            #[cfg(feature = "trace")]
            tracing::error!("Invalid seed length: {} (expected 32)", server_seed.len());
            return Err(FfiNoiseError::Ring { message: "Seed must be 32 bytes".to_string() });
        }
        
        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(&server_seed);
        let seed_zeroizing = Zeroizing::new(seed_arr);
        
        let ring = Arc::new(DummyRing::new_with_device(
            *seed_zeroizing, 
            server_kid.clone(), 
            device_id.clone(),
            0 // initial epoch
        ));

        let server = Arc::new(NoiseServer::<_, ()>::new_direct(
            server_kid,
            device_id,
            ring
        ));

        let mobile_config: MobileConfig = config.into();
        let manager = NoiseManager::new_server(server, mobile_config);

        Ok(Self {
            inner: Arc::new(Mutex::new(manager)),
        })
    }

    pub fn accept_server(&self, first_msg: Vec<u8>) -> Result<String, FfiNoiseError> {
        #[cfg(feature = "trace")]
        tracing::debug!("accept_server called: msg_len={}", first_msg.len());
        
        let mut manager = self.inner.lock().map_err(|e| {
            #[cfg(feature = "trace")]
            tracing::error!("Mutex poisoned in accept_server: {}", e);
            FfiNoiseError::Other { message: "Mutex poisoned".to_string() }
        })?;
        let session_id = manager.accept_server(&first_msg).map_err(FfiNoiseError::from)?;
        
        #[cfg(feature = "trace")]
        tracing::info!("Server accepted connection: session_id={}", session_id);
        
        Ok(session_id.to_string())
    }

    pub fn encrypt(&self, session_id: String, plaintext: Vec<u8>) -> Result<Vec<u8>, FfiNoiseError> {
        #[cfg(feature = "trace")]
        tracing::trace!("encrypt called: session_id={}, plaintext_len={}", session_id, plaintext.len());
        let sid = self.parse_session_id(&session_id)?;
        let mut manager = self.inner.lock().map_err(|e| {
            #[cfg(feature = "trace")]
            tracing::error!("Mutex poisoned in encrypt: {}", e);
            FfiNoiseError::Other { message: "Mutex poisoned".to_string() }
        })?;
        manager.encrypt(&sid, &plaintext).map_err(FfiNoiseError::from)
    }

    pub fn decrypt(&self, session_id: String, ciphertext: Vec<u8>) -> Result<Vec<u8>, FfiNoiseError> {
        #[cfg(feature = "trace")]
        tracing::trace!("decrypt called: session_id={}, ciphertext_len={}", session_id, ciphertext.len());
        
        let sid = self.parse_session_id(&session_id)?;
        let mut manager = self.inner.lock().map_err(|e| {
            #[cfg(feature = "trace")]
            tracing::error!("Mutex poisoned in decrypt: {}", e);
            FfiNoiseError::Other { message: "Mutex poisoned".to_string() }
        })?;
        manager.decrypt(&sid, &ciphertext).map_err(FfiNoiseError::from)
    }

    pub fn save_state(&self, session_id: String) -> Result<FfiSessionState, FfiNoiseError> {
        #[cfg(feature = "trace")]
        tracing::debug!("save_state called: session_id={}", session_id);
        
        let sid = self.parse_session_id(&session_id)?;
        let manager = self.inner.lock().map_err(|e| {
            #[cfg(feature = "trace")]
            tracing::error!("Mutex poisoned in save_state: {}", e);
            FfiNoiseError::Other { message: "Mutex poisoned".to_string() }
        })?;
        let state = manager.save_state(&sid).map_err(FfiNoiseError::from)?;
        Ok(state.into())
    }

    pub fn restore_state(&self, state: FfiSessionState) -> Result<(), FfiNoiseError> {
        #[cfg(feature = "trace")]
        tracing::debug!("restore_state called: session_id={}", state.session_id);
        
        let session_state: crate::mobile_manager::SessionState = state.try_into()
            .map_err(FfiNoiseError::from)?;
            
        let mut manager = self.inner.lock().map_err(|e| {
            #[cfg(feature = "trace")]
            tracing::error!("Mutex poisoned in restore_state: {}", e);
            FfiNoiseError::Other { message: "Mutex poisoned".to_string() }
        })?;
        manager.restore_state(session_state).map_err(FfiNoiseError::from)
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
        
        manager.list_sessions()
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
        let bytes = hex::decode(session_id)
            .map_err(|_| FfiNoiseError::Other { message: "Invalid session ID hex".to_string() })?;
            
        if bytes.len() != 32 {
            return Err(FfiNoiseError::Other { message: "Invalid session ID length".to_string() });
        }
        
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(SessionId(arr))
    }
}

