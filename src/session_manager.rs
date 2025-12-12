use crate::client::NoiseClient;
use crate::datalink_adapter::NoiseLink;
use crate::ring::RingKeyProvider;
use crate::server::NoiseServer;
use crate::session_id::SessionId;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub enum NoiseRole<R: RingKeyProvider> {
    Client(Arc<NoiseClient<R, ()>>),
    Server(Arc<NoiseServer<R, ()>>),
}

/// Manages multiple concurrent Noise sessions
///
/// ## Thread Safety
///
/// `NoiseSessionManager` is **NOT** thread-safe by itself. If you need to access it from
/// multiple threads (e.g., in mobile apps with background workers), wrap it in
/// `Arc<Mutex<NoiseSessionManager<R>>>`:
///
/// ```rust
/// use pubky_noise::{NoiseSessionManager, NoiseClient, DummyRing};
/// use std::sync::{Arc, Mutex};
///
/// # fn example() {
/// let ring = Arc::new(DummyRing::new([1u8; 32], "kid"));
/// let client = Arc::new(NoiseClient::<_, ()>::new_direct("kid", b"device", ring));
/// let manager = Arc::new(Mutex::new(NoiseSessionManager::new_client(client)));
///
/// // Now safe to share across threads
/// let manager_clone = manager.clone();
/// std::thread::spawn(move || {
///     let mut mgr = manager_clone.lock().unwrap();
///     // Use manager...
/// });
/// # }
/// ```
///
/// Alternatively, use `ThreadSafeSessionManager` for built-in thread safety.
pub struct NoiseSessionManager<R: RingKeyProvider> {
    sessions: HashMap<SessionId, NoiseLink>,
    role: NoiseRole<R>,
}

impl<R: RingKeyProvider> NoiseSessionManager<R> {
    pub fn new_client(client: Arc<NoiseClient<R, ()>>) -> Self {
        Self {
            sessions: HashMap::new(),
            role: NoiseRole::Client(client),
        }
    }

    pub fn new_server(server: Arc<NoiseServer<R, ()>>) -> Self {
        Self {
            sessions: HashMap::new(),
            role: NoiseRole::Server(server),
        }
    }

    /// Adds a session to the manager. Returns the old session if one existed with the same ID.
    pub fn add_session(&mut self, session_id: SessionId, link: NoiseLink) -> Option<NoiseLink> {
        self.sessions.insert(session_id, link)
    }

    pub fn get_session(&self, session_id: &SessionId) -> Option<&NoiseLink> {
        self.sessions.get(session_id)
    }

    pub fn get_session_mut(&mut self, session_id: &SessionId) -> Option<&mut NoiseLink> {
        self.sessions.get_mut(session_id)
    }

    pub fn remove_session(&mut self, session_id: &SessionId) -> Option<NoiseLink> {
        self.sessions.remove(session_id)
    }

    pub fn list_sessions(&self) -> Vec<SessionId> {
        self.sessions.keys().cloned().collect()
    }

    pub fn client(&self) -> Option<&Arc<NoiseClient<R, ()>>> {
        match &self.role {
            NoiseRole::Client(c) => Some(c),
            _ => None,
        }
    }

    pub fn server(&self) -> Option<&Arc<NoiseServer<R, ()>>> {
        match &self.role {
            NoiseRole::Server(s) => Some(s),
            _ => None,
        }
    }
}

/// Thread-safe wrapper around NoiseSessionManager
///
/// This provides built-in thread safety using a Mutex, making it safe to share
/// across threads in mobile applications without manual locking.
///
/// ## Example
///
/// ```rust
/// use pubky_noise::{NoiseClient, DummyRing};
/// use pubky_noise::session_manager::ThreadSafeSessionManager;
/// use std::sync::Arc;
///
/// # fn example() {
/// let ring = Arc::new(DummyRing::new([1u8; 32], "kid"));
/// let client = Arc::new(NoiseClient::<_, ()>::new_direct("kid", b"device", ring));
/// let manager = ThreadSafeSessionManager::new_client(client);
///
/// // Clone and use in multiple threads
/// let manager_clone = manager.clone();
/// std::thread::spawn(move || {
///     // No manual locking needed
///     let sessions = manager_clone.list_sessions();
/// });
/// # }
/// ```
pub struct ThreadSafeSessionManager<R: RingKeyProvider> {
    inner: Arc<Mutex<NoiseSessionManager<R>>>,
}

impl<R: RingKeyProvider> ThreadSafeSessionManager<R> {
    /// Create a new thread-safe manager for client role
    pub fn new_client(client: Arc<NoiseClient<R, ()>>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(NoiseSessionManager::new_client(client))),
        }
    }

    /// Create a new thread-safe manager for server role
    pub fn new_server(server: Arc<NoiseServer<R, ()>>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(NoiseSessionManager::new_server(server))),
        }
    }

    /// Add a session to the manager
    ///
    /// Note: Recovers gracefully from lock poisoning rather than panicking.
    pub fn add_session(&self, session_id: SessionId, link: NoiseLink) -> Option<NoiseLink> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .add_session(session_id, link)
    }

    /// Get a session by ID (returns a copy of the session for thread safety)
    ///
    /// Note: For encryption/decryption, use `with_session` or `with_session_mut` instead.
    /// Recovers gracefully from lock poisoning rather than panicking.
    pub fn has_session(&self, session_id: &SessionId) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_session(session_id)
            .is_some()
    }

    /// Remove a session
    ///
    /// Note: Recovers gracefully from lock poisoning rather than panicking.
    pub fn remove_session(&self, session_id: &SessionId) -> Option<NoiseLink> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove_session(session_id)
    }

    /// List all sessions
    ///
    /// Note: Recovers gracefully from lock poisoning rather than panicking.
    pub fn list_sessions(&self) -> Vec<SessionId> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .list_sessions()
    }

    /// Execute a closure with read access to a session
    ///
    /// Note: Recovers gracefully from lock poisoning rather than panicking.
    pub fn with_session<F, T>(&self, session_id: &SessionId, f: F) -> Option<T>
    where
        F: FnOnce(&NoiseLink) -> T,
    {
        let manager = self
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        manager.get_session(session_id).map(f)
    }

    /// Execute a closure with mutable access to a session
    ///
    /// Note: Recovers gracefully from lock poisoning rather than panicking.
    pub fn with_session_mut<F, T>(&self, session_id: &SessionId, f: F) -> Option<T>
    where
        F: FnOnce(&mut NoiseLink) -> T,
    {
        let mut manager = self
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        manager.get_session_mut(session_id).map(f)
    }

    /// Encrypt data using a specific session
    ///
    /// Note: Recovers gracefully from lock poisoning rather than panicking.
    pub fn encrypt(
        &self,
        session_id: &SessionId,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, crate::errors::NoiseError> {
        let mut manager = self
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        manager
            .get_session_mut(session_id)
            .ok_or_else(|| crate::errors::NoiseError::Other("Session not found".to_string()))?
            .encrypt(plaintext)
    }

    /// Decrypt data using a specific session
    ///
    /// Note: Recovers gracefully from lock poisoning rather than panicking.
    pub fn decrypt(
        &self,
        session_id: &SessionId,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, crate::errors::NoiseError> {
        let mut manager = self
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        manager
            .get_session_mut(session_id)
            .ok_or_else(|| crate::errors::NoiseError::Other("Session not found".to_string()))?
            .decrypt(ciphertext)
    }
}

impl<R: RingKeyProvider> Clone for ThreadSafeSessionManager<R> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}
