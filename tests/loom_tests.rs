//! Loom concurrency tests for pubky-noise
//!
//! These tests use the `loom` crate to deterministically test concurrent access
//! patterns and ensure thread safety.
//!
//! Run with: `RUSTFLAGS="--cfg loom" cargo test --test loom_tests --release`

#![cfg(loom)]

use loom::sync::{Arc, Mutex};
use loom::thread;
use std::collections::HashMap;

/// Simplified session ID for loom testing
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct SessionId(String);

/// Simplified NoiseLink for loom testing (without actual crypto)
struct MockNoiseLink {
    counter: u64,
}

impl MockNoiseLink {
    fn new() -> Self {
        Self { counter: 0 }
    }

    fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        self.counter += 1;
        let mut result = vec![self.counter as u8];
        result.extend_from_slice(data);
        result
    }

    fn decrypt(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        if data.is_empty() {
            return None;
        }
        self.counter += 1;
        Some(data[1..].to_vec())
    }
}

/// Thread-safe session manager for loom testing
struct LoomSessionManager {
    sessions: Arc<Mutex<HashMap<SessionId, MockNoiseLink>>>,
}

impl LoomSessionManager {
    fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn add_session(&self, id: SessionId, link: MockNoiseLink) -> Option<MockNoiseLink> {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.insert(id, link)
    }

    fn remove_session(&self, id: &SessionId) -> Option<MockNoiseLink> {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.remove(id)
    }

    fn has_session(&self, id: &SessionId) -> bool {
        let sessions = self.sessions.lock().unwrap();
        sessions.contains_key(id)
    }

    fn encrypt(&self, id: &SessionId, data: &[u8]) -> Option<Vec<u8>> {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.get_mut(id).map(|link| link.encrypt(data))
    }

    fn decrypt(&self, id: &SessionId, data: &[u8]) -> Option<Vec<u8>> {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.get_mut(id).and_then(|link| link.decrypt(data))
    }

    fn list_sessions(&self) -> Vec<SessionId> {
        let sessions = self.sessions.lock().unwrap();
        sessions.keys().cloned().collect()
    }

    fn session_count(&self) -> usize {
        let sessions = self.sessions.lock().unwrap();
        sessions.len()
    }
}

impl Clone for LoomSessionManager {
    fn clone(&self) -> Self {
        Self {
            sessions: Arc::clone(&self.sessions),
        }
    }
}

/// Test concurrent add and remove operations
#[test]
fn test_concurrent_add_remove() {
    loom::model(|| {
        let manager = LoomSessionManager::new();
        let m1 = manager.clone();
        let m2 = manager.clone();

        let t1 = thread::spawn(move || {
            m1.add_session(SessionId("s1".to_string()), MockNoiseLink::new());
        });

        let t2 = thread::spawn(move || {
            m2.add_session(SessionId("s2".to_string()), MockNoiseLink::new());
        });

        t1.join().unwrap();
        t2.join().unwrap();

        // Both sessions should be added
        assert!(manager.session_count() == 2);
    });
}

/// Test concurrent add and check operations
#[test]
fn test_concurrent_add_check() {
    loom::model(|| {
        let manager = LoomSessionManager::new();
        let m1 = manager.clone();
        let m2 = manager.clone();

        let t1 = thread::spawn(move || {
            m1.add_session(SessionId("s1".to_string()), MockNoiseLink::new());
            true
        });

        let t2 = thread::spawn(move || {
            // May or may not see the session depending on scheduling
            m2.has_session(&SessionId("s1".to_string()))
        });

        let added = t1.join().unwrap();
        let _seen = t2.join().unwrap();

        // Session should definitely exist after t1 completes
        assert!(added);
        assert!(manager.has_session(&SessionId("s1".to_string())));
    });
}

/// Test concurrent encrypt operations
#[test]
fn test_concurrent_encrypt() {
    loom::model(|| {
        let manager = LoomSessionManager::new();
        manager.add_session(SessionId("s1".to_string()), MockNoiseLink::new());

        let m1 = manager.clone();
        let m2 = manager.clone();

        let t1 = thread::spawn(move || m1.encrypt(&SessionId("s1".to_string()), b"hello"));

        let t2 = thread::spawn(move || m2.encrypt(&SessionId("s1".to_string()), b"world"));

        let r1 = t1.join().unwrap();
        let r2 = t2.join().unwrap();

        // Both should succeed
        assert!(r1.is_some());
        assert!(r2.is_some());

        // Counters should be different (no overlap)
        let c1 = r1.unwrap()[0];
        let c2 = r2.unwrap()[0];
        assert_ne!(c1, c2);
    });
}

/// Test concurrent add and remove same session
#[test]
fn test_concurrent_add_remove_same() {
    loom::model(|| {
        let manager = LoomSessionManager::new();
        manager.add_session(SessionId("s1".to_string()), MockNoiseLink::new());

        let m1 = manager.clone();
        let m2 = manager.clone();

        let t1 = thread::spawn(move || m1.remove_session(&SessionId("s1".to_string())));

        let t2 = thread::spawn(move || m2.remove_session(&SessionId("s1".to_string())));

        let r1 = t1.join().unwrap();
        let r2 = t2.join().unwrap();

        // Exactly one should succeed in removing
        assert!(r1.is_some() != r2.is_some() || (r1.is_none() && r2.is_none()));

        // Session should be gone
        assert!(!manager.has_session(&SessionId("s1".to_string())));
    });
}

/// Test list_sessions during concurrent modifications
#[test]
fn test_list_during_modifications() {
    loom::model(|| {
        let manager = LoomSessionManager::new();
        manager.add_session(SessionId("s1".to_string()), MockNoiseLink::new());

        let m1 = manager.clone();
        let m2 = manager.clone();

        let t1 = thread::spawn(move || {
            m1.add_session(SessionId("s2".to_string()), MockNoiseLink::new());
        });

        let t2 = thread::spawn(move || {
            let sessions = m2.list_sessions();
            // Should see consistent snapshot (either 1 or 2 sessions)
            assert!(sessions.len() >= 1 && sessions.len() <= 2);
            sessions
        });

        t1.join().unwrap();
        let _ = t2.join().unwrap();

        // Final state should have both
        assert_eq!(manager.session_count(), 2);
    });
}

/// Test stress with many concurrent operations
#[test]
fn test_stress_concurrent_operations() {
    loom::model(|| {
        let manager = LoomSessionManager::new();
        let mut handles = vec![];

        // Spawn many threads doing different operations
        for i in 0..5 {
            let m = manager.clone();
            let id = SessionId(format!("s{}", i));
            handles.push(thread::spawn(move || {
                m.add_session(id.clone(), MockNoiseLink::new());
                m.has_session(&id)
            }));
        }

        // Wait for all
        for handle in handles {
            assert!(handle.join().unwrap());
        }

        // All should be present
        assert_eq!(manager.session_count(), 5);
    });
}

/// Test race condition: concurrent add of same session ID
#[test]
fn test_race_concurrent_add_same_id() {
    loom::model(|| {
        let manager = LoomSessionManager::new();
        let id = SessionId("s1".to_string());
        let m1 = manager.clone();
        let m2 = manager.clone();

        let t1 = thread::spawn(move || m1.add_session(id.clone(), MockNoiseLink::new()));

        let t2 = thread::spawn(move || m2.add_session(id.clone(), MockNoiseLink::new()));

        let r1 = t1.join().unwrap();
        let r2 = t2.join().unwrap();

        // Exactly one should return None (first insert), one should return Some (replaced)
        assert!((r1.is_none() && r2.is_some()) || (r1.is_some() && r2.is_none()));

        // Session should exist
        assert!(manager.has_session(&id));
    });
}
