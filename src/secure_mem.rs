//! Secure memory utilities for key protection.
//!
//! This module provides best-effort memory protection for sensitive key material
//! using platform-specific memory locking (mlock).
//!
//! ## Feature Flag
//!
//! This module is only available when the `secure-mem` feature is enabled:
//!
//! ```toml
//! [dependencies]
//! pubky-noise = { version = "1.0", features = ["secure-mem"] }
//! ```
//!
//! ## Behavior
//!
//! - On supported platforms, memory is locked to prevent swapping to disk
//! - On unsupported platforms or when mlock fails, operations succeed silently
//! - This is defense-in-depth, not a security guarantee
//!
//! ## Limitations
//!
//! - mlock has per-process limits (RLIMIT_MEMLOCK on Linux)
//! - Not all platforms support mlock
//! - Memory may still be accessible to privileged processes
//! - Hibernation may still expose memory contents

use crate::errors::NoiseError;

/// Lock a slice of memory to prevent swapping to disk.
///
/// **Note**: This standalone function cannot maintain lock state across calls.
/// For proper RAII-style locking, use [`LockedBytes`] instead.
///
/// # Returns
///
/// Always returns `Ok(false)` - use `LockedBytes` for actual locking.
#[cfg(feature = "secure-mem")]
pub fn mlock_slice(_data: &mut [u8]) -> Result<bool, NoiseError> {
    // Standalone function cannot maintain lock state.
    // Use LockedBytes wrapper for proper RAII locking.
    Ok(false)
}

/// Unlock a previously locked slice of memory.
///
/// This is a best-effort operation and may not have any effect depending
/// on whether mlock_slice succeeded and platform behavior.
///
/// # Arguments
///
/// * `data` - Mutable slice of data to unlock
#[cfg(feature = "secure-mem")]
pub fn munlock_slice(data: &mut [u8]) -> Result<(), NoiseError> {
    use region::unlock;

    // Attempt to unlock the memory region
    match unlock(data.as_ptr(), data.len()) {
        Ok(()) => Ok(()),
        Err(e) => {
            // Best-effort: log and continue
            #[cfg(feature = "trace")]
            tracing::debug!("munlock failed (best-effort): {:?}", e);
            let _ = e;
            Ok(())
        }
    }
}

/// A wrapper that attempts to lock sensitive data in memory.
///
/// This provides RAII-style memory locking: data is locked on creation
/// and unlocked on drop.
///
/// **Note on Memory Stability**: Data is stored on the heap via `Box` to ensure
/// the locked memory address remains stable even when the `LockedBytes` wrapper
/// is moved. This is important because `mlock` operates on memory addresses,
/// and moving inline data would invalidate the locked region.
///
/// This is best-effort defense-in-depth: on platforms where `mlock` fails or
/// is unsupported, operations continue silently without memory locking.
///
/// # Example
///
/// ```rust,ignore
/// use pubky_noise::secure_mem::LockedBytes;
///
/// let mut key = [0u8; 32];
/// // ... fill key with sensitive data ...
///
/// let locked = LockedBytes::new(key);
/// // Key is now (best-effort) locked in memory
/// // Use locked.as_ref() to access the data
/// // Key is unlocked and zeroed when locked goes out of scope
/// ```
#[cfg(feature = "secure-mem")]
pub struct LockedBytes<const N: usize> {
    /// Data stored on the heap for stable addressing during mlock.
    data: Box<[u8; N]>,
    guard: Option<region::LockGuard>,
}

#[cfg(feature = "secure-mem")]
impl<const N: usize> LockedBytes<N> {
    /// Create a new LockedBytes, attempting to lock the memory.
    ///
    /// The data is moved to the heap to ensure the locked address remains
    /// stable even when this wrapper is moved. Uses `region::lock` directly
    /// for proper memory locking. The lock is released when this struct is dropped.
    pub fn new(data: [u8; N]) -> Self {
        use region::lock;

        // Box the data first so it's on the heap with a stable address
        let boxed_data = Box::new(data);
        let mut s = Self {
            data: boxed_data,
            guard: None,
        };

        // Attempt to lock the memory region (now at a stable heap address)
        match lock(s.data.as_ptr(), s.data.len()) {
            Ok(guard) => s.guard = Some(guard),
            Err(_e) => {
                // Best-effort: continue without lock
                #[cfg(feature = "trace")]
                tracing::debug!("LockedBytes: mlock failed (best-effort): {:?}", _e);
            }
        }
        s
    }

    /// Check if the memory was successfully locked.
    pub fn is_locked(&self) -> bool {
        self.guard.is_some()
    }
}

#[cfg(feature = "secure-mem")]
impl<const N: usize> AsRef<[u8; N]> for LockedBytes<N> {
    fn as_ref(&self) -> &[u8; N] {
        &self.data
    }
}

#[cfg(feature = "secure-mem")]
impl<const N: usize> AsMut<[u8; N]> for LockedBytes<N> {
    fn as_mut(&mut self) -> &mut [u8; N] {
        &mut self.data
    }
}

#[cfg(feature = "secure-mem")]
impl<const N: usize> Drop for LockedBytes<N> {
    fn drop(&mut self) {
        // Zero the data before unlocking
        use zeroize::Zeroize;
        (*self.data).zeroize();

        // Unlock (best-effort via LockGuard drop) after zeroize
        let _ = self.guard.take();
    }
}

#[cfg(test)]
#[cfg(feature = "secure-mem")]
mod tests {
    use super::*;

    #[test]
    fn test_mlock_slice_returns_false() {
        let mut data = [42u8; 32];
        // Standalone mlock_slice always returns false (use LockedBytes instead)
        let result = mlock_slice(&mut data);
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Always false for standalone function
                                   // Data should be unchanged
        assert_eq!(data, [42u8; 32]);
    }

    #[test]
    fn test_munlock_slice_best_effort() {
        let mut data = [42u8; 32];
        // Should not error
        let result = munlock_slice(&mut data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_locked_bytes_lifecycle() {
        let key = [1u8; 32];
        let locked = LockedBytes::new(key);

        // Should be able to access data
        assert_eq!(locked.as_ref(), &[1u8; 32]);

        // is_locked returns whatever the platform supports
        let _ = locked.is_locked();

        // Drop happens automatically and should zero + unlock
    }

    #[test]
    fn test_locked_bytes_zeroize_on_drop() {
        let key = [0xABu8; 32];
        let locked = LockedBytes::new(key);
        let ptr = locked.as_ref().as_ptr();

        drop(locked);

        // After drop, reading from the pointer would be UB,
        // but we can't actually test zeroization safely.
        // This test documents the expected behavior.
        let _ = ptr;
    }
}
