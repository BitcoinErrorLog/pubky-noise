//! Tests for timeout enforcement, path validation, HKDF error handling,
//! and client-side expiry features added in the production readiness audit.

/// Test path validation in StorageBackedMessaging
#[cfg(feature = "storage-queue")]
mod path_validation_tests {
    // These tests require the storage-queue feature and actual Pubky dependencies
    // For unit testing, we focus on the validation logic patterns

    #[test]
    fn test_valid_path_patterns() {
        // Valid paths should pass validation
        let valid_paths = [
            "/pub/my-app/messages",
            "/pub/paykit.app/v0/noise/inbox",
            "/pub/user123/outbox",
            "/a",
            "/pub/app-name/with-dashes",
            "/pub/app_name/with_underscores",
            "/pub/v1.0.0/versioned",
        ];

        for path in valid_paths {
            assert!(is_valid_path(path), "Expected path '{}' to be valid", path);
        }
    }

    #[test]
    fn test_invalid_path_empty() {
        assert!(!is_valid_path(""), "Empty path should be invalid");
    }

    #[test]
    fn test_invalid_path_no_leading_slash() {
        assert!(
            !is_valid_path("pub/my-app/messages"),
            "Path without leading slash should be invalid"
        );
    }

    #[test]
    fn test_invalid_path_traversal() {
        assert!(
            !is_valid_path("/pub/../etc/passwd"),
            "Path with .. should be invalid"
        );
        assert!(
            !is_valid_path("/pub/app/../secrets"),
            "Path with .. in middle should be invalid"
        );
    }

    #[test]
    fn test_invalid_path_double_slash() {
        assert!(
            !is_valid_path("/pub//app/messages"),
            "Path with // should be invalid"
        );
    }

    #[test]
    fn test_invalid_path_special_chars() {
        let invalid_chars = ['<', '>', '|', '?', '*', '"', '\'', '\\', ' ', '\n', '\t'];
        for c in invalid_chars {
            let path = format!("/pub/app{}test", c);
            assert!(!is_valid_path(&path), "Path with '{}' should be invalid", c);
        }
    }

    #[test]
    fn test_invalid_path_too_long() {
        let long_path = format!("/{}", "a".repeat(1025));
        assert!(
            !is_valid_path(&long_path),
            "Path over 1024 chars should be invalid"
        );
    }

    /// Mirror of the validation logic in storage_queue.rs for testing
    fn is_valid_path(path: &str) -> bool {
        if path.is_empty() {
            return false;
        }
        if !path.starts_with('/') {
            return false;
        }
        if path.len() > 1024 {
            return false;
        }
        if path.contains("..") {
            return false;
        }
        if path.contains("//") {
            return false;
        }
        for c in path.chars() {
            if !c.is_alphanumeric() && !matches!(c, '/' | '-' | '_' | '.') {
                return false;
            }
        }
        true
    }
}

/// Test HKDF error handling
mod hkdf_error_tests {

    #[test]
    fn test_hkdf_returns_result() {
        // Test that derive_x25519_for_device_epoch returns a Result
        let seed = [0u8; 32];
        let device_id = b"test-device";
        let epoch = 0u32;

        let result = pubky_noise::kdf::derive_x25519_for_device_epoch(&seed, device_id, epoch);

        // Should succeed with valid inputs
        assert!(result.is_ok(), "HKDF should succeed with valid inputs");

        let key = result.unwrap();
        assert_eq!(key.len(), 32, "Derived key should be 32 bytes");
    }

    #[test]
    fn test_hkdf_key_clamping() {
        // Verify X25519 key clamping is applied
        let seed = [42u8; 32];
        let device_id = b"clamping-test";
        let key = pubky_noise::kdf::derive_x25519_for_device_epoch(&seed, device_id, 0)
            .expect("HKDF should succeed");

        // Check clamping: sk[0] &= 248, sk[31] &= 127, sk[31] |= 64
        assert_eq!(key[0] & 7, 0, "First byte should have lower 3 bits cleared");
        assert_eq!(key[31] & 128, 0, "Last byte should have high bit cleared");
        assert_eq!(key[31] & 64, 64, "Last byte should have bit 6 set");
    }

    #[test]
    fn test_hkdf_deterministic() {
        let seed = [1u8; 32];
        let device_id = b"determinism-test";

        let key1 = pubky_noise::kdf::derive_x25519_for_device_epoch(&seed, device_id, 0).unwrap();
        let key2 = pubky_noise::kdf::derive_x25519_for_device_epoch(&seed, device_id, 0).unwrap();

        assert_eq!(key1, key2, "Same inputs should produce same key");
    }

    #[test]
    fn test_hkdf_epoch_differentiation() {
        let seed = [2u8; 32];
        let device_id = b"epoch-test";

        let key0 = pubky_noise::kdf::derive_x25519_for_device_epoch(&seed, device_id, 0).unwrap();
        let key1 = pubky_noise::kdf::derive_x25519_for_device_epoch(&seed, device_id, 1).unwrap();

        assert_ne!(key0, key1, "Different epochs should produce different keys");
    }

    #[test]
    fn test_hkdf_device_differentiation() {
        let seed = [3u8; 32];

        let key_a =
            pubky_noise::kdf::derive_x25519_for_device_epoch(&seed, b"device-a", 0).unwrap();
        let key_b =
            pubky_noise::kdf::derive_x25519_for_device_epoch(&seed, b"device-b", 0).unwrap();

        assert_ne!(
            key_a, key_b,
            "Different devices should produce different keys"
        );
    }
}

/// Test Rate Limit error structure
mod rate_limit_error_tests {
    use pubky_noise::errors::{NoiseError, NoiseErrorCode};

    #[test]
    fn test_rate_limited_with_retry_after() {
        let err = NoiseError::RateLimited {
            message: "Too many requests".to_string(),
            retry_after_ms: Some(5000),
        };

        assert_eq!(err.code(), NoiseErrorCode::RateLimited);
        assert!(err.is_retryable());
        assert_eq!(err.retry_after_ms(), Some(5000));
    }

    #[test]
    fn test_rate_limited_without_retry_after() {
        let err = NoiseError::RateLimited {
            message: "Slow down".to_string(),
            retry_after_ms: None,
        };

        assert_eq!(err.code(), NoiseErrorCode::RateLimited);
        assert!(err.is_retryable());
        assert_eq!(err.retry_after_ms(), None);
    }

    #[test]
    fn test_timeout_error() {
        let err = NoiseError::Timeout("Operation timed out".to_string());

        assert_eq!(err.code(), NoiseErrorCode::Timeout);
        assert!(err.is_retryable());
        // Timeout has default retry suggestion of 1000ms
        assert_eq!(err.retry_after_ms(), Some(1000));
    }

    #[test]
    fn test_error_display() {
        let err = NoiseError::RateLimited {
            message: "Rate limit exceeded".to_string(),
            retry_after_ms: Some(3000),
        };

        let display = format!("{}", err);
        assert!(display.contains("Rate limit exceeded"));
    }
}

/// Test client-side expiry computation
mod client_expiry_tests {
    use pubky_noise::client::NoiseClient;
    use pubky_noise::ring::DummyRing;
    use std::sync::Arc;

    fn make_ring() -> Arc<DummyRing> {
        Arc::new(DummyRing::new([42u8; 32], "test-kid"))
    }

    #[test]
    fn test_client_default_no_expiry() {
        let ring = make_ring();
        let client = NoiseClient::<DummyRing>::new_direct("test-kid", b"device-1", ring);

        // By default, now_unix is None
        assert!(client.now_unix.is_none());
    }

    #[test]
    fn test_client_with_now_unix() {
        let ring = make_ring();
        let client = NoiseClient::<DummyRing>::new_direct("test-kid", b"device-1", ring)
            .with_now_unix(1700000000);

        assert_eq!(client.now_unix, Some(1700000000));
        // Default expiry is 300 seconds
        assert_eq!(client.expiry_secs, 300);
    }

    #[test]
    fn test_client_custom_expiry() {
        let ring = make_ring();
        let client = NoiseClient::<DummyRing>::new_direct("test-kid", b"device-1", ring)
            .with_now_unix(1700000000)
            .with_expiry_secs(600); // 10 minutes

        assert_eq!(client.now_unix, Some(1700000000));
        assert_eq!(client.expiry_secs, 600);
    }
}

/// Test RetryConfig defaults
mod retry_config_tests {
    #[cfg(feature = "storage-queue")]
    use pubky_noise::storage_queue::RetryConfig;

    #[test]
    #[cfg(feature = "storage-queue")]
    fn test_retry_config_defaults() {
        let config = RetryConfig::default();

        assert_eq!(config.max_retries, 3);
        assert_eq!(config.initial_backoff_ms, 100);
        assert_eq!(config.max_backoff_ms, 5000);
        assert_eq!(config.operation_timeout_ms, 30000); // 30 seconds
    }
}
