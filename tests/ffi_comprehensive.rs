//! Comprehensive FFI layer tests
//!
//! These tests verify the FFI wrapper functionality, type conversions,
//! error handling, and thread safety.

#[cfg(all(test, feature = "uniffi_macros"))]
mod ffi_tests {
    use pubky_noise::ffi::config::{
        battery_saver_config, default_config, derive_device_key, performance_config,
        public_key_from_secret,
    };
    use pubky_noise::ffi::manager::FfiNoiseManager;
    use pubky_noise::ffi::types::{FfiConnectionStatus, FfiMobileConfig};
    use pubky_noise::DummyRing;
    use std::sync::Arc;

    #[test]
    fn test_config_helpers() {
        // Test default config
        let config = default_config();
        assert!(config.auto_reconnect);
        assert_eq!(config.chunk_size, 32768);

        // Test battery saver config
        let battery = battery_saver_config();
        assert!(!battery.auto_reconnect);
        assert!(battery.battery_saver);
        assert_eq!(battery.max_reconnect_attempts, 2);
        assert_eq!(battery.chunk_size, 16384);

        // Test performance config
        let perf = performance_config();
        assert!(perf.auto_reconnect);
        assert!(!perf.battery_saver);
        assert_eq!(perf.max_reconnect_attempts, 10);
        assert_eq!(perf.chunk_size, 65536);
    }

    #[test]
    fn test_key_derivation() {
        let seed = vec![1u8; 32];
        let device_id = b"test-device".to_vec();
        let epoch = 5;

        let key = derive_device_key(seed.clone(), device_id.clone(), epoch);
        assert_eq!(key.len(), 32);

        // Same inputs should produce same output
        let key2 = derive_device_key(seed.clone(), device_id.clone(), epoch);
        assert_eq!(key, key2);

        // Different epoch should produce different output
        let key3 = derive_device_key(seed, device_id, epoch + 1);
        assert_ne!(key, key3);
    }

    #[test]
    fn test_public_key_from_secret() {
        let secret = vec![42u8; 32];
        let pk = public_key_from_secret(secret.clone());

        assert_eq!(pk.len(), 32);

        // Same secret should produce same public key
        let pk2 = public_key_from_secret(secret);
        assert_eq!(pk, pk2);
    }

    #[test]
    fn test_ffi_manager_creation() {
        let config = default_config();
        let seed = vec![1u8; 32];
        let kid = "test-client".to_string();
        let device_id = b"device-123".to_vec();

        let result = FfiNoiseManager::new_client(config, seed, kid, device_id);
        assert!(result.is_ok(), "Failed to create FfiNoiseManager");
    }

    #[test]
    fn test_ffi_manager_invalid_seed() {
        let config = default_config();
        let seed = vec![1u8; 16]; // Wrong size
        let kid = "test-client".to_string();
        let device_id = b"device-123".to_vec();

        let result = FfiNoiseManager::new_client(config, seed, kid, device_id);
        assert!(result.is_err());

        if let Err(e) = result {
            assert!(format!("{:?}", e).contains("32 bytes"));
        }
    }

    #[test]
    fn test_ffi_server_creation() {
        let config = default_config();
        let seed = vec![2u8; 32];
        let kid = "test-server".to_string();
        let device_id = b"server-device".to_vec();

        let result = FfiNoiseManager::new_server(config, seed, kid, device_id);
        assert!(result.is_ok(), "Failed to create server FfiNoiseManager");
    }

    #[test]
    fn test_session_list_empty() {
        let config = default_config();
        let seed = vec![1u8; 32];
        let manager =
            FfiNoiseManager::new_client(config, seed, "test".to_string(), b"dev".to_vec()).unwrap();

        let sessions = manager.list_sessions();
        assert_eq!(sessions.len(), 0);
    }

    #[test]
    fn test_connection_status_conversion() {
        use pubky_noise::ffi::types::FfiConnectionStatus;
        use pubky_noise::mobile_manager::ConnectionStatus as CoreStatus;

        // Test all conversions
        let statuses = vec![
            (CoreStatus::Connected, FfiConnectionStatus::Connected),
            (CoreStatus::Reconnecting, FfiConnectionStatus::Reconnecting),
            (CoreStatus::Disconnected, FfiConnectionStatus::Disconnected),
            (CoreStatus::Error, FfiConnectionStatus::Error),
        ];

        for (core, ffi) in statuses {
            let converted_ffi: FfiConnectionStatus = core.into();
            assert!(matches!(
                (&converted_ffi, &ffi),
                (
                    FfiConnectionStatus::Connected,
                    FfiConnectionStatus::Connected
                ) | (
                    FfiConnectionStatus::Reconnecting,
                    FfiConnectionStatus::Reconnecting
                ) | (
                    FfiConnectionStatus::Disconnected,
                    FfiConnectionStatus::Disconnected
                ) | (FfiConnectionStatus::Error, FfiConnectionStatus::Error)
            ));

            let converted_back: CoreStatus = converted_ffi.into();
            assert_eq!(
                std::mem::discriminant(&core),
                std::mem::discriminant(&converted_back)
            );
        }
    }

    #[test]
    fn test_mobile_config_conversion() {
        use pubky_noise::mobile_manager::MobileConfig;

        let ffi_config = FfiMobileConfig {
            auto_reconnect: true,
            max_reconnect_attempts: 7,
            reconnect_delay_ms: 1500,
            battery_saver: true,
            chunk_size: 40000,
        };

        let core_config: MobileConfig = ffi_config.clone().into();
        assert_eq!(core_config.auto_reconnect, ffi_config.auto_reconnect);
        assert_eq!(
            core_config.max_reconnect_attempts,
            ffi_config.max_reconnect_attempts
        );
        assert_eq!(
            core_config.reconnect_delay_ms,
            ffi_config.reconnect_delay_ms
        );
        assert_eq!(core_config.battery_saver, ffi_config.battery_saver);
        assert_eq!(core_config.chunk_size, ffi_config.chunk_size as usize);

        // Convert back
        let ffi_again: FfiMobileConfig = core_config.into();
        assert_eq!(ffi_again.chunk_size, ffi_config.chunk_size);
    }

    #[test]
    fn test_invalid_session_id_parse() {
        let config = default_config();
        let seed = vec![1u8; 32];
        let manager =
            FfiNoiseManager::new_client(config, seed, "test".to_string(), b"dev".to_vec()).unwrap();

        // Invalid hex
        let result = manager.get_status("not-hex-at-all".to_string());
        assert!(result.is_none());

        // Valid hex but wrong length
        let result = manager.get_status("deadbeef".to_string());
        assert!(result.is_none());
    }

    #[test]
    fn test_encrypt_decrypt_without_session() {
        let config = default_config();
        let seed = vec![1u8; 32];
        let manager =
            FfiNoiseManager::new_client(config, seed, "test".to_string(), b"dev".to_vec()).unwrap();

        // Try to encrypt with non-existent session
        let fake_session = "0".repeat(64); // 32 bytes as hex
        let result = manager.encrypt(fake_session.clone(), b"test".to_vec());
        assert!(result.is_err());

        // Try to decrypt with non-existent session
        let result = manager.decrypt(fake_session, b"test".to_vec());
        assert!(result.is_err());
    }

    #[test]
    fn test_remove_nonexistent_session() {
        let config = default_config();
        let seed = vec![1u8; 32];
        let manager =
            FfiNoiseManager::new_client(config, seed, "test".to_string(), b"dev".to_vec()).unwrap();

        let sessions_before = manager.list_sessions();

        // Remove non-existent session (should not panic)
        let fake_session = "0".repeat(64);
        manager.remove_session(fake_session);

        let sessions_after = manager.list_sessions();
        assert_eq!(sessions_before.len(), sessions_after.len());
    }

    #[test]
    fn test_save_state_nonexistent_session() {
        let config = default_config();
        let seed = vec![1u8; 32];
        let manager =
            FfiNoiseManager::new_client(config, seed, "test".to_string(), b"dev".to_vec()).unwrap();

        let fake_session = "0".repeat(64);
        let result = manager.save_state(fake_session);
        assert!(result.is_err());
    }

    #[test]
    fn test_thread_safety_basic() {
        use std::thread;

        let config = default_config();
        let seed = vec![1u8; 32];
        let manager = Arc::new(
            FfiNoiseManager::new_client(config, seed, "test".to_string(), b"dev".to_vec()).unwrap(),
        );

        let manager1 = manager.clone();
        let manager2 = manager.clone();

        let handle1 = thread::spawn(move || {
            for _ in 0..10 {
                let _ = manager1.list_sessions();
            }
        });

        let handle2 = thread::spawn(move || {
            for _ in 0..10 {
                let _ = manager2.list_sessions();
            }
        });

        handle1.join().unwrap();
        handle2.join().unwrap();
    }

    #[test]
    fn test_error_type_conversions() {
        use pubky_noise::ffi::errors::FfiNoiseError;
        use pubky_noise::NoiseError;

        let test_cases = vec![
            NoiseError::Ring("test ring error".into()),
            NoiseError::Snow("test snow error".into()),
            NoiseError::Network("test network error".into()),
            NoiseError::Timeout("test timeout".into()),
            NoiseError::Storage("test storage error".into()),
            NoiseError::Decryption("test decryption error".into()),
            NoiseError::IdentityVerify,
            NoiseError::RemoteStaticMissing,
            NoiseError::InvalidPeerKey,
        ];

        for error in test_cases {
            let ffi_error: FfiNoiseError = error.into();
            // Just verify it converts without panic
            let _ = format!("{:?}", ffi_error);
        }
    }

    #[test]
    fn test_seed_length_validation() {
        let config = default_config();
        let kid = "test".to_string();
        let device_id = b"dev".to_vec();

        // Test various invalid lengths
        for len in [0, 1, 15, 16, 31, 33, 64] {
            let seed = vec![1u8; len];
            let result =
                FfiNoiseManager::new_client(config.clone(), seed, kid.clone(), device_id.clone());
            assert!(result.is_err(), "Should reject seed of length {}", len);
        }

        // Valid length should work
        let seed = vec![1u8; 32];
        let result = FfiNoiseManager::new_client(config, seed, kid, device_id);
        assert!(result.is_ok());
    }

    #[test]
    fn test_config_presets_are_valid() {
        // Ensure all preset configs have valid values
        let configs = vec![
            default_config(),
            battery_saver_config(),
            performance_config(),
        ];

        for config in configs {
            assert!(config.max_reconnect_attempts > 0);
            assert!(config.reconnect_delay_ms > 0);
            assert!(config.chunk_size >= 1024); // At least 1KB
            assert!(config.chunk_size <= 1024 * 1024); // At most 1MB
        }
    }
}
