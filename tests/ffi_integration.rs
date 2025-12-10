//! Comprehensive FFI layer integration tests
//!
//! This module tests the Foreign Function Interface layer, including:
//! - Type conversions across FFI boundary
//! - Error handling and propagation
//! - Connection lifecycle management
//! - Thread safety
//! - Mobile platform considerations

#![cfg(feature = "uniffi_macros")]

use pubky_noise::ffi::{
    FfiConnectionStatus, FfiMobileConfig, FfiNoiseError, FfiNoiseManager, FfiSessionState,
};
use pubky_noise::mobile_manager::ConnectionStatus;
use pubky_noise::mobile_manager::MobileConfig;

// ============================================================================
// Type Conversion Tests
// ============================================================================

#[test]
fn test_connection_status_round_trip() {
    // Test that ConnectionStatus converts to FFI and back correctly
    let statuses = vec![
        ConnectionStatus::Connected,
        ConnectionStatus::Reconnecting,
        ConnectionStatus::Disconnected,
        ConnectionStatus::Error,
    ];

    for original in statuses {
        let ffi: FfiConnectionStatus = original.clone().into();
        let back: ConnectionStatus = ffi.into();

        // Compare by converting both to discriminants
        assert_eq!(
            std::mem::discriminant(&original),
            std::mem::discriminant(&back),
            "Status should survive round-trip"
        );
    }
}

#[test]
fn test_connection_status_all_variants() {
    // Ensure all ConnectionStatus variants have FFI representations
    let _connected: FfiConnectionStatus = ConnectionStatus::Connected.into();
    let _reconnecting: FfiConnectionStatus = ConnectionStatus::Reconnecting.into();
    let _disconnected: FfiConnectionStatus = ConnectionStatus::Disconnected.into();
    let _error: FfiConnectionStatus = ConnectionStatus::Error.into();

    // If this compiles, all variants are covered
}

#[test]
fn test_mobile_config_conversion_preserves_values() {
    // Test that MobileConfig converts to FFI preserving all field values
    let original = MobileConfig {
        auto_reconnect: true,
        max_reconnect_attempts: 5,
        reconnect_delay_ms: 1000,
        battery_saver: false,
        chunk_size: 32768,
    };

    let ffi: FfiMobileConfig = original.clone().into();

    assert_eq!(ffi.auto_reconnect, original.auto_reconnect);
    assert_eq!(ffi.max_reconnect_attempts, original.max_reconnect_attempts);
    assert_eq!(ffi.reconnect_delay_ms, original.reconnect_delay_ms);
    assert_eq!(ffi.battery_saver, original.battery_saver);
    assert_eq!(ffi.chunk_size, original.chunk_size as u64);
}

#[test]
fn test_mobile_config_round_trip() {
    // Test MobileConfig survives FFI round-trip
    let original = MobileConfig {
        auto_reconnect: false,
        max_reconnect_attempts: 10,
        reconnect_delay_ms: 2500,
        battery_saver: true,
        chunk_size: 16384,
    };

    let ffi: FfiMobileConfig = original.clone().into();
    let back: MobileConfig = ffi.into();

    assert_eq!(back.auto_reconnect, original.auto_reconnect);
    assert_eq!(back.max_reconnect_attempts, original.max_reconnect_attempts);
    assert_eq!(back.reconnect_delay_ms, original.reconnect_delay_ms);
    assert_eq!(back.battery_saver, original.battery_saver);
    assert_eq!(back.chunk_size, original.chunk_size);
}

#[test]
fn test_mobile_config_edge_values() {
    // Test edge case values for mobile config
    let configs = vec![
        MobileConfig {
            auto_reconnect: false,
            max_reconnect_attempts: 0,
            reconnect_delay_ms: 0,
            battery_saver: false,
            chunk_size: 1,
        },
        MobileConfig {
            auto_reconnect: true,
            max_reconnect_attempts: u32::MAX,
            reconnect_delay_ms: u64::MAX,
            battery_saver: true,
            chunk_size: usize::MAX,
        },
    ];

    for config in configs {
        let ffi: FfiMobileConfig = config.clone().into();
        let back: MobileConfig = ffi.into();

        assert_eq!(back.auto_reconnect, config.auto_reconnect);
        assert_eq!(back.max_reconnect_attempts, config.max_reconnect_attempts);
        assert_eq!(back.reconnect_delay_ms, config.reconnect_delay_ms);
        assert_eq!(back.battery_saver, config.battery_saver);
    }
}

#[test]
fn test_mobile_config_clone() {
    // Test that FfiMobileConfig can be cloned
    let original = FfiMobileConfig {
        auto_reconnect: true,
        max_reconnect_attempts: 3,
        reconnect_delay_ms: 500,
        battery_saver: false,
        chunk_size: 8192,
    };

    let cloned = original.clone();

    assert_eq!(cloned.auto_reconnect, original.auto_reconnect);
    assert_eq!(
        cloned.max_reconnect_attempts,
        original.max_reconnect_attempts
    );
    assert_eq!(cloned.reconnect_delay_ms, original.reconnect_delay_ms);
    assert_eq!(cloned.battery_saver, original.battery_saver);
    assert_eq!(cloned.chunk_size, original.chunk_size);
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[test]
fn test_ffi_noise_error_types() {
    // Test that all error types can be created
    let _ring = FfiNoiseError::Ring {
        message: "test".to_string(),
    };
    let _pkarr = FfiNoiseError::Pkarr {
        message: "test".to_string(),
    };
    let _snow = FfiNoiseError::Snow {
        message: "test".to_string(),
    };
    let _serde = FfiNoiseError::Serde {
        message: "test".to_string(),
    };
    let _identity = FfiNoiseError::IdentityVerify;
    let _remote = FfiNoiseError::RemoteStaticMissing;
    let _policy = FfiNoiseError::Policy {
        message: "test".to_string(),
    };
    let _invalid = FfiNoiseError::InvalidPeerKey;
    let _network = FfiNoiseError::Network {
        message: "test".to_string(),
    };
    let _timeout = FfiNoiseError::Timeout {
        message: "test".to_string(),
    };
    let _storage = FfiNoiseError::Storage {
        message: "test".to_string(),
    };
    let _decryption = FfiNoiseError::Decryption {
        message: "test".to_string(),
    };
    let _other = FfiNoiseError::Other {
        message: "test".to_string(),
    };
}

#[test]
fn test_ffi_error_message_preservation() {
    // Test that error messages are preserved
    let msg = "detailed error information";
    let error = FfiNoiseError::Ring {
        message: msg.to_string(),
    };

    match error {
        FfiNoiseError::Ring { message } => assert_eq!(message, msg),
        _ => panic!("Wrong error variant"),
    }
}

#[test]
fn test_ffi_error_different_variants() {
    // Test that different error variants are distinct
    let errors = vec![
        FfiNoiseError::Ring {
            message: "a".to_string(),
        },
        FfiNoiseError::Snow {
            message: "b".to_string(),
        },
        FfiNoiseError::Decryption {
            message: "c".to_string(),
        },
        FfiNoiseError::IdentityVerify,
        FfiNoiseError::RemoteStaticMissing,
        FfiNoiseError::Other {
            message: "f".to_string(),
        },
    ];

    // Each error should be distinguishable
    for (i, error) in errors.iter().enumerate() {
        match error {
            FfiNoiseError::Ring { .. } => assert_eq!(i, 0),
            FfiNoiseError::Snow { .. } => assert_eq!(i, 1),
            FfiNoiseError::Decryption { .. } => assert_eq!(i, 2),
            FfiNoiseError::IdentityVerify => assert_eq!(i, 3),
            FfiNoiseError::RemoteStaticMissing => assert_eq!(i, 4),
            FfiNoiseError::Other { .. } => assert_eq!(i, 5),
            _ => {}
        }
    }
}

#[test]
fn test_ffi_error_empty_messages() {
    // Test that errors can have empty messages
    let _ring = FfiNoiseError::Ring {
        message: String::new(),
    };
    let _network = FfiNoiseError::Network {
        message: String::new(),
    };
    let _other = FfiNoiseError::Other {
        message: String::new(),
    };
}

#[test]
fn test_ffi_error_long_messages() {
    // Test that errors can handle long messages
    let long_msg = "x".repeat(10000);
    let error = FfiNoiseError::Other {
        message: long_msg.clone(),
    };

    match error {
        FfiNoiseError::Other { message } => assert_eq!(message.len(), 10000),
        _ => panic!("Wrong error variant"),
    }
}

#[test]
fn test_ffi_error_no_message_variants() {
    // Test error variants without messages
    let _identity = FfiNoiseError::IdentityVerify;
    let _remote = FfiNoiseError::RemoteStaticMissing;
    let _invalid = FfiNoiseError::InvalidPeerKey;

    // These should compile and be usable
}

// ============================================================================
// Manager Creation Tests
// ============================================================================

#[test]
fn test_ffi_manager_client_creation() {
    // Test creating a client FfiNoiseManager
    let config = FfiMobileConfig {
        auto_reconnect: true,
        max_reconnect_attempts: 5,
        reconnect_delay_ms: 1000,
        battery_saver: false,
        chunk_size: 32768,
    };

    let seed = vec![42u8; 32];
    let kid = "test-kid".to_string();
    let device_id = b"device-1".to_vec();

    let result = FfiNoiseManager::new_client(config, seed, kid, device_id);
    assert!(result.is_ok(), "Should create client manager successfully");
}

#[test]
fn test_ffi_manager_server_creation() {
    // Test creating a server FfiNoiseManager
    let config = FfiMobileConfig {
        auto_reconnect: false,
        max_reconnect_attempts: 3,
        reconnect_delay_ms: 500,
        battery_saver: true,
        chunk_size: 16384,
    };

    let seed = vec![99u8; 32];
    let kid = "server-kid".to_string();
    let device_id = b"server-device".to_vec();

    let result = FfiNoiseManager::new_server(config, seed, kid, device_id);
    assert!(result.is_ok(), "Should create server manager successfully");
}

#[test]
fn test_ffi_manager_different_configs() {
    // Test managers with various configurations
    let configs = vec![
        FfiMobileConfig {
            auto_reconnect: true,
            max_reconnect_attempts: 1,
            reconnect_delay_ms: 100,
            battery_saver: false,
            chunk_size: 1024,
        },
        FfiMobileConfig {
            auto_reconnect: false,
            max_reconnect_attempts: 10,
            reconnect_delay_ms: 5000,
            battery_saver: true,
            chunk_size: 65536,
        },
    ];

    for (i, config) in configs.into_iter().enumerate() {
        let seed = vec![i as u8; 32];
        let kid = format!("kid-{}", i);
        let device_id = format!("device-{}", i).into_bytes();

        let result = FfiNoiseManager::new_client(config, seed, kid, device_id);
        assert!(result.is_ok(), "Config {} should work", i);
    }
}

#[test]
fn test_ffi_manager_invalid_seed_length() {
    // Test that invalid seed length is rejected
    let config = FfiMobileConfig {
        auto_reconnect: true,
        max_reconnect_attempts: 3,
        reconnect_delay_ms: 1000,
        battery_saver: false,
        chunk_size: 32768,
    };

    let short_seed = vec![1u8; 16]; // Too short
    let kid = "test-kid".to_string();
    let device_id = b"device".to_vec();

    let result = FfiNoiseManager::new_client(config, short_seed, kid, device_id);
    assert!(result.is_err(), "Should reject short seed");
}

#[test]
fn test_ffi_manager_empty_kid() {
    // Test behavior with empty key ID
    let config = FfiMobileConfig {
        auto_reconnect: true,
        max_reconnect_attempts: 3,
        reconnect_delay_ms: 1000,
        battery_saver: false,
        chunk_size: 32768,
    };

    let seed = vec![42u8; 32];
    let empty_kid = String::new();
    let device_id = b"device".to_vec();

    // Empty kid might be allowed or rejected depending on implementation
    let _result = FfiNoiseManager::new_client(config, seed, empty_kid, device_id);
    // Just verify it doesn't panic
}

#[test]
fn test_ffi_manager_empty_device_id() {
    // Test behavior with empty device ID
    let config = FfiMobileConfig {
        auto_reconnect: true,
        max_reconnect_attempts: 3,
        reconnect_delay_ms: 1000,
        battery_saver: false,
        chunk_size: 32768,
    };

    let seed = vec![42u8; 32];
    let kid = "test-kid".to_string();
    let empty_device = Vec::new();

    // Empty device ID might be allowed or rejected
    let _result = FfiNoiseManager::new_client(config, seed, kid, empty_device);
    // Just verify it doesn't panic
}

#[test]
fn test_ffi_manager_long_identifiers() {
    // Test with very long identifiers
    let config = FfiMobileConfig {
        auto_reconnect: true,
        max_reconnect_attempts: 3,
        reconnect_delay_ms: 1000,
        battery_saver: false,
        chunk_size: 32768,
    };

    let seed = vec![42u8; 32];
    let long_kid = "x".repeat(1000);
    let long_device_id = vec![42u8; 1000];

    let result = FfiNoiseManager::new_client(config, seed, long_kid, long_device_id);
    // Should handle long identifiers
    assert!(result.is_ok(), "Should handle long identifiers");
}

// ============================================================================
// Session State Tests
// ============================================================================

#[test]
fn test_ffi_session_state_fields() {
    // Test that FfiSessionState has all expected fields
    let state = FfiSessionState {
        session_id: "abcd1234".to_string(),
        peer_static_pk: vec![1u8; 32],
        epoch: 42,
        write_counter: 10,
        read_counter: 5,
        status: FfiConnectionStatus::Connected,
    };

    assert_eq!(state.session_id, "abcd1234");
    assert_eq!(state.peer_static_pk.len(), 32);
    assert_eq!(state.epoch, 42);
    assert_eq!(state.write_counter, 10);
    assert_eq!(state.read_counter, 5);
}

#[test]
fn test_ffi_session_state_with_different_statuses() {
    // Test session state with all status variants
    let statuses = vec![
        FfiConnectionStatus::Connected,
        FfiConnectionStatus::Reconnecting,
        FfiConnectionStatus::Disconnected,
        FfiConnectionStatus::Error,
    ];

    for status in statuses {
        let state = FfiSessionState {
            session_id: "test".to_string(),
            peer_static_pk: vec![0u8; 32],
            epoch: 1,
            write_counter: 0,
            read_counter: 0,
            status,
        };

        // Just verify it can be created with each status
        assert_eq!(state.epoch, 1);
    }
}

#[test]
fn test_ffi_session_state_counter_ranges() {
    // Test session state with various counter values
    let states = vec![(0u64, 0u64), (1, 1), (100, 200), (u64::MAX - 1, u64::MAX)];

    for (write, read) in states {
        let state = FfiSessionState {
            session_id: "test".to_string(),
            peer_static_pk: vec![0u8; 32],
            epoch: 1,
            write_counter: write,
            read_counter: read,
            status: FfiConnectionStatus::Connected,
        };

        assert_eq!(state.write_counter, write);
        assert_eq!(state.read_counter, read);
    }
}

// ============================================================================
// Mobile Configuration Tests
// ============================================================================

#[test]
fn test_mobile_config_battery_saver_combinations() {
    // Test various battery saver configurations
    let configs = vec![
        (true, 1024u64), // Battery saver with small chunks
        (true, 65536),   // Battery saver with large chunks
        (false, 1024),   // No battery saver with small chunks
        (false, 65536),  // No battery saver with large chunks
    ];

    for (battery_saver, chunk_size) in configs {
        let config = FfiMobileConfig {
            auto_reconnect: true,
            max_reconnect_attempts: 3,
            reconnect_delay_ms: 1000,
            battery_saver,
            chunk_size,
        };

        assert_eq!(config.battery_saver, battery_saver);
        assert_eq!(config.chunk_size, chunk_size);
    }
}

#[test]
fn test_mobile_config_reconnect_strategies() {
    // Test different reconnect strategies
    let strategies = vec![
        ("aggressive", 10u32, 100u64),
        ("moderate", 5, 1000),
        ("conservative", 3, 5000),
        ("disabled", 0, 0),
    ];

    for (_name, max_attempts, delay_ms) in strategies {
        let config = FfiMobileConfig {
            auto_reconnect: max_attempts > 0,
            max_reconnect_attempts: max_attempts,
            reconnect_delay_ms: delay_ms,
            battery_saver: false,
            chunk_size: 32768,
        };

        assert_eq!(config.max_reconnect_attempts, max_attempts);
        assert_eq!(config.reconnect_delay_ms, delay_ms);
    }
}

#[test]
fn test_mobile_config_chunk_sizes() {
    // Test various chunk size configurations
    let chunk_sizes = vec![512u64, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072];

    for chunk_size in chunk_sizes {
        let config = FfiMobileConfig {
            auto_reconnect: true,
            max_reconnect_attempts: 3,
            reconnect_delay_ms: 1000,
            battery_saver: false,
            chunk_size,
        };

        assert_eq!(config.chunk_size, chunk_size);

        // Convert to MobileConfig and back
        let mobile: MobileConfig = config.clone().into();
        let back: FfiMobileConfig = mobile.into();

        assert_eq!(back.chunk_size, chunk_size);
    }
}

// ============================================================================
// Thread Safety Tests
// ============================================================================

#[test]
fn test_ffi_types_are_send_sync() {
    // Verify that FFI types can be safely sent between threads
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    // These should compile if types are Send+Sync
    assert_send::<FfiMobileConfig>();
    assert_sync::<FfiMobileConfig>();

    // Note: FfiNoiseManager might not be Sync due to Mutex, that's expected
}

#[test]
fn test_mobile_config_across_threads() {
    // Test that mobile config can be moved across threads
    let config = FfiMobileConfig {
        auto_reconnect: true,
        max_reconnect_attempts: 5,
        reconnect_delay_ms: 1000,
        battery_saver: false,
        chunk_size: 32768,
    };

    let handle = std::thread::spawn(move || {
        assert_eq!(config.max_reconnect_attempts, 5);
        config
    });

    let returned_config = handle.join().unwrap();
    assert_eq!(returned_config.chunk_size, 32768);
}

// ============================================================================
// Data Integrity Tests
// ============================================================================

#[test]
fn test_public_key_size_validation() {
    // Test that public keys maintain correct size through FFI
    let pk_sizes = vec![32, 33, 64]; // Different sizes to test

    for size in pk_sizes {
        let state = FfiSessionState {
            session_id: "test".to_string(),
            peer_static_pk: vec![0u8; size],
            epoch: 1,
            write_counter: 0,
            read_counter: 0,
            status: FfiConnectionStatus::Connected,
        };

        assert_eq!(state.peer_static_pk.len(), size);
    }
}

#[test]
fn test_session_id_format_preservation() {
    // Test various session ID formats
    let session_ids = vec![
        "1234567890abcdef",
        "ABCDEF1234567890",
        "00000000000000000000000000000000",
        "ffffffffffffffffffffffffffffffff",
    ];

    for sid in session_ids {
        let state = FfiSessionState {
            session_id: sid.to_string(),
            peer_static_pk: vec![0u8; 32],
            epoch: 1,
            write_counter: 0,
            read_counter: 0,
            status: FfiConnectionStatus::Connected,
        };

        assert_eq!(state.session_id, sid);
    }
}

#[test]
fn test_epoch_value_ranges() {
    // Test various epoch values
    let epochs = vec![0u32, 1, 100, 1000, u32::MAX];

    for epoch in epochs {
        let state = FfiSessionState {
            session_id: "test".to_string(),
            peer_static_pk: vec![0u8; 32],
            epoch,
            write_counter: 0,
            read_counter: 0,
            status: FfiConnectionStatus::Connected,
        };

        assert_eq!(state.epoch, epoch);
    }
}
