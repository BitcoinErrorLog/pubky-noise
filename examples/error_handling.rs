//! Error Handling Example
//!
//! This example demonstrates proper error handling patterns when
//! using the pubky-noise library.
//!
//! ## Running
//!
//! ```bash
//! cargo run --example error_handling
//! ```
//!
//! ## Overview
//!
//! The library uses a structured error type (`NoiseError`) that:
//! - Provides specific error variants for different failure modes
//! - Includes error codes for FFI/mobile integration
//! - Contains descriptive error messages

use pubky_noise::datalink_adapter::{
    client_complete_ik, client_start_ik_direct, server_accept_ik, server_complete_ik,
};
use pubky_noise::{DummyRing, NoiseClient, NoiseError, NoiseServer, RingKeyProvider};
use std::sync::Arc;

fn main() {
    println!("=== PubkyNoise Error Handling Example ===\n");

    // =========================================================================
    // Error: Invalid Peer Key
    // =========================================================================

    println!("1. Testing invalid peer key error...");

    let ring_client = Arc::new(DummyRing::new([1u8; 32], "kid"));
    let client = NoiseClient::<_, ()>::new_direct("kid", b"device", ring_client);

    // An all-zero key would produce an all-zero shared secret (security issue)
    let invalid_key = [0u8; 32];

    match client_start_ik_direct(&client, &invalid_key, None) {
        Ok(_) => println!("   Unexpected success!"),
        Err(NoiseError::InvalidPeerKey) => {
            println!("   Got expected error: InvalidPeerKey");
            println!("   This protects against weak key attacks");
        }
        Err(e) => println!("   Unexpected error: {:?}", e),
    }

    // =========================================================================
    // Error: Decryption Failure
    // =========================================================================

    println!("\n2. Testing decryption failure...");

    // Setup a valid session first
    let ring_client = Arc::new(DummyRing::new([1u8; 32], "kid"));
    let ring_server = Arc::new(DummyRing::new([2u8; 32], "kid"));

    let client = NoiseClient::<_, ()>::new_direct("kid", b"client", ring_client);
    let server = NoiseServer::<_, ()>::new_direct("kid", b"server", ring_server.clone());

    let server_sk = ring_server
        .derive_device_x25519("kid", b"server", 0)
        .unwrap();
    let server_pk = pubky_noise::kdf::x25519_pk_from_sk(&server_sk);

    let (c_hs, first_msg) = client_start_ik_direct(&client, &server_pk, None).unwrap();
    let (s_hs, _, response) = server_accept_ik(&server, &first_msg).unwrap();
    let _c_link = client_complete_ik(c_hs, &response).unwrap();
    let mut s_link = server_complete_ik(s_hs).unwrap();

    // Try to decrypt garbage data
    let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33];

    match s_link.decrypt(&garbage) {
        Ok(_) => println!("   Unexpected success!"),
        Err(e) => {
            println!("   Got error: {}", e);
            println!("   Error code: {:?}", e.code());

            // Use pattern matching for specific handling
            match e {
                NoiseError::Snow(msg) => {
                    println!("   Snow error (decryption): {}", msg);
                }
                _ => println!("   Other error type"),
            }
        }
    }

    // =========================================================================
    // Using Error Codes for FFI
    // =========================================================================

    println!("\n3. Error codes for FFI integration...");

    let errors = vec![
        NoiseError::Ring("key derivation failed".into()),
        NoiseError::Network("connection refused".into()),
        NoiseError::Timeout("30s elapsed".into()),
        NoiseError::InvalidPeerKey,
        NoiseError::IdentityVerify,
        NoiseError::Decryption("AEAD tag mismatch".into()),
    ];

    println!("   {:20} {:10} Message", "Error Type", "Code");
    println!("   {:20} {:10} -------", "----------", "----");

    for err in errors {
        let code = err.code() as i32;
        let message = err.message();
        let type_name = format!("{:?}", err).split('(').next().unwrap().to_string();
        println!("   {:20} {:10} {}", type_name, code, message);
    }

    // =========================================================================
    // Comprehensive Error Handling Function
    // =========================================================================

    println!("\n4. Comprehensive error handler example...");

    fn handle_noise_error(context: &str, error: NoiseError) {
        match error {
            NoiseError::Ring(msg) => {
                // Key management issue - may need to reset keys
                eprintln!("[CRITICAL] {}: Key error - {}", context, msg);
                // In production: log, alert, possibly reinitialize
            }

            NoiseError::InvalidPeerKey => {
                // Security issue - possible attack
                eprintln!("[SECURITY] {}: Invalid peer key detected!", context);
                // In production: refuse connection, alert security team
            }

            NoiseError::IdentityVerify => {
                // Authentication failed
                eprintln!("[AUTH] {}: Identity verification failed", context);
                // In production: reject connection, log attempt
            }

            NoiseError::Network(msg) => {
                // Network issue - retry may help
                eprintln!("[NETWORK] {}: {} - will retry", context, msg);
                // In production: implement retry with backoff
            }

            NoiseError::Timeout(msg) => {
                // Operation took too long
                eprintln!("[TIMEOUT] {}: {} - check network", context, msg);
                // In production: retry with longer timeout
            }

            NoiseError::Decryption(msg) => {
                // Decryption failed - data may be corrupted
                eprintln!("[CRYPTO] {}: {} - possible tampering", context, msg);
                // In production: may need to reset session
            }

            NoiseError::Snow(msg) => {
                // Protocol error
                eprintln!("[PROTOCOL] {}: {} - internal error", context, msg);
                // In production: log for debugging
            }

            NoiseError::Serde(msg) => {
                // Serialization issue
                eprintln!("[DATA] {}: {} - format error", context, msg);
                // In production: check data format, version compatibility
            }

            NoiseError::Storage(msg) => {
                // Storage operation failed
                eprintln!("[STORAGE] {}: {}", context, msg);
                // In production: check permissions, disk space
            }

            NoiseError::Policy(msg) => {
                // Policy violation (rate limiting, etc.)
                eprintln!("[POLICY] {}: {}", context, msg);
                // In production: back off, respect limits
            }

            NoiseError::RateLimited(msg) => {
                // Rate limited - retry after delay
                eprintln!("[RATE_LIMITED] {}: {} - will retry later", context, msg);
                // In production: parse retry-after and wait
            }

            NoiseError::MaxSessionsExceeded => {
                // Too many sessions for this identity
                eprintln!("[SESSIONS] {}: Maximum sessions exceeded", context);
                // In production: close old sessions first
            }

            NoiseError::SessionExpired(msg) => {
                // Session expired or not found
                eprintln!("[SESSION] {}: {} - re-authenticate", context, msg);
                // In production: create new session
            }

            NoiseError::ConnectionReset(msg) => {
                // Connection was reset
                eprintln!("[RESET] {}: {} - will reconnect", context, msg);
                // In production: reconnect with backoff
            }

            NoiseError::RemoteStaticMissing => {
                // Server key not available
                eprintln!("[CONFIG] {}: Server key not configured", context);
                // In production: fetch key from configuration
            }

            NoiseError::Pkarr(msg) => {
                // PKARR-related error
                eprintln!("[PKARR] {}: {}", context, msg);
            }

            NoiseError::Other(msg) => {
                // Unknown error
                eprintln!("[UNKNOWN] {}: {}", context, msg);
            }
        }
    }

    // Demonstrate the handler
    handle_noise_error("Connection attempt", NoiseError::InvalidPeerKey);
    handle_noise_error(
        "Message send",
        NoiseError::Network("connection reset".into()),
    );

    // =========================================================================
    // Result-Based Error Handling
    // =========================================================================

    println!("\n5. Result-based error handling patterns...");

    fn try_encrypt(
        link: &mut pubky_noise::datalink_adapter::NoiseLink,
        data: &[u8],
    ) -> Result<Vec<u8>, String> {
        link.encrypt(data).map_err(|e| {
            // Convert to application error
            format!("Encryption failed: {} (code: {:?})", e.message(), e.code())
        })
    }

    // Setup another session for this example
    let ring_client = Arc::new(DummyRing::new([3u8; 32], "kid"));
    let ring_server = Arc::new(DummyRing::new([4u8; 32], "kid"));

    let client = NoiseClient::<_, ()>::new_direct("kid", b"client", ring_client);
    let server = NoiseServer::<_, ()>::new_direct("kid", b"server", ring_server.clone());

    let server_sk = ring_server
        .derive_device_x25519("kid", b"server", 0)
        .unwrap();
    let server_pk = pubky_noise::kdf::x25519_pk_from_sk(&server_sk);

    let (c_hs, first_msg) = client_start_ik_direct(&client, &server_pk, None).unwrap();
    let (s_hs, _, response) = server_accept_ik(&server, &first_msg).unwrap();
    let mut c_link = client_complete_ik(c_hs, &response).unwrap();
    let _s_link = server_complete_ik(s_hs).unwrap();

    match try_encrypt(&mut c_link, b"Hello, world!") {
        Ok(ciphertext) => println!("   Encryption succeeded: {} bytes", ciphertext.len()),
        Err(msg) => println!("   Error: {}", msg),
    }

    // =========================================================================
    // Summary
    // =========================================================================

    println!("\n=== Error handling example complete! ===");
    println!("\nKey points:");
    println!("- Use pattern matching for specific error handling");
    println!("- Error codes (NoiseErrorCode) are stable for FFI");
    println!("- Error messages (message()) are for logging/display");
    println!("- Different errors need different recovery strategies");
    println!("- Security errors (InvalidPeerKey, IdentityVerify) need special attention");
}
